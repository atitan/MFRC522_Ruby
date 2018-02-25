class PICC
  FSCI_to_FSC = [16, 24, 32, 40, 48, 64, 96, 128, 256]

  CMD_RATS      = 0xE0
  CMD_PPS       = 0xD0
  CMD_DESELECT  = 0xC2

  attr_reader :uid
  attr_reader :sak

  def initialize(pcd, uid, sak)
    @pcd = pcd
    @uid = uid
    @sak = sak
    @halted = false

    ## ISO mode
    @cid = 0x00 # We don't support CID, fix it to 0
    @fsc = 16 # Assume PICC only supports 16 bytes frame
    @fwt = 256 # 77.33ms(256 ticks) default frame waiting time
    @picc_support_cid = false # PICC support for CID
    @picc_support_nad = false # PICC support for NAD
    @block_number = 0 # ISO frame block number
    @iso_selected = false # If card is in iso mode
  end

  def picc_transceive(send_data, accept_timeout = false, need_bits = false)
    received_data, valid_bits = @pcd.picc_transceive(send_data, accept_timeout)
    if need_bits
      return received_data, valid_bits
    else
      return received_data
    end
  end

  # Wrapper for handling ISO protocol
  def iso_transceive(send_data)
    # Split data according to max buffer size
    send_data = [send_data] unless send_data.is_a? Array
    chained_data = send_data.each_slice(@max_inf_size).to_a

    # Initialize I-block
    pcb = 0x02

    # Send chained data
    until chained_data.empty?
      pcb &= 0xEF # Reset chaining indicator
      pcb |= 0x10 if chained_data.size > 1 # Set chaining
      pcb |= @block_number # Set block number
      data = chained_data.shift

      buffer = [pcb] + data

      finished = false
      until finished
        received_data = handle_wtx(buffer)

        # Retreive response pcb from data
        r_pcb = received_data[0]

        # Received ACK
        if r_pcb & 0xF6 == 0xA2
          # If ACK matches current block number means success
          # Otherwise transmit it again
          if (pcb & 0x01) == (r_pcb & 0x01)
            finished = true
          end
        else
          finished = true
        end
      end

      @block_number ^= 1 # toggle block number for next frame
    end

    received_chained_data = [received_data]

    # Receive chained data
    while r_pcb & 0x10 != 0
      ack = 0xA2 | @block_number # Set block number
      received_data = handle_wtx([ack]) # Send ACK to receive next frame

      r_pcb = received_data[0]

      received_chained_data << received_data

      @block_number ^= 1 # toggle block number for next frame
    end

    # Collect INF from chain
    inf = []
    received_chained_data.each do |data|
      inf_position = 1
      inf_position += 1 if data[0] & 0x08 != 0 # CID present
      inf_position += 1 if data[0] & 0x04 != 0 # NAD present

      inf.concat(data[inf_position..-1])
    end
    inf
  end

  # ISO/IEC 14443-4 select
  def iso_select
    # Send RATS (Request for Answer To Select)
    buffer = [CMD_RATS, 0x50 | @cid]
    received_data = @pcd.picc_transceive(buffer)

    process_ats(received_data)

    # Send PPS (Protocol and Parameter Selection Request)
    buffer = [CMD_PPS | @cid, 0x11, (@dsi << 2) | @dri]
    received_data = @pcd.picc_transceive(buffer)
    raise UnexpectedDataError, 'Incorrect response' if received_data[0] != (0xD0 | @cid)

    # Set PCD baud rate
    @pcd.transceiver_baud_rate(:tx, @dri)
    @pcd.transceiver_baud_rate(:rx, @dsi)

    @block_number = 0
    @max_frame_size = [64, @fsc].min
    @max_inf_size = @max_frame_size - 3 # PCB + CRC16
    @max_inf_size -= 1 if @picc_support_cid
    @max_inf_size -= 1 if @picc_support_nad
    @iso_selected = true
  end

  # Send S(DESELECT)
  def iso_deselect
    buffer = [CMD_DESELECT]
    received_data = @pcd.picc_transceive(buffer)

    result = received_data[0] & 0xF7 == CMD_DESELECT
    @iso_selected = !result
    result
  end

  def restart_communication
    picc_was_in_iso_mode = @iso_selected
    iso_deselect if picc_was_in_iso_mode
    unless @pcd.reestablish_picc_communication(@uid)
      halt
      raise CommunicationError, 'Unable to resume communication or wrong card was presented. Halting cards in the field.'
    end
    iso_select if picc_was_in_iso_mode
  end

  def halt
    iso_deselect if @iso_selected
    @halted = @pcd.picc_halt
  end

  protected

  def crc32(*datas)
    crc = 0xFFFFFFFF

    datas.each do |data|
      data = [data] unless data.is_a? Array
      data.each do |byte|
        crc ^= byte
        8.times do
          flag = crc & 0x01 > 0
          crc >>= 1
          crc ^= 0xEDB88320 if flag
        end
      end
    end
    crc
  end

  private

  def choose_d(value)
    # ISO DS/DR
    # 0b000: 106kBd, 0b001: 212kBd, 0b010: 424kBd, 0b100: 848kBd
    # MFRC522 register & ISO DSI/DRI
    # 0b000: 106kBd, 0b001: 212kBd, 0b010: 424kBd, 0b011: 848kBd
    # Find largest bit(fastest baud rate)
    x = (value >> 2) & 0x01
    y = (value >> 1) & 0x01
    z = value & 0x01

    ((x | y) << 1) + (x | (~y & z))
  end

  # Gether information from ATS (Answer to Select)
  def process_ats(ats)
    position = 1
    t0 = ats[position] # Format byte

    fsci = t0 & 0x0F # PICC buffer size integer
    y1 = (t0 >> 4) & 0x07 # Optional frame(TA, TB, TC) indicator
    @fsc = FSCI_to_FSC.fetch(fsci) # Convert buffer size integer to bytes

    # Frame: TA
    if y1 & 0x01 != 0
      position += 1
      ta = ats[position]

      dr = ta & 0x07 # PCD to PICC baud rate
      ds = (ta >> 4) & 0x07 # PICC to PCD baud rate
      same_d = (ta >> 7) & 0x01

      if same_d != 0
        dr &= ds
        ds &= dr
      end

      @dri = choose_d(dr)
      @dsi = choose_d(ds)
    end

    # Frame: TB
    if y1 & 0x02 != 0
      position += 1
      tb = ats[position]

      fwi = (tb >> 4) & 0x0F # Frame wating integer
      sgfi = tb & 0x0F # Start-up frame guard integer

      # Convert integers to real time
      @fwt = (1 << fwi)
      sgft = (1 << sgfi)

      # Set frame waiting time
      @pcd.internal_timer(@fwt)
    end

    # Get info about CID or NAD
    if y1 & 0x04 != 0
      position += 1
      tc = ats[position]

      @picc_support_cid = true if tc & 0x02 != 0
      @picc_support_nad = true if tc & 0x01 != 0
    end

    # Start-up guard time
    sleep 0.000302 * sgft
  end

  def handle_wtx(data)
    24.times do
      begin
        received_data = @pcd.picc_transceive(data)
      rescue CommunicationError => e
        raise e unless e.is_a? PICCTimeoutError

        # Try sending NAK when timeout
        nak = 0xB2 | @block_number
        data = [nak]
        next
      end

      pcb = received_data[0]

      # WTX detected
      if pcb & 0xF7 == 0xF2
        inf_position = (pcb & 0x08 != 0) ? 2 : 1
        wtxm = received_data[inf_position] & 0x3F

        # Set temporary timer
        @pcd.internal_timer(@fwt * wtxm)

        # Set WTX response
        data = [0xF2, wtxm]
      else
        # Set timer back to FWT
        @pcd.internal_timer(@fwt)

        return received_data
      end
    end

    raise PICCTimeoutError, 'Timeout while handling WTX frame.'
  end
end
