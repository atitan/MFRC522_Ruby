class ISO144434 < PICC
  FSCI_to_FSC = [16, 24, 32, 40, 48, 64, 96, 128, 256]

  CMD_RATS              = 0xE0
  CMD_PPS               = 0xD0
  CMD_DESELECT          = 0xC2
  CMD_SUCCESS           = 0x00
  CMD_ADDITIONAL_FRAME  = 0xAF

  def initialize(pcd, uid, sak)
    super

    @cid = 0x00 # We don't support CID
    @fsc = 16 # Assume PICC only supports 16 bytes frame
    @fwt = 256 # 77.33ms(256 ticks) default frame waiting time

    @support_cid = false
    @support_nad = false
    @block_number = 0
    @selected = false
  end

  # ISO/IEC 14443-4 select
  def select
    # Send RATS (Request for Answer To Select)
    buffer = [CMD_RATS, 0x50 | @cid]
    received_data = @pcd.picc_transceive(buffer)

    dr, ds = process_ats(received_data)

    # Send PPS (Protocol and Parameter Selection Request)
    buffer = [CMD_PPS | @cid, 0x11, (ds << 2) | dr]
    received_data = @pcd.picc_transceive(buffer)
    raise UnexpectedDataError, 'Incorrect response' if received_data[0] != (0xD0 | @cid)

    # Set PCD baud rate
    @pcd.transceiver_baud_rate(:tx, dr)
    @pcd.transceiver_baud_rate(:rx, ds)

    @block_number = 0
    @max_frame_size = [64, @fsc].min
    @max_inf_size = @max_frame_size - 3 # PCB + CRC16
    @max_inf_size -= 1 if @support_cid
    @max_inf_size -= 1 if @support_nad
    @selected = true
  end

  # Send S(DESELECT)
  def deselect
    buffer = [CMD_DESELECT]
    received_data = @pcd.picc_transceive(buffer)

    if received_data[0] & 0xF7 == CMD_DESELECT
      @selected = false
      true
    else
      false
    end
  end

  # Wrapper for handling ISO protocol
  def transceive(send_data)
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

  def resume_communication
    deselect rescue nil
    super
  end

  def halt
    deselect rescue nil
    super
  end

  private

  def convert_iso_baud_rate_to_pcd_setting(value)
    # ISO
    # 0b000: 106kBd, 0b001: 212kBd, 0b010: 424kBd, 0b100: 848kBd
    # MFRC522 register
    # 0b000: 106kBd, 0b001: 212kBd, 0b010: 424kBd, 0b011: 848kBd
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
    @fsc = FSCI_to_FSC[fsci] # Convert buffer size integer to bytes
    dr = 0 # default baud rate 106kBd
    ds = 0

    # Frame: TA
    if y1 & 0x01 != 0
      position += 1
      ta = ats[position]

      dr = ta & 0x07 # PCD to PICC baud rate
      ds = (ta >> 4) & 0x07 # PICC to PCD baud rate

      # Convert fastest baud rate to PCD setting
      dr = convert_iso_baud_rate_to_pcd_setting(dr)
      ds = convert_iso_baud_rate_to_pcd_setting(ds)

      dr = 0
      ds = 0
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

      @support_cid = true if tc & 0x02 != 0
      @support_nad = true if tc & 0x01 != 0
    end

    # Start-up guard time
    sleep 0.000302 * sgft

    return dr, ds
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

    raise PICCTimeoutError
  end
end
