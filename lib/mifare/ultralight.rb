module Mifare
  class Ultralight < ::PICC
    CMD_READ        = 0x30  # Reads 4 pages(16 bytes) from the PICC.
    CMD_WRITE       = 0xA2  # Writes 1 page(4 bytes) to the PICC.
    CMD_3DES_AUTH   = 0x1A  # Ultralight C 3DES Authentication.
    MF_ACK          = 0x0A  # Mifare Acknowledge

    def initialize(pcd, uid, sak)
      super
      # Set transceive timeout to 15ms
      @pcd.internal_timer(50)

      # Check if Ultralight C
      if @model_c = support_3des_auth?
        extend UltralightC
      end
    end

    def transceive(send_data)
      received_data, valid_bits = picc_transceive(send_data, false, true)
      unless valid_bits.nil?
        raise UnexpectedDataError, 'Incorrect Mifare ACK format' if received_data.size != 1 || valid_bits != 4 # ACK is 4 bits long
        raise MifareNakError, "Mifare NAK detected: 0x#{received_data[0].to_bytehex}" if received_data[0] != MF_ACK
      end
      received_data
    end

    def read(block_addr)
      buffer = [CMD_READ, block_addr]

      transceive(buffer)
    end

    def write(page, send_data)
      if send_data.size != 4
        raise UsageError, "Expect 4 bytes data, got: #{send_data.size} byte"
      end

      buffer = [CMD_WRITE, page]
      buffer.concat(send_data)

      transceive(buffer)
    end

    def model_c?
      @model_c
    end

    private

    # Check if PICC support Ultralight 3DES command
    def support_3des_auth?
      # Ask for authentication
      buffer = [CMD_3DES_AUTH, 0x00]

      begin
        transceive(buffer)
        result = true
      rescue CommunicationError
        result = false
      end

      restart_communication
      result
    end
  end
end
