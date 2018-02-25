module Mifare
  class Ultralight < ::PICC
    CMD_READ        = 0x30  # Reads 4 pages(16 bytes) from the PICC.
    CMD_WRITE       = 0xA2  # Writes 1 page(4 bytes) to the PICC.
    CMD_3DES_AUTH   = 0x1A  # Ultralight C 3DES Authentication.

    def initialize(pcd, uid, sak)
      super

      # Check if Ultralight C
      if @model_c = support_3des_auth?
        extend UltralightC
      end
    end

    def transceive(send_data, accept_timeout)
      picc_transceive(send_data, accept_timeout)
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
