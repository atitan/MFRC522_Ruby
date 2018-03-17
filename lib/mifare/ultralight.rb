module MIFARE
  class Ultralight < ::PICC
    CMD_READ                = 0x30  # Reads 4 pages(16 bytes) from the PICC.
    CMD_FAST_READ           = 0x3A  # Reads pages within requested range
    CMD_WRITE               = 0xA2  # Writes 1 page(4 bytes) to the PICC.
    CMD_COMP_WRITE          = 0xA0
    CMD_READ_CNT            = 0x39
    CMD_INCR_CNT            = 0xA5
    CMD_PWD_AUTH            = 0x1B
    CMD_3DES_AUTH           = 0x1A  # Ultralight C 3DES Authentication.
    CMD_GET_VERSION         = 0x60
    CMD_READ_SIG            = 0x3C
    CMD_VCSL                = 0x4B
    CMD_CHECK_TEARING_EVENT = 0x3E
    MF_ACK                  = 0x0A  # Mifare Acknowledge

    CARD_VERSION = Struct.new(
      :vendor_id, :type, :subtype, :major_ver, :minor_ver, :storage_size, :protocol_type
    )

    def initialize(pcd, uid, sak)
      super
      # Set transceive timeout to 15ms
      @pcd.internal_timer(50)

      # Maximum fast read range
      @max_range = ((@pcd.buffer_size - 2) / 4).to_i

      # Check if Ultralight C
      if @model_c = support_3des_auth?
        extend UltralightC
      end

      unless @version = check_version
        if version[:major_ver] == 0x01
          extend UltralightEV1
        end
      end
    end

    def transceive(send_data)
      received_data, valid_bits = picc_transceive(send_data, false, true)
      unless valid_bits == 0
        raise UnexpectedDataError, 'Incorrect Mifare ACK format' if received_data.size != 1 || valid_bits != 4 # ACK is 4 bits long
        raise MifareNakError, "Mifare NAK detected: 0x#{received_data[0].to_bytehex}" if received_data[0] != MF_ACK
      end
      received_data
    end

    def read(block_addr)
      transceive([CMD_READ, block_addr])
    end

    def write(page, send_data)
      if send_data.size != 4
        raise UsageError, "Expect 4 bytes data, got: #{send_data.size} byte"
      end

      transceive([CMD_WRITE, page, *send_data])
    end

    def get_version
      version = transceive([CMD_GET_VERSION])

      expo = (version[6] >> 1) & 0x0F
      if version[6] & 0x01 == 0
        size = 1 << expo
      else
        size = (1 << expo) | (1 << (expo - 1))
      end

      CARD_VERSION.new(
        version[1], version[2], version[3], version[4], version[5], size, version[7]
      )
    end

    def model_c?
      @model_c
    end

    private

    def check_version
      begin
        version = get_version
      rescue CommunicationError
        restart_communication
        return nil
      end
      version
    end

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
