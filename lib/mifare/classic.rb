module Mifare
  class Classic < ::PICC
    CMD_AUTH_KEY_A  = 0x60  # Perform authentication with Key A
    CMD_AUTH_KEY_B  = 0x61  # Perform authentication with Key B
    CMD_READ        = 0x30  # Reads one 16 byte block from the authenticated sector of the PICC.
    CMD_WRITE       = 0xA0  # Writes one 16 byte block to the authenticated sector of the PICC.
    CMD_DECREMENT   = 0xC0  # Decrements the contents of a block and stores the result in the internal data register.
    CMD_INCREMENT   = 0xC1  # Increments the contents of a block and stores the result in the internal data register.
    CMD_RESTORE     = 0xC2  # Reads the contents of a block into the internal data register.
    CMD_TRANSFER    = 0xB0  # Writes the contents of the internal data register to a block.
    MF_ACK          = 0x0A  # Mifare Acknowledge

    def initialize(pcd, uid, sak)
      super
      # Set transceive timeout to 15ms
      @pcd.internal_timer(50)
    end

    def transceive(send_data, accept_timeout = false)
      received_data, valid_bits = picc_transceive(send_data, accept_timeout, true)
      unless valid_bits.nil?
        raise UnexpectedDataError, 'Incorrect Mifare ACK format' if received_data.size != 1 || valid_bits != 4 # ACK is 4 bits long
        raise MifareNakError, "Mifare NAK detected: 0x#{received_data[0].to_bytehex}" if received_data[0] != MF_ACK
      end
      received_data
    end

    def auth(block_addr, key = {})
      if key[:a].nil? && key[:b].nil?
        raise UsageError, 'Missing key data'
      end

      if key[:a]
        cmd = CMD_AUTH_KEY_A
        key = key[:a]
      else
        cmd = CMD_AUTH_KEY_B
        key = key[:b]
      end

      key = [key].pack('H*').bytes
      if key.size != 6
        raise UsageError, "Expect 6 bytes auth key, got: #{key.size} byte"
      end

      @pcd.mifare_crypto1_authenticate(cmd, block_addr, key, @uid)
    end

    def deauth
      @pcd.mifare_crypto1_deauthenticate
    end

    def read(block_addr)
      buffer = [CMD_READ, block_addr]

      transceive(buffer)
    end

    def write(block_addr, send_data)
      if send_data.size != 16
        raise UsageError, "Expect 16 bytes data, got: #{send_data.size} byte"
      end

      buffer = [CMD_WRITE, block_addr]

      # Ask PICC if we can write to block_addr
      transceive(buffer)

      # Then start transfer our data
      transceive(send_data)
    end

    def read_value(block_addr)
      received_data = read(block_addr)

      received_data[0..3].to_sint
    end

    def write_value(block_addr, value)
      # Value block format
      #
      # byte 0..3:   32 bit value in little endian
      # byte 4..7:   copy of byte 0..3, with inverted bits (aka. XOR 255)
      # byte 8..11:  copy of byte 0..3
      # byte 12:     index of backup block (can be any value)
      # byte 13:     copy of byte 12 with inverted bits (aka. XOR 255)
      # byte 14:     copy of byte 12
      # byte 15:     copy of byte 13
      value = [].append_sint(value, 4)

      buffer = []
      buffer[0]  = value[0]
      buffer[1]  = value[1]
      buffer[2]  = value[2]
      buffer[3]  = value[3]
      buffer[4]  = ~buffer[0]
      buffer[5]  = ~buffer[1]
      buffer[6]  = ~buffer[2]
      buffer[7]  = ~buffer[3]
      buffer[8]  = buffer[0]
      buffer[9]  = buffer[1]
      buffer[10] = buffer[2]
      buffer[11] = buffer[3]
      buffer[12] = block_addr
      buffer[13] = ~block_addr
      buffer[14] = buffer[12]
      buffer[15] = buffer[13]
    
      write(block_addr, buffer)
    end

    # Increment: Increments the contents of a block and stores the result in the internal Transfer Buffer
    def increment(block_addr, delta)
      two_step(CMD_INCREMENT, block_addr, delta)
    end

    # Decrement: Decrements the contents of a block and stores the result in the internal Transfer Buffer
    def decrement(block_addr, delta)
      two_step(CMD_DECREMENT, block_addr, delta)
    end

    # Restore: Moves the contents of a block into the internal Transfer Buffer
    def restore(block_addr)
      two_step(CMD_RESTORE, block_addr, 0)
    end

    # Transfer: Writes the contents of the internal Transfer Buffer to a value block
    def transfer(block_addr)
      buffer = [CMD_TRANSFER, block_addr]

      transceive(buffer)
    end

    private

    # Helper for increment, decrement, and restore command
    def two_step(command, block_addr, value)
      buffer = [command, block_addr]
      send_data = [].append_uint(value, 4)

      # Ask PICC if we can write to block_addr
      transceive(buffer)

      # Then start transfer our data
      transceive(send_data, true) # Accept timeout
    end
  end
end
