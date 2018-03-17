module MIFARE
  module UltralightC
    def auth(auth_key)
      if auth_key.cipher_suite != 'des-ede-cbc'
        raise UsageError, 'Incorrect Auth Key Type'
      end

      auth_key.clear_iv
      auth_key.padding_mode(1)

      # Ask for authentication
      buffer = [CMD_3DES_AUTH, 0x00]
      received_data = transceive(buffer)
      card_status = received_data.shift
      raise UnexpectedDataError, 'Auth failed: stage 1' if card_status != 0xAF

      challenge = auth_key.decrypt(received_data)
      challenge_rot = challenge.rotate

      # Generate 8 bytes random number and encrypt it with rotated challenge
      random_number = SecureRandom.random_bytes(8).bytes
      response = auth_key.encrypt(random_number + challenge_rot)

      # Send challenge response
      buffer = [0xAF] + response
      received_data = transceive(buffer)
      card_status = received_data.shift
      raise UnexpectedDataError, 'Auth failed: stage 2' if card_status != 0x00

      # Check if verification matches rotated random_number
      verification = auth_key.decrypt(received_data)

      if random_number.rotate != verification
        restart_communication
        return @authed = false
      end

      @authed = true
    end

    def authed?
      @authed || false
    end

    def write_des_key(key)
      # key should be 16 bytes long
      bytes = [key].pack('H*').bytes
      if bytes.size != 16
        raise UsageError, "Expect 16 bytes 3DES key, got: #{bytes.size} byte"
      end

      # Key1
      write(0x2C, bytes[4..7].reverse)
      write(0x2D, bytes[0..3].reverse)
      # Key2
      write(0x2E, bytes[12..15].reverse)
      write(0x2F, bytes[8..11].reverse)
    end

    def counter_increment(value)
      if value < 0
        raise UsageError, 'Expect positive integer for counter'
      end
      # you can set any value between 0x0000 to 0xFFFF on the first write (initialize)
      # after initialized, counter can only be incremented by 0x01 ~ 0x0F
      write(0x29, [value & 0xFF, (value >> 8) & 0xFF, 0x00, 0x00])
    end

    def enable_protection_from(block_addr)
      if block_addr < 0x03 || block_addr > 0x30
        raise UsageError, 'Requested block beyond memory limit'
      end
      # authentication will be required from `block_addr` to 0x2F
      # valid value are from 0x03 to 0x30
      # set to 0x30 to disable memory protection
      write(0x2A, [block_addr & 0x3F, 0x00, 0x00, 0x00])
    end

    def set_protection_type(type)
      # set to 0 for read-write access restriction (default)
      # set to 1 for write access restriction
      write(0x2B, [type & 0x01, 0x00, 0x00, 0x00])
    end
  end
end
