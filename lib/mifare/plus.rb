module MIFARE
  class Plus < ::PICC
    CMD_WRITE_PERSO       = 0xA8
    CMD_COMMIT_PERSO      = 0xAA
    CMD_MULTI_BLOCK_READ  = 0x38
    CMD_MULTI_BLOCK_WRITE = 0xA8
    CMD_FIRST_AUTH        = 0x70
    CMD_SECOND_AUTH       = 0x72
    CMD_FOLLOWING_AUTH    = 0x76
    CMD_RESET_AUTH        = 0x78
    CMD_VC_DESELECT       = 0x48
    MF_ACK                = 0x0A

    def initialize(pcd, uid, sak)
      super
      invalid_auth
      reset_counter
    end

    def authed?
      !@transaction_identifier.empty?
    end

    def transceive(cmd: , plain_data: [], data: [], tx: nil, rx: nil)
      raise UsageError, 'Call `iso_select` before using commands' unless @iso_selected
      iso_transceive(send_data)
    end

    def auth(key_number, auth_key)
      cmd = authed? ? CMD_FOLLOWING_AUTH : CMD_FIRST_AUTH
      auth_key.padding_mode(2)

      buffer = [cmd].append_uint(key_number, 2)
      buffer << 0x00 unless authed? # No PCDCaps2 to send

      # Ask for authentication
      received_data = iso_transceive(buffer)

      # Receive challenge
      auth_key.clear_iv
      auth_key.set_iv(generate_iv(:decrypt)) if authed?
      challenge = auth_key.decrypt(received_data)
      challenge_rot = challenge.rotate

      # Generate random number and encrypt it with rotated challenge
      random_number = SecureRandom.random_bytes(received_data.size).bytes
      auth_key.clear_iv
      auth_key.set_iv(generate_iv(:encrypt)) if authed?
      response = auth_key.encrypt(random_number + challenge_rot)

      # Send challenge response
      received_data = iso_transceive([CMD_SECOND_AUTH, *response])

      # Check if verification matches rotated random_number
      auth_key.clear_iv
      auth_key.set_iv(generate_iv(:decrypt)) if authed?
      verification = auth_key.decrypt(received_data)
      @transaction_identifier = verification.shift(4)
      response_rot = verification.shift(16)

      if random_number.rotate != response_rot
        raise ReceiptIntegrityError, 'Authentication Failed'
      end

      byte_a = random_number[11..15]
      byte_b = challenge[11..15]
      byte_c = random_number[4..8]
      byte_d = challenge[4..8]
      byte_e = random_number[7..11]
      byte_f = challenge[7..11]
      byte_g = random_number[0..4]
      byte_h = challenge[0..4]
      byte_i = byte_c.xor(byte_d)
      byte_j = byte_g.xor(byte_h)

      enc_key_base = byte_a + byte_b + byte_i + [0x11]
      mac_key_base = byte_e + byte_f + byte_j + [0x22]

      auth_key.clear_iv
      auth_key.set_iv(generate_iv(:encrypt)) if authed?
      enc_key = auth_key.encrypt(enc_key_base)
      @enc_key = Key.new(:aes, enc_key)

      auth_key.clear_iv
      auth_key.set_iv(generate_iv(:encrypt)) if authed?
      mac_key = auth_key.encrypt(mac_key_base)
      @mac_key = Key.new(:aes, mac_key)

      reset_counter
    end

    protected

    def generate_iv(operation)
      buffer = [].append_uint(@read_counter, 2).append_uint(@write_counter, 2)
      buffer.concat(buffer, buffer)

      if operation == :encrypt
        buffer.unshift(@transaction_identifier)
      elsif operation == :decrypt
        buffer.concat(@transaction_identifier)
      else
        raise UsageError, 'Unknown operation mode'
      end
    end

    def generate_mac_payload
      
    end

    def reset_counter
      @session_read_counter = 0
      @read_counter = 0
      @write_counter = 0
    end

    def invalid_auth
      reset_counter
      @transaction_identifier = []
      @enc_key = nil
      @mac_key = nil
    end
  end
end