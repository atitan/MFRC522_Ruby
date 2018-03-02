module MIFARE
  module UltralightEV1
    def auth(passwd)
      passwd_bytes = [passwd].pack('H*').bytes
      if passwd_bytes.size != 4
        raise UsageError, "Expect 4 bytes password in hex, got: #{passwd_bytes.size} byte"
      end

      transceive([CMD_PWD_AUTH, *passwd_bytes])
    end

    def authed?
      @authed || false
    end

    def fast_read(from, to)
      if (to - from + 1) > @max_range
        raise UsageError, "Reading from #{from} to #{to} exceeds PCD receive buffer"
      end

      transceive([CMD_FAST_READ, from, to])
    end

    def read_counter(counter)
      transceive([CMD_READ_CNT, counter])
    end

    def increment_counter(counter)
      transceive([CMD_INCR_CNT, counter])
    end

    def counter_torn?(counter)
      transceive([CMD_CHECK_TEARING_EVENT, counter]) != 0xBD
    end

    def read_signature
      transceive([CMD_READ_SIG, 0x00])
    end
  end
end
