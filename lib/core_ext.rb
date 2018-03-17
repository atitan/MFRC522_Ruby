class Array
  def append_uint(number, byte)
    raise 'Only support unsigned integer' if number < 0
    raise 'Insufficient bytes' if number.abs >= (1 << (byte * 8))

    until byte == 0
      self << (number & 0xFF)
      number >>= 8
      byte -= 1
    end
    self
  end

  def to_uint
    int = 0
    self.each_with_index do |byte, index|
      int |= (byte << (index * 8))
    end
    int
  end

  def append_sint(number, byte)
    raise 'Insufficient bytes' if number.abs >= (1 << (byte * 8))

    sign = (number < 0) ? 1 : 0
    number &= (1 << ((byte * 8) - 1)) - 1
    self.append_uint(number, byte)
    self << (self.pop | (sign << 7))
  end

  def to_sint
    sign = (self.last & 0x80 != 0) ? (-1 ^ ((1 << ((self.size * 8) - 1)) - 1)) : 0
    sign | self.to_uint
  end

  def append_crc16
    append_uint(crc16, 2)
  end

  def check_crc16(remove_after_check = false)
    orig_crc = pop(2)
    old_crc = (orig_crc[1] << 8) + orig_crc[0]
    new_crc = crc16
    concat(orig_crc) unless remove_after_check
    old_crc == new_crc
  end

  def xor(array2)
    zip(array2).map{|x, y| x ^ y }
  end

  private

  def crc16
    crc = 0x6363
    self.each do |byte|
      bb = (byte ^ crc) & 0xFF
      bb = (bb ^ (bb << 4)) & 0xFF
      crc = (crc >> 8) ^ (bb << 8) ^ (bb << 3) ^ (bb >> 4)
    end
    crc & 0xFFFF
  end
end

class Numeric
  def to_bytehex
    self.to_s(16).rjust(2, '0').upcase
  end
end
