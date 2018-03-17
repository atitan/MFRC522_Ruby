require 'mfrc522'
require 'securerandom'

r = MFRC522.new

begin
  r.picc_request(MFRC522::PICC_REQA)
  uid, sak = r.picc_select
  puts "uid: #{uid}"
rescue CommunicationError => e
  abort "Error communicating PICC: #{e.message}"
end

c = MIFARE::Classic.new(r, uid, sak)

# auth test
if c.auth(0x04, a: 'FFFFFFFFFFFF')
  puts 'Auth test OK'
else
  raise 'Auth test Failed'
end

# data block test
rand = SecureRandom.random_bytes(16).bytes
c.write(0x04, rand)
result = c.read(0x04)
if result == rand
  puts 'Read-Write test OK'
else
  raise "Expect #{rand} on data block write test, got: #{result}"
end


# value block test
num = [0, SecureRandom.random_number(100) + 1, (SecureRandom.random_number(100) + 1) * -1]
num2 = [1, SecureRandom.random_number(1000) + 1, SecureRandom.random_number(10000) + 1]

puts "num = #{num}"
puts "num2 = #{num2}"

num.each_with_index do |x, i|
  c.write_value(0x05, x)
  if c.read_value(0x05) == x
    puts "Value Block Write test ##{i} #{x} OK"
  else
    raise "Value Block Write test ##{i} #{x} write Failed"
  end

  num2.each_with_index do |y, j|
    c.write_value(0x05, x)
    c.increment(0x05, y)
    c.transfer(0x05)

    if c.read_value(0x05) == x + y
      puts "Value Block Increment test ##{i}-##{j} #{x}+#{y} OK"
    else
      raise "Value Block Increment test ##{i}-##{j} #{x}+#{y} Failed"
    end
  end
  num2.each_with_index do |y, j|
    c.write_value(0x05, x)
    c.decrement(0x05, y)
    c.transfer(0x05)

    if c.read_value(0x05) == x - y
      puts "Value Block Decrement test ##{i}-##{j} #{x}-#{y} OK"
    else
      raise "Value Block Decrement test ##{i}-##{j} #{x}-#{y} Failed"
    end
  end
  num2.each_with_index do |y, j|
    c.write_value(0x05, x)
    c.decrement(0x05, y)
    c.restore(0x05)
    c.transfer(0x05)

    if c.read_value(0x05) == x
      puts "Value Block Restore test ##{i}-##{j} OK"
    else
      raise "Value Block Restore test ##{i}-##{j} Failed"
    end
  end
end

c.halt
