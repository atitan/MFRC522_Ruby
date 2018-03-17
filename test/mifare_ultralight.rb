require 'mfrc522'
require 'securerandom'

r = MFRC522.new

begin
  r.picc_request(MFRC522::PICC_REQA)
  uid, sak = r.picc_select
rescue CommunicationError => e
  abort "Error communicating PICC: #{e.message}"
end

c = MIFARE::Ultralight.new(r, uid, sak)

rand = SecureRandom.random_bytes(4).bytes
c.write(0x0A, rand)

if c.read(0x0A)[0..3] == rand
  puts 'Read-Write test OK'
else
  raise 'Read-Write test Failed'
end

# Check if Ultralight C
if c.model_c?
  hex = SecureRandom.hex(16)

  puts "Using this key for testing: #{hex}"

  c.write_des_key(hex)

  c.restart_communication

  k = MIFARE::Key.new(:des, hex)
  c.auth(k)

  if c.authed?
    puts 'Auth test OK'
  else
    raise 'Auth test Failed'
  end
end

c.halt
