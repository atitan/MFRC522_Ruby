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

c = MIFARE::DESFire.new(r, uid, sak)
c.select

picc_mk = MIFARE::Key.new(:des, '00'*8)

des_default_key = MIFARE::Key.new(:des, '00'*8)
des2k_default_key = MIFARE::Key.new(:des, '00'*16)
des3k_default_key = MIFARE::Key.new(:des, '00'*24)
aes_default_key = MIFARE::Key.new(:aes, '00'*16)

default_key_setting = MIFARE::DESFire::KEY_SETTING.new

APP1_ID = 3000
APP2_ID = 30000
APP3_ID = 300000
APP4_ID = 16000000

app1_key0 = MIFARE::Key.new(:des, SecureRandom.hex(8))
app1_key0_1 = MIFARE::Key.new(:des, SecureRandom.hex(8))
app1_key1 = MIFARE::Key.new(:des, SecureRandom.hex(8))
app2_key0 = MIFARE::Key.new(:des, SecureRandom.hex(16))
app2_key0_1 = MIFARE::Key.new(:des, SecureRandom.hex(16))
app2_key1 = MIFARE::Key.new(:des, SecureRandom.hex(16))
app3_key0 = MIFARE::Key.new(:des, SecureRandom.hex(24))
app3_key0_1 = MIFARE::Key.new(:des, SecureRandom.hex(24))
app3_key1 = MIFARE::Key.new(:des, SecureRandom.hex(24))
app4_key0 = MIFARE::Key.new(:aes, SecureRandom.hex(16))
app4_key0_1 = MIFARE::Key.new(:aes, SecureRandom.hex(16))
app4_key1 = MIFARE::Key.new(:aes, SecureRandom.hex(16))

c.select_app(0)
puts 'Selected App:0 OK'

c.auth(0, picc_mk)
puts 'Authed with key:0 OK'

c.format_card
puts 'Format card memory OK'

puts "Get_Card_Version: #{c.get_card_version}"

c.create_app(999, MIFARE::DESFire::KEY_SETTING.new, 1, 'des-ede-cbc')
puts 'Created test app:999 for deleting test OK'

c.get_app_ids.each do |id|
  c.delete_app(id)
  puts "Deleted existing app:#{id} OK"
end

# App 1
c.create_app(APP1_ID, default_key_setting, 2, des_default_key.cipher_suite)
puts "Created app:#{APP1_ID} OK"

# App 2
c.create_app(APP2_ID, default_key_setting, 2, des2k_default_key.cipher_suite)
puts "Created app:#{APP2_ID} OK"

# App 3
c.create_app(APP3_ID, default_key_setting, 2, des3k_default_key.cipher_suite)
puts "Created app:#{APP3_ID} OK"

# App 4
c.create_app(APP4_ID, default_key_setting, 2, aes_default_key.cipher_suite)
puts "Created app:#{APP4_ID} OK"

if c.get_app_ids.size == 4
  puts '4 Apps created OK'
else
  raise 'App count incorrect'
end

## Key test
puts "###########################"
puts "#########Auth Test#########"
puts "###########################"
## App 1
c.select_app(APP1_ID)
puts "@@@@@Selected App1 OK@@@@@"

c.auth(0, des_default_key)
puts "Authed with key:0 OK"

if c.get_key_version(0) == 0
  puts 'Get key version OK'
else
  raise 'Unmatched key version'
end

app_key_setting = c.get_key_setting

if app_key_setting[:key_setting] == default_key_setting &&
   app_key_setting[:key_count] == 2 &&
   app_key_setting[:key_type] == des_default_key.cipher_suite
  puts 'Get key setting OK'
else
  raise 'Unmatched key setting'
end

key_setting = app_key_setting[:key_setting]
key_setting.file_management_without_auth = false
puts 'Remove flag file_management_without_auth from key setting'

c.change_key_setting(key_setting)
puts 'Change key setting OK'

app_key_setting = c.get_key_setting

if app_key_setting[:key_setting] == key_setting &&
   app_key_setting[:key_count] == 2 &&
   app_key_setting[:key_type] == des_default_key.cipher_suite
  puts 'Get key setting again OK'
else
  raise 'Unmatched key setting'
end

c.change_key(0, app1_key0)
puts 'Change key from default to app1_key0 OK'

c.auth(0, app1_key0)
puts 'Re-auth OK'

c.change_key(0, app1_key0_1)
puts 'Change key from app1_key0 to app1_key0_1 OK'

c.auth(0, app1_key0_1)
puts 'Re-auth OK'

puts "Get_Card_Version: #{c.get_card_version}"

c.change_key(1, app1_key1, des_default_key)
puts 'Change key 1 using key 0 OK'

c.auth(1, app1_key1)
puts 'Authenticate using key 1 OK'

## App 2
c.select_app(APP2_ID)
puts "@@@@@Selected App2 OK@@@@@"

c.auth(0, des2k_default_key)
puts "Authed with key:0 OK"

c.change_key(0, app2_key0)
puts 'Change key from default to app2_key0 OK'

c.auth(0, app2_key0)
puts 'Re-auth OK'

puts "Get_Card_Version: #{c.get_card_version}"

c.change_key(0, app2_key0_1)
puts 'Change key from app2_key0 to app2_key0_1 OK'

c.auth(0, app2_key0_1)
puts 'Re-auth OK'

## App 3
c.select_app(APP3_ID)
puts "@@@@@Selected App3 OK@@@@@"

c.auth(0, des3k_default_key)
puts "Authed with key:0 OK"

c.change_key(0, app3_key0)
puts 'Change key from default to app3_key0 OK'

c.auth(0, app3_key0)
puts 'Re-auth OK'

c.change_key(0, app3_key0_1)
puts 'Change key from app3_key0 to app3_key0_1 OK'

c.auth(0, app3_key0_1)
puts 'Re-auth OK'

puts "Get_Card_Version: #{c.get_card_version}"

c.change_key(1, app3_key1, des3k_default_key)
puts 'Change key 1 using key 0 OK'

c.auth(1, app3_key1)
puts 'Authenticate using key 1 OK'

## App 4
c.select_app(APP4_ID)
puts "@@@@@Selected App4 OK@@@@@"

c.auth(0, aes_default_key)
puts "Authed with key:0 OK"

c.change_key(0, app4_key0)
puts 'Change key from default to app4_key0 OK'

c.auth(0, app4_key0)
puts 'Re-auth OK'

c.change_key(0, app4_key0_1)
puts 'Change key from app4_key0 to app4_key0_1 OK'

c.auth(0, app4_key0_1)
puts 'Re-auth OK'

puts "Get_Card_Version: #{c.get_card_version}"

c.change_key(1, app4_key1, aes_default_key)
puts 'Change key 1 using key 0 OK'

c.auth(1, app4_key1)
puts 'Authenticate using key 1 OK'

c.get_card_version

## File test
puts "###########################"
puts "#########File Test#########"
puts "###########################"
file_setting = MIFARE::DESFire::FILE_SETTING.new
file_setting.permission = MIFARE::DESFire::FILE_PERMISSION.new(0,0,0,0)
# Data file only
file_setting.size = 150
# Value file only
file_setting.lower_limit = -16000000
file_setting.upper_limit = 16000000
file_setting.limited_credit_value = -3000
file_setting.limited_credit = 0
# Record file only
file_setting.record_size = 20
file_setting.max_record_number = 3

# App 1
c.select_app(APP1_ID)
puts "@@@@@Selected App1 OK@@@@@"

c.auth(0, app1_key0_1)
puts "Authed with key:0 OK"

file_setting.type = :std_data_file
file_setting.communication = :plain
c.create_file(1, file_setting)
puts "Created std_data_file with plain OK"

data = SecureRandom.random_bytes(150).bytes
c.write_data(1, 0, data)
if c.read_data(1, 0, 0) == data
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

file_setting.type = :backup_data_file
file_setting.communication = :mac
c.create_file(2, file_setting)
puts "Created backup_data_file with mac OK"

data = SecureRandom.random_bytes(150).bytes
c.write_data(2, 0, data)
c.commit_transaction
if c.read_data(2, 0, 0) == data
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

file_setting.type = :value_file
file_setting.communication = :encrypt
c.create_file(3, file_setting)
puts "Created value_file with encrypt OK"

data = SecureRandom.random_number(1000000) + 1
data2 = SecureRandom.random_number(1000000) + 1
value = c.read_value(3)
c.credit_value(3, data)
c.commit_transaction
if c.read_value(3) == value + data
  puts "Credit test OK"
else
  raise "Credit test Failed"
end

value = c.read_value(3)
c.debit_value(3, data2)
c.commit_transaction
if c.read_value(3) == value - data2
  puts "Debit test OK"
else
  raise "Debit test Failed"
end

file_setting.type = :cyclic_record_file
file_setting.communication = :plain
c.create_file(4, file_setting)
puts "Created cyclic_record_file with plain OK"

data = SecureRandom.random_bytes(20).bytes
data2 = SecureRandom.random_bytes(20).bytes
c.write_record(4, 0, data)
c.commit_transaction
c.write_record(4, 0, data2)
c.commit_transaction
if c.read_records(4, 1, 1) == data && c.read_records(4, 0, 1) == data2
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

# App 2
c.select_app(APP2_ID)
puts "@@@@@Selected App2 OK@@@@@"

c.auth(0, app2_key0_1)
puts "Authed with key:0 OK"

file_setting.type = :std_data_file
file_setting.communication = :mac
c.create_file(1, file_setting)
puts "Created std_data_file with mac OK"

data = SecureRandom.random_bytes(150).bytes
c.write_data(1, 0, data)
if c.read_data(1, 0, 0) == data
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

file_setting.type = :backup_data_file
file_setting.communication = :encrypt
c.create_file(2, file_setting)
puts "Created backup_data_file with encrypt OK"

data = SecureRandom.random_bytes(150).bytes
c.write_data(2, 0, data)
c.commit_transaction
if c.read_data(2, 0, 0) == data
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

file_setting.type = :linear_record_file
file_setting.communication = :plain
c.create_file(3, file_setting)
puts "Created linear_record_file with plain OK"

data = SecureRandom.random_bytes(20).bytes
data2 = SecureRandom.random_bytes(20).bytes
c.write_record(3, 0, data)
c.commit_transaction
c.write_record(3, 0, data2)
c.commit_transaction
if c.read_records(3, 1, 1) == data && c.read_records(3, 0, 1) == data2
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

file_setting.type = :cyclic_record_file
file_setting.communication = :mac
c.create_file(4, file_setting)
puts "Created cyclic_record_file with mac OK"

data = SecureRandom.random_bytes(20).bytes
data2 = SecureRandom.random_bytes(20).bytes
c.write_record(4, 0, data)
c.commit_transaction
c.write_record(4, 0, data2)
c.commit_transaction
if c.read_records(4, 1, 1) == data && c.read_records(4, 0, 1) == data2
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

# App 3
c.select_app(APP3_ID)
puts "@@@@@Selected App3 OK@@@@@"

c.auth(0, app3_key0_1)
puts "Authed with key:0 OK"

file_setting.type = :std_data_file
file_setting.communication = :encrypt
c.create_file(1, file_setting)
puts "Created std_data_file with encrypt OK"

data = SecureRandom.random_bytes(150).bytes
c.write_data(1, 0, data)
if c.read_data(1, 0, 0) == data
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

file_setting.type = :value_file
file_setting.communication = :plain
c.create_file(2, file_setting)
puts "Created value_file with plain OK"

data = SecureRandom.random_number(1000000) + 1
data2 = SecureRandom.random_number(1000000) + 1
value = c.read_value(2)
c.credit_value(2, data)
c.commit_transaction
if c.read_value(2) == value + data
  puts "Credit test OK"
else
  raise "Credit test Failed"
end

value = c.read_value(2)
c.debit_value(2, data2)
c.commit_transaction
if c.read_value(2) == value - data2
  puts "Debit test OK"
else
  raise "Debit test Failed"
end

file_setting.type = :linear_record_file
file_setting.communication = :mac
c.create_file(3, file_setting)
puts "Created linear_record_file with mac OK"

data = SecureRandom.random_bytes(20).bytes
data2 = SecureRandom.random_bytes(20).bytes
c.write_record(3, 0, data)
c.commit_transaction
c.write_record(3, 0, data2)
c.commit_transaction
if c.read_records(3, 1, 1) == data && c.read_records(3, 0, 1) == data2
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

file_setting.type = :cyclic_record_file
file_setting.communication = :encrypt
c.create_file(4, file_setting)
puts "Created cyclic_record_file with encrypt OK"

data = SecureRandom.random_bytes(20).bytes
data2 = SecureRandom.random_bytes(20).bytes
c.write_record(4, 0, data)
c.commit_transaction
c.write_record(4, 0, data2)
c.commit_transaction
if c.read_records(4, 1, 1) == data && c.read_records(4, 0, 1) == data2
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

# App 4
c.select_app(APP4_ID)
puts "@@@@@Selected App4 OK@@@@@"

c.auth(0, app4_key0_1)
puts "Authed with key:0 OK"

file_setting.type = :backup_data_file
file_setting.communication = :plain
c.create_file(1, file_setting)
puts "Created backup_data_file with plain OK"

data = SecureRandom.random_bytes(150).bytes
c.write_data(1, 0, data)
c.commit_transaction
if c.read_data(1, 0, 0) == data
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

file_setting.type = :value_file
file_setting.communication = :mac
c.create_file(2, file_setting)
puts "Created value_file with mac OK"

data = SecureRandom.random_number(1000000) + 1
data2 = SecureRandom.random_number(1000000) + 1
value = c.read_value(2)
c.credit_value(2, data)
c.commit_transaction
if c.read_value(2) == value + data
  puts "Credit test OK"
else
  raise "Credit test Failed"
end

value = c.read_value(2)
c.debit_value(2, data2)
c.commit_transaction
if c.read_value(2) == value - data2
  puts "Debit test OK"
else
  raise "Debit test Failed"
end

file_setting.type = :linear_record_file
file_setting.communication = :encrypt
c.create_file(3, file_setting)
puts "Created linear_record_file with encrypt OK"

data = SecureRandom.random_bytes(20).bytes
data2 = SecureRandom.random_bytes(20).bytes
c.write_record(3, 0, data)
c.commit_transaction
c.write_record(3, 0, data2)
c.abort_transaction
if c.read_records(3, 0, 1) == data
  puts "Abort transaction test OK"
else
  raise "Abort transaction test Failed"
end

c.write_record(3, 0, data2)
c.commit_transaction
if c.read_records(3, 1, 1) == data && c.read_records(3, 0, 1) == data2
  puts "Read-Write test OK"
else
  raise "Read-Write test Failed"
end

file_setting.communication = :plain
c.change_file_setting(3, file_setting)
if c.get_file_setting(3).communication == :plain
  puts "Change file setting test OK"
else
  raise "Change file setting test Failed"
end

## Finish test
puts "###########################"
puts "#########Clean up##########"
puts "###########################"

c.select_app(0)
puts 'Selected App:0 OK'

c.auth(0, picc_mk)
puts 'Authed with key:0 OK'

c.format_card
puts 'Format card memory OK'

if c.get_app_ids.empty?
  puts 'Apps has been purged OK'
else
  raise 'App still exists after formatting'
end

c.deselect
c.halt
