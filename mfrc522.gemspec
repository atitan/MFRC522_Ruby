Gem::Specification.new do |s|
  s.name        = 'mfrc522'
  s.version     = '3.0.0'
  s.date        = '2021-05-31'
  s.summary     = 'MFRC522 RFID Reader Library for RaspberryPi'
  s.authors     = ['atitan']
  s.email       = 'commit@atifans.net'
  s.files       = Dir['lib/*.rb'] + Dir['lib/mifare/*.rb']
  s.homepage    = 'https://github.com/atitan/MFRC522_Ruby'
  s.license     = 'MIT'

  s.add_runtime_dependency 'fubuki', '1.0.1'
end
