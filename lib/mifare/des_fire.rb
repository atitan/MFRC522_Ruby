module MIFARE
  class DESFire < ::PICC
    # Security Related Commands
    CMD_DES_AUTH                  = 0x1A # Authenticate with DES, 2K3DES, 3K3DES key
    CMD_AES_AUTH                  = 0xAA # Authenticate with AES-128 key
    CMD_GET_KEY_SETTING           = 0x45 # Gets information on the PICC and application master key settings. In addition it returns the maximum number of keys which can be stored within the selected application.
    CMD_CHANGE_KEY_SETTING        = 0x54 # Changes the master key settings on PICC and application level.
    CMD_GET_KEY_VERSION           = 0x64 # Reads out the current key version of any key stored on the PICC.
    CMD_CHANGE_KEY                = 0xC4 # Changes any key stored on the PICC.
    CMD_SET_CONFIGURATION         = 0x5C # Configures and pre-personalizes the card with app default key, UID, and ATS string setup

    # PICC Level Commands
    CMD_CREATE_APP                = 0xCA # Creates new applications on the PICC.
    CMD_DELETE_APP                = 0xDA # Permanently deactivates applications on the PICC.
    CMD_GET_APP_IDS               = 0x6A # Returns the Application IDentifiers of all applications on a PICC.
    CMD_SELECT_APP                = 0x5A # Selects one specific application for further access.
    CMD_FREE_MEMORY               = 0x6E # Returns the free memory available on the card
    CMD_GET_DF_NAMES              = 0x6D # Returns the DF names
    CMD_GET_CARD_VERSION          = 0x60 # Returns manufacturing related data of the PICC.
    CMD_FORMAT_CARD               = 0xFC # Releases the PICC user memory.
    CMD_GET_CARD_UID              = 0x51 # Returns the UID

    # Application Level Commands
    CMD_GET_FILE_IDS              = 0x6F # Returns the File IDentifiers of all active files within the currently selected application.
    CMD_GET_FILE_SETTING          = 0xF5 # Get information on the properties of a specific file.
    CMD_CHANGE_FILE_SETTING       = 0x5F # Changes the access parameters of an existing file.
    CMD_CREATE_STD_DATA_FILE      = 0xCD # Creates files for the storage of plain unformatted user data within an existing application on the PICC.
    CMD_CREATE_BACKUP_DATA_FILE   = 0xCB # Creates files for the storage of plain unformatted user data within an existing application on the PICC, additionally supporting the feature of an integrated backup mechanism.
    CMD_CREATE_VALUE_FILE         = 0xCC # Creates files for the storage and manipulation of 32bit signed integer values within an existing application on the PICC.
    CMD_CREATE_LINEAR_RECORD_FILE = 0xC1 # Creates files for multiple storage of structural similar data, for example for loyalty programs, within an existing application on the PICC. Once the file is filled completely with data records, further writing to the file is not possible unless it is cleared.
    CMD_CREATE_CYCLIC_RECORD_FILE = 0xC0 # Creates files for multiple storage of structural similar data within an existing application on the PICC. Once the file is filled completely with data records, the PICC automatically overwrites the oldest record with the latest written one.
    CMD_DELETE_FILE               = 0xDF # Permanently deactivates a file within the file directory of the currently selected application.

    # Data Manipulation Commands
    CMD_READ_DATA                 = 0xBD # Reads data from Standard Data Files or Backup Data Files.
    CMD_WRITE_DATA                = 0x3D # Writes data to Standard Data Files or Backup Data Files.
    CMD_GET_VALUE                 = 0x6C # Reads the currently stored value from Value Files.
    CMD_CREDIT                    = 0x0C # Increases a value stored in a Value File.
    CMD_DEBIT                     = 0xDC # Decreases a value stored in a Value File.
    CMD_LIMITED_CREDIT            = 0x1C # Allows a limited increase of a value stored in a Value File without having full Credit permissions to the file.
    CMD_WRITE_RECORD              = 0x3B # Writes data to a record in a Cyclic or Linear Record File.
    CMD_READ_RECORDS              = 0xBB # Reads out a set of complete records from a Cyclic or Linear Record File.
    CMD_CLEAR_RECORD_FILE         = 0xEB # Resets a Cyclic or Linear Record File to empty state.
    CMD_COMMIT_TRANSACTION        = 0xC7 # Validates all previous write access’ on Backup Data Files, Value Files and Record Files within one application.
    CMD_ABORT_TRANSACTION         = 0xA7 # Invalidates all previous write access’ on Backup Data Files, Value Files and Record Files within one application.

    # Status code returned by DESFire
    ST_SUCCESS                    = 0x00
    ST_NO_CHANGES                 = 0x0C
    ST_OUT_OF_MEMORY              = 0x0E
    ST_ILLEGAL_COMMAND            = 0x1C
    ST_INTEGRITY_ERROR            = 0x1E
    ST_KEY_NOT_EXIST              = 0x40
    ST_WRONG_COMMAND_LEN          = 0x7E
    ST_PERMISSION_DENIED          = 0x9D
    ST_INCORRECT_PARAM            = 0x9E
    ST_APP_NOT_FOUND              = 0xA0
    ST_APPL_INTEGRITY_ERROR       = 0xA1
    ST_AUTHENTICATION_ERROR       = 0xAE
    ST_ADDITIONAL_FRAME           = 0xAF
    ST_BOUNDARY_ERROR             = 0xBE
    ST_PICC_INTEGRITY_ERROR       = 0xC1
    ST_COMMAND_ABORTED            = 0xCA
    ST_PICC_DISABLED_ERROR        = 0xCD
    ST_COUNT_ERROR                = 0xCE
    ST_DUPLICATE_ERROR            = 0xDE
    ST_EEPROM_ERROR               = 0xEE
    ST_FILE_NOT_FOUND             = 0xF0
    ST_FILE_INTEGRITY_ERROR       = 0xF1

    KEY_TYPE = {'des-ede-cbc' => 0x00, 'des-ede3-cbc' => 0x40, 'aes-128-cbc' => 0x80}

    KEY_SETTING = Struct.new(
      # Key number required for `change_key`
      # 0x00 means only master key is accepted
      # 0x01~0x0D chooses an app key to change any key
      # 0x0E means keys can only change themselves
      # 0x0F freezes all keys, except master key
      # to freeze master key, use :masterkey_changeable
      :privileged_key,
      # Set if master key can be modified
      :masterkey_changeable,
      # Set if file management requires auth
      :file_management_without_auth,
      # Set if file configuration requires auth
      :file_configurable_without_auth,
      # Set if this setting can be modified
      :key_setting_changeable) do
      def initialize(*)
        super
        self.privileged_key = 0 if self.privileged_key.nil?
        self.masterkey_changeable = true if self.masterkey_changeable.nil?
        self.file_management_without_auth = true if self.file_management_without_auth.nil?
        self.file_configurable_without_auth = true if self.file_configurable_without_auth.nil?
        self.key_setting_changeable = true if self.key_setting_changeable.nil?
      end

      def self.import(byte)
        self.new(
          (byte >> 4) & 0x0F,
          byte & 0x01 != 0,
          byte & 0x02 != 0,
          byte & 0x04 != 0,
          byte & 0x08 != 0
        )
      end

      def export
        output = (self.privileged_key << 4)
        output |= 0x01 if self.masterkey_changeable
        output |= 0x02 if self.file_management_without_auth
        output |= 0x04 if self.file_configurable_without_auth
        output |= 0x08 if self.key_setting_changeable
        output
      end
    end

    FILE_TYPE = {
      std_data_file: 0x00, backup_data_file: 0x01, value_file: 0x02,
      linear_record_file: 0x03, cyclic_record_file: 0x04
    }

    FILE_COMMUNICATION = {plain: 0x00, mac: 0x01, encrypt: 0x03}

    # value 0x00 ~ 0x0D are key numbers, 0x0E grants free access, 0x0F always denies access
    FILE_PERMISSION = Struct.new(:read_access, :write_access, :read_write_access, :change_access) do
      def self.import(byte)
        self.new(
          (byte >> 12) & 0x0F,
          (byte >> 8) & 0x0F,
          (byte >> 4) & 0x0F,
          byte & 0x0F
        )
      end

      def export
        (read_access << 12) | (write_access << 8) | (read_write_access << 4) | change_access
      end
    end

    FILE_SETTING = Struct.new(
      :type,
      :communication,
      :permission,
      # Data file only
      :size,
      # Value file only
      :lower_limit,
      :upper_limit,
      :limited_credit_value,
      :limited_credit,
      # Record file only
      :record_size,
      :max_record_number,
      :current_record_number
    )

    CARD_VERSION = Struct.new(
      :hw_vendor, :hw_type, :hw_subtype, :hw_major_ver, :hw_minor_ver, :hw_storage_size, :hw_protocol,
      :sw_vendor, :sw_type, :sw_subtype, :sw_major_ver, :sw_minor_ver, :sw_storage_size, :sw_protocol,
      :uid, :batch_number, :production_week, :production_year
    )

    attr_reader :selected_app

    def initialize(pcd, uid, sak)
      super
      invalid_auth
      @selected_app = false
    end

    def authed?
      @authed.is_a? Numeric
    end

    def select
      iso_select
    end

    def deselect
      invalid_auth
      iso_deselect
    end

    def transceive(cmd: , plain_data: [], data: [], tx: nil, rx: nil, expect: nil, return_data: nil, receive_length: nil, encrypt_padding: nil)
      # Session key is needed for encryption
      if (tx == :encrypt || rx == :encrypt) && !@authed
        raise UnauthenticatedError
      end

      # Separate objects and be compatable with single byte input
      plain_data = plain_data.is_a?(Array) ? plain_data.dup : [plain_data]
      data = data.is_a?(Array) ? data.dup : [data]

      buffer = [cmd] + plain_data

      if @authed
        @session_key.padding_mode(encrypt_padding || 1)
      end

      if tx == :encrypt
        # Calculate CRC on whole frame
        data.append_uint(crc32(buffer, data), 4)
        # Encrypt data only
        data = @session_key.encrypt(data)
      end

      buffer.concat(data)

      if tx != :encrypt && tx != :none && cmd != CMD_ADDITIONAL_FRAME && @authed
        cmac = @session_key.calculate_cmac(buffer)
        # Only first 8 bytes of CMAC are transmitted
        buffer.concat(cmac[0..7]) if tx == :mac
      end

      received_data = []
      card_status = nil
      loop do
        receive_buffer = iso_transceive(buffer.shift(@max_inf_size))

        card_status = receive_buffer.shift
        received_data.concat(receive_buffer)

        break if card_status != ST_ADDITIONAL_FRAME || (buffer.empty? && expect == ST_ADDITIONAL_FRAME)

        buffer.unshift(CMD_ADDITIONAL_FRAME)
      end

      error_msg = check_status_code(card_status)

      unless error_msg.empty?
        invalid_auth
        raise ReceiptStatusError, "0x#{card_status.to_bytehex} - #{error_msg}"
      end

      if expect && expect != card_status
        raise UnexpectedDataError, 'Card status does not match expected value'
      end

      if rx == :encrypt
        if receive_length.nil?
          raise UsageError, 'Lack of receive length for removing padding'
        end
        @session_key.padding_mode((receive_length > 0) ? 1 : 2)
        receive_length += 4 # CRC32
        received_data = @session_key.decrypt(received_data, data_length: receive_length)
        received_crc = received_data.pop(4).to_uint
        crc = crc32(received_data, card_status)
        if crc != received_crc
          raise ReceiptIntegrityError
        end
      elsif rx != :none && @authed && received_data.size >= 8 && card_status == ST_SUCCESS
        received_cmac = received_data.pop(8)
        cmac = @session_key.calculate_cmac(received_data + [card_status])
        # Only first 8 bytes of CMAC are transmitted
        if rx == :mac && cmac[0..7] != received_cmac
          raise ReceiptIntegrityError
        end
      end

      received_data
    end

    def auth(key_number, auth_key)
      cmd = (auth_key.type == :des) ? CMD_DES_AUTH : CMD_AES_AUTH
      rand_size = (auth_key.cipher_suite == 'des-ede-cbc') ? 8 : 16
      auth_key.clear_iv
      auth_key.padding_mode(1)

      # Ask for authentication
      received_data = transceive(cmd: cmd, data: key_number, expect: ST_ADDITIONAL_FRAME, tx: :none, rx: :none)

      # Receive challenge from DESFire
      challenge = auth_key.decrypt(received_data, data_length: rand_size)
      challenge_rot = challenge.rotate

      # Generate random number and encrypt it with rotated challenge
      random_number = SecureRandom.random_bytes(rand_size).bytes
      response = auth_key.encrypt(random_number + challenge_rot)

      # Send challenge response
      received_data = transceive(cmd: CMD_ADDITIONAL_FRAME, data: response, tx: :none, rx: :none)

      # Check if verification matches rotated random_number
      verification = auth_key.decrypt(received_data, data_length: rand_size)

      if random_number.rotate != verification
        halt
        @authed = false

        raise ReceiptIntegrityError, 'Authentication Failed'
      end

      # Generate session key from generated random number(RndA) and challenge(RndB)
      session_key = random_number[0..3] + challenge[0..3]

      if auth_key.key_size > 8
        if auth_key.cipher_suite == 'des-ede-cbc'
          session_key.concat(random_number[4..7] + challenge[4..7])
        elsif auth_key.cipher_suite == 'des-ede3-cbc'
          session_key.concat(random_number[6..9] + challenge[6..9])
          session_key.concat(random_number[12..15] + challenge[12..15])
        elsif auth_key.cipher_suite == 'aes-128-cbc'
          session_key.concat(random_number[12..15] + challenge[12..15])
        end
      end

      @session_key = Key.new(auth_key.type, session_key)
      @session_key.generate_cmac_subkeys
      @authed = key_number

      authed?
    end

    def get_app_ids
      ids = transceive(cmd: CMD_GET_APP_IDS, rx: :mac)

      return ids if ids.empty?

      ids = ids.each_slice(3).to_a
      ids.map do |id|
        id.to_uint
      end
    end

    def app_exist?(id)
      get_app_ids.include?(id)
    end

    def select_app(id)
      transceive(cmd: CMD_SELECT_APP, data: convert_app_id(id))

      invalid_auth
      @selected_app = id
    end

    def create_app(id, key_setting, key_count, cipher_suite)
      raise UnauthenticatedError unless @authed
      raise UsageError, 'An application can only hold up to 14 keys.' if key_count > 14

      buffer = convert_app_id(id) + [key_setting.export, KEY_TYPE.fetch(cipher_suite) | key_count]

      transceive(cmd: CMD_CREATE_APP, data: buffer, rx: :mac)
    end

    def delete_app(id)
      raise UnauthenticatedError unless @authed

      transceive(cmd: CMD_DELETE_APP, data: convert_app_id(id))
    end

    def get_card_version
      version = transceive(cmd: CMD_GET_CARD_VERSION)

      CARD_VERSION.new(
        version[0], version[1], version[2], version[3], version[4], 1 << (version[5] / 2), version[6],
        version[7], version[8], version[9], version[10], version[11], 1 << (version[12] / 2), version[13],
        version[14..20], version[21..25], version[26].to_s(16).to_i, 2000 + version[27].to_s(16).to_i
      )
    end

    def get_free_memory
      transceive(cmd: CMD_FREE_MEMORY)
    end

    def get_df_names
      raise UsageError, 'App 0 should be selected before calling' unless @selected_app == 0

      transceive(cmd: CMD_GET_DF_NAMES)
    end

    def get_card_uid
      raise UnauthenticatedError unless @authed

      transceive(cmd: CMD_GET_CARD_UID, rx: :encrypt, receive_length: 7)
    end

    def format_card
      raise UnauthenticatedError unless @authed

      transceive(cmd: CMD_FORMAT_CARD)
    end

    def set_configuration_byte(disable_format, enable_random_uid)
      raise UnauthenticatedError unless @authed

      flag = 0
      flag |= 0x01 if disable_format
      flag |= 0x02 if enable_random_uid

      transceive(cmd: CMD_SET_CONFIGURATION, plain_data: 0x00, data: [flag], tx: :encrypt)
    end

    def set_default_key(key)
      raise UnauthenticatedError unless @authed

      buffer = key.key
      buffer.append_uint(key.version, 1)

      transceive(cmd: CMD_SET_CONFIGURATION, plain_data: 0x01, data: buffer, tx: :encrypt)
    end

    def set_ats(ats)
      raise UnauthenticatedError unless @authed

      transceive(cmd: CMD_SET_CONFIGURATION, plain_data: 0x02, data: ats, tx: :encrypt, encrypt_padding: 2)
    end

    def get_key_version(key_number)
      received_data = transceive(cmd: CMD_GET_KEY_VERSION, data: key_number, rx: :mac)

      received_data[0]
    end

    def change_key(key_number, new_key, curr_key = nil)
      raise UnauthenticatedError unless @authed
      raise UsageError, 'Invalid key number' if key_number > 13

      cryptogram = new_key.key

      same_key = (key_number == @authed)

      # Only Master Key can change its key type
      key_number |= KEY_TYPE.fetch(new_key.cipher_suite) if @selected_app == 0

      # XOR new key if we're using different one
      unless same_key
        cryptogram = cryptogram.xor(curr_key.key)
      end

      # AES stores key version separately
      if new_key.type == :aes
        cryptogram.append_uint(new_key.version, 1)
      end

      cryptogram.append_uint(crc32([CMD_CHANGE_KEY, key_number], cryptogram), 4)

      unless same_key
        cryptogram.append_uint(crc32(new_key.key), 4)
      end

      # Encrypt cryptogram
      @session_key.padding_mode(1)
      buffer = [key_number] + @session_key.encrypt(cryptogram)

      transceive(cmd: CMD_CHANGE_KEY, data: buffer, tx: :none, rx: :mac)

      # Change current used key will revoke authentication
      invalid_auth if same_key
    end

    def get_key_setting
      received_data = transceive(cmd: CMD_GET_KEY_SETTING)

      { key_setting: KEY_SETTING.import(received_data[0]),
        key_count: received_data[1] & 0x0F,
        key_type: KEY_TYPE.key(received_data[1] & 0xF0) }
    end

    def change_key_setting(key_setting)
      raise UnauthenticatedError unless @authed

      transceive(cmd: CMD_CHANGE_KEY_SETTING, data: key_setting.export, tx: :encrypt, rx: :mac)
    end

    def get_file_ids
      transceive(cmd: CMD_GET_FILE_IDS)
    end

    def file_exist?(id)
      get_file_ids.include?(id)
    end

    def get_file_setting(id)
      received_data = transceive(cmd: CMD_GET_FILE_SETTING, data: id)

      file_setting = FILE_SETTING.new
      file_setting.type = FILE_TYPE.key(received_data.shift)
      file_setting.communication = FILE_COMMUNICATION.key(received_data.shift)
      file_setting.permission = FILE_PERMISSION.import(received_data.shift(2).to_uint)

      case file_setting.type
      when :std_data_file, :backup_data_file
        file_setting.size = received_data.shift(3).to_uint
      when :value_file
        file_setting.lower_limit = received_data.shift(4).to_uint
        file_setting.upper_limit = received_data.shift(4).to_uint
        file_setting.limited_credit_value = received_data.shift(4).to_uint
        file_setting.limited_credit = received_data.shift & 0x01
      when :linear_record_file, :cyclic_record_file
        file_setting.record_size = received_data.shift(3).to_uint
        file_setting.max_record_number = received_data.shift(3).to_uint
        file_setting.current_record_number = received_data.shift(3).to_uint
      end

      file_setting
    end

    def change_file_setting(id, file_setting)
      buffer = []
      buffer.append_uint(FILE_COMMUNICATION.fetch(file_setting.communication), 1)
      buffer.append_uint(file_setting.permission.export, 2)

      transceive(cmd: CMD_CHANGE_FILE_SETTING, plain_data: id, data: buffer, tx: :encrypt)
    end

    def create_file(id, file_setting)
      buffer = [id]
      buffer.append_uint(FILE_COMMUNICATION.fetch(file_setting.communication), 1)
      buffer.append_uint(file_setting.permission.export, 2)

      case file_setting.type
      when :std_data_file, :backup_data_file
        buffer.append_uint(file_setting.size, 3) # PICC will allocate n * 32 bytes memory internally
      when :value_file
        buffer.append_sint(file_setting.lower_limit, 4)
        buffer.append_sint(file_setting.upper_limit, 4)
        buffer.append_sint(file_setting.limited_credit_value, 4)
        buffer.append_uint(file_setting.limited_credit, 1)
      when :linear_record_file, :cyclic_record_file
        buffer.append_uint(file_setting.record_size, 3)
        buffer.append_uint(file_setting.max_record_number, 3)
      end

      cmd = self.class.const_get("CMD_CREATE_#{file_setting.type.to_s.upcase}")

      transceive(cmd: cmd, data: buffer)
    end

    def delete_file(id)
      transceive(cmd: CMD_DELETE_FILE, data: id)
    end

    def read_file(id, cmd, data, length)
      file_setting = get_file_setting(id)
      length *= file_setting.record_size if file_setting.record_size
      transceive(cmd: cmd, data: data, rx: file_setting.communication, receive_length: length)
    end

    def write_file(id, cmd, plain_data, data)
      file_setting = get_file_setting(id)
      transceive(cmd: cmd, plain_data: plain_data, data: data, tx: file_setting.communication)
    end

    def read_data(id, offset, length)
      buffer = []
      buffer.append_uint(id, 1)
      buffer.append_uint(offset, 3)
      buffer.append_uint(length, 3)

      read_file(id, CMD_READ_DATA, buffer, length)
    end

    def write_data(id, offset, data)
      buffer = []
      buffer.append_uint(id, 1)
      buffer.append_uint(offset, 3)
      buffer.append_uint(data.size, 3)

      write_file(id, CMD_WRITE_DATA, buffer, data)
    end

    def read_value(id)
      read_file(id, CMD_GET_VALUE, id, 4).to_sint
    end

    def credit_value(id, delta)
      raise UsageError, 'Negative number is not allowed.' if delta < 0

      buffer = []
      buffer.append_sint(delta, 4)

      write_file(id, CMD_CREDIT, id, buffer)
    end

    def debit_value(id, delta)
      raise UsageError, 'Negative number is not allowed.' if delta < 0

      buffer = []
      buffer.append_sint(delta, 4)

      write_file(id, CMD_DEBIT, id, buffer)
    end

    def limited_credit_value(id, delta)
      raise UsageError, 'Negative number is not allowed.' if delta < 0

      buffer = []
      buffer.append_sint(delta, 4)

      write_file(id, CMD_LIMITED_CREDIT, id, buffer)
    end

    def read_records(id, offset, length)
      buffer = []
      buffer.append_uint(id, 1)
      buffer.append_uint(offset, 3)
      buffer.append_uint(length, 3)

      read_file(id, CMD_READ_RECORDS, buffer, length)
    end

    def write_record(id, offset, data)
      buffer = []
      buffer.append_uint(id, 1)
      buffer.append_uint(offset, 3)
      buffer.append_uint(data.size, 3)

      write_file(id, CMD_WRITE_RECORD, buffer, data)
    end

    def clear_record(id)
      transceive(cmd: CMD_CLEAR_RECORD_FILE, data: id)
    end

    def commit_transaction
      transceive(cmd: CMD_COMMIT_TRANSACTION)
    end

    def abort_transaction
      transceive(cmd: CMD_ABORT_TRANSACTION)
    end

    private

    def invalid_auth
      @authed = false
      @session_key = nil
    end

    def convert_app_id(id)
      raise UsageError, 'Application ID overflow' if id < 0 || id >= (1 << 24)

      [].append_uint(id, 3)
    end

    def check_status_code(code)
      case code
      when ST_SUCCESS, ST_ADDITIONAL_FRAME
        ''
      when ST_NO_CHANGES
        'No changes have been made, authenticate state revoked.'
      when ST_OUT_OF_MEMORY
        'Insufficient NV-Memory to complete command.'
      when ST_ILLEGAL_COMMAND
        'Command code not supported.'
      when ST_INTEGRITY_ERROR
        'CRC or MAC does not match data. Padding bytes not valid.'
      when ST_KEY_NOT_EXIST
        'Invalid key number specified.'
      when ST_WRONG_COMMAND_LEN
        'Length of command string invalid.'
      when ST_PERMISSION_DENIED
        'Current configuration / status does not allow the requested command.'
      when ST_INCORRECT_PARAM
        'Value of the parameter(s) invalid.'
      when ST_APP_NOT_FOUND
        'Requested AID not present on PICC.'
      when ST_APPL_INTEGRITY_ERROR
        'Unrecoverable error within application, application will be disabled.'
      when ST_AUTHENTICATION_ERROR
        'Authentication error or insufficient privilege.'
      when ST_BOUNDARY_ERROR
        'Attempt to read/write data from/to beyond the file\'s/record\'s limits.'
      when ST_PICC_INTEGRITY_ERROR
        'Unrecoverable error within PICC, PICC will be disabled.'
      when ST_COMMAND_ABORTED
        'Previous Command was not fully completed. Not all Frames were requested or provided by the PCD.'
      when ST_PICC_DISABLED_ERROR
        'PICC was disabled by an unrecoverable error.'
      when ST_COUNT_ERROR
        'Number of Applications limited to 28, no additional CreateApplication possible.'
      when ST_DUPLICATE_ERROR
        'Creation of file/application failed because file/application with same number already exists.'
      when ST_EEPROM_ERROR
        'Could not complete NV-write operation due to loss of power, internal backup/rollback mechanism activated.'
      when ST_FILE_NOT_FOUND
        'Specified file number does not exist.'
      when ST_FILE_INTEGRITY_ERROR
        'Unrecoverable error within file, file will be disabled.'
      else
        'Unknown Error Code.'
      end
    end
  end
end
