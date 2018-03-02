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

    def initialize(pcd, uid, sak)
      super
      
    end
  end
end