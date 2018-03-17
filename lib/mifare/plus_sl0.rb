module MIFARE
  module PlusSL0
    def write_perso(block_addr, data)
      transceive(cmd: CMD_WRITE_PERSO, data: [block_addr, *data])
    end

    def commit_perso
      transceive(cmd: CMD_COMMIT_PERSO)
    end
  end
end
