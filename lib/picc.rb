class PICC
  attr_reader :uid
  attr_reader :sak

  def initialize(pcd, uid, sak)
    @pcd = pcd
    @uid = uid
    @sak = sak
    @halted = false
  end

  def resume_communication
    unless @pcd.reestablish_picc_communication(@uid)
      halt
      raise CommunicationError, 'Unable to resume communication or wrong card was presented. Halting cards in the field.'
    end
  end

  def halt
    @halted = @pcd.picc_halt
  end
end
