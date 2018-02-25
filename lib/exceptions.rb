class CommunicationError < StandardError; end
class PICCTimeoutError < CommunicationError; end
class PCDTimeoutError < CommunicationError; end
class IncorrectCRCError < CommunicationError; end
class CollisionError < CommunicationError; end

class UnexpectedDataError < StandardError; end
class UsageError < StandardError; end

class MifareNakError < StandardError; end

class DESFireError < StandardError; end
class UnauthenticatedError < DESFireError; end
class ReceiptStatusError < DESFireError; end
class ReceiptIntegrityError < DESFireError; end
