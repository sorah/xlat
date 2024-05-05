# frozen_string_literal: true

module Xlat
  module AddressTranslation
    # Translate IPv6 address bytestring into IPv4 address and write to given buffer
    # Must return true when translation took place
    #
    # @param ipv6_address [String] IPv6 address bytestring
    # @param buffer [String] Destination packet buffer
    # @param offset [String] Offset in buffer to write IPv6 address
    # @return [Integer, nil] checksum delta value or nil when no translation took place
    def translate_address_to_ipv4(ipv6_address,buffer,offset = 0)
      raise NotImplementedError
    end

    # Translate IPv4 address bytestring into IPv6 address and write to given buffer
    #
    # @param ipv4_address [String] IPv4 address bytestring
    # @param buffer [String] Destination packet buffer
    # @param offset [String] Offset in buffer to write IPv4 address
    # @return [Integer, nil] checksum delta value or nil when no translation took place
    def translate_address_to_ipv6(ipv4_address,buffer,offset = 0)
      raise NotImplementedError
    end

    # # Must return true when receiver (translator) can perform in checksum neutral manner
    # # https://datatracker.ietf.org/doc/html/rfc6052#section-4.1
    # def checksum_neutral?
    #   false
    # end
  end
end
