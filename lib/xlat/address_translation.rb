# frozen_string_literal: true

module Xlat
  module AddressTranslation
    # Translate IPv6 address in the given IO::Buffer into IPv4 address and write to another IO::Buffer.
    # Must return true when translation took place.
    #
    # @param source [IO::Buffer] Buffer from which IPv6 address is read
    # @param source_offset [Integer] Offset in the source IO::Buffer
    # @param destination [IO::Buffer] Buffer into which IPv4 address is written
    # @param destination_offset [Integer] Offset in the destination IO::Buffer
    # @return [Integer, nil] checksum delta value or nil when no translation took place
    def translate_address_to_ipv4(source, source_offset, destination, destination_offset)
      raise NotImplementedError
    end

    # Translate IPv4 address in the given IO::Buffer into IPv6 address and write to another IO::Buffer.
    # Must return true when translation took place.
    #
    # @param source [IO::Buffer] Buffer from which IPv4 address is read
    # @param source_offset [Integer] Offset in the source IO::Buffer
    # @param destination [IO::Buffer] Buffer into which IPv6 address is written
    # @param destination_offset [Integer] Offset in the destination IO::Buffer
    # @return [Integer, nil] checksum delta value or nil when no translation took place
    def translate_address_to_ipv6(source, source_offset, destination, destination_offset)
      raise NotImplementedError
    end

    # # Must return true when receiver (translator) can perform in checksum neutral manner
    # # https://datatracker.ietf.org/doc/html/rfc6052#section-4.1
    # def checksum_neutral?
    #   false
    # end
  end
end
