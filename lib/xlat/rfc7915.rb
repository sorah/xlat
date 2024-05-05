# frozen_string_literal: true

require 'xlat/common'

module Xlat
  # RFC 7915 based stateless IPv4/IPv6 translator (SIIT). Intentionally not thread-safe.
  #
  # https://datatracker.ietf.org/doc/html/rfc7915
  # https://www.rfc-editor.org/info/rfc7915
  class Rfc7915
    extend Xlat::Common
    include Xlat::Common

    class BufferInUse < StandardError; end

    MAX_FRAGMENT_ID = 0xffffffff
    IPV4_NULL_BUFFER = ("\x00".b * 20).freeze
    IPV6_NULL_BUFFER = ("\x00".b * 40).freeze

    # @param source_address_translator [Xlat::AddressTranslation]
    # @param destination_address_translator [Xlat::AddressTranslation]
    def initialize(source_address_translator:, destination_address_translator:)
      @source_address_translator = source_address_translator
      @destination_address_translator = destination_address_translator

      # checksum_neutrality = @source_address_translator.checksum_neutral? && @destination_address_translator.checksum_neutral?

      @next_fragment_identifier = 0

      @ipv4_new_header_buffer = IPV4_NULL_BUFFER.dup
      @ipv6_new_header_buffer = IPV6_NULL_BUFFER.dup
      @output = [nil,nil]
      @new_header_buffer_in_use = false
      return_buffer_ownership
    end

    attr_accessor :next_fragment_identifier

    # Returns array of bytestrings to send as a IPv4 packet. May update original packet content.
    def translate_to_ipv4(ipv6_packet)
      raise BufferInUse if @new_header_buffer_in_use
      raise ArgumentError unless ipv6_packet.version.to_i == 6
      @new_header_buffer_in_use = true
      new_header_buffer = @ipv4_new_header_buffer
      ipv6_bytes = ipv6_packet.bytes
      cs_delta = 0 # delta for incremental update of upper-layer checksum fields

      # Version = 4, IHL = 5
      new_header_buffer.setbyte(0, (4 << 4) + 5)

      # FIXME: ToS ignored

      # Total Length = copy from IPv6; may be updated in later step
      ipv6_length = string_get16be(ipv6_bytes, 4)
      ipv4_length = ipv6_length + 20
      # not considering as a checksum delta because upper layer packet length doesn't take this into account; cs_delta += ipv6_length - ipv4_length
      string_set16be(new_header_buffer, 2, ipv4_length)

      # Identification = generate
      string_set16be(new_header_buffer, 4, make_fragment_id())

      # TTL = copy from IPv6
      new_header_buffer.setbyte(8, ipv6_bytes.getbyte(7))

      # Protocol = copy from IPv6; may be updated in later step for ICMPv6=>4 conversion
      new_header_buffer.setbyte(9, ipv6_packet.proto)

      # Source and Destination address
      cs_delta += @source_address_translator.translate_address_to_ipv4(ipv6_bytes[8,16], new_header_buffer, 12) or return return_buffer_ownership()
      cs_delta += @destination_address_translator.translate_address_to_ipv4(ipv6_bytes[24,16], new_header_buffer, 16) or return return_buffer_ownership()

      # TODO: DF bit
      # TODO: ICMPv6 => ICMPv4

      #p ipv6_bytes.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
      #p new_header_buffer.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')

      ipv4_packet = Protocols::Ip.new(new_header_buffer, proto: Protocols::Ip::Ipv4, l4_bytes: ipv6_packet.l4_bytes, l4_bytes_offset: ipv6_packet.l4_bytes_offset)
      ipv4_packet._parse(false)
      ipv4_packet.cs_delta = cs_delta
      ipv4_packet.apply_changes

      # Recompute checksum (this must be performed after Ip#apply_changes as it updates ipv4 checksum field along with l4 checksum field using delta,
      # while new_header_buffer has no prior checksum value)
      string_set16be(new_header_buffer, 10, 0)
      cksum = Protocols::Ip.checksum(new_header_buffer)
      string_set16be(new_header_buffer, 10, cksum)

      @output[0] = new_header_buffer
      @output[1] = ipv4_packet.l4_bytes[ipv4_packet.l4_bytes_offset..]
      @output
    end

    # Returns array of bytestrings to send as a IPv6 packet. May update original packet content.
    def translate_to_ipv6(ipv4_packet)
      raise BufferInUse if @new_header_buffer_in_use
      raise ArgumentError unless ipv4_packet.version.to_i == 4
      # TODO: support fragment extension and esp
      # TODO: ignore extension
      @new_header_buffer_in_use = true
      ipv4_bytes = ipv4_packet.bytes
      new_header_buffer = @ipv6_new_header_buffer
      cs_delta = 0 # delta for incremental update of upper-layer checksum fields

      # Version = 6, traffic class = 0
      new_header_buffer.setbyte(0, 6 << 4)

      # Flow label = 0

      # Total Length = copy from IPv4; may be updated in later step
      ipv4_length = string_get16be(ipv4_bytes, 2)
      ipv6_length = ipv4_length - 20
      # not considering as a checksum delta because upper layer packet length doesn't take this into account; cs_delta += ipv4_length - ipv6_length
      string_set16be(new_header_buffer, 4, ipv6_length)

      # Next Header = copy from IPv4; may be updated in later step for ICMPv6=>4 conversion
      new_header_buffer.setbyte(6, ipv4_packet.proto)

      # Hop limit = copy from IPv4
      new_header_buffer.setbyte(7, ipv4_bytes.getbyte(8))

      # Source and Destination address
      cs_delta += @source_address_translator.translate_address_to_ipv6(ipv4_bytes[12,4], new_header_buffer, 8) or return return_buffer_ownership()
      cs_delta += @destination_address_translator.translate_address_to_ipv6(ipv4_bytes[16,4], new_header_buffer, 24) or return return_buffer_ownership()

      # TODO: ICMPv4 => ICMPv6

      ipv6_packet = Protocols::Ip.new(new_header_buffer, proto: Protocols::Ip::Ipv6, l4_bytes: ipv4_packet.l4_bytes, l4_bytes_offset: ipv4_packet.l4_bytes_offset)
      ipv6_packet._parse(false)
      ipv6_packet.cs_delta = cs_delta # for upper-layer checksum incremental update
      ipv6_packet.apply_changes

      @output[0] = new_header_buffer
      @output[1] = ipv6_packet.l4_bytes[ipv6_packet.l4_bytes_offset..]
      @output
    end

    def return_buffer_ownership
      @new_header_buffer_in_use = false
      @ipv4_new_header_buffer[0, 20] = IPV4_NULL_BUFFER
      @ipv6_new_header_buffer[0, 40] = IPV6_NULL_BUFFER
      @output[0] = nil
      @output[1] = nil
      nil
    end

    private

    def make_fragment_id
      id = @next_fragment_identifier
      @next_fragment_identifier = @next_fragment_identifier.succ & MAX_FRAGMENT_ID
      id
    end
  end
end
  
