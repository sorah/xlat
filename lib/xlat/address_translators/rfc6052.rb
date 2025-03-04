# frozen_string_literal: true
require 'xlat/address_translation'
require 'xlat/io_buffer_ext'
require 'xlat/common'
require 'ipaddr'

module Xlat
  module AddressTranslators
    # RFC 6052 based IPv4/IPv6 address translator. Accepts Pref64n::/96.
    #
    # https://www.rfc-editor.org/info/rfc6052
    # https://datatracker.ietf.org/doc/html/rfc6052
    class Rfc6052
      include Xlat::AddressTranslation

      def initialize(pref64n_string)
        @pref64n = IPAddr.new(pref64n_string, Socket::AF_INET6)
        unless @pref64n.prefix == 96
          raise ArgumentError, "#{self.class.name} only supports Pref64::/96"
        end

        @pref64n_prefix = IO::Buffer.for(@pref64n.hton).slice(0, 12)
        unless @pref64n_prefix.get_value(:U8, 8) == 0
          raise ArgumentError, "Bits 64-71 in Pref64::/96 must be all zeroes"
        end

        @cs_delta = Xlat::Common.sum16be(@pref64n_prefix)
        @cs_delta = 0 if @cs_delta % 0xffff == 0 # checksum neutrality
        @negative_cs_delta = -@cs_delta
      end

      def translate_address_to_ipv4(source, source_offset, destination, destination_offset)
        preflen = @pref64n_prefix.size
        return unless (source.slice(source_offset, preflen) <=> @pref64n_prefix) == 0
        destination.copy(source, destination_offset, 16 - preflen, source_offset + preflen)

        @negative_cs_delta
      end

      def translate_address_to_ipv6(source, source_offset, destination, destination_offset)
        preflen = @pref64n_prefix.size
        destination.copy(@pref64n_prefix, destination_offset, preflen)
        destination.copy(source, destination_offset + preflen, 16 - preflen, source_offset)

        @cs_delta
      end
    end
  end
end
