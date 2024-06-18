# frozen_string_literal: true
require 'xlat/address_translation'
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
        raise ArgumentError, "#{self.class.name} only supports Pref64n::/96" unless @pref64n.prefix == 96
        @pref64n_prefix = IO::Buffer.for(@pref64n.hton).slice(0, 12)

        @cs_delta = Xlat::Common.sum16be(@pref64n_prefix)
        @cs_delta = 0 if @cs_delta % 0xffff == 0 # checksum neutrality
        @negative_cs_delta = -@cs_delta
      end

      def translate_address_to_ipv4(ipv6_address,buffer,offset = 0)
        return unless (ipv6_address.slice(0, @pref64n_prefix.size) <=> @pref64n_prefix) == 0
        buffer.copy(ipv6_address, offset, 4, 12)

        @negative_cs_delta
      end

      def translate_address_to_ipv6(ipv4_address,buffer,offset = 0)
        buffer.copy(@pref64n_prefix, offset, 12)
        buffer.copy(ipv4_address, offset + 12, 4)

        @cs_delta
      end
    end
  end
end
