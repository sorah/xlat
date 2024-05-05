# frozen_string_literal: true

# This file is based on the source code available at https://github.com/kazuho/rat under MIT License
# 
# Copyright (c) 2022 Kazuho Oku
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.



require_relative './icmp'

module Xlat
  module Protocols
    class Ip
      attr_accessor :bytes
      attr_accessor :proto
      attr_accessor :l4_start
      attr_accessor :l4_bytes
      attr_accessor :l4
      attr_accessor :cs_delta

      attr_writer :l4_start_offset

      attr_reader :version

      def initialize(bytes, proto: nil, l4_bytes: nil, l4_start: nil, l4_bytes_offset: nil)
        @bytes = bytes
        @proto = proto
        @l4_bytes = l4_bytes || bytes
        @l4_bytes_offset = l4_bytes_offset
        @l4_start = l4_start
        @l4 = nil
        @version = nil
        @cs_delta = 0
      end


      def _parse(icmp_payload)
        bytes = @bytes

        # mimimum size for IPv4
        return nil if bytes.length < 20

        case bytes.getbyte(0) >> 4
        when 4
          @version = Ipv4
        when 6
          @version = Ipv6
        else
          return nil
        end

        return nil unless @version.parse(self)

        case @proto
        when Protocols::Udp::PROTOCOL_ID
          @l4 = Protocols::Udp.parse(self, icmp_payload)
        when Protocols::Tcp::PROTOCOL_ID
          @l4 = Protocols::Tcp.parse(self, icmp_payload)
        when @version.icmp_protocol_id
          @l4 = Protocols::Icmp.parse(self)
        end

        self
      end

      def self.parse(bytes, icmp_payload: false)
        new(bytes)._parse(icmp_payload)
      end

      def total_length
        if @l4_bytes_offset
          @l4_start + (@l4_bytes.size - @l4_bytes_offset)
        else
          @bytes.size
        end
      end

      def l4_bytes_offset
        @l4_bytes_offset || @l4_start
      end

      def src_addr
        @version.src_addr(@bytes)
      end

      def src_addr=(new_addr)
        @cs_delta += @version.set_src_addr(@bytes, new_addr)
      end

      def dest_addr
        @version.dest_addr(@bytes)
      end

      def dest_addr=(new_addr)
        @cs_delta += @version.set_dest_addr(@bytes, new_addr)
      end

      def tuple
        @version.tuple(@bytes)
      end

      def update_l4_length
        @cs_delta += @version.update_l4_length(@bytes)
      end

      def apply_changes(icmp_payload: false)
        cs_delta = @cs_delta
        @version.apply(@bytes, cs_delta, icmp_payload:)
        @l4&.apply(cs_delta)
      end

      def self.checksum(bytes, from = nil, len = nil)
        from = 0 if from.nil?
        len = bytes.length - from if len.nil?
        to = from + len - 1

        sum = bytes[from..to].unpack('n*').sum
        sum += bytes.getbyte(to) * 256 if len.odd?
        sum = (sum & 0xffff) + (sum >> 16) while sum > 65535
        ~sum & 0xffff
      end


      # this function assumes 0 <= sum <= 65534
      def self.checksum_adjust(checksum, delta)
        delta %= 65535

        mod65535 = 65534 - checksum
        mod65535 = (mod65535 + delta) % 65535
        65534 - mod65535
      end

      def self.addr_to_s(addr)
        case addr.length
        when 4
          addr.unpack('C4').join('.')
        when 16
          addr.unpack('n8').map { |f| format '%x', f }.join(':').gsub(/(:0)+(?=:)/, ':')
        else
          raise "unexpected address length of #{addr.length}"
        end
      end
    end
  end
end

require_relative './ip/ipv4'
require_relative './ip/ipv6'
require_relative './tcp'
require_relative './udp'
