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


module Xlat
  module Protocols
    class Ip
      attr_accessor :bytes  # IO::Buffer containing L3 header
      attr_accessor :bytes_offset  # Offset where L3 header begins within `bytes`
      attr_accessor :proto  # L4 protocol ID
      attr_accessor :l4_start  # L3 header length
      attr_accessor :l4
      attr_accessor :l4_bytes  # IO::Buffer containing L4 packet
      attr_accessor :l4_bytes_offset  # Offset where L4 header begins within `l4_bytes`
      attr_accessor :l4_bytes_length  # Length of L4 datagram within `l4_bytes`, possibly truncated
      attr_accessor :cs_delta  # Accumulated changes to be applied to L4 checksum

      attr_reader :version

      def initialize(icmp_payload: false)
        @icmp_payload = icmp_payload
        @_tcp = Tcp.new(self, icmp_payload:)
        @_udp = Udp.new(self, icmp_payload:)
      end

      def self.parse(bytes)
        new.parse(bytes:)
      end

      def parse(bytes:, bytes_offset: 0, l4_bytes: nil, l4_bytes_offset: nil)
        @bytes = bytes
        @bytes_offset = bytes_offset
        @proto = nil
        @version = nil
        @l4_start = nil
        @l4 = nil
        @l4_bytes = l4_bytes
        @l4_bytes_offset = l4_bytes_offset
        @l4_bytes_length = nil
        @cs_delta = 0

        # mimimum size for IPv4
        return nil if bytes.size < bytes_offset + 20

        case bytes.get_value(:U8, bytes_offset) >> 4
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
          @l4 = @_udp.parse
        when Protocols::Tcp::PROTOCOL_ID
          @l4 = @_tcp.parse
        when @version.icmp_protocol_id
          @l4 = Protocols::Icmp.parse(self)
        end

        self
      end

      # @param start [Integer] Length of L3 header in octets
      # @param length [Integer] Length of L4 datagram in octets, as specified in L3 header
      # @return [true, false] Whether the given range is valid
      def set_l4_region(start, length)
        @l4_start = start

        unless @l4_bytes
          @l4_bytes = @bytes
          @l4_bytes_offset = @bytes_offset + start
        end

        if @l4_bytes.size < @l4_bytes_offset + length
          if @icmp_payload
            # allow truncation in ICMP payload
            length = @l4_bytes.size - @l4_bytes_offset
            return false if length < 0
          else
            return false
          end
        end

        @l4_bytes_length = length

        true
      end

      # Convert this packet into different IP version using the supplied buffer as header.
      #
      # @param version [Module] New version
      # @param new_header_bytes [IO::Buffer] Buffer to hold L3 header.
      #   The caller is responsible for populating the buffer with a proper content.
      # @param cs_delta [Integer] Checksum delta in the pseudo header to be cancelled with the L4 checksum.
      # @return [Ip] self
      def convert_version!(version, new_header_bytes, cs_delta)
        @bytes = new_header_bytes
        @offset = 0
        @version = version
        @l4_start = new_header_bytes.size
        @cs_delta += cs_delta
        self
      end

      def total_length
        @l4_start + (@l4_bytes.size - @l4_bytes_offset)
      end

      def tuple
        @version.tuple(@bytes, @bytes_offset)
      end

      def apply_changes
        cs_delta = @cs_delta
        @version.apply(@bytes, @bytes_offset, cs_delta, @icmp_payload)
        @l4&.apply(cs_delta)
        @cs_delta = 0
      end

      def self.checksum(bytes, from = nil, len = nil)
        from = 0 if from.nil?
        len = bytes.size - from if len.nil?
        to = from + len - 1

        sum = Common.sum16be(bytes.slice(from, len))
        sum += bytes.get_value(:U8, to) * 256 if len.odd?
        sum = (sum & 0xffff) + (sum >> 16) while sum > 65535
        ~sum & 0xffff
      end

      def self.checksum_list(buffers)
        sum = 0
        offset = 0
        buffers.each do |buf|
          if offset.odd?
            sum += buf.get_value(:U8, 0)
            buf = buf.slice(1)
            offset += 1
          end
          sum += Common.sum16be(buf)
          len = buf.size
          if len.odd?
            sum += buf.get_value(:U8, len - 1) << 8
          end
          offset += len
        end
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

require_relative './icmp'
require_relative './ip/ipv4'
require_relative './ip/ipv6'
require_relative './tcp'
require_relative './udp'
