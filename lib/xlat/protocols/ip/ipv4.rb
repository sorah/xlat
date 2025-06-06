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


require 'xlat/common'
require 'xlat/protocols/icmp'

module Xlat
  module Protocols
    class Ip
      module Ipv4
        extend Xlat::Common

        def self.to_i
          4
        end

        def self.tuple(bytes, offset)
          bytes.slice(offset + 12, 8)
        end

        def self.icmp_protocol_id
          Icmp::Base::V4_PROTOCOL_ID
        end

        def self.icmp_cs_delta(packet)
          0
        end

        def self.new_icmp(packet, type)
          case type
          when Icmp::Echo::V4_TYPE_REQUEST
            Icmp::Echo.new(packet, true)
          when Icmp::Echo::V4_TYPE_REPLY
            Icmp::Echo.new(packet, false)
          when Icmp::Error::V4_TYPE_DEST_UNREACH, Icmp::Error::V4_TYPE_TIME_EXCEEDED, Icmp::Error::V4_TYPE_PARAMETER_PROBLEM
            Icmp::Error.new(packet)
          else
            Icmp::Base.new(packet)
          end
        end

        def self.parse(packet, b0)
          bytes = packet.bytes
          offset = packet.bytes_offset

          header_length = (b0 & 0x0f) * 4
          return false if header_length < 20

          # tos?

          total_length = bytes.get_value(:U16, offset + 2)
          return false if total_length < header_length
          return false unless packet.set_l4_region(header_length, total_length - header_length)

          packet.identification = bytes.get_value(:U16, offset + 4)

          flags_offset = bytes.get_value(:U16, offset + 6)  # reserved:1, DF:1, MF:1, offset:13
          fragment_offset = flags_offset & 0x1fff
          more_fragments = (flags_offset & 0x2000) != 0
          if fragment_offset != 0 || more_fragments
            packet.fragment_offset = fragment_offset
            packet.more_fragments = more_fragments
          end
          packet.dont_fragment = (flags_offset & 0x4000) != 0

          packet.proto = bytes.get_value(:U8, offset + 9)

          true
        end

        def self.apply(bytes, offset, cs_delta, icmp_payload)
          # decrement TTL
          unless icmp_payload
            ttl = bytes.get_value(:U8, offset + 8)
            if ttl > 0
              ttl -= 1
              bytes.set_value(:U8, offset + 8, ttl)
              cs_delta -= 0x0100 # checksum computation is performed per 2 octets
            end
          end

          if cs_delta != 0
            checksum = bytes.get_value(:U16, offset + 10)
            checksum = Ip.checksum_adjust(checksum, cs_delta)
            bytes.set_value(:U16, offset + 10, checksum)
          end
        end
      end
    end
  end
end
