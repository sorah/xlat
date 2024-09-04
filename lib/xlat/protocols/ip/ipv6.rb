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
      module Ipv6
        extend Xlat::Common

        # https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header
        # except ESP (50)
        EXTENSIONS = [0, 43, 44, 51, 60, 135, 139, 140, 253, 254].map { |id| [id, true] }.to_h

        def self.to_i
          6
        end

        def self.tuple(bytes, offset)
          bytes.slice(offset + 8, 32)
        end

        def self.icmp_protocol_id
          Icmp::Base::V6_PROTOCOL_ID
        end

        def self.icmp_cs_delta(packet)
          upper_layer_packet_length = packet.l4_bytes.size - packet.l4_bytes_offset
          Common.sum16be(tuple) + upper_layer_packet_length + packet.proto
        end

        def self.new_icmp(packet, type)
          case type
          when Icmp::Echo::V6_TYPE_REQUEST
            Icmp::Echo.new(packet, true)
          when Icmp::Echo::V6_TYPE_REPLY
            Icmp::Echo.new(packet, true)
          when Icmp::Error::V6_TYPE_DEST_UNREACH, Icmp::Error::V6_TYPE_PACKET_TOO_BIG, Icmp::Error::V6_TYPE_TIME_EXCEEDED, Icmp::Error::V6_TYPE_PARAMETER_PROBLEM
            Icmp::Error.new(packet)
          else
            Icmp::Base.new(packet)
          end
        end

        def self.parse(packet)
          bytes = packet.bytes
          offset = packet.bytes_offset

          return false if bytes.size < 40

          proto = bytes.get_value(:U8, offset + 6)

          # drop packets containing IPv6 extensions (RFC 7045 grudgingly acknowledges existence of such middleboxes)
          return false if EXTENSIONS[proto]

          packet.proto = proto
          packet.l4_start = 40

          true
        end

        def self.apply(bytes, offset, _cs_delta, icmp_payload)
          # decrement hop limit
          unless icmp_payload
            hop_limit = bytes.get_value(:U8, offset + 7)
            if hop_limit > 0
              hop_limit -= 1
              bytes.set_value(:U8, offset + 7, hop_limit)
            end
          end

          # IPv6 has no checksum
        end
      end
    end
  end
end


