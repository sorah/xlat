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

        def self.src_addr(bytes)
          bytes.byteslice(8, 16)
        end

        def self.set_src_addr(bytes, new_addr)
          cs_delta = new_addr.unpack('n*').sum - bytes.unpack('@8n8').sum
          bytes.bytesplice(8, 16, new_addr)
          cs_delta
        end

        def self.dest_addr(bytes)
          bytes.byteslice(24, 16)
        end

        def self.set_dest_addr(bytes, new_addr)
          cs_delta = new_addr.unpack('n*').sum - bytes.unpack('@24n8').sum
          bytes.bytesplice(24, 16, new_addr)
          cs_delta
        end

        def self.tuple(bytes)
          bytes.byteslice(8, 32)
        end

        def self.update_l4_length(bytes)
          orig_length = string_get16be(bytes,4)
          new_length = bytes.length - 40
          string_set16be(bytes,4, new_length)
          new_length - orig_length
        end

        def self.set_l4_length(pseudo_header, packet_bytes, len)
          string_set16be(pseudo_header, 34, len)
          string_set16be(packet.bytes,4, len)
        end

        def self.icmp_protocol_id
          Icmp::Base::V6_PROTOCOL_ID
        end

        def self.icmp_cs_delta(packet)
          upper_layer_packet_length = packet.bytes.length - packet.l4_start
          packet.tuple.unpack('n*').sum + upper_layer_packet_length + packet.proto
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

          return false if bytes.length < 40

          proto = bytes.getbyte(6)

          # drop packets containing IPv6 extensions (RFC 7045 grudgingly acknowledges existence of such middleboxes)
          return false if EXTENSIONS[proto]

          packet.proto = proto
          packet.l4_start = 40

          true
        end

        def self.apply(bytes, cs_delta, icmp_payload: false)
          # decrement hop limit
          unless icmp_payload
            hop_limit = bytes.getbyte(7)
            if hop_limit > 0
              hop_limit -= 1
              bytes.setbyte(7, hop_limit)
            end
          end
        end
      end
    end
  end
end


