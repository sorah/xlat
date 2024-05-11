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

        def self.src_addr(bytes)
          bytes.byteslice(12, 4)
        end

        def self.set_src_addr(bytes, new_addr)
          cs_delta = new_addr.unpack('n*').sum - bytes.unpack('@12n2').sum
          bytes.bytesplice(12, 4, new_addr)
          cs_delta
        end

        def self.dest_addr(bytes)
          bytes.byteslice(16, 4)
        end

        def self.set_dest_addr(bytes, new_addr)
          cs_delta = new_addr.unpack('n*').sum - bytes.unpack('@16n2').sum
          bytes.bytesplice(16, 4, new_addr)
          cs_delta
        end

        def self.tuple(bytes)
          bytes.byteslice(12, 8)
        end

        def self.update_l4_length(bytes)
          orig_length = string_get16be(bytes,2)
          new_length = bytes.length
          string_set16be(bytes,2, new_length)
          new_length - orig_length
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

        def self.parse(packet)
          bytes = packet.bytes

          return false if bytes.getbyte(0) != 0x45
          # tos?
          # totlen?
          # ignore identification
          return false if string_get16be(bytes,6) & 0xbfff != 0 # ignore fragments

          packet.l4_start = 20

          #p bytes.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
          proto = bytes.getbyte(9)
          packet.proto = proto

          true
        end

        def self.apply(bytes, cs_delta, icmp_payload: false)
          # decrement TTL
          unless icmp_payload
            ttl = bytes.getbyte(8)
            if ttl > 0
              ttl -= 1
              bytes.setbyte(8, ttl)
              cs_delta -= 0x0100 # checksum computation is performed per 2 octets
            end
          end

          checksum = string_get16be(bytes,10)
          checksum = Ip.checksum_adjust(checksum, cs_delta)
          string_set16be(bytes,10, checksum)
        end
      end
    end
  end
end
