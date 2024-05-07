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

module Xlat
  module Protocols
    module Icmp
      class Base
        include Xlat::Common

        V4_PROTOCOL_ID = 1
        V6_PROTOCOL_ID = 58

        attr_reader :type, :code

        def initialize(packet)
          @packet = packet
        end

        def _parse
          bytes = @packet.bytes
          off = @packet.l4_start

          @type = bytes.getbyte(off)
          @code = bytes.getbyte(off + 1)

          self
        end

        def self.parse(packet)
          bytes = packet.bytes
          off = packet.l4_start

          return nil if bytes.length - off < 8

          type = bytes.getbyte(off)
          icmp = packet.version.new_icmp(packet, type)
          icmp._parse
        end

        def apply(cs_delta)
          # ICMP does not use pseudo headers
        end

        def self.recalculate_checksum(packet)
          string_set16be(packet.bytes,packet.l4_start + 2, 0)
          checksum = Ip.checksum(packet.bytes, packet.l4_start)
          checksum = Ip.checksum_adjust(checksum, packet.version.icmp_cs_delta(packet)) # pseudo header
          string_set16be(packet.bytes,packet.l4_start + 2, checksum)
        end
      end
    end
  end
end
