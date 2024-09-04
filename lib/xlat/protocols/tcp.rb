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


require_relative './tcpudp'

module Xlat
  module Protocols
    class Tcp < Tcpudp
      PROTOCOL_ID = 6
      DATA_OFFSET_OFFSET = 12
      CHECKSUM_OFFSET = 16
      OPTION_KIND_END = 0
      OPTION_KIND_NOOP = 1
      OPTION_KIND_MSS = 2
      FLAG_FIN = 0x01
      FLAG_SYN = 0x02
      FLAG_RST = 0x04
      FLAG_PST = 0x08
      FLAG_ACK = 0x10
      FLAG_URG = 0x20
      FLAG_ECE = 0x40
      FLAG_CWR = 0x80

      def parse
        packet = @packet
        bytes = packet.l4_bytes
        offset = packet.l4_bytes_offset

        return nil if bytes.size < offset + (@icmp_payload ? 4 : 20)

        super
      end

      def apply(cs_delta)
        return if cs_delta.zero?

        packet = @packet
        bytes = packet.l4_bytes
        offset = packet.l4_bytes_offset

        return if bytes.size < offset + 18

        checksum = bytes.get_value(:U16, offset + 16)
        checksum = _adjust_checksum(checksum, cs_delta)
        bytes.set_value(:U16, offset + 16, checksum)
      end
    end
  end
end
