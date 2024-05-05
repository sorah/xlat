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
    class Udp < Tcpudp
      PROTOCOL_ID = 17
      CHECKSUM_OFFSET = 6

      def self.parse(packet, icmp_payload)
        return nil if packet.total_length < packet.l4_start + (icmp_payload ? 4 : 8)

        Udp.new(packet)
      end

      def apply(cs_delta)
        return if cs_delta.zero?

        return unless @packet.total_length >= @packet.l4_start + 8
        bytes = @packet.l4_bytes
        l4_start = @packet.l4_bytes_offset

        checksum = string_get16be(bytes, l4_start + 6)
        return if checksum == 0

        checksum = 0 if checksum == 65535
        checksum = _adjust_checksum(checksum, cs_delta)
        checksum = 65535 if checksum == 0

        string_set16be(bytes, l4_start + 6, checksum)
      end
    end
  end
end


