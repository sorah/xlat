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


require_relative './base'

module Xlat
  module Protocols
    module Icmp
      class Error < Base
        V4_TYPE_DEST_UNREACH = 3
        V4_TYPE_TIME_EXCEEDED = 11
        V4_TYPE_PARAMETER_PROBLEM = 12

        V6_TYPE_DEST_UNREACH = 1
        V6_TYPE_PACKET_TOO_BIG = 2
        V6_TYPE_TIME_EXCEEDED = 3
        V6_TYPE_PARAMETER_PROBLEM = 4

        attr_accessor :payload_bytes
        attr_accessor :payload_bytes_offset

        def _parse
          super

          packet = @packet

          @payload_bytes = packet.l4_bytes
          @payload_bytes_offset = packet.l4_bytes_offset + 8

          self
        end

        def apply(cs_delta)
          # @original.apply

          # # overwrite packet image with orig packet being built
          # @packet.bytes[@packet.l4_start + 8..] = @original.bytes

          # Base.recalculate_checksum(@packet)
        end
      end
    end
  end
end

