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
      class Echo < Base
        V4_TYPE_REQUEST = 8
        V4_TYPE_REPLY = 0
        V6_TYPE_REQUEST = 128
        V6_TYPE_REPLY = 129

        attr_accessor :src_port, :dest_port

        def initialize(packet, is_req)
          super(packet)
          @is_req = is_req
        end

        def _parse
          super

          port = @packet.bytes.get_value(:U16, @packet.l4_start + 4)
          if @is_req
            @src_port = port
            @dest_port = 0
          else
            @src_port = 0
            @dest_port = port
          end

          self
        end

        def tuple
          [src_port, dest_port].pack('n*')
        end

        def apply(cs_delta)
          #string_set16be(@packet.bytes,@packet.l4_start + 4, @is_req ? @src_port : @dest_port)
          #Base.recalculate_checksum(@packet)
        end
      end
    end
  end
end


