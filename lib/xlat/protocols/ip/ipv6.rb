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
        # except Fragment (44), ESP (50), AH (51)
        EXTENSIONS = Ractor.make_shareable([0, 43, 60, 135, 139, 140, 253, 254].to_h { |id| [id, true] })

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

        def self.parse(packet, _b0)
          bytes = packet.bytes
          bytes_length = packet.bytes_length
          offset = packet.bytes_offset

          return false if bytes_length < 40

          payload_length = bytes.get_value(:U16, offset + 4)
          proto = bytes.get_value(:U8, offset + 6)

          # Minimum of the datagram length indicated by the IPv6 header,
          # and the length from the lower-layer protocol.
          # The datagram may be truncated or have some trailer.
          data_available = [40 + payload_length, bytes_length].min

          # [draft-ietf-6man-eh-limits-19] Section 4 suggests IPv6 nodes
          # to process at least 64 bytes long chain of EHs.
          extensions_length_limit = [payload_length, 64].min
          extensions_length = 0

          while EXTENSIONS[proto]
            extension_start = 40 + extensions_length
            return false if extension_start + 8 > data_available  # EH is at least 8 byte long

            proto = bytes.get_value(:U8, offset + extension_start)
            length = bytes.get_value(:U8, offset + extension_start + 1) * 8 + 8

            extensions_length += length
            return false if extensions_length > extensions_length_limit

            # TODO: Routing header
          end

          if proto == 44  # Fragment
            extension_start = 40 + extensions_length
            return false if extension_start + 8 > data_available

            offset_flags = bytes.get_value(:U16, offset + extension_start + 2)  # offset:13, reserved:2, M:1
            packet.fragment_offset = (offset_flags & 0xfff8) >> 3
            packet.more_fragments = (offset_flags & 0x0001) != 0
            packet.identification = bytes.get_value(:U16, offset + extension_start + 6)

            proto = bytes.get_value(:U8, offset + extension_start)
            extensions_length += 8  # Fragment EH is 8 bytes long
          end

          # We assume Fragment is at the last of EH chain.
          # AH has a non-standard EH format. It doesn't work with NAT anyway.
          if EXTENSIONS[proto] || proto == 44 || proto == 51  # 44=Fragment, 51=AH
            return false
          end

          # ESP is handled as L4 protocol

          return false unless packet.set_l4_region(40 + extensions_length, payload_length - extensions_length)
          packet.proto = proto

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


