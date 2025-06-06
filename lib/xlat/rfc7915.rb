# frozen_string_literal: true

require 'xlat/common'

module Xlat
  # RFC 7915 based stateless IPv4/IPv6 translator (SIIT). Intentionally not thread-safe.
  #
  # https://datatracker.ietf.org/doc/html/rfc7915
  # https://www.rfc-editor.org/info/rfc7915
  class Rfc7915
    extend Xlat::Common
    include Xlat::Common

    class BufferInUse < StandardError; end

    MAX_FRAGMENT_ID = 0xffffffff

    # @param source_address_translator [Xlat::AddressTranslation]
    # @param destination_address_translator [Xlat::AddressTranslation]
    def initialize(source_address_translator:, destination_address_translator:, for_icmp: false)
      @source_address_translator = source_address_translator
      @destination_address_translator = destination_address_translator

      # checksum_neutrality = @source_address_translator.checksum_neutral? && @destination_address_translator.checksum_neutral?

      @next_fragment_identifier = 0

      @ipv4_new_header_buffer = IO::Buffer.new(20)
      @ipv6_new_header_buffer = IO::Buffer.new(40)
      @ipv6_fragment_header_buffer = IO::Buffer.new(8)
      @output = []
      @new_header_buffer_in_use = false
      return_buffer_ownership

      unless for_icmp
        @inner_icmp = self.class.new(source_address_translator: destination_address_translator, destination_address_translator: source_address_translator, for_icmp: true)
        @inner_packet = Protocols::Ip.new(icmp_payload: true)
      end
    end

    attr_reader :next_fragment_identifier

    def next_fragment_identifier=(x)
      @inner_icmp&.next_fragment_identifier = x
      @next_fragment_identifier = x
    end

    # Returns array of bytestrings to send as a IPv4 packet. May update original packet content.
    def translate_to_ipv4(ipv6_packet, max_length)
      raise BufferInUse if @new_header_buffer_in_use
      raise ArgumentError unless ipv6_packet.version.to_i == 6
      icmp_payload = @inner_icmp.nil?
      @new_header_buffer_in_use = true
      new_header_buffer = @ipv4_new_header_buffer
      ipv6_bytes = ipv6_packet.bytes
      ipv6_bytes_offset = ipv6_packet.bytes_offset

      cs_delta = 0 # delta for incremental update of upper-layer checksum fields

      # Version = 4, IHL = 5
      new_header_buffer.set_value(:U8, 0, (4 << 4) + 5)

      # FIXME: ToS ignored

      # Total Length = copy from IPv6; may be updated in later step
      ipv4_length = ipv6_packet.l4_length + 20
      # not considering as a checksum delta because upper layer packet length doesn't take this into account; cs_delta += ipv6_length - ipv4_length
      new_header_buffer.set_value(:U16, 2, ipv4_length)

      ipv6_proto = ipv6_packet.proto

      # Flags and fragment offset
      # reserved: 1, DF: 1, MF: 1, offset: 13
      if fragment_offset = ipv6_packet.fragment_offset
        if ipv6_proto == 58 # icmpv6
          # TODO: what if an ICMPv6 packet is fragmented?
          return return_buffer_ownership()
        end

        # Identification = copy
        identification = ipv6_packet.identification

        # DF: zero
        # MF: copy
        # offset: copy
        mf = ipv6_packet.more_fragments ? 1 : 0
        flags_offset = (mf << 13) | fragment_offset
      else
        # Identification = generate
        identification = make_fragment_id()

        # DF: set to zero if length(translated ipv4 packet) <= 1260; otherwise set to one
        # MF: zero
        # offset: 0
        df = ipv4_length <= 1260 ? 0 : 1
        flags_offset = (df << 14)
      end

      new_header_buffer.set_value(:U16, 4, identification)
      new_header_buffer.set_value(:U16, 6, flags_offset)


      # TTL = copy from IPv6
      new_header_buffer.set_value(:U8, 8, ipv6_bytes.get_value(:U8, ipv6_bytes_offset + 7))

      # Protocol = copy from IPv6; may be updated in later step for ICMPv6=>4 conversion
      new_header_buffer.set_value(:U8, 9, ipv6_proto)

      # Source and Destination address
      cs_delta_a = @source_address_translator.translate_address_to_ipv4(ipv6_bytes.slice(ipv6_bytes_offset + 8,16), new_header_buffer, 12) or return return_buffer_ownership()
      cs_delta_b = @destination_address_translator.translate_address_to_ipv4(ipv6_bytes.slice(ipv6_bytes_offset + 24,16), new_header_buffer, 16) or return return_buffer_ownership()
      cs_delta += cs_delta_a + cs_delta_b

      # TODO: DF bit
      # TODO: discard if expired source route option is present

      if ipv6_proto == 58 # icmpv6
        icmp_result, icmp_output = translate_icmpv6_to_icmpv4(ipv6_packet, new_header_buffer, max_length - 20)
        return return_buffer_ownership() unless icmp_result
        cs_delta += icmp_result
      end

      unless icmp_output
        l4_length = ipv6_packet.l4_bytes_length
        if 20 + l4_length > max_length
          if icmp_payload
            # If icmp_output.nil?, ICMP payload is not structured (RFC4884), thus simply truncatable
            l4_length = max_length - 20
          else
            # FIXME: this should not happen, as L3 header decreases in size
            return return_buffer_ownership()
          end
        end
      end

      #p ipv6_bytes.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
      #p new_header_buffer.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')

      ipv4_packet = ipv6_packet.convert_version!(Protocols::Ip::Ipv4, new_header_buffer, cs_delta)
      ipv4_packet.apply_changes

      # Recompute checksum (this must be performed after Ip#apply_changes as it updates ipv4 checksum field along with l4 checksum field using delta,
      # while new_header_buffer has no prior checksum value)
      new_header_buffer.set_value(:U16, 10, 0)
      cksum = Protocols::Ip.checksum(new_header_buffer)
      new_header_buffer.set_value(:U16, 10, cksum)

      # TODO: Section 5.4. Generation of ICMPv6 Error Messages
      # TODO: Section 5.1.1. IPv6 Fragment Processing

      @output << new_header_buffer
      if icmp_output
        @output.concat(icmp_output)
      else
        @output << ipv4_packet.l4_bytes.slice(ipv4_packet.l4_bytes_offset, l4_length)
      end
      @output
    end

    # Returns array of bytestrings to send as a IPv6 packet. May update original packet content.
    def translate_to_ipv6(ipv4_packet, max_length)
      raise BufferInUse if @new_header_buffer_in_use
      raise ArgumentError unless ipv4_packet.version.to_i == 4
      icmp_payload = @inner_icmp.nil?
      # TODO: support fragment extension and esp
      # TODO: ignore extension
      @new_header_buffer_in_use = true
      ipv4_bytes = ipv4_packet.bytes
      ipv4_bytes_offset = ipv4_packet.bytes_offset
      new_header_buffer = @ipv6_new_header_buffer
      cs_delta = 0 # delta for incremental update of upper-layer checksum fields

      # Version = 6, traffic class = 0
      new_header_buffer.set_value(:U8, 0, 6 << 4)

      # Flow label = 0

      # IPv6 Length = IPv4 total length - IPv4 header length; may be updated in later step
      ipv6_length = ipv4_packet.l4_length

      ipv4_proto = ipv4_packet.proto

      if fragment_offset = ipv4_packet.fragment_offset
        if ipv4_proto == 1 # icmpv4
          # TODO: what if an ICMPv4 packet is fragmented?
          return return_buffer_ownership()
        end

        fragment_header = @ipv6_fragment_header_buffer

        # next header = copy from IPv4
        fragment_header.set_value(:U8, 0, ipv4_proto)

        # reserved = zero; just leave it as it is never set
        # fragment_header.set_value(:U8, 1, 0)

        # Fragment offset and flags = copy from IPv4
        offset_flags = (fragment_offset << 3) | (ipv4_packet.more_fragments ? 1 : 0)
        fragment_header.set_value(:U16, 2, offset_flags)

        # identification = copy from IPv4; upper 16 bits are zero (never set)
        fragment_header.set_value(:U16, 6, ipv4_packet.identification)

        # IPv6 payload length contains the fragment header
        ipv6_length += 8
        # Next Header = ipv6-frag
        ipv6_nexthdr = 44

        max_length -= 8  # fragment header
      else  # non-fragments
        # Next Header = copy from IPv4; may be updated in later step for ICMPv6=>4 conversion
        ipv6_nexthdr = ipv4_proto
      end

      # not considering as a checksum delta because upper layer packet length doesn't take this into account; cs_delta += ipv4_length - ipv6_length
      new_header_buffer.set_value(:U16, 4, ipv6_length)
      new_header_buffer.set_value(:U8, 6, ipv6_nexthdr)

      # Hop limit = copy from IPv4
      new_header_buffer.set_value(:U8, 7, ipv4_bytes.get_value(:U8, ipv4_bytes_offset + 8))

      # Source and Destination address
      cs_delta_a = @destination_address_translator.translate_address_to_ipv6(ipv4_bytes.slice(ipv4_bytes_offset + 12,4), new_header_buffer, 8) or return return_buffer_ownership()
      cs_delta_b = @source_address_translator.translate_address_to_ipv6(ipv4_bytes.slice(ipv4_bytes_offset + 16,4), new_header_buffer, 24) or return return_buffer_ownership()
      cs_delta += cs_delta_a + cs_delta_b

      if ipv4_proto == 1
        icmp_result, icmp_output = translate_icmpv4_to_icmpv6(ipv4_packet, new_header_buffer, max_length - 40)
        return return_buffer_ownership() unless icmp_result
        cs_delta += icmp_result
      end

      unless icmp_output
        l4_length = ipv4_packet.l4_bytes_length
        if 40 + l4_length > max_length
          if icmp_payload
            # If icmp_output.nil?, ICMP payload is not structured (RFC4884), thus simply truncatable
            l4_length = max_length - 40
          else
            # FIXME: generate "fragmentation needed" if DF=1
            return return_buffer_ownership()
          end
        end
      end

      # TODO: generate udp checksum option (section 4.5.)
      ipv6_packet = ipv4_packet.convert_version!(Protocols::Ip::Ipv6, new_header_buffer, cs_delta)
      ipv6_packet.apply_changes

      # TODO: Section 4.4.  Generation of ICMPv4 Error Message

      @output << new_header_buffer
      @output << fragment_header if fragment_header
      if icmp_output
        @output.concat(icmp_output)
      else
        @output << ipv6_packet.l4_bytes.slice(ipv6_packet.l4_bytes_offset, l4_length)
      end
      @output
    end

    def return_buffer_ownership
      @new_header_buffer_in_use = false
      @ipv4_new_header_buffer.clear
      @ipv6_new_header_buffer.clear
      @output.clear
      if @inner_icmp
        @inner_icmp.return_buffer_ownership
      end
      nil
    end

    private def make_fragment_id
      id = @next_fragment_identifier
      @next_fragment_identifier = @next_fragment_identifier.succ & MAX_FRAGMENT_ID
      id
    end

    gen_type_map = ->(h) do
      ary = Array.new(0xff.succ)
      h.each_key do |(type,_)|
        tary = ary[type] = Array.new(0xff.succ.succ)
        h.each do |(type2,code),res|
          next unless type == type2
          tary[code || 0x100] = res
        end
        tary.freeze
      end
      Ractor.make_shareable(ary)
    end

    gen_pointer_map = ->(h) do
      ary = Array.new(40)
      h.each do |from_,to|
        from = from_.is_a?(Integer) ? from_..from_ : from_
        from.each do |f|
          ary[f] = to
        end
      end
      Ractor.make_shareable(ary)
    end

    ICMPV6V4_TYPE_MAP = gen_type_map[{
      [1,0] => [3,1,:error_payload_rfc4884], # destination unreachable, no route to destination
      [1,1] => [3,10,:error_payload_rfc4884], # destination unreachable, admin prohibited
      [1,2] => [3,1,:error_payload_rfc4884], # destination unreachable, beyond scope of source address
      [1,3] => [3,1,:error_payload_rfc4884], # destination unreachable, address unreachable
      [1,4] => [3,3,:error_payload_rfc4884], # destination unreachable, port unreachable

      [2,nil] => [3,4,:mtu], # packet too big

      [3,nil] => [11,nil,:error_payload_rfc4884], # time exceeded (code unchanged)

      [4,0] => [12,0,:pointer],  # parameter problem, err header field
      [4,1] => [3,2,:error_payload], # parameter problem, unrecognised next header type

      [128,0] => [8,0], # echo request
      [129,0] => [0,0], # echo reply
    }]

    # https://datatracker.ietf.org/doc/html/rfc7915#section-5.2 Figure 6
    ICMPV6_POINTER_MAP = gen_pointer_map[{
      0 => 0,
      1 => 1,
      4 => 2,
      5 => 2,
      6 => 9,
      7 => 8,
      8..23 => 12,
      24..39 => 16,
    }]

    ICMPV4V6_TYPE_MAP = gen_type_map[{
      [0,nil] => [129,0], # echo
      [8,nil] => [128,0], # echo reply
      [3,0] => [1,0,:error_payload_rfc4884], # destination unreachable, net unreachable
      [3,1] => [1,1,:error_payload_rfc4884], # destination unreachable, host unreachable
      [3,2] => [4,1,:pointer_static_next_header], # destination unreachable, protocol unreachable
      [3,3] => [1,4,:error_payload_rfc4884], # destination unreachable, port unreachable
      [3,4] => [2,0,:mtu], # destination unreachable, fragmentation needed
      [3,5] => [1,0,:error_payload_rfc4884], # destination unreachable, source route failed
      [3,6] => [1,0,:error_payload_rfc4884], # destination unreachable, ?
      [3,7] => [1,0,:error_payload_rfc4884], # destination unreachable, ?
      [3,8] => [1,0,:error_payload_rfc4884], # destination unreachable, ?
      [3,9] => [1,1,:error_payload_rfc4884], # destination unreachable, host admin prohibited
      [3,10] => [1,1,:error_payload_rfc4884], # destination unreachable, host admin prohibited
      [3,11] => [1,0,:error_payload_rfc4884], # destination unreachable, ?
      [3,12] => [1,0,:error_payload_rfc4884], # destination unreachable, ?
      [3,13] => [1,1,:error_payload_rfc4884], # destination unreachable, admin prohibited
      [3,15] => [1,1,:error_payload_rfc4884], # destination unreachable, precedence cutoff in effect
      [11,nil] => [3,nil,:error_payload_rfc4884], # time exceeded
      [12,0] => [4,0,:pointer], # parameter problem, pointer indicates the error
      [12,2] => [4,0,:pointer], # parameter problem, bad length
    }]

    # https://datatracker.ietf.org/doc/html/rfc7915#section-5.2 Figure 6
    ICMPV4_POINTER_MAP = gen_pointer_map[{
      0 => 0,
      1 => 1,
      2..3 => 4,
      8 => 7,
      9 => 6,
      12..15 => 8,
      16..19 => 24,
    }]

    private def translate_icmpv6_to_icmpv4(ipv6_packet, new_header_buffer, max_length)
      icmpv6 = ipv6_packet.l4
      return unless icmpv6
      outer_cs_delta = 0
      cs_delta = 0

      code_handlers = ICMPV6V4_TYPE_MAP[icmpv6.type]
      return unless code_handlers
      type_handler = code_handlers[icmpv6.code] || code_handlers[0x100]
      return unless type_handler
      new_type,new_code,payload_handler = type_handler

      l4_bytes = ipv6_packet.l4_bytes
      l4_bytes_offset = ipv6_packet.l4_bytes_offset

      #p l4: [l4_bytes[l4_bytes_offset..]].join.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')

      cs_delta += (new_type - icmpv6.type) * 256
      l4_bytes.set_value(:U8, l4_bytes_offset, new_type)
      if new_code
        cs_delta += (new_code - icmpv6.code)
        l4_bytes.set_value(:U8, l4_bytes_offset+1, new_code)
      end

      #p l4: [l4_bytes[l4_bytes_offset..]].join.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')

      translate_payload = false
      l4_length_changed = false

      case payload_handler
      when nil
        # do nothing
      when :error_payload
        translate_payload = true
      when :error_payload_rfc4884
        translate_payload = :error_payload_rfc4884
      when :mtu
        translate_payload = true
        # the header will be updated after translating the payload
      when :pointer
        translate_payload = true
        ptr = l4_bytes.get_value(:U8, l4_bytes_offset+7)
        newptr = ICMPV6_POINTER_MAP[ptr]
        return unless newptr
        l4_bytes.set_value(:U8, l4_bytes_offset+4,newptr)
        l4_bytes.set_value(:U8, l4_bytes_offset+5,0)
        l4_bytes.set_value(:U8, l4_bytes_offset+6,0)
        l4_bytes.set_value(:U8, l4_bytes_offset+7,0)
      else
        raise
      end

      if translate_payload
        return unless @inner_icmp  # Do not translate payload in nested ICMP

        payload_bytes = icmpv6.payload_bytes
        payload_bytes_offset = icmpv6.payload_bytes_offset
        payload_bytes_length = icmpv6.payload_bytes_length

        if translate_payload == :error_payload_rfc4884
          original_datagram_length = l4_bytes.get_value(:U8, l4_bytes_offset+4) * 8
          return unless original_datagram_length < payload_bytes_length
          rfc4884 = original_datagram_length > 0
        end

        original_datagram = @inner_packet.parse(
          bytes: payload_bytes,
          bytes_offset: payload_bytes_offset,
          bytes_length: rfc4884 ? original_datagram_length : payload_bytes_length,
        )
        return unless original_datagram && original_datagram.version.to_i == 6

        max_length -= 8  # ICMPv4 header
        original_datagram_translated = @inner_icmp.translate_to_ipv4(original_datagram, [max_length, 512].min)
        return unless original_datagram_translated

        output = [l4_bytes.slice(l4_bytes_offset, 8), *original_datagram_translated]

        if rfc4884
          translated_length = original_datagram_translated.sum(&:size)

          if translated_length < 128
            # RFC 4884: the "original datagram" field MUST contain at least 128 octets.
            padding_length = 128 - translated_length
            new_original_datagram_length = 128
          else
            # RFC 4884: the "original datagram" field MUST be zero padded to the nearest 32-bit boundary.
            new_original_datagram_length = 4 * translated_length.ceildiv(4)
            padding_length = new_original_datagram_length - translated_length
          end
          output << IO::Buffer.new(padding_length) if padding_length > 0

          max_length -= new_original_datagram_length
          extension = payload_bytes.slice(payload_bytes_offset + original_datagram_length, [payload_bytes_length - original_datagram_length, max_length].min)
          output << extension

          l4_bytes.set_value(:U8, l4_bytes_offset + 4, 0)  # Reserved
          l4_bytes.set_value(:U8, l4_bytes_offset + 5, new_original_datagram_length / 4)
        end

        l4_length_changed = output.sum(&:size)

        if payload_handler == :mtu
          # https://datatracker.ietf.org/doc/html/rfc1191#section-4
          ipv6_mtu = l4_bytes.get_value(:U32, l4_bytes_offset+4)
          ipv4_mtu = ipv6_mtu - 20
          ipv4_mtu -= 8 if original_datagram.fragment_offset  # For Fragment EH
          ipv4_mtu = 0xFFFF if ipv4_mtu > 0xFFFF  # IPv4 MTU is 16-bit field

          l4_bytes.set_value(:U16, l4_bytes_offset+4, 0)  # TODO: RFC4884 "original datagram" length
          l4_bytes.set_value(:U16, l4_bytes_offset+6, ipv4_mtu)
        end

        # Force recalculation of ICMP checksum
        l4_bytes.set_value(:U16, l4_bytes_offset+2,0)
        cksum = output ? Protocols::Ip.checksum_list(output) : Protocols::Ip.checksum(l4_bytes.slice(l4_bytes_offset))
        l4_bytes.set_value(:U16, l4_bytes_offset+2, cksum)
      else
        # For incremental checksum update, remove pseudo header from ICMP checksum
        cs_delta -= sum16be(ipv6_packet.tuple) + ipv6_packet.l4_length + 58

        checksum = l4_bytes.get_value(:U16, l4_bytes_offset+2)
        checksum = Protocols::Ip.checksum_adjust(checksum, cs_delta)
        checksum = 65535 if checksum == 0
        checksum = l4_bytes.set_value(:U16, l4_bytes_offset+2, checksum)
      end

      ### NOTE: this method must not return nil beyond this line - altering outer l3 header ###

      if l4_length_changed
        # Update Outer IPv4 Total Length Field
        new_total_length = 20+l4_length_changed
        #p act: [new_header_buffer.size,l4_bytes[l4_bytes_offset..].size].sum, new_total_length:, present_total_length: string_get16be(new_header_buffer,2)
        outer_cs_delta += new_total_length - new_header_buffer.get_value(:U16, 2)
        new_header_buffer.set_value(:U16, 2,new_total_length)
      end

      new_header_buffer.set_value(:U8, 9, 1) # protocol=icmpv4
      outer_cs_delta += -57 # 58(icmpv6)-1(icmpv4)

      #p l4: [l4_bytes[l4_bytes_offset..]].join.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
      [outer_cs_delta, output]
    end

    private def translate_icmpv4_to_icmpv6(ipv4_packet, new_header_buffer, max_length)
      icmpv4 = ipv4_packet.l4
      return unless icmpv4
      outer_cs_delta = 0
      cs_delta = 0

      code_handlers = ICMPV4V6_TYPE_MAP[icmpv4.type]
      return unless code_handlers
      type_handler = code_handlers[icmpv4.code] || code_handlers[0x100]
      return unless type_handler
      new_type,new_code,payload_handler = type_handler

      l4_bytes = ipv4_packet.l4_bytes
      l4_bytes_offset = ipv4_packet.l4_bytes_offset


      cs_delta += (new_type - icmpv4.type) * 256
      l4_bytes.set_value(:U8, l4_bytes_offset, new_type)
      if new_code
        cs_delta += (new_code - icmpv4.code)
        l4_bytes.set_value(:U8, l4_bytes_offset+1, new_code)
      end

      #p l4: [l4_bytes[l4_bytes_offset..]].join.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')

      translate_payload = false
      l4_length_changed = false

      case payload_handler
      when nil
        # do nothing
      when :error_payload
        translate_payload = true
      when :error_payload_rfc4884
        translate_payload = :error_payload_rfc4884
      when :mtu
        translate_payload = true  # TODO: ICMPv4 Fragmentation Needed can convey RFC4884 extensions
        # the header will be updated after translating the payload
      when :pointer, :pointer_static_next_header
        translate_payload = true
        ptr = l4_bytes.get_value(:U8, l4_bytes_offset+4)

        newptr = case
        when newptr == :pointer_static_next_header
          6 # Next Header
        else
          ICMPV4_POINTER_MAP[ptr]
        end
        return unless newptr
        l4_bytes.set_value(:U16, l4_bytes_offset+4,0)
        l4_bytes.set_value(:U16, l4_bytes_offset+6,newptr)

      else
        raise
      end

      if translate_payload
        return unless @inner_icmp  # Do not translate payload in nested ICMP

        payload_bytes = icmpv4.payload_bytes
        payload_bytes_offset = icmpv4.payload_bytes_offset
        payload_bytes_length = icmpv4.payload_bytes_length

        if translate_payload == :error_payload_rfc4884
          original_datagram_length = l4_bytes.get_value(:U8, l4_bytes_offset+5) * 4
          return unless original_datagram_length < payload_bytes_length
          rfc4884 = original_datagram_length > 0
        end

        original_datagram = @inner_packet.parse(
          bytes: payload_bytes,
          bytes_offset: payload_bytes_offset,
          bytes_length: rfc4884 ? original_datagram_length : payload_bytes_length,
        )
        return unless original_datagram && original_datagram.version.to_i == 4

        max_length -= 8  # ICMPv6 header
        original_datagram_translated = original_datagram && @inner_icmp.translate_to_ipv6(original_datagram, [max_length, 1200].min)
        return unless original_datagram_translated

        output = [l4_bytes.slice(l4_bytes_offset, 8), *original_datagram_translated]

        if rfc4884
          translated_length = original_datagram_translated.sum(&:size)

          # RFC 4884: the "original datagram" field MUST be zero padded to the nearest 64-bit boundary.
          new_original_datagram_length = 8 * translated_length.ceildiv(8)
          padding_length = new_original_datagram_length - translated_length
          output << IO::Buffer.new(padding_length) if padding_length > 0

          max_length -= new_original_datagram_length
          extension = payload_bytes.slice(payload_bytes_offset + original_datagram_length, [payload_bytes_length - original_datagram_length, max_length].min)
          output << extension

          l4_bytes.set_value(:U8, l4_bytes_offset + 4, new_original_datagram_length / 8)
          l4_bytes.set_value(:U8, l4_bytes_offset + 5, 0)  # Reserved
        end

        l4_length_changed = output.sum(&:size)

        if payload_handler == :mtu
          # https://datatracker.ietf.org/doc/html/rfc1191#section-4
          # IPv4 MTU may be zero, which is translated to IPv6 MTU 1280 anyway.
          ipv4_mtu = l4_bytes.get_value(:U16, l4_bytes_offset+6)
          ipv6_mtu = ipv4_mtu + 20
          ipv6_mtu = 1280 if ipv6_mtu < 1280  # IPv6 minimum MTU

          l4_bytes.set_value(:U32, l4_bytes_offset+4, ipv6_mtu)
        end

        # Force recalculation of ICMP checksum
        l4_bytes.set_value(:U16, l4_bytes_offset+2,0)
        cksum = Protocols::Ip.checksum_list(output)
        l4_bytes.set_value(:U16, l4_bytes_offset+2, cksum)
        cksum = Protocols::Ip.checksum_adjust(cksum, Common.sum16be(new_header_buffer.slice(8,32)) + l4_length_changed + 58) # pseudo header
        l4_bytes.set_value(:U16, l4_bytes_offset+2, cksum)

      else
        # For incremental checksum update, ADD pseudo header to ICMP checksum
        # [8,32] = src+dst addr
        cs_delta += Common.sum16be(new_header_buffer.slice(8,32)) + ipv4_packet.l4_length + 58

        checksum = l4_bytes.get_value(:U16, l4_bytes_offset+2)
        checksum = Protocols::Ip.checksum_adjust(checksum, cs_delta)
        checksum = 65535 if checksum == 0
        checksum = l4_bytes.set_value(:U16, l4_bytes_offset+2, checksum)
      end


      ### NOTE: this method must not return nil beyond this line - altering outer l3 header ###

      if l4_length_changed
        # Update Outer IPv6 Payload Length field
        new_payload_length = l4_length_changed
        outer_cs_delta += new_payload_length - new_header_buffer.get_value(:U16,4)
        new_header_buffer.set_value(:U16,4,new_payload_length)
      end

      new_header_buffer.set_value(:U8, 6, 58) # nextheader=icmpv4
      outer_cs_delta += 57 # 58(icmpv6)-1(icmpv4)

      #p l4: [l4_bytes[l4_bytes_offset..]].join.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
      [outer_cs_delta, output]
    end

  end
end
