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
    IPV4_NULL_BUFFER = ("\x00".b * 20).freeze
    IPV6_NULL_BUFFER = ("\x00".b * 40).freeze
    EMPTY = ''.b.freeze

    # @param source_address_translator [Xlat::AddressTranslation]
    # @param destination_address_translator [Xlat::AddressTranslation]
    def initialize(source_address_translator:, destination_address_translator:, for_icmp: false)
      @source_address_translator = source_address_translator
      @destination_address_translator = destination_address_translator

      # checksum_neutrality = @source_address_translator.checksum_neutral? && @destination_address_translator.checksum_neutral?

      @next_fragment_identifier = 0

      @ipv4_new_header_buffer = IO::Buffer.new(20)
      @ipv6_new_header_buffer = IO::Buffer.new(40)
      @output = []
      @new_header_buffer_in_use = false
      return_buffer_ownership

      @inner_icmp = for_icmp ? nil : self.class.new(source_address_translator:, destination_address_translator:, for_icmp: true)
    end

    attr_reader :next_fragment_identifier

    def next_fragment_identifier=(x)
      @inner_icmp&.next_fragment_identifier = x
      @next_fragment_identifier = x
    end

    # Returns array of bytestrings to send as a IPv4 packet. May update original packet content.
    def translate_to_ipv4(ipv6_packet)
      raise BufferInUse if @new_header_buffer_in_use
      raise ArgumentError unless ipv6_packet.version.to_i == 6
      icmp_payload = @inner_icmp.nil?
      @new_header_buffer_in_use = true
      new_header_buffer = @ipv4_new_header_buffer
      ipv6_bytes = ipv6_packet.bytes

      cs_delta = 0 # delta for incremental update of upper-layer checksum fields

      # Version = 4, IHL = 5
      new_header_buffer.set_value(:U8, 0, (4 << 4) + 5)

      # FIXME: ToS ignored

      # Total Length = copy from IPv6; may be updated in later step
      ipv6_length = ipv6_bytes.get_value(:U16, 4)
      ipv4_length = ipv6_length + 20
      # not considering as a checksum delta because upper layer packet length doesn't take this into account; cs_delta += ipv6_length - ipv4_length
      new_header_buffer.set_value(:U16, 2, ipv4_length)

      # Identification = generate
      new_header_buffer.set_value(:U16, 4, make_fragment_id())

      # TTL = copy from IPv6
      new_header_buffer.set_value(:U8, 8, ipv6_bytes.get_value(:U8, 7))

      # Protocol = copy from IPv6; may be updated in later step for ICMPv6=>4 conversion
      new_header_buffer.set_value(:U8, 9, ipv6_packet.proto)

      # Source and Destination address
      cs_delta_a = @source_address_translator.translate_address_to_ipv4(ipv6_bytes.slice(8,16), new_header_buffer, 12) or return return_buffer_ownership()
      cs_delta_b = @destination_address_translator.translate_address_to_ipv4(ipv6_bytes.slice(24,16), new_header_buffer, 16) or return return_buffer_ownership()
      cs_delta += cs_delta_a + cs_delta_b

      # TODO: DF bit

      if !icmp_payload && ipv6_packet.proto == 58 # icmpv6
        icmp_result, icmp_output = translate_icmpv6_to_icmpv4(ipv6_packet, new_header_buffer)
        return return_buffer_ownership() unless icmp_result
        cs_delta += icmp_result
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
        @output << ipv4_packet.l4_bytes.slice(ipv4_packet.l4_bytes_offset)
      end
      @output
    end

    # Returns array of bytestrings to send as a IPv6 packet. May update original packet content.
    def translate_to_ipv6(ipv4_packet)
      raise BufferInUse if @new_header_buffer_in_use
      raise ArgumentError unless ipv4_packet.version.to_i == 4
      icmp_payload = @inner_icmp.nil?
      # TODO: support fragment extension and esp
      # TODO: ignore extension
      @new_header_buffer_in_use = true
      ipv4_bytes = ipv4_packet.bytes
      new_header_buffer = @ipv6_new_header_buffer
      cs_delta = 0 # delta for incremental update of upper-layer checksum fields

      # Version = 6, traffic class = 0
      new_header_buffer.set_value(:U8, 0, 6 << 4)

      # Flow label = 0

      # Total Length = copy from IPv4; may be updated in later step
      ipv4_length = ipv4_bytes.get_value(:U16, 2)
      ipv6_length = ipv4_length - 20
      # not considering as a checksum delta because upper layer packet length doesn't take this into account; cs_delta += ipv4_length - ipv6_length
      new_header_buffer.set_value(:U16, 4, ipv6_length)

      # Next Header = copy from IPv4; may be updated in later step for ICMPv6=>4 conversion
      new_header_buffer.set_value(:U8, 6, ipv4_packet.proto)

      # Hop limit = copy from IPv4
      new_header_buffer.set_value(:U8, 7, ipv4_bytes.get_value(:U8, 8))

      # Source and Destination address
      cs_delta_a = @destination_address_translator.translate_address_to_ipv6(ipv4_bytes.slice(12,4), new_header_buffer, 8) or return return_buffer_ownership()
      cs_delta_b = @source_address_translator.translate_address_to_ipv6(ipv4_bytes.slice(16,4), new_header_buffer, 24) or return return_buffer_ownership()
      cs_delta += cs_delta_a + cs_delta_b

      if !icmp_payload && ipv4_packet.proto == 1 # icmpv4
        icmp_result, icmp_output = translate_icmpv4_to_icmpv6(ipv4_packet, new_header_buffer)
        return return_buffer_ownership() unless icmp_result
        cs_delta += icmp_result
      end

      # TODO: generate udp checksum option (section 4.5.)
      # TODO: ICMPv4 => ICMPv6
      ipv6_packet = ipv4_packet.convert_version!(Protocols::Ip::Ipv6, new_header_buffer, cs_delta)
      ipv6_packet.apply_changes

      # TODO: Section 4.4.  Generation of ICMPv4 Error Message

      @output << new_header_buffer
      if icmp_output
        @output.concat(icmp_output)
      else
        @output << ipv6_packet.l4_bytes.slice(ipv6_packet.l4_bytes_offset)
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
      ary.freeze
    end

    gen_pointer_map = ->(h) do
      ary = Array.new(40)
      h.each do |from_,to|
        from = from_.is_a?(Integer) ? from_..from_ : from_
        from.each do |f|
          ary[f] = to
        end
      end
      ary.freeze
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

    private def translate_icmpv6_to_icmpv4(ipv6_packet, new_header_buffer)
      raise unless @inner_icmp
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
        # https://datatracker.ietf.org/doc/html/rfc1191#section-4
        mtu = l4_bytes.get_value(:U16, l4_bytes_offset+6)
        l4_bytes.set_value(:U16, l4_bytes_offset+4, 0)
        l4_bytes.set_value(:U16, l4_bytes_offset+6,mtu-20) # FIXME: not complete implementation
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
        payload_offset = l4_bytes_offset+8
        payload = Xlat::Protocols::Ip.new(icmp_payload: true).parse(bytes: l4_bytes.slice(payload_offset))
        payload_translated = payload && @inner_icmp.translate_to_ipv4(payload)
        if payload_translated
          output = [
            l4_bytes.slice(l4_bytes_offset, 8),
            payload_translated[0],
            payload_translated[1].slice(0,[payload_translated[1].size,500].min) # FIXME: more appropriate length limit
          ]

          l4_length_changed = output.map(&:size).sum
          if translate_payload == :error_payload_rfc4884 && l4_bytes.get_value(:U8, l4_bytes_offset+4) > 0
            l4_bytes.set_value(:U8, l4_bytes_offset+4, 0)
            l4_bytes.set_value(:U8, l4_bytes_offset+5, l4_length_changed-8)
          end
        end

        # Force recalculation of ICMP checksum
        l4_bytes.set_value(:U16, l4_bytes_offset+2,0)
        cksum = output ? Protocols::Ip.checksum_list(output) : Protocols::Ip.checksum(l4_bytes.slice(l4_bytes_offset))
        l4_bytes.set_value(:U16, l4_bytes_offset+2, cksum)

      else
        # For incremental checksum update, remove pseudo header from ICMP checksum
        upper_layer_packet_length = l4_bytes.size - l4_bytes_offset
        cs_delta -= sum16be(ipv6_packet.tuple) + upper_layer_packet_length + 58

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

    private def translate_icmpv4_to_icmpv6(ipv4_packet, new_header_buffer)
      raise unless @inner_icmp
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
        translate_payload = true
        # https://datatracker.ietf.org/doc/html/rfc1191#section-4
        mtu = l4_bytes.get_value(:U16, l4_bytes_offset+6)
        l4_bytes.set_value(:U16, l4_bytes_offset+4,0)
        new_mtu = mtu+20 # FIXME: not complete implementation
        new_mtu = 1280 if mtu < 1280
        l4_bytes.set_value(:U16, l4_bytes_offset+6,new_mtu)

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
        payload_offset = l4_bytes_offset+8
        payload = Xlat::Protocols::Ip.new(icmp_payload: true).parse(bytes: l4_bytes.slice(payload_offset))
        # TODO: protocol version verification
        payload_translated = payload && @inner_icmp.translate_to_ipv6(payload)
        if payload_translated
          output = [
            l4_bytes.slice(l4_bytes_offset, 8),
            payload_translated[0],
            payload_translated[1].slice(0,[payload_translated[1].size,500].min) # FIXME: more appropriate length limit
          ]

          l4_length_changed = output.map(&:size).sum
          if translate_payload == :error_payload_rfc4884 && l4_bytes.get_value(:U8, l4_bytes_offset+5) > 0
            l4_bytes.set_value(:U8, l4_bytes_offset+4, l4_length_changed-8)
            l4_bytes.set_value(:U8, l4_bytes_offset+5, 0)
          end
        end

        # Force recalculation of ICMP checksum
        l4_bytes.set_value(:U16, l4_bytes_offset+2,0)
        cksum = output ? Protocols::Ip.checksum_list(output) : Protocols::Ip.checksum(l4_bytes.slice(l4_bytes_offset))
        l4_bytes.set_value(:U16, l4_bytes_offset+2, cksum)
        cksum = Protocols::Ip.checksum_adjust(cksum, Common.sum16be(new_header_buffer.slice(8,32)) + l4_length_changed + 58) # pseudo header
        l4_bytes.set_value(:U16, l4_bytes_offset+2, cksum)

      else
        # For incremental checksum update, ADD pseudo header to ICMP checksum
        upper_layer_packet_length = l4_bytes.size - l4_bytes_offset
        # [8,32] = src+dst addr
        cs_delta += Common.sum16be(new_header_buffer.slice(8,32)) + upper_layer_packet_length + 58

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
  
