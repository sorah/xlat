require 'spec_helper'
require 'ipaddr'
require 'xlat/rfc7915'
require 'xlat/protocols/ip'

RSpec.describe Xlat::Rfc7915 do
  module MockAddrTranslator
    def self.translate_address_to_ipv4(ipv6_address,buffer,offset = 0)
      case IPAddr.new_ntoh(ipv6_address).to_s
      when IPAddr.new('64:ff9b:1:fffe::192.0.2.2').to_s
        buffer[offset,4] = IPAddr.new('192.0.2.2').hton
        0
      when IPAddr.new('64:ff9b::192.0.2.3').to_s
        buffer[offset,4] = IPAddr.new('192.0.2.3').hton
        0
      when IPAddr.new('2001:db8:60::192.0.2.7').to_s
        buffer[offset,4] = IPAddr.new('192.0.2.7').hton
        -(0x2001 + 0x0db8 + 0x0060)
      when IPAddr.new('2001:db8:64::192.0.2.8').to_s
        buffer[offset,4] = IPAddr.new('192.0.2.8').hton
        -(0x2001 + 0x0db8 + 0x0064)

      end
    end

    def self.translate_address_to_ipv6(ipv4_address,buffer,offset = 0)
      case IPAddr.new_ntoh(ipv4_address).to_s
      when '192.0.2.2'
        buffer[offset,16] = IPAddr.new('64:ff9b:1:fffe::192.0.2.2').hton
        0
      when '192.0.2.3'
        buffer[offset,16] = IPAddr.new('64:ff9b::192.0.2.3').hton
        0
      when '192.0.2.7'
        buffer[offset,16] = IPAddr.new('2001:db8:60::192.0.2.7').hton
        (0x2001 + 0x0db8 + 0x0060)
      when '192.0.2.8'
        buffer[offset,16] = IPAddr.new('2001:db8:64::192.0.2.8').hton
        (0x2001 + 0x0db8 + 0x0064)
      end
    end
  end

  TEST_PACKET_IPV4_UDP = [
    # ipv4
    %w(45 00),
    %w(00 1d), # total length (20+8+1=29)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(11), # protocol
    %w(33 28), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(0b 3b), # checksum

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  TEST_PACKET_IPV6_UDP = [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 09), # payload length (8+1=9)
    %w(11), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst 

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(af 04), # checksum

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze



  TEST_PACKET_IPV4_TCP = [
    # ipv4
    %w(45 00),
    %w(00 35), # total length (20+32+1=53)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(06), # protocol
    %w(33 1b), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # tcp
    %w(c1 5b), # src port
    %w(00 50), # dst port
    %w(12 34 56 78), # sequence number
    %w(87 65 43 21), # ack number
    %w(80), # doffset+rsrvd
    %w(18), # flags
    %w(fb fb), # window size
    %w(b9 cc), # checksum
    %w(00 00), # urgent pointer
    %w(01),  # tcp option - nop
    %w(01),  # tcp option - nop
    %w(08 0a 77 71 29 f1 76 9a 80 ff),  # tcp option - timestamp

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  TEST_PACKET_IPV6_TCP = [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 21), # payload length (32+1=33)
    %w(06), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst 

    # tcp
    %w(c1 5b), # src port
    %w(00 50), # dst port
    %w(12 34 56 78), # sequence number
    %w(87 65 43 21), # ack number
    %w(80), # doffset+rsrvd
    %w(18), # flags
    %w(fb fb), # window size
    %w(5d 96), # checksum
    %w(00 00), # urgent pointer
    %w(01),  # tcp option - nop
    %w(01),  # tcp option - nop
    %w(08 0a 77 71 29 f1 76 9a 80 ff),  # tcp option - timestamp

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  TEST_PACKET_IPV4_ICMP_ECHO = [
    # ipv4
    %w(45 00),
    %w(00 1d), # total length (20+8+1=29)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(01), # protocol
    %w(33 38), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # icmp
    %w(08 00), # type=8,code=0 (echo request)
    %w(8a fd), # checksum
    %w(12 34), # identifier
    %w(ab cd), # sequence number

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  TEST_PACKET_IPV6_ICMP_ECHO = [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 09), # payload length (8+1=9)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst 

    # icmp
    %w(80 00), # type=128,code=0 (echo request)
    %w(32 73), # checksum
    %w(12 34), # identifier
    %w(ab cd), # sequence number

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  TEST_PACKET_IPV4_ICMP_ADMIN = [
    # ipv4
    %w(45 00),
    %w(00 39), # total length (20+8+20+8+1=57)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(01), # protocol
    %w(33 1c), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # icmp
    %w(03 0a), # type=3,code=10 (unreachable admin prohibited)
    %w(10 7c), # checksum
    %w(00 00 00 00), # unused

    # payload ipv4
    %w(45 00),
    %w(00 1d), # total length (20+8+1=29)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(11), # protocol
    %w(33 32), # checksum
    %w(c0 00 02 02), # src
    %w(c0 00 02 03), # dst

    # payload udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(7b df), # checksum

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  TEST_PACKET_IPV6_ICMP_ADMIN = [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 39), # payload length (8+40+8+1=57)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst 

    # icmp
    %w(01 01), # type=1,code=1 (unreachable admin prohibited)
    %w(3c 7b), # checksum
    %w(00 00 00 00), # unused

    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 09), # payload length (8+1=9)
    %w(11), # next header
    %w(40), # hop limit
    %w(00 64 ff 9b 00 01 ff fe 00 00 00 00 c0 00 02 02), # src
    %w(00 64 ff 9b 00 00 00 00 00 00 00 00 c0 00 02 03), # dst 

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(7b df), # checksum

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  TEST_PACKET_IPV4_ICMP_MTU = [
    # ipv4
    %w(45 00),
    %w(00 39), # total length (20+8+20+8+1=57)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(01), # protocol
    %w(33 1c), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # icmp
    %w(03 04), # type=3,code=4 (packet too big)
    %w(0a ba), # checksum
    %w(00 00 05 c8), # mtu

    # payload ipv4
    %w(45 00),
    %w(00 1d), # total length (20+8+1=29)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(11), # protocol
    %w(33 32), # checksum
    %w(c0 00 02 02), # src
    %w(c0 00 02 03), # dst

    # payload udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(7b df), # checksum

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  TEST_PACKET_IPV6_ICMP_MTU = [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 39), # payload length (8+40+8+1=57)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst 

    # icmp
    %w(02 00), # type=2,code=0 (packet too big)
    %w(35 a0), # checksum
    %w(ff ff 05 dc), # mtu

    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 09), # payload length (8+1=9)
    %w(11), # next header
    %w(40), # hop limit
    %w(00 64 ff 9b 00 01 ff fe 00 00 00 00 c0 00 02 02), # src
    %w(00 64 ff 9b 00 00 00 00 00 00 00 00 c0 00 02 03), # dst 

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(7b df), # checksum

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  TEST_PACKET_IPV4_ICMP_POINTER = [
    # ipv4
    %w(45 00),
    %w(00 39), # total length (20+8+20+8+1=57)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(01), # protocol
    %w(33 1c), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # icmp
    %w(0c 00), # type=12,code=0 (parameter problem)
    %w(fb 85), # checksum
    %w(0c 00 00 00), # pointer

    # payload ipv4
    %w(45 00),
    %w(00 1d), # total length (20+8+1=29)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(11), # protocol
    %w(33 32), # checksum
    %w(c0 00 02 02), # src
    %w(c0 00 02 03), # dst

    # payload udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(7b df), # checksum

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  TEST_PACKET_IPV6_ICMP_POINTER = [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 39), # payload length (8+40+8+1=57)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst 

    # icmp
    %w(04 00), # type=4,code=0 (erroneous header field)
    %w(39 73), # checksum
    %w(00 00 00 09), # pointer

    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 09), # payload length (8+1=9)
    %w(11), # next header
    %w(40), # hop limit
    %w(00 64 ff 9b 00 01 ff fe 00 00 00 00 c0 00 02 02), # src
    %w(00 64 ff 9b 00 00 00 00 00 00 00 00 c0 00 02 03), # dst 

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(7b df), # checksum

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze



  TEST_PACKET_IPV6_ETHERIP = [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 41), # payload length (2+14+40+8+1=65)
    %w(61), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst 

    # etherip
    %w(30 00),
    # ethernet
    %w(00 15 5d 83 05 09 30 7c 5e 10 75 01 86 dd),
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 09), # payload length (8+1=9)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 0a), # src
    %w(20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 0b), # dst 
    # icmp
    %w(80 00), # type=128,code=0 (echo request)
    %w(00 00), # checksum
    %w(12 34), # identifier
    %w(ab cd), # sequence number
    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze
  TEST_PACKET_IPV4_ETHERIP = [
    # ipv4
    %w(45 00),
    %w(00 55), # total length (20+2+14+40+8+1=85)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(61), # protocol
    %w(32 a0), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # etherip
    %w(30 00),
    # ethernet
    %w(00 15 5d 83 05 09 30 7c 5e 10 75 01 86 dd),
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 09), # payload length (8+1=9)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 0a), # src
    %w(20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 0b), # dst 
    # icmp
    %w(80 00), # type=128,code=0 (echo request)
    %w(00 00), # checksum
    %w(12 34), # identifier
    %w(ab cd), # sequence number
    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze


  def expect_packet_equal(version, expected_packet_, output, checksum: nil)
    expected_packet = expected_packet_.dup

    expected_packet.setbyte(version == 4 ? 8 : 7,0x3f) # TTL
    if version == 4
      cs = Xlat::Common.string_get16be(expected_packet, 10)
      Xlat::Common.string_set16be(expected_packet, 10, Xlat::Protocols::Ip.checksum_adjust(cs, -1 * 256)) # TTL
    end

    hdrlen = version == 4 ? 20 : 40

    #p l3expected: expected_packet[...hdrlen].chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
    #p l3actual__: [output[0]].join.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
    #p l4expected: expected_packet[hdrlen..].chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
    #p l4actual__: [output[1]].join.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')

    expect(output[0]).to eq(expected_packet[0...hdrlen])
    expect(output[1]).to eq(expected_packet[hdrlen..])
    assert_checksum(output[0]) if version == 4
  end

  def assert_l4_checksum(version, data = output[1])
    protocol = output[0][version == 4 ? 9 : 6]

    pseudo_header_fields = [
      version == 4 ? output[0][12,4] : output[0][8,16], # l3 src addr
      version == 4 ? output[0][16,4] : output[0][24,16], # l3 dst addr
      "\x00".b,
      protocol, # l3 protocol field
      "\x00\x00".b.tap { Xlat::Common.string_set16be(_1, 0, output[1].size) }, # l4 size
    ]
    case
    when version == 4 && protocol == "\x01".b # ICMPv4 lack pseudo-header
      pseudo_header_fields = []
    end
    pseudo_header = pseudo_header_fields.join.b
    raise unless pseudo_header.size%2==0
    bytes = [
      pseudo_header,
      data || "".b,
    ].join.b
    #p bytes.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
    assert_checksum(bytes)
  end

  def assert_checksum(bytes)
    cs = Xlat::Protocols::Ip.checksum(bytes) 
    cs = 0 if cs == 0xffff
    expect(cs).to eq(0)
  end

  let(:translator) do
    described_class.new(source_address_translator: MockAddrTranslator, destination_address_translator: MockAddrTranslator).tap do |x|
      x.next_fragment_identifier = 0xc398
    end
  end

  describe "meta" do
    self.class.ancestors.flat_map(&:constants).grep(/TEST_PACKET_/).uniq.each do |test_packet_const_name|
      version = test_packet_const_name.to_s.include?('IPV4') ? 4 : 6
      l4cksum = test_packet_const_name.to_s.match?(/_TRUE_|DNS|ICMP|TCP|UDP/i)
      bytes = const_get(test_packet_const_name)
      describe test_packet_const_name do
        let(:output) do
          hdrlen = (version == 4 ? 20 : 40)
          [
            bytes[0...hdrlen],
            bytes[hdrlen..],
          ]
        end

        it "has a correct l3 checksum (ipv4)" do
          assert_checksum(output[0]) if version == 4
        end if version == 4 

        it "has a correct l4 checksum" do
          assert_l4_checksum(version)
        end if l4cksum
      end
    end
  end

  describe "#translate_to_ipv4" do
    context "with udp" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_UDP.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TEST_PACKET_IPV4_UDP, output)
        assert_l4_checksum(4)
      end
    end

    context "with tcp" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_TCP.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TEST_PACKET_IPV4_TCP, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp echo" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_ICMP_ECHO.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TEST_PACKET_IPV4_ICMP_ECHO, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp payload" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_ICMP_ADMIN.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TEST_PACKET_IPV4_ICMP_ADMIN, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp payload + RFC 4884" do
      let!(:output) do
        ipv6 = TEST_PACKET_IPV6_ICMP_ADMIN.dup
        ipv6.setbyte(44,49) # rfc4884 length
        Xlat::Common.string_set16be(ipv6,42,Xlat::Protocols::Ip.checksum_adjust(Xlat::Common.string_get16be(ipv6,42), 49 << 8))

        translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(ipv6))
      end

      it "translates into ipv4" do
        ipv4 = TEST_PACKET_IPV4_ICMP_ADMIN.dup
        ipv4.setbyte(25,29) # rfc4884 length
        Xlat::Common.string_set16be(ipv4,22,Xlat::Protocols::Ip.checksum_adjust(Xlat::Common.string_get16be(ipv4,22), 29))

        expect_packet_equal(4, ipv4, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp mtu" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_ICMP_MTU.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TEST_PACKET_IPV4_ICMP_MTU, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp err header field" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_ICMP_POINTER.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TEST_PACKET_IPV4_ICMP_POINTER, output)
        assert_l4_checksum(4)
      end
    end

    context "with unknown protocol" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_ETHERIP.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TEST_PACKET_IPV4_ETHERIP, output)
      end
    end
  end

  describe "#translate_to_ipv6" do
    context "with udp" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV4_UDP.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TEST_PACKET_IPV6_UDP, output)
      end
    end

    context "with tcp" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV4_TCP.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TEST_PACKET_IPV6_TCP, output)
      end
    end

    context "with icmp echo" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV4_ICMP_ECHO.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TEST_PACKET_IPV6_ICMP_ECHO, output)
        assert_l4_checksum(6)
      end
    end

    context "with icmp payload" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV4_ICMP_ADMIN.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TEST_PACKET_IPV6_ICMP_ADMIN, output)
        assert_l4_checksum(6)
      end
    end

    context "with icmp payload + RFC 4884" do
      let!(:output) do
        ipv4 = TEST_PACKET_IPV4_ICMP_ADMIN.dup
        ipv4.setbyte(25,29) # rfc4884 length
        Xlat::Common.string_set16be(ipv4,22,Xlat::Protocols::Ip.checksum_adjust(Xlat::Common.string_get16be(ipv4,22), 29))

        translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(ipv4))
      end

      it "translates into ipv6" do
        ipv6 = TEST_PACKET_IPV6_ICMP_ADMIN.dup
        ipv6.setbyte(44,49) # rfc4884 length
        Xlat::Common.string_set16be(ipv6,42,Xlat::Protocols::Ip.checksum_adjust(Xlat::Common.string_get16be(ipv6,42), 49 << 8))

        expect_packet_equal(6, ipv6, output)
        assert_l4_checksum(6)
      end
    end

    context "with icmp mtu" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV4_ICMP_MTU.dup)) }

      it "translates into ipv6" do
        ipv6 = TEST_PACKET_IPV6_ICMP_MTU.dup
        # clear first 2 octets from MTU field (32-bit number) contained in TEST_PACKET_IPV6_ICMP_MTU
        # no checksum adjust as -0xffff keep checksum
        ipv6.setbyte(44,0)
        ipv6.setbyte(45,0)

        expect_packet_equal(6, ipv6, output)
        assert_l4_checksum(6)
      end
    end

    context "with icmp err header field" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV4_ICMP_POINTER.dup)) }

      it "translates into ipv6" do
        ipv6 = TEST_PACKET_IPV6_ICMP_POINTER.dup
        ipv6.setbyte(47,0x08) # pointer=8
        Xlat::Common.string_set16be(ipv6,42,Xlat::Protocols::Ip.checksum_adjust(Xlat::Common.string_get16be(ipv6,42), -1))

        expect_packet_equal(6, ipv6, output)
        assert_l4_checksum(6)
      end
    end

    context "with unknown protocol" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV4_ETHERIP.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TEST_PACKET_IPV6_ETHERIP, output)
      end
    end

  end

end
