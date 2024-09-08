require 'spec_helper'
require 'ipaddr'
require 'xlat/rfc7915'
require 'xlat/protocols/ip'

require_relative 'test_packets'

RSpec.describe Xlat::Rfc7915 do
  module MockAddrTranslator
    def self.translate_address_to_ipv4(ipv6_address,buffer,offset = 0)
      case IPAddr.new_ntoh(ipv6_address.get_string).to_s
      when IPAddr.new('64:ff9b:1:fffe::192.0.2.2').to_s
        buffer.copy(IO::Buffer.for(IPAddr.new('192.0.2.2').hton), offset)
        0
      when IPAddr.new('64:ff9b::192.0.2.3').to_s
        buffer.copy(IO::Buffer.for(IPAddr.new('192.0.2.3').hton), offset)
        0
      when IPAddr.new('2001:db8:60::192.0.2.7').to_s
        buffer.copy(IO::Buffer.for(IPAddr.new('192.0.2.7').hton), offset)
        -(0x2001 + 0x0db8 + 0x0060)
      when IPAddr.new('2001:db8:64::192.0.2.8').to_s
        buffer.copy(IO::Buffer.for(IPAddr.new('192.0.2.8').hton), offset)
        -(0x2001 + 0x0db8 + 0x0064)
      end
    end

    def self.translate_address_to_ipv6(ipv4_address,buffer,offset = 0)
      case IPAddr.new_ntoh(ipv4_address.get_string).to_s
      when '192.0.2.2'
        buffer.copy(IO::Buffer.for(IPAddr.new('64:ff9b:1:fffe::192.0.2.2').hton), offset)
        0
      when '192.0.2.3'
        buffer.copy(IO::Buffer.for(IPAddr.new('64:ff9b::192.0.2.3').hton), offset)
        0
      when '192.0.2.7'
        buffer.copy(IO::Buffer.for(IPAddr.new('2001:db8:60::192.0.2.7').hton), offset)
        (0x2001 + 0x0db8 + 0x0060)
      when '192.0.2.8'
        buffer.copy(IO::Buffer.for(IPAddr.new('2001:db8:64::192.0.2.8').hton), offset)
        (0x2001 + 0x0db8 + 0x0064)
      end
    end
  end

  def buffer_from_string(str)
    IO::Buffer.new(str.bytesize).tap do |buf|
      buf.set_string(str)
    end
  end


  def expect_packet_equal(version, expected_packet_, output, checksum: nil)
    expected_packet = expected_packet_.dup

    expected_packet.set_value(:U8, version == 4 ? 8 : 7, 0x3f) # TTL
    if version == 4
      cs = expected_packet.get_value(:U16, 10)
      expected_packet.set_value(:U16, 10, Xlat::Protocols::Ip.checksum_adjust(cs, -1 * 256)) # TTL
    end

    hdrlen = version == 4 ? 20 : 40

    #p l3expected: expected_packet[...hdrlen].chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
    #p l3actual__: [output[0]].join.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
    #p l4expected: expected_packet[hdrlen..].chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
    #p l4actual__: [output[1]].join.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')

    expect(output[0].get_string).to eq(expected_packet.get_string(0, hdrlen))
    expect(output[1..].map(&:get_string).join).to eq(expected_packet.get_string(hdrlen))
    assert_checksum(output[0]) if version == 4
  end

  def assert_l4_checksum(version, data = nil)
    data ||= output[1..-1].map(&:get_string).join
    protocol = output[0].get_string[version == 4 ? 9 : 6]

    pseudo_header_fields = [
      version == 4 ? output[0].get_string(12,4) : output[0].get_string(8,16), # l3 src addr
      version == 4 ? output[0].get_string(16,4) : output[0].get_string(24,16), # l3 dst addr
      "\x00".b,
      protocol, # l3 protocol field
      [data.size].pack('n'), # l4 size
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
    assert_checksum(IO::Buffer.for(bytes))
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
    TestPackets.constants.grep(/TEST_PACKET_/).uniq.each do |test_packet_const_name|
      version = test_packet_const_name.to_s.include?('IPV4') ? 4 : 6
      l4cksum = test_packet_const_name.to_s.match?(/_TRUE_|DNS|ICMP|TCP|UDP/i)
      bytes = TestPackets.const_get(test_packet_const_name)
      describe test_packet_const_name do
        let(:output) do
          hdrlen = (version == 4 ? 20 : 40)
          [
            bytes.slice(0, hdrlen),
            bytes.slice(hdrlen),
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
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV6_UDP.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TestPackets::TEST_PACKET_IPV4_UDP, output)
        assert_l4_checksum(4)
      end
    end

    context "with tcp" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV6_TCP.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TestPackets::TEST_PACKET_IPV4_TCP, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp echo" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV6_ICMP_ECHO.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TestPackets::TEST_PACKET_IPV4_ICMP_ECHO, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp echo reply" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV6_ICMP_ECHO_REPLY.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TestPackets::TEST_PACKET_IPV4_ICMP_ECHO_REPLY, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp payload" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp truncated payload" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN_TRUNC.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN_TRUNC, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp payload + RFC 4884" do
      let!(:output) do
        ipv6 = TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN.dup
        ipv6.set_value(:U8, 44, 49) # rfc4884 length
        ipv6.set_value(:U16, 42, Xlat::Protocols::Ip.checksum_adjust(ipv6.get_value(:U16, 42), 49 << 8))

        translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(ipv6))
      end

      it "translates into ipv4" do
        ipv4 = TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN.dup
        ipv4.set_value(:U8, 25, 29) # rfc4884 length
        ipv4.set_value(:U16, 22, Xlat::Protocols::Ip.checksum_adjust(ipv4.get_value(:U16, 22), 29))

        expect_packet_equal(4, ipv4, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp mtu" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV6_ICMP_MTU.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TestPackets::TEST_PACKET_IPV4_ICMP_MTU, output)
        assert_l4_checksum(4)
      end
    end

    context "with icmp err header field" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV6_ICMP_POINTER.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TestPackets::TEST_PACKET_IPV4_ICMP_POINTER, output)
        assert_l4_checksum(4)
      end
    end

    context "with unknown protocol" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV6_ETHERIP.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TestPackets::TEST_PACKET_IPV4_ETHERIP, output)
      end
    end
  end

  describe "#translate_to_ipv6" do
    context "with udp" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV4_UDP.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TestPackets::TEST_PACKET_IPV6_UDP, output)
      end
    end

    context "with tcp" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV4_TCP.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TestPackets::TEST_PACKET_IPV6_TCP, output)
      end
    end

    context "with icmp echo" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV4_ICMP_ECHO.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TestPackets::TEST_PACKET_IPV6_ICMP_ECHO, output)
        assert_l4_checksum(6)
      end
    end

    context "with icmp echo reply" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV4_ICMP_ECHO_REPLY.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TestPackets::TEST_PACKET_IPV6_ICMP_ECHO_REPLY, output)
        assert_l4_checksum(6)
      end
    end

    context "with icmp payload" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN, output)
        assert_l4_checksum(6)
      end
    end

    context "with truncated icmp payload" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN_TRUNC.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN_TRUNC, output)
        assert_l4_checksum(6)
      end
    end

    context "with icmp payload + RFC 4884" do
      let!(:output) do
        ipv4 = TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN.dup
        ipv4.set_value(:U8, 25, 29) # rfc4884 length
        ipv4.set_value(:U16, 22, Xlat::Protocols::Ip.checksum_adjust(ipv4.get_value(:U16 ,22), 29))

        translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(ipv4))
      end

      it "translates into ipv6" do
        ipv6 = TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN.dup
        ipv6.set_value(:U8, 44, 49) # rfc4884 length
        ipv6.set_value(:U16, 42, Xlat::Protocols::Ip.checksum_adjust(ipv6.get_value(:U16, 42), 49 << 8))

        expect_packet_equal(6, ipv6, output)
        assert_l4_checksum(6)
      end
    end

    context "with icmp mtu" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV4_ICMP_MTU.dup)) }

      it "translates into ipv6" do
        ipv6 = TestPackets::TEST_PACKET_IPV6_ICMP_MTU.dup
        # clear first 2 octets from MTU field (32-bit number) contained in TEST_PACKET_IPV6_ICMP_MTU
        # no checksum adjust as -0xffff keep checksum
        ipv6.set_value(:U16, 44, 0)

        expect_packet_equal(6, ipv6, output)
        assert_l4_checksum(6)
      end
    end

    context "with icmp err header field" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV4_ICMP_POINTER.dup)) }

      it "translates into ipv6" do
        ipv6 = TestPackets::TEST_PACKET_IPV6_ICMP_POINTER.dup
        ipv6.set_value(:U8, 47, 0x08) # pointer=8
        ipv6.set_value(:U16, 42, Xlat::Protocols::Ip.checksum_adjust(ipv6.get_value(:U16, 42), -1))

        expect_packet_equal(6, ipv6, output)
        assert_l4_checksum(6)
      end
    end

    context "with unknown protocol" do
      let!(:output) { translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV4_ETHERIP.dup)) }

      it "translates into ipv6" do
        expect_packet_equal(6, TestPackets::TEST_PACKET_IPV6_ETHERIP, output)
      end
    end

    context "with ICMP incomplete header" do
      let!(:output) {  translator.translate_to_ipv6(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV4_ICMP_INCOMPLETE_HDR.dup)) }

      it "is discarded without error" do
        expect(output).to be_nil
      end
    end

    context "with ICMP6 incomplete header" do
      let!(:output) {  translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TestPackets::TEST_PACKET_IPV6_ICMP_INCOMPLETE_HDR.dup)) }

      it "is discarded without error" do
        expect(output).to be_nil
      end
    end
  end

end
