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

  let(:translator) do
    described_class.new(source_address_translator: MockAddrTranslator, destination_address_translator: MockAddrTranslator).tap do |x|
      x.next_fragment_identifier = 0xc398
    end
  end

  describe "meta" do
    TestPackets.constants.grep(/TEST_PACKET_/).uniq.each do |test_packet_const_name|
      bytes = TestPackets.const_get(test_packet_const_name)
      version = test_packet_const_name.to_s.include?('IPV4') ? 4 : 6
      l4cksum = test_packet_const_name.to_s.match?(/_TRUE_|DNS|ICMP|TCP|UDP/i) && !bytes.respond_to?(:__no_l4_checksum)
      describe test_packet_const_name do
        it do
          expect([bytes]).to have_correct_checksum(version:, l4: l4cksum)
        end
      end
    end
  end

  def parse_packet(buffer)
    ip = Xlat::Protocols::Ip.new
    new_buffer = IO::Buffer.new(1500)
    new_buffer.copy(buffer)
    ip.parse(bytes: new_buffer, bytes_length: buffer.size)
    ip
  end

  describe "#translate_to_ipv4" do
    context "with udp" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_UDP.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_UDP)
      end
    end

    context "with tcp" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_TCP.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_TCP)
      end
    end

    context "with fragmentation" do
      context "head fragment" do
        let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_FRAG_UDP_0_1440.dup), 1500) }

        it "translates into ipv4" do
          expect(output).to have_correct_checksum(version: 4, l4: false).and match_packet(TestPackets::TEST_PACKET_IPV4_FRAG_UDP_0_1440)
        end
      end

      context "tail fragment" do
        let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_FRAG_UDP_1440_1600.dup), 1500) }

        it "translates into ipv4" do
          expect(output).to have_correct_checksum(version: 4, l4: false).and match_packet(TestPackets::TEST_PACKET_IPV4_FRAG_UDP_1440_1600)
        end
      end
    end

    context "with icmp echo" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ECHO.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ECHO)
      end
    end

    context "with icmp echo reply" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ECHO_REPLY.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ECHO_REPLY)
      end
    end

    context "with icmp payload" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN)
      end
    end

    context "with icmp truncated payload" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN_TRUNC.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN_TRUNC)
      end
    end

    context "with icmp payload + RFC 4884" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN_RFC4884.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN_RFC4884)
      end
    end

    context "with fragmented icmp payload" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ICMP_FRAG_PAYLOAD.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_ICMP_FRAG_PAYLOAD)
      end
    end

    context "with icmp mtu" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ICMP_MTU.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_ICMP_MTU)
      end
    end

    context "with icmp err header field" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ICMP_POINTER.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_ICMP_POINTER)
      end
    end

    context "with nested icmp" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ICMP_PAYLOAD.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ICMP_PAYLOAD)
      end
    end

    context "with unknown protocol" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ETHERIP.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4, l4: false).and match_packet(TestPackets::TEST_PACKET_IPV4_ETHERIP)
      end
    end

    context "with extension header" do
      let!(:output) { translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_HOPOPT_DSTOPT_UDP.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 4).and match_packet(TestPackets::TEST_PACKET_IPV4_UDP)
      end
    end

    context "with ICMP6 incomplete header" do
      let!(:output) {  translator.translate_to_ipv4(parse_packet(TestPackets::TEST_PACKET_IPV6_ICMP_INCOMPLETE_HDR.dup), 1500) }

      it "is discarded without error" do
        expect(output).to be_nil
      end
    end
  end

  describe "#translate_to_ipv6" do
    context "with udp" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_UDP.dup), 1500) }

      it "translates into ipv6" do
        expect(output).to have_correct_checksum(version: 6).and match_packet(TestPackets::TEST_PACKET_IPV6_UDP)
      end
    end

    context "with tcp" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_TCP.dup), 1500) }

      it "translates into ipv6" do
        expect(output).to have_correct_checksum(version: 6).and match_packet(TestPackets::TEST_PACKET_IPV6_TCP)
      end
    end

    context "with icmp echo" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ECHO.dup), 1500) }

      it "translates into ipv6" do
        expect(output).to have_correct_checksum(version: 6).and match_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ECHO)
      end
    end

    context "with icmp echo reply" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ECHO_REPLY.dup), 1500) }

      it "translates into ipv6" do
        expect(output).to have_correct_checksum(version: 6).and match_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ECHO_REPLY)
      end
    end

    context "with icmp payload" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN.dup), 1500) }

      it "translates into ipv6" do
        expect(output).to have_correct_checksum(version: 6).and match_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN)
      end
    end

    context "with truncated icmp payload" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN_TRUNC.dup), 1500) }

      it "translates into ipv6" do
        expect(output).to have_correct_checksum(version: 6).and match_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN_TRUNC)
      end
    end

    context "with icmp payload + RFC 4884" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN_RFC4884.dup), 1500) }

      it "translates into ipv6" do
        expect(output).to have_correct_checksum(version: 6).and match_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN_RFC4884)
      end
    end

    context "with fragmented icmp payload" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ICMP_FRAG_PAYLOAD.dup), 1500) }

      it "translates into ipv6" do
        expect(output).to be_nil  # Though we don't support fragments yet, it should not raise
      end
    end

    context "with icmp mtu" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ICMP_MTU.dup), 1500) }

      it "translates into ipv6" do
        ipv6 = TestPackets::TEST_PACKET_IPV6_ICMP_MTU.dup
        # clear first 2 octets from MTU field (32-bit number) contained in TEST_PACKET_IPV6_ICMP_MTU
        # no checksum adjust as -0xffff keep checksum
        ipv6.set_value(:U16, 44, 0)

        expect(output).to have_correct_checksum(version: 6).and match_packet(ipv6)
      end
    end

    context "with icmp err header field" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ICMP_POINTER.dup), 1500) }

      it "translates into ipv6" do
        ipv6 = TestPackets::TEST_PACKET_IPV6_ICMP_POINTER.dup
        ipv6.set_value(:U8, 47, 0x08) # pointer=8
        ipv6.set_value(:U16, 42, Xlat::Protocols::Ip.checksum_adjust(ipv6.get_value(:U16, 42), -1))

        expect(output).to have_correct_checksum(version: 6).and match_packet(ipv6)
      end
    end

    context "with nested icmp" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ICMP_ICMP_PAYLOAD.dup), 1500) }

      it "translates into ipv4" do
        expect(output).to have_correct_checksum(version: 6).and match_packet(TestPackets::TEST_PACKET_IPV6_ICMP_ICMP_PAYLOAD)
      end
    end

    context "with unknown protocol" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ETHERIP.dup), 1500) }

      it "translates into ipv6" do
        expect(output).to have_correct_checksum(version: 6, l4: false).and match_packet(TestPackets::TEST_PACKET_IPV6_ETHERIP)
      end
    end

    context "with IPv4 Options" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_OPTS_UDP.dup), 1500) }

      it "translates into ipv6" do
        expect(output).to have_correct_checksum(version: 6).and match_packet(TestPackets::TEST_PACKET_IPV6_UDP)
      end
    end

    context "with ICMP incomplete header" do
      let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_ICMP_INCOMPLETE_HDR.dup), 1500) }

      it "is discarded without error" do
        expect(output).to be_nil
      end
    end
  end

end
