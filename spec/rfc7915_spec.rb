require 'spec_helper'
require 'ipaddr'
require 'xlat/rfc7915'
require 'xlat/protocols/ip'

require_relative 'test_packets'

RSpec.describe Xlat::Rfc7915 do
  module MockAddrTranslator
    def self.translate_address_to_ipv4(source, source_offset, destination, destination_offset)
      case IPAddr.new_ntoh(source.get_string(source_offset, 16)).to_s
      when IPAddr.new('64:ff9b:1:fffe::192.0.2.2').to_s
        destination.copy(IO::Buffer.for(IPAddr.new('192.0.2.2').hton), destination_offset)
        0
      when IPAddr.new('64:ff9b::192.0.2.3').to_s
        destination.copy(IO::Buffer.for(IPAddr.new('192.0.2.3').hton), destination_offset)
        0
      when IPAddr.new('2001:db8:60::192.0.2.7').to_s
        destination.copy(IO::Buffer.for(IPAddr.new('192.0.2.7').hton), destination_offset)
        -(0x2001 + 0x0db8 + 0x0060)
      when IPAddr.new('2001:db8:64::192.0.2.8').to_s
        destination.copy(IO::Buffer.for(IPAddr.new('192.0.2.8').hton), destination_offset)
        -(0x2001 + 0x0db8 + 0x0064)
      end
    end

    def self.translate_address_to_ipv6(source, source_offset, destination, destination_offset)
      case IPAddr.new_ntoh(source.get_string(source_offset, 4)).to_s
      when '192.0.2.2'
        destination.copy(IO::Buffer.for(IPAddr.new('64:ff9b:1:fffe::192.0.2.2').hton), destination_offset)
        0
      when '192.0.2.3'
        destination.copy(IO::Buffer.for(IPAddr.new('64:ff9b::192.0.2.3').hton), destination_offset)
        0
      when '192.0.2.7'
        destination.copy(IO::Buffer.for(IPAddr.new('2001:db8:60::192.0.2.7').hton), destination_offset)
        (0x2001 + 0x0db8 + 0x0060)
      when '192.0.2.8'
        destination.copy(IO::Buffer.for(IPAddr.new('2001:db8:64::192.0.2.8').hton), destination_offset)
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

    context "icmp packet too big" do
      context "with ipv6 mtu 1500" do
        let!(:ipv6_icmp) { TestPackets::TEST_PACKET_IPV6_ICMP_MTU.with_mtu(1500) }
        let!(:ipv4_icmp) { TestPackets::TEST_PACKET_IPV4_ICMP_MTU.with_mtu(1480) }

        let!(:output) { translator.translate_to_ipv4(parse_packet(ipv6_icmp), 1500) }

        it "translates into ipv4 fragmentation needed with mtu -20" do
          expect([ipv6_icmp]).to have_correct_checksum(version: 6)
          expect(output).to have_correct_checksum(version: 4).and match_packet(ipv4_icmp)
        end
      end

      context "with ipv6 mtu > 0xffff" do
        let!(:ipv6_icmp) { TestPackets::TEST_PACKET_IPV6_ICMP_MTU.with_mtu(78000) }
        let!(:ipv4_icmp) { TestPackets::TEST_PACKET_IPV4_ICMP_MTU.with_mtu(65535) }

        let!(:output) { translator.translate_to_ipv4(parse_packet(ipv6_icmp), 1500) }

        # IPv4 MTU should be capped at 0xFFFF
        it "translates into ipv4 fragmentation needed with mtu = 65535" do
          expect([ipv6_icmp]).to have_correct_checksum(version: 6)
          expect(output).to have_correct_checksum(version: 4).and match_packet(ipv4_icmp)
        end
      end

      context 'with fragmented payload' do
        let!(:ipv6_icmp) { TestPackets::TEST_PACKET_IPV6_ICMP_MTU_FRAG_PAYLOAD.with_mtu(1500) }
        let!(:ipv4_icmp) { TestPackets::TEST_PACKET_IPV4_ICMP_MTU_FRAG_PAYLOAD.with_mtu(1472) }

        let!(:output) { translator.translate_to_ipv4(parse_packet(ipv6_icmp), 1500) }

        it "translates into ipv4 fragmentation needed with mtu -28" do
          expect([ipv6_icmp]).to have_correct_checksum(version: 6)
          expect(output).to have_correct_checksum(version: 4).and match_packet(ipv4_icmp)
        end
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

    context "with fragmentation" do
      context "head fragment" do
        let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_FRAG_UDP_0_1440.dup), 1500) }

        it "translates into ipv6" do
          expect(output).to have_correct_checksum(version: 6, l4: false).and match_packet(TestPackets::TEST_PACKET_IPV6_FRAG_UDP_0_1440)
        end
      end

      context "tail fragment" do
        let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_FRAG_UDP_1440_1600.dup), 1500) }

        it "translates into ipv6" do
          expect(output).to have_correct_checksum(version: 6, l4: false).and match_packet(TestPackets::TEST_PACKET_IPV6_FRAG_UDP_1440_1600)
        end
      end

      context "when translated IPv6 packet exceeds MTU" do
        let!(:output) { translator.translate_to_ipv6(parse_packet(TestPackets::TEST_PACKET_IPV4_FRAG_UDP_0_1472.dup), 1500) }

        it "drops the packet" do
          expect(output).to be_nil
        end
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
        expect(output).to have_correct_checksum(version: 6).and match_packet(TestPackets::TEST_PACKET_IPV6_ICMP_FRAG_PAYLOAD)
      end
    end

    context "icmp fragmentation needed" do
      context "with ipv4 mtu 1480" do
        let!(:ipv4_icmp) { TestPackets::TEST_PACKET_IPV4_ICMP_MTU.with_mtu(1480) }
        let!(:ipv6_icmp) { TestPackets::TEST_PACKET_IPV6_ICMP_MTU.with_mtu(1500) }

        let!(:output) { translator.translate_to_ipv6(parse_packet(ipv4_icmp), 1500) }

        it "translates into ipv6 packet too big with mtu +20" do
          expect([ipv4_icmp]).to have_correct_checksum(version: 4)
          expect(output).to have_correct_checksum(version: 6).and match_packet(ipv6_icmp)
        end
      end

      context "with ipv4 mtu 1280" do
        let!(:ipv4_icmp) { TestPackets::TEST_PACKET_IPV4_ICMP_MTU.with_mtu(1200) }
        let!(:ipv6_icmp) { TestPackets::TEST_PACKET_IPV6_ICMP_MTU.with_mtu(1280) }

        let!(:output) { translator.translate_to_ipv6(parse_packet(ipv4_icmp), 1500) }

        it "translates into ipv6 packet too big with mtu = 1280" do
          expect([ipv4_icmp]).to have_correct_checksum(version: 4)
          expect(output).to have_correct_checksum(version: 6).and match_packet(ipv6_icmp)
        end
      end

      context 'with fragmented payload' do
        let!(:ipv4_icmp) { TestPackets::TEST_PACKET_IPV4_ICMP_MTU_FRAG_PAYLOAD.with_mtu(1480) }
        let!(:ipv6_icmp) { TestPackets::TEST_PACKET_IPV6_ICMP_MTU_FRAG_PAYLOAD.with_mtu(1500) }

        let!(:output) { translator.translate_to_ipv6(parse_packet(ipv4_icmp), 1500) }

        it "translates into ipv6 packet too big with mtu +20" do
          expect([ipv4_icmp]).to have_correct_checksum(version: 4)
          expect(output).to have_correct_checksum(version: 6).and match_packet(ipv6_icmp)
        end
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
