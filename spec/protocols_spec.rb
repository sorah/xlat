require 'spec_helper'
require 'xlat/protocols/ip'

require_relative 'test_packets'

RSpec.describe Xlat::Protocols::Ip do
  subject {  Xlat::Protocols::Ip.new }

  describe '#parse' do

    it 'parses IPv4 TCP' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_TCP)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
        expect(ip.proto).to eq 6
        expect(ip.l4).to be_kind_of Xlat::Protocols::Tcp
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 20
        expect(ip.l4_bytes_length).to eq 33

        expect(ip.identification).to eq 0xC398
        expect(ip.fragment_offset).to be nil
        expect(ip.more_fragments).to be nil
        expect(ip.dont_fragment).to be false
      end
    end

    it 'parses IPv6 TCP' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_TCP)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
        expect(ip.proto).to eq 6
        expect(ip.l4).to be_kind_of Xlat::Protocols::Tcp
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 40
        expect(ip.l4_bytes_length).to eq 33

        expect(ip.identification).to eq nil
        expect(ip.fragment_offset).to be nil
        expect(ip.more_fragments).to be nil
        expect(ip.dont_fragment).to be nil
      end
    end

    it 'parses IPv4 UDP' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_UDP)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
        expect(ip.proto).to eq 17
        expect(ip.l4).to be_kind_of Xlat::Protocols::Udp
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 20
        expect(ip.l4_bytes_length).to eq 9
      end
    end

    it 'parses IPv6 UDP' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_UDP)
      aggregate_failures do
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
        expect(ip.proto).to eq 17
        expect(ip.l4).to be_kind_of Xlat::Protocols::Udp
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 40
        expect(ip.l4_bytes_length).to eq 9
      end
    end

    it 'parses IPv4 with IP options' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_OPTS_UDP)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
        expect(ip.proto).to eq 17
        expect(ip.l4_start).to eq 24
        expect(ip.l4_length).to eq 9
        expect(ip.l4).to be_kind_of Xlat::Protocols::Udp
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 24
        expect(ip.l4_bytes_length).to eq 9
      end
    end

    it 'parses IPv6 with extension header' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_HOPOPT_DSTOPT_UDP)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
        expect(ip.proto).to eq 17
        expect(ip.l4_start).to eq 72
        expect(ip.l4_length).to eq 9
        expect(ip.l4).to be_kind_of Xlat::Protocols::Udp
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 72
        expect(ip.l4_bytes_length).to eq 9
      end
    end

    it 'parses IPv4 ICMP Echo' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_ICMP_ECHO)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
        expect(ip.proto).to eq 1
        expect(ip.l4).to be_kind_of Xlat::Protocols::Icmp::Echo
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 20
        expect(ip.l4_bytes_length).to eq 9
        expect(ip.l4.type).to eq 8
        expect(ip.l4.code).to eq 0
      end
    end

    it 'parses IPv4 ICMP Echo Reply' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_ICMP_ECHO_REPLY)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
        expect(ip.l4).to be_kind_of Xlat::Protocols::Icmp::Echo
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 20
        expect(ip.l4_bytes_length).to eq 9
        expect(ip.l4.type).to eq 0
        expect(ip.l4.code).to eq 0
      end
    end

    it 'parses IPv6 ICMP Echo' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_ICMP_ECHO)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
        expect(ip.l4).to be_kind_of Xlat::Protocols::Icmp::Echo
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 40
        expect(ip.l4_bytes_length).to eq 9
        expect(ip.l4.type).to eq 128
        expect(ip.l4.code).to eq 0
      end
    end

    it 'parses IPv4 ICMP Echo Reply' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_ICMP_ECHO_REPLY)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
        expect(ip.l4).to be_kind_of Xlat::Protocols::Icmp::Echo
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 40
        expect(ip.l4_bytes_length).to eq 9
        expect(ip.l4.type).to eq 129
        expect(ip.l4.code).to eq 0
      end
    end

    it 'parses IPv4 ICMP Error' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
        expect(ip.l4).to be_kind_of Xlat::Protocols::Icmp::Error
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 20
        expect(ip.l4_bytes_length).to eq 37
        expect(ip.l4.type).to eq 3
        expect(ip.l4.code).to eq 10
        expect(ip.l4.payload_bytes).to be ip.bytes
        expect(ip.l4.payload_bytes_offset).to eq 28
      end

      inner = Xlat::Protocols::Ip.new(icmp_payload: true)
        .parse(bytes: ip.l4.payload_bytes, bytes_offset: ip.l4.payload_bytes_offset, bytes_length: ip.l4.payload_bytes_length)
      aggregate_failures do
        expect(inner).to be_kind_of Xlat::Protocols::Ip
        expect(inner.version).to eq Xlat::Protocols::Ip::Ipv4
        expect(inner.proto).to eq 17
        expect(inner.l4).to be_kind_of Xlat::Protocols::Udp
        expect(inner.l4_bytes_offset).to eq 48
        expect(inner.l4_bytes_length).to eq 9
      end
    end

    it 'parses IPv6 ICMP Error' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
        expect(ip.l4).to be_kind_of Xlat::Protocols::Icmp::Error
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 40
        expect(ip.l4.type).to eq 1
        expect(ip.l4.code).to eq 1
        expect(ip.l4.payload_bytes).to be ip.bytes
        expect(ip.l4.payload_bytes_offset).to eq 48
      end

      inner = Xlat::Protocols::Ip.new(icmp_payload: true)
        .parse(bytes: ip.l4.payload_bytes, bytes_offset: ip.l4.payload_bytes_offset, bytes_length: ip.l4.payload_bytes_length)
      aggregate_failures do
        expect(inner).to be_kind_of Xlat::Protocols::Ip
        expect(inner.version).to eq Xlat::Protocols::Ip::Ipv6
        expect(inner.proto).to eq 17
        expect(inner.l4).to be_kind_of Xlat::Protocols::Udp
        expect(inner.l4_bytes_offset).to eq 88
        expect(inner.l4_bytes_length).to eq 9
      end
    end

    it 'parses IPv4 ICMP Error with truncated payload' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_ICMP_ADMIN_TRUNC)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
        expect(ip.l4).to be_kind_of Xlat::Protocols::Icmp::Error
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 20
        expect(ip.l4_bytes_length).to eq 37
        expect(ip.l4.type).to eq 3
        expect(ip.l4.code).to eq 10
        expect(ip.l4.payload_bytes).to be ip.bytes
        expect(ip.l4.payload_bytes_offset).to eq 28
      end

      inner = Xlat::Protocols::Ip.new(icmp_payload: true)
        .parse(bytes: ip.l4.payload_bytes, bytes_offset: ip.l4.payload_bytes_offset, bytes_length: ip.l4.payload_bytes_length)
      aggregate_failures do
        expect(inner).to be_kind_of Xlat::Protocols::Ip
        expect(inner.version).to eq Xlat::Protocols::Ip::Ipv4
        expect(inner.proto).to eq 17
        expect(inner.l4).to be_kind_of Xlat::Protocols::Udp
        expect(inner.l4_bytes_offset).to eq 48
        expect(inner.l4_bytes_length).to eq 9
      end
    end

    it 'parses IPv6 ICMP Error with truncated payload' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_ICMP_ADMIN_TRUNC)
      aggregate_failures do
        expect(ip).to be_kind_of Xlat::Protocols::Ip
        expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
        expect(ip.l4).to be_kind_of Xlat::Protocols::Icmp::Error
        expect(ip.l4_bytes).to be ip.bytes
        expect(ip.l4_bytes_offset).to eq 40
        expect(ip.l4.type).to eq 1
        expect(ip.l4.code).to eq 1
        expect(ip.l4.payload_bytes).to be ip.bytes
        expect(ip.l4.payload_bytes_offset).to eq 48
      end

      inner = Xlat::Protocols::Ip.new(icmp_payload: true)
        .parse(bytes: ip.l4.payload_bytes, bytes_offset: ip.l4.payload_bytes_offset, bytes_length: ip.l4.payload_bytes_length)
      aggregate_failures do
        expect(inner).to be_kind_of Xlat::Protocols::Ip
        expect(inner.version).to eq Xlat::Protocols::Ip::Ipv6
        expect(inner.proto).to eq 17
        expect(inner.l4).to be_kind_of Xlat::Protocols::Udp
        expect(inner.l4_bytes_offset).to eq 88
        expect(inner.l4_bytes_length).to eq 9
      end
    end

    context 'IPv4 fragmentation' do
      it 'parses IPv4 fragmented UDP (first fragment)' do
        ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_FRAG_UDP_0_1472)
        aggregate_failures do
          expect(ip).to be_kind_of Xlat::Protocols::Ip
          expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
          expect(ip.identification).to eq 0xc398
          expect(ip.fragment_offset).to eq 0
          expect(ip.more_fragments).to be true
          expect(ip.dont_fragment).to be false
          expect(ip.l4).to be_kind_of Xlat::Protocols::Udp
          expect(ip.l4_bytes).to be ip.bytes
          expect(ip.l4_bytes_offset).to eq 20
          expect(ip.l4_bytes_length).to eq 1480
        end
      end

      it 'parses IPv4 fragmented UDP (continued fragment)' do
        ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_FRAG_UDP_1472_1600)
        aggregate_failures do
          expect(ip).to be_kind_of Xlat::Protocols::Ip
          expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
          expect(ip.identification).to eq 0xc398
          expect(ip.fragment_offset).to eq 185
          expect(ip.more_fragments).to be false
          expect(ip.dont_fragment).to be false
          expect(ip.l4).to be_nil
          expect(ip.l4_bytes).to be ip.bytes
          expect(ip.l4_bytes_offset).to eq 20
          expect(ip.l4_bytes_length).to eq 128
        end
      end

      it 'parses IPv4 fragmented UDP within ICMPv4 error' do
        ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_ICMP_FRAG_PAYLOAD)
        aggregate_failures do
          expect(ip).to be_kind_of Xlat::Protocols::Ip
          expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
          expect(ip.l4).to be_kind_of Xlat::Protocols::Icmp::Error
          expect(ip.l4_bytes).to be ip.bytes
          expect(ip.l4_bytes_offset).to eq 20
          expect(ip.identification).to eq 0xc398
          expect(ip.fragment_offset).to be_nil
          expect(ip.more_fragments).to be_nil
          expect(ip.dont_fragment).to be false
          expect(ip.l4.type).to eq 3
          expect(ip.l4.code).to eq 10
          expect(ip.l4.payload_bytes).to be ip.bytes
          expect(ip.l4.payload_bytes_offset).to eq 28
        end

        inner = Xlat::Protocols::Ip.new(icmp_payload: true)
          .parse(bytes: ip.l4.payload_bytes, bytes_offset: ip.l4.payload_bytes_offset, bytes_length: ip.l4.payload_bytes_length)
        aggregate_failures do
          expect(inner).to be_kind_of Xlat::Protocols::Ip
          expect(inner.version).to eq Xlat::Protocols::Ip::Ipv4
          expect(inner.l4).to be_kind_of Xlat::Protocols::Udp
          expect(inner.l4_bytes).to be ip.bytes
          expect(inner.l4_bytes_offset).to eq 48
          expect(inner.l4_bytes_length).to eq 16
          expect(inner.identification).to eq 0xc398
          expect(inner.fragment_offset).to eq 0
          expect(inner.more_fragments).to be true
          expect(inner.dont_fragment).to be false
        end
      end
    end

    context 'IPv6 fragmentation' do
      it 'parses IPv6 fragmented UDP (first fragment)' do
        ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_FRAG_UDP_0_1440)
        aggregate_failures do
          expect(ip).to be_kind_of Xlat::Protocols::Ip
          expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
          expect(ip.identification).to eq 0xc398
          expect(ip.fragment_offset).to eq 0
          expect(ip.more_fragments).to be true
          expect(ip.dont_fragment).to be_nil
          expect(ip.l4).to be_kind_of Xlat::Protocols::Udp
          expect(ip.l4_bytes).to be ip.bytes
          expect(ip.l4_bytes_offset).to eq 48
          expect(ip.l4_bytes_length).to eq 1448
        end
      end

      it 'parses IPv6 fragmented UDP (continued fragment)' do
        ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_FRAG_UDP_1440_1600)
        aggregate_failures do
          expect(ip).to be_kind_of Xlat::Protocols::Ip
          expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
          expect(ip.identification).to eq 0xc398
          expect(ip.fragment_offset).to eq 181
          expect(ip.more_fragments).to be false
          expect(ip.dont_fragment).to be_nil
          expect(ip.l4).to be_nil
          expect(ip.l4_bytes).to be ip.bytes
          expect(ip.l4_bytes_offset).to eq 48
          expect(ip.l4_bytes_length).to eq 160
        end
      end

      it 'parses IPv6 fragmented UDP within ICMPv6 error' do
        ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_ICMP_FRAG_PAYLOAD)
        aggregate_failures do
          expect(ip).to be_kind_of Xlat::Protocols::Ip
          expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
          expect(ip.l4).to be_kind_of Xlat::Protocols::Icmp::Error
          expect(ip.l4_bytes).to be ip.bytes
          expect(ip.l4_bytes_offset).to eq 40
          expect(ip.identification).to be_nil
          expect(ip.fragment_offset).to be_nil
          expect(ip.more_fragments).to be_nil
          expect(ip.dont_fragment).to be nil
          expect(ip.l4.type).to eq 1
          expect(ip.l4.code).to eq 1
          expect(ip.l4.payload_bytes).to be ip.bytes
          expect(ip.l4.payload_bytes_offset).to eq 48
        end

        inner = Xlat::Protocols::Ip.new(icmp_payload: true)
          .parse(bytes: ip.l4.payload_bytes, bytes_offset: ip.l4.payload_bytes_offset, bytes_length: ip.l4.payload_bytes_length)
        aggregate_failures do
          expect(inner).to be_kind_of Xlat::Protocols::Ip
          expect(inner.version).to eq Xlat::Protocols::Ip::Ipv6
          expect(inner.l4).to be_kind_of Xlat::Protocols::Udp
          expect(inner.l4_bytes).to be ip.bytes
          expect(inner.l4_bytes_offset).to eq 96  # 40(ipv6)+8(icmpv6)+40(ipv6)+8(ipv6-frag)
          expect(inner.l4_bytes_length).to eq 16
          expect(inner.identification).to eq 0xc398
          expect(inner.fragment_offset).to eq 0
          expect(inner.more_fragments).to be true
          expect(inner.dont_fragment).to be_nil
        end
      end
    end
  end

  describe '#convert_version' do
    it 'converts IPv4 TCP into IPv6' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV4_TCP.dup)

      new_header = IO::Buffer.new(40)
      expect {
        ip.convert_version!(Xlat::Protocols::Ip::Ipv6, new_header, -12)
      }.to not_change { ip.l4_bytes }
        .and not_change { ip.l4_bytes_offset }

      expect(ip.version).to eq Xlat::Protocols::Ip::Ipv6
      expect(ip.proto).to eq 6
      expect(ip.l4).to be_kind_of Xlat::Protocols::Tcp

      expect {
        ip.apply_changes
      }.to change { ip.l4_bytes.get_value(:U16, ip.l4_bytes_offset + 16) }.by(12)
    end

    it 'converts IPv6 TCP into IPv4' do
      ip = subject.parse(bytes: TestPackets::TEST_PACKET_IPV6_TCP.dup)

      new_header = IO::Buffer.new(20)
      expect {
        ip.convert_version!(Xlat::Protocols::Ip::Ipv4, new_header, -12)
      }.to not_change { ip.l4_bytes }
        .and not_change { ip.l4_bytes_offset }

      expect(ip.version).to eq Xlat::Protocols::Ip::Ipv4
      expect(ip.proto).to eq 6
      expect(ip.l4).to be_kind_of Xlat::Protocols::Tcp

      expect {
        ip.apply_changes
      }.to change { ip.l4_bytes.get_value(:U16, ip.l4_bytes_offset + 16) }.by(12)
    end
  end
end
