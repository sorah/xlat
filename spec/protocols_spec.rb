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
        .parse(bytes: ip.l4.payload_bytes, bytes_offset: ip.l4.payload_bytes_offset)
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
        .parse(bytes: ip.l4.payload_bytes, bytes_offset: ip.l4.payload_bytes_offset)
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
        .parse(bytes: ip.l4.payload_bytes, bytes_offset: ip.l4.payload_bytes_offset)
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
        .parse(bytes: ip.l4.payload_bytes, bytes_offset: ip.l4.payload_bytes_offset)
      aggregate_failures do
        expect(inner).to be_kind_of Xlat::Protocols::Ip
        expect(inner.version).to eq Xlat::Protocols::Ip::Ipv6
        expect(inner.proto).to eq 17
        expect(inner.l4).to be_kind_of Xlat::Protocols::Udp
        expect(inner.l4_bytes_offset).to eq 88
        expect(inner.l4_bytes_length).to eq 9
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
