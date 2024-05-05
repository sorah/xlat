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
    %w(00 00), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(7b d5), # checksum

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
    %w(1f 9f), # checksum

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
    %w(00 00), # checksum
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
    %w(7b c8), # checksum
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
    %w(1f 92), # checksum
    %w(00 00), # urgent pointer
    %w(01),  # tcp option - nop
    %w(01),  # tcp option - nop
    %w(08 0a 77 71 29 f1 76 9a 80 ff),  # tcp option - timestamp

    # payload
    %w(af),
  ].flatten.map { _1.to_i(16).chr }.join.b.freeze

  def expect_packet_equal(version, expected_packet_, output, checksum: nil)
    expected_packet = expected_packet_.dup
    expected_packet.setbyte(version == 4 ? 8 : 7,0x3f) # TTL

    if checksum && version == 4
      expected_packet.setbyte(10,checksum[0]) # checksum
      expected_packet.setbyte(11,checksum[1]) # checksum
    end

    #p expected_packet[...40].chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')
    #p [output[0]].join.chars.map { _1.ord.to_s(16).rjust(2,'0') }.join(' ')

    hdrlen = version == 4 ? 20 : 40
    expect(output[0]).to eq(expected_packet[0...hdrlen])
    expect(output[1]).to eq(expected_packet[hdrlen..])
  end

  let(:translator) do
    described_class.new(source_address_translator: MockAddrTranslator, destination_address_translator: MockAddrTranslator).tap do |x|
      x.next_fragment_identifier = 0xc398
    end
  end

  describe "#translate_to_ipv4" do
    context "with udp" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_UDP.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TEST_PACKET_IPV4_UDP, output, checksum: [0x34,0x28])
      end
    end

    context "with tcp" do
      let!(:output) { translator.translate_to_ipv4(Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_TCP.dup)) }

      it "translates into ipv4" do
        expect_packet_equal(4, TEST_PACKET_IPV4_TCP, output, checksum: [0x34,0x1b])
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


  end

end
