module TestPackets
  class << self
    def buffer(ary)
      IO::Buffer.for(ary.flatten.map { _1.to_i(16).chr }.join.b.freeze)
    end
  end

  TEST_PACKET_IPV4_UDP = buffer [
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
  ]

  TEST_PACKET_IPV4_OPTS_UDP = buffer [
    # ipv4
    %w(46 00), # header len (24)
    %w(00 21), # total length (24+8+1=33)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(11), # protocol
    %w(e7 6c), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst
    %w(1e 04 2c b3), # opt: experimental

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(0b 3b), # checksum

    # payload
    %w(af),
  ]

  TEST_PACKET_IPV6_UDP = buffer [
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
  ]

  TEST_PACKET_IPV6_HOPOPT_DSTOPT_UDP = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 29), # payload length (8+16+16+1=41)
    %w(00), # next header (hopopt)
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # hopopt
    %w(3c), # next header (ipv6-opts)
    %w(01), # header extension length (=16)
    %w(1e 0c 01 02 03 04 05 06 07 08 09 0a 0b 0c),

    # ipv6-opts
    %w(11), # next header (udp)
    %w(01), # header extension length (=16)
    %w(1e 0c 01 02 03 04 05 06 07 08 09 0a 0b 0c),

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 09), # length
    %w(af 04), # checksum

    # payload
    %w(af),
  ]

  TEST_PACKET_IPV4_TCP = buffer [
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
  ]

  TEST_PACKET_IPV6_TCP = buffer [
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
  ]

  TEST_PACKET_IPV4_FRAG_ORIGINAL = buffer [
    # ipv4
    %w(45 00),
    %w(06 5c), # total length (20+8+1600=1628)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(11), # protocol
    %w(2c e9), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(06 48), # length (1608)
    %w(67 77), # checksum

    # payload
    %w(de ad be ef) * (1600 / 4),
  ]
  TEST_PACKET_IPV4_FRAG_UDP_0_1472 = buffer [
    # ipv4
    %w(45 00),
    %w(05 dc), # total length (20+8+1472=1500)
    %w(c3 98), # identification
    %w(20 00), # flags (MF)
    %w(40), # ttl
    %w(11), # protocol
    %w(0d 69), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(06 48), # length (1608)
    %w(67 77), # checksum

    # payload
    %w(de ad be ef) * (1472 / 4),
  ]
  def TEST_PACKET_IPV4_FRAG_UDP_0_1472.__no_l4_checksum = true
  TEST_PACKET_IPV4_FRAG_UDP_1472_1600 = buffer [
    # ipv4
    %w(45 00),
    %w(00 94), # total length (20+128=148)
    %w(c3 98), # identification
    %w(00 b9), # flags / offset (1480/8=185)
    %w(40), # ttl
    %w(11), # protocol
    %w(31 f8), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # udp payload (cont.)
    %w(de ad be ef) * (128 / 4),
  ]
  def TEST_PACKET_IPV4_FRAG_UDP_1472_1600.__no_l4_checksum = true

  TEST_PACKET_IPV4_FRAG_UDP_0_1440 = buffer [
    # ipv4
    %w(45 00),
    %w(05 bc), # total length (20+8+1440=1468)
    %w(c3 98), # identification
    %w(20 00), # flags (MF)
    %w(40), # ttl
    %w(11), # protocol
    %w(0d 89), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(06 48), # length (1608)
    %w(67 77), # checksum

    # payload
    %w(de ad be ef) * (1440 / 4),
  ]
  def TEST_PACKET_IPV4_FRAG_UDP_0_1440.__no_l4_checksum = true
  TEST_PACKET_IPV4_FRAG_UDP_1440_1600 = buffer [
    # ipv4
    %w(45 00),
    %w(00 b4), # total length (20+160=180)
    %w(c3 98), # identification
    %w(00 b5), # flags / offset (1448/8=181)
    %w(40), # ttl
    %w(11), # protocol
    %w(31 dc), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # udp payload (cont.)
    %w(de ad be ef) * (160 / 4),
  ]
  def TEST_PACKET_IPV4_FRAG_UDP_1440_1600.__no_l4_checksum = true

  TEST_PACKET_IPV6_FRAG_ORIGINAL = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(06 48), # payload length (8+1600=1608)
    %w(11), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(06 48), # length (1608)
    %w(0b 41), # checksum

    # payload
    %w(de ad be ef) * (1600 / 4),
  ]
  TEST_PACKET_IPV6_FRAG_UDP_0_1440 = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(05 b0), # payload length (8+8+1440=1456)
    %w(2c), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # ipv6-frag
    %w(11), # next header (udp)
    %w(00), # reserved
    %w(00 01), # fragment offset (0) / flags (M)
    %w(00 00 c3 98), # identification

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(06 48), # length (1608)
    %w(0b 41), # checksum

    # payload
    %w(de ad be ef) * (1440 / 4),
  ]
  def TEST_PACKET_IPV6_FRAG_UDP_0_1440.__no_l4_checksum = true
  TEST_PACKET_IPV6_FRAG_UDP_1440_1600 = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 a8), # payload length (8+160=168)
    %w(2c), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # ipv6-frag
    %w(11), # next header (udp)
    %w(00), # reserved
    %w(05 a8), # fragment offset (1448/8=181) / flags
    %w(00 00 c3 98), # identification

    # udp payload (cont.)
    %w(de ad be ef) * (160 / 4),
  ]
  def TEST_PACKET_IPV6_FRAG_UDP_1440_1600.__no_l4_checksum = true

  TEST_PACKET_IPV4_ICMP_ECHO = buffer [
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
  ]

  TEST_PACKET_IPV6_ICMP_ECHO = buffer [
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
  ]

  TEST_PACKET_IPV4_ICMP_ECHO_REPLY = buffer [
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
    %w(00 00), # type=0, code=0 (echo reply)
    %w(92 fd), # checksum
    %w(12 34), # identifier
    %w(ab cd), # sequence number

    # payload
    %w(af),
  ]

  TEST_PACKET_IPV6_ICMP_ECHO_REPLY = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 09), # payload length (8+1=9)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # icmp
    %w(81 00), # type=129,code=0 (echo reply)
    %w(31 73), # checksum
    %w(12 34), # identifier
    %w(ab cd), # sequence number

    # payload
    %w(af),
  ]

  TEST_PACKET_IPV4_ICMP_ADMIN = buffer [
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
  ]

  TEST_PACKET_IPV6_ICMP_ADMIN = buffer [
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
  ]

  TEST_PACKET_IPV4_ICMP_ADMIN_TRUNC = buffer [
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
    %w(8c 54), # checksum
    %w(00 00 00 00), # unused

    # payload ipv4
    %w(45 00),
    %w(00 24), # total length (20+8+8=36)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(11), # protocol
    %w(33 2b), # checksum
    %w(c0 00 02 02), # src
    %w(c0 00 02 03), # dst

    # payload udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 10), # length
    %w(ff ff), # checksum

    # payload
    %w(af),

    # truncated (7 octets)
  ]

  TEST_PACKET_IPV6_ICMP_ADMIN_TRUNC = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 39), # payload length (8+40+8+1=57)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # icmp
    %w(01 01), # type=1,code=1 (unreachable admin prohibited)
    %w(b8 4c), # checksum
    %w(00 00 00 00), # unused

    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 10), # payload length (8+8=16)
    %w(11), # next header
    %w(40), # hop limit
    %w(00 64 ff 9b 00 01 ff fe 00 00 00 00 c0 00 02 02), # src
    %w(00 64 ff 9b 00 00 00 00 00 00 00 00 c0 00 02 03), # dst

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 10), # length
    %w(ff ff), # checksum

    # payload
    %w(af),

    # truncated (7 octets)
  ]

  TEST_PACKET_IPV4_ICMP_MTU = buffer [
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
    %w(10 82), # checksum
    %w(00 00), # reserved
    %w(00 00), # mtu, to be filled

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
  ]
  def TEST_PACKET_IPV4_ICMP_MTU.with_mtu(mtu)
    dup.tap do |pkt|
      pkt.set_value(:U16, 20+2, Xlat::Protocols::Ip.checksum_adjust(pkt.get_value(:U16, 20+2), mtu))
      pkt.set_value(:U16, 20+6, mtu)
    end
  end

  TEST_PACKET_IPV4_ICMP_MTU_FRAG_PAYLOAD = buffer [
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
    %w(10 82), # checksum
    %w(00 00), # reserved
    %w(00 00), # mtu, to be filled

    # payload ipv4
    %w(45 00),
    %w(00 1d), # total length (20+8+1=29)
    %w(c3 98), # identification
    %w(20 00), # flags (MF)
    %w(40), # ttl
    %w(11), # protocol
    %w(13 32), # checksum
    %w(c0 00 02 02), # src
    %w(c0 00 02 03), # dst

    # payload udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(10 00), # length
    %w(6b e8), # checksum

    # payload
    %w(af), # truncated
  ]
  def TEST_PACKET_IPV4_ICMP_MTU_FRAG_PAYLOAD.with_mtu(mtu)
    dup.tap do |pkt|
      pkt.set_value(:U16, 20+2, Xlat::Protocols::Ip.checksum_adjust(pkt.get_value(:U16, 20+2), mtu))
      pkt.set_value(:U16, 20+6, mtu)
    end
  end

  TEST_PACKET_IPV6_ICMP_MTU = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 39), # payload length (8+40+8+1=57)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # icmp
    %w(02 00), # type=2,code=0 (packet too big)
    %w(3b 7c), # checksum
    %w(00 00 00 00), # mtu, to be filled

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
  ]
  def TEST_PACKET_IPV6_ICMP_MTU.with_mtu(mtu)
    dup.tap do |pkt|
      pkt.set_value(:U16, 40+2, Xlat::Protocols::Ip.checksum_adjust(pkt.get_value(:U16, 40+2), mtu))
      pkt.set_value(:U32, 40+4, mtu)
    end
  end

  TEST_PACKET_IPV6_ICMP_MTU_FRAG_PAYLOAD = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 41), # payload length (8+40+8+8+1=65)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # icmp
    %w(02 00), # type=2,code=0 (packet too big)
    %w(4b d2), # checksum
    %w(00 00 00 00), # mtu, to be filled

    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 11), # payload length (8+8+1=17)
    %w(2c), # next header
    %w(40), # hop limit
    %w(00 64 ff 9b 00 01 ff fe 00 00 00 00 c0 00 02 02), # src
    %w(00 64 ff 9b 00 00 00 00 00 00 00 00 c0 00 02 03), # dst

    # ipv6-frag
    %w(11), # next header
    %w(00), # reserved
    %w(00 01), # offset (0), more fragments
    %w(00 00 c3 98), # identification

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(10 00), # length
    %w(6b e8), # checksum

    # payload
    %w(af),  # truncated
  ]
  def TEST_PACKET_IPV6_ICMP_MTU_FRAG_PAYLOAD.with_mtu(mtu)
    dup.tap do |pkt|
      pkt.set_value(:U16, 40+2, Xlat::Protocols::Ip.checksum_adjust(pkt.get_value(:U16, 40+2), mtu))
      pkt.set_value(:U32, 40+4, mtu)
    end
  end

  TEST_PACKET_IPV4_ICMP_POINTER = buffer [
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
  ]

  TEST_PACKET_IPV6_ICMP_POINTER = buffer [
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
  ]

  TEST_PACKET_IPV4_ICMP_ADMIN_RFC4884 = buffer [
    # ipv4
    %w(45 00),
    %w(00 a8), # total length (20+8+20+8+100+4+8=168)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(01), # protocol
    %w(32 ad), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # icmp
    %w(03 0a), # type=3,code=10 (unreachable admin prohibited)
    %w(80 f6), # checksum
    %w(00), # unused
    %w(20), # original datagram length (measured in 32 bits)
    %w(00 00), # unused

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
    %w(0b 45), # checksum

    # payload
    %w(af),

    # padding to 128 bytes
    %w(00) * (128-20-8-1),

    # icmp extension header
    %w(20 00), # version
    %w(78 2f), # checksum

    # icmp extension object (private use)
    %w(00 08), # length
    %w(ff 1b), # class / sub-type
    %w(12 34 56 78), # payload
  ]

  TEST_PACKET_IPV6_ICMP_ADMIN_RFC4884 = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 4c), # payload length (8+40+8+8+4+8=76)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # icmp
    %w(01 01), # type=1,code=1 (unreachable admin prohibited)
    %w(a6 02), # checksum
    %w(07), # original datagram length (measured in 64 bits)
    %w(00 00 00), # unused

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
    %w(0b 45), # checksum

    # payload
    %w(af),

    # padding to 64bit boundary
    %w(00) * 7,

    # icmp extension header
    %w(20 00), # version
    %w(78 2f), # checksum

    # icmp extension object (private use)
    %w(00 08), # length
    %w(ff 1b), # class / sub-type
    %w(12 34 56 78), # payload
  ]

  TEST_PACKET_IPV4_ICMP_FRAG_PAYLOAD = buffer [
    # ipv4
    %w(45 00),
    %w(00 40), # total length (20+8+20+8+8=64)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(01), # protocol
    %w(33 15), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # icmp
    %w(03 0a), # type=3,code=10 (unreachable admin prohibited)
    %w(3f e4), # checksum
    %w(00 00 00 00), # unused

    # payload ipv4
    %w(45 00),
    %w(00 24), # total length (20+8+8=36)
    %w(c3 98), # identification
    %w(20 00), # flags (more fragments)
    %w(40), # ttl
    %w(11), # protocol
    %w(13 2b), # checksum
    %w(c0 00 02 02), # src
    %w(c0 00 02 03), # dst

    # payload udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 18), # length
    %w(3c aa), # checksum

    # payload
    %w(af af af af af af af af),
    # the next fragment contains 8 octets
  ]

  TEST_PACKET_IPV4_ICMP_ICMP_PAYLOAD = buffer [
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
    %w(0b 00), # type=11,code=0 (time exceeded)
    %w(f4 ff), # checksum
    %w(00 00 00 00), # unused

    # ipv4
    %w(45 00),
    %w(00 1d), # total length (20+8+1=29)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(01), # protocol
    %w(33 38), # checksum
    %w(c0 00 02 08), # src
    %w(c0 00 02 07), # dst

    # icmp
    %w(08 00), # type=8,code=0 (echo request)
    %w(8a fd), # checksum
    %w(12 34), # identifier
    %w(ab cd), # sequence number

    # payload
    %w(af),
  ]

  TEST_PACKET_IPV6_ICMP_ICMP_PAYLOAD = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 39), # payload length (8+40+8+1=57)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # icmp
    %w(03 00), # type=3,code=0 (time exceeded)
    %w(82 3f), # checksum
    %w(00 00 00 00), # unused

    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 09), # payload length (9)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # src
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # dst

    # icmp
    %w(80 00), # type=128,code=0 (echo request)
    %w(32 73), # checksum
    %w(12 34), # identifier
    %w(ab cd), # sequence number

    # payload
    %w(af),
  ]

  TEST_PACKET_IPV6_ICMP_FRAG_PAYLOAD = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 48), # payload length (8+40+8+8+8=72)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # icmp
    %w(01 01), # type=1,code=1 (unreachable admin prohibited)
    %w(7c 2b), # checksum
    %w(00 00 00 00), # unused

    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 18), # payload length (8+8+8=24)
    %w(2c), # next header (ipv6-frag)
    %w(40), # hop limit
    %w(00 64 ff 9b 00 01 ff fe 00 00 00 00 c0 00 02 02), # src
    %w(00 64 ff 9b 00 00 00 00 00 00 00 00 c0 00 02 03), # dst

    # ipv6-frag
    %w(11), # next header
    %w(00), # reserved
    %w(00 01), # offset, more fragments
    %w(00 00 c3 98), # identification

    # udp
    %w(c1 5b), # src port
    %w(00 35), # dst port
    %w(00 18), # length
    %w(3c aa), # checksum

    # payload
    %w(af af af af af af af af),
    # the next fragment contains 8 octets
  ]

  TEST_PACKET_IPV6_ETHERIP = buffer [
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
  ]

  TEST_PACKET_IPV4_ETHERIP = buffer [
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
  ]

  TEST_PACKET_IPV4_ICMP_INCOMPLETE_HDR = buffer [
    # ipv4
    %w(45 00),
    %w(00 18), # total length (20+4=24)
    %w(c3 98), # identification
    %w(00 00), # flags
    %w(40), # ttl
    %w(01), # protocol
    %w(33 3d), # checksum
    %w(c0 00 02 07), # src
    %w(c0 00 02 08), # dst

    # icmp
    %w(00 00), # type=0,code=0
    %w(ff ff), # checksum
    # incomplete header
  ]

  TEST_PACKET_IPV6_ICMP_INCOMPLETE_HDR = buffer [
    # ipv6
    %w(60 00 00 00), # version, qos, flow label
    %w(00 04), # payload length (4)
    %w(3a), # next header
    %w(40), # hop limit
    %w(20 01 0d b8 00 60 00 00 00 00 00 00 c0 00 02 07), # src
    %w(20 01 0d b8 00 64 00 00 00 00 00 00 c0 00 02 08), # dst

    # icmp
    %w(00 00), # type=0,code=0
    %w(1f 7b), # checksum
    # incomplete header
  ]
end
