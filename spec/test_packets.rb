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
  ]

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
  ]

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
