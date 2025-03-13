require 'socket'
require 'xlat/io_buffer_ext'

module Xlat
  module Adapters
    class LinuxTun
      DEV_TUN = -'/dev/net/tun'
      IFF_TUN = 0x0001
      IFF_MULTI_QUEUE = 0x0100
      IFF_NO_PI = 0x1000
      TUNSETIFF = 0x400454ca
      SIOCSIFMTU = 0x8922

      def initialize(ifname, multiqueue: false)
        unless ifname.bytesize < Socket::IFNAMSIZ  # maxlen including the terminating NUL
          raise ArgumentError, "Too long interface name: #{ifname}"
        end

        @ifname = ifname
        @mtu = 1500
        @io = File.open(DEV_TUN, 'r+:BINARY')
        options = IFF_TUN | (multiqueue ? IFF_MULTI_QUEUE : 0) | IFF_NO_PI
        @io.ioctl(TUNSETIFF, [@ifname, options].pack("a#{Socket::IFNAMSIZ}s!"))
      end

      attr_reader :mtu

      def mtu=(value)
        Socket.open(Socket::AF_INET, Socket::SOCK_STREAM, 0) do |sock|
          sock.ioctl(SIOCSIFMTU, [@ifname, value].pack("a#{Socket::IFNAMSIZ}i!"))
        end
        @mtu = value
      end

      def read(buf)
        IOBufferExt.readv(@io, [buf])
      end

      def write(*bufs)
        IOBufferExt.writev(@io, bufs)
      end

      def close
        @io.close
      end

      def self.open(...)
        tun = new(...)
        yield tun
      ensure
        tun&.close
      end
    end
  end
end
