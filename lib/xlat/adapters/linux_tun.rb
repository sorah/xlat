require 'socket'

module Xlat
  module Adapters
    class LinuxTun
      DEV_TUN = -'/dev/net/tun'
      IFF_TUN = 0x0001
      IFF_NO_PI = 0x1000
      TUNSETIFF = 0x400454ca
      SIOCSIFMTU = 0x8922

      def initialize(ifname)
        unless ifname.bytesize < Socket::IFNAMSIZ  # maxlen including the terminating NUL
          raise ArgumentError, "Too long interface name: #{ifname}"
        end

        @ifname = ifname
        @mtu = 1500
        @io = File.open(DEV_TUN, 'r+:BINARY')
        @io.ioctl(TUNSETIFF, [@ifname, IFF_TUN | IFF_NO_PI].pack("a#{Socket::IFNAMSIZ}s!"))
      end

      attr_reader :mtu

      def mtu=(value)
        Socket.open(Socket::AF_INET, Socket::SOCK_STREAM, 0) do |sock|
          sock.ioctl(SIOCSIFMTU, [@ifname, value].pack("a#{Socket::IFNAMSIZ}i!"))
        end
        @mtu = value
      end

      def read(buf)
        @io.readpartial(@mtu, buf)
      end

      def write(*bufs)
        @io.write(*bufs)
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
