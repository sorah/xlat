# https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/04/

module Xlat
  class Pcap
    attr_reader :io, :snap_len

    def initialize(io, snap_len: 0xffff)
      @io = io
      @snap_len = snap_len

      write_header
    end

    MAGIC = 0xA1B23C4D  # nanosec timestamp
    MAJOR = 2
    MINOR = 4
    LINKTYPE_RAW = 101  # raw IP

    private def write_header
      h = IO::Buffer.new(24)
      h.set_values(%i[u32 u16 u16 u32 u32 u32 u32], 0, [
        MAGIC,
        MAJOR, MINOR,
        0,
        0,
        @snap_len,
        LINKTYPE_RAW,
      ])

      h.write(@io)
    end

    def write(packet, ts: Time.now)
      caplen = [packet.size, @snap_len].min

      h = IO::Buffer.new(16)
      h.set_values(%i[u32 u32 u32 u32], 0, [
        ts.to_i,
        ts.nsec,
        caplen,
        packet.size,
      ])

      h.write(@io)
      packet.write(@io, caplen)
    end
  end
end
