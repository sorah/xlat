require 'xlat/protocols/ip'

module Xlat
  class Runner
    def initialize(adapter:, translator:, logger: nil)
      @adapter = adapter
      @translator = translator
      @logger = logger
    end

    def run
      mtu = @adapter.mtu
      buffer = IO::Buffer.new(mtu)
      parser = Protocols::Ip.new

      loop do
        length = @adapter.read(buffer)
        if length < 0
          @logger&.error { "Failed to read packet (errno=#{-length})" }
          next
        end

        pkt = parser.parse(bytes: buffer, bytes_length: length)
        unless pkt
          @logger&.info { "DISCARD: not parsable: #{buffer.slice(0, length).inspect}" }
          next
        end

        case
        when pkt.version == Protocols::Ip::Ipv4
          output = @translator.translate_to_ipv6(pkt, mtu)
        when pkt.version == Protocols::Ip::Ipv6
          output = @translator.translate_to_ipv4(pkt, mtu)
        else
          fail 'unknown IP version'
        end

        unless output
          @logger&.info { "DISCARD: not translatable: #{buffer.slice(0, length).inspect}" }
          next
        end

        @adapter.write(*output)
      rescue
        fail "BUG: #{buffer.slice(0, length).inspect}"
      ensure
        @translator.return_buffer_ownership if output
      end
    end
  end
end
