require 'xlat/protocols/ip'

module Xlat
  class Runner
    def initialize(adapter:, translator:, logger: nil)
      @adapter = adapter
      @translator = translator
      @logger = logger
    end

    def run
      buf = IO::Buffer.new(@adapter.mtu)
      parser = Protocols::Ip.new
      output = IOVector.new(5)

      loop do
        bytes = @adapter.read(buf)

        pkt = parser.parse(bytes:)
        unless pkt
          @logger&.info { "DISCARD: not parsable: #{bytes.inspect}" }
          next
        end

        case
        when pkt.version == Protocols::Ip::Ipv4
          translated = @translator.translate_to_ipv6(pkt, output)
        when pkt.version == Protocols::Ip::Ipv6
          translated = @translator.translate_to_ipv4(pkt, output)
        else
          fail 'unknown IP version'
        end

        unless translated
          @logger&.info { "DISCARD: not translatable: #{bytes.inspect}" }
          next
        end

        @adapter.write(*output)
      rescue
        fail "BUG: #{bytes.inspect}"
      ensure
        @translator.return_buffer_ownership if output
      end
    end
  end
end
