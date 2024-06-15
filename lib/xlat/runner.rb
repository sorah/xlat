require 'xlat/protocols/ip'

module Xlat
  class Runner
    def initialize(adapter:, translator:, logger: nil)
      @adapter = adapter
      @translator = translator
      @logger = logger
    end

    def run
      buf = String.new(capacity: @adapter.mtu)

      loop do
        @adapter.read(buf)

        pkt = Protocols::Ip.parse(buf)
        unless pkt
          @logger&.info { "DISCARD: not parsable: #{buf.dump}" }
          next
        end

        case
        when pkt.version == Protocols::Ip::Ipv4
          output = @translator.translate_to_ipv6(pkt)
        when pkt.version == Protocols::Ip::Ipv6
          output = @translator.translate_to_ipv4(pkt)
        else
          fail 'unknown IP version'
        end

        unless output
          @logger&.info { "DISCARD: not translatable: #{buf.dump}" }
          next
        end

        @adapter.write(*output)
      rescue
        fail "BUG: #{buf.dump}"
      ensure
        @translator.return_buffer_ownership if output
      end
    end
  end
end
