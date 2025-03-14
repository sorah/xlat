require_relative './instrumentation'

require 'ruzzy'
require 'xlat/rfc7915'
require 'xlat/address_translators/rfc6052'
require 'xlat/protocols/ip'

@xlat = Xlat::Rfc7915.new(
  source_address_translator: Xlat::AddressTranslators::Rfc6052.new('2001:db8:60::/96'),
  destination_address_translator: Xlat::AddressTranslators::Rfc6052.new('2001:db8:64::/96'),
)

def fuzzing_target(input)
  buffer = IO::Buffer.new(input.bytesize)
  buffer.set_string(input)
  pkt = Xlat::Protocols::Ip.parse(buffer)
  return unless pkt

  case pkt.version.to_i
  when 4
    output = @xlat.translate_to_ipv6(pkt, 1500)
  when 6
    output = @xlat.translate_to_ipv4(pkt, 1500)
  else
    fail 'unknown IP version'
  end

  return output
ensure
  @xlat.return_buffer_ownership
end

test_one_input = lambda do |data|
  fuzzing_target(data) ? 0 : -1
end

RubyVM::YJIT.enable
Ruzzy.fuzz(test_one_input)
