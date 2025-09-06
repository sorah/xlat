require 'xlat/address_translators/rfc6052'
require 'xlat/protocols/ip'
require 'xlat/rfc7915'

require 'benchmark/ips'
require 'pathname'

require_relative '../spec/test_packets'

STATE_DIR = Pathname(__dir__).join('../tmp/benchmark').tap(&:mkpath)

def benchmark(task, &block)
  Benchmark.ips do |bm|
    include TestPackets

    bm.config(warmup: 1, time: 10)

    if label = ENV['XLAT_BENCHMARK_LABEL']
      title = "#{label}: #{task}"
    else
      title = task
    end
    bm.report("#{title}", &block)

    if ENV.key?('XLAT_BENCHMARK_LABEL')
      bm.save! STATE_DIR.join(task)
      bm.compare!
    end
  end
end

source_address_translator = Xlat::AddressTranslators::Rfc6052.new('2001:0db8:0060::/96')
destination_address_translator = Xlat::AddressTranslators::Rfc6052.new('2001:0db8:0064::/96')
rfc7915 = Xlat::Rfc7915.new(source_address_translator:, destination_address_translator:)

benchmark 'UDP 6-to-4' do
  packet = Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_UDP.dup)
  fail unless rfc7915.translate_to_ipv4(packet, 1500)
ensure
  rfc7915.return_buffer_ownership
end

benchmark 'UDP 4-to-6' do
  packet = Xlat::Protocols::Ip.parse(TEST_PACKET_IPV4_UDP.dup)
  fail unless rfc7915.translate_to_ipv6(packet, 1500)
ensure
  rfc7915.return_buffer_ownership
end

benchmark 'TCP 6-to-4' do
  packet = Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_TCP.dup)
  fail unless rfc7915.translate_to_ipv4(packet, 1500)
ensure
  rfc7915.return_buffer_ownership
end

benchmark 'TCP 4-to-6' do
  packet = Xlat::Protocols::Ip.parse(TEST_PACKET_IPV4_TCP.dup)
  fail unless rfc7915.translate_to_ipv6(packet, 1500)
ensure
  rfc7915.return_buffer_ownership
end

benchmark 'ICMP echo 6-to-4' do
  packet = Xlat::Protocols::Ip.parse(TEST_PACKET_IPV6_ICMP_ECHO.dup)
  fail unless rfc7915.translate_to_ipv4(packet, 1500)
ensure
  rfc7915.return_buffer_ownership
end

benchmark 'ICMP echo 4-to-6' do
  packet = Xlat::Protocols::Ip.parse(TEST_PACKET_IPV4_ICMP_ECHO.dup)
  fail unless rfc7915.translate_to_ipv6(packet, 1500)
ensure
  rfc7915.return_buffer_ownership
end
