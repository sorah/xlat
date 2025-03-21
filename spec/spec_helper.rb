# frozen_string_literal: true

require "xlat"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

config.filter_run focus: true
config.run_all_when_everything_filtered = true

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

RSpec::Matchers.define_negated_matcher :not_change, :change

# expected_packet: IO::Buffer
# actual_packet: Array<IO::Buffer>
RSpec::Matchers.define :match_packet do |expected_packet_, adjust_ttl: -1|
  match do |actual_packet|
    @expected_packet = expected_packet_.dup
    case @expected_packet.get_value(:U8, 0) >> 4
    when 4
      @expected_packet.set_value(:U8, 8, @expected_packet.get_value(:U8, 8) + adjust_ttl)
      cs = @expected_packet.get_value(:U16, 10)
      cs = Xlat::Protocols::Ip.checksum_adjust(cs, 256 * adjust_ttl)
      @expected_packet.set_value(:U16, 10, cs)
    when 6
      @expected_packet.set_value(:U8, 7, @expected_packet.get_value(:U8, 7) + adjust_ttl)
    else
      raise ArgumentError, 'unsupported IP version'
    end

    @expected_packet.get_string == actual_packet.map(&:get_string).join
  end

  failure_message do |actual_packet|
    wrap = 16

    msg = +<<~EOF
      Expected the packet to match:
            #{' EXPECTED '.center(3*wrap+wrap/8-2, ?-)} | #{' ACTUAL '.center(3*wrap+wrap/8-2, ?-)}
    EOF

    expected_bytes = @expected_packet.get_string
    actual_bytes = actual_packet.map(&:get_string).join
    length = [expected_bytes.size, actual_bytes.size].max

    hex = lambda {|byte| byte ? byte.unpack1('H2') : '  ' }

    (0...length).step(wrap) do |offset|
      l_expected = +''
      l_actual = +''

      wrap.times do |i|
        if i % 8 == 0
          l_expected << ' '
          l_actual << ' '
        end

        if RSpec.configuration.color and expected_bytes[offset + i] != actual_bytes[offset + i]
          mark, unmark = "\e[1;4m", "\e[22;24m"  # Bold & underline
        else
          mark = unmark = ''
        end

        l_expected << mark << hex[expected_bytes[offset + i]] << unmark << ' '
        l_actual << mark << hex[actual_bytes[offset + i]] << unmark << ' '
      end

      msg << sprintf('%04x', offset) << ':' << l_expected << '|' << l_actual << ?\n
    end

    msg
  end
end

# acutual_packet: Array<IO::Buffer>
RSpec::Matchers.define :have_correct_checksum do |version:, l4: true|
  match do |actual_packet|
    packet = IO::Buffer.for(actual_packet.map(&:get_string).join)
    actual_version = packet.get_value(:U8, 0) >> 4

    if version != actual_version
      raise 'unexpected IP version'
    end

    fragment = false
    case version
    when 4
      l4proto = packet.get_value(:U8, 9)
      l4offset = (packet.get_value(:U8, 0) & 0xf) * 4
      l4length = packet.get_value(:U16, 2) - l4offset
      unless Xlat::Protocols::Ip.checksum(packet.slice(0, l4offset)) == 0
        raise 'incorrect IPv4 checksum'
      end
      fragment = (packet.get_value(:U16, 6) & 0x3fff) != 0
    when 6
      l4proto = packet.get_value(:U8, 6)
      l4offset = 40
      loop do
        case l4proto
        when 0, 43, 60, 135, 139, 140, 253, 254
          l4proto = packet.get_value(:U8, l4offset)
          l4offset += packet.get_value(:U8, l4offset + 1) * 8 + 8
        when 44  # Fragment
          l4proto = packet.get_value(:U8, l4offset)
          l4offset += 8
          fragment = true
        when 51  # AH
          l4proto = packet.get_value(:U8, l4offset)
          l4offset += packet.get_value(:U8, l4offset + 1) * 4 + 8
        else
          break
        end
      end
      l4length = packet.get_value(:U16, 4) - (l4offset - 40)
    else
      raise 'unsupported IP version'
    end

    if l4offset + l4length != packet.size
      raise 'wrong packet length in L3 header'
    end

    if fragment
      raise 'L4 checksum requested but not supported for fragmented packets' if l4
      return true
    end

    pseudo_header = [
      version == 4 ? packet.slice(12, 4) : packet.slice(8, 16),
      version == 4 ? packet.slice(16, 4) : packet.slice(24, 16),
      IO::Buffer.for([0, l4proto, l4length].pack('CCn')),
    ]
    if l4proto == 1  # ICMP
      pseudo_header = []
    end

    case l4proto
    when 1, 6, 17, 58  # ICMP, TCP, UDP, ICMPv6
      l4data = packet.slice(l4offset, l4length)
      if Xlat::Protocols::Ip.checksum_list([*pseudo_header, l4data]) != 0
        raise 'incorrect L4 checksum'
      end
    else
      raise "L4 checksum requested but not supported for this L4 protocol: #{l4proto}" if l4
    end

    true
  end
end
