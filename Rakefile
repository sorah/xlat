# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "rake/extensiontask"

RSpec::Core::RakeTask.new(:spec)

task default: :spec

Rake::ExtensionTask.new("xlat/io_buffer_ext",
  Gem::Specification.load("xlat.gemspec")) do |ext|
  ext.lib_dir = "lib/xlat"
end

task spec: :compile


directory 'doc'

file 'doc/test_packets.xml' => ['doc', 'spec/test_packets.rb', 'Rakefile'] do |f|
  require 'open3'
  require 'pathname'
  require 'rexml'
  require 'xlat/pcap'
  require_relative './spec/test_packets'

  packets = TestPackets.constants.filter_map {|k|
    val = TestPackets.const_get(k)
    next unless val.is_a?(IO::Buffer)

    {
      name: k,
      source_location: TestPackets.const_source_location(k).yield_self {|path, line|
        [Pathname(path).relative_path_from(__dir__), line]
      },
      value: val,
    }
  }.sort_by { _1[:source_location] }

  pdml = Open3.popen2(*%W[tshark -n -r- -Tpdml]) do |stdin, stdout, *|
    pcap = Xlat::Pcap.new(stdin)
    packets.each do |h|
      pcap.write(h[:value], ts: Time.at(0))
    end
    stdin.close

    xml = REXML::Document.new(stdout)

    xml.get_elements('//packet').zip(packets) do |e_packet, pkt|
      comment = "#{pkt[:name]} at #{pkt[:source_location].join(?:)}"

      e_packet.unshift(
        REXML::Element.new('proto').tap {|e_field|
          e_field.add_attribute('name', 'pkt_comment')
          e_field.add_attribute('pos', 0)
          e_field.add_attribute('size', 0)
          e_field.add_attribute('showname', comment)
        },
      )
    end

    File.write(f.name, xml.to_s)
  end
end

file 'doc/pdml2html.xsl' => ['doc'] do |f|
  require 'net/http'
  require 'uri'

  uri = URI.parse('https://gitlab.com/wireshark/wireshark/-/raw/v4.4.0/resources/share/doc/wireshark/pdml2html.xsl').freeze

  File.write(f.name, Net::HTTP.get(uri))
end

desc 'Generate documents'
task gendoc: %w[doc/test_packets.xml doc/pdml2html.xsl]
