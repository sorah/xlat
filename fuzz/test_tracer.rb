#!/usr/bin/env ruby
require_relative '../spec/test_packets.rb'
require 'digest/sha1'
require 'pathname'

corpus_dir = Pathname(__dir__).join('corpus').tap(&:mkpath)
TestPackets.constants.each do |k|
  val = TestPackets.const_get(k)
  next unless val.is_a?(IO::Buffer)

  digest = Digest::SHA1.hexdigest(val.get_string)
  File.write(corpus_dir + digest, val.get_string)
end

require 'ruzzy'

Ruzzy.trace('test_harness.rb')
