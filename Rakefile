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
