# frozen_string_literal: true
require_relative './icmp/base'
require_relative './icmp/echo'
require_relative './icmp/error'

module Xlat
  module Protocols
    module Icmp
      def self.parse(packet)
        Xlat::Protocols::Icmp::Base.parse(packet)
      end
    end
  end
end
