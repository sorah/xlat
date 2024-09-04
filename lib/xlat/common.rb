module Xlat
  module Common
    module_function

    def sum16be(buffer)
      sum = 0
      buffer.each(:U16) do |_, x|
        sum += x
      end
      sum
    end
  end
end
