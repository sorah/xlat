class IO::Buffer
  def <=>(other)
    return -1 if self.size < other.size
    return +1 if self.size > other.size

    self.size.times do |i|
      cmp = self.get_value(:U8, i) <=> self.get_value(:U8, i)
      return cmp if cmp != 0
    end

    return 0
  end
end
