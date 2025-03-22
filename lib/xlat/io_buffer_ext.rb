require 'xlat/io_buffer_ext.so'

class IO::Buffer
  include Xlat::IOBufferExt::Compare
end
