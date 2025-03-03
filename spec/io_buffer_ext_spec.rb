require 'spec_helper'

require 'xlat/io_buffer_ext'

RSpec.describe Xlat::IOBufferExt do
  describe '#readv' do
    TEST_STR = -'01234567890123456789'

    around do |example|
      @r, @w = IO.pipe
      @w.write(TEST_STR)
      example.run
    ensure
      @r.close
      @w.close
    end

    it do
      expect {
        Xlat::IOBufferExt.readv("", [])
      }.to raise_error(TypeError)
    end

    it do
      expect {
        Xlat::IOBufferExt.readv(@r, IO::Buffer.new(1))
      }.to raise_error(TypeError)
    end

    it do
      expect {
        Xlat::IOBufferExt.readv(@r, [1])
      }.to raise_error(TypeError)
    end

    context 'IO is closed' do
      it do
        @r.close
        expect {
          Xlat::IOBufferExt.readv(@r, [])
        }.to raise_error(IOError)
      end
    end

    context 'single buffer' do
      context 'When buffer is larger than data' do
        it 'reads all data' do
          buf = IO::Buffer.new(30)

          expect(Xlat::IOBufferExt.readv(@r, [buf])).to eq 20
          expect(buf.get_string).to eq (TEST_STR + "\x0"*10)
        end
      end

      context 'When buffer is smaller than data' do
        it 'reads data up to buffer length' do
          buf = IO::Buffer.new(10)
          expect(Xlat::IOBufferExt.readv(@r, [buf])).to eq 10
          expect(buf.get_string).to eq TEST_STR[0,10]
          expect(@r.readpartial(100)).to eq TEST_STR[10..-1]
        end
      end
    end
  end

  describe '#writev' do
    around do |example|
      @r, @w = IO.pipe
      example.run
    ensure
      @r.close
      @w.close
    end

    context 'IO is closed' do
      it do
        @r.close
        expect {
          Xlat::IOBufferExt.writev(@w, [IO::Buffer.new(1)])
        }.to raise_error(IOError)
      end
    end

    context 'single buffer' do
      it do
        expect(Xlat::IOBufferExt.writev(@w, [IO::Buffer.for('0123')])).to eq 4
        @w.close
        expect(@r.read).to eq '0123'
      end
    end

    context 'multiple buffers' do
      it do
        bufs = [IO::Buffer.for('0123'), IO::Buffer.for('4567'), IO::Buffer.for('89')]
        expect(Xlat::IOBufferExt.writev(@w, bufs)).to eq 10
        @w.close
        expect(@r.read).to eq '0123456789'
      end
    end
  end
end

RSpec.describe Xlat::IOBufferExt::Compare do
  describe '#compare' do
    context 'when buffers are equal' do
      it 'returns 0' do
        buf1 = IO::Buffer.for('0123')
        buf2 = IO::Buffer.for('0123')
        expect(buf1.compare(buf2)).to eq 0
      end
    end

    context 'when buffers are not equal (less)' do
      it 'returns -1' do
        buf1 = IO::Buffer.for('0123')
        buf2 = IO::Buffer.for('0124')
        expect(buf1.compare(buf2)).to eq -1
      end
    end

    context 'when buffers are not equal (greater)' do
      it 'returns -1' do
        buf1 = IO::Buffer.for('0124')
        buf2 = IO::Buffer.for('0123')
        expect(buf1.compare(buf2)).to eq 1
      end
    end

    context 'when the other buffer is smaller' do
      it 'returns 1' do
        buf1 = IO::Buffer.for('0123')
        buf2 = IO::Buffer.for('012')
        expect { buf1.compare(buf2) }.to raise_error(ArgumentError)
      end
    end

    context 'with offset' do
      context 'when buffers are equal' do
        it 'returns 0' do
          buf1 = IO::Buffer.for('0123')
          buf2 = IO::Buffer.for('123')
          expect(buf1.compare(buf2, 1)).to eq 0
        end
      end
    end

    context 'with offset/length/other_offset' do
      context 'when buffers are equal' do
        it 'returns 0' do
          buf1 = IO::Buffer.for('012345678')
          buf2 = IO::Buffer.for('991234999')
          expect(buf1.compare(buf2, 1, 4, 2)).to eq 0
        end
      end

      context 'when buffers are not equal (less)' do
        it 'returns -1' do
          buf1 = IO::Buffer.for('012345678')
          buf2 = IO::Buffer.for('991234999')
          expect(buf1.compare(buf2, 1, 5, 2)).to eq -1
        end
      end
    end
  end
end