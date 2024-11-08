require 'spec_helper'

require 'xlat/io_buffer_ext'

RSpec.describe Xlat::IOVector do
  describe '#add' do
    before do |example|
      @vec = Xlat::IOVector.new(0)
    end

    it do
      expect { @vec.add(IO::Buffer.for('0123'), -1, 3) }.to raise_error RangeError
    end

    it do
       expect { @vec.add("0123", 0, 3) }.to raise_error TypeError
    end
  end

  describe '#read' do
    TEST_STR = -'01234567890123456789'

    around do |example|
      @vec = Xlat::IOVector.new(0)
      @r, @w = IO.pipe
      @w.write(TEST_STR)
      example.run
    ensure
      @r.close
      @w.close
    end

    context 'IO is closed' do
      it do
        @r.close
        expect {
          @vec.read(@r)
        }.to raise_error(IOError)
      end
    end

    context 'readonly buffer' do
      it do
        @vec.add(IO::Buffer.new(4), 0, 4)
        @vec.add(IO::Buffer.for('0123'), 0, 4)

        expect { @vec.read(@r) }.to raise_error IO::Buffer::AccessError
      end
    end

    context 'single buffer' do
      context 'When buffer is larger than data' do
        it 'reads all data' do
          buf = IO::Buffer.new(30)
          @vec.add(buf, 0, 30)

          expect(@vec.read(@r)).to eq 20
          expect(buf.get_string).to eq ('01234567890123456789' + ?\0*10)
        end
      end

      context 'When buffer is smaller than data' do
        it 'reads data up to buffer length' do
          buf1 = IO::Buffer.new(10)
          buf2 = IO::Buffer.new(10)
          @vec.add(buf1, 0, 5)
          @vec.add(buf2, 5, 5)

          expect(@vec.read(@r)).to eq 10
          expect(buf1.get_string).to eq ('01234' + ?\0*5)
          expect(buf2.get_string).to eq (?\0*5 + '56789')
          expect(@r.readpartial(100)).to eq '0123456789'
        end
      end
    end
  end

  describe '#write' do
    around do |example|
      @vec = Xlat::IOVector.new(0)
      @r, @w = IO.pipe
      example.run
    ensure
      @r.close
      @w.close
    end

    context 'IO is closed' do
      it do
        @vec.add(IO::Buffer.new(1), 0, 1)
        @r.close
        expect {
          @vec.write(@w)
        }.to raise_error(IOError)
      end
    end

    context 'single buffer' do
      it do
        @vec.add(IO::Buffer.for('0123456789'), 2, 4)

        expect(@vec.write(@w)).to eq 4
        @w.close
        expect(@r.read).to eq '2345'
      end
    end

    context 'multiple buffers' do
      it do
        @vec.add(IO::Buffer.for('0123'), 0, 4)
        @vec.add(IO::Buffer.for('4567xx'), 0, 4)
        @vec.add(IO::Buffer.for('yy89zz'), 2, 2)

        expect(@vec.write(@w)).to eq 10
        @w.close
        expect(@r.read).to eq '0123456789'
      end
    end

    context 'out of bounds' do
      it do
        @vec.add(IO::Buffer.for('0123'), 0, 10)
        expect { @vec.write(@w) }.to raise_error ArgumentError
      end

      it do
        @vec.add(IO::Buffer.for('0123'), 10, 1)
        expect { @vec.write(@w) }.to raise_error ArgumentError
      end
    end
  end
end
