require 'spec_helper'
require 'ipaddr'
require 'xlat/address_translators/rfc6052'

RSpec.describe Xlat::AddressTranslators::Rfc6052 do
  WKP = '64:ff9b::/96' # RFC 6052 well-known prefix
  NONSTD = '2001:db8:64::/96' # non standard prefix where not checksum neutral (sum=11805)
  let(:pref64n_string) { WKP }
  let(:translator) { described_class.new(pref64n_string) }

  describe "#translate_address_to_ipv4" do
    it "translates into ipv4" do
      buf = IO::Buffer.new(4)
      expect(translator.translate_address_to_ipv4(IO::Buffer.for(IPAddr.new('64:ff9b::192.0.2.33').hton), 0, buf, 0)).to eq(0)
      expect(buf.get_string).to eq(IPAddr.new('192.0.2.33').hton)
    end

    context "with invalid ipv6 address" do
      it "does nothing" do
        buf = IO::Buffer.for('')
        expect(translator.translate_address_to_ipv4(IO::Buffer.for(IPAddr.new('2001:db8::192.0.2.33').hton), 0, buf, 0)).to eq(nil)
      end
    end

    context "with offset" do
      it "writes translated address at specified offset" do
        buf = IO::Buffer.for("\xaf".b * 20).dup
        expect(translator.translate_address_to_ipv4(IO::Buffer.for(IPAddr.new('64:ff9b::192.0.2.33').hton), 0, buf, 4)).to eq(0)
        expect(buf.size).to eq(20)
        expect(buf.get_string).to eq("\xaf".b * 4 + IPAddr.new('192.0.2.33').hton + "\xaf".b * 12)
      end
    end

    context "with nonstd prefix" do
      let(:pref64n_string) { NONSTD }

      it "translates into ipv4" do
        buf = IO::Buffer.new(4)
        expect(translator.translate_address_to_ipv4(IO::Buffer.for(IPAddr.new('2001:db8:64::192.0.2.33').hton), 0, buf, 0)).to eq(-11805)
        expect(buf.get_string).to eq(IPAddr.new('192.0.2.33').hton)
      end
    end
  end

  describe "#translate_address_to_ipv6" do
    it "translates into ipv6" do
      buf = IO::Buffer.new(16)
      expect(translator.translate_address_to_ipv6(IO::Buffer.for(IPAddr.new('192.0.2.33').hton), 0, buf, 0)).to eq(0)
      expect(buf.get_string).to eq(IPAddr.new('64:ff9b::192.0.2.33').hton)
    end

    context "with offset" do
      it "writes translated address at specified offset" do
        buf = IO::Buffer.for("\xaf".b * 21).dup
        expect(translator.translate_address_to_ipv6(IO::Buffer.for(IPAddr.new('192.0.2.33').hton), 0, buf, 4)).to eq(0)
        expect(buf.size).to eq(21)
        expect(buf.get_string).to eq("\xaf".b * 4 + IPAddr.new('64:ff9b::192.0.2.33').hton + "\xaf".b)
      end
    end

    context "with nonstd prefix" do
      let(:pref64n_string) { NONSTD }

      it "translates into ipv4" do
        buf = IO::Buffer.new(16)
        expect(translator.translate_address_to_ipv6(IO::Buffer.for(IPAddr.new('192.0.2.33').hton), 0, buf, 0)).to eq(11805)
        expect(buf.get_string).to eq(IPAddr.new('2001:db8:64::192.0.2.33').hton)
      end
    end
  end

  context "with prefix other than /96" do
    let(:pref64n_string) { '2001:db8::/64' }
    specify do
      expect { translator }.to raise_error(ArgumentError)
    end
  end

  context "with non-zero reserved bits" do
    let(:pref64n_string) { '2001:db8:0:0:1000::/96' }
    specify do
      expect { translator }.to raise_error(ArgumentError)
    end
  end
end
