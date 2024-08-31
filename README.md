# Xlat

Userland NAT64 implementation on Linux in Ruby.

## Supported usage

- Stateless NAT64 - [RFC 7915](https://datatracker.ietf.org/doc/rfc7915/)
  - Maps 1 IPv6 Address : 1 IPv4 Address
  - Combine with kernel netfilter NAT66 masquerade to archieve stateful NAT64 NAPT functionality (multiple IPv6 address/port : 1 IPv4 Address)
  - `IPv6(src=nat66outer, dst=pref64n+ipv4) -> IPv4(src=ipv4nat64outer, dst=ipv4)`
  - `IPv4(src=ipv4, dst=ipv4nat64outer) -> IPv6(src=pref64n+ipv4, dst=nat66outer)`

<!--
### Todo?

- Stateful NAT64  - [RFC 6146](https://datatracker.ietf.org/doc/rfc6146/)
  - Maps multiple IPv6 addresses and ports : IPv4 addresses and ports
-->

## Installation

```ruby
# Gemfile
source 'https://rubygems.org'
gem 'xlat'
```

## Usage

TODO: Write usage instructions here

## Caveats

- Packets with IPv6 extensions are silently discarded; Unsupported.
- Expecting no difference in IPv4 and IPv6 MTU
- Fragmented packets are silently discarded

## Tips

### Checksum Neutrality

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

### Profiling with Pf2

Requires: Docker, containerlab, iproute2, iperf3.

```shell
cd clab/
./build
containerlab deploy --reconfigure
sudo ip netns exec clab-464xlat-ue-pd-sv iperf3 -s

# in another session:
sudo ip netns exec clab-464xlat-ue-pd-ue iperf3 -c 64:ff9b::192.0.2.80
docker kill --signal=USR1 clab-464xlat-ue-pd-plat
docker cp clab-464xlat-ue-pd-plat:/tmp/xlat-1.pf2profile .
pf2 report ./xlat-1.pf2profile -o ./xlat.json
```


## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/xlat.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

### Credits

- Copyright (c) 2024 Sorah Fukumori
- Copyright (c) 2022 Kazuho Oku
  - Some part of this source code are based on the source code at https://github.com/kazuho/rat available under MIT License
