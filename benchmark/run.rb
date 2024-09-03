warn 'Run as root!!!!!' if Process.euid != 0

require 'securerandom'

@iface = "tun-xlat-#{SecureRandom.hex(3)}"
@trafgen_cfg = File.expand_path(ARGV.shift)
fail "#{@trafgen_cfg} not found" unless File.exist?(@trafgen_cfg)

Dir.chdir(File.expand_path('..', __dir__))

xlat = spawn(*%W[#{RbConfig.ruby} -I./lib ./exe/xlat-siit #@iface 2001:db8:66:d1e0::/96 64:ff9b::/96], %i[out err] => '/tmp/xlat.log')

th = Thread.new do
  loop do
    sleep 10
    Process.kill(:USR1, xlat)
  end
rescue Errno::ESRCH
end

begin
  sleep 1 until system(*%W[ip link show dev #{@iface}])

  system(*%W[ip link set up dev #{@iface}])

  trafgen = spawn(*%W[trafgen -P 1 -i #{@trafgen_cfg} -o #{@iface}], %i[out err] => '/tmp/trafgen.log')
  begin
    system(*%W[ifpps -t 10000 -d #{@iface}])
  ensure
    Process.kill(:KILL, trafgen)
    Process.wait(trafgen)
  end
ensure
  Process.kill(:KILL, xlat)
  Process.wait(xlat)
  th.kill
  th.join
end
