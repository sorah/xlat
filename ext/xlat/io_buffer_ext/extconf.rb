require 'rcx/mkmf/c++20'

$CXXFLAGS << ' -O2'

$CXXFLAGS << ' -MJ$@.json' if checking_for('-MJ flag') { try_compile('', ' -MJtmp.json') }

$CXXFLAGS << ' -Wall' if checking_for('-Wall flag') { try_compile('', ' -Wall') }
$CXXFLAGS << ' -Wextra' if checking_for('-Wextra flag') { try_compile('', ' -Wextra') }

create_header
create_makefile('xlat/io_buffer_ext')
