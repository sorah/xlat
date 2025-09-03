#include "io_buffer_ext.hpp"

#include <array>
#include <cerrno>

#include <rcx/rcx.hpp>
#include <sys/uio.h>

namespace {
  constexpr size_t iov_max = 7;  // Just enough for our use case

  ssize_t io_buffer_readv(rcx::IO const io, rcx::Array const buffers) {
    io.check_readable();
    auto const fd = io.descriptor();

    auto const count = buffers.size();
    if(count > iov_max) {
      throw rcx::Exception::format(rcx::builtin::IOError,
          "readv: too many buffers ({} exceeds limit of {})", count, iov_max);
    }

    std::array<iovec, iov_max> iov;
    for(size_t i = 0; i < count; ++i) {
      auto const bytes = buffers.at<rcx::IOBuffer>(i).bytes();
      iov[i] = {bytes.data(), bytes.size_bytes()};
    }

    ssize_t n;
    do {
      if(auto const result =
              rcx::gvl::without_gvl([fd, &iov, count] { return ::readv(fd, iov.data(), count); },
                  rcx::gvl::ReleaseFlags::IntrFail)) {
        n = *result;
      } else {
        rcx::gvl::check_interrupts();
        continue;
      }
    } while(n < 0 && errno == EINTR);

    if(n < 0) {
      throw rcx::Exception::new_from_errno("readv");
    }

    return n;
  }

  ssize_t io_buffer_writev(rcx::IO const io, rcx::Array const buffers) {
    io.check_writable();
    auto const fd = io.descriptor();

    auto const count = buffers.size();
    if(count > iov_max) {
      throw rcx::Exception::format(rcx::builtin::IOError,
          "writev: too many buffers ({} exceeds limit of {})", count, iov_max);
    }

    std::array<iovec, iov_max> iov;
    for(size_t i = 0; i < count; ++i) {
      auto const bytes = buffers.at<rcx::IOBuffer>(i).cbytes();
      iov[i] = {const_cast<std::byte *>(bytes.data()),  // SAFETY: writev does not write into iov
        bytes.size_bytes()};
    }

    ssize_t n;
    do {
      if(auto const result =
              rcx::gvl::without_gvl([fd, &iov, count] { return ::writev(fd, iov.data(), count); },
                  rcx::gvl::ReleaseFlags::IntrFail)) {
        n = *result;
      } else {
        rcx::gvl::check_interrupts();
        continue;
      }
    } while(n < 0 && errno == EINTR);

    if(n < 0) {
      throw rcx::Exception::new_from_errno("writev");
    }

    return n;
  }
}

extern "C" void Init_io_buffer_ext() {
  rb_ext_ractor_safe(true);

  rcx::detail::cxx_protect([]() {
    using namespace rcx::args;

    auto const io_buffer_ext = rcx::Ruby::get().define_module("Xlat").define_module("IOBufferExt");

    io_buffer_ext.define_singleton_method<void>(
        "readv", io_buffer_readv, arg<rcx::IO, "io">, arg<rcx::Array, "buffers">);
    io_buffer_ext.define_singleton_method<void>(
        "writev", io_buffer_writev, arg<rcx::IO, "io">, arg<rcx::Array, "buffers">);
  });
}
