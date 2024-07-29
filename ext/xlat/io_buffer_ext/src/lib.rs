use std::{
    fs::File,
    io::{IoSlice, IoSliceMut, Read, Write},
    mem::ManuallyDrop,
    os::fd::{AsRawFd as _, FromRawFd as _},
};

use magnus::{function, prelude::*, Error, Object, RArray, RFile, Ruby};

mod gvl;
mod io_buffer;

/// writev(IO, Array[IO::Buffer]) -> Integer
fn writev(ruby: &Ruby, io: RFile, bufs: RArray) -> Result<usize, Error> {
    // Don't take FD ownership from Ruby
    let mut w = ManuallyDrop::new(unsafe { File::from_raw_fd(io.as_raw_fd()) });

    let vec = bufs
        .into_iter()
        .map(|v| {
            io_buffer::IOBuffer::try_convert(v)
                .map(|buf| IoSlice::new(unsafe { &*buf.get_bytes_for_reading() }))
        })
        .collect::<Result<Vec<_>, _>>()?;

    gvl::call_without_gvl2(|| w.write_vectored(&vec))
        .map_err(|e| Error::new(ruby.exception_io_error(), e.to_string()))
}

/// readv(IO, Array[IO::Buffer]) -> Integer
fn readv(ruby: &Ruby, io: RFile, bufs: RArray) -> Result<usize, Error> {
    // Don't take FD ownership from Ruby
    let mut r = ManuallyDrop::new(unsafe { File::from_raw_fd(io.as_raw_fd()) });

    let mut vec = bufs
        .into_iter()
        .map(|v| {
            io_buffer::IOBuffer::try_convert(v)
                .map(|buf| IoSliceMut::new(unsafe { &mut *buf.get_bytes_for_writing() }))
        })
        .collect::<Result<Vec<_>, _>>()?;

    gvl::call_without_gvl2(|| r.read_vectored(&mut vec))
        .map_err(|e| Error::new(ruby.exception_io_error(), e.to_string()))
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("Xlat")?.define_module("IOBufferExt")?;
    module.define_singleton_method("readv", function!(readv, 2))?;
    module.define_singleton_method("writev", function!(writev, 2))?;
    Ok(())
}
