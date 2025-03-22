use std::{
    fs::File,
    io::{ErrorKind, IoSlice, IoSliceMut, Read, Write},
    mem::ManuallyDrop,
    os::fd::{AsRawFd as _, FromRawFd as _, RawFd},
};

use io_buffer::IOBuffer;
use magnus::{
    function, method,
    prelude::*,
    scan_args::{scan_args, Args},
    Error, Object, RArray, RFile, Ruby, Value,
};

mod gvl;
mod io_buffer;

fn file_from_rfile(io: RFile) -> Result<ManuallyDrop<File>, Error> {
    let raw_fd = io.as_raw_fd();
    if raw_fd == -1 as RawFd {
        Err(Error::new(
            Ruby::get_with(io).exception_io_error(),
            "closed stream",
        ))
    } else {
        // Don't take FD ownership from Ruby
        Ok(ManuallyDrop::new(unsafe { File::from_raw_fd(raw_fd) }))
    }
}

/// writev(IO, Array[IO::Buffer]) -> Integer
fn writev(ruby: &Ruby, io: RFile, bufs: RArray) -> Result<usize, Error> {
    let mut w = file_from_rfile(io)?;

    let vec = bufs
        .into_iter()
        .map(|v| {
            IOBuffer::try_convert(v)
                .map(|buf| IoSlice::new(unsafe { &*buf.get_bytes_for_reading() }))
        })
        .collect::<Result<Vec<_>, _>>()?;

    loop {
        match gvl::call_without_gvl2(|| w.write_vectored(&vec)) {
            Ok(n) => return Ok(n),
            Err(err) => {
                if err.kind() != ErrorKind::Interrupted {
                    return Err(Error::new(ruby.exception_io_error(), err.to_string()));
                }
            }
        }
    }
}

/// readv(IO, Array[IO::Buffer]) -> Integer
fn readv(ruby: &Ruby, io: RFile, bufs: RArray) -> Result<usize, Error> {
    let mut r = file_from_rfile(io)?;

    let mut vec = bufs
        .into_iter()
        .map(|v| {
            IOBuffer::try_convert(v)
                .map(|buf| IoSliceMut::new(unsafe { &mut *buf.get_bytes_for_writing() }))
        })
        .collect::<Result<Vec<_>, _>>()?;

    loop {
        match gvl::call_without_gvl2(|| r.read_vectored(&mut vec)) {
            Ok(n) => return Ok(n),
            Err(err) => {
                if err.kind() != ErrorKind::Interrupted {
                    return Err(Error::new(ruby.exception_io_error(), err.to_string()));
                }
            }
        }
    }
}

fn compare(ruby: &Ruby, rself: IOBuffer, args: &[Value]) -> Result<i32, Error> {
    let args: Args<(IOBuffer,), (Option<usize>, Option<usize>, Option<usize>), (), (), (), ()> =
        scan_args(args)?;
    let (other,) = args.required;
    let (offset, length, other_offset) = args.optional;

    let self_slice = unsafe { &*rself.get_bytes_for_reading() }
        .get(offset.unwrap_or(0)..)
        .ok_or_else(|| Error::new(ruby.exception_arg_error(), "offset is out of range"))?;

    let other_slice = unsafe { &*other.get_bytes_for_reading() }
        .get(other_offset.unwrap_or(0)..)
        .ok_or_else(|| Error::new(ruby.exception_arg_error(), "other_offset is out of range"))?;

    let (self_slice, other_slice) = match length {
        Some(length) => {
            let self_slice = self_slice
                .get(..length)
                .ok_or_else(|| Error::new(ruby.exception_arg_error(), "length is out of range"))?;
            let other_slice = other_slice
                .get(..length)
                .ok_or_else(|| Error::new(ruby.exception_arg_error(), "length is out of range"))?;
            (self_slice, other_slice)
        }
        None => {
            if self_slice.len() != other_slice.len() {
                return Err(Error::new(
                    ruby.exception_arg_error(),
                    "lengths of slices are not equal",
                ));
            };
            (self_slice, other_slice)
        }
    };

    assert!(self_slice.len() == other_slice.len());
    Ok(self_slice.cmp(other_slice) as i32)
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    // We don't share objects across Ractors
    unsafe { rb_sys::rb_ext_ractor_safe(true) };

    let m_ext = ruby.define_module("Xlat")?.define_module("IOBufferExt")?;
    m_ext.define_singleton_method("readv", function!(readv, 2))?;
    m_ext.define_singleton_method("writev", function!(writev, 2))?;

    let m_compare = m_ext.define_module("Compare")?;
    m_compare.define_method("compare", method!(compare, -1))?;

    Ok(())
}
