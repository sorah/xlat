use std::{
    fs::File,
    io::{IoSlice, IoSliceMut, Read, Write},
    mem::{self, ManuallyDrop, MaybeUninit},
    os::fd::{AsRawFd as _, FromRawFd as _, RawFd},
    sync::RwLock,
};

use alloca::allocan;
use magnus::{
    function, gc, method,
    prelude::*,
    value::{InnerValue as _, Opaque},
    DataTypeFunctions, Error, IntoValue as _, Object, RFile, Ruby, TypedData, Value,
};

mod alloca;
mod gvl;
mod io_buffer;

use io_buffer::IOBuffer;

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

#[derive(TypedData)]
#[magnus(class = "Xlat::IOVector", mark)]
struct IOVector {
    buffers: RwLock<Vec<(Opaque<Value>, usize, usize)>>, // TODO: how can we use Opaque<IOBuffer>?
}

impl IOVector {
    pub fn new(capacity: usize) -> Self {
        IOVector {
            buffers: RwLock::new(Vec::with_capacity(capacity)),
        }
    }

    pub fn add(&self, buffer: IOBuffer, offset: usize, length: usize) -> Result<(), Error> {
        let mut buffers = self.buffers.write().unwrap();
        buffers.push((Opaque::from(buffer.into_value()), offset, length));
        Ok(())
    }

    pub fn clear(&self) -> Result<(), Error> {
        let mut buffers = self.buffers.write().unwrap();
        buffers.clear();
        Ok(())
    }

    pub fn write(&self, io: RFile) -> Result<usize, Error> {
        let ruby = &Ruby::get_with(io);
        let mut w = file_from_rfile(io)?;

        let buffers = self.buffers.read().unwrap();
        let count = buffers.len();

        allocan::<IoSlice, _>(count, |slices| {
            for i in 0..count {
                let (buffer, offset, length) = buffers[i];
                let buffer = IOBuffer::try_convert(buffer.get_inner_with(ruby))?;

                let slice = unsafe { &*buffer.get_bytes_for_reading() }
                    .get(offset..offset + length)
                    .ok_or_else(|| {
                        Error::new(ruby.exception_arg_error(), "offset/length is out of range")
                    })?;

                slices[i].write(IoSlice::new(slice));
            }

            drop(buffers);

            // Every element in slice is now initialized
            let slices =
                unsafe { mem::transmute::<&mut [MaybeUninit<IoSlice>], &mut [IoSlice]>(slices) };

            gvl::call_without_gvl2(|| w.write_vectored(slices))
                .map_err(|e| Error::new(ruby.exception_io_error(), e.to_string()))
        })
    }

    pub fn read(&self, io: RFile) -> Result<usize, Error> {
        let ruby = &Ruby::get_with(io);
        let mut r = file_from_rfile(io)?;

        let buffers = self.buffers.read().unwrap();
        let count = buffers.len();

        allocan::<IoSliceMut, _>(count, |slices| {
            for i in 0..count {
                let (buffer, offset, length) = buffers[i];
                let buffer = IOBuffer::try_convert(buffer.get_inner_with(ruby))?;

                let slice = unsafe { &mut *buffer.get_bytes_for_writing() }
                    .get_mut(offset..offset + length)
                    .ok_or_else(|| {
                        Error::new(ruby.exception_arg_error(), "offset/length is out of range")
                    })?;

                slices[i].write(IoSliceMut::new(slice));
            }

            drop(buffers);

            // Every element in slice is now initialized
            let slice = unsafe {
                mem::transmute::<&mut [MaybeUninit<IoSliceMut>], &mut [IoSliceMut]>(slices)
            };

            gvl::call_without_gvl2(|| r.read_vectored(slice))
                .map_err(|e| Error::new(ruby.exception_io_error(), e.to_string()))
        })
    }
}

impl DataTypeFunctions for IOVector {
    fn mark(&self, marker: &gc::Marker) {
        // TODO: What if it blocks during GC...?
        for (buffer, _, _) in self.buffers.read().unwrap().iter() {
            marker.mark(*buffer);
        }
    }
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let c_iovector = ruby
        .define_module("Xlat")?
        .define_class("IOVector", ruby.class_object())?;
    c_iovector.define_singleton_method("new", function!(IOVector::new, 1))?;
    c_iovector.define_method("add", method!(IOVector::add, 3))?;
    c_iovector.define_method("clear", method!(IOVector::clear, 0))?;
    c_iovector.define_method("write", method!(IOVector::write, 1))?;
    c_iovector.define_method("read", method!(IOVector::read, 1))?;

    Ok(())
}
