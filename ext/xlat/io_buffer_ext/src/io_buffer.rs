use std::{mem::MaybeUninit, ptr};

use magnus::{
    rb_sys::{AsRawValue as _, FromRawValue as _},
    value::{Lazy, ReprValue as _},
    Error, RClass, Ruby, TryConvert, Value,
};

#[derive(Clone, Copy)]
pub struct IOBuffer(Value);

static RB_C_IO_BUFFER: Lazy<RClass> = Lazy::new(|_ruby| {
    let val = unsafe { Value::from_raw(rb_sys::rb_cIOBuffer) };
    RClass::from_value(val).unwrap()
});

impl IOBuffer {
    pub fn from_value(val: Value) -> Option<Self> {
        if val.is_kind_of(Ruby::get_with(val).get_inner(&RB_C_IO_BUFFER)) {
            Some(IOBuffer(val))
        } else {
            None
        }
    }

    pub fn get_bytes_for_reading(&self) -> *const [u8] {
        let mut ptr = MaybeUninit::uninit();
        let mut len = MaybeUninit::uninit();
        unsafe {
            rb_sys::rb_io_buffer_get_bytes_for_reading(
                self.0.as_raw(),
                ptr.as_mut_ptr(),
                len.as_mut_ptr(),
            );
            ptr::slice_from_raw_parts(ptr.assume_init().cast::<u8>(), len.assume_init() as usize)
        }
    }

    pub fn get_bytes_for_writing(&self) -> *mut [u8] {
        let mut ptr = MaybeUninit::uninit();
        let mut len = MaybeUninit::uninit();
        unsafe {
            rb_sys::rb_io_buffer_get_bytes_for_writing(
                self.0.as_raw(),
                ptr.as_mut_ptr(),
                len.as_mut_ptr(),
            );
            ptr::slice_from_raw_parts_mut(
                ptr.assume_init().cast::<u8>(),
                len.assume_init() as usize,
            )
        }
    }
}

impl TryConvert for IOBuffer {
    fn try_convert(val: Value) -> Result<Self, Error> {
        Self::from_value(val).ok_or_else(|| {
            Error::new(
                Ruby::get_with(val).exception_type_error(),
                format!("no implicit conversion of {} into IO::Buffer", unsafe {
                    val.classname()
                },),
            )
        })
    }
}
