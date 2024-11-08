use std::{mem::MaybeUninit, ptr};

use magnus::{
    rb_sys::{AsRawValue as _, FromRawValue as _},
    value::{InnerValue, Lazy, ReprValue},
    Error, IntoValue, RClass, RTypedData, Ruby, TryConvert, Value,
};

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct IOBuffer(RTypedData);

static RB_C_IO_BUFFER: Lazy<RClass> = Lazy::new(|_ruby| {
    let val = unsafe { Value::from_raw(rb_sys::rb_cIOBuffer) };
    RClass::from_value(val).unwrap()
});

impl IOBuffer {
    pub fn from_value(val: Value) -> Option<Self> {
        RTypedData::from_value(val)
            .filter(|_| val.is_kind_of(RB_C_IO_BUFFER.get_inner_with(&Ruby::get_with(val))))
            .map(Self)
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

impl IntoValue for IOBuffer {
    #[inline]
    fn into_value_with(self, _: &Ruby) -> Value {
        self.0.as_value()
    }
}
