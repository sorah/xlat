use std::{cell::Cell, ffi::c_void, mem, ptr};

struct Data<'a, F, R>
where
    F: FnOnce() -> R,
{
    fun: F,
    ret: &'a Cell<Option<R>>,
}

/// Safety: `pdata` must point to a valid `Data<F, R>` object, which will be bitwise-copied.
unsafe extern "C" fn trampoline<F, R>(pdata: *mut c_void) -> *mut c_void
where
    F: FnOnce() -> R,
{
    let Data { fun, ret } = unsafe { ptr::read(pdata as *const Data<F, R>) };
    ret.set(Some(fun()));

    ptr::null_mut()
}

pub fn call_without_gvl2<F, R>(fun: F) -> R
where
    F: FnOnce() -> R,
{
    let cell = Cell::new(None);

    let data = mem::ManuallyDrop::new(Data { fun, ret: &cell });

    unsafe {
        rb_sys::rb_thread_call_without_gvl2(
            Some(trampoline::<F, R>),
            ptr::from_ref(&data) as *mut c_void,
            None,
            ptr::null_mut(),
        )
    };

    cell.take().expect("BUG")
}
