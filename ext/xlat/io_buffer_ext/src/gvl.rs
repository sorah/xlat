use std::{cell::Cell, ffi::c_void, mem, ops::Deref as _, ptr};

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

    loop {
        unsafe {
            rb_sys::rb_thread_call_without_gvl2(
                Some(trampoline::<F, R>),
                data.deref() as *const Data<F, R> as *mut c_void,
                None,
                ptr::null_mut(),
            );
        }

        // If rb_thread_call_without_gvl2 returns before invoking the callback
        // due to interrupts, the cell remains to be None, and
        // it's safe to retry because data is not consumed yet.
        if let Some(r) = cell.take() {
            return r;
        }

        unsafe { rb_sys::rb_thread_check_ints() }
    }
}
