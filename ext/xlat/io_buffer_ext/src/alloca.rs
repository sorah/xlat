use core::mem::{align_of, size_of, MaybeUninit};
use core::slice;

pub fn allocan<T, R>(n: usize, f: impl FnOnce(&mut [MaybeUninit<T>]) -> R) -> R {
    alloca::with_alloca(
        size_of::<T>() * n + (align_of::<T>() - 1),
        |memory| unsafe {
            let ptr = memory.as_mut_ptr();
            let ptr = ptr.byte_add(align_of::<T>() - ptr as usize % align_of::<T>());
            f(slice::from_raw_parts_mut(ptr.cast(), n))
        },
    )
}
