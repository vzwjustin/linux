// SPDX-License-Identifier: GPL-2.0-only

//! Register set access helpers.

use core::ffi::{c_int, c_uint, c_void};

use kernel::bindings;

#[repr(C)]
/// In-memory buffer descriptor passed to `regset_get` callbacks.
pub struct Membuf {
    p: *mut c_void,
    left: usize,
}

const _: () = assert!(core::mem::size_of::<Membuf>() == 16);

#[repr(C)]
/// Accessible thread CPU state descriptor.
pub struct UserRegset {
    regset_get: Option<
        unsafe extern "C" fn(
            *mut bindings::task_struct,
            *const UserRegset,
            Membuf,
        ) -> c_int,
    >,
    set: *mut c_void,
    active: *mut c_void,
    writeback: *mut c_void,
    n: c_uint,
    size: c_uint,
    align: c_uint,
    bias: c_uint,
    core_note_type: c_uint,
    core_note_name: *const core::ffi::c_char,
}

const _: () = assert!(core::mem::size_of::<UserRegset>() == 64);

/// Internal helper to fetch regset data, optionally allocating a buffer.
///
/// # Safety
///
/// `target` and `regset` must be valid pointers. `data` must point to valid
/// storage for a `void *`.
unsafe fn __regset_get(
    target: *mut bindings::task_struct,
    regset: *const UserRegset,
    mut size: c_uint,
    data: *mut *mut c_void,
) -> c_int {
    // SAFETY: Callers preserve the C contract for `regset`.
    let regset = unsafe { &*regset };

    let regset_get = match regset.regset_get {
        Some(f) => f,
        None => return -(bindings::EOPNOTSUPP as c_int),
    };

    if size > regset.n * regset.size {
        size = regset.n * regset.size;
    }

    // SAFETY: `data` points to valid storage per the C contract.
    let mut p = unsafe { *data };
    let mut to_free: *mut c_void = core::ptr::null_mut();

    if p.is_null() {
        // SAFETY: `kvmalloc_node` is the C allocator, matching the original
        // `kvzalloc` call. `GFP_KERNEL | __GFP_ZERO` matches `kvzalloc`.
        p = unsafe {
            bindings::kvmalloc_node(
                size as usize,
                bindings::GFP_KERNEL | bindings::__GFP_ZERO,
                bindings::NUMA_NO_NODE,
            )
        } as *mut c_void;
        if p.is_null() {
            return -(bindings::ENOMEM as c_int);
        }
        to_free = p;
    }

    let mb = Membuf {
        p,
        left: size as usize,
    };
    // SAFETY: `regset_get` is the C callback, called with the same contract.
    let res = unsafe { regset_get(target, regset, mb) };

    if res < 0 {
        // SAFETY: `to_free` is either null or a valid `kvmalloc` allocation.
        unsafe { bindings::kvfree(to_free as *const c_void) };
        return res;
    }

    // SAFETY: `data` points to valid storage per the C contract.
    unsafe { *data = p };
    (size as c_int) - res
}

#[no_mangle]
/// Fetch regset data into a caller-supplied buffer.
///
/// # Safety
///
/// `target` and `regset` must be valid pointers. `data` must point to a
/// buffer large enough for `size` bytes (or be NULL to request allocation).
pub unsafe extern "C" fn regset_get(
    target: *mut bindings::task_struct,
    regset: *const UserRegset,
    size: c_uint,
    data: *mut c_void,
) -> c_int {
    let mut local = data;
    // SAFETY: Same preconditions as this function; `&mut local` is a valid
    // `void **` pointing to the local copy of `data`.
    unsafe { __regset_get(target, regset, size, &mut local) }
}

#[no_mangle]
/// Fetch regset data into an automatically allocated buffer.
///
/// # Safety
///
/// `target` and `regset` must be valid pointers. `data` must point to valid
/// storage for a `void *`; the caller must free the result with `kvfree`.
pub unsafe extern "C" fn regset_get_alloc(
    target: *mut bindings::task_struct,
    regset: *const UserRegset,
    size: c_uint,
    data: *mut *mut c_void,
) -> c_int {
    // SAFETY: `data` points to valid storage per the C contract.
    unsafe { *data = core::ptr::null_mut() };
    // SAFETY: Same preconditions as this function.
    unsafe { __regset_get(target, regset, size, data) }
}
