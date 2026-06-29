// SPDX-License-Identifier: GPL-2.0-only

//! Parser for the `elfcorehdr=` early parameter.

use kernel::{
    bindings,
    ffi::{c_char, c_int},
};

#[no_mangle]
/// Parses and applies the `elfcorehdr=` early parameter.
///
/// # Safety
///
/// `arg` must either be null or point to a valid NUL-terminated parameter
/// string. `addr` and `size` must point to writable kernel storage.
pub unsafe extern "C" fn setup_elfcorehdr_rs(
    arg: *mut c_char,
    addr: *mut u64,
    size: *mut u64,
) -> c_int {
    if arg.is_null() {
        return -(bindings::EINVAL as c_int);
    }

    let mut end = core::ptr::null_mut();

    // SAFETY: `arg` is non-null and follows the C early-param contract.
    let parsed_addr = unsafe { bindings::memparse(arg.cast_const(), &mut end) };
    // SAFETY: `addr` points to the C global passed by the shim.
    unsafe { *addr = parsed_addr };

    // SAFETY: `end` is written by `memparse` and points within the parameter
    // string when dereferenced here, matching the previous C implementation.
    if unsafe { *end == b'@' as c_char } {
        // SAFETY: `addr` and `size` point to writable C globals.
        unsafe { *size = *addr };
        // SAFETY: `end.add(1)` points after the `@` delimiter.
        let parsed_addr = unsafe { bindings::memparse(end.add(1).cast_const(), &mut end) };
        // SAFETY: `addr` points to the C global passed by the shim.
        unsafe { *addr = parsed_addr };
    }

    if core::ptr::eq(end, arg) {
        -(bindings::EINVAL as c_int)
    } else {
        0
    }
}
