// SPDX-License-Identifier: GPL-2.0-or-later

//! `/proc/config.gz` read helper.

use kernel::{
    bindings,
    ffi::c_void,
};

#[no_mangle]
/// Reads from the embedded compressed kernel config buffer.
///
/// # Safety
///
/// `buf`, `offset`, and `data` must follow the `simple_read_from_buffer`
/// contract. `available` must be the byte length of `data`.
pub unsafe extern "C" fn ikconfig_read_current_rs(
    _file: *mut bindings::file,
    buf: *mut c_void,
    len: usize,
    offset: *mut bindings::loff_t,
    data: *const c_void,
    available: usize,
) -> isize {
    // SAFETY: The C shim passes the exact arguments formerly passed directly
    // to `simple_read_from_buffer`.
    unsafe { bindings::simple_read_from_buffer(buf, len, offset, data, available) }
}
