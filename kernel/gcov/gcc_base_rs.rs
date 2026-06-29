// SPDX-License-Identifier: GPL-2.0

//! GCC gcov initialization support.

use core::ffi::{c_uint, c_void};

extern "C" {
    fn gcov_base_lock();
    fn gcov_base_unlock();
    fn gcov_base_version() -> c_uint;
    fn gcov_base_set_version(version: c_uint);
    fn gcov_base_info_version(info: *mut c_void) -> c_uint;
    fn gcov_base_print_version(version: c_uint);
    fn gcov_base_info_link(info: *mut c_void);
    fn gcov_base_events_enabled() -> bool;
    fn gcov_base_event_add(info: *mut c_void);
}

#[no_mangle]
/// Registers GCC-generated gcov info with the kernel gcov core.
///
/// # Safety
///
/// `info` must point to a valid `struct gcov_info` supplied by GCC-generated
/// constructor code.
pub unsafe extern "C" fn __gcov_init_rs(info: *mut c_void) {
    // SAFETY: C helper wraps the gcov mutex.
    unsafe { gcov_base_lock() };

    // SAFETY: C helper reads the file-local gcov version cache.
    if unsafe { gcov_base_version() } == 0 {
        // SAFETY: `info` is valid per caller contract.
        let version = unsafe { gcov_base_info_version(info) };
        // SAFETY: C helper writes the file-local gcov version cache.
        unsafe { gcov_base_set_version(version) };
        // SAFETY: C helper wraps `pr_info` formatting.
        unsafe { gcov_base_print_version(version) };
    }

    // SAFETY: `info` is valid per caller contract.
    unsafe { gcov_base_info_link(info) };
    // SAFETY: C helper reads the gcov event enable flag.
    if unsafe { gcov_base_events_enabled() } {
        // SAFETY: `info` is valid per caller contract.
        unsafe { gcov_base_event_add(info) };
    }

    // SAFETY: C helper wraps the gcov mutex.
    unsafe { gcov_base_unlock() };
}
