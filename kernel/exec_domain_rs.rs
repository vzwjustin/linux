// SPDX-License-Identifier: GPL-2.0

//! Execution-domain procfs helpers and personality syscall.

use core::ffi::{c_int, c_uint, c_void};
use kernel::bindings;

extern "C" {
    fn ed_get_personality() -> c_uint;
    fn ed_set_personality(pers: c_uint);
}

const EXEC_DOMAINS: &[u8] = b"0-0\tLinux           \t[kernel]\n";

#[no_mangle]
/// Writes the built-in execution-domain listing.
///
/// # Safety
///
/// `m` must follow the `seq_file` show callback contract.
pub unsafe extern "C" fn execdomains_proc_show_rs(m: *mut bindings::seq_file) -> c_int {
    // SAFETY: `m` is supplied by procfs and the byte slice is static.
    unsafe {
        bindings::seq_write(
            m,
            EXEC_DOMAINS.as_ptr() as *const c_void,
            EXEC_DOMAINS.len(),
        )
    }
}

#[no_mangle]
/// Implementation of the `personality` syscall logic.
///
/// # Safety
///
/// No additional safety requirements beyond C calling conventions.
pub unsafe extern "C" fn ksys_personality_rs(personality: c_uint) -> c_uint {
    let old = unsafe { ed_get_personality() };
    if personality != 0xffffffff {
        unsafe { ed_set_personality(personality) };
    }
    old
}
