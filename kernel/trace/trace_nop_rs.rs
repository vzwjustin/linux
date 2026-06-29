// SPDX-License-Identifier: GPL-2.0

//! Set-flag logic for the nop tracer.

use core::ffi::{c_int, c_uint, c_void};

use kernel::bindings;

const TRACE_NOP_OPT_ACCEPT: c_uint = 0x1;
const TRACE_NOP_OPT_REFUSE: c_uint = 0x2;

extern "C" {
    fn nop_print_accept(set: c_int);
    fn nop_print_refuse(set: c_int);
}

#[no_mangle]
/// Handles nop tracer option updates.
///
/// # Safety
///
/// This function matches the C tracer `set_flag` callback ABI. `tr` is not
/// dereferenced because the nop tracer only accepts or rejects known bits.
pub unsafe extern "C" fn nop_set_flag_rs(
    _tr: *mut c_void,
    _old_flags: c_uint,
    bit: c_uint,
    set: c_int,
) -> c_int {
    match bit {
        TRACE_NOP_OPT_ACCEPT => {
            // SAFETY: C helper only prints the integer value.
            unsafe { nop_print_accept(set) };
            0
        }
        TRACE_NOP_OPT_REFUSE => {
            // SAFETY: C helper only prints the integer value.
            unsafe { nop_print_refuse(set) };
            -(bindings::EINVAL as c_int)
        }
        _ => 0,
    }
}
