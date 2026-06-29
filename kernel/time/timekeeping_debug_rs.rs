// SPDX-License-Identifier: GPL-2.0+

//! Debugfs helpers for tracking time spent in suspend.

use core::ffi::{c_int, c_uint, c_ulong};

use kernel::bindings;

const NUM_BINS: c_uint = 32;

extern "C" {
    fn tk_debug_seq_header(s: *mut bindings::seq_file);
    fn tk_debug_seq_bin(s: *mut bindings::seq_file, bin: c_uint, count: c_uint);
    fn tk_debug_sleep_time_bin(bin: c_uint) -> c_uint;
    fn tk_debug_sleep_time_bin_inc(bin: c_uint);
    fn tk_debug_sleep_time_bin_for_seconds(seconds: i64) -> c_int;
    fn tk_debug_print_sleep_time(t: *const bindings::timespec64);
    fn tk_debug_mg_floor_swaps_sum() -> c_ulong;
}

#[no_mangle]
/// Shows the suspend sleep-time histogram in debugfs.
///
/// # Safety
///
/// `s` must point to a valid `seq_file` supplied by the debugfs show path.
pub unsafe extern "C" fn tk_debug_sleep_time_show_rs(s: *mut bindings::seq_file) -> c_int {
    // SAFETY: `s` is valid per caller contract.
    unsafe { tk_debug_seq_header(s) };

    for bin in 0..NUM_BINS {
        // SAFETY: `bin` is bounded by `NUM_BINS`, matching the C array size.
        let count = unsafe { tk_debug_sleep_time_bin(bin) };
        if count == 0 {
            continue;
        }

        // SAFETY: `s` is valid per caller contract; `bin` and `count` were
        // read from the bounded histogram.
        unsafe { tk_debug_seq_bin(s, bin, count) };
    }

    0
}

#[no_mangle]
/// Accounts a suspend sleep interval in the debugfs histogram.
///
/// # Safety
///
/// `t` must point to a valid `timespec64` supplied by the timekeeping code.
pub unsafe extern "C" fn tk_debug_account_sleep_time_rs(t: *const bindings::timespec64) {
    // SAFETY: `t` is valid per caller contract.
    let bin = unsafe { tk_debug_sleep_time_bin_for_seconds((*t).tv_sec) };
    if bin >= 0 {
        // SAFETY: C helper caps the bin to the histogram bounds.
        unsafe { tk_debug_sleep_time_bin_inc(bin as c_uint) };
    }

    // SAFETY: `t` is valid per caller contract.
    unsafe { tk_debug_print_sleep_time(t) };
}

#[no_mangle]
/// Returns the sum of all per-CPU `timekeeping_mg_floor_swaps` counters.
pub extern "C" fn timekeeping_get_mg_floor_swaps_rs() -> c_ulong {
    // SAFETY: C helper encapsulates the per-CPU traversal and data-race read.
    unsafe { tk_debug_mg_floor_swaps_sum() }
}
