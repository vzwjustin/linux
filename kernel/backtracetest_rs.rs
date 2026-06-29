// SPDX-License-Identifier: GPL-2.0-only

//! Simple stack backtrace regression test module logic.

use core::ffi::{c_char, c_int};

extern "C" {
    fn backtrace_test_info(msg: *const c_char);
    fn backtrace_test_dump_stack();
    fn backtrace_test_bh_queue_flush();
    fn backtrace_test_saved_rs();
}

fn pr_info(msg: &'static [u8]) {
    // SAFETY: All callers pass static NUL-terminated messages.
    unsafe { backtrace_test_info(msg.as_ptr().cast()) };
}

#[no_mangle]
/// Runs the backtrace regression test module initialization.
pub extern "C" fn backtrace_regression_test_rs() -> c_int {
    pr_info(b"====[ backtrace testing ]===========\n\0");

    pr_info(b"Testing a backtrace from process context.\n\0");
    pr_info(b"The following trace is a kernel self test and not a bug!\n\0");
    // SAFETY: C helper invokes `dump_stack()` without additional preconditions.
    unsafe { backtrace_test_dump_stack() };

    pr_info(b"Testing a backtrace from BH context.\n\0");
    pr_info(b"The following trace is a kernel self test and not a bug!\n\0");
    // SAFETY: C helper queues and flushes the statically declared work item.
    unsafe { backtrace_test_bh_queue_flush() };

    pr_info(b"Testing a saved backtrace.\n\0");
    pr_info(b"The following trace is a kernel self test and not a bug!\n\0");
    // SAFETY: C helper owns the stack-trace storage and CONFIG_STACKTRACE
    // fallback behavior.
    unsafe { backtrace_test_saved_rs() };

    pr_info(b"====[ end of backtrace testing ]====\n\0");
    0
}
