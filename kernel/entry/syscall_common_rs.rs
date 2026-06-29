// SPDX-License-Identifier: GPL-2.0

//! Out-of-line syscall trace helpers.

use core::ffi::{c_long, c_void};

extern "C" {
    fn syscall_common_trace_sys_enter(regs: *mut c_void, syscall: c_long);
    fn syscall_common_syscall_get_nr(regs: *mut c_void) -> c_long;
    fn syscall_common_trace_sys_exit(regs: *mut c_void, ret: c_long);
}

#[no_mangle]
/// Trace syscall entry and return the (possibly updated) syscall number.
///
/// # Safety
///
/// `regs` must be a valid `struct pt_regs` pointer.
pub unsafe extern "C" fn trace_syscall_enter(regs: *mut c_void, syscall: c_long) -> c_long {
    // SAFETY: C shim invokes the `sys_enter` tracepoint.
    unsafe { syscall_common_trace_sys_enter(regs, syscall) };
    // SAFETY: C shim calls `syscall_get_nr(current, regs)`.
    unsafe { syscall_common_syscall_get_nr(regs) }
}

#[no_mangle]
/// Trace syscall exit.
///
/// # Safety
///
/// `regs` must be a valid `struct pt_regs` pointer.
pub unsafe extern "C" fn trace_syscall_exit(regs: *mut c_void, ret: c_long) {
    // SAFETY: C shim invokes the `sys_exit` tracepoint.
    unsafe { syscall_common_trace_sys_exit(regs, ret) };
}
