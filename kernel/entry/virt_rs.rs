// SPDX-License-Identifier: GPL-2.0

//! Transfer-to-guest-mode work handling.

use core::ffi::{c_int, c_ulong};

use kernel::bindings;

extern "C" {
    fn virt_read_thread_flags() -> c_ulong;
    fn virt_xfer_to_guest_mode_work_mask() -> c_ulong;
    fn virt_mask_sigpending_notify() -> c_ulong;
    fn virt_mask_need_resched() -> c_ulong;
    fn virt_mask_notify_resume() -> c_ulong;
    fn virt_schedule();
    fn virt_resume_user_mode_work();
    fn virt_arch_xfer_to_guest_mode_handle_work(ti_work: c_ulong) -> c_int;
}

fn xfer_to_guest_mode_work(mut ti_work: c_ulong) -> c_int {
    loop {
        if ti_work & unsafe { virt_mask_sigpending_notify() } != 0 {
            return -(bindings::EINTR as c_int);
        }

        if ti_work & unsafe { virt_mask_need_resched() } != 0 {
            // SAFETY: Wraps the C `schedule()` macro.
            unsafe { virt_schedule() };
        }

        if ti_work & unsafe { virt_mask_notify_resume() } != 0 {
            // SAFETY: Wraps `resume_user_mode_work(NULL)`.
            unsafe { virt_resume_user_mode_work() };
        }

        // SAFETY: Architecture hook with the same contract as the C inline.
        let ret = unsafe { virt_arch_xfer_to_guest_mode_handle_work(ti_work) };
        if ret != 0 {
            return ret;
        }

        // SAFETY: Reads current thread flags through the C helper.
        ti_work = unsafe { virt_read_thread_flags() };
        if ti_work & unsafe { virt_xfer_to_guest_mode_work_mask() } == 0 {
            return 0;
        }
    }
}

#[no_mangle]
/// Check and handle pending work before entering guest mode.
///
/// # Safety
///
/// Must follow the C API contract for `xfer_to_guest_mode_handle_work()`.
pub unsafe extern "C" fn xfer_to_guest_mode_handle_work() -> c_int {
    // SAFETY: Reads current thread flags through the C helper.
    let ti_work = unsafe { virt_read_thread_flags() };
    if ti_work & unsafe { virt_xfer_to_guest_mode_work_mask() } == 0 {
        return 0;
    }

    xfer_to_guest_mode_work(ti_work)
}
