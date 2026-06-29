// SPDX-License-Identifier: GPL-2.0
/*
 * Timer tick function for architectures that lack generic clockevents,
 * consolidated here from m68k/ia64/parisc/arm.
 */

use core::ffi::c_ulong;

extern "C" {
    fn tl_jiffies_lock();
    fn tl_jiffies_unlock();
    fn tl_jiffies_seq_begin();
    fn tl_jiffies_seq_end();
    fn tl_do_timer(ticks: c_ulong);
    fn tl_update_wall_time();
    fn tl_update_process_times();
    fn tl_profile_tick();
}

#[no_mangle]
/// Advances the timekeeping infrastructure on legacy timer tick architectures.
///
/// # Safety
///
/// Must be called with interrupts disabled, matching the C API contract.
pub unsafe extern "C" fn legacy_timer_tick(ticks: c_ulong) {
    if ticks != 0 {
        // SAFETY: C shims wrap the jiffies lock and seqcount helpers.
        unsafe { tl_jiffies_lock() };
        unsafe { tl_jiffies_seq_begin() };
        unsafe { tl_do_timer(ticks) };
        unsafe { tl_jiffies_seq_end() };
        unsafe { tl_jiffies_unlock() };
        unsafe { tl_update_wall_time() };
    }

    // SAFETY: C shim wraps `update_process_times(user_mode(get_irq_regs()))`.
    unsafe { tl_update_process_times() };
    // SAFETY: C shim wraps `profile_tick(CPU_PROFILING)`.
    unsafe { tl_profile_tick() };
}
