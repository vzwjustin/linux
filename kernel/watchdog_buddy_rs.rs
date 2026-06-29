// SPDX-License-Identifier: GPL-2.0

//! Hardlockup buddy watchdog support.

use core::ffi::{c_int, c_uint};

extern "C" {
    fn wb_cpumask_next_wrap(cpu: c_uint) -> c_uint;
    fn wb_nr_cpu_ids() -> c_uint;
    fn wb_cpumask_set_cpu(cpu: c_uint);
    fn wb_cpumask_clear_cpu(cpu: c_uint);
    fn wb_smp_wmb();
    fn wb_smp_rmb();
    fn wb_smp_processor_id() -> c_uint;
    fn wb_watchdog_hardlockup_touch_cpu(cpu: c_uint);
    fn wb_watchdog_hardlockup_check(cpu: c_uint);
    fn wb_set_miss_thresh(val: c_int);
}

unsafe fn watchdog_next_cpu(cpu: c_uint) -> c_uint {
    let next_cpu = unsafe { wb_cpumask_next_wrap(cpu) };
    if next_cpu == cpu {
        return unsafe { wb_nr_cpu_ids() };
    }
    next_cpu
}

#[no_mangle]
/// Probe callback for the buddy hardlockup detector.
pub unsafe extern "C" fn watchdog_hardlockup_probe() -> c_int {
    unsafe { wb_set_miss_thresh(3) };
    0
}

#[no_mangle]
/// Enable hardlockup detection for the given CPU.
pub unsafe extern "C" fn watchdog_hardlockup_enable(cpu: c_uint) {
    unsafe { wb_watchdog_hardlockup_touch_cpu(cpu) };

    let next_cpu = unsafe { watchdog_next_cpu(cpu) };
    if next_cpu < unsafe { wb_nr_cpu_ids() } {
        unsafe { wb_watchdog_hardlockup_touch_cpu(next_cpu) };
    }

    unsafe { wb_smp_wmb() };
    unsafe { wb_cpumask_set_cpu(cpu) };
}

#[no_mangle]
/// Disable hardlockup detection for the given CPU.
pub unsafe extern "C" fn watchdog_hardlockup_disable(cpu: c_uint) {
    let next_cpu = unsafe { watchdog_next_cpu(cpu) };

    if next_cpu < unsafe { wb_nr_cpu_ids() } {
        unsafe { wb_watchdog_hardlockup_touch_cpu(next_cpu) };
    }

    unsafe { wb_smp_wmb() };
    unsafe { wb_cpumask_clear_cpu(cpu) };
}

#[no_mangle]
/// Check for a hardlockup on the next CPU in the buddy chain.
pub unsafe extern "C" fn watchdog_buddy_check_hardlockup(_hrtimer_interrupts: c_int) {
    let next_cpu = unsafe { watchdog_next_cpu(wb_smp_processor_id()) };
    if next_cpu >= unsafe { wb_nr_cpu_ids() } {
        return;
    }

    unsafe { wb_smp_rmb() };
    unsafe { wb_watchdog_hardlockup_check(next_cpu) };
}
