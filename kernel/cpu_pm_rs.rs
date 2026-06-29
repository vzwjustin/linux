// SPDX-License-Identifier: GPL-2.0-only

//! CPU power-management notifier helpers.

use core::ffi::{c_int, c_ulong, c_void};

extern "C" {
    fn cpmpm_chain_register(nb: *mut c_void) -> c_int;
    fn cpmpm_chain_unregister(nb: *mut c_void) -> c_int;
    fn cpmpm_notify(event: c_ulong) -> c_int;
    fn cpmpm_notify_robust(event_up: c_ulong, event_down: c_ulong) -> c_int;
    fn cpmpm_cpu_pm_enter() -> c_ulong;
    fn cpmpm_cpu_pm_enter_failed() -> c_ulong;
    fn cpmpm_cpu_pm_exit() -> c_ulong;
    fn cpmpm_cpu_cluster_pm_enter() -> c_ulong;
    fn cpmpm_cpu_cluster_pm_enter_failed() -> c_ulong;
    fn cpmpm_cpu_cluster_pm_exit() -> c_ulong;
}

#[no_mangle]
/// Register a driver with cpu_pm.
///
/// # Safety
///
/// `nb` must be a valid `struct notifier_block` pointer.
pub unsafe extern "C" fn cpu_pm_register_notifier(nb: *mut c_void) -> c_int {
    // SAFETY: Caller provides a valid notifier block.
    unsafe { cpmpm_chain_register(nb) }
}

#[no_mangle]
/// Unregister a driver from cpu_pm.
///
/// # Safety
///
/// `nb` must be a valid registered `struct notifier_block` pointer.
pub unsafe extern "C" fn cpu_pm_unregister_notifier(nb: *mut c_void) -> c_int {
    // SAFETY: Caller provides a valid notifier block.
    unsafe { cpmpm_chain_unregister(nb) }
}

#[no_mangle]
/// Notify listeners that a CPU is entering a low-power state.
pub unsafe extern "C" fn cpu_pm_enter() -> c_int {
    // SAFETY: C shim wraps the notifier chain with the correct events.
    unsafe {
        cpmpm_notify_robust(cpmpm_cpu_pm_enter(), cpmpm_cpu_pm_enter_failed())
    }
}

#[no_mangle]
/// Notify listeners that a CPU is exiting a low-power state.
pub unsafe extern "C" fn cpu_pm_exit() -> c_int {
    // SAFETY: C shim wraps the notifier chain with the correct event.
    unsafe { cpmpm_notify(cpmpm_cpu_pm_exit()) }
}

#[no_mangle]
/// Notify listeners that a CPU cluster is entering a low-power state.
pub unsafe extern "C" fn cpu_cluster_pm_enter() -> c_int {
    // SAFETY: C shim wraps the notifier chain with the correct events.
    unsafe {
        cpmpm_notify_robust(
            cpmpm_cpu_cluster_pm_enter(),
            cpmpm_cpu_cluster_pm_enter_failed(),
        )
    }
}

#[no_mangle]
/// Notify listeners that a CPU cluster is exiting a low-power state.
pub unsafe extern "C" fn cpu_cluster_pm_exit() -> c_int {
    // SAFETY: C shim wraps the notifier chain with the correct event.
    unsafe { cpmpm_notify(cpmpm_cpu_cluster_pm_exit()) }
}
