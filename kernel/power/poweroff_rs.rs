// SPDX-License-Identifier: GPL-2.0-only

//! SysRq poweroff callbacks.

use kernel::bindings;

unsafe extern "C" {
    fn poweroff_kernel_power_off();
    fn poweroff_schedule_on_boot_cpu();
}

#[no_mangle]
/// Workqueue callback that powers off the machine.
///
/// # Safety
///
/// `dummy` follows the workqueue callback contract.
pub unsafe extern "C" fn poweroff_work_rs(_dummy: *mut bindings::work_struct) {
    // SAFETY: C helper directly invokes the existing kernel poweroff API.
    unsafe { poweroff_kernel_power_off() };
}

#[no_mangle]
/// SysRq handler for the poweroff key.
pub extern "C" fn poweroff_handle_sysrq_rs(_key: u8) {
    // SAFETY: C helper schedules the static work item on the boot CPU.
    unsafe { poweroff_schedule_on_boot_cpu() };
}
