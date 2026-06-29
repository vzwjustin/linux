// SPDX-License-Identifier: GPL-2.0

//! IRQ masking helpers for kexec.

use core::ffi::{c_int, c_uint, c_void};

extern "C" {
    fn kexec_nr_irqs() -> c_uint;
    fn kexec_irq_desc(irq: c_uint) -> *mut c_void;
    fn kexec_desc_chip(desc: *mut c_void) -> *mut c_void;
    fn kexec_desc_started(desc: *mut c_void) -> bool;
    fn kexec_clear_vm_forward_enabled() -> bool;
    fn kexec_clear_irq_active(irq: c_uint) -> c_int;
    fn kexec_maybe_eoi(desc: *mut c_void, chip: *mut c_void);
    fn kexec_irq_shutdown(desc: *mut c_void);
}

#[no_mangle]
/// Mask and shut down all IRQs before kexec.
///
/// # Safety
///
/// Must only be called from the kexec path with the same contract as the
/// original C implementation.
pub unsafe extern "C" fn machine_kexec_mask_interrupts() {
    let count = unsafe { kexec_nr_irqs() };

    for irq in 0..count {
        // SAFETY: `kexec_irq_desc` returns a valid desc or null.
        let desc = unsafe { kexec_irq_desc(irq) };
        if desc.is_null() {
            continue;
        }

        // SAFETY: `desc` is valid when non-null.
        let chip = unsafe { kexec_desc_chip(desc) };
        if chip.is_null() || !unsafe { kexec_desc_started(desc) } {
            continue;
        }

        let mut check_eoi = true;
        if unsafe { kexec_clear_vm_forward_enabled() } {
            // SAFETY: Matches the C `irq_set_irqchip_state()` call.
            check_eoi = unsafe { kexec_clear_irq_active(irq) } != 0;
        }

        if check_eoi {
            // SAFETY: `desc` and `chip` are valid per the checks above.
            unsafe { kexec_maybe_eoi(desc, chip) };
        }

        // SAFETY: `desc` is valid per the checks above.
        unsafe { kexec_irq_shutdown(desc) };
    }
}
