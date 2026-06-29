// SPDX-License-Identifier: GPL-2.0-only

//! kexec handover optional debug helpers.

use core::ffi::c_uint;

use kernel::bindings;

extern "C" {
    fn kho_scratch_count() -> c_uint;
    fn kho_scratch_addr(i: c_uint) -> bindings::phys_addr_t;
    fn kho_scratch_size(i: c_uint) -> usize;
}

#[no_mangle]
/// Returns whether a physical range overlaps any KHO scratch region.
///
/// # Safety
///
/// Called from the KHO core while the scratch array is initialized and stable.
pub unsafe extern "C" fn kho_scratch_overlap_rs(phys: bindings::phys_addr_t, size: usize) -> bool {
    let end = phys.wrapping_add(size as bindings::phys_addr_t);

    // SAFETY: C helper reads the current scratch count.
    let count = unsafe { kho_scratch_count() };
    for i in 0..count {
        // SAFETY: `i` is bounded by `kho_scratch_count()`.
        let scratch_start = unsafe { kho_scratch_addr(i) };
        // SAFETY: `i` is bounded by `kho_scratch_count()`.
        let scratch_end =
            scratch_start.wrapping_add(unsafe { kho_scratch_size(i) } as bindings::phys_addr_t);

        if phys < scratch_end && end > scratch_start {
            return true;
        }
    }

    false
}
