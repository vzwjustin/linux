// SPDX-License-Identifier: GPL-2.0-or-later

//! Module kmemleak support.

use core::ffi::{c_uint, c_void};

extern "C" {
    fn module_kmemleak_mem_type_count() -> c_uint;
    fn module_kmemleak_data_type() -> c_uint;
    fn module_kmemleak_init_data_type() -> c_uint;
    fn module_kmemleak_mem_is_rox(module: *const c_void, mem_type: c_uint) -> bool;
    fn module_kmemleak_mem_base(module: *const c_void, mem_type: c_uint) -> *mut c_void;
    fn module_kmemleak_no_scan(ptr: *mut c_void);
}

#[no_mangle]
/// Marks writable, non-executable module sections as not scanned by kmemleak.
///
/// # Safety
///
/// `module` must point to a live `struct module` supplied by the module loader.
/// `info` is part of the C ABI and is intentionally unused, matching the C
/// implementation.
pub unsafe extern "C" fn kmemleak_load_module_rs(module: *const c_void, _info: *const c_void) {
    // SAFETY: C helpers return compile-time enum values.
    let data_type = unsafe { module_kmemleak_data_type() };
    let init_data_type = unsafe { module_kmemleak_init_data_type() };
    let count = unsafe { module_kmemleak_mem_type_count() };

    for mem_type in 0..count {
        if mem_type == data_type || mem_type == init_data_type {
            continue;
        }

        // SAFETY: `mem_type` is bounded by the C-provided type count.
        if unsafe { module_kmemleak_mem_is_rox(module, mem_type) } {
            continue;
        }

        // SAFETY: `mem_type` is bounded by the C-provided type count.
        let base = unsafe { module_kmemleak_mem_base(module, mem_type) };
        // SAFETY: C helper wraps `kmemleak_no_scan` for module memory base.
        unsafe { module_kmemleak_no_scan(base) };
    }
}
