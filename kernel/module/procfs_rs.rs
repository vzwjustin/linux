// SPDX-License-Identifier: GPL-2.0-or-later

//! Helpers for `/proc/modules` formatting decisions.

use core::ffi::{c_char, c_uint, c_void};

extern "C" {
    fn module_proc_is_unformed_rs_helper(module: *const c_void) -> bool;
    fn module_proc_is_going_rs_helper(module: *const c_void) -> bool;
    fn module_proc_is_coming_rs_helper(module: *const c_void) -> bool;
    fn module_proc_mem_type_count_rs_helper() -> c_uint;
    fn module_proc_mem_size_rs_helper(module: *const c_void, mem_type: c_uint) -> c_uint;
    fn module_proc_text_base_rs_helper(module: *const c_void) -> *mut c_void;
    fn module_proc_taints_rs_helper(module: *const c_void) -> c_uint;
}

const UNLOADING: &[u8] = b"Unloading\0";
const LOADING: &[u8] = b"Loading\0";
const LIVE: &[u8] = b"Live\0";

#[no_mangle]
/// Returns whether a module should be hidden from `/proc/modules` output.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_proc_is_unformed_rs(module: *const c_void) -> bool {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_proc_is_unformed_rs_helper(module) }
}

#[no_mangle]
/// Computes the total module memory size reported in `/proc/modules`.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_proc_total_size_rs(module: *const c_void) -> c_uint {
    // SAFETY: C helper exposes the number of module memory types.
    let count = unsafe { module_proc_mem_type_count_rs_helper() };
    let mut size: c_uint = 0;

    for mem_type in 0..count {
        // SAFETY: `mem_type` is bounded by the C-provided memory type count.
        size = size.wrapping_add(unsafe { module_proc_mem_size_rs_helper(module, mem_type) });
    }

    size
}

#[no_mangle]
/// Returns the stable textual module state for `/proc/modules`.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_proc_state_name_rs(module: *const c_void) -> *const c_char {
    // SAFETY: The C caller supplies a valid module pointer.
    if unsafe { module_proc_is_going_rs_helper(module) } {
        UNLOADING.as_ptr().cast()
    // SAFETY: The C caller supplies a valid module pointer.
    } else if unsafe { module_proc_is_coming_rs_helper(module) } {
        LOADING.as_ptr().cast()
    } else {
        LIVE.as_ptr().cast()
    }
}

#[no_mangle]
/// Selects the address value printed in `/proc/modules`.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_proc_address_value_rs(
    module: *const c_void,
    hide_pointers: bool,
) -> *mut c_void {
    if hide_pointers {
        core::ptr::null_mut()
    } else {
        // SAFETY: The C caller supplies a valid module pointer.
        unsafe { module_proc_text_base_rs_helper(module) }
    }
}

#[no_mangle]
/// Returns whether taint flags should be printed for a module.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_proc_has_taints_rs(module: *const c_void) -> bool {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_proc_taints_rs_helper(module) != 0 }
}
