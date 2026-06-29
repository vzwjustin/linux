// SPDX-License-Identifier: GPL-2.0-or-later

//! Helpers for KDB module listing output.

use core::ffi::{c_char, c_uint, c_void};

extern "C" {
    fn module_kdb_is_unformed_rs_helper(module: *const c_void) -> bool;
    fn module_kdb_is_going_rs_helper(module: *const c_void) -> bool;
    fn module_kdb_is_coming_rs_helper(module: *const c_void) -> bool;
    fn module_kdb_text_size_rs_helper(module: *const c_void) -> c_uint;
    fn module_kdb_rodata_size_rs_helper(module: *const c_void) -> c_uint;
    fn module_kdb_ro_after_init_size_rs_helper(module: *const c_void) -> c_uint;
    fn module_kdb_data_size_rs_helper(module: *const c_void) -> c_uint;
    fn module_kdb_text_base_rs_helper(module: *const c_void) -> *mut c_void;
    fn module_kdb_rodata_base_rs_helper(module: *const c_void) -> *mut c_void;
    fn module_kdb_ro_after_init_base_rs_helper(module: *const c_void) -> *mut c_void;
    fn module_kdb_data_base_rs_helper(module: *const c_void) -> *mut c_void;
}

const UNLOADING: &[u8] = b" (Unloading)\0";
const LOADING: &[u8] = b" (Loading)\0";
const LIVE: &[u8] = b" (Live)\0";

#[no_mangle]
/// Returns whether KDB should skip a module entry.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_kdb_is_unformed_rs(module: *const c_void) -> bool {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_kdb_is_unformed_rs_helper(module) }
}

#[no_mangle]
/// Returns the text memory size printed by KDB.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_kdb_text_size_rs(module: *const c_void) -> c_uint {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_kdb_text_size_rs_helper(module) }
}

#[no_mangle]
/// Returns the rodata memory size printed by KDB.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_kdb_rodata_size_rs(module: *const c_void) -> c_uint {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_kdb_rodata_size_rs_helper(module) }
}

#[no_mangle]
/// Returns the ro-after-init memory size printed by KDB.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_kdb_ro_after_init_size_rs(module: *const c_void) -> c_uint {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_kdb_ro_after_init_size_rs_helper(module) }
}

#[no_mangle]
/// Returns the data memory size printed by KDB.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_kdb_data_size_rs(module: *const c_void) -> c_uint {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_kdb_data_size_rs_helper(module) }
}

#[no_mangle]
/// Returns the textual KDB module state suffix.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_kdb_state_name_rs(module: *const c_void) -> *const c_char {
    // SAFETY: The C caller supplies a valid module pointer.
    if unsafe { module_kdb_is_going_rs_helper(module) } {
        UNLOADING.as_ptr().cast()
    // SAFETY: The C caller supplies a valid module pointer.
    } else if unsafe { module_kdb_is_coming_rs_helper(module) } {
        LOADING.as_ptr().cast()
    } else {
        LIVE.as_ptr().cast()
    }
}

#[no_mangle]
/// Returns the text base printed by KDB.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_kdb_text_base_rs(module: *const c_void) -> *mut c_void {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_kdb_text_base_rs_helper(module) }
}

#[no_mangle]
/// Returns the rodata base printed by KDB.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_kdb_rodata_base_rs(module: *const c_void) -> *mut c_void {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_kdb_rodata_base_rs_helper(module) }
}

#[no_mangle]
/// Returns the ro-after-init base printed by KDB.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_kdb_ro_after_init_base_rs(module: *const c_void) -> *mut c_void {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_kdb_ro_after_init_base_rs_helper(module) }
}

#[no_mangle]
/// Returns the data base printed by KDB.
///
/// # Safety
///
/// `module` must point to a valid `struct module`.
pub unsafe extern "C" fn module_kdb_data_base_rs(module: *const c_void) -> *mut c_void {
    // SAFETY: The C caller supplies a valid module pointer.
    unsafe { module_kdb_data_base_rs_helper(module) }
}
