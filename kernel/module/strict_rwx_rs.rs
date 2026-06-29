// SPDX-License-Identifier: GPL-2.0-or-later

//! Module strict RWX section helpers.

use core::ffi::{c_char, c_int, c_uint, c_void};

extern "C" {
    fn module_strict_rwx_enabled_rs_helper() -> bool;
    fn module_have_static_call_inline_rs_helper() -> bool;
    fn module_elf_shnum_rs_helper(hdr: *const c_void) -> c_uint;
    fn module_section_has_wx_rs_helper(sechdrs: *const c_void, index: c_uint) -> bool;
    fn module_section_name_rs_helper(
        sechdrs: *const c_void,
        secstrings: *const c_char,
        index: c_uint,
    ) -> *const c_char;
    fn module_mark_section_ro_after_init_rs_helper(sechdrs: *mut c_void, index: c_uint);
    fn module_enforce_rwx_pr_err_rs_helper(
        modname: *const c_char,
        secname: *const c_char,
        index: c_uint,
    );
}

const DATA_RO_AFTER_INIT: &[u8] = b".data..ro_after_init\0";
const JUMP_TABLE: &[u8] = b"__jump_table\0";
const STATIC_CALL_SITES: &[u8] = b".static_call_sites\0";

unsafe fn c_streq(mut a: *const c_char, mut b: *const u8) -> bool {
    loop {
        // SAFETY: The caller provides valid NUL-terminated C strings.
        let ac = unsafe { *a } as u8;
        // SAFETY: `b` points at one of this module's NUL-terminated byte strings.
        let bc = unsafe { *b };

        if ac != bc {
            return false;
        }
        if ac == 0 {
            return true;
        }

        // SAFETY: Advance within the NUL-terminated strings.
        a = unsafe { a.add(1) };
        b = unsafe { b.add(1) };
    }
}

unsafe fn is_ro_after_init_name(name: *const c_char) -> bool {
    // SAFETY: `name` points into the module section string table.
    let data_ro_after_init = unsafe { c_streq(name, DATA_RO_AFTER_INIT.as_ptr()) };
    // SAFETY: `name` points into the module section string table.
    let jump_table = unsafe { c_streq(name, JUMP_TABLE.as_ptr()) };
    // SAFETY: C helper exposes the matching Kconfig predicate.
    let static_call_inline = unsafe { module_have_static_call_inline_rs_helper() };
    // SAFETY: `name` points into the module section string table.
    let static_call_sites = unsafe { c_streq(name, STATIC_CALL_SITES.as_ptr()) };

    data_ro_after_init || jump_table || (static_call_inline && static_call_sites)
}

#[no_mangle]
/// Rejects module sections that are both writable and executable.
///
/// # Safety
///
/// Pointers must match the C `module_enforce_rwx_sections` contract.
pub unsafe extern "C" fn module_enforce_rwx_sections_rs(
    hdr: *const c_void,
    sechdrs: *const c_void,
    secstrings: *const c_char,
    modname: *const c_char,
    enoexec: c_int,
) -> c_int {
    // SAFETY: C helper exposes the strict RWX Kconfig predicate.
    if !unsafe { module_strict_rwx_enabled_rs_helper() } {
        return 0;
    }

    // SAFETY: `hdr` is the ELF header passed by the C caller.
    let shnum = unsafe { module_elf_shnum_rs_helper(hdr) };
    for i in 0..shnum {
        // SAFETY: `sechdrs` contains `shnum` section headers.
        if unsafe { module_section_has_wx_rs_helper(sechdrs, i) } {
            // SAFETY: Section name pointer is derived from `sechdrs` and `secstrings`.
            let secname = unsafe { module_section_name_rs_helper(sechdrs, secstrings, i) };
            // SAFETY: Helper preserves the original C printk boundary.
            unsafe { module_enforce_rwx_pr_err_rs_helper(modname, secname, i) };
            return enoexec;
        }
    }

    0
}

#[no_mangle]
/// Marks module sections that should become read-only after init.
///
/// # Safety
///
/// Pointers must match the C `module_mark_ro_after_init` contract.
pub unsafe extern "C" fn module_mark_ro_after_init_rs(
    hdr: *const c_void,
    sechdrs: *mut c_void,
    secstrings: *const c_char,
) {
    // SAFETY: `hdr` is the ELF header passed by the C caller.
    let shnum = unsafe { module_elf_shnum_rs_helper(hdr) };
    for i in 1..shnum {
        // SAFETY: Section name pointer is derived from `sechdrs` and `secstrings`.
        let name =
            unsafe { module_section_name_rs_helper(sechdrs as *const c_void, secstrings, i) };
        // SAFETY: `name` points into the module section string table.
        if unsafe { is_ro_after_init_name(name) } {
            // SAFETY: `sechdrs` contains `shnum` section headers.
            unsafe { module_mark_section_ro_after_init_rs_helper(sechdrs, i) };
        }
    }
}
