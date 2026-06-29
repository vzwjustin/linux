// SPDX-License-Identifier: GPL-2.0-or-later

//! Module livepatch ELF persistence support.

use core::ffi::{c_int, c_uint, c_void};

use kernel::bindings;

extern "C" {
    fn module_klp_info_alloc(module: *mut c_void) -> bool;
    fn module_klp_copy_hdr(module: *mut c_void, info: *mut c_void);
    fn module_klp_copy_sechdrs(module: *mut c_void, info: *mut c_void) -> bool;
    fn module_klp_copy_secstrings(module: *mut c_void, info: *mut c_void) -> bool;
    fn module_klp_sym_index(info: *mut c_void) -> c_uint;
    fn module_klp_set_sym_index(module: *mut c_void, symndx: c_uint);
    fn module_klp_repoint_symtab(module: *mut c_void, symndx: c_uint);
    fn module_klp_free_sechdrs(module: *mut c_void);
    fn module_klp_free_info(module: *mut c_void);
}

#[no_mangle]
/// Copies module ELF metadata needed by livepatch.
///
/// # Safety
///
/// `module` and `info` must be valid pointers supplied by the module loader.
pub unsafe extern "C" fn copy_module_elf_rs(module: *mut c_void, info: *mut c_void) -> c_int {
    // SAFETY: C helper allocates `mod->klp_info`.
    if !unsafe { module_klp_info_alloc(module) } {
        return -(bindings::ENOMEM as c_int);
    }

    // SAFETY: C helper copies the ELF header from valid loader metadata.
    unsafe { module_klp_copy_hdr(module, info) };

    // SAFETY: C helper duplicates the section header table.
    if !unsafe { module_klp_copy_sechdrs(module, info) } {
        // SAFETY: `klp_info` was allocated above.
        unsafe { module_klp_free_info(module) };
        return -(bindings::ENOMEM as c_int);
    }

    // SAFETY: C helper duplicates the section string table.
    if !unsafe { module_klp_copy_secstrings(module, info) } {
        // SAFETY: `sechdrs` was allocated above.
        unsafe { module_klp_free_sechdrs(module) };
        // SAFETY: `klp_info` was allocated above.
        unsafe { module_klp_free_info(module) };
        return -(bindings::ENOMEM as c_int);
    }

    // SAFETY: C helper reads `info->index.sym`.
    let symndx = unsafe { module_klp_sym_index(info) };
    // SAFETY: C helper writes `mod->klp_info->symndx`.
    unsafe { module_klp_set_sym_index(module, symndx) };
    // SAFETY: C helper updates the copied section header's `sh_addr`.
    unsafe { module_klp_repoint_symtab(module, symndx) };

    0
}
