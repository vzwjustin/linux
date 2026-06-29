// SPDX-License-Identifier: GPL-2.0

//! DMA remap lookup and teardown helpers.

use core::ffi::{c_ulong, c_void};

extern "C" {
    fn remap_vm_area_flags(cpu_addr: *mut c_void) -> c_ulong;
    fn remap_vm_area_pages(cpu_addr: *mut c_void) -> *mut *mut c_void;
    fn remap_warn_unexpected_vm_flags(cpu_addr: *mut c_void);
    fn remap_warn_invalid_free(cpu_addr: *mut c_void);
    fn remap_vm_dma_coherent_flag() -> c_ulong;
    fn remap_vunmap(cpu_addr: *mut c_void);
}

#[no_mangle]
/// Look up the page array backing a DMA-coherent vmalloc mapping.
///
/// # Safety
///
/// `cpu_addr` must follow the C API contract for `dma_common_find_pages()`.
pub unsafe extern "C" fn dma_common_find_pages(cpu_addr: *mut c_void) -> *mut *mut c_void {
    // SAFETY: C shim wraps `find_vm_area()`.
    let flags = unsafe { remap_vm_area_flags(cpu_addr) };
    if flags == 0 || flags & unsafe { remap_vm_dma_coherent_flag() } == 0 {
        return core::ptr::null_mut();
    }

    if flags != unsafe { remap_vm_dma_coherent_flag() } {
        // SAFETY: Matches the original `WARN()` path.
        unsafe { remap_warn_unexpected_vm_flags(cpu_addr) };
    }

    // SAFETY: `cpu_addr` refers to a valid DMA-coherent vm area.
    unsafe { remap_vm_area_pages(cpu_addr) }
}

#[no_mangle]
/// Unmap a range previously mapped by `dma_common_*_remap`.
///
/// # Safety
///
/// `cpu_addr` must follow the C API contract for `dma_common_free_remap()`.
pub unsafe extern "C" fn dma_common_free_remap(cpu_addr: *mut c_void, _size: usize) {
    // SAFETY: C shim wraps `find_vm_area()`.
    let flags = unsafe { remap_vm_area_flags(cpu_addr) };
    if flags == 0 || flags & unsafe { remap_vm_dma_coherent_flag() } == 0 {
        // SAFETY: C shim issues the same `WARN(1, ...)` as the C version.
        unsafe { remap_warn_invalid_free(cpu_addr) };
        return;
    }

    // SAFETY: `cpu_addr` is a valid DMA-coherent mapping.
    unsafe { remap_vunmap(cpu_addr) };
}
