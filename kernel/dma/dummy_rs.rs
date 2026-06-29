// SPDX-License-Identifier: GPL-2.0

//! Dummy DMA ops that always fail.

use core::ffi::{c_int, c_ulong, c_void};

use kernel::bindings;

extern "C" {
    fn dma_dummy_warn_once();
    fn dma_dummy_mapping_error() -> bindings::dma_addr_t;
}

#[no_mangle]
/// Dummy `mmap` implementation for devices that do not support DMA mapping.
///
/// # Safety
///
/// This function matches the C `dma_map_ops::mmap` callback ABI. All pointer
/// arguments are ignored because the dummy implementation always fails.
pub unsafe extern "C" fn dma_dummy_mmap_rs(
    _dev: *mut bindings::device,
    _vma: *mut bindings::vm_area_struct,
    _cpu_addr: *mut c_void,
    _dma_addr: bindings::dma_addr_t,
    _size: usize,
    _attrs: c_ulong,
) -> c_int {
    -(bindings::ENXIO as c_int)
}

#[no_mangle]
/// Dummy physical address mapper for devices that do not support DMA mapping.
///
/// # Safety
///
/// This function matches the C `dma_map_ops::map_phys` callback ABI. All
/// arguments are ignored because the dummy implementation always fails.
pub unsafe extern "C" fn dma_dummy_map_phys_rs(
    _dev: *mut bindings::device,
    _phys: bindings::phys_addr_t,
    _size: usize,
    _dir: bindings::dma_data_direction,
    _attrs: c_ulong,
) -> bindings::dma_addr_t {
    // SAFETY: C helper returns the architecture-specific `DMA_MAPPING_ERROR`.
    unsafe { dma_dummy_mapping_error() }
}

#[no_mangle]
/// Dummy physical unmapper for unsupported DMA mappings.
///
/// # Safety
///
/// This function matches the C `dma_map_ops::unmap_phys` callback ABI.
pub unsafe extern "C" fn dma_dummy_unmap_phys_rs(
    _dev: *mut bindings::device,
    _dma_handle: bindings::dma_addr_t,
    _size: usize,
    _dir: bindings::dma_data_direction,
    _attrs: c_ulong,
) {
    // SAFETY: C helper wraps `WARN_ON_ONCE(true)`.
    unsafe { dma_dummy_warn_once() };
}

#[no_mangle]
/// Dummy scatterlist mapper for devices that do not support DMA mapping.
///
/// # Safety
///
/// This function matches the C `dma_map_ops::map_sg` callback ABI. All
/// arguments are ignored because the dummy implementation always fails.
pub unsafe extern "C" fn dma_dummy_map_sg_rs(
    _dev: *mut bindings::device,
    _sgl: *mut bindings::scatterlist,
    _nelems: c_int,
    _dir: bindings::dma_data_direction,
    _attrs: c_ulong,
) -> c_int {
    -(bindings::EINVAL as c_int)
}

#[no_mangle]
/// Dummy scatterlist unmapper for unsupported DMA mappings.
///
/// # Safety
///
/// This function matches the C `dma_map_ops::unmap_sg` callback ABI.
pub unsafe extern "C" fn dma_dummy_unmap_sg_rs(
    _dev: *mut bindings::device,
    _sgl: *mut bindings::scatterlist,
    _nelems: c_int,
    _dir: bindings::dma_data_direction,
    _attrs: c_ulong,
) {
    // SAFETY: C helper wraps `WARN_ON_ONCE(true)`.
    unsafe { dma_dummy_warn_once() };
}

#[no_mangle]
/// Reports that no DMA mask is supported by the dummy ops.
///
/// # Safety
///
/// This function matches the C `dma_map_ops::dma_supported` callback ABI.
pub unsafe extern "C" fn dma_dummy_supported_rs(
    _hwdev: *mut bindings::device,
    _mask: u64,
) -> c_int {
    0
}
