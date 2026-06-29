// SPDX-License-Identifier: GPL-2.0

//! DMA channel allocator.

use core::ffi::{c_char, c_int, c_uint};

use kernel::bindings;

extern "C" {
    fn dma_max_channels() -> c_uint;
    fn dma_xchg_lock(dmanr: c_uint, new_val: c_int) -> c_int;
    fn dma_set_device_id(dmanr: c_uint, device_id: *const c_char);
    fn dma_print_warn_free(dmanr: c_uint);
    fn dma_print_warn_free_free(dmanr: c_uint);
}

#[no_mangle]
/// Request and reserve a system DMA channel.
///
/// # Safety
///
/// `device_id` must be a valid pointer to a NUL-terminated string (or NULL
/// when `MAX_DMA_CHANNELS` is not defined).
pub unsafe extern "C" fn request_dma(dmanr: c_uint, device_id: *const c_char) -> c_int {
    let max = unsafe { dma_max_channels() };
    if max == 0 || dmanr >= max {
        return -(bindings::EINVAL as c_int);
    }

    if unsafe { dma_xchg_lock(dmanr, 1) } != 0 {
        return -(bindings::EBUSY as c_int);
    }

    unsafe { dma_set_device_id(dmanr, device_id) };
    0
}

#[no_mangle]
/// Free a reserved system DMA channel.
///
/// # Safety
///
/// No additional safety requirements beyond C calling conventions.
pub unsafe extern "C" fn free_dma(dmanr: c_uint) {
    let max = unsafe { dma_max_channels() };
    if max == 0 {
        return;
    }

    if dmanr >= max {
        unsafe { dma_print_warn_free(dmanr) };
        return;
    }

    if unsafe { dma_xchg_lock(dmanr, 0) } == 0 {
        unsafe { dma_print_warn_free_free(dmanr) };
    }
}
