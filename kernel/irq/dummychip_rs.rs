// SPDX-License-Identifier: GPL-2.0

//! Dummy IRQ chip callback helpers.

use kernel::bindings;

#[no_mangle]
/// No-op IRQ chip callback.
///
/// # Safety
///
/// `data` follows the `struct irq_chip` callback contract.
pub unsafe extern "C" fn irq_dummy_noop_rs(_data: *mut bindings::irq_data) {}

#[no_mangle]
/// No-op IRQ startup callback returning success.
///
/// # Safety
///
/// `data` follows the `struct irq_chip` callback contract.
pub unsafe extern "C" fn irq_dummy_noop_ret_rs(_data: *mut bindings::irq_data) -> u32 {
    0
}
