// SPDX-License-Identifier: GPL-2.0

//! User return notifier support.

use core::ffi::c_void;

extern "C" {
    fn urn_set_tif_notify();
    fn urn_clear_tif_notify();
    fn urn_hlist_add_head(urn: *mut c_void);
    fn urn_hlist_del(urn: *mut c_void);
    fn urn_hlist_empty() -> bool;
}

#[no_mangle]
/// Register a user return notifier on the current CPU.
///
/// # Safety
///
/// `urn` must be a valid pointer to a `struct user_return_notifier`.
pub unsafe extern "C" fn user_return_notifier_register(urn: *mut c_void) {
    unsafe { urn_set_tif_notify() };
    unsafe { urn_hlist_add_head(urn) };
}

#[no_mangle]
/// Unregister a user return notifier.
///
/// # Safety
///
/// `urn` must be a valid pointer to a `struct user_return_notifier` that was
/// previously registered on the current CPU.
pub unsafe extern "C" fn user_return_notifier_unregister(urn: *mut c_void) {
    unsafe { urn_hlist_del(urn) };
    if unsafe { urn_hlist_empty() } {
        unsafe { urn_clear_tif_notify() };
    }
}
