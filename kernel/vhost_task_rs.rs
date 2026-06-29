// SPDX-License-Identifier: GPL-2.0-only

//! vhost worker thread control helpers.

use core::ffi::c_void;

extern "C" {
    fn vhost_task_get_task(vtsk: *mut c_void) -> *mut c_void;
    fn vhost_wake_up_process(task: *mut c_void);
    fn vhost_wake_up_new_task(task: *mut c_void);
}

#[no_mangle]
/// Wake up the vhost_task worker thread.
///
/// # Safety
///
/// `vtsk` must be a valid `struct vhost_task` pointer.
pub unsafe extern "C" fn vhost_task_wake(vtsk: *mut c_void) {
    // SAFETY: `vtsk` is valid and `vhost_task_get_task` returns its `task` field.
    let task = unsafe { vhost_task_get_task(vtsk) };
    // SAFETY: C shim wraps `wake_up_process()`.
    unsafe { vhost_wake_up_process(task) };
}

#[no_mangle]
/// Start a vhost_task created with `vhost_task_create`.
///
/// # Safety
///
/// `vtsk` must be a valid `struct vhost_task` pointer.
pub unsafe extern "C" fn vhost_task_start(vtsk: *mut c_void) {
    // SAFETY: `vtsk` is valid and `vhost_task_get_task` returns its `task` field.
    let task = unsafe { vhost_task_get_task(vtsk) };
    // SAFETY: C shim wraps `wake_up_new_task()`.
    unsafe { vhost_wake_up_new_task(task) };
}
