// SPDX-License-Identifier: GPL-2.0
//! Kernel headers sysfs module init/cleanup.

use core::ffi::{c_int, c_void};

extern "C" {
    fn ikheaders_data_start() -> *const c_void;
    fn ikheaders_data_size() -> usize;
    fn ikheaders_attr_set_private(data: *const c_void);
    fn ikheaders_attr_set_size(size: usize);
    fn ikheaders_sysfs_create() -> c_int;
    fn ikheaders_sysfs_remove();
}

#[no_mangle]
/// Initializes `/sys/kernel/kheaders.tar.xz`.
///
/// # Safety
///
/// Called once by the C module init path after `kernel_kobj` is ready.
pub unsafe extern "C" fn ikheaders_init_rs() -> c_int {
    let data = unsafe { ikheaders_data_start() };
    let size = unsafe { ikheaders_data_size() };

    unsafe { ikheaders_attr_set_private(data) };
    unsafe { ikheaders_attr_set_size(size) };
    unsafe { ikheaders_sysfs_create() }
}

#[no_mangle]
/// Removes `/sys/kernel/kheaders.tar.xz`.
///
/// # Safety
///
/// Called by the C module exit path after successful module init.
pub unsafe extern "C" fn ikheaders_cleanup_rs() {
    unsafe { ikheaders_sysfs_remove() };
}
