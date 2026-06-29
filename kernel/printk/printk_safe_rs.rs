// SPDX-License-Identifier: GPL-2.0-or-later

//! Safe printk context helpers for printk-deadlock-prone contexts.

extern "C" {
    fn printk_force_console_inc();
    fn printk_force_console_dec();
    fn printk_force_console_read() -> bool;
    fn printk_context_inc();
    fn printk_context_dec();
    fn printk_context_read() -> core::ffi::c_int;
    fn printk_cant_migrate();
    fn printk_force_legacy_kthread() -> bool;
    fn printk_in_nmi() -> bool;
    fn printk_cpu_sync_owner() -> bool;
}

#[no_mangle]
/// Enters a context where printk messages must not be suppressed.
pub extern "C" fn printk_force_console_enter() {
    // SAFETY: C helper wraps the file-local atomic increment.
    unsafe { printk_force_console_inc() };
}

#[no_mangle]
/// Exits a context where printk messages must not be suppressed.
pub extern "C" fn printk_force_console_exit() {
    // SAFETY: C helper wraps the file-local atomic decrement.
    unsafe { printk_force_console_dec() };
}

#[no_mangle]
/// Returns whether console-forced printk context is active.
pub extern "C" fn is_printk_force_console() -> bool {
    // SAFETY: C helper wraps the file-local atomic read.
    unsafe { printk_force_console_read() }
}

#[no_mangle]
/// Enters printk-safe context; may be preempted by NMI.
pub extern "C" fn __printk_safe_enter() {
    // SAFETY: C helper wraps this-CPU increment of `printk_context`.
    unsafe { printk_context_inc() };
}

#[no_mangle]
/// Exits printk-safe context; may be preempted by NMI.
pub extern "C" fn __printk_safe_exit() {
    // SAFETY: C helper wraps this-CPU decrement of `printk_context`.
    unsafe { printk_context_dec() };
}

#[no_mangle]
/// Enters printk deferred context with migration disabled by the caller path.
pub extern "C" fn __printk_deferred_enter() {
    // SAFETY: C helper wraps `cant_migrate()`.
    unsafe { printk_cant_migrate() };
    __printk_safe_enter();
}

#[no_mangle]
/// Exits printk deferred context with migration disabled by the caller path.
pub extern "C" fn __printk_deferred_exit() {
    // SAFETY: C helper wraps `cant_migrate()`.
    unsafe { printk_cant_migrate() };
    __printk_safe_exit();
}

#[no_mangle]
/// Returns whether legacy printk should be deferred in the current context.
pub extern "C" fn is_printk_legacy_deferred() -> bool {
    // SAFETY: C helpers wrap the corresponding printk/per-CPU/NMI predicates.
    unsafe {
        printk_force_legacy_kthread()
            || printk_context_read() != 0
            || printk_in_nmi()
            || printk_cpu_sync_owner()
    }
}
