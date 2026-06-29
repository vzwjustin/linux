// SPDX-License-Identifier: GPL-2.0-only

//! Uniprocessor-only support functions. The counterpart to kernel/smp.c.

use core::ffi::{c_int, c_uint, c_void};

use kernel::bindings;

type SmpCallFunc = unsafe extern "C" fn(*mut c_void);
type SmpCondFunc = unsafe extern "C" fn(c_int, *mut c_void) -> bool;

extern "C" {
    fn up_local_irq_save(flags: *mut core::ffi::c_ulong);
    fn up_local_irq_restore(flags: core::ffi::c_ulong);
    fn up_preempt_disable();
    fn up_preempt_enable();
    fn up_cpumask_test_cpu(cpu: c_int, mask: *const bindings::cpumask) -> bool;
    fn up_hypervisor_pin_vcpu(cpu: c_int);
    fn up_call_csd_func(csd: *mut c_void);
}

#[no_mangle]
/// Run a function on a specific CPU. UP-only: cpu must be 0.
///
/// # Safety
///
/// `func` must be a valid function pointer. `info` must be valid for `func`.
pub unsafe extern "C" fn smp_call_function_single(
    cpu: c_int,
    func: SmpCallFunc,
    info: *mut c_void,
    _wait: c_int,
) -> c_int {
    if cpu != 0 {
        return -(bindings::ENXIO as c_int);
    }

    let mut flags: core::ffi::c_ulong = 0;
    // SAFETY: `flags` is a valid local variable; `up_local_irq_save` wraps
    // the C `local_irq_save` macro.
    unsafe { up_local_irq_save(&mut flags) };
    // SAFETY: Caller guarantees `func` and `info` are valid.
    unsafe { func(info) };
    // SAFETY: `flags` was saved by `up_local_irq_save`.
    unsafe { up_local_irq_restore(flags) };

    0
}

#[no_mangle]
/// Run a CSD's function synchronously. UP-only.
///
/// # Safety
///
/// `csd` must point to a valid `call_single_data_t` with `func` and `info`
/// fields set.
pub unsafe extern "C" fn smp_call_function_single_async(
    _cpu: c_int,
    csd: *mut c_void,
) -> c_int {
    let mut flags: core::ffi::c_ulong = 0;
    // SAFETY: `flags` is a valid local variable.
    unsafe { up_local_irq_save(&mut flags) };
    // SAFETY: `csd` is valid per caller contract; `up_call_csd_func` wraps
    // the C `csd->func(csd->info)` call.
    unsafe { up_call_csd_func(csd) };
    // SAFETY: `flags` was saved by `up_local_irq_save`.
    unsafe { up_local_irq_restore(flags) };

    0
}

#[no_mangle]
/// Call a function on all CPUs matching the condition and mask. UP-only.
///
/// # Safety
///
/// `cond_func` may be null. `func` must be a valid function pointer.
/// `info` must be valid for `func`. `mask` must be a valid cpumask pointer.
pub unsafe extern "C" fn on_each_cpu_cond_mask(
    cond_func: Option<SmpCondFunc>,
    func: SmpCallFunc,
    info: *mut c_void,
    _wait: bool,
    mask: *const bindings::cpumask,
) {
    // SAFETY: `up_preempt_disable` wraps the C `preempt_disable` macro.
    unsafe { up_preempt_disable() };

    // SAFETY: `cond_func` is Some here because `is_none()` short-circuits
    // the `||`. `mask` is valid per caller contract.
    let do_call = (cond_func.is_none() || {
        // SAFETY: `cond_func` is Some due to the short-circuit above.
        let cf = unsafe { cond_func.unwrap_unchecked() };
        // SAFETY: Caller guarantees `cond_func` and `info` are valid.
        unsafe { cf(0, info) }
    }) && unsafe { up_cpumask_test_cpu(0, mask) };

    if do_call {
        let mut flags: core::ffi::c_ulong = 0;
        // SAFETY: `flags` is a valid local variable.
        unsafe { up_local_irq_save(&mut flags) };
        // SAFETY: Caller guarantees `func` and `info` are valid.
        unsafe { func(info) };
        // SAFETY: `flags` was saved by `up_local_irq_save`.
        unsafe { up_local_irq_restore(flags) };
    }

    // SAFETY: `up_preempt_enable` wraps the C `preempt_enable` macro.
    unsafe { up_preempt_enable() };
}

#[no_mangle]
/// Call a function on a specific CPU, optionally pinning the hypervisor vCPU.
/// UP-only: cpu must be 0.
///
/// # Safety
///
/// `func` must be a valid function pointer. `par` must be valid for `func`.
pub unsafe extern "C" fn smp_call_on_cpu(
    cpu: c_uint,
    func: unsafe extern "C" fn(*mut c_void) -> c_int,
    par: *mut c_void,
    phys: bool,
) -> c_int {
    if cpu != 0 {
        return -(bindings::ENXIO as c_int);
    }

    if phys {
        // SAFETY: `up_hypervisor_pin_vcpu` wraps the C inline.
        unsafe { up_hypervisor_pin_vcpu(0) };
    }

    // SAFETY: Caller guarantees `func` and `par` are valid.
    let ret = unsafe { func(par) };

    if phys {
        // SAFETY: `up_hypervisor_pin_vcpu` wraps the C inline.
        unsafe { up_hypervisor_pin_vcpu(-1) };
    }

    ret
}
