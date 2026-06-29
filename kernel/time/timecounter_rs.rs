// SPDX-License-Identifier: GPL-2.0-or-later

//! Timecounter helpers.

#[repr(C)]
/// Hardware abstraction for a free-running cycle counter.
pub struct CycleCounter {
    read: Option<unsafe extern "C" fn(*mut CycleCounter) -> u64>,
    mask: u64,
    mult: u32,
    shift: u32,
}

#[repr(C)]
/// Nanosecond counter layered over a cycle counter.
pub struct TimeCounter {
    cc: *mut CycleCounter,
    cycle_last: u64,
    nsec: u64,
    mask: u64,
    frac: u64,
}

#[inline]
fn cyclecounter_cyc2ns(cc: &CycleCounter, cycles: u64, mask: u64, frac: &mut u64) -> u64 {
    let ns = cycles.wrapping_mul(cc.mult as u64).wrapping_add(*frac);
    *frac = ns & mask;
    ns >> cc.shift
}

#[inline]
unsafe fn read_cycle(cc: *mut CycleCounter) -> u64 {
    // SAFETY: The C API requires `cc->read` to be a valid callback.
    unsafe { ((*cc).read.expect("cyclecounter read callback"))(cc) }
}

#[no_mangle]
/// Initializes a time counter.
///
/// # Safety
///
/// `tc` and `cc` must be valid pointers to initialized kernel objects.
pub unsafe extern "C" fn timecounter_init(
    tc: *mut TimeCounter,
    cc: *mut CycleCounter,
    start_tstamp: u64,
) {
    // SAFETY: The caller provides valid pointers according to the C API.
    unsafe {
        (*tc).cc = cc;
        (*tc).cycle_last = read_cycle(cc);
        (*tc).nsec = start_tstamp;
        (*tc).mask = (1u64 << (*cc).shift) - 1;
        (*tc).frac = 0;
    }
}

#[inline]
unsafe fn timecounter_read_delta(tc: *mut TimeCounter) -> u64 {
    // SAFETY: The caller provides a valid `TimeCounter`.
    let cc = unsafe { (*tc).cc };
    // SAFETY: `cc` is valid per the `TimeCounter` invariant.
    let cycle_now = unsafe { read_cycle(cc) };
    // SAFETY: `tc` and `cc` are valid per the caller contract.
    let cycle_delta = unsafe { cycle_now.wrapping_sub((*tc).cycle_last) & (*cc).mask };
    // SAFETY: `tc` and `cc` are valid per the caller contract.
    let ns_offset =
        unsafe { cyclecounter_cyc2ns(&*cc, cycle_delta, (*tc).mask, &mut (*tc).frac) };
    // SAFETY: `tc` is valid per the caller contract.
    unsafe { (*tc).cycle_last = cycle_now };
    ns_offset
}

#[no_mangle]
/// Reads a time counter and updates its accumulated nanoseconds.
///
/// # Safety
///
/// `tc` must be a valid pointer to an initialized time counter.
pub unsafe extern "C" fn timecounter_read(tc: *mut TimeCounter) -> u64 {
    // SAFETY: Same preconditions as this exported function.
    let nsec = unsafe { timecounter_read_delta(tc) };
    // SAFETY: `tc` is valid per the caller contract.
    let nsec = unsafe { nsec.wrapping_add((*tc).nsec) };
    // SAFETY: `tc` is valid per the caller contract.
    unsafe { (*tc).nsec = nsec };
    nsec
}
