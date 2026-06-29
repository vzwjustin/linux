// SPDX-License-Identifier: GPL-2.0

//! Range add, subtract, compact, and sort helpers.

use core::{ffi::c_int, ptr};

use kernel::pr_err;

const __LOG_PREFIX: &[u8] = b"range\0";

#[repr(C)]
/// Inclusive range used by the C `struct range` ABI.
pub struct Range {
    start: u64,
    end: u64,
}

#[inline]
unsafe fn range_at<'a>(range: *mut Range, index: c_int) -> &'a mut Range {
    // SAFETY: Callers preserve the C helper contract: `range` points to an
    // array large enough for `index`.
    unsafe { &mut *range.add(index as usize) }
}

#[inline]
fn swap_range(a: &mut Range, b: &mut Range) {
    core::mem::swap(&mut a.start, &mut b.start);
    core::mem::swap(&mut a.end, &mut b.end);
}

fn sort_range_entries(range: *mut Range, nr_range: c_int) {
    if nr_range <= 1 {
        return;
    }

    let mut i = 1;
    while i < nr_range {
        let mut j = i;
        while j > 0 {
            // SAFETY: `j` and `j - 1` are within the caller-provided range.
            let cur = unsafe { &*range.add(j as usize) };
            let prev = unsafe { &*range.add((j - 1) as usize) };
            if prev.start <= cur.start {
                break;
            }

            // SAFETY: These two indices are distinct and in bounds.
            let a = unsafe { range_at(range, j - 1) as *mut Range };
            let b = unsafe { range_at(range, j) as *mut Range };
            // SAFETY: `a` and `b` point to distinct entries.
            unsafe { swap_range(&mut *a, &mut *b) };
            j -= 1;
        }
        i += 1;
    }
}

#[no_mangle]
/// Adds one range entry without merging.
///
/// # Safety
///
/// `range` must point to an array with at least `az` entries. `nr_range` must
/// be a valid insertion index for that array.
pub unsafe extern "C" fn add_range(
    range: *mut Range,
    az: c_int,
    mut nr_range: c_int,
    start: u64,
    end: u64,
) -> c_int {
    if start >= end {
        return nr_range;
    }

    if nr_range >= az || nr_range < 0 {
        return nr_range;
    }

    // SAFETY: The checks above preserve the C implementation's slot contract.
    let slot = unsafe { range_at(range, nr_range) };
    slot.start = start;
    slot.end = end;
    nr_range += 1;

    nr_range
}

#[no_mangle]
/// Adds one range entry, merging overlapping or touching ranges.
///
/// # Safety
///
/// `range` must point to an array with at least `az` entries, and the first
/// `nr_range` entries must be initialized.
pub unsafe extern "C" fn add_range_with_merge(
    range: *mut Range,
    az: c_int,
    mut nr_range: c_int,
    mut start: u64,
    mut end: u64,
) -> c_int {
    if start >= end {
        return nr_range;
    }

    let mut i = 0;
    while i < nr_range {
        // SAFETY: `i < nr_range`, matching the C loop bound.
        let current = unsafe { range_at(range, i) };
        if current.end == 0 {
            i += 1;
            continue;
        }

        let common_start = core::cmp::max(current.start, start);
        let common_end = core::cmp::min(current.end, end);
        if common_start > common_end {
            i += 1;
            continue;
        }

        start = core::cmp::min(current.start, start);
        end = core::cmp::max(current.end, end);

        let dst = i as usize;
        let src = (i + 1) as usize;
        let count = (nr_range - (i + 1)) as usize;
        // SAFETY: This is the Rust equivalent of the original `memmove`.
        unsafe { ptr::copy(range.add(src), range.add(dst), count) };

        // SAFETY: `nr_range` is positive here because `i < nr_range`.
        let last = unsafe { range_at(range, nr_range - 1) };
        last.start = 0;
        last.end = 0;
        nr_range -= 1;
    }

    // SAFETY: Same preconditions as this function; `add_range` performs slot
    // availability checks before writing.
    unsafe { add_range(range, az, nr_range, start, end) }
}

#[no_mangle]
/// Subtracts one range from all populated entries in the array.
///
/// # Safety
///
/// `range` must point to an array with at least `az` entries.
pub unsafe extern "C" fn subtract_range(range: *mut Range, az: c_int, start: u64, end: u64) {
    if start >= end || az <= 0 {
        return;
    }

    let mut j = 0;
    while j < az {
        // SAFETY: `j < az`, matching the C loop bound.
        let current = unsafe { range_at(range, j) };
        if current.end == 0 {
            j += 1;
            continue;
        }

        if start <= current.start && end >= current.end {
            current.start = 0;
            current.end = 0;
            j += 1;
            continue;
        }

        if start <= current.start && end < current.end && current.start < end {
            current.start = end;
            j += 1;
            continue;
        }

        if start > current.start && end >= current.end && current.end > start {
            current.end = start;
            j += 1;
            continue;
        }

        if start > current.start && end < current.end {
            let old_end = current.end;
            let mut i = 0;
            while i < az {
                // SAFETY: `i < az`, matching the C loop bound.
                if unsafe { range_at(range, i) }.end == 0 {
                    break;
                }
                i += 1;
            }

            if i < az {
                // SAFETY: `i < az`, so this spare slot is valid.
                let spare = unsafe { range_at(range, i) };
                spare.end = old_end;
                spare.start = end;
            } else {
                pr_err!("subtract_range: run out of slot in ranges\n");
            }

            // SAFETY: `j < az`; reborrow after the spare-slot scan.
            let current = unsafe { range_at(range, j) };
            current.end = start;
        }

        j += 1;
    }
}

#[no_mangle]
/// Compacts populated range entries toward the front, sorts them, and returns the count.
///
/// # Safety
///
/// `range` must point to an array with at least `az` entries.
pub unsafe extern "C" fn clean_sort_range(range: *mut Range, az: c_int) -> c_int {
    if az <= 0 {
        return az;
    }

    let mut k = az - 1;
    let mut nr_range = az;
    let mut i = 0;
    while i < k {
        // SAFETY: `i < k < az`.
        if unsafe { range_at(range, i) }.end != 0 {
            i += 1;
            continue;
        }

        let mut j = k;
        while j > i {
            // SAFETY: `j <= k < az`.
            if unsafe { range_at(range, j) }.end != 0 {
                k = j;
                break;
            }
            j -= 1;
        }

        if j == i {
            break;
        }

        // SAFETY: `i` and `k` are valid and distinct entries.
        let src_start = unsafe { range_at(range, k) }.start;
        let src_end = unsafe { range_at(range, k) }.end;
        let dst = unsafe { range_at(range, i) };
        dst.start = src_start;
        dst.end = src_end;
        let src = unsafe { range_at(range, k) };
        src.start = 0;
        src.end = 0;
        k -= 1;
        i += 1;
    }

    i = 0;
    while i < az {
        // SAFETY: `i < az`.
        if unsafe { range_at(range, i) }.end == 0 {
            nr_range = i;
            break;
        }
        i += 1;
    }

    sort_range_entries(range, nr_range);
    nr_range
}

#[no_mangle]
/// Sorts the first `nr_range` entries by start address.
///
/// # Safety
///
/// `range` must point to an array with at least `nr_range` entries.
pub unsafe extern "C" fn sort_range(range: *mut Range, nr_range: c_int) {
    sort_range_entries(range, nr_range);
}
