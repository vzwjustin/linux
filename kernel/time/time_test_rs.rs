// SPDX-License-Identifier: LGPL-2.1+

//! Helper logic for the `time64_to_tm` KUnit coverage.

use core::ffi::{c_int, c_long};

fn is_leap(year: c_long) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[no_mangle]
pub extern "C" fn time_test_last_day_of_month_rs(year: c_long, month: c_int) -> c_int {
    match month {
        2 => 28 + if is_leap(year) { 1 } else { 0 },
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[no_mangle]
/// Advances a broken-down test date by one day.
///
/// # Safety
///
/// `year`, `month`, `mday`, and `yday` must be valid, writable pointers.
pub unsafe extern "C" fn time_test_advance_date_rs(
    year: *mut c_long,
    month: *mut c_int,
    mday: *mut c_int,
    yday: *mut c_int,
) {
    // SAFETY: The caller provides valid writable pointers for the test state.
    let year = unsafe { &mut *year };
    let month = unsafe { &mut *month };
    let mday = unsafe { &mut *mday };
    let yday = unsafe { &mut *yday };

    if *mday != time_test_last_day_of_month_rs(*year, *month) {
        *mday += 1;
        *yday += 1;
        return;
    }

    *mday = 1;
    if *month != 12 {
        *month += 1;
        *yday += 1;
        return;
    }

    *month = 1;
    *yday = 0;
    *year += 1;
}
