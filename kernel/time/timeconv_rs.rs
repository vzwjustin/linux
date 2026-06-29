// SPDX-License-Identifier: LGPL-2.0+

//! Calendar time conversion helpers.

use core::ffi::{c_int, c_long};

use kernel::bindings;

const SECS_PER_HOUR: i64 = 60 * 60;
const SECS_PER_DAY: i64 = SECS_PER_HOUR * 24;

#[no_mangle]
/// Converts seconds since the Unix epoch to a broken-down calendar time.
///
/// # Safety
///
/// `result` must be valid for writes of a `struct tm`.
pub unsafe extern "C" fn time64_to_tm_rs(
    totalsecs: bindings::time64_t,
    offset: c_int,
    result: *mut bindings::tm,
) {
    let mut days = totalsecs / SECS_PER_DAY;
    let mut rem = totalsecs % SECS_PER_DAY;

    rem += offset as i64;
    while rem < 0 {
        rem += SECS_PER_DAY;
        days -= 1;
    }
    while rem >= SECS_PER_DAY {
        rem -= SECS_PER_DAY;
        days += 1;
    }

    // SAFETY: The caller provides a writable `struct tm` pointer.
    let result = unsafe { &mut *result };

    result.tm_hour = (rem / SECS_PER_HOUR) as c_int;
    rem %= SECS_PER_HOUR;
    result.tm_min = (rem / 60) as c_int;
    result.tm_sec = (rem % 60) as c_int;

    result.tm_wday = ((4 + days) % 7) as c_int;
    if result.tm_wday < 0 {
        result.tm_wday += 7;
    }

    /*
     * This is Proposition 6.3 of Neri and Schneider, using the same
     * computational March-through-February calendar as the C implementation.
     */
    let udays = (days as u64).wrapping_add(2_305_843_009_213_814_918);

    let u64tmp = 4 * udays + 3;
    let century = u64tmp / 146_097;
    let day_of_century = ((u64tmp % 146_097) / 4) as u32;

    let u32tmp = 4 * day_of_century + 3;
    let u64tmp = 2_939_745_u64 * u32tmp as u64;
    let year_of_century = u64tmp >> 32;
    let day_of_year = ((u64tmp as u32) / 2_939_745 / 4) as u64;

    let mut year = 100 * century + year_of_century;
    let is_leap_year = if year_of_century != 0 {
        year_of_century % 4 == 0
    } else {
        century % 4 == 0
    };

    let u32tmp = 2141 * day_of_year as u32 + 132_377;
    let mut month = (u32tmp >> 16) as u64;
    let mut day = ((u32tmp as u16) / 2141) as u64;

    let is_jan_or_feb = day_of_year >= 306;

    year = year + u64::from(is_jan_or_feb) - 6_313_183_731_940_000;
    if is_jan_or_feb {
        month -= 12;
    }
    day += 1;
    let day_of_year = if is_jan_or_feb {
        day_of_year - 306
    } else {
        day_of_year + 31 + 28 + u64::from(is_leap_year)
    };

    result.tm_year = (year as c_long - 1900) as c_long;
    result.tm_mon = month as c_int;
    result.tm_mday = day as c_int;
    result.tm_yday = day_of_year as c_int;
}
