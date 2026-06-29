// SPDX-License-Identifier: GPL-2.0

//! Helpers for legacy 16-bit UID/GID syscall compatibility.

use core::ffi::{c_int, c_uint};

extern "C" {
    static overflowuid: c_int;
    static overflowgid: c_int;
}

#[no_mangle]
pub extern "C" fn uid16_low2high_uid_rs(uid: u16) -> c_uint {
    if uid == u16::MAX {
        c_uint::MAX
    } else {
        uid as c_uint
    }
}

#[no_mangle]
pub extern "C" fn uid16_low2high_gid_rs(gid: u16) -> c_uint {
    if gid == u16::MAX {
        c_uint::MAX
    } else {
        gid as c_uint
    }
}

#[no_mangle]
/// Converts a kernel UID to the legacy 16-bit UID value.
///
/// Values that cannot be represented by the legacy ABI are mapped to the
/// configured overflow UID, matching `high2lowuid()`.
pub extern "C" fn uid16_high2low_uid_rs(uid: c_uint) -> u16 {
    if uid & !0xffff != 0 {
        // SAFETY: `overflowuid` is the kernel global used by highuid.h.
        unsafe { overflowuid as u16 }
    } else {
        uid as u16
    }
}

#[no_mangle]
/// Converts a kernel GID to the legacy 16-bit GID value.
///
/// Values that cannot be represented by the legacy ABI are mapped to the
/// configured overflow GID, matching `high2lowgid()`.
pub extern "C" fn uid16_high2low_gid_rs(gid: c_uint) -> u16 {
    if gid & !0xffff != 0 {
        // SAFETY: `overflowgid` is the kernel global used by highuid.h.
        unsafe { overflowgid as u16 }
    } else {
        gid as u16
    }
}
