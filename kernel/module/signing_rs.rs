// SPDX-License-Identifier: GPL-2.0-or-later

//! Helpers for module signature checking.

use core::ffi::{c_char, c_int};

const UNSIGNED: &[u8] = b"unsigned module\0";
const UNSUPPORTED: &[u8] = b"module with unsupported crypto\0";
const UNAVAILABLE: &[u8] = b"module with unavailable key\0";

#[no_mangle]
pub extern "C" fn module_sig_reason_rs(
    err: c_int,
    enodata: c_int,
    enopkg: c_int,
    enokey: c_int,
) -> *const c_char {
    if err == enodata {
        UNSIGNED.as_ptr().cast()
    } else if err == enopkg {
        UNSUPPORTED.as_ptr().cast()
    } else if err == enokey {
        UNAVAILABLE.as_ptr().cast()
    } else {
        core::ptr::null()
    }
}
