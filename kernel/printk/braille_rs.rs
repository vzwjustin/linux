// SPDX-License-Identifier: GPL-2.0

//! Braille console option parser.

use core::ffi::c_int;

use kernel::{bindings, ffi::c_char, pr_err};

const __LOG_PREFIX: &[u8] = b"braille\0";
static EMPTY: [c_char; 1] = [0];

unsafe fn has_prefix(s: *const c_char, prefix: &[u8]) -> bool {
    let mut i = 0;
    while i < prefix.len() {
        // SAFETY: The caller provides a valid NUL-terminated C string.
        if unsafe { *s.add(i) } != prefix[i] as c_char {
            return false;
        }
        i += 1;
    }
    true
}

#[no_mangle]
/// Parses braille console options from a console option string.
///
/// # Safety
///
/// `strp` and `brl_options` must point to valid writable pointers. `*strp`
/// must point to a mutable NUL-terminated command-line string.
pub unsafe extern "C" fn _braille_console_setup(
    strp: *mut *mut c_char,
    brl_options: *mut *mut c_char,
) -> c_int {
    // SAFETY: The C caller passes a valid pointer to the console option string.
    let s = unsafe { *strp };

    // SAFETY: `s` follows the function's C-string contract.
    if unsafe { has_prefix(s, b"brl,") } {
        // SAFETY: The output pointers follow the function contract.
        unsafe {
            *brl_options = EMPTY.as_ptr() as *mut c_char;
            *strp = s.add(4);
        }
        return 0;
    }

    // SAFETY: `s` follows the function's C-string contract.
    if unsafe { has_prefix(s, b"brl=") } {
        // SAFETY: `s` points to at least the checked prefix.
        let options = unsafe { s.add(4) };
        // SAFETY: The output pointer follows the function contract.
        unsafe { *brl_options = options };

        // SAFETY: `options` is a valid C string tail.
        let comma = unsafe { bindings::strchr(options.cast_const(), b',' as c_int) };
        if comma.is_null() {
            pr_err!("need port name for brl=\n");
            return -(bindings::EINVAL as c_int);
        }

        // SAFETY: `comma` points inside the mutable command-line string.
        unsafe {
            *strp = comma.add(1);
            *comma = 0;
        }
    }

    0
}
