// SPDX-License-Identifier: GPL-2.0-or-later

//! Small helpers for module version handling.

use core::ffi::{c_char, c_int};

#[repr(C)]
pub struct ModversionInfoExt {
    remaining: usize,
    crc: *const u32,
    name: *const c_char,
}

unsafe fn c_strlen(mut s: *const c_char) -> usize {
    let mut len = 0;

    // SAFETY: The caller provides a valid NUL-terminated C string.
    while unsafe { *s } != 0 {
        len += 1;
        // SAFETY: Walking within the provided C string until its NUL byte.
        s = unsafe { s.add(1) };
    }
    len
}

unsafe fn skip_until_space(mut s: *const c_char) -> *const c_char {
    // SAFETY: The caller provides a valid NUL-terminated C string.
    while unsafe { *s } != 0 && unsafe { *s } != b' ' as c_char {
        // SAFETY: Walking within the provided C string until NUL or space.
        s = unsafe { s.add(1) };
    }
    s
}

unsafe fn c_strcmp(mut a: *const c_char, mut b: *const c_char) -> c_int {
    loop {
        // SAFETY: The caller provides valid NUL-terminated C strings.
        let ac = unsafe { *a } as u8;
        let bc = unsafe { *b } as u8;

        if ac != bc || ac == 0 {
            return ac as c_int - bc as c_int;
        }

        // SAFETY: Walking within the provided C strings until their NUL byte.
        a = unsafe { a.add(1) };
        b = unsafe { b.add(1) };
    }
}

#[no_mangle]
/// Compares module vermagic strings, optionally ignoring the leading kernel
/// version when symbol CRCs are present.
///
/// # Safety
///
/// `amagic` and `bmagic` must point to valid NUL-terminated C strings.
pub unsafe extern "C" fn same_magic_rs(
    mut amagic: *const c_char,
    mut bmagic: *const c_char,
    has_crcs: bool,
) -> c_int {
    if has_crcs {
        // SAFETY: The caller provides valid NUL-terminated C strings.
        amagic = unsafe { skip_until_space(amagic) };
        bmagic = unsafe { skip_until_space(bmagic) };
    }

    // SAFETY: The caller provides valid NUL-terminated C strings.
    (unsafe { c_strcmp(amagic, bmagic) } == 0) as c_int
}

#[no_mangle]
/// Advances an extended modversion iterator to the next CRC/name pair.
///
/// # Safety
///
/// `vers` must be a valid pointer to the C `struct modversion_info_ext`.
pub unsafe extern "C" fn modversion_ext_advance_rs(vers: *mut ModversionInfoExt) {
    // SAFETY: The caller provides a valid iterator pointer.
    let vers = unsafe { &mut *vers };

    vers.remaining -= 1;
    // SAFETY: The iterator points into arrays prepared by `modversion_ext_start`.
    vers.crc = unsafe { vers.crc.add(1) };
    // SAFETY: `name` points at a NUL-terminated name within the extended name table.
    vers.name = unsafe { vers.name.add(c_strlen(vers.name) + 1) };
}
