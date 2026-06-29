// SPDX-License-Identifier: GPL-2.0+
// Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.

//! Module signature format checks.

use core::ffi::c_int;

use kernel::{
    bindings, pr_err,
    str::{CStr, CStrExt},
};

const MODULE_SIGNATURE_TYPE_PKCS7: u8 = 2;
const __LOG_PREFIX: &[u8] = b"module_signature\0";

#[repr(C)]
/// Trailer describing an appended module signature.
pub struct ModuleSignature {
    algo: u8,
    hash: u8,
    id_type: u8,
    signer_len: u8,
    key_id_len: u8,
    __pad: [u8; 3],
    sig_len: u32,
}

const _: () = assert!(core::mem::size_of::<ModuleSignature>() == 12);

#[inline]
fn be32_to_cpu(value: u32) -> usize {
    u32::from_be(value) as usize
}

#[no_mangle]
/// Checks whether an appended module signature trailer uses the supported format.
///
/// # Safety
///
/// `ms` must point to a valid module signature trailer, and `name` must point
/// to a valid NUL-terminated string.
pub unsafe extern "C" fn mod_check_sig(
    ms: *const ModuleSignature,
    file_len: usize,
    name: *const u8,
) -> c_int {
    // SAFETY: This preserves the C ABI contract: callers must pass a valid
    // pointer to a `struct module_signature`.
    let ms = unsafe { &*ms };

    if be32_to_cpu(ms.sig_len) >= file_len.wrapping_sub(core::mem::size_of::<ModuleSignature>()) {
        return -(bindings::EBADMSG as c_int);
    }

    if ms.id_type != MODULE_SIGNATURE_TYPE_PKCS7 {
        // SAFETY: This preserves the old `%s` contract from the C
        // implementation: callers pass a valid NUL-terminated name.
        let name = unsafe { CStr::from_char_ptr(name) };
        pr_err!("{name}: not signed with expected PKCS#7 message\n");
        return -(bindings::ENOPKG as c_int);
    }

    if ms.algo != 0
        || ms.hash != 0
        || ms.signer_len != 0
        || ms.key_id_len != 0
        || ms.__pad[0] != 0
        || ms.__pad[1] != 0
        || ms.__pad[2] != 0
    {
        // SAFETY: This preserves the old `%s` contract from the C
        // implementation: callers pass a valid NUL-terminated name.
        let name = unsafe { CStr::from_char_ptr(name) };
        pr_err!("{name}: PKCS#7 signature info has unexpected non-zero params\n");
        return -(bindings::EBADMSG as c_int);
    }

    0
}
