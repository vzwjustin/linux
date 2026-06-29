// SPDX-License-Identifier: GPL-2.0

//! Static call fallback helpers.

#[no_mangle]
/// Returns zero for static call sites that use the return-zero fallback.
pub extern "C" fn __static_call_return0() -> isize {
    0
}
