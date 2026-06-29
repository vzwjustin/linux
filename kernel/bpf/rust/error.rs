// SPDX-License-Identifier: GPL-2.0
//! Kernel error code handling for BPF map Rust implementations.
//!
//! This module maps kernel errno values to Rust `Result` types at the FFI
//! boundary. The [`Error`] type wraps a [`NonZeroI32`] holding negative errno
//! values, enabling zero-cost conversion between C error conventions and
//! idiomatic Rust error handling.
//!
//! # Design
//!
//! - Negative integers from C become `Result::Err(Error)`.
//! - Zero and positive integers indicate success.
//! - Unknown/unmapped negative codes are passed through unchanged.
//! - The `Result` type alias defaults to `()` for operations returning only
//!   success/failure status.

// Allow `new_unchecked` in const context — clippy suggests `new().unwrap()` but
// `unwrap` is denied crate-wide via `clippy::unwrap_used` for panic safety.
#![allow(clippy::useless_nonzero_new_unchecked)]

use core::num::NonZeroI32;

/// Kernel error code wrapper. Stores negative errno values.
///
/// The inner value is always a negative `NonZeroI32`, matching the kernel
/// convention where negative return values indicate errors.
///
/// # Examples
///
/// ```ignore
/// use error::Error;
///
/// let e = Error::ENOMEM;
/// assert_eq!(e.to_errno(), -12);
///
/// let e2 = Error::from_errno(-22);
/// assert_eq!(e2, Some(Error::EINVAL));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(NonZeroI32);

impl Error {
    /// Out of memory (`-ENOMEM`, errno 12).
    pub const ENOMEM: Self = Self(
        // SAFETY: -12 is non-zero.
        unsafe { NonZeroI32::new_unchecked(-12) },
    );

    /// Invalid argument (`-EINVAL`, errno 22).
    pub const EINVAL: Self = Self(
        // SAFETY: -22 is non-zero.
        unsafe { NonZeroI32::new_unchecked(-22) },
    );

    /// No such entry (`-ENOENT`, errno 2).
    pub const ENOENT: Self = Self(
        // SAFETY: -2 is non-zero.
        unsafe { NonZeroI32::new_unchecked(-2) },
    );

    /// Argument list too long (`-E2BIG`, errno 7).
    pub const E2BIG: Self = Self(
        // SAFETY: -7 is non-zero.
        unsafe { NonZeroI32::new_unchecked(-7) },
    );

    /// Operation not supported (`-EOPNOTSUPP`, errno 95).
    pub const EOPNOTSUPP: Self = Self(
        // SAFETY: -95 is non-zero.
        unsafe { NonZeroI32::new_unchecked(-95) },
    );

    /// Entry already exists (`-EEXIST`, errno 17).
    pub const EEXIST: Self = Self(
        // SAFETY: -17 is non-zero.
        unsafe { NonZeroI32::new_unchecked(-17) },
    );

    /// Device or resource busy (`-EBUSY`, errno 16).
    pub const EBUSY: Self = Self(
        // SAFETY: -16 is non-zero.
        unsafe { NonZeroI32::new_unchecked(-16) },
    );

    /// No space left on device / structure full (`-ENOSPC`, errno 28).
    pub const ENOSPC: Self = Self(
        // SAFETY: -28 is non-zero.
        unsafe { NonZeroI32::new_unchecked(-28) },
    );

    /// Create an [`Error`] from a raw negative errno code.
    ///
    /// Returns `None` if `code` is zero or positive, since those indicate
    /// success in the kernel convention.
    ///
    /// # Arguments
    ///
    /// * `code` - A raw kernel return code. Must be negative to produce `Some`.
    pub fn from_errno(code: i32) -> Option<Self> {
        NonZeroI32::new(code)
            .filter(|v| v.get() < 0)
            .map(Self)
    }

    /// Convert this error back to the raw kernel error code (negative integer).
    ///
    /// This is the inverse of [`from_errno`](Self::from_errno) for valid error
    /// codes and is used at the FFI boundary when returning errors to C callers.
    pub fn to_errno(self) -> i32 {
        self.0.get()
    }

    /// Interpret a raw kernel return code as a `Result`.
    ///
    /// - If `code` is negative, returns `Err(Error)` wrapping the code
    ///   unchanged (including unknown/unmapped error codes).
    /// - If `code` is zero or positive, returns `Ok(())`.
    ///
    /// # Safety note
    ///
    /// The inner `NonZeroI32::new_unchecked` is safe here because we guard
    /// against zero with the `code < 0` check.
    pub fn from_raw(code: i32) -> Result<()> {
        if code < 0 {
            // SAFETY: `code < 0` guarantees it is non-zero.
            Err(Self(unsafe { NonZeroI32::new_unchecked(code) }))
        } else {
            Ok(())
        }
    }
}

/// A specialized `Result` type for kernel operations.
///
/// Defaults to `()` as the success type, matching the common kernel pattern
/// where functions return 0 on success and a negative errno on failure.
pub type Result<T = ()> = core::result::Result<T, Error>;

/// The upper bound (inclusive) of the ERR_PTR range. In the Linux kernel,
/// error pointers encode negative errno values in the pointer itself, using
/// the range `[-MAX_ERRNO, -1]` where `MAX_ERRNO` is 4095.
const MAX_ERRNO: isize = 4095;

/// Check if a pointer is an ERR_PTR and convert to `Result`.
///
/// In the Linux kernel, C functions sometimes encode error codes inside
/// pointer values. A pointer whose numeric value falls in the range
/// `[-4095, -1]` (inclusive) is an error pointer. This function detects
/// that case and extracts the errno into a `Result::Err`.
///
/// # Safety
///
/// The caller must ensure that `ptr` was returned by a C kernel function
/// that follows the ERR_PTR convention. If the pointer is not an error
/// pointer, it must be valid for its intended use (though this function
/// does not dereference it).
///
/// # Examples
///
/// ```ignore
/// use error::{from_err_ptr, Error};
///
/// // Simulating an ERR_PTR(-ENOMEM) from C
/// let err_ptr = -12isize as *mut u8;
/// let result = unsafe { from_err_ptr(err_ptr) };
/// assert_eq!(result, Err(Error::ENOMEM));
///
/// // A valid (non-error) pointer passes through
/// let valid_ptr = 0x1000usize as *mut u8;
/// let result = unsafe { from_err_ptr(valid_ptr) };
/// assert_eq!(result, Ok(valid_ptr));
/// ```
pub unsafe fn from_err_ptr<T>(ptr: *mut T) -> Result<*mut T> {
    let code = ptr as isize;
    if (-MAX_ERRNO..0).contains(&code) {
        // SAFETY: `code` is in [-4095, -1], so it is non-zero. The caller
        // guarantees the pointer came from a C function using ERR_PTR
        // convention, so interpreting this range as a negative errno is
        // correct.
        Err(Error(NonZeroI32::new_unchecked(code as i32)))
    } else {
        Ok(ptr)
    }
}

/// Check a pointer for NULL and convert to `Result`.
///
/// Many C kernel functions return NULL to indicate failure (often meaning
/// "out of memory" or "not found"). This helper rejects NULL pointers at
/// the FFI boundary, converting them to `Err(Error::EINVAL)` so that safe
/// Rust code never receives a null pointer where a valid reference is
/// expected.
///
/// # Safety
///
/// The caller must ensure that if the pointer is non-null, it is valid for
/// its intended use. This function only checks for the null case; it does
/// not dereference the pointer.
///
/// # Examples
///
/// ```ignore
/// use error::{non_null, Error};
///
/// let null_ptr: *mut u8 = core::ptr::null_mut();
/// let result = unsafe { non_null(null_ptr) };
/// assert_eq!(result, Err(Error::EINVAL));
///
/// let valid_ptr = 0x1000usize as *mut u8;
/// let result = unsafe { non_null(valid_ptr) };
/// assert_eq!(result, Ok(valid_ptr));
/// ```
pub unsafe fn non_null<T>(ptr: *mut T) -> Result<*mut T> {
    if ptr.is_null() {
        Err(Error::EINVAL)
    } else {
        Ok(ptr)
    }
}
