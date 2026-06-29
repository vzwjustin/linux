// SPDX-License-Identifier: GPL-2.0
//! Kernel memory allocator wrapper for BPF map Rust implementations.
//!
//! This module provides a safe interface to the kernel's `__kmalloc` and `kfree`
//! functions, returning `Result` types instead of panicking on allocation
//! failure. It implements the [`GlobalAlloc`] trait for integration with Rust's
//! allocator infrastructure and exposes a [`try_alloc`](KernelAllocator::try_alloc)
//! method for fallible allocation.
//!
//! # Design
//!
//! - Zero-size allocations return null without calling `kmalloc`, matching kernel
//!   convention and avoiding undefined behavior.
//! - Allocation failure returns `Err(Error::ENOMEM)` rather than panicking.
//! - Deallocation delegates directly to `kfree`.
//! - The default `GlobalAlloc::alloc` uses `GFP_KERNEL` flags.

use core::alloc::{GlobalAlloc, Layout};

use crate::bindings;
use crate::error::{Error, Result};

/// Kernel memory allocator that returns errors instead of panicking.
///
/// This struct wraps the kernel's `__kmalloc` and `kfree` functions, providing
/// both a [`GlobalAlloc`] implementation and a fallible [`try_alloc`](Self::try_alloc)
/// method suitable for kernel code where allocation failure must be handled
/// gracefully.
///
/// # Safety Contract
///
/// - Preconditions: `Layout` must have non-zero size for actual allocations.
///   Zero-size layouts are handled by returning null without calling `kmalloc`.
/// - Postconditions on success: returned pointer is non-null, properly aligned
///   for the requested layout, and backed by at least `layout.size()` bytes.
/// - Undefined behavior: calling `dealloc` with a pointer not obtained from
///   this allocator, or calling `dealloc` more than once for the same pointer.
pub struct KernelAllocator;

impl KernelAllocator {
    /// Allocate memory with explicit GFP flags.
    ///
    /// Returns a raw pointer to the allocated memory, or null on failure.
    /// Zero-size allocations return null without invoking `kmalloc`.
    ///
    /// # Arguments
    ///
    /// * `layout` - The memory layout (size and alignment) to allocate.
    /// * `flags` - GFP allocation flags (e.g., `GFP_KERNEL`, `GFP_ATOMIC`).
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `flags` is a valid GFP flag combination for the current execution
    ///   context (e.g., `GFP_ATOMIC` in interrupt context, `GFP_KERNEL` in
    ///   process context).
    pub fn alloc_with_flags(layout: Layout, flags: u32) -> *mut u8 {
        if layout.size() == 0 {
            return core::ptr::null_mut();
        }
        // SAFETY: `layout.size()` is non-zero (checked above). `flags` is
        // required by the caller contract to be a valid GFP combination.
        // `__kmalloc` returns either a valid pointer or null on failure.
        unsafe { bindings::__kmalloc(layout.size(), flags) as *mut u8 }
    }

    /// Try to allocate memory, returning `Result` instead of panicking.
    ///
    /// This is the preferred allocation method in kernel code where allocation
    /// failure must be propagated as an error rather than causing a panic.
    ///
    /// # Arguments
    ///
    /// * `layout` - The memory layout (size and alignment) to allocate.
    /// * `flags` - GFP allocation flags (e.g., `GFP_KERNEL`, `GFP_ATOMIC`).
    ///
    /// # Errors
    ///
    /// Returns `Err(Error::ENOMEM)` if:
    /// - The kernel allocator cannot satisfy the request, or
    /// - The requested size is zero (zero-size allocations are not valid
    ///   allocations and return ENOMEM to signal that no usable memory was
    ///   provided).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use abstractions::alloc::KernelAllocator;
    /// use core::alloc::Layout;
    ///
    /// let layout = Layout::from_size_align(64, 8).unwrap();
    /// let ptr = KernelAllocator::try_alloc(layout, bindings::GFP_KERNEL)?;
    /// // ptr is guaranteed non-null here
    /// ```
    pub fn try_alloc(layout: Layout, flags: u32) -> Result<*mut u8> {
        let ptr = Self::alloc_with_flags(layout, flags);
        if ptr.is_null() {
            Err(Error::ENOMEM)
        } else {
            Ok(ptr)
        }
    }
}

// SAFETY: `KernelAllocator` delegates to `__kmalloc` and `kfree`, which are
// thread-safe kernel allocator primitives. The kernel guarantees that these
// functions can be called from any context where the provided GFP flags are
// appropriate. `GlobalAlloc` requires that `alloc` returns a valid pointer or
// null, and `dealloc` frees memory previously allocated by `alloc` — both
// contracts are upheld by `__kmalloc`/`kfree`.
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::alloc_with_flags(layout, bindings::GFP_KERNEL)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: The caller guarantees that `ptr` was previously allocated by
        // this allocator (via `alloc` or `alloc_with_flags`), and that it has
        // not been deallocated before. `kfree` accepts any pointer returned by
        // `__kmalloc` and handles null gracefully (no-op).
        bindings::kfree(ptr as *const core::ffi::c_void);
    }
}
