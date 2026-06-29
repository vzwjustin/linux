// SPDX-License-Identifier: GPL-2.0
//! BPF map area memory allocator wrapper.
//!
//! This module provides a safe Rust interface over the kernel's
//! `bpf_map_area_alloc` and `bpf_map_area_free` functions, which handle
//! large memory allocations for BPF map data structures. The kernel
//! implementation automatically selects between `kmalloc` and `vmalloc`
//! depending on the requested size.
//!
//! # Usage
//!
//! ```ignore
//! use crate::abstractions::bpf_mem::BpfMapArea;
//!
//! let ptr = BpfMapArea::alloc(4096, bindings::NUMA_NO_NODE)?;
//! // ... use ptr ...
//! unsafe { BpfMapArea::free(ptr); }
//! ```

use crate::bindings;
use crate::error::{Error, Result};

/// Wrapper around `bpf_map_area_alloc` / `bpf_map_area_free` for BPF map
/// memory allocations.
///
/// BPF maps often require large contiguous allocations that may exceed what
/// `kmalloc` can satisfy. The kernel's `bpf_map_area_alloc` transparently
/// falls back to `vmalloc` for large sizes, making it the preferred allocator
/// for map backing storage.
///
/// This wrapper converts NULL returns into `Err(Error::ENOMEM)`, ensuring
/// that callers never receive a null pointer and allocation failures are
/// handled through the standard `Result` error path.
pub struct BpfMapArea;

impl BpfMapArea {
    /// Allocate memory for a BPF map area.
    ///
    /// Calls the kernel's `bpf_map_area_alloc`, which uses `kmalloc` for
    /// small allocations and falls back to `vmalloc` for larger ones.
    ///
    /// # Arguments
    ///
    /// * `size` - The number of bytes to allocate. Must be greater than zero.
    /// * `numa_node` - The NUMA node to allocate on, or `NUMA_NO_NODE` (-1)
    ///   for any node.
    ///
    /// # Returns
    ///
    /// A non-null pointer to the allocated memory on success, or
    /// `Err(Error::ENOMEM)` if the allocation fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::abstractions::bpf_mem::BpfMapArea;
    /// use crate::bindings::NUMA_NO_NODE;
    ///
    /// let ptr = BpfMapArea::alloc(4096, NUMA_NO_NODE)?;
    /// assert!(!ptr.is_null());
    /// unsafe { BpfMapArea::free(ptr); }
    /// ```
    pub fn alloc(size: u64, numa_node: i32) -> Result<*mut u8> {
        // SAFETY: `bpf_map_area_alloc` is always safe to call with any size
        // and numa_node values. It returns NULL on failure, which we handle
        // below by converting to Err(ENOMEM).
        let ptr = unsafe { bindings::bpf_map_area_alloc(size, numa_node) };
        if ptr.is_null() {
            Err(Error::ENOMEM)
        } else {
            Ok(ptr as *mut u8)
        }
    }

    /// Free memory previously allocated by [`BpfMapArea::alloc`].
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    ///
    /// 1. `ptr` was returned by a previous successful call to
    ///    [`BpfMapArea::alloc`].
    /// 2. `ptr` has not already been freed (no double-free).
    /// 3. No references to the allocated memory are used after this call
    ///    (no use-after-free).
    ///
    /// Violating any of these preconditions results in undefined behavior
    /// (memory corruption or kernel crash).
    pub unsafe fn free(ptr: *mut u8) {
        // SAFETY: The caller guarantees that `ptr` was allocated by
        // `bpf_map_area_alloc` and has not been freed yet.
        bindings::bpf_map_area_free(ptr as *mut core::ffi::c_void);
    }
}
