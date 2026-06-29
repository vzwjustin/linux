// SPDX-License-Identifier: GPL-2.0
//! Safe wrapper around kernel bitmap operations.
//!
//! This module provides a [`Bitmap`] type that wraps a raw pointer to an array
//! of `unsigned long` values (the kernel's native bitmap format). Operations
//! use atomic bit manipulation matching the kernel's `set_bit`, `test_bit`, and
//! `clear_bit` semantics.
//!
//! # Usage
//!
//! The [`Bitmap`] is used by the bloom filter and other BPF map types that
//! require bitset storage. The bitmap memory is allocated externally (typically
//! via `bpf_map_area_alloc`) and the [`Bitmap`] provides safe access to
//! individual bits with bounds checking.
//!
//! # Safety Model
//!
//! - In debug builds, out-of-bounds bit indices trigger a `debug_assert!` panic.
//! - In release builds, out-of-bounds access is prevented by an early return
//!   (no-op for set/clear, `false` for test). This avoids memory corruption
//!   while allowing detection via logging or monitoring.
//! - The underlying bit operations use atomic semantics (volatile reads/writes
//!   with appropriate ordering) to match the kernel's `set_bit`/`test_bit`
//!   behavior which is safe for concurrent access.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Number of bits in a `usize` (matches `unsigned long` on the target platform).
const BITS_PER_LONG: usize = usize::BITS as usize;

/// A bitmap wrapping a raw pointer to kernel-allocated bitmap memory.
///
/// The bitmap is stored as an array of `unsigned long` values (represented as
/// `usize` in Rust), matching the kernel's bitmap layout. Each element holds
/// `BITS_PER_LONG` bits.
///
/// # Invariants
///
/// - `ptr` points to a valid, aligned allocation of at least
///   `(nr_bits + BITS_PER_LONG - 1) / BITS_PER_LONG` elements of type `usize`.
/// - The memory at `ptr` remains valid for the lifetime of the `Bitmap`.
/// - The allocation is not freed while the `Bitmap` is in use.
pub struct Bitmap {
    /// Raw pointer to the bitmap memory (array of unsigned long).
    ptr: *mut usize,
    /// Total number of valid bits in the bitmap.
    nr_bits: usize,
}

// SAFETY: Bitmap uses atomic operations for all bit manipulation, making it
// safe to share across threads. The underlying memory is kernel-managed and
// guaranteed to outlive any concurrent access within the map's lifetime.
unsafe impl Send for Bitmap {}

// SAFETY: All bit operations (set_bit, test_bit, clear_bit) use atomic
// load/store with appropriate ordering, so concurrent access from multiple
// threads is safe without external synchronization.
unsafe impl Sync for Bitmap {}

impl Bitmap {
    /// Create a new `Bitmap` wrapping the given raw pointer and bit count.
    ///
    /// # Safety
    ///
    /// - `ptr` must point to a valid, aligned allocation of at least
    ///   `(nr_bits + BITS_PER_LONG - 1) / BITS_PER_LONG` elements of
    ///   `usize` (unsigned long).
    /// - The memory must remain valid for the lifetime of the returned `Bitmap`.
    /// - The caller is responsible for freeing the memory after the `Bitmap` is
    ///   no longer in use.
    #[inline]
    pub unsafe fn new(ptr: *mut usize, nr_bits: usize) -> Self {
        Self { ptr, nr_bits }
    }

    /// Returns the number of bits this bitmap can hold.
    #[inline]
    pub fn nr_bits(&self) -> usize {
        self.nr_bits
    }

    /// Returns the number of `usize` words backing this bitmap.
    #[inline]
    pub fn nr_longs(&self) -> usize {
        self.nr_bits.div_ceil(BITS_PER_LONG)
    }

    /// Atomically set the bit at `index`.
    ///
    /// Uses atomic OR to set the bit, matching kernel `set_bit()` semantics.
    ///
    /// # Bounds Checking
    ///
    /// - Debug builds: panics via `debug_assert!` if `index >= nr_bits`.
    /// - Release builds: returns early (no-op) if `index >= nr_bits`.
    #[inline]
    pub fn set_bit(&self, index: usize) {
        debug_assert!(
            index < self.nr_bits,
            "bitmap set_bit: index {} out of bounds (nr_bits = {})",
            index,
            self.nr_bits
        );

        if index >= self.nr_bits {
            return;
        }

        let word_index = index / BITS_PER_LONG;
        let bit_offset = index % BITS_PER_LONG;

        // SAFETY: We have verified index < nr_bits, which guarantees
        // word_index < nr_longs(). The pointer arithmetic stays within
        // the allocated bitmap memory. We use AtomicUsize to perform an
        // atomic OR, matching kernel set_bit() atomic semantics.
        unsafe {
            let word_ptr = self.ptr.add(word_index) as *const AtomicUsize;
            (*word_ptr).fetch_or(1 << bit_offset, Ordering::Relaxed);
        }
    }

    /// Atomically test whether the bit at `index` is set.
    ///
    /// Uses atomic load to read the bit, matching kernel `test_bit()` semantics.
    ///
    /// # Bounds Checking
    ///
    /// - Debug builds: panics via `debug_assert!` if `index >= nr_bits`.
    /// - Release builds: returns `false` if `index >= nr_bits`.
    #[inline]
    pub fn test_bit(&self, index: usize) -> bool {
        debug_assert!(
            index < self.nr_bits,
            "bitmap test_bit: index {} out of bounds (nr_bits = {})",
            index,
            self.nr_bits
        );

        if index >= self.nr_bits {
            return false;
        }

        let word_index = index / BITS_PER_LONG;
        let bit_offset = index % BITS_PER_LONG;

        // SAFETY: We have verified index < nr_bits, which guarantees
        // word_index < nr_longs(). The pointer arithmetic stays within
        // the allocated bitmap memory. We use AtomicUsize to perform an
        // atomic load, matching kernel test_bit() semantics.
        unsafe {
            let word_ptr = self.ptr.add(word_index) as *const AtomicUsize;
            let word = (*word_ptr).load(Ordering::Relaxed);
            (word & (1 << bit_offset)) != 0
        }
    }

    /// Atomically clear the bit at `index`.
    ///
    /// Uses atomic AND with complement to clear the bit, matching kernel
    /// `clear_bit()` semantics.
    ///
    /// # Bounds Checking
    ///
    /// - Debug builds: panics via `debug_assert!` if `index >= nr_bits`.
    /// - Release builds: returns early (no-op) if `index >= nr_bits`.
    #[inline]
    pub fn clear_bit(&self, index: usize) {
        debug_assert!(
            index < self.nr_bits,
            "bitmap clear_bit: index {} out of bounds (nr_bits = {})",
            index,
            self.nr_bits
        );

        if index >= self.nr_bits {
            return;
        }

        let word_index = index / BITS_PER_LONG;
        let bit_offset = index % BITS_PER_LONG;

        // SAFETY: We have verified index < nr_bits, which guarantees
        // word_index < nr_longs(). The pointer arithmetic stays within
        // the allocated bitmap memory. We use AtomicUsize to perform an
        // atomic AND with the complement, matching kernel clear_bit()
        // atomic semantics.
        unsafe {
            let word_ptr = self.ptr.add(word_index) as *const AtomicUsize;
            (*word_ptr).fetch_and(!(1 << bit_offset), Ordering::Relaxed);
        }
    }
}
