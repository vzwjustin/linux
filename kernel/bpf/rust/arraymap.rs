// SPDX-License-Identifier: GPL-2.0
//! BPF Array Map implementation.
//!
//! This module implements the core BPF array map data structure in Rust,
//! providing `lookup_elem`, `update_elem`, and `delete_elem` operations
//! that match the semantics of the C implementation in `kernel/bpf/arraymap.c`.
//!
//! An array map is a fixed-size, pre-allocated array indexed by a `u32` key.
//! All elements exist from map creation (zero-initialized), so:
//! - Lookup returns a pointer to the value slot (or null if index is out of bounds).
//! - Update copies a new value into the slot (bounds-checked).
//! - Delete is not supported and returns `-EINVAL`.
//!
//! # Safety
//!
//! The `BpfArray` struct uses `#[repr(C)]` to match the kernel's memory layout.
//! The `map` field must be first (for `container_of` compatibility). All pointer
//! arithmetic uses bounds-checked indices before computing offsets.

use core::ffi::c_void;
use core::ptr;

use crate::abstractions::bpf_mem::BpfMapArea;
use crate::bindings;
use crate::error::{Error, Result};

/// BPF Array map structure.
///
/// This struct is the Rust equivalent of `struct bpf_array` from the C
/// implementation. The `#[repr(C)]` attribute ensures field layout matches
/// what the kernel expects for `container_of` usage.
///
/// # Layout
///
/// - `map` must be the first field so that a pointer to `BpfArray` can be
///   cast to/from a pointer to `bpf_map` (the `container_of` pattern).
/// - `elem_size` is the rounded-up value size (aligned to 8 bytes).
/// - `index_mask` is `max_entries - 1` for power-of-2 sizes (Spectre v1
///   mitigation), or `u32::MAX` if not a power of 2.
/// - `value` points to the contiguous backing array of element storage.
#[repr(C)]
pub struct BpfArray {
    /// Embedded BPF map common fields. Must be first for `container_of`.
    pub map: bindings::bpf_map,
    /// Size of each element in bytes (value_size rounded up to 8-byte alignment).
    pub elem_size: u32,
    /// Bitmask for index (power-of-2 optimization for Spectre v1 mitigation).
    /// For power-of-2 max_entries: `max_entries - 1`.
    /// For non-power-of-2: `u32::MAX` (no masking effect).
    pub index_mask: u32,
    /// Pointer to the contiguous value array backing storage.
    /// Total size is `elem_size * max_entries` bytes.
    pub value: *mut u8,
}

// SAFETY: BpfArray is shared across CPUs in the kernel. Access to the value
// array is synchronized by RCU (readers) or the map-level lock (writers).
// The struct itself is allocated and owned by C code; Rust only receives
// pointers to it.
unsafe impl Send for BpfArray {}
unsafe impl Sync for BpfArray {}

impl BpfArray {
    /// Obtain a `&BpfArray` reference from a `*const bpf_map` pointer.
    ///
    /// This implements the `container_of` pattern: given a pointer to the
    /// `map` field (which is at offset 0), we cast it to the containing
    /// `BpfArray` struct.
    ///
    /// # Safety
    ///
    /// - `map_ptr` must be non-null and point to a valid `bpf_map` that is
    ///   the `map` field of a live `BpfArray` allocation.
    /// - The caller must ensure the `BpfArray` remains valid for the lifetime
    ///   of the returned reference.
    #[inline]
    pub unsafe fn from_map_ptr<'a>(map_ptr: *const bindings::bpf_map) -> &'a Self {
        // SAFETY: `map` is at offset 0 in BpfArray (#[repr(C)] and first field),
        // so casting a *const bpf_map to *const BpfArray is valid when the
        // pointer actually points to the map field of a BpfArray.
        &*(map_ptr as *const Self)
    }

    /// Compute a pointer to the element at the given index.
    ///
    /// Applies the `index_mask` for Spectre v1 mitigation before computing
    /// the byte offset into the value array.
    ///
    /// # Safety
    ///
    /// - The caller must have already verified that `index < max_entries`.
    /// - `self.value` must point to a valid allocation of at least
    ///   `elem_size * max_entries` bytes.
    #[inline]
    unsafe fn elem_ptr(&self, index: u32) -> *mut u8 {
        let masked_index = index & self.index_mask;
        // SAFETY: masked_index <= index < max_entries (caller-verified),
        // and the value array is allocated with elem_size * max_entries bytes.
        // The cast to u64 prevents overflow in the multiplication.
        self.value.add((self.elem_size as u64 * masked_index as u64) as usize)
    }
}

/// Look up an element in the array map by index.
///
/// Reads a `u32` index from the key pointer, bounds-checks it against
/// `max_entries`, and returns a pointer to the corresponding value slot.
///
/// # Arguments
///
/// * `map` - Pointer to the `bpf_map` embedded in a `BpfArray`.
/// * `key` - Pointer to a `u32` containing the array index.
///
/// # Returns
///
/// - `*mut c_void` pointing to the value slot on success.
/// - `ptr::null_mut()` if the index is out of bounds.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is part of a `BpfArray`.
/// - `key` must be a valid pointer to at least 4 bytes (a `u32`).
/// - The returned pointer (if non-null) is valid for reads of `map.value_size`
///   bytes. The caller is responsible for not exceeding this bound.
pub unsafe fn array_map_lookup_elem(
    map: *const bindings::bpf_map,
    key: *const c_void,
) -> *mut c_void {
    // SAFETY: Caller guarantees map points to a valid BpfArray.
    let array = BpfArray::from_map_ptr(map);

    // SAFETY: Caller guarantees key points to at least 4 readable bytes.
    let index = ptr::read_unaligned(key as *const u32);

    if index >= (*map).max_entries {
        return ptr::null_mut();
    }

    // SAFETY: index < max_entries verified above; elem_ptr is valid.
    array.elem_ptr(index) as *mut c_void
}

/// Update an element in the array map.
///
/// Reads a `u32` index from the key pointer, bounds-checks it, validates
/// the flags, and copies the provided value into the corresponding slot.
///
/// # Arguments
///
/// * `map` - Pointer to the `bpf_map` embedded in a `BpfArray`.
/// * `key` - Pointer to a `u32` containing the array index.
/// * `value` - Pointer to the new value data to copy into the slot.
/// * `map_flags` - BPF update flags (`BPF_ANY`, `BPF_EXIST`, `BPF_NOEXIST`).
///
/// # Returns
///
/// - `Ok(())` on success.
/// - `Err(EINVAL)` if unknown flags are provided.
/// - `Err(E2BIG)` if the index is out of bounds.
/// - `Err(EEXIST)` if `BPF_NOEXIST` is specified (all array slots always exist).
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is part of a `BpfArray`.
/// - `key` must be a valid pointer to at least 4 bytes (a `u32`).
/// - `value` must be a valid pointer to at least `map.value_size` readable bytes.
pub unsafe fn array_map_update_elem(
    map: *const bindings::bpf_map,
    key: *const c_void,
    value: *const c_void,
    map_flags: u64,
) -> Result {
    // SAFETY: Caller guarantees map points to a valid BpfArray.
    let array = BpfArray::from_map_ptr(map);

    // Validate flags: only BPF_ANY (0), BPF_NOEXIST (1), BPF_EXIST (2) are valid.
    // The BPF_F_LOCK flag is handled separately in the kernel; for our core
    // implementation we reject anything above BPF_EXIST (masking out BPF_F_LOCK).
    if (map_flags & !0x4) > bindings::BPF_EXIST {
        return Err(Error::EINVAL);
    }

    // SAFETY: Caller guarantees key points to at least 4 readable bytes.
    let index = ptr::read_unaligned(key as *const u32);

    // All elements are pre-allocated; out-of-bounds means "cannot insert".
    if index >= (*map).max_entries {
        return Err(Error::E2BIG);
    }

    // BPF_NOEXIST means "insert only if not present", but array slots always
    // exist from creation, so this always fails.
    if map_flags & bindings::BPF_NOEXIST != 0 {
        return Err(Error::EEXIST);
    }

    // SAFETY: index < max_entries verified above; elem_ptr is valid.
    let dst = array.elem_ptr(index);

    // SAFETY: value points to at least value_size readable bytes (caller
    // contract). dst points to elem_size bytes of writable storage. We copy
    // value_size bytes which is <= elem_size.
    ptr::copy_nonoverlapping(
        value as *const u8,
        dst,
        (*map).value_size as usize,
    );

    Ok(())
}

/// Delete an element from the array map.
///
/// For BPF array maps, deletion is not supported. The kernel semantics
/// dictate that `array_map_delete_elem` always returns `-EINVAL` because
/// all elements are pre-allocated and cannot be removed.
///
/// # Arguments
///
/// * `_map` - Pointer to the `bpf_map` (unused).
/// * `_key` - Pointer to the key (unused).
///
/// # Returns
///
/// Always returns `Err(EINVAL)`.
///
/// # Safety
///
/// This function does not dereference any pointers, so it is safe to call
/// with any pointer values (including null), though callers should still
/// provide valid pointers per the general BPF map contract.
pub unsafe fn array_map_delete_elem(
    _map: *const bindings::bpf_map,
    _key: *const c_void,
) -> Result {
    Err(Error::EINVAL)
}

/// Allocate and initialize a BPF array map.
///
/// Reads map attributes from `attr`, validates them, allocates the `BpfArray`
/// struct and the contiguous value array, zero-initializes the value array,
/// and returns a pointer to the embedded `bpf_map` field on success.
///
/// # Algorithm
///
/// 1. Read `value_size`, `max_entries`, and `map_flags` from `attr`.
/// 2. Validate that `value_size > 0` and `max_entries > 0`.
/// 3. Compute `elem_size` by rounding `value_size` up to 8-byte alignment.
/// 4. Compute `index_mask`: if `max_entries` is a power of 2, use
///    `max_entries - 1`; otherwise use `u32::MAX` (no masking effect).
/// 5. Allocate the `BpfArray` struct via `BpfMapArea::alloc`.
/// 6. Allocate the value array (`elem_size * max_entries` bytes) via
///    `BpfMapArea::alloc`.
/// 7. Zero-initialize the value array.
/// 8. Return a pointer to the `map` field of the allocated `BpfArray`.
///
/// # Safety
///
/// - `attr` must be a valid pointer to a `bpf_attr` populated for a
///   `BPF_MAP_CREATE` command.
/// - The caller is responsible for eventually calling [`array_map_free`]
///   on the returned map pointer.
///
/// # Errors
///
/// Returns `Err(EINVAL)` if `value_size` or `max_entries` is zero.
/// Returns `Err(ENOMEM)` if memory allocation fails.
pub unsafe fn array_map_alloc(
    attr: *const bindings::bpf_attr,
) -> Result<*mut bindings::bpf_map> {
    let attr_ref = &*attr;

    // Read attributes from the bpf_attr union.
    let value_size = attr_ref.value_size();
    let max_entries = attr_ref.max_entries();
    let _map_flags = attr_ref.map_flags();

    // Validate: value_size and max_entries must be non-zero.
    if value_size == 0 || max_entries == 0 {
        return Err(Error::EINVAL);
    }

    // Compute elem_size: round value_size up to 8-byte alignment.
    let elem_size = (value_size + 7) & !7;

    // Compute index_mask: if max_entries is a power of 2, use max_entries - 1
    // for Spectre v1 mitigation. Otherwise, use u32::MAX (no masking effect).
    let index_mask = if max_entries.is_power_of_two() {
        max_entries - 1
    } else {
        u32::MAX
    };

    // Allocate the BpfArray struct.
    let array_size = core::mem::size_of::<BpfArray>() as u64;
    let array_ptr = BpfMapArea::alloc(array_size, bindings::NUMA_NO_NODE)?;
    // Safety (cast_ptr_alignment): BpfMapArea::alloc delegates to kmalloc/vmalloc
    // which return memory aligned to at least max_align_t (>= 8 bytes), satisfying
    // the alignment requirement of BpfArray.
    #[allow(clippy::cast_ptr_alignment)]
    let array = array_ptr as *mut BpfArray;

    // Zero-initialize the BpfArray struct.
    // Safety: array_ptr points to a freshly allocated region of array_size bytes.
    ptr::write_bytes(array_ptr, 0, array_size as usize);

    // Allocate the value array: elem_size * max_entries bytes.
    let value_array_size = elem_size as u64 * max_entries as u64;
    let value_ptr = match BpfMapArea::alloc(value_array_size, bindings::NUMA_NO_NODE) {
        Ok(p) => p,
        Err(e) => {
            // Free the already-allocated BpfArray struct before returning.
            // Safety: array_ptr was allocated by BpfMapArea::alloc above.
            BpfMapArea::free(array_ptr);
            return Err(e);
        }
    };

    // Zero-initialize the value array.
    // Safety: value_ptr points to a freshly allocated region of value_array_size bytes.
    ptr::write_bytes(value_ptr, 0, value_array_size as usize);

    // Initialize the BpfArray fields.
    // Safety: array points to a valid, zero-initialized BpfArray allocation.
    (*array).elem_size = elem_size;
    (*array).index_mask = index_mask;
    (*array).value = value_ptr;

    // Initialize common map fields from the user-provided attributes.
    // Safety: &mut (*array).map is a valid bpf_map, attr is valid.
    bindings::bpf_map_init_from_attr(&mut (*array).map, attr);

    // Return pointer to the embedded bpf_map (first field of BpfArray).
    Ok(&mut (*array).map as *mut bindings::bpf_map)
}

/// Free a BPF array map and all its associated memory.
///
/// Deallocates the value array first, then the `BpfArray` struct itself.
/// This matches the kernel's `array_map_free` behavior for the non-percpu,
/// non-mmapable case.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that was previously returned
///   by [`array_map_alloc`].
/// - The map must not be accessed after this call (use-after-free).
/// - This function must be called exactly once per allocation (no double-free).
pub unsafe fn array_map_free(map: *mut bindings::bpf_map) {
    let array = map as *mut BpfArray;

    // Free the value array first.
    // Safety: (*array).value was allocated by BpfMapArea::alloc in array_map_alloc.
    // It has not been freed yet (single ownership, called once).
    let value_ptr = (*array).value;
    if !value_ptr.is_null() {
        BpfMapArea::free(value_ptr);
    }

    // Free the BpfArray struct itself.
    // Safety: array was allocated by BpfMapArea::alloc in array_map_alloc.
    BpfMapArea::free(array as *mut u8);
}

/// Get the next key for iterating over the array map.
///
/// Implements sequential iteration over array indices `[0, max_entries)`.
///
/// # Behavior
///
/// - If `key` is null, writes `0` into `next_key` (start of iteration).
/// - If the current index (read from `key`) is `>= max_entries`, writes `0`
///   into `next_key` (restart iteration from the beginning, matching C behavior).
/// - If the current index is `max_entries - 1` (last element), returns
///   `Err(ENOENT)` indicating iteration is complete.
/// - Otherwise, writes `index + 1` into `next_key`.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is part of a `BpfArray`.
/// - If `key` is non-null, it must point to at least 4 readable bytes (a `u32`).
/// - `next_key` must point to at least 4 writable bytes (a `u32`).
pub unsafe fn array_map_get_next_key(
    map: *const bindings::bpf_map,
    key: *const c_void,
    next_key: *mut c_void,
) -> Result {
    let next = next_key as *mut u32;

    // If key is null or index >= max_entries, return the first key (0).
    let index = if key.is_null() {
        u32::MAX
    } else {
        // Safety: Caller guarantees key points to at least 4 readable bytes.
        ptr::read_unaligned(key as *const u32)
    };

    if index >= (*map).max_entries {
        // Safety: next_key points to at least 4 writable bytes (caller contract).
        ptr::write_unaligned(next, 0);
        return Ok(());
    }

    // If this is the last entry, iteration is complete.
    if index == (*map).max_entries - 1 {
        return Err(Error::ENOENT);
    }

    // Write the next sequential index.
    // Safety: next_key points to at least 4 writable bytes (caller contract).
    ptr::write_unaligned(next, index + 1);
    Ok(())
}
