// SPDX-License-Identifier: GPL-2.0
//! BPF Bloom Filter map implementation.
//!
//! A probabilistic data structure that can test set membership with no false
//! negatives but possible false positives. Supports push (insert) and peek
//! (query) operations.
//!
//! This module implements the Rust equivalent of `kernel/bpf/bloom_filter.c`.
//! The bloom filter uses multiple hash functions (Jenkins hash) to set and
//! test bit positions in a power-of-two sized bitset.
//!
//! # Safety
//!
//! The [`BpfBloomFilter`] struct uses `#[repr(C)]` to maintain layout
//! compatibility with the C `struct bpf_bloom_filter`. The `map` field must
//! be the first field to support the `container_of` pattern used by the
//! kernel's BPF map dispatch.

use crate::abstractions::{Bitmap, BpfMapArea};
use crate::bindings;
use crate::error::{Error, Result};
use core::ffi::c_void;
use core::mem;
use core::ptr;

// ---------------------------------------------------------------------------
// Data Structure
// ---------------------------------------------------------------------------

/// BPF Bloom Filter map.
///
/// Layout matches the C `struct bpf_bloom_filter` for FFI compatibility.
/// The `map` field MUST be the first field to support the kernel's
/// `container_of` macro pattern, where a pointer to `bpf_map` is cast
/// back to the enclosing `BpfBloomFilter`.
///
/// The bitset is a flexible array member that follows the struct in the
/// same allocation. It is accessed via a [`Bitmap`] constructed from a
/// pointer to the trailing memory.
#[repr(C)]
pub struct BpfBloomFilter {
    /// Common BPF map fields. Must be first for container_of.
    pub map: bindings::bpf_map,
    /// Bitmask for the bitset (bitset_size - 1, since size is power of two).
    pub bitset_mask: u32,
    /// Seed for hash computation. Combined with hash index per iteration.
    pub hash_seed: u32,
    /// Number of hash functions to apply for each element.
    pub nr_hash_funcs: u32,
    // Flexible array member: `unsigned long bitset[]` follows in allocated
    // memory. Accessed via `bitset()` method using pointer arithmetic.
}

impl BpfBloomFilter {
    /// Obtain a [`Bitmap`] reference to the trailing bitset data.
    ///
    /// The bitset immediately follows the `BpfBloomFilter` struct in memory,
    /// with `(bitset_mask + 1)` valid bit positions.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `self` points to a valid allocation that
    /// includes sufficient trailing memory for the bitset. This is guaranteed
    /// when the struct was allocated by `bloom_map_alloc` (C side) which
    /// allocates `sizeof(BpfBloomFilter) + bitset_bytes`.
    #[inline]
    unsafe fn bitset(&self) -> Bitmap {
        // The bitset follows immediately after the struct in memory.
        let base = (self as *const Self).add(1) as *mut usize;
        let nr_bits = (self.bitset_mask as usize).wrapping_add(1);
        // SAFETY: Caller guarantees the allocation includes trailing bitset
        // memory of at least `nr_bits / 8` bytes (rounded up to usize
        // alignment). The pointer arithmetic stays within the allocation.
        Bitmap::new(base, nr_bits)
    }

    /// Compute the hash of `value` for the given hash iteration `index`.
    ///
    /// Uses jhash2 (word-aligned path) when value length is a multiple of 4,
    /// otherwise falls back to jhash (byte-level path). The hash seed is
    /// combined with the index to produce independent hash values.
    #[inline]
    fn hash(&self, value: &[u8], index: u32) -> u32 {
        let seed = self.hash_seed.wrapping_add(index);
        let h = if value.len().is_multiple_of(4) {
            jhash2(value, seed)
        } else {
            jhash(value, seed)
        };
        h & self.bitset_mask
    }
}

// ---------------------------------------------------------------------------
// Public API (called from FFI wrappers)
// ---------------------------------------------------------------------------

/// Check if a value might be in the bloom filter.
///
/// Tests all hash bit positions for the given value. Returns `Ok(())` if all
/// bits are set (value is probably in the set), or `Err(ENOENT)` if any bit
/// is unset (value is definitely not in the set).
///
/// # Safety
///
/// - `map` must point to a valid `bpf_map` that is the first field of a
///   `BpfBloomFilter` allocation (i.e., it was created by `bloom_map_alloc`).
/// - `value` must point to a readable buffer of at least `map.value_size` bytes.
pub unsafe fn peek_elem(map: &bindings::bpf_map, value: *const c_void) -> Result {
    // SAFETY: The kernel guarantees `map` is the `map` field of a
    // `BpfBloomFilter` allocated by `bloom_map_alloc`. Using container_of
    // pattern: the map field is at offset 0, so the cast is valid.
    let bloom = &*(map as *const bindings::bpf_map as *const BpfBloomFilter);

    // SAFETY: Caller guarantees `value` points to `map.value_size` readable bytes.
    let value_slice = core::slice::from_raw_parts(value as *const u8, map.value_size as usize);

    let bitset = bloom.bitset();

    let mut i = 0u32;
    while i < bloom.nr_hash_funcs {
        let h = bloom.hash(value_slice, i);
        if !bitset.test_bit(h as usize) {
            return Err(Error::ENOENT);
        }
        i = i.wrapping_add(1);
    }
    Ok(())
}

/// Insert a value into the bloom filter by setting all hash bit positions.
///
/// # Arguments
///
/// - `map`: Reference to the BPF map (must be a bloom filter).
/// - `value`: Pointer to the value data to insert.
/// - `flags`: Update flags. Must be `BPF_ANY` (0); any other value returns `EINVAL`.
///
/// # Safety
///
/// - `map` must point to a valid `bpf_map` that is the first field of a
///   `BpfBloomFilter` allocation (i.e., it was created by `bloom_map_alloc`).
/// - `value` must point to a readable buffer of at least `map.value_size` bytes.
pub unsafe fn push_elem(map: &bindings::bpf_map, value: *const c_void, flags: u64) -> Result {
    if flags != bindings::BPF_ANY {
        return Err(Error::EINVAL);
    }

    // SAFETY: Same container_of reasoning as peek_elem.
    let bloom = &*(map as *const bindings::bpf_map as *const BpfBloomFilter);

    // SAFETY: Caller guarantees `value` points to `map.value_size` readable bytes.
    let value_slice = core::slice::from_raw_parts(value as *const u8, map.value_size as usize);

    let bitset = bloom.bitset();

    let mut i = 0u32;
    while i < bloom.nr_hash_funcs {
        let h = bloom.hash(value_slice, i);
        bitset.set_bit(h as usize);
        i = i.wrapping_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Jenkins Hash Functions
// ---------------------------------------------------------------------------

/// Mix macro equivalent for Jenkins hash.
///
/// This performs the mixing step from Bob Jenkins' hash function.
/// It modifies a, b, c in place to thoroughly mix the bits.
#[inline(always)]
fn jhash_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c);
    *a ^= (*c).rotate_left(4);
    *c = c.wrapping_add(*b);

    *b = b.wrapping_sub(*a);
    *b ^= (*a).rotate_left(6);
    *a = a.wrapping_add(*c);

    *c = c.wrapping_sub(*b);
    *c ^= (*b).rotate_left(8);
    *b = b.wrapping_add(*a);

    *a = a.wrapping_sub(*c);
    *a ^= (*c).rotate_left(16);
    *c = c.wrapping_add(*b);

    *b = b.wrapping_sub(*a);
    *b ^= (*a).rotate_left(19);
    *a = a.wrapping_add(*c);

    *c = c.wrapping_sub(*b);
    *c ^= (*b).rotate_left(4);
    *b = b.wrapping_add(*a);
}

/// Final mixing step for Jenkins hash.
#[inline(always)]
fn jhash_final(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = c.wrapping_sub((*b).rotate_left(14));

    *a ^= *c;
    *a = a.wrapping_sub((*c).rotate_left(11));

    *b ^= *a;
    *b = b.wrapping_sub((*a).rotate_left(25));

    *c ^= *b;
    *c = c.wrapping_sub((*b).rotate_left(16));

    *a ^= *c;
    *a = a.wrapping_sub((*c).rotate_left(4));

    *b ^= *a;
    *b = b.wrapping_sub((*a).rotate_left(14));

    *c ^= *b;
    *c = c.wrapping_sub((*b).rotate_left(24));
}

/// The Jenkins hash initval constant.
const JHASH_INITVAL: u32 = 0xdeadbeef;

/// Jenkins hash for u32 word arrays (jhash2).
///
/// Hashes an array of u32 values. The input byte slice must have a length
/// that is a multiple of 4. The bytes are interpreted as little-endian u32
/// words.
///
/// This matches the kernel's `jhash2(const u32 *k, u32 length, u32 initval)`
/// where `length` is the number of u32 words.
fn jhash2(value: &[u8], initval: u32) -> u32 {
    let len = value.len() / 4; // number of u32 words

    let mut a: u32 = JHASH_INITVAL.wrapping_add((len as u32).wrapping_mul(4)).wrapping_add(initval);
    let mut b: u32 = a;
    let mut c: u32 = a;

    let mut offset = 0usize;
    let mut remaining = len;

    // Process 3 words at a time
    while remaining > 3 {
        a = a.wrapping_add(read_u32_le(value, offset));
        b = b.wrapping_add(read_u32_le(value, offset + 4));
        c = c.wrapping_add(read_u32_le(value, offset + 8));
        jhash_mix(&mut a, &mut b, &mut c);
        remaining -= 3;
        offset += 12;
    }

    // Handle the last few words
    match remaining {
        3 => {
            c = c.wrapping_add(read_u32_le(value, offset + 8));
            b = b.wrapping_add(read_u32_le(value, offset + 4));
            a = a.wrapping_add(read_u32_le(value, offset));
        }
        2 => {
            b = b.wrapping_add(read_u32_le(value, offset + 4));
            a = a.wrapping_add(read_u32_le(value, offset));
        }
        1 => {
            a = a.wrapping_add(read_u32_le(value, offset));
        }
        _ => return c, // zero remaining, nothing to finalize
    }

    jhash_final(&mut a, &mut b, &mut c);
    c
}

/// Jenkins hash for arbitrary byte sequences (jhash).
///
/// Hashes a byte sequence of arbitrary length. This handles the byte-level
/// tail that jhash2 cannot process.
///
/// This matches the kernel's `jhash(const void *key, u32 length, u32 initval)`.
fn jhash(value: &[u8], initval: u32) -> u32 {
    let len = value.len() as u32;
    let mut a: u32 = JHASH_INITVAL.wrapping_add(len).wrapping_add(initval);
    let mut b: u32 = a;
    let mut c: u32 = a;

    let mut offset = 0usize;
    let mut remaining = value.len();

    // Process 12 bytes at a time
    while remaining > 12 {
        a = a.wrapping_add(read_u32_le(value, offset));
        b = b.wrapping_add(read_u32_le(value, offset + 4));
        c = c.wrapping_add(read_u32_le(value, offset + 8));
        jhash_mix(&mut a, &mut b, &mut c);
        remaining -= 12;
        offset += 12;
    }

    // Handle the last up to 12 bytes.
    // The kernel jhash processes remaining bytes in a specific pattern,
    // reading bytes individually and shifting them into u32 values.
    // Bytes are added to c (high bytes), b (middle), a (low) with fallthrough.
    match remaining {
        12 => {
            c = c.wrapping_add((read_byte(value, offset + 11) as u32) << 24);
            c = c.wrapping_add((read_byte(value, offset + 10) as u32) << 16);
            c = c.wrapping_add((read_byte(value, offset + 9) as u32) << 8);
            c = c.wrapping_add(read_byte(value, offset + 8) as u32);
            b = b.wrapping_add((read_byte(value, offset + 7) as u32) << 24);
            b = b.wrapping_add((read_byte(value, offset + 6) as u32) << 16);
            b = b.wrapping_add((read_byte(value, offset + 5) as u32) << 8);
            b = b.wrapping_add(read_byte(value, offset + 4) as u32);
            a = a.wrapping_add((read_byte(value, offset + 3) as u32) << 24);
            a = a.wrapping_add((read_byte(value, offset + 2) as u32) << 16);
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        11 => {
            c = c.wrapping_add((read_byte(value, offset + 10) as u32) << 16);
            c = c.wrapping_add((read_byte(value, offset + 9) as u32) << 8);
            c = c.wrapping_add(read_byte(value, offset + 8) as u32);
            b = b.wrapping_add((read_byte(value, offset + 7) as u32) << 24);
            b = b.wrapping_add((read_byte(value, offset + 6) as u32) << 16);
            b = b.wrapping_add((read_byte(value, offset + 5) as u32) << 8);
            b = b.wrapping_add(read_byte(value, offset + 4) as u32);
            a = a.wrapping_add((read_byte(value, offset + 3) as u32) << 24);
            a = a.wrapping_add((read_byte(value, offset + 2) as u32) << 16);
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        10 => {
            c = c.wrapping_add((read_byte(value, offset + 9) as u32) << 8);
            c = c.wrapping_add(read_byte(value, offset + 8) as u32);
            b = b.wrapping_add((read_byte(value, offset + 7) as u32) << 24);
            b = b.wrapping_add((read_byte(value, offset + 6) as u32) << 16);
            b = b.wrapping_add((read_byte(value, offset + 5) as u32) << 8);
            b = b.wrapping_add(read_byte(value, offset + 4) as u32);
            a = a.wrapping_add((read_byte(value, offset + 3) as u32) << 24);
            a = a.wrapping_add((read_byte(value, offset + 2) as u32) << 16);
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        9 => {
            c = c.wrapping_add(read_byte(value, offset + 8) as u32);
            b = b.wrapping_add((read_byte(value, offset + 7) as u32) << 24);
            b = b.wrapping_add((read_byte(value, offset + 6) as u32) << 16);
            b = b.wrapping_add((read_byte(value, offset + 5) as u32) << 8);
            b = b.wrapping_add(read_byte(value, offset + 4) as u32);
            a = a.wrapping_add((read_byte(value, offset + 3) as u32) << 24);
            a = a.wrapping_add((read_byte(value, offset + 2) as u32) << 16);
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        8 => {
            b = b.wrapping_add((read_byte(value, offset + 7) as u32) << 24);
            b = b.wrapping_add((read_byte(value, offset + 6) as u32) << 16);
            b = b.wrapping_add((read_byte(value, offset + 5) as u32) << 8);
            b = b.wrapping_add(read_byte(value, offset + 4) as u32);
            a = a.wrapping_add((read_byte(value, offset + 3) as u32) << 24);
            a = a.wrapping_add((read_byte(value, offset + 2) as u32) << 16);
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        7 => {
            b = b.wrapping_add((read_byte(value, offset + 6) as u32) << 16);
            b = b.wrapping_add((read_byte(value, offset + 5) as u32) << 8);
            b = b.wrapping_add(read_byte(value, offset + 4) as u32);
            a = a.wrapping_add((read_byte(value, offset + 3) as u32) << 24);
            a = a.wrapping_add((read_byte(value, offset + 2) as u32) << 16);
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        6 => {
            b = b.wrapping_add((read_byte(value, offset + 5) as u32) << 8);
            b = b.wrapping_add(read_byte(value, offset + 4) as u32);
            a = a.wrapping_add((read_byte(value, offset + 3) as u32) << 24);
            a = a.wrapping_add((read_byte(value, offset + 2) as u32) << 16);
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        5 => {
            b = b.wrapping_add(read_byte(value, offset + 4) as u32);
            a = a.wrapping_add((read_byte(value, offset + 3) as u32) << 24);
            a = a.wrapping_add((read_byte(value, offset + 2) as u32) << 16);
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        4 => {
            a = a.wrapping_add((read_byte(value, offset + 3) as u32) << 24);
            a = a.wrapping_add((read_byte(value, offset + 2) as u32) << 16);
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        3 => {
            a = a.wrapping_add((read_byte(value, offset + 2) as u32) << 16);
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        2 => {
            a = a.wrapping_add((read_byte(value, offset + 1) as u32) << 8);
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        1 => {
            a = a.wrapping_add(read_byte(value, offset) as u32);
        }
        _ => return c,
    }

    jhash_final(&mut a, &mut b, &mut c);
    c
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Read a u32 from a byte slice at the given byte offset (little-endian).
///
/// Uses safe slice access with `.get()` to avoid panicking indexing.
/// Returns 0 if the offset is out of bounds (should not happen with correct
/// callers, but prevents UB in release builds).
#[inline(always)]
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    // Use get to avoid panicking indexing (crate denies clippy::indexing_slicing)
    let b0 = data.get(offset).copied().unwrap_or(0) as u32;
    let b1 = data.get(offset + 1).copied().unwrap_or(0) as u32;
    let b2 = data.get(offset + 2).copied().unwrap_or(0) as u32;
    let b3 = data.get(offset + 3).copied().unwrap_or(0) as u32;
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

/// Read a single byte from a slice at the given offset.
///
/// Returns 0 if out of bounds (defensive, should not happen with correct callers).
#[inline(always)]
fn read_byte(data: &[u8], offset: usize) -> u8 {
    data.get(offset).copied().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Allowed map creation flags for bloom filters.
///
/// Only `BPF_F_NUMA_NODE`, `BPF_F_ZERO_SEED`, and access flags (RDONLY/WRONLY)
/// are permitted. All other flags are rejected.
const BLOOM_CREATE_FLAG_MASK: u32 =
    bindings::BPF_F_NUMA_NODE | bindings::BPF_F_ZERO_SEED | bindings::BPF_F_ACCESS_MASK;

/// Number of bits in a `usize` (used for bitset size alignment).
const BITS_PER_LONG: u32 = (mem::size_of::<usize>() * 8) as u32;

// ---------------------------------------------------------------------------
// Map Lifecycle Functions
// ---------------------------------------------------------------------------

/// Allocate and initialize a new BPF bloom filter map.
///
/// Reads configuration from the user-provided `bpf_attr`, validates parameters,
/// computes the optimal bitset size, allocates memory for the struct and
/// trailing bitset, initializes fields, and returns a pointer to the embedded
/// `bpf_map`.
///
/// # Arguments
///
/// * `attr` - Pointer to the `bpf_attr` union populated by the `BPF_MAP_CREATE`
///   syscall command. Must be non-null and valid.
///
/// # Returns
///
/// On success, returns `Ok` with a pointer to the `bpf_map` field of the
/// newly allocated `BpfBloomFilter`. On failure, returns an appropriate error:
///
/// - `Err(EINVAL)` — invalid attribute values (zero value_size, zero max_entries,
///   unsupported flags, invalid nr_hash_funcs).
/// - `Err(ENOMEM)` — memory allocation failure.
///
/// # Safety
///
/// - `attr` must point to a valid `bpf_attr` populated for `BPF_MAP_CREATE`.
/// - The returned `*mut bindings::bpf_map` must be freed via [`bloom_map_free`]
///   when no longer needed.
pub unsafe fn bloom_map_alloc(
    attr: *const bindings::bpf_attr,
) -> Result<*mut bindings::bpf_map> {
    // SAFETY: Caller guarantees `attr` is a valid pointer to a bpf_attr
    // populated for BPF_MAP_CREATE.
    let attr_ref = &*attr;

    let key_size = attr_ref.key_size();
    let value_size = attr_ref.value_size();
    let max_entries = attr_ref.max_entries();
    let map_flags = attr_ref.map_flags();
    let map_extra = attr_ref.map_extra();
    let numa_node_raw = attr_ref.numa_node();

    // Bloom filters are keyless — key_size must be 0
    if key_size != 0 {
        return Err(Error::EINVAL);
    }

    // value_size and max_entries must be non-zero
    if value_size == 0 || max_entries == 0 {
        return Err(Error::EINVAL);
    }

    // Only allowed flags
    if map_flags & !BLOOM_CREATE_FLAG_MASK != 0 {
        return Err(Error::EINVAL);
    }

    // Check that access flags are valid (not both RDONLY and WRONLY)
    if map_flags & bindings::BPF_F_ACCESS_MASK == bindings::BPF_F_ACCESS_MASK {
        return Err(Error::EINVAL);
    }

    // map_extra encodes nr_hash_funcs in the lower 4 bits; upper bits must be 0
    if map_extra & !0xF != 0 {
        return Err(Error::EINVAL);
    }

    let mut nr_hash_funcs = map_extra as u32;
    if nr_hash_funcs == 0 {
        // Default to 5 hash functions if unspecified (matches C implementation)
        nr_hash_funcs = 5;
    }

    // Compute optimal bitset size: n * k / ln(2) ≈ n * k * 7 / 5
    // Round up to power of two for efficient bitmask hashing.
    let (bitset_bytes, bitset_mask) = compute_bitset_params(max_entries, nr_hash_funcs);

    // Determine NUMA node: if BPF_F_NUMA_NODE is set, use the provided value;
    // otherwise use NUMA_NO_NODE (-1).
    let numa_node = if map_flags & bindings::BPF_F_NUMA_NODE != 0 {
        numa_node_raw as i32
    } else {
        bindings::NUMA_NO_NODE
    };

    // Allocate struct + trailing bitset in one contiguous block
    let alloc_size = mem::size_of::<BpfBloomFilter>() as u64 + bitset_bytes as u64;
    let raw_ptr = BpfMapArea::alloc(alloc_size, numa_node)?;

    // SAFETY: BpfMapArea::alloc returned a non-null pointer with at least
    // `alloc_size` bytes. We cast to our struct and initialize all fields.
    // Safety (cast_ptr_alignment): BpfMapArea::alloc delegates to kmalloc/vmalloc
    // which return memory aligned to at least max_align_t (>= 8 bytes), satisfying
    // the alignment requirement of BpfBloomFilter.
    #[allow(clippy::cast_ptr_alignment)]
    let bloom = raw_ptr as *mut BpfBloomFilter;

    // Zero the entire allocation (bitset must start as all-zeros)
    ptr::write_bytes(raw_ptr, 0, alloc_size as usize);

    // Initialize the bpf_map common fields from the attr.
    // SAFETY: bloom->map is within the valid allocation, and attr is valid.
    bindings::bpf_map_init_from_attr(&mut (*bloom).map, attr);

    // Initialize bloom filter specific fields
    (*bloom).nr_hash_funcs = nr_hash_funcs;
    (*bloom).bitset_mask = bitset_mask;

    // Set hash seed: random unless BPF_F_ZERO_SEED is specified
    if map_flags & bindings::BPF_F_ZERO_SEED == 0 {
        // SAFETY: get_random_u32 is always safe to call in kernel context.
        (*bloom).hash_seed = bindings::get_random_u32();
    } else {
        (*bloom).hash_seed = 0;
    }

    // Return pointer to the embedded bpf_map field (first field, offset 0)
    Ok(&mut (*bloom).map as *mut bindings::bpf_map)
}

/// Free a BPF bloom filter map previously allocated by [`bloom_map_alloc`].
///
/// Recovers the `BpfBloomFilter` pointer from the embedded `bpf_map` field
/// using the container_of pattern (the `map` field is at offset 0), then
/// frees the entire allocation via `BpfMapArea::free`.
///
/// # Safety
///
/// - `map` must point to the `bpf_map` field of a `BpfBloomFilter` that was
///   previously allocated by [`bloom_map_alloc`].
/// - `map` must not have been freed already (no double-free).
/// - No references to the bloom filter or its bitset may be used after this call.
pub unsafe fn bloom_map_free(map: *mut bindings::bpf_map) {
    // SAFETY: The `map` field is at offset 0 of BpfBloomFilter (#[repr(C)],
    // first field), so the pointer to `map` is the same as the pointer to
    // the enclosing BpfBloomFilter struct. This is the standard container_of
    // pattern used throughout the kernel.
    let bloom = map as *mut BpfBloomFilter;

    // SAFETY: The caller guarantees `bloom` was allocated by bloom_map_alloc
    // which uses BpfMapArea::alloc. It has not been freed yet.
    BpfMapArea::free(bloom as *mut u8);
}

/// Get next key operation for bloom filter maps.
///
/// Bloom filters are keyless data structures and do not support iteration.
/// This function unconditionally returns `Err(EOPNOTSUPP)`.
///
/// # Arguments
///
/// * `_map` - Unused. Pointer to the BPF map (for signature compatibility).
/// * `_key` - Unused. Pointer to the current key.
/// * `_next_key` - Unused. Pointer to write the next key.
///
/// # Returns
///
/// Always returns `Err(EOPNOTSUPP)`.
pub fn bloom_map_get_next_key(
    _map: *const bindings::bpf_map,
    _key: *const c_void,
    _next_key: *mut c_void,
) -> Result {
    Err(Error::EOPNOTSUPP)
}

// ---------------------------------------------------------------------------
// Internal Helpers for Allocation
// ---------------------------------------------------------------------------

/// Compute the bitset size in bytes and the bitmask for the bloom filter.
///
/// Uses the formula: optimal bits = max_entries * nr_hash_funcs * 7 / 5
/// (approximating 1/ln(2) as 7/5). The result is rounded up to a power of
/// two for efficient bitmask-based indexing. The returned bytes are rounded
/// up to `sizeof(usize)` alignment.
///
/// If intermediate computations overflow u32, falls back to the maximum
/// bitset size (2^32 bits = 512 MiB).
fn compute_bitset_params(max_entries: u32, nr_hash_funcs: u32) -> (u32, u32) {
    // Attempt: nr_bits = max_entries * nr_hash_funcs * 7 / 5
    // Check for overflow at each step.
    let nr_bits = (max_entries as u64)
        .checked_mul(nr_hash_funcs as u64)
        .and_then(|v| v.checked_mul(7))
        .map(|v| v / 5);

    let (bitset_bytes, bitset_mask) = match nr_bits {
        Some(bits) if bits <= (1u64 << 31) => {
            let mut nr = bits as u32;
            if nr <= BITS_PER_LONG {
                nr = BITS_PER_LONG;
            } else {
                nr = roundup_pow_of_two_u32(nr);
            }
            let mask = nr.wrapping_sub(1);
            let bytes = bits_to_bytes(nr);
            (roundup_to_usize(bytes), mask)
        }
        _ => {
            // Overflow or > 2^31: use maximum bitset size
            let mask = u32::MAX;
            let bytes = bits_to_bytes_u64(u32::MAX as u64 + 1);
            (roundup_to_usize(bytes), mask)
        }
    };

    (bitset_bytes, bitset_mask)
}

/// Round up a u32 to the next power of two.
///
/// If the value is already a power of two, it is returned unchanged.
/// If the value is 0 or 1, returns the value unchanged (handled by callers).
#[inline]
fn roundup_pow_of_two_u32(v: u32) -> u32 {
    if v <= 1 {
        return v;
    }
    // Standard bit trick: set all bits below the highest, then add 1
    1u32 << (32 - (v - 1).leading_zeros())
}

/// Convert number of bits to number of bytes (rounding up).
#[inline]
fn bits_to_bytes(bits: u32) -> u32 {
    bits.div_ceil(8)
}

/// Convert number of bits (u64) to number of bytes (u32, clamped).
#[inline]
fn bits_to_bytes_u64(bits: u64) -> u32 {
    let bytes = bits.div_ceil(8);
    if bytes > u32::MAX as u64 {
        u32::MAX
    } else {
        bytes as u32
    }
}

/// Round up a byte count to the nearest multiple of `sizeof(usize)`.
///
/// This matches the kernel's `roundup(bitset_bytes, sizeof(unsigned long))`.
#[inline]
fn roundup_to_usize(bytes: u32) -> u32 {
    let align = mem::size_of::<usize>() as u32;
    (bytes.wrapping_add(align - 1)) & !(align - 1)
}
