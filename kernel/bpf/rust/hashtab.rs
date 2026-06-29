// SPDX-License-Identifier: GPL-2.0
//! BPF Hash Table map implementation.
//!
//! This module implements the Rust equivalent of `kernel/bpf/hashtab.c`.
//! It provides a hash table data structure for BPF maps with per-bucket
//! locking, singly-linked element chains, and RCU-safe lookup.
//!
//! # Data Structure Layout
//!
//! Each bucket contains a spinlock and a pointer to the head of a
//! singly-linked list of `HtabElem` nodes. Elements store a cached hash
//! value followed by key and value data in trailing memory.
//!
//! # Concurrency Model
//!
//! - **Lookup**: Performed under RCU read-side lock without bucket lock.
//!   Walks the chain comparing hash then key bytes.
//! - **Update/Delete**: Acquires per-bucket spinlock, performs chain walk,
//!   inserts/removes element, then releases lock.
//!
//! # bpf_map_ops Wiring
//!
//! The following FFI entry points (in `ffi_wrappers.rs`) are exposed for
//! the C-side `bpf_map_ops htab_map_ops` struct:
//!
//! | C field               | Rust FFI symbol               |
//! |-----------------------|-------------------------------|
//! | `.map_alloc`          | `htab_map_alloc_rs`           |
//! | `.map_free`           | `htab_map_free_rs`            |
//! | `.map_lookup_elem`    | `htab_map_lookup_elem_rs`     |
//! | `.map_update_elem`    | `htab_map_update_elem_rs`     |
//! | `.map_delete_elem`    | `htab_map_delete_elem_rs`     |
//! | `.map_get_next_key`   | `htab_map_get_next_key_rs`    |
//!
//! # Safety
//!
//! The [`BpfHtab`] struct uses `#[repr(C)]` to maintain layout
//! compatibility with the C `struct bpf_htab`. The `map` field must be
//! the first field to support the `container_of` pattern.

use crate::bindings;
use crate::error::{Error, Result};
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Data Structures
// ---------------------------------------------------------------------------

/// Per-bucket structure containing a spinlock and list head.
///
/// Each bucket serializes concurrent insertions and deletions via its own
/// spinlock. The `head` pointer is the start of a singly-linked list of
/// [`HtabElem`] nodes.
#[repr(C)]
pub struct HtabBucket {
    /// Per-bucket spinlock for serializing update/delete operations.
    pub lock: bindings::rqspinlock_t,
    /// Head of the singly-linked element list. Null means empty bucket.
    pub head: *mut HtabElem,
}

/// A single element in the hash table.
///
/// Each element is allocated as a contiguous block:
/// `[HtabElem header][key bytes][value bytes (8-byte aligned)]`
///
/// The `key` and `value` data follow the struct in memory and are accessed
/// via pointer arithmetic through the [`key_ptr`](BpfHtab::elem_key_ptr)
/// and [`value_ptr`](BpfHtab::elem_value_ptr) helpers.
#[repr(C)]
pub struct HtabElem {
    /// Next element in the bucket chain, or null if this is the last.
    pub next: *mut HtabElem,
    /// Cached hash value for fast comparison before full key memcmp.
    pub hash: u32,
    /// Padding for 8-byte alignment of trailing key data.
    pub _pad: u32,
    // Flexible array: key bytes followed by value bytes (8-byte aligned)
    // start immediately after this struct in memory.
}

/// BPF Hash Table map.
///
/// Layout matches the C `struct bpf_htab` for FFI compatibility. The `map`
/// field MUST be the first field to support the kernel's `container_of`
/// macro pattern.
///
/// This is the core hash table supporting `BPF_MAP_TYPE_HASH`. Per-CPU
/// and LRU variants are handled by separate task (13.2).
#[repr(C)]
pub struct BpfHtab {
    /// Common BPF map fields. Must be first for container_of.
    pub map: bindings::bpf_map,
    /// Pointer to the bucket array. Length is `n_buckets`.
    pub buckets: *mut HtabBucket,
    /// Number of buckets (always a power of 2).
    pub n_buckets: u32,
    /// Size of each element allocation in bytes:
    /// `size_of::<HtabElem>() + key_size + round_up(key_size, 8) + value_size`
    pub elem_size: u32,
    /// Random seed for the hash function.
    pub hasher_seed: u32,
    /// Padding for alignment.
    pub _pad: u32,
    /// Current number of elements in the table.
    pub count: AtomicU32,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of buckets allowed (prevent excessive memory usage).
/// Matches the kernel's cap of 2^(31-1) = 1073741824 in C htab.
const HTAB_MAX_BUCKETS: u32 = 1 << 17; // 131072: practical cap for Rust impl

/// Allowed map creation flags for hash tables.
const HTAB_VALID_FLAGS: u32 = bindings::BPF_F_NO_PREALLOC
    | bindings::BPF_F_NUMA_NODE
    | bindings::BPF_F_RDONLY
    | bindings::BPF_F_WRONLY
    | bindings::BPF_F_ZERO_SEED;

// ---------------------------------------------------------------------------
// Lifecycle Operations
// ---------------------------------------------------------------------------

/// Allocate and initialize a new BPF hash table map from the given attributes.
///
/// This is the Rust equivalent of `htab_map_alloc()` in `kernel/bpf/hashtab.c`.
///
/// Steps:
/// 1. Read and validate attr fields (key_size, value_size, max_entries, map_flags).
/// 2. Compute n_buckets as roundup_pow_of_two(max_entries), capped.
/// 3. Compute elem_size: sizeof(HtabElem) + round_up_8(key_size) + value_size.
/// 4. Allocate the BpfHtab struct via BpfMapArea::alloc().
/// 5. Allocate the bucket array via BpfMapArea::alloc().
/// 6. Zero-initialize buckets, set hasher_seed, count = 0.
/// 7. Call bpf_map_init_from_attr, return pointer to map field.
///
/// # Arguments
///
/// * `attr` - Pointer to the bpf_attr populated for BPF_MAP_CREATE.
///
/// # Returns
///
/// A pointer to the `bpf_map` field of the newly allocated `BpfHtab`, or
/// an error on failure (EINVAL for bad params, ENOMEM for alloc failure).
///
/// # Safety
///
/// `attr` must be a valid pointer to a `bpf_attr` populated for BPF_MAP_CREATE.
pub unsafe fn htab_map_alloc(attr: *const bindings::bpf_attr) -> Result<*mut bindings::bpf_map> {
    use crate::abstractions::bpf_mem::BpfMapArea;

    let attr_ref = &*attr;

    // 1. Read attr fields
    let key_size = attr_ref.key_size();
    let value_size = attr_ref.value_size();
    let max_entries = attr_ref.max_entries();
    let map_flags = attr_ref.map_flags();
    let numa_node = if map_flags & bindings::BPF_F_NUMA_NODE != 0 {
        attr_ref.numa_node() as i32
    } else {
        bindings::NUMA_NO_NODE
    };

    // 2. Validate parameters
    if key_size == 0 || value_size == 0 || max_entries == 0 {
        return Err(Error::EINVAL);
    }

    // Reject unknown flags
    if map_flags & !HTAB_VALID_FLAGS != 0 {
        return Err(Error::EINVAL);
    }

    // Reject excessively large entries that could overflow
    if key_size > u32::MAX / 2 || value_size > u32::MAX / 2 {
        return Err(Error::E2BIG);
    }

    // 3. Compute n_buckets: roundup_pow_of_two(max_entries), capped
    let n_buckets = roundup_pow_of_two(max_entries).min(HTAB_MAX_BUCKETS);

    // 4. Compute elem_size: sizeof(HtabElem) + round_up_8(key_size) + value_size
    let htab_elem_hdr = core::mem::size_of::<HtabElem>() as u32;
    let key_aligned = round_up_8(key_size);
    let elem_size = htab_elem_hdr
        .checked_add(key_aligned)
        .and_then(|v| v.checked_add(value_size))
        .ok_or(Error::E2BIG)?;

    // 5. Allocate the BpfHtab struct
    let htab_size = core::mem::size_of::<BpfHtab>() as u64;
    // Safety (cast_ptr_alignment): BpfMapArea::alloc delegates to kmalloc/vmalloc
    // which return memory aligned to at least max_align_t (>= 8 bytes), satisfying
    // the alignment requirement of BpfHtab.
    #[allow(clippy::cast_ptr_alignment)]
    let htab_ptr = BpfMapArea::alloc(htab_size, numa_node)? as *mut BpfHtab;

    // Zero-initialize the entire BpfHtab
    ptr::write_bytes(htab_ptr as *mut u8, 0, htab_size as usize);

    // 6. Allocate the bucket array
    let bucket_size = core::mem::size_of::<HtabBucket>() as u64;
    let buckets_total_size = bucket_size
        .checked_mul(n_buckets as u64)
        .ok_or_else(|| {
            // Free the htab allocation on overflow
            BpfMapArea::free(htab_ptr as *mut u8);
            Error::E2BIG
        })?;

    let buckets_ptr = match BpfMapArea::alloc(buckets_total_size, numa_node) {
        // Safety (cast_ptr_alignment): BpfMapArea::alloc delegates to kmalloc/vmalloc
        // which return memory aligned to at least max_align_t (>= 8 bytes), satisfying
        // the alignment requirement of HtabBucket.
        #[allow(clippy::cast_ptr_alignment)]
        Ok(ptr) => ptr as *mut HtabBucket,
        Err(e) => {
            // Free the htab allocation on bucket alloc failure
            BpfMapArea::free(htab_ptr as *mut u8);
            return Err(e);
        }
    };

    // 7. Zero-initialize buckets (heads are null, locks are zero/unlocked)
    ptr::write_bytes(buckets_ptr as *mut u8, 0, buckets_total_size as usize);

    // Initialize the BpfHtab fields
    let htab = &mut *htab_ptr;
    htab.buckets = buckets_ptr;
    htab.n_buckets = n_buckets;
    htab.elem_size = elem_size;
    htab.count = AtomicU32::new(0);

    // Set hasher_seed: use zero if BPF_F_ZERO_SEED is set, otherwise random
    htab.hasher_seed = if map_flags & bindings::BPF_F_ZERO_SEED != 0 {
        0
    } else {
        bindings::get_random_u32()
    };

    // Initialize the common bpf_map fields from attr
    let map_ptr = &mut htab.map as *mut bindings::bpf_map;
    bindings::bpf_map_init_from_attr(map_ptr, attr);

    Ok(map_ptr)
}

/// Free a BPF hash table map and all associated resources.
///
/// This is the Rust equivalent of `htab_map_free()` in `kernel/bpf/hashtab.c`.
///
/// Steps:
/// 1. Walk all buckets, free all elements in each chain.
/// 2. Free the bucket array.
/// 3. Free the BpfHtab struct.
///
/// # Safety
///
/// - `map` must be a valid pointer to the `bpf_map` field of a `BpfHtab` that
///   was allocated by [`htab_map_alloc`].
/// - Must not be called more than once for the same map.
/// - No concurrent access to this map may occur during free.
pub unsafe fn htab_map_free(map: *mut bindings::bpf_map) {
    use crate::abstractions::bpf_mem::BpfMapArea;

    let htab = &*(map as *const BpfHtab);

    // Walk all buckets and free elements
    for i in 0..htab.n_buckets {
        let bucket = &*htab.bucket_at(i);
        let mut current = bucket.head;
        while !current.is_null() {
            let next = (*current).next;
            // SAFETY: Element was allocated via __kmalloc in htab_map_update_elem.
            bindings::kfree(current as *const c_void);
            current = next;
        }
    }

    // Free the bucket array
    // SAFETY: buckets was allocated via BpfMapArea::alloc in htab_map_alloc.
    BpfMapArea::free(htab.buckets as *mut u8);

    // Free the BpfHtab struct itself
    // SAFETY: htab_ptr was allocated via BpfMapArea::alloc in htab_map_alloc.
    BpfMapArea::free(map as *mut u8);
}

/// Get the next key in the hash table for iteration.
///
/// This is the Rust equivalent of `htab_map_get_next_key()` in
/// `kernel/bpf/hashtab.c`.
///
/// - If `key` is null, returns the first key found (scans from bucket 0).
/// - Otherwise, hashes the key, finds it, then scans for the next element.
/// - Returns ENOENT when iteration is complete (no more keys).
///
/// # Arguments
///
/// * `map` - Pointer to the `bpf_map` (first field of `BpfHtab`)
/// * `key` - Pointer to the current key, or null for first key
/// * `next_key` - Pointer to buffer where the next key will be written
///
/// # Returns
///
/// `Ok(())` on success (next_key has been filled), or `Err(ENOENT)` when
/// there are no more keys.
///
/// # Safety
///
/// - `map` must point to the `bpf_map` field of a valid `BpfHtab`.
/// - If `key` is non-null, it must point to `map.key_size` readable bytes.
/// - `next_key` must point to `map.key_size` writable bytes.
pub unsafe fn htab_map_get_next_key(
    map: *const bindings::bpf_map,
    key: *const c_void,
    next_key: *mut c_void,
) -> Result {
    let htab = &*(map as *const BpfHtab);
    let key_size = (*map).key_size;

    if key.is_null() {
        // Return the first key found: scan buckets from 0
        return get_first_key(htab, key_size, next_key);
    }

    // Hash the provided key and find it in the table
    let key_ptr = key as *const u8;
    let hash = htab_map_hash(key_ptr, key_size, htab.hasher_seed);
    let bucket_idx = htab.bucket_index(hash);
    let bucket = &*htab.bucket_at(bucket_idx);

    // Walk the chain to find the current key
    let mut current = bucket.head;
    let mut found = false;

    while !current.is_null() {
        let elem = &*current;
        if elem.hash == hash {
            let elem_key = BpfHtab::elem_key_ptr(current);
            if keys_equal(elem_key, key_ptr, key_size) {
                found = true;
                // Check if there's a next element in this bucket
                let next = elem.next;
                if !next.is_null() {
                    // Copy the next element's key to next_key
                    let next_elem_key = BpfHtab::elem_key_ptr(next);
                    ptr::copy_nonoverlapping(
                        next_elem_key,
                        next_key as *mut u8,
                        key_size as usize,
                    );
                    return Ok(());
                }
                break;
            }
        }
        current = elem.next;
    }

    if !found {
        // Key not found in the table; return first key as fallback
        // (this matches the kernel behavior when key is stale)
        return get_first_key(htab, key_size, next_key);
    }

    // The key was found but it's the last element in its bucket.
    // Scan subsequent buckets for the next non-empty one.
    let start_bucket = bucket_idx.wrapping_add(1);
    for i in start_bucket..htab.n_buckets {
        let b = &*htab.bucket_at(i);
        if !b.head.is_null() {
            let elem_key = BpfHtab::elem_key_ptr(b.head);
            ptr::copy_nonoverlapping(
                elem_key,
                next_key as *mut u8,
                key_size as usize,
            );
            return Ok(());
        }
    }

    // No more keys — iteration complete
    Err(Error::ENOENT)
}

/// Scan all buckets starting from 0 and return the first key found.
///
/// # Safety
///
/// - `htab` must be a valid reference to a `BpfHtab`.
/// - `next_key` must point to `key_size` writable bytes.
unsafe fn get_first_key(
    htab: &BpfHtab,
    key_size: u32,
    next_key: *mut c_void,
) -> Result {
    for i in 0..htab.n_buckets {
        let bucket = &*htab.bucket_at(i);
        if !bucket.head.is_null() {
            let elem_key = BpfHtab::elem_key_ptr(bucket.head);
            ptr::copy_nonoverlapping(
                elem_key,
                next_key as *mut u8,
                key_size as usize,
            );
            return Ok(());
        }
    }
    // Table is empty
    Err(Error::ENOENT)
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/// Round up to the next power of two. If already a power of two, return as-is.
/// Returns 1 for input 0.
#[inline]
const fn roundup_pow_of_two(v: u32) -> u32 {
    if v == 0 {
        return 1;
    }
    // If v is already a power of two, return it
    if v & (v.wrapping_sub(1)) == 0 {
        return v;
    }
    // Find next power of two: 1 << (32 - leading_zeros(v - 1))
    // Using wrapping arithmetic for safety
    1u32 << (32 - (v.wrapping_sub(1)).leading_zeros())
}

// ---------------------------------------------------------------------------
// LRU Hash Table Variant (BPF_MAP_TYPE_LRU_HASH)
// ---------------------------------------------------------------------------

/// BPF LRU Hash Table map.
///
/// Extends [`BpfHtab`] with an LRU eviction list. When the table is full and
/// a new element is inserted, the least-recently-used element is evicted to
/// make room. Lookups promote elements in the LRU list.
///
/// Layout matches the C `struct bpf_htab` when configured for LRU operation.
/// The `htab` field MUST be first to allow casting between `BpfHtabLru` and
/// `BpfHtab` via pointer arithmetic.
///
/// # TODO
///
/// - Full LRU eviction on `update_elem` when map is at capacity.
/// - LRU promotion (bpf_lru_node_set_ref) on `lookup_elem`.
/// - Integration with `bpf_lru_pop_free` / `bpf_lru_push_free` for
///   element lifecycle management.
/// - Per-CPU local LRU list support for reduced contention.
#[repr(C)]
pub struct BpfHtabLru {
    /// Base hash table — contains map, buckets, count, etc.
    /// Must be first for container_of compatibility.
    pub htab: BpfHtab,
    /// Pointer to the BPF LRU list managing eviction order.
    /// Initialized via `bpf_lru_init` during map creation.
    pub lru: *mut bindings::bpf_lru,
}

// ---------------------------------------------------------------------------
// Per-CPU Hash Table Variant (BPF_MAP_TYPE_PERCPU_HASH)
// ---------------------------------------------------------------------------

/// BPF Per-CPU Hash Table map.
///
/// Each element stores a separate value for each CPU. The key lookup finds
/// the element, but the value returned is CPU-local (the value for the
/// current CPU's slot).
///
/// Layout extends [`BpfHtab`] with a pointer to per-CPU value storage.
/// The `htab` field MUST be first for container_of compatibility.
///
/// # TODO
///
/// - Per-CPU value allocation via `bpf_mem_alloc` with `percpu=true`.
/// - Return current CPU's value slot from `lookup_elem`.
/// - Allocate `num_possible_cpus()` value copies per element.
/// - Handle `bpf_map_update_elem` writing to all CPU slots from syscall
///   context vs. single-CPU slot from BPF program context.
#[repr(C)]
pub struct BpfHtabPercpu {
    /// Base hash table — contains map, buckets, count, etc.
    /// Must be first for container_of compatibility.
    pub htab: BpfHtab,
    /// Pointer to per-CPU memory allocator for value storage.
    /// Each element's value is replicated across CPUs.
    pub pcpu_ma: *mut bindings::bpf_mem_alloc,
}

// ---------------------------------------------------------------------------
// LRU Hash Table Operations (stubs delegating to base htab)
// ---------------------------------------------------------------------------

/// Look up an element in an LRU hash table.
///
/// Performs the same lookup as [`htab_map_lookup_elem`], but in a full
/// implementation would also promote the found element in the LRU list
/// (marking it as recently used to prevent eviction).
///
/// # TODO
///
/// - Call `bpf_lru_node_set_ref()` on the element's embedded LRU node
///   after a successful lookup to mark it as recently accessed.
/// - This prevents the element from being evicted during the next
///   LRU rotation pass.
///
/// # Safety
///
/// Same requirements as [`htab_map_lookup_elem`]:
/// - `map` must point to the `bpf_map` field of a valid `BpfHtabLru`.
/// - `key` must point to `map.key_size` readable bytes.
/// - Must be called within an RCU read-side critical section.
pub unsafe fn htab_lru_map_lookup_elem(
    map: *const bindings::bpf_map,
    key: *const c_void,
) -> *mut c_void {
    // TODO: After lookup, promote element in LRU list via:
    //   let node = get_lru_node_from_elem(elem);
    //   bpf_lru_node_set_ref(node);  // sets ref bit to prevent eviction
    // For now, delegate directly to base lookup.
    htab_map_lookup_elem(map, key)
}

/// Update or insert an element in an LRU hash table.
///
/// Performs the same update as [`htab_map_update_elem`], but in a full
/// implementation would evict the least-recently-used element when the
/// table is at capacity (instead of returning `E2BIG`).
///
/// # TODO
///
/// - When map is full (count >= max_entries), call
///   `bpf_lru_pop_free(&lru, hash)` to obtain a free node by evicting
///   the LRU element.
/// - After successful insertion, set the LRU node reference bit.
/// - On element replacement, call `bpf_lru_push_free` on the old element's
///   LRU node.
/// - Handle the case where `bpf_lru_pop_free` returns NULL (all elements
///   are pinned / cannot be evicted).
///
/// # Safety
///
/// Same requirements as [`htab_map_update_elem`]:
/// - `map` must point to the `bpf_map` field of a valid `BpfHtabLru`.
/// - `key` must point to `map.key_size` readable bytes.
/// - `value` must point to `map.value_size` readable bytes.
/// - Must be called within an RCU read-side critical section.
pub unsafe fn htab_lru_map_update_elem(
    map: *mut bindings::bpf_map,
    key: *const c_void,
    value: *const c_void,
    map_flags: u64,
) -> Result {
    // TODO: Implement LRU eviction when map is full:
    //   1. If count >= max_entries && l_old is null:
    //      let lru_htab = &*(map as *const BpfHtabLru);
    //      let free_node = bindings::bpf_lru_pop_free(lru_htab.lru, hash);
    //      if free_node.is_null() { return Err(Error::EBUSY); }
    //      // Use free_node's backing element for the new insertion
    //   2. On success, mark new element's LRU node as referenced.
    // For now, delegate directly to base update (will return E2BIG at capacity).
    htab_map_update_elem(map, key, value, map_flags)
}

/// Delete an element from an LRU hash table.
///
/// Performs the same delete as [`htab_map_delete_elem`], but in a full
/// implementation would also push the freed element's LRU node back
/// to the free list.
///
/// # TODO
///
/// - After unlinking the element from the bucket chain, call
///   `bpf_lru_push_free(&lru, node)` to return the LRU node to the
///   free pool for reuse by future insertions.
///
/// # Safety
///
/// Same requirements as [`htab_map_delete_elem`].
pub unsafe fn htab_lru_map_delete_elem(
    map: *mut bindings::bpf_map,
    key: *const c_void,
) -> Result {
    // TODO: After successful delete, push element's LRU node to free list:
    //   let lru_htab = &*(map as *const BpfHtabLru);
    //   let node = get_lru_node_from_elem(elem);
    //   bindings::bpf_lru_push_free(lru_htab.lru, node);
    htab_map_delete_elem(map, key)
}

// ---------------------------------------------------------------------------
// Per-CPU Hash Table Operations (stubs delegating to base htab)
// ---------------------------------------------------------------------------

/// Look up an element in a per-CPU hash table.
///
/// In a full implementation, this would return a pointer to the value
/// slot for the current CPU rather than the shared value. Each CPU has
/// its own copy of the value for the same key.
///
/// # TODO
///
/// - After finding the element, compute the per-CPU value pointer:
///   `per_cpu_ptr(elem->ptr_to_pptr, smp_processor_id())`
/// - Return the CPU-local value pointer instead of the shared value.
/// - Ensure this is called with preemption disabled (BPF program context)
///   or with explicit CPU selection (syscall context).
///
/// # Safety
///
/// Same requirements as [`htab_map_lookup_elem`]:
/// - `map` must point to the `bpf_map` field of a valid `BpfHtabPercpu`.
/// - `key` must point to `map.key_size` readable bytes.
/// - Must be called within an RCU read-side critical section.
pub unsafe fn htab_percpu_map_lookup_elem(
    map: *const bindings::bpf_map,
    key: *const c_void,
) -> *mut c_void {
    // TODO: Return per-CPU value for current processor:
    //   let elem = find_elem(map, key);
    //   if !elem.is_null() {
    //       return per_cpu_ptr((*elem).ptr_to_pptr, smp_processor_id());
    //   }
    // For now, delegate to base lookup which returns the shared value.
    htab_map_lookup_elem(map, key)
}

/// Update an element in a per-CPU hash table.
///
/// In a full implementation, this would update only the current CPU's
/// value slot when called from BPF program context, or update all CPU
/// slots when called from syscall context.
///
/// # TODO
///
/// - Allocate per-CPU value storage via `bpf_mem_alloc_init` with
///   `percpu=true` during element creation.
/// - In BPF program context: write only to current CPU's value slot.
/// - In syscall context: write to all CPU slots (value buffer contains
///   `num_possible_cpus()` copies concatenated).
/// - Free per-CPU storage via `bpf_mem_cache_free(&pcpu_ma, ...)` on
///   element deletion.
///
/// # Safety
///
/// Same requirements as [`htab_map_update_elem`]:
/// - `map` must point to the `bpf_map` field of a valid `BpfHtabPercpu`.
/// - `key` must point to `map.key_size` readable bytes.
/// - `value` must point to `map.value_size` readable bytes (or
///   `value_size * num_possible_cpus()` bytes in syscall context).
/// - Must be called within an RCU read-side critical section.
pub unsafe fn htab_percpu_map_update_elem(
    map: *mut bindings::bpf_map,
    key: *const c_void,
    value: *const c_void,
    map_flags: u64,
) -> Result {
    // TODO: Handle per-CPU value semantics:
    //   1. Allocate per-CPU value block for new elements.
    //   2. Copy value to appropriate CPU slot(s).
    //   3. Free old per-CPU block on replacement.
    // For now, delegate to base update.
    htab_map_update_elem(map, key, value, map_flags)
}

/// Delete an element from a per-CPU hash table.
///
/// # TODO
///
/// - After unlinking the element, free its per-CPU value storage via
///   `bpf_mem_cache_free(&htab->pcpu_ma, elem->ptr_to_pptr)`.
///
/// # Safety
///
/// Same requirements as [`htab_map_delete_elem`].
pub unsafe fn htab_percpu_map_delete_elem(
    map: *mut bindings::bpf_map,
    key: *const c_void,
) -> Result {
    // TODO: Free per-CPU value storage after element removal.
    htab_map_delete_elem(map, key)
}

// ---------------------------------------------------------------------------
// Batch Operations (stubs — BPF_MAP_TYPE_HASH and variants)
// ---------------------------------------------------------------------------

/// Batch lookup elements from the hash table.
///
/// Iterates over the table in bucket order, copying keys and values into
/// user-provided buffers. Supports continuation via an opaque batch token.
///
/// # TODO
///
/// - Implement bucket-by-bucket iteration with RCU read lock.
/// - Copy keys/values to userspace via `_copy_to_user` equivalent.
/// - Handle per-CPU and LRU variants (per-CPU copies all CPU values).
/// - Return batch token for continuation on next call.
/// - Respect `count` parameter for maximum elements to return.
///
/// # Safety
///
/// - `map` must point to the `bpf_map` field of a valid `BpfHtab` variant.
/// - Output buffers must be valid for the requested count.
pub unsafe fn htab_map_lookup_batch(
    _map: *const bindings::bpf_map,
    _attr: *const bindings::bpf_attr,
) -> Result {
    // TODO: Implement batch lookup iteration over buckets.
    // This requires:
    //   1. Parse batch parameters from attr (keys_out, values_out, count, batch).
    //   2. Iterate buckets starting from batch token position.
    //   3. For each element, copy key and value to userspace buffers.
    //   4. Update batch token and return count of copied elements.
    Err(Error::EOPNOTSUPP)
}

/// Batch update (insert/replace) elements in the hash table.
///
/// # TODO
///
/// - Accept arrays of keys and values from userspace.
/// - Call update_elem for each key-value pair.
/// - Return count of successfully updated elements.
/// - Handle partial failures (some updates succeed, some fail).
///
/// # Safety
///
/// - `map` must point to the `bpf_map` field of a valid `BpfHtab` variant.
/// - Input buffers must contain `count` key-value pairs.
pub unsafe fn htab_map_update_batch(
    _map: *mut bindings::bpf_map,
    _attr: *const bindings::bpf_attr,
) -> Result {
    // TODO: Implement batch update by iterating input key-value pairs.
    Err(Error::EOPNOTSUPP)
}

/// Batch delete elements from the hash table.
///
/// # TODO
///
/// - Accept array of keys from userspace.
/// - Call delete_elem for each key.
/// - Return count of successfully deleted elements.
/// - Handle partial failures.
///
/// # Safety
///
/// - `map` must point to the `bpf_map` field of a valid `BpfHtab` variant.
/// - Input buffer must contain `count` keys.
pub unsafe fn htab_map_delete_batch(
    _map: *mut bindings::bpf_map,
    _attr: *const bindings::bpf_attr,
) -> Result {
    // TODO: Implement batch delete by iterating input keys.
    Err(Error::EOPNOTSUPP)
}

impl BpfHtab {
    /// Get the bucket index for a given hash value.
    #[inline]
    fn bucket_index(&self, hash: u32) -> u32 {
        hash & (self.n_buckets.wrapping_sub(1))
    }

    /// Get a pointer to the bucket at the given index.
    ///
    /// # Safety
    ///
    /// `index` must be less than `self.n_buckets`, and `self.buckets` must
    /// point to a valid allocation of at least `n_buckets` buckets.
    #[inline]
    unsafe fn bucket_at(&self, index: u32) -> *mut HtabBucket {
        // SAFETY: Caller guarantees index < n_buckets and buckets is valid.
        self.buckets.add(index as usize)
    }

    /// Compute the pointer to the key data of an element.
    ///
    /// The key immediately follows the `HtabElem` struct in memory.
    ///
    /// # Safety
    ///
    /// `elem` must point to a valid `HtabElem` allocation with sufficient
    /// trailing memory for key + value.
    #[inline]
    pub unsafe fn elem_key_ptr(elem: *const HtabElem) -> *const u8 {
        // SAFETY: Key data starts right after the HtabElem struct.
        (elem as *const u8).add(core::mem::size_of::<HtabElem>())
    }

    /// Compute the pointer to the value data of an element.
    ///
    /// The value follows the key, aligned up to 8 bytes.
    ///
    /// # Safety
    ///
    /// `elem` must point to a valid `HtabElem` allocation with sufficient
    /// trailing memory. `key_size` must match the map's key_size.
    #[inline]
    pub unsafe fn elem_value_ptr(elem: *const HtabElem, key_size: u32) -> *const u8 {
        let key_ptr = Self::elem_key_ptr(elem);
        // Round up key_size to next multiple of 8 for value alignment
        let key_aligned = round_up_8(key_size);
        // SAFETY: Value data starts at key_ptr + round_up(key_size, 8).
        key_ptr.add(key_aligned as usize)
    }

    /// Compute a mutable pointer to the key data of an element.
    ///
    /// # Safety
    ///
    /// Same requirements as [`elem_key_ptr`](Self::elem_key_ptr).
    #[inline]
    unsafe fn elem_key_ptr_mut(elem: *mut HtabElem) -> *mut u8 {
        (elem as *mut u8).add(core::mem::size_of::<HtabElem>())
    }

    /// Compute a mutable pointer to the value data of an element.
    ///
    /// # Safety
    ///
    /// Same requirements as [`elem_value_ptr`](Self::elem_value_ptr).
    #[inline]
    unsafe fn elem_value_ptr_mut(elem: *mut HtabElem, key_size: u32) -> *mut u8 {
        let key_ptr = Self::elem_key_ptr_mut(elem);
        let key_aligned = round_up_8(key_size);
        key_ptr.add(key_aligned as usize)
    }
}

// ---------------------------------------------------------------------------
// Hash Function (Jenkins hash — same as bloom filter)
// ---------------------------------------------------------------------------

/// Compute the hash of a key using Jenkins hash, matching the kernel's
/// `htab_map_hash()` which uses jhash2 for word-aligned keys and jhash
/// for arbitrary-length keys.
#[inline]
fn htab_map_hash(key: *const u8, key_size: u32, hasher_seed: u32) -> u32 {
    // SAFETY: Caller guarantees `key` points to `key_size` readable bytes.
    let key_slice = unsafe {
        core::slice::from_raw_parts(key, key_size as usize)
    };
    if key_size.is_multiple_of(4) {
        jhash2(key_slice, hasher_seed)
    } else {
        jhash(key_slice, hasher_seed)
    }
}

// ---------------------------------------------------------------------------
// Core Operations
// ---------------------------------------------------------------------------

/// Look up an element in the hash table by key.
///
/// Walks the bucket chain comparing hash values and key bytes. This is
/// called under RCU read-side lock (no bucket lock needed for read).
///
/// # Arguments
///
/// * `map` - Reference to the `bpf_map` (must be first field of `BpfHtab`)
/// * `key` - Pointer to the key to search for
///
/// # Returns
///
/// Pointer to the value on success, or null if the key is not found.
///
/// # Safety
///
/// - `map` must point to the `bpf_map` field of a valid `BpfHtab`.
/// - `key` must point to `map.key_size` readable bytes.
/// - Must be called within an RCU read-side critical section.
pub unsafe fn htab_map_lookup_elem(
    map: *const bindings::bpf_map,
    key: *const c_void,
) -> *mut c_void {
    // SAFETY: Caller guarantees `map` is the `map` field of a BpfHtab.
    let htab = &*(map as *const BpfHtab);
    let key_size = (*map).key_size;
    let key_ptr = key as *const u8;

    let hash = htab_map_hash(key_ptr, key_size, htab.hasher_seed);
    let bucket_idx = htab.bucket_index(hash);

    // SAFETY: bucket_idx < n_buckets (guaranteed by masking).
    let bucket = &*htab.bucket_at(bucket_idx);

    // Walk the singly-linked list under RCU (no lock needed for reads)
    let mut current = bucket.head;
    while !current.is_null() {
        let elem = &*current;
        if elem.hash == hash {
            // Compare full key bytes
            let elem_key = BpfHtab::elem_key_ptr(current);
            if keys_equal(elem_key, key_ptr, key_size) {
                // Found: return pointer to value data
                return BpfHtab::elem_value_ptr_mut(
                    current, key_size,
                ) as *mut c_void;
            }
        }
        current = elem.next;
    }

    // Not found
    ptr::null_mut()
}

/// Update or insert an element in the hash table.
///
/// Hashes the key, acquires the per-bucket spinlock, searches for an
/// existing element, and either replaces it or inserts a new one at the
/// head of the chain.
///
/// # Arguments
///
/// * `map` - Pointer to the `bpf_map` (must be first field of `BpfHtab`)
/// * `key` - Pointer to the key data
/// * `value` - Pointer to the value data
/// * `map_flags` - Update flags: `BPF_ANY`, `BPF_NOEXIST`, or `BPF_EXIST`
///
/// # Returns
///
/// `Ok(())` on success, or an error:
/// - `EINVAL` - unknown flags
/// - `E2BIG` - map is full and inserting a new element
/// - `EEXIST` - `BPF_NOEXIST` specified but key already exists
/// - `ENOENT` - `BPF_EXIST` specified but key not found
/// - `ENOMEM` - allocation failure
///
/// # Safety
///
/// - `map` must point to the `bpf_map` field of a valid `BpfHtab`.
/// - `key` must point to `map.key_size` readable bytes.
/// - `value` must point to `map.value_size` readable bytes.
/// - Must be called within an RCU read-side critical section.
pub unsafe fn htab_map_update_elem(
    map: *mut bindings::bpf_map,
    key: *const c_void,
    value: *const c_void,
    map_flags: u64,
) -> Result {
    // Validate flags
    if map_flags > bindings::BPF_EXIST {
        return Err(Error::EINVAL);
    }

    let htab = &*(map as *const BpfHtab);
    let key_size = (*map).key_size;
    let value_size = (*map).value_size;
    let key_ptr = key as *const u8;
    let value_ptr = value as *const u8;

    let hash = htab_map_hash(key_ptr, key_size, htab.hasher_seed);
    let bucket_idx = htab.bucket_index(hash);

    // SAFETY: bucket_idx < n_buckets.
    let bucket = htab.bucket_at(bucket_idx);

    // Acquire per-bucket spinlock
    let lock_ptr = &mut (*bucket).lock as *mut bindings::rqspinlock_t;
    // SAFETY: lock_ptr points to a valid, initialized rqspinlock_t.
    bindings::rqspin_lock(lock_ptr);

    // Search for existing element under lock
    let mut current = (*bucket).head;
    let mut l_old: *mut HtabElem = ptr::null_mut();

    while !current.is_null() {
        let elem = &*current;
        if elem.hash == hash {
            let elem_key = BpfHtab::elem_key_ptr(current);
            if keys_equal(elem_key, key_ptr, key_size) {
                l_old = current;
                break;
            }
        }
        current = elem.next;
    }

    // Check flags against what we found
    if let Err(e) = check_flags(l_old, map_flags) {
        // SAFETY: We hold the lock, release it before returning.
        bindings::rqspin_unlock(lock_ptr);
        return Err(e);
    }

    // Check capacity for new insertions
    if l_old.is_null() {
        let current_count = htab.count.load(Ordering::Relaxed);
        if current_count >= (*map).max_entries {
            bindings::rqspin_unlock(lock_ptr);
            return Err(Error::E2BIG);
        }
    }

    // Allocate a new element
    let alloc_size = htab.elem_size as usize;
    // SAFETY: alloc_size > 0 (elem_size includes HtabElem + key + value).
    let new_raw = bindings::__kmalloc(alloc_size, bindings::GFP_ATOMIC);
    if new_raw.is_null() {
        bindings::rqspin_unlock(lock_ptr);
        return Err(Error::ENOMEM);
    }
    let l_new = new_raw as *mut HtabElem;

    // Initialize the new element
    (*l_new).hash = hash;
    (*l_new)._pad = 0;

    // Copy key
    let new_key = BpfHtab::elem_key_ptr_mut(l_new);
    ptr::copy_nonoverlapping(key_ptr, new_key, key_size as usize);

    // Copy value
    let new_value = BpfHtab::elem_value_ptr_mut(l_new, key_size);
    ptr::copy_nonoverlapping(value_ptr, new_value, value_size as usize);

    if !l_old.is_null() {
        // Replacing existing element: splice new into old's position
        // by inserting new at head and unlinking old.
        (*l_new).next = (*bucket).head;
        (*bucket).head = l_new;

        // Unlink old element from chain
        // Walk again to find prev pointer to old element
        let mut scan = &mut (*bucket).head as *mut *mut HtabElem;
        let mut sc = (*bucket).head;
        while !sc.is_null() {
            if sc == l_old {
                // `scan` is never l_new's next ptr since l_new is head
                // and l_old can't be l_new. We already set l_new.next
                // to old head, which may include l_old. Unlink l_old.
                *scan = (*l_old).next;
                break;
            }
            scan = &mut (*sc).next;
            sc = (*sc).next;
        }
    } else {
        // New insertion: insert at head of bucket chain
        (*l_new).next = (*bucket).head;
        (*bucket).head = l_new;
        // Increment count
        htab.count.fetch_add(1, Ordering::Relaxed);
    }

    // Release bucket lock
    bindings::rqspin_unlock(lock_ptr);

    // Free old element if it was replaced (outside lock for safety)
    if !l_old.is_null() {
        // SAFETY: l_old was allocated via __kmalloc and is now unlinked
        // from the chain. In a real kernel implementation this would use
        // kfree_rcu for RCU grace period. For now, direct kfree.
        bindings::kfree(l_old as *const c_void);
    }

    Ok(())
}

/// Delete an element from the hash table by key.
///
/// Hashes the key, acquires the per-bucket spinlock, finds and unlinks
/// the element, releases the lock, then frees the element.
///
/// # Arguments
///
/// * `map` - Pointer to the `bpf_map` (must be first field of `BpfHtab`)
/// * `key` - Pointer to the key to delete
///
/// # Returns
///
/// `Ok(())` on success, or `Err(ENOENT)` if the key was not found.
///
/// # Safety
///
/// - `map` must point to the `bpf_map` field of a valid `BpfHtab`.
/// - `key` must point to `map.key_size` readable bytes.
/// - Must be called within an RCU read-side critical section.
pub unsafe fn htab_map_delete_elem(
    map: *mut bindings::bpf_map,
    key: *const c_void,
) -> Result {
    let htab = &*(map as *const BpfHtab);
    let key_size = (*map).key_size;
    let key_ptr = key as *const u8;

    let hash = htab_map_hash(key_ptr, key_size, htab.hasher_seed);
    let bucket_idx = htab.bucket_index(hash);

    // SAFETY: bucket_idx < n_buckets.
    let bucket = htab.bucket_at(bucket_idx);

    // Acquire per-bucket spinlock
    let lock_ptr = &mut (*bucket).lock as *mut bindings::rqspinlock_t;
    // SAFETY: lock_ptr points to a valid, initialized rqspinlock_t.
    bindings::rqspin_lock(lock_ptr);

    // Walk the chain to find the element and its predecessor
    let mut prev_ptr: *mut *mut HtabElem = &mut (*bucket).head;
    let mut current = (*bucket).head;
    let mut found: *mut HtabElem = ptr::null_mut();

    while !current.is_null() {
        let elem = &*current;
        if elem.hash == hash {
            let elem_key = BpfHtab::elem_key_ptr(current);
            if keys_equal(elem_key, key_ptr, key_size) {
                found = current;
                // Unlink from chain
                *prev_ptr = elem.next;
                break;
            }
        }
        prev_ptr = &mut (*current).next;
        current = elem.next;
    }

    // Release bucket lock
    bindings::rqspin_unlock(lock_ptr);

    if found.is_null() {
        return Err(Error::ENOENT);
    }

    // Decrement element count
    htab.count.fetch_sub(1, Ordering::Relaxed);

    // Free the element (in real kernel: kfree_rcu for grace period safety)
    // SAFETY: `found` was allocated via __kmalloc and is now unlinked.
    bindings::kfree(found as *const c_void);

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/// Check update flags against the current element state.
///
/// - `BPF_NOEXIST`: fails if element already exists (EEXIST)
/// - `BPF_EXIST`: fails if element does not exist (ENOENT)
/// - `BPF_ANY`: always succeeds
#[inline]
fn check_flags(l_old: *const HtabElem, map_flags: u64) -> Result {
    if !l_old.is_null() && map_flags == bindings::BPF_NOEXIST {
        return Err(Error::EEXIST);
    }
    if l_old.is_null() && map_flags == bindings::BPF_EXIST {
        return Err(Error::ENOENT);
    }
    Ok(())
}

/// Compare two key byte sequences for equality.
///
/// # Safety
///
/// Both `a` and `b` must point to at least `len` readable bytes.
#[inline]
unsafe fn keys_equal(a: *const u8, b: *const u8, len: u32) -> bool {
    let mut i = 0u32;
    while i < len {
        // SAFETY: Caller guarantees both pointers have `len` bytes.
        if *a.add(i as usize) != *b.add(i as usize) {
            return false;
        }
        i = i.wrapping_add(1);
    }
    true
}

/// Round up a value to the next multiple of 8.
#[inline]
const fn round_up_8(v: u32) -> u32 {
    (v.wrapping_add(7)) & !7
}

// ---------------------------------------------------------------------------
// Jenkins Hash Functions (same algorithm as bloom_filter.rs)
// ---------------------------------------------------------------------------

/// The Jenkins hash initval constant.
const JHASH_INITVAL: u32 = 0xdeadbeef;

/// Jenkins hash mixing step.
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

/// Jenkins hash final mixing step.
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

/// Jenkins hash for u32 word arrays (jhash2).
///
/// Hashes a byte slice whose length is a multiple of 4, interpreting it
/// as little-endian u32 words.
fn jhash2(value: &[u8], initval: u32) -> u32 {
    let len = value.len() / 4;

    let mut a: u32 = JHASH_INITVAL
        .wrapping_add((len as u32).wrapping_mul(4))
        .wrapping_add(initval);
    let mut b: u32 = a;
    let mut c: u32 = a;

    let mut offset = 0usize;
    let mut remaining = len;

    while remaining > 3 {
        a = a.wrapping_add(read_u32_le(value, offset));
        b = b.wrapping_add(read_u32_le(value, offset + 4));
        c = c.wrapping_add(read_u32_le(value, offset + 8));
        jhash_mix(&mut a, &mut b, &mut c);
        remaining -= 3;
        offset += 12;
    }

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
        _ => return c,
    }

    jhash_final(&mut a, &mut b, &mut c);
    c
}

/// Jenkins hash for arbitrary byte sequences (jhash).
fn jhash(value: &[u8], initval: u32) -> u32 {
    let len = value.len() as u32;
    let mut a: u32 = JHASH_INITVAL.wrapping_add(len).wrapping_add(initval);
    let mut b: u32 = a;
    let mut c: u32 = a;

    let mut offset = 0usize;
    let mut remaining = value.len();

    while remaining > 12 {
        a = a.wrapping_add(read_u32_le(value, offset));
        b = b.wrapping_add(read_u32_le(value, offset + 4));
        c = c.wrapping_add(read_u32_le(value, offset + 8));
        jhash_mix(&mut a, &mut b, &mut c);
        remaining -= 12;
        offset += 12;
    }

    // Handle the last up to 12 bytes using the kernel jhash byte pattern.
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
// Byte-reading helpers
// ---------------------------------------------------------------------------

/// Read a u32 from a byte slice at the given offset (little-endian).
///
/// Returns 0 for out-of-bounds bytes (defensive, should not occur with
/// correct callers).
#[inline(always)]
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    let b0 = data.get(offset).copied().unwrap_or(0) as u32;
    let b1 = data.get(offset + 1).copied().unwrap_or(0) as u32;
    let b2 = data.get(offset + 2).copied().unwrap_or(0) as u32;
    let b3 = data.get(offset + 3).copied().unwrap_or(0) as u32;
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

/// Read a single byte from a slice at the given offset.
///
/// Returns 0 if out of bounds.
#[inline(always)]
fn read_byte(data: &[u8], offset: usize) -> u8 {
    data.get(offset).copied().unwrap_or(0)
}
