// SPDX-License-Identifier: GPL-2.0
//! BPF map ops registration for Rust map implementations.
//!
//! This module defines the [`BpfMapOps`] struct and static instances for each
//! Rust-implemented BPF map type. The kernel's `bpf_map_ops` dispatch table
//! uses these to route map operations to the corresponding Rust FFI wrapper
//! functions.
//!
//! # Layout
//!
//! The [`BpfMapOps`] struct captures the essential subset of `struct bpf_map_ops`
//! fields that our Rust map implementations provide. Function pointers for
//! operations not supported by a given map type are set to `None`.
//!
//! # Linkage
//!
//! Each static ops struct is `#[no_mangle] pub static` so the linker
//! exposes it with a C-compatible symbol name for kernel registration.
//!
//! # Extending
//!
//! To add support for additional operations (e.g., `map_mem_usage`,
//! `map_btf_id`, `map_check_btf`), add the corresponding function pointer
//! field to [`BpfMapOps`] and update each static instance.

use core::ffi::{c_long, c_void};
use crate::bindings::{bpf_attr, bpf_map};

// ---------------------------------------------------------------------------
// Function pointer type aliases matching the kernel's bpf_map_ops signatures.
//
// These use `*mut bpf_map` and `*mut c_void` for pointer arguments, matching
// the kernel C signatures exactly. The kernel always passes mutable pointers
// even for read-only operations.
// ---------------------------------------------------------------------------

/// `struct bpf_map *(*map_alloc)(union bpf_attr *attr)`
pub type MapAllocFn = unsafe extern "C" fn(attr: *const bpf_attr) -> *mut bpf_map;

/// `void (*map_free)(struct bpf_map *map)`
pub type MapFreeFn = unsafe extern "C" fn(map: *mut bpf_map);

/// `void *(*map_lookup_elem)(struct bpf_map *map, void *key)`
pub type MapLookupElemFn = unsafe extern "C" fn(
    map: *mut bpf_map,
    key: *mut c_void,
) -> *mut c_void;

/// `long (*map_update_elem)(struct bpf_map *map, void *key, void *value, u64 flags)`
pub type MapUpdateElemFn = unsafe extern "C" fn(
    map: *mut bpf_map,
    key: *mut c_void,
    value: *mut c_void,
    flags: u64,
) -> c_long;

/// `long (*map_delete_elem)(struct bpf_map *map, void *key)`
pub type MapDeleteElemFn = unsafe extern "C" fn(
    map: *mut bpf_map,
    key: *mut c_void,
) -> c_long;

/// `int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key)`
pub type MapGetNextKeyFn = unsafe extern "C" fn(
    map: *mut bpf_map,
    key: *mut c_void,
    next_key: *mut c_void,
) -> c_long;

/// `long (*map_push_elem)(struct bpf_map *map, void *value, u64 flags)`
pub type MapPushElemFn = unsafe extern "C" fn(
    map: *mut bpf_map,
    value: *mut c_void,
    flags: u64,
) -> c_long;

/// `long (*map_pop_elem)(struct bpf_map *map, void *value)`
pub type MapPopElemFn = unsafe extern "C" fn(
    map: *mut bpf_map,
    value: *mut c_void,
) -> c_long;

/// `long (*map_peek_elem)(struct bpf_map *map, void *value)`
pub type MapPeekElemFn = unsafe extern "C" fn(
    map: *mut bpf_map,
    value: *mut c_void,
) -> c_long;

// ---------------------------------------------------------------------------
// BpfMapOps struct — simplified subset of kernel's struct bpf_map_ops
// ---------------------------------------------------------------------------

/// Simplified representation of `struct bpf_map_ops` containing the
/// essential operation function pointers for BPF map dispatch.
///
/// This struct uses `Option<fn>` for each operation slot. `None` indicates
/// the operation is not supported by the map type. The kernel dispatcher
/// checks for null function pointers before invoking them.
///
/// # Binary Compatibility
///
/// `#[repr(C)]` ensures the layout is compatible with C code that reads
/// function pointers from this struct. Each `Option<fn>` is guaranteed to
/// be pointer-sized (null for `None`, function address for `Some`).
#[repr(C)]
pub struct BpfMapOps {
    /// Allocate and initialize a new map instance.
    pub map_alloc: Option<MapAllocFn>,
    /// Free a map and all associated resources.
    pub map_free: Option<MapFreeFn>,
    /// Look up an element by key (returns pointer to value or null).
    pub map_lookup_elem: Option<MapLookupElemFn>,
    /// Update or insert an element by key.
    pub map_update_elem: Option<MapUpdateElemFn>,
    /// Delete an element by key.
    pub map_delete_elem: Option<MapDeleteElemFn>,
    /// Get the next key for map iteration.
    pub map_get_next_key: Option<MapGetNextKeyFn>,
    /// Push an element (for queue/stack/bloom filter maps).
    pub map_push_elem: Option<MapPushElemFn>,
    /// Pop an element (for queue/stack maps).
    pub map_pop_elem: Option<MapPopElemFn>,
    /// Peek at an element without removing it (for queue/stack/bloom maps).
    pub map_peek_elem: Option<MapPeekElemFn>,
}

// Safety: BpfMapOps contains only function pointers (no mutable state).
// Static instances are read-only after initialization and can be shared
// across threads safely.
unsafe impl Sync for BpfMapOps {}

// ===========================================================================
// Trampoline adapters for array map operations.
//
// The array map FFI wrappers in ffi_wrappers.rs use `*const bpf_map` and
// `*const c_void` for some parameters, but the kernel's bpf_map_ops
// uniformly passes `*mut`. These thin adapters bridge the const/mut gap.
// ===========================================================================

/// Adapter: casts mutable pointers to const for `array_map_lookup_elem_rs`.
///
/// # Safety
///
/// Same preconditions as [`crate::ffi_wrappers::array_map_lookup_elem_rs`].
#[no_mangle]
pub unsafe extern "C" fn array_map_lookup_elem_ops(
    map: *mut bpf_map,
    key: *mut c_void,
) -> *mut c_void {
    crate::ffi_wrappers::array_map_lookup_elem_rs(
        map as *const bpf_map,
        key as *const c_void,
    )
}

/// Adapter: casts mutable pointers to const for `array_map_update_elem_rs`.
///
/// # Safety
///
/// Same preconditions as [`crate::ffi_wrappers::array_map_update_elem_rs`].
#[no_mangle]
pub unsafe extern "C" fn array_map_update_elem_ops(
    map: *mut bpf_map,
    key: *mut c_void,
    value: *mut c_void,
    flags: u64,
) -> c_long {
    crate::ffi_wrappers::array_map_update_elem_rs(
        map as *const bpf_map,
        key as *const c_void,
        value as *const c_void,
        flags,
    )
}

/// Adapter: casts mutable pointers to const for `array_map_delete_elem_rs`.
///
/// # Safety
///
/// Same preconditions as [`crate::ffi_wrappers::array_map_delete_elem_rs`].
#[no_mangle]
pub unsafe extern "C" fn array_map_delete_elem_ops(
    map: *mut bpf_map,
    key: *mut c_void,
) -> c_long {
    crate::ffi_wrappers::array_map_delete_elem_rs(
        map as *const bpf_map,
        key as *const c_void,
    )
}

/// Adapter: casts mutable pointers to const for `array_map_get_next_key_rs`.
///
/// # Safety
///
/// Same preconditions as [`crate::ffi_wrappers::array_map_get_next_key_rs`].
#[no_mangle]
pub unsafe extern "C" fn array_map_get_next_key_ops(
    map: *mut bpf_map,
    key: *mut c_void,
    next_key: *mut c_void,
) -> c_long {
    crate::ffi_wrappers::array_map_get_next_key_rs(
        map as *const bpf_map,
        key as *const c_void,
        next_key,
    )
}

// ===========================================================================
// Static bpf_map_ops instances for each map type
// ===========================================================================

/// BPF map ops for the Rust bloom filter implementation.
///
/// Bloom filters support:
/// - `alloc` / `free` — lifecycle management
/// - `push_elem` — insert a value (set hash bits)
/// - `peek_elem` — query membership (check hash bits)
/// - `get_next_key` — always returns -EOPNOTSUPP (no key iteration)
///
/// They do NOT support `lookup_elem`, `update_elem`, or `delete_elem`.
#[no_mangle]
pub static bloom_map_ops_rs: BpfMapOps = BpfMapOps {
    map_alloc: Some(crate::ffi_wrappers::bloom_map_alloc_rs),
    map_free: Some(crate::ffi_wrappers::bloom_map_free_rs),
    map_lookup_elem: None,
    map_update_elem: None,
    map_delete_elem: None,
    map_get_next_key: Some(crate::ffi_wrappers::bloom_map_get_next_key_rs),
    map_push_elem: Some(crate::ffi_wrappers::bloom_map_push_elem_rs),
    map_pop_elem: None,
    map_peek_elem: Some(crate::ffi_wrappers::bloom_map_peek_elem_rs),
};

/// BPF map ops for the Rust queue map implementation (FIFO).
///
/// Queue maps support:
/// - `alloc` / `free` — lifecycle management
/// - `push_elem` — enqueue a value
/// - `pop_elem` — dequeue the oldest value (FIFO)
/// - `peek_elem` — peek at the oldest value without removing
///
/// They do NOT support `lookup_elem`, `update_elem`, `delete_elem`,
/// or `get_next_key`.
#[no_mangle]
pub static queue_map_ops_rs: BpfMapOps = BpfMapOps {
    map_alloc: Some(crate::ffi_wrappers::queue_stack_map_alloc_rs),
    map_free: Some(crate::ffi_wrappers::queue_stack_map_free_rs),
    map_lookup_elem: None,
    map_update_elem: None,
    map_delete_elem: None,
    map_get_next_key: None,
    map_push_elem: Some(crate::ffi_wrappers::queue_map_push_elem_rs),
    map_pop_elem: Some(crate::ffi_wrappers::queue_map_pop_elem_rs),
    map_peek_elem: Some(crate::ffi_wrappers::queue_map_peek_elem_rs),
};

/// BPF map ops for the Rust stack map implementation (LIFO).
///
/// Stack maps share allocation/free with queue maps but use LIFO
/// pop/peek semantics:
/// - `alloc` / `free` — lifecycle management (same as queue)
/// - `push_elem` — push a value onto the stack
/// - `pop_elem` — pop the most recent value (LIFO)
/// - `peek_elem` — peek at the most recent value without removing
///
/// They do NOT support `lookup_elem`, `update_elem`, `delete_elem`,
/// or `get_next_key`.
#[no_mangle]
pub static stack_map_ops_rs: BpfMapOps = BpfMapOps {
    map_alloc: Some(crate::ffi_wrappers::queue_stack_map_alloc_rs),
    map_free: Some(crate::ffi_wrappers::queue_stack_map_free_rs),
    map_lookup_elem: None,
    map_update_elem: None,
    map_delete_elem: None,
    map_get_next_key: None,
    map_push_elem: Some(crate::ffi_wrappers::queue_map_push_elem_rs),
    map_pop_elem: Some(crate::ffi_wrappers::stack_map_pop_elem_rs),
    map_peek_elem: Some(crate::ffi_wrappers::stack_map_peek_elem_rs),
};

/// BPF map ops for the Rust array map implementation.
///
/// Array maps support:
/// - `alloc` / `free` — lifecycle management
/// - `lookup_elem` — look up by index (u32 key)
/// - `update_elem` — update value at index
/// - `delete_elem` — always returns -EINVAL (cannot delete from array)
/// - `get_next_key` — iterate indices sequentially
#[no_mangle]
pub static array_map_ops_rs: BpfMapOps = BpfMapOps {
    map_alloc: Some(crate::ffi_wrappers::array_map_alloc_rs),
    map_free: Some(crate::ffi_wrappers::array_map_free_rs),
    map_lookup_elem: Some(array_map_lookup_elem_ops),
    map_update_elem: Some(array_map_update_elem_ops),
    map_delete_elem: Some(array_map_delete_elem_ops),
    map_get_next_key: Some(array_map_get_next_key_ops),
    map_push_elem: None,
    map_pop_elem: None,
    map_peek_elem: None,
};

/// BPF map ops for the Rust LPM (Longest Prefix Match) trie implementation.
///
/// LPM trie maps support:
/// - `alloc` / `free` — lifecycle management
/// - `lookup_elem` — longest prefix match lookup
/// - `update_elem` — insert or replace a prefix
/// - `delete_elem` — delete an exact prefix match
/// - `get_next_key` — post-order traversal iteration
#[no_mangle]
pub static trie_map_ops_rs: BpfMapOps = BpfMapOps {
    map_alloc: Some(crate::ffi_wrappers::trie_alloc_rs),
    map_free: Some(crate::ffi_wrappers::trie_free_rs),
    map_lookup_elem: Some(crate::ffi_wrappers::trie_lookup_elem_rs),
    map_update_elem: Some(crate::ffi_wrappers::trie_update_elem_rs),
    map_delete_elem: Some(crate::ffi_wrappers::trie_delete_elem_rs),
    map_get_next_key: Some(crate::ffi_wrappers::trie_get_next_key_rs),
    map_push_elem: None,
    map_pop_elem: None,
    map_peek_elem: None,
};

/// BPF map ops for the Rust ring buffer implementation.
///
/// Ring buffer maps support:
/// - `alloc` / `free` — lifecycle management
///
/// Ring buffer data operations (reserve/submit/discard/output) are
/// invoked through BPF helper function dispatch, not through the
/// standard `bpf_map_ops` table. The ops struct provides only lifecycle
/// management. Lookup/update/delete are not applicable.
#[no_mangle]
pub static ringbuf_map_ops_rs: BpfMapOps = BpfMapOps {
    map_alloc: Some(crate::ffi_wrappers::ringbuf_alloc_rs),
    map_free: Some(crate::ffi_wrappers::ringbuf_free_rs),
    map_lookup_elem: None,
    map_update_elem: None,
    map_delete_elem: None,
    map_get_next_key: None,
    map_push_elem: None,
    map_pop_elem: None,
    map_peek_elem: None,
};

/// BPF map ops for the Rust hash table implementation.
///
/// Hash table maps support:
/// - `alloc` / `free` — lifecycle management
/// - `lookup_elem` — look up by key hash
/// - `update_elem` — insert or update a key-value pair
/// - `delete_elem` — remove a key-value pair
/// - `get_next_key` — iterate over all keys
#[no_mangle]
pub static htab_map_ops_rs: BpfMapOps = BpfMapOps {
    map_alloc: Some(crate::ffi_wrappers::htab_map_alloc_rs),
    map_free: Some(crate::ffi_wrappers::htab_map_free_rs),
    map_lookup_elem: Some(crate::ffi_wrappers::htab_map_lookup_elem_rs),
    map_update_elem: Some(crate::ffi_wrappers::htab_map_update_elem_rs),
    map_delete_elem: Some(crate::ffi_wrappers::htab_map_delete_elem_rs),
    map_get_next_key: Some(crate::ffi_wrappers::htab_map_get_next_key_rs),
    map_push_elem: None,
    map_pop_elem: None,
    map_peek_elem: None,
};
