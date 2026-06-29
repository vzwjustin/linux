// SPDX-License-Identifier: GPL-2.0
//! FFI wrapper layer for BPF map Rust implementations.
//!
//! This module provides the `extern "C"` entry points that C callers
//! (specifically `bpf_map_ops` dispatch) use to invoke Rust map
//! implementations. Each wrapper function:
//!
//! 1. Validates pointer arguments for null (returning `-EINVAL` if null).
//! 2. Calls the inner safe Rust implementation.
//! 3. Converts the Rust `Result<(), Error>` return value to a `c_long`
//!    (0 for `Ok`, negative errno for `Err`).
//!
//! All functions use `#[no_mangle] pub unsafe extern "C"` convention so
//! that the linker exposes them with C-compatible names and calling
//! convention.
//!
//! # Macros
//!
//! - `check_null!`: Validates one or more pointer arguments, returning
//!   `-EINVAL` immediately if any is null.
//!
//! # Helpers
//!
//! - [`result_to_errno`]: Converts `Result<(), Error>` to `core::ffi::c_long`.
//!
//! # Safety Policy
//!
//! These wrappers are the *only* place where raw C pointers cross into
//! Rust code. The macros and helpers ensure that null pointers are
//! rejected at the boundary before any dereference can occur.

use core::ffi::c_long;

// Error is used by the check_null! macro expansion and by wrapper functions
// added in later tasks (6.3, 7.2, 8.2, etc.).
#[allow(unused_imports)]
use crate::error::Error;

/// Validate that one or more pointer expressions are non-null.
///
/// If any pointer is null, the macro causes the enclosing function to
/// return `-EINVAL` as a `c_long`. This prevents null dereferences at the
/// FFI boundary before invoking the inner Rust implementation.
///
/// # Usage
///
/// ```ignore
/// check_null!(map, key, value);
/// ```
///
/// expands roughly to:
///
/// ```ignore
/// if map.is_null() || key.is_null() || value.is_null() {
///     return Error::EINVAL.to_errno() as c_long;
/// }
/// ```
#[macro_export]
macro_rules! check_null {
    ($($ptr:expr),+ $(,)?) => {
        if $( $ptr.is_null() )||+ {
            return $crate::error::Error::EINVAL.to_errno() as ::core::ffi::c_long;
        }
    };
}

/// Convert a `Result<(), Error>` to a `c_long` suitable for returning to
/// C callers.
///
/// - `Ok(())` → `0`
/// - `Err(e)` → negative errno (e.g., `-2` for `ENOENT`, `-12` for `ENOMEM`)
///
/// This is the standard return-value conversion used by all FFI wrapper
/// functions in this module.
///
/// # Examples
///
/// ```ignore
/// let ret = result_to_errno(Ok(()));
/// assert_eq!(ret, 0);
///
/// let ret = result_to_errno(Err(Error::ENOENT));
/// assert_eq!(ret, -2);
/// ```
#[inline]
pub fn result_to_errno(result: crate::error::Result<()>) -> c_long {
    match result {
        Ok(()) => 0,
        Err(e) => e.to_errno() as c_long,
    }
}

/// Convert a `Result<c_long, Error>` to a `c_long`, passing through the
/// success value or mapping the error to a negative errno.
///
/// Use this variant for operations that return a meaningful non-zero value
/// on success (e.g., number of bytes copied).
///
/// - `Ok(n)` → `n`
/// - `Err(e)` → negative errno
#[inline]
pub fn result_value_to_errno(result: crate::error::Result<c_long>) -> c_long {
    match result {
        Ok(v) => v,
        Err(e) => e.to_errno() as c_long,
    }
}

// ===========================================================================
// Bloom Filter FFI Wrappers (Task 6.3)
// ===========================================================================

/// FFI entry point for `bloom_map_peek_elem`.
///
/// Checks if a value might be in the bloom filter. Returns 0 if all hash
/// bits are set (probably in set), or -ENOENT if any bit is unset
/// (definitely not in set).
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is the first field
///   of a `BpfBloomFilter` allocation.
/// - `value` must point to a readable buffer of at least `map.value_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn bloom_map_peek_elem_rs(
    map: *mut crate::bindings::bpf_map,
    value: *mut core::ffi::c_void,
) -> c_long {
    check_null!(map, value);
    // SAFETY: map and value are non-null (checked above). Kernel guarantees
    // map points to a valid bpf_map within a BpfBloomFilter allocation and
    // value has at least map.value_size readable bytes.
    result_to_errno(crate::bloom_filter::peek_elem(&*map, value as *const core::ffi::c_void))
}

/// FFI entry point for `bloom_map_push_elem`.
///
/// Inserts a value into the bloom filter by setting all hash bit positions.
/// `flags` must be `BPF_ANY` (0); any other value returns -EINVAL.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is the first field
///   of a `BpfBloomFilter` allocation.
/// - `value` must point to a readable buffer of at least `map.value_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn bloom_map_push_elem_rs(
    map: *mut crate::bindings::bpf_map,
    value: *mut core::ffi::c_void,
    flags: u64,
) -> c_long {
    check_null!(map, value);
    // SAFETY: map and value are non-null (checked above). Kernel guarantees
    // map points to a valid bpf_map within a BpfBloomFilter allocation and
    // value has at least map.value_size readable bytes.
    result_to_errno(crate::bloom_filter::push_elem(
        &*map,
        value as *const core::ffi::c_void,
        flags,
    ))
}

/// FFI entry point for `bloom_map_alloc`.
///
/// Allocates and initializes a new BPF bloom filter map from the given
/// attributes. Returns a pointer to the `bpf_map` field of the new
/// allocation, or an ERR_PTR-encoded errno on failure.
///
/// # Safety
///
/// - `attr` must be a valid pointer to a `bpf_attr` populated for a
///   BPF_MAP_CREATE command.
#[no_mangle]
pub unsafe extern "C" fn bloom_map_alloc_rs(
    attr: *const crate::bindings::bpf_attr,
) -> *mut crate::bindings::bpf_map {
    if attr.is_null() {
        return Error::EINVAL.to_errno() as isize as *mut crate::bindings::bpf_map;
    }
    // SAFETY: attr is non-null (checked above). Kernel guarantees attr
    // points to a valid bpf_attr populated for BPF_MAP_CREATE.
    match crate::bloom_filter::bloom_map_alloc(attr) {
        Ok(map_ptr) => map_ptr,
        Err(e) => {
            // Return ERR_PTR(errno): kernel convention for map_alloc failure.
            e.to_errno() as isize as *mut crate::bindings::bpf_map
        }
    }
}

/// FFI entry point for `bloom_map_free`.
///
/// Frees a BPF bloom filter map previously allocated by `bloom_map_alloc_rs`.
/// This is a void function that performs no action if `map` is null.
///
/// # Safety
///
/// - `map` must be either null or a valid pointer to the `bpf_map` field of
///   a `BpfBloomFilter` that was allocated by [`bloom_map_alloc_rs`].
/// - Must not be called more than once for the same map.
#[no_mangle]
pub unsafe extern "C" fn bloom_map_free_rs(map: *mut crate::bindings::bpf_map) {
    if map.is_null() {
        return;
    }
    // SAFETY: map is non-null (checked above). Kernel guarantees map points
    // to a valid bpf_map within a BpfBloomFilter allocation created by alloc.
    crate::bloom_filter::bloom_map_free(map);
}

/// FFI entry point for `bloom_map_get_next_key`.
///
/// Bloom filters do not support key iteration. This always returns
/// -EOPNOTSUPP.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map`.
/// - `key` and `next_key` are unused but `map` is validated for null.
#[no_mangle]
pub unsafe extern "C" fn bloom_map_get_next_key_rs(
    map: *mut crate::bindings::bpf_map,
    key: *mut core::ffi::c_void,
    next_key: *mut core::ffi::c_void,
) -> c_long {
    check_null!(map);
    // SAFETY: map is non-null (checked above). key and next_key are unused
    // by the implementation since bloom filters don't support iteration.
    result_to_errno(crate::bloom_filter::bloom_map_get_next_key(
        map as *const crate::bindings::bpf_map,
        key as *const core::ffi::c_void,
        next_key,
    ))
}

// ---------------------------------------------------------------------------
// Array Map FFI wrapper functions (Task 8.2)
// ---------------------------------------------------------------------------

/// FFI entry point for `array_map_lookup_elem`.
///
/// Validates pointer arguments, calls the inner Rust implementation, and
/// returns a pointer to the element or null on failure.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` allocated by the kernel
///   that is part of a `BpfArray` allocation.
/// - `key` must point to at least 4 bytes (a `u32` index).
#[no_mangle]
pub unsafe extern "C" fn array_map_lookup_elem_rs(
    map: *const crate::bindings::bpf_map,
    key: *const core::ffi::c_void,
) -> *mut core::ffi::c_void {
    if map.is_null() || key.is_null() {
        return core::ptr::null_mut();
    }
    // Safety: map and key are non-null (checked above). Kernel guarantees
    // map points to a valid bpf_map within a BpfArray, key has sufficient size.
    crate::arraymap::array_map_lookup_elem(map, key)
}

/// FFI entry point for `array_map_update_elem`.
///
/// Validates pointer arguments, calls the inner Rust implementation, and
/// converts the Result to a c_long errno.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is part of a `BpfArray`.
/// - `key` must point to at least 4 bytes (a `u32` index).
/// - `value` must point to at least `map.value_size` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn array_map_update_elem_rs(
    map: *const crate::bindings::bpf_map,
    key: *const core::ffi::c_void,
    value: *const core::ffi::c_void,
    flags: u64,
) -> c_long {
    check_null!(map, key, value);
    // Safety: map, key, and value are non-null (checked above). Kernel guarantees
    // map points to a valid bpf_map within a BpfArray, key and value have
    // sufficient sizes.
    result_to_errno(crate::arraymap::array_map_update_elem(map, key, value, flags))
}

/// FFI entry point for `array_map_delete_elem`.
///
/// Validates pointer arguments and calls the inner Rust implementation.
/// For array maps, delete always returns -EINVAL.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map`.
/// - `key` must point to at least 4 bytes.
#[no_mangle]
pub unsafe extern "C" fn array_map_delete_elem_rs(
    map: *const crate::bindings::bpf_map,
    key: *const core::ffi::c_void,
) -> c_long {
    check_null!(map, key);
    // Safety: map and key are non-null (checked above). The delete function
    // does not dereference them for array maps (always returns EINVAL).
    result_to_errno(crate::arraymap::array_map_delete_elem(map, key))
}

/// FFI entry point for `array_map_alloc`.
///
/// Validates the attr pointer, calls the inner Rust implementation, and
/// returns a pointer to the newly allocated `bpf_map` or a null pointer
/// on failure.
///
/// # Safety
///
/// - `attr` must be a valid pointer to a `bpf_attr` populated for a
///   `BPF_MAP_CREATE` command.
#[no_mangle]
pub unsafe extern "C" fn array_map_alloc_rs(
    attr: *const crate::bindings::bpf_attr,
) -> *mut crate::bindings::bpf_map {
    if attr.is_null() {
        return core::ptr::null_mut();
    }
    // Safety: attr is non-null (checked above). Kernel guarantees it points
    // to a valid bpf_attr for map creation.
    match crate::arraymap::array_map_alloc(attr) {
        Ok(map_ptr) => map_ptr,
        Err(_) => core::ptr::null_mut(),
    }
}

/// FFI entry point for `array_map_free`.
///
/// Validates the map pointer and calls the inner Rust implementation to
/// free all memory associated with the array map.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that was previously
///   returned by `array_map_alloc_rs`.
/// - The map must not be accessed after this call.
#[no_mangle]
pub unsafe extern "C" fn array_map_free_rs(map: *mut crate::bindings::bpf_map) {
    if map.is_null() {
        return;
    }
    // Safety: map is non-null (checked above). Caller guarantees it was
    // allocated by array_map_alloc and has not been freed yet.
    crate::arraymap::array_map_free(map);
}

/// FFI entry point for `array_map_get_next_key`.
///
/// Validates pointer arguments, calls the inner Rust implementation, and
/// converts the Result to a c_long errno.
///
/// Note: `key` may be null (indicating start of iteration), so only
/// `next_key` is null-checked.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is part of a `BpfArray`.
/// - If `key` is non-null, it must point to at least 4 readable bytes.
/// - `next_key` must point to at least 4 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn array_map_get_next_key_rs(
    map: *const crate::bindings::bpf_map,
    key: *const core::ffi::c_void,
    next_key: *mut core::ffi::c_void,
) -> c_long {
    if map.is_null() || next_key.is_null() {
        return Error::EINVAL.to_errno() as c_long;
    }
    // Safety: map and next_key are non-null (checked above). key may be null
    // (handled by the inner function as "start of iteration"). Kernel guarantees
    // valid pointer sizes.
    result_to_errno(crate::arraymap::array_map_get_next_key(map, key, next_key))
}



// ---------------------------------------------------------------------------
// Queue/Stack Map FFI Wrappers (Task 7.2)
// ---------------------------------------------------------------------------

/// FFI entry point for `queue_stack_map_push_elem`.
///
/// Shared by both queue and stack map types — the push operation is
/// identical (write at head, advance head). Validates pointer arguments,
/// then delegates to the Rust implementation.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is the first field
///   of a `BpfQueueStack` allocated by `queue_stack_map_alloc`.
/// - `value` must point to a readable buffer of at least `map.value_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn queue_map_push_elem_rs(
    map: *mut crate::bindings::bpf_map,
    value: *mut core::ffi::c_void,
    flags: u64,
) -> c_long {
    check_null!(map, value);
    // Safety: map and value are non-null (checked above). The kernel guarantees
    // map is a valid bpf_map within a BpfQueueStack allocation, and value has
    // at least map.value_size readable bytes. We cast map to BpfQueueStack*
    // since the map field is at offset 0 (container_of pattern).
    let qs = map as *mut crate::queue_stack_maps::BpfQueueStack;
    result_to_errno(crate::queue_stack_maps::queue_stack_push_elem(
        qs,
        value as *const core::ffi::c_void,
        flags,
    ))
}

/// FFI entry point for `queue_map_pop_elem`.
///
/// Pops the oldest element from the queue (FIFO order).
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within a `BpfQueueStack`.
/// - `value` must point to a writable buffer of at least `map.value_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn queue_map_pop_elem_rs(
    map: *mut crate::bindings::bpf_map,
    value: *mut core::ffi::c_void,
) -> c_long {
    check_null!(map, value);
    // Safety: map and value are non-null. Kernel guarantees map points to a
    // valid BpfQueueStack and value has sufficient writable space.
    let qs = map as *mut crate::queue_stack_maps::BpfQueueStack;
    result_to_errno(crate::queue_stack_maps::queue_pop_elem(qs, value))
}

/// FFI entry point for `queue_map_peek_elem`.
///
/// Peeks at the oldest element in the queue without removing it (FIFO order).
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within a `BpfQueueStack`.
/// - `value` must point to a writable buffer of at least `map.value_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn queue_map_peek_elem_rs(
    map: *mut crate::bindings::bpf_map,
    value: *mut core::ffi::c_void,
) -> c_long {
    check_null!(map, value);
    // Safety: map and value are non-null. Kernel guarantees valid BpfQueueStack.
    let qs = map as *mut crate::queue_stack_maps::BpfQueueStack;
    result_to_errno(crate::queue_stack_maps::queue_peek_elem(qs, value))
}

/// FFI entry point for `stack_map_pop_elem`.
///
/// Pops the most recently pushed element from the stack (LIFO order).
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within a `BpfQueueStack`.
/// - `value` must point to a writable buffer of at least `map.value_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn stack_map_pop_elem_rs(
    map: *mut crate::bindings::bpf_map,
    value: *mut core::ffi::c_void,
) -> c_long {
    check_null!(map, value);
    // Safety: map and value are non-null. Kernel guarantees valid BpfQueueStack.
    let qs = map as *mut crate::queue_stack_maps::BpfQueueStack;
    result_to_errno(crate::queue_stack_maps::stack_pop_elem(qs, value))
}

/// FFI entry point for `stack_map_peek_elem`.
///
/// Peeks at the most recently pushed element without removing it (LIFO order).
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within a `BpfQueueStack`.
/// - `value` must point to a writable buffer of at least `map.value_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn stack_map_peek_elem_rs(
    map: *mut crate::bindings::bpf_map,
    value: *mut core::ffi::c_void,
) -> c_long {
    check_null!(map, value);
    // Safety: map and value are non-null. Kernel guarantees valid BpfQueueStack.
    let qs = map as *mut crate::queue_stack_maps::BpfQueueStack;
    result_to_errno(crate::queue_stack_maps::stack_peek_elem(qs, value))
}

/// FFI entry point for `queue_stack_map_alloc`.
///
/// Allocates and initializes a new queue or stack map from the given
/// attributes. Returns a pointer to the embedded `bpf_map` on success,
/// or an ERR_PTR-encoded error code on failure.
///
/// # Safety
///
/// - `attr` must point to a valid `bpf_attr` populated for BPF_MAP_CREATE.
#[no_mangle]
pub unsafe extern "C" fn queue_stack_map_alloc_rs(
    attr: *const crate::bindings::bpf_attr,
) -> *mut crate::bindings::bpf_map {
    if attr.is_null() {
        // Return ERR_PTR(-EINVAL) for null attr.
        return Error::EINVAL.to_errno() as isize as *mut crate::bindings::bpf_map;
    }
    // Safety: attr is non-null (checked above). Kernel guarantees it points to
    // a valid bpf_attr for BPF_MAP_CREATE.
    match crate::queue_stack_maps::queue_stack_map_alloc(attr) {
        Ok(map_ptr) => map_ptr,
        Err(e) => {
            // Return ERR_PTR(errno) — the kernel expects alloc functions to
            // return error pointers on failure, not NULL.
            e.to_errno() as isize as *mut crate::bindings::bpf_map
        }
    }
}

/// FFI entry point for `queue_stack_map_free`.
///
/// Frees a queue/stack map previously allocated by `queue_stack_map_alloc_rs`.
/// Called when the map's reference count reaches zero.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within a `BpfQueueStack`
///   that was allocated by `queue_stack_map_alloc`.
/// - Must not be called more than once for the same map.
#[no_mangle]
pub unsafe extern "C" fn queue_stack_map_free_rs(
    map: *mut crate::bindings::bpf_map,
) {
    if map.is_null() {
        return;
    }
    // Safety: map is non-null (checked above). Kernel guarantees it was
    // allocated by queue_stack_map_alloc and has not been freed yet.
    crate::queue_stack_maps::queue_stack_map_free(map);
}

// ===========================================================================
// LPM Trie FFI Wrappers (Task 10.2)
// ===========================================================================

/// FFI entry point for `trie_lookup_elem`.
///
/// Looks up the longest matching prefix in the LPM trie for the given key.
/// Returns a pointer to the value of the best match, or null if no match.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is the first field
///   of an `LpmTrie` allocation.
/// - `key` must point to a readable LPM key (`{ u32 prefixlen; u8 data[]; }`).
#[no_mangle]
pub unsafe extern "C" fn trie_lookup_elem_rs(
    map: *mut crate::bindings::bpf_map,
    key: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    if map.is_null() || key.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: map and key are non-null (checked above). Kernel guarantees
    // map points to a valid bpf_map within an LpmTrie allocation and key
    // has at least key_size readable bytes.
    crate::lpm_trie::trie_lookup_elem(
        map as *const crate::bindings::bpf_map,
        key as *const core::ffi::c_void,
    )
}

/// FFI entry point for `trie_update_elem`.
///
/// Inserts or updates an element in the LPM trie. Validates pointer
/// arguments, delegates to the Rust implementation, and returns errno.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within an `LpmTrie`.
/// - `key` must point to a readable LPM key with at least `key_size` bytes.
/// - `value` must point to at least `map.value_size` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn trie_update_elem_rs(
    map: *mut crate::bindings::bpf_map,
    key: *mut core::ffi::c_void,
    value: *mut core::ffi::c_void,
    flags: u64,
) -> c_long {
    check_null!(map, key, value);
    // SAFETY: map, key, and value are non-null (checked above). Kernel
    // guarantees valid pointers with sufficient sizes.
    result_to_errno(crate::lpm_trie::trie_update_elem(
        map,
        key as *const core::ffi::c_void,
        value as *const core::ffi::c_void,
        flags,
    ))
}

/// FFI entry point for `trie_delete_elem`.
///
/// Deletes the element with the exact matching prefix from the LPM trie.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within an `LpmTrie`.
/// - `key` must point to a readable LPM key with at least `key_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn trie_delete_elem_rs(
    map: *mut crate::bindings::bpf_map,
    key: *mut core::ffi::c_void,
) -> c_long {
    check_null!(map, key);
    // SAFETY: map and key are non-null (checked above). Kernel guarantees
    // valid pointers with sufficient sizes.
    result_to_errno(crate::lpm_trie::trie_delete_elem(
        map,
        key as *const core::ffi::c_void,
    ))
}

/// FFI entry point for `trie_alloc`.
///
/// Allocates and initializes a new LPM trie map from the given attributes.
/// Returns a pointer to the `bpf_map` field of the new allocation on
/// success, or an ERR_PTR-encoded errno on failure.
///
/// # Safety
///
/// - `attr` must be a valid pointer to a `bpf_attr` populated for a
///   BPF_MAP_CREATE command.
#[no_mangle]
pub unsafe extern "C" fn trie_alloc_rs(
    attr: *const crate::bindings::bpf_attr,
) -> *mut crate::bindings::bpf_map {
    if attr.is_null() {
        return Error::EINVAL.to_errno() as isize as *mut crate::bindings::bpf_map;
    }
    // SAFETY: attr is non-null (checked above). Kernel guarantees attr
    // points to a valid bpf_attr populated for BPF_MAP_CREATE.
    match crate::lpm_trie::trie_alloc(attr) {
        Ok(map_ptr) => map_ptr,
        Err(e) => {
            // Return ERR_PTR(errno): kernel convention for map_alloc failure.
            e.to_errno() as isize as *mut crate::bindings::bpf_map
        }
    }
}

/// FFI entry point for `trie_free`.
///
/// Frees an LPM trie map and all its nodes, previously allocated by
/// `trie_alloc_rs`. This is a void function that performs no action if
/// `map` is null.
///
/// # Safety
///
/// - `map` must be either null or a valid pointer to the `bpf_map` field
///   of an `LpmTrie` that was allocated by [`trie_alloc_rs`].
/// - Must not be called more than once for the same map.
#[no_mangle]
pub unsafe extern "C" fn trie_free_rs(map: *mut crate::bindings::bpf_map) {
    if map.is_null() {
        return;
    }
    // SAFETY: map is non-null (checked above). Kernel guarantees map points
    // to a valid bpf_map within an LpmTrie allocation created by trie_alloc.
    crate::lpm_trie::trie_free(map);
}

/// FFI entry point for `trie_get_next_key`.
///
/// Returns the next key in post-order traversal of the LPM trie.
/// If `key` is null, returns the leftmost (most specific) key.
///
/// Note: `key` may be null (indicating start of iteration), so only
/// `map` and `next_key` are null-checked.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within an `LpmTrie`.
/// - If `key` is non-null, it must point to at least `key_size` readable bytes.
/// - `next_key` must point to at least `key_size` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn trie_get_next_key_rs(
    map: *mut crate::bindings::bpf_map,
    key: *mut core::ffi::c_void,
    next_key: *mut core::ffi::c_void,
) -> c_long {
    if map.is_null() || next_key.is_null() {
        return Error::EINVAL.to_errno() as c_long;
    }
    // SAFETY: map and next_key are non-null (checked above). key may be null
    // (handled by the inner function as "start of iteration"). Kernel
    // guarantees valid pointer sizes.
    result_to_errno(crate::lpm_trie::trie_get_next_key(
        map as *const crate::bindings::bpf_map,
        key as *const core::ffi::c_void,
        next_key,
    ))
}


// ===========================================================================
// Ring Buffer FFI Wrappers (Task 11.2)
// ===========================================================================

/// FFI entry point for `ringbuf_map_alloc`.
///
/// Allocates and initializes a new BPF ring buffer map from the given
/// attributes. Returns a pointer to the `bpf_map` field of the new
/// allocation, or an ERR_PTR-encoded errno on failure.
///
/// # Safety
///
/// - `attr` must be a valid pointer to a `bpf_attr` populated for a
///   BPF_MAP_CREATE command.
#[no_mangle]
pub unsafe extern "C" fn ringbuf_alloc_rs(
    attr: *const crate::bindings::bpf_attr,
) -> *mut crate::bindings::bpf_map {
    if attr.is_null() {
        return Error::EINVAL.to_errno() as isize as *mut crate::bindings::bpf_map;
    }
    // SAFETY: attr is non-null (checked above). Kernel guarantees attr
    // points to a valid bpf_attr populated for BPF_MAP_CREATE.
    match crate::ringbuf::ringbuf_alloc(attr) {
        Ok(map_ptr) => map_ptr,
        Err(e) => {
            // Return ERR_PTR(errno): kernel convention for map_alloc failure.
            e.to_errno() as isize as *mut crate::bindings::bpf_map
        }
    }
}

/// FFI entry point for `ringbuf_map_free`.
///
/// Frees a BPF ring buffer map previously allocated by `ringbuf_alloc_rs`.
/// This is a void function that performs no action if `map` is null.
///
/// # Safety
///
/// - `map` must be either null or a valid pointer to the `bpf_map` field of
///   a `BpfRingbuf` that was allocated by [`ringbuf_alloc_rs`].
/// - Must not be called more than once for the same map.
#[no_mangle]
pub unsafe extern "C" fn ringbuf_free_rs(map: *mut crate::bindings::bpf_map) {
    if map.is_null() {
        return;
    }
    // SAFETY: map is non-null (checked above). Kernel guarantees map points
    // to a valid bpf_map within a BpfRingbuf allocation created by alloc.
    crate::ringbuf::ringbuf_free(map);
}

/// FFI entry point for `ringbuf_reserve`.
///
/// Reserves contiguous space in the ring buffer for a record of the given
/// size. Returns a pointer to the reserved data area (past the header), or
/// null if the ring buffer is full.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is the first field
///   of a `BpfRingbuf` allocated by `ringbuf_alloc`.
/// - `size` must be > 0 and fit within the ring buffer capacity.
/// - `flags` is reserved and must be 0.
#[no_mangle]
pub unsafe extern "C" fn ringbuf_reserve_rs(
    map: *mut crate::bindings::bpf_map,
    size: u64,
    flags: u64,
) -> *mut core::ffi::c_void {
    if map.is_null() {
        return core::ptr::null_mut();
    }
    if flags != 0 {
        return core::ptr::null_mut();
    }
    if size == 0 {
        return core::ptr::null_mut();
    }

    // SAFETY: map is non-null (checked above). The map field is at offset 0
    // of BpfRingbuf, so we can cast directly (container_of pattern).
    let rb = &*(map as *const crate::ringbuf::BpfRingbuf);

    // SAFETY: BpfRingbuf struct invariants (valid data/producer_pos/consumer_pos)
    // are guaranteed by ringbuf_alloc.
    match rb.reserve(size) {
        Ok(ptr) => ptr as *mut core::ffi::c_void,
        Err(_) => core::ptr::null_mut(),
    }
}

/// FFI entry point for `ringbuf_submit`.
///
/// Submits a previously reserved record, making it visible to consumers.
/// This is a void function.
///
/// # Safety
///
/// - `data_ptr` must have been returned by a prior call to `ringbuf_reserve_rs`
///   on this ring buffer.
/// - The caller must not use `data_ptr` after this call.
/// - `flags` is reserved and currently unused.
#[no_mangle]
pub unsafe extern "C" fn ringbuf_submit_rs(
    data_ptr: *mut core::ffi::c_void,
    flags: u64,
) {
    if data_ptr.is_null() {
        return;
    }
    let _ = flags; // Reserved for future use.

    // To submit, we need a reference to the BpfRingbuf. However, the submit
    // operation only accesses the record header (located before data_ptr),
    // so we can create a minimal BpfRingbuf reference. In practice, the
    // submit/discard operations are self-contained on the header.
    //
    // We use a helper struct with a dummy BpfRingbuf to access the method.
    // Actually, submit() only modifies the header at data_ptr - HDR_SIZE,
    // which doesn't need any fields from BpfRingbuf itself. We can call it
    // on any valid BpfRingbuf reference since it only uses the data_ptr arg.
    //
    // SAFETY: data_ptr was returned by reserve(), so the header at
    // data_ptr - HDR_SIZE is valid and within the ring buffer allocation.
    // We create a zero BpfRingbuf just to call the method (the method doesn't
    // actually read any self fields for submit — it only operates on data_ptr).
    //
    // A cleaner approach: since submit/discard only touch the header relative
    // to data_ptr, we implement them as associated functions that don't need
    // &self. But the existing API uses &self, so we construct a temporary ref.
    //
    // Actually, looking at the submit() implementation, it DOES reference self
    // indirectly... No, it doesn't — it only uses `data_ptr` parameter.
    // The `&self` is just for method dispatch; it doesn't read self fields.
    // So we can safely use any BpfRingbuf pointer.
    //
    // The simplest correct approach: use a static function that operates on
    // the raw pointer directly. Let's call the method through a zero-initialized
    // dummy. This is safe because submit() doesn't dereference self at all.
    //
    // Better: we factor this to call a standalone helper. For now, we inline
    // the submit logic here which is trivial.
    use core::sync::atomic::{AtomicU32, Ordering};
    const BPF_RINGBUF_HDR_SIZE: usize = core::mem::size_of::<crate::ringbuf::BpfRingbufHdr>();
    const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;

    let hdr = {
        // Safety (cast_ptr_alignment): data_ptr was returned by reserve() which
        // ensures BPF_RINGBUF_ALIGN alignment. Subtracting the header size
        // maintains alignment since BPF_RINGBUF_HDR_SIZE is a multiple of 4.
        #[allow(clippy::cast_ptr_alignment)]
        { (data_ptr as *mut u8).sub(BPF_RINGBUF_HDR_SIZE) as *mut crate::ringbuf::BpfRingbufHdr }
    };
    let hdr_len_ptr = &(*hdr).len as *const u32 as *mut u32;
    let atomic_len = AtomicU32::from_ptr(hdr_len_ptr);
    let current_len = atomic_len.load(Ordering::Acquire);
    let new_len = current_len & !BPF_RINGBUF_BUSY_BIT;
    atomic_len.store(new_len, Ordering::Release);
}

/// FFI entry point for `ringbuf_discard`.
///
/// Discards a previously reserved record. Consumers will skip over this
/// record when advancing. This is a void function.
///
/// # Safety
///
/// - `data_ptr` must have been returned by a prior call to `ringbuf_reserve_rs`
///   on this ring buffer.
/// - The caller must not use `data_ptr` after this call.
/// - `flags` is reserved and currently unused.
#[no_mangle]
pub unsafe extern "C" fn ringbuf_discard_rs(
    data_ptr: *mut core::ffi::c_void,
    flags: u64,
) {
    if data_ptr.is_null() {
        return;
    }
    let _ = flags; // Reserved for future use.

    // SAFETY: data_ptr was returned by reserve(), so the header at
    // data_ptr - HDR_SIZE is valid and within the ring buffer allocation.
    use core::sync::atomic::{AtomicU32, Ordering};
    const BPF_RINGBUF_HDR_SIZE: usize = core::mem::size_of::<crate::ringbuf::BpfRingbufHdr>();
    const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
    const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;

    let hdr = {
        // Safety (cast_ptr_alignment): data_ptr was returned by reserve() which
        // ensures BPF_RINGBUF_ALIGN alignment. Subtracting the header size
        // maintains alignment since BPF_RINGBUF_HDR_SIZE is a multiple of 4.
        #[allow(clippy::cast_ptr_alignment)]
        { (data_ptr as *mut u8).sub(BPF_RINGBUF_HDR_SIZE) as *mut crate::ringbuf::BpfRingbufHdr }
    };
    let hdr_len_ptr = &(*hdr).len as *const u32 as *mut u32;
    let atomic_len = AtomicU32::from_ptr(hdr_len_ptr);
    let current_len = atomic_len.load(Ordering::Acquire);
    let new_len = (current_len & !BPF_RINGBUF_BUSY_BIT) | BPF_RINGBUF_DISCARD_BIT;
    atomic_len.store(new_len, Ordering::Release);
}

/// FFI entry point for `ringbuf_output`.
///
/// Reserves space in the ring buffer, copies `size` bytes from `data`,
/// and submits the record in one atomic operation. Returns 0 on success
/// or a negative errno on failure.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is the first field
///   of a `BpfRingbuf` allocated by `ringbuf_alloc`.
/// - `data` must point to at least `size` bytes of readable memory.
/// - `size` must be > 0.
/// - `flags` must be 0.
#[no_mangle]
pub unsafe extern "C" fn ringbuf_output_rs(
    map: *mut crate::bindings::bpf_map,
    data: *const core::ffi::c_void,
    size: u64,
    flags: u64,
) -> core::ffi::c_long {
    if map.is_null() || data.is_null() {
        return Error::EINVAL.to_errno() as core::ffi::c_long;
    }
    if size == 0 {
        return Error::EINVAL.to_errno() as core::ffi::c_long;
    }

    // SAFETY: map is non-null (checked above). The map field is at offset 0
    // of BpfRingbuf (container_of pattern).
    let rb = &*(map as *const crate::ringbuf::BpfRingbuf);

    // SAFETY: BpfRingbuf invariants guaranteed by ringbuf_alloc. data points
    // to at least size readable bytes (caller guarantee).
    match rb.output(data as *const u8, size, flags) {
        Ok(()) => 0,
        Err(e) => e.to_errno() as core::ffi::c_long,
    }
}

// ===========================================================================
// Hash Table FFI Wrappers (Task 13.3)
// ===========================================================================

/// FFI entry point for `htab_map_lookup_elem`.
///
/// Looks up an element in the hash table by key. Returns a pointer to the
/// value data on success, or null if the key is not found.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` that is the first field
///   of a `BpfHtab` allocation.
/// - `key` must point to at least `map.key_size` readable bytes.
/// - Must be called within an RCU read-side critical section.
#[no_mangle]
pub unsafe extern "C" fn htab_map_lookup_elem_rs(
    map: *mut crate::bindings::bpf_map,
    key: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    if map.is_null() || key.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: map and key are non-null (checked above). Kernel guarantees
    // map points to a valid bpf_map within a BpfHtab allocation and key
    // has at least map.key_size readable bytes.
    crate::hashtab::htab_map_lookup_elem(
        map as *const crate::bindings::bpf_map,
        key as *const core::ffi::c_void,
    )
}

/// FFI entry point for `htab_map_update_elem`.
///
/// Updates or inserts an element in the hash table. Validates pointer
/// arguments, delegates to the Rust implementation, and returns errno.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within a `BpfHtab`.
/// - `key` must point to at least `map.key_size` readable bytes.
/// - `value` must point to at least `map.value_size` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn htab_map_update_elem_rs(
    map: *mut crate::bindings::bpf_map,
    key: *mut core::ffi::c_void,
    value: *mut core::ffi::c_void,
    flags: u64,
) -> c_long {
    check_null!(map, key, value);
    // SAFETY: map, key, and value are non-null (checked above). Kernel
    // guarantees valid pointers with sufficient sizes.
    result_to_errno(crate::hashtab::htab_map_update_elem(
        map,
        key as *const core::ffi::c_void,
        value as *const core::ffi::c_void,
        flags,
    ))
}

/// FFI entry point for `htab_map_delete_elem`.
///
/// Deletes an element from the hash table by key.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within a `BpfHtab`.
/// - `key` must point to at least `map.key_size` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn htab_map_delete_elem_rs(
    map: *mut crate::bindings::bpf_map,
    key: *mut core::ffi::c_void,
) -> c_long {
    check_null!(map, key);
    // SAFETY: map and key are non-null (checked above). Kernel guarantees
    // valid pointers with sufficient sizes.
    result_to_errno(crate::hashtab::htab_map_delete_elem(
        map,
        key as *const core::ffi::c_void,
    ))
}

/// FFI entry point for `htab_map_alloc`.
///
/// Allocates and initializes a new BPF hash table map from the given
/// attributes. Returns a pointer to the `bpf_map` field of the new
/// allocation on success, or an ERR_PTR-encoded errno on failure.
///
/// # Safety
///
/// - `attr` must be a valid pointer to a `bpf_attr` populated for a
///   BPF_MAP_CREATE command.
#[no_mangle]
pub unsafe extern "C" fn htab_map_alloc_rs(
    attr: *const crate::bindings::bpf_attr,
) -> *mut crate::bindings::bpf_map {
    if attr.is_null() {
        return Error::EINVAL.to_errno() as isize as *mut crate::bindings::bpf_map;
    }
    // SAFETY: attr is non-null (checked above). Kernel guarantees attr
    // points to a valid bpf_attr populated for BPF_MAP_CREATE.
    match crate::hashtab::htab_map_alloc(attr) {
        Ok(map_ptr) => map_ptr,
        Err(e) => {
            // Return ERR_PTR(errno): kernel convention for map_alloc failure.
            e.to_errno() as isize as *mut crate::bindings::bpf_map
        }
    }
}

/// FFI entry point for `htab_map_free`.
///
/// Frees a BPF hash table map and all its elements. Called when the map's
/// reference count reaches zero.
///
/// # Safety
///
/// - `map` must be either null or a valid pointer to the `bpf_map` field
///   of a `BpfHtab` that was allocated by [`htab_map_alloc_rs`].
/// - Must not be called more than once for the same map.
#[no_mangle]
pub unsafe extern "C" fn htab_map_free_rs(map: *mut crate::bindings::bpf_map) {
    if map.is_null() {
        return;
    }
    // SAFETY: map is non-null (checked above). Kernel guarantees map points
    // to a valid bpf_map within a BpfHtab allocation created by htab_map_alloc.
    crate::hashtab::htab_map_free(map);
}

/// FFI entry point for `htab_map_get_next_key`.
///
/// Returns the next key in the hash table for iteration. If `key` is null,
/// returns the first key. Returns -ENOENT when iteration is complete.
///
/// Note: `key` may be null (indicating start of iteration), so only
/// `map` and `next_key` are null-checked.
///
/// # Safety
///
/// - `map` must be a valid pointer to a `bpf_map` within a `BpfHtab`.
/// - If `key` is non-null, it must point to at least `map.key_size` readable bytes.
/// - `next_key` must point to at least `map.key_size` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn htab_map_get_next_key_rs(
    map: *mut crate::bindings::bpf_map,
    key: *mut core::ffi::c_void,
    next_key: *mut core::ffi::c_void,
) -> c_long {
    if map.is_null() || next_key.is_null() {
        return Error::EINVAL.to_errno() as c_long;
    }
    // SAFETY: map and next_key are non-null (checked above). key may be null
    // (handled by the inner function as "start of iteration"). Kernel
    // guarantees valid pointer sizes.
    result_to_errno(crate::hashtab::htab_map_get_next_key(
        map as *const crate::bindings::bpf_map,
        key as *const core::ffi::c_void,
        next_key,
    ))
}
