// SPDX-License-Identifier: GPL-2.0
//! BPF Queue and Stack map implementation.
//!
//! This module implements BPF_MAP_TYPE_QUEUE and BPF_MAP_TYPE_STACK maps as a
//! circular buffer. Queue maps provide FIFO semantics (pop from tail, push at
//! head) and stack maps provide LIFO semantics (pop from head-1, push at head).
//!
//! The data structure uses a single contiguous allocation containing the
//! [`BpfQueueStack`] header followed by `size` element slots, where `size` is
//! `max_entries + 1` to distinguish full from empty in the circular buffer.
//!
//! # Concurrency
//!
//! All operations acquire the embedded `rqspinlock_t` before reading or
//! mutating the head/tail pointers or element storage.
//!
//! # Element Layout
//!
//! Elements are stored at a fixed offset after the struct header, accessed via
//! `(index * value_size)` byte offset from the start of the elements region.

use crate::abstractions::bpf_mem::BpfMapArea;
use crate::bindings;
use crate::error::{Error, Result};
use core::ffi::c_void;

/// BPF queue/stack map structure.
///
/// Layout matches the C `struct bpf_queue_stack` for FFI compatibility.
/// The `map` field must be first to support the `container_of` pattern
/// used by the kernel's map dispatch layer.
///
/// # Invariants
///
/// - `head` and `tail` are always in the range `[0, size)`.
/// - `size == max_entries + 1` (one extra slot to differentiate full from empty).
/// - The buffer is empty when `head == tail`.
/// - The buffer is full when `(head + 1) % size == tail`.
/// - Elements are stored in the memory immediately following this struct,
///   aligned to 8 bytes.
#[repr(C)]
pub struct BpfQueueStack {
    /// The common BPF map header. Must be the first field.
    pub map: bindings::bpf_map,
    /// Spinlock protecting head, tail, and element storage.
    pub lock: bindings::rqspinlock_t,
    /// Index of the next write position (push writes here, then advances).
    pub head: u32,
    /// Index of the oldest element (queue pop reads from here).
    pub tail: u32,
    /// Capacity of the circular buffer (`max_entries + 1`).
    pub size: u32,
    // Flexible array `elements[]` follows, aligned to 8 bytes.
    // Accessed via pointer arithmetic from the end of this struct.
}

impl BpfQueueStack {
    /// Returns `true` if the queue/stack contains no elements.
    #[inline]
    fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Returns `true` if the queue/stack is at maximum capacity.
    ///
    /// Full condition: advancing tail by one (mod size) would reach head.
    /// Note: The C implementation checks `(head + 1) % size == tail` for full,
    /// but the actual semantics is that we store up to `size - 1` elements.
    /// Here we mirror the C logic exactly.
    #[inline]
    fn is_full(&self) -> bool {
        let next_head = if self.head + 1 >= self.size {
            0
        } else {
            self.head + 1
        };
        next_head == self.tail
    }

    /// Returns a pointer to the start of the elements region.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `self` was allocated with sufficient
    /// trailing memory for `self.size` elements of `self.map.value_size` bytes
    /// each, aligned to 8 bytes.
    #[inline]
    unsafe fn elements_ptr(&self) -> *mut u8 {
        // The elements follow immediately after the struct, aligned to 8 bytes.
        // In C this is `qs->elements` which is a flexible array member.
        let base = self as *const Self as *const u8;
        let offset = core::mem::size_of::<Self>();
        // Align offset up to 8 bytes (matching C's __aligned(8))
        let aligned_offset = (offset + 7) & !7;
        base.add(aligned_offset) as *mut u8
    }

    /// Returns a pointer to the element at the given index.
    ///
    /// # Safety
    ///
    /// - `index` must be less than `self.size`.
    /// - The struct must have been allocated with sufficient trailing memory.
    #[inline]
    unsafe fn element_at(&self, index: u32) -> *mut u8 {
        let elements = self.elements_ptr();
        let value_size = self.map.value_size as usize;
        elements.add(index as usize * value_size)
    }
}

/// Push an element onto the queue/stack.
///
/// Writes the value at the current `head` position and advances `head`.
/// If the buffer is full and `BPF_EXIST` flag is set, the oldest element
/// is overwritten by advancing `tail`. If the buffer is full and the flag
/// is not set, returns `-E2BIG`.
///
/// This function is shared by both queue and stack map types — the push
/// behavior is identical (write at head, advance head). The difference
/// between queue and stack is only in the pop operation.
///
/// # Safety
///
/// - `qs` must point to a valid, properly initialized `BpfQueueStack`.
/// - `value` must point to at least `qs.map.value_size` readable bytes.
/// - The spinlock must not already be held by the current context.
pub unsafe fn queue_stack_push_elem(
    qs: *mut BpfQueueStack,
    value: *const c_void,
    flags: u64,
) -> Result {
    // BPF_EXIST allows overwriting the oldest element when full.
    let replace = (flags & bindings::BPF_EXIST) != 0;

    // Reject unsupported flag combinations.
    // BPF_NOEXIST is not supported, and flags must not exceed BPF_EXIST.
    if (flags & bindings::BPF_NOEXIST) != 0 || flags > bindings::BPF_EXIST {
        return Err(Error::EINVAL);
    }

    let qs_ref = &mut *qs;

    // Safety: lock is a valid, initialized rqspinlock_t within the BpfQueueStack
    // allocation. We have not acquired it yet in this context.
    bindings::rqspin_lock(&mut qs_ref.lock);

    let result = queue_stack_push_elem_locked(qs_ref, value, replace);

    // Safety: We acquired the lock above; releasing it here.
    bindings::rqspin_unlock(&mut qs_ref.lock);

    result
}

/// Inner push logic, called with the lock already held.
///
/// # Safety
///
/// - The lock must be held by the caller.
/// - `value` must point to valid readable memory of `qs.map.value_size` bytes.
#[inline]
unsafe fn queue_stack_push_elem_locked(
    qs: &mut BpfQueueStack,
    value: *const c_void,
    replace: bool,
) -> Result {
    if qs.is_full() {
        if !replace {
            return Err(Error::E2BIG);
        }
        // Advance tail to overwrite the oldest element.
        qs.tail += 1;
        if qs.tail >= qs.size {
            qs.tail = 0;
        }
    }

    // Write value at head position.
    let dst = qs.element_at(qs.head);
    let value_size = qs.map.value_size as usize;

    // Safety: `dst` points to a valid element slot within the allocation.
    // `value` is guaranteed by the caller to have at least `value_size` bytes.
    // The regions do not overlap (value comes from userspace/BPF program memory,
    // dst is in the map's own allocation).
    core::ptr::copy_nonoverlapping(value as *const u8, dst, value_size);

    // Advance head with wraparound.
    qs.head += 1;
    if qs.head >= qs.size {
        qs.head = 0;
    }

    Ok(())
}

/// Pop an element from the queue (FIFO order).
///
/// Reads the value at the current `tail` position and advances `tail`.
/// Returns `-ENOENT` if the queue is empty. When empty, the output buffer
/// is zeroed (matching C behavior).
///
/// # Safety
///
/// - `qs` must point to a valid, properly initialized `BpfQueueStack`.
/// - `value` must point to a writable buffer of at least `qs.map.value_size` bytes.
/// - The spinlock must not already be held by the current context.
pub unsafe fn queue_pop_elem(qs: *mut BpfQueueStack, value: *mut c_void) -> Result {
    let qs_ref = &mut *qs;

    // Safety: lock is a valid, initialized rqspinlock_t.
    bindings::rqspin_lock(&mut qs_ref.lock);

    let result = queue_get_locked(qs_ref, value, true);

    // Safety: We acquired the lock above.
    bindings::rqspin_unlock(&mut qs_ref.lock);

    result
}

/// Peek at the front element of the queue (FIFO order) without removing it.
///
/// Reads the value at the current `tail` position without advancing any pointer.
/// Returns `-ENOENT` if the queue is empty. When empty, the output buffer
/// is zeroed (matching C behavior).
///
/// # Safety
///
/// - `qs` must point to a valid, properly initialized `BpfQueueStack`.
/// - `value` must point to a writable buffer of at least `qs.map.value_size` bytes.
/// - The spinlock must not already be held by the current context.
pub unsafe fn queue_peek_elem(qs: *mut BpfQueueStack, value: *mut c_void) -> Result {
    let qs_ref = &mut *qs;

    // Safety: lock is a valid, initialized rqspinlock_t.
    bindings::rqspin_lock(&mut qs_ref.lock);

    let result = queue_get_locked(qs_ref, value, false);

    // Safety: We acquired the lock above.
    bindings::rqspin_unlock(&mut qs_ref.lock);

    result
}

/// Inner queue get logic (FIFO), called with the lock held.
///
/// Reads from `tail` (the oldest element). If `delete` is true, advances
/// `tail` to consume the element.
///
/// # Safety
///
/// - The lock must be held by the caller.
/// - `value` must point to a writable buffer of `qs.map.value_size` bytes.
#[inline]
unsafe fn queue_get_locked(
    qs: &mut BpfQueueStack,
    value: *mut c_void,
    delete: bool,
) -> Result {
    let value_size = qs.map.value_size as usize;

    if qs.is_empty() {
        // Zero the output buffer on empty (matches C behavior).
        // Safety: value points to at least value_size writable bytes.
        core::ptr::write_bytes(value as *mut u8, 0, value_size);
        return Err(Error::ENOENT);
    }

    // Read from tail position (oldest element in FIFO order).
    let src = qs.element_at(qs.tail);

    // Safety: src points to a valid element in the allocation, value has
    // sufficient space, and the regions do not overlap.
    core::ptr::copy_nonoverlapping(src, value as *mut u8, value_size);

    if delete {
        // Advance tail with wraparound.
        qs.tail += 1;
        if qs.tail >= qs.size {
            qs.tail = 0;
        }
    }

    Ok(())
}

/// Pop an element from the stack (LIFO order).
///
/// Reads the value at position `(head - 1)` (the most recently pushed element)
/// and retreats `head`. Returns `-ENOENT` if the stack is empty. When empty,
/// the output buffer is zeroed (matching C behavior).
///
/// # Safety
///
/// - `qs` must point to a valid, properly initialized `BpfQueueStack`.
/// - `value` must point to a writable buffer of at least `qs.map.value_size` bytes.
/// - The spinlock must not already be held by the current context.
pub unsafe fn stack_pop_elem(qs: *mut BpfQueueStack, value: *mut c_void) -> Result {
    let qs_ref = &mut *qs;

    // Safety: lock is a valid, initialized rqspinlock_t.
    bindings::rqspin_lock(&mut qs_ref.lock);

    let result = stack_get_locked(qs_ref, value, true);

    // Safety: We acquired the lock above.
    bindings::rqspin_unlock(&mut qs_ref.lock);

    result
}

/// Peek at the top element of the stack (LIFO order) without removing it.
///
/// Reads the value at position `(head - 1)` without modifying any pointer.
/// Returns `-ENOENT` if the stack is empty. When empty, the output buffer
/// is zeroed (matching C behavior).
///
/// # Safety
///
/// - `qs` must point to a valid, properly initialized `BpfQueueStack`.
/// - `value` must point to a writable buffer of at least `qs.map.value_size` bytes.
/// - The spinlock must not already be held by the current context.
pub unsafe fn stack_peek_elem(qs: *mut BpfQueueStack, value: *mut c_void) -> Result {
    let qs_ref = &mut *qs;

    // Safety: lock is a valid, initialized rqspinlock_t.
    bindings::rqspin_lock(&mut qs_ref.lock);

    let result = stack_get_locked(qs_ref, value, false);

    // Safety: We acquired the lock above.
    bindings::rqspin_unlock(&mut qs_ref.lock);

    result
}

/// Inner stack get logic (LIFO), called with the lock held.
///
/// Reads from `head - 1` (the most recently pushed element). If `delete`
/// is true, retreats `head` to remove the element.
///
/// # Safety
///
/// - The lock must be held by the caller.
/// - `value` must point to a writable buffer of `qs.map.value_size` bytes.
#[inline]
unsafe fn stack_get_locked(
    qs: &mut BpfQueueStack,
    value: *mut c_void,
    delete: bool,
) -> Result {
    let value_size = qs.map.value_size as usize;

    if qs.is_empty() {
        // Zero the output buffer on empty (matches C behavior).
        // Safety: value points to at least value_size writable bytes.
        core::ptr::write_bytes(value as *mut u8, 0, value_size);
        return Err(Error::ENOENT);
    }

    // Compute index of the most recently pushed element.
    // head points to the *next* write slot, so the last written is head - 1.
    // Handle wraparound: if head is 0, the last element is at size - 1.
    let index = if qs.head == 0 {
        qs.size - 1
    } else {
        qs.head - 1
    };

    let src = qs.element_at(index);

    // Safety: src points to a valid element in the allocation, value has
    // sufficient space, and the regions do not overlap.
    core::ptr::copy_nonoverlapping(src, value as *mut u8, value_size);

    if delete {
        // Retreat head to remove the top element.
        qs.head = index;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Lifecycle Functions (alloc / free)
// ---------------------------------------------------------------------------

/// Allowed map creation flags for queue and stack maps.
///
/// Matches the C `QUEUE_STACK_CREATE_FLAG_MASK` constant:
/// `BPF_F_NUMA_NODE | BPF_F_ACCESS_MASK`
const QUEUE_STACK_CREATE_FLAG_MASK: u32 = bindings::BPF_F_NUMA_NODE | bindings::BPF_F_ACCESS_MASK;

/// Allocate and initialize a queue/stack map.
///
/// This function:
/// 1. Validates the creation attributes (value_size > 0, max_entries > 0,
///    no unsupported flags).
/// 2. Computes the total allocation size: `sizeof(BpfQueueStack)` (aligned
///    up to 8 bytes) + `(max_entries + 1) * value_size`.
/// 3. Allocates the memory via `BpfMapArea::alloc()`.
/// 4. Initializes the map header via `bpf_map_init_from_attr`.
/// 5. Sets `size = max_entries + 1`, `head = 0`, `tail = 0`, lock zeroed.
/// 6. Returns a pointer to the embedded `bpf_map` field on success.
///
/// # Safety
///
/// - `attr` must point to a valid, fully populated `bpf_attr` for a
///   `BPF_MAP_CREATE` command.
/// - The returned pointer (on success) is a `*mut bpf_map` that must be
///   freed via `queue_stack_map_free` when the map's refcount reaches zero.
pub unsafe fn queue_stack_map_alloc(
    attr: *const bindings::bpf_attr,
) -> Result<*mut bindings::bpf_map> {
    // SAFETY: Caller guarantees `attr` is a valid bpf_attr for BPF_MAP_CREATE.
    let attr_ref = &*attr;

    let value_size = attr_ref.value_size();
    let max_entries = attr_ref.max_entries();
    let map_flags = attr_ref.map_flags();

    // Validate creation parameters (mirrors queue_stack_map_alloc_check in C).
    if max_entries == 0 || value_size == 0 {
        return Err(Error::EINVAL);
    }

    // Reject unsupported flags.
    if map_flags & !QUEUE_STACK_CREATE_FLAG_MASK != 0 {
        return Err(Error::EINVAL);
    }

    // Compute total allocation size.
    // size = max_entries + 1 (one extra slot to distinguish full from empty).
    let size = (max_entries as u64).wrapping_add(1);

    // struct_size = sizeof(BpfQueueStack) aligned up to 8 bytes.
    let struct_size = core::mem::size_of::<BpfQueueStack>();
    let aligned_struct_size = (struct_size + 7) & !7;

    // queue_size = aligned_struct_size + size * value_size
    // Use checked arithmetic to detect overflow.
    let elements_size = match size.checked_mul(value_size as u64) {
        Some(v) => v,
        None => return Err(Error::EINVAL),
    };
    let queue_size = match (aligned_struct_size as u64).checked_add(elements_size) {
        Some(v) => v,
        None => return Err(Error::EINVAL),
    };

    // Determine NUMA node from flags.
    // The bpf_attr stores numa_node as u32, but BpfMapArea::alloc takes i32.
    // When BPF_F_NUMA_NODE is set, use the user-specified node; otherwise
    // use NUMA_NO_NODE (-1).
    let numa_node = if map_flags & bindings::BPF_F_NUMA_NODE != 0 {
        attr_ref.numa_node() as i32
    } else {
        bindings::NUMA_NO_NODE
    };

    // Allocate memory for the map + element array.
    let ptr = BpfMapArea::alloc(queue_size, numa_node)?;

    // Zero-initialize the entire allocation.
    // SAFETY: ptr is non-null (BpfMapArea::alloc returned Ok), and points to
    // `queue_size` bytes of writable memory.
    core::ptr::write_bytes(ptr, 0, queue_size as usize);

    // Cast to our struct type.
    // Safety (cast_ptr_alignment): BpfMapArea::alloc delegates to kmalloc/vmalloc
    // which return memory aligned to at least max_align_t (>= 8 bytes), satisfying
    // the alignment requirement of BpfQueueStack.
    #[allow(clippy::cast_ptr_alignment)]
    let qs = ptr as *mut BpfQueueStack;

    // Initialize common map fields from the user-provided attributes.
    // SAFETY: qs points to a valid, zero-initialized BpfQueueStack, and the
    // `map` field is at offset 0. `attr` is a valid bpf_attr pointer.
    bindings::bpf_map_init_from_attr(&mut (*qs).map, attr);

    // Initialize queue/stack-specific fields.
    (*qs).size = size as u32;
    (*qs).head = 0;
    (*qs).tail = 0;
    // lock is already zeroed (unlocked state) from write_bytes above.

    // Return pointer to the embedded bpf_map (first field, so same address).
    Ok(&mut (*qs).map as *mut bindings::bpf_map)
}

/// Free a queue/stack map and its backing memory.
///
/// Casts the `bpf_map` pointer back to the enclosing `BpfQueueStack` via the
/// `container_of` pattern (map is at offset 0), then frees the entire
/// allocation using `BpfMapArea::free`.
///
/// # Safety
///
/// - `map` must point to a valid `bpf_map` that was allocated by
///   `queue_stack_map_alloc`. Passing any other pointer is undefined behavior.
/// - `map` must not have been freed already (no double-free).
/// - No references to the map or its elements may be used after this call.
pub unsafe fn queue_stack_map_free(map: *mut bindings::bpf_map) {
    // The `map` field is the first field of BpfQueueStack (offset 0), so
    // the pointer to the map IS the pointer to the BpfQueueStack struct.
    // This is the container_of pattern.
    let qs = map as *mut BpfQueueStack;

    // SAFETY: `qs` was allocated by BpfMapArea::alloc in queue_stack_map_alloc.
    // The caller guarantees it has not been freed and no references remain.
    BpfMapArea::free(qs as *mut u8);
}
