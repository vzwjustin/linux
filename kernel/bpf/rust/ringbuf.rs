// SPDX-License-Identifier: GPL-2.0
//! BPF Ring Buffer map implementation.
//!
//! A lock-free, multi-producer ring buffer for efficient data transfer from
//! BPF programs to userspace. The ring buffer uses atomic operations on
//! producer/consumer positions to achieve lock-free reservation and
//! submission of variable-length records.
//!
//! # Design
//!
//! The ring buffer is a power-of-two sized region of memory with separate
//! producer and consumer position counters. Producers atomically reserve
//! space by advancing the producer position via compare-and-swap (CAS).
//! Each record has a header containing the payload length and status bits.
//! Records transition through states: BUSY (being written) → committed
//! (visible to consumer) or BUSY → DISCARDED.
//!
//! The lock-free design avoids spinlocks on the producer fast path, using
//! only atomic operations with appropriate memory ordering.

use crate::abstractions::BpfMapArea;
use crate::bindings;
use crate::error::{Error, Result};
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Bit set in `BpfRingbufHdr::len` while a record is being written.
/// Consumers must not read records with this bit set.
const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;

/// Bit set in `BpfRingbufHdr::len` to indicate a discarded record.
/// Consumers skip over discarded records when advancing.
const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;

/// Alignment for ring buffer records (8 bytes).
/// All record sizes are rounded up to this alignment to ensure proper
/// alignment of subsequent headers and data.
const BPF_RINGBUF_ALIGN: u64 = 8;

/// Size of the ring buffer record header in bytes.
const BPF_RINGBUF_HDR_SIZE: u64 = core::mem::size_of::<BpfRingbufHdr>() as u64;

// ---------------------------------------------------------------------------
// Ring buffer record header
// ---------------------------------------------------------------------------

/// Header prepended to each record in the ring buffer.
///
/// The `len` field encodes both the payload length (lower 30 bits) and
/// status flags (upper 2 bits: BUSY and DISCARD). The `pg_off` field
/// stores the offset of this record from the start of the ring data area.
#[repr(C)]
pub struct BpfRingbufHdr {
    /// Payload length with status bits in upper bits.
    /// - Bit 31: BPF_RINGBUF_BUSY_BIT — record is being written
    /// - Bit 30: BPF_RINGBUF_DISCARD_BIT — record was discarded
    /// - Bits 0..29: actual payload length
    pub len: u32,
    /// Offset from the start of the ring buffer data area.
    pub pg_off: u32,
}

// ---------------------------------------------------------------------------
// BPF Ring Buffer structure
// ---------------------------------------------------------------------------

/// BPF ring buffer map.
///
/// This struct represents a lock-free ring buffer used by BPF programs to
/// efficiently pass variable-length data to userspace consumers. The ring
/// buffer uses atomic producer/consumer positions with no spinlock on the
/// producer fast path.
///
/// # Layout
///
/// The `map` field MUST be the first field to support the `container_of`
/// pattern used by the kernel's BPF map dispatch infrastructure.
///
/// # Memory Ordering
///
/// - Producer position: written with `Release` ordering after record setup
/// - Consumer position: read with `Acquire` ordering to see latest consumer progress
/// - Record header `len` field: written with `Release` after data is ready,
///   read with `Acquire` by consumer to check record availability
///
/// # Safety
///
/// The `data`, `producer_pos`, and `consumer_pos` pointers must remain valid
/// for the lifetime of the ring buffer. They point into memory allocated by
/// the kernel as part of ring buffer creation (mmap-able pages).
#[repr(C)]
pub struct BpfRingbuf {
    /// Embedded BPF map structure (must be first for container_of).
    pub map: bindings::bpf_map,
    /// Bitmask for wrapping positions into the ring (ring_size - 1).
    /// The ring size is always a power of two, so `pos & mask` gives the
    /// offset within the data area.
    pub mask: u64,
    /// Pointer to the ring buffer data pages.
    ///
    /// # Safety
    /// Must point to a valid allocation of at least `mask + 1` bytes.
    pub data: *mut u8,
    /// Pointer to the producer position (atomically updated).
    ///
    /// # Safety
    /// Must point to a valid, aligned u64 in the producer page.
    pub producer_pos: *mut u64,
    /// Pointer to the consumer position (atomically updated).
    ///
    /// # Safety
    /// Must point to a valid, aligned u64 in the consumer page.
    pub consumer_pos: *mut u64,
}

// SAFETY: BpfRingbuf uses atomic operations for all shared state access.
// The data, producer_pos, and consumer_pos pointers reference kernel-managed
// pages that outlive the ring buffer. Access is synchronized via atomics.
unsafe impl Send for BpfRingbuf {}
// SAFETY: All mutable state is accessed through atomic operations, making
// concurrent access from multiple threads safe without external locking.
unsafe impl Sync for BpfRingbuf {}

impl BpfRingbuf {
    // -----------------------------------------------------------------------
    // Atomic accessors
    // -----------------------------------------------------------------------

    /// Read the producer position atomically with Acquire ordering.
    ///
    /// # Safety
    ///
    /// `self.producer_pos` must point to a valid, aligned `u64`.
    unsafe fn load_producer_pos(&self) -> u64 {
        // SAFETY: Caller guarantees producer_pos is valid and aligned.
        // AtomicU64::from_ptr requires a valid, aligned pointer to a u64
        // that is not concurrently accessed through non-atomic operations.
        // The producer page is exclusively accessed via atomic operations.
        let atomic = AtomicU64::from_ptr(self.producer_pos);
        atomic.load(Ordering::Acquire)
    }

    /// Attempt to CAS the producer position from `current` to `new_pos`.
    ///
    /// Returns `Ok(current)` on success or `Err(actual)` on failure.
    ///
    /// # Safety
    ///
    /// `self.producer_pos` must point to a valid, aligned `u64`.
    unsafe fn cas_producer_pos(&self, current: u64, new_pos: u64) -> core::result::Result<u64, u64> {
        // SAFETY: Same validity guarantees as load_producer_pos.
        let atomic = AtomicU64::from_ptr(self.producer_pos);
        atomic.compare_exchange(current, new_pos, Ordering::AcqRel, Ordering::Acquire)
    }

    /// Read the consumer position atomically with Acquire ordering.
    ///
    /// # Safety
    ///
    /// `self.consumer_pos` must point to a valid, aligned `u64`.
    unsafe fn load_consumer_pos(&self) -> u64 {
        // SAFETY: Caller guarantees consumer_pos is valid and aligned.
        // The consumer page is exclusively accessed via atomic operations.
        let atomic = AtomicU64::from_ptr(self.consumer_pos);
        atomic.load(Ordering::Acquire)
    }

    // -----------------------------------------------------------------------
    // Helper functions
    // -----------------------------------------------------------------------

    /// Round a size up to the ring buffer alignment.
    #[inline]
    fn align_size(size: u64) -> u64 {
        (size + BPF_RINGBUF_ALIGN - 1) & !(BPF_RINGBUF_ALIGN - 1)
    }

    /// Get a pointer to the record header for a given position in the ring.
    ///
    /// # Safety
    ///
    /// `pos & self.mask` must be within bounds of `self.data`, and the
    /// resulting pointer must be properly aligned for `BpfRingbufHdr`.
    #[inline]
    unsafe fn hdr_at(&self, pos: u64) -> *mut BpfRingbufHdr {
        // SAFETY: Caller guarantees pos is within the ring. The mask
        // ensures we wrap within the data area. Records are always
        // aligned to BPF_RINGBUF_ALIGN, so the header is aligned.
        // Safety (cast_ptr_alignment): Ring buffer records are always aligned to
        // BPF_RINGBUF_ALIGN (8 bytes), which exceeds BpfRingbufHdr's requirement.
        #[allow(clippy::cast_ptr_alignment)]
        { self.data.add((pos & self.mask) as usize) as *mut BpfRingbufHdr }
    }

    /// Get the total space a record occupies (header + aligned payload).
    #[inline]
    fn record_size(data_size: u64) -> u64 {
        BPF_RINGBUF_HDR_SIZE + Self::align_size(data_size)
    }

    /// Get the ring buffer capacity (mask + 1).
    #[inline]
    fn capacity(&self) -> u64 {
        self.mask + 1
    }

    // -----------------------------------------------------------------------
    // Core operations
    // -----------------------------------------------------------------------

    /// Reserve contiguous space in the ring buffer for a record.
    ///
    /// Atomically advances the producer position to claim space for a record
    /// of `size` bytes. The returned pointer points to the data area of the
    /// reserved record (past the header). The record header is initialized
    /// with the BUSY_BIT set, indicating it is not yet visible to consumers.
    ///
    /// # Arguments
    ///
    /// * `size` - Number of bytes to reserve for the record payload.
    ///
    /// # Returns
    ///
    /// * `Ok(*mut u8)` - Pointer to the reserved data area. The caller must
    ///   subsequently call [`submit`](Self::submit) or [`discard`](Self::discard)
    ///   on this pointer.
    /// * `Err(Error::ENOMEM)` - The ring buffer is full (not enough space
    ///   between producer and consumer positions).
    ///
    /// # Safety
    ///
    /// This function is unsafe because:
    /// - `self.data`, `self.producer_pos`, and `self.consumer_pos` must be valid.
    /// - The caller must ensure `size > 0` and `size` fits within the ring.
    pub unsafe fn reserve(&self, size: u64) -> Result<*mut u8> {
        let total_size = Self::record_size(size);

        // Spin on CAS to atomically reserve space.
        loop {
            // SAFETY: producer_pos is valid (struct invariant).
            let prod_pos = self.load_producer_pos();
            // SAFETY: consumer_pos is valid (struct invariant).
            let cons_pos = self.load_consumer_pos();

            let new_pos = prod_pos + total_size;

            // Check if there is enough space in the ring.
            // The ring is full when the producer would lap the consumer.
            if new_pos - cons_pos > self.capacity() {
                return Err(Error::ENOMEM);
            }

            // Attempt to claim this space atomically.
            // SAFETY: producer_pos is valid (struct invariant).
            match self.cas_producer_pos(prod_pos, new_pos) {
                Ok(_) => {
                    // Successfully reserved. Initialize the record header.
                    // SAFETY: prod_pos is within the ring (we just reserved it),
                    // and the ring data area is large enough.
                    let hdr = self.hdr_at(prod_pos);

                    // Store the record header with BUSY_BIT set.
                    // Use atomic store with Release ordering so that the header
                    // is visible to any thread that reads the producer position.
                    let hdr_len_ptr = &(*hdr).len as *const u32 as *mut u32;
                    let atomic_len = AtomicU32::from_ptr(hdr_len_ptr);
                    atomic_len.store(size as u32 | BPF_RINGBUF_BUSY_BIT, Ordering::Release);

                    // Store the offset from the ring start.
                    (*hdr).pg_off = (prod_pos & self.mask) as u32;

                    // Return pointer to the data area (past the header).
                    let data_ptr = (hdr as *mut u8).add(BPF_RINGBUF_HDR_SIZE as usize);
                    return Ok(data_ptr);
                }
                Err(_) => {
                    // Another producer won the race; retry.
                    core::hint::spin_loop();
                    continue;
                }
            }
        }
    }

    /// Submit a previously reserved record, making it visible to consumers.
    ///
    /// Clears the BUSY_BIT in the record header's `len` field using an
    /// atomic store with Release ordering. After this call, consumers can
    /// read the record data.
    ///
    /// # Arguments
    ///
    /// * `data_ptr` - Pointer to the data area as returned by [`reserve`](Self::reserve).
    ///
    /// # Safety
    ///
    /// - `data_ptr` must have been returned by a prior call to [`reserve`](Self::reserve)
    ///   on this ring buffer.
    /// - The caller must not use `data_ptr` after this call.
    /// - Each reserved record must be submitted or discarded exactly once.
    pub unsafe fn submit(&self, data_ptr: *mut u8) {
        // Walk back from the data pointer to the header.
        // SAFETY: data_ptr was returned by reserve(), which places it
        // exactly BPF_RINGBUF_HDR_SIZE bytes after the header.
        // Safety (cast_ptr_alignment): Ring buffer records are always aligned to
        // BPF_RINGBUF_ALIGN (8 bytes), which exceeds BpfRingbufHdr's requirement.
        #[allow(clippy::cast_ptr_alignment)]
        let hdr = data_ptr.sub(BPF_RINGBUF_HDR_SIZE as usize) as *mut BpfRingbufHdr;

        // Clear the BUSY_BIT to make the record visible.
        // Read current len (which has BUSY_BIT set), clear BUSY_BIT.
        let hdr_len_ptr = &(*hdr).len as *const u32 as *mut u32;
        let atomic_len = AtomicU32::from_ptr(hdr_len_ptr);
        let current_len = atomic_len.load(Ordering::Acquire);
        let new_len = current_len & !BPF_RINGBUF_BUSY_BIT;
        atomic_len.store(new_len, Ordering::Release);
    }

    /// Discard a previously reserved record.
    ///
    /// Sets the DISCARD_BIT and clears the BUSY_BIT in the record header.
    /// Consumers will skip over discarded records when advancing their
    /// position.
    ///
    /// # Arguments
    ///
    /// * `data_ptr` - Pointer to the data area as returned by [`reserve`](Self::reserve).
    ///
    /// # Safety
    ///
    /// - `data_ptr` must have been returned by a prior call to [`reserve`](Self::reserve)
    ///   on this ring buffer.
    /// - The caller must not use `data_ptr` after this call.
    /// - Each reserved record must be submitted or discarded exactly once.
    pub unsafe fn discard(&self, data_ptr: *mut u8) {
        // Walk back from the data pointer to the header.
        // SAFETY: data_ptr was returned by reserve(), which places it
        // exactly BPF_RINGBUF_HDR_SIZE bytes after the header.
        // Safety (cast_ptr_alignment): Ring buffer records are always aligned to
        // BPF_RINGBUF_ALIGN (8 bytes), which exceeds BpfRingbufHdr's requirement.
        #[allow(clippy::cast_ptr_alignment)]
        let hdr = data_ptr.sub(BPF_RINGBUF_HDR_SIZE as usize) as *mut BpfRingbufHdr;

        // Set DISCARD_BIT and clear BUSY_BIT.
        let hdr_len_ptr = &(*hdr).len as *const u32 as *mut u32;
        let atomic_len = AtomicU32::from_ptr(hdr_len_ptr);
        let current_len = atomic_len.load(Ordering::Acquire);
        let new_len = (current_len & !BPF_RINGBUF_BUSY_BIT) | BPF_RINGBUF_DISCARD_BIT;
        atomic_len.store(new_len, Ordering::Release);
    }

    /// Reserve space, copy data, and submit in one operation.
    ///
    /// This is a convenience function combining [`reserve`](Self::reserve),
    /// a memory copy, and [`submit`](Self::submit) into a single call.
    /// If reservation fails, no data is copied and the error is propagated.
    ///
    /// # Arguments
    ///
    /// * `data` - Pointer to the source data to copy into the ring buffer.
    /// * `size` - Number of bytes to copy.
    /// * `flags` - Reserved for future use (must be 0 currently).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Data was successfully written to the ring buffer.
    /// * `Err(Error::ENOMEM)` - Ring buffer is full.
    /// * `Err(Error::EINVAL)` - Invalid flags or null data pointer.
    ///
    /// # Safety
    ///
    /// - All struct invariants (valid pointers) must hold.
    /// - `data` must point to at least `size` bytes of readable memory.
    /// - `size` must be greater than 0.
    pub unsafe fn output(&self, data: *const u8, size: u64, flags: u64) -> Result {
        if data.is_null() {
            return Err(Error::EINVAL);
        }
        if flags != 0 {
            return Err(Error::EINVAL);
        }

        // Reserve space in the ring buffer.
        let dest = self.reserve(size)?;

        // Copy data into the reserved space.
        // SAFETY: `dest` points to `size` bytes of reserved writable memory.
        // `data` points to at least `size` bytes of readable memory (caller
        // guarantees). The regions do not overlap because `dest` is in the
        // ring buffer's internal pages and `data` is caller-provided.
        core::ptr::copy_nonoverlapping(data, dest, size as usize);

        // Submit the record, making it visible to consumers.
        self.submit(dest);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Constants for map creation
// ---------------------------------------------------------------------------

/// Page size constant (4096 bytes on most architectures).
/// Used to validate that max_entries is page-aligned and to compute
/// the sizes of producer/consumer pages.
const PAGE_SIZE: u64 = 4096;

/// Allowed map creation flags for ring buffer maps.
///
/// Matches C `RINGBUF_CREATE_FLAG_MASK`:
/// `BPF_F_NUMA_NODE | BPF_F_RB_OVERWRITE`
///
/// We include BPF_F_NUMA_NODE only since BPF_F_RB_OVERWRITE is not yet
/// exposed in our bindings for the initial conversion.
const RINGBUF_CREATE_FLAG_MASK: u32 = bindings::BPF_F_NUMA_NODE;

// ---------------------------------------------------------------------------
// Lifecycle Functions (alloc / free)
// ---------------------------------------------------------------------------

/// Allocate and initialize a new BPF ring buffer map.
///
/// This function:
/// 1. Reads `max_entries` (ring size) and `map_flags` from `attr`.
/// 2. Validates: `max_entries > 0`, is a power of 2, and is page-aligned.
/// 3. Rejects `key_size != 0` and `value_size != 0` (ring buffer is keyless/valueless).
/// 4. Allocates memory for the `BpfRingbuf` struct, data pages (the ring),
///    a producer position page, and a consumer position page.
/// 5. Initializes `mask = max_entries - 1`, data/producer_pos/consumer_pos
///    pointers, and positions to 0.
/// 6. Calls `bpf_map_init_from_attr` to populate common map fields.
/// 7. Returns a pointer to the embedded `map` field.
///
/// # Arguments
///
/// * `attr` - Pointer to a valid `bpf_attr` populated for `BPF_MAP_CREATE`.
///
/// # Returns
///
/// - `Ok(*mut bpf_map)` — pointer to the embedded `bpf_map` of the new ring buffer.
/// - `Err(EINVAL)` — invalid creation attributes.
/// - `Err(ENOMEM)` — memory allocation failure.
///
/// # Safety
///
/// - `attr` must point to a valid `bpf_attr` populated for `BPF_MAP_CREATE`.
/// - The returned pointer must be freed via [`ringbuf_free`] when done.
pub unsafe fn ringbuf_alloc(
    attr: *const bindings::bpf_attr,
) -> Result<*mut bindings::bpf_map> {
    // SAFETY: Caller guarantees `attr` is a valid bpf_attr for BPF_MAP_CREATE.
    let attr_ref = &*attr;

    let key_size = attr_ref.key_size();
    let value_size = attr_ref.value_size();
    let max_entries = attr_ref.max_entries();
    let map_flags = attr_ref.map_flags();

    // Ring buffers are keyless/valueless — reject non-zero key_size and value_size.
    if key_size != 0 || value_size != 0 {
        return Err(Error::EINVAL);
    }

    // max_entries must be > 0, a power of 2, and page-aligned.
    if max_entries == 0 {
        return Err(Error::EINVAL);
    }
    if !max_entries.is_power_of_two() {
        return Err(Error::EINVAL);
    }
    if !(max_entries as u64).is_multiple_of(PAGE_SIZE) {
        return Err(Error::EINVAL);
    }

    // Reject unsupported flags.
    if map_flags & !RINGBUF_CREATE_FLAG_MASK != 0 {
        return Err(Error::EINVAL);
    }

    // Determine NUMA node from flags.
    let numa_node = if map_flags & bindings::BPF_F_NUMA_NODE != 0 {
        attr_ref.numa_node() as i32
    } else {
        bindings::NUMA_NO_NODE
    };

    // --- Allocation ---
    // We allocate:
    // 1. The BpfRingbuf struct itself
    // 2. Data pages (max_entries bytes for the ring data)
    // 3. Producer position page (PAGE_SIZE bytes, contains u64 producer_pos)
    // 4. Consumer position page (PAGE_SIZE bytes, contains u64 consumer_pos)

    let data_size = max_entries as u64;

    // Allocate the BpfRingbuf struct.
    let struct_size = mem::size_of::<BpfRingbuf>() as u64;
    let rb_ptr = BpfMapArea::alloc(struct_size, numa_node)?;

    // Zero-initialize the struct.
    // SAFETY: rb_ptr is non-null and has struct_size bytes.
    ptr::write_bytes(rb_ptr, 0, struct_size as usize);

    // Safety (cast_ptr_alignment): BpfMapArea::alloc delegates to kmalloc/vmalloc
    // which return memory aligned to at least max_align_t (>= 8 bytes), satisfying
    // the alignment requirement of BpfRingbuf.
    #[allow(clippy::cast_ptr_alignment)]
    let rb = rb_ptr as *mut BpfRingbuf;

    // Allocate data pages.
    let data_ptr = match BpfMapArea::alloc(data_size, numa_node) {
        Ok(p) => p,
        Err(e) => {
            // Free the struct allocation on failure.
            BpfMapArea::free(rb_ptr);
            return Err(e);
        }
    };
    // Zero-initialize data pages.
    // SAFETY: data_ptr is non-null and has data_size bytes.
    ptr::write_bytes(data_ptr, 0, data_size as usize);

    // Allocate producer position page.
    let prod_ptr = match BpfMapArea::alloc(PAGE_SIZE, numa_node) {
        Ok(p) => p,
        Err(e) => {
            BpfMapArea::free(data_ptr);
            BpfMapArea::free(rb_ptr);
            return Err(e);
        }
    };
    // Zero-initialize producer page.
    // SAFETY: prod_ptr is non-null and has PAGE_SIZE bytes.
    ptr::write_bytes(prod_ptr, 0, PAGE_SIZE as usize);

    // Allocate consumer position page.
    let cons_ptr = match BpfMapArea::alloc(PAGE_SIZE, numa_node) {
        Ok(p) => p,
        Err(e) => {
            BpfMapArea::free(prod_ptr);
            BpfMapArea::free(data_ptr);
            BpfMapArea::free(rb_ptr);
            return Err(e);
        }
    };
    // Zero-initialize consumer page.
    // SAFETY: cons_ptr is non-null and has PAGE_SIZE bytes.
    ptr::write_bytes(cons_ptr, 0, PAGE_SIZE as usize);

    // --- Initialize struct fields ---

    // Initialize common map fields from the user-provided attributes.
    // SAFETY: rb->map is valid (part of the zeroed allocation), attr is valid.
    bindings::bpf_map_init_from_attr(&mut (*rb).map, attr);

    // Set ring buffer specific fields.
    (*rb).mask = (max_entries as u64).wrapping_sub(1);
    (*rb).data = data_ptr;
    // Safety (cast_ptr_alignment): BpfMapArea::alloc returns memory aligned to at
    // least max_align_t (>= 8 bytes), satisfying u64 alignment requirements.
    #[allow(clippy::cast_ptr_alignment)]
    {
        (*rb).producer_pos = prod_ptr as *mut u64;
        (*rb).consumer_pos = cons_ptr as *mut u64;
    }

    // Positions are already 0 from zero-initialization of the pages.

    // Return pointer to the embedded bpf_map (first field, offset 0).
    Ok(&mut (*rb).map as *mut bindings::bpf_map)
}

/// Free a BPF ring buffer map previously allocated by [`ringbuf_alloc`].
///
/// Frees the data pages, producer position page, consumer position page,
/// and the `BpfRingbuf` struct itself using `BpfMapArea::free`.
///
/// # Safety
///
/// - `map` must point to the `bpf_map` field of a `BpfRingbuf` that was
///   previously allocated by [`ringbuf_alloc`].
/// - `map` must not have been freed already (no double-free).
/// - No references to the ring buffer or its data may be used after this call.
pub unsafe fn ringbuf_free(map: *mut bindings::bpf_map) {
    // The `map` field is at offset 0 of BpfRingbuf (#[repr(C)], first field),
    // so the pointer to `map` IS the pointer to the enclosing BpfRingbuf.
    // This is the standard container_of pattern.
    let rb = map as *mut BpfRingbuf;

    // Read the pointers before freeing the struct.
    let data_ptr = (*rb).data;
    let prod_ptr = (*rb).producer_pos as *mut u8;
    let cons_ptr = (*rb).consumer_pos as *mut u8;

    // Free consumer position page.
    // SAFETY: cons_ptr was allocated by BpfMapArea::alloc in ringbuf_alloc.
    if !cons_ptr.is_null() {
        BpfMapArea::free(cons_ptr);
    }

    // Free producer position page.
    // SAFETY: prod_ptr was allocated by BpfMapArea::alloc in ringbuf_alloc.
    if !prod_ptr.is_null() {
        BpfMapArea::free(prod_ptr);
    }

    // Free data pages.
    // SAFETY: data_ptr was allocated by BpfMapArea::alloc in ringbuf_alloc.
    if !data_ptr.is_null() {
        BpfMapArea::free(data_ptr);
    }

    // Free the BpfRingbuf struct itself.
    // SAFETY: rb was allocated by BpfMapArea::alloc in ringbuf_alloc.
    BpfMapArea::free(rb as *mut u8);
}
