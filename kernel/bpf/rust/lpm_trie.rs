// SPDX-License-Identifier: GPL-2.0
//! BPF LPM (Longest Prefix Match) Trie implementation.
//!
//! This module implements the LPM trie data structure in Rust, providing
//! `lookup_elem`, `update_elem`, and `delete_elem` operations that match
//! the semantics of the C implementation in `kernel/bpf/lpm_trie.c`.
//!
//! The LPM trie stores prefixes (e.g., IP address ranges) and supports
//! longest-prefix-match lookup: given a key, the trie returns the value
//! associated with the most specific (longest) matching prefix.
//!
//! # Key Format
//!
//! Keys are `{ u32 prefixlen; u8 data[]; }` where `data` contains the
//! prefix bits in big-endian (network) byte order. The `prefixlen` field
//! indicates how many bits of `data` are significant.
//!
//! # Safety
//!
//! - `LpmTrie` uses `#[repr(C)]` for FFI layout compatibility.
//! - `LpmTrieNode` is heap-allocated and managed via RCU.
//! - All mutations are protected by the trie's spinlock.
//! - Readers traverse under RCU read-side critical sections.

// All indexing in this module targets the 2-element `children` array with
// indices that are provably 0 or 1 (from `extract_bit` or literal constants).
#![allow(clippy::indexing_slicing)]

use core::ffi::c_void;
use core::mem;
use core::ptr;

use crate::abstractions::bpf_mem::BpfMapArea;
use crate::bindings;
use crate::error::{Error, Result};

/// Flag indicating an intermediate (non-value-carrying) node.
/// Intermediate nodes are created to split prefixes in the trie and
/// do not represent user-inserted entries.
const LPM_TREE_NODE_FLAG_IM: u32 = 1;

/// Maximum allowed data size in bytes for LPM trie keys.
const LPM_DATA_SIZE_MAX: usize = 256;

/// Minimum allowed data size in bytes for LPM trie keys.
const LPM_DATA_SIZE_MIN: usize = 1;

/// Size of the LPM key header (the `prefixlen` u32 field).
const LPM_KEY_HEADER_SIZE: usize = core::mem::size_of::<u32>();

/// Minimum key size: header + minimum data.
const LPM_KEY_SIZE_MIN: usize = LPM_KEY_HEADER_SIZE + LPM_DATA_SIZE_MIN;

/// Maximum key size: header + maximum data.
const LPM_KEY_SIZE_MAX: usize = LPM_KEY_HEADER_SIZE + LPM_DATA_SIZE_MAX;

/// LPM Trie node.
///
/// Each node stores a prefix (in `data`), its length, flags indicating
/// whether it's an intermediate node, and two child pointers (for bit 0
/// and bit 1 at position `prefixlen`).
///
/// The node is followed in memory by:
/// - `data[data_size]`: the prefix bits
/// - `value[value_size]`: the associated value (only for non-IM nodes)
///
/// # Memory Layout
///
/// ```text
/// +-------------------+
/// | children[0]       |  <- pointer to left child (bit 0)
/// | children[1]       |  <- pointer to right child (bit 1)
/// | prefixlen         |  <- number of significant prefix bits
/// | flags             |  <- LPM_TREE_NODE_FLAG_IM if intermediate
/// | data[data_size]   |  <- prefix bytes (flexible array)
/// | value[value_size] |  <- value bytes (only if not IM)
/// +-------------------+
/// ```
#[repr(C)]
pub struct LpmTrieNode {
    /// Child pointers, RCU-protected. Index 0 = next bit is 0, index 1 = next bit is 1.
    pub children: [*mut LpmTrieNode; 2],
    /// Number of significant bits in this node's prefix.
    pub prefixlen: u32,
    /// Node flags. `LPM_TREE_NODE_FLAG_IM` indicates an intermediate node.
    pub flags: u32,
    // Flexible array: data[] follows immediately after this struct in memory.
    // The actual prefix bytes and value are accessed via pointer arithmetic.
}

/// LPM Trie map structure.
///
/// This struct is the Rust equivalent of `struct lpm_trie` from the C
/// implementation. The `#[repr(C)]` attribute ensures field layout matches
/// what the kernel expects for `container_of` usage.
///
/// # Layout
///
/// - `map` must be the first field for `container_of` compatibility.
/// - `root` is the RCU-protected root node pointer.
/// - `n_entries` tracks current number of real (non-intermediate) entries.
/// - `max_prefixlen` is `data_size * 8` (maximum bits in a key).
/// - `data_size` is `key_size - sizeof(u32)` (key bytes without prefixlen header).
/// - `lock` is a spinlock protecting all mutations.
#[repr(C)]
pub struct LpmTrie {
    /// Embedded BPF map common fields. Must be first for `container_of`.
    pub map: bindings::bpf_map,
    /// Root node pointer (RCU-protected).
    pub root: *mut LpmTrieNode,
    /// BPF memory allocator for node allocation (slab-based).
    pub ma: bindings::bpf_mem_alloc,
    /// Number of non-intermediate entries in the trie.
    pub n_entries: usize,
    /// Maximum prefix length in bits (`data_size * 8`).
    pub max_prefixlen: usize,
    /// Size of key data in bytes (`key_size - 4`).
    pub data_size: usize,
    /// Spinlock protecting trie mutations.
    pub lock: bindings::rqspinlock_t,
}

// SAFETY: LpmTrie is shared across CPUs in the kernel. Access is synchronized
// by RCU (readers) and the spinlock (writers). The struct is allocated by C
// code; Rust only receives pointers to it.
unsafe impl Send for LpmTrie {}
unsafe impl Sync for LpmTrie {}

impl LpmTrie {
    /// Obtain a `&LpmTrie` reference from a `*const bpf_map` pointer.
    ///
    /// Implements the `container_of` pattern: given a pointer to the `map`
    /// field (at offset 0), cast to the containing `LpmTrie`.
    ///
    /// # Safety
    ///
    /// - `map_ptr` must be non-null and point to a valid `bpf_map` that is
    ///   the `map` field of a live `LpmTrie` allocation.
    /// - The `LpmTrie` must remain valid for the lifetime of the returned reference.
    #[inline]
    pub unsafe fn from_map_ptr<'a>(map_ptr: *const bindings::bpf_map) -> &'a Self {
        // SAFETY: `map` is at offset 0 in LpmTrie (#[repr(C)] and first field),
        // so casting a *const bpf_map to *const LpmTrie is valid.
        &*(map_ptr as *const Self)
    }

    /// Obtain a `&mut LpmTrie` reference from a `*mut bpf_map` pointer.
    ///
    /// # Safety
    ///
    /// Same as `from_map_ptr`, plus the caller must have exclusive access
    /// (e.g., holding the spinlock for mutation).
    #[inline]
    pub unsafe fn from_map_ptr_mut<'a>(map_ptr: *mut bindings::bpf_map) -> &'a mut Self {
        // SAFETY: Same justification as from_map_ptr, plus caller ensures exclusivity.
        &mut *(map_ptr as *mut Self)
    }
}

/// Extract a single bit from a byte array at the given bit index.
///
/// The data is interpreted in big-endian bit order: bit 0 is the MSB of
/// byte 0, bit 7 is the LSB of byte 0, bit 8 is the MSB of byte 1, etc.
///
/// # Arguments
///
/// * `data` - Pointer to the byte array.
/// * `index` - Bit index to extract.
///
/// # Returns
///
/// 0 or 1 depending on the bit value.
///
/// # Safety
///
/// - `data` must point to at least `(index / 8) + 1` readable bytes.
#[inline]
unsafe fn extract_bit(data: *const u8, index: usize) -> usize {
    // SAFETY: Caller guarantees data has sufficient bytes.
    let byte = *data.add(index / 8);
    let bit = byte & (1 << (7 - (index % 8)));
    if bit != 0 { 1 } else { 0 }
}

/// Get a pointer to the data (prefix bytes) of a node.
///
/// The data immediately follows the `LpmTrieNode` struct in memory.
///
/// # Safety
///
/// - `node` must point to a valid, allocated `LpmTrieNode` with at least
///   `data_size` bytes following the struct.
#[inline]
unsafe fn node_data(node: *const LpmTrieNode) -> *const u8 {
    (node as *const u8).add(core::mem::size_of::<LpmTrieNode>())
}

/// Get a mutable pointer to the data of a node.
///
/// # Safety
///
/// Same as `node_data`, plus caller must have exclusive access.
#[inline]
unsafe fn node_data_mut(node: *mut LpmTrieNode) -> *mut u8 {
    (node as *mut u8).add(core::mem::size_of::<LpmTrieNode>())
}

/// Get a pointer to the value area of a node.
///
/// The value follows the data in memory: `node + sizeof(LpmTrieNode) + data_size`.
///
/// # Safety
///
/// - `node` must point to a valid node with both `data_size` bytes of prefix
///   data and `value_size` bytes of value following the struct.
#[inline]
unsafe fn node_value(node: *const LpmTrieNode, data_size: usize) -> *const u8 {
    (node as *const u8).add(core::mem::size_of::<LpmTrieNode>() + data_size)
}

/// Determine the longest common prefix between a node and a key.
///
/// Compares the prefix bits of `node` against the key data, stopping at
/// the shorter of `node.prefixlen` and `key_prefixlen`. Returns the number
/// of matching leading bits.
///
/// This mirrors the C `longest_prefix_match()` function which uses
/// big-endian comparison with `fls()` (find last set) to count matching
/// prefix bits efficiently.
///
/// # Safety
///
/// - `node` must be a valid pointer to an `LpmTrieNode` with `data_size`
///   bytes of prefix data.
/// - `key_data` must point to at least `data_size` readable bytes.
unsafe fn longest_prefix_match(
    data_size: usize,
    node: *const LpmTrieNode,
    key_data: *const u8,
    key_prefixlen: u32,
) -> usize {
    let limit = core::cmp::min((*node).prefixlen, key_prefixlen) as usize;
    let n_data = node_data(node);

    let mut prefixlen: usize = 0;
    let mut i: usize = 0;

    // Compare 4 bytes at a time for efficiency.
    // The C code uses be32_to_cpu and fls (find last set, 1-indexed).
    // In Rust, `leading_zeros()` on the XOR gives us the number of
    // matching bits in that word.
    while data_size >= i + 4 {
        // SAFETY: Both n_data and key_data have at least data_size bytes.
        let node_word = u32::from_be(ptr::read_unaligned(n_data.add(i) as *const u32));
        let key_word = u32::from_be(ptr::read_unaligned(key_data.add(i) as *const u32));
        let diff = node_word ^ key_word;

        // leading_zeros gives matching prefix bits in this 32-bit chunk.
        prefixlen += diff.leading_zeros() as usize;
        if prefixlen >= limit {
            return limit;
        }
        if diff != 0 {
            return prefixlen;
        }
        i += 4;
    }

    // Compare 2 bytes at a time.
    if data_size >= i + 2 {
        // SAFETY: Both pointers have at least data_size bytes available.
        let node_half = u16::from_be(ptr::read_unaligned(n_data.add(i) as *const u16));
        let key_half = u16::from_be(ptr::read_unaligned(key_data.add(i) as *const u16));
        let diff = (node_half ^ key_half) as u32;

        // For a 16-bit value, leading zeros of the 32-bit representation minus 16.
        prefixlen += (diff.leading_zeros() as usize).saturating_sub(16);
        if prefixlen >= limit {
            return limit;
        }
        if diff != 0 {
            return prefixlen;
        }
        i += 2;
    }

    // Compare final byte.
    if data_size > i {
        // SAFETY: Both pointers have at least data_size bytes available.
        let diff = (*n_data.add(i) ^ *key_data.add(i)) as u32;
        // For an 8-bit value, leading zeros of the 32-bit representation minus 24.
        prefixlen += (diff.leading_zeros() as usize).saturating_sub(24);
        if prefixlen >= limit {
            return limit;
        }
    }

    prefixlen
}

/// Allocate a new LPM trie node.
///
/// Allocates memory for the node header, data, and value. If `value` is
/// non-null, the value is copied into the allocated node.
///
/// # Safety
///
/// - `trie` must be a valid pointer to an `LpmTrie`.
/// - If `value` is non-null, it must point to at least `trie.map.value_size`
///   readable bytes.
unsafe fn lpm_trie_node_alloc(
    trie: *const LpmTrie,
    value: *const c_void,
) -> *mut LpmTrieNode {
    let data_size = (*trie).data_size;
    let value_size = (*trie).map.value_size as usize;

    // Total node size: struct header + data + value
    let node_size = core::mem::size_of::<LpmTrieNode>() + data_size + value_size;

    // SAFETY: node_size > 0, GFP_ATOMIC for allocation under spinlock.
    let node = bindings::__kmalloc(node_size, bindings::GFP_ATOMIC) as *mut LpmTrieNode;
    if node.is_null() {
        return ptr::null_mut();
    }

    // Zero-initialize the node struct fields.
    ptr::write_bytes(node as *mut u8, 0, node_size);
    (*node).flags = 0;

    // Copy value data if provided.
    if !value.is_null() {
        let val_dst = node_value(node, data_size) as *mut u8;
        // SAFETY: value points to value_size bytes (caller contract),
        // val_dst points to value_size bytes (allocated above).
        ptr::copy_nonoverlapping(value as *const u8, val_dst, value_size);
    }

    node
}

/// Free an LPM trie node.
///
/// # Safety
///
/// - `node` must have been allocated by `lpm_trie_node_alloc` (via `__kmalloc`).
/// - `node` must not be accessed after this call.
/// - It is safe to pass a null pointer (this is a no-op).
#[inline]
unsafe fn lpm_trie_node_free(node: *mut LpmTrieNode) {
    if !node.is_null() {
        // SAFETY: node was allocated by __kmalloc, so kfree is correct.
        bindings::kfree(node as *const c_void);
    }
}

/// Look up an element in the LPM trie.
///
/// Traverses the trie from root, following child pointers based on key bits.
/// At each node, computes the longest prefix match. The last non-intermediate
/// node whose prefix fully matches is the result (longest prefix match).
///
/// Returns a pointer to the value of the best match, or null if no match.
///
/// # Arguments
///
/// * `map` - Pointer to the `bpf_map` embedded in an `LpmTrie`.
/// * `key` - Pointer to the LPM key: `{ u32 prefixlen; u8 data[]; }`.
///
/// # Returns
///
/// - Pointer to the value of the longest matching prefix.
/// - `ptr::null_mut()` if no match is found or if the key's prefixlen exceeds
///   the trie's maximum.
///
/// # Safety
///
/// - `map` must point to a valid `bpf_map` that is part of an `LpmTrie`.
/// - `key` must point to a valid LPM key with at least `4 + data_size` bytes.
/// - Must be called under RCU read-side protection (or with BPF RCU lock held).
pub unsafe fn trie_lookup_elem(
    map: *const bindings::bpf_map,
    key: *const c_void,
) -> *mut c_void {
    let trie = LpmTrie::from_map_ptr(map);
    let key_ptr = key as *const u8;

    // Read prefixlen from the key header (first 4 bytes).
    let key_prefixlen = ptr::read_unaligned(key_ptr as *const u32);

    if key_prefixlen as usize > trie.max_prefixlen {
        return ptr::null_mut();
    }

    // Key data starts after the u32 prefixlen header.
    let key_data = key_ptr.add(LPM_KEY_HEADER_SIZE);

    let mut node = trie.root;
    let mut found: *mut LpmTrieNode = ptr::null_mut();

    // Traverse the trie from root following prefix bits.
    while !node.is_null() {
        let matchlen = longest_prefix_match(
            trie.data_size,
            node,
            key_data,
            key_prefixlen,
        );

        // If we matched the maximum possible prefix, this is an exact match.
        if matchlen == trie.max_prefixlen {
            found = node;
            break;
        }

        // If the match is shorter than the node's prefix, we've diverged.
        if matchlen < (*node).prefixlen as usize {
            break;
        }

        // This node's prefix fully matches. If it's a real node (not
        // intermediate), record it as the current best match.
        if (*node).flags & LPM_TREE_NODE_FLAG_IM == 0 {
            found = node;
        }

        // Descend to the child based on the next bit after the node's prefix.
        let next_bit = extract_bit(key_data, (*node).prefixlen as usize);
        node = (*node).children[next_bit];
    }

    if found.is_null() {
        return ptr::null_mut();
    }

    // Return pointer to the value area (data + data_size).
    node_value(found, trie.data_size) as *mut c_void
}

/// Insert or update an element in the LPM trie.
///
/// Acquires the trie spinlock, traverses to find the insertion point,
/// allocates a new node, and links it into the trie. If replacing an
/// existing node, the old node is freed after the spinlock is released.
///
/// # Algorithm
///
/// 1. Validate flags and key prefixlen.
/// 2. Allocate a new node with the value.
/// 3. Acquire spinlock.
/// 4. Walk the trie to find the insertion slot:
///    - If the slot is empty, insert directly.
///    - If an existing node has the same prefix, replace it.
///    - If the new key diverges mid-node, create an intermediate node.
/// 5. Release spinlock.
/// 6. Free any replaced nodes.
///
/// # Safety
///
/// - `map` must point to a valid `bpf_map` that is part of an `LpmTrie`.
/// - `key` must point to a valid LPM key with at least `4 + data_size` bytes.
/// - `value` must point to at least `map.value_size` readable bytes.
pub unsafe fn trie_update_elem(
    map: *mut bindings::bpf_map,
    key: *const c_void,
    value: *const c_void,
    flags: u64,
) -> Result {
    let trie = LpmTrie::from_map_ptr_mut(map);
    let key_ptr = key as *const u8;

    // Validate flags.
    if flags > bindings::BPF_EXIST {
        return Err(Error::EINVAL);
    }

    // Read key fields.
    let key_prefixlen = ptr::read_unaligned(key_ptr as *const u32);
    let key_data = key_ptr.add(LPM_KEY_HEADER_SIZE);

    if key_prefixlen as usize > trie.max_prefixlen {
        return Err(Error::EINVAL);
    }

    // Allocate a new node with the value.
    let new_node = lpm_trie_node_alloc(trie as *const LpmTrie, value);
    if new_node.is_null() {
        return Err(Error::ENOMEM);
    }

    // Acquire spinlock.
    // SAFETY: trie.lock is a valid, initialized rqspinlock_t.
    let lock_ret = bindings::rqspin_lock(&mut trie.lock);
    if lock_ret != 0 {
        lpm_trie_node_free(new_node);
        return Err(Error::EBUSY);
    }

    // Initialize the new node's fields under the lock.
    (*new_node).prefixlen = key_prefixlen;
    (*new_node).children[0] = ptr::null_mut();
    (*new_node).children[1] = ptr::null_mut();
    // Copy key data into the new node.
    ptr::copy_nonoverlapping(key_data, node_data_mut(new_node), trie.data_size);

    // Walk the trie to find the insertion point.
    let mut slot: *mut *mut LpmTrieNode = &mut trie.root;
    let mut node: *mut LpmTrieNode = *slot;
    let mut matchlen: usize = 0;

    while !node.is_null() {
        matchlen = longest_prefix_match(
            trie.data_size,
            node,
            key_data,
            key_prefixlen,
        );

        if (*node).prefixlen as usize != matchlen
            || (*node).prefixlen == key_prefixlen
        {
            break;
        }

        let next_bit = extract_bit(key_data, (*node).prefixlen as usize);
        slot = &mut (*node).children[next_bit];
        node = *slot;
    }

    // Case 1: Empty slot — insert directly.
    if node.is_null() {
        let ret = trie_check_add_elem(trie, flags);
        if let Err(e) = ret {
            bindings::rqspin_unlock(&mut trie.lock);
            lpm_trie_node_free(new_node);
            return Err(e);
        }
        *slot = new_node;
        bindings::rqspin_unlock(&mut trie.lock);
        return Ok(());
    }

    // Case 2: Existing node with same prefixlen — replace it.
    if (*node).prefixlen as usize == matchlen {
        if (*node).flags & LPM_TREE_NODE_FLAG_IM == 0 {
            // Real node exists — check BPF_NOEXIST flag.
            if flags == bindings::BPF_NOEXIST {
                bindings::rqspin_unlock(&mut trie.lock);
                lpm_trie_node_free(new_node);
                return Err(Error::EEXIST);
            }
        } else {
            // Intermediate node — this is effectively a new entry.
            let ret = trie_check_add_elem(trie, flags);
            if let Err(e) = ret {
                bindings::rqspin_unlock(&mut trie.lock);
                lpm_trie_node_free(new_node);
                return Err(e);
            }
        }

        // Inherit children from the old node.
        (*new_node).children[0] = (*node).children[0];
        (*new_node).children[1] = (*node).children[1];

        // Replace the old node with the new one.
        *slot = new_node;

        bindings::rqspin_unlock(&mut trie.lock);
        // Free old node after releasing lock (RCU-safe in kernel context).
        lpm_trie_node_free(node);
        return Ok(());
    }

    // Case 3: Need to split — either new node is ancestor or need intermediate.
    let ret = trie_check_add_elem(trie, flags);
    if let Err(e) = ret {
        bindings::rqspin_unlock(&mut trie.lock);
        lpm_trie_node_free(new_node);
        return Err(e);
    }

    // Case 3a: New node's prefix fully matched — it becomes an ancestor.
    if matchlen == key_prefixlen as usize {
        let next_bit = extract_bit(node_data(node), matchlen);
        (*new_node).children[next_bit] = node;
        *slot = new_node;
        bindings::rqspin_unlock(&mut trie.lock);
        return Ok(());
    }

    // Case 3b: Need an intermediate node to split the divergence.
    let im_node = lpm_trie_node_alloc(trie as *const LpmTrie, ptr::null());
    if im_node.is_null() {
        // Undo the entry count increment.
        trie.n_entries -= 1;
        bindings::rqspin_unlock(&mut trie.lock);
        lpm_trie_node_free(new_node);
        return Err(Error::ENOMEM);
    }

    (*im_node).prefixlen = matchlen as u32;
    (*im_node).flags = LPM_TREE_NODE_FLAG_IM;
    // Copy prefix data from the existing node (they share the common prefix).
    ptr::copy_nonoverlapping(
        node_data(node),
        node_data_mut(im_node),
        trie.data_size,
    );

    // Determine which child slot gets which node based on the diverging bit.
    if extract_bit(key_data, matchlen) != 0 {
        (*im_node).children[0] = node;
        (*im_node).children[1] = new_node;
    } else {
        (*im_node).children[0] = new_node;
        (*im_node).children[1] = node;
    }

    // Install the intermediate node in place of the existing node.
    *slot = im_node;

    bindings::rqspin_unlock(&mut trie.lock);
    Ok(())
}

/// Check whether a new entry can be added to the trie.
///
/// Validates the `flags` and checks the entry count against `max_entries`.
/// On success, increments `n_entries`.
///
/// # Returns
///
/// - `Ok(())` if the entry can be added.
/// - `Err(ENOENT)` if `flags == BPF_EXIST` and this would be a new entry.
/// - `Err(ENOSPC)` if the trie is at maximum capacity.
///
/// # Safety
///
/// - `trie` must be a valid mutable reference (caller holds spinlock).
unsafe fn trie_check_add_elem(trie: &mut LpmTrie, flags: u64) -> Result {
    if flags == bindings::BPF_EXIST {
        return Err(Error::ENOENT);
    }
    if trie.n_entries == trie.map.max_entries as usize {
        return Err(Error::ENOSPC);
    }
    trie.n_entries += 1;
    Ok(())
}

/// Delete an element from the LPM trie.
///
/// Acquires the trie spinlock, finds the node with the exact matching
/// prefix, unlinks it from the trie, and frees it. Handles three cases:
///
/// 1. Node has two children: mark it as intermediate (don't remove).
/// 2. Node has no children and parent is intermediate: remove both node
///    and parent, promoting the parent's other child.
/// 3. Node has zero or one child: replace with child (or null).
///
/// # Safety
///
/// - `map` must point to a valid `bpf_map` that is part of an `LpmTrie`.
/// - `key` must point to a valid LPM key with at least `4 + data_size` bytes.
pub unsafe fn trie_delete_elem(
    map: *mut bindings::bpf_map,
    key: *const c_void,
) -> Result {
    let trie = LpmTrie::from_map_ptr_mut(map);
    let key_ptr = key as *const u8;

    // Read key fields.
    let key_prefixlen = ptr::read_unaligned(key_ptr as *const u32);
    let key_data = key_ptr.add(LPM_KEY_HEADER_SIZE);

    if key_prefixlen as usize > trie.max_prefixlen {
        return Err(Error::EINVAL);
    }

    // Acquire spinlock.
    // SAFETY: trie.lock is a valid, initialized rqspinlock_t.
    let lock_ret = bindings::rqspin_lock(&mut trie.lock);
    if lock_ret != 0 {
        return Err(Error::EBUSY);
    }

    // Walk the trie to find the target node.
    // `trim` points to the slot containing the target node.
    // `trim2` points to the slot containing the parent (for IM node removal).
    let mut trim: *mut *mut LpmTrieNode = &mut trie.root;
    let mut trim2: *mut *mut LpmTrieNode = trim;
    let mut parent: *mut LpmTrieNode = ptr::null_mut();
    let mut node: *mut LpmTrieNode = *trim;

    while !node.is_null() {
        let matchlen = longest_prefix_match(
            trie.data_size,
            node,
            key_data,
            key_prefixlen,
        );

        if (*node).prefixlen as usize != matchlen
            || (*node).prefixlen == key_prefixlen
        {
            break;
        }

        parent = node;
        trim2 = trim;
        let next_bit = extract_bit(key_data, (*node).prefixlen as usize);
        trim = &mut (*node).children[next_bit];
        node = *trim;
    }

    // Verify we found an exact match that is not an intermediate node.
    if node.is_null()
        || (*node).prefixlen != key_prefixlen
        || (*node).prefixlen as usize != longest_prefix_match(
            trie.data_size, node, key_data, key_prefixlen)
        || (*node).flags & LPM_TREE_NODE_FLAG_IM != 0
    {
        bindings::rqspin_unlock(&mut trie.lock);
        return Err(Error::ENOENT);
    }

    trie.n_entries -= 1;

    let mut free_node: *mut LpmTrieNode = ptr::null_mut();
    let mut free_parent: *mut LpmTrieNode = ptr::null_mut();

    // Case 1: Node has two children — mark as intermediate instead of removing.
    if !(*node).children[0].is_null() && !(*node).children[1].is_null() {
        (*node).flags |= LPM_TREE_NODE_FLAG_IM;
    }
    // Case 2: Parent is intermediate and node has no children —
    // remove both and promote parent's other child.
    else if !parent.is_null()
        && (*parent).flags & LPM_TREE_NODE_FLAG_IM != 0
        && (*node).children[0].is_null()
        && (*node).children[1].is_null()
    {
        if node == (*parent).children[0] {
            *trim2 = (*parent).children[1];
        } else {
            *trim2 = (*parent).children[0];
        }
        free_parent = parent;
        free_node = node;
    }
    // Case 3: Node has zero or one child — replace with child.
    else {
        if !(*node).children[0].is_null() {
            *trim = (*node).children[0];
        } else if !(*node).children[1].is_null() {
            *trim = (*node).children[1];
        } else {
            *trim = ptr::null_mut();
        }
        free_node = node;
    }

    bindings::rqspin_unlock(&mut trie.lock);

    // Free removed nodes after releasing the lock.
    lpm_trie_node_free(free_parent);
    lpm_trie_node_free(free_node);

    Ok(())
}

// ===========================================================================
// Lifecycle functions (Task 10.2)
// ===========================================================================

/// Allowed map creation flags for LPM trie.
///
/// Matches the C `LPM_CREATE_FLAG_MASK`:
/// `BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | BPF_F_ACCESS_MASK`
const LPM_CREATE_FLAG_MASK: u32 =
    bindings::BPF_F_NO_PREALLOC | bindings::BPF_F_NUMA_NODE | bindings::BPF_F_ACCESS_MASK;

/// Minimum value size for LPM trie (1 byte).
const LPM_VAL_SIZE_MIN: usize = 1;

/// Allocate and initialize a new LPM trie map.
///
/// Validates the creation attributes, allocates the `LpmTrie` struct via
/// `BpfMapArea::alloc`, initializes the memory allocator for nodes, and
/// returns a pointer to the embedded `bpf_map` field.
///
/// # Algorithm
///
/// 1. Read attr fields (key_size, value_size, max_entries, map_flags).
/// 2. Validate: key_size in [LPM_KEY_SIZE_MIN, LPM_KEY_SIZE_MAX],
///    value_size >= LPM_VAL_SIZE_MIN, max_entries > 0.
/// 3. Reject unsupported flags (only BPF_F_NO_PREALLOC, BPF_F_NUMA_NODE,
///    and access flags are allowed). BPF_F_NO_PREALLOC must be set.
/// 4. Compute data_size = key_size - 4, max_prefixlen = data_size * 8.
/// 5. Allocate LpmTrie struct via BpfMapArea::alloc().
/// 6. Initialize fields (root=null, n_entries=0, lock=zeroed).
/// 7. Call bpf_map_init_from_attr.
/// 8. Initialize bpf_mem_alloc for node allocation.
/// 9. Return pointer to map field.
///
/// # Safety
///
/// - `attr` must be a valid pointer to a `bpf_attr` populated for a
///   BPF_MAP_CREATE command.
pub unsafe fn trie_alloc(
    attr: *const bindings::bpf_attr,
) -> Result<*mut bindings::bpf_map> {
    // SAFETY: Caller guarantees `attr` is a valid pointer to a bpf_attr
    // populated for BPF_MAP_CREATE.
    let attr_ref = &*attr;

    let key_size = attr_ref.key_size() as usize;
    let value_size = attr_ref.value_size() as usize;
    let max_entries = attr_ref.max_entries();
    let map_flags = attr_ref.map_flags();

    // Validate key_size bounds
    if !(LPM_KEY_SIZE_MIN..=LPM_KEY_SIZE_MAX).contains(&key_size) {
        return Err(Error::EINVAL);
    }

    // Validate value_size > 0
    if value_size < LPM_VAL_SIZE_MIN {
        return Err(Error::EINVAL);
    }

    // Validate max_entries > 0
    if max_entries == 0 {
        return Err(Error::EINVAL);
    }

    // BPF_F_NO_PREALLOC must be set (LPM trie requires it)
    if map_flags & bindings::BPF_F_NO_PREALLOC == 0 {
        return Err(Error::EINVAL);
    }

    // Reject unsupported flags
    if map_flags & !LPM_CREATE_FLAG_MASK != 0 {
        return Err(Error::EINVAL);
    }

    // Check that access flags are valid (not both RDONLY and WRONLY)
    if map_flags & bindings::BPF_F_ACCESS_MASK == bindings::BPF_F_ACCESS_MASK {
        return Err(Error::EINVAL);
    }

    // Compute derived sizes
    let data_size = key_size - LPM_KEY_HEADER_SIZE;
    let max_prefixlen = data_size * 8;

    // Allocate the LpmTrie struct
    let alloc_size = mem::size_of::<LpmTrie>() as u64;
    let raw_ptr = BpfMapArea::alloc(alloc_size, bindings::NUMA_NO_NODE)?;

    // SAFETY: BpfMapArea::alloc returned a non-null pointer with at least
    // alloc_size bytes. We zero-initialize and set up the struct.
    // Safety (cast_ptr_alignment): BpfMapArea::alloc delegates to kmalloc/vmalloc
    // which return memory aligned to at least max_align_t (>= 8 bytes), satisfying
    // the alignment requirement of LpmTrie.
    #[allow(clippy::cast_ptr_alignment)]
    let trie = raw_ptr as *mut LpmTrie;
    ptr::write_bytes(raw_ptr, 0, alloc_size as usize);

    // Initialize the bpf_map common fields from the attr.
    // SAFETY: trie->map is within the valid allocation, and attr is valid.
    bindings::bpf_map_init_from_attr(&mut (*trie).map, attr);

    // Initialize trie-specific fields
    (*trie).data_size = data_size;
    (*trie).max_prefixlen = max_prefixlen;
    (*trie).root = ptr::null_mut();
    (*trie).n_entries = 0;
    (*trie).lock = bindings::rqspinlock_t::new();

    // Initialize the BPF memory allocator for node allocation.
    // leaf_size = sizeof(LpmTrieNode) + data_size + value_size
    let leaf_size = mem::size_of::<LpmTrieNode>() + data_size + value_size;
    let err = bindings::bpf_mem_alloc_init(
        &mut (*trie).ma,
        leaf_size as i32,
        false,
    );
    if err != 0 {
        // Allocation failed, free the trie struct and return the error.
        BpfMapArea::free(raw_ptr);
        // bpf_mem_alloc_init returns negative errno on failure.
        return match Error::from_errno(err) {
            Some(e) => Err(e),
            None => Err(Error::ENOMEM),
        };
    }

    // Return pointer to the embedded bpf_map field (first field, offset 0)
    Ok(&mut (*trie).map as *mut bindings::bpf_map)
}

/// Free an LPM trie map and all its nodes.
///
/// Iteratively walks the trie from the root, always descending to leaf
/// nodes (nodes with no children), frees them, nullifies the parent's
/// reference, and repeats until the tree is empty. Finally frees the
/// memory allocator and the trie struct itself.
///
/// # Safety
///
/// - `map` must point to a valid `bpf_map` that is the first field of an
///   `LpmTrie` previously allocated by [`trie_alloc`].
/// - Must not be called more than once for the same map.
/// - No other references to the trie or its nodes may exist after this call.
pub unsafe fn trie_free(map: *mut bindings::bpf_map) {
    let trie = map as *mut LpmTrie;

    // Walk the tree iteratively, always removing leaf nodes.
    // This mirrors the C implementation's approach: start at root,
    // descend to a childless node, free it, null its parent's pointer,
    // then start over from root.
    loop {
        let mut slot: *mut *mut LpmTrieNode = &mut (*trie).root;

        loop {
            let node = *slot;
            if node.is_null() {
                // Root is null — tree is empty, we're done.
                // Destroy the memory allocator and free the trie struct.
                bindings::bpf_mem_alloc_destroy(&mut (*trie).ma);
                BpfMapArea::free(trie as *mut u8);
                return;
            }

            // Descend to the left child if it exists.
            if !(*node).children[0].is_null() {
                slot = &mut (*node).children[0];
                continue;
            }

            // Descend to the right child if it exists.
            if !(*node).children[1].is_null() {
                slot = &mut (*node).children[1];
                continue;
            }

            // Node has no children — free it and null the slot.
            // SAFETY: Node was allocated by lpm_trie_node_alloc via __kmalloc.
            bindings::kfree(node as *const c_void);
            *slot = ptr::null_mut();
            break;
        }
    }
}

/// Get the next key in post-order traversal of the LPM trie.
///
/// This implements the `get_next_key` operation for key iteration.
/// The traversal follows post-order (more specific keys before less
/// specific ones).
///
/// - If `key` is null or invalid, returns the leftmost leaf key in the trie.
/// - Otherwise, finds the key's position and returns the next key in
///   post-order traversal.
/// - Returns `Err(ENOENT)` when there are no more keys or the trie is empty.
///
/// # Safety
///
/// - `map` must point to a valid `bpf_map` that is part of an `LpmTrie`.
/// - If `key` is non-null, it must point to a valid LPM key with at least
///   `4 + data_size` bytes.
/// - `next_key` must point to a writable buffer of at least `4 + data_size` bytes.
pub unsafe fn trie_get_next_key(
    map: *const bindings::bpf_map,
    key: *const c_void,
    next_key: *mut c_void,
) -> Result {
    let trie = LpmTrie::from_map_ptr(map);

    // Empty trie
    let search_root = trie.root;
    if search_root.is_null() {
        return Err(Error::ENOENT);
    }

    // For null or invalid key, find the leftmost non-intermediate leaf
    if key.is_null() {
        let node = find_leftmost(search_root);
        if node.is_null() {
            return Err(Error::ENOENT);
        }
        copy_node_key(node, trie.data_size, next_key);
        return Ok(());
    }

    let key_ptr = key as *const u8;
    let key_prefixlen = ptr::read_unaligned(key_ptr as *const u32);

    // If prefixlen exceeds max, treat as invalid key → find leftmost
    if key_prefixlen as usize > trie.max_prefixlen {
        let node = find_leftmost(search_root);
        if node.is_null() {
            return Err(Error::ENOENT);
        }
        copy_node_key(node, trie.data_size, next_key);
        return Ok(());
    }

    let key_data = key_ptr.add(LPM_KEY_HEADER_SIZE);

    // Allocate a stack to track the traversal path.
    // Maximum depth is max_prefixlen + 1.
    let stack_size = trie.max_prefixlen + 1;
    let stack_alloc_size = stack_size * mem::size_of::<*mut LpmTrieNode>();
    let stack_ptr = bindings::__kmalloc(stack_alloc_size, bindings::GFP_ATOMIC) as *mut *mut LpmTrieNode;
    if stack_ptr.is_null() {
        return Err(Error::ENOMEM);
    }

    let mut stack_idx: isize = -1;

    // Try to find the exact node for the given key
    let mut node = search_root;
    while !node.is_null() {
        stack_idx += 1;
        *stack_ptr.offset(stack_idx) = node;

        let matchlen = longest_prefix_match(
            trie.data_size,
            node,
            key_data,
            key_prefixlen,
        );

        if (*node).prefixlen as usize != matchlen
            || (*node).prefixlen == key_prefixlen
        {
            break;
        }

        let next_bit = extract_bit(key_data, (*node).prefixlen as usize);
        node = (*node).children[next_bit];
    }

    // If we didn't find the exact node, find leftmost from search_root
    if node.is_null()
        || (*node).prefixlen != key_prefixlen
        || (*node).flags & LPM_TREE_NODE_FLAG_IM != 0
    {
        let leftmost = find_leftmost(search_root);
        if leftmost.is_null() {
            bindings::kfree(stack_ptr as *const c_void);
            return Err(Error::ENOENT);
        }
        copy_node_key(leftmost, trie.data_size, next_key);
        bindings::kfree(stack_ptr as *const c_void);
        return Ok(());
    }

    // The node with the exactly-matching key has been found.
    // Find the first node in post-order after the matched node.
    node = *stack_ptr.offset(stack_idx);
    while stack_idx > 0 {
        let parent = *stack_ptr.offset(stack_idx - 1);

        // If current node is the left child of parent, try the right subtree
        if (*parent).children[0] == node {
            let right_child = (*parent).children[1];
            if !right_child.is_null() {
                let leftmost = find_leftmost(right_child);
                if !leftmost.is_null() {
                    copy_node_key(leftmost, trie.data_size, next_key);
                    bindings::kfree(stack_ptr as *const c_void);
                    return Ok(());
                }
            }
        }

        // If parent is a real (non-intermediate) node, it's next in post-order
        if (*parent).flags & LPM_TREE_NODE_FLAG_IM == 0 {
            copy_node_key(parent, trie.data_size, next_key);
            bindings::kfree(stack_ptr as *const c_void);
            return Ok(());
        }

        node = parent;
        stack_idx -= 1;
    }

    // No more keys
    bindings::kfree(stack_ptr as *const c_void);
    Err(Error::ENOENT)
}

/// Find the leftmost non-intermediate node in the subtree rooted at `root`.
///
/// Follows left children preferentially, returning the deepest
/// non-intermediate node found. For intermediate nodes, always descends
/// left. For real nodes, records as candidate and tries to go deeper
/// (left first, then right).
///
/// # Safety
///
/// - `root` must be a valid, non-null pointer to an `LpmTrieNode`.
unsafe fn find_leftmost(root: *mut LpmTrieNode) -> *mut LpmTrieNode {
    let mut next_node: *mut LpmTrieNode = ptr::null_mut();
    let mut node = root;

    while !node.is_null() {
        if (*node).flags & LPM_TREE_NODE_FLAG_IM != 0 {
            // Intermediate node: always go left
            node = (*node).children[0];
        } else {
            // Real node: record as candidate, try to go deeper
            next_node = node;
            node = (*node).children[0];
            if node.is_null() {
                node = (*next_node).children[1];
            }
        }
    }

    next_node
}

/// Copy a node's key (prefixlen + data) into the output buffer.
///
/// # Safety
///
/// - `node` must point to a valid `LpmTrieNode` with `data_size` bytes of data.
/// - `out` must point to a writable buffer of at least `4 + data_size` bytes.
#[inline]
unsafe fn copy_node_key(node: *const LpmTrieNode, data_size: usize, out: *mut c_void) {
    let out_ptr = out as *mut u8;
    // Write prefixlen (u32) to the first 4 bytes
    ptr::write_unaligned(out_ptr as *mut u32, (*node).prefixlen);
    // Copy the data bytes
    ptr::copy_nonoverlapping(
        node_data(node),
        out_ptr.add(LPM_KEY_HEADER_SIZE),
        data_size,
    );
}
