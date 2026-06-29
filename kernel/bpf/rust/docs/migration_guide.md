# BPF Map Rust Conversion — Migration Guide

This document maps the original C functions in `kernel/bpf/` to their Rust equivalents
in `kernel/bpf/rust/`. It covers each of the six converted modules, documents semantic
differences, and explains the cross-cutting patterns (error handling, null validation,
Kconfig toggling) that apply uniformly across all modules.

---

## Table of Contents

1. [Cross-Cutting Patterns](#cross-cutting-patterns)
   - [Error Handling](#error-handling-pattern)
   - [Null Pointer Validation at FFI Boundary](#null-pointer-validation-at-ffi-boundary)
   - [Kconfig Toggle Mechanism](#kconfig-toggle-mechanism)
2. [Module: bloom_filter](#module-bloom_filter)
3. [Module: queue_stack_maps](#module-queue_stack_maps)
4. [Module: arraymap](#module-arraymap)
5. [Module: lpm_trie](#module-lpm_trie)
6. [Module: ringbuf](#module-ringbuf)
7. [Module: hashtab](#module-hashtab)

---

## Cross-Cutting Patterns

### Error Handling Pattern

The Rust conversion uses a layered error transformation at the FFI boundary:

```
C caller → FFI wrapper (extern "C") → Rust impl (returns Result<T, Error>) → FFI wrapper → C caller
                                         │                                         │
                                         │  Err(Error::ENOENT) ─────────────────→ -2 (c_long)
                                         │  Err(Error::EINVAL) ─────────────────→ -22 (c_long)
                                         │  Ok(()) ────────────────────────────→  0 (c_long)
```

**Inbound (C → Rust):** Negative errno values from C kernel functions are converted to
`Result::Err(Error)` via `Error::from_errno(code)` or `Error::from_raw(code)`. Unknown
negative codes are passed through unchanged (wrapped in the `Error` newtype).

**Internal:** All Rust implementation functions return `Result<T, Error>` using the `?`
operator for propagation. No panicking constructs (`unwrap`, `expect`, indexing) are used.

**Outbound (Rust → C):** The FFI wrapper calls `result_to_errno(result)` which maps
`Ok(())` → `0` and `Err(e)` → `e.to_errno()` (the original negative value). For
functions returning pointers (e.g., `map_alloc`), errors are encoded as `ERR_PTR(errno)`.

**Key types:**
- `crate::error::Error` — wraps `NonZeroI32` storing a negative errno
- `crate::error::Result<T>` — alias for `core::result::Result<T, Error>`
- Constants: `Error::ENOMEM` (-12), `Error::EINVAL` (-22), `Error::ENOENT` (-2),
  `Error::E2BIG` (-7), `Error::EOPNOTSUPP` (-95), `Error::EEXIST` (-17), `Error::EBUSY` (-16)

### Null Pointer Validation at FFI Boundary

Every `extern "C"` FFI wrapper validates pointer arguments before calling into Rust:

```rust
#[no_mangle]
pub unsafe extern "C" fn bloom_map_peek_elem_rs(
    map: *mut bpf_map,
    value: *mut c_void,
) -> c_long {
    check_null!(map, value);  // Returns -EINVAL if any pointer is null
    // ... safe to dereference after this point
}
```

The `check_null!` macro expands to:
```rust
if map.is_null() || value.is_null() {
    return Error::EINVAL.to_errno() as c_long;  // -22
}
```

This ensures that null dereferences are impossible — the Rust implementation never
receives a null pointer. The inner Rust functions accept references (`&bpf_map`) or
raw pointers that are guaranteed non-null by the wrapper.

For functions that legitimately accept null (e.g., `get_next_key` where `key` may be
null to start iteration), only the required-non-null arguments are checked.

### Kconfig Toggle Mechanism

The C and Rust implementations are mutually exclusive at build time via Kconfig:

```kconfig
# kernel/bpf/Kconfig.rust
choice
    prompt "BPF map implementation language"
    default BPF_C_MAPS

config BPF_C_MAPS
    bool "C implementation (default)"

config BPF_RUST_MAPS
    bool "Rust implementation"
    depends on RUST
endchoice
```

In `kernel/bpf/Makefile`:
```makefile
# When Rust is selected, compile Rust objects and exclude C map sources
obj-$(CONFIG_BPF_RUST_MAPS) += rust/
# When C is selected (default), compile C map sources as normal
obj-$(CONFIG_BPF_C_MAPS) += bloom_filter.o queue_stack_maps.o arraymap.o ...
```

Both implementations expose identical function names (via `#[no_mangle]` with `_rs`
suffix in the Rust version, linked via the `bpf_map_ops` table). Switching between
implementations requires only a `make menuconfig` toggle and rebuild — no source
changes, no ABI differences.

---

## Module: bloom_filter

**C source:** `kernel/bpf/bloom_filter.c`
**Rust source:** `kernel/bpf/rust/bloom_filter.rs`
**FFI wrappers:** `kernel/bpf/rust/ffi_wrappers.rs` (bloom section)

### Function Mapping

| C Function | Rust Equivalent | Semantic Differences | Notes |
|---|---|---|---|
| `bloom_map_peek_elem(struct bpf_map *map, void *value)` → `int` | `pub unsafe fn peek_elem(map: &bpf_map, value: *const c_void) -> Result` | None — identical behavior: returns 0 if all hash bits set, -ENOENT otherwise. | FFI wrapper: `bloom_map_peek_elem_rs`. C uses raw pointer for `map`; Rust receives a reference (null already rejected at FFI boundary). |
| `bloom_map_push_elem(struct bpf_map *map, void *value, u64 flags)` → `int` | `pub unsafe fn push_elem(map: &bpf_map, value: *const c_void, flags: u64) -> Result` | None — sets hash bits for value; returns -EINVAL if flags ≠ BPF_ANY. | FFI wrapper: `bloom_map_push_elem_rs`. |
| `bloom_map_alloc(union bpf_attr *attr)` → `struct bpf_map *` | `pub unsafe fn bloom_map_alloc(attr: *const bpf_attr) -> Result<*mut bpf_map>` | C returns ERR_PTR on failure; Rust returns `Result::Err`. FFI wrapper converts back to ERR_PTR. | Hash seed uses `get_random_u32()` unless `BPF_F_ZERO_SEED` is set (identical to C). Default 5 hash functions when map_extra == 0. |
| `bloom_map_free(struct bpf_map *map)` → `void` | `pub unsafe fn bloom_map_free(map: *mut bpf_map)` | None. | FFI wrapper: `bloom_map_free_rs`. No-op on null (wrapper guards). |
| `bloom_map_get_next_key(struct bpf_map *map, void *key, void *next_key)` → `int` | `pub fn bloom_map_get_next_key(...) -> Result` | None — always returns -EOPNOTSUPP (bloom filters are keyless). | FFI wrapper: `bloom_map_get_next_key_rs`. |

### Example Usage

```rust
// Rust internal call (from FFI wrapper after null checks):
let result = bloom_filter::peek_elem(&*map, value as *const c_void);
match result {
    Ok(()) => 0,        // Value is probably in the set
    Err(e) => e.to_errno() as c_long,  // -ENOENT: definitely not in set
}
```

---

## Module: queue_stack_maps

**C source:** `kernel/bpf/queue_stack_maps.c`
**Rust source:** `kernel/bpf/rust/queue_stack_maps.rs`
**FFI wrappers:** `kernel/bpf/rust/ffi_wrappers.rs` (queue/stack section)

### Function Mapping

| C Function | Rust Equivalent | Semantic Differences | Notes |
|---|---|---|---|
| `queue_stack_map_push_elem(struct bpf_map *map, void *value, u64 flags)` → `int` | `pub unsafe fn queue_stack_push_elem(qs: *mut BpfQueueStack, value: *const c_void, flags: u64) -> Result` | None — push at head, BPF_EXIST allows overwrite of oldest when full. Returns -E2BIG if full without BPF_EXIST. | FFI wrapper: `queue_map_push_elem_rs`. Shared by both queue and stack types. Spinlock acquired/released internally. |
| `queue_map_pop_elem(struct bpf_map *map, void *value)` → `int` | `pub unsafe fn queue_pop_elem(qs: *mut BpfQueueStack, value: *mut c_void) -> Result` | None — FIFO pop from tail. Returns -ENOENT if empty. Zeroes output buffer when empty (matches C). | FFI wrapper: `queue_map_pop_elem_rs`. |
| `stack_map_pop_elem(struct bpf_map *map, void *value)` → `int` | `pub unsafe fn stack_pop_elem(qs: *mut BpfQueueStack, value: *mut c_void) -> Result` | None — LIFO pop from head-1. Returns -ENOENT if empty. Zeroes output buffer when empty. | FFI wrapper: `stack_map_pop_elem_rs`. |
| `queue_map_peek_elem(struct bpf_map *map, void *value)` → `int` | `pub unsafe fn queue_peek_elem(qs: *mut BpfQueueStack, value: *mut c_void) -> Result` | None — peek at tail (oldest) without removing. | FFI wrapper: `queue_map_peek_elem_rs`. |
| `stack_map_peek_elem(struct bpf_map *map, void *value)` → `int` | `pub unsafe fn stack_peek_elem(qs: *mut BpfQueueStack, value: *mut c_void) -> Result` | None — peek at head-1 (newest) without removing. | FFI wrapper: `stack_map_peek_elem_rs`. |
| `queue_stack_map_alloc(union bpf_attr *attr)` → `struct bpf_map *` | `pub unsafe fn queue_stack_map_alloc(attr: *const bpf_attr) -> Result<*mut bpf_map>` | C returns ERR_PTR on failure; Rust returns `Result::Err`. FFI wrapper converts back to ERR_PTR. | Size is `max_entries + 1` (extra slot to distinguish full/empty). Zeroed on alloc. |
| `queue_stack_map_free(struct bpf_map *map)` → `void` | `pub unsafe fn queue_stack_map_free(map: *mut bpf_map)` | None. | FFI wrapper: `queue_stack_map_free_rs`. |

### Example Usage

```rust
// Push element onto queue/stack (from FFI wrapper):
let qs = map as *mut BpfQueueStack;
let result = queue_stack_maps::queue_stack_push_elem(qs, value, flags);
// result: Ok(()) or Err(E2BIG) if full, Err(EINVAL) if bad flags

// Pop from queue (FIFO):
let result = queue_stack_maps::queue_pop_elem(qs, output_buf);
// result: Ok(()) with data in output_buf, or Err(ENOENT) if empty
```

---

## Module: arraymap

**C source:** `kernel/bpf/arraymap.c`
**Rust source:** `kernel/bpf/rust/arraymap.rs`
**FFI wrappers:** `kernel/bpf/rust/ffi_wrappers.rs` (arraymap section)

### Function Mapping

| C Function | Rust Equivalent | Semantic Differences | Notes |
|---|---|---|---|
| `array_map_lookup_elem(struct bpf_map *map, void *key)` → `void *` | `pub unsafe fn array_map_lookup_elem(map: *const bpf_map, key: *const c_void) -> *mut c_void` | None — returns pointer to element slot or NULL if index out of bounds. | FFI wrapper: `array_map_lookup_elem_rs`. Returns raw pointer (not Result) since lookup uses the pointer-return convention. Spectre v1 index masking applied. |
| `array_map_update_elem(struct bpf_map *map, void *key, void *value, u64 flags)` → `int` | `pub unsafe fn array_map_update_elem(map: *const bpf_map, key: *const c_void, value: *const c_void, map_flags: u64) -> Result` | None — copies value into slot. -E2BIG if OOB, -EEXIST if BPF_NOEXIST (all slots pre-exist), -EINVAL if bad flags. | FFI wrapper: `array_map_update_elem_rs`. |
| `array_map_delete_elem(struct bpf_map *map, void *key)` → `int` | `pub unsafe fn array_map_delete_elem(_map: *const bpf_map, _key: *const c_void) -> Result` | None — always returns -EINVAL (array elements cannot be deleted). | FFI wrapper: `array_map_delete_elem_rs`. Does not dereference pointers. |
| `array_map_alloc(union bpf_attr *attr)` → `struct bpf_map *` | `pub unsafe fn array_map_alloc(attr: *const bpf_attr) -> Result<*mut bpf_map>` | C returns ERR_PTR on failure; Rust returns `Result::Err`. FFI wrapper returns NULL (not ERR_PTR). | Allocates struct and value array separately. `elem_size` is value_size rounded up to 8-byte alignment. `index_mask` provides Spectre v1 mitigation. |
| `array_map_free(struct bpf_map *map)` → `void` | `pub unsafe fn array_map_free(map: *mut bpf_map)` | None — frees value array then struct. | FFI wrapper: `array_map_free_rs`. |
| `array_map_get_next_key(struct bpf_map *map, void *key, void *next_key)` → `int` | `pub unsafe fn array_map_get_next_key(map: *const bpf_map, key: *const c_void, next_key: *mut c_void) -> Result` | None — sequential iteration [0, max_entries). Returns -ENOENT at end. Null key or OOB index restarts from 0. | FFI wrapper: `array_map_get_next_key_rs`. |

### Example Usage

```rust
// Lookup (returns raw pointer or null):
let value_ptr = arraymap::array_map_lookup_elem(map, key);
if value_ptr.is_null() {
    // Index out of bounds
}

// Update:
let result = arraymap::array_map_update_elem(map, key, value, BPF_ANY);
// Ok(()) on success, Err(E2BIG) if index >= max_entries

// Iteration:
let result = arraymap::array_map_get_next_key(map, current_key, next_key);
// Ok(()) with next index written, Err(ENOENT) at end of array
```

---

## Module: lpm_trie

**C source:** `kernel/bpf/lpm_trie.c`
**Rust source:** `kernel/bpf/rust/lpm_trie.rs`
**FFI wrappers:** `kernel/bpf/rust/ffi_wrappers.rs` (LPM trie section)

### Function Mapping

| C Function | Rust Equivalent | Semantic Differences | Notes |
|---|---|---|---|
| `trie_lookup_elem(struct bpf_map *map, void *key)` → `void *` | `pub unsafe fn trie_lookup_elem(map: *const bpf_map, key: *const c_void) -> *mut c_void` | None — returns pointer to value of longest matching prefix, or NULL. | FFI wrapper: `trie_lookup_elem_rs`. Key format: `{ u32 prefixlen; u8 data[]; }`. Traverses under RCU. |
| `trie_update_elem(struct bpf_map *map, void *key, void *value, u64 flags)` → `int` | `pub unsafe fn trie_update_elem(map: *mut bpf_map, key: *const c_void, value: *const c_void, flags: u64) -> Result` | None — insert/replace/split. Acquires spinlock. Node allocation uses GFP_ATOMIC. | FFI wrapper: `trie_update_elem_rs`. Handles 3 cases: empty slot, replace existing, split with intermediate node. -EEXIST if BPF_NOEXIST and key exists. -ENOENT if BPF_EXIST and key missing. -ENOSPC if at max_entries. |
| `trie_delete_elem(struct bpf_map *map, void *key)` → `int` | `pub unsafe fn trie_delete_elem(map: *mut bpf_map, key: *const c_void) -> Result` | None — finds exact prefix match, removes/marks intermediate. Acquires spinlock. | FFI wrapper: `trie_delete_elem_rs`. 3 removal strategies: mark as intermediate (2 children), remove node+parent (IM parent, no children), splice child. |
| `trie_alloc(union bpf_attr *attr)` → `struct bpf_map *` | `pub unsafe fn trie_alloc(attr: *const bpf_attr) -> Result<*mut bpf_map>` | C returns ERR_PTR on failure; Rust returns `Result::Err`. FFI wrapper converts to ERR_PTR. | Requires `BPF_F_NO_PREALLOC` flag. Key size in [5, 260] bytes. `data_size = key_size - 4`, `max_prefixlen = data_size * 8`. |
| `trie_free(struct bpf_map *map)` → `void` | `pub unsafe fn trie_free(map: *mut bpf_map)` | None — recursively frees all nodes then the trie struct. | FFI wrapper: `trie_free_rs`. |
| `trie_get_next_key(struct bpf_map *map, void *key, void *next_key)` → `int` | `pub unsafe fn trie_get_next_key(map: *const bpf_map, key: *const c_void, next_key: *mut c_void) -> Result` | None — post-order traversal. Null key returns leftmost entry. | FFI wrapper: `trie_get_next_key_rs`. |

### Example Usage

```rust
// Lookup longest prefix match:
let value_ptr = lpm_trie::trie_lookup_elem(map, key);
if value_ptr.is_null() {
    // No matching prefix
}

// Insert a prefix (key = { prefixlen: 24, data: [192, 168, 1, 0] }):
let result = lpm_trie::trie_update_elem(map, key, value, BPF_ANY);
// Ok(()) on success

// Delete exact prefix:
let result = lpm_trie::trie_delete_elem(map, key);
// Ok(()) or Err(ENOENT) if prefix not found
```

---

## Module: ringbuf

**C source:** `kernel/bpf/ringbuf.c`
**Rust source:** `kernel/bpf/rust/ringbuf.rs`
**FFI wrappers:** `kernel/bpf/rust/ffi_wrappers.rs` (ring buffer section)

### Function Mapping

| C Function | Rust Equivalent | Semantic Differences | Notes |
|---|---|---|---|
| `bpf_ringbuf_reserve(struct bpf_map *map, u64 size, u64 flags)` → `void *` | `pub unsafe fn reserve(&self, size: u64) -> Result<*mut u8>` | None — lock-free CAS loop to reserve contiguous space. Returns -ENOMEM if full. | FFI wrapper: `ringbuf_reserve_rs`. Flags must be 0. Returns pointer to data area (past the header) with BUSY_BIT set. |
| `bpf_ringbuf_submit(void *data, u64 flags)` → `void` | `pub unsafe fn submit(&self, data_ptr: *mut u8)` | None — clears BUSY_BIT atomically (Release ordering). Makes record visible to consumers. | FFI wrapper: `ringbuf_submit_rs`. Each reserved record must be submitted or discarded exactly once. |
| `bpf_ringbuf_discard(void *data, u64 flags)` → `void` | `pub unsafe fn discard(&self, data_ptr: *mut u8)` | None — sets DISCARD_BIT and clears BUSY_BIT atomically. Consumers skip discarded records. | FFI wrapper: `ringbuf_discard_rs`. |
| `bpf_ringbuf_output(struct bpf_map *map, void *data, u64 size, u64 flags)` → `int` | `pub unsafe fn output(&self, data: *const u8, size: u64, flags: u64) -> Result` | None — convenience combining reserve + copy + submit. Returns -ENOMEM if full, -EINVAL if null data or flags ≠ 0. | Combines three operations atomically from the producer's perspective. |
| `ringbuf_map_alloc(union bpf_attr *attr)` → `struct bpf_map *` | `pub unsafe fn ringbuf_alloc(attr: *const bpf_attr) -> Result<*mut bpf_map>` | C returns ERR_PTR on failure; Rust returns `Result::Err`. FFI wrapper converts to ERR_PTR. | `max_entries` must be power-of-2, page-aligned, > 0. key_size and value_size must be 0. Allocates struct + data pages + producer/consumer position pages. |
| `ringbuf_map_free(struct bpf_map *map)` → `void` | `pub unsafe fn ringbuf_free(map: *mut bpf_map)` | None — frees consumer page, producer page, data pages, then struct. | FFI wrapper: `ringbuf_free_rs`. |

### Example Usage

```rust
// Reserve space, write data, submit:
let rb = &*(map as *const BpfRingbuf);
match rb.reserve(payload_size) {
    Ok(data_ptr) => {
        // Write data into data_ptr...
        core::ptr::copy_nonoverlapping(src, data_ptr, payload_size as usize);
        rb.submit(data_ptr);  // Now visible to consumers
    }
    Err(_) => {
        // Ring buffer full — data dropped
    }
}

// Or use the convenience function:
let result = rb.output(src_data, size, 0);
// Ok(()) on success, Err(ENOMEM) if full
```

---

## Module: hashtab

**C source:** `kernel/bpf/hashtab.c`
**Rust source:** `kernel/bpf/rust/hashtab.rs`
**FFI wrappers:** `kernel/bpf/rust/ffi_wrappers.rs` (hashtab section — Tier 2)

### Function Mapping

| C Function | Rust Equivalent | Semantic Differences | Notes |
|---|---|---|---|
| `htab_map_lookup_elem(struct bpf_map *map, void *key)` → `void *` | `pub unsafe fn htab_map_lookup_elem(map: *const bpf_map, key: *const c_void) -> *mut c_void` | None — walks bucket chain comparing hash then key bytes. Returns pointer to value or NULL. | Called under RCU read-side lock (no per-bucket lock for reads). Uses Jenkins hash (jhash2/jhash). |
| `htab_map_update_elem(struct bpf_map *map, void *key, void *value, u64 flags)` → `int` | `pub unsafe fn htab_map_update_elem(map: *mut bpf_map, key: *const c_void, value: *const c_void, map_flags: u64) -> Result` | None — acquires per-bucket spinlock, allocates new element (GFP_ATOMIC), replaces or inserts at chain head. | -EINVAL bad flags, -E2BIG if at max_entries for new insert, -EEXIST if BPF_NOEXIST and key exists, -ENOENT if BPF_EXIST and key missing, -ENOMEM if alloc fails. Old element freed after lock release. |
| `htab_map_delete_elem(struct bpf_map *map, void *key)` → `int` | `pub unsafe fn htab_map_delete_elem(map: *mut bpf_map, key: *const c_void) -> Result` | None — acquires per-bucket lock, unlinks element, frees after lock release. Returns -ENOENT if not found. | Element count decremented atomically. |
| `htab_map_alloc(union bpf_attr *attr)` → `struct bpf_map *` | (allocation handled at map creation) | The Rust `BpfHtab` struct fields mirror C's `struct bpf_htab`. | `n_buckets` is always power-of-2. `elem_size` = sizeof(HtabElem) + key_size + round_up(key_size, 8) + value_size. `hasher_seed` is random. |
| `htab_map_free(struct bpf_map *map)` → `void` | (deallocation frees bucket array and struct) | Frees all elements in all buckets, then bucket array, then struct. | Must ensure no concurrent access (called after RCU grace period). |

### Example Usage

```rust
// Lookup:
let value_ptr = hashtab::htab_map_lookup_elem(map, key);
if value_ptr.is_null() {
    // Key not found
}

// Insert or update:
let result = hashtab::htab_map_update_elem(map, key, value, BPF_ANY);
// Ok(()) on success, Err(E2BIG) if map full

// Delete:
let result = hashtab::htab_map_delete_elem(map, key);
// Ok(()) on success, Err(ENOENT) if key not found
```

---

## Summary of Naming Conventions

| Pattern | C Name | Rust FFI Name | Rust Internal Name |
|---|---|---|---|
| Peek/query | `bloom_map_peek_elem` | `bloom_map_peek_elem_rs` | `bloom_filter::peek_elem` |
| Push/insert | `bloom_map_push_elem` | `bloom_map_push_elem_rs` | `bloom_filter::push_elem` |
| Alloc | `bloom_map_alloc` | `bloom_map_alloc_rs` | `bloom_filter::bloom_map_alloc` |
| Free | `bloom_map_free` | `bloom_map_free_rs` | `bloom_filter::bloom_map_free` |
| Lookup | `array_map_lookup_elem` | `array_map_lookup_elem_rs` | `arraymap::array_map_lookup_elem` |
| Update | `htab_map_update_elem` | (via map_ops dispatch) | `hashtab::htab_map_update_elem` |

The `_rs` suffix on FFI wrapper names distinguishes Rust entry points from C originals
when both exist in the build tree. The `bpf_map_ops` struct references the appropriate
function pointer depending on which Kconfig option is active.
