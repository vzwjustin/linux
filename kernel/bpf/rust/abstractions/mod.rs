// SPDX-License-Identifier: GPL-2.0
//! Safe abstractions over unsafe kernel primitives.
//!
//! This module provides safe Rust wrappers around kernel APIs used by the
//! converted BPF map implementations. Each submodule concentrates `unsafe`
//! code in a small, auditable surface and exposes a safe public API.
//!
//! # Purpose
//!
//! The kernel exposes many primitives (spinlocks, memory allocators, RCU,
//! bitmap operations) through C APIs that require careful management of
//! lifetimes, ordering, and error handling. This abstraction layer wraps
//! those APIs once and reuses the wrappers across all converted BPF map
//! modules, ensuring:
//!
//! - Consistent safety documentation and audit surface
//! - RAII-based resource management (locks released on drop, etc.)
//! - Error propagation via `Result` instead of raw errno/null checks
//! - Type-system enforcement of invariants (e.g., lock guard lifetimes)
//!
//! # Submodules
//!
//! - [`lock`] — Safe spinlock wrapper ([`SpinLock<T>`](lock::SpinLock) and
//!   [`SpinLockGuard`]) encoding mutual exclusion in
//!   the type system via RAII guards.
//!
//! - [`alloc`] — Kernel memory allocator ([`KernelAllocator`])
//!   providing fallible allocation via `try_alloc` and implementing
//!   `GlobalAlloc` for integration with Rust's allocator infrastructure.
//!
//! - [`bpf_mem`] — BPF map area allocator ([`BpfMapArea`])
//!   wrapping `bpf_map_area_alloc`/`bpf_map_area_free` for large map
//!   backing storage that may use vmalloc transparently.
//!
//! - [`rcu`] — RCU (Read-Copy-Update) abstractions
//!   ([`RcuReadGuard`] and
//!   [`RcuProtected<T>`](rcu::RcuProtected)) ensuring read-side critical
//!   sections are properly bounded and RCU-protected data is only accessed
//!   while a critical section is active.
//!
//! - [`bitmap`] — Bitmap operations ([`Bitmap`]) providing
//!   atomic set/test/clear bit manipulation matching kernel `set_bit`,
//!   `test_bit`, and `clear_bit` semantics with bounds checking.
//!
//! # Usage
//!
//! Consuming modules can import commonly used types directly from this
//! module without navigating into submodules:
//!
//! ```ignore
//! use crate::abstractions::{SpinLock, KernelAllocator, BpfMapArea, RcuReadGuard, Bitmap};
//! ```
//!
//! For less commonly used types or for clarity, the full submodule path is
//! also available:
//!
//! ```ignore
//! use crate::abstractions::rcu::RcuProtected;
//! use crate::abstractions::lock::SpinLockGuard;
//! ```

pub mod alloc;
pub mod bitmap;
pub mod bpf_mem;
pub mod lock;
pub mod rcu;

// Convenience re-exports of primary types.
//
// Only the most commonly used types from each submodule are re-exported here.
// Internal helpers and less frequently used types remain accessible via their
// full submodule paths.

pub use alloc::KernelAllocator;
pub use bitmap::Bitmap;
pub use bpf_mem::BpfMapArea;
pub use lock::{SpinLock, SpinLockGuard};
pub use rcu::{RcuProtected, RcuReadGuard};
