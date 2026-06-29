// SPDX-License-Identifier: GPL-2.0
//! Safe RCU (Read-Copy-Update) abstraction for BPF map Rust implementations.
//!
//! This module provides safe wrappers around the kernel's RCU read-side
//! critical section API. The [`RcuReadGuard`] type uses RAII to ensure that
//! `rcu_read_lock()` and `rcu_read_unlock()` are always paired correctly.
//! The [`RcuProtected<T>`] wrapper enforces that RCU-protected pointers can
//! only be dereferenced while an RCU read-side critical section is active.
//!
//! # RCU Grace Period Requirements
//!
//! RCU (Read-Copy-Update) is a synchronization mechanism that allows readers
//! to access shared data without acquiring locks. Writers update data by
//! creating a new version, publishing it via an atomic pointer swap, and
//! then waiting for a *grace period* before freeing the old version.
//!
//! Key safety requirements:
//! - Readers must hold an [`RcuReadGuard`] while accessing RCU-protected data.
//! - Readers must not sleep or block while holding an [`RcuReadGuard`], as this
//!   would delay grace period completion and potentially deadlock the system.
//! - Writers must use `synchronize_rcu()` or `call_rcu()` to defer freeing old
//!   data until all pre-existing readers have completed their critical sections.
//! - Pointer updates by writers must use `rcu_assign_pointer()` (or equivalent
//!   atomic store with release ordering) to ensure readers see consistent data.
//! - Readers must use `rcu_dereference()` (or equivalent atomic load with
//!   consume/acquire ordering) to read RCU-protected pointers.

use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::bindings;

/// RAII guard for an RCU read-side critical section.
///
/// Creating an `RcuReadGuard` calls `rcu_read_lock()`, and dropping it calls
/// `rcu_read_unlock()`. This ensures that the RCU read-side critical section
/// is always properly bounded, even in the presence of early returns or panics.
///
/// # Safety Contract
///
/// - **Precondition**: May be created in any context where `rcu_read_lock()` is
///   valid (process context, softirq context, etc.). Must NOT be held across
///   sleeping operations.
/// - **Postcondition**: While this guard exists, RCU-protected data accessed via
///   [`RcuProtected::get`] is guaranteed not to be freed by writers.
/// - **Violation**: Holding this guard across a sleep point (`schedule()`,
///   `mutex_lock()`, `kmalloc(GFP_KERNEL)`, etc.) violates RCU assumptions
///   and can cause grace period stalls or deadlocks.
///
/// # Examples
///
/// ```ignore
/// use crate::abstractions::rcu::RcuReadGuard;
///
/// let guard = RcuReadGuard::new();
/// // Access RCU-protected data here...
/// drop(guard); // Explicitly end the critical section
/// ```
pub struct RcuReadGuard {
    /// Prevent `Send` — RCU read-side critical sections are per-CPU state
    /// and must not be transferred across threads/CPUs.
    _not_send: PhantomData<*mut ()>,
}

impl Default for RcuReadGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl RcuReadGuard {
    /// Enter an RCU read-side critical section.
    ///
    /// Calls `rcu_read_lock()` to mark the beginning of a read-side critical
    /// section. The section ends when this guard is dropped.
    ///
    /// # Safety Note
    ///
    /// While this function is safe to call, the caller must ensure they do not
    /// sleep or block while holding the returned guard. The type system cannot
    /// enforce this constraint, so it is a runtime obligation.
    #[inline]
    pub fn new() -> Self {
        // SAFETY:
        // - Invariant relied upon: `rcu_read_lock()` may be called in any
        //   non-sleeping context and is always safe to nest.
        // - Why it holds: We are constructing a guard that will be dropped
        //   (calling `rcu_read_unlock()`) before the calling function returns
        //   or is interrupted by a matching unlock.
        // - What could violate it: The caller sleeping while holding this guard
        //   would stall RCU grace periods. This is a runtime contract that
        //   cannot be enforced by the type system.
        unsafe { bindings::rcu_read_lock() };
        Self {
            _not_send: PhantomData,
        }
    }
}

impl Drop for RcuReadGuard {
    #[inline]
    fn drop(&mut self) {
        // SAFETY:
        // - Invariant relied upon: Every `rcu_read_lock()` must be paired with
        //   exactly one `rcu_read_unlock()` in the same context.
        // - Why it holds: This drop is called exactly once per `RcuReadGuard`,
        //   which was created by exactly one `rcu_read_lock()` call in `new()`.
        // - What could violate it: Calling `mem::forget()` on the guard would
        //   prevent this drop from running, leaving the RCU lock held
        //   indefinitely. Callers must not forget this guard.
        unsafe { bindings::rcu_read_unlock() };
    }
}

/// A pointer to RCU-protected data of type `T`.
///
/// This wrapper holds a raw pointer to data that is managed under RCU
/// semantics. The data can only be accessed (dereferenced) while holding an
/// [`RcuReadGuard`], which proves that an RCU read-side critical section is
/// active.
///
/// # Safety Contract
///
/// - The wrapped pointer must have been published using proper RCU pointer
///   assignment semantics (e.g., `rcu_assign_pointer()` or atomic store with
///   release ordering on the writer side).
/// - The pointed-to data must remain valid (not freed) for the duration of
///   any RCU read-side critical section that began before the writer called
///   `synchronize_rcu()` or equivalent grace period wait.
/// - Writers must not free the old data until after a grace period has elapsed.
///
/// # Type Parameters
///
/// * `T` - The type of the RCU-protected data. Must be `Send` since the data
///   may be accessed from different CPUs (though always under RCU protection).
pub struct RcuProtected<T> {
    /// The raw pointer to RCU-protected data.
    ///
    /// This is stored as a `NonNull` to encode the invariant that
    /// RCU-protected pointers are never null once initialized (null indicates
    /// the entry does not exist, which is a separate state).
    ptr: NonNull<T>,
}

// SAFETY: `RcuProtected` may be shared across threads because access to the
// underlying data is gated behind `RcuReadGuard`, which ensures proper RCU
// synchronization. The pointer itself is read-only; mutation happens through
// the writer path with proper locking.
unsafe impl<T: Send + Sync> Send for RcuProtected<T> {}

// SAFETY: Multiple threads may hold references to the same `RcuProtected`
// value simultaneously, as the RCU mechanism ensures that the pointed-to
// data remains valid for all concurrent readers.
unsafe impl<T: Send + Sync> Sync for RcuProtected<T> {}

impl<T> RcuProtected<T> {
    /// Create a new `RcuProtected` wrapper around a raw pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// 1. `ptr` is non-null and points to valid, initialized data of type `T`.
    /// 2. The data was published using proper RCU pointer assignment semantics
    ///    (atomic store with release ordering or `rcu_assign_pointer()`).
    /// 3. The data will not be freed until after a full RCU grace period has
    ///    elapsed following any update that replaces this pointer.
    /// 4. The data is safe to read from any CPU without additional
    ///    synchronization (i.e., it is effectively immutable once published,
    ///    or any mutation is handled by the writer creating a new copy).
    #[inline]
    pub unsafe fn new(ptr: *mut T) -> Option<Self> {
        NonNull::new(ptr).map(|nn| Self { ptr: nn })
    }

    /// Create a new `RcuProtected` wrapper from a `NonNull` pointer.
    ///
    /// # Safety
    ///
    /// Same safety requirements as [`RcuProtected::new`], except the non-null
    /// invariant is already guaranteed by the `NonNull` type.
    #[inline]
    pub const unsafe fn from_non_null(ptr: NonNull<T>) -> Self {
        Self { ptr }
    }

    /// Access the RCU-protected data within a read-side critical section.
    ///
    /// Returns a shared reference to the underlying data. The reference is
    /// bounded by the lifetime of the [`RcuReadGuard`], ensuring that the
    /// data cannot be accessed after the critical section ends.
    ///
    /// # Arguments
    ///
    /// * `_guard` - Proof that an RCU read-side critical section is active.
    ///   The reference lifetime is tied to this guard.
    ///
    /// # Safety Note
    ///
    /// This method is safe because:
    /// - The `_guard` parameter proves we hold `rcu_read_lock()`.
    /// - The constructor's safety contract guarantees the pointer is valid
    ///   and the data won't be freed while any read-side critical section
    ///   that started before the grace period is still active.
    /// - The returned reference's lifetime is bounded by the guard's lifetime,
    ///   so it cannot outlive the critical section.
    #[inline]
    pub fn get<'a>(&self, _guard: &'a RcuReadGuard) -> &'a T {
        // SAFETY:
        // - Invariant relied upon: The RCU-protected pointer points to valid
        //   data that will not be freed while any pre-existing read-side
        //   critical section is active.
        // - Why it holds: The `_guard` parameter proves we are inside an RCU
        //   read-side critical section (created by `RcuReadGuard::new()`).
        //   The constructor's safety preconditions guarantee the pointer was
        //   published correctly and the data remains valid during our critical
        //   section.
        // - What could violate it: (a) The writer freeing data without waiting
        //   for a grace period, (b) the pointer being created from an invalid
        //   address, (c) the data being mutated without copy-on-write
        //   semantics. All of these are prevented by the constructor's safety
        //   contract.
        unsafe { self.ptr.as_ref() }
    }

    /// Get the raw pointer to the RCU-protected data.
    ///
    /// This is useful when passing the pointer back to C code or when the
    /// caller needs to perform unsafe operations that require the raw pointer.
    ///
    /// # Safety Note
    ///
    /// The returned pointer is only valid to dereference while an RCU
    /// read-side critical section is active. The caller is responsible for
    /// ensuring this invariant if they dereference the pointer directly.
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr() as *const T
    }

    /// Get a mutable raw pointer to the RCU-protected data.
    ///
    /// # Safety
    ///
    /// This should only be used by writers who hold exclusive access (e.g.,
    /// under a spinlock) and are performing a copy-update operation. Readers
    /// must never use this method.
    #[inline]
    pub unsafe fn as_mut_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}

impl<T> Clone for RcuProtected<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for RcuProtected<T> {}
