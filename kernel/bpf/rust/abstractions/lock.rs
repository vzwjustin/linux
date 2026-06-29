// SPDX-License-Identifier: GPL-2.0
//! Safe spinlock abstraction over the kernel's resilient queued spinlock.
//!
//! This module provides [`SpinLock<T>`], a type-safe wrapper around the
//! kernel's `rqspinlock_t`. The lock protects data of type `T` and encodes
//! lock ownership in the type system via [`SpinLockGuard`], ensuring that
//! the protected data can only be accessed while the lock is held.
//!
//! # Design
//!
//! - The lock and its protected data are co-located in [`SpinLock<T>`],
//!   making it impossible to access the data without acquiring the lock.
//! - [`SpinLockGuard`] implements [`Deref`] and [`DerefMut`], providing
//!   ergonomic access to the protected data.
//! - The guard auto-releases the lock on [`Drop`], preventing lock leaks.
//! - [`PhantomData<*mut ()>`] on the guard prevents it from being sent
//!   across thread boundaries, enforcing that locks are released on the
//!   same CPU/thread where they were acquired.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::bindings;

/// A kernel rqspinlock protecting data of type `T`.
///
/// Encodes lock ownership in the type system via [`SpinLockGuard`]. The
/// protected data can only be accessed through the guard returned by
/// [`lock()`](SpinLock::lock).
///
/// # Safety Contract
///
/// - Precondition: The lock must be initialized (zero-initialized is valid
///   for `rqspinlock_t`) before first use.
/// - Postcondition: While a [`SpinLockGuard`] exists, no other thread can
///   acquire the same lock (mutual exclusion).
/// - Undefined behavior: Using the lock after it has been freed, or
///   re-entering the lock on the same thread (deadlock, not UB per se,
///   but a liveness violation).
///
/// # Examples
///
/// ```ignore
/// // Safety: lock is zero-initialized (valid initial state for rqspinlock_t).
/// let lock = unsafe { SpinLock::new(42u32) };
/// {
///     let mut guard = lock.lock();
///     *guard += 1;
/// } // lock is automatically released here
/// ```
pub struct SpinLock<T> {
    /// The underlying kernel spinlock primitive.
    lock: UnsafeCell<bindings::rqspinlock_t>,
    /// The protected data. Only accessible through a [`SpinLockGuard`].
    data: UnsafeCell<T>,
}

// Safety: `SpinLock<T>` synchronizes all access to the inner `T` through
// the kernel spinlock. As long as `T` can be sent between threads (`Send`),
// the `SpinLock` itself can be both sent between threads and shared across
// threads safely. The spinlock ensures mutual exclusion — only one thread
// can access `T` at a time.
unsafe impl<T: Send> Send for SpinLock<T> {}

// Safety: Sharing a `&SpinLock<T>` across threads is safe because all access
// to the inner `T` goes through `lock()`, which acquires the kernel spinlock
// first. The spinlock provides the synchronization required for `Sync`.
unsafe impl<T: Send> Sync for SpinLock<T> {}

/// RAII guard that provides access to spinlock-protected data.
///
/// Created by [`SpinLock::lock()`]. Dereferences to the protected `T` and
/// automatically releases the lock when dropped.
///
/// # Thread Safety
///
/// The `PhantomData<*mut ()>` field makes this type `!Send`, preventing the
/// guard from being moved to another thread. This enforces that the lock
/// is always released on the same CPU/thread where it was acquired, which
/// is a requirement of the kernel spinlock API.
pub struct SpinLockGuard<'a, T> {
    /// Reference back to the lock, used for data access and unlock.
    lock: &'a SpinLock<T>,
    /// Marker to make the guard `!Send`. Raw pointers are `!Send` and
    /// `!Sync`, preventing this guard from crossing thread boundaries.
    _not_send: PhantomData<*mut ()>,
}

impl<T> SpinLock<T> {
    /// Create a new spinlock wrapping the given data.
    ///
    /// The lock is created in the unlocked state (zero-initialized).
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - The `SpinLock` is not used after the memory it occupies is freed.
    /// - The `SpinLock` is used in a context where spinlocks are permitted
    ///   (not in NMI context unless the lock is NMI-safe).
    /// - The lock initialization is valid for the kernel's rqspinlock
    ///   implementation (zero-init is valid).
    pub const unsafe fn new(data: T) -> Self {
        Self {
            lock: UnsafeCell::new(bindings::rqspinlock_t::new()),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the spinlock, returning a guard that releases on drop.
    ///
    /// This function spins until the lock is acquired. The returned
    /// [`SpinLockGuard`] provides exclusive access to the protected data
    /// and releases the lock when it goes out of scope.
    ///
    /// # Panics
    ///
    /// Does not panic. The kernel spinlock implementation may trigger a
    /// watchdog if the lock is held for too long, but that is a kernel
    /// liveness concern, not a Rust panic.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        // Safety: `self.lock` is a valid, initialized `rqspinlock_t`.
        // We pass a mutable pointer as required by the C API. The
        // `UnsafeCell` provides interior mutability for this purpose.
        // After this call returns, we hold the lock exclusively.
        unsafe { bindings::rqspin_lock(self.lock.get()) };
        SpinLockGuard {
            lock: self,
            _not_send: PhantomData,
        }
    }
}

impl<'a, T> Deref for SpinLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // Safety: We hold the spinlock (guaranteed by the existence of this
        // guard), so we have exclusive access to the data. Creating a shared
        // reference is safe because no other thread can access the data while
        // we hold the lock.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // Safety: We hold the spinlock exclusively (guaranteed by the
        // existence of this guard and the `&mut self` borrow), so we have
        // exclusive mutable access to the data. No other thread can access
        // the data while we hold the lock.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        // Safety: We are the holder of this lock (guaranteed by construction
        // in `SpinLock::lock()`). Releasing it here restores the lock to
        // the unlocked state. After this call, no further access to the
        // protected data is possible through this guard (it is being dropped).
        unsafe { bindings::rqspin_unlock(self.lock.lock.get()) };
    }
}
