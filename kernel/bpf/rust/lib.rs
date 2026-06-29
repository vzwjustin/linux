//! BPF Map Rust implementations for the Linux kernel.
//!
//! This crate provides safe Rust implementations of BPF map data structures,
//! intended to replace the C implementations in `kernel/bpf/`. Each module is
//! gated behind a Kconfig option allowing C and Rust implementations to coexist
//! and be toggled at build time.
//!
//! # Safety Policy
//!
//! - All algorithm and data transformation logic is implemented in safe Rust.
//! - Unsafe code is restricted to FFI boundary interactions and raw pointer
//!   manipulation required by kernel APIs.
//! - Every `unsafe` block includes a structured safety comment documenting the
//!   invariant relied upon, why it holds, and what could violate it.
//! - Panicking constructs (`unwrap`, `expect`, `[]` indexing) are denied at the
//!   crate level via clippy lints.

#![no_std]
#![warn(missing_docs)]
// ─────────────────────────────────────────────────────────────────────────────
// Crate-level lint configuration for kernel Rust coding compliance.
//
// These denials enforce the kernel's no-panic policy and memory safety
// requirements. In kernel context, any panic aborts the faulting task (or
// triggers BUG()), so all constructs that can panic must be replaced with
// fallible alternatives returning Result/Option.
// ─────────────────────────────────────────────────────────────────────────────

// --- Panic-inducing constructs (Requirement 7.6: no panic-prone constructs) ---

// Deny `.unwrap()` — use `ok_or()`/`?` or pattern matching instead.
// Deny `.expect()` — same rationale; the message is irrelevant if we abort.
// Deny `[]` indexing — use `.get()` which returns Option, preventing OOB panics.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
// Deny `panic!()` macro — kernel code must never explicitly panic; return an
// error code to the caller instead.
#![deny(clippy::panic)]
// Deny `todo!()` and `unimplemented!()` — these are placeholder panics that
// must never ship in kernel code. Incomplete functionality should return
// -EOPNOTSUPP or be gated behind a Kconfig option.
#![deny(clippy::todo, clippy::unimplemented)]
// Deny `unreachable!()` — use `core::hint::unreachable_unchecked()` inside
// unsafe blocks with a safety comment, or restructure logic to avoid the need.
// In most cases, returning an error is preferable.
#![deny(clippy::unreachable)]

// --- Pointer safety (Requirement 8.5: clippy with kernel lint set) ---

// Deny casts that change pointer alignment — such casts can cause undefined
// behavior on architectures requiring aligned access. Use `read_unaligned`/
// `write_unaligned` or transmute with explicit alignment checks.
#![deny(clippy::cast_ptr_alignment)]

extern crate alloc;

pub mod bindings;
pub mod error;
pub mod abstractions;
#[cfg(CONFIG_BPF_RUST_MAPS)]
pub mod arraymap;
#[cfg(CONFIG_BPF_RUST_MAPS)]
pub mod bloom_filter;
#[cfg(CONFIG_BPF_RUST_MAPS)]
pub mod ffi_wrappers;
#[cfg(CONFIG_BPF_RUST_MAPS)]
pub mod hashtab;
#[cfg(CONFIG_BPF_RUST_MAPS)]
pub mod lpm_trie;
#[cfg(CONFIG_BPF_RUST_MAPS)]
pub mod queue_stack_maps;
#[cfg(CONFIG_BPF_RUST_MAPS)]
pub mod ringbuf;
#[cfg(CONFIG_BPF_RUST_MAPS)]
pub mod map_ops;
pub mod tooling;

#[cfg(test)]
mod tests;

#[cfg(all(test, CONFIG_BPF_RUST_MAPS))]
mod arraymap_tests;

// ─────────────────────────────────────────────────────────────────────────────
// Panic handler — invokes the kernel's BUG() macro to halt the faulting context.
//
// In kernel builds, panic = "abort" is set, so this handler is the terminal
// action. We call into a C-side wrapper (`kernel_bug`) that expands the BUG()
// macro, which triggers an oops/panic at the kernel level.
//
// Gated behind `#[cfg(not(test))]` to avoid conflicting with the standard
// test harness panic handler during `cargo test` runs.
// ─────────────────────────────────────────────────────────────────────────────

extern "C" {
    /// C-side wrapper that expands the kernel BUG() macro.
    /// Defined in a companion .c file (e.g., `kernel/bpf/rust_helpers.c`).
    fn kernel_bug() -> !;
}

/// Custom panic handler for kernel context (Requirement 7.3).
///
/// When a panic occurs in the Rust BPF crate, this handler invokes the
/// kernel's `BUG()` macro via the `kernel_bug()` FFI helper. This halts
/// the faulting context with a full register dump and backtrace, matching
/// the kernel's expected crash behavior.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Safety: kernel_bug() is provided by the kernel C helper and never
    // returns — it triggers BUG() which halts the current context.
    unsafe { kernel_bug() }
}
