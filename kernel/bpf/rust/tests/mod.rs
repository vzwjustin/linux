//! Property-based and unit test modules for BPF map Rust implementations.
//!
//! This module aggregates all test submodules. Each submodule targets a specific
//! correctness property or functional area defined in the design document.
//!
//! # Running Tests
//!
//! ```sh
//! cargo test
//! ```
//!
//! # Running with Coverage (requires cargo-llvm-cov)
//!
//! ```sh
//! cargo llvm-cov --branch --open
//! ```
//!
//! # Property Test Configuration
//!
//! PropTest is configured via `proptest.toml` at the crate root with a minimum
//! of 1000 iterations per property (Requirement 5.2).

pub mod property_tests;
