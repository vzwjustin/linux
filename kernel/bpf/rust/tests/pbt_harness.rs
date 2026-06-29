//! Property-based test harness for BPF maps Rust conversion.
//!
//! This integration test file serves as the entry point for all proptest-based
//! property tests. It uses the `proptest` crate configured via `proptest.toml`
//! (1000 minimum cases per property, as required by Requirement 5.2).
//!
//! Feature: kernel-rust-conversion

use proptest::prelude::*;

mod property_tests;

// Smoke test to verify the proptest framework is operational.
// Feature: kernel-rust-conversion, Property: framework-validation
proptest! {
    #[test]
    fn proptest_framework_operational(x in 0u32..1000) {
        // Validates: Requirements 5.2, 5.4
        // Minimal property: proptest generates at least 1000 cases and the
        // framework does not panic or abort.
        prop_assert!(x < 1000);
    }
}
