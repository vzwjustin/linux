//! Property-based tests for kernel Rust conversion correctness properties.
//!
//! Each test function in this module corresponds to a numbered correctness
//! property from the design document. Tests use the `proptest` framework and
//! are configured to execute a minimum of 1000 iterations per property via
//! `proptest.toml`.
//!
//! # Properties Covered
//!
//! - Property 1: Tier Classification Correctness (task 15.2)
//! - Property 2: Dependency Cycle Detection (task 15.3)
//! - Property 3: Subsystem Conversion Ranking (task 15.4)
//! - Property 4: Null Pointer Rejection at FFI Boundary (future)
//! - Property 5: Error Code Round-Trip (future)
//! - Property 6: Binary Layout Compatibility (task 15.5)
//! - Property 7: Cross-Implementation Functional Equivalence (task 15.6)
//! - Property 8: Data Structure Operation Invariants (future)
//! - Property 9: Parser/Serializer Round-Trip (future)
//! - Property 10: Allocation Failure Propagation (future)

// Property test implementations will be added by subsequent tasks (15.2–15.7).
