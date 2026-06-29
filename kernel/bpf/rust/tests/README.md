# BPF Maps Rust — Test Suite

Property-based and unit tests for the BPF maps Rust conversion.

## Requirements

- Rust toolchain (stable or nightly)
- `proptest` — added as a dev-dependency in `Cargo.toml`
- `cargo-llvm-cov` — for coverage measurement (install with `cargo install cargo-llvm-cov`)

## Running Tests

```sh
# Run all tests (includes proptest with 1000 min iterations per property)
cargo test

# Run only property-based tests
cargo test --test pbt_harness
```

## Coverage Measurement

The project targets ≥90% branch coverage (Requirement 5.7).

### Install cargo-llvm-cov

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
```

### Generate Coverage Report

```sh
# Branch coverage report (HTML)
cargo llvm-cov --branch --open

# Branch coverage report (text summary)
cargo llvm-cov --branch

# Generate LCOV format for CI integration
cargo llvm-cov --branch --lcov --output-path lcov.info

# Fail if branch coverage drops below 90%
cargo llvm-cov --branch --fail-under-lines 90
```

### CI Integration

In CI pipelines, use the following to gate merges on coverage:

```sh
cargo llvm-cov --branch --fail-under-lines 90 --lcov --output-path lcov.info
```

This ensures that no merge proceeds if branch coverage drops below the 90%
threshold specified in Requirement 5.7.

## Test Organization

| File                    | Purpose                                         |
|-------------------------|-------------------------------------------------|
| `pbt_harness.rs`        | Integration test entry point for proptest       |
| `property_tests.rs`     | Property test implementations (Properties 1–10) |
| `mod.rs`                | Module declarations                             |

## PropTest Configuration

Configuration lives in `proptest.toml` at the crate root:

- **cases**: 1000 (minimum iterations per property, Requirement 5.2)
- **max_shrink_iters**: 10000 (thorough counterexample minimization)
- **timeout**: 60000 ms (generous for complex data structure operations)
