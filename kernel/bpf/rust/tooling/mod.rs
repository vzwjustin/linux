//! Tooling utilities for kernel subsystem conversion analysis.
//!
//! This module provides algorithmic utilities for:
//! - Tier classification of kernel source files based on dependency profiles
//! - Subsystem ranking within a tier by exported-symbol consumer count
//! - Cycle detection in module dependency graphs (Tarjan's SCC algorithm)
//!
//! These are pure analysis functions that do not interact with kernel APIs.

pub mod classify;

pub use classify::{
    classify_tier, detect_cycles, rank_subsystems, CycleDetectionResult, SubsystemInfo, Tier,
};
