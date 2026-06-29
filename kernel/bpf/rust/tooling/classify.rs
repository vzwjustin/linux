//! Tier classification, subsystem ranking, and cycle detection utilities.
//!
//! This module provides purely algorithmic functions for analyzing kernel module
//! dependency graphs and prioritizing subsystems for Rust conversion. It does not
//! interact with kernel APIs.

// The tooling module performs internal array access on data structures it fully
// controls (sized to num_nodes). Allowing indexing here keeps the algorithm
// readable; all indices are bounded by construction.
#![allow(clippy::indexing_slicing)]

use alloc::vec;
use alloc::vec::Vec;

/// Conversion tier assigned to a kernel source file based on its dependency profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// Self-contained data structures with ≤3 local header dependencies and
    /// no exported symbols consumed by other unconverted modules.
    One,
    /// Subsystem modules with 4–10 local header dependencies or that export
    /// symbols consumed by up to 5 other subsystem files.
    Two,
    /// Core infrastructure with >10 local header dependencies or that exports
    /// symbols consumed by more than 5 other subsystem files.
    Three,
}

/// Classify a kernel source file into a conversion tier.
///
/// # Arguments
///
/// * `dep_count` — Number of local header dependencies (excluding kernel-wide API headers).
/// * `consumer_count` — Number of other unconverted modules consuming this file's exported symbols.
///
/// # Tier Rules (Requirement 1.3)
///
/// - **Tier 1**: `dep_count <= 3` AND `consumer_count == 0`
/// - **Tier 2**: (`4 <= dep_count <= 10`) OR (`1 <= consumer_count <= 5`), but NOT meeting Tier 1 criteria
/// - **Tier 3**: `dep_count > 10` OR `consumer_count > 5`
pub fn classify_tier(dep_count: usize, consumer_count: usize) -> Tier {
    // Tier 3 takes priority: high dependency or high consumer count
    if dep_count > 10 || consumer_count > 5 {
        return Tier::Three;
    }

    // Tier 1: low deps AND no consumers
    if dep_count <= 3 && consumer_count == 0 {
        return Tier::One;
    }

    // Everything else is Tier 2
    Tier::Two
}

/// Metadata for a subsystem used in ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemInfo {
    /// Name or identifier of the subsystem.
    pub name: &'static str,
    /// Number of exported symbols consumed by other unconverted modules.
    pub consumer_count: usize,
}

/// Rank subsystems within the same tier by ascending exported-symbol consumer count.
///
/// Subsystems with fewer consumers are converted first, minimizing integration
/// risk (Requirement 1.6).
///
/// The sort is stable: subsystems with equal consumer counts retain their
/// original relative order.
pub fn rank_subsystems(subsystems: &mut [SubsystemInfo]) {
    // Stable sort by ascending consumer_count
    subsystems.sort_by_key(|s| s.consumer_count);
}

/// Result of cycle detection on a module dependency graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleDetectionResult {
    /// Whether any cycle was detected (i.e., any SCC with more than one node).
    pub has_cycle: bool,
    /// All strongly connected components with more than one node.
    /// Each inner Vec contains the node indices forming the cycle.
    pub cycles: Vec<Vec<usize>>,
}

/// Detect cycles in a directed module dependency graph using Tarjan's algorithm.
///
/// A cycle exists if any strongly connected component (SCC) contains more than
/// one node (Requirement 1.5).
///
/// # Arguments
///
/// * `num_nodes` — Total number of nodes (modules) in the graph.
/// * `edges` — Adjacency list where `edges[i]` contains the indices of nodes that node `i` depends on.
///
/// # Returns
///
/// A `CycleDetectionResult` indicating whether cycles exist and listing all
/// non-trivial SCCs (those with more than one node).
pub fn detect_cycles(num_nodes: usize, edges: &[Vec<usize>]) -> CycleDetectionResult {
    let mut state = TarjanState {
        index_counter: 0,
        stack: Vec::new(),
        on_stack: vec![false; num_nodes],
        index: vec![None; num_nodes],
        lowlink: vec![0; num_nodes],
        sccs: Vec::new(),
    };

    for node in 0..num_nodes {
        if state.index[node].is_none() {
            strongconnect(node, edges, &mut state);
        }
    }

    let cycles: Vec<Vec<usize>> = state
        .sccs
        .into_iter()
        .filter(|scc| scc.len() > 1)
        .collect();

    CycleDetectionResult {
        has_cycle: !cycles.is_empty(),
        cycles,
    }
}

/// Internal state for Tarjan's strongly connected components algorithm.
struct TarjanState {
    index_counter: usize,
    stack: Vec<usize>,
    on_stack: Vec<bool>,
    index: Vec<Option<usize>>,
    lowlink: Vec<usize>,
    sccs: Vec<Vec<usize>>,
}

/// Recursive Tarjan's strongconnect procedure.
fn strongconnect(v: usize, edges: &[Vec<usize>], state: &mut TarjanState) {
    state.index[v] = Some(state.index_counter);
    state.lowlink[v] = state.index_counter;
    state.index_counter += 1;
    state.stack.push(v);
    state.on_stack[v] = true;

    // Consider successors of v
    for &w in &edges[v] {
        if state.index[w].is_none() {
            // Successor w has not yet been visited; recurse on it
            strongconnect(w, edges, state);
            state.lowlink[v] = core::cmp::min(state.lowlink[v], state.lowlink[w]);
        } else if state.on_stack[w] {
            // Successor w is on stack and hence in the current SCC
            // Use w's index (not lowlink) per Tarjan's original algorithm
            let w_index = state.index[w].unwrap_or(0);
            state.lowlink[v] = core::cmp::min(state.lowlink[v], w_index);
        }
    }

    // If v is a root node, pop the stack and generate an SCC
    if state.lowlink[v] == state.index[v].unwrap_or(0) {
        let mut scc = Vec::new();
        while let Some(w) = state.stack.pop() {
            state.on_stack[w] = false;
            scc.push(w);
            if w == v {
                break;
            }
        }
        state.sccs.push(scc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Tier Classification Tests ---

    #[test]
    fn test_tier_one_zero_deps_zero_consumers() {
        assert_eq!(classify_tier(0, 0), Tier::One);
    }

    #[test]
    fn test_tier_one_max_deps_zero_consumers() {
        assert_eq!(classify_tier(3, 0), Tier::One);
    }

    #[test]
    fn test_tier_two_four_deps_zero_consumers() {
        assert_eq!(classify_tier(4, 0), Tier::Two);
    }

    #[test]
    fn test_tier_two_ten_deps_zero_consumers() {
        assert_eq!(classify_tier(10, 0), Tier::Two);
    }

    #[test]
    fn test_tier_two_low_deps_some_consumers() {
        assert_eq!(classify_tier(2, 3), Tier::Two);
    }

    #[test]
    fn test_tier_two_boundary_consumers() {
        assert_eq!(classify_tier(0, 5), Tier::Two);
    }

    #[test]
    fn test_tier_three_high_deps() {
        assert_eq!(classify_tier(11, 0), Tier::Three);
    }

    #[test]
    fn test_tier_three_high_consumers() {
        assert_eq!(classify_tier(0, 6), Tier::Three);
    }

    #[test]
    fn test_tier_three_both_high() {
        assert_eq!(classify_tier(15, 10), Tier::Three);
    }

    #[test]
    fn test_tier_two_mid_deps_mid_consumers() {
        assert_eq!(classify_tier(5, 3), Tier::Two);
    }

    // --- Subsystem Ranking Tests ---

    #[test]
    fn test_rank_already_sorted() {
        let mut subsystems = vec![
            SubsystemInfo { name: "a", consumer_count: 1 },
            SubsystemInfo { name: "b", consumer_count: 3 },
            SubsystemInfo { name: "c", consumer_count: 5 },
        ];
        rank_subsystems(&mut subsystems);
        assert_eq!(subsystems[0].name, "a");
        assert_eq!(subsystems[1].name, "b");
        assert_eq!(subsystems[2].name, "c");
    }

    #[test]
    fn test_rank_reverse_order() {
        let mut subsystems = vec![
            SubsystemInfo { name: "c", consumer_count: 5 },
            SubsystemInfo { name: "b", consumer_count: 3 },
            SubsystemInfo { name: "a", consumer_count: 1 },
        ];
        rank_subsystems(&mut subsystems);
        assert_eq!(subsystems[0].name, "a");
        assert_eq!(subsystems[1].name, "b");
        assert_eq!(subsystems[2].name, "c");
    }

    #[test]
    fn test_rank_stable_equal_consumers() {
        let mut subsystems = vec![
            SubsystemInfo { name: "first", consumer_count: 2 },
            SubsystemInfo { name: "second", consumer_count: 2 },
            SubsystemInfo { name: "third", consumer_count: 1 },
        ];
        rank_subsystems(&mut subsystems);
        assert_eq!(subsystems[0].name, "third");
        // Stable sort: "first" and "second" keep relative order
        assert_eq!(subsystems[1].name, "first");
        assert_eq!(subsystems[2].name, "second");
    }

    #[test]
    fn test_rank_empty() {
        let mut subsystems: Vec<SubsystemInfo> = vec![];
        rank_subsystems(&mut subsystems);
        assert!(subsystems.is_empty());
    }

    #[test]
    fn test_rank_single_element() {
        let mut subsystems = vec![
            SubsystemInfo { name: "only", consumer_count: 42 },
        ];
        rank_subsystems(&mut subsystems);
        assert_eq!(subsystems[0].name, "only");
    }

    // --- Cycle Detection Tests ---

    #[test]
    fn test_no_cycles_dag() {
        // A -> B -> C (no cycles)
        let edges = vec![
            vec![1],    // 0 -> 1
            vec![2],    // 1 -> 2
            vec![],     // 2 -> (nothing)
        ];
        let result = detect_cycles(3, &edges);
        assert!(!result.has_cycle);
        assert!(result.cycles.is_empty());
    }

    #[test]
    fn test_simple_cycle() {
        // A -> B -> A (cycle)
        let edges = vec![
            vec![1],    // 0 -> 1
            vec![0],    // 1 -> 0
        ];
        let result = detect_cycles(2, &edges);
        assert!(result.has_cycle);
        assert_eq!(result.cycles.len(), 1);
        let cycle = &result.cycles[0];
        assert_eq!(cycle.len(), 2);
        assert!(cycle.contains(&0));
        assert!(cycle.contains(&1));
    }

    #[test]
    fn test_self_loop_not_a_cycle() {
        // A self-loop is an SCC of size 1 — we only report SCCs with >1 node
        let edges = vec![
            vec![0],    // 0 -> 0 (self-loop)
            vec![],     // 1 -> (nothing)
        ];
        let result = detect_cycles(2, &edges);
        // A self-loop forms an SCC of size 1; per our definition, that's not a cycle
        // Actually, in Tarjan's algorithm a self-loop makes the node its own SCC of size 1.
        // The task says "report a cycle if any SCC has more than one node", so self-loops
        // are not reported as cycles.
        assert!(!result.has_cycle);
    }

    #[test]
    fn test_triangle_cycle() {
        // A -> B -> C -> A
        let edges = vec![
            vec![1],    // 0 -> 1
            vec![2],    // 1 -> 2
            vec![0],    // 2 -> 0
        ];
        let result = detect_cycles(3, &edges);
        assert!(result.has_cycle);
        assert_eq!(result.cycles.len(), 1);
        assert_eq!(result.cycles[0].len(), 3);
    }

    #[test]
    fn test_disconnected_graph_no_cycles() {
        // Four disconnected nodes
        let edges = vec![vec![], vec![], vec![], vec![]];
        let result = detect_cycles(4, &edges);
        assert!(!result.has_cycle);
        assert!(result.cycles.is_empty());
    }

    #[test]
    fn test_multiple_cycles() {
        // Two separate cycles: {0,1} and {2,3}
        let edges = vec![
            vec![1],    // 0 -> 1
            vec![0],    // 1 -> 0
            vec![3],    // 2 -> 3
            vec![2],    // 3 -> 2
        ];
        let result = detect_cycles(4, &edges);
        assert!(result.has_cycle);
        assert_eq!(result.cycles.len(), 2);
    }

    #[test]
    fn test_complex_graph_with_one_cycle() {
        // 0 -> 1 -> 2 -> 3 -> 1 (cycle: 1,2,3), 0 is not part of cycle
        let edges = vec![
            vec![1],    // 0 -> 1
            vec![2],    // 1 -> 2
            vec![3],    // 2 -> 3
            vec![1],    // 3 -> 1
        ];
        let result = detect_cycles(4, &edges);
        assert!(result.has_cycle);
        assert_eq!(result.cycles.len(), 1);
        let cycle = &result.cycles[0];
        assert_eq!(cycle.len(), 3);
        assert!(cycle.contains(&1));
        assert!(cycle.contains(&2));
        assert!(cycle.contains(&3));
        assert!(!cycle.contains(&0));
    }

    #[test]
    fn test_empty_graph() {
        let edges: Vec<Vec<usize>> = vec![];
        let result = detect_cycles(0, &edges);
        assert!(!result.has_cycle);
        assert!(result.cycles.is_empty());
    }
}
