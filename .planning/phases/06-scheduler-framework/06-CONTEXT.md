# Phase 6: Scheduler Framework - Context

**Gathered:** 2026-01-31
**Status:** Ready for planning

<domain>
## Phase Boundary

Multiple scheduling algorithms with runtime selection via sysctl/sockopt. Framework for registering schedulers, selecting paths for each packet, and configuring scheduler behavior per-socket. Builds on Phase 5's bonding state machine and integrates with reorder buffer and failover systems.

Requirements: SCHED-01 through SCHED-07
Schedulers: Round-robin, MinRTT, Weighted, Aggregate, BLEST, ECF

</domain>

<decisions>
## Implementation Decisions

### Scheduler API Design
- Full Linux kernel integration following established patterns
- Both built-in and modular schedulers: core schedulers built-in, external modules allowed for custom schedulers
- Full lifecycle hooks: init, release, get_path, path_added, path_removed, ack_received, loss_detected
- Private per-connection state via void *priv pointer for scheduler-specific data (needed for BLEST/ECF state)

### Path Selection Semantics
- get_path() returns primary path + backup path for redundant send capability
- Scheduler-aware integration with Phase 5: can query reorder buffer depth, pending retransmits, influence failover decisions
- Full access to tquic_path struct for maximum decision-making flexibility
- Explicit TQUIC_SCHED_REDUNDANT flag allows scheduler to request packet duplication on all paths

### Configuration Hierarchy
- Aggregate scheduler as default (fits WAN bonding primary use case)
- Scheduler locked at connection establishment, cannot change mid-connection
- User can set per-path priorities (preferred/backup/avoid) via PM netlink
- Claude's discretion: sysctl/sockopt inheritance model

### Scheduler Behavior Boundaries
- BLEST and ECF: implement faithfully per academic papers (BLEST for head-of-line avoidance, ECF for earliest completion first)
- Claude's discretion: MinRTT tolerance band for similar latencies
- Claude's discretion: 5% minimum weight enforcement for Aggregate scheduler
- Claude's discretion: path skip criteria per scheduler type

</decisions>

<specifics>
## Specific Ideas

- "Full Linux kernel integration" — user emphasized tight integration with kernel patterns throughout
- Core schedulers built-in with module support mirrors TCP congestion control approach
- Path + backup return type enables zero-packet-loss failover from Phase 5

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 06-scheduler-framework*
*Context gathered: 2026-01-31*
