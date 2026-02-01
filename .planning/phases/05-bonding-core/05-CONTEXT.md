# Phase 5: Multi-Path Bonding Core - Context

**Gathered:** 2026-01-31
**Status:** Ready for planning

<domain>
## Phase Boundary

True bandwidth aggregation with reordering buffer for heterogeneous latencies. Two 1Gbps paths yield ~2Gbps aggregate. Seamless failover on path failure. Handles 600ms latency differences (fiber + satellite). Zero application-visible packet loss on path failure.

Scheduler algorithms and congestion control are Phase 6 and Phase 7 respectively. This phase establishes the bonding state machine, reorder buffer, and failover mechanics.

</domain>

<decisions>
## Implementation Decisions

### Aggregation behavior
- **All paths always** — spread traffic across all validated paths simultaneously for maximum throughput
- Bonding activates immediately when second path validates (auto-bond)
- No minimum path count required; single-path gracefully degrades to standard operation
- Path usage proportional to capacity (faster paths carry more traffic)

### Reorder buffer strategy
- **Adaptive buffer sizing** based on observed path latency spread (max RTT - min RTT)
- Buffer must handle 600ms latency difference per success criteria (fiber + satellite scenario)
- Memory limit prevents unbounded growth: configurable via sysctl, reasonable default (e.g., 4MB per connection)
- Buffer releases in-order frames to application as gaps are filled
- Timeout-based gap release for truly lost packets (prevents infinite buffering)
- Per-path sequence tracking to detect missing vs delayed packets

### Failover semantics
- **Fast failure detection** — 3x SRTT without ACK triggers path degradation (matches RFC 9000 PTO)
- **Path states**: ACTIVE → DEGRADED → FAILED (progressive demotion)
- DEGRADED paths: reduce traffic share, don't remove entirely
- FAILED paths: stop sending new data, complete in-flight retransmits
- **Zero packet loss guarantee**: retransmit pending data on remaining paths before declaring connection failure
- Path recovery: FAILED paths can return to ACTIVE via successful PATH_CHALLENGE/RESPONSE (leverages Phase 4 validation)
- Connection failure only when ALL paths fail

### Path weighting
- **Capacity-aware distribution** — send proportionally to each path's measured bandwidth
- Weights derived from cwnd and RTT measurements (available from congestion control in Phase 7, initial estimate from path RTT)
- User-overridable weights via sockopt (SO_TQUIC_PATH_WEIGHT) for policy control
- Weights recalculated on path addition/removal and periodic intervals
- Default: equal weights until measurements available

### Bonding state machine
- **States**: SINGLE_PATH → BONDING_PENDING → BONDED → DEGRADED → SINGLE_PATH
- SINGLE_PATH: normal QUIC operation, no aggregation overhead
- BONDING_PENDING: second path validating, prepare reorder buffer
- BONDED: active aggregation across 2+ paths
- DEGRADED: one or more paths failed, reduced capacity
- Clean transitions: no stuck states, timer-based recovery

### Packet scheduling (foundational)
- This phase implements basic capacity-proportional scheduling
- Round-robin, MinRTT, weighted, and advanced schedulers are Phase 6
- Packets tagged with path selection at send time
- Path selection considers: capacity weight, cwnd availability, packet in-flight count

### Retransmission on failover
- Pending packets (sent but unacked) on failed path are re-queued for remaining paths
- Retransmit queue priority: failed-path packets before new data
- Duplicate detection at receiver handles potential duplicates from path failover

</decisions>

<specifics>
## Specific Ideas

- Success criteria drives design: "Two 1Gbps paths yield approximately 2Gbps aggregate throughput"
- 600ms latency spread requirement drives reorder buffer sizing (fiber typical RTT ~20ms, satellite ~600ms)
- MPTCP patterns: follow net/mptcp/pm.c and mptcp_sched.c for Linux kernel integration
- Seamless failover: application sees continuous stream, kernel handles path switching transparently
- Zero application-visible packet loss: retransmit before giving up

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 05-bonding-core*
*Context gathered: 2026-01-31*
