# Phase 7: Congestion Control - Context

**Gathered:** 2026-01-31
**Status:** Ready for planning

<domain>
## Phase Boundary

Per-path and coupled congestion control for TQUIC multi-path connections. Each path maintains independent CWND, ssthresh, and pacing rate. Multiple CC algorithms supported (Cubic, BBR, COPA, Westwood) with per-path selection. Coupled CC algorithms (OLIA, BALIA) coordinate CWND across paths when enabled. Loss on one path affects only that path's CWND while coupled CC redistributes traffic.

</domain>

<decisions>
## Implementation Decisions

### Algorithm defaults
- Default CC algorithm: Cubic (matches Linux TCP default)
- All four algorithms (Cubic, BBR, COPA, Westwood) enabled and available
- Per-netns sysctl for default CC (net.tquic.cc_algorithm), inherits from init_net
- Per-path CC selection allowed — different paths can use different algorithms
- Auto-select CC by path characteristics: high-RTT paths automatically use BBR
- RTT threshold for BBR auto-selection: Claude's discretion based on research
- Full override flexibility: both PM netlink and sockopt can override path CC

### Coupling behavior
- Both OLIA and BALIA coupled algorithms supported
- Coupled CC is opt-in via sysctl/sockopt (per-path CC by default)
- Default coupled algorithm when enabled: Claude's discretion (OLIA vs BALIA)
- Coupling aggressiveness: Balanced — moderate responsiveness to path changes

### Loss response
- CWND reduction on loss: follow standard algorithm behavior (Claude decides)
- Loss isolation with coupling signal: path CWND isolated, but coupled CC redistributes traffic
- Consecutive losses for degradation: Claude's discretion based on WAN patterns
- ECN support: available but off by default (enable via sysctl)

### Pacing strategy
- Pacing enabled by default, configurable to disable via sysctl/sockopt
- Pacing rate calculation: bandwidth estimate (BBR-style measurement)
- Slow start pacing gain: Claude's discretion based on algorithm requirements
- Pacing implementation: FQ (Fair Queueing) integration with fq qdisc

### Claude's Discretion
- RTT threshold for BBR auto-selection on high-latency paths
- Default coupled CC algorithm choice (OLIA vs BALIA for WAN bonding)
- Standard CWND reduction behavior per algorithm specification
- Consecutive loss count for path degradation
- Slow start pacing gain value

</decisions>

<specifics>
## Specific Ideas

- "Full QUIC protocol deep integration into Linux kernel — best of everything, full flexibility for developers"
- Per-path CC choice enables optimal algorithm per path type (e.g., BBR on satellite, Cubic on fiber)
- Bandwidth-based pacing rate for accuracy (not CWND/RTT approximation)
- FQ integration leverages hardware pacing when available

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 07-congestion-control*
*Context gathered: 2026-01-31*
