---
phase: 06-scheduler-framework
plan: 03
subsystem: scheduler
tags: [aggregate, weighted, cwnd, rtt, deficit-round-robin, drr, capacity]

# Dependency graph
requires:
  - phase: 06-01
    provides: Scheduler framework with registration API
  - phase: 05-01
    provides: Bonding context with TQUIC_MAX_PATHS, weight constants
provides:
  - Aggregate scheduler with cwnd/RTT capacity-proportional selection
  - Weighted scheduler with deficit round-robin algorithm
  - 5% minimum weight floor to prevent path starvation
  - Primary + backup path selection for failover
affects: [07-congestion, 08-vps-endpoint, 10-quality-upstream]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Capacity calculation from cwnd/RTT metrics
    - Deficit Round-Robin for weighted fair scheduling
    - Periodic capacity updates (10ms interval)

key-files:
  created:
    - net/quic/sched_aggregate.c
    - net/quic/sched_weighted.c
  modified:
    - net/quic/Makefile

key-decisions:
  - "Aggregate uses capacity = cwnd * scale / RTT for path scoring"
  - "5% minimum weight floor enforced per RESEARCH.md pitfall #4"
  - "Capacity updates cached with 10ms refresh interval"
  - "DRR quantum = 1500 bytes (~1 MTU) for weighted scheduler"
  - "Aggregate returns primary + backup for failover integration"

patterns-established:
  - "Capacity calculation: capacity = (cwnd * SCALE * 1e6) / rtt_us"
  - "Deficit Round-Robin: deficit += quantum * weight / 100; send if deficit > 0"
  - "Force capacity recalc on path add/remove via timestamp reset"

# Metrics
duration: 2min
completed: 2026-01-31
---

# Phase 6 Plan 3: Aggregate and Weighted Schedulers Summary

**Aggregate scheduler with cwnd/RTT capacity-proportional selection and weighted DRR scheduler with user-defined path priorities**

## Performance

- **Duration:** 2 min
- **Started:** 2026-01-31T23:55:06Z
- **Completed:** 2026-01-31T23:57:15Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments
- Aggregate scheduler maximizes throughput via capacity-proportional path selection (cwnd/RTT)
- 5% minimum weight floor prevents path starvation per RESEARCH.md
- Aggregate returns primary + backup paths for seamless failover integration
- Weighted scheduler uses Deficit Round-Robin for fair traffic distribution
- Weights sync from path->weight (set via PM netlink)
- Both schedulers registered and buildable

## Task Commits

Each task was committed atomically:

1. **Task 1: Create Aggregate scheduler (default)** - `232f7b0d4` (feat)
2. **Task 2: Create Weighted scheduler with deficit round-robin** - `a8f20be0f` (feat)
3. **Task 3: Update Makefile for new schedulers** - `9952d3ea1` (feat)

## Files Created/Modified
- `net/quic/sched_aggregate.c` - Aggregate scheduler with cwnd/RTT capacity calculation, 5% floor, primary+backup selection
- `net/quic/sched_weighted.c` - Weighted scheduler with Deficit Round-Robin, syncs from path->weight
- `net/quic/Makefile` - Added sched_aggregate.o and sched_weighted.o to build

## Decisions Made
- **Capacity formula:** capacity = (cwnd * 1000 * 1e6) / rtt_us provides stable integer math for path scoring
- **10ms update interval:** Avoid recalculating capacity every packet while remaining responsive
- **DRR quantum 1500:** One MTU per scheduling quantum balances granularity vs overhead
- **Default weight 100:** Unconfigured paths get equal weight in weighted scheduler

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Aggregate and weighted schedulers ready for use
- Framework now has 3 built-in schedulers: minrtt, aggregate (default), weighted
- Ready for Phase 06-04 (round-robin scheduler) or Phase 06-05 (sysctl/sockopt integration)

---
*Phase: 06-scheduler-framework*
*Completed: 2026-01-31*
