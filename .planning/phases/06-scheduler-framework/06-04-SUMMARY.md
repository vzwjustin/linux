---
phase: 06-scheduler-framework
plan: 04
subsystem: scheduler
tags: [blest, ecf, blocking-estimation, completion-time, multipath, heterogeneous]

# Dependency graph
requires:
  - phase: 06-01
    provides: Scheduler framework API (tquic_sched.h, register/unregister)
provides:
  - BLEST scheduler for blocking estimation-based scheduling
  - ECF scheduler for earliest completion first scheduling
  - Academic algorithm implementations for heterogeneous paths
affects: [07-congestion, 09-tooling, 10-quality-upstream]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Inflight tracking per path for scheduling decisions"
    - "Completion time estimation from send_rate + RTT"
    - "Blocking estimation to reduce HOL blocking"
    - "ACK/loss feedback hooks for inflight accounting"

key-files:
  created:
    - net/quic/sched_blest.c
    - net/quic/sched_ecf.c
  modified:
    - net/quic/Makefile

key-decisions:
  - "BLEST 1ms default blocking threshold - prevents oscillation for sub-ms blocking"
  - "ECF 10ms rate update interval - balances freshness vs overhead"
  - "Both schedulers track second-best path for failover support"
  - "Send rate from bandwidth measurement or cwnd/RTT fallback"

patterns-established:
  - "blest_path_state tracks inflight_bytes + send_rate per path"
  - "ecf_completion_time formula: (inflight + segment) / rate + RTT"
  - "ACK decreases inflight, loss decreases inflight"

# Metrics
duration: 12min
completed: 2026-01-31
---

# Phase 6 Plan 4: BLEST and ECF Schedulers Summary

**Academic multipath schedulers (BLEST blocking estimation, ECF earliest completion) with inflight tracking and heterogeneous path optimization**

## Performance

- **Duration:** 12 min
- **Started:** 2026-01-31T23:58:00Z
- **Completed:** 2026-01-31T24:10:00Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- Implemented BLEST scheduler from IFIP Networking 2016 paper
- Implemented ECF scheduler from ACM SIGMETRICS 2017 paper
- Both schedulers track per-path inflight bytes for accurate estimation
- ACK/loss feedback hooks maintain inflight accounting
- Blocking estimation prevents head-of-line blocking at receiver
- Completion time calculation considers both bandwidth and latency

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement BLEST scheduler** - `027223079` (feat)
2. **Task 2: Implement ECF scheduler** - `13c0fca4a` (feat)
3. **Task 3: Update Makefile for BLEST and ECF** - `90c81aaeb` (feat)

## Files Created/Modified

- `net/quic/sched_blest.c` - BLEST scheduler with blocking estimation algorithm
- `net/quic/sched_ecf.c` - ECF scheduler with completion time calculation
- `net/quic/Makefile` - Added sched_blest.o and sched_ecf.o to build

## Decisions Made

1. **BLEST blocking threshold: 1ms default**
   - Prevents oscillation for very small blocking times
   - Configurable via module parameter

2. **ECF rate update interval: 10ms**
   - Balances rate freshness vs per-packet overhead
   - Matches aggregate scheduler pattern

3. **Send rate estimation priority**
   - Prefer explicit bandwidth measurement from congestion control
   - Fallback to cwnd/RTT calculation
   - Minimum 1KB/s to avoid division by zero

4. **Both schedulers provide backup path**
   - Second-best path returned for failover support
   - Consistent with aggregate scheduler pattern

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All 5 schedulers now available: aggregate (default), minrtt, weighted, blest, ecf
- Scheduler framework complete for Phase 6
- Ready for Phase 7 congestion control integration
- BLEST/ECF provide advanced scheduling for heterogeneous paths (fiber + cellular)

---
*Phase: 06-scheduler-framework*
*Completed: 2026-01-31*
