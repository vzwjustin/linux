---
phase: 06-scheduler-framework
plan: 02
subsystem: scheduler
tags: [minrtt, round-robin, tolerance-band, path-selection]

dependency-graph:
  requires:
    - "06-01 (tquic_sched.h, tquic_sched_ops API)"
  provides:
    - "MinRTT scheduler with configurable tolerance band"
    - "Simple round-robin scheduler for baseline/testing"
    - "Path and connection structure definitions in shared header"
  affects:
    - "06-03 aggregate scheduler (same registration pattern)"
    - "06-04 BLEST scheduler (same registration pattern)"
    - "06-05 ECF scheduler (same registration pattern)"

tech-stack:
  added: []
  patterns:
    - "Module parameter for runtime tuning (tolerance_pct)"
    - "RCU-safe path list iteration"
    - "Hysteresis via tolerance band to prevent oscillation"
    - "Per-connection scheduler private state (sched_priv)"

file-tracking:
  key-files:
    created:
      - "net/quic/sched_minrtt.c"
    modified:
      - "net/quic/tquic_sched.h"
      - "net/quic/Makefile"

decisions:
  - key: "Path/connection structures in tquic_sched.h"
    choice: "Added tquic_path, tquic_connection, tquic_path_cc, tquic_path_stats to header"
    rationale: "External scheduler modules need access to path state for decision-making"
    tradeoff: "Increases header size but enables modular scheduler development"
  - key: "10% default tolerance band"
    choice: "minrtt_tolerance_pct = 10, tunable via module_param"
    rationale: "Per RESEARCH.md, prevents path flapping when RTTs are within 10%"
    tradeoff: "May delay switching to better path, but avoids oscillation"
  - key: "Single file for both schedulers"
    choice: "sched_minrtt.c contains both MinRTT and round-robin"
    rationale: "Both are simple schedulers, shared module reduces code duplication"
    tradeoff: "File slightly larger but easier to maintain"

metrics:
  duration: "5 minutes"
  completed: "2026-01-31"
---

# Phase 6 Plan 2: MinRTT and Round-Robin Schedulers Summary

**One-liner:** MinRTT scheduler with 10% tolerance band prevents path flapping, plus simple round-robin for baseline testing.

## What Was Built

### MinRTT Scheduler

Selects the path with minimum smoothed RTT for each packet, with a configurable tolerance band to prevent oscillation.

**Key features:**
- Uses `path->cc.smoothed_rtt_us` for RTT comparison
- Default 10% tolerance band (switch only if new path is significantly better)
- Tracks current path state for hysteresis
- Updates cached RTT on ACK feedback
- Handles path add/remove events gracefully

**Tolerance band algorithm:**
```
tolerance_threshold = current_rtt * (100 - tolerance_pct) / 100
if new_rtt >= tolerance_threshold:
    stay with current path  # RTT difference not significant
else:
    switch to new path
```

### Round-Robin Scheduler

Simple scheduler that distributes packets evenly across all active paths.

**Key features:**
- Increments index counter on each get_path() call
- Selects path at `(next_index % active_count)`
- No path preference or RTT consideration
- Useful for baseline testing and simple load balancing

### Header Structure Updates

Added full path and connection structure definitions to `tquic_sched.h`:
- `struct tquic_path` with state, weight, priority, stats, cc
- `struct tquic_path_cc` with cwnd, RTT, bandwidth, loss rate
- `struct tquic_path_stats` with packet counters
- `struct tquic_connection` with path list and scheduler state
- `enum tquic_path_state` (ACTIVE, STANDBY, FAILED, PROBING)

## Commits

| Hash | Type | Description |
|------|------|-------------|
| cfb21bc | feat | MinRTT scheduler with tolerance band + header structures |
| 38d134c | feat | Add sched_minrtt.o to TQUIC build |

## Key Files

| File | Purpose |
|------|---------|
| `net/quic/sched_minrtt.c` | MinRTT and round-robin scheduler implementations |
| `net/quic/tquic_sched.h` | Path/connection structures for scheduler access |
| `net/quic/Makefile` | Build integration |

## API Surface

### Module Parameters

```
minrtt.tolerance_pct (default: 10)
  RTT tolerance percentage for path switching.
  Higher values = more sticky to current path.
  0 = always switch to best path (no tolerance).
```

### Scheduler Registration

Both schedulers register via `tquic_register_scheduler()`:
- `"minrtt"` - MinRTT with tolerance band
- `"rr"` - Round-robin distribution

## Deviations from Plan

None - plan executed exactly as written.

## Testing Notes

### MinRTT Testing Scenarios

1. **Two paths with similar RTT (45ms vs 50ms):**
   - With 10% tolerance: stays on current path (50 * 0.9 = 45)
   - Without tolerance: would oscillate between paths

2. **Significant RTT difference (20ms vs 50ms):**
   - Immediately switches to faster path
   - Tolerance threshold: 50 * 0.9 = 45 > 20, so switch

3. **Path removal:**
   - Current path removed: scheduler invalidates state
   - Next get_path() selects new best path

### Round-Robin Testing

1. **Three active paths:**
   - Packets distributed 1-2-3-1-2-3-...
   - Even distribution regardless of RTT

## Next Phase Readiness

Phase 06-03 (Aggregate scheduler) can proceed:
- Registration pattern established
- Header structures defined
- Build integration pattern shown

---

*Summary generated: 2026-01-31T23:58:00Z*
