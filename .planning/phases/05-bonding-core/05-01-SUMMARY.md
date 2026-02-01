# Phase 05 Plan 01: Bonding State Machine Summary

**One-liner:** Bonding state machine (SINGLE_PATH/PENDING/ACTIVE/DEGRADED) with capacity-proportional weights and sockopt override.

## Metadata

| Field | Value |
|-------|-------|
| Phase | 05-bonding-core |
| Plan | 01 |
| Subsystem | WAN bonding |
| Tags | bonding, state-machine, multipath, capacity-weights |
| Completed | 2026-01-31 |
| Duration | ~7 minutes |

## Dependencies

- **Requires:** Phase 04 (path manager, validation, netlink)
- **Provides:** Bonding state machine, capacity weight derivation, sockopt API
- **Affects:** Phase 05-02 (reorder buffer), Phase 06 (scheduler), Phase 07 (congestion)

## Tech Stack

- **Added:** tquic_bonding.h, tquic_bonding.c
- **Patterns:** State machine, callback-driven architecture, workqueue for async weight updates

## Summary

Implemented the bonding state machine that coordinates multi-path bandwidth aggregation lifecycle for TQUIC connections.

### State Machine

Four states with well-defined transitions:

1. **SINGLE_PATH** - Normal QUIC operation, no aggregation overhead
2. **PENDING** - Second path validating, reorder buffer allocated
3. **ACTIVE** - Aggregating across 2+ validated paths
4. **DEGRADED** - Reduced capacity due to failed paths

State transitions triggered by path events (validation, failure, add, remove) via callbacks from path manager.

### Capacity Weights

Derived from cwnd/RTT measurements for proportional traffic distribution:
- Formula: `weight[i] = (cwnd[i]/RTT[i]) / sum(cwnd[j]/RTT[j])`
- Minimum 5% weight floor prevents path starvation (RESEARCH.md pitfall #4)
- User-overridable via `TQUIC_BOND_PATH_WEIGHT` sockopt
- Async weight recalculation via workqueue

### Integration Points

Path manager callbacks wired up:
- `on_path_available` -> `tquic_bonding_on_path_validated`
- `on_path_failed` -> `tquic_bonding_on_path_failed`
- Path add/remove also trigger bonding state updates

### Reorder Buffer

Placeholder structure created (full implementation in 05-02):
- Allocated lazily when entering PENDING state
- Default 4MB max size, configurable via sysctl
- Freed when returning to SINGLE_PATH

## Key Files

| File | Role |
|------|------|
| `net/quic/tquic_bonding.h` | State machine types and API declarations |
| `net/quic/tquic_bonding.c` | State machine implementation, weight derivation |
| `net/quic/tquic_path.c` | Integration: bonding field, callback wiring |
| `net/tquic/tquic_socket.c` | TQUIC_BOND_PATH_WEIGHT sockopt handler |
| `include/uapi/linux/tquic.h` | User API: tquic_path_weight_args struct |
| `include/net/tquic.h` | Kernel API: tquic_bond_set/get_path_weight |
| `net/quic/Makefile` | Build: added tquic_bonding.o |

## Commits

| Hash | Description |
|------|-------------|
| 974bd59 | feat(05-01): add bonding state machine header |
| 5ec58f4 | feat(05-01): implement bonding state machine and capacity weights |
| 902d98d | feat(05-01): wire bonding into path manager and add sockopt |

## Decisions Made

| Decision | Rationale |
|----------|-----------|
| State names SINGLE_PATH/PENDING/ACTIVE/DEGRADED | Match CONTEXT.md terminology, clear semantics |
| 5% minimum weight floor | Prevent path starvation per RESEARCH.md pitfall #4 |
| Workqueue for async weight updates | Avoid blocking data path during recalculation |
| Reorder buffer allocated in PENDING | Prepare before ACTIVE, release in SINGLE_PATH |
| Path manager owns bonding context | Clean lifecycle management, callback integration |
| Cast conn->scheduler to path_manager | Temporary until proper connection structure field |

## Deviations from Plan

None - plan executed exactly as written.

## Verification Results

All success criteria met:

- [x] tquic_bonding.h exists with state enum and context struct
- [x] tquic_bonding.c implements state machine with all transitions
- [x] Capacity weights calculated from cwnd/RTT
- [x] Minimum weight floor (5%) enforced
- [x] User weight override via sockopt
- [x] Path manager creates/destroys bonding context
- [x] Path events trigger state updates
- [x] All EXPORT_SYMBOL_GPL for public API (17 exports)

## Next Phase Readiness

Ready for 05-02 (reorder buffer implementation):
- State machine tracks when buffer needed (PENDING/ACTIVE states)
- Placeholder structure defined in tquic_bonding.c
- Max buffer size configurable via bc->max_buffer_bytes
- Buffer allocation/free hooks in place
