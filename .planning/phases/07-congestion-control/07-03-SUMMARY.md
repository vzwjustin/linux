# Phase 07 Plan 03: Coupled CC and ECN Integration Summary

**Completed:** 2026-02-01
**Duration:** ~5 minutes
**Status:** Complete

## One-liner

Coupled CC (OLIA/BALIA) integration with path lifecycle and ECN CE mark handling.

## What Was Built

### Task 1: Coupled CC Coordination Layer (tquic_cong.c, tquic_cong.h, tquic.h)

Added connection-level coupled CC management:
- `tquic_cong_enable_coupling(conn, algo)` - Enable coupled CC with OLIA/LIA/BALIA
- `tquic_cong_disable_coupling(conn)` - Disable and revert to per-path CC
- `tquic_cong_is_coupling_enabled(conn)` - Query coupling status
- `coupled_cc` field added to `tquic_connection` struct
- `TQUIC_COUPLED_NONE` enum value for explicit disable
- OLIA is default coupled algorithm per RESEARCH.md recommendation

### Task 2: Path Lifecycle Integration (coupled.c)

Added exported functions for path management:
- `tquic_coupled_create(conn, algo)` - Create connection-level coupled state
- `tquic_coupled_destroy(state)` - Release coupled state
- `tquic_coupled_attach_path(state, path)` - Integrate path into coupled CC
- `tquic_coupled_detach_path(state, path)` - Remove path from coupled CC
- `tquic_coupled_on_ack_ext()` - External ACK dispatch
- `tquic_coupled_on_loss_ext()` - External loss dispatch (only affects that path's CWND)

### Task 3: ECN Support (tquic_input.c, tquic_cong.c, tquic_mib.h)

Added ECN CE mark handling:
- Updated `tquic_process_ack_frame()` to handle ACK_ECN (0x03) frames
- Parse ECT(0), ECT(1), and ECN-CE counts per RFC 9000 Section 19.3.2
- `on_ecn` callback added to `tquic_cong_ops` structure
- `tquic_cong_on_ecn(path, ecn_ce_count)` dispatch function
- MIB counters: `ECNACKSRX`, `ECNACKSTX`, `ECNCEMARKSRX`, `ECNECT0RX`, `ECNECT1RX`

## Commits

| Hash | Description |
|------|-------------|
| 0e290f7b7 | feat(07-03): add coupled CC coordination layer |
| a3f75b7a1 | feat(07-03): add coupled.c path lifecycle integration |

Note: ECN input handling was included in commit 2841af585 (07-02) due to parallel execution.

## Files Modified

| File | Changes |
|------|---------|
| include/net/tquic.h | Added coupled_cc field, TQUIC_COUPLED_NONE, on_ecn callback, coordination API |
| net/tquic/cong/tquic_cong.c | Added coupled CC coordination layer, ECN dispatch |
| net/tquic/cong/tquic_cong.h | Added coupled CC and ECN function declarations |
| net/tquic/cong/coupled.c | Added path lifecycle integration functions |
| net/tquic/tquic_input.c | Added ACK_ECN frame parsing and ECN CE handling |
| net/tquic/tquic_mib.h | Added ECN MIB counters |

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| OLIA as default coupled algorithm | Per RESEARCH.md: RFC-standardized, TCP-friendly at shared bottlenecks |
| Loss on one path affects only that path's CWND | Per CONTEXT.md requirement for path isolation |
| ECN off by default (net.tquic.ecn_enabled = 0) | Per CONTEXT.md: "available but off by default" |
| ECN CE treated like loss | Per RFC 9002 Section 7.1, CC should reduce CWND |
| Opaque tquic_coupled_state pointer | Allows internal coupled_state to remain private |

## Verification

### Success Criteria Met

- [x] Coupled CC can be enabled per-connection via `tquic_cong_enable_coupling()`
- [x] OLIA is default coupled algorithm
- [x] Paths are automatically attached/detached from coupled state
- [x] Coupled callbacks coordinate CWND across paths
- [x] Loss on one path reduces only that path's CWND (per CONTEXT.md)
- [x] ECN CE marks signal congestion when ECN enabled
- [x] ECN is off by default (net.tquic.ecn_enabled = 0)

### Key Links Verified

- `tquic_cong.c` -> `coupled.c` via `tquic_coupled_*` function calls
- `tquic_input.c` -> `tquic_cong_on_ecn()` via ECN CE handler

## Deviations from Plan

None - plan executed exactly as written.

## Next Phase Readiness

Phase 07-04 (CC sysctl/sockopt runtime configuration) can proceed:
- Coupled CC enable/disable functions ready
- ECN sysctl already available (net.tquic.ecn_enabled)
- Per-netns CC defaults in place from 07-02
