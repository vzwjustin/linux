---
phase: 03-diagnostics
plan: 01
subsystem: diagnostics
tags: [inet_diag, ss, netlink, UAPI]
dependency-graph:
  requires: [02-04]
  provides: [inet_diag-handler, tquic_info-struct, TQUIC_DIAG_ATTR-enum]
  affects: [03-02, 09-*]
tech-stack:
  added: []
  patterns: [inet_diag_handler, netlink_attributes, rhashtable_iteration]
key-files:
  created:
    - include/uapi/linux/tquic_diag.h
    - net/tquic/tquic_diag.c
  modified:
    - net/tquic/Makefile
    - include/net/tquic.h
decisions:
  - id: diag-001
    choice: "CAP_NET_ADMIN required for CID visibility"
    rationale: "CIDs are sensitive for packet capture correlation, consistent with MPTCP"
  - id: diag-002
    choice: "State names use hybrid format"
    rationale: "Per CONTEXT.md: QUIC state (TCP equivalent) aids operators"
  - id: diag-003
    choice: "MODULE_ALIAS for auto-loading"
    rationale: "Per RESEARCH.md pitfall #4: ss auto-loads diag module"
metrics:
  duration: 2m37s
  completed: 2026-01-31
---

# Phase 3 Plan 01: inet_diag Handler Summary

inet_diag handler enabling ss tool visibility of TQUIC connections with CAP_NET_ADMIN protected CIDs and hybrid state names

## Completed Tasks

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Create tquic_diag.h UAPI header | 875104b07 | include/uapi/linux/tquic_diag.h |
| 2 | Implement tquic_diag.c inet_diag handler | cc2aba001 | net/tquic/tquic_diag.c, Makefile, include/net/tquic.h |

## Implementation Details

### Task 1: UAPI Header

Created `include/uapi/linux/tquic_diag.h` with:

- `TQUIC_DIAG_ATTR_*` enum for top-level netlink attributes (INFO, SCID, DCID, VERSION, PATHS, STREAMS)
- `TQUIC_DIAG_PATH_*` enum for nested per-path attributes (ID, STATE, RTT, CWND, TX_BYTES, RX_BYTES, LOST)
- `struct tquic_info` for basic ss output (state, num_paths, num_streams, rtt_us, tx_bytes, rx_bytes, retransmits)
- `enum tquic_diag_path_state` and `enum tquic_diag_conn_state` mirroring internal enums

### Task 2: inet_diag Handler

Created `net/tquic/tquic_diag.c` (494 lines) following MPTCP pattern:

**Handler Functions:**
- `tquic_diag_dump()` - Iterates global `tquic_conn_table` rhashtable with namespace filtering
- `tquic_diag_dump_one()` - Single connection lookup by socket cookie
- `tquic_diag_get_info()` - Fills `struct tquic_info` with connection state, paths, streams, RTT, bytes
- `tquic_diag_get_aux()` - Extended attributes: QUIC version, CIDs (CAP_NET_ADMIN only), per-path breakdown

**Key Implementation Choices:**
- State names array with hybrid format: `"CONNECTED (ESTABLISHED)"`
- CAP_NET_ADMIN check for CID visibility (sensitive for packet capture)
- `MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 2-263)` for auto-loading
- Namespace isolation via `net_eq(sock_net(sk), net)` filtering

**Makefile Update:**
- Added `tquic_diag.o` to `tquic-y` object list

**Header Update:**
- Added `tquic_diag_init()` and `tquic_diag_exit()` declarations to `include/net/tquic.h`

## Decisions Made

| ID | Decision | Rationale |
|----|----------|-----------|
| diag-001 | CAP_NET_ADMIN required to see connection IDs | CIDs are sensitive info needed for packet capture correlation; consistent with MPTCP approach |
| diag-002 | State names use hybrid format: "QUIC_STATE (TCP_EQUIV)" | Per CONTEXT.md, aids operators familiar with TCP states |
| diag-003 | MODULE_ALIAS for auto-loading | Per RESEARCH.md pitfall #4: ensures ss tool can auto-load module |

## Deviations from Plan

None - plan executed exactly as written.

## Verification Results

All verification criteria pass:

1. `grep -r "inet_diag_register" net/tquic/` - Shows handler registration
2. `grep -r "TQUIC_DIAG_ATTR" include/uapi/linux/` - Shows UAPI attributes
3. tquic_diag.c at 494 lines (> 200 minimum requirement)
4. State names follow "QUIC (TCP)" hybrid format per CONTEXT.md

## Next Phase Readiness

**Dependencies satisfied for 03-02:**
- inet_diag handler provides infrastructure for proc/MIB integration
- `struct tquic_info` defines standard diagnostic info structure
- State name mapping pattern established

**No blockers identified.**

## Artifacts

### include/uapi/linux/tquic_diag.h (113 lines)
```c
/* Key structures */
enum { TQUIC_DIAG_ATTR_* };     /* 7 attributes */
enum { TQUIC_DIAG_PATH_* };     /* 8 path attributes */
struct tquic_info { ... };      /* 8 fields */
```

### net/tquic/tquic_diag.c (494 lines)
```c
/* Key functions */
static void tquic_diag_dump(...);
static int tquic_diag_dump_one(...);
static void tquic_diag_get_info(...);
static int tquic_diag_get_aux(...);

/* Handler registration */
static const struct inet_diag_handler tquic_diag_handler = {
    .idiag_type = IPPROTO_TQUIC,  /* 263 */
    ...
};
```
