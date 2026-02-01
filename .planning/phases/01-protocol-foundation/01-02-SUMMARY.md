---
phase: 01-protocol-foundation
plan: 02
subsystem: tquic-headers
tags: [uapi, netlink, path-manager, socket, lock-hierarchy]

dependency-graph:
  requires: ["01-01"]
  provides:
    - tquic_pm.h UAPI header for path manager netlink
    - protocol.h internal header with lock documentation
    - tquic_sock structure consolidation
  affects: ["04-path-manager", "02-socket-api"]

tech-stack:
  added: []
  patterns:
    - mptcp_pm.h netlink interface pattern
    - mptcp/protocol.h internal header pattern
    - Lock hierarchy documentation pattern

file-tracking:
  created:
    - include/uapi/linux/tquic_pm.h
    - net/tquic/protocol.h
  modified:
    - net/tquic/tquic_socket.c
    - net/tquic/tquic_proto.c
    - net/tquic/tquic_ipv6.c

decisions:
  - id: pm-netlink-pattern
    description: Follow mptcp_pm.h pattern for path manager netlink interface
    rationale: Maintains consistency with existing multipath protocol patterns
  - id: internal-header
    description: Create net/tquic/protocol.h as internal header separate from public include/net/tquic.h
    rationale: Follows mptcp/protocol.h pattern for internal definitions and lock documentation
  - id: bit-shift-flags
    description: Use (1 << N) for PM flags instead of BIT() macro
    rationale: BIT() macro not available in UAPI headers (userspace)

metrics:
  duration: 2m16s
  completed: 2026-01-31
---

# Phase 01 Plan 02: UAPI Headers and Internal Protocol Header Summary

**One-liner:** tquic_pm.h UAPI for path manager netlink plus protocol.h internal header with lock hierarchy documentation

## What Was Built

### 1. include/uapi/linux/tquic_pm.h
Path manager netlink interface for userspace path management:

- `TQUIC_PM_NAME` and `TQUIC_PM_VER` constants
- `enum tquic_pm_cmd`: ADD_PATH, DEL_PATH, GET_PATH, SET_PATH_STATE, FLUSH_PATHS, SET_LIMITS, GET_LIMITS, SET_FLAGS, ANNOUNCE, REMOVE
- `enum tquic_pm_attr`: TOKEN, PATH_ID, FAMILY, SADDR4/6, DADDR4/6, SPORT, DPORT, FLAGS, STATE, IF_IDX, PRIORITY, WEIGHT, MAX_PATHS, SUBFLOWS
- Path flags: SIGNAL, SUBFLOW, BACKUP, FULLMESH, IMPLICIT
- `enum tquic_pm_event`: CREATED, ESTABLISHED, CLOSED, ANNOUNCED, REMOVED, PRIORITY, LISTENER_CREATED, LISTENER_CLOSED

### 2. net/tquic/protocol.h
Internal header with lock documentation and helper functions:

- Complete lock hierarchy documentation (sk_lock > conn_lock > path_lock > cc_lock > stream_lock)
- Reference counting documentation for conn, path, stream
- `tquic_sk()` conversion macro (guarded to avoid duplicate definition)
- `tquic_inet6_sk()` for IPv6 socket info
- Socket flags: MULTIPATH_ENABLED, BONDING_ENABLED, SERVER_MODE, HANDSHAKE_DONE, CLOSING
- Connection lock helpers: `tquic_conn_lock()`, `tquic_conn_unlock()`
- Data lock macros: `tquic_data_lock()`, `tquic_data_unlock()`
- Debug helper: `tquic_sk_owned_by_me()`

### 3. Source File Updates
Added `#include "protocol.h"` to:
- `net/tquic/tquic_socket.c`
- `net/tquic/tquic_proto.c`
- `net/tquic/tquic_ipv6.c` (with TODO for inline tquic6_sock cleanup)

## Commits

| Commit | Description | Files |
|--------|-------------|-------|
| 8a37380dd | add tquic_pm.h UAPI header for path manager | include/uapi/linux/tquic_pm.h |
| a9ca4796c | add protocol.h internal header with lock documentation | net/tquic/protocol.h |
| a60d01d20 | add protocol.h include to tquic source files | tquic_socket.c, tquic_proto.c, tquic_ipv6.c |

## Key Links Established

| From | To | Via | Pattern |
|------|-----|-----|---------|
| net/tquic/protocol.h | net/tquic/tquic_socket.c | struct tquic_sock definition | `#include "protocol.h"` |
| include/uapi/linux/tquic_pm.h | net/tquic/tquic_netlink.c (future) | PM command definitions | TQUIC_PM_CMD_* |

Note: The netlink wiring (tquic_netlink.c using TQUIC_PM_CMD_*) is deferred to Phase 4 (Path Manager Implementation).

## Deviations from Plan

None - plan executed exactly as written.

## Decisions Made

1. **PM Flag Encoding**: Used `(1 << N)` instead of `BIT()` macro for path flags in UAPI header since BIT() is not available in userspace headers.

2. **tquic_sk Guard**: Added `#ifndef tquic_sk` guard in protocol.h since `include/net/tquic.h` already defines it. The internal header documents it and provides it only if not already defined.

3. **tquic6_sock Inline**: Left the inline `struct tquic6_sock` definition in tquic_ipv6.c with a TODO comment for future cleanup. The canonical definition exists in `include/net/tquic.h`.

## Verification Results

All verification criteria passed:
- [x] tquic_pm.h exists with TQUIC_PM_CMD_ADD_PATH
- [x] protocol.h exists with tquic_sk documentation
- [x] Lock hierarchy documentation present in protocol.h
- [x] tquic_socket.c, tquic_proto.c, tquic_ipv6.c include protocol.h

## Next Phase Readiness

- **Phase 02 (Socket API)**: protocol.h provides lock documentation needed for socket operations
- **Phase 04 (Path Manager)**: tquic_pm.h defines the netlink interface to be implemented

No blockers identified.
