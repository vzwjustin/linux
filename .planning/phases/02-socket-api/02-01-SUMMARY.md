---
phase: 02-socket-api
plan: 01
subsystem: socket-handshake
tags: [tls, handshake, connect, net-handshake, equic, error-codes]
depends:
  requires: [01-01, 01-02, 01-03]
  provides: [blocking-connect, tls-handshake, equic-errors]
  affects: [02-02, 02-03, 02-04]
tech-stack:
  added: [net/handshake]
  patterns: [completion-wait, tlshd-delegation, async-callback]
key-files:
  created:
    - net/tquic/tquic_handshake.c
  modified:
    - include/uapi/linux/tquic.h
    - include/net/tquic.h
    - net/tquic/tquic_socket.c
    - net/tquic/protocol.h
    - net/tquic/Makefile
decisions:
  - id: equic-base-500
    choice: EQUIC_BASE=500
    reason: Avoid collision with standard errno (max ~133)
  - id: handshake-timeout-fixed
    choice: Fixed 30s timeout, not configurable
    reason: Per CONTEXT.md design decision
  - id: net-handshake-delegation
    choice: Use net/handshake tlshd delegation
    reason: Matches NFS over TLS pattern (sunrpc/xprtsock.c)
metrics:
  duration: 4m
  completed: 2026-01-31
---

# Phase 02 Plan 01: Client connect() with TLS 1.3 Handshake Summary

Blocking connect() with TLS 1.3 handshake via net/handshake delegation to tlshd daemon.

## Objective Achieved

Implemented client connect() that:
- Blocks until TLS 1.3 handshake completes or 30s timeout
- Transitions socket from TCP_SYN_SENT to TCP_ESTABLISHED on success
- Returns EQUIC_* error codes for QUIC-native error semantics
- Integrates with kernel net/handshake infrastructure

## Changes Made

### Task 1: EQUIC Error Codes (include/uapi/linux/tquic.h)

Added 24 QUIC-native error codes:
- EQUIC_BASE at 500 (avoids errno collision)
- 17 RFC 9000 transport errors (EQUIC_NO_ERROR through EQUIC_NO_VIABLE_PATH)
- 5 crypto/handshake errors (EQUIC_HANDSHAKE_FAILED, EQUIC_HANDSHAKE_TIMEOUT, etc.)
- TQUIC_HANDSHAKE_TIMEOUT_MS constant (30000ms)

### Task 2: TLS Handshake Integration (net/tquic/tquic_handshake.c)

Created new file implementing net/handshake integration:
- `tquic_start_handshake()` - Initiates async TLS handshake via tlshd
- `tquic_wait_for_handshake()` - Blocks until completion with timeout
- `tquic_handshake_done()` - Callback when tlshd completes
- `tquic_handshake_cleanup()` - Resource cleanup
- `tquic_handshake_in_progress()` - Status check

Added to tquic_sock structure:
- `handshake_state` pointer for tracking handshake progress
- `flags` field for socket flags (TQUIC_F_*)

### Task 3: Blocking connect() (net/tquic/tquic_socket.c)

Rewrote tquic_connect() to implement proper blocking handshake:
1. Store peer address
2. Add initial path to connection
3. Initialize connection state machine
4. Set state to TCP_SYN_SENT
5. Call tquic_start_handshake() (async initiation)
6. Release socket lock
7. Call tquic_wait_for_handshake() (blocking wait)
8. Reacquire lock, verify TQUIC_F_HANDSHAKE_DONE
9. Set state to TCP_ESTABLISHED on success

Updated tquic_destroy_sock() to call tquic_handshake_cleanup().

## Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Error code base | 500 | Standard errno max is ~133, leaves room for future errno expansion |
| Handshake timeout | Fixed 30s | Per CONTEXT.md, not configurable per-socket |
| TLS delegation | net/handshake | Same pattern as NFS over TLS (sunrpc/xprtsock.c) |
| Async + wait | Completion | Standard kernel pattern for async-then-block |

## Files Summary

| File | Change | Lines |
|------|--------|-------|
| include/uapi/linux/tquic.h | Added EQUIC_* error codes | +41 |
| net/tquic/tquic_handshake.c | New file - handshake integration | +341 |
| include/net/tquic.h | Added handshake_state, flags to tquic_sock | +12 |
| net/tquic/tquic_socket.c | Rewrote connect() with blocking handshake | +87/-13 |
| net/tquic/protocol.h | Added handshake function declarations | +45 |
| net/tquic/Makefile | Added tquic_handshake.o | +1 |

## Commit Log

| Hash | Type | Description |
|------|------|-------------|
| 08f4581e8 | feat | Add EQUIC error codes to UAPI header |
| d6d01283f | feat | Add TLS handshake integration via net/handshake |
| bf55317eb | feat | Wire connect() to blocking TLS handshake |

## Verification Results

1. EQUIC_* error codes defined: 24 definitions in UAPI header
2. tquic_handshake.c exists with net/handshake integration (tls_client_hello_x509)
3. connect() calls tquic_start_handshake() and tquic_wait_for_handshake()
4. Socket state transitions: TCP_CLOSE -> TCP_SYN_SENT -> TCP_ESTABLISHED

## Deviations from Plan

None - plan executed exactly as written.

## Next Phase Readiness

Plan 02-02 (Server listen/accept) can proceed. Dependencies satisfied:
- Socket flags infrastructure in place (TQUIC_F_*)
- Handshake completion pattern established
- EQUIC error codes available for server errors

---

*Plan completed: 2026-01-31*
*Duration: ~4 minutes*
