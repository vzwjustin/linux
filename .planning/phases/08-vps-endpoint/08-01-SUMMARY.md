---
phase: 08-vps-endpoint
plan: 01
subsystem: server
tags: [psk, authentication, rate-limiting, migration, session-ttl, multi-tenant]

dependency-graph:
  requires:
    - 02-socket-api (socket infrastructure, handshake callbacks)
    - 04-path-manager-completion (path validation, PATH_CHALLENGE/RESPONSE)
    - 07-congestion-control (CC per path for isolated connections)
  provides:
    - Multi-tenant VPS server connection handling
    - PSK-based router authentication
    - Per-client connection rate limiting
    - Session state preservation across router reconnects
  affects:
    - 08-02 (uses tquic_client for tunnel client binding)
    - 09-tooling (client management CLI, stats display)

tech-stack:
  added:
    - rhashtable for O(1) client lookup by PSK identity
    - Token bucket rate limiting algorithm
  patterns:
    - Per-client state tracking for multi-tenant isolation
    - Session TTL timer for router reconnect handling
    - Queue-with-timeout for temporary path loss

file-tracking:
  created:
    - net/tquic/tquic_server.c
  modified:
    - include/net/tquic.h
    - include/uapi/linux/tquic.h
    - net/tquic/tquic_socket.c
    - net/tquic/tquic_handshake.c
    - net/tquic/tquic_migration.c
    - net/tquic/protocol.h
    - net/tquic/Makefile

decisions:
  - key: token-bucket-rate-limit
    choice: Token bucket with 1-second burst capacity
    rationale: Smooth rate limiting, handles burst reconnects
  - key: session-ttl-default
    choice: 120 seconds per CONTEXT.md
    rationale: Balance between memory usage and router reconnect time
  - key: queue-timeout-default
    choice: 30 seconds per CONTEXT.md
    rationale: Reasonable window for temporary path failures
  - key: psk-identity-max-length
    choice: 64 bytes per RFC 8446 Section 4.2.11
    rationale: Standard TLS 1.3 PSK identity limit

metrics:
  duration: 6m
  completed: 2026-02-01
---

# Phase 8 Plan 1: Multi-Tenant Server Connection Handling Summary

**One-liner:** PSK-based multi-tenant VPS server with per-client rate limiting and session TTL for router reconnects

## What Was Built

### Task 1: Multi-tenant server connection tracking with rate limiting

Created `net/tquic/tquic_server.c` implementing:

- **struct tquic_client**: Per-router client state including:
  - PSK identity and key (up to 64 bytes identity, 32 bytes key)
  - Port range allocation and bandwidth limits
  - Connection count and traffic statistics
  - Token bucket rate limiting (default 10 conn/sec)
  - Session TTL for reconnects (default 120s)
  - QoS traffic class weights

- **rhashtable for client lookup**: O(1) lookup by PSK identity string for efficient handshake processing

- **Token bucket rate limiting**:
  - `tquic_client_rate_refill()`: Refills tokens based on elapsed time
  - `tquic_client_rate_limit_check()`: Returns true if connection allowed, consumes token
  - Max bucket size = rate limit (1 second of burst)
  - Ratelimited logging on limit hits

- **Client lifecycle management**:
  - `tquic_client_register(identity, len, psk)`: Register new client
  - `tquic_client_unregister(identity, len)`: Remove client with RCU cleanup
  - `tquic_server_bind_client(conn, client)`: Bind connection after auth
  - `tquic_server_unbind_client(conn)`: Unbind on connection close

- Extended `struct tquic_connection` with:
  - `struct tquic_client *client` pointer for server-side binding
  - `enum tquic_conn_role role` (CLIENT or SERVER)

### Task 2: PSK identity sockopt and handshake integration

- **SO_TQUIC_PSK_IDENTITY sockopt (value 22)**:
  - setsockopt: Store PSK identity for client connections
  - getsockopt: Retrieve current PSK identity
  - Identity length validation (1-64 bytes)

- **Server-side PSK callback**:
  - `tquic_server_psk_callback()`: TLS layer callback for PSK lookup
  - Calls `tquic_client_lookup_by_psk()` to find client
  - Checks rate limit via `tquic_client_rate_limit_check()`
  - Returns PSK for TLS handshake or rejects with EQUIC_CONNECTION_REFUSED
  - Binds client to connection for resource tracking

- **Rejection handling**:
  - Unknown PSK identity: Rejected with EQUIC_CONNECTION_REFUSED
  - Rate limit exceeded: Rejected with EQUIC_CONNECTION_REFUSED
  - Ratelimited logging prevents log flooding

### Task 3: Connection migration support for VPS

- **Server-side migration handler**:
  - `tquic_server_handle_migration(conn, path, new_remote)`: Updates path remote address when router's source IP changes
  - Triggers PATH_CHALLENGE validation for new address
  - Increments migration statistics

- **Session TTL for router reconnects**:
  - `struct tquic_session_state`: Tracks session during path unavailability
  - `tquic_server_start_session_ttl(conn)`: Starts TTL timer (default 120s)
  - `tquic_session_ttl_expired()`: Timer callback that closes connection
  - `tquic_server_session_resume(conn, path)`: Cancels TTL, drains queue

- **Queue-with-timeout for path-down**:
  - `tquic_server_queue_packet(conn, skb)`: Queues packets during outage
  - 30-second timeout per CONTEXT.md
  - 1024 packet limit to prevent memory exhaustion

- **Path recovery checking**:
  - `tquic_server_check_path_recovery(conn)`: Checks if UNAVAILABLE paths can recover
  - Triggers validation when network device comes back up

## Key Implementation Details

### Rate Limiting Algorithm

```c
// Token bucket with configurable rate (default 10/sec)
// Refill: tokens += (elapsed_ns / 1e9) * rate_limit
// Cap at bucket size (1 second of burst)
// Check: if tokens > 0, decrement and allow; else reject
```

### Session TTL State Machine

```
All paths up -> Path down -> Start TTL timer (120s)
                    |
                    +-> Path recovers within TTL -> Resume session
                    |
                    +-> TTL expires -> Close connection
```

### PSK Handshake Flow

```
ClientHello with PSK identity
    |
    v
tquic_server_psk_callback()
    |
    +-> tquic_client_lookup_by_psk() -> Not found? REJECT
    |
    +-> tquic_client_rate_limit_check() -> Rate limited? REJECT
    |
    +-> tquic_server_get_client_psk() -> Return PSK for TLS
    |
    +-> tquic_server_bind_client() -> Track connection
```

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | b9f7aa537 | Multi-tenant server connection tracking with rate limiting |
| 2 | 143e3c6a6 | PSK identity sockopt and handshake integration |
| 3 | fbacf8ab3 | VPS connection migration support with session TTL |

## Deviations from Plan

None - plan executed exactly as written.

## Files Modified

| File | Changes |
|------|---------|
| net/tquic/tquic_server.c | New file: 610 lines, multi-tenant server implementation |
| include/net/tquic.h | Added tquic_client forward decl, conn role enum, client pointer |
| include/uapi/linux/tquic.h | Added SO_TQUIC_PSK_IDENTITY sockopt (22) |
| net/tquic/tquic_socket.c | Added PSK identity setsockopt/getsockopt handlers |
| net/tquic/tquic_handshake.c | Added server PSK callback with rate limiting |
| net/tquic/tquic_migration.c | Added server migration, session TTL, packet queue |
| net/tquic/protocol.h | Added server function declarations |
| net/tquic/Makefile | Added tquic_server.o to build |

## Next Phase Readiness

**Prerequisites for 08-02 (TCP Tunnel Termination):**
- tquic_client structure provides client binding for tunnels
- Rate limiting prevents abuse via excessive tunnels
- Session TTL enables tunnel persistence across router reconnects

**Prerequisites for 09-tooling:**
- tquic_client_register/unregister API for CLI management
- tquic_client_get_stats for monitoring
- tquic_client_set_rate_limit for configuration

## Success Criteria Verification

- [x] tquic_server.c implements multi-tenant client tracking with rhashtable
- [x] struct tquic_client has conn_rate_limit and token bucket fields
- [x] tquic_client_rate_limit_check() implements token bucket algorithm
- [x] SO_TQUIC_PSK_IDENTITY sockopt configures PSK for connections
- [x] Server handshake validates PSK identity, checks rate limit, and binds to client config
- [x] Rate limit exceeded connections rejected with EQUIC_CONNECTION_REFUSED
- [x] Unknown PSK identity rejected with EQUIC_CONNECTION_REFUSED
- [x] Connection migration updates path when source IP changes
- [x] Session state preserved during temporary path loss (up to TTL)
- [x] No 0-RTT (full handshake required per CONTEXT.md)
