# Phase 2: Socket API Completion - Context

**Gathered:** 2026-01-31
**Status:** Ready for planning

<domain>
## Phase Boundary

Full BSD socket API for TQUIC with proper connection lifecycle and handshake. Delivers connect(), listen(), accept(), sendmsg(), recvmsg(), stream multiplexing, and connection ID migration. Path management and multi-path bonding are separate phases.

</domain>

<decisions>
## Implementation Decisions

### Error Semantics
- New EQUIC* error codes that expose QUIC error codes directly (not TCP-like ECONNREFUSED)
- EPIPE + SIGPIPE on send/recv to closed stream — match TCP behavior
- No extended getsockopt for QUIC errors — standard errno is enough
- Blocking connect() waits until full TLS handshake completes

### Stream Model
- Hybrid model: connection socket + child stream sockets
- ioctl(TQUIC_NEW_STREAM) on connection socket returns new stream fd
- Flags to ioctl select stream type: TQUIC_STREAM_BIDI / TQUIC_STREAM_UNIDI
- Block on stream limit — ioctl blocks until peer grants more streams

### Handshake Behavior
- 0-RTT early data opt-in via sockopt (disabled by default)
- Fixed 30-second kernel handshake timeout, not configurable per-socket
- In-kernel TLS 1.3 implementation (like kTLS) — no userspace upcalls
- System trust store for server certificate verification

### Migration Policy
- Both automatic and explicit migration modes
- Automatic migration on NAT rebind detection by default
- Explicit migration via setsockopt to force immediate migration
- Immediate PATH_CHALLENGE on new path after migration
- Sockopt poll for migration status (getsockopt to check)

### Claude's Discretion
- Connection ID pool size and management strategy (per QUIC RFC recommendations)
- Exact EQUIC* error code values and mapping to QUIC transport errors
- Internal handshake state machine structure
- kTLS integration details

</decisions>

<specifics>
## Specific Ideas

- Error codes should feel QUIC-native — developers shouldn't need to decode TCP-style errors
- Stream sockets should be first-class fds that work with poll/epoll/select
- Handshake must be synchronous from app perspective — connect() returns means ready to send

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-socket-api*
*Context gathered: 2026-01-31*
