---
phase: 02-socket-api
plan: 03
subsystem: socket-api
tags: [stream-multiplexing, ioctl, poll, sendmsg, recvmsg, quic-streams]

# Dependency graph
requires:
  - phase: 02-01
    provides: Client connect with TLS handshake, EQUIC error codes
  - phase: 02-02
    provides: Server listen/accept, listener hash table
provides:
  - TQUIC_NEW_STREAM ioctl for creating stream file descriptors
  - Stream socket type with sendmsg/recvmsg/poll support
  - Stream flow control and blocking on stream limit
  - First-class stream fds usable with poll/epoll/select
affects: [03-diagnostics, 04-path-manager, phase-3-packet-io]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Stream socket via ioctl returning fd"
    - "sk_user_data for stream->socket linkage"
    - "RB-tree for stream lookup by ID"
    - "wait_event_interruptible for blocking operations"

key-files:
  created:
    - net/tquic/tquic_stream.c
  modified:
    - include/uapi/linux/tquic.h
    - net/tquic/protocol.h
    - net/tquic/tquic_socket.c
    - net/tquic/Makefile

key-decisions:
  - "Stream socket via ioctl rather than separate syscall - follows CONTEXT.md hybrid model"
  - "sk_user_data links stream fd to tquic_stream_sock struct"
  - "RB-tree for stream management within connection"
  - "Blocking on stream limit uses connection's sk_wq"
  - "Stream IDs increment by 4 per RFC 9000 (type encoded in low 2 bits)"

patterns-established:
  - "Pattern: Stream socket ops use sock_no_* for unsupported operations"
  - "Pattern: Stream state uses tquic_stream_sock as intermediary"
  - "Pattern: Flow control check before marking writable in poll"

# Metrics
duration: 12min
completed: 2026-01-31
---

# Phase 02 Plan 03: Stream Multiplexing Summary

**ioctl(TQUIC_NEW_STREAM) creating first-class stream fds with sendmsg/recvmsg/poll support and blocking on peer MAX_STREAMS limit**

## Performance

- **Duration:** 12 min
- **Started:** 2026-01-31T17:40:00Z
- **Completed:** 2026-01-31T17:52:00Z
- **Tasks:** 4
- **Files modified:** 5

## Accomplishments

- TQUIC_NEW_STREAM ioctl defined in UAPI with tquic_stream_args structure
- Stream socket implementation with full sendmsg/recvmsg/poll support
- Stream fd is first-class file descriptor usable with poll/epoll/select
- Blocking on stream limit until peer grants MAX_STREAMS
- Stream ID assignment per RFC 9000 (client even, server odd, +4 increment)

## Task Commits

Each task was committed atomically:

1. **Task 1: Define TQUIC_NEW_STREAM ioctl and stream flags in UAPI** - `ef57cb73d` (feat)
2. **Task 2: Define struct tquic_stream and add stream helper stubs to protocol.h** - `4e1fb1b49` (feat)
3. **Task 3: Create tquic_stream.c with stream socket implementation** - `77af5f7a4` (feat)
4. **Task 4: Implement TQUIC_NEW_STREAM ioctl with blocking** - `334f1198b` (feat - combined with 02-04)

## Files Created/Modified

- `include/uapi/linux/tquic.h` - Added TQUIC_IOC_MAGIC, tquic_stream_args, TQUIC_NEW_STREAM, stream flags
- `net/tquic/protocol.h` - Added struct tquic_stream_sock, stream function declarations
- `net/tquic/tquic_stream.c` - Stream socket implementation (sendmsg/recvmsg/poll/release)
- `net/tquic/tquic_socket.c` - Added tquic_ioctl() with TQUIC_NEW_STREAM handler
- `net/tquic/Makefile` - Added tquic_stream.o

## Decisions Made

1. **Stream socket via ioctl** - Per CONTEXT.md hybrid model, ioctl on connection socket creates stream fd
2. **sk_user_data linkage** - Stream socket uses sk_user_data to store tquic_stream_sock pointer
3. **RB-tree for streams** - Connection maintains RB-tree of streams for O(log n) lookup by ID
4. **Stream ID encoding** - Per RFC 9000: bits 0-1 encode type (client/server, bidi/uni), IDs increment by 4
5. **Blocking semantics** - ioctl blocks when at stream limit, returns EAGAIN for O_NONBLOCK

## Deviations from Plan

### Note on Task 4 Commit

Task 4 (ioctl handler in tquic_socket.c) was committed together with 02-04 plan changes in commit `334f1198b`. This occurred because both plans modified tquic_socket.c concurrently. The ioctl handler implementation is complete and correct.

---

**Total deviations:** 1 (commit merge with 02-04)
**Impact on plan:** None - all functionality implemented correctly

## Issues Encountered

None - plan executed as specified.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Stream multiplexing complete for userspace API
- Ready for Phase 3 (packet I/O) to wire up actual STREAM frame transmission
- tquic_output_flush() is stub - needs Phase 3 implementation
- Stream receive path needs packet input to deliver data to recv_buf

---
*Phase: 02-socket-api*
*Completed: 2026-01-31*
