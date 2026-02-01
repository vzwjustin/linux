---
phase: 04-path-manager-completion
plan: 03
subsystem: path-validation
tags: [rfc-9000, path-validation, rtt-estimation, adaptive-timeout, quic-frames]

# Dependency graph
requires:
  - phase: 04-01
    provides: PM type framework and kernel PM with interface discovery
  - phase: 04-02
    provides: PM netlink interface with path events
  - phase: 03-02
    provides: MIB counters including TQUIC_MIB_PATHVALIDATED

provides:
  - RFC 9000-compliant PATH_CHALLENGE/RESPONSE validation
  - Adaptive timeout based on 3x SRTT (100ms to 10s range)
  - RTT estimation using RFC 6298 algorithm
  - Response queue limit (256) to prevent memory exhaustion
  - 3-retry validation with automatic failover
  - VALIDATED/FAILED events via PM netlink

affects: [05-bonding-core, 06-scheduler, connection-migration]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "RFC 6298 RTT calculation (SRTT/RTTVAR)"
    - "Adaptive validation timeout: 3x SRTT + 4x RTTVAR"
    - "Response queue depth limit pattern for DoS prevention"
    - "Timer-based retransmission with exponential backoff"

key-files:
  created:
    - net/tquic/pm/path_validation.c
  modified:
    - include/net/tquic.h
    - net/tquic/pm/Makefile
    - net/tquic/tquic_input.c
    - net/tquic/tquic_main.c
    - net/tquic/pm/path_manager.c

key-decisions:
  - "3x SRTT multiplier for validation timeout (balances LAN/satellite)"
  - "256-frame response queue limit prevents memory exhaustion attacks"
  - "SRTT initialized to 100ms (TQUIC_DEFAULT_RTT) before first sample"
  - "Validation starts immediately when path added (non-backup paths)"
  - "Both VALIDATED and ACTIVE states are acceptable for scheduler"

patterns-established:
  - "Validation state in struct tquic_path (challenge_data, timer, retries)"
  - "Response queue pattern: skb_queue_head + atomic_t count for limit enforcement"
  - "Path validation handlers separate from frame encoding (modularity)"
  - "del_timer_sync + skb_queue_purge cleanup pattern in path removal"

# Metrics
duration: 4min 40sec
completed: 2026-01-31
---

# Phase 04 Plan 03: Path Validation Summary

**RFC 9000 PATH_CHALLENGE/RESPONSE with adaptive timeouts (3x SRTT), RTT estimation via RFC 6298, and 256-frame queue limit for DoS prevention**

## Performance

- **Duration:** 4 minutes 40 seconds
- **Started:** 2026-01-31T19:28:20Z
- **Completed:** 2026-01-31T19:33:01Z
- **Tasks:** 3 of 3 completed
- **Files modified:** 6

## Accomplishments

- PATH_CHALLENGE sent immediately when path added with random 8-byte challenge
- PATH_RESPONSE validates path and updates RTT using RFC 6298 (SRTT/RTTVAR)
- 3 retries with adaptive timeout (3x SRTT + 4x RTTVAR, clamped 100ms-10s) before path marked FAILED
- Response queue limited to 256 frames prevents memory exhaustion attacks
- Validation wired into path lifecycle (start on add, cleanup on remove)
- Scheduler only selects VALIDATED or ACTIVE paths

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement path validation state machine** - `21a869ea2` (feat)
   - Created path_validation.c with validation state machine
   - Added validation state to struct tquic_path
   - Implemented tquic_path_start_validation(), tquic_path_validation_timeout()
   - Implemented tquic_path_handle_challenge() with 256-frame queue limit
   - Implemented tquic_path_handle_response() with RTT calculation
   - RFC 6298 RTT estimation in tquic_pm_update_rtt()

2. **Task 2: Wire PATH_CHALLENGE/RESPONSE to validation handlers** - `219026c92` (feat)
   - Updated tquic_process_path_challenge_frame() to call tquic_path_handle_challenge()
   - Updated tquic_process_path_response_frame() to call tquic_path_handle_response()
   - Connected tquic_path_send_challenge() to existing tquic_send_path_challenge()
   - Frame encoding/decoding already exists in frame.c (verified 9 bytes)

3. **Task 3: Wire validation into path lifecycle** - `0d45ff549` (feat)
   - Initialize validation state in tquic_conn_add_path() (timer, queue, retries)
   - Start validation immediately via tquic_path_start_validation()
   - Clean up validation in tquic_conn_remove_path() (del_timer_sync, skb_queue_purge)
   - Updated tquic_pm_select_path() to only select VALIDATED or ACTIVE paths

## Files Created/Modified

- `net/tquic/pm/path_validation.c` (new) - PATH_CHALLENGE/RESPONSE validation logic
- `include/net/tquic.h` - Added validation and response fields to struct tquic_path
- `net/tquic/pm/Makefile` - Added path_validation.o
- `net/tquic/tquic_input.c` - Updated frame handlers to call validation module
- `net/tquic/tquic_main.c` - Initialize/cleanup validation in path lifecycle
- `net/tquic/pm/path_manager.c` - Scheduler checks for VALIDATED/ACTIVE state

## Decisions Made

1. **3x SRTT multiplier for validation timeout**
   - Rationale: RFC 9000 recommendation balances fast LAN (1ms) and slow satellite (500ms) networks
   - Implementation: timeout = 3 * SRTT + max(1ms, 4 * RTTVAR), clamped to 100ms-10s

2. **256-frame response queue limit**
   - Rationale: Prevent memory exhaustion from PATH_CHALLENGE floods (DoS mitigation)
   - Implementation: atomic_t count, check in tquic_path_handle_challenge(), return -ENOBUFS

3. **SRTT initialized to 100ms**
   - Rationale: TQUIC_DEFAULT_RTT provides reasonable default before first sample
   - Implementation: path->stats.rtt_smoothed = TQUIC_DEFAULT_RTT * 1000 in tquic_conn_add_path()

4. **Immediate validation on path add**
   - Rationale: Paths must be validated before data transmission per RFC 9000 Section 9
   - Implementation: tquic_path_start_validation() called at end of tquic_conn_add_path()

5. **Both VALIDATED and ACTIVE states acceptable**
   - Rationale: VALIDATED = passed validation, ACTIVE = in use for data; both are usable
   - Implementation: Scheduler checks `state != ACTIVE && state != VALIDATED` as exclusion

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - frame encoding/decoding already existed in frame.c, input dispatch already hooked up.

## Next Phase Readiness

**Ready for Phase 05 (Bonding Core):**
- Paths are validated before use
- RTT estimates available for scheduler decisions
- Failover triggered on validation failure via tquic_bond_path_failed()
- VALIDATED/FAILED events emitted for userspace monitoring

**Ready for Phase 06 (Scheduler):**
- RTT statistics (SRTT, RTTVAR, min_rtt) available in path->stats
- Scheduler can safely select from VALIDATED/ACTIVE paths only
- Path priority and weight fields ready for weighted schedulers

**Blockers:** None

**Concerns:** None

---
*Phase: 04-path-manager-completion*
*Completed: 2026-01-31*
