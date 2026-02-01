---
phase: 08-vps-endpoint
plan: 02
subsystem: networking
tags: [tquic, tunnel, splice, qos, dscp, hairpin, tproxy, nat, icmp]

# Dependency graph
requires:
  - phase: 08-01
    provides: PSK authentication, client registration
  - phase: 02-03
    provides: QUIC stream socket implementation
provides:
  - TCP-over-QUIC tunnel termination
  - Zero-copy splice forwarding
  - QoS traffic classification with DSCP marking
  - Hairpin traffic detection and routing
  - TPROXY transparent proxy mode
  - ICMP passthrough for ping/traceroute
affects: [08-03, 08-04, 09-tooling]

# Tech tracking
tech-stack:
  added: [kernel splice, pipe_inode_info, nftables masquerade integration]
  patterns: [workqueue-based async connect, bitmap port allocation, hash table hairpin lookup]

key-files:
  created:
    - net/tquic/tquic_tunnel.c
    - net/tquic/tquic_qos.c
    - net/tquic/tquic_forward.c
  modified:
    - include/net/tquic.h

key-decisions:
  - "Stream header format: 1-byte AF + 4/16-byte IP + 2-byte port + 1-byte QoS hint"
  - "Traffic classes map to DSCP: realtime=EF(46), interactive=AF41(34), bulk=BE(0), background=CS1(8)"
  - "Port-based overrides: SIP ports always realtime, BitTorrent always background"
  - "1000 ports per client with bitmap allocation (125 bytes per client)"

patterns-established:
  - "Tunnel accessor functions for cross-module field access"
  - "Workqueue for async TCP connect to avoid blocking"
  - "Hash table for O(1) hairpin client lookup"

# Metrics
duration: 7min
completed: 2026-02-01
---

# Phase 8 Plan 2: TCP Tunnel Termination Summary

**TCP-over-QUIC tunnel termination with zero-copy splice forwarding, 4-class QoS, hairpin detection, and TPROXY support**

## Performance

- **Duration:** 7 min
- **Started:** 2026-02-01T03:06:51Z
- **Completed:** 2026-02-01T03:13:56Z
- **Tasks:** 3
- **Files modified:** 4 (3 created, 1 modified)

## Accomplishments

- TCP tunnel termination with kernel sockets and async connect via workqueue
- Zero-copy splice forwarding using SPLICE_F_MOVE between QUIC streams and TCP sockets
- QoS classification from router hints with DSCP marking for external QoS
- Hairpin traffic detection routing directly between VPS clients
- TPROXY mode with IP_TRANSPARENT for transparent proxying
- ICMP passthrough for ping/traceroute from router perspective
- TCP Fast Open enabled on outbound connections

## Task Commits

Each task was committed atomically:

1. **Task 1: TCP tunnel termination with QoS classification and TPROXY** - `092b6b1fb` (feat)
2. **Task 2: Zero-copy splice forwarding with hairpin detection** - `a9ae8da9f` (feat)
3. **Task 3: NAT masquerade and ICMP passthrough** - `9d761b8b3` (feat)

## Files Created/Modified

- `net/tquic/tquic_tunnel.c` - TCP-over-QUIC tunnel state machine, port allocation, TPROXY, ICMP handling
- `net/tquic/tquic_qos.c` - Traffic classification from router hints, DSCP marking, port-based overrides
- `net/tquic/tquic_forward.c` - Splice forwarding, hairpin detection, NAT verification, MTU handling
- `include/net/tquic.h` - Public API declarations for tunnel, QoS, and forward subsystems

## Decisions Made

| Decision | Rationale |
|----------|-----------|
| Stream header: AF + IP + port + QoS | Minimal header for tunnel setup, QoS hint inline |
| 4 DSCP classes with port overrides | Matches tc HTB patterns, safety for known traffic |
| Bitmap port allocation | O(1) alloc/free, 125 bytes per 1000 ports |
| Hash table for hairpin | O(1) lookup for client-to-client routing |
| Workqueue for TCP connect | Non-blocking, avoids softirq context issues |

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - all implementations followed standard kernel patterns.

## User Setup Required

None - kernel module integration only. NAT masquerade requires external nftables configuration:

```bash
nft add table inet tquic
nft add chain inet tquic postrouting { type nat hook postrouting priority srcnat; }
nft add rule inet tquic postrouting oifname "eth0" masquerade
```

## Next Phase Readiness

- Tunnel termination ready for path monitoring integration (08-03)
- QoS statistics available for Prometheus metrics export (08-04)
- Hairpin detection enables router-to-router traffic via VPS

---
*Phase: 08-vps-endpoint*
*Completed: 2026-02-01*
