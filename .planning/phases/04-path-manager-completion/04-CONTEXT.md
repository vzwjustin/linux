# Phase 4: Path Manager Completion - Context

**Gathered:** 2026-01-31
**Status:** Ready for planning

<domain>
## Phase Boundary

Full path manager with kernel automatic mode and userspace daemon interface. Includes PATH_CHALLENGE/PATH_RESPONSE validation, dynamic path add/remove without connection disruption, and netlink events for path state changes. Scheduling algorithms and bonding strategies are separate phases.

</domain>

<decisions>
## Implementation Decisions

### Netlink interface design
- Follow MPTCP genetlink pattern (TQUIC_PM_CMD_*)
- Full command set: ADD_PATH, DEL_PATH, SET_FLAGS, GET_PATH, FLUSH_PATHS
- Extended ACK with NLMSGERR_ATTR_MSG for detailed error strings
- Both global defaults (sysctl) and per-connection overrides (netlink with connection token)

### Path discovery policy
- Auto-add paths when interface comes up AND has a default route
- Configurable interface filter via sysctl (exclude patterns), default excludes loopback and virtual (lo, veth, bridge)
- When interface goes down: mark path unavailable but keep state for fast recovery
- Default 8 paths per connection (matches active_connection_id_limit), configurable via sysctl

### Validation behavior
- Send PATH_CHALLENGE immediately when path is added
- 3 retries before marking path as failed
- Validation timeout: 3x smoothed RTT (adaptive to path latency)
- On revalidation failure: immediate failover to other paths, start revalidation attempts

### Event notifications
- All state changes trigger events: ADDED, VALIDATED, FAILED, REMOVED, DEGRADED
- Events include path metrics (RTT, loss rate, bandwidth estimate)
- Rate-limited to 100 events/sec default, configurable via sysctl
- Multicast group TQUIC_PM_GRP_EVENTS for multiple listeners

### Claude's Discretion
- Exact netlink attribute encoding (nested vs flat)
- Interface type detection mechanism
- Initial RTT estimate for paths with no history
- Event queue implementation details

</decisions>

<specifics>
## Specific Ideas

- "Full QUIC protocol implementation kernel wide deep" — comprehensive approach, no shortcuts
- "Complete build out" — configurable where flexibility matters, sensible defaults everywhere
- Follow MPTCP patterns closely for kernel developer familiarity

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 04-path-manager-completion*
*Context gathered: 2026-01-31*
