# Phase 1: Protocol Foundation - Context

**Gathered:** 2026-01-30
**Status:** Ready for planning

<domain>
## Phase Boundary

TQUIC becomes a first-class kernel protocol with proper IPPROTO assignment and UAPI headers. This phase establishes the foundation: socket creation works, headers are installed, and locking hierarchy is documented. Actual socket operations (connect, accept, send, recv) are Phase 2.

</domain>

<decisions>
## Implementation Decisions

### Header Organization
- Claude's discretion on header split (tquic.h vs tquic_pm.h)
- Claude's discretion on sockopt constant ranges
- Claude's discretion on control interface (sockopts + netlink vs ioctls)
- Claude's discretion on reserved fields for ABI stability

### Error Behavior
- Claude's discretion on error codes for module-not-loaded
- Claude's discretion on crypto availability check timing (socket vs connect)
- Claude's discretion on invalid sockopt error codes
- Claude's discretion on QUIC protocol error mapping (existing errno vs TQUIC-specific)

### Kconfig Integration
- Claude's discretion on tristate vs bool
- Claude's discretion on menu location
- Claude's discretion on dependency style (select vs depends)
- Claude's discretion on debug sub-options

### Documentation Style
- **User decision:** Both header section AND inline comments for locking
  - File header: LOCKING section with full hierarchy overview
  - Inline: Specific lock requirements at each lock definition
- Claude's discretion on kernel-doc format usage
- Claude's discretion on lockdep annotation style
- Claude's discretion on architecture design doc inclusion

### Claude's Discretion
User delegated nearly all Phase 1 decisions to Claude, with one exception:

**Locked decision:** Locking documentation uses BOTH approaches:
1. File header LOCKING section for hierarchy overview
2. Inline comments for specific lock requirements

For all other areas, Claude should follow kernel conventions, MPTCP patterns, and upstream best practices.

</decisions>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches following kernel networking conventions.

User trusts Claude to make implementation decisions that will pass upstream review.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 01-protocol-foundation*
*Context gathered: 2026-01-30*
