# Phase 3: Diagnostics Integration - Context

**Gathered:** 2026-01-31
**Status:** Ready for planning

<domain>
## Phase Boundary

Make TQUIC connections visible to Linux networking tools (ss, proc) and enable debugging via MIB statistics. This phase adds observability — the ability to see connection state, path health, and error conditions. Active path management and control belong in Phase 4.

</domain>

<decisions>
## Implementation Decisions

### ss output format
- Basic `ss -t` shows state + active path count (not just state)
- State names use hybrid format: QUIC states with TCP equivalents in parentheses (e.g., "CONNECTED (ESTABLISHED)")
- Extended `ss -ti` shows both levels: connection summary line + per-path breakdown below
- Connection IDs shown in full hex in extended output — needed for packet capture correlation

### MIB counter design
- Granularity: global totals + per-path breakdown (matches multi-path focus)
- Counter categories: both traffic (packets, bytes, retransmits) AND path health (RTT samples, loss events, path failures, migrations)
- Monotonic main counters with separate reset interface for interval measurements
- Naming convention: Claude's discretion to match kernel style

### proc interface structure
- Hybrid layout matching TCP pattern: /proc/net/tquic (connections) + /proc/net/tquic_stat (counters)
- Fixed-column format for connection listing (space-separated, awk-parseable)
- Header row with column names in proc files (self-documenting)
- Path visibility: Claude's discretion on inline vs separate file

### Error visibility
- EQUIC error codes shown as both numeric and symbolic: "501 (EQUIC_FLOW_CONTROL)"
- Dual error logging: important errors to dmesg, all errors to dedicated ring buffer
- Ring buffer entries include full context: error + connection (CID, addresses) + stack trace + related counters
- Per-error-code counters: full implementation with counter for each EQUIC_* code

</decisions>

<specifics>
## Specific Ideas

- User wants "full kernel implementation complete" — comprehensive diagnostics, not minimal viable
- Connection IDs must be full (not truncated) for packet capture correlation
- Both ss and proc should be self-documenting (headers, symbolic names)

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 03-diagnostics*
*Context gathered: 2026-01-31*
