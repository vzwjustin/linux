# Phase 8: VPS Aggregation Endpoint - Context

**Gathered:** 2026-01-31
**Status:** Ready for planning

<domain>
## Phase Boundary

Server-side TQUIC implementation for VPS traffic aggregation. Accepts multi-path TQUIC connections from home routers, forwards traffic to internet destinations transparently, and provides real-time path monitoring. The VPS acts as the aggregation point where bonded WAN connections converge.

</domain>

<decisions>
## Implementation Decisions

### Connection Acceptance
- Pre-shared key (PSK) authentication for router connections
- Multi-tenant: single VPS serves multiple router clients, isolated by PSK identity
- Auto-accept on valid PSK — no admin approval step
- Resource-based client limits — accept until memory/CPU constraints, no hard cap

### Traffic Forwarding Model
- NAT masquerade for outbound traffic — all traffic exits with VPS public IP
- Full bidirectional support via shared IP + port ranges per router (e.g., client1: 10000-10999)
- TCP-over-QUIC tunnel — router encapsulates TCP in QUIC, VPS terminates and forwards as native TCP
- QUIC-only — no general UDP tunneling, other UDP uses normal routing
- VPS IP (NAT) for source on outbound TCP — no client IP preservation
- Persistent session state across router reconnects with configurable TTL
- Queue with timeout (e.g., 30s) when all paths to a router go down, then drop

### Protocol Handling
- Per-path MTU tracking — segment packets appropriately per path
- Dual-stack IPv4/IPv6 support
- PMTUD signaling for oversized packets — no VPS-side fragmentation
- Full ICMP passthrough — enables ping/traceroute from router's perspective
- DNS queries tunneled through — router controls its own DNS servers
- No 0-RTT — always require full handshake for security
- Connection migration supported when client source IP changes

### Performance Optimization
- Zero-copy forwarding via splice/sendfile for TCP termination
- TCP Fast Open (TFO) enabled for outbound connections
- GRO/GSO enabled for high-throughput packet processing
- No connection pooling — new connection per request
- TPROXY support for transparent proxying of specific ports

### Quality of Service
- VPS-side QoS classification with 4 traffic classes:
  - Real-time (VoIP/video) — lowest latency, highest priority
  - Interactive (gaming) — low latency, tolerates small jitter
  - Bulk (downloads) — best-effort, fills available bandwidth
  - Background — lowest priority, uses idle capacity only
- Router hints for flow classification — router tags flows, VPS honors hints
- Configurable per-client bandwidth limits
- Traffic shaping (delay packets) when exceeding limits, not drop
- Connection rate limiting per client — prevents abuse

### Security & Policy
- IP blocklisting for outbound destinations
- Blocklist managed via both config file (persistent) and runtime API (dynamic)
- Configurable hairpin traffic (router-to-router via VPS)
- Detailed connection logging: source, destination, bytes, duration
- Logs to both syslog/journald and dedicated log file

### Path Monitoring
- Statistics exposed via both proc filesystem (/proc/net/tquic/*) and netlink API
- Per-path metrics tracked:
  - Bandwidth (Tx/Rx bytes and packets)
  - Latency (RTT min/avg/max)
  - Loss rate (packet loss percentage)
  - Jitter (RTT variance)
- 5-second metric update interval
- Both built-in web dashboard (localhost) and Prometheus /metrics endpoint
- Built-in alerts for path degradation plus metrics export for external alerting

### Deployment
- Ubuntu/Debian primary target — apt package (.deb)
- Config directory: /etc/tquic.d/*.conf for modular configuration
- systemd service for process management
- Kernel data path (packet forwarding), userspace control daemon (config/monitoring)

### Claude's Discretion
- HTTP/3 connection coalescing strategy
- Exact port range allocation algorithm
- Built-in dashboard implementation details
- Prometheus metric naming conventions
- Specific QoS queue discipline parameters
- Log rotation configuration

</decisions>

<specifics>
## Specific Ideas

- VPS is the aggregation endpoint that home routers connect to — this is the "server side" of the WAN bonding solution
- Should integrate seamlessly with the kernel TQUIC implementation from Phases 1-7
- Real-time path monitoring is critical for operators to understand bonding behavior
- The web dashboard is for quick visual checks; Prometheus is for production monitoring stacks

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 08-vps-endpoint*
*Context gathered: 2026-01-31*
