---
phase: 08-vps-endpoint
plan: 03
subsystem: vps-daemon
tags: [go, daemon, prometheus, netlink, monitoring]
dependency-graph:
  requires: ["08-01", "08-02"]
  provides: ["tquicd-daemon", "prometheus-metrics", "web-dashboard", "connection-logging"]
  affects: ["09-tooling"]
tech-stack:
  added:
    - go-genetlink (github.com/mdlayher/genetlink)
    - prometheus-client-golang (github.com/prometheus/client_golang)
    - fsnotify (github.com/fsnotify/fsnotify)
    - go-systemd (github.com/coreos/go-systemd/v22)
  patterns:
    - genetlink-communication
    - prometheus-metrics-collection
    - config-hot-reload
    - systemd-notify
key-files:
  created:
    - tools/tquic/tquicd/main.go
    - tools/tquic/tquicd/go.mod
    - tools/tquic/tquicd/config/config.go
    - tools/tquic/tquicd/config/loader.go
    - tools/tquic/tquicd/netlink/types.go
    - tools/tquic/tquicd/netlink/client.go
    - tools/tquic/tquicd/netlink/events.go
    - tools/tquic/tquicd/monitor/collector.go
    - tools/tquic/tquicd/monitor/alerter.go
    - tools/tquic/tquicd/monitor/logger.go
    - tools/tquic/tquicd/api/prometheus.go
    - tools/tquic/tquicd/api/dashboard.go
    - tools/tquic/tquicd/api/blocklist.go
    - tools/tquic/tquicd/qos/htb.go
  modified: []
decisions:
  - id: genetlink-graceful-degradation
    choice: "Return nil client if kernel module not loaded"
    rationale: "Allow daemon to start without kernel module for config validation"
  - id: ring-buffer-connection-events
    choice: "100-entry ring buffer for recent connections"
    rationale: "Balance memory usage vs. dashboard history"
  - id: 5-second-metric-poll
    choice: "Poll kernel every 5 seconds for path stats"
    rationale: "Per CONTEXT.md, matches kernel update interval"
  - id: alert-thresholds
    choice: ">5% loss, >500ms RTT, >100ms jitter"
    rationale: "Reasonable defaults for WAN bonding paths"
metrics:
  duration: "8 minutes"
  completed: 2026-02-01
---

# Phase 08 Plan 03: tquicd Daemon Summary

Go userspace daemon with configuration loading, Prometheus metrics, real-time web dashboard, and detailed connection logging via genetlink communication with TQUIC kernel module.

## What Was Built

### Daemon Core (main.go - 475 lines)
- Command-line flags: `-c` (config dir), `-v` (verbose), `--version`
- Signal handling: SIGHUP for config reload, SIGTERM/SIGINT for graceful shutdown
- systemd notify integration for service ready state
- Goroutine management with WaitGroup for clean shutdown

### Configuration System (config/*.go)
- `Config`, `GlobalConfig`, `ClientConfig`, `BlocklistConfig` types
- INI-style parser for `/etc/tquic.d/*.conf` files
- Validation: PSK base64 decoding, port range overlap check, bandwidth parsing
- Hot reload via fsnotify watching config directory
- `ConnLogFile` field for dedicated JSON connection log

### Netlink Communication (netlink/*.go)
- Generic netlink client for TQUIC family
- `RegisterClient`, `GetPathStats`, `GetClientStats`, `SetBlocklist` commands
- Multicast subscription for connection events (OPEN/CLOSE/MIGRATE)
- `PathStats` struct with RTT (min/avg/max), loss rate, jitter, byte counters
- `ConnectionEvent` with source/dest IPs, ports, traffic class, duration

### Prometheus Metrics (monitor/collector.go)
```
tquic_connections_total{client, traffic_class}
tquic_connections_active{client}
tquic_path_bytes_total{client, path_id, direction}
tquic_path_rtt_seconds{client, path_id, stat}
tquic_path_loss_ratio{client, path_id}
tquic_path_jitter_seconds{client, path_id}
tquic_path_bandwidth_bytes{client, path_id}
tquic_client_connection_count{client}
tquic_path_degraded_total{client, path_id, reason}
```

### Connection Logging (monitor/logger.go)
- Dual output: syslog + JSON file (`/var/log/tquic/connections.log`)
- Structured log entries with timestamp, client, source, dest, bytes, duration, traffic class
- Ring buffer for 100 most recent connections (dashboard access)
- Per-client filtering for log queries

### Path Alerting (monitor/alerter.go)
- Threshold-based detection: loss >5%, RTT >500ms, jitter >100ms
- Alert state tracking to avoid repeated alerts
- Recovery logging when paths return to healthy
- Syslog integration for alerts

### Web Dashboard (api/dashboard.go)
- Single HTML page with inline CSS/JS (no external dependencies)
- Auto-refresh every 5 seconds via fetch API
- Color-coded path health: green (healthy), yellow (degraded), red (failed)
- Displays per-client and per-path statistics
- Recent connections table with last 20 entries

### API Endpoints
- `GET /metrics` - Prometheus metrics (port 9100)
- `GET /` - Dashboard HTML (port 8080, localhost only)
- `GET /api/stats` - JSON path and client statistics
- `GET /api/connections/recent` - Last 100 connection events
- `GET/POST/DELETE /api/blocklist` - Runtime blocklist management

### QoS Setup (qos/htb.go)
- HTB qdisc creation via `tc` command execution
- 4 traffic classes: realtime, interactive, bulk, background
- DSCP-based classification: EF, AF41, BE, CS1
- Per-client bandwidth limits with `SetClientBandwidth()`
- SFQ leaf qdisc for fairness within classes

## Commits

| Hash | Description |
|------|-------------|
| ced300d8e | feat(08-03): add tquicd daemon core and configuration loader |
| 49a9f2cee | feat(08-03): add netlink client, Prometheus metrics, and connection logging |
| 3b14bf939 | feat(08-03): add HTTP APIs for Prometheus, dashboard, blocklist, and QoS |

## Deviations from Plan

None - plan executed exactly as written.

## Key Implementation Details

### Genetlink Integration
Uses `github.com/mdlayher/genetlink` for type-safe netlink communication. Client gracefully degrades if kernel module isn't loaded (returns errors but doesn't crash).

### Connection Event Flow
```
Kernel TQUIC module
    |
    v (netlink multicast)
Client.SubscribeConnectionEvents()
    |
    v
ConnectionLogger.LogConnection()
    |
    +--> syslog (structured text)
    +--> JSON file (machine-readable)
    +--> ring buffer (dashboard access)
```

### Config Hot Reload
```
SIGHUP received
    |
    v
configLoader.Load()
    |
    v
onConfigChange(cfg)
    |
    +--> RegisterClient() for each client
    +--> SetupHTB() for QoS
    +--> SetClientBandwidth() for limits
```

## Testing Verification

- [x] main.go has 475 lines (exceeds 100 minimum)
- [x] `type Config struct` present in config/config.go
- [x] `ConnLogFile` field in GlobalConfig
- [x] `prometheus.NewCounterVec` in collector.go
- [x] `TQUIC_EVENT_CONN_*` constants in events.go
- [x] `ConnectionLogEntry` struct in logger.go
- [x] `/api/stats` and `/api/connections/recent` endpoints
- [x] POST/DELETE /api/blocklist handlers
- [x] `tc qdisc` commands in htb.go

## Next Phase Readiness

**Phase 09 (Tooling):** tquicd provides foundation for:
- CLI tools can query `/api/stats` for path information
- Prometheus metrics enable Grafana dashboards
- Connection logs enable traffic analysis
- Blocklist API enables firewall integration

**Blockers:** None

## Files Created

```
tools/tquic/tquicd/
├── main.go                    # 475 lines - daemon entry point
├── go.mod                     # Go module definition
├── config/
│   ├── config.go              # Configuration types
│   └── loader.go              # INI parser and hot reload
├── netlink/
│   ├── types.go               # PathStats, ConnectionEvent, etc.
│   ├── client.go              # Genetlink client
│   └── events.go              # Event subscription
├── monitor/
│   ├── collector.go           # Prometheus metrics
│   ├── alerter.go             # Path degradation alerts
│   └── logger.go              # Connection logging
├── api/
│   ├── prometheus.go          # /metrics endpoint
│   ├── dashboard.go           # Web dashboard + /api/stats
│   └── blocklist.go           # Blocklist API
└── qos/
    └── htb.go                 # TC HTB setup
```
