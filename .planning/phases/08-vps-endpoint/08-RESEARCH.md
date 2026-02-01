# Phase 8: VPS Aggregation Endpoint - Research

**Researched:** 2026-01-31
**Domain:** VPS server-side TQUIC implementation, traffic forwarding, monitoring
**Confidence:** HIGH

## Summary

This phase implements the server-side VPS endpoint for TQUIC WAN bonding. The existing kernel TQUIC implementation (Phases 1-7) provides a robust foundation with full socket API, multi-path support, PSK authentication in the TLS handshake, path monitoring via /proc and netlink, and congestion control with pacing. Phase 8 builds upon this by adding:

1. **Server-side connection acceptance** with PSK authentication for multi-tenant isolation
2. **Traffic forwarding** using kernel TCP termination with zero-copy splice/sendfile and NAT masquerade
3. **Path monitoring** with Prometheus metrics export and web dashboard
4. **Deployment packaging** as a Debian .deb with systemd integration

The architecture uses a hybrid approach: kernel data path for high-performance packet forwarding (leveraging existing TQUIC proto handlers), and a userspace control daemon (Go) for configuration, monitoring APIs, and Prometheus/dashboard endpoints.

**Primary recommendation:** Leverage existing kernel TQUIC implementation for connection handling; implement userspace `tquicd` daemon in Go for config management, Prometheus metrics, and web dashboard.

## Standard Stack

The established components for this domain:

### Core - Kernel Data Path
| Component | Location | Purpose | Why Standard |
|-----------|----------|---------|--------------|
| TQUIC proto handler | net/tquic/tquic_proto.c | Accept incoming connections | Already handles listen/accept |
| PSK handshake | net/tquic/crypto/handshake.c | Router authentication | TLS 1.3 PSK already implemented |
| Netlink API | net/tquic/tquic_netlink.c | Path/connection config | Generic netlink already working |
| splice/sendfile | kernel built-in | Zero-copy TCP forward | Standard Linux zero-copy mechanism |
| nftables NAT | netfilter | Masquerade outbound | Standard kernel NAT framework |

### Core - Userspace Control Daemon
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Go | 1.22+ | Daemon implementation | Static binaries, good netlink support |
| github.com/vishvananda/netlink | latest | Netlink communication | De facto Go netlink library |
| github.com/prometheus/client_golang | v1.19+ | Prometheus metrics | Official Prometheus Go client |
| net/http | stdlib | Dashboard/metrics HTTP | Go stdlib for simple HTTP |

### Supporting
| Library/Tool | Version | Purpose | When to Use |
|--------------|---------|---------|-------------|
| tc (iproute2) | system | HTB qdisc QoS setup | Traffic class configuration |
| nftables | system | NAT masquerade rules | Outbound traffic handling |
| systemd | system | Service management | Process lifecycle |
| logrotate | system | Log rotation | Dedicated log file rotation |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Go daemon | Rust daemon | Rust has better performance but Go has simpler netlink libraries |
| nftables | iptables | iptables works but nftables is modern standard |
| Prometheus | StatsD | Prometheus is pull-based, better for this use case |

**Installation (userspace):**
```bash
# Daemon build dependencies
go mod init github.com/linux/tquicd
go get github.com/vishvananda/netlink
go get github.com/prometheus/client_golang/prometheus
go get github.com/prometheus/client_golang/prometheus/promhttp

# System dependencies (runtime)
apt install iproute2 nftables
```

## Architecture Patterns

### Recommended Project Structure
```
tools/tquic/
├── tquicd/               # Userspace daemon
│   ├── main.go           # Entry point, signal handling
│   ├── config/           # Configuration parsing
│   │   ├── config.go     # Config types
│   │   └── loader.go     # /etc/tquic.d/*.conf loader
│   ├── netlink/          # Kernel communication
│   │   ├── client.go     # Netlink client wrapper
│   │   └── types.go      # Netlink message types
│   ├── forward/          # Traffic forwarding logic
│   │   ├── nat.go        # NAT/masquerade setup
│   │   └── tunnel.go     # TCP tunnel termination
│   ├── monitor/          # Metrics collection
│   │   ├── collector.go  # Path stats collector
│   │   └── alerter.go    # Degradation alerts
│   ├── api/              # HTTP APIs
│   │   ├── prometheus.go # /metrics endpoint
│   │   ├── dashboard.go  # Web dashboard
│   │   └── blocklist.go  # Runtime blocklist API
│   └── qos/              # QoS management
│       └── htb.go        # tc HTB setup
├── debian/               # Package files
│   ├── control           # Package metadata
│   ├── rules             # Build rules
│   ├── tquicd.service    # systemd unit
│   └── postinst          # Post-install script
└── web/                  # Dashboard static files
    └── index.html        # Single-page dashboard
```

### Pattern 1: Kernel Data Path + Userspace Control Plane
**What:** Kernel handles all data-plane operations (connection handling, packet forwarding), userspace handles control-plane (config, monitoring, API)
**When to use:** High-performance networking with complex management requirements
**Example:**
```c
// Kernel: tquic_proto.c already handles server accept
static int tquic_v4_rcv(struct sk_buff *skb)
{
    // CID lookup finds connection
    conn = tquic_conn_lookup_by_cid(&dcid);
    if (conn) {
        tquic_udp_deliver_to_conn(conn, conn->active_path, skb);
    }
}

// Userspace daemon queries stats via netlink
// and exposes them via Prometheus
```

### Pattern 2: PSK Multi-Tenant Isolation
**What:** Use TLS 1.3 PSK identity to isolate router clients; each PSK maps to a client
**When to use:** Multiple home routers connecting to single VPS
**Example:**
```go
// Config: /etc/tquic.d/clients.conf
// [client_home1]
// psk = base64_encoded_key
// port_range = 10000-10999
// bandwidth_limit = 100mbit

type ClientConfig struct {
    Name           string
    PSK            []byte
    PortRangeStart uint16
    PortRangeEnd   uint16
    BandwidthLimit string
}
```

### Pattern 3: Zero-Copy TCP Forwarding with splice()
**What:** Use splice() to forward TCP data between QUIC tunnel and outbound TCP without copying to userspace
**When to use:** High-throughput traffic forwarding
**Example:**
```c
// Source: kernel.org/doc/html/latest/networking/msg_zerocopy.html
// Kernel-side forwarding using pipe + splice
int forward_tcp(int tquic_stream_fd, int tcp_sock_fd) {
    int pipefd[2];
    pipe(pipefd);

    // Zero-copy from QUIC stream to pipe
    ssize_t n = splice(tquic_stream_fd, NULL, pipefd[1], NULL,
                       PIPE_SIZE, SPLICE_F_MOVE);

    // Zero-copy from pipe to TCP socket
    splice(pipefd[0], NULL, tcp_sock_fd, NULL, n, SPLICE_F_MOVE);
}
```

### Pattern 4: HTB QoS with Traffic Classes
**What:** Use HTB qdisc with 4 classes for QoS prioritization
**When to use:** VPS-side QoS classification
**Example:**
```bash
# Source: man7.org/linux/man-pages/man8/tc-htb.8.html
# Create HTB qdisc with 4 traffic classes
tc qdisc add dev eth0 root handle 1: htb default 40

# Root class (total bandwidth)
tc class add dev eth0 parent 1: classid 1:1 htb rate 1000mbit

# Real-time (VoIP/video) - highest priority
tc class add dev eth0 parent 1:1 classid 1:10 htb rate 100mbit ceil 1000mbit prio 0

# Interactive (gaming)
tc class add dev eth0 parent 1:1 classid 1:20 htb rate 200mbit ceil 1000mbit prio 1

# Bulk (downloads)
tc class add dev eth0 parent 1:1 classid 1:30 htb rate 500mbit ceil 1000mbit prio 2

# Background
tc class add dev eth0 parent 1:1 classid 1:40 htb rate 200mbit ceil 1000mbit prio 3

# SFQ for fair queuing within classes
tc qdisc add dev eth0 parent 1:10 handle 10: sfq perturb 10
tc qdisc add dev eth0 parent 1:20 handle 20: sfq perturb 10
tc qdisc add dev eth0 parent 1:30 handle 30: sfq perturb 10
tc qdisc add dev eth0 parent 1:40 handle 40: sfq perturb 10
```

### Pattern 5: Prometheus Metric Naming
**What:** Follow Prometheus naming conventions for TQUIC metrics
**When to use:** All exposed metrics
**Example:**
```go
// Source: prometheus.io/docs/practices/naming/
var (
    pathBytesTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: "tquic",
            Subsystem: "path",
            Name:      "bytes_total",
            Help:      "Total bytes transmitted per path",
        },
        []string{"client", "path_id", "direction"},
    )

    pathRttSeconds = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Namespace: "tquic",
            Subsystem: "path",
            Name:      "rtt_seconds",
            Help:      "Current smoothed RTT in seconds",
        },
        []string{"client", "path_id"},
    )

    pathLossRatio = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Namespace: "tquic",
            Subsystem: "path",
            Name:      "loss_ratio",
            Help:      "Packet loss ratio (0.0-1.0)",
        },
        []string{"client", "path_id"},
    )
)
```

### Anti-Patterns to Avoid
- **Hand-rolling NAT:** Use nftables masquerade, not custom NAT code
- **Userspace data path:** Keep packet forwarding in kernel; userspace is too slow
- **Blocking netlink calls:** Use non-blocking netlink with epoll in Go
- **Unbounded port allocation:** Track port ranges per client to prevent exhaustion
- **Shared PSK:** Each client MUST have unique PSK for isolation

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| NAT masquerade | Custom NAT translation | nftables masquerade | Connection tracking is complex |
| TCP termination | Custom TCP stack | Kernel TCP + splice | TCP has many edge cases |
| QoS scheduling | Custom scheduler | tc HTB qdisc | HTB is mature, well-tested |
| Metrics export | Custom HTTP scraper | prometheus/client_golang | Standard format, tooling |
| Log rotation | Custom rotation | logrotate | System-standard, cron-integrated |
| Service management | Custom daemonization | systemd | Restart, logging, dependencies |
| Package management | Custom installer | dpkg/apt .deb | Standard Debian workflow |
| TLS PSK validation | Custom PSK matching | Existing crypto/handshake.c | Already implemented correctly |

**Key insight:** The kernel TQUIC implementation already handles the hard parts (QUIC protocol, multi-path, congestion control). Phase 8 is primarily integration and plumbing, not protocol implementation.

## Common Pitfalls

### Pitfall 1: Blocking Netlink Calls
**What goes wrong:** Netlink recv() blocks the main loop, causing metrics lag
**Why it happens:** Default Go netlink is synchronous
**How to avoid:** Use goroutine per netlink subscription, or use netlink.Subscribe with channels
**Warning signs:** Metrics update slower than 5-second interval

### Pitfall 2: Port Range Exhaustion
**What goes wrong:** Client port range fills up, new connections fail
**Why it happens:** No tracking of port allocation per client
**How to avoid:** Implement port allocator with bitmap per client, reclaim on TCP close
**Warning signs:** EADDRINUSE errors in logs

### Pitfall 3: Connection Tracking Table Overflow
**What goes wrong:** nftables conntrack table fills, new connections dropped
**Why it happens:** Default conntrack table size is too small for many tunneled connections
**How to avoid:** Tune /proc/sys/net/netfilter/nf_conntrack_max (at least 2x expected connections)
**Warning signs:** "nf_conntrack: table full" in dmesg

### Pitfall 4: GRO/GSO Not Enabled
**What goes wrong:** CPU bottleneck at high throughput
**Why it happens:** GRO/GSO disabled by default on some interfaces
**How to avoid:** Enable in postinst: `ethtool -K eth0 gro on gso on`
**Warning signs:** High softirq CPU, low throughput despite bandwidth

### Pitfall 5: Missing TCP Fast Open Sysctl
**What goes wrong:** Each outbound TCP adds 1 RTT latency
**Why it happens:** TFO disabled by default
**How to avoid:** Set `net.ipv4.tcp_fastopen = 3` in postinst
**Warning signs:** Slow initial connection time for tunneled TCP

### Pitfall 6: Dashboard CORS Issues
**What goes wrong:** Browser blocks dashboard requests
**Why it happens:** Dashboard served from localhost, metrics from different origin
**How to avoid:** Serve dashboard and metrics from same port, or proper CORS headers
**Warning signs:** Browser console shows CORS errors

### Pitfall 7: Session State TTL Too Short
**What goes wrong:** Router reconnects lose forwarded connections
**Why it happens:** TTL expires during brief network outage
**How to avoid:** Default TTL should be 60-120 seconds, configurable
**Warning signs:** Connections dropped on brief router disconnects

## Code Examples

Verified patterns from official sources:

### Prometheus Metrics Registration
```go
// Source: pkg.go.dev/github.com/prometheus/client_golang/prometheus
package monitor

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "net/http"
)

func init() {
    prometheus.MustRegister(
        tquic_connections_total,
        tquic_path_bytes_total,
        tquic_path_rtt_seconds,
        tquic_path_loss_ratio,
        tquic_path_bandwidth_bytes,
        tquic_path_jitter_seconds,
    )
}

var (
    tquic_connections_total = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: "tquic",
            Name:      "connections_total",
            Help:      "Total number of TQUIC connections",
        },
        []string{"client"},
    )

    tquic_path_bytes_total = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: "tquic",
            Subsystem: "path",
            Name:      "bytes_total",
            Help:      "Total bytes per path",
        },
        []string{"client", "path_id", "direction"},
    )

    tquic_path_rtt_seconds = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Namespace: "tquic",
            Subsystem: "path",
            Name:      "rtt_seconds",
            Help:      "Smoothed RTT in seconds",
        },
        []string{"client", "path_id"},
    )

    tquic_path_loss_ratio = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Namespace: "tquic",
            Subsystem: "path",
            Name:      "loss_ratio",
            Help:      "Packet loss ratio",
        },
        []string{"client", "path_id"},
    )

    tquic_path_bandwidth_bytes = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Namespace: "tquic",
            Subsystem: "path",
            Name:      "bandwidth_bytes",
            Help:      "Estimated bandwidth in bytes per second",
        },
        []string{"client", "path_id"},
    )

    tquic_path_jitter_seconds = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Namespace: "tquic",
            Subsystem: "path",
            Name:      "jitter_seconds",
            Help:      "RTT variance (jitter) in seconds",
        },
        []string{"client", "path_id"},
    )
)

func ServeMetrics(addr string) {
    http.Handle("/metrics", promhttp.Handler())
    http.ListenAndServe(addr, nil)
}
```

### nftables NAT Masquerade Setup
```bash
# Source: wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)
#!/bin/bash
# /etc/tquic.d/nft-setup.sh

nft add table inet tquic
nft add chain inet tquic postrouting { type nat hook postrouting priority srcnat \; }
nft add rule inet tquic postrouting oifname "eth0" masquerade

# Per-client port range marking (for QoS)
# Client 1: ports 10000-10999
nft add rule inet tquic postrouting tcp sport 10000-10999 meta mark set 0x1
# Client 2: ports 11000-11999
nft add rule inet tquic postrouting tcp sport 11000-11999 meta mark set 0x2
```

### systemd Service File
```ini
# Source: manpages.debian.org/testing/debhelper/dh_installsystemd.1.en.html
# debian/tquicd.service
[Unit]
Description=TQUIC VPS Aggregation Daemon
Documentation=man:tquicd(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/tquicd
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/tquic /run/tquicd

# Capability for network operations
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

### Debian postinst Script
```bash
#!/bin/bash
# Source: wiki.debian.org/Teams/pkg-systemd/Packaging
# debian/postinst

set -e

case "$1" in
    configure)
        # Create config directory
        mkdir -p /etc/tquic.d

        # Set kernel parameters for high-performance networking
        cat > /etc/sysctl.d/90-tquic.conf << 'EOF'
# TQUIC VPS tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_fastopen = 3
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
EOF
        sysctl -p /etc/sysctl.d/90-tquic.conf || true

        # Enable GRO/GSO on primary interface
        PRIMARY_IF=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
        if [ -n "$PRIMARY_IF" ]; then
            ethtool -K "$PRIMARY_IF" gro on gso on 2>/dev/null || true
        fi

        # Create log directory
        mkdir -p /var/log/tquic

        # Enable and start service
        systemctl daemon-reload
        deb-systemd-invoke enable tquicd.service
        deb-systemd-invoke start tquicd.service
        ;;
esac

#DEBHELPER#
```

### Config File Parser
```go
// /etc/tquic.d/tquicd.conf format
/*
[global]
listen_port = 443
metrics_port = 9100
dashboard_port = 8080
log_file = /var/log/tquic/tquicd.log
session_ttl = 120

[client.home1]
psk = base64_key_here
port_range = 10000-10999
bandwidth_limit = 100mbit
traffic_classes = realtime:10,interactive:20,bulk:50,background:20

[client.home2]
psk = base64_key_here2
port_range = 11000-11999
bandwidth_limit = 50mbit

[blocklist]
file = /etc/tquic.d/blocklist.txt
*/

package config

import (
    "bufio"
    "encoding/base64"
    "os"
    "path/filepath"
    "strings"
)

type Config struct {
    Global    GlobalConfig
    Clients   map[string]ClientConfig
    Blocklist BlocklistConfig
}

type GlobalConfig struct {
    ListenPort    int
    MetricsPort   int
    DashboardPort int
    LogFile       string
    SessionTTL    int  // seconds
}

type ClientConfig struct {
    Name           string
    PSK            []byte
    PortRangeStart uint16
    PortRangeEnd   uint16
    BandwidthLimit string
    TrafficClasses map[string]int  // class -> percentage
}

func LoadConfigDir(dir string) (*Config, error) {
    // Load all .conf files from /etc/tquic.d/
    files, err := filepath.Glob(filepath.Join(dir, "*.conf"))
    if err != nil {
        return nil, err
    }

    cfg := &Config{
        Clients: make(map[string]ClientConfig),
    }

    for _, f := range files {
        if err := parseConfigFile(f, cfg); err != nil {
            return nil, err
        }
    }

    return cfg, nil
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| iptables NAT | nftables NAT | Linux 3.13+ (2014), matured 5.x | Better performance, unified syntax |
| sendfile only | splice + MSG_ZEROCOPY | Linux 4.14+ (2017) | True zero-copy for sockets |
| PFIFO qdisc | fq/fq_codel with HTB | Linux 3.5+ (2012) | Better latency under load |
| init scripts | systemd units | Ubuntu 16.04+ | Reliable restart, cgroups |
| Custom metrics | Prometheus OpenMetrics | ~2016 | Standard tooling ecosystem |

**Deprecated/outdated:**
- iptables: Still works but nftables is preferred for new code
- sendfile without splice: splice is more flexible for socket-to-socket
- /etc/init.d scripts: systemd is standard on all target distros

## Open Questions

Things that couldn't be fully resolved:

1. **HTTP/3 Connection Coalescing (Claude's Discretion)**
   - What we know: QUIC supports multiple streams over single connection
   - What's unclear: Optimal coalescing strategy for tunneled HTTP/3
   - Recommendation: Start with no coalescing (separate tunnel per destination), add optimization later

2. **Exact Port Range Algorithm (Claude's Discretion)**
   - What we know: Need 1000 ports per client, dynamic allocation
   - What's unclear: Best allocation strategy (contiguous vs scattered)
   - Recommendation: Use contiguous ranges for simpler nftables rules; start at 10000, increment by 1000 per client

3. **Dashboard Implementation (Claude's Discretion)**
   - What we know: Simple localhost-only dashboard for quick checks
   - What's unclear: Best minimal UI framework
   - Recommendation: Single HTML file with inline CSS/JS, fetch /metrics API, no external dependencies

4. **Path Degradation Alert Thresholds**
   - What we know: Need alerts for loss > X%, RTT > Y ms
   - What's unclear: What thresholds are appropriate
   - Recommendation: Default loss > 5%, RTT > 500ms; make configurable

## Sources

### Primary (HIGH confidence)
- Existing kernel TQUIC code (net/tquic/*.c) - PSK support, netlink API, proc interface
- [Linux kernel TPROXY documentation](https://docs.kernel.org/networking/tproxy.html) - TPROXY transparent proxy
- [Prometheus metric naming](https://prometheus.io/docs/practices/naming/) - Metric conventions
- [splice(2) man page](https://man7.org/linux/man-pages/man2/splice.2.html) - Zero-copy forwarding
- [tc-htb(8) man page](https://www.man7.org/linux/man-pages/man8/tc-htb.8.html) - HTB QoS configuration
- [nftables NAT wiki](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)) - NAT masquerade setup
- [dh_installsystemd man page](https://manpages.debian.org/testing/debhelper/dh_installsystemd.1.en.html) - Debian systemd packaging

### Secondary (MEDIUM confidence)
- [Cloudflare SOCKMAP article](https://blog.cloudflare.com/sockmap-tcp-splicing-of-the-future/) - Zero-copy patterns
- [Zero-copy networking LWN](https://lwn.net/Articles/726917/) - MSG_ZEROCOPY background
- [RFC 9001 QUIC/TLS](https://quicwg.org/base-drafts/rfc9001.html) - PSK authentication in QUIC
- [Prometheus Go client](https://pkg.go.dev/github.com/prometheus/client_golang/prometheus) - Go library API

### Tertiary (LOW confidence)
- Community patterns for tc QoS configuration (require validation with actual deployment)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Based on existing kernel code and official kernel/Prometheus documentation
- Architecture: HIGH - Patterns derived from existing TQUIC implementation and standard Linux networking
- Pitfalls: MEDIUM - Some based on general networking experience, would benefit from validation

**Research date:** 2026-01-31
**Valid until:** 90 days (stable kernel APIs, stable Prometheus conventions)
