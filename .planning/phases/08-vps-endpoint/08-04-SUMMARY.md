---
phase: 08-vps-endpoint
plan: 04
subsystem: packaging
tags: [debian, deb, systemd, nftables, tproxy, sysctl]
dependency-graph:
  requires: ["08-03"]
  provides: ["debian-package", "systemd-service", "tproxy-setup", "kernel-tuning"]
  affects: ["09-tooling"]
tech-stack:
  added:
    - debhelper-compat (= 13)
    - dpkg-buildpackage
  patterns:
    - debian-package-structure
    - systemd-service-hardening
    - nftables-tproxy
    - sysctl-tuning
key-files:
  created:
    - tools/tquic/debian/control
    - tools/tquic/debian/changelog
    - tools/tquic/debian/compat
    - tools/tquic/debian/rules
    - tools/tquic/debian/conffiles
    - tools/tquic/debian/tquicd.service
    - tools/tquic/debian/postinst
    - tools/tquic/debian/postrm
    - tools/tquic/Makefile
    - tools/tquic/tquicd/example.conf
  modified: []
decisions:
  - id: debhelper-level-13
    choice: "debhelper-compat (= 13)"
    rationale: "Modern debhelper with systemd integration"
  - id: systemd-type-notify
    choice: "Type=notify for systemd service"
    rationale: "Daemon calls sd_notify for proper service ready state"
  - id: nftables-tproxy-tables
    choice: "Separate inet tquic (NAT) and ip tquic_tproxy (mangle) tables"
    rationale: "NAT for masquerade, mangle for TPROXY - clean separation"
  - id: fwmark-routing
    choice: "fwmark 1 lookup 100 with local 0.0.0.0/0 route"
    rationale: "Standard TPROXY packet routing pattern"
  - id: security-hardening
    choice: "NoNewPrivileges, ProtectSystem=strict, minimal capabilities"
    rationale: "Defense in depth for network daemon"
metrics:
  duration: "2 minutes"
  completed: 2026-02-01
---

# Phase 08 Plan 04: Debian Package Summary

Debian package (.deb) for tquicd with systemd service, kernel parameter tuning for high-performance networking, and TPROXY nftables rules for transparent proxying.

## Performance

- **Duration:** 2 min
- **Started:** 2026-02-01T03:28:39Z
- **Completed:** 2026-02-01T03:30:25Z
- **Tasks:** 3
- **Files modified:** 10

## Accomplishments
- Debian package structure with control, rules, changelog for dpkg-buildpackage
- systemd service with security hardening (NoNewPrivileges, ProtectSystem, minimal caps)
- postinst creates /etc/sysctl.d/90-tquic.conf with kernel tuning and enables TPROXY
- nftables tables for NAT masquerade and TPROXY transparent proxying
- Clean uninstall via postrm removes all config, nftables tables, and routing rules

## Task Commits

Each task was committed atomically:

1. **Task 1: Debian package structure and control files** - `ac34f0f` (feat)
2. **Task 2: systemd service and security hardening** - `555b8a6` (feat)
3. **Task 3: postinst script with kernel tuning and TPROXY rules** - `e106018` (feat)

## Files Created/Modified

### debian/ Directory
- `control` - Package metadata: Source: tquicd, Architecture: amd64, Depends: iproute2, nftables
- `changelog` - Initial release 1.0.0-1 with feature list
- `compat` - debhelper level 13
- `rules` - Makefile calling go build, install to /usr/bin/tquicd
- `conffiles` - Marks /etc/tquic.d/example.conf as config file
- `tquicd.service` - systemd unit with security hardening and capabilities
- `postinst` - Post-install: sysctl tuning, TPROXY nftables setup, GRO/GSO enable
- `postrm` - Post-remove: cleanup sysctl, nftables, routing rules

### Build System
- `tools/tquic/Makefile` - `make all`, `make deb`, `make clean` targets

### Configuration
- `tools/tquic/tquicd/example.conf` - Template config with TPROXY ports option

## Decisions Made

1. **debhelper level 13** - Modern debhelper with built-in systemd integration
2. **Type=notify** - Daemon uses sd_notify() for proper service ready signaling
3. **Separate nftables tables** - inet tquic for NAT, ip tquic_tproxy for mangle/TPROXY
4. **fwmark 1 lookup 100** - Standard TPROXY routing pattern with local route table
5. **Security hardening** - NoNewPrivileges, ProtectSystem=strict, PrivateTmp, minimal capabilities

## Deviations from Plan

None - plan executed exactly as written.

## Key Implementation Details

### systemd Service Hardening
```ini
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/tquic /run/tquicd /etc/tquic.d
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
```

### Kernel Tuning (/etc/sysctl.d/90-tquic.conf)
```
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_fastopen = 3
net.netfilter.nf_conntrack_max = 1048576
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
```

### TPROXY Setup Flow
```
postinst configure
    |
    +--> nft add table inet tquic (NAT)
    |    +--> chain postrouting masquerade
    |
    +--> nft add table ip tquic_tproxy (mangle)
    |    +--> chain prerouting priority mangle
    |
    +--> ip rule add fwmark 1 lookup 100
    +--> ip route add local 0.0.0.0/0 dev lo table 100
```

### Package Build
```bash
cd tools/tquic
make deb          # Runs dpkg-buildpackage -us -uc -b
# Creates ../tquicd_1.0.0-1_amd64.deb
```

### Deployment
```bash
sudo apt install ./tquicd_1.0.0-1_amd64.deb
# postinst runs automatically:
# - Creates /etc/sysctl.d/90-tquic.conf
# - Sets up nftables tables
# - Enables GRO/GSO
# - Starts tquicd.service
```

## Testing Verification

- [x] debian/control has "Package: tquicd"
- [x] debian/rules has dh_auto_build override
- [x] debian/changelog has version 1.0.0-1
- [x] tquicd.service has Type=notify
- [x] tquicd.service has CAP_NET_ADMIN
- [x] tquicd.service has ProtectSystem=strict
- [x] postinst creates 90-tquic.conf
- [x] postinst has ip_forward and route_localnet
- [x] postinst creates inet tquic table
- [x] postinst creates ip tquic_tproxy table
- [x] postinst adds fwmark routing rule
- [x] postrm cleans up tables and rules
- [x] Makefile has deb target

## Next Phase Readiness

**Phase 08 Complete:** VPS endpoint is fully deployable via apt install:
- Multi-tenant server with PSK authentication (08-01)
- TCP tunnel termination with zero-copy splice (08-02)
- tquicd daemon with Prometheus and dashboard (08-03)
- Debian package with systemd and TPROXY (08-04)

**Phase 09 (Tooling):** Ready for:
- CLI tools for client-side path management
- tquic_show for diagnostics output
- Configuration generators

**Blockers:** None

## Files Created

```
tools/tquic/
├── Makefile                   # make all/deb/clean
├── debian/
│   ├── control               # Package metadata
│   ├── changelog             # Version history
│   ├── compat                # debhelper level 13
│   ├── rules                 # Build rules
│   ├── conffiles             # Config file list
│   ├── tquicd.service        # systemd unit
│   ├── postinst              # Post-install script
│   └── postrm                # Post-remove script
└── tquicd/
    └── example.conf          # Template configuration
```
