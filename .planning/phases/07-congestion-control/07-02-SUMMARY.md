# Phase 7 Plan 2: Per-Netns CC Configuration Summary

---
phase: "07-congestion-control"
plan: "02"
subsystem: "cc-configuration"
tags: ["congestion-control", "sysctl", "sockopt", "bbr", "per-netns"]

dependency-graph:
  requires: ["07-01"]
  provides: ["per-netns-cc-config", "so-tquic-congestion", "bbr-auto-selection"]
  affects: ["07-03", "07-04"]

tech-stack:
  added: []
  patterns: ["per-netns-sysctl-handlers", "rtt-based-auto-selection", "sockopt-cc-preference"]

key-files:
  created: []
  modified:
    - include/net/netns/tquic.h
    - net/tquic/tquic_sysctl.c
    - net/tquic/tquic_socket.c
    - include/uapi/linux/tquic.h
    - include/net/tquic.h
    - net/tquic/cong/tquic_cong.c
    - net/tquic/cong/tquic_cong.h

decisions:
  - id: "bbr-rtt-threshold-100ms"
    choice: "100ms default threshold for BBR auto-selection"
    rationale: "Reasonable boundary between LAN and WAN paths"
  - id: "auto-cc-keyword"
    choice: "'auto' as special sockopt value for RTT-based selection"
    rationale: "Clear semantic for enabling automatic per-path CC selection"
  - id: "cc-preference-not-locked"
    choice: "CC preference can be set on established connections"
    rationale: "Unlike scheduler, CC affects new paths only, not existing ones"

metrics:
  duration: "~5 minutes"
  completed: "2026-02-01"
  tasks: 3/3
---

## One-Liner

Per-netns CC sysctl (net.tquic.cc_algorithm), SO_TQUIC_CONGESTION sockopt, BBR auto-selection for paths with RTT >= 100ms threshold.

## What Was Built

### Task 1: Per-netns CC Configuration in netns Structure

Extended `struct netns_tquic` with congestion control configuration:
- `default_cong __rcu *` - RCU-protected pointer to default CC algorithm
- `cc_name[16]` - Buffer for sysctl CC algorithm name
- `bbr_rtt_threshold_ms` - RTT threshold for BBR auto-selection (default 100ms)
- `coupled_enabled` - Enable coupled CC for multipath fairness
- `ecn_enabled` - Enable ECN for congestion signals (default off)

Added CC framework functions:
- `tquic_cong_set_default()` - Set per-netns default CC
- `tquic_cong_get_default()` - Get per-netns default CC ops
- `tquic_cong_get_default_name()` - Get per-netns default CC name
- `tquic_cong_select_for_rtt()` - RTT-based algorithm selection
- `tquic_cong_is_bbr_preferred()` - Check if BBR should be used

### Task 2: Per-netns CC Sysctl Entries

Added sysctl handlers and entries:
- `net.tquic.cc_algorithm` - Set default CC algorithm for namespace
- `net.tquic.bbr_rtt_threshold_ms` - RTT threshold for BBR auto-selection
- `net.tquic.cc_coupled` - Enable/disable coupled CC
- `net.tquic.ecn_enabled` - Enable/disable ECN support

Added accessor functions:
- `tquic_net_get_cc_algorithm()`
- `tquic_net_get_bbr_rtt_threshold()`
- `tquic_net_get_cc_coupled()`
- `tquic_net_get_ecn_enabled()`

### Task 3: SO_TQUIC_CONGESTION Sockopt and BBR Auto-Selection

Added UAPI sockopt documentation for `SO_TQUIC_CONGESTION`.

Extended `struct tquic_sock`:
- `requested_congestion[16]` - CC preference before connect

Added sockopt handlers:
- `setsockopt(TQUIC_CONGESTION)` - Set CC preference (including "auto")
- `getsockopt(TQUIC_CONGESTION)` - Get current CC preference

Added RTT-based initialization function:
- `tquic_cong_init_path_with_rtt()` - Initialize path CC with auto-selection

## Commits

| Hash | Message |
|------|---------|
| 3578658db | feat(07-02): add per-netns CC configuration to netns structure |
| da3b0f24f | feat(07-02): add per-netns CC sysctl and BBR auto-selection sysctl |
| 2841af585 | feat(07-02): add SO_TQUIC_CONGESTION sockopt and BBR auto-selection |

## Decisions Made

### BBR RTT Threshold (100ms)
- **Decision:** Default BBR auto-selection threshold is 100ms
- **Rationale:** LAN paths typically have RTT < 10ms, WAN paths > 50ms. 100ms clearly identifies high-latency paths (satellite, intercontinental) that benefit from BBR's bandwidth probing
- **Configurable:** Via `net.tquic.bbr_rtt_threshold_ms` sysctl

### Auto-Selection Keyword
- **Decision:** Use "auto" as special sockopt value
- **Rationale:** Clear semantic distinction from algorithm names; enables per-path automatic selection based on RTT

### CC Preference Not Locked at Connection Establishment
- **Decision:** Unlike scheduler, CC preference can be changed on established connections
- **Rationale:** CC preference only affects newly created paths, not existing ones. Scheduler affects packet routing immediately, requiring connection-level lock

## Deviations from Plan

None - plan executed exactly as written.

## Key Patterns Established

### Per-netns Sysctl Handler Pattern
```c
static int proc_tquic_cc_algorithm(struct ctl_table *table, int write,
                                   void *buffer, size_t *lenp, loff_t *ppos)
{
    struct net *net = current->nsproxy->net_ns;
    // Read: get from netns, Write: validate and set to netns
}
```

### RTT-Based Auto-Selection Pattern
```c
const char *tquic_cong_select_for_rtt(struct net *net, u64 rtt_us)
{
    if (net && net->tquic.bbr_rtt_threshold_ms > 0 &&
        tquic_cong_is_bbr_preferred(net, rtt_us)) {
        return "bbr";
    }
    return tquic_cong_get_default_name(net);
}
```

## Next Phase Readiness

Phase 07-03 (Coupled CC) can proceed:
- Per-netns `coupled_enabled` flag available
- CC framework extended with coupling stubs in header
- Path lifecycle hooks ready for coupled CC integration

## Files Changed

| File | Changes |
|------|---------|
| include/net/netns/tquic.h | Added CC fields to netns_tquic struct |
| net/tquic/cong/tquic_cong.c | Added per-netns CC functions and RTT-based init |
| net/tquic/cong/tquic_cong.h | Added function declarations for per-netns CC |
| net/tquic/tquic_sysctl.c | Added CC sysctl handlers and entries |
| net/tquic/tquic_socket.c | Added TQUIC_CONGESTION sockopt handlers |
| include/uapi/linux/tquic.h | Added SO_TQUIC_CONGESTION documentation |
| include/net/tquic.h | Added requested_congestion to tquic_sock |

## Verification

All success criteria met:
- [x] net.tquic.cc_algorithm sysctl changes default CC for namespace
- [x] net.tquic.bbr_rtt_threshold_ms configures BBR auto-selection (default 100ms)
- [x] SO_TQUIC_CONGESTION sockopt sets CC before connect
- [x] tquic_cong_init_path_with_rtt() supports RTT-based BBR selection
- [x] net.tquic.cc_coupled controls coupled CC default
- [x] net.tquic.ecn_enabled controls ECN (default off)
