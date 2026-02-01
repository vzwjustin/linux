# Phase 3: Diagnostics Integration - Research

**Researched:** 2026-01-31
**Domain:** Linux kernel socket diagnostics (inet_diag, SNMP MIB, /proc)
**Confidence:** HIGH

## Summary

This phase adds observability to TQUIC connections through three integrated subsystems: inet_diag (ss tool), proc filesystem, and SNMP-style MIB counters. Research of TCP, MPTCP, and TLS implementations reveals mature, well-documented patterns that TQUIC should follow.

The inet_diag infrastructure uses a handler registration model where protocol-specific handlers implement `dump`, `dump_one`, and `idiag_get_info` callbacks. The ss tool uses NETLINK_SOCK_DIAG to query these handlers via netlink. For proc interfaces, the kernel provides `proc_create_net_single()` for simple files and seq_file iterators for connection listings. MIB counters use per-CPU arrays with SNMP_INC_STATS macros for lock-free incrementing.

**Primary recommendation:** Implement `tquic_diag.c` following MPTCP's `mptcp_diag.c` pattern (simpler than TCP), create `tquic_mib.c/h` for counters, and extend existing proc entries in `tquic_proto.c` with proper connection iteration and statistics display.

## Standard Stack

The "standard stack" for kernel diagnostics is not external libraries but kernel subsystems:

### Core

| Subsystem | Location | Purpose | Why Standard |
|-----------|----------|---------|--------------|
| inet_diag | net/ipv4/inet_diag.c | ss tool socket diagnostics | Standard for all inet protocols |
| sock_diag | net/core/sock_diag.c | NETLINK_SOCK_DIAG interface | Kernel standard |
| SNMP MIB | include/net/snmp.h | Per-CPU counter infrastructure | Used by TCP, UDP, MPTCP |
| seq_file | include/linux/seq_file.h | /proc file iteration | Standard proc interface |
| proc_fs | include/linux/proc_fs.h | /proc file creation | Standard proc API |

### Supporting

| Subsystem | Location | Purpose | When to Use |
|-----------|----------|---------|-------------|
| netlink | include/net/netlink.h | Kernel-userspace messaging | For ss tool integration |
| percpu | include/linux/percpu.h | Per-CPU data allocation | For scalable counters |
| pernet_operations | include/net/net_namespace.h | Per-netns initialization | For namespace-aware stats |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| seq_file for /proc | single_open | seq_file better for large lists, single_open for small static output |
| SNMP MIB | atomic counters | MIB gives structured naming and integration with netstat/snmp |
| inet_diag | custom netlink | inet_diag gives ss integration for free |

## Architecture Patterns

### Recommended Project Structure

```
net/tquic/
├── tquic_diag.c        # inet_diag handler for ss tool
├── tquic_mib.h         # MIB counter enum and macros
├── tquic_mib.c         # Counter registration and proc output
└── tquic_proto.c       # Extended proc entries (connections, paths)
```

### Pattern 1: inet_diag Handler Registration

**What:** Protocol-specific handler that responds to ss queries
**When to use:** Any inet protocol that should be visible in `ss` output

```c
// Source: net/mptcp/mptcp_diag.c
static const struct inet_diag_handler tquic_diag_handler = {
    .owner           = THIS_MODULE,
    .dump            = tquic_diag_dump,      // List all connections
    .dump_one        = tquic_diag_dump_one,  // Single connection lookup
    .idiag_get_info  = tquic_diag_get_info,  // Fill protocol-specific info
    .idiag_get_aux   = tquic_diag_get_aux,   // Extended info (paths, streams)
    .idiag_type      = IPPROTO_TQUIC,        // Protocol number (263)
    .idiag_info_size = sizeof(struct tquic_info),
};

static int __init tquic_diag_init(void)
{
    return inet_diag_register(&tquic_diag_handler);
}
```

### Pattern 2: MIB Counter Definition

**What:** Per-CPU counters with symbolic names for statistics
**When to use:** Any countable events (packets, errors, state transitions)

```c
// Source: net/mptcp/mib.h
enum linux_tquic_mib_field {
    TQUIC_MIB_NUM = 0,
    TQUIC_MIB_HANDSHAKESCOMPLETE,    /* Successful handshakes */
    TQUIC_MIB_HANDSHAKESFAILED,       /* Failed handshakes */
    TQUIC_MIB_PACKETSRX,              /* Packets received */
    TQUIC_MIB_PACKETSTX,              /* Packets transmitted */
    TQUIC_MIB_BYTESRX,                /* Bytes received */
    TQUIC_MIB_BYTESTX,                /* Bytes transmitted */
    TQUIC_MIB_RETRANSMISSIONS,        /* Retransmitted packets */
    TQUIC_MIB_PATHMIGRATIONS,         /* Path migrations */
    TQUIC_MIB_PATHFAILURES,           /* Path failures */
    TQUIC_MIB_CONNTIMEDOUT,           /* Connection timeouts */
    TQUIC_MIB_CONNCLOSED,             /* Connections closed gracefully */
    TQUIC_MIB_CONNRESET,              /* Connection resets */
    TQUIC_MIB_RTTSAMPLES,             /* RTT measurements taken */
    TQUIC_MIB_LOSSEVENTS,             /* Loss detection events */
    TQUIC_MIB_CURRESTAB,              /* Currently established */
    /* Per-EQUIC error counters */
    TQUIC_MIB_EQUIC_FLOW_CONTROL,
    TQUIC_MIB_EQUIC_STREAM_LIMIT,
    TQUIC_MIB_EQUIC_PROTOCOL_VIOLATION,
    /* ... more EQUIC errors ... */
    __TQUIC_MIB_MAX
};

struct tquic_mib {
    unsigned long mibs[__TQUIC_MIB_MAX];
};

static inline void TQUIC_INC_STATS(struct net *net,
                                   enum linux_tquic_mib_field field)
{
    if (likely(net->mib.tquic_statistics))
        SNMP_INC_STATS(net->mib.tquic_statistics, field);
}
```

### Pattern 3: Proc Connection Listing with seq_file

**What:** Iterating hash tables to list connections
**When to use:** /proc/net/tquic connection listing

```c
// Source: net/ipv4/tcp_ipv4.c get_tcp4_sock()
static void tquic_conn_seq_show(struct seq_file *f, struct tquic_connection *conn)
{
    struct tquic_sock *tsk = tquic_sk(conn->sk);
    char scid_hex[TQUIC_MAX_CID_LEN * 2 + 1];

    /* Format: sl local_address:port rem_address:port state paths streams ... */
    bin2hex(scid_hex, conn->scid.id, conn->scid.len);

    seq_printf(f, "%4d: %08X:%04X %08X:%04X %s %d %d %llu %llu\n",
        seq_num,
        local_addr, local_port,
        remote_addr, remote_port,
        tquic_state_name(conn->state),  /* CONNECTED (ESTABLISHED) */
        conn->num_paths,
        rb_entry_count(&conn->streams),
        conn->stats.tx_bytes,
        conn->stats.rx_bytes);
}
```

### Pattern 4: Extended ss Info via Netlink Attributes

**What:** Additional protocol info in `ss -i` output
**When to use:** RTT, congestion, per-path details

```c
// Source: net/mptcp/diag.c subflow_get_info()
static int tquic_diag_get_aux(struct sock *sk, bool net_admin,
                              struct sk_buff *skb)
{
    struct tquic_sock *tsk = tquic_sk(sk);
    struct tquic_connection *conn = tsk->conn;
    struct tquic_path *path;
    struct nlattr *nest;

    /* Connection-level info */
    if (nla_put_u32(skb, TQUIC_DIAG_ATTR_VERSION, conn->version))
        return -EMSGSIZE;
    if (nla_put(skb, TQUIC_DIAG_ATTR_SCID, conn->scid.len, conn->scid.id))
        return -EMSGSIZE;

    /* Per-path info */
    nest = nla_nest_start(skb, TQUIC_DIAG_ATTR_PATHS);
    list_for_each_entry(path, &conn->paths, list) {
        /* path_id, state, rtt, cwnd, bytes_tx, bytes_rx */
        nla_put_u32(skb, TQUIC_DIAG_PATH_ID, path->path_id);
        nla_put_u8(skb, TQUIC_DIAG_PATH_STATE, path->state);
        nla_put_u32(skb, TQUIC_DIAG_PATH_RTT, path->stats.rtt_smoothed);
        /* ... */
    }
    nla_nest_end(skb, nest);

    return 0;
}
```

### Pattern 5: Error Ring Buffer

**What:** Circular buffer for detailed error context
**When to use:** Debugging without dmesg flooding

```c
// Kernel pattern from tracing infrastructure
struct tquic_error_entry {
    ktime_t timestamp;
    u32 error_code;
    u8 scid[TQUIC_MAX_CID_LEN];
    u8 scid_len;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    u32 path_id;
    u32 related_counter;  /* MIB counter at time of error */
    char message[64];
};

#define TQUIC_ERROR_RING_SIZE 256

struct tquic_error_ring {
    struct tquic_error_entry entries[TQUIC_ERROR_RING_SIZE];
    atomic_t head;
    atomic_t count;
    spinlock_t lock;  /* For reading full entries */
};

static inline void tquic_log_error(struct tquic_connection *conn,
                                   u32 error_code, const char *msg)
{
    struct tquic_error_entry *entry;
    int head = atomic_inc_return(&ring->head) % TQUIC_ERROR_RING_SIZE;

    entry = &ring->entries[head];
    entry->timestamp = ktime_get();
    entry->error_code = error_code;
    /* Fill other fields... */

    if (error_is_important(error_code))
        pr_warn_ratelimited("TQUIC: %d (%s) for CID %*phN\n",
                           error_code, tquic_error_name(error_code),
                           conn->scid.len, conn->scid.id);
}
```

### Anti-Patterns to Avoid

- **Global counters without per-CPU:** Race conditions, cache line bouncing
- **seq_file without proper locking:** Use RCU or spin_lock for iteration
- **Oversized proc output:** Use seq_has_overflowed() to detect buffer exhaustion
- **Blocking in diag callbacks:** inet_diag runs under RCU, keep fast
- **Missing CAP_NET_ADMIN checks:** Sensitive info (CIDs) needs capability check

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Per-CPU counters | Raw atomics or locked arrays | SNMP_INC_STATS macros | Handles 32/64-bit, CPU-local batching |
| Proc file reading | Raw seq_read | proc_create_net_single | Handles open/read/close, netns |
| Connection listing | Custom format parsing | seq_file with headers | Self-documenting, awk-friendly |
| Error strings | switch statements | Lookup table with EQUIC_BASE offset | Avoids code duplication |
| ss integration | Custom netlink protocol | inet_diag handler | ss already knows how to display |

**Key insight:** The kernel has mature infrastructure for every aspect of socket diagnostics. TQUIC should slot into existing patterns rather than creating new interfaces.

## Common Pitfalls

### Pitfall 1: MIB Counter Overflow

**What goes wrong:** 32-bit counter wraps on busy systems
**Why it happens:** Using `unsigned long` which is 32-bit on some platforms
**How to avoid:** Use `u64` for byte counters, check with SNMP_ADD_STATS64
**Warning signs:** Counter values decrease unexpectedly

### Pitfall 2: seq_file Buffer Exhaustion

**What goes wrong:** Large connection list truncates silently
**Why it happens:** Default buffer too small for many connections
**How to avoid:** Check `seq_has_overflowed()`, use pagination in iteration
**Warning signs:** Output ends mid-line or missing connections

### Pitfall 3: Holding Locks During seq_printf

**What goes wrong:** Deadlock or performance issues
**Why it happens:** seq_file can allocate memory, which may block
**How to avoid:** Copy data under lock, format outside lock
**Warning signs:** System hangs when reading /proc/net/tquic

### Pitfall 4: Module Alias Mismatch

**What goes wrong:** ss doesn't load tquic_diag module automatically
**Why it happens:** MODULE_ALIAS string doesn't match ss query
**How to avoid:** Use `MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 2-263)`
**Warning signs:** ss shows nothing until `modprobe tquic_diag`

### Pitfall 5: Missing Namespace Isolation

**What goes wrong:** /proc/net/tquic shows connections from other namespaces
**Why it happens:** Not using `seq_file_net()` in iteration
**How to avoid:** Always filter by `net_eq(sock_net(sk), seq_file_net(seq))`
**Warning signs:** Container users see host connections

## Code Examples

### Complete MIB Registration

```c
// Source: net/mptcp/mib.c (simplified for TQUIC)
static const struct snmp_mib tquic_snmp_list[] = {
    SNMP_MIB_ITEM("HandshakesComplete", TQUIC_MIB_HANDSHAKESCOMPLETE),
    SNMP_MIB_ITEM("HandshakesFailed", TQUIC_MIB_HANDSHAKESFAILED),
    SNMP_MIB_ITEM("PacketsRx", TQUIC_MIB_PACKETSRX),
    SNMP_MIB_ITEM("PacketsTx", TQUIC_MIB_PACKETSTX),
    SNMP_MIB_ITEM("BytesRx", TQUIC_MIB_BYTESRX),
    SNMP_MIB_ITEM("BytesTx", TQUIC_MIB_BYTESTX),
    SNMP_MIB_ITEM("Retransmissions", TQUIC_MIB_RETRANSMISSIONS),
    SNMP_MIB_ITEM("PathMigrations", TQUIC_MIB_PATHMIGRATIONS),
    SNMP_MIB_ITEM("PathFailures", TQUIC_MIB_PATHFAILURES),
    SNMP_MIB_ITEM("ConnTimedOut", TQUIC_MIB_CONNTIMEDOUT),
    SNMP_MIB_ITEM("ConnClosed", TQUIC_MIB_CONNCLOSED),
    SNMP_MIB_ITEM("ConnReset", TQUIC_MIB_CONNRESET),
    SNMP_MIB_ITEM("RttSamples", TQUIC_MIB_RTTSAMPLES),
    SNMP_MIB_ITEM("LossEvents", TQUIC_MIB_LOSSEVENTS),
    SNMP_MIB_ITEM("CurrEstab", TQUIC_MIB_CURRESTAB),
    /* EQUIC error counters */
    SNMP_MIB_ITEM("EquicFlowControl", TQUIC_MIB_EQUIC_FLOW_CONTROL),
    SNMP_MIB_ITEM("EquicStreamLimit", TQUIC_MIB_EQUIC_STREAM_LIMIT),
    SNMP_MIB_ITEM("EquicProtocolViolation", TQUIC_MIB_EQUIC_PROTOCOL_VIOLATION),
    SNMP_MIB_SENTINEL
};

void tquic_seq_show(struct seq_file *seq)
{
    unsigned long sum[ARRAY_SIZE(tquic_snmp_list) - 1];
    struct net *net = seq->private;
    int i;

    seq_puts(seq, "\nTquicExt:");
    for (i = 0; tquic_snmp_list[i].name; i++)
        seq_printf(seq, " %s", tquic_snmp_list[i].name);

    seq_puts(seq, "\nTquicExt:");
    memset(sum, 0, sizeof(sum));
    if (net->mib.tquic_statistics)
        snmp_get_cpu_field_batch(sum, tquic_snmp_list,
                                 net->mib.tquic_statistics);
    for (i = 0; tquic_snmp_list[i].name; i++)
        seq_printf(seq, " %lu", sum[i]);
    seq_putc(seq, '\n');
}
```

### State Name with TCP Equivalent

```c
// Per CONTEXT.md: "CONNECTED (ESTABLISHED)"
static const char *tquic_state_names[] = {
    [TQUIC_CONN_IDLE]       = "IDLE (CLOSED)",
    [TQUIC_CONN_CONNECTING] = "CONNECTING (SYN_SENT)",
    [TQUIC_CONN_CONNECTED]  = "CONNECTED (ESTABLISHED)",
    [TQUIC_CONN_CLOSING]    = "CLOSING (FIN_WAIT1)",
    [TQUIC_CONN_DRAINING]   = "DRAINING (TIME_WAIT)",
    [TQUIC_CONN_CLOSED]     = "CLOSED (CLOSED)",
};

static inline const char *tquic_state_name(enum tquic_conn_state state)
{
    if (state >= ARRAY_SIZE(tquic_state_names))
        return "UNKNOWN";
    return tquic_state_names[state];
}
```

### EQUIC Error Code Lookup

```c
// Per CONTEXT.md: "501 (EQUIC_FLOW_CONTROL)"
static const char *equic_error_names[] = {
    [0x00] = "EQUIC_NO_ERROR",
    [0x01] = "EQUIC_INTERNAL_ERROR",
    [0x02] = "EQUIC_CONNECTION_REFUSED",
    [0x03] = "EQUIC_FLOW_CONTROL",
    [0x04] = "EQUIC_STREAM_LIMIT",
    [0x05] = "EQUIC_STREAM_STATE",
    [0x06] = "EQUIC_FINAL_SIZE",
    [0x07] = "EQUIC_FRAME_ENCODING",
    [0x08] = "EQUIC_TRANSPORT_PARAM",
    [0x09] = "EQUIC_CONNECTION_ID_LIMIT",
    [0x0a] = "EQUIC_PROTOCOL_VIOLATION",
    [0x0b] = "EQUIC_INVALID_TOKEN",
    [0x0c] = "EQUIC_APPLICATION_ERROR",
    [0x0d] = "EQUIC_CRYPTO_BUFFER",
    [0x0e] = "EQUIC_KEY_UPDATE",
    [0x0f] = "EQUIC_AEAD_LIMIT",
    [0x10] = "EQUIC_NO_VIABLE_PATH",
};

static inline const char *tquic_error_name(u32 error_code)
{
    u32 idx;
    if (error_code < EQUIC_BASE)
        return "UNKNOWN";
    idx = error_code - EQUIC_BASE;
    if (idx >= ARRAY_SIZE(equic_error_names) || !equic_error_names[idx])
        return "UNKNOWN_EQUIC";
    return equic_error_names[idx];
}

/* Format: "501 (EQUIC_FLOW_CONTROL)" */
static inline int tquic_error_format(char *buf, size_t len, u32 error_code)
{
    return scnprintf(buf, len, "%u (%s)", error_code,
                     tquic_error_name(error_code));
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Global stats file | Per-netns stats | Kernel 2.6.24 | Container isolation |
| sysfs for stats | /proc/net with SNMP MIB | Always | Structured naming |
| Manual netlink | inet_diag handler | Kernel 3.3 | ss tool integration |
| Open-coded iteration | seq_file | Kernel 2.5 | Memory-safe large outputs |

**Deprecated/outdated:**
- **proc_net_create()**: Use proc_create_net_single() or proc_create_net()
- **create_proc_entry()**: Replaced by proc_create()
- **Single global counter arrays**: Use per-CPU with SNMP macros

## Open Questions

1. **CID Display Format for Extended ss Output**
   - What we know: Full hex required per CONTEXT.md
   - What's unclear: Whether to use colons/dashes for readability
   - Recommendation: Use plain hex (no separators) to match Wireshark display filters

2. **Path Visibility in /proc**
   - What we know: Fixed-column format required
   - What's unclear: Inline per-connection or separate /proc/net/tquic_paths
   - Recommendation: Inline is simpler; separate file if path count >> connection count

3. **Ring Buffer Size**
   - What we know: Need dedicated error ring buffer
   - What's unclear: Optimal size for typical server workloads
   - Recommendation: Start with 256 entries (4KB), make configurable via sysctl

## Sources

### Primary (HIGH confidence)
- net/ipv4/tcp_diag.c - TCP inet_diag handler pattern
- net/mptcp/mptcp_diag.c - MPTCP inet_diag handler (simpler pattern)
- net/mptcp/mib.c, mib.h - MPTCP MIB counter implementation
- net/ipv4/proc.c - TCP/IP proc statistics output
- net/ipv4/tcp_ipv4.c - TCP connection seq_file iteration
- include/linux/inet_diag.h - inet_diag handler interface
- include/net/snmp.h - SNMP MIB macros

### Secondary (MEDIUM confidence)
- include/uapi/linux/inet_diag.h - Userspace diag structures
- include/uapi/linux/snmp.h - MIB enum definitions

### Tertiary (LOW confidence)
- None - all patterns verified from kernel source

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - All subsystems verified in kernel source
- Architecture: HIGH - Patterns directly from TCP/MPTCP implementations
- Pitfalls: HIGH - Common issues documented in kernel commit history

**Research date:** 2026-01-31
**Valid until:** 2026-03-01 (stable kernel interfaces)
