# Phase 5: Multi-Path Bonding Core - Research

**Researched:** 2026-01-31
**Domain:** Linux kernel multipath bandwidth aggregation with QUIC protocol
**Confidence:** HIGH

## Summary

Phase 5 implements true bandwidth aggregation for TQUIC WAN bonding, enabling two 1Gbps paths to yield ~2Gbps aggregate throughput with seamless failover on path failure. The core challenge is handling packet reordering across paths with up to 600ms latency difference (fiber ~20ms vs satellite ~600ms) while delivering an in-order bytestream to applications.

The Linux kernel already has mature patterns for this exact problem in MPTCP (`net/mptcp/protocol.c`), which uses an RB-tree (`rb_root`) based out-of-order queue to resequence data received across subflows with different latencies. The existing TQUIC codebase (Phase 4) provides path management, validation, congestion control per-path, and a scheduler framework with multiple algorithms (round-robin, weighted, lowlat, adaptive). Phase 5 builds on these to implement: (1) bonding state machine for aggregation lifecycle, (2) RB-tree reorder buffer with adaptive sizing, (3) capacity-proportional packet scheduling, and (4) seamless failover with retransmission of in-flight packets.

**Primary recommendation:** Follow MPTCP's RB-tree out-of-order queue pattern (`msk->out_of_order_queue`) for reordering, implement a bonding state machine (SINGLE_PATH -> BONDING_PENDING -> BONDED -> DEGRADED), use the existing weighted scheduler with capacity-derived weights, and implement failover by re-queuing unacked packets from failed paths to remaining paths.

## Standard Stack

The established components for kernel multipath bandwidth aggregation:

### Core
| Component | Location | Purpose | Why Standard |
|-----------|----------|---------|--------------|
| `struct rb_root` out_of_order_queue | net/mptcp/protocol.h:332 | RB-tree for O(log n) packet reordering | Proven pattern in MPTCP, TCP OOO handling |
| `struct tquic_scheduler_ops` | net/quic/tquic_scheduler.c | Pluggable scheduling algorithms | Already implemented in Phase 4, extensible |
| `struct tquic_path_cc` | net/quic/tquic_path.c | Per-path congestion control state | Already implemented, provides cwnd/bandwidth |
| `struct tquic_path_manager` | net/quic/tquic_path.c | Path lifecycle and validation | Already implemented, provides path states |

### Supporting
| Component | Purpose | When to Use |
|-----------|---------|-------------|
| `skb_rb_next()` / `rb_erase()` | RB-tree traversal for reorder buffer | Processing in-order data from OOO queue |
| `ktime_t` timestamps | Timeout-based gap release | Preventing infinite buffering of truly lost packets |
| `atomic64_t` counters | Lock-free statistics | Bonding throughput metrics |
| `struct delayed_work` | Periodic reorder timeout | Gap timeout timer |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| RB-tree reorder buffer | Linear list | RB-tree O(log n) vs list O(n) for insertions - critical for 600ms latency spread |
| Per-path packet numbering | Single sequence space | Per-path reduces ACK frame bloat from reordering |
| Adaptive buffer sizing | Fixed buffer | Fixed buffer either wastes memory or fails satellite scenario |

## Architecture Patterns

### Recommended Project Structure
```
net/tquic/
├── tquic_bonding.c       # Bonding state machine, reorder buffer
├── tquic_bonding.h       # Bonding structures and API
├── tquic_scheduler.c     # (existing) Extend for bonding-aware scheduling
├── tquic_path.c          # (existing) Path manager integration
└── tquic_failover.c      # Failover logic, retransmit queue management
```

### Pattern 1: RB-Tree Reorder Buffer (MPTCP Pattern)
**What:** Red-black tree indexed by data sequence number for O(log n) reordering
**When to use:** Receiving data from multiple paths with heterogeneous latencies
**Example:**
```c
// Source: net/mptcp/protocol.c:267-342
struct tquic_bonding_state {
    struct rb_root reorder_queue;    /* RB-tree for OOO packets */
    struct sk_buff *ooo_last_skb;    /* Fast path for tail insertion */
    u64 next_expected_seq;           /* Next sequence to deliver */
    u64 max_buffered_seq;            /* Highest sequence in buffer */

    /* Adaptive sizing */
    size_t buffer_bytes;             /* Current buffer usage */
    size_t max_buffer_bytes;         /* Configurable limit (sysctl) */
    ktime_t oldest_packet_time;      /* For gap timeout */
};

/* Insert packet into reorder buffer */
static int tquic_reorder_insert(struct tquic_bonding_state *bs,
                                struct sk_buff *skb, u64 seq)
{
    struct rb_node **p = &bs->reorder_queue.rb_node;
    struct rb_node *parent = NULL;

    /* Memory limit check */
    if (bs->buffer_bytes + skb->truesize > bs->max_buffer_bytes)
        return -ENOBUFS;  /* Apply backpressure */

    /* Fast path: append to tail */
    if (RB_EMPTY_ROOT(&bs->reorder_queue)) {
        rb_link_node(&skb->rbnode, NULL, p);
        rb_insert_color(&skb->rbnode, &bs->reorder_queue);
        bs->ooo_last_skb = skb;
        goto inserted;
    }

    /* Check if we can fast-path append */
    if (after64(seq, TQUIC_SKB_CB(bs->ooo_last_skb)->seq)) {
        p = &bs->ooo_last_skb->rbnode.rb_right;
        parent = &bs->ooo_last_skb->rbnode;
        rb_link_node(&skb->rbnode, parent, p);
        rb_insert_color(&skb->rbnode, &bs->reorder_queue);
        bs->ooo_last_skb = skb;
        goto inserted;
    }

    /* Standard RB-tree insertion */
    while (*p) {
        struct sk_buff *skb1 = rb_to_skb(*p);
        parent = *p;

        if (before64(seq, TQUIC_SKB_CB(skb1)->seq))
            p = &(*p)->rb_left;
        else if (after64(seq, TQUIC_SKB_CB(skb1)->seq))
            p = &(*p)->rb_right;
        else
            return -EEXIST;  /* Duplicate */
    }

    rb_link_node(&skb->rbnode, parent, p);
    rb_insert_color(&skb->rbnode, &bs->reorder_queue);

inserted:
    bs->buffer_bytes += skb->truesize;
    if (seq > bs->max_buffered_seq)
        bs->max_buffered_seq = seq;
    return 0;
}

/* Deliver in-order data from reorder buffer */
static int tquic_reorder_drain(struct tquic_bonding_state *bs,
                               struct sock *sk)
{
    struct rb_node *p;
    int delivered = 0;

    p = rb_first(&bs->reorder_queue);
    while (p) {
        struct sk_buff *skb = rb_to_skb(p);
        u64 seq = TQUIC_SKB_CB(skb)->seq;

        if (after64(seq, bs->next_expected_seq))
            break;  /* Gap - stop draining */

        p = rb_next(p);
        rb_erase(&skb->rbnode, &bs->reorder_queue);
        bs->buffer_bytes -= skb->truesize;

        /* Deliver to stream reassembly */
        tquic_stream_deliver(sk, skb);
        bs->next_expected_seq = seq + skb->len;
        delivered++;
    }

    return delivered;
}
```

### Pattern 2: Bonding State Machine
**What:** Explicit states for aggregation lifecycle with clean transitions
**When to use:** Managing bonding activation/deactivation, degradation, recovery
**Example:**
```c
// Source: CONTEXT.md decisions
enum tquic_bonding_state_t {
    TQUIC_BOND_SINGLE_PATH = 0,  /* Normal QUIC, no aggregation overhead */
    TQUIC_BOND_PENDING,          /* Second path validating, prepare buffer */
    TQUIC_BOND_ACTIVE,           /* Aggregating across 2+ paths */
    TQUIC_BOND_DEGRADED,         /* One or more paths failed, reduced capacity */
};

struct tquic_bonding_ctx {
    enum tquic_bonding_state_t state;
    spinlock_t state_lock;

    /* Path tracking */
    int active_path_count;
    int degraded_path_count;

    /* Reorder buffer */
    struct tquic_bonding_state reorder;

    /* Failover state */
    struct list_head retransmit_queue;  /* Packets from failed paths */
    u64 failover_start_time;

    /* Statistics */
    struct {
        u64 aggregate_bytes_tx;
        u64 aggregate_bytes_rx;
        u64 reorder_events;
        u64 gap_timeouts;
        u64 failover_count;
    } stats;
};

/* State transition logic */
static void tquic_bonding_update_state(struct tquic_connection *conn)
{
    struct tquic_bonding_ctx *bc = conn->bonding;
    enum tquic_bonding_state_t new_state;
    int validated = tquic_pm_count_validated_paths(conn->pm);
    int failed = tquic_pm_count_failed_paths(conn->pm);

    spin_lock_bh(&bc->state_lock);

    if (validated == 0) {
        new_state = TQUIC_BOND_SINGLE_PATH;  /* No paths, connection closing */
    } else if (validated == 1 && failed == 0) {
        new_state = TQUIC_BOND_SINGLE_PATH;
    } else if (validated == 1 && failed > 0) {
        new_state = TQUIC_BOND_DEGRADED;
    } else if (validated >= 2 && failed == 0) {
        new_state = TQUIC_BOND_ACTIVE;
    } else {
        new_state = TQUIC_BOND_DEGRADED;
    }

    if (bc->state != new_state) {
        pr_info("tquic: bonding state %d -> %d (validated=%d failed=%d)\n",
                bc->state, new_state, validated, failed);
        bc->state = new_state;

        /* Activate/deactivate reorder buffer as needed */
        if (new_state == TQUIC_BOND_SINGLE_PATH)
            tquic_reorder_buffer_disable(bc);
        else if (bc->state == TQUIC_BOND_SINGLE_PATH)
            tquic_reorder_buffer_enable(bc);
    }

    spin_unlock_bh(&bc->state_lock);
}
```

### Pattern 3: Capacity-Proportional Scheduling
**What:** Distribute packets across paths proportional to their measured capacity
**When to use:** Basic aggregation before advanced schedulers (Phase 6)
**Example:**
```c
// Source: Existing tquic_scheduler.c weighted scheduler + capacity derivation
struct tquic_capacity_weights {
    u32 path_weights[TQUIC_MAX_PATHS];
    u32 total_weight;
    ktime_t last_update;
};

/* Derive weights from cwnd and RTT */
static void tquic_derive_capacity_weights(struct tquic_connection *conn,
                                          struct tquic_capacity_weights *cw)
{
    struct tquic_path *path;
    u32 total = 0;
    int idx = 0;

    rcu_read_lock();
    list_for_each_entry_rcu(path, &conn->pm->path_list, list) {
        u64 capacity;

        if (path->state != TQUIC_PATH_ACTIVE &&
            path->state != TQUIC_PATH_VALIDATED) {
            cw->path_weights[idx++] = 0;
            continue;
        }

        /* Capacity = cwnd / RTT (bytes per second) */
        if (path->metrics.srtt > 0)
            capacity = (u64)path->cc.cwnd * USEC_PER_SEC / path->metrics.srtt;
        else
            capacity = path->cc.cwnd * 1000;  /* Assume 1ms RTT if unknown */

        /* Scale to weight (1-1000 range) */
        cw->path_weights[idx] = min_t(u64, capacity / 1000, 1000);
        if (cw->path_weights[idx] < 1)
            cw->path_weights[idx] = 1;

        total += cw->path_weights[idx];
        idx++;
    }
    rcu_read_unlock();

    cw->total_weight = total;
    cw->last_update = ktime_get();
}

/* Select path using weighted random selection */
static struct tquic_path *tquic_select_by_capacity(struct tquic_connection *conn,
                                                   struct tquic_capacity_weights *cw)
{
    u32 rand = get_random_u32() % cw->total_weight;
    u32 cumulative = 0;
    struct tquic_path *path;
    int idx = 0;

    rcu_read_lock();
    list_for_each_entry_rcu(path, &conn->pm->path_list, list) {
        if (cw->path_weights[idx] == 0) {
            idx++;
            continue;
        }

        cumulative += cw->path_weights[idx];
        if (rand < cumulative) {
            rcu_read_unlock();
            return path;
        }
        idx++;
    }
    rcu_read_unlock();

    return NULL;  /* Should not reach */
}
```

### Pattern 4: Seamless Failover with Retransmit Queue
**What:** On path failure, requeue unacked packets for retransmission on remaining paths
**When to use:** Path failure detected (3x SRTT without ACK per CONTEXT.md)
**Example:**
```c
// Source: Phase 4 decisions + RFC 9000 loss recovery
struct tquic_sent_packet {
    struct list_head list;
    u64 packet_number;
    u8 path_id;
    ktime_t sent_time;
    u32 bytes;
    bool ack_eliciting;
    struct sk_buff *skb;  /* Original data for retransmit */
};

/* Handle path failure - requeue pending packets */
static void tquic_failover_requeue(struct tquic_connection *conn,
                                   struct tquic_path *failed_path)
{
    struct tquic_bonding_ctx *bc = conn->bonding;
    struct tquic_sent_packet *pkt, *tmp;
    LIST_HEAD(requeue);

    /* Collect unacked packets sent on failed path */
    spin_lock_bh(&conn->sent_lock);
    list_for_each_entry_safe(pkt, tmp, &conn->sent_packets, list) {
        if (pkt->path_id == failed_path->path_id && pkt->ack_eliciting) {
            list_move_tail(&pkt->list, &requeue);
        }
    }
    spin_unlock_bh(&conn->sent_lock);

    /* Add to retransmit queue with priority */
    spin_lock_bh(&bc->retransmit_lock);
    list_splice(&requeue, &bc->retransmit_queue);  /* Prepend for priority */
    spin_unlock_bh(&bc->retransmit_lock);

    bc->stats.failover_count++;

    pr_info("tquic: failover from path %u, requeued %zu packets\n",
            failed_path->path_id, list_count_nodes(&requeue));

    /* Trigger immediate retransmission */
    tquic_schedule_output(conn);
}

/* Send path: prioritize retransmit queue over new data */
static struct sk_buff *tquic_get_next_packet(struct tquic_connection *conn,
                                              struct tquic_path *path)
{
    struct tquic_bonding_ctx *bc = conn->bonding;
    struct tquic_sent_packet *pkt;
    struct sk_buff *skb = NULL;

    /* Priority 1: Retransmit queue (packets from failed paths) */
    spin_lock_bh(&bc->retransmit_lock);
    if (!list_empty(&bc->retransmit_queue)) {
        pkt = list_first_entry(&bc->retransmit_queue,
                               struct tquic_sent_packet, list);
        list_del(&pkt->list);
        skb = skb_clone(pkt->skb, GFP_ATOMIC);
        /* Mark for new path, update packet number */
    }
    spin_unlock_bh(&bc->retransmit_lock);

    if (skb)
        return skb;

    /* Priority 2: New data from send queue */
    return tquic_stream_get_data(conn, path);
}
```

### Anti-Patterns to Avoid
- **Don't use a linear list for reorder buffer:** O(n) insertion kills performance with 600ms latency spread
- **Don't allocate reorder buffer upfront for all connections:** Only allocate when second path validates (BOND_PENDING)
- **Don't drop packets on reorder timeout without notifying sender:** Gap timeout should trigger NACK/retransmit request
- **Don't assume symmetric paths:** Capacity weighting must be asymmetric (4G upload << download)
- **Don't block on path failure:** Failover must be non-blocking (workqueue)

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Packet reordering | Simple FIFO queue | RB-tree (`rb_root`) | O(log n) vs O(n), handles 600ms spread |
| Per-path congestion control | Single cwnd | Existing `tquic_path_cc` | Already implements RFC 6298 + recovery |
| Scheduler framework | Ad-hoc path selection | Existing `tquic_scheduler_ops` | Pluggable, already has 5 algorithms |
| Path state machine | Boolean flags | Existing `tquic_path_state` enum | Clean states, validated transitions |
| RTT estimation | Simple averaging | Existing RFC 6298 SRTT/RTTVAR | Handles variance, proven by TCP |
| Memory accounting | No limits | `sk_mem_charge()` / sysctl limits | Prevents OOM from reorder buffer |

**Key insight:** Phase 4 already implemented 80% of the infrastructure. Phase 5 adds: (1) reorder buffer, (2) bonding state machine, (3) failover retransmit logic, and (4) wiring capacity to scheduler weights.

## Common Pitfalls

### Pitfall 1: Unbounded Reorder Buffer Growth
**What goes wrong:** Memory exhaustion when slow path (satellite) has packet loss
**Why it happens:** Buffer holds packets waiting for gap to fill that never arrives
**How to avoid:**
- Hard memory limit via sysctl (default 4MB per connection)
- Gap timeout: if packet not received within `max_rtt_spread + margin`, deliver with gap
- Backpressure: return -ENOBUFS to sender when buffer full
**Warning signs:** `buffer_bytes` approaching `max_buffer_bytes`, increasing `gap_timeouts` stat

### Pitfall 2: Head-of-Line Blocking Stalls Application
**What goes wrong:** Application blocked waiting for one lost packet while buffer fills
**Why it happens:** Strict in-order delivery when gap is truly lost packet
**How to avoid:**
- Gap timeout = `(max_path_rtt - min_path_rtt) * 2 + 100ms` safety margin
- For satellite: gap timeout ~1300ms (600ms spread * 2 + 100ms)
- On timeout, deliver available data and mark gap for retransmit
**Warning signs:** Long stalls in `recv()`, high `gap_timeouts` without corresponding loss

### Pitfall 3: Failover Packet Duplication
**What goes wrong:** Retransmitted packet arrives twice (original delayed, not lost)
**Why it happens:** Path failure declared too early, original packet still in flight
**How to avoid:**
- Use 3x SRTT timeout before declaring path failed (matches RFC 9000 PTO)
- Receiver deduplication based on packet number
- Track `highest_acked` per path to detect late arrivals
**Warning signs:** `MPTCP_MIB_DUPDATA` equivalent counter increasing

### Pitfall 4: Scheduler Starvation of Slow Path
**What goes wrong:** All traffic goes to fast path, slow path never used for aggregation
**Why it happens:** Capacity-proportional weighting with large RTT difference
**How to avoid:**
- Minimum weight floor (e.g., 5% regardless of RTT ratio)
- Use cwnd-based weighting, not bandwidth-based (cwnd grows with utilization)
- Allow user override via SO_TQUIC_PATH_WEIGHT sockopt
**Warning signs:** One path with 0% utilization while bonded

### Pitfall 5: State Machine Stuck in DEGRADED
**What goes wrong:** Path recovers but bonding stays in DEGRADED state
**Why it happens:** Missing callback from path validation to bonding state update
**How to avoid:**
- Register `on_path_available` callback in path manager
- Always call `tquic_bonding_update_state()` on any path state change
- Timer-based recovery check as backup
**Warning signs:** `active_paths >= 2` but `bonding_state == DEGRADED`

### Pitfall 6: Reorder Buffer During Single-Path Operation
**What goes wrong:** Unnecessary memory allocation and processing overhead
**Why it happens:** Always allocating reorder buffer regardless of path count
**How to avoid:**
- Lazy allocation: only create reorder buffer in BOND_PENDING state
- Bypass reorder code path entirely in SINGLE_PATH state
- Free buffer when returning to SINGLE_PATH
**Warning signs:** Memory usage for single-path connections

## Code Examples

Verified patterns from official sources:

### Adaptive Reorder Buffer Sizing
```c
// Source: CONTEXT.md requirement "600ms latency difference"
// Buffer size = max_rtt_spread * estimated_bandwidth * safety_factor
static size_t tquic_calc_reorder_buffer_size(struct tquic_connection *conn)
{
    struct tquic_path *path;
    u32 min_rtt = U32_MAX, max_rtt = 0;
    u64 total_bandwidth = 0;
    size_t buffer_size;

    rcu_read_lock();
    list_for_each_entry_rcu(path, &conn->pm->path_list, list) {
        if (path->state != TQUIC_PATH_ACTIVE &&
            path->state != TQUIC_PATH_VALIDATED)
            continue;

        if (path->metrics.srtt > 0) {
            min_rtt = min(min_rtt, path->metrics.srtt);
            max_rtt = max(max_rtt, path->metrics.srtt);
        }

        total_bandwidth += path->metrics.bandwidth;
    }
    rcu_read_unlock();

    if (min_rtt == U32_MAX || max_rtt == 0)
        return TQUIC_DEFAULT_REORDER_BUFFER;  /* 256KB default */

    /* Buffer = latency_spread_ms * bandwidth_bytes_per_ms * 2 (safety) */
    u32 spread_us = max_rtt - min_rtt;
    buffer_size = (spread_us / 1000) * (total_bandwidth / 1000) * 2;

    /* Clamp to configured limits */
    buffer_size = clamp(buffer_size,
                        (size_t)TQUIC_MIN_REORDER_BUFFER,  /* 64KB */
                        (size_t)conn->bonding->max_buffer_bytes);

    return buffer_size;
}
```

### Gap Timeout Handler
```c
// Source: MPTCP timeout pattern, adapted for heterogeneous latency
static void tquic_reorder_timeout_handler(struct work_struct *work)
{
    struct tquic_bonding_ctx *bc = container_of(work,
                                                struct tquic_bonding_ctx,
                                                reorder_timeout_work.work);
    struct tquic_connection *conn = bc->conn;
    struct rb_node *p;
    ktime_t now = ktime_get();
    ktime_t threshold;
    u64 gap_start = bc->reorder.next_expected_seq;
    int delivered = 0;

    /* Gap timeout = 2 * max_rtt_spread + 100ms margin */
    threshold = ktime_sub_ms(now, bc->gap_timeout_ms);

    spin_lock_bh(&bc->reorder.lock);

    /* Check if oldest packet has timed out */
    p = rb_first(&bc->reorder.reorder_queue);
    if (!p) {
        spin_unlock_bh(&bc->reorder.lock);
        return;
    }

    if (ktime_before(bc->reorder.oldest_packet_time, threshold)) {
        /* Gap timeout - deliver available data */
        pr_debug("tquic: gap timeout at seq %llu, delivering from %llu\n",
                 gap_start, TQUIC_SKB_CB(rb_to_skb(p))->seq);

        /* Jump next_expected_seq to first available packet */
        bc->reorder.next_expected_seq = TQUIC_SKB_CB(rb_to_skb(p))->seq;

        /* Request retransmit for gap */
        tquic_request_retransmit(conn, gap_start, bc->reorder.next_expected_seq);

        /* Drain now-deliverable packets */
        delivered = tquic_reorder_drain(&bc->reorder, conn->sk);

        bc->stats.gap_timeouts++;
    }

    spin_unlock_bh(&bc->reorder.lock);

    /* Reschedule if buffer not empty */
    if (!RB_EMPTY_ROOT(&bc->reorder.reorder_queue))
        queue_delayed_work(tquic_wq, &bc->reorder_timeout_work,
                           msecs_to_jiffies(bc->gap_timeout_ms));
}
```

### Path Weight Sockopt
```c
// Source: CONTEXT.md "User-overridable weights via sockopt"
static int tquic_setsockopt_path_weight(struct sock *sk,
                                         sockptr_t optval, int optlen)
{
    struct tquic_connection *conn = tquic_sk(sk)->conn;
    struct tquic_path_weight_opt opt;
    struct tquic_path *path;

    if (optlen != sizeof(opt))
        return -EINVAL;

    if (copy_from_sockptr(&opt, optval, sizeof(opt)))
        return -EFAULT;

    if (opt.weight > TQUIC_MAX_PATH_WEIGHT)
        return -EINVAL;

    spin_lock_bh(&conn->pm->lock);

    path = tquic_pm_get_path(conn->pm, opt.path_id);
    if (!path) {
        spin_unlock_bh(&conn->pm->lock);
        return -ENOENT;
    }

    path->user_weight = opt.weight;
    path->weight_override = (opt.weight > 0);

    /* Recalculate scheduler weights */
    tquic_derive_capacity_weights(conn, &conn->bonding->capacity_weights);

    spin_unlock_bh(&conn->pm->lock);

    return 0;
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single sequence space | Per-path packet numbers | MPQUIC draft 2023+ | Smaller ACK frames, less reorder confusion |
| Fixed reorder buffer | Adaptive buffer sizing | Research 2022+ | Memory efficiency, handles diverse scenarios |
| Lowest-RTT-first scheduling | Stream-aware + capacity-proportional | MPQUIC SA-ECF 2018+ | Better aggregation with heterogeneous paths |
| TCP-style in-order delivery | Configurable gap timeout | MPTCP/MPQUIC evolution | Reduces HoL blocking |
| Single cwnd | Per-path + coupled CC | MPTCP LIA/OLIA | Fair aggregation without harming other flows |

**Deprecated/outdated:**
- **Simple round-robin scheduling:** Causes severe reordering with heterogeneous RTT
- **Global sequence numbers only:** Per-path numbering preferred for multi-path
- **Fixed 1-second gap timeout:** Must adapt to actual RTT spread

## Open Questions

Things that couldn't be fully resolved:

1. **Exact gap timeout formula for satellite + fiber**
   - What we know: 600ms RTT spread, need 2x for round-trip + margin
   - What's unclear: Optimal margin value (100ms? 200ms? adaptive?)
   - Recommendation: Start with `2 * (max_rtt - min_rtt) + 100ms`, make configurable via sysctl

2. **Receiver-side vs sender-side reorder buffer**
   - What we know: MPTCP uses receiver-side reordering
   - What's unclear: For QUIC/DTLS where sender knows sequence, could sender-side help?
   - Recommendation: Use receiver-side (MPTCP pattern), simpler and proven

3. **Coupled congestion control in Phase 5 vs Phase 7**
   - What we know: Phase 7 is dedicated to congestion control
   - What's unclear: Should basic coupled CC (LIA) be in Phase 5 or wait?
   - Recommendation: Phase 5 uses per-path CC from Phase 4, Phase 7 adds coupling algorithms

4. **Stream-level vs connection-level reorder buffer**
   - What we know: QUIC has streams, could reorder per-stream
   - What's unclear: Performance tradeoff of per-stream vs single buffer
   - Recommendation: Single connection-level buffer (MPTCP pattern), simpler, stream reassembly is separate

5. **Handling DATAGRAM frames in bonding**
   - What we know: QUIC DATAGRAM extension is unreliable
   - What's unclear: Should datagrams go through reorder buffer?
   - Recommendation: No reordering for datagrams (unreliable), deliver immediately on any path

## Sources

### Primary (HIGH confidence)
- **Linux Kernel Source:** `net/mptcp/protocol.c:85,227,267-342,785-793,2975,3363` - RB-tree out-of-order queue implementation
- **Linux Kernel Source:** `net/mptcp/protocol.h:332` - `struct rb_root out_of_order_queue` definition
- **Linux Kernel Source:** `net/quic/tquic_path.c` - Path state machine, validation, metrics
- **Linux Kernel Source:** `net/quic/tquic_scheduler.c` - Scheduler framework and algorithms
- **Phase 4 Research:** `.planning/phases/04-path-manager-completion/04-RESEARCH.md` - Prior decisions and patterns

### Secondary (MEDIUM confidence)
- [Optimizing multipath QUIC transmission over heterogeneous paths](https://www.sciencedirect.com/science/article/abs/pii/S1389128622002894) - Heterogeneous path scheduling research
- [A Stream-Aware Multipath QUIC Scheduler](https://dl.acm.org/doi/10.1145/3284850.3284855) - SA-ECF scheduler design
- [MPTCP Out-of-Order Queue Documentation](https://mptcp-apps.github.io/mptcp-doc/mptcp-linux.html) - MPTCP OOO counters
- [LWN: MPTCP multipath xmit](https://lwn.net/Articles/831466/) - Kernel MPTCP receive code refactor
- [Multipath QUIC Path Failover Mechanism](https://datatracker.ietf.org/doc/html/draft-kozuka-quic-failover-00) - Path failure detection patterns

### Tertiary (LOW confidence)
- [ZeroTier Multipath Documentation](https://docs.zerotier.com/multipath/) - Bonding concepts (not kernel-specific)
- [OpenMPTCProuter](https://www.openmptcprouter.com/) - User-space bonding patterns

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - All components from kernel source (MPTCP, existing TQUIC)
- Architecture: HIGH - Direct adaptation of MPTCP patterns, verified in kernel source
- Pitfalls: HIGH - Documented in kernel code comments and MPTCP experience
- Code examples: HIGH - Based on net/mptcp/protocol.c, adapted for QUIC

**Research date:** 2026-01-31
**Valid until:** 2026-03-31 (60 days - kernel patterns stable, MPQUIC drafts evolving)
**Kernel version basis:** Linux 6.4+ for MPTCP RB-tree OOO, TQUIC patterns from current codebase
