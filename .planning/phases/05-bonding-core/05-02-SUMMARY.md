# Phase 5 Plan 02: Adaptive Reorder Buffer Summary

---
phase: 05-bonding-core
plan: 02
subsystem: wan-bonding
tags: [rbtree, reorder, multipath, latency, bonding]
requires:
  - 05-01  # Bonding state machine (provides context for buffer lifecycle)
provides:
  - RB-tree reorder buffer with O(log n) insertion
  - Adaptive sizing based on RTT spread
  - Gap timeout for heterogeneous latencies
  - Memory limit enforcement
affects:
  - 06-scheduler  # Uses reorder buffer for packet reassembly
  - 07-congestion  # RTT spread affects timeout tuning
tech-stack:
  added: []
  patterns:
    - RB-tree packet ordering (MPTCP out_of_order_queue pattern)
    - SKB control block for sequence tracking
    - Adaptive timeout based on path RTT spread
key-files:
  created:
    - net/quic/tquic_reorder.h
    - net/quic/tquic_reorder.c
  modified:
    - net/quic/tquic_bonding.h
    - net/quic/tquic_bonding.c
    - net/quic/Makefile
decisions:
  - key: rbtree-for-reorder
    choice: RB-tree with rb_root
    rationale: O(log n) insertion critical for 600ms latency spread with many buffered packets
  - key: last-skb-fast-path
    choice: Tail insertion optimization via last_skb pointer
    rationale: Nearly-in-order packets (common case) skip tree traversal
  - key: gap-timeout-formula
    choice: "2 * rtt_spread + 100ms"
    rationale: Handles worst-case where slow path packet arrives after fast path delivered many
  - key: default-buffer-256kb
    choice: 256KB default, 4MB max
    rationale: Balances memory usage with 600ms spread requirement at 1Gbps
  - key: lazy-allocation
    choice: Allocate buffer in BOND_PENDING/ACTIVE states only
    rationale: No memory overhead for single-path connections
metrics:
  duration: ~5m
  completed: 2026-01-31
---

**One-liner:** RB-tree reorder buffer with O(log n) insertion, adaptive timeout for 600ms latency spread (fiber+satellite), lazy allocation on bonding activation.

## What Was Built

Implemented the adaptive RB-tree reorder buffer for handling packet reordering across heterogeneous latency paths, enabling true bandwidth aggregation for TQUIC WAN bonding.

### Key Components

1. **tquic_reorder.h** - Header with structures and API
   - `struct tquic_reorder_buffer` with `rb_root` queue
   - `struct tquic_reorder_cb` for SKB sequence tracking
   - `struct tquic_reorder_stats` for diagnostics
   - Configuration constants for buffer sizing

2. **tquic_reorder.c** - RB-tree buffer implementation
   - O(log n) insertion with `rb_insert_color`
   - Fast path: in-order packets returned immediately
   - Fast path: tail insertion via `last_skb` pointer
   - Gap timeout handler for stuck packets
   - Memory limit enforcement with `-ENOBUFS` backpressure
   - Adaptive sizing based on RTT spread

3. **Bonding Integration** - Wired to state machine
   - Buffer allocated on BOND_PENDING/ACTIVE transition
   - Buffer freed on SINGLE_PATH transition
   - `tquic_bonding_update_rtt_spread()` for timeout adaptation
   - Dedicated workqueue for timeout work

### Design Patterns

- **MPTCP out_of_order_queue pattern**: RB-tree indexed by sequence number
- **SKB control block**: Metadata stored in skb->cb for zero-copy
- **Adaptive timeout**: 2 * (max_rtt - min_rtt) + 100ms margin
- **Lazy allocation**: No buffer for single-path connections

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | ec2a43b38 | Add RB-tree reorder buffer header |
| 2 | 6dc266bcd | Implement RB-tree reorder buffer core |
| 3 | 299e12585 | Wire reorder buffer to bonding context |

## API Surface

### Lifecycle
```c
struct tquic_reorder_buffer *tquic_reorder_alloc(gfp_t gfp);
int tquic_reorder_init(struct tquic_reorder_buffer *rb, size_t max_bytes,
                       struct workqueue_struct *wq, void *priv);
void tquic_reorder_destroy(struct tquic_reorder_buffer *rb);
```

### Core Operations
```c
int tquic_reorder_insert(struct tquic_reorder_buffer *rb, struct sk_buff *skb,
                         u64 seq, u32 len, u8 path_id);
// Returns: 1 = delivered immediately, 0 = buffered, <0 = error

int tquic_reorder_drain(struct tquic_reorder_buffer *rb,
                        void (*deliver)(void *ctx, struct sk_buff *skb),
                        void *ctx);
// Returns: number of packets delivered

void tquic_reorder_flush_timeout(struct tquic_reorder_buffer *rb,
                                 void (*deliver)(void *ctx, struct sk_buff *skb),
                                 void *ctx);
```

### Adaptive Configuration
```c
void tquic_reorder_update_timeout(struct tquic_reorder_buffer *rb, u32 timeout_ms);
void tquic_reorder_update_rtt(struct tquic_reorder_buffer *rb,
                              u32 path_rtt_us, bool is_min);
void tquic_reorder_adapt_size(struct tquic_reorder_buffer *rb,
                              u64 aggregate_bandwidth);
```

## Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Data structure | RB-tree | O(log n) insertion handles high packet counts with 600ms spread |
| Fast path optimization | last_skb tail pointer | Nearly-in-order packets (common) skip tree traversal |
| Gap timeout formula | 2 * spread + 100ms | Handles worst-case slow path arrival |
| Default buffer size | 256KB | Balances memory with 600ms * 1Gbps requirement |
| Allocation strategy | Lazy on BOND_PENDING | No overhead for single-path connections |
| Memory limit action | Return -ENOBUFS | Backpressure rather than dropping silently |

## Deviations from Plan

None - plan executed exactly as written. The prerequisite tquic_bonding.h/c files from plan 05-01 were already present in the codebase, enabling direct integration.

## Verification Results

All success criteria verified:
- [x] tquic_reorder.h exists with rb_root based structure
- [x] tquic_reorder.c implements RB-tree insert/drain/timeout
- [x] Fast path for in-order packets (return 1, don't buffer)
- [x] Fast path for tail insertion (last_skb optimization)
- [x] Gap timeout releases stuck packets
- [x] Memory limit prevents unbounded growth
- [x] Adaptive sizing based on RTT spread
- [x] Bonding context creates/destroys reorder buffer
- [x] All EXPORT_SYMBOL_GPL for public API (10 exports)

## Next Phase Readiness

**Ready for Phase 05-03 (Failover):** The reorder buffer provides the data plane foundation for handling out-of-order packets during path failover. When packets from a failed path arrive after retransmission on another path, the buffer correctly handles duplicates and sequence gaps.

**Ready for Phase 06 (Scheduler):** Schedulers can use `tquic_bonding_get_reorder()` to access the buffer for packet insertion on receive path.

**Integration points for Phase 07 (Congestion):**
- `tquic_bonding_update_rtt_spread()` should be called when path RTT measurements update
- Buffer timeout auto-adapts to observed RTT spread

## Files Changed

| File | Change Type | Purpose |
|------|-------------|---------|
| net/quic/tquic_reorder.h | Created | RB-tree buffer types and API |
| net/quic/tquic_reorder.c | Created | Buffer implementation (568 lines) |
| net/quic/tquic_bonding.h | Modified | Added reorder integration helpers |
| net/quic/tquic_bonding.c | Modified | Wired buffer lifecycle to state machine |
| net/quic/Makefile | Modified | Added tquic_reorder.o |

---

*Plan completed: 2026-01-31*
*Duration: ~5 minutes*
*Executor: Claude Opus 4.5*
