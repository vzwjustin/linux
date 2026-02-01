# Phase 6: Scheduler Framework - Research

**Researched:** 2026-01-31
**Domain:** Linux kernel pluggable algorithm framework (multipath packet scheduling)
**Confidence:** HIGH

## Summary

This research investigates how to implement a pluggable scheduler framework for TQUIC multipath packet scheduling, following established Linux kernel patterns. The framework must support multiple scheduling algorithms (Round-robin, MinRTT, Weighted, Aggregate, BLEST, ECF) with runtime selection via sysctl and sockopt.

The Linux kernel has two highly relevant precedents: TCP congestion control (tcp_congestion_ops) and MPTCP packet scheduling (mptcp_sched_ops). Both use identical architectural patterns: a registration system with spinlock-protected linked lists, per-connection algorithm selection locked at establishment time, lifecycle hooks (init/release), and module support via module_get/put. MPTCP's scheduler pattern is the closer match since it deals with path selection rather than congestion response.

The standard approach uses:
- struct tquic_sched_ops with function pointers (get_path being required, others optional)
- Global DEFINE_SPINLOCK + LIST_HEAD for registration
- Per-network-namespace default scheduler (rcu_dereference on net->tquic.default_scheduler)
- Per-socket scheduler pointer locked at connection establishment
- Both sysctl (net.tquic.scheduler) and sockopt (SO_TQUIC_SCHEDULER) for configuration
- Built-in core schedulers, modular external schedulers allowed

**Primary recommendation:** Follow MPTCP's mptcp_sched_ops pattern exactly, adapting for TQUIC's primary+backup path return semantics and scheduler-specific private state needs.

## Standard Stack

The established libraries/tools for this domain:

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Linux kernel | 6.13+ | Pluggable algorithm framework | Only framework (kernel module) |
| spinlock_t | kernel API | Registration list protection | Universal kernel synchronization |
| RCU | kernel API | Lockless scheduler lookup | Standard for read-mostly data |
| module.h | kernel API | Modular scheduler support | Kernel module infrastructure |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| sysctl | kernel API | Per-netns default configuration | Global/namespace defaults |
| sockopt | kernel API | Per-socket configuration | Connection-specific overrides |
| jhash | kernel API | Unique scheduler key generation | Fast hash for name→key (TCP uses this) |
| bpf_try_module_get | kernel API | Safe module refcounting | Prevent unload while in use |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| MPTCP pattern | TCP congestion control pattern | MPTCP is closer match (path selection vs cwnd adjustment) |
| Spinlock list | RCU-only list | Need write-side synchronization for registration |
| Per-netns default | Global-only default | Breaks containerization, rejected |

**Installation:**
N/A - Kernel subsystem (no external dependencies)

## Architecture Patterns

### Recommended Project Structure
```
net/tquic/
├── sched.c              # Core scheduler framework (registration, lookup, init/release)
├── sched_rr.c           # Round-robin scheduler
├── sched_minrtt.c       # MinRTT scheduler
├── sched_weighted.c     # Weighted scheduler
├── sched_aggregate.c    # Aggregate scheduler (default)
├── sched_blest.c        # BLEST scheduler
├── sched_ecf.c          # ECF scheduler
include/net/
└── tquic.h              # struct tquic_sched_ops definition
```

### Pattern 1: Scheduler Operations Structure
**What:** Function pointer struct defining scheduler interface
**When to use:** Every scheduler implementation
**Example:**
```c
// Source: Adapted from include/net/mptcp.h (struct mptcp_sched_ops)
// and include/net/tcp.h (struct tcp_congestion_ops)

struct tquic_sched_ops {
	/* Fast path: called on every packet send (cache-line optimized) */

	/* Get path for next packet (REQUIRED)
	 * Returns: primary path + optional backup path
	 * Context: softirq, conn->lock held
	 */
	int (*get_path)(struct tquic_connection *conn,
			struct tquic_path **primary,
			struct tquic_path **backup,
			u32 flags);

	/* Slow path: lifecycle and event hooks */

	/* Initialize scheduler state (optional)
	 * Called at connection establishment
	 * Can allocate private state, store in conn->sched_priv
	 */
	void (*init)(struct tquic_connection *conn);

	/* Release scheduler state (optional)
	 * Called at connection teardown
	 * Must free conn->sched_priv if allocated
	 */
	void (*release)(struct tquic_connection *conn);

	/* Path lifecycle events (optional) */
	void (*path_added)(struct tquic_connection *conn,
			   struct tquic_path *path);
	void (*path_removed)(struct tquic_connection *conn,
			     struct tquic_path *path);

	/* Feedback events for adaptive schedulers (optional) */
	void (*ack_received)(struct tquic_connection *conn,
			     struct tquic_path *path,
			     u64 acked_seq);
	void (*loss_detected)(struct tquic_connection *conn,
			      struct tquic_path *path,
			      u64 lost_seq);

	/* Metadata */
	char name[TQUIC_SCHED_NAME_MAX];
	struct module *owner;
	struct list_head list;
} ____cacheline_aligned_in_smp;

#define TQUIC_SCHED_NAME_MAX 16
```

### Pattern 2: Registration System
**What:** Global list with spinlock protection and RCU for lookups
**When to use:** Scheduler framework core (sched.c)
**Example:**
```c
// Source: net/mptcp/sched.c and net/ipv4/tcp_cong.c

static DEFINE_SPINLOCK(tquic_sched_list_lock);
static LIST_HEAD(tquic_sched_list);

/* Find scheduler by name (must hold rcu_read_lock) */
struct tquic_sched_ops *tquic_sched_find(const char *name)
{
	struct tquic_sched_ops *sched, *ret = NULL;

	list_for_each_entry_rcu(sched, &tquic_sched_list, list) {
		if (!strcmp(sched->name, name)) {
			ret = sched;
			break;
		}
	}
	return ret;
}

/* Register new scheduler */
int tquic_register_scheduler(struct tquic_sched_ops *sched)
{
	int ret;

	ret = tquic_validate_scheduler(sched);
	if (ret)
		return ret;

	spin_lock(&tquic_sched_list_lock);
	if (tquic_sched_find(sched->name)) {
		pr_notice("%s already registered\n", sched->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&sched->list, &tquic_sched_list);
		pr_debug("%s registered\n", sched->name);
	}
	spin_unlock(&tquic_sched_list_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_register_scheduler);

void tquic_unregister_scheduler(struct tquic_sched_ops *sched)
{
	spin_lock(&tquic_sched_list_lock);
	list_del_rcu(&sched->list);
	spin_unlock(&tquic_sched_list_lock);

	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(tquic_unregister_scheduler);
```

### Pattern 3: Per-Connection Scheduler Assignment
**What:** Lock scheduler at connection establishment, prevent mid-connection changes
**When to use:** Connection initialization and sockopt handling
**Example:**
```c
// Source: net/ipv4/tcp_cong.c (tcp_init_congestion_control)
// and net/mptcp/sched.c (mptcp_init_sched)

int tquic_init_scheduler(struct tquic_connection *conn,
			 struct tquic_sched_ops *sched)
{
	if (!sched) {
		/* Use per-netns default */
		struct net *net = sock_net(conn->sk);
		rcu_read_lock();
		sched = rcu_dereference(net->tquic.default_scheduler);
		rcu_read_unlock();

		if (!sched)
			sched = &tquic_sched_aggregate; /* fallback */
	}

	if (!bpf_try_module_get(sched, sched->owner))
		return -EBUSY;

	conn->sched = sched;
	conn->sched_priv = NULL; /* Scheduler can allocate in init() */

	if (sched->init)
		sched->init(conn);

	pr_debug("conn=%p sched=%s\n", conn, sched->name);
	return 0;
}

void tquic_release_scheduler(struct tquic_connection *conn)
{
	struct tquic_sched_ops *sched = conn->sched;

	if (!sched)
		return;

	if (sched->release)
		sched->release(conn);

	conn->sched = NULL;
	conn->sched_priv = NULL;

	bpf_module_put(sched, sched->owner);
}
```

### Pattern 4: Sysctl Configuration (Per-Namespace Default)
**What:** Per-network-namespace default scheduler via sysctl
**When to use:** Sysctl registration for net.tquic.scheduler
**Example:**
```c
// Source: net/ipv4/tcp_cong.c (tcp_set_default_congestion_control)
// and net/ipv4/sysctl_net_ipv4.c

/* In struct netns_tquic (added to struct net) */
struct netns_tquic {
	struct tquic_sched_ops __rcu *default_scheduler;
	/* ... other per-netns state ... */
};

/* Sysctl handler */
static int tquic_set_default_scheduler(struct ctl_table *table, int write,
					void *buffer, size_t *lenp,
					loff_t *ppos)
{
	struct net *net = container_of(table->data, struct net,
				       tquic.default_scheduler);
	char name[TQUIC_SCHED_NAME_MAX];
	struct tquic_sched_ops *sched;
	const struct tquic_sched_ops *prev;
	int ret;

	if (!write)
		return proc_dostring(table, write, buffer, lenp, ppos);

	ret = proc_dostring(table, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	rcu_read_lock();
	sched = tquic_sched_find(name);
	if (!sched) {
		ret = -ENOENT;
	} else if (!bpf_try_module_get(sched, sched->owner)) {
		ret = -EBUSY;
	} else {
		prev = xchg(&net->tquic.default_scheduler, sched);
		if (prev)
			bpf_module_put(prev, prev->owner);
		ret = 0;
	}
	rcu_read_unlock();

	return ret;
}

static struct ctl_table tquic_net_table[] = {
	{
		.procname	= "scheduler",
		.maxlen		= TQUIC_SCHED_NAME_MAX,
		.mode		= 0644,
		.proc_handler	= tquic_set_default_scheduler,
	},
	{ }
};
```

### Pattern 5: Sockopt Configuration (Per-Socket Override)
**What:** SO_TQUIC_SCHEDULER sockopt to override per-socket before connection
**When to use:** Socket option handling (only before ESTABLISHED state)
**Example:**
```c
// Source: net/ipv4/tcp.c (do_tcp_setsockopt, TCP_CONGESTION case)

case SO_TQUIC_SCHEDULER: {
	char name[TQUIC_SCHED_NAME_MAX];
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_sched_ops *sched;
	int val;

	if (optlen < 1)
		return -EINVAL;

	val = strncpy_from_sockptr(name, optval,
				   min_t(long, TQUIC_SCHED_NAME_MAX - 1,
					 optlen));
	if (val < 0)
		return -EFAULT;
	name[val] = 0;

	/* Cannot change after connection established */
	if (tsk->conn && tsk->conn->state != TQUIC_CONN_STATE_IDLE)
		return -EISCONN;

	rcu_read_lock();
	sched = tquic_sched_find(name);
	if (!sched) {
		rcu_read_unlock();
		return -ENOENT;
	}

	/* Store for later initialization */
	tsk->requested_scheduler = sched;
	rcu_read_unlock();

	return 0;
}
```

### Pattern 6: Scheduler Implementation (Simple Example)
**What:** Concrete scheduler implementation (Round-robin)
**When to use:** Each scheduler algorithm
**Example:**
```c
// Source: Based on MPTCP default scheduler pattern

static int tquic_sched_rr_get_path(struct tquic_connection *conn,
				   struct tquic_path **primary,
				   struct tquic_path **backup,
				   u32 flags)
{
	struct tquic_path *path;
	u32 *rr_counter = conn->sched_priv;
	u32 idx = 0, target;

	if (list_empty(&conn->paths))
		return -ENOENT;

	/* Round-robin across active paths */
	target = (*rr_counter)++ % conn->num_active_paths;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		if (idx++ == target) {
			*primary = path;
			*backup = NULL; /* RR doesn't use backup */
			return 0;
		}
	}

	return -ENOENT;
}

static void tquic_sched_rr_init(struct tquic_connection *conn)
{
	u32 *counter = kzalloc(sizeof(*counter), GFP_KERNEL);
	if (counter) {
		*counter = 0;
		conn->sched_priv = counter;
	}
}

static void tquic_sched_rr_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

static struct tquic_sched_ops tquic_sched_rr = {
	.get_path	= tquic_sched_rr_get_path,
	.init		= tquic_sched_rr_init,
	.release	= tquic_sched_rr_release,
	.name		= "rr",
	.owner		= THIS_MODULE,
};

static int __init tquic_sched_rr_register(void)
{
	return tquic_register_scheduler(&tquic_sched_rr);
}
module_init(tquic_sched_rr_register);

static void __exit tquic_sched_rr_unregister(void)
{
	tquic_unregister_scheduler(&tquic_sched_rr);
}
module_exit(tquic_sched_rr_unregister);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Round-Robin Scheduler");
```

### Anti-Patterns to Avoid
- **Changing scheduler mid-connection:** Breaks invariants, creates race conditions. Lock at establishment like TCP congestion control.
- **Global-only default scheduler:** Breaks network namespace isolation. Use per-netns defaults.
- **Holding conn->lock during get_path():** Already held by caller, would deadlock. Document lock context.
- **Allocating memory in get_path():** Fast path, called per-packet. Use GFP_ATOMIC or pre-allocate in init().
- **Module unload without synchronize_rcu():** Can cause use-after-free. MPTCP/TCP pattern is synchronize_rcu() after list_del_rcu().

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Scheduler name→pointer lookup | Hash table or linear array | RCU-protected linked list with linear search | TCP/MPTCP use this pattern, < 10 schedulers makes linear fine |
| Module reference counting | Manual refcount | bpf_try_module_get/bpf_module_put | Handles BPF and regular modules, prevents unload races |
| Network namespace isolation | Custom per-socket config | struct netns_tquic in struct net | Kernel-wide pattern for per-netns state |
| Sysctl string handling | Custom parsing | proc_dostring + validation | Handles all edge cases (length, NUL termination, etc.) |
| RCU synchronization | Manual barriers | synchronize_rcu() | Kernel primitive, handles all memory orderings |

**Key insight:** The kernel already has battle-tested patterns for pluggable algorithms (TCP CC, MPTCP sched, net scheduler). Don't invent new mechanisms when existing ones fit perfectly.

## Common Pitfalls

### Pitfall 1: Forgetting to Lock Scheduler at Connection Establishment
**What goes wrong:** User changes sockopt after handshake starts, scheduler switches mid-flight, state inconsistency
**Why it happens:** Seems like flexibility to allow runtime changes
**How to avoid:**
- Check conn->state in sockopt handler, return -EISCONN if not IDLE
- Lock scheduler during tquic_init_scheduler(), never allow change after
- Document clearly in API: "scheduler must be set before connect/listen"
**Warning signs:** Crashes when scheduler release() is called with wrong private state type

### Pitfall 2: Not Handling Module Unload Correctly
**What goes wrong:** Scheduler module unloaded while connection still using it → crash
**Why it happens:** Forgot module_get/put or didn't synchronize_rcu() on unregister
**How to avoid:**
- Always bpf_try_module_get() in init, bpf_module_put() in release
- Always synchronize_rcu() after list_del_rcu() in unregister
- Test with: load module, create connection, unload module (should fail with -EBUSY)
**Warning signs:** Kernel oops on scheduler callback after module unload

### Pitfall 3: Memory Allocation in Fast Path (get_path)
**What goes wrong:** GFP_KERNEL allocation in softirq context → "sleeping function called from invalid context" BUG
**Why it happens:** get_path() called per packet from softirq, can't sleep
**How to avoid:**
- Pre-allocate all scheduler state in init() (GFP_KERNEL allowed there)
- Use GFP_ATOMIC in get_path() only if absolutely necessary
- Store state in conn->sched_priv (void pointer, scheduler owns)
**Warning signs:** BUG: scheduling while atomic, might_sleep() warnings

### Pitfall 4: Global State in Scheduler
**What goes wrong:** Multiple connections share state, breaks isolation, race conditions
**Why it happens:** Using static variables instead of per-connection state
**How to avoid:**
- All connection-specific state in conn->sched_priv (allocated in init, freed in release)
- Read-only global state OK (e.g., tunable parameters with module_param)
- Per-path state in path->sched_priv if needed
**Warning signs:** Scheduler works for one connection, breaks with multiple

### Pitfall 5: Not Validating Required Callbacks
**What goes wrong:** Scheduler registered without get_path() → NULL pointer dereference
**Why it happens:** Forgot to implement required callback
**How to avoid:**
- tquic_validate_scheduler() must check get_path != NULL (required)
- All other callbacks optional, check before calling: if (sched->init) sched->init(conn);
- Follow TCP pattern: return -EINVAL with pr_err if validation fails
**Warning signs:** Kernel NULL pointer dereference at scheduler->get_path()

### Pitfall 6: Network Namespace Leaks
**What goes wrong:** Parent netns default scheduler changes when child netns changes its default
**Why it happens:** Using global pointer instead of per-netns
**How to avoid:**
- Store default in struct netns_tquic, not global variable
- Use rcu_dereference(net->tquic.default_scheduler) for lookups
- Each netns gets independent default initialized to "aggregate"
**Warning signs:** Container isolation tests fail, scheduler changes leak across namespaces

## Code Examples

Verified patterns from official sources:

### MPTCP Scheduler Registration Pattern
```c
// Source: net/mptcp/sched.c
// URL: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/mptcp/sched.c

static DEFINE_SPINLOCK(mptcp_sched_list_lock);
static LIST_HEAD(mptcp_sched_list);

/* Must be called with rcu read lock held */
struct mptcp_sched_ops *mptcp_sched_find(const char *name)
{
	struct mptcp_sched_ops *sched, *ret = NULL;

	list_for_each_entry_rcu(sched, &mptcp_sched_list, list) {
		if (!strcmp(sched->name, name)) {
			ret = sched;
			break;
		}
	}

	return ret;
}

int mptcp_register_scheduler(struct mptcp_sched_ops *sched)
{
	int ret;

	ret = mptcp_validate_scheduler(sched);
	if (ret)
		return ret;

	spin_lock(&mptcp_sched_list_lock);
	if (mptcp_sched_find(sched->name)) {
		spin_unlock(&mptcp_sched_list_lock);
		return -EEXIST;
	}
	list_add_tail_rcu(&sched->list, &mptcp_sched_list);
	spin_unlock(&mptcp_sched_list_lock);

	pr_debug("%s registered\n", sched->name);
	return 0;
}

void mptcp_unregister_scheduler(struct mptcp_sched_ops *sched)
{
	if (sched == &mptcp_sched_default)
		return;

	spin_lock(&mptcp_sched_list_lock);
	list_del_rcu(&sched->list);
	spin_unlock(&mptcp_sched_list_lock);
}
```

### TCP Congestion Control Module Pattern
```c
// Source: net/ipv4/tcp_vegas.c
// URL: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/tcp_vegas.c

static struct tcp_congestion_ops tcp_vegas __read_mostly = {
	.init		= tcp_vegas_init,
	.ssthresh	= tcp_reno_ssthresh,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cong_avoid	= tcp_vegas_cong_avoid,
	.pkts_acked	= tcp_vegas_pkts_acked,
	.set_state	= tcp_vegas_state,
	.cwnd_event	= tcp_vegas_cwnd_event,
	.get_info	= tcp_vegas_get_info,

	.owner		= THIS_MODULE,
	.name		= "vegas",
};

static int __init tcp_vegas_register(void)
{
	BUILD_BUG_ON(sizeof(struct vegas) > ICSK_CA_PRIV_SIZE);
	tcp_register_congestion_control(&tcp_vegas);
	return 0;
}

static void __exit tcp_vegas_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_vegas);
}

module_init(tcp_vegas_register);
module_exit(tcp_vegas_unregister);

MODULE_AUTHOR("Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Vegas");
```

### TCP Congestion Control Sockopt Handling
```c
// Source: net/ipv4/tcp.c (do_tcp_setsockopt)
// URL: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/tcp.c

case TCP_CONGESTION: {
	char name[TCP_CA_NAME_MAX];

	if (optlen < 1)
		return -EINVAL;

	val = strncpy_from_sockptr(name, optval,
				min_t(long, TCP_CA_NAME_MAX-1, optlen));
	if (val < 0)
		return -EFAULT;
	name[val] = 0;

	sockopt_lock_sock(sk);
	err = tcp_set_congestion_control(sk, name, !has_current_bpf_ctx(),
					 sockopt_ns_capable(sock_net(sk)->user_ns,
							    CAP_NET_ADMIN));
	sockopt_release_sock(sk);
	return err;
}
```

## Scheduler Algorithms Research

### BLEST (Blocking Estimation-Based Scheduler)
**What:** Estimates blocking delay for each path, waits for fast path if it will finish sooner
**Algorithm:**
- Track inflight data per path
- Estimate completion time = (inflight + new_data) / bandwidth
- If fast path completion < slow path send time, wait for fast path
- Reduces head-of-line blocking at receiver

**Implementation guidance:**
- Per-path state: inflight bytes, last_send_time
- Need path_added/removed hooks to maintain state
- Need ack_received to update inflight tracking
- get_path(): Calculate completion time for each path, choose best

**References:**
- [BLEST: Blocking estimation-based MPTCP scheduler for heterogeneous networks (IFIP 2016)](https://dl.ifip.org/db/conf/networking/networking2016/1570234725.pdf)
- [Performance Analysis of Multipath QUIC Schedulers (Springer 2026)](https://link.springer.com/chapter/10.1007/978-3-032-10459-5_37)

### ECF (Earliest Completion First)
**What:** Selects path with earliest estimated completion time for next segment
**Algorithm:**
- For each path: est_completion = (inflight + segment_size) / send_rate + RTT
- Choose path with minimum est_completion
- Considers both bandwidth and RTT (not just RTT like MinRTT)
- Better utilization under path heterogeneity

**Implementation guidance:**
- Per-path state: send_rate (from BW estimation), inflight count
- More complex than BLEST: needs rate estimation
- Need ack_received for rate updates
- get_path(): Iterate paths, calculate completion, return minimum

**References:**
- [ECF: An MPTCP Path Scheduler to Manage Heterogeneous Paths (ACM SIGMETRICS 2017)](https://dl.acm.org/doi/10.1145/3143361.3143376)
- [MPTCP ECF Implementation (GitHub PR)](https://github.com/multipath-tcp/mptcp/pull/351/commits)

### MinRTT
**What:** Standard scheduler, sends on path with lowest RTT that has available cwnd
**Algorithm:**
- Iterate active paths
- Select path with min(RTT) where cwnd available
- Simple, fast, no per-path state needed

**Implementation guidance:**
- No sched_priv needed
- get_path() only: linear scan of paths, check path->stats.rtt_smoothed
- Tolerance band (Claude's discretion): send on path if RTT within X% of minimum (prevents flapping)

### Round-Robin
**What:** Distributes packets evenly across paths in round-robin order
**Algorithm:**
- Maintain counter, increment each send
- Select path[counter % num_paths]
- Equal distribution regardless of path quality

**Implementation guidance:**
- sched_priv: u32 counter
- init(): allocate counter, set to 0
- get_path(): counter++ % num_active_paths

### Weighted
**What:** Respects user-defined path priorities/weights
**Algorithm:**
- User sets per-path weight (0-255)
- Weighted round-robin: path selected proportional to weight
- Higher weight = more packets

**Implementation guidance:**
- Use path->weight (already in tquic_path struct)
- sched_priv: weighted RR state (token bucket or cumulative counter)
- get_path(): Weighted random or deficit round-robin

### Aggregate
**What:** Maximizes combined throughput across all paths (default scheduler)
**Algorithm:**
- Calculate per-path capacity weight from cwnd/RTT
- Send on path with highest available capacity
- Fill fastest paths first, overflow to slower paths
- 5% minimum weight enforcement (Claude's discretion): ensure slow paths get some traffic

**Implementation guidance:**
- get_path(): Calculate capacity = cwnd / RTT for each path, choose max
- Integration with Phase 5 bonding: use existing capacity calculation
- No sched_priv needed if using path->stats directly

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Global scheduler only | Per-netns default | ~2013 (netns support) | Container isolation |
| Manual module refcount | bpf_try_module_get | ~2020 (BPF integration) | Unified BPF+module handling |
| Custom lookup | RCU-protected list | ~2005 (RCU introduction) | Lockless fast path |
| Hardcoded schedulers | Pluggable framework | MPTCP v0.89+ | Extensibility |

**Deprecated/outdated:**
- Direct module_get/put: Use bpf_try_module_get/bpf_module_put (handles both BPF and regular modules)
- Global default scheduler: Always use per-netns (net->tquic.default_scheduler)
- Allowing mid-connection scheduler change: Locked at establishment (TCP pattern)

## Open Questions

1. **Primary + Backup Path Return Semantics**
   - What we know: User wants get_path() to return primary + optional backup for redundant send
   - What's unclear: Should backup be used automatically on primary failure, or only when TQUIC_SCHED_REDUNDANT flag set?
   - Recommendation: Backup used only with TQUIC_SCHED_REDUNDANT flag. Otherwise backup is advisory (for failover to pre-validate).

2. **Scheduler State Size Limit**
   - What we know: TCP uses BUILD_BUG_ON(sizeof(priv) > ICSK_CA_PRIV_SIZE) to enforce inline storage
   - What's unclear: Should TQUIC have fixed sched_priv size or allow dynamic allocation?
   - Recommendation: Allow dynamic allocation (conn->sched_priv is void*), no size limit. Simpler, more flexible for BLEST/ECF complex state.

3. **MinRTT Tolerance Band**
   - What we know: Pure minRTT can cause path flapping when RTTs are similar
   - What's unclear: What tolerance % is appropriate?
   - Recommendation: Start with 10% tolerance (if path RTT within 10% of minimum, keep current path). Make it a module parameter for tuning.

4. **Path Skip Criteria**
   - What we know: Schedulers should be able to skip paths (degraded, no cwnd, etc.)
   - What's unclear: Should framework enforce common skip logic or leave to each scheduler?
   - Recommendation: Framework provides helper (tquic_path_can_send(path)) that checks state, cwnd. Schedulers can use or override.

5. **Aggregate Scheduler 5% Minimum Weight**
   - What we know: User wants some traffic on slow paths to prevent complete starvation
   - What's unclear: 5% of what? Total weight? Total packets?
   - Recommendation: 5% of total capacity weight. If slow path falls below 5% of total, boost to 5%. Prevents complete starvation while maximizing fast path use.

## Sources

### Primary (HIGH confidence)
- Linux kernel source (v6.13): net/mptcp/sched.c, net/ipv4/tcp_cong.c, include/net/mptcp.h, include/net/tcp.h
- MPTCP scheduler implementation pattern (built-in kernel code)
- TCP congestion control framework (built-in kernel code)
- Network namespace sysctl infrastructure (net/ipv4/sysctl_net_ipv4.c)

### Secondary (MEDIUM confidence)
- [BLEST: Blocking estimation-based MPTCP scheduler for heterogeneous networks (IFIP 2016)](https://dl.ifip.org/db/conf/networking/networking2016/1570234725.pdf)
- [ECF: An MPTCP Path Scheduler to Manage Heterogeneous Paths (ACM SIGMETRICS 2017)](https://dl.acm.org/doi/10.1145/3143361.3143376)
- [Performance Analysis of Multipath QUIC Schedulers for Video Streaming over Hybrid 5G-Satcom Networks (Springer 2026)](https://link.springer.com/chapter/10.1007/978-3-032-10459-5_37)
- [MPTCP scheduler evaluation research (ArXiv 2024)](https://arxiv.org/html/2511.14550v1)

### Tertiary (LOW confidence)
- WebSearch results on MPTCP scheduler comparison (multiple sources, 2024-2026)
- Community discussions on round-robin vs minRTT tradeoffs

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Direct examination of kernel source code (MPTCP, TCP patterns)
- Architecture: HIGH - Patterns verified in net/mptcp/sched.c and net/ipv4/tcp_cong.c
- Pitfalls: HIGH - Known issues from kernel code comments and locking documentation
- BLEST/ECF algorithms: MEDIUM - Academic papers describe algorithms but implementation details require interpretation
- Sysctl/sockopt: HIGH - Pattern verified in sysctl_net_ipv4.c and tcp.c

**Research date:** 2026-01-31
**Valid until:** ~2026-03-31 (30 days - kernel patterns are stable, but scheduler research is active)
