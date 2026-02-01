# Phase 02: Socket API Completion - Research

**Researched:** 2026-01-31
**Domain:** Linux kernel socket implementation, QUIC protocol, TLS 1.3 integration
**Confidence:** MEDIUM-HIGH

## Summary

Socket API completion for TQUIC requires implementing the standard BSD socket operations (connect, listen, accept, sendmsg, recvmsg) following kernel patterns established by MPTCP. The key challenges are TLS 1.3 handshake integration, stream multiplexing within kernel socket abstractions, and connection ID management for migration.

The MPTCP subsystem provides the canonical pattern: a `struct proto` with operation callbacks, `struct proto_ops` for socket-level operations, and careful lock hierarchy management. MPTCP demonstrates how to layer a new transport protocol over existing UDP/TCP infrastructure using subflows.

For TQUIC, Phase 1 established IPPROTO_TQUIC=263 and lockdep infrastructure. Phase 2 builds on this by implementing connection lifecycle (connect/listen/accept), TLS handshake (delegated to userspace via net/handshake), stream multiplexing (using ioctl to create stream file descriptors), and connection ID management for migration.

**Primary recommendation:** Follow MPTCP's architectural pattern with proto/proto_ops structures, delegate TLS handshake to userspace via net/handshake interface (like NFS over TLS), implement stream multiplexing using ioctl TQUIC_NEW_STREAM to create child stream file descriptors, and use dedicated QUIC error codes (EQUIC*) that map to RFC 9000 transport errors.

## Standard Stack

### Core Kernel Subsystems

| Component | Version | Purpose | Why Standard |
|-----------|---------|---------|--------------|
| net/handshake | Kernel 5.19+ | TLS handshake delegation to userspace | Used by NFS over TLS, SMB over TLS |
| kTLS (net/tls) | Kernel 4.13+ | In-kernel TLS symmetric encryption | Industry standard for TLS acceleration |
| MPTCP subsystem | Kernel 5.6+ | Multipath socket implementation pattern | Reference architecture for connection-oriented protocols |
| UDP encapsulation | Core | QUIC transport over UDP | Required by RFC 9000 |

### Supporting Infrastructure

| Component | Version | Purpose | When to Use |
|-----------|---------|---------|-------------|
| RCU (Read-Copy-Update) | Core | Lock-free stream lookup | Stream hash table access |
| rhashtable | Core | Resizable hash tables | Connection ID lookup |
| netlink/genetlink | Core | Userspace path management | Path manager communication |
| lockdep | Core | Lock validation | Socket lock hierarchy verification |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| net/handshake | In-kernel TLS 1.3 | Requires kernel crypto complexity, security surface in kernel |
| ioctl for streams | sendmsg with stream ID in ancillary data | No first-class stream file descriptors for poll/epoll |
| EQUIC* error codes | Reuse ECONNREFUSED/ETIMEDOUT | Loses QUIC-specific error semantics |

**Installation:**
No external dependencies - all kernel subsystems.

## Architecture Patterns

### Recommended Project Structure

```
net/tquic/
├── tquic_proto.c         # struct proto, socket lifecycle
├── tquic_socket.c        # struct proto_ops, BSD socket ops
├── tquic_handshake.c     # TLS 1.3 handshake via net/handshake
├── tquic_stream.c        # Stream multiplexing, ioctl
├── tquic_cid.c           # Connection ID management
├── tquic_migration.c     # Connection migration logic
├── protocol.h            # Internal structures, lock docs
include/uapi/linux/
└── tquic.h               # UAPI definitions, ioctl codes
```

### Pattern 1: Socket Operations Structure (MPTCP Pattern)

**What:** Define `struct proto` with lifecycle callbacks and `struct proto_ops` with BSD socket operations.

**When to use:** For all connection-oriented kernel protocols.

**Example:**
```c
// Source: net/mptcp/protocol.c:4010
static struct proto tquic_prot = {
	.name		= "TQUIC",
	.owner		= THIS_MODULE,
	.init		= tquic_init_sock,
	.connect	= tquic_connect,
	.disconnect	= tquic_disconnect,
	.close		= tquic_close,
	.accept		= tquic_accept,
	.setsockopt	= tquic_setsockopt,
	.getsockopt	= tquic_getsockopt,
	.shutdown	= tquic_shutdown,
	.destroy	= tquic_destroy,
	.sendmsg	= tquic_sendmsg,
	.recvmsg	= tquic_recvmsg,
	.ioctl		= tquic_ioctl,
	.hash		= tquic_hash,
	.unhash		= tquic_unhash,
	.get_port	= tquic_get_port,
	.obj_size	= sizeof(struct tquic_sock),
};

static const struct proto_ops tquic_stream_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= inet_release,
	.bind		= tquic_bind,
	.connect	= inet_stream_connect,  // Wraps tquic_prot.connect
	.accept		= tquic_stream_accept,
	.listen		= tquic_listen,
	.sendmsg	= inet_sendmsg,
	.recvmsg	= inet_recvmsg,
	.ioctl		= inet_ioctl,
	.poll		= tquic_poll,
	// ... standard ops
};
```

### Pattern 2: Handshake Delegation to Userspace

**What:** Use net/handshake netlink interface to delegate TLS 1.3 handshake to userspace daemon (tlshd).

**When to use:** When TLS handshake complexity should not be in kernel.

**Example:**
```c
// Source: Kernel TLS documentation, lxin/tls_hs pattern
// In tquic_connect():
struct tls_handshake_args args = {
	.ta_sock = sock,
	.ta_done = tquic_handshake_done,
	.ta_timeout_ms = 30000,  // Fixed 30s timeout per CONTEXT.md
};

// Initiate handshake (async)
ret = tls_client_hello_x509(&args, GFP_KERNEL);
if (ret < 0)
	return ret;

// Callback when handshake completes:
static void tquic_handshake_done(void *data, int status, key_serial_t peerid)
{
	struct sock *sk = data;
	struct tquic_sock *tsk = tquic_sk(sk);

	if (status == 0) {
		// Handshake successful, extract keys
		tquic_install_crypto_state(sk);
		tsk->flags |= TQUIC_F_HANDSHAKE_DONE;
		mptcp_set_state(sk, TCP_ESTABLISHED);
	} else {
		// Handshake failed
		tquic_set_state(sk, TCP_CLOSE);
		sk->sk_err = ECONNREFUSED;
	}
	sk->sk_state_change(sk);
}
```

### Pattern 3: Stream Multiplexing via ioctl

**What:** Create child stream sockets as file descriptors using ioctl, allowing streams to work with poll/epoll/select.

**When to use:** When protocol supports multiple independent byte streams over single connection.

**Example:**
```c
// UAPI definition in include/uapi/linux/tquic.h
#define TQUIC_NEW_STREAM   _IOWR('Q', 1, struct tquic_stream_args)

struct tquic_stream_args {
	__u64 stream_id;        // OUT: assigned stream ID
	__u32 flags;            // IN: TQUIC_STREAM_BIDI or TQUIC_STREAM_UNIDI
	__u32 reserved;
};

// In tquic_ioctl():
static int tquic_ioctl(struct sock *sk, int cmd, int *karg)
{
	switch (cmd) {
	case TQUIC_NEW_STREAM: {
		struct tquic_stream_args args;
		struct socket *stream_sock;
		int stream_fd;

		if (copy_from_user(&args, uarg, sizeof(args)))
			return -EFAULT;

		// Block if at stream limit (per CONTEXT.md decision)
		ret = tquic_wait_for_stream_credit(sk, args.flags);
		if (ret < 0)
			return ret;

		// Create new stream socket
		ret = tquic_create_stream_socket(sk, &args, &stream_sock);
		if (ret < 0)
			return ret;

		// Install as file descriptor
		stream_fd = sock_map_fd(stream_sock, 0);
		if (stream_fd < 0) {
			sock_release(stream_sock);
			return stream_fd;
		}

		args.stream_id = stream_sock->stream_id;
		if (copy_to_user(uarg, &args, sizeof(args))) {
			close_fd(stream_fd);
			return -EFAULT;
		}

		return stream_fd;  // Return fd as ioctl result
	}
	default:
		return -ENOIOCTLCMD;
	}
}
```

### Pattern 4: Connection ID Management (RFC 9000)

**What:** Maintain pool of connection IDs with sequence numbers, support retirement and migration.

**When to use:** For QUIC connection ID de-multiplexing and migration.

**Example:**
```c
// Source: RFC 9000 Section 5.1, quic-go connection-migration patterns
struct tquic_cid_pool {
	struct rhashtable cid_table;     // Hash: CID -> connection
	spinlock_t lock;
	u64 next_seq_num;
	u8 active_cid_limit;             // From peer's active_connection_id_limit
};

// Issue new connection ID
static int tquic_issue_cid(struct tquic_connection *conn, struct tquic_cid *cid)
{
	spin_lock_bh(&conn->cid_pool.lock);

	if (conn->cid_pool.issued_count >= conn->cid_pool.active_cid_limit) {
		spin_unlock_bh(&conn->cid_pool.lock);
		return -ENOSPC;  // At CID limit
	}

	cid->seq_num = conn->cid_pool.next_seq_num++;
	get_random_bytes(cid->id, TQUIC_DEFAULT_CID_LEN);
	cid->len = TQUIC_DEFAULT_CID_LEN;

	// Add to hash table
	rhashtable_insert_fast(&conn->cid_pool.cid_table,
	                       &cid->node, cid_rht_params);
	conn->cid_pool.issued_count++;

	spin_unlock_bh(&conn->cid_pool.lock);

	// Send NEW_CONNECTION_ID frame to peer
	tquic_send_new_connection_id(conn, cid);

	return 0;
}

// Retire old connection ID
static void tquic_retire_cid(struct tquic_connection *conn, u64 seq_num)
{
	struct tquic_cid *cid;

	spin_lock_bh(&conn->cid_pool.lock);
	cid = tquic_find_cid_by_seq(conn, seq_num);
	if (cid) {
		rhashtable_remove_fast(&conn->cid_pool.cid_table,
		                       &cid->node, cid_rht_params);
		conn->cid_pool.issued_count--;
		kfree_rcu(cid, rcu);
	}
	spin_unlock_bh(&conn->cid_pool.lock);
}
```

### Pattern 5: Connection Migration with Path Validation

**What:** Automatic migration on NAT rebind, explicit migration via sockopt, immediate PATH_CHALLENGE.

**When to use:** When source address changes or migration is explicitly requested.

**Example:**
```c
// Source: RFC 9000 Section 8, CONTEXT.md migration decisions
// Automatic migration on receiving packet from new source
static void tquic_handle_migration(struct tquic_connection *conn,
                                   struct sockaddr_storage *new_addr)
{
	struct tquic_path *new_path;

	// Check if migration allowed
	if (!conn->migration_enabled)
		return;  // Drop packet

	// Allocate new path
	new_path = tquic_path_create(conn, new_addr);
	if (!new_path)
		return;

	// Immediate path validation (per CONTEXT.md)
	tquic_send_path_challenge(conn, new_path);
	new_path->state = TQUIC_PATH_PENDING;

	// Don't switch active_path until PATH_RESPONSE received
	spin_lock_bh(&conn->lock);
	list_add(&new_path->list, &conn->paths);
	spin_unlock_bh(&conn->lock);
}

// Explicit migration via setsockopt (per CONTEXT.md)
static int tquic_migrate_explicit(struct sock *sk, struct sockaddr *new_addr)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_path *new_path;

	lock_sock(sk);

	// Create path for new address
	new_path = tquic_path_create(conn, new_addr);
	if (!new_path) {
		release_sock(sk);
		return -ENOMEM;
	}

	// Issue new connection ID for migration
	ret = tquic_issue_cid(conn, &new_path->local_cid);
	if (ret < 0) {
		tquic_path_free(new_path);
		release_sock(sk);
		return ret;
	}

	// Immediate PATH_CHALLENGE (per CONTEXT.md)
	tquic_send_path_challenge(conn, new_path);

	// Switch to new path immediately (explicit migration)
	spin_lock_bh(&conn->lock);
	conn->active_path = new_path;
	list_add(&new_path->list, &conn->paths);
	spin_unlock_bh(&conn->lock);

	release_sock(sk);
	return 0;
}
```

### Anti-Patterns to Avoid

- **Holding socket lock during handshake:** MPTCP releases subflow lock during connect to avoid blocking. Handshake is asynchronous via net/handshake.
- **Manual TLS state machine in kernel:** Use net/handshake delegation. In-kernel TLS is complex and security-sensitive.
- **Reusing TCP state transitions:** QUIC has different state machine (IDLE->CONNECTING->HANDSHAKE->CONNECTED). Don't force-fit TCP states.
- **Stream state in sendmsg ancillary data only:** Creates no stream file descriptors. Use ioctl to create child stream sockets for poll/epoll support.
- **Holding multiple stream locks:** Can deadlock. Use connection lock for multi-stream operations.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| TLS 1.3 handshake | Custom crypto state machine | net/handshake + tlshd | Security-audited, used by NFS/SMB, keeps crypto out of kernel |
| Connection ID hash table | Linear search or custom hash | rhashtable | Resizable, RCU-safe, optimized for network code |
| Stream lookup | Array or linked list | RCU hash table with stream ID key | Lock-free reads, scales to 2^60 streams |
| Error code mapping | Custom error translation | Define EQUIC* errno range | Preserves QUIC semantics per CONTEXT.md |
| Socket lock hierarchy | Ad-hoc spinlocks | Follow MPTCP pattern with lockdep | Prevents deadlocks, validated by lockdep |
| Migration path validation | Custom probing | RFC 9000 PATH_CHALLENGE/PATH_RESPONSE | Standardized, prevents address spoofing |

**Key insight:** Kernel networking code has established patterns for TLS offload (kTLS), handshake delegation (net/handshake), and multipath protocols (MPTCP). Reusing these prevents security bugs and benefits from existing review.

## Common Pitfalls

### Pitfall 1: Socket State Machine Confusion During Handshake

**What goes wrong:** Setting socket to TCP_ESTABLISHED before TLS handshake completes, or leaving in intermediate state after handshake failure. This causes userspace to attempt I/O on non-ready socket.

**Why it happens:** QUIC handshake is asynchronous (delegated to tlshd). Socket state must track actual connection readiness.

**How to avoid:**
- Set state to TCP_SYN_SENT in tquic_connect() before initiating handshake
- Only transition to TCP_ESTABLISHED in handshake completion callback after keys installed
- On handshake failure, set TCP_CLOSE and sk->sk_err appropriately
- Use blocking connect() that waits for handshake (per CONTEXT.md decision)

**Warning signs:**
- sendmsg() returns ENOTCONN after connect() returns success
- Socket appears connected but has no crypto keys
- Lockdep warnings about state transitions in softirq context

### Pitfall 2: Stream Limit Exhaustion Without Blocking

**What goes wrong:** ioctl(TQUIC_NEW_STREAM) returns -ENOSPC when peer's max_streams limit reached, forcing userspace to poll-retry.

**Why it happens:** RFC 9000 stream limits are negotiated. Can't create more streams until peer sends MAX_STREAMS frame.

**How to avoid:**
- Block in ioctl until stream credit available (per CONTEXT.md decision)
- Use wait queue woken by MAX_STREAMS frame reception
- Support O_NONBLOCK flag for non-blocking ioctl variant
- Return -EINTR if interrupted

**Warning signs:**
- Userspace busy-loops retrying ioctl
- "Too many open streams" errors under load
- Performance degradation when approaching limits

### Pitfall 3: Connection ID Reuse During Migration

**What goes wrong:** Reusing retired connection ID for migration allows on-path observers to link old and new paths, breaking privacy.

**Why it happens:** Connection ID pool management doesn't track retired CIDs properly, or migration code picks CID from active pool without checking retirement state.

**How to avoid:**
- Use fresh connection ID for each migration (RFC 9000 requirement)
- Mark CIDs as retired in hash table before removal
- Pre-allocate CID pool during handshake
- Validate seq_num ordering (never reuse lower seq_num)

**Warning signs:**
- Privacy leak: observer can track connection across network changes
- RETIRE_CONNECTION_ID frames not sent
- rhashtable corruption under migration

### Pitfall 4: Handshake Timeout Configuration Per-Socket

**What goes wrong:** Exposing per-socket handshake timeout via setsockopt creates DoS vector (clients requesting extreme timeouts).

**Why it happens:** Trying to provide flexibility similar to TCP_USER_TIMEOUT.

**How to avoid:**
- Fixed 30-second kernel handshake timeout (per CONTEXT.md decision)
- Reject setsockopt attempts to change it (return -ENOPROTOOPT)
- Document in manpage that timeout is not configurable
- Userspace can implement own timeout via alarm/timerfd

**Warning signs:**
- setsockopt(TQUIC_HANDSHAKE_TIMEOUT) accepted but ignored
- Inconsistent timeout behavior across sockets
- Resource exhaustion from slow handshakes

### Pitfall 5: Lock Ordering Violation in Migration Path

**What goes wrong:** Migration callback from softirq holds conn->lock, then attempts lock_sock() to update socket state. But lock_sock() can sleep, and softirq context cannot sleep → kernel BUG.

**Why it happens:** Migration triggered by packet reception in softirq, but socket updates need process context lock.

**How to avoid:**
- Check sock_owned_by_user() in softirq
- If locked, defer migration to release_cb or workqueue
- Follow MPTCP's delegated_action pattern for deferred work
- Never call lock_sock() from softirq/BH context

**Warning signs:**
- "BUG: scheduling while atomic" in migration path
- Lockdep warnings about lock nesting
- Deadlocks under migration stress test

### Pitfall 6: EPIPE Without SIGPIPE on Stream Close

**What goes wrong:** sendmsg() to closed stream returns -EPIPE but doesn't send SIGPIPE to process, breaking TCP compatibility.

**Why it happens:** Forgot to check sock_flag(sk, SOCK_NOSIGPIPE) and send_sig() in error path.

**How to avoid:**
- In tquic_sendmsg(), check stream state before transmission
- If stream closed/reset, set err = -EPIPE
- Call send_sig(SIGPIPE, current, 0) unless MSG_NOSIGNAL or SOCK_NOSIGPIPE
- Match TCP behavior exactly (per CONTEXT.md decision)

**Warning signs:**
- Userspace expecting signal doesn't receive it
- Inconsistent error behavior vs TCP
- Shell scripts don't terminate on broken pipe

### Pitfall 7: Amplification Attack During Handshake

**What goes wrong:** Server sends large responses before validating client address, enabling amplification DDoS.

**Why it happens:** Responding to Initial packets without address validation.

**How to avoid:**
- Limit response to 3x received bytes before address validated
- Use QUIC Retry packet with token for address validation
- Track anti-amplification limit per source address
- Reset limit after successful handshake

**Warning signs:**
- Server sends multi-packet responses to single Initial packet
- No Retry packets sent in listen path
- Amplification factor > 3 in tests

## Code Examples

### Connect and Blocking Handshake

```c
// Source: net/mptcp/protocol.c:3932, adapted for TQUIC with handshake
static int tquic_connect(struct sock *sk, struct sockaddr_unsized *uaddr,
                        int addr_len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn;
	int err;

	lock_sock(sk);

	// Allocate connection state
	conn = tquic_connection_alloc(sk);
	if (!conn) {
		err = -ENOMEM;
		goto unlock;
	}
	tsk->conn = conn;

	// Generate initial connection IDs
	tquic_generate_cid(&conn->scid, TQUIC_DEFAULT_CID_LEN);

	// Set state before handshake
	tquic_set_state(sk, TCP_SYN_SENT);

	// Store peer address
	memcpy(&conn->peer_addr, uaddr, addr_len);

	// Initiate TLS handshake (async, via net/handshake)
	err = tquic_start_handshake(sk);
	if (err < 0)
		goto close;

	// Blocking connect waits for handshake (per CONTEXT.md)
	if (!tsk->flags & TQUIC_F_HANDSHAKE_DONE) {
		err = tquic_wait_for_handshake(sk, 30000);  // 30s timeout
		if (err < 0)
			goto close;
	}

	// Handshake complete, copy addresses
	tquic_copy_inaddrs(sk);

	release_sock(sk);
	return 0;

close:
	tquic_set_state(sk, TCP_CLOSE);
	tquic_connection_free(conn);
	tsk->conn = NULL;
unlock:
	release_sock(sk);
	return err;
}
```

### Listen and Accept with Handshake

```c
// Source: net/mptcp/protocol.c:4070, 4173
static int tquic_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	int err;

	lock_sock(sk);

	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM) {
		err = -EINVAL;
		goto unlock;
	}

	// Transition to LISTEN
	tquic_set_state(sk, TCP_LISTEN);

	// Initialize accept queue
	err = tquic_init_accept_queue(sk, backlog);
	if (err < 0)
		goto unlock;

	// Register with UDP demux for incoming packets
	err = tquic_register_listener(sk);

unlock:
	release_sock(sk);
	return err;
}

static int tquic_stream_accept(struct socket *sock, struct socket *newsock,
                               struct proto_accept_arg *arg)
{
	struct sock *sk = sock->sk, *newsk;
	struct tquic_sock *newtsk;

	// Wait for incoming connection (may block)
	newsk = tquic_accept_queue_get(sk, arg->flags, &err);
	if (!newsk)
		return err;

	newtsk = tquic_sk(newsk);

	// Handshake already completed in background
	// (tlshd handles server handshake on accept queue entries)
	if (!(newtsk->flags & TQUIC_F_HANDSHAKE_DONE)) {
		sock_put(newsk);
		return -ECONNABORTED;
	}

	// Attach to new socket structure
	sock_graft(newsk, newsock);

	return 0;
}
```

### Stream Creation via ioctl

```c
// UAPI header: include/uapi/linux/tquic.h
#define TQUIC_NEW_STREAM   _IOWR('Q', 1, struct tquic_stream_args)
#define TQUIC_STREAM_BIDI  0x00
#define TQUIC_STREAM_UNIDI 0x01

struct tquic_stream_args {
	__u64 stream_id;   // OUT: assigned stream ID
	__u32 flags;       // IN: stream type flags
	__u32 reserved;
};

// Implementation in net/tquic/tquic_stream.c
static int tquic_ioctl(struct sock *sk, int cmd, void __user *uarg)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	switch (cmd) {
	case TQUIC_NEW_STREAM: {
		struct tquic_stream_args args;
		struct socket *stream_sock;
		struct tquic_stream *stream;
		int stream_fd;

		if (copy_from_user(&args, uarg, sizeof(args)))
			return -EFAULT;

		// Validate flags
		if (args.flags > TQUIC_STREAM_UNIDI)
			return -EINVAL;

		// Block until stream credit available (per CONTEXT.md)
		ret = wait_event_interruptible(tsk->conn->stream_wq,
			tquic_can_open_stream(tsk->conn, args.flags));
		if (ret < 0)
			return -EINTR;

		// Allocate stream
		stream = tquic_stream_create(tsk->conn, args.flags);
		if (!stream)
			return -ENOMEM;

		// Create socket for stream
		ret = sock_create(sk->sk_family, SOCK_STREAM,
		                  IPPROTO_TQUIC, &stream_sock);
		if (ret < 0) {
			tquic_stream_free(stream);
			return ret;
		}

		// Attach stream to socket
		stream_sock->stream = stream;
		stream->sock = stream_sock->sk;

		// Get file descriptor
		stream_fd = sock_map_fd(stream_sock, O_CLOEXEC);
		if (stream_fd < 0) {
			sock_release(stream_sock);
			return stream_fd;
		}

		// Return stream ID to userspace
		args.stream_id = stream->id;
		if (copy_to_user(uarg, &args, sizeof(args))) {
			close_fd(stream_fd);
			return -EFAULT;
		}

		return stream_fd;  // ioctl returns fd
	}
	default:
		return -ENOIOCTLCMD;
	}
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Userspace QUIC only | In-kernel QUIC (lxin/quic) | 2024-2026 | Reduced syscall overhead for kernel consumers (NFS, SMB) |
| Full TLS in kernel | Handshake delegation (net/handshake) | Kernel 5.19 (2022) | Security boundary: crypto in userspace |
| kTLS TX only | kTLS TX + RX | Kernel 4.17 (2018) | Bidirectional TLS offload |
| TCP-style socket only | Stream multiplexing per socket | Draft (2026) | First-class stream support in kernel |
| Single-path QUIC | Connection migration in spec | RFC 9000 (2021) | Mobile/NAT environments |

**Deprecated/outdated:**
- **QUIC crypto (Google QUIC):** Replaced by TLS 1.3 in IETF QUIC (RFC 9000)
- **In-kernel TLS handshake:** Deprecated in favor of net/handshake delegation
- **Stream ID in sendmsg ancillary data only:** Draft proposal, superseded by ioctl approach for first-class stream file descriptors

## Open Questions

1. **0-RTT Early Data Key Management**
   - What we know: 0-RTT opt-in via sockopt (per CONTEXT.md), disabled by default
   - What's unclear: How does net/handshake expose 0-RTT keys? Does tlshd return early data keys separately?
   - Recommendation: Investigate NFS over TLS 0-RTT implementation, may need net/handshake API extension

2. **Connection ID Pool Size**
   - What we know: RFC 9000 recommends negotiating active_connection_id_limit during handshake, default 2
   - What's unclear: Optimal pool size for WAN bonding (Phase 4) with 16 paths?
   - Recommendation: Start with active_connection_id_limit=8 (paths * 2 for migration), tune based on testing

3. **Stream File Descriptor Inheritance**
   - What we know: ioctl returns stream fd, should work with poll/epoll
   - What's unclear: What happens on fork()? Should stream fds be inherited, or marked CLOEXEC?
   - Recommendation: Mark stream fds as O_CLOEXEC by default (match pipe2 behavior), document in manpage

4. **Handshake Failure Error Codes**
   - What we know: Map QUIC transport errors to EQUIC* (per CONTEXT.md)
   - What's unclear: How does net/handshake report TLS alert codes (certificate failures, etc.)?
   - Recommendation: Define EQUIC_TLS_BASE + alert_code range, verify with net/handshake maintainers

5. **Migration During Active Transmission**
   - What we know: Immediate PATH_CHALLENGE on migration (per CONTEXT.md)
   - What's unclear: Should in-flight packets be retransmitted on new path immediately, or wait for PATH_RESPONSE?
   - Recommendation: Wait for PATH_RESPONSE before switching send path, match RFC 9000 conservative approach

## Sources

### Primary (HIGH confidence)

- **Linux kernel MPTCP subsystem** - net/mptcp/protocol.c, net/mptcp/protocol.h (reference architecture)
- **Kernel TLS documentation** - https://docs.kernel.org/networking/tls.html (kTLS patterns)
- **RFC 9000: QUIC Transport Protocol** - https://www.rfc-editor.org/rfc/rfc9000.html (connection ID, migration, streams)
- **IANA QUIC Transport Error Codes** - https://www.iana.org/assignments/quic/quic.xhtml (error code registry)
- **lxin/quic kernel implementation** - https://github.com/lxin/quic (kernel QUIC architecture reference)
- **lxin/tls_hs** - https://github.com/lxin/tls_hs (kernel TLS handshake patterns)

### Secondary (MEDIUM confidence)

- **IETF Draft: Socket APIs for In-kernel QUIC** - https://www.ietf.org/archive/id/draft-lxin-quic-socket-apis-02.html (stream multiplexing patterns, expires 2026-03-22)
- **LWN: QUIC for the kernel** - https://lwn.net/Articles/1029851/ (architectural discussion, challenges)
- **Linux Kernel Labs: Networking** - https://linux-kernel-labs.github.io/refs/heads/master/labs/networking.html (socket layer patterns)
- **quic-go connection migration** - https://quic-go.net/docs/quic/connection-migration/ (migration patterns)

### Tertiary (LOW confidence)

- WebSearch findings on QUIC implementation pitfalls (requires verification with RFC 9000)
- Security research on QUIC amplification attacks (2022 publications, may have mitigations in RFC)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - All kernel subsystems verified in mainline (MPTCP, kTLS, net/handshake)
- Architecture: HIGH - MPTCP pattern is production-proven, net/handshake used by NFS/SMB
- Pitfalls: MEDIUM - Based on WebSearch + RFC analysis, not all verified with kernel maintainers
- Stream multiplexing: MEDIUM - Draft spec (expires 2026-03), ioctl pattern is custom but follows kernel conventions
- Migration: HIGH - RFC 9000 is authoritative, CONTEXT.md decisions are explicit

**Research date:** 2026-01-31
**Valid until:** 2026-03-15 (before draft-lxin-quic-socket-apis expires, may need update if API changes)
