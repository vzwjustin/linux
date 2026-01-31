/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Internal Definitions
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides internal socket structure definitions and
 * locking documentation for the TQUIC subsystem. It follows the
 * pattern established by net/mptcp/protocol.h.
 *
 * LOCKING:
 * ========
 * Lock hierarchy (acquire in this order, never reverse):
 *
 *   1. sk->sk_lock.slock (socket lock)
 *        |
 *        +-- 2. conn->lock (connection state lock)
 *                  |
 *                  +-- 3. path->state_lock (per-path state)
 *                            |
 *                            +-- 4. cc->lock (congestion control)
 *                                      |
 *                                      +-- 5. stream->lock (per-stream)
 *
 * Socket lock (sk->sk_lock):
 *   - Standard socket lock, use lock_sock()/release_sock()
 *   - Required for most socket operations
 *   - Can sleep (process context only)
 *
 * Connection lock (conn->lock):
 *   - Spinlock (bh_lock variant for softirq safety)
 *   - Protects: state transitions, path list, global seqnums
 *   - Use spin_lock_bh(&conn->lock)
 *
 * Path state lock (path->state_lock):
 *   - Per-path spinlock
 *   - Protects: path state, RTT samples, congestion state
 *   - Never hold multiple path locks simultaneously
 *
 * Congestion control lock (cc->lock):
 *   - Per-path CC spinlock
 *   - Protects: cwnd, ssthresh, pacing rate
 *
 * Stream lock (stream->lock):
 *   - Per-stream spinlock
 *   - Protects: stream state, flow control, buffers
 *   - Never hold multiple stream locks simultaneously
 *
 * Reference counting:
 *   - conn: refcount_t, use tquic_conn_get/put
 *   - path: refcount_t, use tquic_path_get/put
 *   - stream: refcount_t, RCU for lookup
 *
 * Error paths:
 *   - Use goto cleanup pattern
 *   - Release locks in reverse order
 *   - Drop references before returning
 */

#ifndef _NET_TQUIC_PROTOCOL_H
#define _NET_TQUIC_PROTOCOL_H

#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <net/inet_connection_sock.h>
#include <net/tquic.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_path;
struct tquic_stream;
struct tquic_path_manager;

/*
 * TQUIC connection states
 * Note: These mirror the enum in include/net/tquic.h for consistency
 */
enum tquic_conn_state_internal {
	TQUIC_CONN_STATE_IDLE = 0,
	TQUIC_CONN_STATE_CONNECTING,
	TQUIC_CONN_STATE_HANDSHAKE,
	TQUIC_CONN_STATE_CONNECTED,
	TQUIC_CONN_STATE_CLOSING,
	TQUIC_CONN_STATE_DRAINING,
	TQUIC_CONN_STATE_CLOSED,
};

/*
 * TQUIC socket structure
 *
 * IMPORTANT: inet_connection_sock MUST be the first member.
 * This enables casting between struct sock and tquic_sock via
 * the standard inet_csk() and then container_of patterns.
 *
 * The public definition in include/net/tquic.h is the canonical
 * source. This header provides internal documentation and any
 * internal-only extensions.
 */

/*
 * tquic_sk - Convert struct sock to tquic_sock
 * @sk: socket to convert
 *
 * This macro is already defined in include/net/tquic.h.
 * Re-declaring here for documentation purposes.
 *
 * Usage:
 *   struct tquic_sock *tsk = tquic_sk(sk);
 */
#ifndef tquic_sk
static inline struct tquic_sock *tquic_sk(const struct sock *sk)
{
	return (struct tquic_sock *)sk;
}
#endif

/*
 * IPv6 TQUIC socket structure
 * Used for AF_INET6 sockets
 *
 * Note: This is already defined in include/net/tquic.h (struct tquic6_sock).
 * The tquic_ipv6.c file has its own inline definition which should be
 * migrated to use this header in future cleanup.
 */

/*
 * tquic_inet6_sk - Get IPv6 pinfo from TQUIC socket
 * @sk: socket to get IPv6 info from
 *
 * For IPv6 sockets, retrieves the ipv6_pinfo structure.
 * The socket must be an AF_INET6 socket.
 */
#if IS_ENABLED(CONFIG_IPV6)
static inline struct ipv6_pinfo *tquic_inet6_sk(const struct sock *sk)
{
	return &((struct tquic6_sock *)sk)->inet6;
}
#endif

/*
 * Socket flags
 */
#define TQUIC_F_MULTIPATH_ENABLED	BIT(0)
#define TQUIC_F_BONDING_ENABLED		BIT(1)
#define TQUIC_F_SERVER_MODE		BIT(2)
#define TQUIC_F_HANDSHAKE_DONE		BIT(3)
#define TQUIC_F_CLOSING			BIT(4)

/*
 * Connection lock helpers
 *
 * These provide softirq-safe locking for connection state.
 * Always use these instead of raw spinlock operations.
 */
static inline void tquic_conn_lock(struct tquic_connection *conn)
{
	spin_lock_bh(&conn->lock);
}

static inline void tquic_conn_unlock(struct tquic_connection *conn)
{
	spin_unlock_bh(&conn->lock);
}

/*
 * Socket owned by user check
 *
 * Returns true if the socket lock is held by the user (process context).
 * Used to defer operations that cannot be done in softirq context.
 */
static inline bool tquic_sk_owned_by_user(const struct sock *sk)
{
	return sock_owned_by_user(sk);
}

/*
 * Socket data lock helpers
 *
 * For protecting socket data that may be accessed from both
 * process context and softirq context.
 */
#define tquic_data_lock(sk) spin_lock_bh(&(sk)->sk_lock.slock)
#define tquic_data_unlock(sk) spin_unlock_bh(&(sk)->sk_lock.slock)

/*
 * Debug helpers
 */
#ifdef CONFIG_DEBUG_NET
static inline void tquic_sk_owned_by_me(const struct tquic_sock *tsk)
{
	sock_owned_by_me((const struct sock *)tsk);
}
#else
static inline void tquic_sk_owned_by_me(const struct tquic_sock *tsk) {}
#endif

/*
 * Lockdep class keys for TQUIC socket locks
 *
 * These are used to distinguish lock instances so lockdep can properly
 * validate locking patterns between different socket types (IPv4 vs IPv6)
 * and different lock levels (socket lock vs connection lock).
 *
 * Keys are indexed: [0] = IPv4, [1] = IPv6
 */
extern struct lock_class_key tquic_slock_keys[2];
extern struct lock_class_key tquic_lock_keys[2];

/*
 * Connection lock class keys
 * Separate from socket locks for proper nesting validation
 */
extern struct lock_class_key tquic_conn_lock_key;
extern struct lock_class_key tquic_path_lock_key;
extern struct lock_class_key tquic_stream_lock_key;

#endif /* _NET_TQUIC_PROTOCOL_H */
