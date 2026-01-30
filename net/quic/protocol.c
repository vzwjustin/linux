// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - IETF QUIC Protocol (RFC 9000) Implementation for Linux
 *
 * Copyright (c) 2024 Linux QUIC Authors
 *
 * This file implements the core QUIC protocol handling including:
 * - Socket operations (create, bind, connect, listen, accept, sendmsg, recvmsg)
 * - Connection state machine
 * - Timer management (loss detection, idle timeout, PTO)
 * - Protocol registration with the kernel
 *
 * QUIC is a multiplexed and secure transport protocol built on top of UDP.
 * It provides reliable, in-order delivery of data while minimizing latency.
 */

#define pr_fmt(fmt) "QUIC: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <linux/inetdevice.h>
#include <linux/jhash.h>
#include <linux/vmalloc.h>

#include <net/sock.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/addrconf.h>
#include <net/transp_v6.h>

#include <linux/uaccess.h>
#include <asm/ioctls.h>

/*
 * Address family for QUIC - using 46 as specified
 * This should be added to include/linux/socket.h eventually
 */
#ifndef AF_QUIC
#define AF_QUIC		46
#endif
#ifndef PF_QUIC
#define PF_QUIC		AF_QUIC
#endif

/* QUIC protocol number (not an IP protocol, but used internally) */
#define IPPROTO_QUIC	261

/* ============================================================================
 * Module Parameters
 * ============================================================================
 */

/* Maximum number of connections per socket (for listening sockets) */
static unsigned int quic_max_connections = 1024;
module_param(quic_max_connections, uint, 0644);
MODULE_PARM_DESC(quic_max_connections, "Maximum connections per listening socket");

/* Default idle timeout in milliseconds */
static unsigned int quic_idle_timeout_ms = 30000;
module_param(quic_idle_timeout_ms, uint, 0644);
MODULE_PARM_DESC(quic_idle_timeout_ms, "Default idle timeout in milliseconds");

/* Initial RTT estimate in microseconds */
static unsigned int quic_initial_rtt_us = 333000;
module_param(quic_initial_rtt_us, uint, 0644);
MODULE_PARM_DESC(quic_initial_rtt_us, "Initial RTT estimate in microseconds");

/* Maximum UDP payload size */
static unsigned int quic_max_udp_payload = 1472;
module_param(quic_max_udp_payload, uint, 0644);
MODULE_PARM_DESC(quic_max_udp_payload, "Maximum UDP payload size");

/* Maximum streams per connection */
static unsigned int quic_max_streams_bidi = 100;
module_param(quic_max_streams_bidi, uint, 0644);
MODULE_PARM_DESC(quic_max_streams_bidi, "Maximum bidirectional streams");

static unsigned int quic_max_streams_uni = 100;
module_param(quic_max_streams_uni, uint, 0644);
MODULE_PARM_DESC(quic_max_streams_uni, "Maximum unidirectional streams");

/* Flow control parameters */
static unsigned int quic_initial_max_data = 1048576;
module_param(quic_initial_max_data, uint, 0644);
MODULE_PARM_DESC(quic_initial_max_data, "Initial maximum data (connection-level)");

static unsigned int quic_initial_max_stream_data = 262144;
module_param(quic_initial_max_stream_data, uint, 0644);
MODULE_PARM_DESC(quic_initial_max_stream_data, "Initial maximum stream data");

/* ACK delay exponent */
static unsigned int quic_ack_delay_exponent = 3;
module_param(quic_ack_delay_exponent, uint, 0644);
MODULE_PARM_DESC(quic_ack_delay_exponent, "ACK delay exponent (default 3)");

/* Maximum ACK delay in milliseconds */
static unsigned int quic_max_ack_delay_ms = 25;
module_param(quic_max_ack_delay_ms, uint, 0644);
MODULE_PARM_DESC(quic_max_ack_delay_ms, "Maximum ACK delay in milliseconds");

/* ============================================================================
 * QUIC State Definitions
 * ============================================================================
 */

/* QUIC connection states per RFC 9000 */
enum quic_state {
	QUIC_STATE_IDLE = 0,		/* Initial state, no connection */
	QUIC_STATE_HANDSHAKE,		/* TLS handshake in progress */
	QUIC_STATE_CONNECTED,		/* Handshake complete, data transfer */
	QUIC_STATE_CLOSING,		/* Sent CONNECTION_CLOSE, waiting */
	QUIC_STATE_DRAINING,		/* Received CONNECTION_CLOSE, draining */
	QUIC_STATE_CLOSED,		/* Connection fully closed */
	QUIC_STATE_LISTEN,		/* Server: listening for connections */

	QUIC_STATE_MAX
};

/* State transition flags */
#define QUICF_STATE_IDLE	(1 << QUIC_STATE_IDLE)
#define QUICF_STATE_HANDSHAKE	(1 << QUIC_STATE_HANDSHAKE)
#define QUICF_STATE_CONNECTED	(1 << QUIC_STATE_CONNECTED)
#define QUICF_STATE_CLOSING	(1 << QUIC_STATE_CLOSING)
#define QUICF_STATE_DRAINING	(1 << QUIC_STATE_DRAINING)
#define QUICF_STATE_CLOSED	(1 << QUIC_STATE_CLOSED)
#define QUICF_STATE_LISTEN	(1 << QUIC_STATE_LISTEN)

/* QUIC timer types */
enum quic_timer_type {
	QUIC_TIMER_LOSS,		/* Loss detection timer */
	QUIC_TIMER_IDLE,		/* Idle timeout timer */
	QUIC_TIMER_PTO,			/* Probe timeout timer */
	QUIC_TIMER_ACK,			/* Delayed ACK timer */
	QUIC_TIMER_DRAIN,		/* Draining period timer */

	QUIC_TIMER_MAX
};

/* QUIC events for state machine */
enum quic_event {
	QUIC_EVENT_CONNECT,		/* Connect initiated */
	QUIC_EVENT_ACCEPT,		/* Accept connection */
	QUIC_EVENT_HANDSHAKE_DONE,	/* TLS handshake complete */
	QUIC_EVENT_DATA,		/* Data received */
	QUIC_EVENT_CLOSE,		/* Close initiated */
	QUIC_EVENT_CONN_CLOSE_RECV,	/* CONNECTION_CLOSE received */
	QUIC_EVENT_TIMEOUT,		/* Timer expired */
	QUIC_EVENT_ERROR,		/* Error occurred */
};

/* QUIC connection flags */
enum quic_conn_flags {
	QUIC_CONN_FLAG_SERVER = 0,	/* Server-side connection */
	QUIC_CONN_FLAG_0RTT_ENABLED,	/* 0-RTT data allowed */
	QUIC_CONN_FLAG_HANDSHAKE_CONFIRMED, /* Handshake confirmed */
	QUIC_CONN_FLAG_KEY_UPDATE,	/* Key update in progress */
	QUIC_CONN_FLAG_CLOSING,		/* Connection closing */
	QUIC_CONN_FLAG_DRAINING,	/* Connection draining */
	QUIC_CONN_FLAG_HAS_DATA,	/* Has pending data */
};

/* ============================================================================
 * QUIC Data Structures
 * ============================================================================
 */

/* Forward declarations */
struct quic_sock;
struct quic_connection;
struct quic_stream;

/* Connection ID structure */
struct quic_connection_id {
	u8 len;
	u8 data[20];	/* Max CID length per RFC 9000 */
};

/* QUIC packet number space */
enum quic_pn_space {
	QUIC_PN_SPACE_INITIAL = 0,
	QUIC_PN_SPACE_HANDSHAKE,
	QUIC_PN_SPACE_APPLICATION,
	QUIC_PN_SPACE_MAX
};

/* Packet number tracking */
struct quic_pn_state {
	u64 largest_sent;
	u64 largest_acked;
	u64 next_pn;
	u64 largest_recv;
	u64 recv_time;
	struct list_head sent_packets;
	spinlock_t lock;
};

/* RTT estimation */
struct quic_rtt {
	u64 min_rtt;		/* Minimum RTT observed */
	u64 smoothed_rtt;	/* Smoothed RTT */
	u64 rtt_var;		/* RTT variance */
	u64 latest_rtt;		/* Most recent RTT sample */
	u64 first_rtt_sample;	/* Time of first sample */
};

/* Congestion control state */
struct quic_congestion {
	u64 cwnd;			/* Congestion window */
	u64 bytes_in_flight;		/* Bytes sent but not acked */
	u64 ssthresh;			/* Slow start threshold */
	u64 recovery_start;		/* Recovery period start time */
	u32 ecn_ce_count;		/* ECN CE counter */
	bool in_recovery;		/* In recovery period */
	bool in_slow_start;		/* In slow start */
};

/* Flow control state */
struct quic_flow_control {
	u64 max_data;			/* Maximum data allowed */
	u64 data_sent;			/* Data sent so far */
	u64 data_received;		/* Data received so far */
	u64 max_stream_data_local;	/* Local stream limit */
	u64 max_stream_data_remote;	/* Remote stream limit */
};

/* QUIC stream structure */
struct quic_stream {
	struct list_head node;		/* List linkage */
	u64 stream_id;			/* Stream identifier */
	u64 send_offset;		/* Next byte to send */
	u64 recv_offset;		/* Next byte expected */
	u64 max_send_data;		/* Max data sendable */
	u64 max_recv_data;		/* Max data receivable */
	struct sk_buff_head send_queue;	/* Send buffer */
	struct sk_buff_head recv_queue;	/* Receive buffer */
	spinlock_t lock;
	u8 state;			/* Stream state */
	u8 flags;			/* Stream flags */
	struct quic_connection *conn;	/* Parent connection */
};

/* QUIC connection structure */
struct quic_connection {
	struct list_head node;		/* List linkage */
	struct hlist_node hash_node;	/* Hash table linkage */
	struct rcu_head rcu;		/* RCU protection */
	refcount_t refcount;		/* Reference count */

	/* Connection identifiers */
	struct quic_connection_id local_cid;
	struct quic_connection_id remote_cid;
	struct quic_connection_id original_dcid;

	/* Addresses */
	union {
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} local_addr;
	union {
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} remote_addr;
	sa_family_t addr_family;

	/* State */
	enum quic_state state;
	unsigned long flags;
	u32 version;			/* QUIC version */

	/* Packet number spaces */
	struct quic_pn_state pn_spaces[QUIC_PN_SPACE_MAX];

	/* RTT and congestion */
	struct quic_rtt rtt;
	struct quic_congestion congestion;
	struct quic_flow_control flow;

	/* Streams */
	struct list_head streams;
	spinlock_t streams_lock;
	u64 next_stream_id_bidi;
	u64 next_stream_id_uni;
	u32 max_streams_bidi;
	u32 max_streams_uni;

	/* Timers */
	struct timer_list timers[QUIC_TIMER_MAX];
	unsigned long timer_expires[QUIC_TIMER_MAX];

	/* Crypto state */
	void *crypto_ctx;		/* Opaque crypto context */
	u8 handshake_data[4096];	/* Handshake buffer */
	size_t handshake_len;

	/* Queues */
	struct sk_buff_head tx_queue;	/* Transmit queue */
	struct sk_buff_head rx_queue;	/* Receive queue */
	struct sk_buff_head ack_queue;	/* Pending ACKs */

	/* Statistics */
	u64 packets_sent;
	u64 packets_recv;
	u64 bytes_sent;
	u64 bytes_recv;
	u64 packets_lost;

	/* Parent socket */
	struct quic_sock *qsk;

	/* Error handling */
	u64 error_code;
	char error_reason[256];

	/* Work queue for deferred processing */
	struct work_struct work;
};

/* Accept queue entry */
struct quic_accept_entry {
	struct list_head node;
	struct quic_connection *conn;
};

/* QUIC socket structure */
struct quic_sock {
	/* Must be first member - allows casting */
	struct sock sk;

	/* UDP socket used as transport */
	struct socket *udp_sock;

	/* Connection state (for connected sockets) */
	struct quic_connection *conn;

	/* Accept queue (for listening sockets) */
	struct list_head accept_queue;
	spinlock_t accept_lock;
	u32 accept_queue_len;
	u32 max_accept_queue;

	/* Connection hash table */
	struct hlist_head *conn_hash;
	u32 conn_hash_size;
	spinlock_t conn_hash_lock;

	/* Local address info */
	union {
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} local_addr;

	/* Socket options */
	u32 idle_timeout;
	u32 max_udp_payload_size;
	u32 initial_max_data;
	u32 initial_max_stream_data_bidi_local;
	u32 initial_max_stream_data_bidi_remote;
	u32 initial_max_stream_data_uni;
	u32 initial_max_streams_bidi;
	u32 initial_max_streams_uni;
	u8 ack_delay_exponent;
	u8 max_ack_delay;
	bool disable_active_migration;
	bool grease_quic_bit;

	/* Statistics */
	u64 total_connections;
	u64 active_connections;
};

/* ============================================================================
 * Memory Caches
 * ============================================================================
 */

static struct kmem_cache *quic_conn_cachep;
static struct kmem_cache *quic_stream_cachep;
static struct percpu_counter quic_sockets_allocated;
static struct workqueue_struct *quic_workqueue;

/* ============================================================================
 * Helper Macros and Inline Functions
 * ============================================================================
 */

static inline struct quic_sock *quic_sk(const struct sock *sk)
{
	return (struct quic_sock *)sk;
}

static inline struct sock *quic_to_sock(struct quic_sock *qsk)
{
	return (struct sock *)qsk;
}

static inline bool quic_state_is_connected(enum quic_state state)
{
	return state == QUIC_STATE_CONNECTED;
}

static inline bool quic_state_can_send(enum quic_state state)
{
	return state == QUIC_STATE_HANDSHAKE ||
	       state == QUIC_STATE_CONNECTED;
}

static inline bool quic_state_can_recv(enum quic_state state)
{
	return state == QUIC_STATE_HANDSHAKE ||
	       state == QUIC_STATE_CONNECTED ||
	       state == QUIC_STATE_CLOSING ||
	       state == QUIC_STATE_DRAINING;
}

/* ============================================================================
 * Connection ID Management
 * ============================================================================
 */

static void quic_generate_connection_id(struct quic_connection_id *cid, u8 len)
{
	if (len > sizeof(cid->data))
		len = sizeof(cid->data);
	cid->len = len;
	get_random_bytes(cid->data, len);
}

static bool quic_cid_equal(const struct quic_connection_id *a,
			   const struct quic_connection_id *b)
{
	if (a->len != b->len)
		return false;
	return memcmp(a->data, b->data, a->len) == 0;
}

static u32 quic_cid_hash(const struct quic_connection_id *cid, u32 hash_size)
{
	return jhash(cid->data, cid->len, 0) % hash_size;
}

/* ============================================================================
 * Connection Hash Table
 * ============================================================================
 */

static struct quic_connection *quic_conn_lookup(struct quic_sock *qsk,
						const struct quic_connection_id *cid)
{
	struct quic_connection *conn;
	u32 hash;

	if (!qsk->conn_hash)
		return NULL;

	hash = quic_cid_hash(cid, qsk->conn_hash_size);

	rcu_read_lock();
	hlist_for_each_entry_rcu(conn, &qsk->conn_hash[hash], hash_node) {
		if (quic_cid_equal(&conn->local_cid, cid)) {
			if (refcount_inc_not_zero(&conn->refcount)) {
				rcu_read_unlock();
				return conn;
			}
		}
	}
	rcu_read_unlock();

	return NULL;
}

static int quic_conn_hash_insert(struct quic_sock *qsk,
				 struct quic_connection *conn)
{
	u32 hash;

	if (!qsk->conn_hash)
		return -EINVAL;

	hash = quic_cid_hash(&conn->local_cid, qsk->conn_hash_size);

	spin_lock_bh(&qsk->conn_hash_lock);
	hlist_add_head_rcu(&conn->hash_node, &qsk->conn_hash[hash]);
	spin_unlock_bh(&qsk->conn_hash_lock);

	return 0;
}

static void quic_conn_hash_remove(struct quic_sock *qsk,
				  struct quic_connection *conn)
{
	spin_lock_bh(&qsk->conn_hash_lock);
	hlist_del_rcu(&conn->hash_node);
	spin_unlock_bh(&qsk->conn_hash_lock);
}

/* ============================================================================
 * RTT Estimation
 * ============================================================================
 */

static void quic_rtt_init(struct quic_rtt *rtt)
{
	rtt->min_rtt = U64_MAX;
	rtt->smoothed_rtt = quic_initial_rtt_us;
	rtt->rtt_var = quic_initial_rtt_us / 2;
	rtt->latest_rtt = 0;
	rtt->first_rtt_sample = 0;
}

static void quic_rtt_update(struct quic_rtt *rtt, u64 latest_rtt, u64 ack_delay)
{
	rtt->latest_rtt = latest_rtt;

	if (rtt->first_rtt_sample == 0) {
		rtt->first_rtt_sample = ktime_get_ns();
		rtt->min_rtt = latest_rtt;
		rtt->smoothed_rtt = latest_rtt;
		rtt->rtt_var = latest_rtt / 2;
		return;
	}

	/* Update min RTT */
	if (latest_rtt < rtt->min_rtt)
		rtt->min_rtt = latest_rtt;

	/* Adjust for ACK delay */
	if (latest_rtt > rtt->min_rtt + ack_delay)
		latest_rtt -= ack_delay;

	/* RFC 9002 RTT estimation */
	rtt->rtt_var = (3 * rtt->rtt_var + abs((s64)rtt->smoothed_rtt - (s64)latest_rtt)) / 4;
	rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + latest_rtt) / 8;
}

static u64 quic_pto(struct quic_rtt *rtt)
{
	/* PTO = smoothed_rtt + max(4*rtt_var, kGranularity) + max_ack_delay */
	u64 pto = rtt->smoothed_rtt;
	u64 var_component = max_t(u64, 4 * rtt->rtt_var, 1000); /* 1ms granularity */

	pto += var_component;
	pto += quic_max_ack_delay_ms * 1000; /* Convert to microseconds */

	return pto;
}

/* ============================================================================
 * Congestion Control
 * ============================================================================
 */

#define QUIC_INITIAL_CWND	(14720)	/* ~10 packets */
#define QUIC_MIN_CWND		(2 * quic_max_udp_payload)
#define QUIC_LOSS_REDUCTION_FACTOR	2

static void quic_congestion_init(struct quic_congestion *cc)
{
	cc->cwnd = QUIC_INITIAL_CWND;
	cc->bytes_in_flight = 0;
	cc->ssthresh = U64_MAX;
	cc->recovery_start = 0;
	cc->ecn_ce_count = 0;
	cc->in_recovery = false;
	cc->in_slow_start = true;
}

static void quic_congestion_on_ack(struct quic_congestion *cc, u64 bytes_acked)
{
	if (cc->in_recovery)
		return;

	if (cc->in_slow_start) {
		cc->cwnd += bytes_acked;
		if (cc->cwnd >= cc->ssthresh)
			cc->in_slow_start = false;
	} else {
		/* Congestion avoidance */
		cc->cwnd += quic_max_udp_payload * bytes_acked / cc->cwnd;
	}
}

static void quic_congestion_on_loss(struct quic_congestion *cc, u64 sent_time)
{
	if (cc->in_recovery && sent_time <= cc->recovery_start)
		return;

	cc->recovery_start = ktime_get_ns();
	cc->in_recovery = true;
	cc->ssthresh = cc->cwnd / QUIC_LOSS_REDUCTION_FACTOR;
	cc->cwnd = max_t(u64, cc->ssthresh, QUIC_MIN_CWND);
	cc->in_slow_start = false;
}

static bool quic_congestion_can_send(struct quic_congestion *cc, u64 bytes)
{
	return cc->bytes_in_flight + bytes <= cc->cwnd;
}

/* ============================================================================
 * Flow Control
 * ============================================================================
 */

static void quic_flow_init(struct quic_flow_control *flow)
{
	flow->max_data = quic_initial_max_data;
	flow->data_sent = 0;
	flow->data_received = 0;
	flow->max_stream_data_local = quic_initial_max_stream_data;
	flow->max_stream_data_remote = quic_initial_max_stream_data;
}

static bool quic_flow_can_send(struct quic_flow_control *flow, u64 bytes)
{
	return flow->data_sent + bytes <= flow->max_data;
}

static void quic_flow_on_send(struct quic_flow_control *flow, u64 bytes)
{
	flow->data_sent += bytes;
}

static void quic_flow_on_recv(struct quic_flow_control *flow, u64 bytes)
{
	flow->data_received += bytes;
}

/* ============================================================================
 * Timer Handling
 * ============================================================================
 */

static void quic_timer_loss_handler(struct timer_list *t);
static void quic_timer_idle_handler(struct timer_list *t);
static void quic_timer_pto_handler(struct timer_list *t);
static void quic_timer_ack_handler(struct timer_list *t);
static void quic_timer_drain_handler(struct timer_list *t);

typedef void (*quic_timer_fn)(struct timer_list *);

static const quic_timer_fn quic_timer_handlers[QUIC_TIMER_MAX] = {
	[QUIC_TIMER_LOSS] = quic_timer_loss_handler,
	[QUIC_TIMER_IDLE] = quic_timer_idle_handler,
	[QUIC_TIMER_PTO] = quic_timer_pto_handler,
	[QUIC_TIMER_ACK] = quic_timer_ack_handler,
	[QUIC_TIMER_DRAIN] = quic_timer_drain_handler,
};

static struct quic_connection *quic_conn_from_timer(struct timer_list *t,
						    enum quic_timer_type type)
{
	return container_of(t, struct quic_connection, timers[type]);
}

static void quic_timer_set(struct quic_connection *conn,
			   enum quic_timer_type type, unsigned long expires)
{
	struct timer_list *timer = &conn->timers[type];

	conn->timer_expires[type] = expires;
	mod_timer(timer, expires);
}

static void quic_timer_stop(struct quic_connection *conn,
			    enum quic_timer_type type)
{
	del_timer(&conn->timers[type]);
	conn->timer_expires[type] = 0;
}

static void quic_timer_stop_all(struct quic_connection *conn)
{
	int i;

	for (i = 0; i < QUIC_TIMER_MAX; i++)
		quic_timer_stop(conn, i);
}

static void quic_timer_loss_handler(struct timer_list *t)
{
	struct quic_connection *conn = quic_conn_from_timer(t, QUIC_TIMER_LOSS);
	struct quic_sock *qsk = conn->qsk;
	struct sock *sk = quic_to_sock(qsk);

	pr_debug("loss timer fired for conn %p\n", conn);

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		/* Detect lost packets and retransmit */
		int i;

		for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
			struct quic_pn_state *pn = &conn->pn_spaces[i];
			struct sk_buff *skb, *tmp;
			u64 loss_delay;

			/* Loss delay = max(kTimeThreshold * max(smoothed_rtt, latest_rtt),
			 *                  kGranularity)
			 */
			loss_delay = max(conn->rtt.smoothed_rtt, conn->rtt.latest_rtt);
			loss_delay = loss_delay * 9 / 8; /* 9/8 time threshold */
			loss_delay = max_t(u64, loss_delay, 1000); /* 1ms granularity */

			spin_lock(&pn->lock);
			list_for_each_entry_safe(skb, tmp, &pn->sent_packets, list) {
				u64 sent_time = (u64)(uintptr_t)skb->cb;
				u64 now = ktime_get_ns();

				if (now - sent_time > loss_delay * 1000) {
					/* Packet considered lost */
					list_del(&skb->list);
					conn->packets_lost++;
					quic_congestion_on_loss(&conn->congestion, sent_time);
					/* Queue for retransmission */
					skb_queue_tail(&conn->tx_queue, skb);
				}
			}
			spin_unlock(&pn->lock);
		}

		/* Rearm timer if needed */
		if (!skb_queue_empty(&conn->tx_queue)) {
			quic_timer_set(conn, QUIC_TIMER_LOSS,
				       jiffies + usecs_to_jiffies(quic_pto(&conn->rtt)));
		}
	}
	bh_unlock_sock(sk);
}

static void quic_timer_idle_handler(struct timer_list *t)
{
	struct quic_connection *conn = quic_conn_from_timer(t, QUIC_TIMER_IDLE);
	struct quic_sock *qsk = conn->qsk;
	struct sock *sk = quic_to_sock(qsk);

	pr_debug("idle timer fired for conn %p\n", conn);

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		/* Connection timed out */
		conn->state = QUIC_STATE_CLOSED;
		conn->error_code = 0; /* No error, just timeout */
		sk->sk_err = ETIMEDOUT;
		sk_error_report(sk);
		sk->sk_state_change(sk);
	}
	bh_unlock_sock(sk);
}

static void quic_timer_pto_handler(struct timer_list *t)
{
	struct quic_connection *conn = quic_conn_from_timer(t, QUIC_TIMER_PTO);
	struct quic_sock *qsk = conn->qsk;
	struct sock *sk = quic_to_sock(qsk);

	pr_debug("PTO timer fired for conn %p\n", conn);

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		/* Send probe packet */
		if (quic_state_can_send(conn->state)) {
			/* In a full implementation, we would send a PING frame
			 * or retransmit data here
			 */
			pr_debug("sending probe packet\n");
		}
	}
	bh_unlock_sock(sk);
}

static void quic_timer_ack_handler(struct timer_list *t)
{
	struct quic_connection *conn = quic_conn_from_timer(t, QUIC_TIMER_ACK);
	struct quic_sock *qsk = conn->qsk;
	struct sock *sk = quic_to_sock(qsk);

	pr_debug("ACK timer fired for conn %p\n", conn);

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		/* Send pending ACKs */
		if (!skb_queue_empty(&conn->ack_queue)) {
			/* In a full implementation, we would generate and send
			 * an ACK frame here
			 */
			pr_debug("sending delayed ACK\n");
		}
	}
	bh_unlock_sock(sk);
}

static void quic_timer_drain_handler(struct timer_list *t)
{
	struct quic_connection *conn = quic_conn_from_timer(t, QUIC_TIMER_DRAIN);
	struct quic_sock *qsk = conn->qsk;
	struct sock *sk = quic_to_sock(qsk);

	pr_debug("drain timer fired for conn %p\n", conn);

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		/* Draining period complete */
		conn->state = QUIC_STATE_CLOSED;
		sk->sk_state_change(sk);
	}
	bh_unlock_sock(sk);
}

/* Reset idle timer on activity */
static void quic_timer_reset_idle(struct quic_connection *conn)
{
	unsigned long timeout;

	if (conn->state == QUIC_STATE_CLOSED)
		return;

	timeout = jiffies + msecs_to_jiffies(conn->qsk->idle_timeout);
	quic_timer_set(conn, QUIC_TIMER_IDLE, timeout);
}

/* Update loss detection timer */
static void quic_timer_update_loss(struct quic_connection *conn)
{
	u64 pto;
	unsigned long timeout;

	if (conn->state != QUIC_STATE_CONNECTED &&
	    conn->state != QUIC_STATE_HANDSHAKE)
		return;

	pto = quic_pto(&conn->rtt);
	timeout = jiffies + usecs_to_jiffies(pto);
	quic_timer_set(conn, QUIC_TIMER_LOSS, timeout);
}

/* ============================================================================
 * State Machine
 * ============================================================================
 */

static const char *quic_state_names[] = {
	[QUIC_STATE_IDLE] = "IDLE",
	[QUIC_STATE_HANDSHAKE] = "HANDSHAKE",
	[QUIC_STATE_CONNECTED] = "CONNECTED",
	[QUIC_STATE_CLOSING] = "CLOSING",
	[QUIC_STATE_DRAINING] = "DRAINING",
	[QUIC_STATE_CLOSED] = "CLOSED",
	[QUIC_STATE_LISTEN] = "LISTEN",
};

static const char *quic_event_names[] = {
	[QUIC_EVENT_CONNECT] = "CONNECT",
	[QUIC_EVENT_ACCEPT] = "ACCEPT",
	[QUIC_EVENT_HANDSHAKE_DONE] = "HANDSHAKE_DONE",
	[QUIC_EVENT_DATA] = "DATA",
	[QUIC_EVENT_CLOSE] = "CLOSE",
	[QUIC_EVENT_CONN_CLOSE_RECV] = "CONN_CLOSE_RECV",
	[QUIC_EVENT_TIMEOUT] = "TIMEOUT",
	[QUIC_EVENT_ERROR] = "ERROR",
};

static int quic_state_machine(struct quic_connection *conn, enum quic_event event)
{
	enum quic_state old_state = conn->state;
	enum quic_state new_state = old_state;
	int ret = 0;

	pr_debug("state machine: state=%s event=%s\n",
		 quic_state_names[old_state], quic_event_names[event]);

	switch (old_state) {
	case QUIC_STATE_IDLE:
		switch (event) {
		case QUIC_EVENT_CONNECT:
			new_state = QUIC_STATE_HANDSHAKE;
			break;
		case QUIC_EVENT_ACCEPT:
			new_state = QUIC_STATE_HANDSHAKE;
			break;
		default:
			ret = -EINVAL;
			break;
		}
		break;

	case QUIC_STATE_HANDSHAKE:
		switch (event) {
		case QUIC_EVENT_HANDSHAKE_DONE:
			new_state = QUIC_STATE_CONNECTED;
			set_bit(QUIC_CONN_FLAG_HANDSHAKE_CONFIRMED, &conn->flags);
			break;
		case QUIC_EVENT_CLOSE:
			new_state = QUIC_STATE_CLOSING;
			break;
		case QUIC_EVENT_CONN_CLOSE_RECV:
			new_state = QUIC_STATE_DRAINING;
			break;
		case QUIC_EVENT_ERROR:
		case QUIC_EVENT_TIMEOUT:
			new_state = QUIC_STATE_CLOSED;
			break;
		case QUIC_EVENT_DATA:
			/* Stay in handshake, process data */
			break;
		default:
			ret = -EINVAL;
			break;
		}
		break;

	case QUIC_STATE_CONNECTED:
		switch (event) {
		case QUIC_EVENT_CLOSE:
			new_state = QUIC_STATE_CLOSING;
			set_bit(QUIC_CONN_FLAG_CLOSING, &conn->flags);
			break;
		case QUIC_EVENT_CONN_CLOSE_RECV:
			new_state = QUIC_STATE_DRAINING;
			set_bit(QUIC_CONN_FLAG_DRAINING, &conn->flags);
			break;
		case QUIC_EVENT_DATA:
			/* Stay connected, process data */
			break;
		case QUIC_EVENT_ERROR:
			new_state = QUIC_STATE_CLOSING;
			break;
		case QUIC_EVENT_TIMEOUT:
			new_state = QUIC_STATE_CLOSED;
			break;
		default:
			ret = -EINVAL;
			break;
		}
		break;

	case QUIC_STATE_CLOSING:
		switch (event) {
		case QUIC_EVENT_CONN_CLOSE_RECV:
			new_state = QUIC_STATE_DRAINING;
			break;
		case QUIC_EVENT_TIMEOUT:
			new_state = QUIC_STATE_CLOSED;
			break;
		case QUIC_EVENT_DATA:
			/* Ignore data in closing state */
			break;
		default:
			/* Ignore most events in closing state */
			break;
		}
		break;

	case QUIC_STATE_DRAINING:
		switch (event) {
		case QUIC_EVENT_TIMEOUT:
			new_state = QUIC_STATE_CLOSED;
			break;
		default:
			/* Ignore all events in draining state except timeout */
			break;
		}
		break;

	case QUIC_STATE_CLOSED:
		/* No transitions from closed state */
		ret = -ECONNRESET;
		break;

	case QUIC_STATE_LISTEN:
		switch (event) {
		case QUIC_EVENT_ACCEPT:
			/* Create new connection in handshake state */
			break;
		case QUIC_EVENT_CLOSE:
			new_state = QUIC_STATE_CLOSED;
			break;
		default:
			ret = -EINVAL;
			break;
		}
		break;

	default:
		pr_err("invalid state %d\n", old_state);
		ret = -EINVAL;
		break;
	}

	if (new_state != old_state) {
		pr_debug("state transition: %s -> %s\n",
			 quic_state_names[old_state], quic_state_names[new_state]);
		conn->state = new_state;

		/* Handle state entry actions */
		switch (new_state) {
		case QUIC_STATE_CLOSING:
			/* Start closing timer (3 * PTO) */
			quic_timer_set(conn, QUIC_TIMER_DRAIN,
				       jiffies + usecs_to_jiffies(3 * quic_pto(&conn->rtt)));
			break;
		case QUIC_STATE_DRAINING:
			/* Start draining timer (3 * PTO) */
			quic_timer_set(conn, QUIC_TIMER_DRAIN,
				       jiffies + usecs_to_jiffies(3 * quic_pto(&conn->rtt)));
			/* Stop all other timers */
			quic_timer_stop(conn, QUIC_TIMER_LOSS);
			quic_timer_stop(conn, QUIC_TIMER_PTO);
			quic_timer_stop(conn, QUIC_TIMER_ACK);
			break;
		case QUIC_STATE_CLOSED:
			/* Stop all timers */
			quic_timer_stop_all(conn);
			break;
		case QUIC_STATE_CONNECTED:
			/* Reset idle timer */
			quic_timer_reset_idle(conn);
			break;
		default:
			break;
		}
	}

	return ret;
}

/* ============================================================================
 * Connection Management
 * ============================================================================
 */

static void quic_conn_work(struct work_struct *work)
{
	struct quic_connection *conn = container_of(work, struct quic_connection, work);
	struct quic_sock *qsk = conn->qsk;
	struct sock *sk = quic_to_sock(qsk);

	lock_sock(sk);

	/* Process pending TX */
	while (!skb_queue_empty(&conn->tx_queue) &&
	       quic_congestion_can_send(&conn->congestion, quic_max_udp_payload)) {
		struct sk_buff *skb;
		int ret;

		skb = skb_dequeue(&conn->tx_queue);
		if (!skb)
			break;

		/* Send via UDP */
		if (qsk->udp_sock) {
			struct msghdr msg = {};
			struct kvec iov;

			iov.iov_base = skb->data;
			iov.iov_len = skb->len;
			iov_iter_kvec(&msg.msg_iter, ITER_SOURCE, &iov, 1, skb->len);

			ret = sock_sendmsg(qsk->udp_sock, &msg);
			if (ret < 0) {
				pr_debug("UDP send failed: %d\n", ret);
				skb_queue_head(&conn->tx_queue, skb);
				break;
			}

			conn->packets_sent++;
			conn->bytes_sent += skb->len;
			conn->congestion.bytes_in_flight += skb->len;
		}

		kfree_skb(skb);
	}

	release_sock(sk);
}

static struct quic_connection *quic_conn_alloc(struct quic_sock *qsk, gfp_t gfp)
{
	struct quic_connection *conn;
	int i;

	conn = kmem_cache_zalloc(quic_conn_cachep, gfp);
	if (!conn)
		return NULL;

	refcount_set(&conn->refcount, 1);
	conn->qsk = qsk;
	conn->state = QUIC_STATE_IDLE;
	conn->version = 1; /* QUIC v1 */

	/* Initialize packet number spaces */
	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		INIT_LIST_HEAD(&conn->pn_spaces[i].sent_packets);
		spin_lock_init(&conn->pn_spaces[i].lock);
	}

	/* Initialize RTT and congestion control */
	quic_rtt_init(&conn->rtt);
	quic_congestion_init(&conn->congestion);
	quic_flow_init(&conn->flow);

	/* Initialize streams */
	INIT_LIST_HEAD(&conn->streams);
	spin_lock_init(&conn->streams_lock);
	conn->max_streams_bidi = quic_max_streams_bidi;
	conn->max_streams_uni = quic_max_streams_uni;

	/* Initialize timers */
	for (i = 0; i < QUIC_TIMER_MAX; i++)
		timer_setup(&conn->timers[i], quic_timer_handlers[i], 0);

	/* Initialize queues */
	skb_queue_head_init(&conn->tx_queue);
	skb_queue_head_init(&conn->rx_queue);
	skb_queue_head_init(&conn->ack_queue);

	/* Initialize work */
	INIT_WORK(&conn->work, quic_conn_work);

	/* Generate local connection ID */
	quic_generate_connection_id(&conn->local_cid, 8);

	return conn;
}

static void quic_conn_free_rcu(struct rcu_head *head)
{
	struct quic_connection *conn = container_of(head, struct quic_connection, rcu);

	skb_queue_purge(&conn->tx_queue);
	skb_queue_purge(&conn->rx_queue);
	skb_queue_purge(&conn->ack_queue);

	kmem_cache_free(quic_conn_cachep, conn);
}

static void quic_conn_put(struct quic_connection *conn)
{
	if (refcount_dec_and_test(&conn->refcount)) {
		quic_timer_stop_all(conn);
		cancel_work_sync(&conn->work);
		call_rcu(&conn->rcu, quic_conn_free_rcu);
	}
}

static void quic_conn_get(struct quic_connection *conn)
{
	refcount_inc(&conn->refcount);
}

/* ============================================================================
 * Stream Management
 * ============================================================================
 */

static struct quic_stream *quic_stream_alloc(struct quic_connection *conn,
					     u64 stream_id, gfp_t gfp)
{
	struct quic_stream *stream;

	stream = kmem_cache_zalloc(quic_stream_cachep, gfp);
	if (!stream)
		return NULL;

	stream->stream_id = stream_id;
	stream->conn = conn;
	stream->max_send_data = conn->qsk->initial_max_stream_data_bidi_remote;
	stream->max_recv_data = conn->qsk->initial_max_stream_data_bidi_local;
	spin_lock_init(&stream->lock);
	skb_queue_head_init(&stream->send_queue);
	skb_queue_head_init(&stream->recv_queue);
	INIT_LIST_HEAD(&stream->node);

	return stream;
}

static void quic_stream_free(struct quic_stream *stream)
{
	skb_queue_purge(&stream->send_queue);
	skb_queue_purge(&stream->recv_queue);
	kmem_cache_free(quic_stream_cachep, stream);
}

static struct quic_stream *quic_stream_find(struct quic_connection *conn, u64 stream_id)
{
	struct quic_stream *stream;

	spin_lock_bh(&conn->streams_lock);
	list_for_each_entry(stream, &conn->streams, node) {
		if (stream->stream_id == stream_id) {
			spin_unlock_bh(&conn->streams_lock);
			return stream;
		}
	}
	spin_unlock_bh(&conn->streams_lock);

	return NULL;
}

static struct quic_stream *quic_stream_create(struct quic_connection *conn,
					      bool bidi, gfp_t gfp)
{
	struct quic_stream *stream;
	u64 stream_id;

	/* Calculate stream ID based on initiator and type */
	if (bidi) {
		stream_id = conn->next_stream_id_bidi;
		conn->next_stream_id_bidi += 4;
	} else {
		stream_id = conn->next_stream_id_uni;
		conn->next_stream_id_uni += 4;
	}

	/* Adjust for client/server */
	if (test_bit(QUIC_CONN_FLAG_SERVER, &conn->flags))
		stream_id |= 1;

	stream = quic_stream_alloc(conn, stream_id, gfp);
	if (!stream)
		return NULL;

	spin_lock_bh(&conn->streams_lock);
	list_add_tail(&stream->node, &conn->streams);
	spin_unlock_bh(&conn->streams_lock);

	return stream;
}

/* ============================================================================
 * UDP Encapsulation
 * ============================================================================
 */

static void quic_udp_recv(struct sock *sk, struct sk_buff *skb)
{
	struct quic_sock *qsk;
	struct quic_connection *conn = NULL;
	struct quic_connection_id dcid;
	u8 *data;
	int len;

	rcu_read_lock();
	qsk = rcu_dereference(sk->sk_user_data);
	if (!qsk) {
		rcu_read_unlock();
		kfree_skb(skb);
		return;
	}
	rcu_read_unlock();

	data = skb->data;
	len = skb->len;

	/* Minimum QUIC packet size check */
	if (len < 21) {
		kfree_skb(skb);
		return;
	}

	/* Extract destination connection ID */
	if (data[0] & 0x80) {
		/* Long header */
		if (len < 7) {
			kfree_skb(skb);
			return;
		}
		dcid.len = data[5];
		if (dcid.len > 20 || len < 6 + dcid.len) {
			kfree_skb(skb);
			return;
		}
		memcpy(dcid.data, &data[6], dcid.len);
	} else {
		/* Short header - use configured CID length */
		dcid.len = 8; /* Default length */
		if (len < 1 + dcid.len) {
			kfree_skb(skb);
			return;
		}
		memcpy(dcid.data, &data[1], dcid.len);
	}

	/* Find connection */
	conn = quic_conn_lookup(qsk, &dcid);
	if (!conn) {
		/* For listening sockets, this might be a new connection */
		if (qsk->sk.sk_state == TCP_LISTEN) {
			/* Handle new connection - would need Initial packet processing */
			pr_debug("potential new connection\n");
		}
		kfree_skb(skb);
		return;
	}

	/* Queue packet for processing */
	skb_queue_tail(&conn->rx_queue, skb);

	/* Reset idle timer */
	quic_timer_reset_idle(conn);

	/* Update statistics */
	conn->packets_recv++;
	conn->bytes_recv += len;

	/* Schedule work */
	queue_work(quic_workqueue, &conn->work);

	quic_conn_put(conn);
}

static int quic_udp_encap_rcv(struct sock *sk, struct sk_buff *skb)
{
	/* Called by UDP layer for encapsulated packets */
	quic_udp_recv(sk, skb);
	return 0;
}

static int quic_setup_udp_sock(struct quic_sock *qsk)
{
	struct socket *sock;
	struct sock *sk;
	int err;

	err = sock_create_kern(sock_net(&qsk->sk), qsk->sk.sk_family,
			       SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (err)
		return err;

	sk = sock->sk;

	/* Set up encapsulation callbacks */
	udp_sk(sk)->encap_type = 1; /* Custom encapsulation */
	udp_sk(sk)->encap_rcv = quic_udp_encap_rcv;
	rcu_assign_pointer(sk->sk_user_data, qsk);

	/* Enable immediate callback */
	udp_encap_enable();

	qsk->udp_sock = sock;

	return 0;
}

static void quic_release_udp_sock(struct quic_sock *qsk)
{
	if (qsk->udp_sock) {
		struct sock *sk = qsk->udp_sock->sk;

		rcu_assign_pointer(sk->sk_user_data, NULL);
		synchronize_rcu();
		sock_release(qsk->udp_sock);
		qsk->udp_sock = NULL;
	}
}

/* ============================================================================
 * Socket Operations
 * ============================================================================
 */

static int quic_init_sock(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);

	pr_debug("init_sock: sk=%p\n", sk);

	/* Initialize socket state */
	sk->sk_state = TCP_CLOSE;
	sock_set_flag(sk, SOCK_RCU_FREE);

	/* Initialize accept queue */
	INIT_LIST_HEAD(&qsk->accept_queue);
	spin_lock_init(&qsk->accept_lock);
	qsk->accept_queue_len = 0;
	qsk->max_accept_queue = quic_max_connections;

	/* Initialize connection hash */
	qsk->conn_hash_size = 256;
	qsk->conn_hash = kcalloc(qsk->conn_hash_size,
				 sizeof(struct hlist_head), GFP_KERNEL);
	if (!qsk->conn_hash)
		return -ENOMEM;
	spin_lock_init(&qsk->conn_hash_lock);

	/* Set default socket options */
	qsk->idle_timeout = quic_idle_timeout_ms;
	qsk->max_udp_payload_size = quic_max_udp_payload;
	qsk->initial_max_data = quic_initial_max_data;
	qsk->initial_max_stream_data_bidi_local = quic_initial_max_stream_data;
	qsk->initial_max_stream_data_bidi_remote = quic_initial_max_stream_data;
	qsk->initial_max_stream_data_uni = quic_initial_max_stream_data;
	qsk->initial_max_streams_bidi = quic_max_streams_bidi;
	qsk->initial_max_streams_uni = quic_max_streams_uni;
	qsk->ack_delay_exponent = quic_ack_delay_exponent;
	qsk->max_ack_delay = quic_max_ack_delay_ms;

	/* Set up UDP socket */
	if (quic_setup_udp_sock(qsk) < 0) {
		kfree(qsk->conn_hash);
		return -ENOMEM;
	}

	percpu_counter_inc(&quic_sockets_allocated);

	return 0;
}

static void quic_destroy_sock(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_accept_entry *entry, *tmp;

	pr_debug("destroy_sock: sk=%p\n", sk);

	/* Release UDP socket */
	quic_release_udp_sock(qsk);

	/* Free connection */
	if (qsk->conn) {
		quic_conn_put(qsk->conn);
		qsk->conn = NULL;
	}

	/* Free accept queue */
	spin_lock_bh(&qsk->accept_lock);
	list_for_each_entry_safe(entry, tmp, &qsk->accept_queue, node) {
		list_del(&entry->node);
		quic_conn_put(entry->conn);
		kfree(entry);
	}
	spin_unlock_bh(&qsk->accept_lock);

	/* Free connection hash */
	kfree(qsk->conn_hash);

	percpu_counter_dec(&quic_sockets_allocated);
}

static void quic_close(struct sock *sk, long timeout)
{
	struct quic_sock *qsk = quic_sk(sk);

	pr_debug("close: sk=%p timeout=%ld\n", sk, timeout);

	lock_sock(sk);

	if (qsk->conn && qsk->conn->state == QUIC_STATE_CONNECTED) {
		/* Initiate graceful close */
		quic_state_machine(qsk->conn, QUIC_EVENT_CLOSE);
	}

	sk->sk_state = TCP_CLOSE;
	sk->sk_shutdown = SHUTDOWN_MASK;

	release_sock(sk);

	sk_common_release(sk);
}

static int quic_connect(struct sock *sk, struct sockaddr_unsized *uaddr, int addr_len)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn;
	struct sockaddr_in *addr4 = (struct sockaddr_in *)uaddr;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)uaddr;
	int err;

	pr_debug("connect: sk=%p\n", sk);

	lock_sock(sk);

	if (sk->sk_state != TCP_CLOSE) {
		err = -EISCONN;
		goto out;
	}

	/* Validate address */
	if (sk->sk_family == AF_INET) {
		if (addr_len < sizeof(struct sockaddr_in)) {
			err = -EINVAL;
			goto out;
		}
		if (addr4->sin_family != AF_INET) {
			err = -EAFNOSUPPORT;
			goto out;
		}
	} else if (sk->sk_family == AF_INET6) {
		if (addr_len < sizeof(struct sockaddr_in6)) {
			err = -EINVAL;
			goto out;
		}
		if (addr6->sin6_family != AF_INET6) {
			err = -EAFNOSUPPORT;
			goto out;
		}
	} else {
		err = -EAFNOSUPPORT;
		goto out;
	}

	/* Allocate connection */
	conn = quic_conn_alloc(qsk, GFP_KERNEL);
	if (!conn) {
		err = -ENOMEM;
		goto out;
	}

	/* Store remote address */
	conn->addr_family = sk->sk_family;
	if (sk->sk_family == AF_INET) {
		memcpy(&conn->remote_addr.addr4, addr4, sizeof(*addr4));
	} else {
		memcpy(&conn->remote_addr.addr6, addr6, sizeof(*addr6));
	}

	/* Connect UDP socket */
	err = kernel_connect(qsk->udp_sock, (struct sockaddr *)uaddr, addr_len, 0);
	if (err)
		goto err_free_conn;

	/* Start handshake */
	err = quic_state_machine(conn, QUIC_EVENT_CONNECT);
	if (err)
		goto err_free_conn;

	/* Add to hash table */
	err = quic_conn_hash_insert(qsk, conn);
	if (err)
		goto err_free_conn;

	qsk->conn = conn;
	sk->sk_state = TCP_SYN_SENT;

	/* In a full implementation, we would send Initial packet here */
	pr_debug("connection initiated\n");

	/* For now, simulate immediate connection (handshake would complete async) */
	quic_state_machine(conn, QUIC_EVENT_HANDSHAKE_DONE);
	sk->sk_state = TCP_ESTABLISHED;

	release_sock(sk);
	return 0;

err_free_conn:
	quic_conn_put(conn);
out:
	release_sock(sk);
	return err;
}

static int quic_disconnect(struct sock *sk, int flags)
{
	struct quic_sock *qsk = quic_sk(sk);

	pr_debug("disconnect: sk=%p\n", sk);

	lock_sock(sk);

	if (qsk->conn) {
		quic_state_machine(qsk->conn, QUIC_EVENT_CLOSE);
	}

	sk->sk_state = TCP_CLOSE;

	release_sock(sk);
	return 0;
}

static int quic_bind(struct socket *sock, struct sockaddr_unsized *uaddr, int addr_len)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	struct sockaddr_in *addr4 = (struct sockaddr_in *)uaddr;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)uaddr;
	int err;

	pr_debug("bind: sk=%p\n", sk);

	lock_sock(sk);

	/* Validate address family */
	if (sk->sk_family == AF_INET) {
		if (addr_len < sizeof(struct sockaddr_in)) {
			err = -EINVAL;
			goto out;
		}
		if (addr4->sin_family != AF_INET) {
			err = -EAFNOSUPPORT;
			goto out;
		}
		memcpy(&qsk->local_addr.addr4, addr4, sizeof(*addr4));
	} else if (sk->sk_family == AF_INET6) {
		if (addr_len < sizeof(struct sockaddr_in6)) {
			err = -EINVAL;
			goto out;
		}
		if (addr6->sin6_family != AF_INET6) {
			err = -EAFNOSUPPORT;
			goto out;
		}
		memcpy(&qsk->local_addr.addr6, addr6, sizeof(*addr6));
	} else {
		err = -EAFNOSUPPORT;
		goto out;
	}

	/* Bind the UDP socket */
	err = kernel_bind(qsk->udp_sock, (struct sockaddr *)uaddr, addr_len);
	if (err)
		goto out;

	sk->sk_state = TCP_BOUND;
	err = 0;

out:
	release_sock(sk);
	return err;
}

static int quic_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	int err = 0;

	pr_debug("listen: sk=%p backlog=%d\n", sk, backlog);

	lock_sock(sk);

	if (sk->sk_state != TCP_CLOSE && sk->sk_state != TCP_BOUND) {
		err = -EINVAL;
		goto out;
	}

	qsk->max_accept_queue = backlog;
	sk->sk_state = TCP_LISTEN;

out:
	release_sock(sk);
	return err;
}

static struct sock *quic_accept(struct sock *sk, struct proto_accept_arg *arg)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_accept_entry *entry;
	struct quic_connection *conn;
	struct socket *newsock;
	struct sock *newsk;
	int err;

	pr_debug("accept: sk=%p\n", sk);

	if (sk->sk_state != TCP_LISTEN) {
		arg->err = -EINVAL;
		return NULL;
	}

	/* Wait for connection */
	for (;;) {
		spin_lock_bh(&qsk->accept_lock);
		if (!list_empty(&qsk->accept_queue)) {
			entry = list_first_entry(&qsk->accept_queue,
						 struct quic_accept_entry, node);
			list_del(&entry->node);
			qsk->accept_queue_len--;
			spin_unlock_bh(&qsk->accept_lock);
			conn = entry->conn;
			kfree(entry);
			break;
		}
		spin_unlock_bh(&qsk->accept_lock);

		if (arg->flags & O_NONBLOCK) {
			arg->err = -EAGAIN;
			return NULL;
		}

		/* Wait for new connection */
		err = sock_wait_for_wmem(sk, 0);
		if (err) {
			arg->err = err;
			return NULL;
		}
	}

	/* Create new socket for the connection */
	err = sock_create_lite(sk->sk_family, sk->sk_type, sk->sk_protocol, &newsock);
	if (err) {
		quic_conn_put(conn);
		arg->err = err;
		return NULL;
	}

	newsk = sk_alloc(sock_net(sk), sk->sk_family, GFP_KERNEL, sk->sk_prot, arg->kern);
	if (!newsk) {
		sock_release(newsock);
		quic_conn_put(conn);
		arg->err = -ENOMEM;
		return NULL;
	}

	sock_init_data(newsock, newsk);
	newsock->ops = sk->sk_socket->ops;
	newsk->sk_state = TCP_ESTABLISHED;

	/* Associate connection with new socket */
	quic_sk(newsk)->conn = conn;
	conn->qsk = quic_sk(newsk);

	return newsk;
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn;
	struct quic_stream *stream;
	struct sk_buff *skb;
	size_t sent = 0;
	int err;

	pr_debug("sendmsg: sk=%p len=%zu\n", sk, len);

	lock_sock(sk);

	conn = qsk->conn;
	if (!conn || !quic_state_can_send(conn->state)) {
		err = -ENOTCONN;
		goto out;
	}

	/* Get or create default stream */
	stream = quic_stream_find(conn, 0);
	if (!stream) {
		stream = quic_stream_create(conn, true, GFP_KERNEL);
		if (!stream) {
			err = -ENOMEM;
			goto out;
		}
	}

	/* Check flow control */
	if (!quic_flow_can_send(&conn->flow, len)) {
		if (msg->msg_flags & MSG_DONTWAIT) {
			err = -EAGAIN;
			goto out;
		}
		/* Would need to wait for flow control credit */
	}

	/* Copy data to send buffer */
	while (sent < len) {
		size_t chunk = min_t(size_t, len - sent, quic_max_udp_payload - 100);

		skb = alloc_skb(chunk + 100, GFP_KERNEL);
		if (!skb) {
			err = sent ? sent : -ENOMEM;
			goto out;
		}

		skb_reserve(skb, 50); /* Room for headers */

		err = skb_copy_datagram_from_iter(skb, 0, &msg->msg_iter, chunk);
		if (err) {
			kfree_skb(skb);
			err = sent ? sent : err;
			goto out;
		}

		skb_put(skb, chunk);

		/* In a full implementation, we would add QUIC headers here */

		/* Queue for transmission */
		skb_queue_tail(&conn->tx_queue, skb);
		sent += chunk;

		quic_flow_on_send(&conn->flow, chunk);
	}

	/* Schedule transmission */
	queue_work(quic_workqueue, &conn->work);

	/* Update timers */
	quic_timer_reset_idle(conn);
	quic_timer_update_loss(conn);

	err = sent;

out:
	release_sock(sk);
	return err;
}

static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			int flags, int *addr_len)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn;
	struct sk_buff *skb;
	size_t copied = 0;
	int err;

	pr_debug("recvmsg: sk=%p len=%zu flags=%d\n", sk, len, flags);

	lock_sock(sk);

	conn = qsk->conn;
	if (!conn) {
		err = -ENOTCONN;
		goto out;
	}

	/* Wait for data */
	while (skb_queue_empty(&conn->rx_queue)) {
		if (!quic_state_can_recv(conn->state)) {
			err = 0; /* EOF */
			goto out;
		}

		if (flags & MSG_DONTWAIT) {
			err = -EAGAIN;
			goto out;
		}

		release_sock(sk);
		err = wait_event_interruptible(sk->sk_wq->wait,
					       !skb_queue_empty(&conn->rx_queue) ||
					       !quic_state_can_recv(conn->state));
		lock_sock(sk);

		if (err)
			goto out;
	}

	/* Copy data to user */
	while (copied < len && !skb_queue_empty(&conn->rx_queue)) {
		size_t chunk;

		skb = skb_peek(&conn->rx_queue);
		if (!skb)
			break;

		chunk = min_t(size_t, len - copied, skb->len);

		err = skb_copy_datagram_msg(skb, 0, msg, chunk);
		if (err)
			goto out;

		copied += chunk;

		if (chunk >= skb->len) {
			skb_unlink(skb, &conn->rx_queue);
			kfree_skb(skb);
		} else {
			skb_pull(skb, chunk);
		}

		quic_flow_on_recv(&conn->flow, chunk);
	}

	/* Update idle timer */
	quic_timer_reset_idle(conn);

	err = copied;

out:
	release_sock(sk);
	return err;
}

static __poll_t quic_poll(struct file *file, struct socket *sock,
			  struct poll_table_struct *wait)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	__poll_t mask = 0;

	sock_poll_wait(file, sock, wait);

	if (sk->sk_state == TCP_LISTEN) {
		/* Listening socket - check accept queue */
		spin_lock_bh(&qsk->accept_lock);
		if (!list_empty(&qsk->accept_queue))
			mask |= EPOLLIN | EPOLLRDNORM;
		spin_unlock_bh(&qsk->accept_lock);
		return mask;
	}

	if (sk->sk_state == TCP_CLOSE)
		mask |= EPOLLHUP;

	if (sk->sk_err)
		mask |= EPOLLERR;

	if (qsk->conn) {
		struct quic_connection *conn = qsk->conn;

		/* Check for readable data */
		if (!skb_queue_empty(&conn->rx_queue))
			mask |= EPOLLIN | EPOLLRDNORM;

		/* Check for writability */
		if (quic_state_can_send(conn->state) &&
		    quic_congestion_can_send(&conn->congestion, quic_max_udp_payload))
			mask |= EPOLLOUT | EPOLLWRNORM;

		/* Check for connection close */
		if (conn->state == QUIC_STATE_CLOSED ||
		    conn->state == QUIC_STATE_DRAINING)
			mask |= EPOLLHUP;
	} else if (sk->sk_state == TCP_ESTABLISHED) {
		/* Connected but no connection struct - error */
		mask |= EPOLLERR;
	}

	return mask;
}

static int quic_ioctl(struct sock *sk, int cmd, int *karg)
{
	struct quic_sock *qsk = quic_sk(sk);
	int val = 0;

	pr_debug("ioctl: sk=%p cmd=%d\n", sk, cmd);

	switch (cmd) {
	case SIOCINQ:
		/* Return amount of data in receive buffer */
		if (qsk->conn)
			val = skb_queue_len(&qsk->conn->rx_queue);
		*karg = val;
		return 0;

	case SIOCOUTQ:
		/* Return amount of data in send buffer */
		if (qsk->conn)
			val = skb_queue_len(&qsk->conn->tx_queue);
		*karg = val;
		return 0;

	default:
		return -ENOIOCTLCMD;
	}
}

/* QUIC-specific socket options */
#define SOL_QUIC		289	/* QUIC socket options level */

/* Option names */
#define QUIC_SOCKOPT_VERSION		1
#define QUIC_SOCKOPT_IDLE_TIMEOUT	2
#define QUIC_SOCKOPT_MAX_DATA		3
#define QUIC_SOCKOPT_MAX_STREAM_DATA	4
#define QUIC_SOCKOPT_MAX_STREAMS_BIDI	5
#define QUIC_SOCKOPT_MAX_STREAMS_UNI	6
#define QUIC_SOCKOPT_ACK_DELAY_EXPONENT	7
#define QUIC_SOCKOPT_MAX_ACK_DELAY	8
#define QUIC_SOCKOPT_DISABLE_MIGRATION	9
#define QUIC_SOCKOPT_STATS		10

struct quic_stats {
	u64 packets_sent;
	u64 packets_recv;
	u64 bytes_sent;
	u64 bytes_recv;
	u64 packets_lost;
	u64 rtt_min;
	u64 rtt_smoothed;
	u64 cwnd;
	u64 bytes_in_flight;
};

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	struct quic_sock *qsk = quic_sk(sk);
	int val;
	int err = 0;

	pr_debug("setsockopt: sk=%p level=%d optname=%d\n", sk, level, optname);

	if (level != SOL_QUIC)
		return -ENOPROTOOPT;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (copy_from_sockptr(&val, optval, sizeof(int)))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case QUIC_SOCKOPT_IDLE_TIMEOUT:
		if (val < 0) {
			err = -EINVAL;
			break;
		}
		qsk->idle_timeout = val;
		break;

	case QUIC_SOCKOPT_MAX_DATA:
		if (val < 0) {
			err = -EINVAL;
			break;
		}
		qsk->initial_max_data = val;
		break;

	case QUIC_SOCKOPT_MAX_STREAM_DATA:
		if (val < 0) {
			err = -EINVAL;
			break;
		}
		qsk->initial_max_stream_data_bidi_local = val;
		qsk->initial_max_stream_data_bidi_remote = val;
		qsk->initial_max_stream_data_uni = val;
		break;

	case QUIC_SOCKOPT_MAX_STREAMS_BIDI:
		if (val < 0) {
			err = -EINVAL;
			break;
		}
		qsk->initial_max_streams_bidi = val;
		break;

	case QUIC_SOCKOPT_MAX_STREAMS_UNI:
		if (val < 0) {
			err = -EINVAL;
			break;
		}
		qsk->initial_max_streams_uni = val;
		break;

	case QUIC_SOCKOPT_ACK_DELAY_EXPONENT:
		if (val < 0 || val > 20) {
			err = -EINVAL;
			break;
		}
		qsk->ack_delay_exponent = val;
		break;

	case QUIC_SOCKOPT_MAX_ACK_DELAY:
		if (val < 0 || val > 16383) {
			err = -EINVAL;
			break;
		}
		qsk->max_ack_delay = val;
		break;

	case QUIC_SOCKOPT_DISABLE_MIGRATION:
		qsk->disable_active_migration = !!val;
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}

static int quic_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_stats stats;
	int val;
	int len;

	pr_debug("getsockopt: sk=%p level=%d optname=%d\n", sk, level, optname);

	if (level != SOL_QUIC)
		return -ENOPROTOOPT;

	if (get_user(len, optlen))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case QUIC_SOCKOPT_VERSION:
		val = 1; /* QUIC v1 */
		break;

	case QUIC_SOCKOPT_IDLE_TIMEOUT:
		val = qsk->idle_timeout;
		break;

	case QUIC_SOCKOPT_MAX_DATA:
		val = qsk->initial_max_data;
		break;

	case QUIC_SOCKOPT_MAX_STREAM_DATA:
		val = qsk->initial_max_stream_data_bidi_local;
		break;

	case QUIC_SOCKOPT_MAX_STREAMS_BIDI:
		val = qsk->initial_max_streams_bidi;
		break;

	case QUIC_SOCKOPT_MAX_STREAMS_UNI:
		val = qsk->initial_max_streams_uni;
		break;

	case QUIC_SOCKOPT_ACK_DELAY_EXPONENT:
		val = qsk->ack_delay_exponent;
		break;

	case QUIC_SOCKOPT_MAX_ACK_DELAY:
		val = qsk->max_ack_delay;
		break;

	case QUIC_SOCKOPT_DISABLE_MIGRATION:
		val = qsk->disable_active_migration;
		break;

	case QUIC_SOCKOPT_STATS:
		if (len < sizeof(stats)) {
			release_sock(sk);
			return -EINVAL;
		}
		memset(&stats, 0, sizeof(stats));
		if (qsk->conn) {
			stats.packets_sent = qsk->conn->packets_sent;
			stats.packets_recv = qsk->conn->packets_recv;
			stats.bytes_sent = qsk->conn->bytes_sent;
			stats.bytes_recv = qsk->conn->bytes_recv;
			stats.packets_lost = qsk->conn->packets_lost;
			stats.rtt_min = qsk->conn->rtt.min_rtt;
			stats.rtt_smoothed = qsk->conn->rtt.smoothed_rtt;
			stats.cwnd = qsk->conn->congestion.cwnd;
			stats.bytes_in_flight = qsk->conn->congestion.bytes_in_flight;
		}
		release_sock(sk);
		if (put_user(sizeof(stats), optlen))
			return -EFAULT;
		if (copy_to_user(optval, &stats, sizeof(stats)))
			return -EFAULT;
		return 0;

	default:
		release_sock(sk);
		return -ENOPROTOOPT;
	}

	release_sock(sk);

	if (put_user(sizeof(int), optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, sizeof(int)))
		return -EFAULT;

	return 0;
}

static int quic_hash(struct sock *sk)
{
	/* QUIC manages its own connection hash */
	return 0;
}

static void quic_unhash(struct sock *sk)
{
	/* QUIC manages its own connection hash */
}

static int quic_get_port(struct sock *sk, unsigned short snum)
{
	struct quic_sock *qsk = quic_sk(sk);

	/* Delegate to UDP socket */
	if (qsk->udp_sock)
		return inet_csk_get_port(qsk->udp_sock->sk, snum);

	return 0;
}

/* ============================================================================
 * Protocol Definitions
 * ============================================================================
 */

static struct proto quic_prot = {
	.name		= "QUIC",
	.owner		= THIS_MODULE,
	.init		= quic_init_sock,
	.destroy	= quic_destroy_sock,
	.close		= quic_close,
	.connect	= quic_connect,
	.disconnect	= quic_disconnect,
	.accept		= quic_accept,
	.ioctl		= quic_ioctl,
	.setsockopt	= quic_setsockopt,
	.getsockopt	= quic_getsockopt,
	.sendmsg	= quic_sendmsg,
	.recvmsg	= quic_recvmsg,
	.hash		= quic_hash,
	.unhash		= quic_unhash,
	.get_port	= quic_get_port,
	.sockets_allocated = &quic_sockets_allocated,
	.obj_size	= sizeof(struct quic_sock),
	.slab_flags	= SLAB_TYPESAFE_BY_RCU,
	.no_autobind	= true,
};

static int quic_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	pr_debug("release: sock=%p sk=%p\n", sock, sk);

	sock->sk = NULL;
	return sk->sk_prot->close(sk, 0) ? : 0;
}

static int quic_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)uaddr;

	if (peer) {
		if (!qsk->conn)
			return -ENOTCONN;

		if (sk->sk_family == AF_INET) {
			memcpy(sin, &qsk->conn->remote_addr.addr4, sizeof(*sin));
			return sizeof(*sin);
		} else {
			memcpy(sin6, &qsk->conn->remote_addr.addr6, sizeof(*sin6));
			return sizeof(*sin6);
		}
	} else {
		if (sk->sk_family == AF_INET) {
			memcpy(sin, &qsk->local_addr.addr4, sizeof(*sin));
			return sizeof(*sin);
		} else {
			memcpy(sin6, &qsk->local_addr.addr6, sizeof(*sin6));
			return sizeof(*sin6);
		}
	}
}

static int quic_stream_accept(struct socket *sock, struct socket *newsock,
			      struct proto_accept_arg *arg)
{
	struct sock *sk = sock->sk;
	struct sock *newsk;

	lock_sock(sk);
	newsk = sk->sk_prot->accept(sk, arg);
	release_sock(sk);

	if (!newsk)
		return arg->err;

	lock_sock(newsk);
	sock_graft(newsk, newsock);
	newsock->state = SS_CONNECTED;
	release_sock(newsk);

	return 0;
}

static int quic_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	int err = 0;

	pr_debug("shutdown: sk=%p how=%d\n", sk, how);

	lock_sock(sk);

	if (qsk->conn && quic_state_can_send(qsk->conn->state)) {
		quic_state_machine(qsk->conn, QUIC_EVENT_CLOSE);
	}

	sk->sk_shutdown |= how;

	release_sock(sk);
	return err;
}

static const struct proto_ops quic_stream_ops = {
	.family		= PF_QUIC,
	.owner		= THIS_MODULE,
	.release	= quic_release,
	.bind		= quic_bind,
	.connect	= inet_stream_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= quic_stream_accept,
	.getname	= quic_getname,
	.poll		= quic_poll,
	.ioctl		= sock_no_ioctl,
	.gettstamp	= sock_gettstamp,
	.listen		= quic_listen,
	.shutdown	= quic_shutdown,
	.setsockopt	= sock_common_setsockopt,
	.getsockopt	= sock_common_getsockopt,
	.sendmsg	= inet_sendmsg,
	.recvmsg	= inet_recvmsg,
	.mmap		= sock_no_mmap,
};

/* ============================================================================
 * Socket Creation
 * ============================================================================
 */

static int quic_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct sock *sk;
	int err;

	pr_debug("create: protocol=%d kern=%d\n", protocol, kern);

	/* Only support SOCK_STREAM and SOCK_DGRAM for QUIC */
	if (sock->type != SOCK_STREAM && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	/* Allocate socket */
	sk = sk_alloc(net, PF_QUIC, GFP_KERNEL, &quic_prot, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	sk->sk_protocol = protocol;

	sock->ops = &quic_stream_ops;
	sock->state = SS_UNCONNECTED;

	/* Initialize protocol-specific state */
	err = sk->sk_prot->init(sk);
	if (err) {
		sk_common_release(sk);
		return err;
	}

	return 0;
}

/* ============================================================================
 * Protocol Family Registration
 * ============================================================================
 */

static const struct net_proto_family quic_family_ops = {
	.family	= PF_QUIC,
	.create	= quic_create,
	.owner	= THIS_MODULE,
};

/* Also register as INET protocol for interoperability */
static struct inet_protosw quic_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_QUIC,
	.prot		= &quic_prot,
	.ops		= &quic_stream_ops,
	.flags		= 0,
};

/* ============================================================================
 * Module Init/Exit
 * ============================================================================
 */

static int __init quic_proto_init(void)
{
	int err;

	pr_info("QUIC Protocol support initializing\n");

	/* Allocate slab caches */
	quic_conn_cachep = kmem_cache_create("quic_connection",
					     sizeof(struct quic_connection),
					     0, SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT,
					     NULL);
	if (!quic_conn_cachep) {
		pr_err("failed to allocate connection cache\n");
		return -ENOMEM;
	}

	quic_stream_cachep = kmem_cache_create("quic_stream",
					       sizeof(struct quic_stream),
					       0, SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT,
					       NULL);
	if (!quic_stream_cachep) {
		pr_err("failed to allocate stream cache\n");
		err = -ENOMEM;
		goto err_stream_cache;
	}

	/* Initialize socket counter */
	err = percpu_counter_init(&quic_sockets_allocated, 0, GFP_KERNEL);
	if (err) {
		pr_err("failed to allocate socket counter\n");
		goto err_counter;
	}

	/* Create workqueue */
	quic_workqueue = alloc_workqueue("quic", WQ_HIGHPRI | WQ_MEM_RECLAIM, 0);
	if (!quic_workqueue) {
		pr_err("failed to allocate workqueue\n");
		err = -ENOMEM;
		goto err_workqueue;
	}

	/* Register protocol */
	err = proto_register(&quic_prot, 1);
	if (err) {
		pr_err("failed to register protocol: %d\n", err);
		goto err_proto;
	}

	/* Register socket family */
	err = sock_register(&quic_family_ops);
	if (err) {
		pr_err("failed to register socket family: %d\n", err);
		goto err_family;
	}

	/* Register with INET layer for IPv4 */
	inet_register_protosw(&quic_stream_protosw);

	pr_info("QUIC Protocol support initialized (AF_QUIC=%d)\n", AF_QUIC);
	pr_info("  max_connections=%u idle_timeout=%ums initial_rtt=%uus\n",
		quic_max_connections, quic_idle_timeout_ms, quic_initial_rtt_us);
	pr_info("  max_udp_payload=%u max_streams_bidi=%u max_streams_uni=%u\n",
		quic_max_udp_payload, quic_max_streams_bidi, quic_max_streams_uni);

	return 0;

err_family:
	proto_unregister(&quic_prot);
err_proto:
	destroy_workqueue(quic_workqueue);
err_workqueue:
	percpu_counter_destroy(&quic_sockets_allocated);
err_counter:
	kmem_cache_destroy(quic_stream_cachep);
err_stream_cache:
	kmem_cache_destroy(quic_conn_cachep);
	return err;
}

static void __exit quic_proto_exit(void)
{
	pr_info("QUIC Protocol support exiting\n");

	/* Unregister from INET layer */
	inet_unregister_protosw(&quic_stream_protosw);

	/* Unregister socket family */
	sock_unregister(PF_QUIC);

	/* Unregister protocol */
	proto_unregister(&quic_prot);

	/* Destroy workqueue */
	destroy_workqueue(quic_workqueue);

	/* Destroy socket counter */
	percpu_counter_destroy(&quic_sockets_allocated);

	/* Destroy slab caches */
	kmem_cache_destroy(quic_stream_cachep);
	kmem_cache_destroy(quic_conn_cachep);

	pr_info("QUIC Protocol support removed\n");
}

module_init(quic_proto_init);
module_exit(quic_proto_exit);

MODULE_AUTHOR("Linux QUIC Authors");
MODULE_DESCRIPTION("QUIC Protocol (RFC 9000) Implementation");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
MODULE_ALIAS_NETPROTO(PF_QUIC);
