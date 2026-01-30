// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Connection Management
 *
 * Implementation of QUIC connection management per RFC 9000.
 * Includes connection ID management, state machine, handshake handling,
 * connection migration, congestion control, RTT estimation, and flow control.
 *
 * Copyright (c) 2024 Linux QUIC Contributors
 */

#define pr_fmt(fmt) "QUIC: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <net/udp.h>

/*
 * QUIC Connection ID - RFC 9000 Section 5.1
 * Connection IDs are used to identify connections at endpoints.
 * Each endpoint selects connection IDs for its peer to use.
 */
#define QUIC_CID_MAX_LEN		20
#define QUIC_CID_MIN_LEN		0
#define QUIC_CID_DEFAULT_LEN		8

/* Maximum number of connection IDs per connection (RFC 9000 Section 5.1.1) */
#define QUIC_MAX_CIDS_PER_CONN		8

/* Connection ID hashtable size (power of 2) */
#define QUIC_CID_HASH_BITS		12

/* Path validation timeout (in milliseconds) - RFC 9000 Section 8.2.4 */
#define QUIC_PATH_VALIDATION_TIMEOUT_MS	30000

/* Initial RTT estimate (RFC 9002 Section 6.2.2) */
#define QUIC_INITIAL_RTT_US		333000	/* 333ms */

/* RTT constants per RFC 9002 */
#define QUIC_RTT_GRANULARITY_US		1000	/* 1ms */
#define QUIC_MAX_ACK_DELAY_US		25000	/* 25ms default */
#define QUIC_PTO_MULTIPLIER		3

/* Congestion control constants per RFC 9002 */
#define QUIC_INITIAL_WINDOW_PACKETS	10
#define QUIC_MIN_WINDOW_PACKETS		2
#define QUIC_LOSS_REDUCTION_FACTOR	2	/* Multiplicative decrease factor */
#define QUIC_PERSISTENT_CONGESTION_THRESHOLD	3

/* Default packet sizes */
#define QUIC_MIN_MTU			1200
#define QUIC_DEFAULT_MTU		1280

/* Flow control defaults (RFC 9000 Section 4) */
#define QUIC_DEFAULT_MAX_DATA			BIT(20)		/* 1MB */
#define QUIC_DEFAULT_MAX_STREAM_DATA_BIDI	BIT(18)		/* 256KB */
#define QUIC_DEFAULT_MAX_STREAM_DATA_UNI	BIT(18)		/* 256KB */

/* Connection states per RFC 9000 */
enum quic_conn_state {
	QUIC_CONN_STATE_IDLE = 0,
	QUIC_CONN_STATE_HANDSHAKE,
	QUIC_CONN_STATE_EARLY_DATA,
	QUIC_CONN_STATE_CONNECTED,
	QUIC_CONN_STATE_CLOSING,
	QUIC_CONN_STATE_DRAINING,
	QUIC_CONN_STATE_CLOSED,
	__QUIC_CONN_STATE_MAX
};

/* Handshake states */
enum quic_handshake_state {
	QUIC_HS_STATE_INITIAL = 0,
	QUIC_HS_STATE_CLIENT_HELLO_SENT,
	QUIC_HS_STATE_SERVER_HELLO_RECEIVED,
	QUIC_HS_STATE_HANDSHAKE_KEYS_DERIVED,
	QUIC_HS_STATE_CLIENT_FINISHED_SENT,
	QUIC_HS_STATE_SERVER_FINISHED_RECEIVED,
	QUIC_HS_STATE_HANDSHAKE_CONFIRMED,
	QUIC_HS_STATE_COMPLETE,
	QUIC_HS_STATE_FAILED,
	__QUIC_HS_STATE_MAX
};

/* Path validation states */
enum quic_path_state {
	QUIC_PATH_STATE_UNKNOWN = 0,
	QUIC_PATH_STATE_VALIDATING,
	QUIC_PATH_STATE_VALIDATED,
	QUIC_PATH_STATE_FAILED,
	__QUIC_PATH_STATE_MAX
};

/* Congestion controller states per RFC 9002 */
enum quic_cc_state {
	QUIC_CC_STATE_SLOW_START = 0,
	QUIC_CC_STATE_CONGESTION_AVOIDANCE,
	QUIC_CC_STATE_RECOVERY,
	__QUIC_CC_STATE_MAX
};

/* QUIC Connection ID structure */
struct quic_cid {
	u8			data[QUIC_CID_MAX_LEN];
	u8			len;
	u64			seq_num;		/* Sequence number for this CID */
	u8			stateless_reset_token[16];
	bool			has_reset_token;
	struct hlist_node	hash_node;		/* For CID hashtable */
	struct list_head	list_node;		/* Per-connection CID list */
	struct quic_connection	*conn;			/* Back pointer to connection */
	struct rcu_head		rcu;
	refcount_t		refcnt;
};

/* RTT estimation structure per RFC 9002 */
struct quic_rtt {
	u64			latest_rtt;		/* Most recent RTT sample */
	u64			smoothed_rtt;		/* Smoothed RTT (SRTT) */
	u64			rtt_var;		/* RTT variation (RTTVAR) */
	u64			min_rtt;		/* Minimum RTT observed */
	u64			max_ack_delay;		/* Maximum ACK delay */
	ktime_t			first_rtt_sample_time;	/* Time of first sample */
	bool			has_first_sample;	/* Have we received a sample? */
	spinlock_t		lock;			/* Protects RTT fields */
};

/* Congestion control state per RFC 9002 */
struct quic_congestion_control {
	enum quic_cc_state	state;
	u64			cwnd;			/* Congestion window in bytes */
	u64			ssthresh;		/* Slow start threshold */
	u64			bytes_in_flight;	/* Outstanding data */
	u64			recovery_start_time;	/* Start of recovery period */
	u64			congestion_recovery_start_time;
	u64			bytes_acked_in_ca;	/* For congestion avoidance */
	u32			ecn_ce_counters[3];	/* ECN counters per PN space */

	/* Persistent congestion detection */
	ktime_t			first_sent_time;
	ktime_t			last_sent_time;

	/* Statistics */
	u64			total_bytes_sent;
	u64			total_bytes_acked;
	u64			total_bytes_lost;
	u64			packets_sent;
	u64			packets_acked;
	u64			packets_lost;

	spinlock_t		lock;			/* Protects CC state */
};

/* Flow control state per RFC 9000 Section 4 */
struct quic_flow_control {
	/* Connection-level flow control */
	u64			max_data_local;		/* Max data we can receive */
	u64			max_data_remote;	/* Max data we can send */
	u64			data_sent;		/* Total bytes sent */
	u64			data_received;		/* Total bytes received */

	/* Window update thresholds */
	u64			max_data_next;		/* Next MAX_DATA to send */
	bool			max_data_update_needed;	/* Need to send MAX_DATA */

	/* Stream count limits */
	u64			max_streams_bidi_local;
	u64			max_streams_bidi_remote;
	u64			max_streams_uni_local;
	u64			max_streams_uni_remote;
	u64			streams_bidi_opened;
	u64			streams_uni_opened;

	spinlock_t		lock;			/* Protects flow state */
};

/* Path information for connection migration */
struct quic_path {
	struct sockaddr_storage	local_addr;
	struct sockaddr_storage	peer_addr;
	enum quic_path_state	state;
	u8			challenge[8];		/* PATH_CHALLENGE data */
	u8			response[8];		/* PATH_RESPONSE data */
	ktime_t			challenge_sent_time;
	int			challenge_count;
	u32			mtu;			/* Path MTU */
	bool			validated;
	bool			is_primary;
	struct list_head	list_node;
	struct rcu_head		rcu;
};

/* Sent packet information for loss detection */
struct quic_sent_packet {
	u64			packet_number;
	ktime_t			sent_time;
	u32			sent_bytes;		/* Bytes in this packet */
	bool			ack_eliciting;		/* Requires ACK */
	bool			in_flight;		/* Counts against cwnd */
	bool			is_crypto;		/* Contains CRYPTO frames */
	u8			encryption_level;	/* 0=Initial,1=HS,2=1-RTT */
	struct list_head	list_node;
};

/* Main QUIC connection structure */
struct quic_connection {
	/* Connection identifiers */
	struct quic_cid		*local_cid;		/* Primary local CID */
	struct quic_cid		*remote_cid;		/* Primary remote CID */
	struct list_head	local_cids;		/* All local CIDs */
	struct list_head	remote_cids;		/* All remote CIDs */
	u64			next_local_cid_seq;	/* Next sequence for local CIDs */
	u64			next_remote_cid_seq;	/* Next sequence for remote CIDs */
	spinlock_t		cid_lock;

	/* Connection state */
	enum quic_conn_state	state;
	enum quic_handshake_state hs_state;
	rwlock_t		state_lock;

	/* Paths (for migration support) */
	struct quic_path	*primary_path;
	struct list_head	paths;
	spinlock_t		path_lock;		/* Protects path list */
	struct work_struct	migration_work;

	/* Packet numbers per encryption level */
	u64			next_pn[3];		/* Next PN to send */
	u64			largest_acked_pn[3];	/* Largest acknowledged PN */
	u64			largest_recv_pn[3];	/* Largest received PN */
	spinlock_t		pn_lock;		/* Protects PN fields */

	/* Sent packet tracking for loss detection */
	struct list_head	sent_packets[3];	/* Per encryption level */
	spinlock_t		sent_lock;		/* Protects sent_packets */

	/* Loss detection timers */
	struct timer_list	loss_detection_timer;
	ktime_t			time_of_last_sent_ack_eliciting_packet[3];
	u32			pto_count;

	/* RTT and congestion control */
	struct quic_rtt		rtt;
	struct quic_congestion_control cc;
	struct quic_flow_control flow;

	/* Socket and network */
	struct sock		*sk;			/* Underlying UDP socket */
	struct net		*net;

	/* Handshake data */
	u8			*initial_secret;
	u8			*handshake_secret;
	u8			*application_secret;
	struct work_struct	handshake_work;
	struct completion	handshake_done;

	/* Version and parameters */
	u32			version;		/* QUIC version */
	u64			idle_timeout;		/* Idle timeout in ms */
	u32			max_udp_payload;	/* Max UDP payload size */

	/* Reference counting and lifecycle */
	refcount_t		refcnt;
	struct rcu_head		rcu;
	struct work_struct	destroy_work;

	/* Statistics */
	atomic64_t		bytes_sent;
	atomic64_t		bytes_received;
	atomic64_t		packets_sent;
	atomic64_t		packets_received;

	/* Flags */
	unsigned long		flags;
#define QUIC_CONN_FLAG_SERVER		BIT(0)
#define QUIC_CONN_FLAG_0RTT_ENABLED	BIT(1)
#define QUIC_CONN_FLAG_HANDSHAKE_CONFIRMED BIT(2)
#define QUIC_CONN_FLAG_KEY_UPDATE_PENDING BIT(3)
#define QUIC_CONN_FLAG_CLOSING		BIT(4)
#define QUIC_CONN_FLAG_DRAINING		BIT(5)

	/* Debug/tracing */
	u64			conn_id_debug;		/* For logging */
};

/* Global CID hashtable */
static DEFINE_HASHTABLE(quic_cid_hash, QUIC_CID_HASH_BITS);
static DEFINE_SPINLOCK(quic_cid_hash_lock);

/* Memory cache for connections */
static struct kmem_cache *quic_conn_cache __read_mostly;
static struct kmem_cache *quic_cid_cache __read_mostly;
static struct kmem_cache *quic_path_cache __read_mostly;
static struct kmem_cache *quic_sent_pkt_cache __read_mostly;

/* Workqueue for async operations */
static struct workqueue_struct *quic_wq __read_mostly;

/* Forward declarations */
static void quic_conn_destroy_work(struct work_struct *work);
static void quic_conn_handshake_work(struct work_struct *work);
static void quic_conn_migration_work(struct work_struct *work);
static void quic_loss_detection_timeout(struct timer_list *timer);

/*
 * ============================================================================
 * Connection ID Management (RFC 9000 Section 5.1)
 * ============================================================================
 */

/**
 * quic_cid_hash_fn - Calculate hash for a connection ID
 * @cid: Connection ID data
 * @len: Length of the connection ID
 *
 * Returns: Hash value for the CID
 */
static inline u32 quic_cid_hash_fn(const u8 *cid, u8 len)
{
	u32 hash = 0;
	int i;

	/* Simple hash combining all bytes */
	for (i = 0; i < len; i++)
		hash = hash * 31 + cid[i];

	return hash;
}

/**
 * quic_cid_generate - Generate a new random connection ID
 * @cid: Pointer to CID structure to fill
 * @len: Desired length of the CID (0-20 bytes)
 *
 * Generates a cryptographically random connection ID per RFC 9000 Section 5.1.
 * The CID should be unpredictable to prevent connection correlation.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_cid_generate(struct quic_cid *cid, u8 len)
{
	if (!cid)
		return -EINVAL;

	if (len > QUIC_CID_MAX_LEN)
		return -EINVAL;

	memset(cid, 0, sizeof(*cid));

	if (len > 0)
		get_random_bytes(cid->data, len);

	cid->len = len;
	cid->seq_num = 0;
	cid->has_reset_token = false;
	refcount_set(&cid->refcnt, 1);
	INIT_HLIST_NODE(&cid->hash_node);
	INIT_LIST_HEAD(&cid->list_node);
	cid->conn = NULL;

	return 0;
}
EXPORT_SYMBOL_GPL(quic_cid_generate);

/**
 * quic_cid_copy - Copy a connection ID
 * @dst: Destination CID
 * @src: Source CID
 */
static void quic_cid_copy(struct quic_cid *dst, const struct quic_cid *src)
{
	memcpy(dst->data, src->data, src->len);
	dst->len = src->len;
	dst->seq_num = src->seq_num;
	dst->has_reset_token = src->has_reset_token;
	if (src->has_reset_token)
		memcpy(dst->stateless_reset_token, src->stateless_reset_token, 16);
}

/**
 * quic_cid_equal - Compare two connection IDs
 * @cid1: First CID
 * @cid2: Second CID
 *
 * Returns: true if CIDs are equal, false otherwise
 */
static bool quic_cid_equal(const struct quic_cid *cid1, const struct quic_cid *cid2)
{
	if (cid1->len != cid2->len)
		return false;

	return memcmp(cid1->data, cid2->data, cid1->len) == 0;
}

/**
 * quic_cid_alloc - Allocate a new CID structure
 *
 * Returns: Pointer to new CID or NULL on failure
 */
static struct quic_cid *quic_cid_alloc(void)
{
	struct quic_cid *cid;

	cid = kmem_cache_zalloc(quic_cid_cache, GFP_ATOMIC);
	if (!cid)
		return NULL;

	refcount_set(&cid->refcnt, 1);
	INIT_HLIST_NODE(&cid->hash_node);
	INIT_LIST_HEAD(&cid->list_node);

	return cid;
}

/**
 * quic_cid_free_rcu - RCU callback to free CID
 * @head: RCU head embedded in CID
 */
static void quic_cid_free_rcu(struct rcu_head *head)
{
	struct quic_cid *cid = container_of(head, struct quic_cid, rcu);

	kmem_cache_free(quic_cid_cache, cid);
}

/**
 * quic_cid_put - Release reference to CID
 * @cid: Connection ID to release
 */
static void quic_cid_put(struct quic_cid *cid)
{
	if (cid && refcount_dec_and_test(&cid->refcnt))
		call_rcu(&cid->rcu, quic_cid_free_rcu);
}

/**
 * quic_cid_get - Acquire reference to CID
 * @cid: Connection ID to reference
 */
static void quic_cid_get(struct quic_cid *cid)
{
	if (cid)
		refcount_inc(&cid->refcnt);
}

/**
 * quic_cid_add - Add a connection ID to the global hashtable
 * @cid: Connection ID to add
 * @conn: Connection this CID belongs to
 *
 * Adds the CID to the global lookup table and the connection's CID list.
 * Must be called with appropriate locking.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_cid_add(struct quic_cid *cid, struct quic_connection *conn)
{
	u32 hash;

	if (!cid || !conn)
		return -EINVAL;

	/* Zero-length CIDs don't go in the hashtable */
	if (cid->len == 0)
		return 0;

	hash = quic_cid_hash_fn(cid->data, cid->len);
	cid->conn = conn;
	quic_cid_get(cid);

	spin_lock_bh(&quic_cid_hash_lock);
	hash_add_rcu(quic_cid_hash, &cid->hash_node, hash);
	spin_unlock_bh(&quic_cid_hash_lock);

	spin_lock_bh(&conn->cid_lock);
	list_add_tail_rcu(&cid->list_node, &conn->local_cids);
	spin_unlock_bh(&conn->cid_lock);

	pr_debug("CID added: len=%u seq=%llu conn=%p\n",
		 cid->len, cid->seq_num, conn);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_cid_add);

/**
 * quic_cid_remove - Remove a connection ID from the hashtable
 * @cid: Connection ID to remove
 *
 * Removes the CID from the global lookup table and the connection's list.
 * The CID is freed via RCU after removal.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_cid_remove(struct quic_cid *cid)
{
	struct quic_connection *conn;

	if (!cid)
		return -EINVAL;

	conn = cid->conn;

	if (cid->len > 0) {
		spin_lock_bh(&quic_cid_hash_lock);
		hash_del_rcu(&cid->hash_node);
		spin_unlock_bh(&quic_cid_hash_lock);
	}

	if (conn) {
		spin_lock_bh(&conn->cid_lock);
		list_del_rcu(&cid->list_node);
		spin_unlock_bh(&conn->cid_lock);
	}

	pr_debug("CID removed: len=%u seq=%llu\n", cid->len, cid->seq_num);

	quic_cid_put(cid);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_cid_remove);

/**
 * quic_cid_lookup - Look up a connection by connection ID
 * @cid_data: Connection ID data to look up
 * @cid_len: Length of the connection ID
 *
 * Searches the global CID hashtable for a matching connection.
 * Returns with a reference on the connection if found.
 *
 * Returns: Pointer to connection or NULL if not found
 */
struct quic_connection *quic_cid_lookup(const u8 *cid_data, u8 cid_len)
{
	struct quic_connection *conn = NULL;
	struct quic_cid *cid;
	u32 hash;

	if (!cid_data || cid_len == 0)
		return NULL;

	hash = quic_cid_hash_fn(cid_data, cid_len);

	rcu_read_lock();
	hash_for_each_possible_rcu(quic_cid_hash, cid, hash_node, hash) {
		if (cid->len == cid_len &&
		    memcmp(cid->data, cid_data, cid_len) == 0) {
			conn = cid->conn;
			if (conn && refcount_inc_not_zero(&conn->refcnt)) {
				rcu_read_unlock();
				return conn;
			}
			conn = NULL;
		}
	}
	rcu_read_unlock();

	return NULL;
}
EXPORT_SYMBOL_GPL(quic_cid_lookup);

/**
 * quic_cid_retire - Retire a connection ID
 * @conn: Connection owning the CID
 * @seq_num: Sequence number of CID to retire
 *
 * Retires a connection ID per RFC 9000 Section 5.1.2.
 * Generates a new CID if needed to maintain minimum CIDs.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_cid_retire(struct quic_connection *conn, u64 seq_num)
{
	struct quic_cid *cid, *tmp;
	int ret = -ENOENT;

	if (!conn)
		return -EINVAL;

	spin_lock_bh(&conn->cid_lock);
	list_for_each_entry_safe(cid, tmp, &conn->local_cids, list_node) {
		if (cid->seq_num == seq_num) {
			/* Don't retire if this is the only CID */
			if (list_is_singular(&conn->local_cids)) {
				spin_unlock_bh(&conn->cid_lock);
				return -EBUSY;
			}

			/* Update primary CID if needed */
			if (conn->local_cid == cid) {
				struct quic_cid *new_primary;

				new_primary = list_first_entry(&conn->local_cids,
							       struct quic_cid,
							       list_node);
				if (new_primary == cid)
					new_primary = list_next_entry(cid, list_node);
				conn->local_cid = new_primary;
			}

			spin_unlock_bh(&conn->cid_lock);
			quic_cid_remove(cid);
			return 0;
		}
	}
	spin_unlock_bh(&conn->cid_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(quic_cid_retire);

/**
 * quic_cid_new_local - Generate and add a new local CID
 * @conn: Connection to add CID to
 *
 * Returns: Pointer to new CID or ERR_PTR on failure
 */
struct quic_cid *quic_cid_new_local(struct quic_connection *conn)
{
	struct quic_cid *cid;
	int ret;

	if (!conn)
		return ERR_PTR(-EINVAL);

	cid = quic_cid_alloc();
	if (!cid)
		return ERR_PTR(-ENOMEM);

	ret = quic_cid_generate(cid, QUIC_CID_DEFAULT_LEN);
	if (ret) {
		quic_cid_put(cid);
		return ERR_PTR(ret);
	}

	spin_lock_bh(&conn->cid_lock);
	cid->seq_num = conn->next_local_cid_seq++;
	spin_unlock_bh(&conn->cid_lock);

	/* Generate stateless reset token */
	get_random_bytes(cid->stateless_reset_token, 16);
	cid->has_reset_token = true;

	ret = quic_cid_add(cid, conn);
	if (ret) {
		quic_cid_put(cid);
		return ERR_PTR(ret);
	}

	return cid;
}
EXPORT_SYMBOL_GPL(quic_cid_new_local);

/*
 * ============================================================================
 * RTT Estimation (RFC 9002 Section 5)
 * ============================================================================
 */

/**
 * quic_rtt_init - Initialize RTT estimation state
 * @rtt: RTT structure to initialize
 */
static void quic_rtt_init(struct quic_rtt *rtt)
{
	spin_lock_init(&rtt->lock);
	rtt->latest_rtt = 0;
	rtt->smoothed_rtt = QUIC_INITIAL_RTT_US;
	rtt->rtt_var = QUIC_INITIAL_RTT_US / 2;
	rtt->min_rtt = U64_MAX;
	rtt->max_ack_delay = QUIC_MAX_ACK_DELAY_US;
	rtt->has_first_sample = false;
}

/**
 * quic_rtt_update - Update RTT estimates with a new sample
 * @rtt: RTT state
 * @latest_rtt: The latest RTT measurement in microseconds
 * @ack_delay: ACK delay reported by peer in microseconds
 * @is_handshake: Whether this is a handshake packet
 *
 * Updates the RTT estimates per RFC 9002 Section 5.3.
 */
void quic_rtt_update(struct quic_rtt *rtt, u64 latest_rtt, u64 ack_delay,
		     bool is_handshake)
{
	u64 adjusted_rtt;

	if (!rtt || latest_rtt == 0)
		return;

	spin_lock_bh(&rtt->lock);

	rtt->latest_rtt = latest_rtt;

	/* Update minimum RTT */
	if (latest_rtt < rtt->min_rtt)
		rtt->min_rtt = latest_rtt;

	/* First RTT sample */
	if (!rtt->has_first_sample) {
		rtt->smoothed_rtt = latest_rtt;
		rtt->rtt_var = latest_rtt / 2;
		rtt->first_rtt_sample_time = ktime_get();
		rtt->has_first_sample = true;
		spin_unlock_bh(&rtt->lock);
		return;
	}

	/* Limit ack_delay by max_ack_delay for non-handshake packets */
	if (!is_handshake && ack_delay > rtt->max_ack_delay)
		ack_delay = rtt->max_ack_delay;

	/* Adjust RTT sample per RFC 9002 Section 5.3 */
	adjusted_rtt = latest_rtt;
	if (latest_rtt >= rtt->min_rtt + ack_delay)
		adjusted_rtt = latest_rtt - ack_delay;

	/* Update SRTT and RTTVAR per RFC 9002 */
	/* RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - adjusted_rtt| */
	if (adjusted_rtt > rtt->smoothed_rtt)
		rtt->rtt_var = (3 * rtt->rtt_var +
				(adjusted_rtt - rtt->smoothed_rtt)) / 4;
	else
		rtt->rtt_var = (3 * rtt->rtt_var +
				(rtt->smoothed_rtt - adjusted_rtt)) / 4;

	/* SRTT = 7/8 * SRTT + 1/8 * adjusted_rtt */
	rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + adjusted_rtt) / 8;

	spin_unlock_bh(&rtt->lock);

	pr_debug("RTT update: latest=%llu adj=%llu srtt=%llu rttvar=%llu min=%llu\n",
		 latest_rtt, adjusted_rtt, rtt->smoothed_rtt,
		 rtt->rtt_var, rtt->min_rtt);
}
EXPORT_SYMBOL_GPL(quic_rtt_update);

/**
 * quic_rtt_get_pto - Calculate the Probe Timeout (PTO)
 * @rtt: RTT state
 * @ack_eliciting_in_flight: Whether ACK-eliciting packets are in flight
 *
 * Calculates PTO per RFC 9002 Section 6.2.1.
 * PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
 *
 * Returns: PTO value in microseconds
 */
u64 quic_rtt_get_pto(struct quic_rtt *rtt, bool ack_eliciting_in_flight)
{
	u64 pto;
	u64 rtt_var_term;

	if (!rtt)
		return QUIC_INITIAL_RTT_US * QUIC_PTO_MULTIPLIER;

	spin_lock_bh(&rtt->lock);

	/* PTO = SRTT + max(4*RTTVAR, kGranularity) + max_ack_delay */
	rtt_var_term = 4 * rtt->rtt_var;
	if (rtt_var_term < QUIC_RTT_GRANULARITY_US)
		rtt_var_term = QUIC_RTT_GRANULARITY_US;

	pto = rtt->smoothed_rtt + rtt_var_term;

	if (ack_eliciting_in_flight)
		pto += rtt->max_ack_delay;

	spin_unlock_bh(&rtt->lock);

	return pto;
}
EXPORT_SYMBOL_GPL(quic_rtt_get_pto);

/**
 * quic_rtt_get_loss_delay - Get the time threshold for loss detection
 * @rtt: RTT state
 *
 * Returns: Loss delay threshold in microseconds per RFC 9002 Section 6.1.2
 */
static u64 quic_rtt_get_loss_delay(struct quic_rtt *rtt)
{
	u64 loss_delay;

	spin_lock_bh(&rtt->lock);

	/* max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity) */
	loss_delay = max(rtt->smoothed_rtt, rtt->latest_rtt);
	/* kTimeThreshold = 9/8 */
	loss_delay = loss_delay * 9 / 8;
	if (loss_delay < QUIC_RTT_GRANULARITY_US)
		loss_delay = QUIC_RTT_GRANULARITY_US;

	spin_unlock_bh(&rtt->lock);

	return loss_delay;
}

/*
 * ============================================================================
 * Congestion Control (RFC 9002 Section 7)
 * ============================================================================
 */

/**
 * quic_cc_init - Initialize congestion control state
 * @cc: Congestion control structure
 * @mtu: Path MTU for initial window calculation
 */
void quic_cc_init(struct quic_congestion_control *cc, u32 mtu)
{
	if (!cc)
		return;

	spin_lock_init(&cc->lock);
	memset(cc, 0, sizeof(*cc));

	/* Initial window per RFC 9002 Section 7.2 */
	/* min(10 * max_datagram_size, max(14720, 2 * max_datagram_size)) */
	cc->cwnd = min_t(u64, QUIC_INITIAL_WINDOW_PACKETS * mtu,
			 max_t(u64, 14720, 2 * mtu));
	cc->ssthresh = U64_MAX;
	cc->state = QUIC_CC_STATE_SLOW_START;
	cc->bytes_in_flight = 0;
	cc->recovery_start_time = 0;

	pr_debug("CC init: cwnd=%llu ssthresh=%llu\n", cc->cwnd, cc->ssthresh);
}
EXPORT_SYMBOL_GPL(quic_cc_init);

/**
 * quic_cc_on_packet_sent - Called when a packet is sent
 * @cc: Congestion control state
 * @bytes_sent: Number of bytes in the packet
 * @in_flight: Whether this packet is in flight
 */
void quic_cc_on_packet_sent(struct quic_congestion_control *cc, u32 bytes_sent,
			    bool in_flight)
{
	if (!cc)
		return;

	spin_lock_bh(&cc->lock);

	if (in_flight) {
		cc->bytes_in_flight += bytes_sent;
		cc->last_sent_time = ktime_get();
		if (cc->first_sent_time == 0)
			cc->first_sent_time = cc->last_sent_time;
	}

	cc->total_bytes_sent += bytes_sent;
	cc->packets_sent++;

	spin_unlock_bh(&cc->lock);
}
EXPORT_SYMBOL_GPL(quic_cc_on_packet_sent);

/**
 * quic_cc_on_packet_acked - Called when a packet is acknowledged
 * @cc: Congestion control state
 * @bytes_acked: Number of bytes acknowledged
 * @rtt: Current RTT state for timing information
 *
 * Implements NewReno-style congestion control per RFC 9002 Section 7.3.
 */
void quic_cc_on_packet_acked(struct quic_congestion_control *cc,
			     u32 bytes_acked, struct quic_rtt *rtt)
{
	u64 now;

	if (!cc || bytes_acked == 0)
		return;

	spin_lock_bh(&cc->lock);

	cc->bytes_in_flight -= min_t(u64, bytes_acked, cc->bytes_in_flight);
	cc->total_bytes_acked += bytes_acked;
	cc->packets_acked++;

	now = ktime_get_ns();

	/* Exit recovery if this ACK is for packets sent after recovery started */
	if (cc->state == QUIC_CC_STATE_RECOVERY &&
	    now > cc->recovery_start_time) {
		cc->state = QUIC_CC_STATE_CONGESTION_AVOIDANCE;
		pr_debug("CC: exiting recovery, cwnd=%llu\n", cc->cwnd);
	}

	/* Don't increase cwnd during recovery */
	if (cc->state == QUIC_CC_STATE_RECOVERY) {
		spin_unlock_bh(&cc->lock);
		return;
	}

	/* Slow start: increase cwnd by bytes_acked */
	if (cc->state == QUIC_CC_STATE_SLOW_START) {
		cc->cwnd += bytes_acked;
		if (cc->cwnd >= cc->ssthresh) {
			cc->state = QUIC_CC_STATE_CONGESTION_AVOIDANCE;
			cc->bytes_acked_in_ca = 0;
			pr_debug("CC: slow start -> CA, cwnd=%llu\n", cc->cwnd);
		}
	}
	/* Congestion avoidance: AIMD */
	else if (cc->state == QUIC_CC_STATE_CONGESTION_AVOIDANCE) {
		/* Increase by max_datagram_size per cwnd acknowledged */
		cc->bytes_acked_in_ca += bytes_acked;
		if (cc->bytes_acked_in_ca >= cc->cwnd) {
			cc->cwnd += QUIC_DEFAULT_MTU;
			cc->bytes_acked_in_ca = 0;
		}
	}

	spin_unlock_bh(&cc->lock);

	pr_debug("CC acked: bytes=%u cwnd=%llu in_flight=%llu state=%d\n",
		 bytes_acked, cc->cwnd, cc->bytes_in_flight, cc->state);
}
EXPORT_SYMBOL_GPL(quic_cc_on_packet_acked);

/**
 * quic_cc_on_packet_lost - Called when a packet is declared lost
 * @cc: Congestion control state
 * @bytes_lost: Number of bytes lost
 * @sent_time: Time the lost packet was sent
 *
 * Implements loss response per RFC 9002 Section 7.3.1.
 */
void quic_cc_on_packet_lost(struct quic_congestion_control *cc, u32 bytes_lost,
			    ktime_t sent_time)
{
	u64 sent_time_ns = ktime_to_ns(sent_time);

	if (!cc || bytes_lost == 0)
		return;

	spin_lock_bh(&cc->lock);

	cc->bytes_in_flight -= min_t(u64, bytes_lost, cc->bytes_in_flight);
	cc->total_bytes_lost += bytes_lost;
	cc->packets_lost++;

	/* Only enter recovery once per RTT */
	if (cc->recovery_start_time == 0 ||
	    sent_time_ns > cc->congestion_recovery_start_time) {
		/* Enter recovery */
		cc->state = QUIC_CC_STATE_RECOVERY;
		cc->recovery_start_time = ktime_get_ns();
		cc->congestion_recovery_start_time = cc->recovery_start_time;

		/* Multiplicative decrease per RFC 9002 */
		cc->ssthresh = cc->cwnd / QUIC_LOSS_REDUCTION_FACTOR;
		cc->cwnd = max_t(u64, cc->ssthresh,
				 QUIC_MIN_WINDOW_PACKETS * QUIC_DEFAULT_MTU);

		pr_debug("CC loss: entering recovery, cwnd=%llu ssthresh=%llu\n",
			 cc->cwnd, cc->ssthresh);
	}

	spin_unlock_bh(&cc->lock);
}
EXPORT_SYMBOL_GPL(quic_cc_on_packet_lost);

/**
 * quic_cc_on_persistent_congestion - Handle persistent congestion
 * @cc: Congestion control state
 *
 * Resets congestion window per RFC 9002 Section 7.6.2.
 */
static void quic_cc_on_persistent_congestion(struct quic_congestion_control *cc)
{
	spin_lock_bh(&cc->lock);

	/* Reset to minimum window */
	cc->cwnd = QUIC_MIN_WINDOW_PACKETS * QUIC_DEFAULT_MTU;
	cc->ssthresh = cc->cwnd;
	cc->state = QUIC_CC_STATE_SLOW_START;

	pr_debug("CC: persistent congestion, reset cwnd=%llu\n", cc->cwnd);

	spin_unlock_bh(&cc->lock);
}

/**
 * quic_cc_can_send - Check if congestion window allows sending
 * @cc: Congestion control state
 * @bytes: Number of bytes to send
 *
 * Returns: true if sending is allowed, false otherwise
 */
bool quic_cc_can_send(struct quic_congestion_control *cc, u32 bytes)
{
	bool can_send;

	if (!cc)
		return true;

	spin_lock_bh(&cc->lock);
	can_send = (cc->bytes_in_flight + bytes <= cc->cwnd);
	spin_unlock_bh(&cc->lock);

	return can_send;
}
EXPORT_SYMBOL_GPL(quic_cc_can_send);

/*
 * ============================================================================
 * Flow Control (RFC 9000 Section 4)
 * ============================================================================
 */

/**
 * quic_flow_init - Initialize flow control state
 * @flow: Flow control structure
 */
static void quic_flow_init(struct quic_flow_control *flow)
{
	spin_lock_init(&flow->lock);

	flow->max_data_local = QUIC_DEFAULT_MAX_DATA;
	flow->max_data_remote = QUIC_DEFAULT_MAX_DATA;
	flow->data_sent = 0;
	flow->data_received = 0;
	flow->max_data_next = QUIC_DEFAULT_MAX_DATA;
	flow->max_data_update_needed = false;

	/* Default stream limits */
	flow->max_streams_bidi_local = 100;
	flow->max_streams_bidi_remote = 100;
	flow->max_streams_uni_local = 100;
	flow->max_streams_uni_remote = 100;
	flow->streams_bidi_opened = 0;
	flow->streams_uni_opened = 0;
}

/**
 * quic_conn_update_max_data - Update the MAX_DATA limit
 * @conn: QUIC connection
 * @new_limit: New maximum data limit
 *
 * Updates the connection-level flow control limit per RFC 9000 Section 4.1.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_conn_update_max_data(struct quic_connection *conn, u64 new_limit)
{
	if (!conn)
		return -EINVAL;

	spin_lock_bh(&conn->flow.lock);

	/* MAX_DATA can only increase per RFC 9000 */
	if (new_limit > conn->flow.max_data_remote) {
		conn->flow.max_data_remote = new_limit;
		pr_debug("Flow: updated max_data_remote to %llu\n", new_limit);
	}

	spin_unlock_bh(&conn->flow.lock);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_conn_update_max_data);

/**
 * quic_conn_check_flow_control - Check if sending is allowed by flow control
 * @conn: QUIC connection
 * @bytes: Number of bytes to send
 *
 * Returns: true if sending is allowed, false if blocked by flow control
 */
bool quic_conn_check_flow_control(struct quic_connection *conn, u64 bytes)
{
	bool allowed;

	if (!conn)
		return false;

	spin_lock_bh(&conn->flow.lock);
	allowed = (conn->flow.data_sent + bytes <= conn->flow.max_data_remote);
	spin_unlock_bh(&conn->flow.lock);

	return allowed;
}
EXPORT_SYMBOL_GPL(quic_conn_check_flow_control);

/**
 * quic_conn_consume_flow_credit - Consume flow control credit
 * @conn: QUIC connection
 * @bytes: Number of bytes being sent
 *
 * Returns: 0 on success, -EAGAIN if blocked
 */
int quic_conn_consume_flow_credit(struct quic_connection *conn, u64 bytes)
{
	int ret = 0;

	if (!conn)
		return -EINVAL;

	spin_lock_bh(&conn->flow.lock);

	if (conn->flow.data_sent + bytes > conn->flow.max_data_remote) {
		ret = -EAGAIN;
	} else {
		conn->flow.data_sent += bytes;
	}

	spin_unlock_bh(&conn->flow.lock);

	return ret;
}

/**
 * quic_conn_receive_flow_credit - Track received data for flow control
 * @conn: QUIC connection
 * @bytes: Number of bytes received
 *
 * Returns: true if MAX_DATA frame should be sent
 */
bool quic_conn_receive_flow_credit(struct quic_connection *conn, u64 bytes)
{
	bool send_update = false;

	if (!conn)
		return false;

	spin_lock_bh(&conn->flow.lock);

	conn->flow.data_received += bytes;

	/* Check if we should send a MAX_DATA update */
	/* Send update when half of the window has been consumed */
	if (conn->flow.data_received > conn->flow.max_data_local / 2 &&
	    !conn->flow.max_data_update_needed) {
		conn->flow.max_data_next = conn->flow.data_received +
					   QUIC_DEFAULT_MAX_DATA;
		conn->flow.max_data_update_needed = true;
		send_update = true;
	}

	spin_unlock_bh(&conn->flow.lock);

	return send_update;
}

/*
 * ============================================================================
 * Connection State Management
 * ============================================================================
 */

/**
 * quic_conn_set_state - Change connection state with locking
 * @conn: QUIC connection
 * @new_state: New state to transition to
 *
 * Returns: 0 on success, negative error code on invalid transition
 */
int quic_conn_set_state(struct quic_connection *conn,
			enum quic_conn_state new_state)
{
	enum quic_conn_state old_state;
	int ret = 0;

	if (!conn || new_state >= __QUIC_CONN_STATE_MAX)
		return -EINVAL;

	write_lock_bh(&conn->state_lock);

	old_state = conn->state;

	/* Validate state transitions per RFC 9000 */
	switch (new_state) {
	case QUIC_CONN_STATE_IDLE:
		/* Can only be initial state */
		if (old_state != QUIC_CONN_STATE_IDLE)
			ret = -EINVAL;
		break;

	case QUIC_CONN_STATE_HANDSHAKE:
		if (old_state != QUIC_CONN_STATE_IDLE)
			ret = -EINVAL;
		break;

	case QUIC_CONN_STATE_EARLY_DATA:
		if (old_state != QUIC_CONN_STATE_HANDSHAKE)
			ret = -EINVAL;
		break;

	case QUIC_CONN_STATE_CONNECTED:
		if (old_state != QUIC_CONN_STATE_HANDSHAKE &&
		    old_state != QUIC_CONN_STATE_EARLY_DATA)
			ret = -EINVAL;
		break;

	case QUIC_CONN_STATE_CLOSING:
		if (old_state == QUIC_CONN_STATE_DRAINING ||
		    old_state == QUIC_CONN_STATE_CLOSED)
			ret = -EINVAL;
		break;

	case QUIC_CONN_STATE_DRAINING:
		if (old_state == QUIC_CONN_STATE_CLOSED)
			ret = -EINVAL;
		break;

	case QUIC_CONN_STATE_CLOSED:
		/* Can transition to closed from any state */
		break;

	default:
		ret = -EINVAL;
	}

	if (ret == 0) {
		conn->state = new_state;
		pr_debug("Connection %p state: %d -> %d\n",
			 conn, old_state, new_state);
	}

	write_unlock_bh(&conn->state_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(quic_conn_set_state);

/**
 * quic_conn_get_state - Get current connection state
 * @conn: QUIC connection
 *
 * Returns: Current connection state
 */
enum quic_conn_state quic_conn_get_state(struct quic_connection *conn)
{
	enum quic_conn_state state;

	if (!conn)
		return QUIC_CONN_STATE_CLOSED;

	read_lock_bh(&conn->state_lock);
	state = conn->state;
	read_unlock_bh(&conn->state_lock);

	return state;
}
EXPORT_SYMBOL_GPL(quic_conn_get_state);

/*
 * ============================================================================
 * Handshake Management
 * ============================================================================
 */

/**
 * quic_conn_start_handshake - Initiate QUIC handshake
 * @conn: QUIC connection
 *
 * Starts the QUIC handshake process per RFC 9000 Section 7.
 * For clients, this sends the Initial packet with CRYPTO frames.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_conn_start_handshake(struct quic_connection *conn)
{
	int ret;

	if (!conn)
		return -EINVAL;

	ret = quic_conn_set_state(conn, QUIC_CONN_STATE_HANDSHAKE);
	if (ret)
		return ret;

	write_lock_bh(&conn->state_lock);
	conn->hs_state = QUIC_HS_STATE_INITIAL;
	write_unlock_bh(&conn->state_lock);

	/* Schedule handshake work */
	init_completion(&conn->handshake_done);
	queue_work(quic_wq, &conn->handshake_work);

	pr_debug("Handshake started for connection %p\n", conn);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_conn_start_handshake);

/**
 * quic_conn_process_handshake - Process handshake packet
 * @conn: QUIC connection
 * @data: Packet data
 * @len: Length of packet data
 *
 * Processes CRYPTO frames from handshake packets.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_conn_process_handshake(struct quic_connection *conn,
				const u8 *data, size_t len)
{
	enum quic_conn_state state;

	if (!conn || !data || len == 0)
		return -EINVAL;

	state = quic_conn_get_state(conn);
	if (state != QUIC_CONN_STATE_HANDSHAKE &&
	    state != QUIC_CONN_STATE_EARLY_DATA)
		return -EINVAL;

	write_lock_bh(&conn->state_lock);

	switch (conn->hs_state) {
	case QUIC_HS_STATE_INITIAL:
		/* Client waiting for ServerHello */
		if (!(conn->flags & QUIC_CONN_FLAG_SERVER)) {
			conn->hs_state = QUIC_HS_STATE_SERVER_HELLO_RECEIVED;
		} else {
			/* Server received ClientHello */
			conn->hs_state = QUIC_HS_STATE_CLIENT_HELLO_SENT;
		}
		break;

	case QUIC_HS_STATE_CLIENT_HELLO_SENT:
		/* Server processing ClientHello */
		conn->hs_state = QUIC_HS_STATE_HANDSHAKE_KEYS_DERIVED;
		break;

	case QUIC_HS_STATE_SERVER_HELLO_RECEIVED:
		/* Client deriving handshake keys */
		conn->hs_state = QUIC_HS_STATE_HANDSHAKE_KEYS_DERIVED;
		break;

	case QUIC_HS_STATE_HANDSHAKE_KEYS_DERIVED:
		/* Processing handshake messages */
		if (conn->flags & QUIC_CONN_FLAG_SERVER)
			conn->hs_state = QUIC_HS_STATE_CLIENT_FINISHED_SENT;
		else
			conn->hs_state = QUIC_HS_STATE_SERVER_FINISHED_RECEIVED;
		break;

	case QUIC_HS_STATE_CLIENT_FINISHED_SENT:
	case QUIC_HS_STATE_SERVER_FINISHED_RECEIVED:
		conn->hs_state = QUIC_HS_STATE_HANDSHAKE_CONFIRMED;
		break;

	default:
		break;
	}

	write_unlock_bh(&conn->state_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_conn_process_handshake);

/**
 * quic_conn_complete_handshake - Complete the QUIC handshake
 * @conn: QUIC connection
 *
 * Called when handshake is complete. Transitions to connected state
 * and enables 1-RTT packet processing.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_conn_complete_handshake(struct quic_connection *conn)
{
	int ret;

	if (!conn)
		return -EINVAL;

	write_lock_bh(&conn->state_lock);

	if (conn->hs_state != QUIC_HS_STATE_HANDSHAKE_CONFIRMED) {
		write_unlock_bh(&conn->state_lock);
		return -EINVAL;
	}

	conn->hs_state = QUIC_HS_STATE_COMPLETE;
	conn->flags |= QUIC_CONN_FLAG_HANDSHAKE_CONFIRMED;

	write_unlock_bh(&conn->state_lock);

	ret = quic_conn_set_state(conn, QUIC_CONN_STATE_CONNECTED);
	if (ret)
		return ret;

	complete_all(&conn->handshake_done);

	pr_debug("Handshake complete for connection %p\n", conn);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_conn_complete_handshake);

/**
 * quic_conn_handshake_work - Workqueue handler for handshake
 * @work: Work structure
 */
static void quic_conn_handshake_work(struct work_struct *work)
{
	struct quic_connection *conn = container_of(work, struct quic_connection,
						    handshake_work);
	enum quic_handshake_state hs_state;

	read_lock_bh(&conn->state_lock);
	hs_state = conn->hs_state;
	read_unlock_bh(&conn->state_lock);

	/*
	 * In a full implementation, this would:
	 * 1. Generate/process TLS messages
	 * 2. Derive encryption keys
	 * 3. Send CRYPTO frames
	 * 4. Handle retransmission
	 */

	pr_debug("Handshake work: conn=%p state=%d\n", conn, hs_state);
}

/*
 * ============================================================================
 * Connection Migration (RFC 9000 Section 9)
 * ============================================================================
 */

/**
 * quic_path_alloc - Allocate a new path structure
 *
 * Returns: Pointer to new path or NULL on failure
 */
static struct quic_path *quic_path_alloc(void)
{
	struct quic_path *path;

	path = kmem_cache_zalloc(quic_path_cache, GFP_ATOMIC);
	if (!path)
		return NULL;

	path->state = QUIC_PATH_STATE_UNKNOWN;
	path->mtu = QUIC_DEFAULT_MTU;
	path->validated = false;
	path->is_primary = false;
	INIT_LIST_HEAD(&path->list_node);

	return path;
}

/**
 * quic_path_free_rcu - RCU callback to free path
 * @head: RCU head
 */
static void quic_path_free_rcu(struct rcu_head *head)
{
	struct quic_path *path = container_of(head, struct quic_path, rcu);

	kmem_cache_free(quic_path_cache, path);
}

/**
 * quic_conn_migrate - Migrate connection to a new path
 * @conn: QUIC connection
 * @new_local: New local address
 * @new_remote: New remote address
 *
 * Initiates connection migration per RFC 9000 Section 9.
 * This is important for TQUIC WAN bonding scenarios.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_conn_migrate(struct quic_connection *conn,
		      const struct sockaddr_storage *new_local,
		      const struct sockaddr_storage *new_remote)
{
	struct quic_path *new_path;
	enum quic_conn_state state;
	int ret;

	if (!conn || !new_remote)
		return -EINVAL;

	state = quic_conn_get_state(conn);
	if (state != QUIC_CONN_STATE_CONNECTED)
		return -EINVAL;

	new_path = quic_path_alloc();
	if (!new_path)
		return -ENOMEM;

	/* Copy addresses */
	if (new_local)
		memcpy(&new_path->local_addr, new_local, sizeof(*new_local));
	memcpy(&new_path->peer_addr, new_remote, sizeof(*new_remote));

	/* Add to path list */
	spin_lock_bh(&conn->path_lock);
	list_add_tail_rcu(&new_path->list_node, &conn->paths);
	spin_unlock_bh(&conn->path_lock);

	/* Start path validation */
	ret = quic_conn_validate_path(conn, new_path);
	if (ret) {
		spin_lock_bh(&conn->path_lock);
		list_del_rcu(&new_path->list_node);
		spin_unlock_bh(&conn->path_lock);
		call_rcu(&new_path->rcu, quic_path_free_rcu);
		return ret;
	}

	pr_debug("Migration initiated for conn %p to new path\n", conn);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_conn_migrate);

/**
 * quic_conn_validate_path - Validate a new path
 * @conn: QUIC connection
 * @path: Path to validate
 *
 * Sends PATH_CHALLENGE frames per RFC 9000 Section 8.2.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_conn_validate_path(struct quic_connection *conn,
			    struct quic_path *path)
{
	if (!conn || !path)
		return -EINVAL;

	/* Generate random challenge data */
	get_random_bytes(path->challenge, sizeof(path->challenge));

	path->state = QUIC_PATH_STATE_VALIDATING;
	path->challenge_sent_time = ktime_get();
	path->challenge_count = 1;

	/*
	 * In a full implementation, this would:
	 * 1. Create a PATH_CHALLENGE frame
	 * 2. Send it on the new path
	 * 3. Set up timeout for response
	 */

	/* Schedule work to handle timeout/retransmission */
	queue_work(quic_wq, &conn->migration_work);

	pr_debug("Path validation started for conn %p\n", conn);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_conn_validate_path);

/**
 * quic_conn_handle_path_response - Handle PATH_RESPONSE frame
 * @conn: QUIC connection
 * @data: PATH_RESPONSE data (8 bytes)
 *
 * Validates that the response matches a sent challenge.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_conn_handle_path_response(struct quic_connection *conn, const u8 *data)
{
	struct quic_path *path;
	bool found = false;

	if (!conn || !data)
		return -EINVAL;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list_node) {
		if (path->state == QUIC_PATH_STATE_VALIDATING &&
		    memcmp(path->challenge, data, 8) == 0) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	if (!found)
		return -ENOENT;

	spin_lock_bh(&conn->path_lock);
	path->state = QUIC_PATH_STATE_VALIDATED;
	path->validated = true;

	/* Make this the primary path if it's the first validated path */
	if (!conn->primary_path || !conn->primary_path->validated) {
		if (conn->primary_path)
			conn->primary_path->is_primary = false;
		path->is_primary = true;
		conn->primary_path = path;
	}
	spin_unlock_bh(&conn->path_lock);

	pr_debug("Path validated for conn %p\n", conn);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_conn_handle_path_response);

/**
 * quic_conn_update_peer_address - Update peer address after migration
 * @conn: QUIC connection
 * @new_addr: New peer address
 *
 * Updates the peer address when receiving packets from a new address.
 * Per RFC 9000 Section 9.3, this requires path validation.
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_conn_update_peer_address(struct quic_connection *conn,
				  const struct sockaddr_storage *new_addr)
{
	struct quic_path *path;

	if (!conn || !new_addr)
		return -EINVAL;

	/* Check if this is already a known path */
	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list_node) {
		if (memcmp(&path->peer_addr, new_addr, sizeof(*new_addr)) == 0) {
			rcu_read_unlock();
			/* Path already exists */
			if (path->validated && !path->is_primary) {
				/* Switch to this validated path */
				spin_lock_bh(&conn->path_lock);
				if (conn->primary_path)
					conn->primary_path->is_primary = false;
				path->is_primary = true;
				conn->primary_path = path;
				spin_unlock_bh(&conn->path_lock);
			}
			return 0;
		}
	}
	rcu_read_unlock();

	/* New path - initiate migration with validation */
	return quic_conn_migrate(conn, NULL, new_addr);
}
EXPORT_SYMBOL_GPL(quic_conn_update_peer_address);

/**
 * quic_conn_migration_work - Workqueue handler for migration
 * @work: Work structure
 */
static void quic_conn_migration_work(struct work_struct *work)
{
	struct quic_connection *conn = container_of(work, struct quic_connection,
						    migration_work);
	struct quic_path *path;
	ktime_t now = ktime_get();
	s64 elapsed_ms;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list_node) {
		if (path->state != QUIC_PATH_STATE_VALIDATING)
			continue;

		elapsed_ms = ktime_ms_delta(now, path->challenge_sent_time);

		if (elapsed_ms > QUIC_PATH_VALIDATION_TIMEOUT_MS) {
			/* Path validation timed out */
			spin_lock_bh(&conn->path_lock);
			path->state = QUIC_PATH_STATE_FAILED;
			spin_unlock_bh(&conn->path_lock);
			pr_debug("Path validation timeout for conn %p\n", conn);
		} else if (path->challenge_count < 3) {
			/* Retransmit challenge */
			get_random_bytes(path->challenge, sizeof(path->challenge));
			path->challenge_sent_time = now;
			path->challenge_count++;
			/* Re-schedule work */
			queue_work(quic_wq, &conn->migration_work);
		}
	}
	rcu_read_unlock();
}

/*
 * ============================================================================
 * Loss Detection (RFC 9002 Section 6)
 * ============================================================================
 */

/**
 * quic_loss_detection_timeout - Timer callback for loss detection
 * @timer: Timer that fired
 */
static void quic_loss_detection_timeout(struct timer_list *timer)
{
	struct quic_connection *conn = container_of(timer, struct quic_connection,
						    loss_detection_timer);
	struct quic_sent_packet *pkt, *tmp;
	ktime_t now = ktime_get();
	u64 loss_delay;
	int level;

	loss_delay = quic_rtt_get_loss_delay(&conn->rtt);

	/* Check each encryption level */
	for (level = 0; level < 3; level++) {
		spin_lock_bh(&conn->sent_lock);

		list_for_each_entry_safe(pkt, tmp, &conn->sent_packets[level],
					 list_node) {
			s64 elapsed = ktime_us_delta(now, pkt->sent_time);

			if (elapsed > loss_delay && pkt->in_flight) {
				/* Packet is lost */
				quic_cc_on_packet_lost(&conn->cc, pkt->sent_bytes,
						       pkt->sent_time);
				list_del(&pkt->list_node);
				kmem_cache_free(quic_sent_pkt_cache, pkt);
			}
		}

		spin_unlock_bh(&conn->sent_lock);
	}

	/* Check for PTO */
	conn->pto_count++;

	/* Reschedule if there are still packets in flight */
	if (conn->cc.bytes_in_flight > 0) {
		u64 pto = quic_rtt_get_pto(&conn->rtt, true);
		/* Apply exponential backoff */
		pto = pto * (1 << min(conn->pto_count, 6u));
		mod_timer(&conn->loss_detection_timer,
			  jiffies + usecs_to_jiffies(pto));
	}
}

/**
 * quic_conn_set_loss_detection_timer - Set/update loss detection timer
 * @conn: QUIC connection
 */
static void quic_conn_set_loss_detection_timer(struct quic_connection *conn)
{
	u64 pto;
	int level;
	bool has_inflight = false;

	for (level = 0; level < 3; level++) {
		spin_lock_bh(&conn->sent_lock);
		if (!list_empty(&conn->sent_packets[level]))
			has_inflight = true;
		spin_unlock_bh(&conn->sent_lock);
	}

	if (!has_inflight) {
		del_timer(&conn->loss_detection_timer);
		return;
	}

	pto = quic_rtt_get_pto(&conn->rtt, true);
	mod_timer(&conn->loss_detection_timer, jiffies + usecs_to_jiffies(pto));
}

/**
 * quic_conn_on_packet_sent - Record a sent packet
 * @conn: QUIC connection
 * @pn: Packet number
 * @bytes: Bytes in the packet
 * @ack_eliciting: Whether the packet is ACK-eliciting
 * @in_flight: Whether the packet counts against bytes in flight
 * @level: Encryption level (0=Initial, 1=Handshake, 2=1-RTT)
 */
int quic_conn_on_packet_sent(struct quic_connection *conn, u64 pn,
			     u32 bytes, bool ack_eliciting,
			     bool in_flight, u8 level)
{
	struct quic_sent_packet *pkt;

	if (!conn || level >= 3)
		return -EINVAL;

	pkt = kmem_cache_zalloc(quic_sent_pkt_cache, GFP_ATOMIC);
	if (!pkt)
		return -ENOMEM;

	pkt->packet_number = pn;
	pkt->sent_time = ktime_get();
	pkt->sent_bytes = bytes;
	pkt->ack_eliciting = ack_eliciting;
	pkt->in_flight = in_flight;
	pkt->encryption_level = level;
	INIT_LIST_HEAD(&pkt->list_node);

	spin_lock_bh(&conn->sent_lock);
	list_add_tail(&pkt->list_node, &conn->sent_packets[level]);
	spin_unlock_bh(&conn->sent_lock);

	if (in_flight) {
		quic_cc_on_packet_sent(&conn->cc, bytes, true);
		conn->time_of_last_sent_ack_eliciting_packet[level] = pkt->sent_time;
	}

	atomic64_add(bytes, &conn->bytes_sent);
	atomic64_inc(&conn->packets_sent);

	/* Update loss detection timer */
	if (ack_eliciting)
		quic_conn_set_loss_detection_timer(conn);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_conn_on_packet_sent);

/**
 * quic_conn_on_ack_received - Process received ACK frame
 * @conn: QUIC connection
 * @largest_acked: Largest packet number acknowledged
 * @ack_delay: ACK delay reported by peer
 * @level: Encryption level
 */
int quic_conn_on_ack_received(struct quic_connection *conn, u64 largest_acked,
			      u64 ack_delay, u8 level)
{
	struct quic_sent_packet *pkt, *tmp;
	ktime_t now = ktime_get();
	u64 latest_rtt = 0;
	bool is_handshake;

	if (!conn || level >= 3)
		return -EINVAL;

	is_handshake = (level != 2);

	spin_lock_bh(&conn->sent_lock);

	list_for_each_entry_safe(pkt, tmp, &conn->sent_packets[level],
				 list_node) {
		if (pkt->packet_number > largest_acked)
			continue;

		/* Calculate RTT for the largest acknowledged packet */
		if (pkt->packet_number == largest_acked && pkt->ack_eliciting) {
			latest_rtt = ktime_us_delta(now, pkt->sent_time);
		}

		/* Mark as acknowledged */
		if (pkt->in_flight) {
			quic_cc_on_packet_acked(&conn->cc, pkt->sent_bytes,
						&conn->rtt);
		}

		list_del(&pkt->list_node);
		kmem_cache_free(quic_sent_pkt_cache, pkt);
	}

	spin_unlock_bh(&conn->sent_lock);

	/* Update RTT */
	if (latest_rtt > 0)
		quic_rtt_update(&conn->rtt, latest_rtt, ack_delay, is_handshake);

	/* Reset PTO count on acknowledgment */
	spin_lock_bh(&conn->pn_lock);
	if (largest_acked > conn->largest_acked_pn[level])
		conn->largest_acked_pn[level] = largest_acked;
	conn->pto_count = 0;
	spin_unlock_bh(&conn->pn_lock);

	/* Update loss detection timer */
	quic_conn_set_loss_detection_timer(conn);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_conn_on_ack_received);

/*
 * ============================================================================
 * Connection Allocation and Lifecycle
 * ============================================================================
 */

/**
 * quic_connection_init - Initialize a connection structure
 * @conn: Connection to initialize
 * @sk: Underlying socket
 * @is_server: Whether this is a server connection
 *
 * Returns: 0 on success, negative error code on failure
 */
int quic_connection_init(struct quic_connection *conn, struct sock *sk,
			 bool is_server)
{
	int i;

	if (!conn)
		return -EINVAL;

	memset(conn, 0, sizeof(*conn));

	/* Initialize locks */
	spin_lock_init(&conn->cid_lock);
	rwlock_init(&conn->state_lock);
	spin_lock_init(&conn->path_lock);
	spin_lock_init(&conn->pn_lock);
	spin_lock_init(&conn->sent_lock);

	/* Initialize lists */
	INIT_LIST_HEAD(&conn->local_cids);
	INIT_LIST_HEAD(&conn->remote_cids);
	INIT_LIST_HEAD(&conn->paths);

	for (i = 0; i < 3; i++)
		INIT_LIST_HEAD(&conn->sent_packets[i]);

	/* Initialize state */
	conn->state = QUIC_CONN_STATE_IDLE;
	conn->hs_state = QUIC_HS_STATE_INITIAL;

	if (is_server)
		conn->flags |= QUIC_CONN_FLAG_SERVER;

	/* Initialize subsystems */
	quic_rtt_init(&conn->rtt);
	quic_cc_init(&conn->cc, QUIC_DEFAULT_MTU);
	quic_flow_init(&conn->flow);

	/* Initialize timers */
	timer_setup(&conn->loss_detection_timer, quic_loss_detection_timeout, 0);

	/* Initialize work items */
	INIT_WORK(&conn->handshake_work, quic_conn_handshake_work);
	INIT_WORK(&conn->migration_work, quic_conn_migration_work);
	INIT_WORK(&conn->destroy_work, quic_conn_destroy_work);
	init_completion(&conn->handshake_done);

	/* Set socket and network namespace */
	conn->sk = sk;
	if (sk)
		conn->net = sock_net(sk);

	/* Set default parameters */
	conn->version = 1;  /* QUIC v1 */
	conn->idle_timeout = 30000;  /* 30 seconds */
	conn->max_udp_payload = QUIC_DEFAULT_MTU;

	/* Initialize reference count */
	refcount_set(&conn->refcnt, 1);

	/* Generate debug ID */
	conn->conn_id_debug = get_random_u64();

	pr_debug("Connection %p initialized (server=%d)\n", conn, is_server);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_connection_init);

/**
 * quic_connection_alloc - Allocate and initialize a new connection
 * @sk: Underlying socket
 * @is_server: Whether this is a server connection
 *
 * Returns: Pointer to new connection or ERR_PTR on failure
 */
struct quic_connection *quic_connection_alloc(struct sock *sk, bool is_server)
{
	struct quic_connection *conn;
	struct quic_cid *local_cid;
	struct quic_path *path;
	int ret;

	conn = kmem_cache_zalloc(quic_conn_cache, GFP_KERNEL);
	if (!conn)
		return ERR_PTR(-ENOMEM);

	ret = quic_connection_init(conn, sk, is_server);
	if (ret) {
		kmem_cache_free(quic_conn_cache, conn);
		return ERR_PTR(ret);
	}

	/* Generate initial local connection ID */
	local_cid = quic_cid_alloc();
	if (!local_cid) {
		kmem_cache_free(quic_conn_cache, conn);
		return ERR_PTR(-ENOMEM);
	}

	ret = quic_cid_generate(local_cid, QUIC_CID_DEFAULT_LEN);
	if (ret) {
		quic_cid_put(local_cid);
		kmem_cache_free(quic_conn_cache, conn);
		return ERR_PTR(ret);
	}

	local_cid->seq_num = conn->next_local_cid_seq++;

	/* Generate stateless reset token */
	get_random_bytes(local_cid->stateless_reset_token, 16);
	local_cid->has_reset_token = true;

	ret = quic_cid_add(local_cid, conn);
	if (ret) {
		quic_cid_put(local_cid);
		kmem_cache_free(quic_conn_cache, conn);
		return ERR_PTR(ret);
	}

	conn->local_cid = local_cid;

	/* Create initial path */
	path = quic_path_alloc();
	if (!path) {
		quic_cid_remove(local_cid);
		kmem_cache_free(quic_conn_cache, conn);
		return ERR_PTR(-ENOMEM);
	}

	path->is_primary = true;
	path->mtu = QUIC_DEFAULT_MTU;

	spin_lock_bh(&conn->path_lock);
	list_add_tail_rcu(&path->list_node, &conn->paths);
	conn->primary_path = path;
	spin_unlock_bh(&conn->path_lock);

	pr_debug("Connection %p allocated\n", conn);

	return conn;
}
EXPORT_SYMBOL_GPL(quic_connection_alloc);

/**
 * quic_connection_get - Acquire reference to connection
 * @conn: Connection to reference
 */
void quic_connection_get(struct quic_connection *conn)
{
	if (conn)
		refcount_inc(&conn->refcnt);
}
EXPORT_SYMBOL_GPL(quic_connection_get);

/**
 * quic_connection_put - Release reference to connection
 * @conn: Connection to release
 */
void quic_connection_put(struct quic_connection *conn)
{
	if (conn && refcount_dec_and_test(&conn->refcnt))
		queue_work(quic_wq, &conn->destroy_work);
}
EXPORT_SYMBOL_GPL(quic_connection_put);

/**
 * quic_conn_destroy_work - Workqueue handler for connection destruction
 * @work: Work structure
 */
static void quic_conn_destroy_work(struct work_struct *work)
{
	struct quic_connection *conn = container_of(work, struct quic_connection,
						    destroy_work);

	quic_connection_free(conn);
}

/**
 * quic_connection_free - Free a connection and all resources
 * @conn: Connection to free
 */
void quic_connection_free(struct quic_connection *conn)
{
	struct quic_cid *cid, *cid_tmp;
	struct quic_path *path, *path_tmp;
	struct quic_sent_packet *pkt, *pkt_tmp;
	int level;

	if (!conn)
		return;

	pr_debug("Connection %p being freed\n", conn);

	/* Cancel timers */
	del_timer_sync(&conn->loss_detection_timer);

	/* Cancel pending work */
	cancel_work_sync(&conn->handshake_work);
	cancel_work_sync(&conn->migration_work);

	/* Free all local CIDs */
	spin_lock_bh(&conn->cid_lock);
	list_for_each_entry_safe(cid, cid_tmp, &conn->local_cids, list_node) {
		list_del_rcu(&cid->list_node);
		spin_unlock_bh(&conn->cid_lock);

		if (cid->len > 0) {
			spin_lock_bh(&quic_cid_hash_lock);
			hash_del_rcu(&cid->hash_node);
			spin_unlock_bh(&quic_cid_hash_lock);
		}
		quic_cid_put(cid);

		spin_lock_bh(&conn->cid_lock);
	}

	/* Free remote CIDs (not in hashtable) */
	list_for_each_entry_safe(cid, cid_tmp, &conn->remote_cids, list_node) {
		list_del(&cid->list_node);
		quic_cid_put(cid);
	}
	spin_unlock_bh(&conn->cid_lock);

	/* Free paths */
	spin_lock_bh(&conn->path_lock);
	list_for_each_entry_safe(path, path_tmp, &conn->paths, list_node) {
		list_del_rcu(&path->list_node);
		call_rcu(&path->rcu, quic_path_free_rcu);
	}
	conn->primary_path = NULL;
	spin_unlock_bh(&conn->path_lock);

	/* Free sent packets */
	for (level = 0; level < 3; level++) {
		spin_lock_bh(&conn->sent_lock);
		list_for_each_entry_safe(pkt, pkt_tmp, &conn->sent_packets[level],
					 list_node) {
			list_del(&pkt->list_node);
			kmem_cache_free(quic_sent_pkt_cache, pkt);
		}
		spin_unlock_bh(&conn->sent_lock);
	}

	/* Free secrets */
	kfree(conn->initial_secret);
	kfree(conn->handshake_secret);
	kfree(conn->application_secret);

	/* Free the connection structure */
	kmem_cache_free(quic_conn_cache, conn);
}
EXPORT_SYMBOL_GPL(quic_connection_free);

/*
 * ============================================================================
 * Module Initialization
 * ============================================================================
 */

/**
 * quic_connection_module_init - Initialize the connection module
 *
 * Returns: 0 on success, negative error code on failure
 */
int __init quic_connection_module_init(void)
{
	int ret = 0;

	/* Create memory caches */
	quic_conn_cache = kmem_cache_create("quic_connection",
					    sizeof(struct quic_connection),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_conn_cache) {
		ret = -ENOMEM;
		goto out;
	}

	quic_cid_cache = kmem_cache_create("quic_cid",
					   sizeof(struct quic_cid),
					   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_cid_cache) {
		ret = -ENOMEM;
		goto free_conn_cache;
	}

	quic_path_cache = kmem_cache_create("quic_path",
					    sizeof(struct quic_path),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_path_cache) {
		ret = -ENOMEM;
		goto free_cid_cache;
	}

	quic_sent_pkt_cache = kmem_cache_create("quic_sent_packet",
						sizeof(struct quic_sent_packet),
						0, SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_sent_pkt_cache) {
		ret = -ENOMEM;
		goto free_path_cache;
	}

	/* Create workqueue */
	quic_wq = alloc_workqueue("quic_wq",
				  WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	if (!quic_wq) {
		ret = -ENOMEM;
		goto free_sent_cache;
	}

	pr_info("QUIC connection module initialized\n");
	return 0;

free_sent_cache:
	kmem_cache_destroy(quic_sent_pkt_cache);
free_path_cache:
	kmem_cache_destroy(quic_path_cache);
free_cid_cache:
	kmem_cache_destroy(quic_cid_cache);
free_conn_cache:
	kmem_cache_destroy(quic_conn_cache);
out:
	return ret;
}

/**
 * quic_connection_module_exit - Cleanup the connection module
 */
void __exit quic_connection_module_exit(void)
{
	/* Destroy workqueue */
	if (quic_wq)
		destroy_workqueue(quic_wq);

	/* Wait for RCU callbacks */
	rcu_barrier();

	/* Destroy memory caches */
	kmem_cache_destroy(quic_sent_pkt_cache);
	kmem_cache_destroy(quic_path_cache);
	kmem_cache_destroy(quic_cid_cache);
	kmem_cache_destroy(quic_conn_cache);

	pr_info("QUIC connection module cleaned up\n");
}

MODULE_DESCRIPTION("QUIC Connection Management");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux QUIC Contributors");
