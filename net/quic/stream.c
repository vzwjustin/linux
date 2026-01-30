// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Stream Handling
 *
 * Implementation of QUIC stream management as defined in RFC 9000 Section 3.
 * Supports TQUIC multipath with concurrent access from multiple paths.
 *
 * Copyright (c) 2024 Linux QUIC Team
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/workqueue.h>
#include <net/sock.h>

/*
 * QUIC Stream States (RFC 9000 Section 3)
 *
 * Send-side states (Section 3.1):
 *   Ready -> Send -> Data Sent -> Data Recvd
 *                 \-> Reset Sent -> Reset Recvd
 *
 * Receive-side states (Section 3.2):
 *   Recv -> Size Known -> Data Recvd -> Data Read
 *        \-> Reset Recvd -> Reset Read
 *
 * Simplified combined state model:
 */
enum quic_stream_state {
	QUIC_STREAM_IDLE = 0,		/* Initial state */
	QUIC_STREAM_OPEN,		/* Both directions open */
	QUIC_STREAM_HALF_CLOSED_LOCAL,	/* Local side closed (sent FIN) */
	QUIC_STREAM_HALF_CLOSED_REMOTE,	/* Remote side closed (received FIN) */
	QUIC_STREAM_CLOSED,		/* Both directions closed */
	QUIC_STREAM_RESET_SENT,		/* RESET_STREAM sent */
	QUIC_STREAM_RESET_RECVD,	/* RESET_STREAM received */
	__QUIC_STREAM_STATE_MAX
};

/* Stream type bits in stream ID (RFC 9000 Section 2.1) */
#define QUIC_STREAM_TYPE_CLIENT_BIDI	0x00
#define QUIC_STREAM_TYPE_SERVER_BIDI	0x01
#define QUIC_STREAM_TYPE_CLIENT_UNI	0x02
#define QUIC_STREAM_TYPE_SERVER_UNI	0x03

#define QUIC_STREAM_DIR_MASK		0x02	/* Bit 1: uni(1) or bidi(0) */
#define QUIC_STREAM_INITIATOR_MASK	0x01	/* Bit 0: server(1) or client(0) */

/* Stream frame flags */
#define QUIC_STREAM_FRAME_FIN		0x01
#define QUIC_STREAM_FRAME_LEN		0x02
#define QUIC_STREAM_FRAME_OFF		0x04

/* Default limits */
#define QUIC_STREAM_DEFAULT_MAX_DATA		(1 << 20)	/* 1 MB */
#define QUIC_STREAM_DEFAULT_MAX_STREAMS		100
#define QUIC_STREAM_REORDER_BUFFER_SIZE		64

/* Priority levels (0 = highest, 255 = lowest) */
#define QUIC_STREAM_PRIORITY_HIGHEST	0
#define QUIC_STREAM_PRIORITY_DEFAULT	128
#define QUIC_STREAM_PRIORITY_LOWEST	255

/*
 * Out-of-order data fragment for reassembly
 */
struct quic_stream_fragment {
	struct rb_node		node;		/* RB tree node for ordering */
	u64			offset;		/* Offset within stream */
	u32			len;		/* Fragment length */
	struct sk_buff		*skb;		/* Data buffer */
};

/*
 * QUIC Stream structure
 */
struct quic_stream {
	/* Tree linkage for stream lookup */
	struct rb_node		node;		/* RB tree node */
	u64			id;		/* Stream ID */

	/* Reference counting */
	struct kref		kref;

	/* State machine */
	enum quic_stream_state	state;
	spinlock_t		state_lock;

	/* Send side */
	spinlock_t		send_lock;
	struct sk_buff_head	send_queue;	/* Data queued for sending */
	u64			send_offset;	/* Next offset to send */
	u64			send_max_data;	/* Max data we can send (peer's limit) */
	u64			bytes_sent;	/* Total bytes sent */
	u64			bytes_acked;	/* Total bytes acknowledged */
	bool			send_fin;	/* FIN requested */
	bool			fin_sent;	/* FIN has been sent */
	bool			fin_acked;	/* FIN has been acknowledged */
	u64			reset_error_code;

	/* Receive side */
	spinlock_t		recv_lock;
	struct sk_buff_head	recv_queue;	/* In-order data ready to read */
	struct rb_root		recv_reorder;	/* Out-of-order fragments */
	u64			recv_offset;	/* Next expected offset */
	u64			recv_max_data;	/* Max data we will accept (our limit) */
	u64			bytes_recvd;	/* Total bytes received */
	u64			bytes_read;	/* Total bytes read by application */
	bool			recv_fin;	/* FIN received */
	bool			fin_read;	/* FIN delivered to application */
	u64			final_size;	/* Final stream size (if FIN received) */
	u64			stop_sending_code;
	bool			stop_sending;

	/* Flow control */
	spinlock_t		fc_lock;
	u64			fc_window;	/* Current flow control window */
	u64			fc_blocked_at;	/* Offset at which we're blocked */
	bool			fc_blocked;	/* We are blocked on flow control */

	/* Priority and scheduling */
	u8			priority;	/* Stream priority (0-255) */
	u16			weight;		/* Scheduling weight */
	bool			has_data;	/* Has data ready to send */
	struct list_head	sched_node;	/* Scheduling list linkage */

	/* Multipath support (TQUIC) */
	u32			path_affinity;	/* Preferred path ID, 0 = any */
	atomic_t		active_paths;	/* Number of paths using this stream */

	/* Statistics */
	u64			frames_sent;
	u64			frames_recvd;
	ktime_t			created_time;
	ktime_t			last_activity;

	/* Back-pointer to connection */
	void			*conn;
};

/*
 * Stream manager - manages all streams for a connection
 */
struct quic_stream_manager {
	spinlock_t		lock;
	struct rb_root		streams;	/* All streams by ID */
	u32			num_streams;

	/* Stream ID allocation */
	u64			next_bidi_local;	/* Next local bidi stream ID */
	u64			next_uni_local;		/* Next local uni stream ID */
	u64			max_bidi_remote;	/* Max remote bidi stream ID */
	u64			max_uni_remote;		/* Max remote uni stream ID */

	/* Limits */
	u64			max_streams_bidi;	/* Max bidi streams */
	u64			max_streams_uni;	/* Max uni streams */
	u64			initial_max_stream_data_bidi_local;
	u64			initial_max_stream_data_bidi_remote;
	u64			initial_max_stream_data_uni;

	/* Scheduling */
	spinlock_t		sched_lock;
	struct list_head	sched_list;	/* Streams with data to send */
	u32			sched_count;

	/* Role: 0 = client, 1 = server */
	u8			is_server;

	/* Memory management */
	struct kmem_cache	*stream_cache;
	struct kmem_cache	*fragment_cache;

	/* Connection back-pointer */
	void			*conn;
};

/* Forward declarations */
static void quic_stream_destroy(struct kref *kref);
static void quic_stream_reassemble_try(struct quic_stream *stream);
static int quic_fragment_cmp(struct rb_node *node, const struct rb_node *parent);
static int quic_fragment_key_cmp(const void *key, const struct rb_node *node);

/*
 * ============================================================================
 * Stream ID Management (RFC 9000 Section 2.1)
 * ============================================================================
 *
 * Stream IDs are 62-bit integers with the following encoding:
 *   - Bit 0: Client-initiated (0) or Server-initiated (1)
 *   - Bit 1: Bidirectional (0) or Unidirectional (1)
 *   - Bits 2+: Sequence number
 *
 * This gives the following stream ID patterns:
 *   Client-initiated bidirectional: 0, 4, 8, 12, 16, ...
 *   Server-initiated bidirectional: 1, 5, 9, 13, 17, ...
 *   Client-initiated unidirectional: 2, 6, 10, 14, 18, ...
 *   Server-initiated unidirectional: 3, 7, 11, 15, 19, ...
 */

/**
 * quic_stream_is_local - Check if stream was locally initiated
 * @mgr: Stream manager
 * @stream_id: Stream ID to check
 *
 * Returns true if the stream was initiated by the local endpoint.
 */
bool quic_stream_is_local(struct quic_stream_manager *mgr, u64 stream_id)
{
	u8 initiator = stream_id & QUIC_STREAM_INITIATOR_MASK;

	return (initiator == 0 && !mgr->is_server) ||
	       (initiator == 1 && mgr->is_server);
}
EXPORT_SYMBOL_GPL(quic_stream_is_local);

/**
 * quic_stream_is_bidi - Check if stream is bidirectional
 * @stream_id: Stream ID to check
 *
 * Returns true if the stream is bidirectional.
 */
bool quic_stream_is_bidi(u64 stream_id)
{
	return (stream_id & QUIC_STREAM_DIR_MASK) == 0;
}
EXPORT_SYMBOL_GPL(quic_stream_is_bidi);

/**
 * quic_stream_is_client_initiated - Check if stream was client-initiated
 * @stream_id: Stream ID to check
 *
 * Returns true if the stream was initiated by the client.
 */
static inline bool quic_stream_is_client_initiated(u64 stream_id)
{
	return (stream_id & QUIC_STREAM_INITIATOR_MASK) == 0;
}

/**
 * quic_stream_get_type - Get the stream type from ID
 * @stream_id: Stream ID
 *
 * Returns the 2-bit stream type (0-3).
 */
static inline u8 quic_stream_get_type(u64 stream_id)
{
	return stream_id & 0x03;
}

/**
 * quic_stream_get_next_id - Get next stream ID for new stream
 * @mgr: Stream manager
 * @bidi: True for bidirectional, false for unidirectional
 *
 * Returns the next available stream ID of the requested type,
 * or -1 if stream limit reached.
 */
s64 quic_stream_get_next_id(struct quic_stream_manager *mgr, bool bidi)
{
	s64 stream_id;
	unsigned long flags;

	spin_lock_irqsave(&mgr->lock, flags);

	if (bidi) {
		/* Check against max streams limit */
		if ((mgr->next_bidi_local >> 2) >= mgr->max_streams_bidi) {
			spin_unlock_irqrestore(&mgr->lock, flags);
			return -1;
		}
		stream_id = mgr->next_bidi_local;
		mgr->next_bidi_local += 4;
	} else {
		if ((mgr->next_uni_local >> 2) >= mgr->max_streams_uni) {
			spin_unlock_irqrestore(&mgr->lock, flags);
			return -1;
		}
		stream_id = mgr->next_uni_local;
		mgr->next_uni_local += 4;
	}

	spin_unlock_irqrestore(&mgr->lock, flags);
	return stream_id;
}
EXPORT_SYMBOL_GPL(quic_stream_get_next_id);

/**
 * quic_stream_id_valid_for_role - Validate stream ID for our role
 * @mgr: Stream manager
 * @stream_id: Stream ID to validate
 * @creating: True if we are creating this stream
 *
 * Returns true if the stream ID is valid for our role.
 */
static bool quic_stream_id_valid_for_role(struct quic_stream_manager *mgr,
					  u64 stream_id, bool creating)
{
	bool local = quic_stream_is_local(mgr, stream_id);

	/* If creating, must be local. If receiving, must be remote */
	return creating ? local : !local;
}

/*
 * ============================================================================
 * Stream Allocation and Management
 * ============================================================================
 */

/* RB tree comparison for stream lookup */
static int quic_stream_cmp(struct rb_node *node, const struct rb_node *parent)
{
	struct quic_stream *s1 = rb_entry(node, struct quic_stream, node);
	struct quic_stream *s2 = rb_entry(parent, struct quic_stream, node);

	if (s1->id < s2->id)
		return -1;
	else if (s1->id > s2->id)
		return 1;
	return 0;
}

static int quic_stream_key_cmp(const void *key, const struct rb_node *node)
{
	const u64 *id = key;
	struct quic_stream *stream = rb_entry(node, struct quic_stream, node);

	if (*id < stream->id)
		return -1;
	else if (*id > stream->id)
		return 1;
	return 0;
}

/**
 * quic_stream_alloc - Allocate a new stream structure
 * @mgr: Stream manager
 * @stream_id: Stream ID for the new stream
 * @gfp: Memory allocation flags
 *
 * Allocates and initializes a new stream structure. Does not add
 * it to the stream manager.
 *
 * Returns the allocated stream or NULL on failure.
 */
struct quic_stream *quic_stream_alloc(struct quic_stream_manager *mgr,
				      u64 stream_id, gfp_t gfp)
{
	struct quic_stream *stream;
	bool bidi = quic_stream_is_bidi(stream_id);
	bool local = quic_stream_is_local(mgr, stream_id);

	if (mgr->stream_cache)
		stream = kmem_cache_zalloc(mgr->stream_cache, gfp);
	else
		stream = kzalloc(sizeof(*stream), gfp);

	if (!stream)
		return NULL;

	/* Initialize basic fields */
	stream->id = stream_id;
	kref_init(&stream->kref);
	stream->state = QUIC_STREAM_IDLE;
	stream->conn = mgr->conn;

	/* Initialize locks */
	spin_lock_init(&stream->state_lock);
	spin_lock_init(&stream->send_lock);
	spin_lock_init(&stream->recv_lock);
	spin_lock_init(&stream->fc_lock);

	/* Initialize send side */
	skb_queue_head_init(&stream->send_queue);
	stream->send_offset = 0;
	stream->bytes_sent = 0;
	stream->bytes_acked = 0;
	stream->send_fin = false;
	stream->fin_sent = false;
	stream->fin_acked = false;

	/* Set initial max data based on stream type and initiator */
	if (bidi) {
		if (local)
			stream->send_max_data = mgr->initial_max_stream_data_bidi_local;
		else
			stream->send_max_data = mgr->initial_max_stream_data_bidi_remote;
	} else {
		if (local)
			stream->send_max_data = mgr->initial_max_stream_data_uni;
		else
			stream->send_max_data = 0; /* Can't send on remote-initiated uni */
	}

	/* Initialize receive side */
	skb_queue_head_init(&stream->recv_queue);
	stream->recv_reorder = RB_ROOT;
	stream->recv_offset = 0;
	stream->bytes_recvd = 0;
	stream->bytes_read = 0;
	stream->recv_fin = false;
	stream->fin_read = false;
	stream->final_size = 0;
	stream->stop_sending = false;

	/* Set receive max data */
	if (bidi) {
		if (local)
			stream->recv_max_data = mgr->initial_max_stream_data_bidi_remote;
		else
			stream->recv_max_data = mgr->initial_max_stream_data_bidi_local;
	} else {
		if (!local)
			stream->recv_max_data = mgr->initial_max_stream_data_uni;
		else
			stream->recv_max_data = 0; /* Can't receive on local-initiated uni */
	}

	/* Initialize flow control */
	stream->fc_window = stream->recv_max_data;
	stream->fc_blocked = false;
	stream->fc_blocked_at = 0;

	/* Initialize priority and scheduling */
	stream->priority = QUIC_STREAM_PRIORITY_DEFAULT;
	stream->weight = 16; /* Default weight */
	stream->has_data = false;
	INIT_LIST_HEAD(&stream->sched_node);

	/* Initialize multipath support */
	stream->path_affinity = 0; /* No affinity by default */
	atomic_set(&stream->active_paths, 0);

	/* Initialize timestamps */
	stream->created_time = ktime_get();
	stream->last_activity = stream->created_time;
	stream->frames_sent = 0;
	stream->frames_recvd = 0;

	RB_CLEAR_NODE(&stream->node);

	return stream;
}
EXPORT_SYMBOL_GPL(quic_stream_alloc);

/**
 * quic_stream_init - Initialize a stream and add to manager
 * @mgr: Stream manager
 * @stream: Stream to initialize
 *
 * Adds an allocated stream to the stream manager's tree.
 * The stream must have been allocated with quic_stream_alloc().
 *
 * Returns 0 on success, negative error on failure.
 */
int quic_stream_init(struct quic_stream_manager *mgr, struct quic_stream *stream)
{
	struct rb_node *existing;
	unsigned long flags;

	if (!stream || RB_EMPTY_NODE(&stream->node) == 0)
		return -EINVAL;

	spin_lock_irqsave(&mgr->lock, flags);

	/* Check for duplicate stream ID */
	existing = rb_find_add(&stream->node, &mgr->streams, quic_stream_cmp);
	if (existing) {
		spin_unlock_irqrestore(&mgr->lock, flags);
		return -EEXIST;
	}

	mgr->num_streams++;

	/* Transition to OPEN state */
	stream->state = QUIC_STREAM_OPEN;

	spin_unlock_irqrestore(&mgr->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_stream_init);

/**
 * quic_stream_get - Get a reference to a stream
 * @stream: Stream to reference
 *
 * Increments the stream's reference count.
 */
void quic_stream_get(struct quic_stream *stream)
{
	if (stream)
		kref_get(&stream->kref);
}
EXPORT_SYMBOL_GPL(quic_stream_get);

/**
 * quic_stream_put - Release a stream reference
 * @stream: Stream to release
 *
 * Decrements the stream's reference count. When the count
 * reaches zero, the stream is freed.
 */
void quic_stream_put(struct quic_stream *stream)
{
	if (stream)
		kref_put(&stream->kref, quic_stream_destroy);
}
EXPORT_SYMBOL_GPL(quic_stream_put);

/**
 * quic_stream_destroy - Destroy a stream (kref callback)
 * @kref: kref embedded in stream
 */
static void quic_stream_destroy(struct kref *kref)
{
	struct quic_stream *stream = container_of(kref, struct quic_stream, kref);
	struct quic_stream_fragment *frag, *tmp;

	/* Free send queue */
	skb_queue_purge(&stream->send_queue);

	/* Free receive queue */
	skb_queue_purge(&stream->recv_queue);

	/* Free reorder buffer */
	rbtree_postorder_for_each_entry_safe(frag, tmp, &stream->recv_reorder, node) {
		if (frag->skb)
			kfree_skb(frag->skb);
		kfree(frag);
	}

	kfree(stream);
}

/**
 * quic_stream_free - Remove stream from manager and release
 * @mgr: Stream manager
 * @stream: Stream to free
 *
 * Removes the stream from the manager's tree and releases the reference.
 */
void quic_stream_free(struct quic_stream_manager *mgr, struct quic_stream *stream)
{
	unsigned long flags;

	if (!stream)
		return;

	spin_lock_irqsave(&mgr->lock, flags);

	if (!RB_EMPTY_NODE(&stream->node)) {
		rb_erase(&stream->node, &mgr->streams);
		RB_CLEAR_NODE(&stream->node);
		mgr->num_streams--;
	}

	/* Remove from scheduler list if present */
	spin_lock(&mgr->sched_lock);
	if (!list_empty(&stream->sched_node)) {
		list_del_init(&stream->sched_node);
		mgr->sched_count--;
	}
	spin_unlock(&mgr->sched_lock);

	spin_unlock_irqrestore(&mgr->lock, flags);

	quic_stream_put(stream);
}
EXPORT_SYMBOL_GPL(quic_stream_free);

/**
 * quic_stream_lookup - Find a stream by ID
 * @mgr: Stream manager
 * @stream_id: Stream ID to find
 *
 * Returns the stream with a reference held, or NULL if not found.
 * Caller must call quic_stream_put() when done.
 */
struct quic_stream *quic_stream_lookup(struct quic_stream_manager *mgr, u64 stream_id)
{
	struct rb_node *node;
	struct quic_stream *stream = NULL;
	unsigned long flags;

	spin_lock_irqsave(&mgr->lock, flags);

	node = rb_find(&stream_id, &mgr->streams, quic_stream_key_cmp);
	if (node) {
		stream = rb_entry(node, struct quic_stream, node);
		quic_stream_get(stream);
	}

	spin_unlock_irqrestore(&mgr->lock, flags);
	return stream;
}
EXPORT_SYMBOL_GPL(quic_stream_lookup);

/**
 * quic_stream_get_or_create - Get existing stream or create new one
 * @mgr: Stream manager
 * @stream_id: Stream ID
 * @created: Output flag, set to true if stream was created
 * @gfp: Memory allocation flags
 *
 * Returns stream with reference held, or NULL on error.
 */
struct quic_stream *quic_stream_get_or_create(struct quic_stream_manager *mgr,
					      u64 stream_id, bool *created,
					      gfp_t gfp)
{
	struct quic_stream *stream;
	int ret;

	if (created)
		*created = false;

	/* First try to find existing stream */
	stream = quic_stream_lookup(mgr, stream_id);
	if (stream)
		return stream;

	/* Validate stream ID for creation */
	if (!quic_stream_id_valid_for_role(mgr, stream_id, quic_stream_is_local(mgr, stream_id)))
		return NULL;

	/* Allocate new stream */
	stream = quic_stream_alloc(mgr, stream_id, gfp);
	if (!stream)
		return NULL;

	/* Add to manager */
	ret = quic_stream_init(mgr, stream);
	if (ret) {
		/* Stream may have been created by another path (TQUIC) */
		quic_stream_put(stream);
		stream = quic_stream_lookup(mgr, stream_id);
		return stream;
	}

	if (created)
		*created = true;

	/* Return with reference from allocation */
	return stream;
}
EXPORT_SYMBOL_GPL(quic_stream_get_or_create);

/*
 * ============================================================================
 * Stream State Machine (RFC 9000 Section 3)
 * ============================================================================
 */

static const char *quic_stream_state_names[] = {
	[QUIC_STREAM_IDLE] = "IDLE",
	[QUIC_STREAM_OPEN] = "OPEN",
	[QUIC_STREAM_HALF_CLOSED_LOCAL] = "HALF_CLOSED_LOCAL",
	[QUIC_STREAM_HALF_CLOSED_REMOTE] = "HALF_CLOSED_REMOTE",
	[QUIC_STREAM_CLOSED] = "CLOSED",
	[QUIC_STREAM_RESET_SENT] = "RESET_SENT",
	[QUIC_STREAM_RESET_RECVD] = "RESET_RECVD",
};

/**
 * quic_stream_state_name - Get human-readable state name
 * @state: Stream state
 */
const char *quic_stream_state_name(enum quic_stream_state state)
{
	if (state >= __QUIC_STREAM_STATE_MAX)
		return "UNKNOWN";
	return quic_stream_state_names[state];
}
EXPORT_SYMBOL_GPL(quic_stream_state_name);

/**
 * quic_stream_set_state - Set stream state directly
 * @stream: Stream to modify
 * @new_state: New state
 *
 * Sets the stream state without validation. Use quic_stream_transition()
 * for validated state transitions.
 */
void quic_stream_set_state(struct quic_stream *stream,
			   enum quic_stream_state new_state)
{
	unsigned long flags;

	spin_lock_irqsave(&stream->state_lock, flags);
	stream->state = new_state;
	stream->last_activity = ktime_get();
	spin_unlock_irqrestore(&stream->state_lock, flags);
}
EXPORT_SYMBOL_GPL(quic_stream_set_state);

/**
 * quic_stream_get_state - Get current stream state
 * @stream: Stream to query
 */
enum quic_stream_state quic_stream_get_state(struct quic_stream *stream)
{
	enum quic_stream_state state;
	unsigned long flags;

	spin_lock_irqsave(&stream->state_lock, flags);
	state = stream->state;
	spin_unlock_irqrestore(&stream->state_lock, flags);

	return state;
}
EXPORT_SYMBOL_GPL(quic_stream_get_state);

/*
 * State transition table
 * Returns true if transition is valid
 */
static bool quic_stream_transition_valid(enum quic_stream_state from,
					 enum quic_stream_state to)
{
	switch (from) {
	case QUIC_STREAM_IDLE:
		return to == QUIC_STREAM_OPEN;

	case QUIC_STREAM_OPEN:
		return to == QUIC_STREAM_HALF_CLOSED_LOCAL ||
		       to == QUIC_STREAM_HALF_CLOSED_REMOTE ||
		       to == QUIC_STREAM_CLOSED ||
		       to == QUIC_STREAM_RESET_SENT ||
		       to == QUIC_STREAM_RESET_RECVD;

	case QUIC_STREAM_HALF_CLOSED_LOCAL:
		return to == QUIC_STREAM_CLOSED ||
		       to == QUIC_STREAM_RESET_RECVD;

	case QUIC_STREAM_HALF_CLOSED_REMOTE:
		return to == QUIC_STREAM_CLOSED ||
		       to == QUIC_STREAM_RESET_SENT;

	case QUIC_STREAM_RESET_SENT:
		return to == QUIC_STREAM_CLOSED;

	case QUIC_STREAM_RESET_RECVD:
		return to == QUIC_STREAM_CLOSED;

	case QUIC_STREAM_CLOSED:
		return false; /* Terminal state */

	default:
		return false;
	}
}

/**
 * quic_stream_transition - Attempt validated state transition
 * @stream: Stream to transition
 * @new_state: Target state
 *
 * Returns 0 on success, -EINVAL if transition is not valid.
 */
int quic_stream_transition(struct quic_stream *stream,
			   enum quic_stream_state new_state)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&stream->state_lock, flags);

	if (!quic_stream_transition_valid(stream->state, new_state)) {
		ret = -EINVAL;
		goto out;
	}

	stream->state = new_state;
	stream->last_activity = ktime_get();

out:
	spin_unlock_irqrestore(&stream->state_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(quic_stream_transition);

/**
 * quic_stream_can_send - Check if sending is allowed
 * @stream: Stream to check
 */
bool quic_stream_can_send(struct quic_stream *stream)
{
	enum quic_stream_state state;
	unsigned long flags;

	spin_lock_irqsave(&stream->state_lock, flags);
	state = stream->state;
	spin_unlock_irqrestore(&stream->state_lock, flags);

	return state == QUIC_STREAM_OPEN ||
	       state == QUIC_STREAM_HALF_CLOSED_REMOTE;
}
EXPORT_SYMBOL_GPL(quic_stream_can_send);

/**
 * quic_stream_can_recv - Check if receiving is allowed
 * @stream: Stream to check
 */
bool quic_stream_can_recv(struct quic_stream *stream)
{
	enum quic_stream_state state;
	unsigned long flags;

	spin_lock_irqsave(&stream->state_lock, flags);
	state = stream->state;
	spin_unlock_irqrestore(&stream->state_lock, flags);

	return state == QUIC_STREAM_OPEN ||
	       state == QUIC_STREAM_HALF_CLOSED_LOCAL;
}
EXPORT_SYMBOL_GPL(quic_stream_can_recv);

/*
 * ============================================================================
 * Send Operations
 * ============================================================================
 */

/**
 * quic_stream_send - Queue data for sending on a stream
 * @stream: Stream to send on
 * @data: Data buffer
 * @len: Length of data
 * @gfp: Memory allocation flags
 *
 * Copies data into sk_buff and queues it for sending. Flow control
 * is checked and data may be partially queued.
 *
 * Returns number of bytes queued, or negative error.
 */
ssize_t quic_stream_send(struct quic_stream *stream, const void *data,
			 size_t len, gfp_t gfp)
{
	struct sk_buff *skb;
	size_t avail, to_send;
	unsigned long flags;
	ssize_t sent = 0;

	if (!quic_stream_can_send(stream))
		return -EPIPE;

	spin_lock_irqsave(&stream->send_lock, flags);

	/* Check flow control */
	spin_lock(&stream->fc_lock);
	avail = stream->send_max_data - stream->bytes_sent;
	if (avail == 0) {
		stream->fc_blocked = true;
		stream->fc_blocked_at = stream->send_max_data;
		spin_unlock(&stream->fc_lock);
		spin_unlock_irqrestore(&stream->send_lock, flags);
		return -EAGAIN;
	}
	spin_unlock(&stream->fc_lock);

	to_send = min(len, avail);

	while (to_send > 0) {
		size_t chunk = min_t(size_t, to_send, SKB_MAX_ALLOC);

		skb = alloc_skb(chunk, gfp);
		if (!skb) {
			if (sent == 0)
				sent = -ENOMEM;
			break;
		}

		skb_put_data(skb, data + sent, chunk);

		/* Store offset in skb->cb for later frame generation */
		*(u64 *)skb->cb = stream->send_offset;

		skb_queue_tail(&stream->send_queue, skb);

		stream->send_offset += chunk;
		stream->bytes_sent += chunk;
		sent += chunk;
		to_send -= chunk;
	}

	if (sent > 0) {
		stream->has_data = true;
		stream->last_activity = ktime_get();
	}

	spin_unlock_irqrestore(&stream->send_lock, flags);

	return sent;
}
EXPORT_SYMBOL_GPL(quic_stream_send);

/**
 * quic_stream_send_fin - Mark stream for FIN (end of data)
 * @stream: Stream to finish
 *
 * Marks the stream to send FIN with the next frame. This closes
 * the send side of the stream.
 *
 * Returns 0 on success, negative error on failure.
 */
int quic_stream_send_fin(struct quic_stream *stream)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&stream->send_lock, flags);

	if (stream->send_fin) {
		/* Already marked for FIN */
		ret = -EALREADY;
		goto out;
	}

	stream->send_fin = true;
	stream->has_data = true; /* Need to send FIN frame */

out:
	spin_unlock_irqrestore(&stream->send_lock, flags);

	if (ret == 0) {
		/* Transition state when FIN is acknowledged */
		spin_lock_irqsave(&stream->state_lock, flags);
		if (stream->state == QUIC_STREAM_HALF_CLOSED_REMOTE)
			stream->state = QUIC_STREAM_CLOSED;
		else if (stream->state == QUIC_STREAM_OPEN)
			stream->state = QUIC_STREAM_HALF_CLOSED_LOCAL;
		spin_unlock_irqrestore(&stream->state_lock, flags);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(quic_stream_send_fin);

/**
 * quic_stream_reset - Reset stream with RESET_STREAM frame
 * @stream: Stream to reset
 * @error_code: Application error code
 *
 * Abruptly terminates the sending side of the stream. Any unsent
 * data is discarded.
 *
 * Returns 0 on success, negative error on failure.
 */
int quic_stream_reset(struct quic_stream *stream, u64 error_code)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&stream->state_lock, flags);

	/* Check if reset is allowed */
	if (stream->state != QUIC_STREAM_OPEN &&
	    stream->state != QUIC_STREAM_HALF_CLOSED_REMOTE) {
		spin_unlock_irqrestore(&stream->state_lock, flags);
		return -EINVAL;
	}

	stream->state = QUIC_STREAM_RESET_SENT;
	spin_unlock_irqrestore(&stream->state_lock, flags);

	/* Clear send queue */
	spin_lock_irqsave(&stream->send_lock, flags);
	stream->reset_error_code = error_code;
	skb_queue_purge(&stream->send_queue);
	stream->send_fin = false;
	stream->has_data = true; /* Need to send RESET_STREAM */
	spin_unlock_irqrestore(&stream->send_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_stream_reset);

/**
 * quic_stream_ack_data - Handle acknowledgment of sent data
 * @stream: Stream that had data acknowledged
 * @offset: Starting offset of acknowledged range
 * @len: Length of acknowledged range
 *
 * Updates stream state based on acknowledgment.
 */
void quic_stream_ack_data(struct quic_stream *stream, u64 offset, u64 len)
{
	unsigned long flags;

	spin_lock_irqsave(&stream->send_lock, flags);

	/* Update bytes acked (simplified - real impl needs gap tracking) */
	if (offset + len > stream->bytes_acked)
		stream->bytes_acked = offset + len;

	/* Check if FIN was acknowledged */
	if (stream->fin_sent && stream->bytes_acked >= stream->send_offset) {
		stream->fin_acked = true;
	}

	spin_unlock_irqrestore(&stream->send_lock, flags);

	/* Handle FIN acknowledgment state transition */
	if (stream->fin_acked) {
		spin_lock_irqsave(&stream->state_lock, flags);
		if (stream->state == QUIC_STREAM_HALF_CLOSED_LOCAL &&
		    stream->recv_fin && stream->fin_read) {
			stream->state = QUIC_STREAM_CLOSED;
		}
		spin_unlock_irqrestore(&stream->state_lock, flags);
	}
}
EXPORT_SYMBOL_GPL(quic_stream_ack_data);

/*
 * ============================================================================
 * Receive Operations
 * ============================================================================
 */

/* Fragment RB tree comparison functions */
static int quic_fragment_cmp(struct rb_node *node, const struct rb_node *parent)
{
	struct quic_stream_fragment *f1 = rb_entry(node, struct quic_stream_fragment, node);
	struct quic_stream_fragment *f2 = rb_entry(parent, struct quic_stream_fragment, node);

	if (f1->offset < f2->offset)
		return -1;
	else if (f1->offset > f2->offset)
		return 1;
	return 0;
}

static int quic_fragment_key_cmp(const void *key, const struct rb_node *node)
{
	const u64 *offset = key;
	struct quic_stream_fragment *frag = rb_entry(node, struct quic_stream_fragment, node);

	if (*offset < frag->offset)
		return -1;
	else if (*offset >= frag->offset + frag->len)
		return 1;
	return 0;
}

/**
 * quic_stream_receive - Receive data into stream
 * @stream: Stream to receive on
 * @skb: Data buffer (ownership transferred on success)
 * @offset: Offset within stream
 * @fin: True if this completes the stream
 *
 * Handles incoming STREAM frame data. Out-of-order data is buffered
 * for reassembly.
 *
 * Returns 0 on success, negative error on failure.
 */
int quic_stream_receive(struct quic_stream *stream, struct sk_buff *skb,
			u64 offset, bool fin)
{
	struct quic_stream_fragment *frag;
	unsigned long flags;
	u32 len = skb->len;
	int ret = 0;

	if (!quic_stream_can_recv(stream)) {
		kfree_skb(skb);
		return -EPIPE;
	}

	spin_lock_irqsave(&stream->recv_lock, flags);

	/* Flow control check */
	if (offset + len > stream->recv_max_data) {
		ret = -ENOSPC; /* Flow control violation */
		goto out_unlock;
	}

	/* Handle FIN */
	if (fin) {
		if (stream->recv_fin && stream->final_size != offset + len) {
			ret = -EPROTO; /* Conflicting final size */
			goto out_unlock;
		}
		stream->recv_fin = true;
		stream->final_size = offset + len;
	}

	/* Check if data is already received (duplicate) */
	if (offset + len <= stream->recv_offset) {
		/* Completely duplicate data, discard */
		ret = 0;
		goto out_unlock;
	}

	/* Check if data is in-order */
	if (offset == stream->recv_offset) {
		/* In-order data - add directly to receive queue */
		skb_queue_tail(&stream->recv_queue, skb);
		stream->recv_offset += len;
		stream->bytes_recvd += len;
		stream->frames_recvd++;

		/* Try to reassemble any buffered fragments */
		spin_unlock_irqrestore(&stream->recv_lock, flags);
		quic_stream_reassemble_try(stream);
		return 0;
	}

	/* Out-of-order data - buffer for reassembly */
	if (offset < stream->recv_offset) {
		/* Partial overlap with already-received data */
		u64 overlap = stream->recv_offset - offset;

		if (overlap >= len) {
			/* Completely overlapping */
			ret = 0;
			goto out_unlock;
		}

		/* Trim the overlapping part */
		skb_pull(skb, overlap);
		offset += overlap;
		len -= overlap;
	}

	/* Allocate fragment structure */
	frag = kzalloc(sizeof(*frag), GFP_ATOMIC);
	if (!frag) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	frag->offset = offset;
	frag->len = len;
	frag->skb = skb;

	/* Insert into reorder buffer */
	if (rb_find_add(&frag->node, &stream->recv_reorder, quic_fragment_cmp)) {
		/* Duplicate fragment */
		kfree(frag);
		ret = 0;
		goto out_unlock;
	}

	stream->frames_recvd++;
	spin_unlock_irqrestore(&stream->recv_lock, flags);

	return 0;

out_unlock:
	spin_unlock_irqrestore(&stream->recv_lock, flags);
	if (ret != 0)
		kfree_skb(skb);
	return ret;
}
EXPORT_SYMBOL_GPL(quic_stream_receive);

/**
 * quic_stream_reassemble_try - Try to reassemble buffered fragments
 * @stream: Stream to reassemble
 *
 * Moves contiguous fragments from the reorder buffer to the receive queue.
 */
static void quic_stream_reassemble_try(struct quic_stream *stream)
{
	struct quic_stream_fragment *frag;
	struct rb_node *node;
	unsigned long flags;

	spin_lock_irqsave(&stream->recv_lock, flags);

	while ((node = rb_first(&stream->recv_reorder)) != NULL) {
		frag = rb_entry(node, struct quic_stream_fragment, node);

		/* Check if this fragment is next in sequence */
		if (frag->offset > stream->recv_offset)
			break; /* Gap exists */

		if (frag->offset + frag->len <= stream->recv_offset) {
			/* Fragment is now obsolete (duplicate) */
			rb_erase(node, &stream->recv_reorder);
			kfree_skb(frag->skb);
			kfree(frag);
			continue;
		}

		/* Fragment is contiguous or overlapping */
		if (frag->offset < stream->recv_offset) {
			/* Partial overlap - trim */
			u64 trim = stream->recv_offset - frag->offset;

			skb_pull(frag->skb, trim);
			frag->offset += trim;
			frag->len -= trim;
		}

		/* Remove from reorder buffer */
		rb_erase(node, &stream->recv_reorder);

		/* Add to receive queue */
		skb_queue_tail(&stream->recv_queue, frag->skb);
		stream->recv_offset += frag->len;
		stream->bytes_recvd += frag->len;

		kfree(frag);
	}

	spin_unlock_irqrestore(&stream->recv_lock, flags);
}

/**
 * quic_stream_reassemble - Force reassembly of stream data
 * @stream: Stream to reassemble
 *
 * Public interface to trigger reassembly. Called when new in-order
 * data might enable reassembly of buffered fragments.
 */
void quic_stream_reassemble(struct quic_stream *stream)
{
	quic_stream_reassemble_try(stream);
}
EXPORT_SYMBOL_GPL(quic_stream_reassemble);

/**
 * quic_stream_read - Read data from stream
 * @stream: Stream to read from
 * @buf: Buffer to read into
 * @len: Maximum bytes to read
 * @fin: Output - set to true if FIN was received and all data read
 *
 * Copies data from the receive queue to the user buffer.
 *
 * Returns number of bytes read, 0 if no data available, negative on error.
 */
ssize_t quic_stream_read(struct quic_stream *stream, void *buf, size_t len,
			 bool *fin)
{
	struct sk_buff *skb;
	unsigned long flags;
	ssize_t copied = 0;

	if (fin)
		*fin = false;

	spin_lock_irqsave(&stream->recv_lock, flags);

	while (copied < len && (skb = skb_peek(&stream->recv_queue)) != NULL) {
		size_t avail = skb->len;
		size_t to_copy = min(len - copied, avail);

		skb_copy_bits(skb, 0, buf + copied, to_copy);
		copied += to_copy;
		stream->bytes_read += to_copy;

		if (to_copy < avail) {
			/* Partial read - pull from skb */
			skb_pull(skb, to_copy);
		} else {
			/* Complete read - free skb */
			skb_unlink(skb, &stream->recv_queue);
			kfree_skb(skb);
		}
	}

	/* Check for FIN */
	if (stream->recv_fin && stream->bytes_read >= stream->final_size) {
		stream->fin_read = true;
		if (fin)
			*fin = true;

		/* State transition */
		if (stream->state == QUIC_STREAM_OPEN)
			stream->state = QUIC_STREAM_HALF_CLOSED_REMOTE;
		else if (stream->state == QUIC_STREAM_HALF_CLOSED_LOCAL)
			stream->state = QUIC_STREAM_CLOSED;
	}

	stream->last_activity = ktime_get();
	spin_unlock_irqrestore(&stream->recv_lock, flags);

	return copied;
}
EXPORT_SYMBOL_GPL(quic_stream_read);

/**
 * quic_stream_stop_sending - Request peer stop sending with STOP_SENDING
 * @stream: Stream to stop
 * @error_code: Application error code
 *
 * Sends a STOP_SENDING frame to request the peer stop transmitting.
 *
 * Returns 0 on success, negative error on failure.
 */
int quic_stream_stop_sending(struct quic_stream *stream, u64 error_code)
{
	unsigned long flags;

	spin_lock_irqsave(&stream->recv_lock, flags);

	if (stream->stop_sending) {
		spin_unlock_irqrestore(&stream->recv_lock, flags);
		return -EALREADY;
	}

	stream->stop_sending = true;
	stream->stop_sending_code = error_code;
	stream->has_data = true; /* Need to send STOP_SENDING frame */

	spin_unlock_irqrestore(&stream->recv_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_stream_stop_sending);

/**
 * quic_stream_handle_reset - Handle received RESET_STREAM frame
 * @stream: Stream that was reset
 * @error_code: Error code from peer
 * @final_size: Final size indicated by peer
 *
 * Processes an incoming RESET_STREAM frame.
 *
 * Returns 0 on success, negative error on failure.
 */
int quic_stream_handle_reset(struct quic_stream *stream, u64 error_code,
			     u64 final_size)
{
	unsigned long flags;

	spin_lock_irqsave(&stream->state_lock, flags);

	if (stream->state == QUIC_STREAM_CLOSED) {
		spin_unlock_irqrestore(&stream->state_lock, flags);
		return 0; /* Already closed */
	}

	/* Validate final size if we already received FIN */
	spin_lock(&stream->recv_lock);
	if (stream->recv_fin && stream->final_size != final_size) {
		spin_unlock(&stream->recv_lock);
		spin_unlock_irqrestore(&stream->state_lock, flags);
		return -EPROTO; /* Conflicting final size */
	}

	stream->recv_fin = true;
	stream->final_size = final_size;
	stream->reset_error_code = error_code;

	/* Discard buffered data */
	skb_queue_purge(&stream->recv_queue);
	spin_unlock(&stream->recv_lock);

	/* Transition state */
	if (stream->state == QUIC_STREAM_OPEN ||
	    stream->state == QUIC_STREAM_HALF_CLOSED_LOCAL) {
		stream->state = QUIC_STREAM_RESET_RECVD;
	}

	spin_unlock_irqrestore(&stream->state_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_stream_handle_reset);

/*
 * ============================================================================
 * Flow Control (Per-Stream)
 * ============================================================================
 */

/**
 * quic_stream_update_max_data - Update MAX_STREAM_DATA (flow control window)
 * @stream: Stream to update
 * @max_data: New maximum data offset
 *
 * Called when receiving MAX_STREAM_DATA frame from peer.
 *
 * Returns true if window was increased (unblocks sending).
 */
bool quic_stream_update_max_data(struct quic_stream *stream, u64 max_data)
{
	unsigned long flags;
	bool unblocked = false;

	spin_lock_irqsave(&stream->fc_lock, flags);

	if (max_data > stream->send_max_data) {
		stream->send_max_data = max_data;

		if (stream->fc_blocked && max_data > stream->fc_blocked_at) {
			stream->fc_blocked = false;
			unblocked = true;
		}
	}

	spin_unlock_irqrestore(&stream->fc_lock, flags);

	return unblocked;
}
EXPORT_SYMBOL_GPL(quic_stream_update_max_data);

/**
 * quic_stream_blocked - Handle STREAM_DATA_BLOCKED from peer
 * @stream: Stream that is blocked
 * @offset: Offset at which peer is blocked
 *
 * Called when receiving STREAM_DATA_BLOCKED frame from peer.
 * May trigger sending of MAX_STREAM_DATA frame.
 *
 * Returns true if we should send MAX_STREAM_DATA.
 */
bool quic_stream_blocked(struct quic_stream *stream, u64 offset)
{
	unsigned long flags;
	bool should_update = false;

	spin_lock_irqsave(&stream->recv_lock, flags);

	/* Check if we can increase the window */
	if (offset >= stream->recv_max_data) {
		/* Peer is at our limit - consider increasing */
		u64 consumed = stream->bytes_read;
		u64 buffered = stream->bytes_recvd - consumed;

		/* Increase window if we've consumed significant data */
		if (consumed > stream->recv_max_data / 2) {
			stream->recv_max_data += consumed;
			should_update = true;
		}
	}

	spin_unlock_irqrestore(&stream->recv_lock, flags);

	return should_update;
}
EXPORT_SYMBOL_GPL(quic_stream_blocked);

/**
 * quic_stream_get_max_data_to_send - Get MAX_STREAM_DATA value to send
 * @stream: Stream to query
 *
 * Returns the current receive window limit to advertise to peer.
 */
u64 quic_stream_get_max_data_to_send(struct quic_stream *stream)
{
	unsigned long flags;
	u64 max_data;

	spin_lock_irqsave(&stream->recv_lock, flags);
	max_data = stream->recv_max_data;
	spin_unlock_irqrestore(&stream->recv_lock, flags);

	return max_data;
}
EXPORT_SYMBOL_GPL(quic_stream_get_max_data_to_send);

/**
 * quic_stream_is_blocked - Check if stream is flow control blocked
 * @stream: Stream to check
 */
bool quic_stream_is_blocked(struct quic_stream *stream)
{
	unsigned long flags;
	bool blocked;

	spin_lock_irqsave(&stream->fc_lock, flags);
	blocked = stream->fc_blocked;
	spin_unlock_irqrestore(&stream->fc_lock, flags);

	return blocked;
}
EXPORT_SYMBOL_GPL(quic_stream_is_blocked);

/*
 * ============================================================================
 * Priority and Scheduling
 * ============================================================================
 */

/**
 * quic_stream_set_priority - Set stream priority
 * @stream: Stream to modify
 * @priority: Priority value (0 = highest, 255 = lowest)
 *
 * Higher priority streams are scheduled before lower priority ones.
 */
void quic_stream_set_priority(struct quic_stream *stream, u8 priority)
{
	stream->priority = priority;
}
EXPORT_SYMBOL_GPL(quic_stream_set_priority);

/**
 * quic_stream_get_priority - Get stream priority
 * @stream: Stream to query
 */
u8 quic_stream_get_priority(struct quic_stream *stream)
{
	return stream->priority;
}
EXPORT_SYMBOL_GPL(quic_stream_get_priority);

/**
 * quic_stream_set_weight - Set stream scheduling weight
 * @stream: Stream to modify
 * @weight: Weight value (1-256)
 *
 * Weight affects bandwidth distribution among same-priority streams.
 */
void quic_stream_set_weight(struct quic_stream *stream, u16 weight)
{
	if (weight < 1)
		weight = 1;
	else if (weight > 256)
		weight = 256;
	stream->weight = weight;
}
EXPORT_SYMBOL_GPL(quic_stream_set_weight);

/**
 * quic_stream_schedule - Add stream to scheduler
 * @mgr: Stream manager
 * @stream: Stream to schedule
 *
 * Adds a stream to the scheduler list if it has data to send.
 */
void quic_stream_schedule(struct quic_stream_manager *mgr, struct quic_stream *stream)
{
	unsigned long flags;

	if (!stream->has_data)
		return;

	spin_lock_irqsave(&mgr->sched_lock, flags);

	if (list_empty(&stream->sched_node)) {
		/* Insert sorted by priority (lower value = higher priority) */
		struct quic_stream *s;
		struct list_head *pos = &mgr->sched_list;

		list_for_each_entry(s, &mgr->sched_list, sched_node) {
			if (stream->priority < s->priority) {
				pos = &s->sched_node;
				break;
			}
		}
		list_add_tail(&stream->sched_node, pos);
		mgr->sched_count++;
		quic_stream_get(stream); /* Reference for scheduler */
	}

	spin_unlock_irqrestore(&mgr->sched_lock, flags);
}
EXPORT_SYMBOL_GPL(quic_stream_schedule);

/**
 * quic_stream_unschedule - Remove stream from scheduler
 * @mgr: Stream manager
 * @stream: Stream to remove
 */
void quic_stream_unschedule(struct quic_stream_manager *mgr, struct quic_stream *stream)
{
	unsigned long flags;

	spin_lock_irqsave(&mgr->sched_lock, flags);

	if (!list_empty(&stream->sched_node)) {
		list_del_init(&stream->sched_node);
		mgr->sched_count--;
		quic_stream_put(stream); /* Release scheduler reference */
	}

	spin_unlock_irqrestore(&mgr->sched_lock, flags);
}
EXPORT_SYMBOL_GPL(quic_stream_unschedule);

/**
 * quic_stream_get_next_to_send - Get next stream with data to send
 * @mgr: Stream manager
 *
 * Returns the highest priority stream with data ready to send.
 * Returns stream with reference held, or NULL if no streams have data.
 */
struct quic_stream *quic_stream_get_next_to_send(struct quic_stream_manager *mgr)
{
	struct quic_stream *stream = NULL;
	unsigned long flags;

	spin_lock_irqsave(&mgr->sched_lock, flags);

	if (!list_empty(&mgr->sched_list)) {
		stream = list_first_entry(&mgr->sched_list, struct quic_stream, sched_node);

		/* Verify stream still has data */
		if (stream->has_data) {
			quic_stream_get(stream);
		} else {
			/* Remove from scheduler */
			list_del_init(&stream->sched_node);
			mgr->sched_count--;
			quic_stream_put(stream);
			stream = NULL;
		}
	}

	spin_unlock_irqrestore(&mgr->sched_lock, flags);

	return stream;
}
EXPORT_SYMBOL_GPL(quic_stream_get_next_to_send);

/**
 * quic_stream_get_next_to_send_rr - Round-robin stream selection
 * @mgr: Stream manager
 *
 * Gets next stream using weighted round-robin among same priority.
 * Returns stream with reference held, or NULL.
 */
struct quic_stream *quic_stream_get_next_to_send_rr(struct quic_stream_manager *mgr)
{
	struct quic_stream *stream, *selected = NULL;
	unsigned long flags;

	spin_lock_irqsave(&mgr->sched_lock, flags);

	if (list_empty(&mgr->sched_list)) {
		spin_unlock_irqrestore(&mgr->sched_lock, flags);
		return NULL;
	}

	/* Find first stream with data at highest priority */
	list_for_each_entry(stream, &mgr->sched_list, sched_node) {
		if (stream->has_data && quic_stream_can_send(stream)) {
			selected = stream;
			break;
		}
	}

	if (selected) {
		/* Move to end of same-priority group for round-robin */
		struct quic_stream *next;
		u8 prio = selected->priority;

		list_del_init(&selected->sched_node);

		/* Find insertion point (after all same-priority streams) */
		list_for_each_entry(next, &mgr->sched_list, sched_node) {
			if (next->priority > prio)
				break;
		}
		list_add_tail(&selected->sched_node, &next->sched_node);

		quic_stream_get(selected);
	}

	spin_unlock_irqrestore(&mgr->sched_lock, flags);

	return selected;
}
EXPORT_SYMBOL_GPL(quic_stream_get_next_to_send_rr);

/*
 * ============================================================================
 * Stream Frame Generation
 * ============================================================================
 */

/**
 * quic_stream_frame_header_size - Calculate STREAM frame header size
 * @stream_id: Stream ID
 * @offset: Data offset
 * @has_length: True if length field will be included
 *
 * Returns the size of the STREAM frame header.
 */
static size_t quic_stream_frame_header_size(u64 stream_id, u64 offset, bool has_length)
{
	size_t size = 1; /* Frame type byte */

	/* Variable-length integer encoding sizes */
	if (stream_id < 64)
		size += 1;
	else if (stream_id < 16384)
		size += 2;
	else if (stream_id < 1073741824)
		size += 4;
	else
		size += 8;

	if (offset > 0) {
		if (offset < 64)
			size += 1;
		else if (offset < 16384)
			size += 2;
		else if (offset < 1073741824)
			size += 4;
		else
			size += 8;
	}

	if (has_length)
		size += 2; /* Length field (up to 2 bytes for typical frames) */

	return size;
}

/**
 * quic_stream_encode_varint - Encode variable-length integer
 * @buf: Buffer to write to
 * @val: Value to encode
 *
 * Returns number of bytes written.
 */
static int quic_stream_encode_varint(u8 *buf, u64 val)
{
	if (val < 64) {
		buf[0] = val;
		return 1;
	} else if (val < 16384) {
		buf[0] = 0x40 | (val >> 8);
		buf[1] = val & 0xff;
		return 2;
	} else if (val < 1073741824) {
		buf[0] = 0x80 | (val >> 24);
		buf[1] = (val >> 16) & 0xff;
		buf[2] = (val >> 8) & 0xff;
		buf[3] = val & 0xff;
		return 4;
	} else {
		buf[0] = 0xc0 | (val >> 56);
		buf[1] = (val >> 48) & 0xff;
		buf[2] = (val >> 40) & 0xff;
		buf[3] = (val >> 32) & 0xff;
		buf[4] = (val >> 24) & 0xff;
		buf[5] = (val >> 16) & 0xff;
		buf[6] = (val >> 8) & 0xff;
		buf[7] = val & 0xff;
		return 8;
	}
}

/**
 * quic_stream_create_frame - Create a STREAM frame
 * @stream: Source stream
 * @max_size: Maximum frame size (including header)
 * @offset_out: Output - offset of data in frame
 * @len_out: Output - length of data in frame
 * @fin_out: Output - true if FIN is included
 *
 * Creates a STREAM frame from queued data. Returns an sk_buff containing
 * the frame, or NULL if no data available or on error.
 *
 * The frame format (RFC 9000 Section 19.8):
 *   - Type (1 byte): 0x08-0x0f with bits for OFF, LEN, FIN
 *   - Stream ID (variable)
 *   - [Offset] (variable, if OFF bit set)
 *   - [Length] (variable, if LEN bit set)
 *   - Stream Data
 */
struct sk_buff *quic_stream_create_frame(struct quic_stream *stream,
					 size_t max_size,
					 u64 *offset_out,
					 size_t *len_out,
					 bool *fin_out)
{
	struct sk_buff *skb, *data_skb;
	unsigned long flags;
	size_t hdr_size, data_size, frame_size;
	u64 offset;
	u8 *p;
	u8 frame_type;
	bool fin = false;
	bool has_offset, has_length;

	if (!quic_stream_can_send(stream))
		return NULL;

	spin_lock_irqsave(&stream->send_lock, flags);

	/* Check if we have data or need to send FIN */
	data_skb = skb_peek(&stream->send_queue);
	if (!data_skb && !stream->send_fin) {
		stream->has_data = false;
		spin_unlock_irqrestore(&stream->send_lock, flags);
		return NULL;
	}

	/* Get offset from first queued skb or current send position */
	if (data_skb)
		offset = *(u64 *)data_skb->cb;
	else
		offset = stream->send_offset;

	/* Determine frame flags */
	has_offset = (offset > 0);
	has_length = true; /* Always include length for simplicity */

	/* Calculate header size */
	hdr_size = quic_stream_frame_header_size(stream->id, offset, has_length);

	if (hdr_size >= max_size) {
		spin_unlock_irqrestore(&stream->send_lock, flags);
		return NULL;
	}

	/* Calculate maximum data size */
	data_size = max_size - hdr_size;
	if (data_skb)
		data_size = min_t(size_t, data_size, data_skb->len);

	/* Check if this completes the stream */
	if (stream->send_fin && (!data_skb || data_skb->len <= data_size)) {
		fin = true;
	}

	/* Check flow control */
	spin_lock(&stream->fc_lock);
	if (stream->bytes_sent + data_size > stream->send_max_data) {
		data_size = stream->send_max_data - stream->bytes_sent;
		if (data_size == 0) {
			stream->fc_blocked = true;
			stream->fc_blocked_at = stream->send_max_data;
			spin_unlock(&stream->fc_lock);
			spin_unlock_irqrestore(&stream->send_lock, flags);
			return NULL;
		}
		fin = false; /* Can't send FIN if flow controlled */
	}
	spin_unlock(&stream->fc_lock);

	frame_size = hdr_size + data_size;

	/* Allocate frame buffer */
	skb = alloc_skb(frame_size, GFP_ATOMIC);
	if (!skb) {
		spin_unlock_irqrestore(&stream->send_lock, flags);
		return NULL;
	}

	p = skb_put(skb, frame_size);

	/* Build frame type byte */
	frame_type = 0x08; /* STREAM frame base */
	if (has_offset)
		frame_type |= QUIC_STREAM_FRAME_OFF;
	if (has_length)
		frame_type |= QUIC_STREAM_FRAME_LEN;
	if (fin)
		frame_type |= QUIC_STREAM_FRAME_FIN;

	*p++ = frame_type;

	/* Encode Stream ID */
	p += quic_stream_encode_varint(p, stream->id);

	/* Encode Offset (if present) */
	if (has_offset)
		p += quic_stream_encode_varint(p, offset);

	/* Encode Length */
	if (has_length)
		p += quic_stream_encode_varint(p, data_size);

	/* Copy data */
	if (data_skb && data_size > 0) {
		skb_copy_bits(data_skb, 0, p, data_size);

		/* Update or consume data skb */
		if (data_size < data_skb->len) {
			skb_pull(data_skb, data_size);
			*(u64 *)data_skb->cb += data_size;
		} else {
			__skb_unlink(data_skb, &stream->send_queue);
			kfree_skb(data_skb);
		}
	}

	/* Update stream state */
	if (fin) {
		stream->fin_sent = true;
	}
	stream->frames_sent++;
	stream->last_activity = ktime_get();

	/* Check if more data to send */
	if (skb_queue_empty(&stream->send_queue) && !stream->send_fin) {
		stream->has_data = false;
	}

	spin_unlock_irqrestore(&stream->send_lock, flags);

	/* Set output parameters */
	if (offset_out)
		*offset_out = offset;
	if (len_out)
		*len_out = data_size;
	if (fin_out)
		*fin_out = fin;

	return skb;
}
EXPORT_SYMBOL_GPL(quic_stream_create_frame);

/**
 * quic_stream_create_reset_frame - Create RESET_STREAM frame
 * @stream: Stream to reset
 * @max_size: Maximum frame size
 *
 * Creates a RESET_STREAM frame (RFC 9000 Section 19.4):
 *   - Type (1 byte): 0x04
 *   - Stream ID (variable)
 *   - Application Protocol Error Code (variable)
 *   - Final Size (variable)
 */
struct sk_buff *quic_stream_create_reset_frame(struct quic_stream *stream,
					       size_t max_size)
{
	struct sk_buff *skb;
	unsigned long flags;
	u8 *p;
	size_t frame_size;

	spin_lock_irqsave(&stream->send_lock, flags);

	/* Estimate frame size (1 + 8 + 8 + 8 max) */
	frame_size = 25;
	if (frame_size > max_size) {
		spin_unlock_irqrestore(&stream->send_lock, flags);
		return NULL;
	}

	skb = alloc_skb(frame_size, GFP_ATOMIC);
	if (!skb) {
		spin_unlock_irqrestore(&stream->send_lock, flags);
		return NULL;
	}

	p = skb_put(skb, 0); /* We'll adjust length after encoding */

	/* Frame type */
	*skb_put(skb, 1) = 0x04;

	/* Stream ID */
	p = skb_put(skb, 8);
	p += quic_stream_encode_varint(p - 8, stream->id);
	skb_trim(skb, p - skb->data);

	/* Error Code */
	p = skb_put(skb, 8);
	p += quic_stream_encode_varint(p - 8, stream->reset_error_code);
	skb_trim(skb, p - skb->data);

	/* Final Size */
	p = skb_put(skb, 8);
	p += quic_stream_encode_varint(p - 8, stream->send_offset);
	skb_trim(skb, p - skb->data);

	spin_unlock_irqrestore(&stream->send_lock, flags);

	return skb;
}
EXPORT_SYMBOL_GPL(quic_stream_create_reset_frame);

/**
 * quic_stream_create_stop_sending_frame - Create STOP_SENDING frame
 * @stream: Stream requesting stop
 * @max_size: Maximum frame size
 *
 * Creates a STOP_SENDING frame (RFC 9000 Section 19.5):
 *   - Type (1 byte): 0x05
 *   - Stream ID (variable)
 *   - Application Protocol Error Code (variable)
 */
struct sk_buff *quic_stream_create_stop_sending_frame(struct quic_stream *stream,
						      size_t max_size)
{
	struct sk_buff *skb;
	unsigned long flags;
	u8 *p;
	size_t frame_size;

	spin_lock_irqsave(&stream->recv_lock, flags);

	if (!stream->stop_sending) {
		spin_unlock_irqrestore(&stream->recv_lock, flags);
		return NULL;
	}

	/* Estimate frame size (1 + 8 + 8 max) */
	frame_size = 17;
	if (frame_size > max_size) {
		spin_unlock_irqrestore(&stream->recv_lock, flags);
		return NULL;
	}

	skb = alloc_skb(frame_size, GFP_ATOMIC);
	if (!skb) {
		spin_unlock_irqrestore(&stream->recv_lock, flags);
		return NULL;
	}

	p = skb_put(skb, 0);

	/* Frame type */
	*skb_put(skb, 1) = 0x05;

	/* Stream ID */
	p = skb_put(skb, 8);
	p += quic_stream_encode_varint(p - 8, stream->id);
	skb_trim(skb, p - skb->data);

	/* Error Code */
	p = skb_put(skb, 8);
	p += quic_stream_encode_varint(p - 8, stream->stop_sending_code);
	skb_trim(skb, p - skb->data);

	spin_unlock_irqrestore(&stream->recv_lock, flags);

	return skb;
}
EXPORT_SYMBOL_GPL(quic_stream_create_stop_sending_frame);

/**
 * quic_stream_create_max_stream_data_frame - Create MAX_STREAM_DATA frame
 * @stream: Stream to update flow control
 * @max_size: Maximum frame size
 *
 * Creates a MAX_STREAM_DATA frame (RFC 9000 Section 19.10):
 *   - Type (1 byte): 0x11
 *   - Stream ID (variable)
 *   - Maximum Stream Data (variable)
 */
struct sk_buff *quic_stream_create_max_stream_data_frame(struct quic_stream *stream,
							 size_t max_size)
{
	struct sk_buff *skb;
	unsigned long flags;
	u8 *p;
	size_t frame_size;

	/* Estimate frame size (1 + 8 + 8 max) */
	frame_size = 17;
	if (frame_size > max_size)
		return NULL;

	skb = alloc_skb(frame_size, GFP_ATOMIC);
	if (!skb)
		return NULL;

	spin_lock_irqsave(&stream->recv_lock, flags);

	p = skb_put(skb, 0);

	/* Frame type */
	*skb_put(skb, 1) = 0x11;

	/* Stream ID */
	p = skb_put(skb, 8);
	p += quic_stream_encode_varint(p - 8, stream->id);
	skb_trim(skb, p - skb->data);

	/* Maximum Stream Data */
	p = skb_put(skb, 8);
	p += quic_stream_encode_varint(p - 8, stream->recv_max_data);
	skb_trim(skb, p - skb->data);

	spin_unlock_irqrestore(&stream->recv_lock, flags);

	return skb;
}
EXPORT_SYMBOL_GPL(quic_stream_create_max_stream_data_frame);

/**
 * quic_stream_create_blocked_frame - Create STREAM_DATA_BLOCKED frame
 * @stream: Stream that is blocked
 * @max_size: Maximum frame size
 *
 * Creates a STREAM_DATA_BLOCKED frame (RFC 9000 Section 19.13):
 *   - Type (1 byte): 0x15
 *   - Stream ID (variable)
 *   - Maximum Stream Data (variable)
 */
struct sk_buff *quic_stream_create_blocked_frame(struct quic_stream *stream,
						 size_t max_size)
{
	struct sk_buff *skb;
	unsigned long flags;
	u8 *p;
	size_t frame_size;

	/* Estimate frame size (1 + 8 + 8 max) */
	frame_size = 17;
	if (frame_size > max_size)
		return NULL;

	skb = alloc_skb(frame_size, GFP_ATOMIC);
	if (!skb)
		return NULL;

	spin_lock_irqsave(&stream->fc_lock, flags);

	if (!stream->fc_blocked) {
		spin_unlock_irqrestore(&stream->fc_lock, flags);
		kfree_skb(skb);
		return NULL;
	}

	p = skb_put(skb, 0);

	/* Frame type */
	*skb_put(skb, 1) = 0x15;

	/* Stream ID */
	p = skb_put(skb, 8);
	p += quic_stream_encode_varint(p - 8, stream->id);
	skb_trim(skb, p - skb->data);

	/* Maximum Stream Data (our limit) */
	p = skb_put(skb, 8);
	p += quic_stream_encode_varint(p - 8, stream->fc_blocked_at);
	skb_trim(skb, p - skb->data);

	spin_unlock_irqrestore(&stream->fc_lock, flags);

	return skb;
}
EXPORT_SYMBOL_GPL(quic_stream_create_blocked_frame);

/*
 * ============================================================================
 * Stream Manager Operations
 * ============================================================================
 */

/**
 * quic_stream_manager_init - Initialize stream manager
 * @mgr: Manager to initialize
 * @is_server: True if this is a server endpoint
 * @conn: Connection this manager belongs to
 *
 * Returns 0 on success, negative error on failure.
 */
int quic_stream_manager_init(struct quic_stream_manager *mgr, bool is_server,
			     void *conn)
{
	memset(mgr, 0, sizeof(*mgr));

	spin_lock_init(&mgr->lock);
	spin_lock_init(&mgr->sched_lock);
	mgr->streams = RB_ROOT;
	INIT_LIST_HEAD(&mgr->sched_list);

	mgr->is_server = is_server ? 1 : 0;
	mgr->conn = conn;

	/* Initialize stream ID counters based on role */
	if (is_server) {
		mgr->next_bidi_local = QUIC_STREAM_TYPE_SERVER_BIDI;
		mgr->next_uni_local = QUIC_STREAM_TYPE_SERVER_UNI;
	} else {
		mgr->next_bidi_local = QUIC_STREAM_TYPE_CLIENT_BIDI;
		mgr->next_uni_local = QUIC_STREAM_TYPE_CLIENT_UNI;
	}

	/* Set default limits */
	mgr->max_streams_bidi = QUIC_STREAM_DEFAULT_MAX_STREAMS;
	mgr->max_streams_uni = QUIC_STREAM_DEFAULT_MAX_STREAMS;
	mgr->initial_max_stream_data_bidi_local = QUIC_STREAM_DEFAULT_MAX_DATA;
	mgr->initial_max_stream_data_bidi_remote = QUIC_STREAM_DEFAULT_MAX_DATA;
	mgr->initial_max_stream_data_uni = QUIC_STREAM_DEFAULT_MAX_DATA;

	return 0;
}
EXPORT_SYMBOL_GPL(quic_stream_manager_init);

/**
 * quic_stream_manager_destroy - Destroy stream manager and all streams
 * @mgr: Manager to destroy
 */
void quic_stream_manager_destroy(struct quic_stream_manager *mgr)
{
	struct quic_stream *stream, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&mgr->lock, flags);

	/* Free all streams */
	rbtree_postorder_for_each_entry_safe(stream, tmp, &mgr->streams, node) {
		RB_CLEAR_NODE(&stream->node);
		quic_stream_put(stream);
	}

	mgr->streams = RB_ROOT;
	mgr->num_streams = 0;

	/* Clear scheduler list */
	spin_lock(&mgr->sched_lock);
	while (!list_empty(&mgr->sched_list)) {
		stream = list_first_entry(&mgr->sched_list, struct quic_stream, sched_node);
		list_del_init(&stream->sched_node);
		quic_stream_put(stream);
	}
	mgr->sched_count = 0;
	spin_unlock(&mgr->sched_lock);

	spin_unlock_irqrestore(&mgr->lock, flags);

	if (mgr->stream_cache)
		kmem_cache_destroy(mgr->stream_cache);
	if (mgr->fragment_cache)
		kmem_cache_destroy(mgr->fragment_cache);
}
EXPORT_SYMBOL_GPL(quic_stream_manager_destroy);

/**
 * quic_stream_manager_set_limits - Set stream limits from transport params
 * @mgr: Stream manager
 * @max_bidi: Maximum bidirectional streams
 * @max_uni: Maximum unidirectional streams
 * @max_data_bidi_local: Max data for local-initiated bidi streams
 * @max_data_bidi_remote: Max data for remote-initiated bidi streams
 * @max_data_uni: Max data for unidirectional streams
 */
void quic_stream_manager_set_limits(struct quic_stream_manager *mgr,
				    u64 max_bidi, u64 max_uni,
				    u64 max_data_bidi_local,
				    u64 max_data_bidi_remote,
				    u64 max_data_uni)
{
	unsigned long flags;

	spin_lock_irqsave(&mgr->lock, flags);
	mgr->max_streams_bidi = max_bidi;
	mgr->max_streams_uni = max_uni;
	mgr->initial_max_stream_data_bidi_local = max_data_bidi_local;
	mgr->initial_max_stream_data_bidi_remote = max_data_bidi_remote;
	mgr->initial_max_stream_data_uni = max_data_uni;
	spin_unlock_irqrestore(&mgr->lock, flags);
}
EXPORT_SYMBOL_GPL(quic_stream_manager_set_limits);

/**
 * quic_stream_manager_for_each - Iterate over all streams
 * @mgr: Stream manager
 * @fn: Callback function
 * @data: User data passed to callback
 *
 * Calls fn(stream, data) for each stream. Callback should not
 * sleep or modify the stream tree.
 */
void quic_stream_manager_for_each(struct quic_stream_manager *mgr,
				  void (*fn)(struct quic_stream *, void *),
				  void *data)
{
	struct rb_node *node;
	unsigned long flags;

	spin_lock_irqsave(&mgr->lock, flags);

	for (node = rb_first(&mgr->streams); node; node = rb_next(node)) {
		struct quic_stream *stream = rb_entry(node, struct quic_stream, node);

		fn(stream, data);
	}

	spin_unlock_irqrestore(&mgr->lock, flags);
}
EXPORT_SYMBOL_GPL(quic_stream_manager_for_each);

/*
 * ============================================================================
 * Multipath Support (TQUIC)
 * ============================================================================
 */

/**
 * quic_stream_set_path_affinity - Set preferred path for stream
 * @stream: Stream to configure
 * @path_id: Preferred path ID (0 = no affinity)
 *
 * Sets the preferred path for this stream. Used by TQUIC for
 * multipath scheduling.
 */
void quic_stream_set_path_affinity(struct quic_stream *stream, u32 path_id)
{
	stream->path_affinity = path_id;
}
EXPORT_SYMBOL_GPL(quic_stream_set_path_affinity);

/**
 * quic_stream_get_path_affinity - Get preferred path for stream
 * @stream: Stream to query
 *
 * Returns the preferred path ID, or 0 if no affinity.
 */
u32 quic_stream_get_path_affinity(struct quic_stream *stream)
{
	return stream->path_affinity;
}
EXPORT_SYMBOL_GPL(quic_stream_get_path_affinity);

/**
 * quic_stream_path_attach - Mark path as using stream
 * @stream: Stream being used
 *
 * Increments the active path count for TQUIC multipath tracking.
 */
void quic_stream_path_attach(struct quic_stream *stream)
{
	atomic_inc(&stream->active_paths);
}
EXPORT_SYMBOL_GPL(quic_stream_path_attach);

/**
 * quic_stream_path_detach - Mark path as no longer using stream
 * @stream: Stream being released
 *
 * Decrements the active path count.
 */
void quic_stream_path_detach(struct quic_stream *stream)
{
	atomic_dec(&stream->active_paths);
}
EXPORT_SYMBOL_GPL(quic_stream_path_detach);

/**
 * quic_stream_get_active_paths - Get number of active paths
 * @stream: Stream to query
 *
 * Returns the number of paths currently using this stream.
 */
int quic_stream_get_active_paths(struct quic_stream *stream)
{
	return atomic_read(&stream->active_paths);
}
EXPORT_SYMBOL_GPL(quic_stream_get_active_paths);

/*
 * ============================================================================
 * Statistics and Debugging
 * ============================================================================
 */

/**
 * quic_stream_get_stats - Get stream statistics
 * @stream: Stream to query
 * @bytes_sent: Output - total bytes sent
 * @bytes_recvd: Output - total bytes received
 * @frames_sent: Output - total frames sent
 * @frames_recvd: Output - total frames received
 */
void quic_stream_get_stats(struct quic_stream *stream,
			   u64 *bytes_sent, u64 *bytes_recvd,
			   u64 *frames_sent, u64 *frames_recvd)
{
	unsigned long flags;

	spin_lock_irqsave(&stream->send_lock, flags);
	if (bytes_sent)
		*bytes_sent = stream->bytes_sent;
	if (frames_sent)
		*frames_sent = stream->frames_sent;
	spin_unlock_irqrestore(&stream->send_lock, flags);

	spin_lock_irqsave(&stream->recv_lock, flags);
	if (bytes_recvd)
		*bytes_recvd = stream->bytes_recvd;
	if (frames_recvd)
		*frames_recvd = stream->frames_recvd;
	spin_unlock_irqrestore(&stream->recv_lock, flags);
}
EXPORT_SYMBOL_GPL(quic_stream_get_stats);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux QUIC Team");
MODULE_DESCRIPTION("QUIC Stream Management");
