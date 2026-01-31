/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QUIC		An implementation of the QUIC transport protocol for Linux
 *
 *		Definitions for the QUIC protocol module.
 *
 * Authors:	Linux QUIC Team
 */
#ifndef _NET_QUIC_H
#define _NET_QUIC_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <crypto/aead.h>

/* Forward declarations */
struct quic_connection;
struct quic_stream;
struct quic_packet;
struct quic_frame;
struct quic_crypto_ctx;
struct quic_sock;
struct quic_path;
struct net_device;

/*
 * QUIC protocol constants (RFC 9000)
 */
#define QUIC_VERSION_1			0x00000001
#define QUIC_VERSION_2			0x6b3343cf

#define QUIC_MAX_CONNECTION_ID_LEN	20
#define QUIC_MIN_CONNECTION_ID_LEN	0
#define QUIC_STATELESS_RESET_TOKEN_LEN	16
#define QUIC_RETRY_INTEGRITY_TAG_LEN	16
#define QUIC_MAX_UDP_PAYLOAD		65527

/* Initial window and limits */
#define QUIC_INITIAL_CWND		14720
#define QUIC_MIN_CWND			2400
#define QUIC_LOSS_REDUCTION_FACTOR	2

/* Packet number space indices */
#define QUIC_PN_SPACE_INITIAL		0
#define QUIC_PN_SPACE_HANDSHAKE		1
#define QUIC_PN_SPACE_APPLICATION	2
#define QUIC_PN_SPACE_COUNT		3

/* RTT constants (in microseconds) */
#define QUIC_INITIAL_RTT_US		333000	/* 333ms */
#define QUIC_MAX_ACK_DELAY_US		25000	/* 25ms */
#define QUIC_TIME_THRESHOLD_NUM		9
#define QUIC_TIME_THRESHOLD_DEN		8
#define QUIC_PACKET_THRESHOLD		3

/* Timer types */
#define QUIC_TIMER_LOSS_DETECTION	0
#define QUIC_TIMER_ACK			1
#define QUIC_TIMER_IDLE			2
#define QUIC_TIMER_KEEPALIVE		3
#define QUIC_TIMER_PATH_CHALLENGE	4
#define QUIC_TIMER_COUNT		5

/* QUIC frame types (RFC 9000) */
#define QUIC_FRAME_PADDING		0x00
#define QUIC_FRAME_PING			0x01
#define QUIC_FRAME_ACK			0x02
#define QUIC_FRAME_ACK_ECN		0x03
#define QUIC_FRAME_RESET_STREAM		0x04
#define QUIC_FRAME_STOP_SENDING		0x05
#define QUIC_FRAME_CRYPTO		0x06
#define QUIC_FRAME_NEW_TOKEN		0x07
#define QUIC_FRAME_STREAM		0x08
#define QUIC_FRAME_MAX_DATA		0x10
#define QUIC_FRAME_MAX_STREAM_DATA	0x11
#define QUIC_FRAME_MAX_STREAMS_BIDI	0x12
#define QUIC_FRAME_MAX_STREAMS_UNI	0x13
#define QUIC_FRAME_DATA_BLOCKED		0x14
#define QUIC_FRAME_STREAM_DATA_BLOCKED	0x15
#define QUIC_FRAME_STREAMS_BLOCKED_BIDI	0x16
#define QUIC_FRAME_STREAMS_BLOCKED_UNI	0x17
#define QUIC_FRAME_NEW_CONNECTION_ID	0x18
#define QUIC_FRAME_RETIRE_CONNECTION_ID	0x19
#define QUIC_FRAME_PATH_CHALLENGE	0x1a
#define QUIC_FRAME_PATH_RESPONSE	0x1b
#define QUIC_FRAME_CONNECTION_CLOSE	0x1c
#define QUIC_FRAME_CONNECTION_CLOSE_APP	0x1d
#define QUIC_FRAME_HANDSHAKE_DONE	0x1e
#define QUIC_FRAME_DATAGRAM		0x30
#define QUIC_FRAME_DATAGRAM_LEN		0x31

/* QUIC connection states */
enum quic_state {
	QUIC_STATE_IDLE = 0,
	QUIC_STATE_CONNECTING,
	QUIC_STATE_HANDSHAKE,
	QUIC_STATE_CONNECTED,
	QUIC_STATE_CLOSING,
	QUIC_STATE_DRAINING,
	QUIC_STATE_CLOSED,
};

/* QUIC stream states (RFC 9000 Section 3) */
enum quic_stream_state {
	/* Sending states */
	QUIC_STREAM_SEND_READY = 0,
	QUIC_STREAM_SEND_SEND,
	QUIC_STREAM_SEND_DATA_SENT,
	QUIC_STREAM_SEND_DATA_RECVD,
	QUIC_STREAM_SEND_RESET_SENT,
	QUIC_STREAM_SEND_RESET_RECVD,

	/* Receiving states */
	QUIC_STREAM_RECV_RECV = 0x10,
	QUIC_STREAM_RECV_SIZE_KNOWN,
	QUIC_STREAM_RECV_DATA_RECVD,
	QUIC_STREAM_RECV_DATA_READ,
	QUIC_STREAM_RECV_RESET_RECVD,
	QUIC_STREAM_RECV_RESET_READ,
};

/* TLS cipher suites for QUIC */
enum quic_cipher_suite {
	QUIC_CIPHER_AES_128_GCM_SHA256 = 0x1301,
	QUIC_CIPHER_AES_256_GCM_SHA384 = 0x1302,
	QUIC_CIPHER_CHACHA20_POLY1305_SHA256 = 0x1303,
};

/* QUIC encryption level */
enum quic_encryption_level {
	QUIC_ENC_LEVEL_INITIAL = 0,
	QUIC_ENC_LEVEL_EARLY_DATA,
	QUIC_ENC_LEVEL_HANDSHAKE,
	QUIC_ENC_LEVEL_APPLICATION,
	QUIC_ENC_LEVEL_COUNT,
};

/*
 * QUIC Connection ID structure
 *
 * Supports multiple connection IDs for migration and NAT rebinding
 */
struct quic_connection_id {
	struct list_head	list;		/* Link in connection ID list */
	u8			data[QUIC_MAX_CONNECTION_ID_LEN];
	u8			len;
	u64			seq_num;	/* Sequence number for retire */
	u8			stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
	bool			has_reset_token;
	refcount_t		refcnt;
	struct rcu_head		rcu;
};

/*
 * QUIC Connection ID set - manages multiple CIDs
 */
struct quic_cid_set {
	struct list_head	cids;		/* List of quic_connection_id */
	struct quic_connection_id *active;	/* Currently active CID */
	spinlock_t		lock;
	u64			retire_prior_to;
	u64			next_seq_num;
	u32			active_count;
	u32			max_count;
};

/*
 * QUIC crypto key material
 */
struct quic_keys {
	u8			*key;		/* AEAD key */
	u8			*iv;		/* Initialization vector */
	u8			*hp_key;	/* Header protection key */
	u32			key_len;
	u32			iv_len;
	u32			hp_key_len;
	struct crypto_aead	*aead;		/* AEAD cipher handle */
	struct crypto_cipher	*hp_cipher;	/* HP cipher handle */
};

/*
 * QUIC crypto context - manages encryption state per connection
 */
struct quic_crypto_ctx {
	enum quic_cipher_suite	cipher_suite;
	struct quic_keys	tx_keys[QUIC_ENC_LEVEL_COUNT];
	struct quic_keys	rx_keys[QUIC_ENC_LEVEL_COUNT];
	enum quic_encryption_level current_tx_level;
	enum quic_encryption_level current_rx_level;

	/* TLS handshake state */
	void			*tls_ctx;	/* TLS library context */
	u8			*tls_early_data;
	u32			tls_early_data_len;
	bool			handshake_complete;
	bool			zero_rtt_accepted;

	/* Key update state */
	u64			key_phase;
	bool			key_update_pending;
	ktime_t			key_update_time;

	spinlock_t		lock;
};

/*
 * QUIC ACK range for acknowledgment tracking
 */
struct quic_ack_range {
	u64			start;
	u64			end;
};

/*
 * QUIC sent packet info for loss detection
 */
struct quic_sent_packet {
	struct list_head	list;
	u64			pkt_num;
	ktime_t			sent_time;
	u32			sent_bytes;	/* Bytes in this packet (ack-eliciting) */
	u8			pn_space;
	bool			ack_eliciting;
	bool			in_flight;
	bool			has_crypto_data;
	struct sk_buff		*skb;		/* Original packet for retransmission */
};

/*
 * QUIC packet number space state
 *
 * Maintains per-space packet number and acknowledgment state
 */
struct quic_pn_space {
	u64			next_pkt_num;		/* Next packet number to send */
	u64			largest_sent_pkt;	/* Largest sent packet number */
	u64			largest_acked_pkt;	/* Largest acknowledged packet */
	ktime_t			largest_acked_time;

	/* Received packet tracking for ACK generation */
	u64			largest_recv_pkt;
	ktime_t			largest_recv_time;
	struct quic_ack_range	ack_ranges[64];		/* ACK ranges to send */
	u32			ack_range_count;
	bool			ack_pending;
	ktime_t			ack_delay_until;

	/* ECN counters */
	u64			ecn_ect0_count;
	u64			ecn_ect1_count;
	u64			ecn_ce_count;

	/* Sent packets pending acknowledgment */
	struct list_head	sent_packets;
	u32			sent_packet_count;
	u64			bytes_in_flight;

	/* Loss detection */
	ktime_t			loss_time;
	u64			loss_pkt_num;

	spinlock_t		lock;
};

/*
 * QUIC RTT measurement state
 */
struct quic_rtt_stats {
	ktime_t			latest_rtt;	/* Most recent RTT measurement */
	ktime_t			smoothed_rtt;	/* EWMA of RTT */
	ktime_t			rttvar;		/* RTT variance */
	ktime_t			min_rtt;	/* Minimum RTT observed */
	ktime_t			max_ack_delay;	/* Maximum ACK delay peer will use */
	ktime_t			first_rtt_sample;
	bool			has_sample;
};

/*
 * QUIC congestion control state
 */
struct quic_congestion {
	u64			cwnd;			/* Congestion window (bytes) */
	u64			ssthresh;		/* Slow start threshold */
	u64			bytes_in_flight;	/* Unacknowledged bytes */
	u64			bytes_acked;		/* Total bytes acked */
	u64			bytes_sent;		/* Total bytes sent */

	/* Recovery state */
	u64			recovery_start_pkt;	/* Packet starting recovery */
	ktime_t			recovery_start_time;
	bool			in_recovery;
	bool			in_slow_start;

	/* ECN feedback */
	u64			ecn_ce_counter;
	bool			ecn_enabled;

	/* Pacing */
	u64			pacing_rate;		/* Bytes per second */
	ktime_t			next_send_time;

	/* Congestion control algorithm state */
	void			*cc_data;		/* Algorithm-specific data */
	const struct quic_cc_ops *cc_ops;

	/* Persistent congestion detection */
	ktime_t			first_sent_time;
	ktime_t			last_sent_time;
	u32			persistent_congestion_threshold;

	spinlock_t		lock;
};

/*
 * QUIC congestion control operations
 */
struct quic_cc_ops {
	const char		*name;
	void			(*init)(struct quic_congestion *cc);
	void			(*on_packet_sent)(struct quic_congestion *cc, u32 bytes);
	void			(*on_packet_acked)(struct quic_congestion *cc,
						   struct quic_sent_packet *pkt,
						   ktime_t rtt);
	void			(*on_packet_lost)(struct quic_congestion *cc,
						  struct quic_sent_packet *pkt);
	void			(*on_ecn_ce)(struct quic_congestion *cc);
	void			(*on_persistent_congestion)(struct quic_congestion *cc);
	void			(*release)(struct quic_congestion *cc);

	struct module		*owner;
	struct list_head	list;
};

/*
 * QUIC loss detection state
 */
struct quic_loss_detection {
	u32			pto_count;		/* PTO retry count */
	ktime_t			loss_time[QUIC_PN_SPACE_COUNT];
	ktime_t			time_of_last_ack;
	u64			largest_acked[QUIC_PN_SPACE_COUNT];
	bool			peer_completed_addr_validation;

	/* Anti-amplification state (server before handshake complete) */
	u64			bytes_sent;
	u64			bytes_received;
	bool			anti_amplification_limited;
};

/*
 * QUIC flow control state - connection level
 */
struct quic_flow_control {
	u64			max_data;		/* Max data we can receive */
	u64			max_data_next;		/* Next MAX_DATA to send */
	u64			data_sent;		/* Total data sent */
	u64			data_received;		/* Total data received */
	u64			peer_max_data;		/* Max data peer can receive */

	/* Stream limits */
	u64			max_streams_bidi;
	u64			max_streams_uni;
	u64			peer_max_streams_bidi;
	u64			peer_max_streams_uni;
	u64			streams_bidi_opened;
	u64			streams_uni_opened;
	u64			peer_streams_bidi_opened;
	u64			peer_streams_uni_opened;

	/* Blocked state */
	bool			data_blocked;
	bool			streams_blocked_bidi;
	bool			streams_blocked_uni;

	spinlock_t		lock;
};

/*
 * QUIC timer management
 */
struct quic_timers {
	struct timer_list	timer[QUIC_TIMER_COUNT];
	ktime_t			expiry[QUIC_TIMER_COUNT];
	unsigned long		enabled;		/* Bitmask of enabled timers */
	spinlock_t		lock;
};

/*
 * QUIC transport parameters (RFC 9000 Section 18)
 */
struct quic_transport_params {
	u8			original_dest_cid[QUIC_MAX_CONNECTION_ID_LEN];
	u8			original_dest_cid_len;
	u8			initial_source_cid[QUIC_MAX_CONNECTION_ID_LEN];
	u8			initial_source_cid_len;
	u8			retry_source_cid[QUIC_MAX_CONNECTION_ID_LEN];
	u8			retry_source_cid_len;
	u8			stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
	bool			has_stateless_reset_token;

	u64			max_idle_timeout;	/* ms */
	u64			max_udp_payload_size;
	u64			initial_max_data;
	u64			initial_max_stream_data_bidi_local;
	u64			initial_max_stream_data_bidi_remote;
	u64			initial_max_stream_data_uni;
	u64			initial_max_streams_bidi;
	u64			initial_max_streams_uni;
	u64			ack_delay_exponent;
	u64			max_ack_delay;		/* ms */
	u64			active_connection_id_limit;
	bool			disable_active_migration;
	u8			preferred_address[64];
	u8			preferred_address_len;
	bool			grease_quic_bit;
};

/*
 * QUIC stream structure
 *
 * Represents a single bidirectional or unidirectional stream
 */
struct quic_stream {
	struct rb_node		node;		/* Link in connection's stream tree */
	struct list_head	list;		/* Link in ready-to-send list */
	u64			stream_id;

	/* State machine */
	enum quic_stream_state	send_state;
	enum quic_stream_state	recv_state;

	/* Send buffer */
	struct sk_buff_head	send_queue;
	u64			send_offset;	/* Next byte offset to send */
	u64			send_max_data;	/* Flow control limit */
	u64			send_fin_offset;/* FIN offset if set */
	bool			send_fin;	/* FIN queued */
	bool			send_fin_sent;	/* FIN has been sent */
	bool			send_fin_acked;	/* FIN has been acknowledged */
	bool			send_blocked;	/* Blocked on flow control */

	/* Receive buffer */
	struct sk_buff_head	recv_queue;
	struct rb_root		recv_ooo;	/* Out-of-order received data */
	u64			recv_offset;	/* Next expected byte offset */
	u64			recv_max_data;	/* Flow control limit we advertise */
	u64			recv_max_data_next;
	u64			recv_fin_offset;/* FIN offset if received */
	bool			recv_fin;	/* FIN received */
	bool			recv_fin_read;	/* FIN delivered to application */

	/* RESET_STREAM state */
	u64			reset_error_code;
	u64			reset_final_size;
	bool			reset_sent;
	bool			reset_received;

	/* STOP_SENDING state */
	u64			stop_error_code;
	bool			stop_sent;
	bool			stop_received;

	/* Priority and scheduling */
	u8			priority;	/* 0-255, 0 = highest */
	bool			incremental;	/* Incremental delivery flag */
	bool			on_send_list;	/* Currently on send list */

	/* Connection backpointer */
	struct quic_connection	*conn;

	/* Statistics */
	u64			bytes_sent;
	u64			bytes_received;
	u64			bytes_retransmitted;

	refcount_t		refcnt;
	spinlock_t		lock;
	struct rcu_head		rcu;
};

/*
 * QUIC connection structure
 *
 * Main structure representing a QUIC connection
 */
struct quic_connection {
	/* Socket and network layer linkage */
	struct quic_sock	*qsk;		/* Parent QUIC socket */
	struct sock		*sk;		/* Network socket backpointer */
	struct hlist_node	hash_node;	/* Connection lookup hash */

	/* Connection state */
	enum quic_state		state;
	bool			is_server;
	bool			handshake_confirmed;
	bool			migration_disabled;
	u32			version;

	/* Connection IDs */
	struct quic_cid_set	source_cids;	/* Our connection IDs */
	struct quic_cid_set	dest_cids;	/* Peer's connection IDs */
	u8			original_dcid[QUIC_MAX_CONNECTION_ID_LEN];
	u8			original_dcid_len;

	/* Crypto state */
	struct quic_crypto_ctx	crypto;

	/* Stream management */
	struct rb_root		streams;	/* All streams by ID */
	struct list_head	streams_send_ready;  /* Streams with data to send */
	u64			next_stream_id_bidi; /* Next local bidi stream ID */
	u64			next_stream_id_uni;  /* Next local uni stream ID */
	u32			stream_count;
	rwlock_t		streams_lock;

	/* Packet number spaces */
	struct quic_pn_space	pn_space[QUIC_PN_SPACE_COUNT];
	u8			current_pn_space;

	/* Congestion control */
	struct quic_congestion	congestion;

	/* RTT estimation */
	struct quic_rtt_stats	rtt;

	/* Loss detection */
	struct quic_loss_detection loss;

	/* Flow control */
	struct quic_flow_control flow;

	/* Timer management */
	struct quic_timers	timers;
	struct work_struct	timeout_work;

	/* Transport parameters */
	struct quic_transport_params local_params;
	struct quic_transport_params peer_params;

	/* Path information */
	struct sockaddr_storage	local_addr;
	struct sockaddr_storage	peer_addr;
	struct net_device	*net_dev;
	u32			mtu;
	u32			pmtu;

	/* Connection close */
	u64			close_error_code;
	u8			*close_reason;
	u32			close_reason_len;
	bool			close_is_app_error;

	/* Statistics */
	u64			packets_sent;
	u64			packets_received;
	u64			packets_lost;
	u64			bytes_sent;
	u64			bytes_received;

	/* Reference counting and synchronization */
	refcount_t		refcnt;
	spinlock_t		lock;		/* Main connection lock */
	struct rcu_head		rcu;

	/* Debug and tracing */
	u64			conn_id_debug;	/* For logging */
};

/*
 * QUIC packet structure
 *
 * Represents a QUIC packet being built or processed
 */
struct quic_packet {
	struct sk_buff		*skb;

	/* Header info */
	u8			type;		/* Packet type */
	u8			pn_len;		/* Packet number length */
	u8			dcid[QUIC_MAX_CONNECTION_ID_LEN];
	u8			dcid_len;
	u8			scid[QUIC_MAX_CONNECTION_ID_LEN];
	u8			scid_len;
	u32			version;

	/* Packet number */
	u64			pkt_num;
	u8			pn_space;

	/* Payload */
	u8			*payload;
	u32			payload_len;
	u32			payload_capacity;

	/* Token (for Initial and Retry) */
	u8			*token;
	u32			token_len;

	/* Encryption info */
	enum quic_encryption_level enc_level;
	bool			encrypted;

	/* Flags */
	bool			ack_eliciting;
	bool			has_crypto;
	bool			has_stream;
	bool			has_ack;
};

/*
 * QUIC frame structure
 *
 * Represents a decoded QUIC frame
 */
struct quic_frame {
	u8			type;

	union {
		/* ACK frame */
		struct {
			u64	largest_acked;
			u64	ack_delay;
			u64	ack_range_count;
			u64	first_ack_range;
			struct quic_ack_range *ranges;
			/* ECN counts (if ACK_ECN) */
			u64	ecn_ect0;
			u64	ecn_ect1;
			u64	ecn_ce;
		} ack;

		/* RESET_STREAM frame */
		struct {
			u64	stream_id;
			u64	error_code;
			u64	final_size;
		} reset_stream;

		/* STOP_SENDING frame */
		struct {
			u64	stream_id;
			u64	error_code;
		} stop_sending;

		/* CRYPTO frame */
		struct {
			u64	offset;
			u64	length;
			u8	*data;
		} crypto;

		/* NEW_TOKEN frame */
		struct {
			u64	token_len;
			u8	*token;
		} new_token;

		/* STREAM frame */
		struct {
			u64	stream_id;
			u64	offset;
			u64	length;
			u8	*data;
			bool	fin;
		} stream;

		/* MAX_DATA frame */
		struct {
			u64	max_data;
		} max_data;

		/* MAX_STREAM_DATA frame */
		struct {
			u64	stream_id;
			u64	max_stream_data;
		} max_stream_data;

		/* MAX_STREAMS frame */
		struct {
			u64	max_streams;
		} max_streams;

		/* DATA_BLOCKED frame */
		struct {
			u64	limit;
		} data_blocked;

		/* STREAM_DATA_BLOCKED frame */
		struct {
			u64	stream_id;
			u64	limit;
		} stream_data_blocked;

		/* STREAMS_BLOCKED frame */
		struct {
			u64	limit;
		} streams_blocked;

		/* NEW_CONNECTION_ID frame */
		struct {
			u64	seq_num;
			u64	retire_prior_to;
			u8	cid_len;
			u8	cid[QUIC_MAX_CONNECTION_ID_LEN];
			u8	stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
		} new_connection_id;

		/* RETIRE_CONNECTION_ID frame */
		struct {
			u64	seq_num;
		} retire_connection_id;

		/* PATH_CHALLENGE frame */
		struct {
			u8	data[8];
		} path_challenge;

		/* PATH_RESPONSE frame */
		struct {
			u8	data[8];
		} path_response;

		/* CONNECTION_CLOSE frame */
		struct {
			u64	error_code;
			u64	frame_type;	/* For transport errors */
			u64	reason_len;
			u8	*reason;
		} connection_close;

		/* DATAGRAM frame */
		struct {
			u64	length;
			u8	*data;
		} datagram;
	};
};

/*
 * QUIC socket structure
 *
 * Extends inet_connection_sock for QUIC
 */
struct quic_sock {
	/* inet_connection_sock must be first */
	struct inet_connection_sock icsk;

	/* Connection management */
	struct quic_connection	*conn;		/* Active connection */
	struct list_head	accept_queue;	/* Incoming connections (server) */
	u32			accept_queue_len;
	u32			max_accept_queue;

	/* Socket options */
	u32			max_streams_bidi;
	u32			max_streams_uni;
	u32			max_data;
	u32			max_stream_data;
	u32			idle_timeout;
	u32			max_udp_payload;
	bool			disable_migration;
	bool			zero_rtt_enabled;
	bool			grease_quic_bit;

	/* Early data / 0-RTT */
	u8			*session_ticket;
	u32			session_ticket_len;
	u8			*early_data;
	u32			early_data_len;

	/* Datagram support */
	bool			datagram_enabled;
	u32			max_datagram_size;
	struct sk_buff_head	datagram_recv_queue;

	/* Work queue for async operations */
	struct work_struct	work;

	/* Statistics */
	u64			streams_opened;
	u64			streams_closed;
};

#define quic_sk(ptr) container_of_const(ptr, struct quic_sock, icsk.icsk_inet.sk)

/*
 * QUIC protocol operations
 */
extern struct proto quic_prot;
extern struct proto quicv6_prot;

/*
 * Connection management functions
 */
struct quic_connection *quic_connection_alloc(struct sock *sk, gfp_t gfp);
void quic_connection_free(struct quic_connection *conn);
void quic_connection_hold(struct quic_connection *conn);
void quic_connection_put(struct quic_connection *conn);
int quic_connection_init(struct quic_connection *conn, bool is_server);
void quic_connection_close(struct quic_connection *conn, u64 error_code,
			   const char *reason, u32 reason_len, bool app_error);

/*
 * Stream management functions
 */
struct quic_stream *quic_stream_alloc(struct quic_connection *conn,
				      u64 stream_id, gfp_t gfp);
void quic_stream_free(struct quic_stream *stream);
void quic_stream_hold(struct quic_stream *stream);
void quic_stream_put(struct quic_stream *stream);
struct quic_stream *quic_stream_lookup(struct quic_connection *conn, u64 stream_id);
struct quic_stream *quic_stream_open(struct quic_connection *conn, bool bidi);
int quic_stream_send(struct quic_stream *stream, struct msghdr *msg, size_t len);
int quic_stream_recv(struct quic_stream *stream, struct msghdr *msg, size_t len);
int quic_stream_close(struct quic_stream *stream, u64 error_code);
int quic_stream_reset(struct quic_stream *stream, u64 error_code);
void quic_stream_stop_sending(struct quic_stream *stream, u64 error_code);

/*
 * Packet send/receive functions
 */
int quic_send_packet(struct quic_connection *conn, struct quic_packet *pkt);
int quic_receive_packet(struct quic_connection *conn, struct sk_buff *skb);
struct quic_packet *quic_packet_alloc(struct quic_connection *conn,
				      u8 type, gfp_t gfp);
void quic_packet_free(struct quic_packet *pkt);
int quic_packet_build(struct quic_connection *conn, struct quic_packet *pkt);
int quic_packet_encrypt(struct quic_connection *conn, struct quic_packet *pkt);
int quic_packet_decrypt(struct quic_connection *conn, struct quic_packet *pkt);

/*
 * Frame processing functions
 */
int quic_process_frame(struct quic_connection *conn, struct quic_frame *frame);
int quic_parse_frame(const u8 *data, u32 len, struct quic_frame *frame);
int quic_build_frame(struct quic_packet *pkt, struct quic_frame *frame);
int quic_send_ack_frame(struct quic_connection *conn, u8 pn_space);
int quic_send_crypto_frame(struct quic_connection *conn, const u8 *data,
			   u32 len, u64 offset, u8 enc_level);
int quic_send_stream_frame(struct quic_connection *conn, struct quic_stream *stream);
int quic_send_max_data_frame(struct quic_connection *conn);
int quic_send_max_stream_data_frame(struct quic_connection *conn,
				    struct quic_stream *stream);
int quic_send_connection_close(struct quic_connection *conn, u64 error_code,
			       u64 frame_type, const char *reason, u32 reason_len);

/*
 * Crypto functions
 */
int quic_crypto_init(struct quic_crypto_ctx *ctx, enum quic_cipher_suite cipher);
void quic_crypto_release(struct quic_crypto_ctx *ctx);
int quic_crypto_derive_initial_keys(struct quic_crypto_ctx *ctx,
				    const u8 *dcid, u8 dcid_len, bool is_server);
int quic_crypto_set_encryption_secrets(struct quic_crypto_ctx *ctx,
				       enum quic_encryption_level level,
				       const u8 *read_secret,
				       const u8 *write_secret, u32 secret_len);
int quic_crypto_update_keys(struct quic_crypto_ctx *ctx);

/*
 * Congestion control functions
 */
void quic_cc_init(struct quic_congestion *cc);
void quic_cc_release(struct quic_congestion *cc);
void quic_cc_on_packet_sent(struct quic_congestion *cc, u32 bytes);
void quic_cc_on_packet_acked(struct quic_congestion *cc,
			     struct quic_sent_packet *pkt, ktime_t rtt);
void quic_cc_on_packet_lost(struct quic_congestion *cc,
			    struct quic_sent_packet *pkt);
void quic_cc_on_ecn_ce(struct quic_congestion *cc);
bool quic_cc_can_send(struct quic_congestion *cc, u32 bytes);
int quic_cc_register(struct quic_cc_ops *ops);
void quic_cc_unregister(struct quic_cc_ops *ops);

/*
 * RTT estimation functions
 */
void quic_rtt_init(struct quic_rtt_stats *rtt);
void quic_rtt_update(struct quic_rtt_stats *rtt, ktime_t latest,
		     ktime_t ack_delay, bool ack_delay_valid);
ktime_t quic_rtt_get_pto(struct quic_rtt_stats *rtt, u8 pn_space,
			 u32 pto_count, bool has_handshake_keys);

/*
 * Loss detection functions
 */
void quic_loss_init(struct quic_loss_detection *loss);
void quic_loss_on_packet_sent(struct quic_connection *conn,
			      struct quic_sent_packet *pkt);
void quic_loss_on_ack_received(struct quic_connection *conn, u8 pn_space,
			       u64 largest_acked, ktime_t ack_delay);
void quic_loss_detect_lost_packets(struct quic_connection *conn, u8 pn_space);
void quic_loss_set_timer(struct quic_connection *conn);
void quic_loss_on_timeout(struct quic_connection *conn);

/*
 * Flow control functions
 */
void quic_flow_init(struct quic_flow_control *flow,
		    struct quic_transport_params *params);
bool quic_flow_can_send(struct quic_flow_control *flow, u64 bytes);
void quic_flow_on_data_sent(struct quic_flow_control *flow, u64 bytes);
void quic_flow_on_data_received(struct quic_flow_control *flow, u64 bytes);
void quic_flow_on_max_data(struct quic_flow_control *flow, u64 max_data);
bool quic_flow_can_open_stream(struct quic_flow_control *flow, bool bidi);
void quic_flow_on_stream_opened(struct quic_flow_control *flow, bool bidi, bool local);

/*
 * Timer functions
 */
void quic_timer_init(struct quic_connection *conn);
void quic_timer_release(struct quic_connection *conn);
void quic_timer_set(struct quic_connection *conn, u8 timer, ktime_t expiry);
void quic_timer_cancel(struct quic_connection *conn, u8 timer);
void quic_timer_handler(struct timer_list *t);

/*
 * Connection ID functions
 */
int quic_cid_init(struct quic_cid_set *set);
void quic_cid_release(struct quic_cid_set *set);
struct quic_connection_id *quic_cid_new(struct quic_cid_set *set,
					const u8 *cid, u8 len, gfp_t gfp);
void quic_cid_retire(struct quic_cid_set *set, u64 seq_num);
struct quic_connection_id *quic_cid_get_active(struct quic_cid_set *set);
int quic_cid_set_active(struct quic_cid_set *set, u64 seq_num);

/*
 * Protocol registration
 */
int quic_proto_init(void);
void quic_proto_exit(void);
int quic_register_net(struct net *net);
void quic_unregister_net(struct net *net);

/*
 * Socket operations
 */
int quic_connect(struct sock *sk, struct sockaddr *addr, int addr_len);
int quic_disconnect(struct sock *sk, int flags);
int quic_accept(struct sock *sk, struct sock *newsk, int flags, bool kern);
int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		 int flags, int *addr_len);
__poll_t quic_poll(struct file *file, struct socket *sock,
		   struct poll_table_struct *wait);
int quic_setsockopt(struct sock *sk, int level, int optname,
		    sockptr_t optval, unsigned int optlen);
int quic_getsockopt(struct sock *sk, int level, int optname,
		    char __user *optval, int __user *optlen);
void quic_close(struct sock *sk, long timeout);
int quic_ioctl(struct sock *sk, int cmd, int *karg);

/*
 * Transport parameter functions
 */
int quic_encode_transport_params(struct quic_transport_params *params,
				 u8 *buf, u32 buf_len, u32 *out_len);
int quic_decode_transport_params(const u8 *buf, u32 len,
				 struct quic_transport_params *params);
void quic_transport_params_init(struct quic_transport_params *params);

/*
 * Inline helper functions
 */

static inline bool quic_stream_is_bidi(u64 stream_id)
{
	return (stream_id & 0x2) == 0;
}

static inline bool quic_stream_is_local(u64 stream_id, bool is_server)
{
	bool initiated_by_server = (stream_id & 0x1) != 0;
	return initiated_by_server == is_server;
}

static inline u64 quic_stream_next_id(u64 current, bool bidi)
{
	return current + 4;
}

static inline bool quic_pn_space_discarded(struct quic_connection *conn, u8 space)
{
	if (space == QUIC_PN_SPACE_INITIAL)
		return conn->crypto.current_tx_level > QUIC_ENC_LEVEL_INITIAL;
	if (space == QUIC_PN_SPACE_HANDSHAKE)
		return conn->crypto.current_tx_level > QUIC_ENC_LEVEL_HANDSHAKE;
	return false;
}

static inline enum quic_encryption_level quic_pn_space_to_enc_level(u8 space)
{
	switch (space) {
	case QUIC_PN_SPACE_INITIAL:
		return QUIC_ENC_LEVEL_INITIAL;
	case QUIC_PN_SPACE_HANDSHAKE:
		return QUIC_ENC_LEVEL_HANDSHAKE;
	case QUIC_PN_SPACE_APPLICATION:
		return QUIC_ENC_LEVEL_APPLICATION;
	default:
		return QUIC_ENC_LEVEL_APPLICATION;
	}
}

static inline u8 quic_enc_level_to_pn_space(enum quic_encryption_level level)
{
	switch (level) {
	case QUIC_ENC_LEVEL_INITIAL:
		return QUIC_PN_SPACE_INITIAL;
	case QUIC_ENC_LEVEL_EARLY_DATA:
	case QUIC_ENC_LEVEL_APPLICATION:
		return QUIC_PN_SPACE_APPLICATION;
	case QUIC_ENC_LEVEL_HANDSHAKE:
		return QUIC_PN_SPACE_HANDSHAKE;
	default:
		return QUIC_PN_SPACE_APPLICATION;
	}
}

static inline bool quic_is_long_header(u8 first_byte)
{
	return (first_byte & 0x80) != 0;
}

static inline void quic_connection_lock(struct quic_connection *conn)
{
	spin_lock_bh(&conn->lock);
}

static inline void quic_connection_unlock(struct quic_connection *conn)
{
	spin_unlock_bh(&conn->lock);
}

#define quic_for_each_stream(__conn, __stream)				\
	for (__stream = rb_entry_safe(rb_first(&(__conn)->streams),	\
				      struct quic_stream, node);	\
	     __stream;							\
	     __stream = rb_entry_safe(rb_next(&__stream->node),		\
				      struct quic_stream, node))

#define quic_for_each_stream_safe(__conn, __stream, __tmp)		\
	for (__stream = rb_entry_safe(rb_first(&(__conn)->streams),	\
				      struct quic_stream, node),	\
	     __tmp = __stream ?						\
		rb_entry_safe(rb_next(&__stream->node),			\
			      struct quic_stream, node) : NULL;		\
	     __stream;							\
	     __stream = __tmp,						\
	     __tmp = __stream ?						\
		rb_entry_safe(rb_next(&__stream->node),			\
			      struct quic_stream, node) : NULL)

/*
 * Debug and statistics
 */
#ifdef CONFIG_QUIC_DEBUG
void quic_debug_dump_connection(struct quic_connection *conn);
void quic_debug_dump_packet(struct quic_packet *pkt);
#else
static inline void quic_debug_dump_connection(struct quic_connection *conn) {}
static inline void quic_debug_dump_packet(struct quic_packet *pkt) {}
#endif

#endif /* _NET_QUIC_H */
