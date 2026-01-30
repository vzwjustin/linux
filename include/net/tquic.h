/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: WAN Bonding over QUIC
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides the main TQUIC API for kernel consumers
 * and socket interface definitions.
 */

#ifndef _NET_TQUIC_H
#define _NET_TQUIC_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <uapi/linux/tquic.h>

/* Protocol version numbers */
#define TQUIC_VERSION_1		0x00000001
#define TQUIC_VERSION_2		0x6b3343cf  /* QUIC v2 */
#define TQUIC_VERSION_CURRENT	TQUIC_VERSION_1

/* Connection ID constraints */
#define TQUIC_MAX_CID_LEN	20
#define TQUIC_MIN_CID_LEN	0
#define TQUIC_DEFAULT_CID_LEN	8

/* Packet number spaces */
#define TQUIC_PN_SPACE_INITIAL	0
#define TQUIC_PN_SPACE_HANDSHAKE	1
#define TQUIC_PN_SPACE_APPLICATION	2
#define TQUIC_PN_SPACE_COUNT	3

/* Stream limits */
#define TQUIC_MAX_STREAMS_BIDI	(1ULL << 60)
#define TQUIC_MAX_STREAMS_UNI	(1ULL << 60)

/* Flow control defaults */
#define TQUIC_DEFAULT_MAX_DATA		(1 << 20)   /* 1 MB */
#define TQUIC_DEFAULT_MAX_STREAM_DATA	(1 << 18)   /* 256 KB */

/* Timing constants (in ms) */
#define TQUIC_DEFAULT_IDLE_TIMEOUT	30000
#define TQUIC_MIN_RTT			1
#define TQUIC_DEFAULT_RTT		100
#define TQUIC_MAX_ACK_DELAY		25

/* Path limits for WAN bonding */
#define TQUIC_MAX_PATHS		16
#define TQUIC_MIN_PATHS		1
#define TQUIC_DEFAULT_PATHS	4

struct tquic_sock;
struct tquic_connection;
struct tquic_stream;
struct tquic_path;
struct tquic_frame;
struct tquic_packet;

/**
 * enum tquic_conn_state - Connection state machine states
 * @TQUIC_CONN_IDLE: Initial state, no connection
 * @TQUIC_CONN_CONNECTING: Client initiating connection
 * @TQUIC_CONN_CONNECTED: Connection established
 * @TQUIC_CONN_CLOSING: Connection being closed gracefully
 * @TQUIC_CONN_DRAINING: Draining period before close
 * @TQUIC_CONN_CLOSED: Connection fully closed
 */
enum tquic_conn_state {
	TQUIC_CONN_IDLE = 0,
	TQUIC_CONN_CONNECTING,
	TQUIC_CONN_CONNECTED,
	TQUIC_CONN_CLOSING,
	TQUIC_CONN_DRAINING,
	TQUIC_CONN_CLOSED,
};

/**
 * enum tquic_stream_state - Stream state machine
 */
enum tquic_stream_state {
	TQUIC_STREAM_IDLE = 0,
	TQUIC_STREAM_OPEN,
	TQUIC_STREAM_SEND,
	TQUIC_STREAM_RECV,
	TQUIC_STREAM_SIZE_KNOWN,
	TQUIC_STREAM_DATA_SENT,
	TQUIC_STREAM_DATA_RECVD,
	TQUIC_STREAM_RESET_SENT,
	TQUIC_STREAM_RESET_RECVD,
	TQUIC_STREAM_CLOSED,
};

/**
 * enum tquic_path_state - Path state for WAN bonding
 * @TQUIC_PATH_UNUSED: Path slot not in use
 * @TQUIC_PATH_PENDING: Path validation in progress
 * @TQUIC_PATH_ACTIVE: Path validated and usable
 * @TQUIC_PATH_STANDBY: Path usable but not preferred
 * @TQUIC_PATH_FAILED: Path has failed, may recover
 * @TQUIC_PATH_CLOSED: Path permanently closed
 */
enum tquic_path_state {
	TQUIC_PATH_UNUSED = 0,
	TQUIC_PATH_PENDING,
	TQUIC_PATH_ACTIVE,
	TQUIC_PATH_STANDBY,
	TQUIC_PATH_FAILED,
	TQUIC_PATH_CLOSED,
};

/**
 * struct tquic_cid - Connection ID
 * @len: Length of the connection ID (0-20)
 * @id: The connection ID bytes
 * @seq_num: Sequence number for this CID
 * @retire_prior_to: Retire CIDs before this sequence
 * @node: Hash table linkage
 */
struct tquic_cid {
	u8 len;
	u8 id[TQUIC_MAX_CID_LEN];
	u64 seq_num;
	u64 retire_prior_to;
	struct rhash_head node;
};

/**
 * struct tquic_path_stats - Per-path statistics
 * @tx_packets: Packets transmitted
 * @tx_bytes: Bytes transmitted
 * @rx_packets: Packets received
 * @rx_bytes: Bytes received
 * @lost_packets: Detected lost packets
 * @rtt_min: Minimum observed RTT (us)
 * @rtt_smoothed: Smoothed RTT (us)
 * @rtt_variance: RTT variance (us)
 * @bandwidth: Estimated bandwidth (bytes/s)
 * @cwnd: Current congestion window
 */
struct tquic_path_stats {
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets;
	u64 rx_bytes;
	u64 lost_packets;
	u32 rtt_min;
	u32 rtt_smoothed;
	u32 rtt_variance;
	u64 bandwidth;
	u32 cwnd;
};

/**
 * struct tquic_path - A network path for WAN bonding
 * @state: Current path state
 * @path_id: Unique identifier for this path
 * @local_addr: Local address for this path
 * @remote_addr: Remote address for this path
 * @local_cid: Local connection ID for this path
 * @remote_cid: Remote connection ID for this path
 * @stats: Path statistics
 * @cong: Congestion control state
 * @mtu: Path MTU
 * @priority: Path priority (lower = preferred)
 * @weight: Weight for weighted schedulers
 * @last_activity: Timestamp of last activity
 * @validation_timer: Path validation timer
 * @probe_count: Number of outstanding probes
 * @challenge_data: PATH_CHALLENGE data
 * @list: Connection's path list linkage
 */
struct tquic_path {
	enum tquic_path_state state;
	u32 path_id;

	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;

	struct tquic_cid local_cid;
	struct tquic_cid remote_cid;

	struct tquic_path_stats stats;
	void *cong;  /* Congestion control state */

	u32 mtu;
	u8 priority;
	u8 weight;

	ktime_t last_activity;
	struct timer_list validation_timer;
	u8 probe_count;
	u8 challenge_data[8];

	struct list_head list;
};

/**
 * struct tquic_stream - A QUIC stream
 * @id: Stream identifier
 * @state: Current stream state
 * @conn: Parent connection
 * @send_buf: Send buffer
 * @recv_buf: Receive buffer
 * @send_offset: Current send offset
 * @recv_offset: Current receive offset
 * @max_send_data: Maximum data allowed to send
 * @max_recv_data: Maximum data allowed to receive
 * @priority: Stream priority
 * @blocked: Stream is flow-control blocked
 * @fin_sent: FIN has been sent
 * @fin_received: FIN has been received
 * @node: Connection's stream tree linkage
 * @wait: Wait queue for blocking operations
 */
struct tquic_stream {
	u64 id;
	enum tquic_stream_state state;
	struct tquic_connection *conn;

	struct sk_buff_head send_buf;
	struct sk_buff_head recv_buf;

	u64 send_offset;
	u64 recv_offset;
	u64 max_send_data;
	u64 max_recv_data;

	u8 priority;
	bool blocked;
	bool fin_sent;
	bool fin_received;

	struct rb_node node;
	wait_queue_head_t wait;
};

/**
 * struct tquic_conn_stats - Connection-level statistics
 */
struct tquic_conn_stats {
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets;
	u64 rx_bytes;
	u64 lost_packets;
	u64 retransmissions;
	u64 path_migrations;
	u64 streams_opened;
	u64 streams_closed;
	ktime_t established_time;
};

/**
 * struct tquic_connection - A TQUIC connection
 * @state: Current connection state
 * @version: Negotiated QUIC version
 * @scid: Source (local) connection ID
 * @dcid: Destination (remote) connection ID
 * @paths: List of network paths
 * @active_path: Currently active primary path
 * @num_paths: Number of paths
 * @streams: RB-tree of streams
 * @next_stream_id_bidi: Next bidirectional stream ID
 * @next_stream_id_uni: Next unidirectional stream ID
 * @max_streams_bidi: Maximum bidirectional streams
 * @max_streams_uni: Maximum unidirectional streams
 * @max_data_local: Local max data limit
 * @max_data_remote: Remote max data limit
 * @data_sent: Total data sent
 * @data_received: Total data received
 * @stats: Connection statistics
 * @idle_timeout: Idle timeout in ms
 * @idle_timer: Idle timeout timer
 * @ack_timer: Delayed ACK timer
 * @loss_timer: Loss detection timer
 * @crypto_state: TLS/crypto state
 * @scheduler: Packet scheduler
 * @lock: Connection lock
 * @refcnt: Reference counter
 * @sk: Associated socket
 * @node: Global connection hash linkage
 */
struct tquic_connection {
	enum tquic_conn_state state;
	u32 version;

	struct tquic_cid scid;
	struct tquic_cid dcid;

	/* Multi-path support for WAN bonding */
	struct list_head paths;
	struct tquic_path *active_path;
	u8 num_paths;

	/* Stream management */
	struct rb_root streams;
	u64 next_stream_id_bidi;
	u64 next_stream_id_uni;
	u64 max_streams_bidi;
	u64 max_streams_uni;

	/* Flow control */
	u64 max_data_local;
	u64 max_data_remote;
	u64 data_sent;
	u64 data_received;

	struct tquic_conn_stats stats;

	/* Timers */
	u32 idle_timeout;
	struct timer_list idle_timer;
	struct timer_list ack_timer;
	struct timer_list loss_timer;

	/* Crypto */
	void *crypto_state;

	/* Scheduler */
	void *scheduler;

	spinlock_t lock;
	refcount_t refcnt;
	struct sock *sk;
	struct rhash_head node;
};

/**
 * struct tquic_sock - TQUIC socket structure
 * @inet: Inet connection socket base
 * @conn: Associated TQUIC connection
 * @bind_addr: Bound local address
 * @connect_addr: Connected remote address
 * @accept_queue: Queue of incoming connections
 * @accept_queue_len: Length of accept queue
 * @max_accept_queue: Maximum accept queue length
 * @default_stream: Default stream for simple operations
 */
struct tquic_sock {
	struct inet_connection_sock inet;
	struct tquic_connection *conn;

	struct sockaddr_storage bind_addr;
	struct sockaddr_storage connect_addr;

	struct list_head accept_queue;
	u32 accept_queue_len;
	u32 max_accept_queue;

	struct tquic_stream *default_stream;
};

static inline struct tquic_sock *tquic_sk(struct sock *sk)
{
	return (struct tquic_sock *)sk;
}

/* Bonding operations */
struct tquic_bond_ops {
	const char *name;

	int (*add_path)(struct tquic_connection *conn,
			struct sockaddr *local,
			struct sockaddr *remote);
	int (*remove_path)(struct tquic_connection *conn, u32 path_id);
	int (*set_path_priority)(struct tquic_connection *conn,
				 u32 path_id, u8 priority);
	int (*get_path_info)(struct tquic_connection *conn,
			     u32 path_id, struct tquic_path_info *info);

	struct tquic_path *(*select_path)(struct tquic_connection *conn,
					  struct sk_buff *skb);
	void (*path_event)(struct tquic_connection *conn,
			   struct tquic_path *path, int event);
};

/* Scheduler operations */
struct tquic_sched_ops {
	const char *name;
	struct module *owner;

	void *(*init)(struct tquic_connection *conn);
	void (*release)(void *sched_data);

	struct tquic_path *(*select)(void *sched_data,
				     struct tquic_connection *conn,
				     struct sk_buff *skb);
	void (*feedback)(void *sched_data,
			 struct tquic_path *path,
			 struct sk_buff *skb,
			 bool success);

	struct list_head list;
};

/* Congestion control operations */
struct tquic_cong_ops {
	const char *name;
	struct module *owner;
	u32 key;

	void *(*init)(struct tquic_path *path);
	void (*release)(void *cong_data);

	void (*on_packet_sent)(void *cong_data, u64 bytes, ktime_t sent_time);
	void (*on_ack)(void *cong_data, u64 bytes_acked, u64 rtt_us);
	void (*on_loss)(void *cong_data, u64 bytes_lost);
	void (*on_rtt_update)(void *cong_data, u64 rtt_us);

	u64 (*get_cwnd)(void *cong_data);
	u64 (*get_pacing_rate)(void *cong_data);
	bool (*can_send)(void *cong_data, u64 bytes);

	struct list_head list;
};

/* Core API functions */
int tquic_connect(struct sock *sk, struct sockaddr *addr, int addr_len);
int tquic_accept(struct sock *sk, struct sock *newsk, int flags, bool kern);
int tquic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int tquic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags);
int tquic_close(struct sock *sk, long timeout);
__poll_t tquic_poll(struct file *file, struct socket *sock, poll_table *wait);

/* Connection management */
struct tquic_connection *tquic_conn_create(struct sock *sk, gfp_t gfp);
void tquic_conn_destroy(struct tquic_connection *conn);
int tquic_conn_add_path(struct tquic_connection *conn,
			struct sockaddr *local, struct sockaddr *remote);
int tquic_conn_remove_path(struct tquic_connection *conn, u32 path_id);
struct tquic_path *tquic_conn_get_path(struct tquic_connection *conn, u32 path_id);
void tquic_conn_migrate(struct tquic_connection *conn, struct tquic_path *new_path);

/* Stream management */
struct tquic_stream *tquic_stream_open(struct tquic_connection *conn, bool bidi);
void tquic_stream_close(struct tquic_stream *stream);
int tquic_stream_send(struct tquic_stream *stream, const void *data, size_t len, bool fin);
int tquic_stream_recv(struct tquic_stream *stream, void *data, size_t len);
void tquic_stream_reset(struct tquic_stream *stream, u64 error_code);

/* Path management for WAN bonding */
int tquic_path_probe(struct tquic_connection *conn, struct tquic_path *path);
void tquic_path_validate(struct tquic_connection *conn, struct tquic_path *path);
void tquic_path_update_stats(struct tquic_path *path, struct sk_buff *skb, bool success);
int tquic_path_set_weight(struct tquic_path *path, u8 weight);

/* Scheduler registration */
int tquic_register_scheduler(struct tquic_sched_ops *ops);
void tquic_unregister_scheduler(struct tquic_sched_ops *ops);

/* Congestion control registration */
int tquic_register_cong(struct tquic_cong_ops *ops);
void tquic_unregister_cong(struct tquic_cong_ops *ops);

/* Module initialization */
int __init tquic_init(void);
void __exit tquic_exit(void);

/* Netlink interface */
int __init tquic_netlink_init(void);
void __exit tquic_netlink_exit(void);

/* Sysctl interface */
int __init tquic_sysctl_init(void);
void __exit tquic_sysctl_exit(void);

#endif /* _NET_TQUIC_H */
