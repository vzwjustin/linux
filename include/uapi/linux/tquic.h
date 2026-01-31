/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * TQUIC: WAN Bonding over QUIC - User API
 *
 * Copyright (c) 2026 Linux Foundation
 */

#ifndef _UAPI_LINUX_TQUIC_H
#define _UAPI_LINUX_TQUIC_H

#include <linux/types.h>
#include <linux/socket.h>

/* Protocol number for TQUIC */
#define IPPROTO_TQUIC	253  /* Experimental */

/* Socket options at SOL_TQUIC level */
#define SOL_TQUIC	288

/* TQUIC socket options */
#define TQUIC_NODELAY		1   /* Disable Nagle algorithm */
#define TQUIC_MAXSEG		2   /* Maximum segment size */
#define TQUIC_CORK		3   /* Cork data before sending */
#define TQUIC_KEEPIDLE		4   /* Idle time before keepalive */
#define TQUIC_KEEPINTVL		5   /* Keepalive interval */
#define TQUIC_KEEPCNT		6   /* Keepalive probe count */
#define TQUIC_INFO		7   /* Connection info (read-only) */
#define TQUIC_CONGESTION	8   /* Congestion control algorithm */
#define TQUIC_SCHEDULER		9   /* Path scheduler algorithm */
#define TQUIC_IDLE_TIMEOUT	10  /* Idle timeout in ms */
#define TQUIC_MAX_DATA		11  /* Maximum data per connection */
#define TQUIC_MAX_STREAM_DATA	12  /* Maximum data per stream */
#define TQUIC_MAX_STREAMS_BIDI	13  /* Maximum bidirectional streams */
#define TQUIC_MAX_STREAMS_UNI	14  /* Maximum unidirectional streams */
#define TQUIC_ACK_DELAY		15  /* Maximum ACK delay in ms */
#define TQUIC_MIGRATION		16  /* Enable/disable connection migration */
#define TQUIC_MULTIPATH		17  /* Enable/disable multipath */
#define TQUIC_PATH_STATUS	18  /* Path status (bonding) */
#define TQUIC_ACTIVE_PATH	19  /* Set active path (bonding) */
#define TQUIC_ZEROCOPY		20  /* Enable zero-copy send */

/* WAN Bonding specific socket options */
#define TQUIC_BOND_MODE		50  /* Bonding mode */
#define TQUIC_BOND_ADD_PATH	51  /* Add a path to bond */
#define TQUIC_BOND_DEL_PATH	52  /* Remove a path from bond */
#define TQUIC_BOND_PATH_PRIO	53  /* Set path priority */
#define TQUIC_BOND_PATH_WEIGHT	54  /* Set path weight */
#define TQUIC_BOND_FAILOVER	55  /* Failover configuration */
#define TQUIC_BOND_PRIMARY	56  /* Set primary path */
#define TQUIC_BOND_STATS	57  /* Get bonding statistics */
#define TQUIC_BOND_REORDER_WIN	58  /* Reorder window size */
#define TQUIC_BOND_AGGR_MODE	59  /* Aggregation mode */

/* Stream-level options (via ancillary data) */
#define TQUIC_STREAM_ID		100
#define TQUIC_STREAM_PRIORITY	101
#define TQUIC_STREAM_RESET	102
#define TQUIC_STREAM_FIN	103

/* Bonding modes */
#define TQUIC_BOND_MODE_NONE		0  /* Single path only */
#define TQUIC_BOND_MODE_FAILOVER	1  /* Active-backup failover */
#define TQUIC_BOND_MODE_ROUNDROBIN	2  /* Round-robin scheduling */
#define TQUIC_BOND_MODE_WEIGHTED	3  /* Weighted scheduling */
#define TQUIC_BOND_MODE_MINRTT		4  /* Minimum RTT selection */
#define TQUIC_BOND_MODE_REDUNDANT	5  /* Send on all paths */
#define TQUIC_BOND_MODE_AGGREGATE	6  /* True bandwidth aggregation */
#define TQUIC_BOND_MODE_BLEST		7  /* BLEST scheduler */
#define TQUIC_BOND_MODE_ECF		8  /* Earliest completion first */

/* Aggregation modes for true bonding */
#define TQUIC_AGGR_PACKET	0  /* Packet-level striping */
#define TQUIC_AGGR_STREAM	1  /* Stream-level distribution */
#define TQUIC_AGGR_HYBRID	2  /* Adaptive hybrid */

/* Path states (visible to userspace) */
#define TQUIC_PATH_STATE_UNUSED		0
#define TQUIC_PATH_STATE_PENDING	1
#define TQUIC_PATH_STATE_ACTIVE		2
#define TQUIC_PATH_STATE_STANDBY	3
#define TQUIC_PATH_STATE_FAILED		4

/* Failover settings */
#define TQUIC_FAILOVER_IMMEDIATE	0  /* Immediate failover */
#define TQUIC_FAILOVER_DEFERRED		1  /* Wait for confirmation */
#define TQUIC_FAILOVER_MANUAL		2  /* Manual failover only */

/* Maximum values */
#define TQUIC_MAX_PATHS_USER		16
#define TQUIC_MAX_CONG_NAME		16
#define TQUIC_MAX_SCHED_NAME		16

/**
 * struct tquic_info - Connection information
 * @state: Connection state
 * @version: QUIC version
 * @rtt: Smoothed RTT in microseconds
 * @rtt_var: RTT variance in microseconds
 * @cwnd: Congestion window
 * @bytes_sent: Total bytes sent
 * @bytes_received: Total bytes received
 * @packets_sent: Total packets sent
 * @packets_received: Total packets received
 * @packets_lost: Total packets lost
 * @streams_active: Number of active streams
 * @paths_active: Number of active paths (bonding)
 * @idle_timeout: Idle timeout in ms
 */
struct tquic_info {
	__u8	state;
	__u8	paths_active;
	__u16	streams_active;
	__u32	version;
	__u32	rtt;
	__u32	rtt_var;
	__u32	cwnd;
	__u32	idle_timeout;
	__u64	bytes_sent;
	__u64	bytes_received;
	__u64	packets_sent;
	__u64	packets_received;
	__u64	packets_lost;
};

/**
 * struct tquic_path_info - Path information for WAN bonding
 * @path_id: Path identifier
 * @state: Path state
 * @priority: Path priority (0 = highest)
 * @weight: Weight for weighted scheduling
 * @mtu: Path MTU
 * @rtt: Smoothed RTT in microseconds
 * @rtt_var: RTT variance
 * @bandwidth: Estimated bandwidth in bytes/sec
 * @cwnd: Congestion window
 * @bytes_sent: Bytes sent on this path
 * @bytes_received: Bytes received on this path
 * @packets_lost: Packets lost on this path
 * @local_addr: Local address
 * @remote_addr: Remote address
 */
struct tquic_path_info {
	__u32	path_id;
	__u8	state;
	__u8	priority;
	__u8	weight;
	__u8	reserved;
	__u32	mtu;
	__u32	rtt;
	__u32	rtt_var;
	__u64	bandwidth;
	__u32	cwnd;
	__u32	reserved2;
	__u64	bytes_sent;
	__u64	bytes_received;
	__u64	packets_lost;
	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;
};

/**
 * struct tquic_bond_config - Bonding configuration
 * @mode: Bonding mode
 * @aggr_mode: Aggregation mode
 * @failover_mode: Failover behavior
 * @reorder_window: Reorder buffer size in packets
 * @probe_interval: Path probe interval in ms
 * @failover_timeout: Failover detection timeout in ms
 */
struct tquic_bond_config {
	__u8	mode;
	__u8	aggr_mode;
	__u8	failover_mode;
	__u8	reserved;
	__u32	reorder_window;
	__u32	probe_interval;
	__u32	failover_timeout;
};

/**
 * struct tquic_add_path - Add path request
 * @local_addr: Local address for the path
 * @remote_addr: Remote address for the path
 * @priority: Initial priority (0 = highest)
 * @weight: Initial weight for weighted scheduling
 * @flags: Path flags
 */
struct tquic_add_path {
	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;
	__u8	priority;
	__u8	weight;
	__u16	flags;
	__u32	reserved;
};

/* Path flags */
#define TQUIC_PATH_FLAG_BACKUP		(1 << 0)  /* Backup path only */
#define TQUIC_PATH_FLAG_NOVALIDATE	(1 << 1)  /* Skip validation */
#define TQUIC_PATH_FLAG_PREFERRED	(1 << 2)  /* Preferred path */

/**
 * struct tquic_bond_stats - Bonding statistics
 * @total_paths: Total paths ever added
 * @active_paths: Currently active paths
 * @failed_paths: Paths that have failed
 * @migrations: Number of path migrations
 * @failovers: Number of failover events
 * @reorder_events: Packets reordered
 * @bytes_aggregated: Bytes sent via aggregation
 */
struct tquic_bond_stats {
	__u32	total_paths;
	__u32	active_paths;
	__u32	failed_paths;
	__u32	standby_paths;
	__u64	migrations;
	__u64	failovers;
	__u64	reorder_events;
	__u64	bytes_aggregated;
};

/* Netlink interface */
#define TQUIC_GENL_NAME		"TQUIC"
#define TQUIC_GENL_VERSION	1

/* Netlink commands */
enum {
	TQUIC_CMD_UNSPEC,
	TQUIC_CMD_GET_CONN,	/* Get connection info */
	TQUIC_CMD_SET_CONN,	/* Modify connection */
	TQUIC_CMD_GET_PATH,	/* Get path info */
	TQUIC_CMD_ADD_PATH,	/* Add bonding path */
	TQUIC_CMD_DEL_PATH,	/* Remove bonding path */
	TQUIC_CMD_SET_PATH,	/* Modify path */
	TQUIC_CMD_GET_STATS,	/* Get statistics */
	TQUIC_CMD_SET_BOND,	/* Configure bonding */
	TQUIC_CMD_MIGRATE,	/* Trigger migration */
	TQUIC_CMD_NEW_CONN,	/* New connection notification */
	TQUIC_CMD_DEL_CONN,	/* Connection closed notification */
	TQUIC_CMD_PATH_EVENT,	/* Path state change notification */
	__TQUIC_CMD_MAX,
};
#define TQUIC_CMD_MAX (__TQUIC_CMD_MAX - 1)

/* Netlink attributes */
enum {
	TQUIC_ATTR_UNSPEC,
	TQUIC_ATTR_CONN_ID,	/* Connection identifier */
	TQUIC_ATTR_PATH_ID,	/* Path identifier */
	TQUIC_ATTR_LOCAL_ADDR,	/* Local address */
	TQUIC_ATTR_REMOTE_ADDR,	/* Remote address */
	TQUIC_ATTR_STATE,	/* State */
	TQUIC_ATTR_PRIORITY,	/* Priority */
	TQUIC_ATTR_WEIGHT,	/* Weight */
	TQUIC_ATTR_RTT,		/* RTT in microseconds */
	TQUIC_ATTR_BANDWIDTH,	/* Bandwidth in bytes/sec */
	TQUIC_ATTR_CWND,	/* Congestion window */
	TQUIC_ATTR_BYTES_SENT,	/* Bytes sent */
	TQUIC_ATTR_BYTES_RECV,	/* Bytes received */
	TQUIC_ATTR_PACKETS_LOST,/* Packets lost */
	TQUIC_ATTR_BOND_MODE,	/* Bonding mode */
	TQUIC_ATTR_BOND_CONFIG,	/* Full bond config */
	TQUIC_ATTR_PATH_INFO,	/* Full path info */
	TQUIC_ATTR_CONN_INFO,	/* Full connection info */
	TQUIC_ATTR_BOND_STATS,	/* Bonding statistics */
	TQUIC_ATTR_FLAGS,	/* Flags */
	TQUIC_ATTR_EVENT,	/* Event type */
	TQUIC_ATTR_PAD,
	__TQUIC_ATTR_MAX,
};
#define TQUIC_ATTR_MAX (__TQUIC_ATTR_MAX - 1)

/* Path events (for netlink notifications) */
enum tquic_path_event {
	TQUIC_PATH_EVENT_ADD,
	TQUIC_PATH_EVENT_REMOVE,
	TQUIC_PATH_EVENT_ACTIVE,
	TQUIC_PATH_EVENT_STANDBY,
	TQUIC_PATH_EVENT_FAILED,
	TQUIC_PATH_EVENT_RECOVERED,
	TQUIC_PATH_EVENT_MIGRATE,
};

/* Multicast groups */
enum tquic_nl_groups {
	TQUIC_NL_GRP_NONE,
	TQUIC_NL_GRP_CONN,	/* Connection events */
	TQUIC_NL_GRP_PATH,	/* Path events */
	__TQUIC_NL_GRP_MAX,
};
#define TQUIC_NL_GRP_MAX (__TQUIC_NL_GRP_MAX - 1)

/*
 * QUIC-native error codes (EQUIC*)
 *
 * These map to RFC 9000 QUIC Transport Error Codes.
 * They are returned via errno and provide QUIC-specific
 * error semantics rather than TCP-like mappings.
 *
 * Base value starts at 500 to avoid collision with standard errno.
 */
#define EQUIC_BASE			500

/* Transport errors (RFC 9000 Section 20.1) */
#define EQUIC_NO_ERROR			(EQUIC_BASE + 0x00)  /* 0x00 */
#define EQUIC_INTERNAL_ERROR		(EQUIC_BASE + 0x01)  /* 0x01 */
#define EQUIC_CONNECTION_REFUSED	(EQUIC_BASE + 0x02)  /* 0x02 */
#define EQUIC_FLOW_CONTROL		(EQUIC_BASE + 0x03)  /* 0x03 */
#define EQUIC_STREAM_LIMIT		(EQUIC_BASE + 0x04)  /* 0x04 */
#define EQUIC_STREAM_STATE		(EQUIC_BASE + 0x05)  /* 0x05 */
#define EQUIC_FINAL_SIZE		(EQUIC_BASE + 0x06)  /* 0x06 */
#define EQUIC_FRAME_ENCODING		(EQUIC_BASE + 0x07)  /* 0x07 */
#define EQUIC_TRANSPORT_PARAM		(EQUIC_BASE + 0x08)  /* 0x08 */
#define EQUIC_CONNECTION_ID_LIMIT	(EQUIC_BASE + 0x09)  /* 0x09 */
#define EQUIC_PROTOCOL_VIOLATION	(EQUIC_BASE + 0x0a)  /* 0x0a */
#define EQUIC_INVALID_TOKEN		(EQUIC_BASE + 0x0b)  /* 0x0b */
#define EQUIC_APPLICATION_ERROR		(EQUIC_BASE + 0x0c)  /* 0x0c */
#define EQUIC_CRYPTO_BUFFER		(EQUIC_BASE + 0x0d)  /* 0x0d */
#define EQUIC_KEY_UPDATE		(EQUIC_BASE + 0x0e)  /* 0x0e */
#define EQUIC_AEAD_LIMIT		(EQUIC_BASE + 0x0f)  /* 0x0f */
#define EQUIC_NO_VIABLE_PATH		(EQUIC_BASE + 0x10)  /* 0x10 */

/* Crypto errors (0x100 + TLS alert) */
#define EQUIC_CRYPTO_BASE		(EQUIC_BASE + 0x100)
#define EQUIC_HANDSHAKE_FAILED		(EQUIC_CRYPTO_BASE + 0x00)  /* Generic handshake failure */
#define EQUIC_CERT_EXPIRED		(EQUIC_CRYPTO_BASE + 0x2d)  /* Certificate expired (alert 45) */
#define EQUIC_CERT_REVOKED		(EQUIC_CRYPTO_BASE + 0x2c)  /* Certificate revoked (alert 44) */
#define EQUIC_UNKNOWN_CA		(EQUIC_CRYPTO_BASE + 0x30)  /* Unknown CA (alert 48) */
#define EQUIC_HANDSHAKE_TIMEOUT		(EQUIC_CRYPTO_BASE + 0xff)  /* Handshake timeout */

/* Connection timeout (fixed per CONTEXT.md) */
#define TQUIC_HANDSHAKE_TIMEOUT_MS	30000  /* Fixed 30 second timeout */

#endif /* _UAPI_LINUX_TQUIC_H */
