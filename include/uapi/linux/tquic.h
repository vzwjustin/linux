/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * TQUIC	Transport QUIC with Multi-Path and WAN Bonding Extensions
 *		for the LINUX operating system.
 *
 *	TQUIC extends the base QUIC protocol with multi-path transport
 *	capabilities, enabling simultaneous use of multiple network paths
 *	for improved throughput, redundancy, and WAN bonding scenarios.
 *
 * Authors:	TQUIC Kernel Development Team
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
#ifndef _UAPI_LINUX_TQUIC_H
#define _UAPI_LINUX_TQUIC_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/quic.h>

/*
 * TQUIC socket option level (same as QUIC)
 */
#define SOL_TQUIC		SOL_QUIC

/*
 * TQUIC-specific socket options for multi-path/WAN bonding
 * Start from 100 to avoid conflicts with base QUIC options
 */
#define TQUIC_SOCKOPT_MULTIPATH_ENABLED		100	/* Enable multi-path */
#define TQUIC_SOCKOPT_PATH_SCHEDULER		101	/* Set path scheduler */
#define TQUIC_SOCKOPT_ADD_PATH			102	/* Add a new path */
#define TQUIC_SOCKOPT_REMOVE_PATH		103	/* Remove a path */
#define TQUIC_SOCKOPT_SET_PATH_STATE		104	/* Set path state */
#define TQUIC_SOCKOPT_SET_PATH_PRIORITY		105	/* Set path priority */
#define TQUIC_SOCKOPT_SET_PATH_WEIGHT		106	/* Set path weight */
#define TQUIC_SOCKOPT_GET_PATH_STATS		107	/* Get path statistics */
#define TQUIC_SOCKOPT_GET_ALL_PATHS		108	/* Get all path info */
#define TQUIC_SOCKOPT_WAN_INTERFACE		109	/* Set WAN interface info */
#define TQUIC_SOCKOPT_BONDING_MODE		110	/* Set bonding mode */
#define TQUIC_SOCKOPT_FAILOVER_TIMEOUT		111	/* Failover timeout (ms) */
#define TQUIC_SOCKOPT_PATH_PROBE_INTERVAL	112	/* Path probe interval */
#define TQUIC_SOCKOPT_PATH_IDLE_TIMEOUT		113	/* Path idle timeout */
#define TQUIC_SOCKOPT_MIN_PATHS			114	/* Min paths to maintain */
#define TQUIC_SOCKOPT_MAX_PATHS			115	/* Max paths allowed */
#define TQUIC_SOCKOPT_PATH_REINJECTION		116	/* Enable reinjection */
#define TQUIC_SOCKOPT_AGGREGATE_BANDWIDTH	117	/* Get aggregate BW */
#define TQUIC_SOCKOPT_PREFERRED_PATH		118	/* Set preferred path */
#define TQUIC_SOCKOPT_PATH_ATTRIBUTES		119	/* Set path attributes */
#define TQUIC_SOCKOPT_SCHEDULER_PARAMS		120	/* Scheduler parameters */
#define TQUIC_SOCKOPT_ECN_PATH			121	/* ECN per-path config */
#define TQUIC_SOCKOPT_PATH_MTU			122	/* Per-path MTU */
#define TQUIC_SOCKOPT_PATH_CWND			123	/* Get path cwnd */
#define TQUIC_SOCKOPT_MULTIPATH_INFO		124	/* Get multipath info */
#define TQUIC_SOCKOPT_PATH_QUALITY		125	/* Get path quality score */
#define TQUIC_SOCKOPT_PACKET_DISTRIBUTION	126	/* Get packet distribution */

/*
 * Path states for multi-path TQUIC
 */
enum tquic_path_state {
	TQUIC_PATH_AVAILABLE = 0,	/* Path is available but not active */
	TQUIC_PATH_STANDBY = 1,		/* Path is standby (backup) */
	TQUIC_PATH_ACTIVE = 2,		/* Path is actively used */
	TQUIC_PATH_FAILED = 3,		/* Path has failed */
	TQUIC_PATH_PROBING = 4,		/* Path is being probed */
	TQUIC_PATH_VALIDATING = 5,	/* Path validation in progress */
	TQUIC_PATH_DEGRADED = 6,	/* Path performance degraded */
	TQUIC_PATH_DRAINING = 7,	/* Path is being drained */
};

#define TQUICF_PATH_AVAILABLE	(1 << TQUIC_PATH_AVAILABLE)
#define TQUICF_PATH_STANDBY	(1 << TQUIC_PATH_STANDBY)
#define TQUICF_PATH_ACTIVE	(1 << TQUIC_PATH_ACTIVE)
#define TQUICF_PATH_FAILED	(1 << TQUIC_PATH_FAILED)
#define TQUICF_PATH_PROBING	(1 << TQUIC_PATH_PROBING)
#define TQUICF_PATH_VALIDATING	(1 << TQUIC_PATH_VALIDATING)
#define TQUICF_PATH_DEGRADED	(1 << TQUIC_PATH_DEGRADED)
#define TQUICF_PATH_DRAINING	(1 << TQUIC_PATH_DRAINING)

/*
 * Scheduler types for packet distribution across paths
 */
enum tquic_scheduler_type {
	TQUIC_SCHED_ROUND_ROBIN = 0,	/* Round-robin across paths */
	TQUIC_SCHED_WEIGHTED = 1,	/* Weighted distribution */
	TQUIC_SCHED_LOWEST_LATENCY = 2,	/* Prefer lowest latency path */
	TQUIC_SCHED_REDUNDANT = 3,	/* Send on all paths (redundant) */
	TQUIC_SCHED_HIGHEST_BW = 4,	/* Prefer highest bandwidth path */
	TQUIC_SCHED_BLEST = 5,		/* Blocking estimation scheduler */
	TQUIC_SCHED_ECF = 6,		/* Earliest completion first */
	TQUIC_SCHED_MINRTT = 7,		/* Minimum RTT scheduler */
	TQUIC_SCHED_ADAPTIVE = 8,	/* Adaptive scheduler */
	TQUIC_SCHED_CUSTOM = 9,		/* Custom/BPF scheduler */
};

/*
 * Bonding modes for WAN aggregation
 */
enum tquic_bonding_mode {
	TQUIC_BOND_NONE = 0,		/* No bonding, single path */
	TQUIC_BOND_ACTIVE_BACKUP = 1,	/* Active-backup failover */
	TQUIC_BOND_LOAD_BALANCE = 2,	/* Load balancing */
	TQUIC_BOND_AGGREGATE = 3,	/* Bandwidth aggregation */
	TQUIC_BOND_BROADCAST = 4,	/* Broadcast on all paths */
	TQUIC_BOND_ADAPTIVE = 5,	/* Adaptive mode */
};

/*
 * Path attributes/capabilities
 */
#define TQUIC_PATH_ATTR_METERED		0x0001	/* Metered connection */
#define TQUIC_PATH_ATTR_LOW_POWER	0x0002	/* Low power interface */
#define TQUIC_PATH_ATTR_EXPENSIVE	0x0004	/* Expensive (e.g., LTE) */
#define TQUIC_PATH_ATTR_WIFI		0x0008	/* WiFi interface */
#define TQUIC_PATH_ATTR_CELLULAR	0x0010	/* Cellular interface */
#define TQUIC_PATH_ATTR_ETHERNET	0x0020	/* Ethernet interface */
#define TQUIC_PATH_ATTR_VPN		0x0040	/* VPN tunnel */
#define TQUIC_PATH_ATTR_LOOPBACK	0x0080	/* Loopback interface */
#define TQUIC_PATH_ATTR_SATELLITE	0x0100	/* Satellite link */
#define TQUIC_PATH_ATTR_DSL		0x0200	/* DSL connection */
#define TQUIC_PATH_ATTR_FIBER		0x0400	/* Fiber connection */
#define TQUIC_PATH_ATTR_BONDED		0x0800	/* Part of bond interface */

/*
 * Path quality metrics flags
 */
#define TQUIC_QUALITY_RTT_VALID		0x01	/* RTT measurement valid */
#define TQUIC_QUALITY_BW_VALID		0x02	/* Bandwidth estimate valid */
#define TQUIC_QUALITY_LOSS_VALID	0x04	/* Loss rate valid */
#define TQUIC_QUALITY_JITTER_VALID	0x08	/* Jitter measurement valid */

/*
 * WAN interface information structure
 */
struct tquic_wan_interface {
	__u32		ifindex;		/* Interface index */
	char		ifname[16];		/* Interface name */
	__u8		state;			/* Interface state */
	__u8		type;			/* Interface type */
	__u16		flags;			/* Interface flags */
	__u32		attributes;		/* TQUIC_PATH_ATTR_* */

	/* Address configuration */
	struct __kernel_sockaddr_storage local_addr;	/* Local address */
	struct __kernel_sockaddr_storage gateway;	/* Gateway address */

	/* Link characteristics */
	__u64		link_speed;		/* Speed in bits/second */
	__u32		mtu;			/* Interface MTU */
	__u32		tx_queue_len;		/* TX queue length */

	/* Cost/preference */
	__u32		cost;			/* Path cost (lower = better) */
	__u32		priority;		/* Priority (higher = better) */
	__u32		weight;			/* Weight for scheduling */
	__u32		reserved;

	/* Statistics */
	__u64		rx_bytes;		/* Received bytes */
	__u64		tx_bytes;		/* Transmitted bytes */
	__u64		rx_packets;		/* Received packets */
	__u64		tx_packets;		/* Transmitted packets */
	__u64		rx_errors;		/* Receive errors */
	__u64		tx_errors;		/* Transmit errors */
	__u64		rx_dropped;		/* Dropped on receive */
	__u64		tx_dropped;		/* Dropped on transmit */
} __attribute__((aligned(8)));

/* WAN interface states */
enum tquic_wan_state {
	TQUIC_WAN_DOWN = 0,		/* Interface is down */
	TQUIC_WAN_CONNECTING = 1,	/* Connecting */
	TQUIC_WAN_UP = 2,		/* Interface is up */
	TQUIC_WAN_DISCONNECTING = 3,	/* Disconnecting */
};

/* WAN interface types */
enum tquic_wan_type {
	TQUIC_WAN_TYPE_UNKNOWN = 0,
	TQUIC_WAN_TYPE_ETHERNET = 1,
	TQUIC_WAN_TYPE_WIFI = 2,
	TQUIC_WAN_TYPE_CELLULAR = 3,
	TQUIC_WAN_TYPE_VPN = 4,
	TQUIC_WAN_TYPE_SATELLITE = 5,
	TQUIC_WAN_TYPE_DSL = 6,
	TQUIC_WAN_TYPE_FIBER = 7,
	TQUIC_WAN_TYPE_LOOPBACK = 8,
};

/*
 * Path statistics structure
 */
struct tquic_path_stats {
	__u32		path_id;		/* Path identifier */
	__u8		state;			/* Current path state */
	__u8		scheduler_selected;	/* Selected by scheduler */
	__u8		ecn_capable;		/* ECN capability */
	__u8		validated;		/* Path validated */

	/* RTT measurements (microseconds) */
	__u32		rtt_min;		/* Minimum RTT */
	__u32		rtt_max;		/* Maximum RTT */
	__u32		rtt_avg;		/* Average RTT */
	__u32		rtt_smoothed;		/* Smoothed RTT */
	__u32		rtt_variance;		/* RTT variance */
	__u32		rtt_latest;		/* Latest RTT sample */
	__u64		rtt_samples;		/* Number of RTT samples */

	/* Bandwidth estimates (bytes/second) */
	__u64		bandwidth_estimate;	/* Current bandwidth estimate */
	__u64		bandwidth_max;		/* Maximum observed bandwidth */
	__u64		bandwidth_min;		/* Minimum observed bandwidth */
	__u64		bandwidth_avg;		/* Average bandwidth */
	__u64		delivery_rate;		/* Current delivery rate */
	__u64		pacing_rate;		/* Current pacing rate */

	/* Loss statistics */
	__u32		loss_rate;		/* Loss rate (per million) */
	__u32		loss_count;		/* Total lost packets */
	__u32		spurious_loss_count;	/* Spurious loss (recovered) */
	__u32		reorder_count;		/* Reordering events */

	/* Jitter (microseconds) */
	__u32		jitter_min;		/* Minimum jitter */
	__u32		jitter_max;		/* Maximum jitter */
	__u32		jitter_avg;		/* Average jitter */
	__u32		jitter_latest;		/* Latest jitter sample */

	/* Congestion control */
	__u64		cwnd;			/* Congestion window */
	__u64		bytes_in_flight;	/* Bytes in flight */
	__u32		ssthresh;		/* Slow start threshold */
	__u8		cc_state;		/* Congestion control state */
	__u8		app_limited;		/* Application limited */
	__u16		reserved1;

	/* Packet/byte counters */
	__u64		packets_sent;		/* Packets sent on path */
	__u64		packets_received;	/* Packets received */
	__u64		packets_acked;		/* Packets acknowledged */
	__u64		packets_lost;		/* Packets lost */
	__u64		packets_retransmitted;	/* Packets retransmitted */
	__u64		bytes_sent;		/* Bytes sent */
	__u64		bytes_received;		/* Bytes received */
	__u64		bytes_acked;		/* Bytes acknowledged */
	__u64		bytes_lost;		/* Bytes lost */
	__u64		bytes_retransmitted;	/* Bytes retransmitted */

	/* ECN counters */
	__u64		ecn_ect0_count;		/* ECT(0) marked packets */
	__u64		ecn_ect1_count;		/* ECT(1) marked packets */
	__u64		ecn_ce_count;		/* CE marked packets */

	/* Scheduling statistics */
	__u64		scheduled_count;	/* Times scheduled by sched */
	__u64		skipped_count;		/* Times skipped */
	__u64		bytes_scheduled;	/* Total bytes scheduled */

	/* Timing (nanoseconds since boot) */
	__u64		last_send_time;		/* Last packet send time */
	__u64		last_recv_time;		/* Last packet receive time */
	__u64		last_ack_time;		/* Last ACK receive time */
	__u64		path_established;	/* Path establishment time */
	__u64		path_validated_time;	/* Path validation time */

	/* Quality metrics */
	__u32		quality_score;		/* Overall quality (0-100) */
	__u32		quality_flags;		/* TQUIC_QUALITY_* */

	/* Reserved for future use */
	__u64		reserved2[4];
} __attribute__((aligned(8)));

/*
 * Multi-path connection info structure
 */
struct tquic_multipath_info {
	__u8		enabled;		/* Multi-path enabled */
	__u8		scheduler_type;		/* Active scheduler type */
	__u8		bonding_mode;		/* Bonding mode */
	__u8		num_paths;		/* Number of paths */
	__u8		num_active;		/* Active paths */
	__u8		num_standby;		/* Standby paths */
	__u8		num_failed;		/* Failed paths */
	__u8		reserved;

	/* Aggregate statistics */
	__u64		total_bytes_sent;	/* Total across all paths */
	__u64		total_bytes_received;
	__u64		total_packets_sent;
	__u64		total_packets_received;

	/* Aggregate bandwidth */
	__u64		aggregate_bandwidth;	/* Sum of all path bandwidths */
	__u64		effective_bandwidth;	/* Effective usable bandwidth */

	/* Scheduler stats */
	__u64		scheduler_decisions;	/* Total scheduling decisions */
	__u64		path_switches;		/* Path switch count */

	/* Configuration */
	__u32		min_paths;		/* Minimum paths to maintain */
	__u32		max_paths;		/* Maximum paths allowed */
	__u32		failover_timeout;	/* Failover timeout (ms) */
	__u32		probe_interval;		/* Path probe interval (ms) */

	/* Reserved */
	__u64		reserved2[4];
} __attribute__((aligned(8)));

/*
 * Path configuration structure
 */
struct tquic_path_config {
	__u32		path_id;		/* Path identifier */
	__u8		state;			/* Desired state */
	__u8		priority;		/* Priority (0-255) */
	__u16		weight;			/* Weight for scheduling */
	__u32		attributes;		/* TQUIC_PATH_ATTR_* */
	__u32		reserved;

	/* Address pair */
	struct __kernel_sockaddr_storage local_addr;
	struct __kernel_sockaddr_storage remote_addr;

	/* Limits */
	__u64		max_bandwidth;		/* Max bandwidth to use */
	__u32		max_packets_per_rtt;	/* Max packets per RTT */
	__u32		mtu;			/* Path MTU override */
} __attribute__((aligned(8)));

/*
 * Scheduler parameters structure
 */
struct tquic_scheduler_params {
	__u8		type;			/* Scheduler type */
	__u8		reserved[3];

	/* Common parameters */
	__u32		reinjection_threshold;	/* Reinjection threshold (ms) */
	__u32		switch_threshold;	/* Path switch threshold */
	__u32		stale_threshold;	/* Stale path threshold (ms) */

	/* Weighted scheduler parameters */
	__u32		weight_rtt;		/* RTT weight factor */
	__u32		weight_bw;		/* Bandwidth weight factor */
	__u32		weight_loss;		/* Loss rate weight factor */

	/* Adaptive scheduler parameters */
	__u32		adapt_interval;		/* Adaptation interval (ms) */
	__u32		adapt_rtt_factor;	/* RTT adaptation factor */
	__u32		adapt_bw_factor;	/* Bandwidth adaptation factor */

	/* Reserved for scheduler-specific params */
	__u64		reserved2[8];
} __attribute__((aligned(8)));

/*
 * Packet distribution info structure
 */
struct tquic_packet_distribution {
	__u32		num_paths;		/* Number of paths */
	__u32		reserved;
	/* Per-path distribution (percentage, 0-100) */
	struct {
		__u32	path_id;		/* Path identifier */
		__u32	percentage;		/* Distribution percentage */
		__u64	packets;		/* Packets sent on path */
		__u64	bytes;			/* Bytes sent on path */
	} paths[16];				/* Max 16 paths */
} __attribute__((aligned(8)));

/*
 * Netlink family and commands for TQUIC path management
 */
#define TQUIC_PM_NAME		"tquic_pm"
#define TQUIC_PM_VERSION	1

#define TQUIC_PM_CMD_GRP_NAME	"tquic_pm_cmds"
#define TQUIC_PM_EV_GRP_NAME	"tquic_pm_events"

/*
 * Netlink commands for TQUIC path management
 */
enum tquic_pm_cmd {
	TQUIC_PM_CMD_UNSPEC = 0,
	TQUIC_PM_CMD_ADD_PATH,		/* Add a new path */
	TQUIC_PM_CMD_DEL_PATH,		/* Delete a path */
	TQUIC_PM_CMD_GET_PATH,		/* Get path info */
	TQUIC_PM_CMD_SET_PATH,		/* Set path configuration */
	TQUIC_PM_CMD_FLUSH_PATHS,	/* Flush all paths */
	TQUIC_PM_CMD_SET_SCHEDULER,	/* Set scheduler type */
	TQUIC_PM_CMD_GET_SCHEDULER,	/* Get scheduler info */
	TQUIC_PM_CMD_SET_BONDING,	/* Set bonding mode */
	TQUIC_PM_CMD_GET_BONDING,	/* Get bonding info */
	TQUIC_PM_CMD_PATH_PROBE,	/* Trigger path probe */
	TQUIC_PM_CMD_PATH_MIGRATE,	/* Migrate to path */
	TQUIC_PM_CMD_SET_LIMITS,	/* Set path limits */
	TQUIC_PM_CMD_GET_LIMITS,	/* Get path limits */
	TQUIC_PM_CMD_GET_STATS,		/* Get path statistics */
	TQUIC_PM_CMD_CLEAR_STATS,	/* Clear path statistics */
	TQUIC_PM_CMD_ADD_INTERFACE,	/* Add WAN interface */
	TQUIC_PM_CMD_DEL_INTERFACE,	/* Delete WAN interface */
	TQUIC_PM_CMD_GET_INTERFACE,	/* Get interface info */
	TQUIC_PM_CMD_SUBSCRIBE,		/* Subscribe to events */
	TQUIC_PM_CMD_UNSUBSCRIBE,	/* Unsubscribe from events */

	__TQUIC_PM_CMD_AFTER_LAST
};
#define TQUIC_PM_CMD_MAX	(__TQUIC_PM_CMD_AFTER_LAST - 1)

/*
 * Netlink events for TQUIC path management
 */
enum tquic_pm_event {
	TQUIC_PM_EVENT_UNSPEC = 0,
	TQUIC_PM_EVENT_PATH_ADDED,	/* New path added */
	TQUIC_PM_EVENT_PATH_REMOVED,	/* Path removed */
	TQUIC_PM_EVENT_PATH_UP,		/* Path became available */
	TQUIC_PM_EVENT_PATH_DOWN,	/* Path went down */
	TQUIC_PM_EVENT_PATH_DEGRADED,	/* Path performance degraded */
	TQUIC_PM_EVENT_PATH_RECOVERED,	/* Path recovered */
	TQUIC_PM_EVENT_PATH_VALIDATED,	/* Path validated */
	TQUIC_PM_EVENT_PATH_FAILED,	/* Path validation failed */
	TQUIC_PM_EVENT_FAILOVER,	/* Failover occurred */
	TQUIC_PM_EVENT_FAILBACK,	/* Failback occurred */
	TQUIC_PM_EVENT_SCHEDULER_SWITCH, /* Scheduler switched paths */
	TQUIC_PM_EVENT_INTERFACE_UP,	/* Interface came up */
	TQUIC_PM_EVENT_INTERFACE_DOWN,	/* Interface went down */
	TQUIC_PM_EVENT_CONGESTION,	/* Congestion detected */
	TQUIC_PM_EVENT_QUALITY_CHANGE,	/* Path quality changed */

	__TQUIC_PM_EVENT_AFTER_LAST
};
#define TQUIC_PM_EVENT_MAX	(__TQUIC_PM_EVENT_AFTER_LAST - 1)

/*
 * Netlink attributes for path information
 */
enum tquic_pm_path_attr {
	TQUIC_PM_PATH_ATTR_UNSPEC = 0,
	TQUIC_PM_PATH_ATTR_ID,		/* Path ID (__u32) */
	TQUIC_PM_PATH_ATTR_STATE,	/* Path state (__u8) */
	TQUIC_PM_PATH_ATTR_LOCAL_ADDR,	/* Local address (sockaddr) */
	TQUIC_PM_PATH_ATTR_REMOTE_ADDR,	/* Remote address (sockaddr) */
	TQUIC_PM_PATH_ATTR_IFINDEX,	/* Interface index (__u32) */
	TQUIC_PM_PATH_ATTR_PRIORITY,	/* Priority (__u8) */
	TQUIC_PM_PATH_ATTR_WEIGHT,	/* Weight (__u16) */
	TQUIC_PM_PATH_ATTR_FLAGS,	/* Flags (__u32) */
	TQUIC_PM_PATH_ATTR_ATTRIBUTES,	/* Attributes (__u32) */
	TQUIC_PM_PATH_ATTR_MTU,		/* MTU (__u32) */
	TQUIC_PM_PATH_ATTR_RTT,		/* RTT in us (__u32) */
	TQUIC_PM_PATH_ATTR_RTT_VAR,	/* RTT variance (__u32) */
	TQUIC_PM_PATH_ATTR_BANDWIDTH,	/* Bandwidth estimate (__u64) */
	TQUIC_PM_PATH_ATTR_LOSS_RATE,	/* Loss rate per million (__u32) */
	TQUIC_PM_PATH_ATTR_CWND,	/* Congestion window (__u64) */
	TQUIC_PM_PATH_ATTR_BYTES_SENT,	/* Bytes sent (__u64) */
	TQUIC_PM_PATH_ATTR_BYTES_RECV,	/* Bytes received (__u64) */
	TQUIC_PM_PATH_ATTR_PACKETS_SENT, /* Packets sent (__u64) */
	TQUIC_PM_PATH_ATTR_PACKETS_RECV, /* Packets received (__u64) */
	TQUIC_PM_PATH_ATTR_PACKETS_LOST, /* Packets lost (__u64) */
	TQUIC_PM_PATH_ATTR_QUALITY,	/* Quality score (__u32) */
	TQUIC_PM_PATH_ATTR_STATS,	/* Full stats (struct tquic_path_stats) */

	__TQUIC_PM_PATH_ATTR_AFTER_LAST
};
#define TQUIC_PM_PATH_ATTR_MAX	(__TQUIC_PM_PATH_ATTR_AFTER_LAST - 1)

/*
 * Netlink attributes for scheduler configuration
 */
enum tquic_pm_sched_attr {
	TQUIC_PM_SCHED_ATTR_UNSPEC = 0,
	TQUIC_PM_SCHED_ATTR_TYPE,	/* Scheduler type (__u8) */
	TQUIC_PM_SCHED_ATTR_NAME,	/* Scheduler name (string) */
	TQUIC_PM_SCHED_ATTR_PARAMS,	/* Parameters (struct) */
	TQUIC_PM_SCHED_ATTR_DECISIONS,	/* Decision count (__u64) */
	TQUIC_PM_SCHED_ATTR_SWITCHES,	/* Path switch count (__u64) */

	__TQUIC_PM_SCHED_ATTR_AFTER_LAST
};
#define TQUIC_PM_SCHED_ATTR_MAX	(__TQUIC_PM_SCHED_ATTR_AFTER_LAST - 1)

/*
 * Netlink attributes for bonding configuration
 */
enum tquic_pm_bond_attr {
	TQUIC_PM_BOND_ATTR_UNSPEC = 0,
	TQUIC_PM_BOND_ATTR_MODE,	/* Bonding mode (__u8) */
	TQUIC_PM_BOND_ATTR_FAILOVER_MS,	/* Failover timeout (__u32) */
	TQUIC_PM_BOND_ATTR_PRIMARY_ID,	/* Primary path ID (__u32) */
	TQUIC_PM_BOND_ATTR_ACTIVE_PATHS,/* Active path count (__u8) */
	TQUIC_PM_BOND_ATTR_TOTAL_PATHS,	/* Total path count (__u8) */
	TQUIC_PM_BOND_ATTR_AGG_BW,	/* Aggregate bandwidth (__u64) */

	__TQUIC_PM_BOND_ATTR_AFTER_LAST
};
#define TQUIC_PM_BOND_ATTR_MAX	(__TQUIC_PM_BOND_ATTR_AFTER_LAST - 1)

/*
 * Netlink attributes for WAN interface
 */
enum tquic_pm_iface_attr {
	TQUIC_PM_IFACE_ATTR_UNSPEC = 0,
	TQUIC_PM_IFACE_ATTR_IFINDEX,	/* Interface index (__u32) */
	TQUIC_PM_IFACE_ATTR_IFNAME,	/* Interface name (string) */
	TQUIC_PM_IFACE_ATTR_STATE,	/* Interface state (__u8) */
	TQUIC_PM_IFACE_ATTR_TYPE,	/* Interface type (__u8) */
	TQUIC_PM_IFACE_ATTR_ADDR,	/* Address (sockaddr) */
	TQUIC_PM_IFACE_ATTR_GATEWAY,	/* Gateway (sockaddr) */
	TQUIC_PM_IFACE_ATTR_MTU,	/* MTU (__u32) */
	TQUIC_PM_IFACE_ATTR_SPEED,	/* Link speed (__u64) */
	TQUIC_PM_IFACE_ATTR_FLAGS,	/* Flags (__u32) */
	TQUIC_PM_IFACE_ATTR_COST,	/* Cost (__u32) */
	TQUIC_PM_IFACE_ATTR_PRIORITY,	/* Priority (__u32) */
	TQUIC_PM_IFACE_ATTR_WEIGHT,	/* Weight (__u32) */
	TQUIC_PM_IFACE_ATTR_RX_BYTES,	/* RX bytes (__u64) */
	TQUIC_PM_IFACE_ATTR_TX_BYTES,	/* TX bytes (__u64) */
	TQUIC_PM_IFACE_ATTR_RX_PACKETS,	/* RX packets (__u64) */
	TQUIC_PM_IFACE_ATTR_TX_PACKETS,	/* TX packets (__u64) */

	__TQUIC_PM_IFACE_ATTR_AFTER_LAST
};
#define TQUIC_PM_IFACE_ATTR_MAX	(__TQUIC_PM_IFACE_ATTR_AFTER_LAST - 1)

/*
 * Netlink top-level attributes for TQUIC PM
 */
enum tquic_pm_attr {
	TQUIC_PM_ATTR_UNSPEC = 0,
	TQUIC_PM_ATTR_TOKEN,		/* Connection token (__u32) */
	TQUIC_PM_ATTR_PATH,		/* Path attrs (nested) */
	TQUIC_PM_ATTR_SCHEDULER,	/* Scheduler attrs (nested) */
	TQUIC_PM_ATTR_BONDING,		/* Bonding attrs (nested) */
	TQUIC_PM_ATTR_INTERFACE,	/* Interface attrs (nested) */
	TQUIC_PM_ATTR_EVENT,		/* Event type (__u8) */
	TQUIC_PM_ATTR_ERROR,		/* Error code (__s32) */
	TQUIC_PM_ATTR_MULTIPATH_INFO,	/* Multipath info (struct) */

	__TQUIC_PM_ATTR_AFTER_LAST
};
#define TQUIC_PM_ATTR_MAX	(__TQUIC_PM_ATTR_AFTER_LAST - 1)

/*
 * Event flags for netlink notifications
 */
#define TQUIC_PM_EV_FLAG_PATH_PRIMARY	0x01	/* Primary path event */
#define TQUIC_PM_EV_FLAG_AUTOMATIC	0x02	/* Automatic action */
#define TQUIC_PM_EV_FLAG_USER_INITIATED	0x04	/* User initiated action */

/*
 * ioctl commands for TQUIC multi-path control
 */
#define TQUIC_IOC_MAGIC			'T'

/* Multi-path management */
#define TQUIC_IOC_ENABLE_MULTIPATH	_IOW(TQUIC_IOC_MAGIC, 1, __u32)
#define TQUIC_IOC_DISABLE_MULTIPATH	_IO(TQUIC_IOC_MAGIC, 2)
#define TQUIC_IOC_ADD_PATH		_IOW(TQUIC_IOC_MAGIC, 3, struct tquic_path_config)
#define TQUIC_IOC_REMOVE_PATH		_IOW(TQUIC_IOC_MAGIC, 4, __u32)
#define TQUIC_IOC_SET_PATH_STATE	_IOW(TQUIC_IOC_MAGIC, 5, struct tquic_path_state_change)
#define TQUIC_IOC_GET_PATH_STATS	_IOWR(TQUIC_IOC_MAGIC, 6, struct tquic_path_stats)
#define TQUIC_IOC_GET_ALL_PATHS		_IOR(TQUIC_IOC_MAGIC, 7, struct tquic_all_paths)

/* Scheduler control */
#define TQUIC_IOC_SET_SCHEDULER		_IOW(TQUIC_IOC_MAGIC, 10, struct tquic_scheduler_params)
#define TQUIC_IOC_GET_SCHEDULER		_IOR(TQUIC_IOC_MAGIC, 11, struct tquic_scheduler_params)

/* Bonding control */
#define TQUIC_IOC_SET_BONDING_MODE	_IOW(TQUIC_IOC_MAGIC, 20, __u32)
#define TQUIC_IOC_GET_BONDING_MODE	_IOR(TQUIC_IOC_MAGIC, 21, __u32)
#define TQUIC_IOC_TRIGGER_FAILOVER	_IOW(TQUIC_IOC_MAGIC, 22, __u32)
#define TQUIC_IOC_TRIGGER_FAILBACK	_IOW(TQUIC_IOC_MAGIC, 23, __u32)

/* WAN interface management */
#define TQUIC_IOC_ADD_INTERFACE		_IOW(TQUIC_IOC_MAGIC, 30, struct tquic_wan_interface)
#define TQUIC_IOC_REMOVE_INTERFACE	_IOW(TQUIC_IOC_MAGIC, 31, __u32)
#define TQUIC_IOC_GET_INTERFACE		_IOWR(TQUIC_IOC_MAGIC, 32, struct tquic_wan_interface)
#define TQUIC_IOC_LIST_INTERFACES	_IOR(TQUIC_IOC_MAGIC, 33, struct tquic_interface_list)

/* Multi-path info */
#define TQUIC_IOC_GET_MULTIPATH_INFO	_IOR(TQUIC_IOC_MAGIC, 40, struct tquic_multipath_info)
#define TQUIC_IOC_GET_DISTRIBUTION	_IOR(TQUIC_IOC_MAGIC, 41, struct tquic_packet_distribution)

/*
 * Path state change structure
 */
struct tquic_path_state_change {
	__u32		path_id;		/* Path identifier */
	__u8		new_state;		/* New state (tquic_path_state) */
	__u8		reserved[3];
} __attribute__((aligned(8)));

/*
 * All paths query structure
 */
struct tquic_all_paths {
	__u32		num_paths;		/* out: number of paths */
	__u32		max_paths;		/* in: max paths to return */
	struct tquic_path_stats paths[0];	/* Variable length array */
} __attribute__((aligned(8)));

/*
 * Interface list structure
 */
struct tquic_interface_list {
	__u32		num_interfaces;		/* Number of interfaces */
	__u32		reserved;
	struct tquic_wan_interface interfaces[0]; /* Variable length array */
} __attribute__((aligned(8)));

/*
 * Constants for TQUIC
 */
#define TQUIC_MAX_PATHS			16	/* Maximum paths per connection */
#define TQUIC_MAX_INTERFACES		32	/* Maximum WAN interfaces */
#define TQUIC_DEFAULT_FAILOVER_MS	1000	/* Default failover timeout */
#define TQUIC_DEFAULT_PROBE_INTERVAL_MS	5000	/* Default probe interval */
#define TQUIC_MIN_PROBE_INTERVAL_MS	100	/* Minimum probe interval */
#define TQUIC_MAX_PROBE_INTERVAL_MS	60000	/* Maximum probe interval */
#define TQUIC_DEFAULT_PATH_IDLE_MS	30000	/* Default path idle timeout */
#define TQUIC_MIN_PATH_PRIORITY		0	/* Minimum path priority */
#define TQUIC_MAX_PATH_PRIORITY		255	/* Maximum path priority */
#define TQUIC_MIN_PATH_WEIGHT		1	/* Minimum path weight */
#define TQUIC_MAX_PATH_WEIGHT		65535	/* Maximum path weight */
#define TQUIC_QUALITY_SCORE_MAX		100	/* Maximum quality score */

/*
 * cmsg types for TQUIC sendmsg/recvmsg
 */
#define TQUIC_CMSG_PATH_ID		10	/* Specify path for message */
#define TQUIC_CMSG_PATH_HINT		11	/* Path preference hint */
#define TQUIC_CMSG_REDUNDANT		12	/* Send on all paths */

/*
 * Flags for path operations
 */
#define TQUIC_PATH_FLAG_PROBE_FIRST	0x01	/* Probe before activating */
#define TQUIC_PATH_FLAG_NO_FAILOVER	0x02	/* Don't use for failover */
#define TQUIC_PATH_FLAG_BACKUP_ONLY	0x04	/* Use only as backup */
#define TQUIC_PATH_FLAG_NO_DATA		0x08	/* Don't send data (probe only) */
#define TQUIC_PATH_FLAG_FORCE_ACTIVATE	0x10	/* Force activation */

#endif /* _UAPI_LINUX_TQUIC_H */
