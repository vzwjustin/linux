/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * TQUIC		Multipath QUIC with WAN bonding support for Linux
 *
 *		Definitions for TQUIC multipath protocol extension.
 *		Enables simultaneous use of multiple network paths for
 *		bandwidth aggregation and seamless failover.
 *
 * Authors:	Linux TQUIC Team
 */
#ifndef _NET_TQUIC_H
#define _NET_TQUIC_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <net/quic.h>

/* Forward declarations */
struct tquic_path;
struct tquic_path_manager;
struct tquic_scheduler;
struct tquic_scheduler_ops;
struct tquic_wan_interface;
struct tquic_bonding_group;

/*
 * TQUIC protocol constants
 */
#define TQUIC_MAX_PATHS			8
#define TQUIC_PATH_CHALLENGE_LEN	8
#define TQUIC_PATH_PROBE_INTERVAL_MS	1000
#define TQUIC_PATH_TIMEOUT_MS		30000
#define TQUIC_BANDWIDTH_SAMPLE_WINDOW	10

/* Path states */
enum tquic_path_state {
	TQUIC_PATH_STATE_UNUSED = 0,
	TQUIC_PATH_STATE_PENDING,	/* Awaiting validation */
	TQUIC_PATH_STATE_VALIDATING,	/* PATH_CHALLENGE sent */
	TQUIC_PATH_STATE_ACTIVE,	/* Fully validated and usable */
	TQUIC_PATH_STATE_STANDBY,	/* Valid but not actively used */
	TQUIC_PATH_STATE_DEGRADED,	/* High loss or latency detected */
	TQUIC_PATH_STATE_FAILED,	/* Path has failed */
	TQUIC_PATH_STATE_CLOSING,	/* Being torn down */
};

/* Path flags */
#define TQUIC_PATH_FLAG_PRIMARY		BIT(0)	/* Primary path for connection */
#define TQUIC_PATH_FLAG_BACKUP		BIT(1)	/* Backup path */
#define TQUIC_PATH_FLAG_VALIDATED	BIT(2)	/* Path validated via challenge */
#define TQUIC_PATH_FLAG_ECN_CAPABLE	BIT(3)	/* ECN supported on this path */
#define TQUIC_PATH_FLAG_MTU_PROBING	BIT(4)	/* MTU discovery in progress */
#define TQUIC_PATH_FLAG_SCHEDULED	BIT(5)	/* Currently being used by scheduler */
#define TQUIC_PATH_FLAG_LOCAL_CHANGE	BIT(6)	/* Local address changed */
#define TQUIC_PATH_FLAG_PEER_CHANGE	BIT(7)	/* Peer address changed */

/* Scheduler types */
enum tquic_scheduler_type {
	TQUIC_SCHED_ROUND_ROBIN = 0,	/* Simple round-robin */
	TQUIC_SCHED_LOWEST_LATENCY,	/* Prefer lowest RTT path */
	TQUIC_SCHED_REDUNDANT,		/* Send on all paths */
	TQUIC_SCHED_WEIGHTED,		/* Weighted by bandwidth */
	TQUIC_SCHED_BLEST,		/* BLEST algorithm */
	TQUIC_SCHED_ECF,		/* Earliest Completion First */
	TQUIC_SCHED_CUSTOM,		/* User-defined */
};

/* Path events for notifications */
enum tquic_path_event {
	TQUIC_PATH_EVENT_NEW = 0,	/* New path added */
	TQUIC_PATH_EVENT_ACTIVE,	/* Path became active */
	TQUIC_PATH_EVENT_STANDBY,	/* Path moved to standby */
	TQUIC_PATH_EVENT_DEGRADED,	/* Path performance degraded */
	TQUIC_PATH_EVENT_FAILED,	/* Path failed */
	TQUIC_PATH_EVENT_REMOVED,	/* Path removed */
	TQUIC_PATH_EVENT_MTU_CHANGE,	/* Path MTU changed */
	TQUIC_PATH_EVENT_ADDR_CHANGE,	/* Address changed on path */
};

/* WAN interface types */
enum tquic_wan_type {
	TQUIC_WAN_TYPE_UNKNOWN = 0,
	TQUIC_WAN_TYPE_ETHERNET,
	TQUIC_WAN_TYPE_WIFI,
	TQUIC_WAN_TYPE_CELLULAR_4G,
	TQUIC_WAN_TYPE_CELLULAR_5G,
	TQUIC_WAN_TYPE_SATELLITE,
	TQUIC_WAN_TYPE_VPN,
};

/*
 * Bandwidth estimation sample
 */
struct tquic_bw_sample {
	u64			bytes_acked;
	ktime_t			interval;
	ktime_t			timestamp;
	u64			bandwidth;	/* bits per second */
	bool			app_limited;
};

/*
 * Path RTT measurements
 */
struct tquic_path_rtt {
	ktime_t			latest_rtt;
	ktime_t			smoothed_rtt;
	ktime_t			rttvar;
	ktime_t			min_rtt;
	ktime_t			max_rtt;
	u64			sample_count;
	ktime_t			last_sample_time;
};

/*
 * Path loss statistics
 */
struct tquic_path_loss_stats {
	u64			packets_sent;
	u64			packets_lost;
	u64			packets_retransmitted;
	u64			bytes_sent;
	u64			bytes_lost;
	u64			bytes_retransmitted;

	/* Rolling window loss tracking */
	u32			loss_window[16];
	u8			loss_window_idx;
	u32			current_loss_rate;	/* Per 10000 */
	ktime_t			last_loss_time;
};

/*
 * Path bandwidth estimation state
 */
struct tquic_path_bandwidth {
	u64			estimated_bw;		/* Current estimate (bps) */
	u64			max_bw;			/* Maximum observed */
	u64			min_bw;			/* Minimum observed */
	u64			available_bw;		/* Available bandwidth */

	/* Sample history */
	struct tquic_bw_sample	samples[TQUIC_BANDWIDTH_SAMPLE_WINDOW];
	u8			sample_idx;
	u8			sample_count;

	/* Delivery rate tracking */
	u64			delivered_bytes;
	ktime_t			delivered_time;
	u64			first_sent_time;
	u64			sent_bytes;

	/* Bottleneck detection */
	bool			bottleneck_detected;
	u64			bottleneck_bw;
	ktime_t			bottleneck_time;

	spinlock_t		lock;
};

/*
 * Path congestion control state (per-path)
 */
struct tquic_path_congestion {
	u64			cwnd;
	u64			ssthresh;
	u64			bytes_in_flight;
	u64			bytes_acked;

	bool			in_recovery;
	bool			in_slow_start;
	u64			recovery_start_pkt;

	/* Pacing */
	u64			pacing_rate;
	ktime_t			next_send_time;
	u32			pacing_gain;		/* Fixed point, 1024 = 1.0 */

	/* ECN state */
	u64			ecn_ce_count;
	bool			ecn_in_use;

	spinlock_t		lock;
};

/*
 * Path challenge/response tracking
 */
struct tquic_path_validation {
	u8			challenge_data[TQUIC_PATH_CHALLENGE_LEN];
	ktime_t			challenge_sent_time;
	u32			challenge_count;
	bool			challenge_pending;
	bool			response_received;

	/* Peer-initiated challenge */
	u8			peer_challenge[TQUIC_PATH_CHALLENGE_LEN];
	bool			peer_challenge_pending;
};

/*
 * TQUIC path structure
 *
 * Represents a single network path between local and remote endpoints
 */
struct tquic_path {
	struct list_head	list;		/* Link in path manager */
	struct rb_node		node;		/* For path lookup by ID */

	/* Path identification */
	u32			path_id;
	u8			local_cid[QUIC_MAX_CONNECTION_ID_LEN];
	u8			local_cid_len;
	u8			peer_cid[QUIC_MAX_CONNECTION_ID_LEN];
	u8			peer_cid_len;

	/* Addresses */
	struct sockaddr_storage	local_addr;
	struct sockaddr_storage	peer_addr;

	/* Network device binding */
	struct net_device	*net_dev;
	int			ifindex;
	char			ifname[IFNAMSIZ];

	/* Path state */
	enum tquic_path_state	state;
	unsigned long		flags;
	ktime_t			state_change_time;
	ktime_t			creation_time;
	ktime_t			last_activity;

	/* RTT measurements */
	struct tquic_path_rtt	rtt;

	/* Bandwidth estimation */
	struct tquic_path_bandwidth bandwidth;

	/* Loss statistics */
	struct tquic_path_loss_stats loss;

	/* Congestion control (per-path) */
	struct tquic_path_congestion congestion;

	/* Path validation */
	struct tquic_path_validation validation;

	/* Path MTU */
	u32			mtu;
	u32			pmtu;
	bool			pmtu_probe_pending;
	ktime_t			pmtu_probe_time;

	/* Packet counters */
	u64			packets_sent;
	u64			packets_received;
	u64			packets_acked;
	u64			bytes_sent;
	u64			bytes_received;
	u64			bytes_acked;

	/* Scheduling weight and priority */
	u32			weight;		/* For weighted scheduling */
	u8			priority;	/* 0 = highest */
	bool			schedulable;	/* Can be used for new data */

	/* ECN capability */
	bool			ecn_capable;
	u64			ecn_ect0_sent;
	u64			ecn_ect1_sent;
	u64			ecn_ce_received;

	/* Timer for path probing */
	struct timer_list	probe_timer;
	u32			probe_interval_ms;

	/* Backpointer */
	struct tquic_path_manager *pm;

	/* Reference counting */
	refcount_t		refcnt;
	struct rcu_head		rcu;
	spinlock_t		lock;
};

/*
 * Path notification callback
 */
typedef void (*tquic_path_notify_fn)(struct tquic_path_manager *pm,
				     struct tquic_path *path,
				     enum tquic_path_event event,
				     void *data);

/*
 * TQUIC path manager
 *
 * Manages multiple paths for a QUIC connection
 */
struct tquic_path_manager {
	/* Path storage */
	struct list_head	paths;		/* All paths */
	struct rb_root		paths_by_id;	/* Paths indexed by ID */
	u32			path_count;
	u32			active_path_count;
	u32			max_paths;

	/* Primary and backup tracking */
	struct tquic_path	*primary_path;
	struct tquic_path	*backup_path;

	/* Path ID allocation */
	u32			next_path_id;
	unsigned long		path_id_bitmap[BITS_TO_LONGS(TQUIC_MAX_PATHS)];

	/* Scheduler */
	struct tquic_scheduler	*scheduler;
	enum tquic_scheduler_type sched_type;

	/* Connection backpointer */
	struct quic_connection	*conn;

	/* Path discovery and monitoring */
	struct work_struct	discovery_work;
	struct work_struct	monitor_work;
	struct timer_list	monitor_timer;
	u32			monitor_interval_ms;
	bool			auto_discovery;
	bool			monitoring_enabled;

	/* Address change handling */
	bool			allow_migration;
	ktime_t			last_migration_time;
	u32			migration_count;

	/* Notification callback */
	tquic_path_notify_fn	notify_fn;
	void			*notify_data;

	/* WAN bonding integration */
	struct tquic_bonding_group *bonding_group;
	bool			bonding_enabled;

	/* Aggregate statistics */
	u64			total_bytes_sent;
	u64			total_bytes_received;
	u64			aggregate_bandwidth;

	/* Reference counting and synchronization */
	refcount_t		refcnt;
	rwlock_t		lock;		/* Protects path list */
	spinlock_t		state_lock;	/* Protects state changes */
};

/*
 * TQUIC scheduler context for scheduling decisions
 */
struct tquic_sched_ctx {
	struct quic_stream	*stream;	/* Stream being scheduled (may be NULL) */
	u32			data_len;	/* Bytes to send */
	u8			frame_type;	/* Type of frame to send */
	bool			retransmit;	/* Is this a retransmission */
	bool			ack_eliciting;	/* Requires acknowledgment */
	ktime_t			deadline;	/* Optional deadline */
	u8			priority;	/* Scheduling priority */
};

/*
 * TQUIC scheduler operations
 *
 * Virtual function table for path schedulers
 */
struct tquic_scheduler_ops {
	const char		*name;

	/* Initialize scheduler state */
	int			(*init)(struct tquic_scheduler *sched);

	/* Release scheduler resources */
	void			(*release)(struct tquic_scheduler *sched);

	/* Select a path for sending */
	struct tquic_path	*(*select_path)(struct tquic_scheduler *sched,
						struct tquic_sched_ctx *ctx);

	/* Called when a packet is sent */
	void			(*on_packet_sent)(struct tquic_scheduler *sched,
						  struct tquic_path *path,
						  u32 bytes);

	/* Called when a packet is acknowledged */
	void			(*on_packet_acked)(struct tquic_scheduler *sched,
						   struct tquic_path *path,
						   u32 bytes,
						   ktime_t rtt);

	/* Called when a packet is lost */
	void			(*on_packet_lost)(struct tquic_scheduler *sched,
						  struct tquic_path *path,
						  u32 bytes);

	/* Called when path state changes */
	void			(*on_path_change)(struct tquic_scheduler *sched,
						  struct tquic_path *path,
						  enum tquic_path_event event);

	/* Update scheduler parameters */
	int			(*set_param)(struct tquic_scheduler *sched,
					     int param, u64 value);

	/* Get scheduler statistics */
	void			(*get_stats)(struct tquic_scheduler *sched,
					     void *stats, size_t len);

	struct module		*owner;
	struct list_head	list;
};

/*
 * TQUIC scheduler structure
 */
struct tquic_scheduler {
	const struct tquic_scheduler_ops *ops;
	struct tquic_path_manager *pm;

	/* Scheduler type and name */
	enum tquic_scheduler_type type;
	char			name[32];

	/* Round-robin state */
	struct tquic_path	*rr_last_path;
	u32			rr_counter;

	/* Weighted scheduling state */
	u32			*path_weights;
	u32			*path_credits;
	u32			total_weight;

	/* BLEST/ECF state */
	ktime_t			*path_completion_time;
	u64			*path_estimated_rate;

	/* Redundant scheduling state */
	bool			redundant_enabled;
	u32			redundancy_level;	/* 1-N paths */

	/* Custom scheduler data */
	void			*priv_data;
	u32			priv_data_len;

	/* Statistics */
	u64			decisions_made;
	u64			paths_switched;
	u64			reinjections;

	spinlock_t		lock;
	refcount_t		refcnt;
};

/*
 * WAN interface tracking
 */
struct tquic_wan_interface {
	struct list_head	list;
	struct net_device	*dev;
	int			ifindex;
	char			ifname[IFNAMSIZ];
	enum tquic_wan_type	type;

	/* Interface state */
	bool			up;
	bool			running;
	bool			available;

	/* Interface characteristics */
	u64			bandwidth;	/* Estimated bandwidth (bps) */
	u32			latency_ms;	/* Typical latency */
	u32			jitter_ms;	/* Typical jitter */
	u32			loss_rate;	/* Per 10000 */
	u32			mtu;

	/* Cost metrics (for metered connections) */
	bool			metered;
	u32			cost_per_mb;	/* Cost per megabyte */
	u64			bytes_quota;	/* Monthly quota */
	u64			bytes_used;	/* Bytes used this period */

	/* Preference */
	u8			priority;	/* Lower = more preferred */
	u32			weight;		/* For weighted selection */
	bool			allow_new_connections;
	bool			allow_migration;

	/* Statistics */
	u64			bytes_sent;
	u64			bytes_received;
	u64			connections_count;

	/* Notifier for interface changes */
	struct notifier_block	notifier;

	refcount_t		refcnt;
	spinlock_t		lock;
	struct rcu_head		rcu;
};

/*
 * WAN bonding group - groups interfaces for bonding
 */
struct tquic_bonding_group {
	struct list_head	interfaces;	/* List of WAN interfaces */
	u32			interface_count;

	/* Bonding policy */
	enum tquic_scheduler_type default_scheduler;
	bool			balance_on_stream;	/* Balance per-stream */
	bool			allow_cross_wan;	/* Allow multi-WAN paths */

	/* Failover configuration */
	bool			failover_enabled;
	u32			failover_timeout_ms;
	bool			failback_enabled;
	u32			failback_delay_ms;

	/* Aggregate bandwidth tracking */
	u64			total_bandwidth;
	u64			available_bandwidth;

	/* Active paths across all connections */
	atomic_t		active_connections;
	atomic_t		active_paths;

	/* Global statistics */
	atomic64_t		total_bytes_sent;
	atomic64_t		total_bytes_received;

	rwlock_t		lock;
	refcount_t		refcnt;
};

/*
 * Path management functions
 */
struct tquic_path_manager *tquic_path_manager_alloc(struct quic_connection *conn,
						    gfp_t gfp);
void tquic_path_manager_free(struct tquic_path_manager *pm);
int tquic_path_manager_init(struct tquic_path_manager *pm);
void tquic_path_manager_release(struct tquic_path_manager *pm);

/* Path operations */
struct tquic_path *tquic_path_alloc(struct tquic_path_manager *pm, gfp_t gfp);
void tquic_path_free(struct tquic_path *path);
void tquic_path_hold(struct tquic_path *path);
void tquic_path_put(struct tquic_path *path);

int tquic_path_add(struct tquic_path_manager *pm,
		   struct sockaddr_storage *local_addr,
		   struct sockaddr_storage *peer_addr,
		   struct net_device *dev);
int tquic_path_remove(struct tquic_path_manager *pm, u32 path_id);
struct tquic_path *tquic_path_lookup(struct tquic_path_manager *pm, u32 path_id);
struct tquic_path *tquic_path_lookup_by_addr(struct tquic_path_manager *pm,
					     struct sockaddr_storage *local,
					     struct sockaddr_storage *peer);
struct tquic_path *tquic_path_lookup_by_cid(struct tquic_path_manager *pm,
					    const u8 *cid, u8 cid_len);

/* Path state management */
int tquic_path_set_state(struct tquic_path *path, enum tquic_path_state state);
int tquic_path_set_primary(struct tquic_path_manager *pm, u32 path_id);
int tquic_path_set_backup(struct tquic_path_manager *pm, u32 path_id);
bool tquic_path_is_usable(struct tquic_path *path);
bool tquic_path_is_active(struct tquic_path *path);

/* Path validation */
int tquic_path_validate(struct tquic_path *path);
int tquic_path_send_challenge(struct tquic_path *path);
int tquic_path_handle_challenge(struct tquic_path *path, const u8 *data);
int tquic_path_handle_response(struct tquic_path *path, const u8 *data);

/* Path measurements */
void tquic_path_update_rtt(struct tquic_path *path, ktime_t rtt);
void tquic_path_update_bandwidth(struct tquic_path *path, u64 bytes,
				 ktime_t interval);
void tquic_path_record_loss(struct tquic_path *path, u32 packets, u64 bytes);
u32 tquic_path_get_loss_rate(struct tquic_path *path);
u64 tquic_path_get_bandwidth(struct tquic_path *path);
ktime_t tquic_path_get_rtt(struct tquic_path *path);

/* Path MTU discovery */
int tquic_path_start_pmtu_discovery(struct tquic_path *path);
void tquic_path_update_pmtu(struct tquic_path *path, u32 pmtu);
void tquic_path_pmtu_probe_complete(struct tquic_path *path, bool success);

/*
 * Scheduler functions
 */
struct tquic_scheduler *tquic_scheduler_alloc(struct tquic_path_manager *pm,
					      enum tquic_scheduler_type type,
					      gfp_t gfp);
void tquic_scheduler_free(struct tquic_scheduler *sched);
int tquic_scheduler_init(struct tquic_scheduler *sched);
void tquic_scheduler_release(struct tquic_scheduler *sched);

/* Scheduler selection */
struct tquic_path *tquic_scheduler_select_path(struct tquic_scheduler *sched,
					       struct tquic_sched_ctx *ctx);
struct tquic_path *tquic_scheduler_select_for_retransmit(struct tquic_scheduler *sched,
							 struct tquic_path *orig_path,
							 u32 bytes);

/* Scheduler events */
void tquic_scheduler_on_packet_sent(struct tquic_scheduler *sched,
				    struct tquic_path *path, u32 bytes);
void tquic_scheduler_on_packet_acked(struct tquic_scheduler *sched,
				     struct tquic_path *path, u32 bytes,
				     ktime_t rtt);
void tquic_scheduler_on_packet_lost(struct tquic_scheduler *sched,
				    struct tquic_path *path, u32 bytes);
void tquic_scheduler_on_path_change(struct tquic_scheduler *sched,
				    struct tquic_path *path,
				    enum tquic_path_event event);

/* Scheduler registration */
int tquic_scheduler_register(struct tquic_scheduler_ops *ops);
void tquic_scheduler_unregister(struct tquic_scheduler_ops *ops);
const struct tquic_scheduler_ops *tquic_scheduler_find(const char *name);
void tquic_scheduler_get_available(char *buf, size_t maxlen);

/*
 * WAN interface management
 */
struct tquic_wan_interface *tquic_wan_interface_alloc(struct net_device *dev,
						      gfp_t gfp);
void tquic_wan_interface_free(struct tquic_wan_interface *iface);
void tquic_wan_interface_hold(struct tquic_wan_interface *iface);
void tquic_wan_interface_put(struct tquic_wan_interface *iface);

int tquic_wan_interface_register(struct tquic_bonding_group *group,
				 struct net_device *dev,
				 enum tquic_wan_type type);
void tquic_wan_interface_unregister(struct tquic_bonding_group *group,
				    struct net_device *dev);
struct tquic_wan_interface *tquic_wan_interface_lookup(struct tquic_bonding_group *group,
						       int ifindex);
int tquic_wan_interface_set_priority(struct tquic_wan_interface *iface, u8 priority);
int tquic_wan_interface_set_weight(struct tquic_wan_interface *iface, u32 weight);
int tquic_wan_interface_set_metered(struct tquic_wan_interface *iface,
				    bool metered, u32 cost_per_mb, u64 quota);

/* WAN interface monitoring */
void tquic_wan_interface_update_stats(struct tquic_wan_interface *iface);
void tquic_wan_interface_update_state(struct tquic_wan_interface *iface);
bool tquic_wan_interface_is_available(struct tquic_wan_interface *iface);

/*
 * Bonding group management
 */
struct tquic_bonding_group *tquic_bonding_group_alloc(gfp_t gfp);
void tquic_bonding_group_free(struct tquic_bonding_group *group);
int tquic_bonding_group_init(struct tquic_bonding_group *group);
void tquic_bonding_group_release(struct tquic_bonding_group *group);

int tquic_bonding_group_add_interface(struct tquic_bonding_group *group,
				      struct tquic_wan_interface *iface);
void tquic_bonding_group_remove_interface(struct tquic_bonding_group *group,
					  struct tquic_wan_interface *iface);
struct tquic_wan_interface *tquic_bonding_group_select_interface(
					struct tquic_bonding_group *group,
					struct sockaddr_storage *dest);
void tquic_bonding_group_update_bandwidth(struct tquic_bonding_group *group);

/* Bonding policy */
int tquic_bonding_set_scheduler(struct tquic_bonding_group *group,
				enum tquic_scheduler_type type);
int tquic_bonding_set_failover(struct tquic_bonding_group *group,
			       bool enabled, u32 timeout_ms);
int tquic_bonding_set_failback(struct tquic_bonding_group *group,
			       bool enabled, u32 delay_ms);

/*
 * Path discovery and migration
 */
int tquic_discover_paths(struct tquic_path_manager *pm);
int tquic_migrate_to_path(struct tquic_path_manager *pm, struct tquic_path *path);
int tquic_migrate_to_address(struct tquic_path_manager *pm,
			     struct sockaddr_storage *local,
			     struct sockaddr_storage *peer);
void tquic_handle_nat_rebinding(struct tquic_path_manager *pm,
				struct sockaddr_storage *new_peer_addr);

/*
 * Connection integration
 */
int tquic_connection_enable_multipath(struct quic_connection *conn);
void tquic_connection_disable_multipath(struct quic_connection *conn);
int tquic_connection_set_scheduler(struct quic_connection *conn,
				   enum tquic_scheduler_type type);
int tquic_connection_add_path(struct quic_connection *conn,
			      struct sockaddr_storage *local,
			      struct sockaddr_storage *peer);
int tquic_connection_remove_path(struct quic_connection *conn, u32 path_id);

/*
 * Protocol registration
 */
int tquic_proto_init(void);
void tquic_proto_exit(void);

/*
 * Sysctl parameters
 */
extern int sysctl_tquic_max_paths;
extern int sysctl_tquic_path_probe_interval;
extern int sysctl_tquic_path_timeout;
extern int sysctl_tquic_default_scheduler;
extern int sysctl_tquic_auto_discovery;

/*
 * Inline helper functions
 */

static inline bool tquic_path_manager_has_paths(struct tquic_path_manager *pm)
{
	return pm->path_count > 0;
}

static inline bool tquic_path_manager_multipath_active(struct tquic_path_manager *pm)
{
	return pm->active_path_count > 1;
}

static inline struct tquic_path *tquic_path_manager_get_primary(
						struct tquic_path_manager *pm)
{
	return rcu_dereference(pm->primary_path);
}

static inline void tquic_path_lock(struct tquic_path *path)
{
	spin_lock_bh(&path->lock);
}

static inline void tquic_path_unlock(struct tquic_path *path)
{
	spin_unlock_bh(&path->lock);
}

static inline void tquic_path_manager_read_lock(struct tquic_path_manager *pm)
{
	read_lock_bh(&pm->lock);
}

static inline void tquic_path_manager_read_unlock(struct tquic_path_manager *pm)
{
	read_unlock_bh(&pm->lock);
}

static inline void tquic_path_manager_write_lock(struct tquic_path_manager *pm)
{
	write_lock_bh(&pm->lock);
}

static inline void tquic_path_manager_write_unlock(struct tquic_path_manager *pm)
{
	write_unlock_bh(&pm->lock);
}

static inline u64 tquic_path_bytes_in_flight(struct tquic_path *path)
{
	return READ_ONCE(path->congestion.bytes_in_flight);
}

static inline bool tquic_path_can_send(struct tquic_path *path, u32 bytes)
{
	return tquic_path_bytes_in_flight(path) + bytes <=
	       READ_ONCE(path->congestion.cwnd);
}

static inline ktime_t tquic_path_smoothed_rtt(struct tquic_path *path)
{
	return READ_ONCE(path->rtt.smoothed_rtt);
}

static inline u32 tquic_path_current_loss_rate(struct tquic_path *path)
{
	return READ_ONCE(path->loss.current_loss_rate);
}

#define tquic_for_each_path(__pm, __path)				\
	list_for_each_entry(__path, &(__pm)->paths, list)

#define tquic_for_each_path_safe(__pm, __path, __tmp)			\
	list_for_each_entry_safe(__path, __tmp, &(__pm)->paths, list)

#define tquic_for_each_path_rcu(__pm, __path)				\
	list_for_each_entry_rcu(__path, &(__pm)->paths, list)

#define tquic_for_each_active_path(__pm, __path)			\
	list_for_each_entry(__path, &(__pm)->paths, list)		\
		if (tquic_path_is_active(__path))

#define tquic_for_each_wan_interface(__group, __iface)			\
	list_for_each_entry(__iface, &(__group)->interfaces, list)

#define tquic_for_each_wan_interface_safe(__group, __iface, __tmp)	\
	list_for_each_entry_safe(__iface, __tmp, &(__group)->interfaces, list)

/*
 * Debug and statistics
 */
#ifdef CONFIG_TQUIC_DEBUG
void tquic_debug_dump_path(struct tquic_path *path);
void tquic_debug_dump_path_manager(struct tquic_path_manager *pm);
void tquic_debug_dump_scheduler(struct tquic_scheduler *sched);
#else
static inline void tquic_debug_dump_path(struct tquic_path *path) {}
static inline void tquic_debug_dump_path_manager(struct tquic_path_manager *pm) {}
static inline void tquic_debug_dump_scheduler(struct tquic_scheduler *sched) {}
#endif

/*
 * Statistics structures for userspace
 */
struct tquic_path_stats {
	u32			path_id;
	enum tquic_path_state	state;
	u64			packets_sent;
	u64			packets_received;
	u64			packets_lost;
	u64			bytes_sent;
	u64			bytes_received;
	u64			bandwidth_bps;
	u32			rtt_us;
	u32			rttvar_us;
	u32			min_rtt_us;
	u32			loss_rate;		/* Per 10000 */
	u32			cwnd;
	u32			ssthresh;
	u32			mtu;
};

struct tquic_path_manager_stats {
	u32			path_count;
	u32			active_path_count;
	u64			total_bytes_sent;
	u64			total_bytes_received;
	u64			aggregate_bandwidth;
	u32			scheduler_decisions;
	u32			path_switches;
	u32			migrations;
};

int tquic_get_path_stats(struct tquic_path *path, struct tquic_path_stats *stats);
int tquic_get_path_manager_stats(struct tquic_path_manager *pm,
				 struct tquic_path_manager_stats *stats);

#endif /* _NET_TQUIC_H */
