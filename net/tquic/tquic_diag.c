// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC socket monitoring support
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides sock_diag netlink interface for TQUIC sockets,
 * enabling tools like ss to display TQUIC connection information.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/tquic.h>
#include <uapi/linux/tquic.h>

/*
 * TQUIC diagnostic context for iteration
 */
struct tquic_diag_ctx {
	long s_slot;
	long s_num;
	unsigned int l_slot;
	unsigned int l_num;
};

/*
 * TQUIC info structure for userspace
 * This matches struct tquic_multipath_info from UAPI
 */
struct tquic_diag_info {
	__u8		multipath_enabled;
	__u8		scheduler_type;
	__u8		bonding_mode;
	__u8		num_paths;
	__u8		num_active;
	__u8		num_standby;
	__u8		num_failed;
	__u8		reserved;
	__u64		total_bytes_sent;
	__u64		total_bytes_received;
	__u64		total_packets_sent;
	__u64		total_packets_received;
	__u64		aggregate_bandwidth;
	__u64		effective_bandwidth;
	__u64		scheduler_decisions;
	__u64		path_switches;
	__u32		min_paths;
	__u32		max_paths;
	__u32		failover_timeout;
	__u32		probe_interval;
} __packed;

/*
 * Forward declarations for external TQUIC functions
 */
extern struct rhashtable tquic_conn_table;
extern const struct rhashtable_params tquic_conn_params;

/* Iterator for TQUIC connections */
struct tquic_connection *tquic_diag_iter_next(struct net *net,
					      long *s_slot, long *s_num);

/*
 * Fill in TQUIC-specific diagnostic information
 */
static void tquic_diag_fill_info(struct sock *sk, struct tquic_diag_info *info)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	int active = 0, standby = 0, failed = 0;

	memset(info, 0, sizeof(*info));

	/* Get TQUIC connection from socket - accessing through quic_sock */
	conn = ((struct quic_sock *)sk)->conn;
	if (!conn)
		return;

	/* Basic info */
	info->multipath_enabled = !list_empty(&conn->paths);

	/* Count paths by state */
	list_for_each_entry(path, &conn->paths, list) {
		switch (path->state) {
		case TQUIC_PATH_ACTIVE:
			active++;
			break;
		case TQUIC_PATH_STANDBY:
			standby++;
			break;
		case TQUIC_PATH_FAILED:
			failed++;
			break;
		default:
			break;
		}
	}

	info->num_paths = conn->num_paths;
	info->num_active = active;
	info->num_standby = standby;
	info->num_failed = failed;

	/* Scheduler info */
	if (conn->scheduler) {
		info->scheduler_type = conn->scheduler->type;
		info->scheduler_decisions = conn->scheduler->decisions;
		info->path_switches = conn->scheduler->path_switches;
	}

	/* Statistics */
	info->total_bytes_sent = conn->stats.tx_bytes;
	info->total_bytes_received = conn->stats.rx_bytes;
	info->total_packets_sent = conn->stats.tx_packets;
	info->total_packets_received = conn->stats.rx_packets;

	/* Aggregate bandwidth (sum across active paths) */
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE) {
			info->aggregate_bandwidth += path->bandwidth.estimated_bw;
		}
	}
	info->effective_bandwidth = info->aggregate_bandwidth;

	/* Configuration */
	info->min_paths = 1;
	info->max_paths = TQUIC_MAX_PATHS;
	info->failover_timeout = TQUIC_DEFAULT_FAILOVER_MS;
	info->probe_interval = TQUIC_DEFAULT_PROBE_INTERVAL_MS;
}

/*
 * Dump a single TQUIC socket for diagnostics
 */
static int tquic_diag_dump_one(struct netlink_callback *cb,
			       const struct inet_diag_req_v2 *req)
{
	struct sk_buff *in_skb = cb->skb;
	struct net *net = sock_net(in_skb->sk);
	struct sk_buff *rep;
	struct sock *sk;
	struct tquic_connection *conn;
	int err = -ENOENT;

	/* Lookup connection by token (stored in cookie) */
	rcu_read_lock();
	/* Use connection lookup via global table */
	conn = NULL; /* TODO: Implement lookup by token */
	rcu_read_unlock();

	if (!conn)
		goto out_nosk;

	sk = conn->sk;
	if (!sk || !net_eq(sock_net(sk), net))
		goto out_nosk;

	err = -ENOMEM;
	rep = nlmsg_new(nla_total_size(sizeof(struct inet_diag_msg)) +
			inet_diag_msg_attrs_size() +
			nla_total_size(sizeof(struct tquic_diag_info)) +
			nla_total_size(sizeof(struct inet_diag_meminfo)) + 64,
			GFP_KERNEL);
	if (!rep)
		goto out;

	err = inet_sk_diag_fill(sk, inet_csk(sk), rep, cb, req, 0,
				netlink_net_capable(in_skb, CAP_NET_ADMIN));
	if (err < 0) {
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(rep);
		goto out;
	}

	err = nlmsg_unicast(net->diag_nlsk, rep, NETLINK_CB(in_skb).portid);

out:
	sock_put(sk);

out_nosk:
	return err;
}

/*
 * Check if socket matches filter and dump it
 */
static int sk_diag_dump(struct sock *sk, struct sk_buff *skb,
			struct netlink_callback *cb,
			const struct inet_diag_req_v2 *req,
			bool net_admin)
{
	if (!inet_diag_bc_sk(cb->data, sk))
		return 0;

	return inet_sk_diag_fill(sk, inet_csk(sk), skb, cb, req, NLM_F_MULTI,
				 net_admin);
}

/*
 * Iterate through TQUIC connections
 * This iterates through the global connection hashtable
 */
static struct tquic_connection *tquic_diag_iter_next_conn(struct net *net,
							  long *slot,
							  long *num)
{
	struct tquic_connection *conn = NULL;
	struct rhashtable_iter iter;
	int count = 0;
	long target = *num;

	rhashtable_walk_enter(&tquic_conn_table, &iter);
	rhashtable_walk_start(&iter);

	while ((conn = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(conn)) {
			if (PTR_ERR(conn) == -EAGAIN)
				continue;
			break;
		}

		if (!conn->sk || !net_eq(sock_net(conn->sk), net))
			continue;

		if (count >= target) {
			/* Found next connection */
			if (!refcount_inc_not_zero(&conn->refcnt))
				continue;
			(*num)++;
			break;
		}
		count++;
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	return IS_ERR(conn) ? NULL : conn;
}

/*
 * Dump all TQUIC connections
 */
static void tquic_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			    const struct inet_diag_req_v2 *r)
{
	bool net_admin = netlink_net_capable(cb->skb, CAP_NET_ADMIN);
	struct tquic_diag_ctx *diag_ctx = (void *)cb->ctx;
	struct net *net = sock_net(skb->sk);
	struct tquic_connection *conn;

	BUILD_BUG_ON(sizeof(cb->ctx) < sizeof(*diag_ctx));

	while ((conn = tquic_diag_iter_next_conn(net, &diag_ctx->s_slot,
						 &diag_ctx->s_num)) != NULL) {
		struct inet_sock *inet = inet_sk(conn->sk);
		struct sock *sk = conn->sk;
		int ret = 0;

		/* Filter by state */
		if (!(r->idiag_states & (1 << sk->sk_state)))
			goto next;

		/* Filter by family */
		if (r->sdiag_family != AF_UNSPEC &&
		    sk->sk_family != r->sdiag_family)
			goto next;

		/* Filter by source port */
		if (r->id.idiag_sport != inet->inet_sport &&
		    r->id.idiag_sport)
			goto next;

		/* Filter by destination port */
		if (r->id.idiag_dport != inet->inet_dport &&
		    r->id.idiag_dport)
			goto next;

		ret = sk_diag_dump(sk, skb, cb, r, net_admin);
next:
		/* Release connection reference */
		if (refcount_dec_and_test(&conn->refcnt))
			tquic_conn_destroy(conn);

		if (ret < 0) {
			/* Will retry on the same position */
			diag_ctx->s_num--;
			break;
		}
		cond_resched();
	}
}

/*
 * Get TQUIC-specific diagnostic info for a socket
 */
static void tquic_diag_get_info(struct sock *sk, struct inet_diag_msg *r,
				void *_info)
{
	struct tquic_diag_info *info = _info;
	struct tquic_connection *conn;

	/* Set queue sizes */
	r->idiag_rqueue = sk_rmem_alloc_get(sk);
	r->idiag_wqueue = sk_wmem_alloc_get(sk);

	/* Check if listening socket */
	if (inet_sk_state_load(sk) == TCP_LISTEN) {
		r->idiag_rqueue = READ_ONCE(sk->sk_ack_backlog);
		r->idiag_wqueue = READ_ONCE(sk->sk_max_ack_backlog);
	}

	if (!info)
		return;

	/* Get TQUIC connection and fill multipath info */
	conn = ((struct quic_sock *)sk)->conn;
	if (conn) {
		tquic_diag_fill_info(sk, info);
	} else {
		memset(info, 0, sizeof(*info));
	}
}

/*
 * TQUIC diagnostic handler registration
 */
static const struct inet_diag_handler tquic_diag_handler = {
	.owner		 = THIS_MODULE,
	.dump		 = tquic_diag_dump,
	.dump_one	 = tquic_diag_dump_one,
	.idiag_get_info  = tquic_diag_get_info,
	.idiag_type	 = IPPROTO_UDP, /* QUIC runs over UDP */
	.idiag_info_size = sizeof(struct tquic_diag_info),
};

/*
 * TQUIC diagnostic handler for IPv6
 */
static const struct inet_diag_handler tquic6_diag_handler = {
	.owner		 = THIS_MODULE,
	.dump		 = tquic_diag_dump,
	.dump_one	 = tquic_diag_dump_one,
	.idiag_get_info  = tquic_diag_get_info,
	.idiag_type	 = IPPROTO_UDP,
	.idiag_info_size = sizeof(struct tquic_diag_info),
};

/*
 * Proc file system interface for TQUIC connections
 * /proc/net/tquic_connections
 */
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static int tquic_seq_show(struct seq_file *seq, void *v)
{
	struct tquic_connection *conn = v;
	struct sock *sk;
	struct inet_sock *inet;
	struct tquic_path *path;
	int path_count = 0;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "  sl  local_address  remote_address  st  paths  active  tx_bytes  rx_bytes\n");
		return 0;
	}

	sk = conn->sk;
	if (!sk)
		return 0;

	inet = inet_sk(sk);

	/* Count active paths */
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE)
			path_count++;
	}

	seq_printf(seq, "%4d: %pI4:%04X %pI4:%04X %02X  %5d  %5d  %8llu  %8llu\n",
		   0, /* slot */
		   &inet->inet_saddr, ntohs(inet->inet_sport),
		   &inet->inet_daddr, ntohs(inet->inet_dport),
		   sk->sk_state,
		   conn->num_paths,
		   path_count,
		   conn->stats.tx_bytes,
		   conn->stats.rx_bytes);

	return 0;
}

static void *tquic_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(RCU)
{
	rcu_read_lock();
	if (*pos == 0)
		return SEQ_START_TOKEN;
	/* TODO: Return actual connection at position */
	return NULL;
}

static void *tquic_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	/* TODO: Return next connection */
	return NULL;
}

static void tquic_seq_stop(struct seq_file *seq, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

static const struct seq_operations tquic_seq_ops = {
	.start	= tquic_seq_start,
	.next	= tquic_seq_next,
	.stop	= tquic_seq_stop,
	.show	= tquic_seq_show,
};
#endif /* CONFIG_PROC_FS */

/*
 * Module initialization
 */
static int __init tquic_diag_init(void)
{
	int err;

	err = inet_diag_register(&tquic_diag_handler);
	if (err)
		return err;

#ifdef CONFIG_PROC_FS
	if (!proc_create_net("tquic_connections", 0444, init_net.proc_net,
			     &tquic_seq_ops, sizeof(struct seq_net_private))) {
		inet_diag_unregister(&tquic_diag_handler);
		return -ENOMEM;
	}
#endif

	pr_info("TQUIC: socket diagnostics registered\n");
	return 0;
}

static void __exit tquic_diag_exit(void)
{
#ifdef CONFIG_PROC_FS
	remove_proc_entry("tquic_connections", init_net.proc_net);
#endif
	inet_diag_unregister(&tquic_diag_handler);
	pr_info("TQUIC: socket diagnostics unregistered\n");
}

module_init(tquic_diag_init);
module_exit(tquic_diag_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC socket monitoring via SOCK_DIAG");
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 2-17 /* AF_INET - IPPROTO_UDP */);
