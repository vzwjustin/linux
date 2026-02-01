// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Protocol Handler Registration with Deep Kernel Integration
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This file implements the protocol handler registration for TQUIC,
 * including inet_protosw registration, network namespace support,
 * proc/sysctl per-netns registration, socket creation callbacks,
 * complete packet processing, ICMP error handling, and BPF tracepoints.
 *
 * Based on patterns from net/sctp/protocol.c, net/ipv4/tcp_ipv4.c,
 * and net/mptcp/protocol.c
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sysctl.h>
#include <linux/inetdevice.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/hashtable.h>
#include <linux/rculist.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/inet_sock.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <linux/icmpv6.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/transp_v6.h>
#endif

#include <net/tquic.h>

/* Enable tracepoints */
#define CREATE_TRACE_POINTS
#include <trace/events/tquic.h>

/* Connection lookup hash table for incoming packets */
#define TQUIC_CONN_HASH_BITS	10
static DEFINE_HASHTABLE(tquic_conn_hash, TQUIC_CONN_HASH_BITS);
static DEFINE_SPINLOCK(tquic_conn_hash_lock);

/* QUIC packet header constants */
#define QUIC_FORM_BIT		0x80
#define QUIC_FIXED_BIT		0x40
#define QUIC_MAX_CID_LEN	20

/* Network namespace identifier */
static unsigned int tquic_net_id __read_mostly;

/*
 * Per-network namespace TQUIC data
 */
struct tquic_net {
	/* Sysctl parameters */
	int enabled;
	int bond_mode;
	int max_paths;
	int reorder_window;
	int probe_interval;
	int failover_timeout;
	int idle_timeout;
	int initial_rtt;
	int initial_cwnd;
	int debug_level;

	/* Proc entries */
	struct proc_dir_entry *proc_net_tquic;

	/* Sysctl header */
	struct ctl_table_header *sysctl_header;

	/* Connection tracking for this namespace */
	struct list_head connections;
	spinlock_t conn_lock;
	atomic_t conn_count;

	/* Statistics */
	atomic64_t total_tx_bytes;
	atomic64_t total_rx_bytes;
	atomic64_t total_connections;
};

/* Access per-netns data */
static inline struct tquic_net *tquic_pernet(const struct net *net)
{
	return net_generic(net, tquic_net_id);
}

/*
 * Forward declarations
 */
static int tquic_v4_rcv(struct sk_buff *skb);
static int tquic_v4_err(struct sk_buff *skb, u32 info);

#if IS_ENABLED(CONFIG_IPV6)
static int tquic_v6_rcv(struct sk_buff *skb);
static int tquic_v6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
			u8 type, u8 code, int offset, __be32 info);
#endif

/* Scheduler/congestion helper stubs if not defined elsewhere */
__weak struct tquic_sched_ops *tquic_sched_find(const char *name)
{
	return NULL;
}

__weak void tquic_sched_set_default(const char *name)
{
}

__weak void *tquic_bond_init(struct tquic_connection *conn)
{
	return NULL;
}

__weak void tquic_bond_cleanup(void *scheduler)
{
}

__weak int tquic_bond_set_mode(struct tquic_connection *conn, int mode)
{
	return 0;
}

__weak int tquic_bond_get_stats(struct tquic_connection *conn,
				struct tquic_bond_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	return 0;
}

/*
 * Connection hash lookup functions
 */

static u32 tquic_conn_hash_fn(const u8 *cid, u8 cid_len)
{
	return jhash(cid, cid_len, 0);
}

/**
 * tquic_conn_lookup - Find connection by connection ID
 * @cid: Connection ID bytes
 * @cid_len: Length of connection ID
 *
 * Returns: Connection with incremented refcount, or NULL
 */
struct tquic_connection *tquic_conn_lookup(const u8 *cid, u8 cid_len)
{
	struct tquic_connection *conn;
	u32 hash;

	if (!cid || cid_len == 0 || cid_len > QUIC_MAX_CID_LEN)
		return NULL;

	hash = tquic_conn_hash_fn(cid, cid_len);

	rcu_read_lock();
	hash_for_each_possible_rcu(tquic_conn_hash, conn, hash_node, hash) {
		if (conn->scid.len == cid_len &&
		    memcmp(conn->scid.id, cid, cid_len) == 0) {
			if (refcount_inc_not_zero(&conn->refcnt)) {
				rcu_read_unlock();
				return conn;
			}
		}
		if (conn->dcid.len == cid_len &&
		    memcmp(conn->dcid.id, cid, cid_len) == 0) {
			if (refcount_inc_not_zero(&conn->refcnt)) {
				rcu_read_unlock();
				return conn;
			}
		}
	}
	rcu_read_unlock();

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_conn_lookup);

/**
 * tquic_conn_insert - Insert connection into hash table
 * @conn: Connection to insert
 */
void tquic_conn_insert(struct tquic_connection *conn)
{
	u32 hash;

	if (!conn || conn->scid.len == 0)
		return;

	hash = tquic_conn_hash_fn(conn->scid.id, conn->scid.len);

	spin_lock_bh(&tquic_conn_hash_lock);
	hash_add_rcu(tquic_conn_hash, &conn->hash_node, hash);
	spin_unlock_bh(&tquic_conn_hash_lock);
}
EXPORT_SYMBOL_GPL(tquic_conn_insert);

/**
 * tquic_conn_remove - Remove connection from hash table
 * @conn: Connection to remove
 */
void tquic_conn_remove(struct tquic_connection *conn)
{
	if (!conn)
		return;

	spin_lock_bh(&tquic_conn_hash_lock);
	hash_del_rcu(&conn->hash_node);
	spin_unlock_bh(&tquic_conn_hash_lock);
}
EXPORT_SYMBOL_GPL(tquic_conn_remove);

/*
 * QUIC packet parsing helpers
 */

/**
 * tquic_parse_quic_header - Parse QUIC packet header
 * @data: Packet data (after UDP header)
 * @len: Data length
 * @dcid: Output destination connection ID
 * @dcid_len: Output DCID length
 * @is_long: Output whether long header format
 *
 * Returns: 0 on success, negative on error
 */
static int tquic_parse_quic_header(const u8 *data, size_t len,
				   u8 *dcid, u8 *dcid_len, bool *is_long)
{
	const u8 *p = data;
	u8 first_byte;

	if (len < 1)
		return -EINVAL;

	first_byte = *p++;
	len--;

	/* Verify fixed bit (QUIC invariant) */
	if (!(first_byte & QUIC_FIXED_BIT))
		return -EINVAL;

	*is_long = !!(first_byte & QUIC_FORM_BIT);

	if (*is_long) {
		/* Long header: skip version (4 bytes) */
		if (len < 5)
			return -EINVAL;
		p += 4;
		len -= 4;

		/* DCID length */
		*dcid_len = *p++;
		len--;
		if (*dcid_len > QUIC_MAX_CID_LEN || len < *dcid_len)
			return -EINVAL;

		memcpy(dcid, p, *dcid_len);
	} else {
		/* Short header: DCID follows immediately
		 * We don't know the expected length without connection state,
		 * so use a reasonable default
		 */
		*dcid_len = min_t(size_t, 8, len);
		memcpy(dcid, p, *dcid_len);
	}

	return 0;
}

/*
 * IPv4 Protocol Handler
 */

/**
 * tquic_v4_rcv - IPv4 receive handler for TQUIC packets
 * @skb: Received socket buffer
 *
 * This is the main entry point for TQUIC packets received over IPv4.
 * It parses the QUIC header, looks up the connection, and delivers
 * the packet to the appropriate handler.
 *
 * Returns: 0 on success
 */
static int tquic_v4_rcv(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	struct tquic_net *tn = tquic_pernet(net);
	struct iphdr *iph;
	struct tquic_connection *conn = NULL;
	const u8 *quic_data;
	size_t quic_len;
	u8 dcid[QUIC_MAX_CID_LEN];
	u8 dcid_len = 0;
	bool is_long_header;
	int err;

	if (!tn->enabled) {
		kfree_skb(skb);
		return 0;
	}

	/* Ensure we have the IP header */
	if (!pskb_may_pull(skb, sizeof(struct iphdr))) {
		kfree_skb(skb);
		return 0;
	}

	iph = ip_hdr(skb);

	/* Get QUIC payload (skb->data should point past IP header) */
	quic_data = skb->data;
	quic_len = skb->len;

	if (quic_len < 1) {
		kfree_skb(skb);
		return 0;
	}

	/* Parse QUIC header to extract connection ID */
	err = tquic_parse_quic_header(quic_data, quic_len,
				      dcid, &dcid_len, &is_long_header);
	if (err) {
		pr_debug("tquic: failed to parse QUIC header\n");
		kfree_skb(skb);
		return 0;
	}

	/* Lookup connection by destination connection ID */
	if (dcid_len > 0)
		conn = tquic_conn_lookup(dcid, dcid_len);

	/* Update statistics */
	atomic64_add(skb->len, &tn->total_rx_bytes);

	if (conn) {
		struct tquic_path *path = NULL;

		/* Find the path this packet arrived on */
		if (conn->paths) {
			int i;
			for (i = 0; i < conn->num_paths; i++) {
				struct sockaddr_in *addr;
				addr = (struct sockaddr_in *)&conn->paths[i].local_addr;
				if (addr->sin_addr.s_addr == iph->daddr) {
					path = &conn->paths[i];
					break;
				}
			}
		}

		/* Update connection statistics */
		conn->stats.rx_packets++;
		conn->stats.rx_bytes += skb->len;

		/* Fire tracepoint */
		trace_tquic_packet_recv(conn, path, 0, skb->len,
					is_long_header ? 1 : 0);

		/* Deliver packet to connection handler */
		if (conn->sk) {
			struct tquic_sock *tsk = tquic_sk(conn->sk);

			/* Queue to socket receive buffer */
			if (tsk && tsk->default_stream) {
				skb_queue_tail(&tsk->default_stream->recv_buf, skb);
				conn->sk->sk_data_ready(conn->sk);
				tquic_conn_put(conn);
				return 0;
			}
		}

		tquic_conn_put(conn);
	} else {
		pr_debug("tquic: no connection found for DCID\n");
	}

	/* Packet not consumed, drop it */
	kfree_skb(skb);
	return 0;
}

/**
 * tquic_v4_err - IPv4 ICMP error handler for TQUIC
 * @skb: ICMP error packet
 * @info: ICMP info (e.g., MTU for PMTUD)
 *
 * Handles ICMP errors received for TQUIC packets:
 * - Destination Unreachable: Mark path as failed
 * - Packet Too Big: Update path MTU
 * - Time Exceeded: Increment TTL or mark path degraded
 *
 * Returns: 0 on success
 */
static int tquic_v4_err(struct sk_buff *skb, u32 info)
{
	const struct iphdr *iph;
	struct icmphdr *icmph;
	const u8 *quic_data;
	size_t quic_len;
	struct tquic_connection *conn;
	u8 dcid[QUIC_MAX_CID_LEN];
	u8 dcid_len = 0;
	bool is_long_header;
	int icmp_offset;
	u8 type, code;

	/* ICMP header is at skb->data, original IP header follows */
	icmph = icmp_hdr(skb);
	type = icmph->type;
	code = icmph->code;

	/* Get the original packet's IP header (embedded in ICMP) */
	icmp_offset = skb_transport_offset(skb) + sizeof(struct icmphdr);
	if (!pskb_may_pull(skb, icmp_offset + sizeof(struct iphdr)))
		return 0;

	iph = (const struct iphdr *)(skb->data + icmp_offset);

	/* Get QUIC data from the original packet */
	quic_data = (const u8 *)iph + (iph->ihl * 4);
	quic_len = ntohs(iph->tot_len) - (iph->ihl * 4);

	if (quic_len < 1)
		return 0;

	/* Parse QUIC header to find connection */
	if (tquic_parse_quic_header(quic_data, quic_len,
				    dcid, &dcid_len, &is_long_header) < 0)
		return 0;

	conn = tquic_conn_lookup(dcid, dcid_len);
	if (!conn) {
		pr_debug("tquic: ICMP error for unknown connection\n");
		return 0;
	}

	pr_debug("tquic: ICMP error type=%u code=%u info=%u\n", type, code, info);

	/* Fire tracepoint */
	trace_tquic_icmp_error(conn, NULL, type, code, info);

	/* Handle different ICMP types */
	switch (type) {
	case ICMP_DEST_UNREACH:
		switch (code) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
		case ICMP_PORT_UNREACH:
			/* Mark path as failed, trigger failover */
			if (conn->num_paths > 0) {
				struct tquic_path *path = &conn->paths[0];
				int i;

				/* Find the affected path */
				for (i = 0; i < conn->num_paths; i++) {
					struct sockaddr_in *addr;
					addr = (struct sockaddr_in *)&conn->paths[i].local_addr;
					if (addr->sin_addr.s_addr == iph->saddr) {
						path = &conn->paths[i];
						break;
					}
				}

				trace_tquic_path_state_change(conn, path,
							      path->state,
							      TQUIC_PATH_FAILED);
				path->state = TQUIC_PATH_FAILED;
				path->fail_count++;

				/* Trigger failover if we have multiple paths */
				if (conn->num_paths > 1)
					tquic_trigger_failover(conn, path);
			}
			break;

		case ICMP_FRAG_NEEDED:
			/* Path MTU discovery - update MTU */
			if (info > 0 && conn->num_paths > 0) {
				u32 new_mtu = info;
				int i;

				for (i = 0; i < conn->num_paths; i++) {
					struct sockaddr_in *addr;
					addr = (struct sockaddr_in *)&conn->paths[i].local_addr;
					if (addr->sin_addr.s_addr == iph->saddr) {
						conn->paths[i].mtu = min(conn->paths[i].mtu, new_mtu);
						pr_debug("tquic: path %d MTU updated to %u\n",
							 i, conn->paths[i].mtu);
						break;
					}
				}
			}
			break;
		}
		break;

	case ICMP_TIME_EXCEEDED:
		/* TTL exceeded - path may have routing issues */
		if (conn->num_paths > 0) {
			/* Mark path as degraded */
			conn->paths[0].state = TQUIC_PATH_DEGRADED;
		}
		break;

	case ICMP_PARAMETERPROB:
		/* Parameter problem - usually indicates configuration issue */
		break;

	default:
		break;
	}

	tquic_conn_put(conn);
	return 0;
}

/* IPv4 net_protocol definition */
static const struct net_protocol tquic_protocol = {
	.handler	= tquic_v4_rcv,
	.err_handler	= tquic_v4_err,
	.no_policy	= 1,
};

/*
 * IPv6 Protocol Handler
 */
#if IS_ENABLED(CONFIG_IPV6)

/**
 * tquic_v6_rcv - IPv6 receive handler for TQUIC packets
 * @skb: Received socket buffer
 *
 * This is the main entry point for TQUIC packets received over IPv6.
 *
 * Returns: 0 on success
 */
static int tquic_v6_rcv(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	struct tquic_net *tn = tquic_pernet(net);
	struct ipv6hdr *ip6h;
	struct tquic_connection *conn = NULL;
	const u8 *quic_data;
	size_t quic_len;
	u8 dcid[QUIC_MAX_CID_LEN];
	u8 dcid_len = 0;
	bool is_long_header;
	int err;

	if (!tn->enabled) {
		kfree_skb(skb);
		return 0;
	}

	/* Ensure we have the IPv6 header */
	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr))) {
		kfree_skb(skb);
		return 0;
	}

	ip6h = ipv6_hdr(skb);

	/* Get QUIC payload */
	quic_data = skb->data;
	quic_len = skb->len;

	if (quic_len < 1) {
		kfree_skb(skb);
		return 0;
	}

	/* Parse QUIC header to extract connection ID */
	err = tquic_parse_quic_header(quic_data, quic_len,
				      dcid, &dcid_len, &is_long_header);
	if (err) {
		pr_debug("tquic: failed to parse QUIC header (v6)\n");
		kfree_skb(skb);
		return 0;
	}

	/* Lookup connection by destination connection ID */
	if (dcid_len > 0)
		conn = tquic_conn_lookup(dcid, dcid_len);

	/* Update statistics */
	atomic64_add(skb->len, &tn->total_rx_bytes);

	if (conn) {
		struct tquic_path *path = NULL;

		/* Find the path this packet arrived on */
		if (conn->paths) {
			int i;
			for (i = 0; i < conn->num_paths; i++) {
				struct sockaddr_in6 *addr;
				addr = (struct sockaddr_in6 *)&conn->paths[i].local_addr;
				if (addr->sin6_family == AF_INET6 &&
				    ipv6_addr_equal(&addr->sin6_addr, &ip6h->daddr)) {
					path = &conn->paths[i];
					break;
				}
			}
		}

		/* Update connection statistics */
		conn->stats.rx_packets++;
		conn->stats.rx_bytes += skb->len;

		/* Fire tracepoint */
		trace_tquic_packet_recv(conn, path, 0, skb->len,
					is_long_header ? 1 : 0);

		/* Deliver packet to connection handler */
		if (conn->sk) {
			struct tquic_sock *tsk = tquic_sk(conn->sk);

			if (tsk && tsk->default_stream) {
				skb_queue_tail(&tsk->default_stream->recv_buf, skb);
				conn->sk->sk_data_ready(conn->sk);
				tquic_conn_put(conn);
				return 0;
			}
		}

		tquic_conn_put(conn);
	} else {
		pr_debug("tquic: no connection found for DCID (v6)\n");
	}

	/* Packet not consumed, drop it */
	kfree_skb(skb);
	return 0;
}

/**
 * tquic_v6_err - IPv6 ICMPv6 error handler for TQUIC
 * @skb: ICMPv6 error packet
 * @opt: IPv6 extension header options
 * @type: ICMPv6 type
 * @code: ICMPv6 code
 * @offset: Offset to the offending header
 * @info: ICMPv6 info (e.g., MTU for Packet Too Big)
 *
 * Handles ICMPv6 errors for TQUIC connections:
 * - Destination Unreachable: Mark path as failed
 * - Packet Too Big: Update path MTU
 * - Time Exceeded: Mark path as degraded
 *
 * Returns: 0 on success
 */
static int tquic_v6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
			u8 type, u8 code, int offset, __be32 info)
{
	const struct ipv6hdr *ip6h;
	const u8 *quic_data;
	size_t quic_len;
	struct tquic_connection *conn;
	u8 dcid[QUIC_MAX_CID_LEN];
	u8 dcid_len = 0;
	bool is_long_header;
	int hdr_len;

	/* Get the original packet's IPv6 header (embedded in ICMPv6) */
	hdr_len = offset + sizeof(struct ipv6hdr);
	if (!pskb_may_pull(skb, hdr_len))
		return 0;

	ip6h = (const struct ipv6hdr *)(skb->data + offset);

	/* Get QUIC data from the original packet */
	quic_data = (const u8 *)ip6h + sizeof(struct ipv6hdr);
	quic_len = ntohs(ip6h->payload_len);

	if (quic_len < 1)
		return 0;

	/* Parse QUIC header to find connection */
	if (tquic_parse_quic_header(quic_data, quic_len,
				    dcid, &dcid_len, &is_long_header) < 0)
		return 0;

	conn = tquic_conn_lookup(dcid, dcid_len);
	if (!conn) {
		pr_debug("tquic: ICMPv6 error for unknown connection\n");
		return 0;
	}

	pr_debug("tquic: ICMPv6 error type=%u code=%u info=%u\n",
		 type, code, ntohl(info));

	/* Fire tracepoint */
	trace_tquic_icmp_error(conn, NULL, type, code, ntohl(info));

	/* Handle different ICMPv6 types */
	switch (type) {
	case ICMPV6_DEST_UNREACH:
		switch (code) {
		case ICMPV6_NOROUTE:
		case ICMPV6_ADDR_UNREACH:
		case ICMPV6_PORT_UNREACH:
			/* Mark path as failed, trigger failover */
			if (conn->num_paths > 0) {
				struct tquic_path *path = &conn->paths[0];
				int i;

				/* Find the affected path */
				for (i = 0; i < conn->num_paths; i++) {
					struct sockaddr_in6 *addr;
					addr = (struct sockaddr_in6 *)&conn->paths[i].local_addr;
					if (addr->sin6_family == AF_INET6 &&
					    ipv6_addr_equal(&addr->sin6_addr, &ip6h->saddr)) {
						path = &conn->paths[i];
						break;
					}
				}

				trace_tquic_path_state_change(conn, path,
							      path->state,
							      TQUIC_PATH_FAILED);
				path->state = TQUIC_PATH_FAILED;
				path->fail_count++;

				/* Trigger failover if we have multiple paths */
				if (conn->num_paths > 1)
					tquic_trigger_failover(conn, path);
			}
			break;
		}
		break;

	case ICMPV6_PKT_TOOBIG:
		/* Path MTU discovery - update MTU */
		if (ntohl(info) > 0 && conn->num_paths > 0) {
			u32 new_mtu = ntohl(info);
			int i;

			for (i = 0; i < conn->num_paths; i++) {
				struct sockaddr_in6 *addr;
				addr = (struct sockaddr_in6 *)&conn->paths[i].local_addr;
				if (addr->sin6_family == AF_INET6 &&
				    ipv6_addr_equal(&addr->sin6_addr, &ip6h->saddr)) {
					conn->paths[i].mtu = min(conn->paths[i].mtu, new_mtu);
					pr_debug("tquic: path %d MTU updated to %u (v6)\n",
						 i, conn->paths[i].mtu);
					break;
				}
			}
		}
		break;

	case ICMPV6_TIME_EXCEED:
		/* Hop limit exceeded - path may have routing issues */
		if (conn->num_paths > 0) {
			conn->paths[0].state = TQUIC_PATH_DEGRADED;
		}
		break;

	case ICMPV6_PARAMPROB:
		/* Parameter problem */
		break;

	default:
		break;
	}

	tquic_conn_put(conn);
	return 0;
}

/* IPv6 net_protocol definition */
static const struct inet6_protocol tquicv6_protocol = {
	.handler	= tquic_v6_rcv,
	.err_handler	= tquic_v6_err,
	.flags		= INET6_PROTO_NOPOLICY | INET6_PROTO_FINAL,
};

#endif /* CONFIG_IPV6 */

/*
 * Socket Creation Callback
 */
static int tquic_create_socket(struct net *net, struct socket *sock,
			       int protocol, int kern)
{
	struct tquic_net *tn = tquic_pernet(net);
	struct sock *sk;
	int ret;

	if (!tn->enabled)
		return -EPROTONOSUPPORT;

	/* Validate socket type */
	if (sock->type != SOCK_STREAM && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;

	/* Let inet_create do the actual work via protosw */
	ret = inet_create(net, sock, protocol, kern);
	if (ret < 0)
		return ret;

	sk = sock->sk;

	/* Additional TQUIC-specific socket initialization */
	atomic64_inc(&tn->total_connections);

	pr_debug("created TQUIC socket, protocol=%d\n", protocol);

	return 0;
}

/*
 * IPv4 Socket Operations
 */

/* Socket release */
static int tquic_inet_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	return inet_release(sock);
}

/* IPv4 proto_ops */
static const struct proto_ops tquic_inet_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= tquic_inet_release,
	.bind		= inet_bind,
	.connect	= inet_stream_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= inet_accept,
	.getname	= inet_getname,
	.poll		= tcp_poll,
	.ioctl		= inet_ioctl,
	.listen		= inet_listen,
	.shutdown	= inet_shutdown,
	.setsockopt	= sock_common_setsockopt,
	.getsockopt	= sock_common_getsockopt,
	.sendmsg	= inet_sendmsg,
	.recvmsg	= inet_recvmsg,
	.mmap		= sock_no_mmap,
};

/* TQUIC protocol definition for IPv4 */
static struct proto tquic_prot = {
	.name		= "TQUIC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tquic_sock),
	.close		= tquic_close,
	.connect	= tquic_connect,
	.sendmsg	= tquic_sendmsg,
	.recvmsg	= tquic_recvmsg,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= inet_csk_get_port,
	.sockets_allocated = &tcp_sockets_allocated,
	.memory_allocated = &tcp_memory_allocated,
	.memory_pressure = &tcp_memory_pressure,
	.sysctl_mem	= sysctl_tcp_mem,
	.sysctl_wmem	= sysctl_tcp_wmem,
	.sysctl_rmem	= sysctl_tcp_rmem,
};

/* inet_protosw for TQUIC over IPv4 - SOCK_STREAM */
static struct inet_protosw tquic_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquic_prot,
	.ops		= &tquic_inet_ops,
	.flags		= INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK,
};

/* inet_protosw for TQUIC over IPv4 - SOCK_DGRAM (for connectionless mode) */
static struct inet_protosw tquic_dgram_protosw = {
	.type		= SOCK_DGRAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquic_prot,
	.ops		= &tquic_inet_ops,
	.flags		= INET_PROTOSW_PERMANENT,
};

/*
 * IPv6 Socket Operations
 */
#if IS_ENABLED(CONFIG_IPV6)

/* IPv6 proto_ops */
static const struct proto_ops tquic_inet6_ops = {
	.family		= PF_INET6,
	.owner		= THIS_MODULE,
	.release	= tquic_inet_release,
	.bind		= inet6_bind,
	.connect	= inet_stream_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= inet_accept,
	.getname	= inet6_getname,
	.poll		= tcp_poll,
	.ioctl		= inet6_ioctl,
	.listen		= inet_listen,
	.shutdown	= inet_shutdown,
	.setsockopt	= sock_common_setsockopt,
	.getsockopt	= sock_common_getsockopt,
	.sendmsg	= inet_sendmsg,
	.recvmsg	= inet_recvmsg,
	.mmap		= sock_no_mmap,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= inet6_compat_ioctl,
#endif
};

/* TQUIC protocol definition for IPv6 */
static struct proto tquicv6_prot = {
	.name		= "TQUICv6",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tquic_sock),
	.close		= tquic_close,
	.connect	= tquic_connect,
	.sendmsg	= tquic_sendmsg,
	.recvmsg	= tquic_recvmsg,
	.hash		= inet6_hash,
	.unhash		= inet_unhash,
	.get_port	= inet_csk_get_port,
	.sockets_allocated = &tcp_sockets_allocated,
	.memory_allocated = &tcp_memory_allocated,
	.memory_pressure = &tcp_memory_pressure,
	.sysctl_mem	= sysctl_tcp_mem,
	.sysctl_wmem	= sysctl_tcp_wmem,
	.sysctl_rmem	= sysctl_tcp_rmem,
};

/* inet6_protosw for TQUIC over IPv6 - SOCK_STREAM */
static struct inet_protosw tquicv6_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquicv6_prot,
	.ops		= &tquic_inet6_ops,
	.flags		= INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK,
};

/* inet6_protosw for TQUIC over IPv6 - SOCK_DGRAM */
static struct inet_protosw tquicv6_dgram_protosw = {
	.type		= SOCK_DGRAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquicv6_prot,
	.ops		= &tquic_inet6_ops,
	.flags		= INET_PROTOSW_PERMANENT,
};

#endif /* CONFIG_IPV6 */

/*
 * Net Protocol Family
 */
static const struct net_proto_family tquic_family_ops = {
	.family		= PF_INET,
	.create		= tquic_create_socket,
	.owner		= THIS_MODULE,
};

/*
 * Per-Network Namespace Sysctl
 */

/* Sysctl min/max values */
static int sysctl_zero;
static int sysctl_one = 1;
static int sysctl_max_paths = TQUIC_MAX_PATHS;
static int sysctl_max_reorder = 1024;
static int sysctl_max_timeout = 60000;
static int sysctl_max_rtt = 10000;
static int sysctl_max_cwnd = 10000;
static int sysctl_max_bond_mode = TQUIC_BOND_MODE_ECF;

/* Per-netns sysctl table template */
static struct ctl_table tquic_net_sysctl_table[] = {
	{
		.procname	= "enabled",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_zero,
		.extra2		= &sysctl_one,
	},
	{
		.procname	= "default_bond_mode",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_zero,
		.extra2		= &sysctl_max_bond_mode,
	},
	{
		.procname	= "max_paths",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_paths,
	},
	{
		.procname	= "reorder_window",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_reorder,
	},
	{
		.procname	= "probe_interval_ms",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_timeout,
	},
	{
		.procname	= "failover_timeout_ms",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_timeout,
	},
	{
		.procname	= "idle_timeout_ms",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_timeout,
	},
	{
		.procname	= "initial_rtt_ms",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_rtt,
	},
	{
		.procname	= "initial_cwnd_packets",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_cwnd,
	},
	{
		.procname	= "debug_level",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static int tquic_net_sysctl_register(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);
	struct ctl_table *table;
	int i;

	table = kmemdup(tquic_net_sysctl_table, sizeof(tquic_net_sysctl_table),
			GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	/* Link sysctl entries to per-netns data */
	i = 0;
	table[i++].data = &tn->enabled;
	table[i++].data = &tn->bond_mode;
	table[i++].data = &tn->max_paths;
	table[i++].data = &tn->reorder_window;
	table[i++].data = &tn->probe_interval;
	table[i++].data = &tn->failover_timeout;
	table[i++].data = &tn->idle_timeout;
	table[i++].data = &tn->initial_rtt;
	table[i++].data = &tn->initial_cwnd;
	table[i++].data = &tn->debug_level;

	tn->sysctl_header = register_net_sysctl(net, "net/tquic", table);
	if (!tn->sysctl_header) {
		kfree(table);
		return -ENOMEM;
	}

	return 0;
}

static void tquic_net_sysctl_unregister(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);
	struct ctl_table *table;

	if (tn->sysctl_header) {
		table = tn->sysctl_header->ctl_table_arg;
		unregister_net_sysctl_table(tn->sysctl_header);
		kfree(table);
		tn->sysctl_header = NULL;
	}
}

/*
 * Per-Network Namespace Proc Entries
 */

/* /proc/net/tquic/connections */
static int tquic_proc_connections_show(struct seq_file *s, void *v)
{
	struct net *net = seq_file_net(s);
	struct tquic_net *tn = tquic_pernet(net);

	seq_puts(s, "# TQUIC Connections (per-netns)\n");
	seq_puts(s, "# SCID State Paths Streams TxBytes RxBytes\n");

	spin_lock(&tn->conn_lock);
	/* TODO: Iterate through per-netns connection list */
	spin_unlock(&tn->conn_lock);

	seq_printf(s, "# Total connections: %d\n", atomic_read(&tn->conn_count));

	return 0;
}

/* /proc/net/tquic/paths */
static int tquic_proc_paths_show(struct seq_file *s, void *v)
{
	struct net *net = seq_file_net(s);
	struct tquic_net *tn = tquic_pernet(net);

	seq_puts(s, "# TQUIC Paths (WAN Bonding)\n");
	seq_puts(s, "# ConnID PathID State Prio Weight RTT(us) BW(Bps)\n");

	spin_lock(&tn->conn_lock);
	/* TODO: Iterate through paths */
	spin_unlock(&tn->conn_lock);

	return 0;
}

/* /proc/net/tquic/stats */
static int tquic_proc_stats_show(struct seq_file *s, void *v)
{
	struct net *net = seq_file_net(s);
	struct tquic_net *tn = tquic_pernet(net);

	seq_puts(s, "TQUIC Statistics (per-netns)\n");
	seq_puts(s, "============================\n");
	seq_printf(s, "Enabled:            %d\n", tn->enabled);
	seq_printf(s, "Active connections: %d\n", atomic_read(&tn->conn_count));
	seq_printf(s, "Total connections:  %llu\n",
		   atomic64_read(&tn->total_connections));
	seq_printf(s, "Bytes transmitted:  %llu\n",
		   atomic64_read(&tn->total_tx_bytes));
	seq_printf(s, "Bytes received:     %llu\n",
		   atomic64_read(&tn->total_rx_bytes));
	seq_printf(s, "Default bond mode:  %d\n", tn->bond_mode);
	seq_printf(s, "Max paths:          %d\n", tn->max_paths);
	seq_printf(s, "Reorder window:     %d\n", tn->reorder_window);
	seq_printf(s, "Probe interval:     %d ms\n", tn->probe_interval);
	seq_printf(s, "Failover timeout:   %d ms\n", tn->failover_timeout);
	seq_printf(s, "Idle timeout:       %d ms\n", tn->idle_timeout);
	seq_printf(s, "Initial RTT:        %d ms\n", tn->initial_rtt);
	seq_printf(s, "Initial cwnd:       %d\n", tn->initial_cwnd);

	return 0;
}

DEFINE_PROC_SHOW_ATTRIBUTE(tquic_proc_connections);
DEFINE_PROC_SHOW_ATTRIBUTE(tquic_proc_paths);
DEFINE_PROC_SHOW_ATTRIBUTE(tquic_proc_stats);

static int tquic_proc_init(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);

	tn->proc_net_tquic = proc_net_mkdir(net, "tquic", net->proc_net);
	if (!tn->proc_net_tquic)
		return -ENOMEM;

	if (!proc_create_net_single("connections", 0444, tn->proc_net_tquic,
				    tquic_proc_connections_show, NULL))
		goto err;

	if (!proc_create_net_single("paths", 0444, tn->proc_net_tquic,
				    tquic_proc_paths_show, NULL))
		goto err;

	if (!proc_create_net_single("stats", 0444, tn->proc_net_tquic,
				    tquic_proc_stats_show, NULL))
		goto err;

	return 0;

err:
	remove_proc_subtree("tquic", net->proc_net);
	tn->proc_net_tquic = NULL;
	return -ENOMEM;
}

static void tquic_proc_exit(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);

	if (tn->proc_net_tquic) {
		remove_proc_subtree("tquic", net->proc_net);
		tn->proc_net_tquic = NULL;
	}
}

/*
 * Per-Network Namespace Init/Exit
 */

/* Initialize per-netns TQUIC data and default values */
static int __net_init tquic_net_init(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);
	int ret;

	/* Initialize default values */
	tn->enabled = 1;
	tn->bond_mode = TQUIC_BOND_MODE_AGGREGATE;
	tn->max_paths = TQUIC_MAX_PATHS;
	tn->reorder_window = 64;
	tn->probe_interval = 1000;
	tn->failover_timeout = 3000;
	tn->idle_timeout = 30000;
	tn->initial_rtt = 100;
	tn->initial_cwnd = 10;
	tn->debug_level = 0;

	/* Initialize connection tracking */
	INIT_LIST_HEAD(&tn->connections);
	spin_lock_init(&tn->conn_lock);
	atomic_set(&tn->conn_count, 0);

	/* Initialize statistics */
	atomic64_set(&tn->total_tx_bytes, 0);
	atomic64_set(&tn->total_rx_bytes, 0);
	atomic64_set(&tn->total_connections, 0);

	/* Register sysctl */
	ret = tquic_net_sysctl_register(net);
	if (ret)
		return ret;

#ifdef CONFIG_PROC_FS
	/* Initialize proc entries */
	ret = tquic_proc_init(net);
	if (ret)
		goto err_proc;
#endif

	pr_debug("TQUIC initialized for netns\n");
	return 0;

#ifdef CONFIG_PROC_FS
err_proc:
	tquic_net_sysctl_unregister(net);
	return ret;
#endif
}

/* Cleanup per-netns TQUIC data */
static void __net_exit tquic_net_exit(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);

	/* TODO: Close all connections in this namespace */

#ifdef CONFIG_PROC_FS
	tquic_proc_exit(net);
#endif
	tquic_net_sysctl_unregister(net);

	/* Verify all connections are cleaned up */
	WARN_ON(atomic_read(&tn->conn_count) != 0);

	pr_debug("TQUIC exited for netns\n");
}

/* pernet_operations for TQUIC defaults */
static struct pernet_operations tquic_net_ops = {
	.init	= tquic_net_init,
	.exit	= tquic_net_exit,
	.id	= &tquic_net_id,
	.size	= sizeof(struct tquic_net),
};

/*
 * IPv4 Protocol Registration
 */
static int tquic_v4_protosw_init(void)
{
	int ret;

	ret = proto_register(&tquic_prot, 1);
	if (ret)
		return ret;

	/* Register TQUIC with socket layer */
	inet_register_protosw(&tquic_stream_protosw);
	inet_register_protosw(&tquic_dgram_protosw);

	pr_info("TQUIC IPv4 protosw registered\n");
	return 0;
}

static void tquic_v4_protosw_exit(void)
{
	inet_unregister_protosw(&tquic_dgram_protosw);
	inet_unregister_protosw(&tquic_stream_protosw);
	proto_unregister(&tquic_prot);
}

static int tquic_v4_add_protocol(void)
{
	if (inet_add_protocol(&tquic_protocol, IPPROTO_TQUIC) < 0) {
		pr_err("Failed to register TQUIC protocol handler\n");
		return -EAGAIN;
	}

	pr_info("TQUIC IPv4 protocol handler registered\n");
	return 0;
}

static void tquic_v4_del_protocol(void)
{
	inet_del_protocol(&tquic_protocol, IPPROTO_TQUIC);
}

/*
 * IPv6 Protocol Registration
 */
#if IS_ENABLED(CONFIG_IPV6)

static int tquic_v6_protosw_init(void)
{
	int ret;

	ret = proto_register(&tquicv6_prot, 1);
	if (ret)
		return ret;

	/* Register TQUICv6 with socket layer */
	inet6_register_protosw(&tquicv6_stream_protosw);
	inet6_register_protosw(&tquicv6_dgram_protosw);

	pr_info("TQUIC IPv6 protosw registered\n");
	return 0;
}

static void tquic_v6_protosw_exit(void)
{
	inet6_unregister_protosw(&tquicv6_dgram_protosw);
	inet6_unregister_protosw(&tquicv6_stream_protosw);
	proto_unregister(&tquicv6_prot);
}

static int tquic_v6_add_protocol(void)
{
	if (inet6_add_protocol(&tquicv6_protocol, IPPROTO_TQUIC) < 0) {
		pr_err("Failed to register TQUICv6 protocol handler\n");
		return -EAGAIN;
	}

	pr_info("TQUIC IPv6 protocol handler registered\n");
	return 0;
}

static void tquic_v6_del_protocol(void)
{
	inet6_del_protocol(&tquicv6_protocol, IPPROTO_TQUIC);
}

#else /* !CONFIG_IPV6 */

static inline int tquic_v6_protosw_init(void) { return 0; }
static inline void tquic_v6_protosw_exit(void) { }
static inline int tquic_v6_add_protocol(void) { return 0; }
static inline void tquic_v6_del_protocol(void) { }

#endif /* CONFIG_IPV6 */

/*
 * Module Init/Exit
 */
int __init tquic_proto_init(void)
{
	int ret;

	pr_info("TQUIC protocol handler initializing\n");

	/* Register pernet operations first */
	ret = register_pernet_subsys(&tquic_net_ops);
	if (ret)
		goto err_pernet;

	/* Register IPv4 protosw */
	ret = tquic_v4_protosw_init();
	if (ret)
		goto err_v4_protosw;

	/* Register IPv6 protosw */
	ret = tquic_v6_protosw_init();
	if (ret)
		goto err_v6_protosw;

	/* Register IPv4 protocol handler */
	ret = tquic_v4_add_protocol();
	if (ret)
		goto err_v4_protocol;

	/* Register IPv6 protocol handler */
	ret = tquic_v6_add_protocol();
	if (ret)
		goto err_v6_protocol;

	pr_info("TQUIC protocol handler initialized successfully\n");
	return 0;

err_v6_protocol:
	tquic_v4_del_protocol();
err_v4_protocol:
	tquic_v6_protosw_exit();
err_v6_protosw:
	tquic_v4_protosw_exit();
err_v4_protosw:
	unregister_pernet_subsys(&tquic_net_ops);
err_pernet:
	pr_err("TQUIC protocol handler initialization failed: %d\n", ret);
	return ret;
}

void __exit tquic_proto_exit(void)
{
	pr_info("TQUIC protocol handler exiting\n");

	/* Unregister protocol handlers */
	tquic_v6_del_protocol();
	tquic_v4_del_protocol();

	/* Unregister protosw */
	tquic_v6_protosw_exit();
	tquic_v4_protosw_exit();

	/* Unregister pernet operations */
	unregister_pernet_subsys(&tquic_net_ops);

	pr_info("TQUIC protocol handler exited\n");
}

/*
 * Accessor functions for per-netns sysctl values
 */
int tquic_net_get_enabled(struct net *net)
{
	return tquic_pernet(net)->enabled;
}
EXPORT_SYMBOL_GPL(tquic_net_get_enabled);

int tquic_net_get_bond_mode(struct net *net)
{
	return tquic_pernet(net)->bond_mode;
}
EXPORT_SYMBOL_GPL(tquic_net_get_bond_mode);

int tquic_net_get_max_paths(struct net *net)
{
	return tquic_pernet(net)->max_paths;
}
EXPORT_SYMBOL_GPL(tquic_net_get_max_paths);

int tquic_net_get_reorder_window(struct net *net)
{
	return tquic_pernet(net)->reorder_window;
}
EXPORT_SYMBOL_GPL(tquic_net_get_reorder_window);

int tquic_net_get_probe_interval(struct net *net)
{
	return tquic_pernet(net)->probe_interval;
}
EXPORT_SYMBOL_GPL(tquic_net_get_probe_interval);

int tquic_net_get_failover_timeout(struct net *net)
{
	return tquic_pernet(net)->failover_timeout;
}
EXPORT_SYMBOL_GPL(tquic_net_get_failover_timeout);

int tquic_net_get_idle_timeout(struct net *net)
{
	return tquic_pernet(net)->idle_timeout;
}
EXPORT_SYMBOL_GPL(tquic_net_get_idle_timeout);

int tquic_net_get_initial_rtt(struct net *net)
{
	return tquic_pernet(net)->initial_rtt;
}
EXPORT_SYMBOL_GPL(tquic_net_get_initial_rtt);

int tquic_net_get_initial_cwnd(struct net *net)
{
	return tquic_pernet(net)->initial_cwnd;
}
EXPORT_SYMBOL_GPL(tquic_net_get_initial_cwnd);

int tquic_net_get_debug_level(struct net *net)
{
	return tquic_pernet(net)->debug_level;
}
EXPORT_SYMBOL_GPL(tquic_net_get_debug_level);

void tquic_net_update_tx_stats(struct net *net, u64 bytes)
{
	atomic64_add(bytes, &tquic_pernet(net)->total_tx_bytes);
}
EXPORT_SYMBOL_GPL(tquic_net_update_tx_stats);

void tquic_net_update_rx_stats(struct net *net, u64 bytes)
{
	atomic64_add(bytes, &tquic_pernet(net)->total_rx_bytes);
}
EXPORT_SYMBOL_GPL(tquic_net_update_rx_stats);
