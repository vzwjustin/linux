// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Congestion Control Framework
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Central CC registry and path lifecycle integration for TQUIC.
 *
 * This module provides:
 * - CC algorithm registration/unregistration
 * - RCU-protected algorithm lookup by name
 * - Per-path CC state initialization and release
 * - Callback dispatch for ACK/loss/RTT events
 *
 * The framework follows the kernel tcp_cong.c pattern with adaptations
 * for TQUIC's per-path congestion control model.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/jhash.h>
#include <net/tquic.h>
#include <net/net_namespace.h>
#include <net/netns/tquic.h>
#include "tquic_cong.h"

/*
 * Global CC algorithm registry
 * Protected by tquic_cong_list_lock for modifications,
 * RCU for read access.
 */
static DEFINE_SPINLOCK(tquic_cong_list_lock);
static LIST_HEAD(tquic_cong_list);

/*
 * Default initial cwnd when no CC algorithm is available
 */
#define TQUIC_DEFAULT_CWND	(10 * 1200)	/* 10 packets */

/*
 * tquic_register_cong - Register a CC algorithm
 * @ca: Pointer to the CC algorithm ops structure
 *
 * Adds the CC algorithm to the global registry.
 * The algorithm must have a unique name.
 *
 * Return: 0 on success, -EEXIST if name already registered
 */
int tquic_register_cong(struct tquic_cong_ops *ca)
{
	struct tquic_cong_ops *existing;
	int ret = 0;

	if (!ca || !ca->name || !ca->init || !ca->release)
		return -EINVAL;

	/* Compute key for fast lookup */
	ca->key = jhash(ca->name, strlen(ca->name), 0);

	spin_lock(&tquic_cong_list_lock);

	/* Check for duplicate */
	list_for_each_entry(existing, &tquic_cong_list, list) {
		if (strcmp(existing->name, ca->name) == 0) {
			pr_notice("tquic_cong: %s already registered\n",
				  ca->name);
			ret = -EEXIST;
			goto out_unlock;
		}
	}

	/* Add to list (RCU-safe) */
	list_add_tail_rcu(&ca->list, &tquic_cong_list);
	pr_info("tquic_cong: registered %s\n", ca->name);

out_unlock:
	spin_unlock(&tquic_cong_list_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_register_cong);

/*
 * tquic_unregister_cong - Unregister a CC algorithm
 * @ca: Pointer to the CC algorithm ops structure to unregister
 *
 * Removes the CC algorithm from the global registry.
 * Callers must ensure no paths are using this algorithm.
 */
void tquic_unregister_cong(struct tquic_cong_ops *ca)
{
	if (!ca)
		return;

	spin_lock(&tquic_cong_list_lock);
	list_del_rcu(&ca->list);
	spin_unlock(&tquic_cong_list_lock);

	/* Wait for RCU grace period before returning */
	synchronize_rcu();

	pr_info("tquic_cong: unregistered %s\n", ca->name);
}
EXPORT_SYMBOL_GPL(tquic_unregister_cong);

/*
 * tquic_cong_find - Find CC algorithm by name
 * @name: Name of the CC algorithm to find
 *
 * RCU-protected lookup of registered CC algorithms.
 *
 * Return: Pointer to CC ops if found, NULL otherwise
 */
struct tquic_cong_ops *tquic_cong_find(const char *name)
{
	struct tquic_cong_ops *ca;

	if (!name || strlen(name) == 0)
		return NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(ca, &tquic_cong_list, list) {
		if (strcmp(ca->name, name) == 0) {
			/* Try to get module reference */
			if (ca->owner && !try_module_get(ca->owner)) {
				rcu_read_unlock();
				return NULL;
			}
			rcu_read_unlock();
			return ca;
		}
	}
	rcu_read_unlock();

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_cong_find);

/*
 * tquic_cong_find_key - Find CC algorithm by precomputed key
 * @key: Hash key of the algorithm name
 *
 * Used for faster lookup when key is already computed.
 *
 * Return: Pointer to CC ops if found, NULL otherwise
 */
static struct tquic_cong_ops *tquic_cong_find_key(u32 key)
{
	struct tquic_cong_ops *ca;

	rcu_read_lock();
	list_for_each_entry_rcu(ca, &tquic_cong_list, list) {
		if (ca->key == key) {
			if (ca->owner && !try_module_get(ca->owner)) {
				rcu_read_unlock();
				return NULL;
			}
			rcu_read_unlock();
			return ca;
		}
	}
	rcu_read_unlock();

	return NULL;
}

/*
 * tquic_cong_put - Release CC algorithm module reference
 * @ca: CC algorithm ops to release
 */
static void tquic_cong_put(struct tquic_cong_ops *ca)
{
	if (ca && ca->owner)
		module_put(ca->owner);
}

/*
 * tquic_cong_init_path - Initialize CC state for a path
 * @path: Path to initialize CC for
 * @name: CC algorithm name (NULL for default)
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_cong_init_path(struct tquic_path *path, const char *name)
{
	struct tquic_cong_ops *ca;
	void *cong_state;
	const char *algo_name;

	if (!path)
		return -EINVAL;

	/* Use default if no name specified */
	algo_name = name ? name : TQUIC_DEFAULT_CC_NAME;

	/* Find the CC algorithm */
	ca = tquic_cong_find(algo_name);
	if (!ca) {
		/* Try to auto-load the module */
		request_module("tquic-cong-%s", algo_name);
		ca = tquic_cong_find(algo_name);
	}

	if (!ca) {
		pr_warn("tquic_cong: algorithm '%s' not found, trying default\n",
			algo_name);
		/* Fall back to default */
		if (strcmp(algo_name, TQUIC_DEFAULT_CC_NAME) != 0) {
			ca = tquic_cong_find(TQUIC_DEFAULT_CC_NAME);
			if (!ca) {
				request_module("tquic-cong-%s",
					       TQUIC_DEFAULT_CC_NAME);
				ca = tquic_cong_find(TQUIC_DEFAULT_CC_NAME);
			}
		}
	}

	if (!ca) {
		pr_warn("tquic_cong: no CC algorithm available for path %u\n",
			path->path_id);
		/* Initialize with default cwnd, no CC ops */
		path->cong = NULL;
		path->cong_ops = NULL;
		path->stats.cwnd = TQUIC_DEFAULT_CWND;
		return 0;  /* Not fatal - path can operate without CC */
	}

	/* Initialize per-path CC state */
	cong_state = ca->init(path);
	if (!cong_state) {
		tquic_cong_put(ca);
		pr_warn("tquic_cong: failed to init %s for path %u\n",
			ca->name, path->path_id);
		return -ENOMEM;
	}

	/* Store CC state and ops in path */
	path->cong = cong_state;
	path->cong_ops = ca;

	/* Initialize cwnd from CC algorithm */
	if (ca->get_cwnd)
		path->stats.cwnd = ca->get_cwnd(cong_state);
	else
		path->stats.cwnd = TQUIC_DEFAULT_CWND;

	pr_debug("tquic_cong: initialized %s for path %u (cwnd=%u)\n",
		 ca->name, path->path_id, path->stats.cwnd);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_init_path);

/*
 * tquic_cong_release_path - Release CC state for a path
 * @path: Path whose CC state should be released
 */
void tquic_cong_release_path(struct tquic_path *path)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return;

	ca = path->cong_ops;
	if (ca && path->cong) {
		/* Call CC algorithm's release function */
		if (ca->release)
			ca->release(path->cong);

		/* Release module reference */
		tquic_cong_put(ca);

		pr_debug("tquic_cong: released %s for path %u\n",
			 ca->name, path->path_id);
	}

	/* Clear path's CC state */
	path->cong = NULL;
	path->cong_ops = NULL;
}
EXPORT_SYMBOL_GPL(tquic_cong_release_path);

/*
 * tquic_cong_on_ack - Dispatch ACK event to path's CC algorithm
 * @path: Path that received the ACK
 * @bytes_acked: Number of bytes acknowledged
 * @rtt_us: RTT sample in microseconds
 */
void tquic_cong_on_ack(struct tquic_path *path, u64 bytes_acked, u64 rtt_us)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return;

	ca = path->cong_ops;
	if (ca && ca->on_ack && path->cong) {
		ca->on_ack(path->cong, bytes_acked, rtt_us);

		/* Update path stats from CC state */
		if (ca->get_cwnd)
			path->stats.cwnd = ca->get_cwnd(path->cong);
	}
}
EXPORT_SYMBOL_GPL(tquic_cong_on_ack);

/*
 * tquic_cong_on_loss - Dispatch loss event to path's CC algorithm
 * @path: Path that experienced loss
 * @bytes_lost: Number of bytes detected as lost
 */
void tquic_cong_on_loss(struct tquic_path *path, u64 bytes_lost)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return;

	ca = path->cong_ops;
	if (ca && ca->on_loss && path->cong) {
		ca->on_loss(path->cong, bytes_lost);

		/* Update path stats from CC state */
		if (ca->get_cwnd)
			path->stats.cwnd = ca->get_cwnd(path->cong);
	}
}
EXPORT_SYMBOL_GPL(tquic_cong_on_loss);

/*
 * tquic_cong_on_rtt - Dispatch RTT update to path's CC algorithm
 * @path: Path with RTT update
 * @rtt_us: RTT sample in microseconds
 */
void tquic_cong_on_rtt(struct tquic_path *path, u64 rtt_us)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return;

	ca = path->cong_ops;
	if (ca && ca->on_rtt_update && path->cong)
		ca->on_rtt_update(path->cong, rtt_us);
}
EXPORT_SYMBOL_GPL(tquic_cong_on_rtt);

/*
 * tquic_cong_get_cwnd - Get current cwnd from path's CC algorithm
 * @path: Path to query
 *
 * Return: Current congestion window in bytes
 */
u64 tquic_cong_get_cwnd(struct tquic_path *path)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return TQUIC_DEFAULT_CWND;

	ca = path->cong_ops;
	if (ca && ca->get_cwnd && path->cong)
		return ca->get_cwnd(path->cong);

	return path->stats.cwnd ?: TQUIC_DEFAULT_CWND;
}
EXPORT_SYMBOL_GPL(tquic_cong_get_cwnd);

/*
 * tquic_cong_get_pacing_rate - Get pacing rate from path's CC algorithm
 * @path: Path to query
 *
 * Return: Current pacing rate in bytes/sec, or 0 if no pacing
 */
u64 tquic_cong_get_pacing_rate(struct tquic_path *path)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return 0;

	ca = path->cong_ops;
	if (ca && ca->get_pacing_rate && path->cong)
		return ca->get_pacing_rate(path->cong);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_get_pacing_rate);

/*
 * tquic_cong_on_packet_sent - Notify CC of packet transmission
 * @path: Path the packet was sent on
 * @bytes: Number of bytes sent
 * @sent_time: Time the packet was sent
 */
void tquic_cong_on_packet_sent(struct tquic_path *path, u64 bytes,
			       ktime_t sent_time)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return;

	ca = path->cong_ops;
	if (ca && ca->on_packet_sent && path->cong)
		ca->on_packet_sent(path->cong, bytes, sent_time);
}
EXPORT_SYMBOL_GPL(tquic_cong_on_packet_sent);

/*
 * =============================================================================
 * Per-Network Namespace CC Configuration
 * =============================================================================
 */

/*
 * tquic_cong_set_default - Set default CC algorithm for a network namespace
 * @net: Network namespace
 * @name: CC algorithm name
 *
 * Return: 0 on success, -ENOENT if algorithm not found, -EBUSY if module fails
 */
int tquic_cong_set_default(struct net *net, const char *name)
{
	struct tquic_cong_ops *ca, *old_ca;

	if (!net || !name)
		return -EINVAL;

	/* Find and get reference to the CC algorithm */
	ca = tquic_cong_find(name);
	if (!ca) {
		/* Try to load the module */
		request_module("tquic-cong-%s", name);
		ca = tquic_cong_find(name);
		if (!ca) {
			pr_warn("tquic_cong: algorithm '%s' not found\n", name);
			return -ENOENT;
		}
	}

	/* Store name in netns buffer */
	strscpy(net->tquic.cc_name, name, NETNS_TQUIC_CC_NAME_MAX);

	/* Swap default CC algorithm (RCU protected) */
	spin_lock(&tquic_cong_list_lock);
	old_ca = rcu_dereference_protected(net->tquic.default_cong,
					   lockdep_is_held(&tquic_cong_list_lock));
	rcu_assign_pointer(net->tquic.default_cong, ca);
	spin_unlock(&tquic_cong_list_lock);

	/* Release old CC algorithm's module reference */
	if (old_ca && old_ca->owner)
		module_put(old_ca->owner);

	pr_debug("tquic_cong: netns default CC set to '%s'\n", name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_set_default);

/*
 * tquic_cong_get_default - Get default CC algorithm for a network namespace
 * @net: Network namespace
 *
 * Return: Pointer to default CC ops, or NULL if none set
 */
struct tquic_cong_ops *tquic_cong_get_default(struct net *net)
{
	if (!net)
		return NULL;

	return rcu_dereference(net->tquic.default_cong);
}
EXPORT_SYMBOL_GPL(tquic_cong_get_default);

/*
 * tquic_cong_get_default_name - Get default CC algorithm name for a netns
 * @net: Network namespace
 *
 * Return: CC algorithm name string, or "cubic" as fallback
 */
const char *tquic_cong_get_default_name(struct net *net)
{
	struct tquic_cong_ops *ca;
	const char *name;

	if (!net)
		return TQUIC_DEFAULT_CC_NAME;

	rcu_read_lock();
	ca = rcu_dereference(net->tquic.default_cong);
	if (ca)
		name = ca->name;
	else if (net->tquic.cc_name[0])
		name = net->tquic.cc_name;
	else
		name = TQUIC_DEFAULT_CC_NAME;
	rcu_read_unlock();

	return name;
}
EXPORT_SYMBOL_GPL(tquic_cong_get_default_name);

/*
 * tquic_cong_is_bbr_preferred - Check if BBR should be used for RTT
 * @net: Network namespace
 * @rtt_us: Path RTT in microseconds
 *
 * Return: true if RTT exceeds the BBR auto-selection threshold
 */
bool tquic_cong_is_bbr_preferred(struct net *net, u64 rtt_us)
{
	u32 threshold_us;

	if (!net)
		return false;

	/* Convert threshold from ms to us */
	threshold_us = net->tquic.bbr_rtt_threshold_ms * 1000;

	/* BBR is preferred for high-RTT paths */
	return rtt_us >= threshold_us;
}
EXPORT_SYMBOL_GPL(tquic_cong_is_bbr_preferred);

/*
 * tquic_cong_select_for_rtt - Select CC algorithm based on RTT
 * @net: Network namespace for configuration
 * @rtt_us: Path RTT in microseconds
 *
 * Return: CC algorithm name to use for this path
 */
const char *tquic_cong_select_for_rtt(struct net *net, u64 rtt_us)
{
	/* If BBR is preferred for high RTT and threshold is set */
	if (net && net->tquic.bbr_rtt_threshold_ms > 0 &&
	    tquic_cong_is_bbr_preferred(net, rtt_us)) {
		return "bbr";
	}

	/* Otherwise use the per-netns default */
	return tquic_cong_get_default_name(net);
}
EXPORT_SYMBOL_GPL(tquic_cong_select_for_rtt);

MODULE_DESCRIPTION("TQUIC Congestion Control Framework");
MODULE_LICENSE("GPL");
