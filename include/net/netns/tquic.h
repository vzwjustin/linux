/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Per-Network Namespace State
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header defines per-network-namespace state for the TQUIC subsystem.
 * Each network namespace has its own MIB counters and error ring buffer.
 */

#ifndef _NET_NETNS_TQUIC_H
#define _NET_NETNS_TQUIC_H

/* Forward declarations */
struct tquic_mib;
struct tquic_error_ring;
struct tquic_sched_ops;

/* Scheduler name buffer size (matches TQUIC_SCHED_NAME_MAX) */
#define NETNS_TQUIC_SCHED_NAME_MAX	16

/**
 * struct netns_tquic - Per-network-namespace TQUIC state
 * @mib: Pointer to per-CPU MIB statistics counters
 * @error_ring: Pointer to error ring buffer for debugging
 * @default_scheduler: RCU-protected pointer to default scheduler ops
 * @sched_name: Buffer for sysctl scheduler name (net.tquic.scheduler)
 *
 * This structure is embedded in struct net (via net->tquic).
 * It holds namespace-specific state that needs to be isolated
 * between different network namespaces.
 *
 * The mib field points to per-CPU counters allocated lazily
 * when the first TQUIC socket is created in the namespace.
 *
 * The error_ring provides a circular buffer of recent errors
 * for debugging, accessible via /proc/net/tquic_errors.
 *
 * The default_scheduler and sched_name fields support per-netns
 * scheduler configuration. Containers can have different default
 * schedulers via sysctl net.tquic.scheduler.
 */
struct netns_tquic {
	struct tquic_mib __percpu *mib;
	struct tquic_error_ring *error_ring;

	/* Per-netns default scheduler (RCU protected) */
	struct tquic_sched_ops __rcu *default_scheduler;

	/* Sysctl buffer for scheduler name */
	char sched_name[NETNS_TQUIC_SCHED_NAME_MAX];
};

#endif /* _NET_NETNS_TQUIC_H */
