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

/**
 * struct netns_tquic - Per-network-namespace TQUIC state
 * @mib: Pointer to per-CPU MIB statistics counters
 * @error_ring: Pointer to error ring buffer for debugging
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
 */
struct netns_tquic {
	struct tquic_mib __percpu *mib;
	struct tquic_error_ring *error_ring;
};

#endif /* _NET_NETNS_TQUIC_H */
