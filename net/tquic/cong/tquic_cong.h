/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Congestion Control Framework
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Central CC framework for TQUIC multipath WAN bonding.
 * Provides algorithm registration, per-path lifecycle management,
 * and callback dispatch for ACK/loss/RTT events.
 */

#ifndef _TQUIC_CONG_H
#define _TQUIC_CONG_H

#include <linux/types.h>
#include <net/tquic.h>

/*
 * Default CC algorithm name - used when no CC is specified
 */
#define TQUIC_DEFAULT_CC_NAME	"cubic"

/*
 * Maximum CC algorithm name length
 */
#define TQUIC_CC_NAME_MAX	16

/*
 * tquic_cong_find - Find CC algorithm by name
 * @name: Name of the CC algorithm to find
 *
 * RCU-protected lookup of registered CC algorithms.
 * Returns pointer to tquic_cong_ops if found, NULL otherwise.
 * Caller must hold RCU read lock or ensure ops won't be unregistered.
 *
 * Return: Pointer to CC ops or NULL if not found
 */
struct tquic_cong_ops *tquic_cong_find(const char *name);

/*
 * tquic_cong_init_path - Initialize CC state for a path
 * @path: Path to initialize CC for
 * @name: CC algorithm name (NULL for default)
 *
 * Finds the CC algorithm by name (or uses default "cubic"),
 * calls the algorithm's init function to create per-path state,
 * and stores the ops pointer in the path for callback dispatch.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_cong_init_path(struct tquic_path *path, const char *name);

/*
 * tquic_cong_release_path - Release CC state for a path
 * @path: Path whose CC state should be released
 *
 * Calls the CC algorithm's release function if CC state exists,
 * clears the path's cong and cong_ops pointers.
 * Safe to call with NULL CC state.
 */
void tquic_cong_release_path(struct tquic_path *path);

/*
 * tquic_cong_on_ack - Dispatch ACK event to path's CC algorithm
 * @path: Path that received the ACK
 * @bytes_acked: Number of bytes acknowledged
 * @rtt_us: RTT sample in microseconds
 *
 * Calls the path's CC algorithm on_ack callback if registered.
 * Updates path->stats.cwnd from the CC algorithm after callback.
 */
void tquic_cong_on_ack(struct tquic_path *path, u64 bytes_acked, u64 rtt_us);

/*
 * tquic_cong_on_loss - Dispatch loss event to path's CC algorithm
 * @path: Path that experienced loss
 * @bytes_lost: Number of bytes detected as lost
 *
 * Calls the path's CC algorithm on_loss callback if registered.
 */
void tquic_cong_on_loss(struct tquic_path *path, u64 bytes_lost);

/*
 * tquic_cong_on_rtt - Dispatch RTT update to path's CC algorithm
 * @path: Path with RTT update
 * @rtt_us: RTT sample in microseconds
 *
 * Calls the path's CC algorithm on_rtt_update callback if registered.
 */
void tquic_cong_on_rtt(struct tquic_path *path, u64 rtt_us);

/*
 * tquic_cong_get_cwnd - Get current cwnd from path's CC algorithm
 * @path: Path to query
 *
 * Return: Current congestion window in bytes, or default if no CC
 */
u64 tquic_cong_get_cwnd(struct tquic_path *path);

/*
 * tquic_cong_get_pacing_rate - Get pacing rate from path's CC algorithm
 * @path: Path to query
 *
 * Return: Current pacing rate in bytes/sec, or 0 if no pacing
 */
u64 tquic_cong_get_pacing_rate(struct tquic_path *path);

#endif /* _TQUIC_CONG_H */
