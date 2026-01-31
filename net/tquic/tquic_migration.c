// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Connection Migration Stubs
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides API surface for connection migration.
 * Full implementation in Phase 4 (Path Manager).
 *
 * Phase 2 scope:
 * - API definitions (UAPI, sockopt handlers)
 * - Status reporting (always returns NONE/no migration)
 * - Stubs return -ENOSYS for actual migration operations
 *
 * Phase 4 will implement:
 * - Automatic NAT rebind migration
 * - Explicit migration via sockopt
 * - PATH_CHALLENGE/PATH_RESPONSE handling
 * - Path state machine
 * - Multipath support
 *
 * RFC 9000 Connection Migration Overview:
 * - Connection migration allows a connection to continue even when the
 *   endpoint's IP address or port changes (e.g., NAT rebinding, WiFi->LTE)
 * - Migration uses PATH_CHALLENGE/PATH_RESPONSE frames to validate new paths
 * - Each migration should use a fresh connection ID to prevent linkability
 * - Server must validate client address before sending significant data
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <net/tquic.h>
#include "protocol.h"

/*
 * =============================================================================
 * PATH MANAGEMENT STUBS
 *
 * TODO Phase 4: Implement full path management with:
 * - Path list in connection
 * - Path state machine (UNUSED -> PENDING -> ACTIVE/STANDBY/FAILED)
 * - RTT/congestion tracking per path
 * - Path selection/scheduling for multipath
 * =============================================================================
 */

/**
 * tquic_path_find_by_addr - Find path by address (stub)
 * @conn: Connection to search
 * @addr: Address to find
 *
 * TODO Phase 4: Implement path lookup by address pair.
 * Should iterate conn->paths and compare local/remote addresses.
 *
 * Returns: Path pointer or NULL if not found
 */
struct tquic_path *tquic_path_find_by_addr(struct tquic_connection *conn,
					   const struct sockaddr_storage *addr)
{
	/* TODO Phase 4: Search conn->paths list by address
	 *
	 * Implementation outline:
	 * list_for_each_entry(path, &conn->paths, list) {
	 *     if (sockaddr_equal(&path->local_addr, addr) ||
	 *         sockaddr_equal(&path->remote_addr, addr))
	 *         return path;
	 * }
	 */
	return NULL;
}

/**
 * tquic_path_create - Create new path (stub)
 * @conn: Connection to add path to
 * @local: Local address for path
 * @remote: Remote address for path
 *
 * TODO Phase 4: Allocate path, add to connection, initialize stats.
 *
 * Returns: New path pointer or NULL on failure
 */
struct tquic_path *tquic_path_create(struct tquic_connection *conn,
				     const struct sockaddr_storage *local,
				     const struct sockaddr_storage *remote)
{
	/* TODO Phase 4: Full path creation with:
	 * 1. Allocate struct tquic_path
	 * 2. Copy local and remote addresses
	 * 3. Assign unique path_id from conn->next_path_id++
	 * 4. Set state to TQUIC_PATH_PENDING
	 * 5. Add to conn->paths list
	 * 6. Initialize RTT estimates (from conn defaults or peer)
	 * 7. Initialize congestion control state
	 * 8. Start path validation timer
	 */
	return NULL;
}

/**
 * tquic_path_free - Free path (stub)
 * @path: Path to free
 *
 * TODO Phase 4: Remove from connection, free resources.
 */
void tquic_path_free(struct tquic_path *path)
{
	/* TODO Phase 4: Full path cleanup with:
	 * 1. Remove from conn->paths list
	 * 2. Cancel validation timer
	 * 3. Release CID assigned to this path
	 * 4. Free congestion control state
	 * 5. Free path structure
	 */
	if (path)
		kfree(path);
}

/**
 * tquic_migration_send_path_challenge - Send PATH_CHALLENGE frame (stub)
 * @conn: Connection
 * @path: Path to send challenge on
 *
 * TODO Phase 4: Build and send PATH_CHALLENGE with random data.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migration_send_path_challenge(struct tquic_connection *conn,
					struct tquic_path *path)
{
	/* TODO Phase 4: PATH_CHALLENGE implementation:
	 * 1. Generate 8 bytes of cryptographically random challenge data
	 * 2. Store in path->challenge_data for later verification
	 * 3. Build PATH_CHALLENGE frame (type 0x1a, 8 bytes data)
	 * 4. Send frame on the specified path
	 * 5. Set path state to TQUIC_PATH_PENDING
	 * 6. Start validation timer (per RFC 9000, 3*PTO)
	 */
	pr_debug("tquic: PATH_CHALLENGE requested (stub)\n");
	return -ENOSYS;
}

/**
 * tquic_migration_path_event - Notify userspace of path event (stub)
 * @conn: Connection
 * @path: Path that changed
 * @event: Event type (TQUIC_PATH_EVENT_*)
 *
 * TODO Phase 4: Send netlink notification for path events.
 */
void tquic_migration_path_event(struct tquic_connection *conn,
				struct tquic_path *path, int event)
{
	/* TODO Phase 4: Netlink notification implementation:
	 * 1. Build TQUIC_CMD_PATH_EVENT message
	 * 2. Include path_id, state, event type
	 * 3. Multicast to TQUIC_NL_GRP_PATH group
	 */
	pr_debug("tquic: path event %d (stub)\n", event);
}

/*
 * =============================================================================
 * MIGRATION API
 *
 * These functions provide the sockopt API surface.
 * Full implementation in Phase 4 (Path Manager).
 * =============================================================================
 */

/**
 * tquic_migrate_explicit - Explicit migration via sockopt (stub)
 * @conn: Connection to migrate
 * @new_local: New local address to migrate to
 * @flags: Migration flags (TQUIC_MIGRATE_FLAG_*)
 *
 * Phase 2: Returns -ENOSYS (not implemented).
 * Phase 4: Will implement full migration with PATH_CHALLENGE.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migrate_explicit(struct tquic_connection *conn,
			   struct sockaddr_storage *new_local,
			   u32 flags)
{
	if (!conn)
		return -EINVAL;

	if (conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/*
	 * TODO Phase 4: Implement migration with:
	 * 1. Validate new_local address is usable
	 * 2. Get fresh CID via tquic_cid_get_for_migration()
	 *    - If no CID available, may need to wait for NEW_CONNECTION_ID
	 * 3. Create new path via tquic_path_create()
	 * 4. Assign CID to new path
	 * 5. Send PATH_CHALLENGE on new path
	 * 6. Set migration state to TQUIC_MIGRATE_PROBING
	 * 7. Wait for PATH_RESPONSE (async via callback)
	 * 8. On success: switch active path, notify userspace
	 * 9. On timeout: mark migration failed, clean up
	 *
	 * TQUIC_MIGRATE_FLAG_PROBE_ONLY: Don't switch, just validate
	 * TQUIC_MIGRATE_FLAG_FORCE: Migrate even if current path is OK
	 */

	pr_info("tquic: explicit migration not yet implemented (Phase 4)\n");
	return -ENOSYS;
}

/**
 * tquic_migrate_auto - Automatic migration on NAT rebind (stub)
 * @conn: Connection
 * @path: Current path
 * @new_addr: New remote address detected
 *
 * Phase 2: Does nothing, returns -ENOSYS.
 * Phase 4: Will detect source address change and trigger migration.
 *
 * Called from packet input path when peer's source address changes.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migrate_auto(struct tquic_connection *conn,
		       struct tquic_path *path,
		       struct sockaddr_storage *new_addr)
{
	/*
	 * TODO Phase 4: Implement automatic migration with:
	 * 1. Detect source address change in packet input
	 * 2. Verify this isn't a spoofed packet (anti-amplification)
	 * 3. If peer initiated migration (we received from new address):
	 *    - Create new path for new address
	 *    - Send PATH_CHALLENGE to validate
	 *    - Don't send significant data until validated
	 * 4. If we initiated (our address changed):
	 *    - Similar process but we are the migrating party
	 *
	 * Key per RFC 9000:
	 * - Must limit data sent to unvalidated address (anti-amplification)
	 * - Should use fresh CID to prevent linkability
	 * - Should probe both old and new paths initially
	 */

	pr_debug("tquic: auto migration not yet implemented (Phase 4)\n");
	return -ENOSYS;
}

/**
 * tquic_migration_get_status - Get current migration status
 * @conn: Connection
 * @info: OUT - Migration status information
 *
 * Phase 2: Always returns TQUIC_MIGRATE_NONE (no migration in progress).
 * Phase 4: Will return actual migration state from conn->migration_state.
 *
 * Returns: 0 on success
 */
int tquic_migration_get_status(struct tquic_connection *conn,
			       struct tquic_migrate_info *info)
{
	memset(info, 0, sizeof(*info));
	info->status = TQUIC_MIGRATE_NONE;

	if (!conn)
		return 0;

	/*
	 * TODO Phase 4: Return actual migration state from conn:
	 * - status: current migration status enum
	 * - old_path_id: ID of previous/current active path
	 * - new_path_id: ID of path being migrated to
	 * - probe_rtt: RTT from PATH_CHALLENGE/RESPONSE if validated
	 * - error_code: Error code if migration failed
	 * - old_local: Previous local address
	 * - new_local: New local address (if migrating)
	 * - remote: Remote address
	 *
	 * Migration state machine:
	 * TQUIC_MIGRATE_NONE -> TQUIC_MIGRATE_PROBING (challenge sent)
	 * TQUIC_MIGRATE_PROBING -> TQUIC_MIGRATE_VALIDATED (response received)
	 * TQUIC_MIGRATE_PROBING -> TQUIC_MIGRATE_FAILED (timeout)
	 * TQUIC_MIGRATE_VALIDATED -> TQUIC_MIGRATE_NONE (complete)
	 */

	return 0;
}

/**
 * tquic_migration_cleanup - Clean up migration state
 * @conn: Connection
 *
 * Called during connection teardown to free any migration-related resources.
 */
void tquic_migration_cleanup(struct tquic_connection *conn)
{
	/* TODO Phase 4: Free migration state if present
	 *
	 * 1. Cancel any pending PATH_CHALLENGE timers
	 * 2. Free pending path structures
	 * 3. Clear migration state
	 */
}

/*
 * =============================================================================
 * PATH_RESPONSE HANDLING (Stubs)
 *
 * These will be called from packet input path in Phase 4.
 * =============================================================================
 */

/**
 * tquic_migration_handle_path_challenge - Handle received PATH_CHALLENGE
 * @conn: Connection
 * @path: Path frame arrived on
 * @data: 8-byte challenge data
 *
 * TODO Phase 4: Echo back with PATH_RESPONSE.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migration_handle_path_challenge(struct tquic_connection *conn,
					  struct tquic_path *path,
					  const u8 *data)
{
	/* TODO Phase 4:
	 * 1. Build PATH_RESPONSE frame with same 8-byte data
	 * 2. Send on same path the challenge arrived on
	 * 3. This echoes the challenge back to prove path validity
	 */
	pr_debug("tquic: PATH_CHALLENGE received (stub)\n");
	return -ENOSYS;
}

/**
 * tquic_migration_handle_path_response - Handle received PATH_RESPONSE
 * @conn: Connection
 * @path: Path frame arrived on
 * @data: 8-byte response data
 *
 * TODO Phase 4: Validate response matches our challenge.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_migration_handle_path_response(struct tquic_connection *conn,
					 struct tquic_path *path,
					 const u8 *data)
{
	/* TODO Phase 4:
	 * 1. Check if data matches path->challenge_data
	 * 2. If match: path is validated
	 *    - Set path state to TQUIC_PATH_ACTIVE
	 *    - Calculate RTT from challenge/response
	 *    - If migrating, switch active path
	 *    - Notify userspace via netlink
	 * 3. If no match: protocol error
	 */
	pr_debug("tquic: PATH_RESPONSE received (stub)\n");
	return -ENOSYS;
}
