/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * TQUIC Path Manager Netlink Interface
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header defines the netlink interface for the TQUIC path manager,
 * following the pattern established by MPTCP (mptcp_pm.h).
 */
#ifndef _UAPI_LINUX_TQUIC_PM_H
#define _UAPI_LINUX_TQUIC_PM_H

#include <linux/types.h>

#define TQUIC_PM_NAME		"tquic_pm"
#define TQUIC_PM_VER		1

/*
 * Path Manager Commands
 * Sent via genetlink to manage paths on TQUIC connections
 */
enum tquic_pm_cmd {
	TQUIC_PM_CMD_UNSPEC,
	TQUIC_PM_CMD_ADD_PATH,		/* Add a new path */
	TQUIC_PM_CMD_DEL_PATH,		/* Remove a path */
	TQUIC_PM_CMD_GET_PATH,		/* Get path info */
	TQUIC_PM_CMD_SET_PATH_STATE,	/* Set path state */
	TQUIC_PM_CMD_FLUSH_PATHS,	/* Remove all paths */
	TQUIC_PM_CMD_SET_LIMITS,	/* Set path limits */
	TQUIC_PM_CMD_GET_LIMITS,	/* Get path limits */
	TQUIC_PM_CMD_SET_FLAGS,		/* Set path flags */
	TQUIC_PM_CMD_ANNOUNCE,		/* Announce new address */
	TQUIC_PM_CMD_REMOVE,		/* Remove address */

	__TQUIC_PM_CMD_AFTER_LAST,
	TQUIC_PM_CMD_MAX = __TQUIC_PM_CMD_AFTER_LAST - 1,
};

/*
 * Path Manager Attributes
 */
enum tquic_pm_attr {
	TQUIC_PM_ATTR_UNSPEC,

	/* Connection identification */
	TQUIC_PM_ATTR_TOKEN,		/* u32: Connection token */

	/* Path identification */
	TQUIC_PM_ATTR_PATH_ID,		/* u8: Path identifier */
	TQUIC_PM_ATTR_FAMILY,		/* u16: Address family */

	/* Addresses */
	TQUIC_PM_ATTR_SADDR4,		/* struct in_addr */
	TQUIC_PM_ATTR_SADDR6,		/* struct in6_addr */
	TQUIC_PM_ATTR_DADDR4,		/* struct in_addr */
	TQUIC_PM_ATTR_DADDR6,		/* struct in6_addr */
	TQUIC_PM_ATTR_SPORT,		/* u16: Source port */
	TQUIC_PM_ATTR_DPORT,		/* u16: Destination port */

	/* Path state and flags */
	TQUIC_PM_ATTR_FLAGS,		/* u32: Path flags */
	TQUIC_PM_ATTR_STATE,		/* u8: Path state */
	TQUIC_PM_ATTR_IF_IDX,		/* s32: Interface index */

	/* Path properties */
	TQUIC_PM_ATTR_PRIORITY,		/* u8: Path priority */
	TQUIC_PM_ATTR_WEIGHT,		/* u8: Path weight */

	/* Limits */
	TQUIC_PM_ATTR_MAX_PATHS,	/* u8: Maximum paths */
	TQUIC_PM_ATTR_SUBFLOWS,		/* u8: Current subflow count */

	__TQUIC_PM_ATTR_AFTER_LAST,
	TQUIC_PM_ATTR_MAX = __TQUIC_PM_ATTR_AFTER_LAST - 1,
};

/*
 * Path flags for TQUIC_PM_ATTR_FLAGS
 */
#define TQUIC_PM_ADDR_FLAG_SIGNAL	(1 << 0)	/* Announce to peer */
#define TQUIC_PM_ADDR_FLAG_SUBFLOW	(1 << 1)	/* Create subflow */
#define TQUIC_PM_ADDR_FLAG_BACKUP	(1 << 2)	/* Backup path */
#define TQUIC_PM_ADDR_FLAG_FULLMESH	(1 << 3)	/* Full mesh mode */
#define TQUIC_PM_ADDR_FLAG_IMPLICIT	(1 << 4)	/* Implicit endpoint */

/*
 * Path Manager Events (multicast notifications)
 */
enum tquic_pm_event {
	TQUIC_PM_EVENT_UNSPEC,
	TQUIC_PM_EVENT_CREATED,		/* New path created */
	TQUIC_PM_EVENT_ESTABLISHED,	/* Path validated */
	TQUIC_PM_EVENT_CLOSED,		/* Path closed */
	TQUIC_PM_EVENT_ANNOUNCED,	/* Address announced */
	TQUIC_PM_EVENT_REMOVED,		/* Address removed */
	TQUIC_PM_EVENT_PRIORITY,	/* Priority changed */
	TQUIC_PM_EVENT_LISTENER_CREATED,
	TQUIC_PM_EVENT_LISTENER_CLOSED,

	__TQUIC_PM_EVENT_AFTER_LAST,
	TQUIC_PM_EVENT_MAX = __TQUIC_PM_EVENT_AFTER_LAST - 1,
};

#endif /* _UAPI_LINUX_TQUIC_PM_H */
