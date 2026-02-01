---
phase: 02-socket-api
plan: 04
subsystem: cid-migration
tags: [cid, migration, rhashtable, sockopt, RFC-9000]
depends:
  requires: ["02-01", "02-02"]
  provides: ["cid-pool", "migration-api", "migration-stubs"]
  affects: ["04-path-manager", "03-diagnostics"]
tech-stack:
  added: []
  patterns: ["rhashtable-lookup", "spinlock-pool", "sockopt-dispatch"]
key-files:
  created:
    - net/tquic/tquic_cid.c
    - net/tquic/tquic_migration.c
  modified:
    - include/uapi/linux/tquic.h
    - net/tquic/protocol.h
    - net/tquic/tquic_socket.c
    - net/tquic/Makefile
    - include/net/tquic.h
decisions:
  - key: rhashtable-for-cid-lookup
    choice: "Global rhashtable for CID->connection lookup"
    rationale: "O(1) lookup for packet demux, automatic shrinking, kernel standard"
  - key: cid-pool-default-8
    choice: "Default CID pool size of 8 per RFC 9000"
    rationale: "Matches TQUIC_ACTIVE_CID_LIMIT transport parameter default"
  - key: migration-returns-enosys
    choice: "TQUIC_MIGRATE returns -ENOSYS in Phase 2"
    rationale: "API surface ready but full implementation deferred to Phase 4"
metrics:
  duration: "~5 minutes"
  completed: "2026-01-31"
---

# Phase 2 Plan 4: CID Pool Management and Migration Stubs Summary

CID pool management with rhashtable-based lookup; migration API surface returning -ENOSYS pending Phase 4 implementation.

## What Was Built

### 1. Migration UAPI Definitions (include/uapi/linux/tquic.h)

Added connection migration socket option definitions:

```c
#define TQUIC_MIGRATE           70  /* Trigger explicit migration */
#define TQUIC_MIGRATE_STATUS    71  /* Get migration status (read-only) */
#define TQUIC_MIGRATION_ENABLED 72  /* Enable/disable automatic migration */

struct tquic_migrate_args {
    struct sockaddr_storage local_addr;
    __u32 flags;
    __u32 reserved;
};

enum tquic_migrate_status {
    TQUIC_MIGRATE_NONE = 0,
    TQUIC_MIGRATE_PROBING,
    TQUIC_MIGRATE_VALIDATED,
    TQUIC_MIGRATE_FAILED,
};

struct tquic_migrate_info {
    __u32 status;
    __u32 old_path_id;
    __u32 new_path_id;
    __u32 probe_rtt;
    __u32 error_code;
    __u32 reserved;
    struct sockaddr_storage old_local;
    struct sockaddr_storage new_local;
    struct sockaddr_storage remote;
};

#define TQUIC_CID_POOL_MIN          2
#define TQUIC_CID_POOL_DEFAULT      8
#define TQUIC_ACTIVE_CID_LIMIT      8
```

### 2. CID Pool Management (net/tquic/tquic_cid.c)

Fully functional CID pool implementing RFC 9000 Section 5.1:

**Core Functions:**
- `tquic_cid_pool_init()`: Allocate pool, generate initial CID, register in hash
- `tquic_cid_pool_destroy()`: Free all CIDs and pool on connection teardown
- `tquic_cid_issue()`: Create new CID, register in hash, queue NEW_CONNECTION_ID
- `tquic_cid_retire()`: Mark CID retired, remove from hash on RETIRE_CONNECTION_ID
- `tquic_cid_lookup()`: O(1) rhashtable lookup for packet demuxing
- `tquic_cid_get_for_migration()`: Find unused remote CID for migration
- `tquic_cid_add_remote()`: Store peer's NEW_CONNECTION_ID for sending

**Implementation Details:**
```c
/* Global hash table for O(1) CID->connection lookup */
static struct rhashtable tquic_cid_table;

/* CID entry structure with hash linkage */
struct tquic_cid_entry {
    struct tquic_cid cid;
    u64 seq_num;
    u8 reset_token[16];
    struct tquic_connection *conn;
    enum tquic_cid_state state;  /* UNUSED, ACTIVE, RETIRED */
    struct tquic_path *path;
    struct rhash_head node;      /* Hash table linkage */
    struct list_head list;       /* Pool list linkage */
};

/* CID pool per connection */
struct tquic_cid_pool {
    spinlock_t lock;
    struct list_head local_cids;   /* CIDs we issue to peer */
    struct list_head remote_cids;  /* CIDs peer issues to us */
    u64 next_seq;
    u32 active_count;
    u8 cid_len;                    /* Default 8 bytes */
    u8 active_cid_limit;           /* Default 8 per transport param */
};
```

**Frame Send Stubs (Full impl Phase 3):**
- `tquic_send_new_connection_id()`: Queue NEW_CONNECTION_ID frame
- `tquic_send_retire_connection_id()`: Queue RETIRE_CONNECTION_ID frame

### 3. Migration Stubs (net/tquic/tquic_migration.c)

API surface with clear Phase 4 TODO markers:

**Migration Functions:**
- `tquic_migrate_explicit()`: Returns -ENOSYS (Phase 4 implements full migration)
- `tquic_migrate_auto()`: Returns -ENOSYS (Phase 4 implements NAT rebind)
- `tquic_migration_get_status()`: Always returns TQUIC_MIGRATE_NONE
- `tquic_migration_cleanup()`: Placeholder for connection teardown

**Path Management Stubs:**
- `tquic_path_find_by_addr()`: Returns NULL (Phase 4 implements search)
- `tquic_path_create()`: Returns NULL (Phase 4 implements allocation)
- `tquic_path_free()`: Basic kfree (Phase 4 adds full cleanup)
- `tquic_migration_send_path_challenge()`: Returns -ENOSYS
- `tquic_migration_path_event()`: pr_debug only

**PATH_CHALLENGE/RESPONSE Stubs:**
- `tquic_migration_handle_path_challenge()`: Returns -ENOSYS
- `tquic_migration_handle_path_response()`: Returns -ENOSYS

### 4. Sockopt Handlers (net/tquic/tquic_socket.c)

Added migration sockopt handling:

```c
/* setsockopt handlers */
case TQUIC_MIGRATE:
    /* Validates args, calls tquic_migrate_explicit() */
    /* Returns -ENOSYS in Phase 2 */

case TQUIC_MIGRATION_ENABLED:
    /* Sets/clears TQUIC_F_MIGRATION_ENABLED flag */

/* getsockopt handlers */
case TQUIC_MIGRATE_STATUS:
    /* Returns tquic_migrate_info via tquic_migration_get_status() */
    /* Always TQUIC_MIGRATE_NONE in Phase 2 */

case TQUIC_MIGRATION_ENABLED:
    /* Returns migration enabled state */
```

## Architecture Decisions

### CID Pool with rhashtable

Chose kernel rhashtable for global CID lookup:
- O(1) average-case lookup for packet demuxing
- Lock-free read path via RCU
- Automatic shrinking when CIDs retired
- Standard kernel pattern (used by conntrack, etc.)

### Separate Local/Remote CID Lists

Pool maintains two lists:
- `local_cids`: CIDs we generate and issue to peer via NEW_CONNECTION_ID
- `remote_cids`: CIDs peer issues to us via their NEW_CONNECTION_ID

Only local CIDs are registered in global hash table (for incoming packet lookup).

### Migration Stubs Return -ENOSYS

Per plan, Phase 2 provides API surface only:
- setsockopt(TQUIC_MIGRATE) returns -ENOSYS
- Full PATH_CHALLENGE/RESPONSE handling deferred to Phase 4
- Status always reports TQUIC_MIGRATE_NONE

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | 1a8aa84b0 | Define migration sockopt, status structures, and CID pool declarations |
| 2 | beea3c3f5 | Create tquic_cid.c with connection ID pool management |
| 3 | 334f1198b | Create tquic_migration.c with migration stubs and path management stubs |

## Files Changed

### Created
- `net/tquic/tquic_cid.c` - CID pool implementation (560 lines)
- `net/tquic/tquic_migration.c` - Migration stubs (365 lines)

### Modified
- `include/uapi/linux/tquic.h` - Migration sockopts and structures
- `net/tquic/protocol.h` - CID pool and migration function declarations
- `net/tquic/tquic_socket.c` - Sockopt handlers for TQUIC_MIGRATE*
- `net/tquic/Makefile` - Added tquic_cid.o, tquic_migration.o
- `include/net/tquic.h` - Added cid_pool field to tquic_connection

## Deviations from Plan

None - plan executed exactly as written.

## Verification Results

| Check | Status |
|-------|--------|
| TQUIC_MIGRATE sockopt in UAPI | Pass |
| struct tquic_path functions in protocol.h | Pass |
| CID pool init/issue/retire/lookup | Pass |
| setsockopt(TQUIC_MIGRATE) returns -ENOSYS | Pass |
| getsockopt(TQUIC_MIGRATE_STATUS) returns NONE | Pass |
| TODO Phase 4 markers present | Pass (19 markers) |
| Frame send stubs exist | Pass |

## Phase 4 Integration Points

The following will be implemented in Phase 4 (Path Manager):

1. **Full Migration Implementation:**
   - `tquic_migrate_explicit()`: PATH_CHALLENGE, path switch, CID assignment
   - `tquic_migrate_auto()`: NAT rebind detection, automatic migration

2. **Path State Machine:**
   - UNUSED -> PENDING -> ACTIVE/STANDBY/FAILED
   - Path validation timers
   - Per-path congestion control

3. **PATH_CHALLENGE/RESPONSE:**
   - Random challenge data generation
   - Response validation
   - RTT measurement from challenge/response

4. **Multipath Support:**
   - CID-to-path assignment
   - Path selection for sending
   - Path probing and monitoring

## Next Phase Readiness

Phase 2 Socket API is complete. Ready for:
- **Phase 3 (Diagnostics):** Connection stats via CID pool, path status queries
- **Phase 4 (Path Manager):** Full migration implementation using CID pool
