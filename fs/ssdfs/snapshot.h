// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshot.h - snapshot's declarations.
 *
 * Copyright (c) 2021-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_SNAPSHOT_H
#define _SSDFS_SNAPSHOT_H

/*
 * struct ssdfs_time_range - time range definition
 * @minute: minute of the time range
 * @hour: hour of the time range
 * @day: day of the time range
 * @month: month of the time range
 * @year: year of the time range
 */
struct ssdfs_time_range {
	u32 minute;
	u32 hour;
	u32 day;
	u32 month;
	u32 year;
};

#define SSDFS_ANY_MINUTE			U32_MAX
#define SSDFS_ANY_HOUR				U32_MAX
#define SSDFS_ANY_DAY				U32_MAX
#define SSDFS_ANY_MONTH				U32_MAX
#define SSDFS_ANY_YEAR				U32_MAX

/*
 * struct ssdfs_snapshot_details - snapshot details
 * @create_time: snapshot's timestamp
 * @cno: snapshot's checkpoint
 * @mode: snapshot mode (READ-ONLY|READ-WRITE)
 * @expiration: snapshot expiration time (WEEK|MONTH|YEAR|NEVER)
 * @ino: target/root object's inode ID
 * @uuid: snapshot's UUID
 */
struct ssdfs_snapshot_details {
	u64 create_time;
	u64 cno;
	u32 mode;
	u32 expiration;
	u64 ino;
	u8 uuid[SSDFS_UUID_SIZE];
};

/*
 * struct ssdfs_snapshot_rule_details - snapshot rule details
 * @mode: snapshot mode (READ-ONLY|READ-WRITE)
 * @type: snapshot type (PERIODIC|ONE-TIME)
 * @expiration: snapshot expiration time (WEEK|MONTH|YEAR|NEVER)
 * @frequency: taking snapshot frequency (FSYNC|HOUR|DAY|WEEK)
 * @snapshots_threshold: max number of simultaneously available snapshots
 * @snapshots_number: currently created number of snapshots
 * @last_snapshot_cno: checkpoint of last snapshot
 * @ino: target/root object's inode ID
 * @uuid: snapshot's UUID
 */
struct ssdfs_snapshot_rule_details {
	u32 mode;
	u32 type;
	u32 expiration;
	u32 frequency;
	u32 snapshots_threshold;
	u32 snapshots_number;
	u64 last_snapshot_cno;
	u64 ino;
	u8 uuid[SSDFS_UUID_SIZE];
};

/*
 * struct ssdfs_snapshot_info - snapshot details
 * @name: snapshot name
 * @uuid: snapshot UUID
 * @mode: snapshot mode (READ-ONLY|READ-WRITE)
 * @type: snapshot type (PERIODIC|ONE-TIME)
 * @expiration: snapshot expiration time (WEEK|MONTH|YEAR|NEVER)
 * @frequency: taking snapshot frequency (FSYNC|HOUR|DAY|WEEK)
 * @snapshots_threshold: max number of simultaneously available snapshots
 * @time_range: time range to select/modify/delete snapshots
 * @buf: buffer to share the snapshot details
 * @buf_size: size of buffer in bytes
 */
struct ssdfs_snapshot_info {
	char name[SSDFS_MAX_NAME_LEN];
	u8 uuid[SSDFS_UUID_SIZE];

	int mode;
	int type;
	int expiration;
	int frequency;
	u32 snapshots_threshold;
	struct ssdfs_time_range time_range;

	char __user *buf;
	u64 buf_size;
};

/* Requested operation */
enum {
	SSDFS_UNKNOWN_OPERATION,
	SSDFS_CREATE_SNAPSHOT,
	SSDFS_LIST_SNAPSHOTS,
	SSDFS_MODIFY_SNAPSHOT,
	SSDFS_REMOVE_SNAPSHOT,
	SSDFS_REMOVE_RANGE,
	SSDFS_SHOW_SNAPSHOT_DETAILS,
	SSDFS_LIST_SNAPSHOT_RULES,
	SSDFS_OPERATION_TYPE_MAX
};

/*
 * struct ssdfs_snapshot_request - snapshot request
 * @list: snapshot requests queue list
 * @operation: requested operation
 * @ino: inode ID of object under snapshot
 * @info: snapshot request's info
 */
struct ssdfs_snapshot_request {
	struct list_head list;
	int operation;
	u64 ino;
	struct ssdfs_snapshot_info info;
};

/*
 * struct ssdfs_snapshot_rule_item - snapshot rule item
 * @list: snapshot rules list
 * @rule: snapshot rule's info
 */
struct ssdfs_snapshot_rule_item {
	struct list_head list;
	struct ssdfs_snapshot_rule_info rule;
};

/*
 * struct ssdfs_timestamp_range - range of timestamps
 * @start: starting timestamp
 * @end: ending timestamp
 */
struct ssdfs_timestamp_range {
	u64 start;
	u64 end;
};

/*
 * struct ssdfs_snapshot_id - snapshot ID
 * @timestamp: snapshot timestamp
 * @uuid: snapshot UUID (could be NULL)
 * @name: snapshot name (could be NULL)
 */
struct ssdfs_snapshot_id {
	u64 timestamp;
	u8 *uuid;
	char *name;
};

#define SSDFS_UNKNOWN_TIMESTAMP		(0)

#define SSDFS_SNAP_DETAILS(ptr) \
	((struct ssdfs_snapshot_details *)(ptr))
#define SSDFS_SNAP_RULE_DETAILS(ptr) \
	((struct ssdfs_snapshot_rule_details *)(ptr))

struct ssdfs_snapshot_subsystem;
struct ssdfs_fs_info;

/*
 * Inline functions
 */

static inline
bool is_snapshot_rule_requested(struct ssdfs_snapshot_request *snr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!snr);
#endif /* CONFIG_SSDFS_DEBUG */

	return snr->info.type == SSDFS_PERIODIC_SNAPSHOT;
}

static inline
bool is_ssdfs_snapshot_mode_correct(int mode)
{
	switch (mode) {
	case SSDFS_READ_ONLY_SNAPSHOT:
	case SSDFS_READ_WRITE_SNAPSHOT:
		return true;

	default:
		/* do nothing */
		break;
	}

	return false;
}

static inline
bool is_ssdfs_snapshot_type_correct(int type)
{
	switch (type) {
	case SSDFS_ONE_TIME_SNAPSHOT:
	case SSDFS_PERIODIC_SNAPSHOT:
		return true;

	default:
		/* do nothing */
		break;
	}

	return false;
}

static inline
bool is_ssdfs_snapshot_expiration_correct(int expiration)
{
	switch (expiration) {
	case SSDFS_EXPIRATION_IN_WEEK:
	case SSDFS_EXPIRATION_IN_MONTH:
	case SSDFS_EXPIRATION_IN_YEAR:
	case SSDFS_NEVER_EXPIRED:
		return true;

	default:
		/* do nothing */
		break;
	}

	return false;
}

static inline
bool is_ssdfs_snapshot_frequency_correct(int frequency)
{
	switch (frequency) {
	case SSDFS_SYNCFS_FREQUENCY:
	case SSDFS_HOUR_FREQUENCY:
	case SSDFS_DAY_FREQUENCY:
	case SSDFS_WEEK_FREQUENCY:
	case SSDFS_MONTH_FREQUENCY:
		return true;

	default:
		/* do nothing */
		break;
	}

	return false;
}

/*
 * is_uuids_identical() - check the UUIDs identity
 * @uuid1: first UUID instance
 * @uuid2: second UUID instance
 */
static inline
bool is_uuids_identical(const u8 *uuid1, const u8 *uuid2)
{
	return memcmp(uuid1, uuid2, SSDFS_UUID_SIZE) == 0;
}

/*
 * Snapshots subsystem's API
 */
int ssdfs_snapshot_subsystem_init(struct ssdfs_fs_info *fsi);
int ssdfs_snapshot_subsystem_destroy(struct ssdfs_fs_info *fsi);

int ssdfs_convert_time2timestamp_range(struct ssdfs_fs_info *fsi,
					struct ssdfs_time_range *range1,
					struct ssdfs_timestamp_range *range2);

#endif /* _SSDFS_SNAPSHOT_H */
