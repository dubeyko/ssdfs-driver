//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshot.h - snapshot's declarations.
 *
 * Copyright (c) 2021 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_SNAPSHOT_H
#define _SSDFS_SNAPSHOT_H

/*
 * struct ssdfs_time_range - time range definition
 * @day: day of the time range
 * @month: month of the time range
 * @year: year of the time range
 */
struct ssdfs_time_range {
	u32 day;
	u32 month;
	u32 year;
};

#define SSDFS_ANY_DAY				U32_MAX
#define SSDFS_ANY_MONTH				U32_MAX
#define SSDFS_ANY_YEAR				U32_MAX

/*
 * struct ssdfs_snapshot_info - snapshot details
 * @name: snapshot name
 * @uuid: snapshot UUID
 * @mode: snapshot mode (READ-ONLY|READ-WRITE)
 * @type: snapshot type (PERIODIC|ONE-TIME)
 * @expiration: snapshot expiration time (WEEK|MONTH|YEAR|NEVER)
 * @frequency: taking snapshot frequency (FSYNC|HOUR|DAY|WEEK)
 * @existing_snapshots: max number of simultaneously available snapshots
 * @time_range: time range to select/modify/delete snapshots
 */
struct ssdfs_snapshot_info {
	char name[SSDFS_MAX_NAME_LEN];
	u8 uuid[SSDFS_UUID_SIZE];

	int mode;
	int type;
	int expiration;
	int frequency;
	u32 existing_snapshots;
	struct ssdfs_time_range time_range;
};

/* Snapshot mode */
enum {
	SSDFS_UNKNOWN_SNAPSHOT_MODE,
	SSDFS_READ_ONLY_SNAPSHOT,
	SSDFS_READ_WRITE_SNAPSHOT,
	SSDFS_SNAPSHOT_MODE_MAX
};

#define SSDFS_READ_ONLY_MODE_STR	"READ_ONLY"
#define SSDFS_READ_WRITE_MODE_STR	"READ_WRITE"

/* Snapshot type */
enum {
	SSDFS_UNKNOWN_SNAPSHOT_TYPE,
	SSDFS_ONE_TIME_SNAPSHOT,
	SSDFS_PERIODIC_SNAPSHOT,
	SSDFS_SNAPSHOT_TYPE_MAX
};

#define SSDFS_ONE_TIME_TYPE_STR		"ONE-TIME"
#define SSDFS_PERIODIC_TYPE_STR		"PERIODIC"

/* Snapshot expiration */
enum {
	SSDFS_UNKNOWN_EXPIRATION_POINT,
	SSDFS_EXPIRATION_IN_WEEK,
	SSDFS_EXPIRATION_IN_MONTH,
	SSDFS_EXPIRATION_IN_YEAR,
	SSDFS_NEVER_EXPIRED,
	SSDFS_EXPIRATION_POINT_MAX
};

#define SSDFS_WEEK_EXPIRATION_POINT_STR		"WEEK"
#define SSDFS_MONTH_EXPIRATION_POINT_STR	"MONTH"
#define SSDFS_YEAR_EXPIRATION_POINT_STR		"YEAR"
#define SSDFS_NEVER_EXPIRED_STR			"NEVER"

/* Snapshot creation frequency */
enum {
	SSDFS_UNKNOWN_FREQUENCY,
	SSDFS_FSYNC_FREQUENCY,
	SSDFS_HOUR_FREQUENCY,
	SSDFS_DAY_FREQUENCY,
	SSDFS_WEEK_FREQUENCY,
	SSDFS_MONTH_FREQUENCY,
	SSDFS_CREATION_FREQUENCY_MAX
};

#define SSDFS_FSYNC_FREQUENCY_STR		"FSYNC"
#define SSDFS_HOUR_FREQUENCY_STR		"HOUR"
#define SSDFS_DAY_FREQUENCY_STR			"DAY"
#define SSDFS_WEEK_FREQUENCY_STR		"WEEK"
#define SSDFS_MONTH_FREQUENCY_STR		"MONTH"

#define SSDFS_INFINITE_SNAPSHOTS_NUMBER		U32_MAX
#define SSDFS_UNDEFINED_SNAPSHOTS_NUMBER	(0)

#endif /* _SSDFS_SNAPSHOT_H */
