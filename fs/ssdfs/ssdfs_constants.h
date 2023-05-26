// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs_constants.h - SSDFS constant declarations.
 *
 * Copyright (c) 2019-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_CONSTANTS_H
#define _SSDFS_CONSTANTS_H

/*
 * Thread types
 */
enum {
	SSDFS_PEB_READ_THREAD,
	SSDFS_PEB_FLUSH_THREAD,
	SSDFS_PEB_GC_THREAD,
#ifdef CONFIG_SSDFS_ONLINE_FSCK
	SSDFS_PEB_FSCK_THREAD,
#endif /* CONFIG_SSDFS_ONLINE_FSCK */
	SSDFS_PEB_THREAD_TYPE_MAX,
};

enum {
	SSDFS_SEG_USING_GC_THREAD,
	SSDFS_SEG_USED_GC_THREAD,
	SSDFS_SEG_PRE_DIRTY_GC_THREAD,
	SSDFS_SEG_DIRTY_GC_THREAD,
	SSDFS_GC_THREAD_TYPE_MAX,
};

enum {
	SSDFS_256B	= 256,
	SSDFS_512B	= 512,
	SSDFS_1KB	= 1024,
	SSDFS_2KB	= 2048,
	SSDFS_4KB	= 4096,
	SSDFS_8KB	= 8192,
	SSDFS_16KB	= 16384,
	SSDFS_32KB	= 32768,
	SSDFS_64KB	= 65536,
	SSDFS_128KB	= 131072,
	SSDFS_256KB	= 262144,
	SSDFS_512KB	= 524288,
	SSDFS_1MB	= 1048576,
	SSDFS_2MB	= 2097152,
	SSDFS_8MB	= 8388608,
	SSDFS_16MB	= 16777216,
	SSDFS_32MB	= 33554432,
	SSDFS_64MB	= 67108864,
	SSDFS_128MB	= 134217728,
	SSDFS_256MB	= 268435456,
	SSDFS_512MB	= 536870912,
	SSDFS_1GB	= 1073741824,
	SSDFS_2GB	= 2147483648,
	SSDFS_8GB	= 8589934592,
	SSDFS_16GB	= 17179869184,
	SSDFS_32GB	= 34359738368,
	SSDFS_64GB	= 68719476736,
};

enum {
	SSDFS_UNKNOWN_PAGE_TYPE,
	SSDFS_USER_DATA_PAGES,
	SSDFS_METADATA_PAGES,
	SSDFS_PAGES_TYPE_MAX
};

#define SSDFS_INVALID_CNO	U64_MAX
#define SSDFS_SECTOR_SHIFT	9
#define SSDFS_DEFAULT_TIMEOUT	(msecs_to_jiffies(120000))
#define SSDFS_NANOSECS_PER_SEC	(1000000000)
#define SSDFS_SECS_PER_HOUR	(60 * 60)
#define SSDFS_HOURS_PER_DAY	(24)
#define SSDFS_DAYS_PER_WEEK	(7)
#define SSDFS_WEEKS_PER_MONTH	(4)

/*
 * Every PEB contains a sequence of logs. Log starts from
 * header and could be ended by footer. Header and footer
 * requires as minimum 2 logical blocks for metadata.
 * It needs to prevent 2 logical blocks from allocation
 * in every erase block (PEB).
 */
#define SSDFS_RESERVED_FREE_PAGE_THRESHOLD_PER_PEB	(2)

#endif /* _SSDFS_CONSTANTS_H */
