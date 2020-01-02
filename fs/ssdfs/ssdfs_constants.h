//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs_constants.h - SSDFS constant declarations.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
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
	SSDFS_PEB_THREAD_TYPE_MAX,
};

enum {
	SSDFS_512B	= 512,
	SSDFS_2KB	= 2048,
	SSDFS_4KB	= 4096,
	SSDFS_8KB	= 8192,
	SSDFS_16KB	= 16384,
	SSDFS_128KB	= 131072,
	SSDFS_256KB	= 262144,
	SSDFS_512KB	= 524288,
	SSDFS_2MB	= 2097152,
	SSDFS_8MB	= 8388608,
};

#define SSDFS_INVALID_CNO	U64_MAX
#define SSDFS_SECTOR_SHIFT	9
#define SSDFS_DEFAULT_TIMEOUT	(msecs_to_jiffies(120000))

#endif /* _SSDFS_CONSTANTS_H */
