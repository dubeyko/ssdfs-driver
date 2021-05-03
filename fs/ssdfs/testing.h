//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/testing.h - testing infrastructure's declarations.
 *
 * Copyright (c) 2019-2021 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_TESTING_H
#define _SSDFS_TESTING_H

#include "common_bitmap.h"
#include "request_queue.h"

/* Enable tests */
#define SSDFS_ENABLE_EXTENTS_TREE_TESTING	(1 << 0)
#define SSDFS_ENABLE_DENTRIES_TREE_TESTING	(1 << 1)

#define SSDFS_FILE_SIZE_MAX_TESTING_THRESHOLD		(1073741824) // 1GB
#define SSDFS_EXTENT_LEN_TESTING_MAX			(16)

#define SSDFS_FILE_NUMBER_MAX_TESTING_THRESHOLD		(100000)

#ifdef CONFIG_SSDFS_TESTING
int ssdfs_do_testing(struct ssdfs_fs_info *fsi, u64 flags);
#else
static inline
int ssdfs_do_testing(struct ssdfs_fs_info *fsi, u64 flags)
{
	return 0;
}
#endif /* CONFIG_SSDFS_TESTING */

#endif /* _SSDFS_TESTING_H */
