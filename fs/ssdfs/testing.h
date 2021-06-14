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

/*
 * struct ssdfs_testing_environment - define testing environment
 * @subsystems: enable testing particular subsystems
 * @page_size: logical block size in bytes
 *
 * @files_number_threshold: maximum number of files
 *
 * @file_size_threshold: maximum size of file in bytes
 * @extent_len_threshold: maximum extent length in logical blocks
 */
struct ssdfs_testing_environment {
	u64 subsystems;
	u32 page_size;

	u64 files_number_threshold;

	u64 file_size_threshold;
	u16 extent_len_threshold;
};

/* Subsystem tests */
#define SSDFS_ENABLE_EXTENTS_TREE_TESTING	(1 << 0)
#define SSDFS_ENABLE_DENTRIES_TREE_TESTING	(1 << 1)

#ifdef CONFIG_SSDFS_TESTING
int ssdfs_do_testing(struct ssdfs_fs_info *fsi,
		     struct ssdfs_testing_environment *env);
#else
static inline
int ssdfs_do_testing(struct ssdfs_fs_info *fsi,
		     struct ssdfs_testing_environment *env)
{
	SSDFS_ERR("Testing is not supported. "
		  "Please, enable CONFIG_SSDFS_TESTING option.\n");

	return -EOPNOTSUPP;
}
#endif /* CONFIG_SSDFS_TESTING */

#endif /* _SSDFS_TESTING_H */
