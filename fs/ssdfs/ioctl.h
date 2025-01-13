/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ioctl.h - IOCTL related declaration.
 *
 * Copyright (c) 2019-2025 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_IOCTL_H
#define _SSDFS_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#include "testing.h"
#include "snapshot.h"

#define SSDFS_IOCTL_MAGIC 0xdf

/*
 * SSDFS_IOC_DO_TESTING - run internal testing
 */
#define SSDFS_IOC_DO_TESTING _IOW(SSDFS_IOCTL_MAGIC, 1, \
				  struct ssdfs_testing_environment)

/*
 * Snapshot related IOCTLs
 */
#define SSDFS_IOC_CREATE_SNAPSHOT	_IOW(SSDFS_IOCTL_MAGIC, 2, \
					     struct ssdfs_snapshot_info)
#define SSDFS_IOC_LIST_SNAPSHOTS	_IOWR(SSDFS_IOCTL_MAGIC, 3, \
					     struct ssdfs_snapshot_info)
#define SSDFS_IOC_MODIFY_SNAPSHOT	_IOW(SSDFS_IOCTL_MAGIC, 4, \
					     struct ssdfs_snapshot_info)
#define SSDFS_IOC_REMOVE_SNAPSHOT	_IOW(SSDFS_IOCTL_MAGIC, 5, \
					     struct ssdfs_snapshot_info)
#define SSDFS_IOC_REMOVE_RANGE		_IOW(SSDFS_IOCTL_MAGIC, 6, \
					     struct ssdfs_snapshot_info)
#define SSDFS_IOC_SHOW_DETAILS		_IOWR(SSDFS_IOCTL_MAGIC, 7, \
					     struct ssdfs_snapshot_info)
#define SSDFS_IOC_LIST_SNAPSHOT_RULES	_IOWR(SSDFS_IOCTL_MAGIC, 8, \
					     struct ssdfs_snapshot_info)

/*
 * The tunefs related IOCTLs
 */
#define SSDFS_IOC_TUNEFS_GET_CONFIG	_IOR(SSDFS_IOCTL_MAGIC, 9, \
					     struct ssdfs_tunefs_options)
#define SSDFS_IOC_TUNEFS_SET_CONFIG	_IOWR(SSDFS_IOCTL_MAGIC, 10, \
					     struct ssdfs_tunefs_options)

#endif /* _SSDFS_IOCTL_H */
