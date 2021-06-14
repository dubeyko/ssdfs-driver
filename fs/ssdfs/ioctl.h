//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ioctl.h - IOCTL related declaration.
 *
 * Copyright (c) 2019-2021 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_IOCTL_H
#define _SSDFS_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#include "testing.h"

#define SSDFS_IOCTL_MAGIC 0xdf

/*
 * SSDFS_IOC_DO_TESTING - run internal testing
 */
#define SSDFS_IOC_DO_TESTING _IOW(SSDFS_IOCTL_MAGIC, 1, \
				  struct ssdfs_testing_environment)

#endif /* _SSDFS_IOCTL_H */
