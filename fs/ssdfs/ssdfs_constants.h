//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 *  SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs_constants.h - SSDFS constant declarations.
 *
 * Copyright (c) 2019 Viacheslav Dubeyko <slava@dubeyko.com>
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

#endif /* _SSDFS_CONSTANTS_H */
