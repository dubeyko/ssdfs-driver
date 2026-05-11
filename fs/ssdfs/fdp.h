/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/fdp.h - FDP (Flexible Data Placement) support declarations.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_FDP_H
#define _SSDFS_FDP_H

#include <linux/ssdfs_fs.h>

/*
 * SSDFS_FDP_STREAM_NONE - no explicit placement hint (device default)
 *
 * Using stream 0 tells the block layer and FDP-capable NVMe devices to
 * apply their own placement policy, giving up host-directed placement.
 */
#define SSDFS_FDP_STREAM_NONE		0

/*
 * Minimum number of FDP write streams required to activate FDP support.
 * With fewer than 2 streams, there is no benefit in host-directed placement.
 */
#define SSDFS_FDP_MIN_STREAMS		2

/*
 * struct ssdfs_fdp_hint - per-file FDP write-stream preference
 * @write_stream: FDP placement stream ID for this file's user data.
 * @reserved: padding, must be zero
 */
struct ssdfs_fdp_hint {
	__u8  write_stream;
	__u8  reserved[3];
};

/*
 * struct ssdfs_fdp_info - FDP capability and current configuration
 * @streams_count: number of FDP write streams on this device (0 = no FDP)
 * @inode_stream: the explicit stream set on the queried inode (0 = auto)
 * @reserved: padding, must be zero
 */
struct ssdfs_fdp_info {
	__u16 streams_count;
	__u8  inode_stream;
	__u8  reserved;
};

void ssdfs_bdev_detect_fdp(struct ssdfs_fs_info *fsi);
u8 ssdfs_seg2fdp_stream(struct ssdfs_fs_info *fsi, int type);

#endif /* _SSDFS_FDP_H */
