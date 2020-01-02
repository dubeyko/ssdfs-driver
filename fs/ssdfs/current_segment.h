//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/current_segment.h - current segment abstraction declarations.
 *
 * Copyright (c) 2014-2020 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2020, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#ifndef _SSDFS_CURRENT_SEGMENT_H
#define _SSDFS_CURRENT_SEGMENT_H

/*
 * struct ssdfs_current_segment - current segment container
 * @lock: exclusive lock of current segment object
 * @type: current segment type
 * @real_seg: concrete current segment
 * @fsi: pointer on shared file system object
 */
struct ssdfs_current_segment {
	struct mutex lock;
	int type;
	struct ssdfs_segment_info *real_seg;
	struct ssdfs_fs_info *fsi;
};

/*
 * struct ssdfs_current_segs_array - array of current segments
 * @lock: current segments array's lock
 * @objects: array of pointers on current segment objects
 * @buffer: buffer for all current segment objects
 */
struct ssdfs_current_segs_array {
	struct rw_semaphore lock;
	struct ssdfs_current_segment *objects[SSDFS_CUR_SEGS_COUNT];
	u8 buffer[sizeof(struct ssdfs_current_segment) * SSDFS_CUR_SEGS_COUNT];
};

/*
 * Inline functions
 */
static inline
bool is_ssdfs_current_segment_empty(struct ssdfs_current_segment *cur_seg)
{
	return cur_seg->real_seg == NULL;
}

/*
 * Current segment container's API
 */
int ssdfs_current_segment_array_create(struct ssdfs_fs_info *fsi);
void ssdfs_destroy_all_curent_segments(struct ssdfs_fs_info *fsi);
void ssdfs_current_segment_array_destroy(struct ssdfs_fs_info *fsi);

void ssdfs_current_segment_lock(struct ssdfs_current_segment *cur_seg);
void ssdfs_current_segment_unlock(struct ssdfs_current_segment *cur_seg);

int ssdfs_current_segment_add(struct ssdfs_current_segment *cur_seg,
			      struct ssdfs_segment_info *si);
void ssdfs_current_segment_remove(struct ssdfs_current_segment *cur_seg);

#endif /* _SSDFS_CURRENT_SEGMENT_H */
