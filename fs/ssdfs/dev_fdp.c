/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dev_fdp.c - FDP (Flexible Data Placement) support implementation.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "fdp.h"

#include <trace/events/ssdfs.h>

/*
 * ssdfs_fdp_init_stream_map() - assign write streams to segment types
 * @fsi: in-core filesystem info
 */
static void ssdfs_fdp_init_stream_map(struct ssdfs_fs_info *fsi)
{
	u16 max_streams = fsi->device.fdp.streams_count;

	memset(fsi->device.fdp.stream_map, SSDFS_FDP_STREAM_NONE,
	       sizeof(fsi->device.fdp.stream_map));

	if (max_streams < SSDFS_FDP_MIN_STREAMS)
		return;

	if (max_streams == 2) {
		fsi->device.fdp.metadata_streams = 1;
		fsi->device.fdp.user_data_streams = 1;

		fsi->device.fdp.stream_map[SSDFS_SB_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_INITIAL_SNAPSHOT_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_SEGBMAP_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_MAPTBL_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_LEAF_NODE_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_HYBRID_NODE_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_INDEX_NODE_SEG_TYPE] = 1;

		fsi->device.fdp.stream_map[SSDFS_USER_DATA_SEG_TYPE] = 2;
	} else if (max_streams == 3) {
		fsi->device.fdp.metadata_streams = 2;
		fsi->device.fdp.user_data_streams = 1;

		fsi->device.fdp.stream_map[SSDFS_SB_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_INITIAL_SNAPSHOT_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_SEGBMAP_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_MAPTBL_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_LEAF_NODE_SEG_TYPE] = 2;
		fsi->device.fdp.stream_map[SSDFS_HYBRID_NODE_SEG_TYPE] = 2;
		fsi->device.fdp.stream_map[SSDFS_INDEX_NODE_SEG_TYPE] = 2;

		fsi->device.fdp.stream_map[SSDFS_USER_DATA_SEG_TYPE] = 3;
	} else if (max_streams == 4) {
		fsi->device.fdp.metadata_streams = 3;
		fsi->device.fdp.user_data_streams = 1;

		fsi->device.fdp.stream_map[SSDFS_SB_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_INITIAL_SNAPSHOT_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_SEGBMAP_SEG_TYPE] = 2;
		fsi->device.fdp.stream_map[SSDFS_MAPTBL_SEG_TYPE] = 2;
		fsi->device.fdp.stream_map[SSDFS_LEAF_NODE_SEG_TYPE] = 3;
		fsi->device.fdp.stream_map[SSDFS_HYBRID_NODE_SEG_TYPE] = 3;
		fsi->device.fdp.stream_map[SSDFS_INDEX_NODE_SEG_TYPE] = 3;

		fsi->device.fdp.stream_map[SSDFS_USER_DATA_SEG_TYPE] = 4;
	} else if (max_streams == 5) {
		fsi->device.fdp.metadata_streams = 4;
		fsi->device.fdp.user_data_streams = 1;

		fsi->device.fdp.stream_map[SSDFS_SB_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_INITIAL_SNAPSHOT_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_SEGBMAP_SEG_TYPE] = 2;
		fsi->device.fdp.stream_map[SSDFS_MAPTBL_SEG_TYPE] = 3;
		fsi->device.fdp.stream_map[SSDFS_LEAF_NODE_SEG_TYPE] = 4;
		fsi->device.fdp.stream_map[SSDFS_HYBRID_NODE_SEG_TYPE] = 4;
		fsi->device.fdp.stream_map[SSDFS_INDEX_NODE_SEG_TYPE] = 4;

		fsi->device.fdp.stream_map[SSDFS_USER_DATA_SEG_TYPE] = 5;
	} else {
		fsi->device.fdp.metadata_streams = 4;
		fsi->device.fdp.user_data_streams =
			max_streams - fsi->device.fdp.metadata_streams;

		fsi->device.fdp.stream_map[SSDFS_SB_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_INITIAL_SNAPSHOT_SEG_TYPE] = 1;
		fsi->device.fdp.stream_map[SSDFS_SEGBMAP_SEG_TYPE] = 2;
		fsi->device.fdp.stream_map[SSDFS_MAPTBL_SEG_TYPE] = 3;
		fsi->device.fdp.stream_map[SSDFS_LEAF_NODE_SEG_TYPE] = 4;
		fsi->device.fdp.stream_map[SSDFS_HYBRID_NODE_SEG_TYPE] = 4;
		fsi->device.fdp.stream_map[SSDFS_INDEX_NODE_SEG_TYPE] = 4;

		fsi->device.fdp.stream_map[SSDFS_USER_DATA_SEG_TYPE] = 5;
	}
}

/*
 * ssdfs_bdev_detect_fdp() - probe FDP support and build stream map
 * @fsi: in-core filesystem info
 *
 * Queries the block device for NVMe write-stream support. If the device
 * reports at least SSDFS_FDP_MIN_STREAMS, populates stream_map[] with
 * a stream assignment for each segment type.
 *
 * Calling this on an MTD, ZNS, or regular device is safe;
 * in that case the function does nothing.
 */
void ssdfs_bdev_detect_fdp(struct ssdfs_fs_info *fsi)
{
	u16 max_streams;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!fsi->sb->s_bdev)
		return;

	switch (fsi->device.type) {
	case SSDFS_REGULAR_DEVICE:
		/* continue logic */
		break;

	default:
		SSDFS_WARN("incorrect call of method!!!\n");
		return;
	}

	max_streams = bdev_max_write_streams(fsi->sb->s_bdev);
	if (max_streams < SSDFS_FDP_MIN_STREAMS)
		return;

	fsi->device.type = SSDFS_FDP_DEVICE;
	fsi->device.fdp.streams_count = max_streams;
	fsi->device.fdp.metadata_streams = 0;
	fsi->device.fdp.user_data_streams = max_streams;

	ssdfs_fdp_init_stream_map(fsi);

	SSDFS_INFO("FDP: device supports %u write streams; "
		   "enabled host-directed data placement\n",
		   max_streams);
}

/*
 * ssdfs_seg2fdp_stream() - stream ID for a segment type
 * @fsi: in-core filesystem info
 * @type: segment type
 *
 * Returns the configured FDP write-stream ID, or SSDFS_FDP_STREAM_NONE
 * when FDP is not active or the type is out of range.
 */
u8 ssdfs_seg2fdp_stream(struct ssdfs_fs_info *fsi, int type)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (fsi->device.type) {
	case SSDFS_FDP_DEVICE:
		/* continue logic */
		break;

	default:
		return SSDFS_FDP_STREAM_NONE;
	}

	if (type < SSDFS_UNKNOWN_SEG_TYPE || type > SSDFS_LAST_KNOWN_SEG_TYPE)
		return SSDFS_FDP_STREAM_NONE;

	return fsi->device.fdp.stream_map[type];
}
