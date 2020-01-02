//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment.h - segment concept declarations.
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

#ifndef _SSDFS_SEGMENT_H
#define _SSDFS_SEGMENT_H

#include "peb.h"
#include "segment_block_bitmap.h"

/* Available indexes for destination */
enum {
	SSDFS_LAST_DESTINATION,
	SSDFS_CREATING_DESTINATION,
	SSDFS_DESTINATION_MAX
};

/* Possible states of destination descriptor */
enum {
	SSDFS_EMPTY_DESTINATION,
	SSDFS_DESTINATION_UNDER_CREATION,
	SSDFS_VALID_DESTINATION,
	SSDFS_OBSOLETE_DESTINATION,
	SSDFS_DESTINATION_STATE_MAX
};

/*
 * struct ssdfs_migration_destination - destination descriptor
 * @state: descriptor's state
 * @destination_pebs: count of destination PEBs for migration
 * @shared_peb_index: shared index of destination PEB for migration
 */
struct ssdfs_migration_destination {
	int state;
	int destination_pebs;
	int shared_peb_index;
};

/*
 * struct ssdfs_segment_migration_info - migration info
 * @migrating_pebs: count of migrating PEBs
 * @wait: wait queue for relation creation
 * @lock: migration data lock
 * @array: destination descriptors
 */
struct ssdfs_segment_migration_info {
	atomic_t migrating_pebs;
	wait_queue_head_t wait;

	spinlock_t lock;
	struct ssdfs_migration_destination array[SSDFS_DESTINATION_MAX];
};

/*
 * struct ssdfs_segment_info - segment object description
 * @seg_id: segment identification number
 * @log_pages: count of pages in full partial log
 * @create_threads: number of flush PEB's threads for new page requests
 * @seg_type: segment type
 * @peb_array: array of PEB's descriptors
 * @pebs_count: count of items in PEBS array
 * @migration: migration info
 * @refs_count: counter of references on segment object
 * @destruct_queue: wait queue for segment destruction
 * @seg_state: current state of segment
 * @create_rq: new page requests queue
 * @wait_queue: array of PEBs' wait queues
 * @blk_bmap: segment's block bitmap
 * @blk2off_table: offset translation table
 * @fsi: pointer on shared file system object
 * @seg_kobj: /sys/fs/ssdfs/<device>/<segN> kernel object
 * @seg_kobj_unregister: completion state for <segN> kernel object
 */
struct ssdfs_segment_info {
	/* Static data */
	u64 seg_id;
	u16 log_pages;
	u8 create_threads;
	u16 seg_type;

	/* Segment's PEB's containers array */
	struct ssdfs_peb_container *peb_array;
	u16 pebs_count;

	/* Migration info */
	struct ssdfs_segment_migration_info migration;

	/* Reference counter */
	atomic_t refs_count;
	wait_queue_head_t destruct_queue;

	/* Mutable data */
	atomic_t seg_state;

	/*
	 * New pages processing:
	 * requests queue, wait queue
	 */
	struct ssdfs_requests_queue create_rq;

	/* Threads' wait queues */
	wait_queue_head_t wait_queue[SSDFS_PEB_THREAD_TYPE_MAX];

	struct ssdfs_segment_blk_bmap blk_bmap;
	struct ssdfs_blk2off_table *blk2off_table;
	struct ssdfs_fs_info *fsi;

	/* /sys/fs/ssdfs/<device>/<segN> */
	struct kobject seg_kobj;
	struct completion seg_kobj_unregister;
	struct ssdfs_sysfs_seg_subgroups *seg_subgroups;
};

/*
 * Inline functions
 */

/*
 * CUR_SEG_TYPE() - convert request class into current segment type
 */
static inline
int CUR_SEG_TYPE(int req_class)
{
	int cur_seg_type = SSDFS_CUR_SEGS_COUNT;

	switch (req_class) {
	case SSDFS_PEB_PRE_ALLOCATE_DATA_REQ:
	case SSDFS_PEB_CREATE_DATA_REQ:
		cur_seg_type = SSDFS_CUR_DATA_SEG;
		break;

	case SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ:
	case SSDFS_PEB_CREATE_LNODE_REQ:
		cur_seg_type = SSDFS_CUR_LNODE_SEG;
		break;

	case SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ:
	case SSDFS_PEB_CREATE_HNODE_REQ:
		cur_seg_type = SSDFS_CUR_HNODE_SEG;
		break;

	case SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ:
	case SSDFS_PEB_CREATE_IDXNODE_REQ:
		cur_seg_type = SSDFS_CUR_IDXNODE_SEG;
		break;

	default:
		BUG();
	}

	return cur_seg_type;
}

/*
 * SEG_TYPE() - convert request class into segment type
 */
static inline
int SEG_TYPE(int req_class)
{
	int seg_type = SSDFS_LAST_KNOWN_SEG_TYPE;

	switch (req_class) {
	case SSDFS_PEB_PRE_ALLOCATE_DATA_REQ:
	case SSDFS_PEB_CREATE_DATA_REQ:
		seg_type = SSDFS_USER_DATA_SEG_TYPE;
		break;

	case SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ:
	case SSDFS_PEB_CREATE_LNODE_REQ:
		seg_type = SSDFS_LEAF_NODE_SEG_TYPE;
		break;

	case SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ:
	case SSDFS_PEB_CREATE_HNODE_REQ:
		seg_type = SSDFS_HYBRID_NODE_SEG_TYPE;
		break;

	case SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ:
	case SSDFS_PEB_CREATE_IDXNODE_REQ:
		seg_type = SSDFS_INDEX_NODE_SEG_TYPE;
		break;

	default:
		BUG();
	}

	return seg_type;
}

/*
 * SEG_TYPE_TO_USING_STATE() - convert segment type to segment using state
 * @seg_type: segment type
 */
static inline
int SEG_TYPE_TO_USING_STATE(u16 seg_type)
{
	switch (seg_type) {
	case SSDFS_USER_DATA_SEG_TYPE:
		return SSDFS_SEG_DATA_USING;

	case SSDFS_LEAF_NODE_SEG_TYPE:
		return SSDFS_SEG_LEAF_NODE_USING;

	case SSDFS_HYBRID_NODE_SEG_TYPE:
		return SSDFS_SEG_HYBRID_NODE_USING;

	case SSDFS_INDEX_NODE_SEG_TYPE:
		return SSDFS_SEG_INDEX_NODE_USING;
	}

	return SSDFS_SEG_STATE_MAX;
}

/*
 * Segment object's API
 */
struct ssdfs_segment_info *
ssdfs_segment_create_object(struct ssdfs_fs_info *fsi,
			    u64 seg,
			    int seg_state,
			    u16 seg_type,
			    u16 log_pages,
			    u8 create_threads);
int ssdfs_segment_destroy_object(struct ssdfs_segment_info *si);
void ssdfs_segment_get_object(struct ssdfs_segment_info *si);
void ssdfs_segment_put_object(struct ssdfs_segment_info *si);

struct ssdfs_segment_info *
ssdfs_grab_segment(struct ssdfs_fs_info *fsi, int seg_type, u64 seg_id);

int ssdfs_segment_read_block_sync(struct ssdfs_segment_info *si,
				  struct ssdfs_segment_request *req);
int ssdfs_segment_read_block_async(struct ssdfs_segment_info *si,
				  struct ssdfs_segment_request *req);

int ssdfs_segment_pre_alloc_data_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_data_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_leaf_node_block_sync(struct ssdfs_fs_info *fsi,
					   struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_leaf_node_block_async(struct ssdfs_fs_info *fsi,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_hybrid_node_block_sync(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_hybrid_node_block_async(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_index_node_block_sync(struct ssdfs_fs_info *fsi,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_index_node_block_async(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);

int ssdfs_segment_add_data_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req);
int ssdfs_segment_add_data_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req);
int ssdfs_segment_add_leaf_node_block_sync(struct ssdfs_fs_info *fsi,
					   struct ssdfs_segment_request *req);
int ssdfs_segment_add_leaf_node_block_async(struct ssdfs_fs_info *fsi,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_add_hybrid_node_block_sync(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);
int ssdfs_segment_add_hybrid_node_block_async(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);
int ssdfs_segment_add_index_node_block_sync(struct ssdfs_fs_info *fsi,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_add_index_node_block_async(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);

int ssdfs_segment_pre_alloc_data_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_data_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_leaf_node_extent_sync(struct ssdfs_fs_info *fsi,
					   struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_leaf_node_extent_async(struct ssdfs_fs_info *fsi,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_hybrid_node_extent_sync(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_hybrid_node_extent_async(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_index_node_extent_sync(struct ssdfs_fs_info *fsi,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_pre_alloc_index_node_extent_async(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);

int ssdfs_segment_add_data_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req);
int ssdfs_segment_add_data_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req);
int ssdfs_segment_add_leaf_node_extent_sync(struct ssdfs_fs_info *fsi,
					   struct ssdfs_segment_request *req);
int ssdfs_segment_add_leaf_node_extent_async(struct ssdfs_fs_info *fsi,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_add_hybrid_node_extent_sync(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);
int ssdfs_segment_add_hybrid_node_extent_async(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);
int ssdfs_segment_add_index_node_extent_sync(struct ssdfs_fs_info *fsi,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_add_index_node_extent_async(struct ssdfs_fs_info *fsi,
					     struct ssdfs_segment_request *req);

int ssdfs_segment_update_block_sync(struct ssdfs_segment_info *si,
				    struct ssdfs_segment_request *req);
int ssdfs_segment_update_block_async(struct ssdfs_segment_info *si,
				     int req_type,
				     struct ssdfs_segment_request *req);
int ssdfs_segment_update_extent_sync(struct ssdfs_segment_info *si,
				     struct ssdfs_segment_request *req);
int ssdfs_segment_update_extent_async(struct ssdfs_segment_info *si,
				      int req_type,
				      struct ssdfs_segment_request *req);
int ssdfs_segment_update_pre_alloc_block_sync(struct ssdfs_segment_info *si,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_update_pre_alloc_block_async(struct ssdfs_segment_info *si,
					    int req_type,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_update_pre_alloc_extent_sync(struct ssdfs_segment_info *si,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_update_pre_alloc_extent_async(struct ssdfs_segment_info *si,
					    int req_type,
					    struct ssdfs_segment_request *req);

int ssdfs_segment_prepare_migration_sync(struct ssdfs_segment_info *si,
					 struct ssdfs_segment_request *req);
int ssdfs_segment_prepare_migration_async(struct ssdfs_segment_info *si,
					  int req_type,
					  struct ssdfs_segment_request *req);
int ssdfs_segment_commit_log_sync(struct ssdfs_segment_info *si,
				  struct ssdfs_segment_request *req);
int ssdfs_segment_commit_log_async(struct ssdfs_segment_info *si,
				   int req_type,
				   struct ssdfs_segment_request *req);

int ssdfs_segment_invalidate_logical_block(struct ssdfs_segment_info *si,
					   u32 blk_offset);
int ssdfs_segment_invalidate_logical_extent(struct ssdfs_segment_info *si,
					    u32 start_off, u32 blks_count);

int ssdfs_segment_migrate_range_async(struct ssdfs_segment_info *si,
				      struct ssdfs_segment_request *req);
int ssdfs_segment_migrate_pre_alloc_page_async(struct ssdfs_segment_info *si,
					    struct ssdfs_segment_request *req);
int ssdfs_segment_migrate_fragment_async(struct ssdfs_segment_info *si,
					 struct ssdfs_segment_request *req);

#endif /* _SSDFS_SEGMENT_H */
