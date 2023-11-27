// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/request_queue.h - request queue declarations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 *
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot
 *                  Zvonimir Bandic
 */

#ifndef _SSDFS_REQUEST_QUEUE_H
#define _SSDFS_REQUEST_QUEUE_H

#include <linux/pagevec.h>

/*
 * struct ssdfs_requests_queue - requests queue descriptor
 * @lock: requests queue's lock
 * @list: requests queue's list
 */
struct ssdfs_requests_queue {
	spinlock_t lock;
	struct list_head list;
};

/*
 * Request classes
 */
enum {
	SSDFS_UNKNOWN_REQ_CLASS,		/* 0x00 */
	SSDFS_PEB_READ_REQ,			/* 0x01 */
	SSDFS_PEB_PRE_ALLOCATE_DATA_REQ,	/* 0x02 */
	SSDFS_PEB_CREATE_DATA_REQ,		/* 0x03 */
	SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ,	/* 0x04 */
	SSDFS_PEB_CREATE_LNODE_REQ,		/* 0x05 */
	SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ,	/* 0x06 */
	SSDFS_PEB_CREATE_HNODE_REQ,		/* 0x07 */
	SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ,	/* 0x08 */
	SSDFS_PEB_CREATE_IDXNODE_REQ,		/* 0x09 */
	SSDFS_PEB_UPDATE_REQ,			/* 0x0A */
	SSDFS_PEB_PRE_ALLOC_UPDATE_REQ,		/* 0x0B */
	SSDFS_PEB_DIFF_ON_WRITE_REQ,		/* 0x0C */
	SSDFS_PEB_COLLECT_GARBAGE_REQ,		/* 0x0D */
	SSDFS_ZONE_USER_DATA_MIGRATE_REQ,	/* 0x0E */
	SSDFS_PEB_FSCK_CHECK_REQ,		/* 0x0F */
	SSDFS_PEB_REQ_CLASS_MAX,		/* 0x10 */
};

/*
 * Request commands
 */
enum {
	SSDFS_UNKNOWN_CMD,			/* 0x00 */
	SSDFS_READ_PAGE,			/* 0x01 */
	SSDFS_READ_PAGES_READAHEAD,		/* 0x02 */
	SSDFS_READ_SRC_ALL_LOG_HEADERS,		/* 0x03 */
	SSDFS_READ_DST_ALL_LOG_HEADERS,		/* 0x04 */
	SSDFS_READ_BLK_BMAP_INIT_CLEAN_PEB,	/* 0x05 */
	SSDFS_READ_BLK_BMAP_SRC_USING_PEB,	/* 0x06 */
	SSDFS_READ_BLK_BMAP_DST_USING_PEB,	/* 0x07 */
	SSDFS_READ_BLK_BMAP_SRC_USED_PEB,	/* 0x08 */
	SSDFS_READ_BLK_BMAP_DST_USED_PEB,	/* 0x09 */
	SSDFS_READ_BLK2OFF_TABLE_SRC_PEB,	/* 0x0A */
	SSDFS_READ_BLK2OFF_TABLE_DST_PEB,	/* 0x0B */
	SSDFS_READ_INIT_SEGBMAP,		/* 0x0C */
	SSDFS_READ_INIT_MAPTBL,			/* 0x0D */
	SSDFS_READ_SRC_LAST_LOG_FOOTER,		/* 0x0E */
	SSDFS_READ_DST_LAST_LOG_FOOTER,		/* 0x0F */
	SSDFS_READ_CMD_MAX,			/* 0x10 */
	SSDFS_CREATE_BLOCK,			/* 0x11 */
	SSDFS_CREATE_EXTENT,			/* 0x12 */
	SSDFS_MIGRATE_ZONE_USER_BLOCK,		/* 0x13 */
	SSDFS_MIGRATE_ZONE_USER_EXTENT,		/* 0x14 */
	SSDFS_CREATE_CMD_MAX,			/* 0x15 */
	SSDFS_UPDATE_BLOCK,			/* 0x16 */
	SSDFS_UPDATE_PRE_ALLOC_BLOCK,		/* 0x17 */
	SSDFS_UPDATE_EXTENT,			/* 0x18 */
	SSDFS_UPDATE_PRE_ALLOC_EXTENT,		/* 0x19 */
	SSDFS_COMMIT_LOG_NOW,			/* 0x1A */
	SSDFS_START_MIGRATION_NOW,		/* 0x1B */
	SSDFS_EXTENT_WAS_INVALIDATED,		/* 0x1C */
	SSDFS_UPDATE_CMD_MAX,			/* 0x1D */
	SSDFS_BTREE_NODE_DIFF,			/* 0x1E */
	SSDFS_USER_DATA_DIFF,			/* 0x1F */
	SSDFS_DIFF_ON_WRITE_MAX,		/* 0x20 */
	SSDFS_COPY_PAGE,			/* 0x21 */
	SSDFS_COPY_PRE_ALLOC_PAGE,		/* 0x22 */
	SSDFS_MIGRATE_RANGE,			/* 0x23 */
	SSDFS_MIGRATE_PRE_ALLOC_PAGE,		/* 0x24 */
	SSDFS_MIGRATE_FRAGMENT,			/* 0x25 */
	SSDFS_COLLECT_GARBAGE_CMD_MAX,		/* 0x26 */
	SSDFS_FSCK_CHECK_LOG_METADATA,		/* 0x27 */
	SSDFS_FSCK_PAYLOAD_SCRUBBING,		/* 0x28 */
	SSDFS_FSCK_CHECK_METADATA_IN_PAYLOAD,	/* 0x29 */
	SSDFS_FSCK_RECOVER_METADATA,		/* 0x2A */
	SSDFS_FSCK_RECOVER_USER_DATA,		/* 0x2B */
	SSDFS_FSCK_CMD_MAX,			/* 0x2C */
	SSDFS_KNOWN_CMD_MAX,			/* 0x2D */
};

/*
 * Request types
 */
enum {
	SSDFS_UNKNOWN_REQ_TYPE,
	SSDFS_REQ_SYNC,
	SSDFS_REQ_ASYNC,
	SSDFS_REQ_ASYNC_NO_FREE,
	SSDFS_REQ_TYPE_MAX,
};

/*
 * Request flags
 */
#define SSDFS_REQ_DONT_FREE_FOLIOS			(1 << 0)
#define SSDFS_REQ_READ_ONLY_CACHE			(1 << 1)
#define SSDFS_REQ_PREPARE_DIFF				(1 << 2)
#define SSDFS_REQ_FLAGS_MASK				0x7

/*
 * Result states
 */
enum {
	SSDFS_UNKNOWN_REQ_RESULT,
	SSDFS_REQ_CREATED,
	SSDFS_REQ_STARTED,
	SSDFS_REQ_FINISHED,
	SSDFS_REQ_FAILED,
	SSDFS_REQ_RESULT_MAX
};

/*
 * struct ssdfs_logical_extent - logical extent descriptor
 * @ino: inode identification number
 * @logical_offset: logical offset from file's begin in bytes
 * @data_bytes: valid bytes count in request
 * @cno: checkpoint
 * @parent_snapshot: parent snapshot
 */
struct ssdfs_logical_extent {
	u64 ino;
	u64 logical_offset;
	u32 data_bytes;
	u64 cno;
	u64 parent_snapshot;
};

/*
 * struct ssdfs_request_internal_data - private request data
 * @class: request class
 * @cmd: request command
 * @type: request type
 * @refs_count: reference counter
 * @flags: request flags
 * @block_size: block size in bytes
 * @wait_queue: queue for result waiting
 */
struct ssdfs_request_internal_data {
	int class;
	int cmd;
	int type;
	atomic_t refs_count;
	u32 flags;
	u32 block_size;
	wait_queue_head_t wait_queue;
};

/*
 * struct ssdfs_request_result - requst result
 * @batch: array of memory folios
 * @old_state: array of memory folios with initial state
 * @diffs: array of diffs
 * @processed_blks: count of processed blocks
 * @state: result's state
 * @wait: wait-for-completion of operation
 * @err: code of error
 */
struct ssdfs_request_result {
	struct folio_batch batch;
	struct folio_batch old_state;
	struct folio_batch diffs;
	int processed_blks;
	atomic_t state;
	struct completion wait;
	int err;
};

/*
 * struct ssdfs_segment_request - segment I/O request
 * @list: requests queue list
 * @extent: logical extent descriptor
 * @place: logical blocks placement in segment
 * @private: internal data of request
 * @result: request result description
 */
struct ssdfs_segment_request {
	struct list_head list;
	struct ssdfs_logical_extent extent;
	struct ssdfs_volume_extent place;
	struct ssdfs_request_internal_data private;
	struct ssdfs_request_result result;
};

/*
 * struct ssdfs_peb_phys_offset - PEB's physical offset
 * @state: physical offset state
 * @peb_index: PEB's index
 * @peb_migration_id: identification number of PEB in migration sequence
 * @peb_page: PEB's page index
 * @log_area: identification number of log area
 * @byte_offset: offset in bytes from area's beginning
 */
struct ssdfs_peb_phys_offset {
	int state;
	u16 peb_index;
	u8 peb_migration_id;
	u16 peb_page;
	u8 log_area;
	u32 byte_offset;
};

/* Physical offset states */
enum {
	SSDFS_PHYS_OFFSET_UNKNOWN_STATE,
	SSDFS_PHYS_OFFSET_REGULAR_OFFSET,
	SSDFS_PHYS_OFFSET_DEDUPLICATED_OFFSET,
	SSDFS_PHYS_OFFSET_STATE_MAX
};

struct ssdfs_segment_info;

/*
 * struct ssdfs_seg2req_pair - segment/request pair
 * @si: pointer on segment object
 * @req: pointer on request object
 */
struct ssdfs_seg2req_pair {
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_request *req;
};

/*
 * struct ssdfs_segment_request_pool - segment requests pool
 * @pointers: array of pointers on segment requests
 * @count: current number of requests in pool
 * @req_class: request class
 * @req_command: request command
 * @req_type: request type
 */
struct ssdfs_segment_request_pool {
#define SSDFS_SEG_REQ_PTR_NUMBER_MAX	(15)
	struct ssdfs_segment_request *pointers[SSDFS_SEG_REQ_PTR_NUMBER_MAX];
	u8 count;

	int req_class;
	int req_command;
	int req_type;
};

/*
 * struct ssdfs_dirty_folios_batch - dirty folios batch
 * @state: batch state
 * @fvec: folio vector with dirty folios
 * @processed_blks: number processed blocks
 * @requested_extent: requested to store extent
 * @allocated_extent: really allocated extent of logical blocks
 * @place: logical blocks placement in segment
 */
struct ssdfs_dirty_folios_batch {
	int state;

	struct folio_batch fvec;
	u8 processed_blks;

	struct ssdfs_logical_extent requested_extent;
	struct ssdfs_blk2off_range allocated_extent;
	struct ssdfs_volume_extent place;
};

/*
 * Dirty batch states
 */
enum {
	SSDFS_DIRTY_BATCH_UNKNOWN_STATE,
	SSDFS_DIRTY_BATCH_CREATED,
	SSDFS_DIRTY_BATCH_HAS_UNPROCESSED_BLOCKS,
	SSDFS_DIRTY_BATCH_STATE_MAX
};

/*
 * Request's inline functions
 */

/*
 * ssdfs_segment_request_pool_init() - initialize request pool
 * @pool: request pool
 */
static inline
void ssdfs_segment_request_pool_init(struct ssdfs_segment_request_pool *pool)
{
	size_t item_size = sizeof(struct ssdfs_segment_request *);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pool);
#endif /* CONFIG_SSDFS_DEBUG */

	pool->req_class = SSDFS_UNKNOWN_REQ_CLASS;
	pool->req_command = SSDFS_UNKNOWN_CMD;
	pool->req_type = SSDFS_UNKNOWN_REQ_TYPE;

	memset(pool->pointers, 0, item_size * SSDFS_SEG_REQ_PTR_NUMBER_MAX);
	pool->count = 0;
}

/*
 * ssdfs_dirty_folios_batch_init() - initialize dirty folios batch
 * @batch: dirty folios batch
 */
static inline
void ssdfs_dirty_folios_batch_init(struct ssdfs_dirty_folios_batch *batch)
{
	size_t extent_desc_size = sizeof(struct ssdfs_logical_extent);
	size_t range_desc_size = sizeof(struct ssdfs_blk2off_range);
	size_t place_desc_size = sizeof(struct ssdfs_volume_extent);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!batch);
#endif /* CONFIG_SSDFS_DEBUG */

	batch->state = SSDFS_DIRTY_BATCH_CREATED;

	folio_batch_init(&batch->fvec);
	batch->processed_blks = 0;

	memset(&batch->requested_extent, 0xFF, extent_desc_size);
	memset(&batch->allocated_extent, 0xFF, range_desc_size);
	memset(&batch->place, 0xFF, place_desc_size);
}

/*
 * is_ssdfs_dirty_batch_not_processed() - check that dirty batch is not processed
 * @batch: dirty folios batch
 */
static inline
bool is_ssdfs_dirty_batch_not_processed(struct ssdfs_dirty_folios_batch *batch)
{
	return batch->state == SSDFS_DIRTY_BATCH_HAS_UNPROCESSED_BLOCKS;
}

/*
 * is_ssdfs_logical_extent_invalid() - check that logical extent is invalid
 */
static inline
bool is_ssdfs_logical_extent_invalid(struct ssdfs_logical_extent *extent)
{
	return extent->ino >= U64_MAX ||
		extent->logical_offset >= U64_MAX ||
		extent->data_bytes >= U32_MAX ||
		extent->cno >= U64_MAX ||
		extent->parent_snapshot >= U64_MAX;
}

/*
 * ssdfs_dirty_folios_batch_prepare_logical_extent() - prepare logical extent
 * @ino: inode id
 * @logical_offset: logical offset in bytes from file's beginning
 * @data_bytes: extent length in bytes
 * @cno: checkpoint number
 * @parent_snapshot: parent snapshot number
 * @req: segment request [out]
 */
static inline void
ssdfs_dirty_folios_batch_prepare_logical_extent(u64 ino,
					u64 logical_offset,
					u32 data_bytes,
					u64 cno,
					u64 parent_snapshot,
					struct ssdfs_dirty_folios_batch *batch)
{
	batch->requested_extent.ino = ino;
	batch->requested_extent.logical_offset = logical_offset;
	batch->requested_extent.data_bytes = data_bytes;
	batch->requested_extent.cno = cno;
	batch->requested_extent.parent_snapshot = parent_snapshot;
}

/*
 * ssdfs_request_prepare_logical_extent() - prepare logical extent
 * @ino: inode id
 * @logical_offset: logical offset in bytes from file's beginning
 * @data_bytes: extent length in bytes
 * @cno: checkpoint number
 * @parent_snapshot: parent snapshot number
 * @req: segment request [out]
 */
static inline
void ssdfs_request_prepare_logical_extent(u64 ino,
					  u64 logical_offset,
					  u32 data_bytes,
					  u64 cno,
					  u64 parent_snapshot,
					  struct ssdfs_segment_request *req)
{
	req->extent.ino = ino;
	req->extent.logical_offset = logical_offset;
	req->extent.data_bytes = data_bytes;
	req->extent.cno = cno;
	req->extent.parent_snapshot = parent_snapshot;
}

/*
 * ssdfs_request_prepare_internal_data() - prepare request's internal data
 * @class: request class
 * @cmd: request command
 * @type: request type
 * @req: segment request [out]
 */
static inline
void ssdfs_request_prepare_internal_data(int class, int cmd, int type,
					 struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
	BUG_ON(class <= SSDFS_UNKNOWN_REQ_CLASS ||
		class >= SSDFS_PEB_REQ_CLASS_MAX);
	BUG_ON(cmd <= SSDFS_UNKNOWN_CMD || cmd >= SSDFS_KNOWN_CMD_MAX);
	BUG_ON(type <= SSDFS_UNKNOWN_REQ_TYPE ||
		type >= SSDFS_REQ_TYPE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	req->private.class = class;
	req->private.cmd = cmd;
	req->private.type = type;
}

/*
 * ssdfs_request_define_segment() - define segment number
 * @seg_id: segment number
 * @req: segment request [out]
 */
static inline
void ssdfs_request_define_segment(u64 seg_id,
				  struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
	BUG_ON(seg_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	req->place.start.seg_id = seg_id;
}

/*
 * ssdfs_request_define_volume_extent() - define logical volume extent
 * @start: starting logical block number
 * @len: count of logical blocks in the extent
 * @req: segment request [out]
 */
static inline
void ssdfs_request_define_volume_extent(u16 start, u16 len,
					struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
	BUG_ON(start == U16_MAX);
	BUG_ON(len == U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	req->place.start.blk_index = start;
	req->place.len = len;
}

/*
 * has_request_been_executed() - check that reqeust has been executed
 * @req: segment request
 */
static inline
bool has_request_been_executed(struct ssdfs_segment_request *req)
{
	bool has_been_executed = false;

	switch (atomic_read(&req->result.state)) {
	case SSDFS_REQ_CREATED:
	case SSDFS_REQ_STARTED:
		has_been_executed = false;
		break;

	case SSDFS_REQ_FINISHED:
	case SSDFS_REQ_FAILED:
		has_been_executed = true;
		break;

	default:
		SSDFS_ERR("invalid result's state %#x\n",
			  atomic_read(&req->result.state));
		has_been_executed = true;
	}

	return has_been_executed;
}

/*
 * Request queue's API
 */
void ssdfs_requests_queue_init(struct ssdfs_requests_queue *rq);
bool is_ssdfs_requests_queue_empty(struct ssdfs_requests_queue *rq);
void ssdfs_requests_queue_add_tail(struct ssdfs_requests_queue *rq,
				   struct ssdfs_segment_request *req);
void ssdfs_requests_queue_add_tail_inc(struct ssdfs_fs_info *fsi,
					struct ssdfs_requests_queue *rq,
					struct ssdfs_segment_request *req);
void ssdfs_requests_queue_add_head(struct ssdfs_requests_queue *rq,
				   struct ssdfs_segment_request *req);
void ssdfs_requests_queue_add_head_inc(struct ssdfs_fs_info *fsi,
					struct ssdfs_requests_queue *rq,
					struct ssdfs_segment_request *req);
int ssdfs_requests_queue_remove_first(struct ssdfs_requests_queue *rq,
				      struct ssdfs_segment_request **req);
void ssdfs_requests_queue_remove_all(struct ssdfs_requests_queue *rq,
				     int err);

/*
 * Request's API
 */
void ssdfs_zero_seg_req_obj_cache_ptr(void);
int ssdfs_init_seg_req_obj_cache(void);
void ssdfs_shrink_seg_req_obj_cache(void);
void ssdfs_destroy_seg_req_obj_cache(void);

int ssdfs_dirty_folios_batch_add_folio(struct folio *folio,
					struct ssdfs_dirty_folios_batch *batch);

struct ssdfs_segment_request *ssdfs_request_alloc(void);
void ssdfs_request_free(struct ssdfs_segment_request *req);
void ssdfs_request_init(struct ssdfs_segment_request *req, u32 block_size);
void ssdfs_get_request(struct ssdfs_segment_request *req);
void ssdfs_put_request(struct ssdfs_segment_request *req);
int ssdfs_request_add_folio(struct folio *folio,
			    struct ssdfs_segment_request *req);
int ssdfs_request_add_diff_folio(struct folio *folio,
				 struct ssdfs_segment_request *req);
struct folio *
ssdfs_request_allocate_and_add_folio(struct ssdfs_segment_request *req);
struct folio *
ssdfs_request_allocate_and_add_diff_folio(struct ssdfs_segment_request *req);
struct folio *
ssdfs_request_allocate_and_add_old_state_folio(struct ssdfs_segment_request *req);
struct page *
ssdfs_request_allocate_locked_page(struct ssdfs_segment_request *req,
				   int page_index);
struct folio *
ssdfs_request_allocate_locked_diff_folio(struct ssdfs_segment_request *req,
					 int folio_index);
int ssdfs_request_add_allocated_folio_locked(struct ssdfs_segment_request *req);
int ssdfs_request_add_allocated_diff_locked(struct ssdfs_segment_request *req);
int ssdfs_request_add_old_state_folio_locked(struct ssdfs_segment_request *req);
void ssdfs_request_unlock_and_remove_folios(struct ssdfs_segment_request *req);
void ssdfs_request_unlock_and_remove_update(struct ssdfs_segment_request *req);
void ssdfs_request_unlock_and_remove_diffs(struct ssdfs_segment_request *req);
void ssdfs_request_unlock_and_remove_old_state(struct ssdfs_segment_request *req);
int ssdfs_request_switch_update_on_diff(struct ssdfs_fs_info *fsi,
					struct folio *diff_folio,
					struct ssdfs_segment_request *req);
void ssdfs_request_unlock_and_forget_folio(struct ssdfs_segment_request *req,
					   int folio_index);
void ssdfs_free_flush_request_folios(struct ssdfs_segment_request *req);
u32 ssdfs_peb_extent_length(struct ssdfs_segment_info *si,
			    struct folio_batch *batch);

#endif /* _SSDFS_REQUEST_QUEUE_H */
