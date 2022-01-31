//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/request_queue.h - request queue declarations.
 *
 * Copyright (c) 2014-2022 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2022, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
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
	SSDFS_UNKNOWN_REQ_CLASS,
	SSDFS_PEB_READ_REQ,
	SSDFS_PEB_PRE_ALLOCATE_DATA_REQ,
	SSDFS_PEB_CREATE_DATA_REQ,
	SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ,
	SSDFS_PEB_CREATE_LNODE_REQ,
	SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ,
	SSDFS_PEB_CREATE_HNODE_REQ,
	SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ,
	SSDFS_PEB_CREATE_IDXNODE_REQ,
	SSDFS_PEB_UPDATE_REQ,
	SSDFS_PEB_PRE_ALLOC_UPDATE_REQ,
	SSDFS_PEB_COLLECT_GARBAGE_REQ,
	SSDFS_PEB_REQ_CLASS_MAX,
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
	SSDFS_READ_BLK_BMAP_SRC_USING_PEB,	/* 0x05 */
	SSDFS_READ_BLK_BMAP_DST_USING_PEB,	/* 0x06 */
	SSDFS_READ_BLK_BMAP_SRC_USED_PEB,	/* 0x07 */
	SSDFS_READ_BLK_BMAP_DST_USED_PEB,	/* 0x08 */
	SSDFS_READ_BLK2OFF_TABLE_SRC_PEB,	/* 0x09 */
	SSDFS_READ_BLK2OFF_TABLE_DST_PEB,	/* 0x0A */
	SSDFS_READ_INIT_SEGBMAP,		/* 0x0B */
	SSDFS_READ_INIT_MAPTBL,			/* 0x0C */
	SSDFS_READ_CMD_MAX,			/* 0x0D */
	SSDFS_CREATE_BLOCK,			/* 0x0E */
	SSDFS_CREATE_EXTENT,			/* 0x0F */
	SSDFS_CREATE_CMD_MAX,			/* 0x10 */
	SSDFS_UPDATE_BLOCK,			/* 0x11 */
	SSDFS_UPDATE_PRE_ALLOC_BLOCK,		/* 0x12 */
	SSDFS_UPDATE_EXTENT,			/* 0x13 */
	SSDFS_UPDATE_PRE_ALLOC_EXTENT,		/* 0x14 */
	SSDFS_COMMIT_LOG_NOW,			/* 0x15 */
	SSDFS_START_MIGRATION_NOW,		/* 0x16 */
	SSDFS_EXTENT_WAS_INVALIDATED,		/* 0x17 */
	SSDFS_UPDATE_CMD_MAX,			/* 0x18 */
	SSDFS_COPY_PAGE,			/* 0x19 */
	SSDFS_COPY_PRE_ALLOC_PAGE,		/* 0x1A */
	SSDFS_MIGRATE_RANGE,			/* 0x1B */
	SSDFS_MIGRATE_PRE_ALLOC_PAGE,		/* 0x1C */
	SSDFS_MIGRATE_FRAGMENT,			/* 0x1D */
	SSDFS_COLLECT_GARBAGE_CMD_MAX,		/* 0x1E */
	SSDFS_KNOWN_CMD_MAX,			/* 0x1F */
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
 * Request types
 */
#define SSDFS_REQ_DONT_FREE_PAGES			(1 << 0)
#define SSDFS_REQ_FLAGS_MASK				0x1

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
 * @wait_queue: queue for result waiting
 */
struct ssdfs_request_internal_data {
	int class;
	int cmd;
	int type;
	atomic_t refs_count;
	u32 flags;
	wait_queue_head_t wait_queue;
};

/*
 * struct ssdfs_request_result - requst result
 * @pvec: array of memory pages
 * @processed_blks: count of processed physical pages
 * @state: result's state
 * @wait: wait-for-completion of operation
 * @err: code of error
 */
struct ssdfs_request_result {
	struct pagevec pvec;
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
 * @peb_index: PEB's index
 * @peb_migration_id: identification number of PEB in migration sequence
 * @peb_page: PEB's page index
 * @log_area: identification number of log area
 * @byte_offset: offset in bytes from area's beginning
 */
struct ssdfs_peb_phys_offset {
	u16 peb_index;
	u8 peb_migration_id;
	u16 peb_page;
	u8 log_area;
	u32 byte_offset;
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
 * Request's inline functions
 */

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

struct ssdfs_segment_request *ssdfs_request_alloc(void);
void ssdfs_request_free(struct ssdfs_segment_request *req);
void ssdfs_request_init(struct ssdfs_segment_request *req);
void ssdfs_get_request(struct ssdfs_segment_request *req);
void ssdfs_put_request(struct ssdfs_segment_request *req);
int ssdfs_request_add_page(struct page *page,
			   struct ssdfs_segment_request *req);
struct page *
ssdfs_request_allocate_and_add_page(struct ssdfs_segment_request *req);
int ssdfs_request_add_allocated_page_locked(struct ssdfs_segment_request *req);
void ssdfs_request_unlock_and_remove_page(struct ssdfs_segment_request *req,
					  int page_index);
void ssdfs_request_unlock_and_remove_pages(struct ssdfs_segment_request *req);
void ssdfs_free_flush_request_pages(struct ssdfs_segment_request *req);
u8 ssdfs_peb_extent_length(struct ssdfs_segment_info *si,
			   struct pagevec *pvec);

#endif /* _SSDFS_REQUEST_QUEUE_H */
