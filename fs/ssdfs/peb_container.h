// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_container.h - PEB container declarations.
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

#ifndef _SSDFS_PEB_CONTAINER_H
#define _SSDFS_PEB_CONTAINER_H

#include "block_bitmap.h"
#include "peb.h"

/* PEB container's array indexes */
enum {
	SSDFS_SEG_PEB1,
	SSDFS_SEG_PEB2,
	SSDFS_SEG_PEB_ITEMS_MAX
};

/* PEB container possible states */
enum {
	SSDFS_PEB_CONTAINER_EMPTY,
	SSDFS_PEB1_SRC_CONTAINER,
	SSDFS_PEB1_DST_CONTAINER,
	SSDFS_PEB1_SRC_PEB2_DST_CONTAINER,
	SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER,
	SSDFS_PEB2_SRC_CONTAINER,
	SSDFS_PEB2_DST_CONTAINER,
	SSDFS_PEB2_SRC_PEB1_DST_CONTAINER,
	SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER,
	SSDFS_PEB_CONTAINER_STATE_MAX
};

/*
 * PEB migration state
 */
enum {
	SSDFS_PEB_UNKNOWN_MIGRATION_STATE,
	SSDFS_PEB_NOT_MIGRATING,
	SSDFS_PEB_MIGRATION_PREPARATION,
	SSDFS_PEB_RELATION_PREPARATION,
	SSDFS_PEB_UNDER_MIGRATION,
	SSDFS_PEB_FINISHING_MIGRATION,
	SSDFS_PEB_MIGRATION_STATE_MAX
};

/*
 * PEB migration phase
 */
enum {
	SSDFS_PEB_MIGRATION_STATUS_UNKNOWN,
	SSDFS_SRC_PEB_NOT_EXHAUSTED,
	SSDFS_DST_PEB_RECEIVES_DATA,
	SSDFS_SHARED_ZONE_RECEIVES_DATA,
	SSDFS_PEB_MIGRATION_PHASE_MAX
};

/*
 * struct ssdfs_thread_state - PEB container's thread state
 * @state: current state of the thread
 * @req: pointer on segment request
 * @postponed_req: pointer on postponed segment request
 * @skip_finish_flush_request: should commit skip the finish request?
 * @has_extent_been_invalidated: has been extent invalidated?
 * @has_migration_check_requested: has migration check been requested?
 * @err: current error
 */
struct ssdfs_thread_state {
#define SSDFS_THREAD_UNKNOWN_STATE	(-1)
	int state;
	struct ssdfs_segment_request *req;
	struct ssdfs_segment_request *postponed_req;
	bool skip_finish_flush_request;
	bool has_extent_been_invalidated;
	bool has_migration_check_requested;
	int err;
};

/*
 * struct ssdfs_peb_container - PEB container
 * @peb_type: type of PEB
 * @peb_index: index of PEB in the array
 * @log_pages: count of pages in full log
 * @thread_state: threads state
 * @threads: PEB container's threads array
 * @read_rq: read requests queue
 * @update_rq: update requests queue
 * @crq_ptr_lock: lock of pointer on create requests queue
 * @create_rq: pointer on shared new page requests queue
 * @fsck_rq: online FSCK requests queue
 * @parent_si: pointer on parent segment object
 * @migration_lock: migration lock
 * @migration_state: PEB migration state
 * @migration_phase: PEB migration phase
 * @items_state: items array state
 * @shared_free_dst_blks: count of blocks that destination is able to share
 * @migration_wq: wait queue for migration operations
 * @cache_protection: PEB cache protection window
 * @lock: container's internals lock
 * @src_peb: pointer on source PEB
 * @dst_peb: pointer on destination PEB
 * @dst_peb_refs: reference counter of destination PEB (sharing counter)
 * @items: buffers for PEB objects
 * @peb_kobj: /sys/fs/ssdfs/<device>/<segN>/<pebN> kernel object
 * @peb_kobj_unregister: completion state for <pebN> kernel object
 */
struct ssdfs_peb_container {
	/* Static data */
	u8 peb_type;
	u16 peb_index;
	u32 log_pages;

	/* PEB container's threads */
	struct ssdfs_thread_state thread_state[SSDFS_PEB_THREAD_TYPE_MAX];
	struct ssdfs_thread_info thread[SSDFS_PEB_THREAD_TYPE_MAX];

	/* Read requests queue */
	struct ssdfs_requests_queue read_rq;

	/* Update requests queue */
	struct ssdfs_requests_queue update_rq;

	spinlock_t pending_lock;
	u32 pending_updated_user_data_pages;

	/* Shared new page requests queue */
	spinlock_t crq_ptr_lock;
	struct ssdfs_requests_queue *create_rq;

	/* Online FSCK requests queue */
#ifdef CONFIG_SSDFS_ONLINE_FSCK
	struct ssdfs_requests_queue fsck_rq;
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	/* Parent segment */
	struct ssdfs_segment_info *parent_si;

	/* Migration info */
	struct mutex migration_lock;
	atomic_t migration_state;
	atomic_t migration_phase;
	atomic_t items_state;
	atomic_t shared_free_dst_blks;
	wait_queue_head_t migration_wq;

	/* PEB cache protection window */
	struct ssdfs_protection_window cache_protection;

	/* PEB objects */
	struct rw_semaphore lock;
	struct ssdfs_peb_info *src_peb;
	struct ssdfs_peb_info *dst_peb;
	atomic_t dst_peb_refs;
	struct ssdfs_peb_info items[SSDFS_SEG_PEB_ITEMS_MAX];

	/* /sys/fs/ssdfs/<device>/<segN>/<pebN> */
	struct kobject peb_kobj;
	struct completion peb_kobj_unregister;
};

#define PEBI_PTR(pebi) \
	((struct ssdfs_peb_info *)(pebi))
#define PEBC_PTR(pebc) \
	((struct ssdfs_peb_container *)(pebc))
#define READ_RQ_PTR(pebc) \
	(&PEBC_PTR(pebc)->read_rq)

#define SSDFS_GC_FINISH_MIGRATION	(4)

/*
 * Inline functions
 */
static inline
bool is_peb_container_empty(struct ssdfs_peb_container *pebc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	return atomic_read(&pebc->items_state) == SSDFS_PEB_CONTAINER_EMPTY;
}

/*
 * is_create_requests_queue_empty() - check that create queue has requests
 * @pebc: pointer on PEB container
 */
static inline
bool is_create_requests_queue_empty(struct ssdfs_peb_container *pebc)
{
	bool is_create_rq_empty = true;

	spin_lock(&pebc->crq_ptr_lock);
	if (pebc->create_rq) {
		is_create_rq_empty =
			is_ssdfs_requests_queue_empty(pebc->create_rq);
	}
	spin_unlock(&pebc->crq_ptr_lock);

	return is_create_rq_empty;
}

/*
 * have_flush_requests() - check that create or update queue have requests
 * @pebc: pointer on PEB container
 */
static inline
bool have_flush_requests(struct ssdfs_peb_container *pebc)
{
	bool is_create_rq_empty = true;
	bool is_update_rq_empty = true;

	is_create_rq_empty = is_create_requests_queue_empty(pebc);
	is_update_rq_empty = is_ssdfs_requests_queue_empty(&pebc->update_rq);

	return !is_create_rq_empty || !is_update_rq_empty;
}

/*
 * is_fsck_requests_queue_empty() - check that FSCK queue has requests
 * @pebc: pointer on PEB container
 */
static inline
bool is_fsck_requests_queue_empty(struct ssdfs_peb_container *pebc)
{
#ifdef CONFIG_SSDFS_ONLINE_FSCK
	return is_ssdfs_requests_queue_empty(&pebc->fsck_rq);
#else
	return true;
#endif /* CONFIG_SSDFS_ONLINE_FSCK */
}

static inline
bool is_ssdfs_peb_containing_user_data(struct ssdfs_peb_container *pebc)
{
	return pebc->peb_type == SSDFS_MAPTBL_DATA_PEB_TYPE;
}

static inline
void SSDFS_THREAD_STATE_INIT(struct ssdfs_thread_state *thread_state)
{
	thread_state->state = SSDFS_THREAD_UNKNOWN_STATE;
	thread_state->req = NULL;
	thread_state->postponed_req = NULL;
	thread_state->skip_finish_flush_request = false;
	thread_state->has_extent_been_invalidated = false;
	thread_state->has_migration_check_requested = false;
	thread_state->err = 0;
}

/*
 * PEB container's API
 */
int ssdfs_peb_container_create(struct ssdfs_fs_info *fsi,
				u64 seg, u32 peb_index,
				u8 peb_type,
				u32 log_pages,
				struct ssdfs_segment_info *si);
void ssdfs_peb_container_destroy(struct ssdfs_peb_container *pebc);

int ssdfs_peb_container_invalidate_block(struct ssdfs_peb_container *pebc,
				    struct ssdfs_phys_offset_descriptor *desc);
int ssdfs_peb_get_free_pages(struct ssdfs_peb_container *pebc);
int ssdfs_peb_get_used_data_pages(struct ssdfs_peb_container *pebc);
int ssdfs_peb_get_invalid_pages(struct ssdfs_peb_container *pebc);

int ssdfs_peb_join_create_requests_queue(struct ssdfs_peb_container *pebc,
					 struct ssdfs_requests_queue *create_rq);
void ssdfs_peb_forget_create_requests_queue(struct ssdfs_peb_container *pebc);
bool is_peb_joined_into_create_requests_queue(struct ssdfs_peb_container *pebc);

struct ssdfs_peb_info *
ssdfs_get_current_peb_locked(struct ssdfs_peb_container *pebc);
void ssdfs_unlock_current_peb(struct ssdfs_peb_container *pebc);
struct ssdfs_peb_info *
ssdfs_get_peb_for_migration_id(struct ssdfs_peb_container *pebc,
			       u8 migration_id);

int ssdfs_peb_container_create_destination(struct ssdfs_peb_container *ptr);
int ssdfs_peb_container_forget_source(struct ssdfs_peb_container *pebc);
int ssdfs_peb_container_forget_relation(struct ssdfs_peb_container *pebc);
int ssdfs_peb_container_change_state(struct ssdfs_peb_container *pebc);

/*
 * PEB container's private API
 */
int ssdfs_peb_gc_thread_func(void *data);
int ssdfs_peb_read_thread_func(void *data);
int ssdfs_peb_flush_thread_func(void *data);
int ssdfs_peb_fsck_thread_func(void *data);

u16 ssdfs_peb_estimate_reserved_metapages(u32 page_size, u32 pages_per_peb,
					  u16 log_pages, u32 pebs_per_seg,
					  bool is_migrating);
int ssdfs_peb_read_page(struct ssdfs_peb_container *pebc,
			struct ssdfs_segment_request *req,
			struct completion **end);
int ssdfs_peb_readahead_pages(struct ssdfs_peb_container *pebc,
			      struct ssdfs_segment_request *req,
			      struct completion **end);
void ssdfs_peb_mark_request_block_uptodate(struct ssdfs_peb_container *pebc,
					   struct ssdfs_segment_request *req,
					   int blk_index);
int ssdfs_peb_copy_page(struct ssdfs_peb_container *pebc,
			u32 logical_blk,
			struct ssdfs_segment_request *req);
int ssdfs_peb_copy_pages_range(struct ssdfs_peb_container *pebc,
				struct ssdfs_block_bmap_range *range,
				struct ssdfs_segment_request *req);
int ssdfs_peb_copy_pre_alloc_page(struct ssdfs_peb_container *pebc,
				  u32 logical_blk,
				  struct ssdfs_segment_request *req);
int __ssdfs_peb_get_block_state_desc(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_metadata_descriptor *area_desc,
				struct ssdfs_block_state_descriptor *desc,
				u64 *cno, u64 *parent_snapshot);
int ssdfs_blk_desc_buffer_init(struct ssdfs_peb_container *pebc,
				struct ssdfs_segment_request *req,
				struct ssdfs_phys_offset_descriptor *desc_off,
				struct ssdfs_offset_position *pos,
				struct ssdfs_metadata_descriptor *array,
				size_t array_size);
int ssdfs_peb_read_block_state(struct ssdfs_peb_container *pebc,
				struct ssdfs_segment_request *req,
				struct ssdfs_phys_offset_descriptor *desc_off,
				struct ssdfs_offset_position *pos,
				struct ssdfs_metadata_descriptor *array,
				size_t array_size);
bool ssdfs_peb_has_dirty_pages(struct ssdfs_peb_info *pebi);
int ssdfs_collect_dirty_segments_now(struct ssdfs_fs_info *fsi);

#endif /* _SSDFS_PEB_CONTAINER_H */
