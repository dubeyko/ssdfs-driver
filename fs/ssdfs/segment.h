/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment.h - segment concept declarations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2024 Viacheslav Dubeyko <slava@dubeyko.com>
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
 * @lock: migration data lock
 * @array: destination descriptors
 */
struct ssdfs_segment_migration_info {
	atomic_t migrating_pebs;

	spinlock_t lock;
	struct ssdfs_migration_destination array[SSDFS_DESTINATION_MAX];
};

/*
 * struct ssdfs_segment_info - segment object description
 * @seg_id: segment identification number
 * @log_pages: count of pages in full partial log
 * @create_threads: number of flush PEB's threads for new page requests
 * @seg_type: segment type
 * @protection: segment's protection window
 * @seg_state: current state of segment
 * @obj_state: segment object's state
 * @activity_type: type of activity with segment object
 * @peb_array: array of PEB's descriptors
 * @pebs_count: count of items in PEBS array
 * @migration: migration info
 * @refs_count: counter of references on segment object
 * @object_queue: wait queue for segment creation/destruction
 * @create_rq: new page requests queue
 * @pending_lock: lock of pending pages' counter
 * @pending_new_user_data_pages: counter of pending new user data pages
 * @invalidated_user_data_pages: counter of invalidated user data pages
 * @wait_queue: array of PEBs' wait queues
 * @blk_bmap: segment's block bitmap
 * @blk2off_table: offset translation table
 * @fsi: pointer on shared file system object
 * @seg_kobj: /sys/fs/ssdfs/<device>/segments/<segN> kernel object
 * @seg_kobj_unregister: completion state for <segN> kernel object
 * @pebs_kobj: /sys/fs/<ssdfs>/<device>/segments/<segN>/pebs kernel object
 * @pebs_kobj_unregister: completion state for pebs kernel object
 */
struct ssdfs_segment_info {
	/* Static data */
	u64 seg_id;
	u16 log_pages;
	u8 create_threads;
	u16 seg_type;

	/* Checkpoints set */
	struct ssdfs_protection_window protection;

	/* Mutable data */
	atomic_t seg_state;
	atomic_t obj_state;
	atomic_t activity_type;

	/* Segment's PEB's containers array */
	struct ssdfs_peb_container *peb_array;
	u16 pebs_count;

	/* Migration info */
	struct ssdfs_segment_migration_info migration;

	/* Reference counter */
	atomic_t refs_count;
	wait_queue_head_t object_queue;

	/*
	 * New pages processing:
	 * requests queue, wait queue
	 */
	struct ssdfs_requests_queue create_rq;

	spinlock_t pending_lock;
	u32 pending_new_user_data_pages;
	u32 invalidated_user_data_pages;

	/* Threads' wait queues */
	wait_queue_head_t wait_queue[SSDFS_PEB_THREAD_TYPE_MAX];

	struct ssdfs_segment_blk_bmap blk_bmap;
	struct ssdfs_blk2off_table *blk2off_table;
	struct ssdfs_fs_info *fsi;

	/* /sys/fs/ssdfs/<device>/segments/<segN> */
	struct kobject *seg_kobj;
	struct kobject seg_kobj_buf;
	struct completion seg_kobj_unregister;

	/* /sys/fs/<ssdfs>/<device>/segments/<segN>/pebs */
	struct kobject pebs_kobj;
	struct completion pebs_kobj_unregister;
};

/* Segment object states */
enum {
	SSDFS_SEG_OBJECT_UNKNOWN_STATE,
	SSDFS_SEG_OBJECT_UNDER_CREATION,
	SSDFS_SEG_OBJECT_CREATED,
	SSDFS_CURRENT_SEG_OBJECT,
	SSDFS_SEG_OBJECT_FAILURE,
	SSDFS_SEG_OBJECT_STATE_MAX
};

/* Segment object's activity type */
enum {
	SSDFS_SEG_OBJECT_NO_ACTIVITY,
	SSDFS_SEG_OBJECT_REGULAR_ACTIVITY,
	SSDFS_SEG_UNDER_GC_ACTIVITY,
	SSDFS_SEG_UNDER_INVALIDATION,
	SSDFS_SEG_OBJECT_ACTIVITY_TYPE_MAX
};

/*
 * Inline functions
 */

/*
 * is_ssdfs_segment_created() - check that segment object is created
 *
 * This function returns TRUE for the case of successful
 * creation of segment's object or failure of the creation.
 * The responsibility of the caller to check that
 * segment object has been created successfully.
 */
static inline
bool is_ssdfs_segment_created(struct ssdfs_segment_info *si)
{
	bool is_created = false;

	switch (atomic_read(&si->obj_state)) {
	case SSDFS_SEG_OBJECT_CREATED:
	case SSDFS_CURRENT_SEG_OBJECT:
	case SSDFS_SEG_OBJECT_FAILURE:
		is_created = true;
		break;

	default:
		is_created = false;
		break;
	}

	return is_created;
}

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

	case SSDFS_ZONE_USER_DATA_MIGRATE_REQ:
		cur_seg_type = SSDFS_CUR_DATA_UPDATE_SEG;
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
 * SEG_TYPE2MASK() - convert segment type into search mask
 */
static inline
int SEG_TYPE2MASK(int seg_type)
{
	int mask;

	switch (seg_type) {
	case SSDFS_USER_DATA_SEG_TYPE:
		mask = SSDFS_SEG_DATA_USING_STATE_FLAG;
		break;

	case SSDFS_LEAF_NODE_SEG_TYPE:
		mask = SSDFS_SEG_LEAF_NODE_USING_STATE_FLAG;
		break;

	case SSDFS_HYBRID_NODE_SEG_TYPE:
		mask = SSDFS_SEG_HYBRID_NODE_USING_STATE_FLAG;
		break;

	case SSDFS_INDEX_NODE_SEG_TYPE:
		mask = SSDFS_SEG_INDEX_NODE_USING_STATE_FLAG;
		break;

	default:
		BUG();
	};

	return mask;
}

/*
 * SEG_TYPE_TO_CUR_SEG_TYPE() - convert segment type to current segment type
 * @seg_type: segment type
 */
static inline
int SEG_TYPE_TO_CUR_SEG_TYPE(u16 seg_type)
{
	int cur_seg_type = SSDFS_CUR_SEGS_COUNT;

	switch (seg_type) {
	case SSDFS_USER_DATA_SEG_TYPE:
		return SSDFS_CUR_DATA_SEG;

	case SSDFS_LEAF_NODE_SEG_TYPE:
		return SSDFS_CUR_LNODE_SEG;

	case SSDFS_HYBRID_NODE_SEG_TYPE:
		return SSDFS_CUR_HNODE_SEG;

	case SSDFS_INDEX_NODE_SEG_TYPE:
		return SSDFS_CUR_IDXNODE_SEG;
	}

	return cur_seg_type;
}

static inline
void ssdfs_account_user_data_flush_request(struct ssdfs_segment_info *si)
{
	u64 flush_requests = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	if (si->seg_type == SSDFS_USER_DATA_SEG_TYPE) {
		spin_lock(&si->fsi->volume_state_lock);
		si->fsi->flushing_user_data_requests++;
		flush_requests = si->fsi->flushing_user_data_requests;
		spin_unlock(&si->fsi->volume_state_lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_id %llu, flush_requests %llu\n",
			  si->seg_id, flush_requests);
#endif /* CONFIG_SSDFS_DEBUG */
	}
}

static inline
void ssdfs_forget_user_data_flush_request(struct ssdfs_segment_info *si)
{
	u64 flush_requests = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	if (si->seg_type == SSDFS_USER_DATA_SEG_TYPE) {
		spin_lock(&si->fsi->volume_state_lock);
		flush_requests = si->fsi->flushing_user_data_requests;
		if (flush_requests > 0) {
			si->fsi->flushing_user_data_requests--;
			flush_requests = si->fsi->flushing_user_data_requests;
		} else
			err = -ERANGE;
		spin_unlock(&si->fsi->volume_state_lock);

		if (unlikely(err))
			SSDFS_WARN("fail to decrement\n");

		if (flush_requests == 0)
			wake_up_all(&si->fsi->finish_user_data_flush_wq);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_id %llu, flush_requests %llu\n",
			  si->seg_id, flush_requests);
#endif /* CONFIG_SSDFS_DEBUG */
	}
}

static inline
bool is_user_data_pages_invalidated(struct ssdfs_segment_info *si)
{
	u64 invalidated = 0;

	if (si->seg_type != SSDFS_USER_DATA_SEG_TYPE)
		return false;

	spin_lock(&si->pending_lock);
	invalidated = si->invalidated_user_data_pages;
	spin_unlock(&si->pending_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, invalidated %llu\n",
		  si->seg_id, invalidated);
#endif /* CONFIG_SSDFS_DEBUG */

	return invalidated > 0;
}

static inline
void ssdfs_account_invalidated_user_data_pages(struct ssdfs_segment_info *si,
						u32 count)
{
	u64 invalidated = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("si %p, count %u\n",
		  si, count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (si->seg_type == SSDFS_USER_DATA_SEG_TYPE) {
		spin_lock(&si->pending_lock);
		si->invalidated_user_data_pages += count;
		invalidated = si->invalidated_user_data_pages;
		spin_unlock(&si->pending_lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_id %llu, invalidated %llu\n",
			  si->seg_id, invalidated);
#endif /* CONFIG_SSDFS_DEBUG */
	}
}

static inline
void ssdfs_forget_invalidated_user_data_pages(struct ssdfs_segment_info *si)
{
	u64 invalidated = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	if (si->seg_type == SSDFS_USER_DATA_SEG_TYPE) {
		spin_lock(&si->pending_lock);
		invalidated = si->invalidated_user_data_pages;
		si->invalidated_user_data_pages = 0;
		spin_unlock(&si->pending_lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_id %llu, invalidated %llu\n",
			  si->seg_id, invalidated);
#endif /* CONFIG_SSDFS_DEBUG */
	}
}

static inline
void ssdfs_account_commit_log_request(struct ssdfs_segment_info *si)
{
	u64 commit_log_requests = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&si->fsi->volume_state_lock);
	si->fsi->commit_log_requests++;
	commit_log_requests = si->fsi->commit_log_requests;
	spin_unlock(&si->fsi->volume_state_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, commit_log_requests %llu\n",
		  si->seg_id, commit_log_requests);
#endif /* CONFIG_SSDFS_DEBUG */
}

static inline
void ssdfs_forget_commit_log_request(struct ssdfs_segment_info *si)
{
	u64 commit_log_requests = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&si->fsi->volume_state_lock);
	commit_log_requests = si->fsi->commit_log_requests;
	if (commit_log_requests > 0) {
		si->fsi->commit_log_requests--;
		commit_log_requests = si->fsi->commit_log_requests;
	} else
		err = -ERANGE;
	spin_unlock(&si->fsi->volume_state_lock);

	if (unlikely(err))
		SSDFS_WARN("fail to decrement\n");

	if (commit_log_requests == 0)
		wake_up_all(&si->fsi->finish_commit_log_flush_wq);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, commit_log_requests %llu\n",
		  si->seg_id, commit_log_requests);
#endif /* CONFIG_SSDFS_DEBUG */
}

static inline
void ssdfs_protection_account_request(struct ssdfs_protection_window *ptr,
				      u64 current_cno)
{
#ifdef CONFIG_SSDFS_DEBUG
	u64 create_cno;
	u64 last_request_cno;
	u32 reqs_count;
	u64 protected_range;
	u64 future_request_cno;
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&ptr->cno_lock);

	if (ptr->reqs_count == 0) {
		ptr->reqs_count = 1;
		ptr->last_request_cno = current_cno;
	} else
		ptr->reqs_count++;

#ifdef CONFIG_SSDFS_DEBUG
	create_cno = ptr->create_cno;
	last_request_cno = ptr->last_request_cno;
	reqs_count = ptr->reqs_count;
	protected_range = ptr->protected_range;
	future_request_cno = ptr->future_request_cno;
#endif /* CONFIG_SSDFS_DEBUG */

	spin_unlock(&ptr->cno_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create_cno %llu, "
		  "last_request_cno %llu, reqs_count %u, "
		  "protected_range %llu, future_request_cno %llu\n",
		  create_cno,
		  last_request_cno, reqs_count,
		  protected_range, future_request_cno);
#endif /* CONFIG_SSDFS_DEBUG */
}

static inline
void ssdfs_protection_forget_request(struct ssdfs_protection_window *ptr,
				     u64 current_cno)
{
	u64 create_cno;
	u64 last_request_cno;
	u32 reqs_count;
	u64 protected_range;
	u64 future_request_cno;
	int err = 0;

	spin_lock(&ptr->cno_lock);

	if (ptr->reqs_count == 0) {
		err = -ERANGE;
		goto finish_process_request;
	} else if (ptr->reqs_count == 1) {
		ptr->reqs_count--;

		if (ptr->last_request_cno >= current_cno) {
			err = -ERANGE;
			goto finish_process_request;
		} else {
			u64 diff = current_cno - ptr->last_request_cno;
			u64 last_range = ptr->protected_range;
			ptr->protected_range = max_t(u64, last_range, diff);
			ptr->last_request_cno = current_cno;
			ptr->future_request_cno =
				current_cno + ptr->protected_range;
		}
	} else
		ptr->reqs_count--;

finish_process_request:
	create_cno = ptr->create_cno;
	last_request_cno = ptr->last_request_cno;
	reqs_count = ptr->reqs_count;
	protected_range = ptr->protected_range;
	future_request_cno = ptr->future_request_cno;

	spin_unlock(&ptr->cno_lock);

	if (unlikely(err)) {
		SSDFS_WARN("create_cno %llu, "
			   "last_request_cno %llu, reqs_count %u, "
			   "protected_range %llu, future_request_cno %llu\n",
			   create_cno,
			   last_request_cno, reqs_count,
			   protected_range, future_request_cno);
		return;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create_cno %llu, "
		  "last_request_cno %llu, reqs_count %u, "
		  "protected_range %llu, future_request_cno %llu\n",
		  create_cno,
		  last_request_cno, reqs_count,
		  protected_range, future_request_cno);
#endif /* CONFIG_SSDFS_DEBUG */
}

static inline
void ssdfs_segment_create_request_cno(struct ssdfs_segment_info *si)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_protection_account_request(&si->protection,
				ssdfs_current_cno(si->fsi->sb));
}

static inline
void ssdfs_segment_finish_request_cno(struct ssdfs_segment_info *si)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_protection_forget_request(&si->protection,
				ssdfs_current_cno(si->fsi->sb));
}

static inline
bool should_gc_doesnt_touch_segment(struct ssdfs_segment_info *si)
{
#ifdef CONFIG_SSDFS_DEBUG
	u64 create_cno;
	u64 last_request_cno;
	u32 reqs_count;
	u64 protected_range;
	u64 future_request_cno;
#endif /* CONFIG_SSDFS_DEBUG */
	u64 cur_cno;
	bool dont_touch = false;

	spin_lock(&si->protection.cno_lock);
	if (si->protection.reqs_count > 0) {
		/* segment is under processing */
		dont_touch = true;
	} else {
		cur_cno = ssdfs_current_cno(si->fsi->sb);
		if (cur_cno <= si->protection.future_request_cno) {
			/* segment is under protection window yet */
			dont_touch = true;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	create_cno = si->protection.create_cno;
	last_request_cno = si->protection.last_request_cno;
	reqs_count = si->protection.reqs_count;
	protected_range = si->protection.protected_range;
	future_request_cno = si->protection.future_request_cno;
#endif /* CONFIG_SSDFS_DEBUG */

	spin_unlock(&si->protection.cno_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, create_cno %llu, "
		  "last_request_cno %llu, reqs_count %u, "
		  "protected_range %llu, future_request_cno %llu, "
		  "dont_touch %#x\n",
		  si->seg_id, create_cno,
		  last_request_cno, reqs_count,
		  protected_range, future_request_cno,
		  dont_touch);
#endif /* CONFIG_SSDFS_DEBUG */

	return dont_touch;
}

static inline
void ssdfs_peb_read_request_cno(struct ssdfs_peb_container *pebc)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_protection_account_request(&pebc->cache_protection,
			ssdfs_current_cno(pebc->parent_si->fsi->sb));
}

static inline
void ssdfs_peb_finish_read_request_cno(struct ssdfs_peb_container *pebc)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_protection_forget_request(&pebc->cache_protection,
			ssdfs_current_cno(pebc->parent_si->fsi->sb));
}

static inline
bool is_it_time_free_peb_cache_memory(struct ssdfs_peb_container *pebc)
{
#ifdef CONFIG_SSDFS_DEBUG
	u64 create_cno;
	u64 last_request_cno;
	u32 reqs_count;
	u64 protected_range;
	u64 future_request_cno;
#endif /* CONFIG_SSDFS_DEBUG */
	u64 cur_cno;
	bool dont_touch = false;

	spin_lock(&pebc->cache_protection.cno_lock);
	if (pebc->cache_protection.reqs_count > 0) {
		/* PEB has read requests */
		dont_touch = true;
	} else {
		cur_cno = ssdfs_current_cno(pebc->parent_si->fsi->sb);
		if (cur_cno <= pebc->cache_protection.future_request_cno) {
			/* PEB is under protection window yet */
			dont_touch = true;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	create_cno = pebc->cache_protection.create_cno;
	last_request_cno = pebc->cache_protection.last_request_cno;
	reqs_count = pebc->cache_protection.reqs_count;
	protected_range = pebc->cache_protection.protected_range;
	future_request_cno = pebc->cache_protection.future_request_cno;
#endif /* CONFIG_SSDFS_DEBUG */

	spin_unlock(&pebc->cache_protection.cno_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, peb_index %u, create_cno %llu, "
		  "last_request_cno %llu, reqs_count %u, "
		  "protected_range %llu, future_request_cno %llu, "
		  "dont_touch %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  create_cno,
		  last_request_cno, reqs_count,
		  protected_range, future_request_cno,
		  dont_touch);
#endif /* CONFIG_SSDFS_DEBUG */

	return !dont_touch;
}

/*
 * Segment object's API
 */
struct ssdfs_segment_info *ssdfs_segment_allocate_object(u64 seg_id);
void ssdfs_segment_free_object(struct ssdfs_segment_info *si);
int ssdfs_segment_create_object(struct ssdfs_fs_info *fsi,
				u64 seg,
				int seg_state,
				u16 seg_type,
				u16 log_pages,
				u8 create_threads,
				struct ssdfs_segment_info *si);
int ssdfs_segment_destroy_object(struct ssdfs_segment_info *si);
void ssdfs_segment_get_object(struct ssdfs_segment_info *si);
void ssdfs_segment_put_object(struct ssdfs_segment_info *si);

struct ssdfs_segment_info *
ssdfs_grab_segment(struct ssdfs_fs_info *fsi, int seg_type, u64 seg_id,
		   u64 start_search_id);

int ssdfs_segment_read_block_sync(struct ssdfs_segment_info *si,
				  struct ssdfs_segment_request *req);
int ssdfs_segment_read_block_async(struct ssdfs_segment_info *si,
				  int req_type,
				  struct ssdfs_segment_request *req);

int ssdfs_segment_pre_alloc_data_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_pre_alloc_data_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_pre_alloc_leaf_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_pre_alloc_leaf_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_pre_alloc_hybrid_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_pre_alloc_hybrid_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_pre_alloc_index_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_pre_alloc_index_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);

int ssdfs_segment_add_data_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_add_data_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_migrate_zone_block_sync(struct ssdfs_fs_info *fsi,
					  int req_type,
					  struct ssdfs_segment_request *req,
					  u64 *seg_id,
					  struct ssdfs_blk2off_range *extent);
int ssdfs_segment_migrate_zone_block_async(struct ssdfs_fs_info *fsi,
					   int req_type,
					   struct ssdfs_segment_request *req,
					   u64 *seg_id,
					   struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_leaf_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_leaf_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_hybrid_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_hybrid_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_index_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_index_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);

int ssdfs_segment_pre_alloc_data_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_pre_alloc_data_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_pre_alloc_leaf_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_pre_alloc_leaf_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_pre_alloc_hybrid_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_pre_alloc_hybrid_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_pre_alloc_index_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_pre_alloc_index_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);

int ssdfs_segment_add_data_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_add_data_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_migrate_zone_extent_sync(struct ssdfs_fs_info *fsi,
					   int req_type,
					   struct ssdfs_segment_request *req,
					   u64 *seg_id,
					   struct ssdfs_blk2off_range *extent);
int ssdfs_segment_migrate_zone_extent_async(struct ssdfs_fs_info *fsi,
					    int req_type,
					    struct ssdfs_segment_request *req,
					    u64 *seg_id,
					    struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_xattr_blob_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_xattr_blob_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_leaf_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_leaf_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_hybrid_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_hybrid_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_index_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);
int ssdfs_segment_add_index_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent);

int ssdfs_segment_update_data_block_sync(struct ssdfs_segment_info *si,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_update_data_block_async(struct ssdfs_segment_info *si,
					int req_type,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_update_data_extent_sync(struct ssdfs_segment_info *si,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
int ssdfs_segment_update_data_extent_async(struct ssdfs_segment_info *si,
					int req_type,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch);
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

int ssdfs_segment_node_diff_on_write_sync(struct ssdfs_segment_info *si,
					  struct ssdfs_segment_request *req);
int ssdfs_segment_node_diff_on_write_async(struct ssdfs_segment_info *si,
					   int req_type,
					   struct ssdfs_segment_request *req);
int ssdfs_segment_data_diff_on_write_sync(struct ssdfs_segment_info *si,
					  struct ssdfs_segment_request *req);
int ssdfs_segment_data_diff_on_write_async(struct ssdfs_segment_info *si,
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
int ssdfs_segment_commit_log_sync2(struct ssdfs_segment_info *si,
				   u16 peb_index,
				   struct ssdfs_segment_request *req);
int ssdfs_segment_commit_log_async2(struct ssdfs_segment_info *si,
				    int req_type, u16 peb_index,
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

/*
 * Internal segment object's API
 */
struct ssdfs_segment_info *
__ssdfs_create_new_segment(struct ssdfs_fs_info *fsi,
			   u64 seg_id, int seg_state,
			   u16 seg_type, u16 log_pages,
			   u8 create_threads);
int ssdfs_segment_change_state(struct ssdfs_segment_info *si);
int ssdfs_segment_detect_search_range(struct ssdfs_fs_info *fsi,
				      u64 *start_seg, u64 *end_seg);

#endif /* _SSDFS_SEGMENT_H */
