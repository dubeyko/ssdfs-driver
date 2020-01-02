//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/current_segment.c - current segment abstraction implementation.
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

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "page_array.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "current_segment.h"
#include "segment_tree.h"

#include <trace/events/ssdfs.h>

/******************************************************************************
 *               CURRENT SEGMENT CONTAINER FUNCTIONALITY                      *
 ******************************************************************************/

/*
 * ssdfs_current_segment_init() - init current segment container
 * @fsi: pointer on shared file system object
 * @type: current segment type
 * @cur_seg: pointer on current segment container [out]
 */
static
void ssdfs_current_segment_init(struct ssdfs_fs_info *fsi,
				int type,
				struct ssdfs_current_segment *cur_seg)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !cur_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	mutex_init(&cur_seg->lock);
	cur_seg->type = type;
	cur_seg->real_seg = NULL;
	cur_seg->fsi = fsi;
}

/*
 * ssdfs_current_segment_destroy() - destroy current segment
 * @cur_seg: pointer on current segment container
 */
static
void ssdfs_current_segment_destroy(struct ssdfs_current_segment *cur_seg)
{
	struct ssdfs_segment_info *si = NULL;
	int err;

	if (!cur_seg)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(mutex_is_locked(&cur_seg->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_current_segment_empty(cur_seg)) {
		ssdfs_current_segment_lock(cur_seg);
		si = cur_seg->real_seg;
		ssdfs_current_segment_remove(cur_seg);
		ssdfs_current_segment_unlock(cur_seg);
	}

	if (si) {
		err = ssdfs_segment_tree_remove(si->fsi, si);
		if (unlikely(err)) {
			SSDFS_WARN("fail to remove segment from tree: "
				   "seg %llu, err %d\n",
				   si->seg_id, err);
		}
	}
}

/*
 * ssdfs_current_segment_lock() - lock current segment
 * @cur_seg: pointer on current segment container
 */
void ssdfs_current_segment_lock(struct ssdfs_current_segment *cur_seg)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	err = mutex_lock_killable(&cur_seg->lock);
	WARN_ON(err);
}

/*
 * ssdfs_current_segment_unlock() - unlock current segment
 * @cur_seg: pointer on current segment container
 */
void ssdfs_current_segment_unlock(struct ssdfs_current_segment *cur_seg)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg);
	WARN_ON(!mutex_is_locked(&cur_seg->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	mutex_unlock(&cur_seg->lock);
}

/*
 * need_select_flush_threads() - check necessity to select flush threads
 * @seg_state: segment state
 */
static inline
bool need_select_flush_threads(int seg_state)
{
	bool need_select = true;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg_state >= SSDFS_SEG_STATE_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (seg_state) {
	case SSDFS_SEG_CLEAN:
	case SSDFS_SEG_DATA_USING:
	case SSDFS_SEG_LEAF_NODE_USING:
	case SSDFS_SEG_HYBRID_NODE_USING:
	case SSDFS_SEG_INDEX_NODE_USING:
		need_select = true;
		break;

	case SSDFS_SEG_USED:
	case SSDFS_SEG_PRE_DIRTY:
	case SSDFS_SEG_DIRTY:
		need_select = false;
		break;

	default:
		BUG();
	}

	return need_select;
}

/*
 * ssdfs_segment_select_flush_threads() - select flush threads
 * @si: pointer on segment object
 * @max_free_pages: max value and position pair
 *
 * This function selects PEBs' flush threads that will process
 * new pages requests.
 */
static
int ssdfs_segment_select_flush_threads(struct ssdfs_segment_info *si,
					struct ssdfs_value_pair *max_free_pages)
{
	int start_pos;
	u8 found_flush_threads = 0;
	int peb_free_pages;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !max_free_pages);
	BUG_ON(max_free_pages->value <= 0);
	BUG_ON(max_free_pages->pos < 0);
	BUG_ON(max_free_pages->pos >= si->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, max free pages: value %d, pos %d\n",
		  si->seg_id, max_free_pages->value, max_free_pages->pos);

	if (!need_select_flush_threads(atomic_read(&si->seg_state)) ||
	    atomic_read(&si->blk_bmap.free_logical_blks) == 0) {
		SSDFS_DBG("segment %llu can't be used as current: \n",
			  si->seg_id);
		return -ENOSPC;
	}

	start_pos = max_free_pages->pos + si->create_threads - 1;
	start_pos /= si->create_threads;
	start_pos *= si->create_threads;

	if (start_pos >= si->pebs_count)
		start_pos = 0;

	for (i = start_pos; i < si->pebs_count; i++) {
		struct ssdfs_peb_container *pebc = &si->peb_array[i];

		if (found_flush_threads == si->create_threads)
			break;

		peb_free_pages = ssdfs_peb_get_free_pages(pebc);
		if (unlikely(peb_free_pages < 0)) {
			err = peb_free_pages;
			SSDFS_ERR("fail to calculate PEB's free pages: "
				  "pebc %p, seg %llu, peb index %d, err %d\n",
				  pebc, si->seg_id, i, err);
			return err;
		}

		if (peb_free_pages == 0 ||
		    is_peb_joined_into_create_requests_queue(pebc))
			continue;

		err = ssdfs_peb_join_create_requests_queue(pebc,
							   &si->create_rq);
		if (unlikely(err)) {
			SSDFS_ERR("fail to join create requests queue: "
				  "seg %llu, peb index %d, err %d\n",
				  si->seg_id, i, err);
			return err;
		}
		found_flush_threads++;
	}

	for (i = 0; i < start_pos; i++) {
		struct ssdfs_peb_container *pebc = &si->peb_array[i];

		if (found_flush_threads == si->create_threads)
			break;

		peb_free_pages = ssdfs_peb_get_free_pages(pebc);
		if (unlikely(peb_free_pages < 0)) {
			err = peb_free_pages;
			SSDFS_ERR("fail to calculate PEB's free pages: "
				  "pebc %p, seg %llu, peb index %d, err %d\n",
				  pebc, si->seg_id, i, err);
			return err;
		}

		if (peb_free_pages == 0 ||
		    is_peb_joined_into_create_requests_queue(pebc))
			continue;

		err = ssdfs_peb_join_create_requests_queue(pebc,
							   &si->create_rq);
		if (unlikely(err)) {
			SSDFS_ERR("fail to join create requests queue: "
				  "seg %llu, peb index %d, err %d\n",
				  si->seg_id, i, err);
			return err;
		}
		found_flush_threads++;
	}

	return 0;
}

/*
 * ssdfs_current_segment_add() - prepare current segment
 * @cur_seg: pointer on current segment container
 * @si: pointer on segment object
 *
 * This function tries to make segment object @si as current.
 * If segment is "clean" or "using" then it can be a current
 * segment that processes new page requests.
 * In such case, segment object is initialized by pointer on
 * new page requests queue. Also it chooses flush threads of several
 * PEBs as actual threads for proccessing new page requests in
 * parallel. It makes sense to restrict count of such threads by
 * CPUs number or independent dies number. Number of free pages in
 * PEB can be a basis for choosing thread as actual thread for
 * proccessing new page requests. Namely, first @flush_threads that
 * has as maximum as possible free pages choose for this role, firstly.
 * When some thread fills the log then it delegates your role
 * to a next candidate thread in the chain.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_current_segment_add(struct ssdfs_current_segment *cur_seg,
			      struct ssdfs_segment_info *si)
{
	struct ssdfs_value_pair max_free_pages;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !si);

	if (!mutex_is_locked(&cur_seg->lock)) {
		SSDFS_WARN("current segment container should be locked\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, log_pages %u, create_threads %u, seg_type %#x\n",
		  si->seg_id, si->log_pages,
		  si->create_threads, si->seg_type);

	BUG_ON(!is_ssdfs_current_segment_empty(cur_seg));

	max_free_pages.value = 0;
	max_free_pages.pos = -1;

	for (i = 0; i < si->pebs_count; i++) {
		int peb_free_pages;
		struct ssdfs_peb_container *pebc = &si->peb_array[i];

		peb_free_pages = ssdfs_peb_get_free_pages(pebc);
		if (unlikely(peb_free_pages < 0)) {
			err = peb_free_pages;
			SSDFS_ERR("fail to calculate PEB's free pages: "
				  "pebc %p, seg %llu, peb index %d, err %d\n",
				  pebc, si->seg_id, i, err);
			return err;
		} else if (peb_free_pages == 0) {
			SSDFS_DBG("seg %llu, peb_index %u, free_pages %d\n",
				  si->seg_id, pebc->peb_index,
				  peb_free_pages);
		}

		if (max_free_pages.value < peb_free_pages) {
			max_free_pages.value = peb_free_pages;
			max_free_pages.pos = i;
		}
	}

	if (max_free_pages.value <= 0 || max_free_pages.pos < 0) {
		SSDFS_DBG("segment %llu can't be used as current: "
			  "max_free_pages.value %d, "
			  "max_free_pages.pos %d\n",
			  si->seg_id,
			  max_free_pages.value,
			  max_free_pages.pos);
		return -ENOSPC;
	}

	err = ssdfs_segment_select_flush_threads(si, &max_free_pages);
	if (err == -ENOSPC) {
		SSDFS_DBG("segment %llu can't be used as current\n",
			  si->seg_id);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to select flush threads: "
			  "seg %llu, max free pages: value %d, pos %d, "
			  "err %d\n",
			  si->seg_id, max_free_pages.value, max_free_pages.pos,
			  err);
		return err;
	}

	ssdfs_segment_get_object(si);
	cur_seg->real_seg = si;

	return 0;
}

/*
 * ssdfs_current_segment_remove() - remove current segment
 * @cur_seg: pointer on current segment container
 */
void ssdfs_current_segment_remove(struct ssdfs_current_segment *cur_seg)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg);

	if (!mutex_is_locked(&cur_seg->lock))
		SSDFS_WARN("current segment container should be locked\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_ssdfs_current_segment_empty(cur_seg)) {
		SSDFS_WARN("current segment container is empty\n");
		return;
	}

	SSDFS_DBG("seg %llu, log_pages %u, create_threads %u, seg_type %#x\n",
		  cur_seg->real_seg->seg_id,
		  cur_seg->real_seg->log_pages,
		  cur_seg->real_seg->create_threads,
		  cur_seg->real_seg->seg_type);

	ssdfs_segment_put_object(cur_seg->real_seg);
	cur_seg->real_seg = NULL;
}

/******************************************************************************
 *                 CURRENT SEGMENTS ARRAY FUNCTIONALITY                       *
 ******************************************************************************/

/*
 * ssdfs_current_segment_array_create() - create current segments array
 * @fsi: pointer on shared file system object
 */
int ssdfs_current_segment_array_create(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_segment_info *si;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	fsi->cur_segs = kzalloc(sizeof(struct ssdfs_current_segs_array),
				GFP_KERNEL);
	if (!fsi->cur_segs) {
		SSDFS_ERR("fail to allocate current segments array\n");
		return -ENOMEM;
	}

	init_rwsem(&fsi->cur_segs->lock);

	for (i = 0; i < SSDFS_CUR_SEGS_COUNT; i++) {
		u64 seg;
		size_t offset = i * sizeof(struct ssdfs_current_segment);
		u8 *start_ptr = fsi->cur_segs->buffer;
		struct ssdfs_current_segment *object = NULL;
		int seg_state, seg_type;
		u16 log_pages;
		u16 create_threads;

		object = (struct ssdfs_current_segment *)(start_ptr + offset);
		fsi->cur_segs->objects[i] = object;
		ssdfs_current_segment_init(fsi, i, object);

		seg = le64_to_cpu(fsi->vs->cur_segs[i]);

		if (seg == U64_MAX)
			continue;

		switch (i) {
		case SSDFS_CUR_DATA_SEG:
			seg_state = SSDFS_SEG_DATA_USING;
			seg_type = SSDFS_USER_DATA_SEG_TYPE;
			log_pages = le16_to_cpu(fsi->vh->user_data_log_pages);
			break;

		case SSDFS_CUR_LNODE_SEG:
			seg_state = SSDFS_SEG_LEAF_NODE_USING;
			seg_type = SSDFS_LEAF_NODE_SEG_TYPE;
			log_pages = le16_to_cpu(fsi->vh->lnodes_seg_log_pages);
			break;

		case SSDFS_CUR_HNODE_SEG:
			seg_state = SSDFS_SEG_HYBRID_NODE_USING;
			seg_type = SSDFS_HYBRID_NODE_SEG_TYPE;
			log_pages = le16_to_cpu(fsi->vh->hnodes_seg_log_pages);
			break;

		case SSDFS_CUR_IDXNODE_SEG:
			seg_state = SSDFS_SEG_INDEX_NODE_USING;
			seg_type = SSDFS_INDEX_NODE_SEG_TYPE;
			log_pages = le16_to_cpu(fsi->vh->inodes_seg_log_pages);
			break;

		default:
			BUG();
		};

		/* TODO: make final desicion later */
		create_threads = SSDFS_CREATE_THREADS_DEFAULT;

		si = ssdfs_segment_create_object(fsi, seg,
						 seg_state, seg_type,
						 log_pages,
						 create_threads);
		if (IS_ERR_OR_NULL(si)) {
			SSDFS_WARN("fail to create segment object: "
				   "seg %llu, err %d\n",
				   seg, err);
			continue;
		}

		err = ssdfs_segment_tree_add(fsi, si);
		if (unlikely(err)) {
			ssdfs_segment_destroy_object(si);
			SSDFS_ERR("fail to add segment object into tree: "
				  "seg %llu, err %d\n",
				  seg, err);
			goto destroy_cur_segs;
		}

		ssdfs_current_segment_lock(object);
		err = ssdfs_current_segment_add(object, si);
		ssdfs_current_segment_unlock(object);

		if (err == -ENOSPC) {
			SSDFS_DBG("current segment is absent\n");
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to make segment %llu as current: "
				  "err %d\n",
				  seg, err);
			goto destroy_cur_segs;
		}
	}

	SSDFS_DBG("DONE: create current segment array\n");

	return 0;

destroy_cur_segs:
	for (; i >= 0; i--) {
		si = NULL;

		ssdfs_current_segment_lock(fsi->cur_segs->objects[i]);
		if (fsi->cur_segs->objects[i])
			si = fsi->cur_segs->objects[i]->real_seg;
		ssdfs_current_segment_remove(fsi->cur_segs->objects[i]);
		ssdfs_current_segment_unlock(fsi->cur_segs->objects[i]);

		if (si) {
			int err1;
			err1 = ssdfs_segment_tree_remove(si->fsi, si);
			SSDFS_WARN("fail to remove segment from tree: "
				   "seg %llu, err %d\n",
				   si->seg_id, err1);
		}
	}

	kfree(fsi->cur_segs);
	fsi->cur_segs = NULL;

	return err;
}

/*
 * ssdfs_destroy_all_curent_segments() - destroy all current segments
 * @fsi: pointer on shared file system object
 */
void ssdfs_destroy_all_curent_segments(struct ssdfs_fs_info *fsi)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi->cur_segs %p\n", fsi->cur_segs);

	if (!fsi->cur_segs)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(rwsem_is_locked(&fsi->cur_segs->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fsi->cur_segs->lock);
	for (i = 0; i < SSDFS_CUR_SEGS_COUNT; i++)
		ssdfs_current_segment_destroy(fsi->cur_segs->objects[i]);
	up_write(&fsi->cur_segs->lock);
}

/*
 * ssdfs_current_segment_array_destroy() - destroy current segments array
 * @fsi: pointer on shared file system object
 */
void ssdfs_current_segment_array_destroy(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi->cur_segs %p\n", fsi->cur_segs);

	if (!fsi->cur_segs)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(rwsem_is_locked(&fsi->cur_segs->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	kfree(fsi->cur_segs);
	fsi->cur_segs = NULL;
}
