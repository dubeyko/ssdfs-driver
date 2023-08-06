// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/current_segment.c - current segment abstraction implementation.
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

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "ssdfs.h"
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "page_array.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "current_segment.h"
#include "segment_tree.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_cur_seg_page_leaks;
atomic64_t ssdfs_cur_seg_folio_leaks;
atomic64_t ssdfs_cur_seg_memory_leaks;
atomic64_t ssdfs_cur_seg_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_cur_seg_cache_leaks_increment(void *kaddr)
 * void ssdfs_cur_seg_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_cur_seg_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_cur_seg_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_cur_seg_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_cur_seg_kfree(void *kaddr)
 * struct page *ssdfs_cur_seg_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_cur_seg_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_cur_seg_free_page(struct page *page)
 * void ssdfs_cur_seg_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(cur_seg)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(cur_seg)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_cur_seg_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_cur_seg_page_leaks, 0);
	atomic64_set(&ssdfs_cur_seg_folio_leaks, 0);
	atomic64_set(&ssdfs_cur_seg_memory_leaks, 0);
	atomic64_set(&ssdfs_cur_seg_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_cur_seg_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_cur_seg_page_leaks) != 0) {
		SSDFS_ERR("CURRENT SEGMENT: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_cur_seg_page_leaks));
	}

	if (atomic64_read(&ssdfs_cur_seg_folio_leaks) != 0) {
		SSDFS_ERR("CURRENT SEGMENT: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_cur_seg_folio_leaks));
	}

	if (atomic64_read(&ssdfs_cur_seg_memory_leaks) != 0) {
		SSDFS_ERR("CURRENT SEGMENT: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_cur_seg_memory_leaks));
	}

	if (atomic64_read(&ssdfs_cur_seg_cache_leaks) != 0) {
		SSDFS_ERR("CURRENT SEGMENT: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_cur_seg_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/******************************************************************************
 *               CURRENT SEGMENT CONTAINER FUNCTIONALITY                      *
 ******************************************************************************/

/*
 * ssdfs_current_segment_init() - init current segment container
 * @fsi: pointer on shared file system object
 * @type: current segment type
 * @seg_id: segment ID
 * @cur_seg: pointer on current segment container [out]
 */
static
void ssdfs_current_segment_init(struct ssdfs_fs_info *fsi,
				int type,
				u64 seg_id,
				struct ssdfs_current_segment *cur_seg)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !cur_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	mutex_init(&cur_seg->lock);
	cur_seg->type = type;
	cur_seg->seg_id = seg_id;
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
	if (!cur_seg)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(mutex_is_locked(&cur_seg->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_current_segment_empty(cur_seg)) {
		ssdfs_current_segment_lock(cur_seg);
		ssdfs_current_segment_remove(cur_seg);
		ssdfs_current_segment_unlock(cur_seg);
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

	SSDFS_DBG("seg %llu, max free pages: value %d, pos %d\n",
		  si->seg_id, max_free_pages->value, max_free_pages->pos);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!need_select_flush_threads(atomic_read(&si->seg_state)) ||
	    atomic_read(&si->blk_bmap.seg_free_blks) == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu can't be used as current: \n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
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
	int state;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !si);

	if (!mutex_is_locked(&cur_seg->lock)) {
		SSDFS_WARN("current segment container should be locked\n");
		return -EINVAL;
	}

	SSDFS_DBG("seg %llu, log_pages %u, create_threads %u, seg_type %#x\n",
		  si->seg_id, si->log_pages,
		  si->create_threads, si->seg_type);
#endif /* CONFIG_SSDFS_DEBUG */

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
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("seg %llu, peb_index %u, free_pages %d\n",
				  si->seg_id, pebc->peb_index,
				  peb_free_pages);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		if (max_free_pages.value < peb_free_pages) {
			max_free_pages.value = peb_free_pages;
			max_free_pages.pos = i;
		}
	}

	if (max_free_pages.value <= 0 || max_free_pages.pos < 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu can't be used as current: "
			  "max_free_pages.value %d, "
			  "max_free_pages.pos %d\n",
			  si->seg_id,
			  max_free_pages.value,
			  max_free_pages.pos);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOSPC;
	}

	err = ssdfs_segment_select_flush_threads(si, &max_free_pages);
	if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu can't be used as current\n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
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

	state = atomic_cmpxchg(&si->obj_state,
				SSDFS_SEG_OBJECT_CREATED,
				SSDFS_CURRENT_SEG_OBJECT);
	if (state < SSDFS_SEG_OBJECT_CREATED ||
	    state >= SSDFS_CURRENT_SEG_OBJECT) {
		ssdfs_segment_put_object(si);
		SSDFS_WARN("unexpected state %#x\n",
			   state);
		return -ERANGE;
	}

	cur_seg->real_seg = si;
	cur_seg->seg_id = si->seg_id;

	return 0;
}

/*
 * ssdfs_current_segment_remove() - remove current segment
 * @cur_seg: pointer on current segment container
 */
void ssdfs_current_segment_remove(struct ssdfs_current_segment *cur_seg)
{
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg);

	if (!mutex_is_locked(&cur_seg->lock))
		SSDFS_WARN("current segment container should be locked\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_ssdfs_current_segment_empty(cur_seg)) {
		SSDFS_WARN("current segment container is empty\n");
		return;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, log_pages %u, create_threads %u, seg_type %#x\n",
		  cur_seg->real_seg->seg_id,
		  cur_seg->real_seg->log_pages,
		  cur_seg->real_seg->create_threads,
		  cur_seg->real_seg->seg_type);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_cmpxchg(&cur_seg->real_seg->obj_state,
				SSDFS_CURRENT_SEG_OBJECT,
				SSDFS_SEG_OBJECT_CREATED);
	if (state <= SSDFS_SEG_OBJECT_CREATED ||
	    state > SSDFS_CURRENT_SEG_OBJECT) {
		SSDFS_WARN("unexpected state %#x\n",
			   state);
	}

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

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->cur_segs =
		ssdfs_cur_seg_kzalloc(sizeof(struct ssdfs_current_segs_array),
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

		object = (struct ssdfs_current_segment *)(start_ptr + offset);
		fsi->cur_segs->objects[i] = object;
		seg = le64_to_cpu(fsi->vs->cur_segs[i]);

		ssdfs_current_segment_init(fsi, i, seg, object);

		if (seg == U64_MAX)
			continue;

		switch (i) {
		case SSDFS_CUR_DATA_SEG:
		case SSDFS_CUR_DATA_UPDATE_SEG:
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

		si = __ssdfs_create_new_segment(fsi, seg,
						seg_state, seg_type,
						log_pages,
						fsi->create_threads_per_seg);
		if (IS_ERR_OR_NULL(si)) {
			err = (si == NULL ? -ENOMEM : PTR_ERR(si));
			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto destroy_cur_segs;
			} else {
				SSDFS_WARN("fail to create segment object: "
					   "seg %llu, err %d\n",
					   seg, err);
				goto destroy_cur_segs;
			}
		}

		ssdfs_current_segment_lock(object);
		err = ssdfs_current_segment_add(object, si);
		ssdfs_current_segment_unlock(object);

		if (err == -ENOSPC) {
			err = ssdfs_segment_change_state(si);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change segment's state: "
					  "seg %llu, err %d\n",
					  seg, err);
				goto destroy_cur_segs;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("current segment is absent\n");
#endif /* CONFIG_SSDFS_DEBUG */
			ssdfs_segment_put_object(si);
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to make segment %llu as current: "
				  "err %d\n",
				  seg, err);
			goto destroy_cur_segs;
		} else {
			/*
			 * Segment object was referenced two times
			 * in __ssdfs_create_new_segment() and
			 * ssdfs_current_segment_add().
			 */
			ssdfs_segment_put_object(si);
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DONE: create current segment array\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

destroy_cur_segs:
	for (; i >= 0; i--) {
		struct ssdfs_current_segment *cur_seg;

		cur_seg = fsi->cur_segs->objects[i];

		ssdfs_current_segment_lock(cur_seg);
		ssdfs_current_segment_remove(cur_seg);
		ssdfs_current_segment_unlock(cur_seg);
	}

	ssdfs_cur_seg_kfree(fsi->cur_segs);
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

	SSDFS_DBG("fsi->cur_segs %p\n", fsi->cur_segs);
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("fsi->cur_segs %p\n", fsi->cur_segs);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!fsi->cur_segs)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(rwsem_is_locked(&fsi->cur_segs->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_cur_seg_kfree(fsi->cur_segs);
	fsi->cur_segs = NULL;
}
