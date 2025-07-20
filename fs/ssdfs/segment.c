/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment.c - segment concept related functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2025 Viacheslav Dubeyko <slava@dubeyko.com>
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

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "block_bitmap.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "current_segment.h"
#include "segment_tree.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_seg_obj_folio_leaks;
atomic64_t ssdfs_seg_obj_memory_leaks;
atomic64_t ssdfs_seg_obj_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_seg_obj_cache_leaks_increment(void *kaddr)
 * void ssdfs_seg_obj_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_seg_obj_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_seg_obj_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_seg_obj_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_seg_obj_kfree(void *kaddr)
 * struct folio *ssdfs_seg_obj_alloc_folio(gfp_t gfp_mask,
 *                                         unsigned int order)
 * struct folio *ssdfs_seg_obj_add_batch_folio(struct folio_batch *batch,
 *                                             unsigned int order)
 * void ssdfs_seg_obj_free_folio(struct folio *folio)
 * void ssdfs_seg_obj_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(seg_obj)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(seg_obj)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_seg_obj_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_seg_obj_folio_leaks, 0);
	atomic64_set(&ssdfs_seg_obj_memory_leaks, 0);
	atomic64_set(&ssdfs_seg_obj_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_seg_obj_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_seg_obj_folio_leaks) != 0) {
		SSDFS_ERR("SEGMENT: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_seg_obj_folio_leaks));
	}

	if (atomic64_read(&ssdfs_seg_obj_memory_leaks) != 0) {
		SSDFS_ERR("SEGMENT: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_seg_obj_memory_leaks));
	}

	if (atomic64_read(&ssdfs_seg_obj_cache_leaks) != 0) {
		SSDFS_ERR("SEGMENT: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_seg_obj_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static struct kmem_cache *ssdfs_seg_obj_cachep;

static void ssdfs_init_seg_object_once(void *obj)
{
	struct ssdfs_segment_info *seg_obj = obj;

	atomic_set(&seg_obj->refs_count, 0);
}

void ssdfs_shrink_seg_obj_cache(void)
{
	if (ssdfs_seg_obj_cachep)
		kmem_cache_shrink(ssdfs_seg_obj_cachep);
}

void ssdfs_zero_seg_obj_cache_ptr(void)
{
	ssdfs_seg_obj_cachep = NULL;
}

void ssdfs_destroy_seg_obj_cache(void)
{
	if (ssdfs_seg_obj_cachep)
		kmem_cache_destroy(ssdfs_seg_obj_cachep);
}

int ssdfs_init_seg_obj_cache(void)
{
	ssdfs_seg_obj_cachep = kmem_cache_create("ssdfs_seg_obj_cache",
					sizeof(struct ssdfs_segment_info), 0,
					SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
					ssdfs_init_seg_object_once);
	if (!ssdfs_seg_obj_cachep) {
		SSDFS_ERR("unable to create segment objects cache\n");
		return -ENOMEM;
	}

	return 0;
}

/******************************************************************************
 *                       SEGMENT OBJECT FUNCTIONALITY                         *
 ******************************************************************************/

/*
 * ssdfs_segment_allocate_object() - allocate segment object
 * @seg_id: segment number
 *
 * This function tries to allocate segment object.
 *
 * RETURN:
 * [success] - pointer on allocated segment object
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 */
struct ssdfs_segment_info *ssdfs_segment_allocate_object(u64 seg_id)
{
	struct ssdfs_segment_info *ptr;
	unsigned int nofs_flags;

	nofs_flags = memalloc_nofs_save();
	ptr = kmem_cache_alloc(ssdfs_seg_obj_cachep, GFP_KERNEL);
	memalloc_nofs_restore(nofs_flags);

	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for segment %llu\n",
			  seg_id);
		return ERR_PTR(-ENOMEM);
	}

	ssdfs_seg_obj_cache_leaks_increment(ptr);

	memset(ptr, 0, sizeof(struct ssdfs_segment_info));
	atomic_set(&ptr->obj_state, SSDFS_SEG_OBJECT_UNDER_CREATION);
	atomic_set(&ptr->activity_type, SSDFS_SEG_OBJECT_NO_ACTIVITY);
	ptr->seg_id = seg_id;
	atomic_set(&ptr->refs_count, 0);
	init_waitqueue_head(&ptr->object_queue);

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ptr->writeback_folios, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segment object %p, seg_id %llu\n",
		  ptr, seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return ptr;
}

/*
 * ssdfs_segment_free_object() - free segment object
 * @si: pointer on segment object
 *
 * This function tries to free segment object.
 */
void ssdfs_segment_free_object(struct ssdfs_segment_info *si)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segment object %p\n", si);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!si)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&si->obj_state)) {
	case SSDFS_SEG_OBJECT_UNDER_CREATION:
	case SSDFS_SEG_OBJECT_CREATED:
	case SSDFS_CURRENT_SEG_OBJECT:
	case SSDFS_SEG_OBJECT_FAILURE:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected segment object's state %#x\n",
			   atomic_read(&si->obj_state));
		break;
	}

	switch (atomic_read(&si->activity_type)) {
	case SSDFS_SEG_OBJECT_NO_ACTIVITY:
	case SSDFS_SEG_OBJECT_REGULAR_ACTIVITY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected segment object's activity %#x\n",
			   atomic_read(&si->activity_type));
		break;
	}

	ssdfs_seg_obj_cache_leaks_decrement(si);
	kmem_cache_free(ssdfs_seg_obj_cachep, si);
}

/*
 * ssdfs_segment_destroy_object() - destroy segment object
 * @si: pointer on segment object
 *
 * This function tries to destroy segment object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EBUSY      - segment object is referenced yet.
 * %-EIO        - I/O error.
 */
int ssdfs_segment_destroy_object(struct ssdfs_segment_info *si)
{
	int refs_count;
	int res;
	int err = 0;

	if (!si)
		return 0;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, seg_state %#x, log_pages %u, "
		  "create_threads %u\n",
		  si->seg_id, atomic_read(&si->seg_state),
		  si->log_pages, si->create_threads);
	SSDFS_ERR("obj_state %#x\n",
		  atomic_read(&si->obj_state));
#else
	SSDFS_DBG("seg %llu, seg_state %#x, log_pages %u, "
		  "create_threads %u\n",
		  si->seg_id, atomic_read(&si->seg_state),
		  si->log_pages, si->create_threads);
	SSDFS_DBG("obj_state %#x\n",
		  atomic_read(&si->obj_state));
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	switch (atomic_read(&si->obj_state)) {
	case SSDFS_SEG_OBJECT_UNDER_CREATION:
	case SSDFS_SEG_OBJECT_CREATED:
	case SSDFS_CURRENT_SEG_OBJECT:
		/* expected state */
		break;

	default:
		SSDFS_WARN("unexpected segment object's state %#x\n",
			   atomic_read(&si->obj_state));
		break;
	}

	refs_count = atomic_read(&si->refs_count);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("si %p, seg %llu, refs_count %d\n",
		  si, si->seg_id, refs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (refs_count != 0) {
		wait_queue_head_t *wq = &si->object_queue;

		res = wait_event_killable_timeout(*wq,
				atomic_read(&si->refs_count) <= 0,
				SSDFS_DEFAULT_TIMEOUT);
		if (res < 0) {
			err = res;
			WARN_ON(1);
		} else if (res > 1) {
			/*
			 * Condition changed before timeout
			 */
		} else {
			/* timeout is elapsed */
			err = -ERANGE;
			WARN_ON(1);
		}

		if (atomic_read(&si->refs_count) != 0) {
			SSDFS_WARN("destroy object of segment %llu: "
				   "refs_count %d\n",
				   si->seg_id, refs_count);

			if (si->peb_array) {
				struct ssdfs_peb_container *pebc;
				int i;

				for (i = 0; i < si->pebs_count; i++) {
					pebc = &si->peb_array[i];

					if (pebc->src_peb) {
						SSDFS_ERR("src peb_id %llu\n",
							  pebc->src_peb->peb_id);
					}

					if (pebc->dst_peb) {
						SSDFS_ERR("dst peb_id %llu\n",
							  pebc->dst_peb->peb_id);
					}
				}
			}

			atomic_set(&si->refs_count, 0);
		}
	}

	ssdfs_sysfs_delete_seg_group(si);

	if (si->peb_array) {
		struct ssdfs_peb_container *pebc;
		int i;

		for (i = 0; i < si->pebs_count; i++) {
			pebc = &si->peb_array[i];
			ssdfs_peb_container_destroy(pebc);
		}

		ssdfs_seg_obj_kfree(si->peb_array);
	}

	ssdfs_segment_blk_bmap_destroy(&si->blk_bmap);

	if (si->blk2off_table)
		ssdfs_blk2off_table_destroy(si->blk2off_table);

	if (!is_ssdfs_requests_queue_empty(&si->create_rq)) {
		SSDFS_WARN("create queue is not empty\n");
		ssdfs_requests_queue_remove_all(si->fsi, &si->create_rq,
						-ENOSPC);
	}

	ssdfs_segment_free_object(si);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_segment_create_object() - create segment object
 * @fsi: pointer on shared file system object
 * @seg: segment number
 * @seg_state: segment state
 * @seg_type: segment type
 * @log_pages: count of pages in log
 * @create_threads: number of flush PEB's threads for new page requests
 * @si: pointer on segment object [in|out]
 *
 * This function tries to create segment object for @seg
 * identification number.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_create_object(struct ssdfs_fs_info *fsi,
				u64 seg,
				int seg_state,
				u16 seg_type,
				u16 log_pages,
				u8 create_threads,
				struct ssdfs_segment_info *si)
{
	struct ssdfs_peb_container *pebc;
	int state = SSDFS_BLK2OFF_OBJECT_CREATED;
	struct ssdfs_migration_destination *destination;
	int refs_count = fsi->pebs_per_seg;
	int destination_pebs = 0;
	int init_flag, init_state;
	u32 logical_blk_capacity;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !si);

	if (seg_state >= SSDFS_SEG_STATE_MAX) {
		SSDFS_ERR("invalid segment state %#x\n", seg_state);
		return -EINVAL;
	}

	if (seg_type > SSDFS_LAST_KNOWN_SEG_TYPE) {
		SSDFS_ERR("invalid segment type %#x\n", seg_type);
		return -EINVAL;
	}

	if (create_threads > fsi->pebs_per_seg ||
	    fsi->pebs_per_seg % create_threads) {
		SSDFS_ERR("invalid create threads count %u\n",
			  create_threads);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p, seg %llu, seg_state %#x, log_pages %u, "
		  "create_threads %u\n",
		  fsi, seg, seg_state, log_pages, create_threads);
#else
	SSDFS_DBG("fsi %p, seg %llu, seg_state %#x, log_pages %u, "
		  "create_threads %u\n",
		  fsi, seg, seg_state, log_pages, create_threads);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (seg >= fsi->nsegs) {
		SSDFS_ERR("requested seg %llu >= nsegs %llu\n",
			  seg, fsi->nsegs);
		return -EINVAL;
	}

	switch (atomic_read(&si->obj_state)) {
	case SSDFS_SEG_OBJECT_UNDER_CREATION:
		/* expected state */
		break;

	default:
		SSDFS_WARN("invalid segment object's state %#x\n",
			   atomic_read(&si->obj_state));
		ssdfs_segment_free_object(si);
		return -EINVAL;
	}

	si->seg_id = seg;
	si->seg_type = seg_type;
	si->log_pages = log_pages;
	si->create_threads = create_threads;
	si->fsi = fsi;
	init_rwsem(&si->modification_lock);
	atomic_set(&si->seg_state, seg_state);
	ssdfs_requests_queue_init(&si->create_rq);

	spin_lock_init(&si->protection.cno_lock);
	si->protection.create_cno = ssdfs_current_cno(fsi->sb);
	si->protection.last_request_cno = si->protection.create_cno;
	si->protection.reqs_count = 0;
	si->protection.protected_range = 0;
	si->protection.future_request_cno = si->protection.create_cno;

	spin_lock_init(&si->pending_lock);
	si->pending_new_user_data_pages = 0;
	si->invalidated_user_data_pages = 0;

	si->pebs_count = fsi->pebs_per_seg;
	si->peb_array = ssdfs_seg_obj_kcalloc(si->pebs_count,
				       sizeof(struct ssdfs_peb_container),
				       GFP_KERNEL);
	if (!si->peb_array) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory for peb array\n");
		goto fail_construct_seg_obj;
	}

	atomic_set(&si->migration.migrating_pebs, 0);
	spin_lock_init(&si->migration.lock);

	destination = &si->migration.array[SSDFS_LAST_DESTINATION];
	destination->state = SSDFS_EMPTY_DESTINATION;
	destination->destination_pebs = 0;
	destination->shared_peb_index = -1;

	destination = &si->migration.array[SSDFS_CREATING_DESTINATION];
	destination->state = SSDFS_EMPTY_DESTINATION;
	destination->destination_pebs = 0;
	destination->shared_peb_index = -1;

	for (i = 0; i < SSDFS_PEB_THREAD_TYPE_MAX; i++)
		init_waitqueue_head(&si->wait_queue[i]);

	if (seg_state == SSDFS_SEG_CLEAN) {
		state = SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT;
		init_flag = SSDFS_BLK_BMAP_CREATE;
		init_state = SSDFS_BLK_FREE;
	} else {
		init_flag = SSDFS_BLK_BMAP_INIT;
		init_state = SSDFS_BLK_STATE_MAX;
	}

	logical_blk_capacity = fsi->leb_pages_capacity * fsi->pebs_per_seg;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create segment block bitmap: seg %llu\n", seg);
#else
	SSDFS_DBG("create segment block bitmap: seg %llu\n", seg);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_segment_blk_bmap_create(si, init_flag, init_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create segment block bitmap: "
			  "err %d\n", err);
		goto free_peb_array;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create blk2off table: seg %llu\n", seg);
#else
	SSDFS_DBG("create blk2off table: seg %llu\n", seg);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	si->blk2off_table = ssdfs_blk2off_table_create(fsi,
							logical_blk_capacity,
							SSDFS_SEG_OFF_TABLE,
							state);
	if (!si->blk2off_table) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory for translation table\n");
		goto destroy_seg_blk_bmap;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create PEB containers: seg %llu\n", seg);
#else
	SSDFS_DBG("create PEB containers: seg %llu\n", seg);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	for (i = 0; i < si->pebs_count; i++) {
		err = ssdfs_peb_container_create(fsi, seg, i,
						  SEG2PEB_TYPE(seg_type),
						  log_pages, si);
		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("NO FREE SPACE: "
				  "unable to create segment: "
				  "seg %llu, peb_index %d\n",
				  seg, i);
#endif /* CONFIG_SSDFS_DEBUG */
			goto destroy_blk2off_table;
		} else if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			goto destroy_blk2off_table;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create PEB container: "
				  "seg %llu, peb index %d, err %d\n",
				  seg, i, err);
			goto destroy_blk2off_table;
		}
	}

	for (i = 0; i < si->pebs_count; i++) {
		int cur_refs = atomic_read(&si->peb_array[i].dst_peb_refs);
		int items_state = atomic_read(&si->peb_array[i].items_state);

		switch (items_state) {
		case SSDFS_PEB1_DST_CONTAINER:
		case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
		case SSDFS_PEB2_DST_CONTAINER:
		case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
			destination_pebs++;
			break;

		default:
			/* do nothing */
			break;
		}

		if (cur_refs == 0)
			continue;

		if (cur_refs < refs_count)
			refs_count = cur_refs;
	}

	destination = &si->migration.array[SSDFS_LAST_DESTINATION];
	spin_lock(&si->migration.lock);
	destination->shared_peb_index = refs_count;
	destination->destination_pebs = destination_pebs;
	destination->state = SSDFS_VALID_DESTINATION;
	spin_unlock(&si->migration.lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("get free pages: seg %llu\n", seg);
#else
	SSDFS_DBG("get free pages: seg %llu\n", seg);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	/*
	 * The goal of this cycle is to finish segment object
	 * initialization. The segment object should have
	 * valid value of free blocks number.
	 * The ssdfs_peb_get_free_pages() method waits the
	 * ending of PEB object complete initialization.
	 */
	for (i = 0; i < si->pebs_count; i++) {
		int peb_free_pages;
		struct ssdfs_peb_container *pebc = &si->peb_array[i];

		if (is_peb_container_empty(pebc)) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("segment %llu hasn't PEB %d\n",
				  seg, i);
#endif /* CONFIG_SSDFS_DEBUG */
			continue;
		}

		peb_free_pages = ssdfs_peb_get_free_pages(pebc);
		if (unlikely(peb_free_pages < 0)) {
			err = peb_free_pages;
			SSDFS_ERR("fail to calculate PEB's free pages: "
				  "seg %llu, peb index %d, err %d\n",
				  seg, i, err);
			i = si->pebs_count;
			goto destroy_blk2off_table;
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create sysfs group: seg %llu\n", seg);
#else
	SSDFS_DBG("create sysfs group: seg %llu\n", seg);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_sysfs_create_seg_group(si);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create segment's sysfs group: "
			  "seg %llu, err %d\n",
			  seg, err);
		i = si->pebs_count;
		goto destroy_blk2off_table;
	}

	atomic_set(&si->obj_state, SSDFS_SEG_OBJECT_CREATED);
	atomic_set(&si->activity_type, SSDFS_SEG_OBJECT_REGULAR_ACTIVITY);
	wake_up_all(&si->object_queue);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("segment %llu has been created\n",
		  seg);
#else
	SSDFS_DBG("segment %llu has been created\n",
		  seg);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

destroy_blk2off_table:
	for (j = 0; j < i; j++) {
		pebc = &si->peb_array[j];
		ssdfs_peb_container_destroy(pebc);
	}

	ssdfs_blk2off_table_destroy(si->blk2off_table);

destroy_seg_blk_bmap:
	ssdfs_segment_blk_bmap_destroy(&si->blk_bmap);

free_peb_array:
	ssdfs_seg_obj_kfree(si->peb_array);

fail_construct_seg_obj:
	if (err == -ENOSPC || err == -EINTR) {
		/*
		 * Don't change segment object state
		 */
	} else
		atomic_set(&si->obj_state, SSDFS_SEG_OBJECT_FAILURE);

	wake_up_all(&si->object_queue);
	ssdfs_segment_free_object(si);

	return err;
}

/*
 * ssdfs_segment_get_object() - increment segment's reference counter
 * @si: pointer on segment object
 */
void ssdfs_segment_get_object(struct ssdfs_segment_info *si)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("seg_id %llu, refs_count %d\n",
		  si->seg_id, atomic_read(&si->refs_count));
#endif /* CONFIG_SSDFS_DEBUG */

	WARN_ON(atomic_inc_return(&si->refs_count) <= 0);
}

/*
 * ssdfs_segment_put_object() - decerement segment's reference counter
 * @si: pointer on segment object
 */
void ssdfs_segment_put_object(struct ssdfs_segment_info *si)
{
	if (!si)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, refs_count %d\n",
		  si->seg_id, atomic_read(&si->refs_count));
#endif /* CONFIG_SSDFS_DEBUG */

	WARN_ON(atomic_dec_return(&si->refs_count) < 0);

	if (atomic_read(&si->refs_count) <= 0)
		wake_up_all(&si->object_queue);
}

/*
 * ssdfs_segment_detect_search_range() - detect search range
 * @fsi: pointer on shared file system object
 * @start_seg: starting ID for segment search [in|out]
 * @end_seg: ending ID for segment search [out]
 *
 * This method tries to detect the search range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - unable to find valid range for search.
 */
int ssdfs_segment_detect_search_range(struct ssdfs_fs_info *fsi,
				      u64 *start_seg, u64 *end_seg)
{
	struct completion *init_end;
	u64 start_leb;
	u64 end_leb;
	u64 found_seg_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !start_seg || !end_seg);

	SSDFS_DBG("fsi %p, start_search_id %llu\n",
		  fsi, *start_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	if (*start_seg >= fsi->nsegs) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_seg %llu >= nsegs %llu\n",
			  *start_seg, fsi->nsegs);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

	start_leb = ssdfs_get_leb_id_for_peb_index(fsi, *start_seg, 0);
	if (start_leb >= U64_MAX) {
		SSDFS_ERR("invalid leb_id for seg_id %llu\n",
			  *start_seg);
		return -ERANGE;
	}

	err = ssdfs_maptbl_recommend_search_range(fsi, &start_leb,
						  &end_leb, &init_end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(init_end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			goto finish_seg_id_correction;
		}

		start_leb = ssdfs_get_leb_id_for_peb_index(fsi, *start_seg, 0);
		if (start_leb >= U64_MAX) {
			SSDFS_ERR("invalid leb_id for seg_id %llu\n",
				  *start_seg);
			return -ERANGE;
		}

		err = ssdfs_maptbl_recommend_search_range(fsi, &start_leb,
							  &end_leb, &init_end);
	}

	if (err == -ENOENT) {
		*start_seg = U64_MAX;
		*end_seg = U64_MAX;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find search range: leb_id %llu\n",
			  start_leb);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_seg_id_correction;
	} else if (unlikely(err)) {
		*start_seg = U64_MAX;
		*end_seg = U64_MAX;
		SSDFS_ERR("fail to find search range: "
			  "leb_id %llu, err %d\n",
			  start_leb, err);
		goto finish_seg_id_correction;
	}

	found_seg_id = SSDFS_LEB2SEG(fsi, start_leb);
	*start_seg = found_seg_id;

	found_seg_id = SSDFS_LEB2SEG(fsi, end_leb);
	if (found_seg_id == 0 || found_seg_id == *start_seg)
		*end_seg = found_seg_id + 1;
	else
		*end_seg = found_seg_id;

finish_seg_id_correction:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_seg %llu, end_seg %llu, err %d\n",
		  *start_seg, *end_seg, err);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_find_using_segment() - find a segment in using state
 * @fsi: pointer on shared file system object
 * @seg_type: segment type
 * @start_search_id: starting ID for segment search
 * @upper_search_bound: upper ID bound for search
 * @seg_id: found segment ID [out]
 * @seg_state: found segment state [out]
 *
 * This method tries to find a segment in using state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - unable to find a new segment.
 */
static
int ssdfs_find_using_segment(struct ssdfs_fs_info *fsi, int seg_type,
			     u64 start_search_id, u64 upper_search_bound,
			     u64 *seg_id, int *seg_state)
{
	int new_state;
	u64 start_seg = start_search_id;
	u64 end_seg = upper_search_bound;
	u64 leb_id;
	u16 pebs_per_fragment;
	u16 pebs_per_stripe;
	u16 stripes_per_fragment;
	struct completion *init_end;
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !seg_id || !seg_state);

	SSDFS_DBG("fsi %p, seg_type %#x, "
		  "start_search_id %llu, "
		  "upper_search_bound %llu\n",
		  fsi, seg_type,
		  start_search_id, upper_search_bound);
#endif /* CONFIG_SSDFS_DEBUG */

	*seg_id = U64_MAX;
	*seg_state = SSDFS_SEG_STATE_MAX;

	switch (seg_type) {
	case SSDFS_USER_DATA_SEG_TYPE:
		new_state = SSDFS_SEG_DATA_USING;
		break;

	case SSDFS_LEAF_NODE_SEG_TYPE:
		new_state = SSDFS_SEG_LEAF_NODE_USING;
		break;

	case SSDFS_HYBRID_NODE_SEG_TYPE:
		new_state = SSDFS_SEG_HYBRID_NODE_USING;
		break;

	case SSDFS_INDEX_NODE_SEG_TYPE:
		new_state = SSDFS_SEG_INDEX_NODE_USING;
		break;

	default:
		BUG();
	};

	if (start_seg <= end_seg) {
		/*
		 * Continue logic
		 */
	} else {
		err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find segment in range: "
			  "start_seg %llu, end_seg %llu\n",
			  start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_search;
	}

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi, start_seg, 0);
	if (leb_id >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to define LEB ID: start_seg %llu\n",
			  start_seg);
		goto finish_search;
	}

	err = ssdfs_maptbl_define_fragment_info(fsi, leb_id,
						&pebs_per_fragment,
						&pebs_per_stripe,
						&stripes_per_fragment);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define fragment info: "
			  "err %d\n", err);
		goto finish_search;
	}

	end_seg = min_t(u64, upper_search_bound,
			start_seg + pebs_per_fragment);

	res = ssdfs_segbmap_find_and_set(fsi->segbmap,
					 start_seg, end_seg,
					 SEG_TYPE_TO_USING_STATE(seg_type),
					 SEG_TYPE2MASK(seg_type),
					 new_state,
					 seg_id, &init_end);
	if (res >= 0) {
		/* Define segment state */
		*seg_state = res;
	} else if (res == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(init_end);
		if (unlikely(err)) {
			SSDFS_ERR("segbmap init failed: "
				  "err %d\n", err);
			goto finish_search;
		}

		res = ssdfs_segbmap_find_and_set(fsi->segbmap,
						 start_seg, end_seg,
						 SEG_TYPE_TO_USING_STATE(seg_type),
						 SEG_TYPE2MASK(seg_type),
						 new_state,
						 seg_id, &init_end);
		if (res >= 0) {
			/* Define segment state */
			*seg_state = res;
		} else if (res == -ENODATA) {
			err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find using segment in range: "
				  "start_seg %llu, end_seg %llu\n",
				  start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_search;
		} else if (res == -EAGAIN) {
			err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find using segment in range: "
				  "start_seg %llu, end_seg %llu\n",
				  start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_search;
		} else {
			err = res;
			SSDFS_ERR("fail to find segment in range: "
				  "start_seg %llu, end_seg %llu, err %d\n",
				  start_seg, end_seg, res);
			goto finish_search;
		}
	} else if (res == -ENODATA) {
		err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find using segment in range: "
			  "start_seg %llu, end_seg %llu\n",
			  start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_search;
	} else {
		SSDFS_ERR("fail to find segment in range: "
			  "start_seg %llu, end_seg %llu, err %d\n",
			  start_seg, end_seg, res);
		goto finish_search;
	}

finish_search:
	if (err == -ENOENT)
		*seg_id = end_seg;

	return err;
}

/*
 * ssdfs_find_clean_segment() - find a segment in clean state
 * @fsi: pointer on shared file system object
 * @seg_type: segment type
 * @start_search_id: starting ID for segment search
 * @upper_search_bound: upper ID bound for search
 * @seg_id: found segment ID [out]
 * @seg_state: found segment state [out]
 *
 * This method tries to find a segment in clean state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - unable to find a new segment.
 */
static
int ssdfs_find_clean_segment(struct ssdfs_fs_info *fsi, int seg_type,
			     u64 start_search_id, u64 upper_search_bound,
			     u64 *seg_id, int *seg_state)
{
	int new_state;
	u64 start_seg = start_search_id;
	u64 end_seg = upper_search_bound;
	u64 recommended_start = start_search_id;
	u64 recommended_end = upper_search_bound;
	struct completion *init_end;
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !seg_id || !seg_state);

	SSDFS_DBG("fsi %p, seg_type %#x, "
		  "start_search_id %llu, "
		  "upper_search_bound %llu\n",
		  fsi, seg_type,
		  start_search_id, upper_search_bound);
#endif /* CONFIG_SSDFS_DEBUG */

	*seg_id = U64_MAX;
	*seg_state = SSDFS_SEG_STATE_MAX;

	switch (seg_type) {
	case SSDFS_USER_DATA_SEG_TYPE:
		new_state = SSDFS_SEG_DATA_USING;
		break;

	case SSDFS_LEAF_NODE_SEG_TYPE:
		new_state = SSDFS_SEG_LEAF_NODE_USING;
		break;

	case SSDFS_HYBRID_NODE_SEG_TYPE:
		new_state = SSDFS_SEG_HYBRID_NODE_USING;
		break;

	case SSDFS_INDEX_NODE_SEG_TYPE:
		new_state = SSDFS_SEG_INDEX_NODE_USING;
		break;

	default:
		BUG();
	};

	recommended_start = start_seg;
	recommended_end = end_seg;

	err = ssdfs_segment_detect_search_range(fsi,
						&recommended_start,
						&recommended_end);
	if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find fragment for search: "
			  "start_seg %llu, end_seg %llu\n",
			  recommended_start, recommended_end);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_search;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to define a search range: "
			  "start_search_id %llu, err %d\n",
			  start_search_id, err);
		goto finish_search;
	}

	start_seg = recommended_start;
	end_seg = recommended_end;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("recommended range: "
		  "start_seg %llu, end_seg %llu\n",
		  start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start_seg <= end_seg) {
		/*
		 * Continue logic
		 */
	} else {
		err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find segment in range: "
			  "start_seg %llu, end_seg %llu\n",
			  start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_search;
	}

	res = ssdfs_segbmap_find_and_set(fsi->segbmap,
					 start_seg, end_seg,
					 SSDFS_SEG_CLEAN,
					 SSDFS_SEG_CLEAN_STATE_FLAG,
					 new_state,
					 seg_id, &init_end);
	if (res >= 0) {
		/* Define segment state */
		*seg_state = res;
	} else if (res == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(init_end);
		if (unlikely(err)) {
			SSDFS_ERR("segbmap init failed: "
				  "err %d\n", err);
			goto finish_search;
		}

		res = ssdfs_segbmap_find_and_set(fsi->segbmap,
						 start_seg, end_seg,
						 SSDFS_SEG_CLEAN,
						 SSDFS_SEG_CLEAN_STATE_FLAG,
						 new_state,
						 seg_id, &init_end);
		if (res >= 0) {
			/* Define segment state */
			*seg_state = res;
		} else if (res == -ENODATA) {
			err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find segment in range: "
				  "start_seg %llu, end_seg %llu\n",
				  start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_search;
		} else {
			err = res;
			SSDFS_ERR("fail to find segment in range: "
				  "start_seg %llu, end_seg %llu, err %d\n",
				  start_seg, end_seg, res);
			goto finish_search;
		}
	} else if (res == -ENODATA) {
		err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find segment in range: "
			  "start_seg %llu, end_seg %llu\n",
			  start_seg, end_seg);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_search;
	} else {
		SSDFS_ERR("fail to find segment in range: "
			  "start_seg %llu, end_seg %llu, err %d\n",
			  start_seg, end_seg, res);
		goto finish_search;
	}

finish_search:
	if (err == -ENOENT)
		*seg_id = end_seg;

	return err;
}

/*
 * ssdfs_find_new_segment() - find a new segment
 * @fsi: pointer on shared file system object
 * @state: segment search state [in|out]
 *
 * This method tries to find a new segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - unable to find a new segment.
 */
static
int ssdfs_find_new_segment(struct ssdfs_fs_info *fsi,
			   struct ssdfs_segment_search_state *state)
{
	u64 start_id;
	u64 upper_bound;
	int threshold = SSDFS_MAX_NUMBER_OF_TRIES;
	u64 panic_threshold;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !state);

	SSDFS_DBG("fsi %p, seg_type %#x, "
		  "start_search_id %llu, seg_id %llu, "
		  "number_of_tries %d\n",
		  fsi, state->request.seg_type,
		  state->request.start_search_id,
		  state->result.seg_id,
		  state->result.number_of_tries);
#endif /* CONFIG_SSDFS_DEBUG */

	if (state->result.number_of_tries < 0) {
		SSDFS_DBG("unexpected number_of_tries %d\n",
			  state->result.number_of_tries);
		state->result.number_of_tries = 0;
	}

	panic_threshold = (fsi->nsegs * fsi->pebs_per_seg) * 2;

	if (state->result.number_of_tries >= panic_threshold) {
		SSDFS_WARN("too much number of tries %d\n",
			   state->result.number_of_tries);
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		err = -ENOSPC;
		goto finish_search;
#endif /* CONFIG_SSDFS_DEBUG */
	}

	if (state->result.number_of_tries == 0) {
		start_id = 0;
		upper_bound = state->request.start_search_id;

		err = ssdfs_find_using_segment(fsi, state->request.seg_type,
						start_id, upper_bound,
						&state->result.seg_id,
						&state->result.seg_state);
		if (err == -ENOENT) {
			err = 0;
			/* continue logic */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a new segment: "
				  "start_id %llu, err %d\n",
				  start_id, err);
			goto finish_search;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("found seg_id %llu\n",
				  state->result.seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_search;
		}
	}

	if (state->result.number_of_tries < threshold) {
		start_id = state->request.start_search_id + 1;
		upper_bound = fsi->nsegs;

		err = ssdfs_find_using_segment(fsi, state->request.seg_type,
						start_id, upper_bound,
						&state->result.seg_id,
						&state->result.seg_state);
		if (err == -ENOENT) {
			err = 0;
			/* continue logic */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a new segment: "
				  "start_id %llu, err %d\n",
				  start_id, err);
			goto finish_search;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("found seg_id %llu\n",
				  state->result.seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_search;
		}
	}

	start_id = 0;
	upper_bound = state->request.start_search_id;

	while (start_id < state->request.start_search_id) {
		err = ssdfs_find_clean_segment(fsi, state->request.seg_type,
						start_id, upper_bound,
						&state->result.seg_id,
						&state->result.seg_state);
		if (err == -ENOENT) {
			err = 0;
			start_id = state->result.seg_id;
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a new segment: "
				  "start_id %llu, err %d\n",
				  start_id, err);
			goto finish_search;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("found seg_id %llu\n",
				  state->result.seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_search;
		}
	}

	start_id = state->request.start_search_id + 1;
	upper_bound = fsi->nsegs;

	while (start_id < fsi->nsegs) {
		err = ssdfs_find_clean_segment(fsi, state->request.seg_type,
						start_id, upper_bound,
						&state->result.seg_id,
						&state->result.seg_state);
		if (err == -ENOENT) {
			err = 0;
			start_id = state->result.seg_id;
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a new segment: "
				  "start_id %llu, err %d\n",
				  start_id, err);
			goto finish_search;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("found seg_id %llu\n",
				  state->result.seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_search;
		}
	}

	start_id = state->request.start_search_id + 1;
	upper_bound = fsi->nsegs;

	while (start_id < fsi->nsegs) {
		err = ssdfs_find_using_segment(fsi, state->request.seg_type,
						start_id, upper_bound,
						&state->result.seg_id,
						&state->result.seg_state);
		if (err == -ENOENT) {
			err = 0;
			start_id = state->result.seg_id;
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a new segment: "
				  "start_id %llu, err %d\n",
				  start_id, err);
			goto finish_search;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("found seg_id %llu\n",
				  state->result.seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_search;
		}
	}

	start_id = 0;
	upper_bound = state->request.start_search_id;

	while (start_id < state->request.start_search_id) {
		err = ssdfs_find_using_segment(fsi, state->request.seg_type,
						start_id, upper_bound,
						&state->result.seg_id,
						&state->result.seg_state);
		if (err == -ENOENT) {
			err = 0;
			start_id = state->result.seg_id;
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a new segment: "
				  "start_id %llu, err %d\n",
				  start_id, err);
			goto finish_search;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("found seg_id %llu\n",
				  state->result.seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_search;
		}
	}

	err = -ENOSPC;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("no free space for a new segment: "
		  "seg_type %#x\n",
		  state->request.seg_type);
#endif /* CONFIG_SSDFS_DEBUG */

finish_search:
	state->result.number_of_tries++;
	return err;
}

/*
 * __ssdfs_create_new_segment() - create new segment and add into the tree
 * @fsi: pointer on shared file system object
 * @seg_id: segment number
 * @seg_state: segment state
 * @seg_type: segment type
 * @log_pages: count of pages in log
 * @create_threads: number of flush PEB's threads for new page requests
 *
 * This function tries to create segment object for @seg
 * identification number.
 *
 * RETURN:
 * [success] - pointer on created segment object
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
struct ssdfs_segment_info *
__ssdfs_create_new_segment(struct ssdfs_fs_info *fsi,
			   u64 seg_id, int seg_state,
			   u16 seg_type, u16 log_pages,
			   u8 create_threads)
{
	struct ssdfs_segment_info *si;
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	if (seg_state >= SSDFS_SEG_STATE_MAX) {
		SSDFS_ERR("invalid segment state %#x\n", seg_state);
		return ERR_PTR(-EINVAL);
	}

	if (seg_type > SSDFS_LAST_KNOWN_SEG_TYPE) {
		SSDFS_ERR("invalid segment type %#x\n", seg_type);
		return ERR_PTR(-EINVAL);
	}

	if (create_threads > fsi->pebs_per_seg ||
	    fsi->pebs_per_seg % create_threads) {
		SSDFS_ERR("invalid create threads count %u\n",
			  create_threads);
		return ERR_PTR(-EINVAL);
	}

	SSDFS_DBG("fsi %p, seg %llu, seg_state %#x, log_pages %u, "
		  "create_threads %u\n",
		  fsi, seg_id, seg_state, log_pages, create_threads);
#endif /* CONFIG_SSDFS_DEBUG */

	si = ssdfs_segment_allocate_object(seg_id);
	if (IS_ERR_OR_NULL(si)) {
		SSDFS_ERR("fail to allocate segment: "
			  "seg %llu, err %ld\n",
			  seg_id, PTR_ERR(si));
		return si;
	}

	err = ssdfs_segment_tree_add(fsi, si);
	if (err == -EEXIST) {
		wait_queue_head_t *wq;

		ssdfs_segment_free_object(si);

		si = ssdfs_segment_tree_find(fsi, seg_id);
		if (IS_ERR_OR_NULL(si)) {
			SSDFS_ERR("fail to find segment: "
				  "seg %llu, err %d\n",
				  seg_id, err);
			return ERR_PTR(err);
		}

		ssdfs_segment_get_object(si);
		wq = &si->object_queue;

		res = wait_event_killable_timeout(*wq,
				is_ssdfs_segment_created(si),
				SSDFS_DEFAULT_TIMEOUT);
		if (res < 0) {
			err = res;
			WARN_ON(1);
		} else if (res > 1) {
			/*
			 * Condition changed before timeout
			 */
		} else {
			/* timeout is elapsed */
			err = -ERANGE;
			WARN_ON(1);
		}

		switch (atomic_read(&si->obj_state)) {
		case SSDFS_SEG_OBJECT_CREATED:
		case SSDFS_CURRENT_SEG_OBJECT:
			/* do nothing */
			break;

		default:
			ssdfs_segment_put_object(si);
			SSDFS_ERR("fail to create segment: "
				  "seg %llu\n",
				  seg_id);
			return ERR_PTR(-ERANGE);
		}

		return si;
	} else if (unlikely(err)) {
		ssdfs_segment_free_object(si);
		SSDFS_ERR("fail to add segment into tree: "
			  "seg %llu, err %d\n",
			  seg_id, err);
		return ERR_PTR(err);
	} else {
		err = ssdfs_segment_create_object(fsi,
						  seg_id,
						  seg_state,
						  seg_type,
						  log_pages,
						  create_threads,
						  si);
		if (unlikely(err)) {
			int res;

			res = ssdfs_segment_tree_remove(fsi, si);
			if (unlikely(res)) {
				SSDFS_WARN("fail to remove segment: "
					   "seg %llu, err %d\n",
					   si->seg_id, res);
			}
		}

		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("NO FREE SPACE: "
				  "unable to create segment: "
				  "seg %llu\n",
				  seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return ERR_PTR(err);
		} else if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			return ERR_PTR(err);
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create segment: "
				  "seg %llu, err %d\n",
				  seg_id, err);
			return ERR_PTR(err);
		}
	}

	ssdfs_segment_get_object(si);
	return si;
}

/*
 * ssdfs_create_segment_in_tree() - create segment in the segment tree
 * @fsi: pointer on shared file system object
 * @state: segment search state [in|out]
 *
 * This function tries to create segment object in the segment tree.
 *
 * RETURN:
 * [success] - pointer on created segment object
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ENOSPC     - unable to create segment.
 * %-ERANGE     - internal error.
 */
static
struct ssdfs_segment_info *
ssdfs_create_segment_in_tree(struct ssdfs_fs_info *fsi,
			     struct ssdfs_segment_search_state *state)
{
	struct ssdfs_segment_info *si = NULL;
	struct completion *init_end;
	u16 log_pages;
	u8 create_threads;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !state);
	BUG_ON(state->request.seg_type != SSDFS_LEAF_NODE_SEG_TYPE &&
		state->request.seg_type != SSDFS_HYBRID_NODE_SEG_TYPE &&
		state->request.seg_type != SSDFS_INDEX_NODE_SEG_TYPE &&
		state->request.seg_type != SSDFS_USER_DATA_SEG_TYPE);

	SSDFS_DBG("fsi %p, seg_type %#x, "
		  "seg_id %llu, start_search_id %llu\n",
		  fsi, state->request.seg_type,
		  state->result.seg_id,
		  state->request.start_search_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (state->result.seg_state >= SSDFS_SEG_STATE_MAX) {
		state->result.seg_state =
				ssdfs_segbmap_get_state(fsi->segbmap,
							state->result.seg_id,
							&init_end);
		if (state->result.seg_state == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(init_end);
			if (unlikely(err)) {
				SSDFS_ERR("segbmap init failed: "
					  "err %d\n", err);
				goto unable_create_segment;
			}

			state->result.seg_state =
					ssdfs_segbmap_get_state(fsi->segbmap,
							state->result.seg_id,
							&init_end);
			if (state->result.seg_state < 0)
				goto fail_define_seg_state;
		} else if (state->result.seg_state < 0) {
fail_define_seg_state:
			err = state->result.seg_state;
			SSDFS_ERR("fail to define segment state: "
				  "seg %llu\n",
				  state->result.seg_id);
			goto unable_create_segment;
		}
	}

	switch (state->result.seg_state) {
	case SSDFS_SEG_CLEAN:
	case SSDFS_SEG_DATA_USING:
	case SSDFS_SEG_LEAF_NODE_USING:
	case SSDFS_SEG_HYBRID_NODE_USING:
	case SSDFS_SEG_INDEX_NODE_USING:
	case SSDFS_SEG_USED:
	case SSDFS_SEG_PRE_DIRTY:
		/* expected state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("seg %llu has unexpected state %#x\n",
			  state->result.seg_id,
			  state->result.seg_state);
		goto unable_create_segment;
	};

	switch (state->request.seg_type) {
	case SSDFS_USER_DATA_SEG_TYPE:
		log_pages = fsi->segs_tree->user_data_log_pages;
		break;

	case SSDFS_LEAF_NODE_SEG_TYPE:
		log_pages = fsi->segs_tree->lnodes_seg_log_pages;
		break;

	case SSDFS_HYBRID_NODE_SEG_TYPE:
		log_pages = fsi->segs_tree->hnodes_seg_log_pages;
		break;

	case SSDFS_INDEX_NODE_SEG_TYPE:
		log_pages = fsi->segs_tree->inodes_seg_log_pages;
		break;

	default:
		log_pages = fsi->segs_tree->default_log_pages;
		break;
	};

	create_threads = fsi->create_threads_per_seg;
	si = __ssdfs_create_new_segment(fsi,
					state->result.seg_id,
					state->result.seg_state,
					state->request.seg_type,
					log_pages,
					create_threads);
	if (IS_ERR_OR_NULL(si)) {
		err = (si == NULL ? -ENOMEM : PTR_ERR(si));
		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("NO FREE SPACE: "
				  "unable to create segment: "
				  "seg %llu\n",
				  state->result.seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
			goto unable_create_segment;
		} else if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			goto unable_create_segment;
		} else {
			SSDFS_ERR("fail to add new segment: "
				  "seg %llu, err %d\n",
				  state->result.seg_id, err);
			goto unable_create_segment;
		}
	} else {
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("finished: seg_id %llu\n",
			  state->result.seg_id);
#else
		SSDFS_DBG("finished: seg_id %llu\n",
			  state->result.seg_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
	}

	return si;

unable_create_segment:
	return ERR_PTR(err);
}

/*
 * ssdfs_find_and_create_new_segment() - find and create a new segment
 * @fsi: pointer on shared file system object
 * @state: segment search state [in|out]
 *
 * This function tries to find and create a new segment.
 *
 * RETURN:
 * [success] - pointer on created segment object
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ENOSPC     - no free space for a new segment.
 * %-ERANGE     - internal error.
 */
static
struct ssdfs_segment_info *
ssdfs_find_and_create_new_segment(struct ssdfs_fs_info *fsi,
				  struct ssdfs_segment_search_state *state)
{
	struct ssdfs_segment_info *si = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !state);
	BUG_ON(state->request.seg_type != SSDFS_LEAF_NODE_SEG_TYPE &&
		state->request.seg_type != SSDFS_HYBRID_NODE_SEG_TYPE &&
		state->request.seg_type != SSDFS_INDEX_NODE_SEG_TYPE &&
		state->request.seg_type != SSDFS_USER_DATA_SEG_TYPE);

	SSDFS_DBG("fsi %p, seg_type %#x, "
		  "seg_id %llu, start_search_id %llu\n",
		  fsi, state->request.seg_type,
		  state->result.seg_id,
		  state->request.start_search_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!state->request.need_find_new_segment) {
		err = -EINVAL;
		SSDFS_ERR("unexpected request state\n");
		goto unable_create_new_segment;
	}

	do {
		err = ssdfs_find_new_segment(fsi, state);
		if (err == -ENOSPC) {
			SSDFS_DBG("no free space for a new segment\n");
			goto unable_create_new_segment;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a new segment: "
				  "start_search_id %llu, "
				  "seg_type %#x, err %d\n",
				  state->request.start_search_id,
				  state->request.seg_type, err);
			goto unable_create_new_segment;
		}

		si = ssdfs_create_segment_in_tree(fsi, state);
		if (IS_ERR_OR_NULL(si)) {
			err = (si == NULL ? -ENOMEM : PTR_ERR(si));
			if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("NO FREE SPACE: "
					  "unable to create segment: "
					  "seg %llu\n",
					  state->result.seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

				/* try to find another segment */
				err = -EAGAIN;
			} else if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto unable_create_new_segment;
			} else {
				SSDFS_ERR("fail to add new segment: "
					  "seg %llu, err %d\n",
					  state->result.seg_id, err);
				goto unable_create_new_segment;
			}
		} else {
#ifdef CONFIG_SSDFS_TRACK_API_CALL
			SSDFS_ERR("finished: seg_id %llu\n",
				  state->result.seg_id);
#else
			SSDFS_DBG("finished: seg_id %llu\n",
				  state->result.seg_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
		}
	} while (err == -EAGAIN);

	return si;

unable_create_new_segment:
	return ERR_PTR(err);
}

/*
 * ssdfs_grab_segment() - get or create segment object
 * @fsi: pointer on shared file system object
 * @state: segment search state [in|out]
 *
 * This method tries to get or to create segment object of
 * @state->request.seg_type. If @state->result.seg_id is U64_MAX
 * then it needs to find segment that will be in "clean" or "using" state.
 * The @state->request.start_search_id is defining the range for search.
 * If this value is equal to U64_MAX then it is ignored.
 * The found segment number should be used for segment object
 * creation and adding into the segment tree. Otherwise,
 * if @state->result.seg_id contains valid segment number,
 * the method should try to find segment object in the segments tree.
 * If the segment object is not found then segment state
 * will be detected via segment bitmap, segment object will be created and
 * to be added into the segment tree. Finally, reference counter of segment
 * object will be incremented.
 *
 * RETURN:
 * [success] - pointer on segment object.
 * [failure] - error code:
 *
 * %-ENOSPC     - no free space for a new segment.
 * %-ERANGE     - internal error.
 */
struct ssdfs_segment_info *
ssdfs_grab_segment(struct ssdfs_fs_info *fsi,
		   struct ssdfs_segment_search_state *state)
{
	struct ssdfs_segment_info *si;
	wait_queue_head_t *wq;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !state);
	BUG_ON(state->request.seg_type != SSDFS_LEAF_NODE_SEG_TYPE &&
		state->request.seg_type != SSDFS_HYBRID_NODE_SEG_TYPE &&
		state->request.seg_type != SSDFS_INDEX_NODE_SEG_TYPE &&
		state->request.seg_type != SSDFS_USER_DATA_SEG_TYPE);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p, seg_type %#x, "
		  "seg_id %llu, start_search_id %llu\n",
		  fsi, state->request.seg_type,
		  state->result.seg_id,
		  state->request.start_search_id);
#else
	SSDFS_DBG("fsi %p, seg_type %#x, "
		  "seg_id %llu, start_search_id %llu\n",
		  fsi, state->request.seg_type,
		  state->result.seg_id,
		  state->request.start_search_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (state->request.need_find_new_segment) {
		si = ssdfs_find_and_create_new_segment(fsi, state);
		if (IS_ERR_OR_NULL(si)) {
			err = PTR_ERR(si);

			if (err == -ENOSPC) {
				SSDFS_DBG("no free space for a new segment\n");
				return ERR_PTR(err);
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to find a new segment: "
					  "start_search_id %llu, "
					  "seg_type %#x, err %d\n",
					  state->request.start_search_id,
					  state->request.seg_type, err);
				return ERR_PTR(err);
			}
		}
	} else {
		si = ssdfs_segment_tree_find(fsi, state->result.seg_id);
		if (IS_ERR_OR_NULL(si)) {
			err = PTR_ERR(si);

			if (err == -ENODATA) {
				si = ssdfs_create_segment_in_tree(fsi, state);
				if (IS_ERR_OR_NULL(si)) {
					err = (si == NULL ? -ENOMEM : PTR_ERR(si));
					if (err == -EINTR) {
						/*
						 * Ignore this error.
						 */
						return ERR_PTR(err);
					} else {
						SSDFS_ERR("fail to create segment: "
							  "seg %llu, err %d\n",
							  state->result.seg_id,
							  err);
						return ERR_PTR(err);
					}
				}
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to find segment: "
					  "seg %llu, err %d\n",
					  state->result.seg_id, err);
				return ERR_PTR(err);
			} else {
				SSDFS_ERR("segment tree returns NULL\n");
				return ERR_PTR(-ERANGE);
			}
		} else {
			wq = &si->object_queue;
			ssdfs_segment_get_object(si);

			switch (atomic_read(&si->obj_state)) {
			case SSDFS_SEG_OBJECT_CREATED:
			case SSDFS_CURRENT_SEG_OBJECT:
				/* do nothing */
				break;

			default:
				err = wait_event_killable_timeout(*wq,
						is_ssdfs_segment_created(si),
						SSDFS_DEFAULT_TIMEOUT);
				if (err < 0) {
					ssdfs_segment_put_object(si);
					SSDFS_WARN("fail to grab segment: "
						   "seg %llu\n",
						   state->result.seg_id);
					return ERR_PTR(-ERANGE);
				}
			}
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: seg_id %llu\n", state->result.seg_id);
#else
	SSDFS_DBG("finished: seg_id %llu\n", state->result.seg_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return si;
}

/*
 * is_ssdfs_segment_ready_for_requests() - is segment ready for requests
 * @si: segment info
 *
 * This method checks that segment is completely initialized and
 * it is ready for requests.
 */
bool is_ssdfs_segment_ready_for_requests(struct ssdfs_segment_info *si)
{
	struct ssdfs_blk2off_table *table;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("seg %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	table = si->blk2off_table;

	switch (atomic_read(&table->state)) {
	case SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT:
		return true;

	default:
		/* do nothing */
		break;
	}

	return false;
}

/*
 * ssdfs_wait_segment_init_end() - wait segment readiness
 * @si: segment info
 *
 * This method waits segment readiness for requests.
 */
int ssdfs_wait_segment_init_end(struct ssdfs_segment_info *si)
{
	struct ssdfs_blk2off_table *table;
	struct completion *end;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("seg_id %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	table = si->blk2off_table;
	end = &table->full_init_end;

	err = SSDFS_WAIT_COMPLETION(end);
	if (unlikely(err)) {
		SSDFS_ERR("blk2off init failed: "
			  "seg_id %llu, err %d\n",
			  si->seg_id, err);
		return err;
	}

	return 0;
}

/*
 * __ssdfs_segment_read_block() - read segment's block
 * @si: segment info
 * @req: segment request [in|out]
 */
static
int __ssdfs_segment_read_block(struct ssdfs_segment_info *si,
			       struct ssdfs_segment_request *req)
{
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *po_desc;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_requests_queue *rq;
	wait_queue_head_t *wait;
	u16 peb_index = U16_MAX;
	u16 logical_blk;
	struct ssdfs_offset_position pos = {0};
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	table = si->blk2off_table;
	logical_blk = req->place.start.blk_index;

	po_desc = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index, NULL, &pos);
	if (IS_ERR_OR_NULL(po_desc)) {
		err = (po_desc == NULL ? -ERANGE : PTR_ERR(po_desc));
		SSDFS_ERR("fail to convert: "
			  "seg %llu, ino %llu, logical_offset %llu, "
			  "logical_blk %u, err %d\n",
			  si->seg_id, req->extent.ino,
			  req->extent.logical_offset,
			  logical_blk, err);
		return err;
	}

	if (peb_index >= si->pebs_count) {
		SSDFS_ERR("peb_index %u >= si->pebs_count %u\n",
			  peb_index, si->pebs_count);
		return -ERANGE;
	}

	pebc = &si->peb_array[peb_index];

	ssdfs_peb_read_request_cno(pebc);

	rq = &pebc->read_rq;
	ssdfs_requests_queue_add_tail(rq, req);

	wait = &si->wait_queue[SSDFS_PEB_READ_THREAD];
	wake_up_all(wait);

	return 0;
}

/*
 * ssdfs_segment_read_block_sync() - read segment's block synchronously
 * @si: segment info
 * @req: segment request [in|out]
 */
int ssdfs_segment_read_block_sync(struct ssdfs_segment_info *si,
				  struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    SSDFS_READ_PAGE,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_read_block(si, req);
}

/*
 * ssdfs_segment_read_block_async() - read segment's block asynchronously
 * @req_type: request type
 * @si: segment info
 * @req: segment request [in|out]
 */
int ssdfs_segment_read_block_async(struct ssdfs_segment_info *si,
				  int req_type,
				  struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    SSDFS_READ_PAGE,
					    req_type, req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_read_block(si, req);
}

/*
 * ssdfs_segment_get_used_data_pages() - get segment's used data pages count
 * @si: segment object
 *
 * This function tries to get segment's used data pages count.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 */
int ssdfs_segment_get_used_data_pages(struct ssdfs_segment_info *si)
{
	int used_pages = 0;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("seg %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < si->pebs_count; i++) {
		struct ssdfs_peb_container *pebc = &si->peb_array[i];

		err = ssdfs_peb_get_used_data_pages(pebc);
		if (err < 0) {
			SSDFS_ERR("fail to get used data pages count: "
				  "seg %llu, peb index %d, err %d\n",
				  si->seg_id, i, err);
			return err;
		} else
			used_pages += err;
	}

	return used_pages;
}

/*
 * should_segment_being_in_using_state() - should segment being in using state?
 * @si: pointer on segment object
 */
static inline
bool should_segment_being_in_using_state(struct ssdfs_segment_info *si)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < si->pebs_count; i++) {
		struct ssdfs_peb_container *pebc = &si->peb_array[i];

		switch (atomic_read(&pebc->peb_state)) {
		case SSDFS_MAPTBL_USING_PEB_STATE:
		case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			return true;

		default:
			/* continue */
			break;
		}
	}

	return false;
}

/*
 * should_segment_be_dirty() - checking and return new segment state
 * @si: pointer on segment object
 */
static inline
int should_segment_be_dirty(struct ssdfs_segment_info *si)
{
	int seg_type;
	int new_seg_state = SSDFS_SEG_STATE_MAX;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_type = si->seg_type;

	if (should_segment_being_in_using_state(si)) {
		new_seg_state = SEG_TYPE_TO_USING_STATE(seg_type);
		if (new_seg_state < 0 || new_seg_state == SSDFS_SEG_STATE_MAX) {
			SSDFS_ERR("invalid seg_type %#x\n",
				  seg_type);
			return SSDFS_SEG_STATE_MAX;
		}
	} else {
		new_seg_state = SSDFS_SEG_DIRTY;
	}

	return new_seg_state;
}

/*
 * should_segment_be_pre_dirty() - checking and return new segment state
 * @si: pointer on segment object
 */
static inline
int should_segment_be_pre_dirty(struct ssdfs_segment_info *si)
{
	int seg_type;
	int new_seg_state = SSDFS_SEG_STATE_MAX;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_type = si->seg_type;

	if (should_segment_being_in_using_state(si)) {
		new_seg_state = SEG_TYPE_TO_USING_STATE(seg_type);
		if (new_seg_state < 0 || new_seg_state == SSDFS_SEG_STATE_MAX) {
			SSDFS_ERR("invalid seg_type %#x\n",
				  seg_type);
			return SSDFS_SEG_STATE_MAX;
		}
	} else {
		new_seg_state = SSDFS_SEG_PRE_DIRTY;
	}

	return new_seg_state;
}

/*
 * ssdfs_segment_change_state() - change segment state
 * @si: pointer on segment object
 */
int ssdfs_segment_change_state(struct ssdfs_segment_info *si)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_bmap *segbmap;
	struct ssdfs_blk2off_table *blk2off_tbl;
	u16 used_logical_blks;
	int free_pages, invalid_pages;
	int pages_capacity;
	int physical_capacity;
	bool is_inflated = false;
	bool need_change_state = false;
	int seg_state, old_seg_state;
	int new_seg_state = SSDFS_SEG_STATE_MAX;
	u64 seg_id;
	struct completion *init_end;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = si->fsi;
	seg_id = si->seg_id;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("si %p, seg_id %llu\n",
		  si, seg_id);
#else
	SSDFS_DBG("si %p, seg_id %llu\n",
		  si, seg_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	blk2off_tbl = si->blk2off_table;
	segbmap = si->fsi->segbmap;

	down_write(&si->modification_lock);

	err = ssdfs_blk2off_table_get_used_logical_blks(blk2off_tbl,
							&used_logical_blks);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get used logical blocks count: "
			  "err %d\n",
			  err);
		goto finish_segment_state_change;
	} else if (used_logical_blks == U16_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid used logical blocks count\n");
		goto finish_segment_state_change;
	}

	seg_state = atomic_read(&si->seg_state);
	free_pages = ssdfs_segment_blk_bmap_get_free_pages(&si->blk_bmap);
	invalid_pages = ssdfs_segment_blk_bmap_get_invalid_pages(&si->blk_bmap);
	pages_capacity = ssdfs_segment_blk_bmap_get_capacity(&si->blk_bmap);
	physical_capacity = fsi->pages_per_seg;
	is_inflated = physical_capacity < pages_capacity;

	if (pages_capacity < physical_capacity) {
		SSDFS_ERR("pages_capacity %d > physical_capacity %d\n",
			  pages_capacity, physical_capacity);
		return -ERANGE;
	}

	if (is_inflated) {
		struct ssdfs_segment_blk_bmap *seg_blkbmap;
		struct ssdfs_peb_blk_bmap *peb_blkbmap;
		int corrected_free_pages = 0;

		seg_blkbmap = &si->blk_bmap;

		for (i = 0; i < si->pebs_count; i++) {
			struct ssdfs_peb_container *pebc;
			int calculated;

			pebc = &si->peb_array[i];
			peb_blkbmap = &seg_blkbmap->peb[i];

			if (!can_peb_process_create_requests(pebc)) {
				/* don't account free blocks */
				continue;
			}

			calculated =
				ssdfs_peb_blk_bmap_get_free_pages(peb_blkbmap);
			if (calculated < 0) {
				/* ignore error */
				SSDFS_ERR("fail to get peb[%d] free pages: "
					  "seg_id %llu, err %d\n",
					  i, seg_id, calculated);
				continue;
			}

			corrected_free_pages += calculated;
		}

		if (corrected_free_pages < free_pages) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("correct free pages: "
				  "seg_id %llu, corrected_free_pages %d, "
				  "free_pages %d\n",
				  seg_id, corrected_free_pages, free_pages);
#endif /* CONFIG_SSDFS_DEBUG */
			free_pages = corrected_free_pages;
		}
	}

	if (free_pages > pages_capacity) {
		SSDFS_ERR("free_pages %d > pages_capacity %u\n",
			  free_pages, pages_capacity);
		return -ERANGE;
	}

	switch (seg_state) {
	case SSDFS_SEG_CLEAN:
		if (free_pages == pages_capacity) {
			/*
			 * Do nothing.
			 */
		} else if (free_pages > 0) {
			need_change_state = true;

			if (invalid_pages > 0) {
				new_seg_state = should_segment_be_pre_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			} else {
				new_seg_state =
					SEG_TYPE_TO_USING_STATE(si->seg_type);
				if (new_seg_state < 0 ||
				    new_seg_state == SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid seg_type %#x\n",
						  si->seg_type);
					goto finish_segment_state_change;
				}
			}
		} else {
			need_change_state = true;

			if (invalid_pages == 0)
				new_seg_state = SSDFS_SEG_USED;
			else if (used_logical_blks == 0) {
				new_seg_state = should_segment_be_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			} else {
				new_seg_state = should_segment_be_pre_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			}
		}
		break;

	case SSDFS_SEG_DATA_USING:
	case SSDFS_SEG_LEAF_NODE_USING:
	case SSDFS_SEG_HYBRID_NODE_USING:
	case SSDFS_SEG_INDEX_NODE_USING:
		if (free_pages == pages_capacity) {
			if (invalid_pages == 0 && used_logical_blks == 0) {
				need_change_state = true;
				new_seg_state = SSDFS_SEG_CLEAN;
			} else {
				err = -ERANGE;
				SSDFS_ERR("free_pages %d == pages_capacity %u\n",
					  free_pages, pages_capacity);
				goto finish_segment_state_change;
			}
		} else if (free_pages > 0) {
			if (invalid_pages > 0) {
				need_change_state = true;

				new_seg_state = should_segment_be_pre_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			}
		} else {
			need_change_state = true;

			if (invalid_pages == 0)
				new_seg_state = SSDFS_SEG_USED;
			else if (used_logical_blks == 0) {
				new_seg_state = should_segment_be_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			} else {
				new_seg_state = should_segment_be_pre_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			}
		}
		break;

	case SSDFS_SEG_USED:
		if (free_pages == pages_capacity) {
			if (invalid_pages == 0 && used_logical_blks == 0) {
				need_change_state = true;
				new_seg_state = SSDFS_SEG_CLEAN;
			} else {
				err = -ERANGE;
				SSDFS_ERR("free_pages %d == pages_capacity %u\n",
					  free_pages, pages_capacity);
				goto finish_segment_state_change;
			}
		} else if (invalid_pages > 0) {
			need_change_state = true;

			if (used_logical_blks > 0) {
				new_seg_state = should_segment_be_pre_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			} else if (free_pages > 0) {
				new_seg_state = should_segment_be_pre_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			} else {
				new_seg_state = should_segment_be_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			}
		} else if (free_pages > 0) {
			need_change_state = true;
			new_seg_state = SEG_TYPE_TO_USING_STATE(si->seg_type);
			if (new_seg_state < 0 ||
			    new_seg_state == SSDFS_SEG_STATE_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid seg_type %#x\n",
					  si->seg_type);
				goto finish_segment_state_change;
			}
		}
		break;

	case SSDFS_SEG_PRE_DIRTY:
		if (free_pages == pages_capacity) {
			if (invalid_pages == 0 && used_logical_blks == 0) {
				need_change_state = true;
				new_seg_state = SSDFS_SEG_CLEAN;
			} else {
				err = -ERANGE;
				SSDFS_ERR("free_pages %d == pages_capacity %u\n",
					  free_pages, pages_capacity);
				goto finish_segment_state_change;
			}
		} else if (invalid_pages > 0) {
			if (used_logical_blks == 0) {
				need_change_state = true;
				new_seg_state = should_segment_be_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			}
		} else if (free_pages > 0) {
			need_change_state = true;
			new_seg_state = SEG_TYPE_TO_USING_STATE(si->seg_type);
			if (new_seg_state < 0 ||
			    new_seg_state == SSDFS_SEG_STATE_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid seg_type %#x\n",
					  si->seg_type);
				goto finish_segment_state_change;
			}
		} else if (free_pages == 0 && invalid_pages == 0) {
			if (used_logical_blks == 0) {
				need_change_state = true;
				new_seg_state = SSDFS_SEG_CLEAN;
			} else {
				need_change_state = true;
				new_seg_state = SSDFS_SEG_USED;
			}
		}
		break;

	case SSDFS_SEG_DIRTY:
		if (free_pages == pages_capacity) {
			if (invalid_pages == 0 && used_logical_blks == 0) {
				need_change_state = true;
				new_seg_state = SSDFS_SEG_CLEAN;
			} else {
				err = -ERANGE;
				SSDFS_ERR("free_pages %d == pages_capacity %u\n",
					  free_pages, pages_capacity);
				goto finish_segment_state_change;
			}
		} else if (invalid_pages > 0) {
			if (used_logical_blks > 0 || free_pages > 0) {
				need_change_state = true;
				new_seg_state = should_segment_be_pre_dirty(si);
				if (new_seg_state >= SSDFS_SEG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_ERR("invalid new_seg_state %#x\n",
						  new_seg_state);
					goto finish_segment_state_change;
				}
			}
		} else if (free_pages > 0) {
			need_change_state = true;
			new_seg_state = SEG_TYPE_TO_USING_STATE(si->seg_type);
			if (new_seg_state < 0 ||
			    new_seg_state == SSDFS_SEG_STATE_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid seg_type %#x\n",
					  si->seg_type);
				goto finish_segment_state_change;
			}
		} else if (free_pages == 0 && invalid_pages == 0) {
			if (used_logical_blks == 0) {
				need_change_state = true;
				new_seg_state = SSDFS_SEG_CLEAN;
			} else {
				need_change_state = true;
				new_seg_state = SSDFS_SEG_USED;
			}
		}
		break;

	case SSDFS_SEG_BAD:
	case SSDFS_SEG_RESERVED:
		/* do nothing */
		break;

	default:
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("old_state %#x, new_state %#x, "
		  "need_change_state %#x, free_pages %d, "
		  "invalid_pages %d, used_logical_blks %u\n",
		  seg_state, new_seg_state,
		  need_change_state, free_pages,
		  invalid_pages, used_logical_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!need_change_state) {
		err = 0;
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("no need to change state: "
			  "old_state %#x, new_state %#x, "
			  "free_pages %d, invalid_pages %d, "
			  "used_logical_blks %u\n",
			  seg_state, new_seg_state,
			  free_pages,
			  invalid_pages,
			  used_logical_blks);
#else
		SSDFS_DBG("no need to change state: "
			  "old_state %#x, new_state %#x, "
			  "free_pages %d, invalid_pages %d, "
			  "used_logical_blks %u\n",
			  seg_state, new_seg_state,
			  free_pages,
			  invalid_pages,
			  used_logical_blks);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
		goto finish_segment_state_change;
	}

	err = ssdfs_segbmap_change_state(segbmap, seg_id,
					 new_seg_state, &init_end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(init_end);
		if (unlikely(err)) {
			SSDFS_ERR("segbmap init failed: "
				  "err %d\n", err);
			goto finish_segment_state_change;
		}

		err = ssdfs_segbmap_change_state(segbmap, seg_id,
						 new_seg_state,
						 &init_end);
		if (unlikely(err))
			goto fail_change_state;
	} else if (unlikely(err)) {
fail_change_state:
		SSDFS_ERR("fail to change segment state: "
			  "seg %llu, state %#x, err %d\n",
			  seg_id, new_seg_state, err);
		goto finish_segment_state_change;
	}

	old_seg_state = atomic_cmpxchg(&si->seg_state,
					seg_state, new_seg_state);
	if (old_seg_state != seg_state) {
		if (old_seg_state == new_seg_state) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("old_seg_state %#x == new_seg_state %#x\n",
				  old_seg_state, new_seg_state);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			SSDFS_WARN("old_seg_state %#x != seg_state %#x\n",
				   old_seg_state, seg_state);
		}
	}

finish_segment_state_change:
	up_write(&si->modification_lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_current_segment_change_state() - change current segment state
 * @cur_seg: pointer on current segment
 */
static
int ssdfs_current_segment_change_state(struct ssdfs_current_segment *cur_seg)
{
	struct ssdfs_segment_info *si;
	u64 seg_id;
	int seg_state;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg);
	BUG_ON(!mutex_is_locked(&cur_seg->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	si = cur_seg->real_seg;

	if (!si) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("current segment is empty\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	seg_id = si->seg_id;

	down_read(&cur_seg->real_seg->modification_lock);
	seg_state = atomic_read(&cur_seg->real_seg->seg_state);
	up_read(&cur_seg->real_seg->modification_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_seg %p, si %p, seg_id %llu, seg_state %#x\n",
		  cur_seg, si, seg_id, seg_state);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (seg_state) {
	case SSDFS_SEG_CLEAN:
	case SSDFS_SEG_DATA_USING:
	case SSDFS_SEG_LEAF_NODE_USING:
	case SSDFS_SEG_HYBRID_NODE_USING:
	case SSDFS_SEG_INDEX_NODE_USING:
	case SSDFS_SEG_USED:
	case SSDFS_SEG_PRE_DIRTY:
	case SSDFS_SEG_DIRTY:
		if (!is_ssdfs_segment_ready_for_requests(si)) {
			err = ssdfs_wait_segment_init_end(si);
			if (unlikely(err)) {
				SSDFS_ERR("segment initialization failed: "
					  "seg %llu, err %d\n",
					  si->seg_id, err);
				return err;
			}
		}

		err = ssdfs_segment_change_state(si);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change segment's state: "
				  "seg_id %llu, err %d\n",
				  seg_id, err);
			return err;
		}
		break;

	case SSDFS_SEG_BAD:
	case SSDFS_SEG_RESERVED:
		SSDFS_ERR("invalid segment state: %#x\n",
			  seg_state);
		return -ERANGE;

	default:
		BUG();
	}

	return 0;
}

/*
 * ssdfs_calculate_zns_reservation_threshold() - reservation threshold
 */
static inline
u32 ssdfs_calculate_zns_reservation_threshold(void)
{
	u32 threshold;

	threshold = SSDFS_CUR_SEGS_COUNT * 2;
	threshold += SSDFS_SB_CHAIN_MAX * SSDFS_SB_SEG_COPY_MAX;
	threshold += SSDFS_SEGBMAP_SEGS * SSDFS_SEGBMAP_SEG_COPY_MAX;
	threshold += SSDFS_MAPTBL_RESERVED_EXTENTS * SSDFS_MAPTBL_SEG_COPY_MAX;

	return threshold;
}

/*
 * CHECKED_SEG_TYPE() - correct segment type
 * @fsi: pointer on shared file system object
 * @cur_seg_type: checking segment type
 */
static inline
int CHECKED_SEG_TYPE(struct ssdfs_fs_info *fsi, int cur_seg_type)
{
	u32 threshold = ssdfs_calculate_zns_reservation_threshold();

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!fsi->is_zns_device)
		return cur_seg_type;

	if (threshold < (fsi->max_open_zones / 2))
		return cur_seg_type;

	switch (cur_seg_type) {
	case SSDFS_CUR_LNODE_SEG:
	case SSDFS_CUR_HNODE_SEG:
	case SSDFS_CUR_IDXNODE_SEG:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment type %#x is corrected to %#x\n",
			  cur_seg_type, SSDFS_CUR_LNODE_SEG);
#endif /* CONFIG_SSDFS_DEBUG */
		return SSDFS_CUR_LNODE_SEG;

	default:
		/* do nothing */
		break;
	}

	return cur_seg_type;
}

/*
 * can_current_segment_be_added() - check that current segment can be added
 * @si: pointer on segment object
 */
static inline
bool can_current_segment_be_added(struct ssdfs_segment_info *si)
{
	struct ssdfs_fs_info *fsi;
	u32 threshold = ssdfs_calculate_zns_reservation_threshold();
	int open_zones;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = si->fsi;

	if (!fsi->is_zns_device)
		return true;

	switch (si->seg_type) {
	case SSDFS_LEAF_NODE_SEG_TYPE:
	case SSDFS_HYBRID_NODE_SEG_TYPE:
	case SSDFS_INDEX_NODE_SEG_TYPE:
		open_zones = atomic_read(&fsi->open_zones);

		if (threshold < ((fsi->max_open_zones - open_zones) / 2))
			return true;
		else
			return false;

	case SSDFS_USER_DATA_SEG_TYPE:
		return true;

	default:
		/* do nothing */
		break;
	}

	SSDFS_WARN("unexpected segment type %#x\n",
		   si->seg_type);

	return false;
}

/*
 * ssdfs_remove_current_segment() - remove current segment
 */
static inline
int ssdfs_remove_current_segment(struct ssdfs_current_segment *cur_seg)
{
	struct ssdfs_segment_info *si;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!cur_seg->real_seg)
		return 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu\n",
		  cur_seg->real_seg->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	si = cur_seg->real_seg;

	err = ssdfs_current_segment_change_state(cur_seg);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change segment state: "
			  "seg %llu, err %d\n",
			  si->seg_id, err);
		return err;
	}

	if (can_current_segment_be_added(si)) {
		ssdfs_current_segment_remove(cur_seg);
		return 0;
	}

	return -ENOSPC;
}

/*
 * ssdfs_add_request_into_create_queue() - add request into create queue
 * @cur_seg: current segment container
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add segment request into create queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - request pool is full.
 * %-ENODATA    - all pages have been processed.
 * %-EAGAIN     - not all memory pages have been processed.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_add_request_into_create_queue(struct ssdfs_current_segment *cur_seg,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_requests_queue *create_rq;
	struct ssdfs_segment_request *req;
	struct ssdfs_content_block *block;
	struct inode *inode;
	struct folio *folio;
	struct ssdfs_inode_info *ii;
	struct ssdfs_extents_btree_info *etree;
	u32 not_proccessed;
	u32 data_bytes;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !pool || !batch);
	BUG_ON(pool->req_class <= SSDFS_PEB_READ_REQ ||
		pool->req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = cur_seg->fsi;
	si = cur_seg->real_seg;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("seg_id %llu, req_class %d, req_type %d\n",
		  si->seg_id, pool->req_class, pool->req_type);

	if (pool->count > SSDFS_SEG_REQ_PTR_NUMBER_MAX) {
		SSDFS_ERR("request pool is corrupted: "
			  "count %u\n", pool->count);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (pool->count >= SSDFS_SEG_REQ_PTR_NUMBER_MAX) {
		SSDFS_DBG("request pool is full: "
			  "count %u\n", pool->count);
		return -ENOSPC;
	}

	if (batch->processed_blks >= batch->content.count) {
		SSDFS_ERR("all blocks have been processed: "
			  "dirty_blocks %u, processed_blks %u\n",
			  batch->content.count,
			  batch->processed_blks);
		return -ENODATA;
	}

	not_proccessed = batch->content.count - batch->processed_blks;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(batch->allocated_extent.start_lblk >= U16_MAX);
	BUG_ON(batch->allocated_extent.len == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	if (batch->allocated_extent.len > not_proccessed) {
		SSDFS_ERR("allocated_extent.len %u > not_proccessed %u\n",
			  batch->allocated_extent.len, not_proccessed);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("batch_size %u, batch->processed_blks %u, "
		  "not_proccessed %u, batch->allocated_extent.len %u\n",
		  batch->content.count,
		  batch->processed_blks,
		  not_proccessed,
		  batch->allocated_extent.len);
#endif /* CONFIG_SSDFS_DEBUG */

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req, fsi->pagesize);
	ssdfs_get_request(req);

	ssdfs_request_prepare_internal_data(pool->req_class,
					    pool->req_command,
					    pool->req_type,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	switch (si->seg_type) {
	case SSDFS_USER_DATA_SEG_TYPE:
		req->private.flags |= SSDFS_REQ_DONT_FREE_FOLIOS;
		break;

	default:
		/* do nothing */
		break;
	}

	data_bytes = (u32)batch->allocated_extent.len * fsi->pagesize;
	data_bytes = min_t(u32, data_bytes, batch->requested_extent.data_bytes);

	ssdfs_request_prepare_logical_extent(batch->requested_extent.ino,
					batch->requested_extent.logical_offset,
					data_bytes,
					batch->requested_extent.cno,
					batch->requested_extent.parent_snapshot,
					req);

	ssdfs_request_define_volume_extent(batch->allocated_extent.start_lblk,
					   batch->allocated_extent.len,
					   req);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON((batch->processed_blks +
			batch->allocated_extent.len) >
					batch->content.count);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < batch->allocated_extent.len; i++) {
		u32 blk_index = batch->processed_blks + i;

		block = &batch->content.blocks[blk_index];

		for (j = 0; j < folio_batch_count(&block->batch); j++) {
			err = ssdfs_request_add_folio(block->batch.folios[j],
						      i, req);
			if (err) {
				SSDFS_ERR("fail to add folio into request: "
					  "ino %llu, folio_index %d, err %d\n",
					  batch->requested_extent.ino, j, err);
				goto fail_add_request_into_create_queue;
			}

			WARN_ON(!folio_test_writeback(block->batch.folios[j]));
			ssdfs_request_writeback_folios_inc(req);
		}
	}

	err = ssdfs_current_segment_change_state(cur_seg);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change segment state: "
			  "seg %llu, err %d\n",
			  cur_seg->real_seg->seg_id, err);
		goto fail_add_request_into_create_queue;
	}

	block = &batch->content.blocks[batch->processed_blks];
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(folio_batch_count(&block->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */
	folio = block->batch.folios[0];
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */
	inode = folio->mapping->host;

	err = ssdfs_extents_tree_add_extent(inode, req);
	if (err) {
		SSDFS_ERR("fail to add extent: "
			  "ino %llu, folio_index %llu, "
			  "err %d\n",
			  batch->requested_extent.ino,
			  (u64)folio_index(folio), err);
		goto fail_add_request_into_create_queue;
	}

	inode_add_bytes(inode, data_bytes);

	ii = SSDFS_I(inode);
	etree = SSDFS_EXTREE(ii);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!etree);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&etree->lock);
	err = ssdfs_extents_tree_add_updated_seg_id(etree, si->seg_id);
	up_write(&etree->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to add updated segment in queue: "
			  "seg_id %llu, err %d\n",
			  si->seg_id, err);
		goto fail_add_request_into_create_queue;
	}

	batch->processed_blks += batch->allocated_extent.len;

	if (batch->requested_extent.data_bytes > data_bytes) {
		batch->requested_extent.logical_offset += data_bytes;
		batch->requested_extent.data_bytes -= data_bytes;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("PROCESSED: data_bytes %u, "
			  "NEW STATE: logical_offset %llu, data_bytes %u\n",
			  data_bytes,
			  batch->requested_extent.logical_offset,
			  batch->requested_extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		err = -EAGAIN;
	}

	ssdfs_account_user_data_flush_request(si, req);
	ssdfs_segment_create_request_cno(si);

	pool->pointers[pool->count] = req;
	pool->count++;

	create_rq = &si->create_rq;
	ssdfs_requests_queue_add_tail_inc(fsi, create_rq, req);
	wake_up_all(&si->wait_queue[SSDFS_PEB_FLUSH_THREAD]);
	wake_up_all(&fsi->pending_wq);

	return err;

fail_add_request_into_create_queue:
	ssdfs_put_request(req);
	ssdfs_request_free(req, si);
	return err;
}

/*
 * __ssdfs_blk2off_table_allocate_extent() - allocate data extent
 * @cur_seg: current segment container
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 * @reserved_blks: number of reserved blocks
 * @allocated_blks: pointer on real number of allocated blocks [out]
 *
 * This function tries to allocate data extent in current segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - extent allocated partially.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_blk2off_table_allocate_extent(struct ssdfs_current_segment *cur_seg,
					  struct ssdfs_segment_request_pool *pool,
					  struct ssdfs_dirty_folios_batch *batch,
					  u32 reserved_blks,
					  u32 *allocated_blks)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *blk_bmap;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_blk2off_range *extent;
	int capacity;
	int free_blks;
	int used_blks;
	int invalid_blks;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !pool || !batch || !allocated_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = cur_seg->fsi;
	si = cur_seg->real_seg;
	table = si->blk2off_table;
	*allocated_blks = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("seg_id %llu, req_class %d, "
		  "req_type %d, data_bytes %u, "
		  "reserved_blks %u\n",
		  si->seg_id, pool->req_class, pool->req_type,
		  batch->requested_extent.data_bytes,
		  reserved_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	blk_bmap = &si->blk_bmap;
	capacity = ssdfs_segment_blk_bmap_get_capacity(blk_bmap);

#ifdef CONFIG_SSDFS_DEBUG
	free_blks = ssdfs_segment_blk_bmap_get_free_pages(blk_bmap);
	used_blks = ssdfs_segment_blk_bmap_get_used_pages(blk_bmap);
	invalid_blks = ssdfs_segment_blk_bmap_get_invalid_pages(blk_bmap);

	SSDFS_DBG("seg_id %llu, req_class %d, "
		  "req_type %d, data_bytes %u, "
		  "reserved_blks %u, capacity %d, "
		  "free_blks %d, used_blks %d, "
		  "invalid_blks %d\n",
		  si->seg_id, pool->req_class, pool->req_type,
		  batch->requested_extent.data_bytes,
		  reserved_blks, capacity, free_blks,
		  used_blks, invalid_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	extent = &batch->allocated_extent;
	err = ssdfs_blk2off_table_allocate_extent(table, reserved_blks,
						  capacity, extent);
	if (err == -EAGAIN) {
		struct completion *end = &table->full_init_end;

		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_blk2off_table_allocate_extent(table,
							  reserved_blks,
							  capacity,
							  extent);
	}

	if (err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("extent allocated partially: "
			  "logical_offset %llu, data_bytes %u\n",
			  batch->requested_extent.logical_offset,
			  batch->requested_extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */
		err = -EAGAIN;
	} else if (unlikely(err)) {
		free_blks = ssdfs_segment_blk_bmap_get_free_pages(blk_bmap);
		used_blks = ssdfs_segment_blk_bmap_get_used_pages(blk_bmap);
		invalid_blks =
			ssdfs_segment_blk_bmap_get_invalid_pages(blk_bmap);
		SSDFS_ERR("fail to allocate logical extent: "
			  "seg_id %llu, req_class %d, "
			  "req_type %d, data_bytes %u, "
			  "reserved_blks %u, capacity %d, "
			  "free_blks %d, used_blks %d, "
			  "invalid_blks %d, err %d\n",
			  si->seg_id, pool->req_class, pool->req_type,
			  batch->requested_extent.data_bytes,
			  reserved_blks, capacity, free_blks,
			  used_blks, invalid_blks, err);
		return err;
	} else if (extent->len != reserved_blks) {
		err = -ERANGE;
		SSDFS_ERR("fail to allocate logical extent: "
			  "extent->len %u != reserved_blks %u\n",
			  extent->len, reserved_blks);
		return err;
	}

	*allocated_blks = extent->len;

	err = ssdfs_add_request_into_create_queue(cur_seg, pool, batch);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("NEW STATE: logical_offset %llu, data_bytes %u\n",
			  batch->requested_extent.logical_offset,
			  batch->requested_extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to process extent: "
			  "seg %llu, err %d\n",
			  cur_seg->real_seg->seg_id, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_segment_allocate_data_extent() - allocate data extent
 * @cur_seg: current segment container
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to allocate data extent in current segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - request pool is full.
 * %-EAGAIN     - not all memory pages have been processed.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_segment_allocate_data_extent(struct ssdfs_current_segment *cur_seg,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *blk_bmap;
	u32 extent_bytes;
	u32 blks_count;
	u32 reserved_blks = 0;
	u32 allocated_blks;
	int err = 0;
	int err2;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !pool || !batch);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = cur_seg->fsi;
	si = cur_seg->real_seg;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("seg_id %llu, req_class %d, "
		  "req_type %d, data_bytes %u\n",
		  si->seg_id, pool->req_class, pool->req_type,
		  batch->requested_extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pool->count >= SSDFS_SEG_REQ_PTR_NUMBER_MAX) {
		SSDFS_DBG("request pool is full: "
			  "count %u\n", pool->count);
		return -ENOSPC;
	}

	extent_bytes = batch->requested_extent.data_bytes;
	extent_bytes += fsi->pagesize - 1;
	blks_count = extent_bytes >> fsi->log_pagesize;

	blk_bmap = &si->blk_bmap;

	err = ssdfs_segment_blk_bmap_reserve_extent(blk_bmap, blks_count,
						    &reserved_blks);
	if (err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu hasn't enough free pages\n",
			  cur_seg->real_seg->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_allocate_extent;
	} else if (err == -EAGAIN) {
		while (reserved_blks > 0) {
			err2 = __ssdfs_blk2off_table_allocate_extent(cur_seg,
							    pool,
							    batch,
							    reserved_blks,
							    &allocated_blks);
			if (err2 == -EAGAIN) {
				if (allocated_blks > reserved_blks ||
				    allocated_blks == 0) {
					err = -ERANGE;
					SSDFS_ERR("invalid state: "
						  "allocated_blks %u, "
						  "reserved_blks %u\n",
						  allocated_blks,
						  reserved_blks);
					goto finish_allocate_extent;
				}

				reserved_blks -= allocated_blks;
			} else if (unlikely(err2)) {
				err = err2;
				SSDFS_ERR("fail to allocate logical extent: "
					  "err %d\n", err);
				goto finish_allocate_extent;
			} else {
				if (allocated_blks != reserved_blks) {
					err = -ERANGE;
					SSDFS_ERR("invalid state: "
						  "allocated_blks %u, "
						  "reserved_blks %u\n",
						  allocated_blks,
						  reserved_blks);
					goto finish_allocate_extent;
				}

				reserved_blks -= allocated_blks;
			}
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to reserve logical extent: "
			  "seg %llu, err %d\n",
			  cur_seg->real_seg->seg_id, err);
		goto finish_allocate_extent;
	} else {
		if (reserved_blks != blks_count) {
			SSDFS_WARN("reserved_blks %u != blks_count %u\n",
				   reserved_blks, blks_count);
		}

		while (reserved_blks > 0) {
			err2 = __ssdfs_blk2off_table_allocate_extent(cur_seg,
							    pool,
							    batch,
							    reserved_blks,
							    &allocated_blks);
			if (err2 == -EAGAIN) {
				if (allocated_blks > reserved_blks ||
				    allocated_blks == 0) {
					err = -ERANGE;
					SSDFS_ERR("invalid state: "
						  "allocated_blks %u, "
						  "reserved_blks %u\n",
						  allocated_blks,
						  reserved_blks);
					goto finish_allocate_extent;
				}

				reserved_blks -= allocated_blks;
			} else if (unlikely(err2)) {
				err = err2;
				SSDFS_ERR("fail to allocate logical extent: "
					  "err %d\n", err);
				goto finish_allocate_extent;
			} else {
				if (allocated_blks != reserved_blks) {
					err = -ERANGE;
					SSDFS_ERR("invalid state: "
						  "allocated_blks %u, "
						  "reserved_blks %u\n",
						  allocated_blks,
						  reserved_blks);
					goto finish_allocate_extent;
				}

				reserved_blks -= allocated_blks;
			}
		}
	}

finish_allocate_extent:
	return err;
}

/*
 * ssdfs_add_new_current_segment() - add new current segment
 * @cur_seg: current segment container
 * @seg_search: segment search state
 * @seg_type: requested segment type
 *
 * This function tries to add new current segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - there is no more clean segments.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_add_new_current_segment(struct ssdfs_current_segment *cur_seg,
				  struct ssdfs_segment_search_state *seg_search,
				  int seg_type)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !seg_search);
	BUG_ON(!is_ssdfs_current_segment_locked(cur_seg));

	SSDFS_DBG("current segment: type %#x, seg_id %llu, real_seg %px\n",
		  cur_seg->type, cur_seg->seg_id, cur_seg->real_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = cur_seg->fsi;

	if (!is_ssdfs_current_segment_empty(cur_seg)) {
		err = ssdfs_remove_current_segment(cur_seg);
		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to add current segment: "
				  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to remove current segment: "
				  "err %d\n", err);
			return err;
		}
	}

	do {
		err = 0;

		seg_search->request.start_search_id = cur_seg->seg_id;
		seg_search->request.need_find_new_segment = true;

		si = ssdfs_grab_segment(fsi, seg_search);
		if (IS_ERR_OR_NULL(si)) {
			err = (si == NULL ? -ENOMEM : PTR_ERR(si));
			if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to create segment object: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
				SSDFS_ERR("fail to create segment object: "
					  "err %d\n", err);
			}

			return err;
		}

		if (cur_seg->seg_id == si->seg_id) {
			/*
			 * ssdfs_grab_segment() has got object already.
			 */
			ssdfs_segment_put_object(si);
			err = -ENOSPC;
			SSDFS_DBG("there is no more clean segments\n");
			return err;
		}

		err = ssdfs_current_segment_add(cur_seg, si, seg_search);
		/*
		 * ssdfs_grab_segment() has got object already.
		 */
		ssdfs_segment_put_object(si);

		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to add segment %llu as current: "
				  "err %d\n",
				  si->seg_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			cur_seg->seg_id = si->seg_id;
			/* continue search */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add segment %llu as current: "
				  "err %d\n",
				  si->seg_id, err);
			return err;
		}
	} while (err == -ENOSPC);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("current segment has been added: "
		  "type %#x, seg_id %llu, real_seg %px\n",
		  cur_seg->type, cur_seg->seg_id, cur_seg->real_seg);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * __ssdfs_segment_add_data_extent() - add new data extent into segment
 * @cur_seg: current segment container
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add new extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_data_extent(struct ssdfs_current_segment *cur_seg,
				    struct ssdfs_segment_request_pool *pool,
				    struct ssdfs_dirty_folios_batch *batch)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_search_state seg_search;
	int seg_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !pool || !batch);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  batch->requested_extent.ino,
		  batch->requested_extent.logical_offset,
		  batch->requested_extent.data_bytes,
		  batch->requested_extent.cno,
		  batch->requested_extent.parent_snapshot);
	SSDFS_ERR("current segment: type %#x, seg_id %llu, real_seg %px\n",
		  cur_seg->type, cur_seg->seg_id, cur_seg->real_seg);
#else
	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  batch->requested_extent.ino,
		  batch->requested_extent.logical_offset,
		  batch->requested_extent.data_bytes,
		  batch->requested_extent.cno,
		  batch->requested_extent.parent_snapshot);
	SSDFS_DBG("current segment: type %#x, seg_id %llu, real_seg %px\n",
		  cur_seg->type, cur_seg->seg_id, cur_seg->real_seg);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = cur_seg->fsi;

	ssdfs_current_segment_lock(cur_seg);

	seg_type = CHECKED_SEG_TYPE(fsi, SEG_TYPE(pool->req_class));
	ssdfs_segment_search_state_init(&seg_search, seg_type,
					U64_MAX, U64_MAX);

	if (is_ssdfs_current_segment_empty(cur_seg)) {
		err = ssdfs_add_new_current_segment(cur_seg,
						    &seg_search,
						    seg_type);
		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to add current segment: "
				  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_add_extent;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add current segment: "
				  "err %d\n", err);
			goto finish_add_extent;
		}
	}

	do {
		err = 0;

		err = ssdfs_segment_allocate_data_extent(cur_seg, pool, batch);
		if (err == -E2BIG || err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("segment %llu hasn't enough free pages\n",
				  cur_seg->real_seg->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_add_new_current_segment(cur_seg,
							    &seg_search,
							    seg_type);
			if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to add current segment: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_add_extent;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to add current segment: "
					  "err %d\n", err);
				goto finish_add_extent;
			} else {
				/* try next current segment */
				err = -EAGAIN;
			}
		} else if (err == -ENOSPC) {
			err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("request pool is full\n");
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_add_extent;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to reserve logical extent: "
				  "seg %llu, err %d\n",
				  cur_seg->real_seg->seg_id, err);
			goto finish_add_extent;
		}
	} while (err == -EAGAIN);

finish_add_extent:
	ssdfs_current_segment_unlock(cur_seg);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	if (cur_seg->real_seg) {
		SSDFS_ERR("finished: seg %llu\n",
			  cur_seg->real_seg->seg_id);
	}
#else
	if (cur_seg->real_seg) {
		SSDFS_DBG("finished: seg %llu\n",
			  cur_seg->real_seg->seg_id);
	}
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to add extent: "
			  "ino %llu, "
			  "requested (logical_offset %llu, data_bytes %u), "
			  "allocated (start_blk %u, len %u), "
			  "err %d\n",
			  batch->requested_extent.ino,
			  batch->requested_extent.logical_offset,
			  batch->requested_extent.data_bytes,
			  batch->allocated_extent.start_lblk,
			  batch->allocated_extent.len,
			  err);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("request pool is full\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (err) {
		SSDFS_ERR("fail to add extent: "
			  "ino %llu, "
			  "requested (logical_offset %llu, data_bytes %u), "
			  "allocated (start_blk %u, len %u), "
			  "err %d\n",
			  batch->requested_extent.ino,
			  batch->requested_extent.logical_offset,
			  batch->requested_extent.data_bytes,
			  batch->allocated_extent.start_lblk,
			  batch->allocated_extent.len,
			  err);
		return err;
	}

	return 0;
}

/*
 * __ssdfs_segment_add_data_block() - add new data block into segment
 * @cur_seg: current segment container
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_data_block(struct ssdfs_current_segment *cur_seg,
				   struct ssdfs_segment_request_pool *pool,
				   struct ssdfs_dirty_folios_batch *batch)
{
	return __ssdfs_segment_add_data_extent(cur_seg, pool, batch);
}

/*
 * __ssdfs_segment_add_data_block_sync() - add new data block synchronously
 * @fsi: pointer on shared file system object
 * @req_class: request class
 * @req_type: request type
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_data_block_sync(struct ssdfs_fs_info *fsi,
					int req_class,
					int req_type,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pool || !batch);
	BUG_ON(pool->req_class <= SSDFS_PEB_READ_REQ ||
		pool->req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  batch->requested_extent.ino,
		  batch->requested_extent.logical_offset,
		  batch->requested_extent.data_bytes,
		  batch->requested_extent.cno,
		  batch->requested_extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	pool->req_class = req_class;
	pool->req_command = SSDFS_CREATE_BLOCK;
	pool->req_type = req_type;

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(pool->req_class)];
	err = __ssdfs_segment_add_data_block(cur_seg, pool, batch);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * __ssdfs_segment_add_data_block_async() - add new data block asynchronously
 * @fsi: pointer on shared file system object
 * @req_class: request class
 * @req_type: request type
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_data_block_async(struct ssdfs_fs_info *fsi,
					 int req_class,
					 int req_type,
					 struct ssdfs_segment_request_pool *pool,
					 struct ssdfs_dirty_folios_batch *batch)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pool || !batch);
	BUG_ON(req_class <= SSDFS_PEB_READ_REQ ||
		req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  batch->requested_extent.ino,
		  batch->requested_extent.logical_offset,
		  batch->requested_extent.data_bytes,
		  batch->requested_extent.cno,
		  batch->requested_extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	pool->req_class = req_class;
	pool->req_command = SSDFS_CREATE_BLOCK;
	pool->req_type = req_type;

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(pool->req_class)];
	err = __ssdfs_segment_add_data_block(cur_seg, pool, batch);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_pre_alloc_data_block_sync() - synchronous pre-alloc data block
 * @fsi: pointer on shared file system object
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to pre-allocate a new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_data_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	return __ssdfs_segment_add_data_block_sync(fsi,
					      SSDFS_PEB_PRE_ALLOCATE_DATA_REQ,
					      SSDFS_REQ_SYNC,
					      pool, batch);
}

/*
 * ssdfs_segment_pre_alloc_data_block_async() - async pre-alloc data block
 * @fsi: pointer on shared file system object
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to pre-allocate a new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_data_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	return __ssdfs_segment_add_data_block_async(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_DATA_REQ,
					       SSDFS_REQ_ASYNC,
					       pool, batch);
}

/*
 * ssdfs_segment_add_data_block_sync() - add new data block synchronously
 * @fsi: pointer on shared file system object
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_data_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	return __ssdfs_segment_add_data_block_sync(fsi,
						SSDFS_PEB_CREATE_DATA_REQ,
						SSDFS_REQ_SYNC,
						pool, batch);
}

/*
 * ssdfs_segment_add_data_block_async() - add new data block asynchronously
 * @fsi: pointer on shared file system object
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_data_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	return __ssdfs_segment_add_data_block_async(fsi,
						SSDFS_PEB_CREATE_DATA_REQ,
						SSDFS_REQ_ASYNC,
						pool, batch);
}

/*
 * __ssdfs_segment_add_block() - add new block into segment
 * @cur_seg: current segment container
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_block(struct ssdfs_current_segment *cur_seg,
			       struct ssdfs_segment_request *req,
			       u64 *seg_id,
			       struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_search_state seg_search;
	int seg_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !req || !seg_id || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
	SSDFS_ERR("current segment: type %#x, seg_id %llu, real_seg %px\n",
		  cur_seg->type, cur_seg->seg_id, cur_seg->real_seg);
#else
	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
	SSDFS_DBG("current segment: type %#x, seg_id %llu, real_seg %px\n",
		  cur_seg->type, cur_seg->seg_id, cur_seg->real_seg);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = cur_seg->fsi;
	*seg_id = U64_MAX;

	ssdfs_current_segment_lock(cur_seg);

	seg_type = CHECKED_SEG_TYPE(fsi, SEG_TYPE(req->private.class));
	ssdfs_segment_search_state_init(&seg_search, seg_type,
					U64_MAX, U64_MAX);

try_current_segment:
	if (is_ssdfs_current_segment_empty(cur_seg)) {
add_new_current_segment:
		seg_search.request.start_search_id = cur_seg->seg_id;
		seg_search.request.need_find_new_segment = true;
		si = ssdfs_grab_segment(cur_seg->fsi, &seg_search);
		if (IS_ERR_OR_NULL(si)) {
			err = (si == NULL ? -ENOMEM : PTR_ERR(si));
			if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to create segment object: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
				SSDFS_ERR("fail to create segment object: "
					  "err %d\n", err);
			}

			goto finish_add_block;
		}

		if (cur_seg->seg_id == si->seg_id) {
			/*
			 * ssdfs_grab_segment() has got object already.
			 */
			ssdfs_segment_put_object(si);
			err = -ENOSPC;
			SSDFS_DBG("there is no more clean segments\n");
			goto finish_add_block;
		}

		err = ssdfs_current_segment_add(cur_seg, si, &seg_search);
		/*
		 * ssdfs_grab_segment() has got object already.
		 */
		ssdfs_segment_put_object(si);

		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to add segment %llu as current: "
				  "err %d\n",
				  si->seg_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			cur_seg->seg_id = si->seg_id;
			goto add_new_current_segment;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add segment %llu as current: "
				  "err %d\n",
				  si->seg_id, err);
			goto finish_add_block;
		}

		goto try_current_segment;
	} else {
		si = cur_seg->real_seg;

		err = ssdfs_segment_blk_bmap_reserve_block(&si->blk_bmap);
		if (err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("segment %llu hasn't enough free pages\n",
				  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_remove_current_segment(cur_seg);
			if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to add current segment: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_add_block;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to remove current segment: "
					  "seg %llu, err %d\n",
					  si->seg_id, err);
				goto finish_add_block;
			} else
				goto add_new_current_segment;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to reserve logical block: "
				  "seg %llu, err %d\n",
				  cur_seg->real_seg->seg_id, err);
			goto finish_add_block;
		} else {
			struct ssdfs_blk2off_table *table;
			struct ssdfs_requests_queue *create_rq;
			wait_queue_head_t *wait;
			u16 blk;
			int capacity;

			table = si->blk2off_table;

			*seg_id = si->seg_id;
			ssdfs_request_define_segment(si->seg_id, req);

			capacity =
			    ssdfs_segment_blk_bmap_get_capacity(&si->blk_bmap);

			err = ssdfs_blk2off_table_allocate_block(table,
								 capacity,
								 &blk);
			if (err == -EAGAIN) {
				struct completion *end;
				end = &table->full_init_end;

				err = SSDFS_WAIT_COMPLETION(end);
				if (unlikely(err)) {
					SSDFS_ERR("blk2off init failed: "
						  "err %d\n", err);
					goto finish_add_block;
				}

				err = ssdfs_blk2off_table_allocate_block(table,
								      capacity,
								      &blk);
			}

			if (unlikely(err)) {
				SSDFS_ERR("fail to allocate logical block\n");
				goto finish_add_block;
			}

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(blk > U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

			extent->start_lblk = blk;
			extent->len = 1;

			ssdfs_request_define_volume_extent(blk, 1, req);

			err = ssdfs_current_segment_change_state(cur_seg);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change segment state: "
					  "seg %llu, err %d\n",
					  cur_seg->real_seg->seg_id, err);
				goto finish_add_block;
			}

			ssdfs_account_user_data_flush_request(si, req);
			ssdfs_segment_create_request_cno(si);

			create_rq = &si->create_rq;
			ssdfs_requests_queue_add_tail_inc(si->fsi,
							create_rq, req);

			wait = &si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
			wake_up_all(wait);
			wake_up_all(&si->fsi->pending_wq);
		}
	}

finish_add_block:
	ssdfs_current_segment_unlock(cur_seg);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: seg %llu\n",
		  cur_seg->real_seg->seg_id);
#else
	SSDFS_DBG("finished: seg %llu\n",
		  cur_seg->real_seg->seg_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to add block: "
			  "ino %llu, logical_offset %llu, err %d\n",
			  req->extent.ino, req->extent.logical_offset, err);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (err) {
		SSDFS_ERR("fail to add block: "
			  "ino %llu, logical_offset %llu, err %d\n",
			  req->extent.ino, req->extent.logical_offset, err);
		return err;
	}

	return 0;
}

/*
 * __ssdfs_segment_add_block_sync() - add new block synchronously
 * @fsi: pointer on shared file system object
 * @req_class: request class
 * @req_type: request type
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_block_sync(struct ssdfs_fs_info *fsi,
				   int req_class,
				   int req_type,
				   struct ssdfs_segment_request *req,
				   u64 *seg_id,
				   struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON(req_class <= SSDFS_PEB_READ_REQ ||
		req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_SYNC:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_CREATE_BLOCK,
					    req_type, req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_block(cur_seg, req, seg_id, extent);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * __ssdfs_segment_add_block_async() - add new block asynchronously
 * @fsi: pointer on shared file system object
 * @req_class: request class
 * @req_type: request type
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_block_async(struct ssdfs_fs_info *fsi,
				    int req_class,
				    int req_type,
				    struct ssdfs_segment_request *req,
				    u64 *seg_id,
				    struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON(req_class <= SSDFS_PEB_READ_REQ ||
		req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_CREATE_BLOCK,
					    req_type, req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_block(cur_seg, req, seg_id, extent);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_pre_alloc_leaf_node_block_sync() - sync pre-alloc leaf node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate a leaf node's block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_leaf_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_sync(fsi,
					      SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ,
					      SSDFS_REQ_SYNC,
					      req, seg_id, extent);
}

/*
 * ssdfs_segment_pre_alloc_leaf_node_block_async() - async pre-alloc leaf node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate a leaf node's block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_leaf_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_async(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ,
					       SSDFS_REQ_ASYNC,
					       req, seg_id, extent);
}

/*
 * ssdfs_segment_pre_alloc_hybrid_node_block_sync() - sync pre-alloc hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate a hybrid node's block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_hybrid_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_sync(fsi,
					      SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ,
					      SSDFS_REQ_SYNC,
					      req, seg_id, extent);
}

/*
 * ssdfs_segment_pre_alloc_hybrid_node_block_async() - pre-alloc hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate a hybrid node's block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_hybrid_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_async(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ,
					       SSDFS_REQ_ASYNC,
					       req, seg_id, extent);
}

/*
 * ssdfs_segment_pre_alloc_index_node_block_sync() - sync pre-alloc index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate an index node's block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_index_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_sync(fsi,
					     SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ,
					     SSDFS_REQ_SYNC,
					     req, seg_id, extent);
}

/*
 * ssdfs_segment_pre_alloc_index_node_block_async() - pre-alloc index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate an index node's block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_index_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_async(fsi,
					     SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ,
					     SSDFS_REQ_ASYNC,
					     req, seg_id, extent);
}

/*
 * ssdfs_segment_migrate_zone_block_sync() - migrate zone block synchronously
 * @fsi: pointer on shared file system object
 * @req_type: request type
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to migrate user data block from
 * exhausted zone into current zone for user data updates.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_migrate_zone_block_sync(struct ssdfs_fs_info *fsi,
					  int req_type,
					  struct ssdfs_segment_request *req,
					  u64 *seg_id,
					  struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_current_segment *cur_seg;
	int req_class = SSDFS_ZONE_USER_DATA_MIGRATE_REQ;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_SYNC:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_MIGRATE_ZONE_USER_BLOCK,
					    req_type, req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_block(cur_seg, req, seg_id, extent);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_migrate_zone_block_async() - migrate zone block asynchronously
 * @fsi: pointer on shared file system object
 * @req_type: request type
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to migrate user data block from
 * exhausted zone into current zone for user data updates.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_migrate_zone_block_async(struct ssdfs_fs_info *fsi,
					   int req_type,
					   struct ssdfs_segment_request *req,
					   u64 *seg_id,
					   struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_current_segment *cur_seg;
	int req_class = SSDFS_ZONE_USER_DATA_MIGRATE_REQ;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_MIGRATE_ZONE_USER_BLOCK,
					    req_type, req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_block(cur_seg, req, seg_id, extent);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_add_leaf_node_block_sync() - add new leaf node synchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new leaf node's block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_leaf_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_sync(fsi,
						SSDFS_PEB_CREATE_LNODE_REQ,
						SSDFS_REQ_SYNC,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_leaf_node_block_async() - add new leaf node asynchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new leaf node's block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_leaf_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_async(fsi,
						SSDFS_PEB_CREATE_LNODE_REQ,
						SSDFS_REQ_ASYNC,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_hybrid_node_block_sync() - add new hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new hybrid node's block into segment
 * synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_hybrid_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_sync(fsi,
						SSDFS_PEB_CREATE_HNODE_REQ,
						SSDFS_REQ_SYNC,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_hybrid_node_block_async() - add new hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new hybrid node's block into segment
 * asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_hybrid_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_async(fsi,
						SSDFS_PEB_CREATE_HNODE_REQ,
						SSDFS_REQ_ASYNC,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_index_node_block_sync() - add new index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new index node's block into segment
 * synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_index_node_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_sync(fsi,
						SSDFS_PEB_CREATE_IDXNODE_REQ,
						SSDFS_REQ_SYNC,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_index_node_block_async() - add new index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new index node's block into segment
 * asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_index_node_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_block_async(fsi,
						SSDFS_PEB_CREATE_IDXNODE_REQ,
						SSDFS_REQ_ASYNC,
						req, seg_id, extent);
}

/*
 * __ssdfs_segment_add_data_extent_sync() - add new extent synchronously
 * @fsi: pointer on shared file system object
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add new data extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_data_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pool || !batch);
	BUG_ON(pool->req_class <= SSDFS_PEB_READ_REQ ||
		pool->req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  batch->requested_extent.ino,
		  batch->requested_extent.logical_offset,
		  batch->requested_extent.data_bytes,
		  batch->requested_extent.cno,
		  batch->requested_extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	pool->req_command = SSDFS_CREATE_EXTENT;
	pool->req_type = SSDFS_REQ_SYNC;

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(pool->req_class)];
	err = __ssdfs_segment_add_data_extent(cur_seg, pool, batch);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * __ssdfs_segment_add_data_extent_async() - add new data extent asynchronously
 * @fsi: pointer on shared file system object
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add new extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_data_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pool || !batch);
	BUG_ON(pool->req_class <= SSDFS_PEB_READ_REQ ||
		pool->req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  batch->requested_extent.ino,
		  batch->requested_extent.logical_offset,
		  batch->requested_extent.data_bytes,
		  batch->requested_extent.cno,
		  batch->requested_extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	pool->req_command = SSDFS_CREATE_EXTENT;
	pool->req_type = SSDFS_REQ_ASYNC;

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(pool->req_class)];
	err = __ssdfs_segment_add_data_extent(cur_seg, pool, batch);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_pre_alloc_data_extent_sync() - sync pre-alloc a data extent
 * @fsi: pointer on shared file system object
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to pre-allocate a new data extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_data_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pool || !batch);
#endif /* CONFIG_SSDFS_DEBUG */

	pool->req_class = SSDFS_PEB_PRE_ALLOCATE_DATA_REQ;
	return __ssdfs_segment_add_data_extent_sync(fsi, pool, batch);
}

/*
 * ssdfs_segment_pre_alloc_data_extent_async() - async pre-alloc a data extent
 * @fsi: pointer on shared file system object
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to pre-allocate a new data extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_data_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pool || !batch);
#endif /* CONFIG_SSDFS_DEBUG */

	pool->req_class = SSDFS_PEB_PRE_ALLOCATE_DATA_REQ;
	return __ssdfs_segment_add_data_extent_async(fsi, pool, batch);
}

/*
 * ssdfs_segment_add_data_extent_sync() - add new data extent synchronously
 * @fsi: pointer on shared file system object
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add new data extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_data_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pool || !batch);
#endif /* CONFIG_SSDFS_DEBUG */

	pool->req_class = SSDFS_PEB_CREATE_DATA_REQ;
	return __ssdfs_segment_add_data_extent_sync(fsi, pool, batch);
}

/*
 * ssdfs_segment_add_data_extent_async() - add new data extent asynchronously
 * @fsi: pointer on shared file system object
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add new data extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-EAGAIN     - request pool is full.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_data_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pool || !batch);
#endif /* CONFIG_SSDFS_DEBUG */

	pool->req_class = SSDFS_PEB_CREATE_DATA_REQ;
	return __ssdfs_segment_add_data_extent_async(fsi, pool, batch);
}

/*
 * __ssdfs_segment_add_extent() - add new extent into segment
 * @cur_seg: current segment container
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_extent(struct ssdfs_current_segment *cur_seg,
			       struct ssdfs_segment_request *req,
			       u64 *seg_id,
			       struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_search_state seg_search;
	int seg_type;
	int err = 0;
	int res = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !req || !seg_id || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
	SSDFS_ERR("current segment: type %#x, seg_id %llu, real_seg %px\n",
		  cur_seg->type, cur_seg->seg_id, cur_seg->real_seg);
#else
	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
	SSDFS_DBG("current segment: type %#x, seg_id %llu, real_seg %px\n",
		  cur_seg->type, cur_seg->seg_id, cur_seg->real_seg);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = cur_seg->fsi;
	*seg_id = U64_MAX;

	ssdfs_current_segment_lock(cur_seg);

	seg_type = CHECKED_SEG_TYPE(fsi, SEG_TYPE(req->private.class));
	ssdfs_segment_search_state_init(&seg_search, seg_type,
					U64_MAX, U64_MAX);

try_current_segment:
	if (is_ssdfs_current_segment_empty(cur_seg)) {

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("current segment is empty\n");
#endif /* CONFIG_SSDFS_DEBUG */

add_new_current_segment:
		seg_search.request.start_search_id = cur_seg->seg_id;
		seg_search.request.need_find_new_segment = true;
		si = ssdfs_grab_segment(fsi, &seg_search);
		if (IS_ERR_OR_NULL(si)) {
			err = (si == NULL ? -ENOMEM : PTR_ERR(si));
			if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to create segment object: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
				SSDFS_ERR("fail to create segment object: "
					  "err %d\n", err);
			}

			goto finish_add_extent;
		}

		if (cur_seg->seg_id == si->seg_id) {
			/*
			 * ssdfs_grab_segment() has got object already.
			 */
			ssdfs_segment_put_object(si);
			err = -ENOSPC;
			SSDFS_DBG("there is no more clean segments\n");
			goto finish_add_extent;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("add current segment: seg_id %llu\n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_current_segment_add(cur_seg, si, &seg_search);
		/*
		 * ssdfs_grab_segment() has got object already.
		 */
		ssdfs_segment_put_object(si);

		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to add segment %llu as current: "
				  "err %d\n",
				  si->seg_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
			cur_seg->seg_id = si->seg_id;
			goto add_new_current_segment;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add segment %llu as current: "
				  "err %d\n",
				  si->seg_id, err);
			goto finish_add_extent;
		}

		goto try_current_segment;
	} else {
		struct ssdfs_blk2off_table *table;
		struct ssdfs_requests_queue *create_rq;
		struct ssdfs_segment_blk_bmap *blk_bmap;
		u32 extent_bytes = req->extent.data_bytes;
		u16 blks_count;
		u32 reserved_blks = 0;
		int capacity;

		extent_bytes += fsi->pagesize - 1;
		blks_count = extent_bytes >> fsi->log_pagesize;

		si = cur_seg->real_seg;
		blk_bmap = &si->blk_bmap;

		err = ssdfs_segment_blk_bmap_reserve_extent(&si->blk_bmap,
							    blks_count,
							    &reserved_blks);
		if (err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("segment %llu hasn't enough free pages\n",
				  cur_seg->real_seg->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_remove_current_segment(cur_seg);
			if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to add current segment: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_add_extent;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to remove current segment: "
					  "seg %llu, err %d\n",
					  si->seg_id, err);
				goto finish_add_extent;
			} else
				goto add_new_current_segment;
		} else if (err == -EAGAIN) {
			res = err;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("segment %llu hasn't enough free pages: "
				  "reserved_blks %u\n",
				  cur_seg->real_seg->seg_id,
				  reserved_blks);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_remove_current_segment(cur_seg);
			if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to add current segment: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_add_extent;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to remove current segment: "
					  "seg %llu, err %d\n",
					  si->seg_id, err);
				goto finish_add_extent;
			}

			/* continue logic */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to reserve logical extent: "
				  "seg %llu, err %d\n",
				  cur_seg->real_seg->seg_id, err);
			goto finish_add_extent;
		}

		table = si->blk2off_table;

		*seg_id = si->seg_id;
		ssdfs_request_define_segment(si->seg_id, req);

		capacity = ssdfs_segment_blk_bmap_get_capacity(blk_bmap);

		err = ssdfs_blk2off_table_allocate_extent(table,
							  reserved_blks,
							  capacity,
							  extent);
		if (err == -EAGAIN) {
			struct completion *end;
			end = &table->full_init_end;

			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("blk2off init failed: "
					  "seg_id %llu, err %d\n",
					  *seg_id, err);
				goto finish_add_extent;
			}

			err = ssdfs_blk2off_table_allocate_extent(table,
								reserved_blks,
								capacity,
								extent);
		}

		if (err == -ENODATA) {
			SSDFS_DBG("unable to allocate: "
				  "seg_id %llu, "
				  "extent (start_lblk %u, len %u), "
				  "reserved_blks %u\n",
				  *seg_id,
				  extent->start_lblk,
				  extent->len,
				  reserved_blks);

			err = ssdfs_segment_blk_bmap_release_extent(blk_bmap,
								reserved_blks);
			if (unlikely(err)) {
				SSDFS_ERR("fail to release extent: "
					  "seg %llu, err %d\n",
					  si->seg_id, err);
				goto finish_add_extent;
			}

			err = ssdfs_remove_current_segment(cur_seg);
			if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to add current segment: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_add_extent;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to remove current segment: "
					  "seg %llu, err %d\n",
					  si->seg_id, err);
				goto finish_add_extent;
			} else
				goto add_new_current_segment;
		} else if (err == -E2BIG) {
			u32 diff = reserved_blks - extent->len;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("extent allocated partially: "
				  "seg_id %llu, "
				  "extent (start_lblk %u, len %u), "
				  "reserved_blks %u\n",
				  *seg_id,
				  extent->start_lblk,
				  extent->len,
				  reserved_blks);

			BUG_ON(extent->len == reserved_blks);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_segment_blk_bmap_release_extent(blk_bmap,
								    diff);
			if (unlikely(err)) {
				SSDFS_ERR("fail to release extent: "
					  "seg %llu, err %d\n",
					  si->seg_id, err);
				goto finish_add_extent;
			}

			reserved_blks = extent->len;
			/* continue logic */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to allocate logical extent: "
				  "seg_id %llu, err %d\n",
				  *seg_id, err);
			goto finish_add_extent;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(extent->start_lblk >= U16_MAX);

		SSDFS_DBG("extent has been allocated: "
			  "seg_id %llu, "
			  "extent (start_lblk %u, len %u), "
			  "reserved_blks %u, err %d\n",
			  *seg_id,
			  extent->start_lblk,
			  extent->len,
			  reserved_blks,
			  err);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_request_define_volume_extent(extent->start_lblk,
						   extent->len, req);
		req->extent.data_bytes = (u32)extent->len * fsi->pagesize;

		err = ssdfs_current_segment_change_state(cur_seg);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change segment state: "
				  "seg %llu, err %d\n",
				  cur_seg->real_seg->seg_id, err);
			goto finish_add_extent;
		}

		ssdfs_account_user_data_flush_request(si, req);
		ssdfs_segment_create_request_cno(si);

		create_rq = &si->create_rq;
		ssdfs_requests_queue_add_tail_inc(si->fsi,
						create_rq, req);
		wake_up_all(&si->wait_queue[SSDFS_PEB_FLUSH_THREAD]);
		wake_up_all(&si->fsi->pending_wq);
	}

finish_add_extent:
	ssdfs_current_segment_unlock(cur_seg);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	if (cur_seg->real_seg) {
		SSDFS_ERR("finished: seg %llu\n",
			  cur_seg->real_seg->seg_id);
	}
#else
	if (cur_seg->real_seg) {
		SSDFS_DBG("finished: seg %llu\n",
			  cur_seg->real_seg->seg_id);
	}
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to add extent: "
			  "ino %llu, logical_offset %llu, err %d\n",
			  req->extent.ino, req->extent.logical_offset, err);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (err) {
		SSDFS_ERR("fail to add extent: "
			  "ino %llu, logical_offset %llu, err %d\n",
			  req->extent.ino, req->extent.logical_offset, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("extent has been allocated: "
		  "seg_id %llu, "
		  "extent (start_lblk %u, len %u), "
		  "err %d, res %d\n",
		  *seg_id,
		  extent->start_lblk,
		  extent->len,
		  err, res);
#endif /* CONFIG_SSDFS_DEBUG */

	return res;
}

/*
 * __ssdfs_segment_add_extent_sync() - add new extent synchronously
 * @fsi: pointer on shared file system object
 * @req_class: request class
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_extent_sync(struct ssdfs_fs_info *fsi,
				    int req_class,
				    struct ssdfs_segment_request *req,
				    u64 *seg_id,
				    struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON(req_class <= SSDFS_PEB_READ_REQ ||
		req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_CREATE_EXTENT,
					    SSDFS_REQ_SYNC,
					    req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_extent(cur_seg, req, seg_id, extent);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * __ssdfs_segment_add_extent_async() - add new extent asynchronously
 * @fsi: pointer on shared file system object
 * @req_class: request class
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_add_extent_async(struct ssdfs_fs_info *fsi,
				     int req_class,
				     struct ssdfs_segment_request *req,
				     u64 *seg_id,
				     struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON(req_class <= SSDFS_PEB_READ_REQ ||
		req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_CREATE_EXTENT,
					    SSDFS_REQ_ASYNC,
					    req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_extent(cur_seg, req, seg_id, extent);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_pre_alloc_leaf_node_extent_sync() - pre-alloc a leaf node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate a leaf node's extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_leaf_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_sync(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ,
					       req, seg_id, extent);
}

/*
 * ssdfs_segment_pre_alloc_leaf_node_extent_async() - pre-alloc a leaf node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate a leaf node's extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_leaf_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_async(fsi,
					    SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ,
					    req, seg_id, extent);
}

/*
 * ssdfs_segment_pre_alloc_hybrid_node_extent_sync() - pre-alloc a hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate a hybrid node's extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_hybrid_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_sync(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ,
					       req, seg_id, extent);
}

/*
 * ssdfs_segment_pre_alloc_hybrid_node_extent_sync() - pre-alloc a hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate a hybrid node's extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_hybrid_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_async(fsi,
					    SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ,
					    req, seg_id, extent);
}

/*
 * ssdfs_segment_pre_alloc_index_node_extent_sync() - pre-alloc an index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate an index node's extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_index_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_sync(fsi,
					    SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ,
					    req, seg_id, extent);
}

/*
 * ssdfs_segment_pre_alloc_index_node_extent_sync() - pre-alloc an index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to pre-allocate an index node's extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_index_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_async(fsi,
					    SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ,
					    req, seg_id, extent);
}

/*
 * ssdfs_segment_migrate_zone_extent_sync() - migrate zone extent synchronously
 * @fsi: pointer on shared file system object
 * @req_type: request type
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to migrate user data extent from
 * exhausted zone into current zone for user data updates.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_migrate_zone_extent_sync(struct ssdfs_fs_info *fsi,
					   int req_type,
					   struct ssdfs_segment_request *req,
					   u64 *seg_id,
					   struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_current_segment *cur_seg;
	int req_class = SSDFS_ZONE_USER_DATA_MIGRATE_REQ;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_SYNC:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_MIGRATE_ZONE_USER_EXTENT,
					    req_type, req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_extent(cur_seg, req, seg_id, extent);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_migrate_zone_extent_async() - migrate zone extent asynchronously
 * @fsi: pointer on shared file system object
 * @req_type: request type
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to migrate user data exent from
 * exhausted zone into current zone for user data updates.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_migrate_zone_extent_async(struct ssdfs_fs_info *fsi,
					    int req_type,
					    struct ssdfs_segment_request *req,
					    u64 *seg_id,
					    struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_current_segment *cur_seg;
	int req_class = SSDFS_ZONE_USER_DATA_MIGRATE_REQ;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_MIGRATE_ZONE_USER_EXTENT,
					    req_type, req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_extent(cur_seg, req, seg_id, extent);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_move_peb_extent_sync() - move PEB's extent synchronously
 * @fsi: pointer on shared file system object
 * @req_type: request type
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to move inflated user data extent into
 * another erase block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_move_peb_extent_sync(struct ssdfs_fs_info *fsi,
					int req_type,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_current_segment *cur_seg;
	int req_class = SSDFS_PEB_USER_DATA_MOVE_REQ;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_SYNC:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_MOVE_PEB_USER_EXTENT,
					    req_type, req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_extent(cur_seg, req, seg_id, extent);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_move_peb_extent_async() - move PEB's extent asynchronously
 * @fsi: pointer on shared file system object
 * @req_type: request type
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to move inflated user data extent into
 * another erase block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_move_peb_extent_async(struct ssdfs_fs_info *fsi,
					int req_type,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	struct ssdfs_current_segment *cur_seg;
	int req_class = SSDFS_PEB_USER_DATA_MOVE_REQ;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_MOVE_PEB_USER_EXTENT,
					    req_type, req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_extent(cur_seg, req, seg_id, extent);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_add_xattr_blob_sync() - store xattr blob synchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to xattr blob into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_xattr_blob_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_sync(fsi,
						SSDFS_PEB_CREATE_DATA_REQ,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_xattr_blob_async() - store xattr blob asynchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to xattr blob into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_xattr_blob_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_async(fsi,
						SSDFS_PEB_CREATE_DATA_REQ,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_leaf_node_extent_sync() - add new leaf node synchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new leaf node's extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_leaf_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_sync(fsi,
						SSDFS_PEB_CREATE_LNODE_REQ,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_leaf_node_extent_async() - add new leaf node asynchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new leaf node's extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_leaf_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_async(fsi,
						SSDFS_PEB_CREATE_LNODE_REQ,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_hybrid_node_extent_sync() - add new hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new hybrid node's extent into segment
 * synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_hybrid_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_sync(fsi,
						SSDFS_PEB_CREATE_HNODE_REQ,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_hybrid_node_extent_async() - add new hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new hybrid node's extent into segment
 * asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_hybrid_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_async(fsi,
						SSDFS_PEB_CREATE_HNODE_REQ,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_index_node_extent_sync() - add new index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new index node's extent into segment
 * synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_index_node_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_sync(fsi,
						SSDFS_PEB_CREATE_IDXNODE_REQ,
						req, seg_id, extent);
}

/*
 * ssdfs_segment_add_index_node_extent_async() - add new index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 * @seg_id: segment ID [out]
 * @extent: (pre-)allocated extent [out]
 *
 * This function tries to add new index node's extent into segment
 * asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_index_node_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req,
					u64 *seg_id,
					struct ssdfs_blk2off_range *extent)
{
	return __ssdfs_segment_add_extent_async(fsi,
						SSDFS_PEB_CREATE_IDXNODE_REQ,
						req, seg_id, extent);
}

static inline
int ssdfs_account_user_data_pages_as_pending(struct ssdfs_peb_container *pebc,
					     u32 count)
{
	struct ssdfs_fs_info *fsi;
	u64 updated = 0;
	u32 pending = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;

	if (!is_ssdfs_peb_containing_user_data(pebc))
		return 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, peb_index %u, count %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&fsi->volume_state_lock);
	updated = fsi->updated_user_data_pages;
	if (fsi->updated_user_data_pages >= count) {
		fsi->updated_user_data_pages -= count;
	} else {
		err = -ERANGE;
		fsi->updated_user_data_pages = 0;
	}
	spin_unlock(&fsi->volume_state_lock);

	if (err) {
		SSDFS_DBG("count %u is bigger than updated %llu\n",
			  count, updated);
	}

	spin_lock(&pebc->pending_lock);
	pebc->pending_updated_user_data_pages += count;
	pending = pebc->pending_updated_user_data_pages;
	spin_unlock(&pebc->pending_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, peb_index %u, "
		  "updated %llu, pending %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  updated, pending);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_add_request_into_update_queue() - add request into update queue
 * @si: segment info
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to add segment request into update queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - request pool is full.
 * %-ENODATA    - all pages have been processed.
 * %-EAGAIN     - not all memory pages have been processed.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_add_request_into_update_queue(struct ssdfs_segment_info *si,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *po_desc;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_requests_queue *update_rq;
	struct ssdfs_segment_request *req;
	struct ssdfs_content_block *block;
	wait_queue_head_t *wait;
	struct ssdfs_offset_position pos = {0};
	u16 peb_index = U16_MAX;
	u16 logical_blk;
	u16 len;
	u32 not_proccessed;
	u32 data_bytes;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !pool || !batch);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = si->fsi;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, req_class %d, req_type %d\n",
		  si->seg_id, pool->req_class, pool->req_type);

	if (pool->count > SSDFS_SEG_REQ_PTR_NUMBER_MAX) {
		SSDFS_ERR("request pool is corrupted: "
			  "count %u\n", pool->count);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (pool->count >= SSDFS_SEG_REQ_PTR_NUMBER_MAX) {
		SSDFS_DBG("request pool is full: "
			  "count %u\n", pool->count);
		return -ENOSPC;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(batch->place.start.seg_id >= U64_MAX);
	BUG_ON(batch->place.start.blk_index >= U16_MAX);
	BUG_ON(batch->place.len == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	if (batch->processed_blks >= batch->content.count) {
		SSDFS_ERR("all blocks have been processed: "
			  "dirty_blocks %u, processed_blks %u\n",
			  batch->content.count,
			  batch->processed_blks);
		return -ENODATA;
	}

	not_proccessed = batch->content.count - batch->processed_blks;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("batch_size %u, batch->processed_blks %u, "
		  "not_proccessed %u, batch->place.len %u\n",
		  batch->content.count,
		  batch->processed_blks,
		  not_proccessed,
		  batch->place.len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (batch->place.len > not_proccessed) {
		SSDFS_ERR("batch->place.len %u > not_proccessed %u\n",
			  batch->place.len, not_proccessed);
		return -ERANGE;
	}

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req, fsi->pagesize);
	ssdfs_get_request(req);

	ssdfs_request_prepare_internal_data(pool->req_class,
					    pool->req_command,
					    pool->req_type,
					    req);

	if (batch->place.start.seg_id != si->seg_id) {
		err = -ERANGE;
		SSDFS_ERR("invalid request: "
			  "seg_id1 %llu != seg_id2 %llu\n",
			  batch->place.start.seg_id,
			  si->seg_id);
		goto fail_add_request_into_update_queue;
	}

	ssdfs_request_define_segment(si->seg_id, req);

	switch (si->seg_type) {
	case SSDFS_USER_DATA_SEG_TYPE:
		req->private.flags |= SSDFS_REQ_DONT_FREE_FOLIOS;
		break;

	default:
		/* do nothing */
		break;
	}

	data_bytes = (u32)batch->place.len * fsi->pagesize;
	data_bytes = min_t(u32, data_bytes, batch->requested_extent.data_bytes);

	ssdfs_request_prepare_logical_extent(batch->requested_extent.ino,
					batch->requested_extent.logical_offset,
					data_bytes,
					batch->requested_extent.cno,
					batch->requested_extent.parent_snapshot,
					req);
	ssdfs_request_define_volume_extent(batch->place.start.blk_index,
					   batch->place.len,
					   req);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(batch->content.count == 0);
	BUG_ON(not_proccessed == 0);
	BUG_ON((batch->processed_blks + batch->place.len) >
						batch->content.count);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, blk_index %u, len %u\n",
		  batch->requested_extent.ino,
		  (u64)batch->requested_extent.logical_offset,
		  data_bytes,
		  batch->place.start.blk_index,
		  batch->place.len);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < batch->place.len; i++) {
		u32 blk_index = batch->processed_blks + i;

		block = &batch->content.blocks[blk_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folio_batch_count(&block->batch) == 0);

		SSDFS_DBG("batch->processed_blks %u, blk_index %u\n",
			  batch->processed_blks, blk_index);
#endif /* CONFIG_SSDFS_DEBUG */

		for (j = 0; j < folio_batch_count(&block->batch); j++) {
			struct folio *folio = block->batch.folios[j];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);

			SSDFS_DBG("ino %llu, blk_index %d, folio_index %lu\n",
				  batch->requested_extent.ino,
				  blk_index,
				  folio_index(folio));
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_request_add_folio(folio, i, req);
			if (err) {
				SSDFS_ERR("fail to add folio into request: "
					  "ino %llu, blk_index %d, err %d\n",
					  batch->requested_extent.ino, i, err);
				goto fail_add_request_into_update_queue;
			}

			WARN_ON(!folio_test_writeback(folio));
			ssdfs_request_writeback_folios_inc(req);
		}
	}

	batch->processed_blks += batch->place.len;

	if (batch->requested_extent.data_bytes > data_bytes) {
		batch->requested_extent.logical_offset += data_bytes;
		batch->requested_extent.data_bytes -= data_bytes;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("PROCESSED: data_bytes %u, "
			  "NEW STATE: logical_offset %llu, data_bytes %u\n",
			  data_bytes,
			  batch->requested_extent.logical_offset,
			  batch->requested_extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		err = -EAGAIN;
	}

	pool->pointers[pool->count] = req;
	pool->count++;

	table = si->blk2off_table;
	logical_blk = batch->place.start.blk_index;
	len = batch->place.len;

	po_desc = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index, NULL, &pos);
	if (IS_ERR_OR_NULL(po_desc)) {
		err = (po_desc == NULL ? -ERANGE : PTR_ERR(po_desc));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		goto fail_add_request_into_update_queue;
	}

	if (peb_index >= si->pebs_count) {
		err = -ERANGE;
		SSDFS_ERR("peb_index %u >= si->pebs_count %u\n",
			  peb_index, si->pebs_count);
		goto fail_add_request_into_update_queue;
	}

	pebc = &si->peb_array[peb_index];
	update_rq = &pebc->update_rq;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "logical_blk %u, data_bytes %u, blks %u, "
		  "cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->place.len,
		  req->extent.cno, req->extent.parent_snapshot);
	SSDFS_DBG("req->private.class %#x, req->private.cmd %#x\n",
		  req->private.class, req->private.cmd);
#endif /* CONFIG_SSDFS_DEBUG */

	if (len > 0) {
		u32 mem_pages;

		mem_pages = SSDFS_MEM_PAGES_PER_LOGICAL_BLOCK(fsi);
		mem_pages *= len;

		err = ssdfs_account_user_data_pages_as_pending(pebc, mem_pages);
		if (unlikely(err)) {
			SSDFS_ERR("fail to make pages as pending: "
				  "len %u, err %d\n",
				  len, err);
			return err;
		}
	} else {
		SSDFS_WARN("unexpected len %u\n", len);
	}

	switch (req->private.cmd) {
	case SSDFS_COMMIT_LOG_NOW:
		ssdfs_account_commit_log_request(si);
		break;

	default:
		ssdfs_account_user_data_flush_request(si, req);
		break;
	}

	ssdfs_segment_create_request_cno(si);

	switch (req->private.class) {
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		ssdfs_requests_queue_add_head_inc(si->fsi, update_rq, req);
		break;

	default:
		ssdfs_requests_queue_add_tail_inc(si->fsi, update_rq, req);
		break;
	}

	wait = &si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
	wake_up_all(wait);
	wake_up_all(&si->fsi->pending_wq);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;

fail_add_request_into_update_queue:
	ssdfs_put_request(req);
	ssdfs_request_free(req, si);
	return err;
}

/*
 * ssdfs_segment_update_data_block_sync() - update block in segment
 * @si: segment info
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to update a block in segment.
 */
int ssdfs_segment_update_data_block_sync(struct ssdfs_segment_info *si,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !pool || !batch);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  batch->requested_extent.ino,
		  batch->requested_extent.logical_offset,
		  batch->requested_extent.data_bytes,
		  batch->requested_extent.cno,
		  batch->requested_extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	pool->req_class = SSDFS_PEB_UPDATE_REQ;
	pool->req_command = SSDFS_UPDATE_BLOCK;
	pool->req_type = SSDFS_REQ_SYNC;

	return ssdfs_add_request_into_update_queue(si, pool, batch);
}

/*
 * ssdfs_segment_update_data_block_async() - update block in segment
 * @si: segment info
 * @req_type: request type
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to update a block in segment.
 */
int ssdfs_segment_update_data_block_async(struct ssdfs_segment_info *si,
					int req_type,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !pool || !batch);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  batch->requested_extent.ino,
		  batch->requested_extent.logical_offset,
		  batch->requested_extent.data_bytes,
		  batch->requested_extent.cno,
		  batch->requested_extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	pool->req_class = SSDFS_PEB_UPDATE_REQ;
	pool->req_command = SSDFS_UPDATE_BLOCK;
	pool->req_type = req_type;

	return ssdfs_add_request_into_update_queue(si, pool, batch);
}

/*
 * __ssdfs_segment_update_block() - update block in segment
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to update a block in segment.
 */
static
int __ssdfs_segment_update_block(struct ssdfs_segment_info *si,
				 struct ssdfs_segment_request *req)
{
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *po_desc;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_requests_queue *rq;
	wait_queue_head_t *wait;
	struct ssdfs_offset_position pos = {0};
	u16 peb_index = U16_MAX;
	u16 logical_blk;
	u16 len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#else
	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, blks %u, "
		  "cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->place.len,
		  req->extent.cno, req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	table = si->blk2off_table;
	logical_blk = req->place.start.blk_index;
	len = req->place.len;

	po_desc = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index, NULL, &pos);
	if (IS_ERR_OR_NULL(po_desc)) {
		err = (po_desc == NULL ? -ERANGE : PTR_ERR(po_desc));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

	if (peb_index >= si->pebs_count) {
		SSDFS_ERR("peb_index %u >= si->pebs_count %u\n",
			  peb_index, si->pebs_count);
		return -ERANGE;
	}

	pebc = &si->peb_array[peb_index];
	rq = &pebc->update_rq;

	switch (req->private.cmd) {
	case SSDFS_COMMIT_LOG_NOW:
		ssdfs_account_commit_log_request(si);
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
			  "logical_blk %u, data_bytes %u, blks %u, "
			  "cno %llu, parent_snapshot %llu\n",
			  si->seg_id,
			  req->extent.ino, req->extent.logical_offset,
			  req->place.start.blk_index,
			  req->extent.data_bytes, req->place.len,
			  req->extent.cno, req->extent.parent_snapshot);
		SSDFS_DBG("req->private.class %#x, req->private.cmd %#x\n",
			  req->private.class, req->private.cmd);
#endif /* CONFIG_SSDFS_DEBUG */

		if (len > 0) {
			u32 mem_pages;

			mem_pages = SSDFS_MEM_PAGES_PER_LOGICAL_BLOCK(si->fsi);
			mem_pages *= len;

			err = ssdfs_account_user_data_pages_as_pending(pebc,
								    mem_pages);
			if (unlikely(err)) {
				SSDFS_ERR("fail to make pages as pending: "
					  "len %u, err %d\n",
					  len, err);
				return err;
			}
		} else {
			SSDFS_WARN("unexpected len %u\n", len);
		}

		ssdfs_account_user_data_flush_request(si, req);
		break;
	}

	ssdfs_segment_create_request_cno(si);

	switch (req->private.class) {
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		ssdfs_requests_queue_add_head_inc(si->fsi, rq, req);
		break;

	default:
		ssdfs_requests_queue_add_tail_inc(si->fsi, rq, req);
		break;
	}

	wait = &si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
	wake_up_all(wait);
	wake_up_all(&si->fsi->pending_wq);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_segment_update_block_sync() - update block synchronously
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to update the block synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_update_block_sync(struct ssdfs_segment_info *si,
				    struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_UPDATE_BLOCK,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_block(si, req);
}

/*
 * ssdfs_segment_update_block_async() - update block asynchronously
 * @si: segment info
 * @req_type: request type
 * @req: segment request [in|out]
 *
 * This function tries to update the block asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_update_block_async(struct ssdfs_segment_info *si,
				     int req_type,
				     struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_UPDATE_BLOCK,
					    req_type, req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_block(si, req);
}

/*
 * ssdfs_segment_update_data_extent_sync() - update extent in segment
 * @si: segment info
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to update an extent in segment.
 */
int ssdfs_segment_update_data_extent_sync(struct ssdfs_segment_info *si,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !pool || !batch);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  batch->requested_extent.ino,
		  batch->requested_extent.logical_offset,
		  batch->requested_extent.data_bytes,
		  batch->requested_extent.cno,
		  batch->requested_extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	pool->req_class = SSDFS_PEB_UPDATE_REQ;
	pool->req_command = SSDFS_UPDATE_EXTENT;
	pool->req_type = SSDFS_REQ_SYNC;

	return ssdfs_add_request_into_update_queue(si, pool, batch);
}

/*
 * ssdfs_segment_update_data_extent_sync() - update extent in segment
 * @si: segment info
 * @req_type: request type
 * @pool: pool of segment requests [in|out]
 * @batch: dirty pages batch [in|out]
 *
 * This function tries to update an extent in segment.
 */
int ssdfs_segment_update_data_extent_async(struct ssdfs_segment_info *si,
					int req_type,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !pool || !batch);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  batch->requested_extent.ino,
		  batch->requested_extent.logical_offset,
		  batch->requested_extent.data_bytes,
		  batch->requested_extent.cno,
		  batch->requested_extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	pool->req_class = SSDFS_PEB_UPDATE_REQ;
	pool->req_command = SSDFS_UPDATE_EXTENT;
	pool->req_type = req_type;

	return ssdfs_add_request_into_update_queue(si, pool, batch);
}

/*
 * __ssdfs_segment_update_extent() - update extent in segment
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to update an extent in segment.
 */
static
int __ssdfs_segment_update_extent(struct ssdfs_segment_info *si,
				  struct ssdfs_segment_request *req)
{
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *po_desc;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_requests_queue *rq;
	wait_queue_head_t *wait;
	u16 blk, len;
	u16 peb_index = U16_MAX;
	struct ssdfs_offset_position pos = {0};
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, ino %llu, logical_offset %llu, "
		  "logical_blk %u, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#else
	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "logical_blk %u, data_bytes %u, blks %u, "
		  "cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->place.len,
		  req->extent.cno, req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	table = si->blk2off_table;
	blk = req->place.start.blk_index;
	len = req->place.len;

	if (len == 0) {
		SSDFS_WARN("empty extent\n");
		return -ERANGE;
	}

	for (i = 0; i < len; i++) {
		u16 cur_peb_index = U16_MAX;

		po_desc = ssdfs_blk2off_table_convert(table, blk + i,
							&cur_peb_index,
							NULL, &pos);
		if (IS_ERR_OR_NULL(po_desc)) {
			err = (po_desc == NULL ? -ERANGE : PTR_ERR(po_desc));
			SSDFS_ERR("fail to convert: "
				  "seg %llu, ino %llu, "
				  "logical_blk %u, err %d\n",
				  si->seg_id, req->extent.ino,
				  blk + i, err);
			return err;
		}

		if (cur_peb_index >= U16_MAX) {
			SSDFS_ERR("invalid peb_index\n");
			return -ERANGE;
		}

		if (peb_index == U16_MAX)
			peb_index = cur_peb_index;
		else if (peb_index != cur_peb_index) {
			SSDFS_ERR("peb_index %u != cur_peb_index %u\n",
				  peb_index, cur_peb_index);
			return -ERANGE;
		}
	}

	if (peb_index >= si->pebs_count) {
		SSDFS_ERR("peb_index %u >= si->pebs_count %u\n",
			  peb_index, si->pebs_count);
		return -ERANGE;
	}

	pebc = &si->peb_array[peb_index];
	rq = &pebc->update_rq;

	switch (req->private.cmd) {
	case SSDFS_COMMIT_LOG_NOW:
		ssdfs_account_commit_log_request(si);
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
			  "logical_blk %u, data_bytes %u, blks %u, "
			  "cno %llu, parent_snapshot %llu\n",
			  si->seg_id,
			  req->extent.ino, req->extent.logical_offset,
			  req->place.start.blk_index,
			  req->extent.data_bytes, req->place.len,
			  req->extent.cno, req->extent.parent_snapshot);
		SSDFS_DBG("req->private.class %#x, req->private.cmd %#x\n",
			  req->private.class, req->private.cmd);
#endif /* CONFIG_SSDFS_DEBUG */

		if (len > 0) {
			u32 mem_pages;

			mem_pages = SSDFS_MEM_PAGES_PER_LOGICAL_BLOCK(si->fsi);
			mem_pages *= len;

			err = ssdfs_account_user_data_pages_as_pending(pebc,
								    mem_pages);
			if (unlikely(err)) {
				SSDFS_ERR("fail to make pages as pending: "
					  "len %u, err %d\n",
					  len, err);
				return err;
			}
		} else {
			SSDFS_WARN("unexpected len %u\n", len);
		}

		ssdfs_account_user_data_flush_request(si, req);
		break;
	}

	ssdfs_segment_create_request_cno(si);

	switch (req->private.class) {
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
	case SSDFS_MIGRATE_RANGE:
		ssdfs_requests_queue_add_head_inc(si->fsi, rq, req);
		break;

	default:
		ssdfs_requests_queue_add_tail_inc(si->fsi, rq, req);
		break;
	}

	wait = &si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
	wake_up_all(wait);
	wake_up_all(&si->fsi->pending_wq);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_segment_update_extent_sync() - update extent synchronously
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to update the extent synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_update_extent_sync(struct ssdfs_segment_info *si,
				     struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_UPDATE_EXTENT,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_update_extent_async() - update extent asynchronously
 * @si: segment info
 * @req_type: request type
 * @req: segment request [in|out]
 *
 * This function tries to update the extent asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_update_extent_async(struct ssdfs_segment_info *si,
				      int req_type,
				      struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_UPDATE_EXTENT,
					    req_type, req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_update_pre_alloc_block_sync() - update pre-allocated block
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to update the pre-allocated block synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_update_pre_alloc_block_sync(struct ssdfs_segment_info *si,
					    struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_PRE_ALLOC_UPDATE_REQ,
					    SSDFS_UPDATE_PRE_ALLOC_BLOCK,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_update_pre_alloc_block_async() - update pre-allocated block
 * @si: segment info
 * @req_type: request type
 * @req: segment request [in|out]
 *
 * This function tries to update the pre-allocated block asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_update_pre_alloc_block_async(struct ssdfs_segment_info *si,
					    int req_type,
					    struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_PRE_ALLOC_UPDATE_REQ,
					    SSDFS_UPDATE_PRE_ALLOC_BLOCK,
					    req_type, req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_update_pre_alloc_extent_sync() - update pre-allocated extent
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to update the pre-allocated extent synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_update_pre_alloc_extent_sync(struct ssdfs_segment_info *si,
					    struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_PRE_ALLOC_UPDATE_REQ,
					    SSDFS_UPDATE_PRE_ALLOC_EXTENT,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_update_pre_alloc_extent_async() - update pre-allocated extent
 * @si: segment info
 * @req_type: request type
 * @req: segment request [in|out]
 *
 * This function tries to update the pre-allocated extent asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_update_pre_alloc_extent_async(struct ssdfs_segment_info *si,
					    int req_type,
					    struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_PRE_ALLOC_UPDATE_REQ,
					    SSDFS_UPDATE_PRE_ALLOC_EXTENT,
					    req_type, req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_node_diff_on_write_sync() - Diff-On-Write btree node
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to execute Diff-On-Write operation
 * on btree node synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_node_diff_on_write_sync(struct ssdfs_segment_info *si,
					  struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_DIFF_ON_WRITE_REQ,
					    SSDFS_BTREE_NODE_DIFF,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_node_diff_on_write_async() - Diff-On-Write btree node
 * @si: segment info
 * @req_type: request type
 * @req: segment request [in|out]
 *
 * This function tries to execute Diff-On-Write operation
 * on btree node asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_node_diff_on_write_async(struct ssdfs_segment_info *si,
					   int req_type,
					   struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_DIFF_ON_WRITE_REQ,
					    SSDFS_BTREE_NODE_DIFF,
					    req_type, req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_data_diff_on_write_sync() - Diff-On-Write user data
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to execute Diff-On-Write operation
 * on user data synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_data_diff_on_write_sync(struct ssdfs_segment_info *si,
					  struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_DIFF_ON_WRITE_REQ,
					    SSDFS_USER_DATA_DIFF,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_block(si, req);
}

/*
 * ssdfs_segment_data_diff_on_write_async() - Diff-On-Write user data
 * @si: segment info
 * @req_type: request type
 * @req: segment request [in|out]
 *
 * This function tries to execute Diff-On-Write operation
 * on user data asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_data_diff_on_write_async(struct ssdfs_segment_info *si,
					   int req_type,
					   struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_DIFF_ON_WRITE_REQ,
					    SSDFS_USER_DATA_DIFF,
					    req_type, req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_block(si, req);
}

/*
 * ssdfs_segment_prepare_migration_sync() - request to prepare migration
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to request to prepare or to start the migration
 * synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_prepare_migration_sync(struct ssdfs_segment_info *si,
					 struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_START_MIGRATION_NOW,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_prepare_migration_async() - request to prepare migration
 * @si: segment info
 * @req_type: request type
 * @req: segment request [in|out]
 *
 * This function tries to request to prepare or to start the migration
 * asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_prepare_migration_async(struct ssdfs_segment_info *si,
					  int req_type,
					  struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_START_MIGRATION_NOW,
					    req_type, req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_commit_log_sync() - request the commit log operation
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to request the commit log operation
 * synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_commit_log_sync(struct ssdfs_segment_info *si,
				  struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_COMMIT_LOG_NOW,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_commit_log_async() - request the commit log operation
 * @si: segment info
 * @req_type: request type
 * @req: segment request [in|out]
 *
 * This function tries to request the commit log operation
 * asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_commit_log_async(struct ssdfs_segment_info *si,
				   int req_type,
				   struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_COMMIT_LOG_NOW,
					    req_type, req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * __ssdfs_segment_commit_log2() - request the commit log operation
 * @si: segment info
 * @peb_index: PEB's index
 * @req: segment request [in|out]
 *
 * This function tries to request the commit log operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_segment_commit_log2(struct ssdfs_segment_info *si,
				u16 peb_index,
				struct ssdfs_segment_request *req)
{
	struct ssdfs_peb_container *pebc;
	struct ssdfs_requests_queue *rq;
	wait_queue_head_t *wait;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, peb_index, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_index >= si->pebs_count) {
		SSDFS_ERR("peb_index %u >= si->pebs_count %u\n",
			  peb_index, si->pebs_count);
		return -ERANGE;
	}

	ssdfs_account_commit_log_request(si);
	ssdfs_segment_create_request_cno(si);

	pebc = &si->peb_array[peb_index];
	rq = &pebc->update_rq;

	switch (req->private.class) {
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		ssdfs_requests_queue_add_head_inc(si->fsi, rq, req);
		break;

	default:
		ssdfs_requests_queue_add_tail_inc(si->fsi, rq, req);
		break;
	}

	wait = &si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
	wake_up_all(wait);
	wake_up_all(&si->fsi->pending_wq);

	return 0;
}

/*
 * ssdfs_segment_commit_log_sync2() - request the commit log operation
 * @si: segment info
 * @peb_index: PEB's index
 * @req: segment request [in|out]
 *
 * This function tries to request the commit log operation
 * synchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_commit_log_sync2(struct ssdfs_segment_info *si,
				   u16 peb_index,
				   struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, peb_index, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_COMMIT_LOG_NOW,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_commit_log2(si, peb_index, req);
}

/*
 * ssdfs_segment_commit_log_async2() - request the commit log operation
 * @si: segment info
 * @req_type: request type
 * @peb_index: PEB's index
 * @req: segment request [in|out]
 *
 * This function tries to request the commit log operation
 * asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_commit_log_async2(struct ssdfs_segment_info *si,
				    int req_type, u16 peb_index,
				    struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, peb_index, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req_type) {
	case SSDFS_REQ_ASYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		/* expected request type */
		break;

	default:
		SSDFS_ERR("unexpected request type %#x\n",
			  req_type);
		return -EINVAL;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_COMMIT_LOG_NOW,
					    req_type, req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_commit_log2(si, peb_index, req);
}

struct ssdfs_invalidating_extent {
	u16 peb_index;
	u32 start_blk;
	u32 len;
};

/*
 * ssdfs_segment_invalidate_peb_logical_extent() - invalidate logical extent
 * @si: segment info
 * @extent: invalidating extent
 *
 * This function tries to invalidate extent of logical blocks.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_segment_invalidate_peb_logical_extent(struct ssdfs_segment_info *si,
					struct ssdfs_invalidating_extent *extent)
{
	struct ssdfs_peb_container *pebc;
	struct ssdfs_segment_request *req = NULL;
	struct ssdfs_requests_queue *rq;
	wait_queue_head_t *wait;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !extent);

	SSDFS_DBG("seg %llu, peb_index %u, start_blk %u, len %u\n",
		  si->seg_id, extent->peb_index,
		  extent->start_blk, extent->len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (extent->len == 0)
		return 0;

	if (extent->peb_index >= si->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  extent->peb_index, si->pebs_count);
		return -ERANGE;
	}

	pebc = &si->peb_array[extent->peb_index];

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req, si->fsi->pagesize);
	ssdfs_get_request(req);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(extent->start_blk >= U16_MAX);
	BUG_ON(extent->len >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	ssdfs_request_define_volume_extent((u16)extent->start_blk,
					   (u16)extent->len, req);

	ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
					    SSDFS_INVALIDATE_EXTENT,
					    SSDFS_REQ_ASYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	ssdfs_account_user_data_flush_request(si, req);
	ssdfs_segment_create_request_cno(si);

	rq = &pebc->update_rq;
	ssdfs_requests_queue_add_tail_inc(si->fsi, rq, req);

	wait = &si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
	wake_up_all(wait);
	wake_up_all(&si->fsi->pending_wq);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_segment_invalidate_logical_extent() - invalidate logical extent
 * @si: segment info
 * @start_off: starting logical block
 * @blks_count: count of logical blocks in the extent
 *
 * This function tries to invalidate extent of logical blocks.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_invalidate_logical_extent(struct ssdfs_segment_info *si,
					    u32 start_off, u32 blks_count)
{
	struct ssdfs_blk2off_table *blk2off_tbl = NULL;
	struct ssdfs_phys_offset_descriptor *off_desc = NULL;
	struct ssdfs_offset_position pos = {0};
	struct ssdfs_invalidating_extent extent;
	u32 blk;
	u32 upper_blk = start_off + blks_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("si %p, seg %llu, start_off %u, blks_count %u\n",
		  si, si->seg_id, start_off, blks_count);
#else
	SSDFS_DBG("si %p, seg %llu, start_off %u, blks_count %u\n",
		  si, si->seg_id, start_off, blks_count);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	blk2off_tbl = si->blk2off_table;

	ssdfs_account_invalidated_user_data_pages(si, blks_count);

	extent.peb_index = U16_MAX;
	extent.start_blk = start_off;
	extent.len = 0;

	for (blk = start_off; blk < upper_blk; blk++) {
		u16 peb_index = U16_MAX;

		if (blk >= U16_MAX) {
			SSDFS_ERR("invalid logical block number: %u\n",
				  blk);
			return -ERANGE;
		}

		off_desc = ssdfs_blk2off_table_convert(blk2off_tbl,
							(u16)blk,
							&peb_index,
							NULL, &pos);
		if (IS_ERR_OR_NULL(off_desc)) {
			err = !off_desc ? -ERANGE : PTR_ERR(off_desc);

			SSDFS_ERR("fail to convert logical block: "
				  "blk %u, err %d\n",
				  blk, err);

			ssdfs_segment_invalidate_peb_logical_extent(si,
								    &extent);
			return err;
		}

		if (extent.peb_index >= U16_MAX) {
			extent.peb_index = peb_index;
			extent.len++;
		} else if (extent.peb_index != peb_index) {
			err = ssdfs_segment_invalidate_peb_logical_extent(si,
								      &extent);
			if (unlikely(err)) {
				SSDFS_ERR("fail to invalidate logical extent: "
					  "seg %llu, peb_index %u, "
					  "start_blk %u, len %u, err %d\n",
					  si->seg_id, extent.peb_index,
					  extent.start_blk, extent.len,
					  err);
				return err;
			}

			extent.peb_index = peb_index;
			extent.start_blk = blk;
			extent.len = 1;
		} else {
			extent.len++;
		}
	}

	if (extent.len > 0) {
		err = ssdfs_segment_invalidate_peb_logical_extent(si, &extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate logical extent: "
				  "seg %llu, peb_index %u, "
				  "start_blk %u, len %u, err %d\n",
				  si->seg_id, extent.peb_index,
				  extent.start_blk, extent.len,
				  err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_segment_invalidate_logical_block() - invalidate logical block
 * @si: segment info
 * @blk_offset: logical block number
 *
 * This function tries to invalidate a logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_invalidate_logical_block(struct ssdfs_segment_info *si,
					   u32 blk_offset)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("si %p, seg %llu, blk_offset %u\n",
		  si, si->seg_id, blk_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_segment_invalidate_logical_extent(si, blk_offset, 1);
}

/*
 * ssdfs_segment_migrate_range_async() - migrate range by flush thread
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to migrate the range by flush thread
 * asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_migrate_range_async(struct ssdfs_segment_info *si,
				      struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_COLLECT_GARBAGE_REQ,
					    SSDFS_MIGRATE_RANGE,
					    SSDFS_REQ_ASYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_migrate_pre_alloc_page_async() - migrate page by flush thread
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to migrate the pre-allocated page by flush thread
 * asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_migrate_pre_alloc_page_async(struct ssdfs_segment_info *si,
					    struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_COLLECT_GARBAGE_REQ,
					    SSDFS_MIGRATE_PRE_ALLOC_PAGE,
					    SSDFS_REQ_ASYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}

/*
 * ssdfs_segment_migrate_fragment_async() - migrate fragment by flush thread
 * @si: segment info
 * @req: segment request [in|out]
 *
 * This function tries to migrate the fragment by flush thread
 * asynchronously.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_migrate_fragment_async(struct ssdfs_segment_info *si,
					 struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_internal_data(SSDFS_PEB_COLLECT_GARBAGE_REQ,
					    SSDFS_MIGRATE_FRAGMENT,
					    SSDFS_REQ_ASYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}
