/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_tree.c - segment tree implementation.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2026 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include <linux/xarray.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "segment_bitmap.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"
#include "segment_tree.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_seg_tree_folio_leaks;
atomic64_t ssdfs_seg_tree_memory_leaks;
atomic64_t ssdfs_seg_tree_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_seg_tree_cache_leaks_increment(void *kaddr)
 * void ssdfs_seg_tree_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_seg_tree_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_seg_tree_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_seg_tree_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_seg_tree_kfree(void *kaddr)
 * struct folio *ssdfs_seg_tree_alloc_folio(gfp_t gfp_mask,
 *                                          unsigned int order)
 * struct folio *ssdfs_seg_tree_add_batch_folio(struct folio_batch *batch,
 *                                              unsigned int order)
 * void ssdfs_seg_tree_free_folio(struct folio *folio)
 * void ssdfs_seg_tree_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(seg_tree)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(seg_tree)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_seg_tree_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_seg_tree_folio_leaks, 0);
	atomic64_set(&ssdfs_seg_tree_memory_leaks, 0);
	atomic64_set(&ssdfs_seg_tree_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_seg_tree_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_seg_tree_folio_leaks) != 0) {
		SSDFS_ERR("SEGMENT TREE: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_seg_tree_folio_leaks));
	}

	if (atomic64_read(&ssdfs_seg_tree_memory_leaks) != 0) {
		SSDFS_ERR("SEGMENT TREE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_seg_tree_memory_leaks));
	}

	if (atomic64_read(&ssdfs_seg_tree_cache_leaks) != 0) {
		SSDFS_ERR("SEGMENT TREE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_seg_tree_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/******************************************************************************
 *                   SEGMENT OBJECTS QUEUE FUNCTIONALITY                      *
 ******************************************************************************/

static struct kmem_cache *ssdfs_seg_object_info_cachep;

void ssdfs_zero_seg_object_info_cache_ptr(void)
{
	ssdfs_seg_object_info_cachep = NULL;
}

static
void ssdfs_init_seg_object_info_once(void *obj)
{
	struct ssdfs_seg_object_info *soi_obj = obj;

	memset(soi_obj, 0, sizeof(struct ssdfs_seg_object_info));
}

void ssdfs_shrink_seg_object_info_cache(void)
{
	if (ssdfs_seg_object_info_cachep)
		kmem_cache_shrink(ssdfs_seg_object_info_cachep);
}

void ssdfs_destroy_seg_object_info_cache(void)
{
	if (ssdfs_seg_object_info_cachep)
		kmem_cache_destroy(ssdfs_seg_object_info_cachep);
}

int ssdfs_init_seg_object_info_cache(void)
{
	ssdfs_seg_object_info_cachep =
		kmem_cache_create("ssdfs_seg_object_info_cache",
				  sizeof(struct ssdfs_seg_object_info), 0,
				  SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
				  ssdfs_init_seg_object_info_once);
	if (!ssdfs_seg_object_info_cachep) {
		SSDFS_ERR("unable to create segment object info cache\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_seg_objects_queue_init() - initialize segment objects queue
 * @soq: initialized segment objects queue
 */
void ssdfs_seg_objects_queue_init(struct ssdfs_seg_objects_queue *soq)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!soq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock_init(&soq->lock);
	INIT_LIST_HEAD(&soq->list);
}

/*
 * is_ssdfs_seg_objects_queue_empty() - check that segment objects queue is empty
 * @soq: segment objects queue
 */
bool is_ssdfs_seg_objects_queue_empty(struct ssdfs_seg_objects_queue *soq)
{
	bool is_empty;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!soq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&soq->lock);
	is_empty = list_empty_careful(&soq->list);
	spin_unlock(&soq->lock);

	return is_empty;
}

/*
 * ssdfs_seg_objects_queue_add_head() - add segment object info at the head
 * @soq: segment objects queue
 * @soi: segment object info
 */
void ssdfs_seg_objects_queue_add_head(struct ssdfs_seg_objects_queue *soq,
				      struct ssdfs_seg_object_info *soi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!soq || !soi || !soi->si);

	SSDFS_DBG("seg_id %llu\n", soi->si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&soq->lock);
	list_add(&soi->list, &soq->list);
	spin_unlock(&soq->lock);
}

/*
 * ssdfs_seg_object_queue_add_tail() - add segment object info at the tail
 * @soq: segment objects queue
 * @soi: segment object info
 */
void ssdfs_seg_objects_queue_add_tail(struct ssdfs_seg_objects_queue *soq,
				      struct ssdfs_seg_object_info *soi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!soq || !soi || !soi->si);

	SSDFS_DBG("seg_id %llu\n", soi->si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&soq->lock);
	list_add_tail(&soi->list, &soq->list);
	spin_unlock(&soq->lock);
}

/*
 * ssdfs_seg_objects_queue_remove_first() - remove first object from queue
 * @soq: segment objects queue
 * @soi: first segment object info [out]
 *
 * This function get first segment object info in @soq,
 * remove it from queue and return as @soi.
 *
 * RETURN:
 * [success] - @soi contains pointer on segment object info.
 * [failure] - error code:
 *
 * %-ENODATA     - queue is empty.
 * %-ENOENT      - first entry is NULL.
 */
int ssdfs_seg_objects_queue_remove_first(struct ssdfs_seg_objects_queue *soq,
					 struct ssdfs_seg_object_info **soi)
{
	bool is_empty;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!soq || !soi);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&soq->lock);
	is_empty = list_empty_careful(&soq->list);
	if (!is_empty) {
		*soi = list_first_entry_or_null(&soq->list,
						struct ssdfs_seg_object_info,
						list);
		if (!*soi) {
			SSDFS_WARN("first entry is NULL\n");
			err = -ENOENT;
		} else
			list_del(&(*soi)->list);
	}
	spin_unlock(&soq->lock);

	if (is_empty) {
		SSDFS_WARN("segment object info queue is empty\n");
		err = -ENODATA;
	}

	return err;
}

/*
 * ssdfs_seg_objects_queue_remove_all() - remove all items from queue
 * @soq: segment objects queue
 *
 * This function removes all items from the queue.
 */
void ssdfs_seg_objects_queue_remove_all(struct ssdfs_seg_objects_queue *soq)
{
	bool is_empty;
	LIST_HEAD(tmp_list);
	struct list_head *this, *next;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!soq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&soq->lock);
	is_empty = list_empty_careful(&soq->list);
	if (!is_empty)
		list_replace_init(&soq->list, &tmp_list);
	spin_unlock(&soq->lock);

	if (is_empty)
		return;

	list_for_each_safe(this, next, &tmp_list) {
		struct ssdfs_seg_object_info *soi;

		soi = list_entry(this, struct ssdfs_seg_object_info, list);
		list_del(&soi->list);

		ssdfs_seg_object_info_free(soi);
	}
}

/*
 * ssdfs_seg_object_info_alloc() - allocate memory for segment object info
 */
struct ssdfs_seg_object_info *ssdfs_seg_object_info_alloc(void)
{
	struct ssdfs_seg_object_info *ptr;
	unsigned int nofs_flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_seg_object_info_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	nofs_flags = memalloc_nofs_save();
	ptr = kmem_cache_alloc(ssdfs_seg_object_info_cachep, GFP_KERNEL);
	memalloc_nofs_restore(nofs_flags);

	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for segment object info\n");
		return ERR_PTR(-ENOMEM);
	}

	ssdfs_seg_tree_cache_leaks_increment(ptr);

	return ptr;
}

/*
 * ssdfs_seg_object_info_free() - free memory for segment object info
 */
void ssdfs_seg_object_info_free(struct ssdfs_seg_object_info *soi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_seg_object_info_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!soi)
		return;

	ssdfs_seg_tree_cache_leaks_decrement(soi);
	kmem_cache_free(ssdfs_seg_object_info_cachep, soi);
}

/*
 * ssdfs_seg_object_info_init() - segment object info initialization
 * @soi: segment object info
 * @si: pointer on segment object
 */
void ssdfs_seg_object_info_init(struct ssdfs_seg_object_info *soi,
				struct ssdfs_segment_info *si)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!soi || !si);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(soi, 0, sizeof(struct ssdfs_seg_object_info));

	INIT_LIST_HEAD(&soi->list);
	soi->si = si;
}

/******************************************************************************
 *                    SEGMENTS TREE SHRINKER FUNCTIONALITY                    *
 ******************************************************************************/

/*
 * ssdfs_segs_tree_can_be_shrunk() - check if a segment object can be evicted
 * @si: pointer on segment object
 *
 * This method checks whether an idle segment object is a candidate
 * for eviction under memory pressure. The checks are intentionally
 * conservative: any sign of in-flight work causes the segment to be
 * skipped.
 *
 * RETURN:
 * [true]  - segment can be evicted
 * [false] - segment must be kept
 */
static
bool ssdfs_segs_tree_can_be_shrunk(struct ssdfs_segment_info *si)
{
	struct ssdfs_peb_container *pebc;
	struct ssdfs_peb_info *pebi;
	u64 peb_id;
	bool is_rq_empty;
	bool is_fq_empty;
	bool peb_has_dirty_folios = false;
	bool is_blk_bmap_dirty = false;
	u32 reqs_count;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_unmount_in_progress(si))
		return false;

	if (atomic_read(&si->refs_count) != 0)
		return false;

	switch (atomic_read(&si->obj_state)) {
	case SSDFS_SEG_OBJECT_CREATED:
		/* eligible */
		break;

	default:
		return false;
	}

	switch (si->seg_type) {
	case SSDFS_SEGBMAP_SEG_TYPE:
	case SSDFS_MAPTBL_SEG_TYPE:
		return false;

	default:
		break;
	}

	switch (atomic_read(&si->activity_type)) {
	case SSDFS_SEG_OBJECT_NO_ACTIVITY:
	case SSDFS_SEG_OBJECT_REGULAR_ACTIVITY:
		break;

	default:
		return false;
	}

	for (i = 0; i < si->pebs_count; i++) {
		pebc = &si->peb_array[i];

		is_rq_empty = is_ssdfs_requests_queue_empty(READ_RQ_PTR(pebc));
		is_fq_empty = !have_flush_requests(pebc);

		is_blk_bmap_dirty =
			is_ssdfs_segment_blk_bmap_dirty(&si->blk_bmap, i);

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi))
			return false;

		ssdfs_peb_current_log_lock(pebi);
		peb_has_dirty_folios = ssdfs_peb_has_dirty_folios(pebi);
		peb_id = pebi->peb_id;
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_id %llu, peb_id %llu, refs_count %d, "
			  "peb_has_dirty_folios %#x, "
			  "not empty: (read %#x, flush %#x), "
			  "is_blk_bmap_dirty %#x\n",
			  si->seg_id, peb_id,
			  atomic_read(&si->refs_count),
			  peb_has_dirty_folios,
			  !is_rq_empty, !is_fq_empty,
			  is_blk_bmap_dirty);
#endif /* CONFIG_SSDFS_DEBUG */

		if (!is_rq_empty || !is_fq_empty ||
		    peb_has_dirty_folios || is_blk_bmap_dirty)
			return false;
	}

	spin_lock(&si->protection.cno_lock);
	reqs_count = si->protection.reqs_count;
	spin_unlock(&si->protection.cno_lock);

	if (reqs_count > 0)
		return false;

	return true;
}

/*
 * ssdfs_segs_tree_count_objects() - count shrinkable segment objects
 * @shrink: pointer on shrinker descriptor
 * @sc: shrink control descriptor
 *
 * This method estimates the number of idle segment objects that could
 * be evicted to reclaim memory.
 *
 * RETURN: count of shrinkable objects, or SHRINK_EMPTY if none.
 */
static
unsigned long ssdfs_segs_tree_count_objects(struct shrinker *shrink,
					    struct shrink_control *sc)
{
	struct ssdfs_fs_info *fsi = shrink->private_data;
	struct ssdfs_segment_info *si;
	unsigned long count = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&fsi->segs_tree.segs_list_lock);
	list_for_each_entry(si, &fsi->segs_tree.segs_list, list) {
		if (atomic_read(&si->refs_count) != 0)
			continue;

		if (atomic_read(&si->obj_state) != SSDFS_SEG_OBJECT_CREATED)
			continue;

		if (si->seg_type == SSDFS_SEGBMAP_SEG_TYPE ||
		    si->seg_type == SSDFS_MAPTBL_SEG_TYPE)
			continue;

		count++;
	}
	spin_unlock(&fsi->segs_tree.segs_list_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("shrinkable segs count %lu\n", count);
#endif /* CONFIG_SSDFS_DEBUG */

	return count ? count : SHRINK_EMPTY;
}

/*
 * ssdfs_segs_tree_scan_objects() - evict idle segment objects under pressure
 * @shrink: pointer on shrinker descriptor
 * @sc: shrink control descriptor
 *
 * This method evicts up to @sc->nr_to_scan idle segment objects from the
 * segments tree, queuing them for asynchronous destruction by the GC thread.
 * It operates in two phases to avoid sleeping while holding the tree lock:
 *
 *  Phase 1 (under tree write lock): identify eligible segments, remove them
 *          from the xarray and the global list, mark them PRE_DELETED, and
 *          collect them in a local list.
 *
 *  Phase 2 (lock released): destroy segment objects in the local list.
 *
 * RETURN: number of objects freed, or SHRINK_STOP on context mismatch.
 */
static
unsigned long ssdfs_segs_tree_scan_objects(struct shrinker *shrink,
					   struct shrink_control *sc)
{
	struct ssdfs_fs_info *fsi = shrink->private_data;
	struct ssdfs_segment_info *si, *tmp;
	LIST_HEAD(to_destroy);
	unsigned long freed = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p, nr_to_scan %lu, gfp_mask %#x\n",
		  fsi, sc->nr_to_scan, sc->gfp_mask);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(sc->gfp_mask & __GFP_FS))
		return SHRINK_STOP;

	down_write(&fsi->segs_tree.lock);

	list_for_each_entry_safe(si, tmp, &fsi->segs_tree.segs_list, list) {
		if (freed >= sc->nr_to_scan)
			break;

		if (!ssdfs_segs_tree_can_be_shrunk(si))
			continue;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("shrink segment: seg_id %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

		xa_erase(&fsi->segs_tree.objects, si->seg_id);
		ssdfs_sysfs_delete_seg_group(si);

		spin_lock(&fsi->segs_tree.segs_list_lock);
		list_del_init(&si->list);
		if (fsi->segs_tree.segs_count > 0)
			fsi->segs_tree.segs_count--;
		spin_unlock(&fsi->segs_tree.segs_list_lock);

		atomic_set(&si->obj_state, SSDFS_SEG_OBJECT_PRE_DELETED);

		list_add_tail(&si->list, &to_destroy);
		freed++;
	}

	up_write(&fsi->segs_tree.lock);

	if (freed == 0)
		return 0;

	list_for_each_entry_safe(si, tmp, &to_destroy, list) {
		list_del_init(&si->list);

		err = ssdfs_segment_destroy_object(si);
		if (err) {
			SSDFS_WARN("fail to destroy: "
				   "seg %llu, err %d\n",
				   si->seg_id, err);
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("freed %lu segment objects\n", freed);
#endif /* CONFIG_SSDFS_DEBUG */

	return freed;
}

/******************************************************************************
 *                        SEGMENTS TREE FUNCTIONALITY                         *
 ******************************************************************************/

/*
 * ssdfs_segment_tree_create() - create segments tree
 * @fsi: pointer on shared file system object
 */
int ssdfs_segment_tree_create(struct ssdfs_fs_info *fsi)
{
	size_t dentries_desc_size =
		sizeof(struct ssdfs_dentries_btree_descriptor);
	size_t extents_desc_size =
		sizeof(struct ssdfs_extents_btree_descriptor);
	size_t xattr_desc_size =
		sizeof(struct ssdfs_xattr_btree_descriptor);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(&fsi->segs_tree, 0, sizeof(struct ssdfs_segment_tree));

	ssdfs_memcpy(&fsi->segs_tree.dentries_btree,
		     0, dentries_desc_size,
		     &fsi->vh->dentries_btree,
		     0, dentries_desc_size,
		     dentries_desc_size);
	ssdfs_memcpy(&fsi->segs_tree.extents_btree, 0, extents_desc_size,
		     &fsi->vh->extents_btree, 0, extents_desc_size,
		     extents_desc_size);
	ssdfs_memcpy(&fsi->segs_tree.xattr_btree, 0, xattr_desc_size,
		     &fsi->vh->xattr_btree, 0, xattr_desc_size,
		     xattr_desc_size);

	fsi->segs_tree.lnodes_seg_log_pages =
		le16_to_cpu(fsi->vh->lnodes_seg_log_pages);
	fsi->segs_tree.hnodes_seg_log_pages =
		le16_to_cpu(fsi->vh->hnodes_seg_log_pages);
	fsi->segs_tree.inodes_seg_log_pages =
		le16_to_cpu(fsi->vh->inodes_seg_log_pages);
	fsi->segs_tree.user_data_log_pages =
		le16_to_cpu(fsi->vh->user_data_log_pages);
	fsi->segs_tree.default_log_pages = SSDFS_LOG_PAGES_DEFAULT;

	init_rwsem(&fsi->segs_tree.lock);
	xa_init(&fsi->segs_tree.objects);

	spin_lock_init(&fsi->segs_tree.segs_list_lock);
	INIT_LIST_HEAD(&fsi->segs_tree.segs_list);
	fsi->segs_tree.segs_count = 0;

	fsi->segs_tree.shrinker =
			shrinker_alloc(0, "ssdfs-segs-tree:%s",
					fsi->sb->s_id);
	if (!fsi->segs_tree.shrinker) {
		SSDFS_WARN("fail to allocate segments tree shrinker\n");
	} else {
		fsi->segs_tree.shrinker->count_objects =
					ssdfs_segs_tree_count_objects;
		fsi->segs_tree.shrinker->scan_objects =
					ssdfs_segs_tree_scan_objects;
		fsi->segs_tree.shrinker->seeks = DEFAULT_SEEKS;
		fsi->segs_tree.shrinker->private_data = fsi;
		shrinker_register(fsi->segs_tree.shrinker);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DONE: create segment tree\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_segment_tree_destroy_segment_objects() - destroy all segment objects
 * @fsi: pointer on shared file system object
 */
static
void ssdfs_segment_tree_destroy_segment_objects(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_segment_info *si;
	unsigned long seg_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	xa_for_each(&fsi->segs_tree.objects, seg_id, si) {
		if (!si) {
			SSDFS_WARN("segment object is NULL: "
				   "seg_id %lu\n", seg_id);
			continue;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("si %p, seg_id %llu\n", si, si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

		if (atomic_read(&si->refs_count) > 0) {
			wait_queue_head_t *wq = &si->object_queue;
			int res;

			res = wait_event_killable_timeout(*wq,
				atomic_read(&si->refs_count) <= 0,
				SSDFS_DEFAULT_TIMEOUT);
			if (res < 0) {
				SSDFS_ERR("si %p, seg_id %llu\n",
					  si, si->seg_id);
				WARN_ON(1);
			} else if (res > 1) {
				/*
				 * Condition changed before timeout
				 */
			} else {
				/* timeout is elapsed */
				SSDFS_ERR("si %p, seg_id %llu\n",
					  si, si->seg_id);
				WARN_ON(1);
			}
		}

		spin_lock(&fsi->segs_tree.segs_list_lock);
		if (!list_empty(&si->list)) {
			list_del_init(&si->list);
			if (fsi->segs_tree.segs_count > 0)
				fsi->segs_tree.segs_count--;
		}
		spin_unlock(&fsi->segs_tree.segs_list_lock);

		xa_erase(&fsi->segs_tree.objects, seg_id);

		err = ssdfs_segment_destroy_object(si);
		if (err) {
			SSDFS_WARN("fail to destroy segment object: "
				   "seg %llu, err %d\n",
				   si->seg_id, err);
		}
	}
}

/*
 * ssdfs_segment_tree_destroy() - destroy segments tree
 * @fsi: pointer on shared file system object
 */
void ssdfs_segment_tree_destroy(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_seg_objects_queue *soq;
	struct ssdfs_seg_object_info *soi;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fsi->segs_tree.shrinker) {
		shrinker_free(fsi->segs_tree.shrinker);
		fsi->segs_tree.shrinker = NULL;
	}

	soq = &fsi->pre_destroyed_segs_rq;

	down_write(&fsi->segs_tree.lock);

	while (!is_ssdfs_seg_objects_queue_empty(soq)) {
		err = ssdfs_seg_objects_queue_remove_first(soq, &soi);
		if (err == -ENODATA) {
			/* empty queue */
			err = 0;
			break;
		} else if (err == -ENOENT) {
			SSDFS_WARN("request queue contains NULL request\n");
			err = 0;
			continue;
		} else if (unlikely(err < 0)) {
			SSDFS_CRIT("fail to get request from the queue: "
				   "err %d\n",
				   err);
			break;
		}

		if (!soi->si) {
			SSDFS_ERR("segment object pointer is NULL\n");
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("DESTROY PRE-DELETED SEGMENT: seg_id %llu\n",
				  soi->si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_segment_destroy_object(soi->si);
			if (err) {
				SSDFS_WARN("fail to destroy: "
					   "seg %llu, err %d\n",
					   soi->si->seg_id, err);
			}
		}

		ssdfs_seg_object_info_free(soi);
	}

	ssdfs_segment_tree_destroy_segment_objects(fsi);
	xa_destroy(&fsi->segs_tree.objects);

	up_write(&fsi->segs_tree.lock);
}

/*
 * ssdfs_segment_tree_add() - add segment object into the tree
 * @fsi: pointer on shared file system object
 * @si: pointer on segment object
 *
 * This method tries to add the valid pointer on segment
 * object into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM  - fail to allocate memory.
 * %-EEXIST  - segment has been added already.
 */
int ssdfs_segment_tree_add(struct ssdfs_fs_info *fsi,
			   struct ssdfs_segment_info *si)
{
	struct ssdfs_segment_info *object;
	void *result;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !si);

	SSDFS_DBG("fsi %p, si %p, seg %llu\n",
		  fsi, si, si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fsi->segs_tree.lock);

	object = xa_load(&fsi->segs_tree.objects, si->seg_id);
	if (object) {
		err = -EEXIST;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("object exists for segment %llu\n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_add_segment;
	}

	result = xa_store(&fsi->segs_tree.objects, si->seg_id, si, GFP_KERNEL);
	if (xa_is_err(result)) {
		err = xa_err(result);
		SSDFS_ERR("fail to store segment object: "
			  "seg %llu, err %d\n",
			  si->seg_id, err);
		goto finish_add_segment;
	}

	ssdfs_segment_get_object(si);

	spin_lock(&fsi->segs_tree.segs_list_lock);
	list_add_tail(&si->list, &fsi->segs_tree.segs_list);
	fsi->segs_tree.segs_count++;
	spin_unlock(&fsi->segs_tree.segs_list_lock);

finish_add_segment:
	up_write(&fsi->segs_tree.lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_segment_tree_remove() - remove segment object from the tree
 * @fsi: pointer on shared file system object
 * @si: pointer on segment object
 *
 * This method tries to remove the valid pointer on segment
 * object from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA  - segment tree hasn't object for @si.
 * %-ENOENT   - segment has pre-deleted state.
 * %-EBUSY    - segment object is referenced yet.
 */
int ssdfs_segment_tree_remove(struct ssdfs_fs_info *fsi,
			      struct ssdfs_segment_info *si)
{
	struct ssdfs_segment_info *object;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !si);

	SSDFS_DBG("fsi %p, si %p, seg %llu\n",
		  fsi, si, si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fsi->segs_tree.lock);

	switch (atomic_read(&si->obj_state)) {
	case SSDFS_SEG_OBJECT_PRE_DELETED:
		err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu has pre-deleted state\n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_remove_segment;

	default:
		/* continue logic */
		break;
	}

	if (atomic_read(&si->refs_count) > 0) {
		err = -EBUSY;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu has refs_count %d\n",
			  si->seg_id, atomic_read(&si->refs_count));
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_remove_segment;
	}

	object = xa_erase(&fsi->segs_tree.objects, si->seg_id);
	if (!object) {
		err = -ENODATA;
		SSDFS_ERR("failed to remove segment object: "
			  "seg %llu\n",
			  si->seg_id);
		goto finish_remove_segment;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(object != si);
#endif /* CONFIG_SSDFS_DEBUG */

	/*
	 * Prevent from error of creation
	 * the same segment in another thread.
	 */
	ssdfs_sysfs_delete_seg_group(si);

	spin_lock(&fsi->segs_tree.segs_list_lock);
	if (!list_empty(&si->list)) {
		list_del_init(&si->list);
		if (fsi->segs_tree.segs_count > 0)
			fsi->segs_tree.segs_count--;
	}
	spin_unlock(&fsi->segs_tree.segs_list_lock);

finish_remove_segment:
	up_write(&fsi->segs_tree.lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_segment_tree_find() - find segment object in the tree
 * @fsi: pointer on shared file system object
 * @seg_id: segment number
 *
 * This method tries to find the valid pointer on segment
 * object for @seg_id.
 *
 * RETURN:
 * [success] - pointer on found segment object
 * [failure] - error code:
 *
 * %-EINVAL   - invalid input.
 * %-ENODATA  - segment tree hasn't object for @seg_id.
 */
struct ssdfs_segment_info *
ssdfs_segment_tree_find(struct ssdfs_fs_info *fsi, u64 seg_id)
{
	struct ssdfs_segment_info *object;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	if (seg_id >= fsi->nsegs) {
		SSDFS_ERR("seg_id %llu >= fsi->nsegs %llu\n",
			  seg_id, fsi->nsegs);
		return ERR_PTR(-EINVAL);
	}

	SSDFS_DBG("fsi %p, seg_id %llu\n",
		  fsi, seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&fsi->segs_tree.lock);

	object = xa_load(&fsi->segs_tree.objects, seg_id);
	if (!object) {
		object = ERR_PTR(-ENODATA);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find segment object: "
			  "seg %llu\n",
			  seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
		ssdfs_segment_get_object(object);
	}

	up_read(&fsi->segs_tree.lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return object;
}

/*
 * ssdfs_segment_tree_get_segs_count() - get count of created segment objects
 * @fsi: pointer on shared file system object
 *
 * This method returns the number of segment objects currently tracked
 * in the global segments list.
 *
 * RETURN: count of created segment objects.
 */
u64 ssdfs_segment_tree_get_segs_count(struct ssdfs_fs_info *fsi)
{
	u64 count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&fsi->segs_tree.segs_list_lock);
	count = fsi->segs_tree.segs_count;
	spin_unlock(&fsi->segs_tree.segs_list_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segs_count %llu\n", count);
#endif /* CONFIG_SSDFS_DEBUG */

	return count;
}
