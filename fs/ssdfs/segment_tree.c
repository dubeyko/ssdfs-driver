/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_tree.c - segment tree implementation.
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

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "segment_bitmap.h"
#include "folio_array.h"
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
	u64 nsegs;
	u64 capacity;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->segs_tree =
		ssdfs_seg_tree_kzalloc(sizeof(struct ssdfs_segment_tree),
					GFP_KERNEL);
	if (!fsi->segs_tree) {
		SSDFS_ERR("fail to allocate segment tree's root object\n");
		return -ENOMEM;
	}

	ssdfs_memcpy(&fsi->segs_tree->dentries_btree,
		     0, dentries_desc_size,
		     &fsi->vh->dentries_btree,
		     0, dentries_desc_size,
		     dentries_desc_size);
	ssdfs_memcpy(&fsi->segs_tree->extents_btree, 0, extents_desc_size,
		     &fsi->vh->extents_btree, 0, extents_desc_size,
		     extents_desc_size);
	ssdfs_memcpy(&fsi->segs_tree->xattr_btree, 0, xattr_desc_size,
		     &fsi->vh->xattr_btree, 0, xattr_desc_size,
		     xattr_desc_size);

	fsi->segs_tree->lnodes_seg_log_pages =
		le16_to_cpu(fsi->vh->lnodes_seg_log_pages);
	fsi->segs_tree->hnodes_seg_log_pages =
		le16_to_cpu(fsi->vh->hnodes_seg_log_pages);
	fsi->segs_tree->inodes_seg_log_pages =
		le16_to_cpu(fsi->vh->inodes_seg_log_pages);
	fsi->segs_tree->user_data_log_pages =
		le16_to_cpu(fsi->vh->user_data_log_pages);
	fsi->segs_tree->default_log_pages = SSDFS_LOG_PAGES_DEFAULT;

	nsegs = fsi->nsegs + SSDFS_SEG_OBJ_PTR_PER_PAGE - 1;
	capacity = div_u64(nsegs, SSDFS_SEG_OBJ_PTR_PER_PAGE);

	if (capacity >= U32_MAX) {
		err = -E2BIG;
		SSDFS_ERR("fail to create segment tree: "
			  "capacity %llu is too huge\n",
			  capacity);
		goto free_memory;
	}

	init_rwsem(&fsi->segs_tree->lock);
	fsi->segs_tree->capacity = (u32)capacity;

	err = ssdfs_create_folio_array(&fsi->segs_tree->folios,
					get_order(PAGE_SIZE),
					(u32)capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create folio array: "
			  "capacity %llu, err %d\n",
			  capacity, err);
		goto free_memory;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DONE: create segment tree\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

free_memory:
	ssdfs_seg_tree_kfree(fsi->segs_tree);
	fsi->segs_tree = NULL;

	return err;
}

/*
 * ssdfs_segment_tree_destroy_objects_in_folio() - destroy objects in folio
 * @fsi: pointer on shared file system object
 * @folio: pointer on memory folio
 */
static
void ssdfs_segment_tree_destroy_objects_in_folio(struct ssdfs_fs_info *fsi,
						 struct folio *folio)
{
	struct ssdfs_segment_info **kaddr;
	size_t ptr_size = sizeof(struct ssdfs_segment_info *);
	size_t ptrs_per_page = PAGE_SIZE / ptr_size;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio || !fsi || !fsi->segs_tree);

	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_get(folio);
	ssdfs_folio_lock(folio);

	kaddr = (struct ssdfs_segment_info **)kmap_local_folio(folio, 0);

	for (i = 0; i < ptrs_per_page; i++) {
		struct ssdfs_segment_info *si = *(kaddr + i);

		if (si) {
			wait_queue_head_t *wq = &si->object_queue;
			int res;
			int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("si %p, seg_id %llu\n", si, si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

			if (atomic_read(&si->refs_count) > 0) {
				ssdfs_folio_unlock(folio);

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

				ssdfs_folio_lock(folio);
			}

			err = ssdfs_segment_destroy_object(si);
			if (err) {
				SSDFS_WARN("fail to destroy segment object: "
					   "seg %llu, err %d\n",
					   si->seg_id, err);
			}
		}

	}

	kunmap_local(kaddr);

	__ssdfs_clear_dirty_folio(folio);

	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
	SSDFS_DBG("folio_index %ld, flags %#lx\n",
		  folio->index, folio->flags);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_segment_tree_destroy_objects_in_array() - destroy objects in array
 * @fsi: pointer on shared file system object
 * @batch: memory folio batch
 */
static
void ssdfs_segment_tree_destroy_objects_in_array(struct ssdfs_fs_info *fsi,
						 struct folio_batch *batch)
{
	struct folio *folio;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !batch);

	SSDFS_DBG("batch %p, batch_count %u\n",
		  batch,
		  folio_batch_count(batch));
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < folio_batch_count(batch); i++) {
		folio = batch->folios[i];

		if (!folio) {
			SSDFS_WARN("folio pointer is NULL: "
				   "index %d\n",
				   i);
			continue;
		}

		ssdfs_segment_tree_destroy_objects_in_folio(fsi, folio);
	}
}

/*
 * ssdfs_segment_tree_destroy_segment_objects() - destroy all segment objects
 * @fsi: pointer on shared file system object
 */
static
void ssdfs_segment_tree_destroy_segment_objects(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_folio_array *folios;
	struct folio_batch fbatch;
	pgoff_t index = 0;
	pgoff_t end = fsi->segs_tree->capacity;
	int nr_folios;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segs_tree);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	folios = &fsi->segs_tree->folios;
	folio_batch_init(&fbatch);

	do {
		folio_batch_reinit(&fbatch);

		err = ssdfs_folio_array_lookup_range(folios,
						     &index, end,
						     SSDFS_DIRTY_FOLIO_TAG,
						     fsi->segs_tree->capacity,
						     &fbatch);
		if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find dirty folios: "
				  "start %lu, end %lu, err %d\n",
				  index, end, err);
#endif /* CONFIG_SSDFS_DEBUG */
			return;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find dirty folios: "
				  "start %lu, end %lu, err %d\n",
				  index, end, err);
			return;
		}

		nr_folios = folio_batch_count(&fbatch);

		if (nr_folios > 0) {
			ssdfs_segment_tree_destroy_objects_in_array(fsi,
								    &fbatch);

			for (i = 0; i < nr_folios; i++) {
				struct folio *folio;

				folio = fbatch.folios[i];

				if (!folio)
					continue;

				ssdfs_folio_array_clear_dirty_folio(folios,
								folio->index);
			}

			index = fbatch.folios[nr_folios - 1]->index + 1;
		}
	} while (folio_batch_count(&fbatch) > 0);
}

/*
 * ssdfs_segment_tree_destroy() - destroy segments tree
 * @fsi: pointer on shared file system object
 */
void ssdfs_segment_tree_destroy(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segs_tree);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!fsi->segs_tree)
		return;

	down_write(&fsi->segs_tree->lock);
	ssdfs_segment_tree_destroy_segment_objects(fsi);
	ssdfs_destroy_folio_array(&fsi->segs_tree->folios);
	up_write(&fsi->segs_tree->lock);

	ssdfs_seg_tree_kfree(fsi->segs_tree);
	fsi->segs_tree = NULL;
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
	pgoff_t folio_index;
	u32 object_index;
	struct folio *folio;
	struct ssdfs_segment_info **kaddr, *object;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segs_tree || !si);

	SSDFS_DBG("fsi %p, si %p, seg %llu\n",
		  fsi, si, si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	folio_index = div_u64_rem(si->seg_id, SSDFS_SEG_OBJ_PTR_PER_PAGE,
				 &object_index);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio_index %lu, object_index %u\n",
		  folio_index, object_index);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fsi->segs_tree->lock);

	folio = ssdfs_folio_array_grab_folio(&fsi->segs_tree->folios,
					     folio_index);
	if (!folio) {
		err = -ENOMEM;
		SSDFS_ERR("fail to grab folio: folio_index %lu\n",
			  folio_index);
		goto finish_add_segment;
	}

	kaddr = (struct ssdfs_segment_info **)kmap_local_folio(folio, 0);
	object = *(kaddr + object_index);
	if (object) {
		err = -EEXIST;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("object exists for segment %llu\n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
	} else
		*(kaddr + object_index) = si;
	kunmap_local(kaddr);

	folio_mark_uptodate(folio);
	if (!folio_test_dirty(folio)) {
		ssdfs_folio_array_set_folio_dirty(&fsi->segs_tree->folios,
						  folio_index);
	}

	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
	SSDFS_DBG("folio_index %ld, flags %#lx\n",
		  folio->index, folio->flags);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!err)
		ssdfs_segment_get_object(si);

finish_add_segment:
	up_write(&fsi->segs_tree->lock);

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
	pgoff_t folio_index;
	u32 object_index;
	struct folio *folio;
	struct ssdfs_segment_info **kaddr, *object;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segs_tree || !si);

	SSDFS_DBG("fsi %p, si %p, seg %llu\n",
		  fsi, si, si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	folio_index = div_u64_rem(si->seg_id, SSDFS_SEG_OBJ_PTR_PER_PAGE,
				  &object_index);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio_index %lu, object_index %u\n",
		  folio_index, object_index);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&fsi->segs_tree->lock);

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

	folio = ssdfs_folio_array_get_folio_locked(&fsi->segs_tree->folios,
						   folio_index);
	if (IS_ERR(folio)) {
		err = -ENODATA;
		SSDFS_ERR("failed to remove segment object: "
			  "seg %llu\n",
			  si->seg_id);
		goto finish_remove_segment;
	} else if (!folio) {
		err = -ENODATA;
		SSDFS_ERR("failed to remove segment object: "
			  "seg %llu\n",
			  si->seg_id);
		goto finish_remove_segment;
	}

	kaddr = (struct ssdfs_segment_info **)kmap_local_folio(folio, 0);
	object = *(kaddr + object_index);
	if (!object) {
		err = -ENODATA;
		SSDFS_WARN("object ptr is NULL: "
			   "seg %llu\n",
			   si->seg_id);
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(object != si);
#endif /* CONFIG_SSDFS_DEBUG */
		*(kaddr + object_index) = NULL;
	}
	kunmap_local(kaddr);

	folio_mark_uptodate(folio);
	if (!folio_test_dirty(folio)) {
		ssdfs_folio_array_set_folio_dirty(&fsi->segs_tree->folios,
						  folio_index);
	}

	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	/*
	 * Prevent from error of creation
	 * the same segment in another thread.
	 */
	ssdfs_sysfs_delete_seg_group(si);

finish_remove_segment:
	up_write(&fsi->segs_tree->lock);

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
	pgoff_t folio_index;
	u32 object_index;
	struct folio *folio;
	struct ssdfs_segment_info **kaddr, *object;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segs_tree);

	if (seg_id >= fsi->nsegs) {
		SSDFS_ERR("seg_id %llu >= fsi->nsegs %llu\n",
			  seg_id, fsi->nsegs);
		return ERR_PTR(-EINVAL);
	}

	SSDFS_DBG("fsi %p, seg_id %llu\n",
		  fsi, seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	folio_index = div_u64_rem(seg_id, SSDFS_SEG_OBJ_PTR_PER_PAGE,
				  &object_index);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio_index %lu, object_index %u\n",
		  folio_index, object_index);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&fsi->segs_tree->lock);

	folio = ssdfs_folio_array_get_folio_locked(&fsi->segs_tree->folios,
						   folio_index);
	if (IS_ERR(folio)) {
		object = ERR_PTR(-ENODATA);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find segment object: "
			  "seg %llu\n",
			  seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_find_segment;
	} else if (!folio) {
		object = ERR_PTR(-ENODATA);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find segment object: "
			  "seg %llu\n",
			  seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_find_segment;
	}

	kaddr = (struct ssdfs_segment_info **)kmap_local_folio(folio, 0);

	object = *(kaddr + object_index);

	if (!object) {
		object = ERR_PTR(-ENODATA);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find segment object: "
			  "seg %llu\n",
			  seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	if (!IS_ERR_OR_NULL(object))
		ssdfs_segment_get_object(object);

finish_find_segment:
	up_read(&fsi->segs_tree->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return object;
}
