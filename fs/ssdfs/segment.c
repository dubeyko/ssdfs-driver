//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment.c - segment concept related functionality.
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

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "block_bitmap.h"
#include "offset_translation_table.h"
#include "page_array.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "current_segment.h"
#include "segment_tree.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

static struct kmem_cache *ssdfs_seg_obj_cachep;

static void ssdfs_init_seg_object_once(void *obj)
{
	struct ssdfs_segment_info *seg_obj = obj;

	atomic_set(&seg_obj->refs_count, 0);
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
					SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD |
					SLAB_ACCOUNT,
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
	int err = 0;

	if (!si)
		return 0;

	SSDFS_DBG("seg %llu, seg_state %#x, log_pages %u, "
		  "create_threads %u\n",
		  si->seg_id, atomic_read(&si->seg_state),
		  si->log_pages, si->create_threads);

	refs_count = atomic_read(&si->refs_count);

	SSDFS_DBG("si %p, seg %llu, refs_count %d\n",
		  si, si->seg_id, refs_count);

	if (refs_count != 0) {
		SSDFS_WARN("unable to destroy object of segment %llu: "
			   "refs_count %d\n",
			   si->seg_id, refs_count);
		return -EBUSY;
	}

	if (si->peb_array) {
		struct ssdfs_peb_container *pebc;
		int i;

		for (i = 0; i < si->pebs_count; i++) {
			pebc = &si->peb_array[i];
			ssdfs_peb_container_destroy(pebc);
		}

		kfree(si->peb_array);
	}

	ssdfs_segment_blk_bmap_destroy(&si->blk_bmap);
	ssdfs_blk2off_table_destroy(si->blk2off_table);

	if (!is_ssdfs_requests_queue_empty(&si->create_rq)) {
		SSDFS_WARN("create queue is not empty\n");
		ssdfs_requests_queue_remove_all(&si->create_rq, -ENOSPC);
	}

	ssdfs_sysfs_delete_seg_group(si);

	kmem_cache_free(ssdfs_seg_obj_cachep, si);
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
 *
 * This function tries to create segment object for @seg
 * identification number.
 *
 * RETURN:
 * [success] - pointer on constructed segment object
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
struct ssdfs_segment_info *
ssdfs_segment_create_object(struct ssdfs_fs_info *fsi,
			    u64 seg,
			    int seg_state,
			    u16 seg_type,
			    u16 log_pages,
			    u8 create_threads)
{
	struct ssdfs_segment_info *ptr;
	int state = SSDFS_BLK2OFF_OBJECT_CREATED;
	struct ssdfs_migration_destination *destination;
	int refs_count = fsi->pebs_per_seg;
	int destination_pebs = 0;
	int init_flag, init_state;
	int i;
	int err;

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, seg %llu, seg_state %#x, log_pages %u, "
		  "create_threads %u\n",
		  fsi, seg, seg_state, log_pages, create_threads);

	if (seg >= fsi->nsegs) {
		SSDFS_ERR("requested seg %llu >= nsegs %llu\n",
			  seg, fsi->nsegs);
		return ERR_PTR(-EINVAL);
	}

	ptr = kmem_cache_alloc(ssdfs_seg_obj_cachep, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for segment %llu\n",
			  seg);
		return ERR_PTR(-ENOMEM);
	}

	memset(ptr, 0, sizeof(struct ssdfs_segment_info));

	ptr->seg_id = seg;
	ptr->seg_type = seg_type;
	ptr->log_pages = log_pages;
	ptr->create_threads = create_threads;
	ptr->fsi = fsi;
	atomic_set(&ptr->seg_state, seg_state);
	atomic_set(&ptr->refs_count, 0);
	init_waitqueue_head(&ptr->destruct_queue);
	ssdfs_requests_queue_init(&ptr->create_rq);

	err = ssdfs_sysfs_create_seg_group(ptr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create segment's sysfs group: "
			  "seg %llu, err %d\n",
			  seg, err);
		goto destroy_seg_obj;
	}

	ptr->pebs_count = fsi->pebs_per_seg;
	ptr->peb_array = kcalloc(ptr->pebs_count,
				 sizeof(struct ssdfs_peb_container),
				 GFP_NOFS);
	if (!ptr->peb_array) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory for peb array\n");
		goto destroy_seg_obj;
	}

	atomic_set(&ptr->migration.migrating_pebs, 0);
	init_waitqueue_head(&ptr->migration.wait);
	spin_lock_init(&ptr->migration.lock);

	destination = &ptr->migration.array[SSDFS_LAST_DESTINATION];
	destination->state = SSDFS_EMPTY_DESTINATION;
	destination->destination_pebs = 0;
	destination->shared_peb_index = -1;

	destination = &ptr->migration.array[SSDFS_CREATING_DESTINATION];
	destination->state = SSDFS_EMPTY_DESTINATION;
	destination->destination_pebs = 0;
	destination->shared_peb_index = -1;

	for (i = 0; i < SSDFS_PEB_THREAD_TYPE_MAX; i++)
		init_waitqueue_head(&ptr->wait_queue[i]);

	if (seg_state == SSDFS_SEG_CLEAN) {
		state = SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT;
		init_flag = SSDFS_BLK_BMAP_CREATE;
		init_state = SSDFS_BLK_FREE;
	} else {
		init_flag = SSDFS_BLK_BMAP_INIT;
		init_state = SSDFS_BLK_STATE_MAX;
	}

	err = ssdfs_segment_blk_bmap_create(ptr, fsi->pages_per_peb,
					    init_flag, init_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create segment block bitmap: "
			  "err %d\n", err);
		goto destroy_seg_obj;
	}

	ptr->blk2off_table = ssdfs_blk2off_table_create(fsi, fsi->pages_per_seg,
							SSDFS_SEG_OFF_TABLE,
							state);
	if (!ptr->blk2off_table) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory for translation table\n");
		goto destroy_seg_obj;
	}

	for (i = 0; i < ptr->pebs_count; i++) {
		err = ssdfs_peb_container_create(fsi, seg, i,
						  SEG2PEB_TYPE(seg_type),
						  log_pages, ptr);
		if (err) {
			SSDFS_ERR("fail to create PEB container: "
				  "seg %llu, peb index %d, err %d\n",
				  seg, i, err);
			goto destroy_seg_obj;
		}
	}

	for (i = 0; i < ptr->pebs_count; i++) {
		int cur_refs = atomic_read(&ptr->peb_array[i].dst_peb_refs);
		int items_state = atomic_read(&ptr->peb_array[i].items_state);

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

	destination = &ptr->migration.array[SSDFS_LAST_DESTINATION];
	spin_lock(&ptr->migration.lock);
	destination->shared_peb_index = refs_count;
	destination->destination_pebs = destination_pebs;
	destination->state = SSDFS_VALID_DESTINATION;
	spin_unlock(&ptr->migration.lock);

	/*
	 * The goal of this cycle is to finish segment object
	 * initialization. The segment object should have
	 * valid value of free blocks number.
	 * The ssdfs_peb_get_free_pages() method waits the
	 * ending of PEB object complete initialization.
	 */
	for (i = 0; i < ptr->pebs_count; i++) {
		int peb_free_pages;
		struct ssdfs_peb_container *pebc = &ptr->peb_array[i];

		if (is_peb_container_empty(pebc)) {
			SSDFS_DBG("segment %llu hasn't PEB %d\n",
				  seg, i);
			continue;
		}

		peb_free_pages = ssdfs_peb_get_free_pages(pebc);
		if (unlikely(peb_free_pages < 0)) {
			err = peb_free_pages;
			SSDFS_ERR("fail to calculate PEB's free pages: "
				  "seg %llu, peb index %d, err %d\n",
				  seg, i, err);
			goto destroy_seg_obj;
		}
	}

	return ptr;

destroy_seg_obj:
	ssdfs_segment_destroy_object(ptr);
	return ERR_PTR(err);
}

/*
 * ssdfs_segment_get_object() - increment segment's reference counter
 * @si: pointer on segment object
 */
void ssdfs_segment_get_object(struct ssdfs_segment_info *si)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, refs_count %d\n",
		  si->seg_id, atomic_read(&si->refs_count));

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

	SSDFS_DBG("seg_id %llu, refs_count %d\n",
		  si->seg_id, atomic_read(&si->refs_count));

	WARN_ON(atomic_dec_return(&si->refs_count) < 0);

	if (atomic_read(&si->refs_count) <= 0)
		wake_up_all(&si->destruct_queue);
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
		mask = SSDFS_SEG_DATA_USING;
		break;

	case SSDFS_LEAF_NODE_SEG_TYPE:
		mask = SSDFS_SEG_LEAF_NODE_USING;
		break;

	case SSDFS_HYBRID_NODE_SEG_TYPE:
		mask = SSDFS_SEG_HYBRID_NODE_USING;
		break;

	case SSDFS_INDEX_NODE_SEG_TYPE:
		mask = SSDFS_SEG_INDEX_NODE_USING;
		break;

	default:
		BUG();
	};

	return mask;
}

/*
 * ssdfs_grab_segment() - get or create segment object
 * @fsi: pointer on shared file system object
 * @seg_type: type of segment
 * @seg_id: segment number
 *
 * This method tries to get or to create segment object of
 * @seg_type. If @seg_id is U64_MAX then it needs to find
 * segment that will be in "clean" or "using" state. The found
 * segment number should be used for segment object creation
 * and adding into the segment tree. Otherwise, if @seg_id
 * contains valid segment number, the method should try
 * to find segment object in the segments tree. If the segment
 * object is not found then segment state will be detected via
 * segment bitmap, segment object will be created and to be added
 * into the segment tree. Finally, reference counter of segment
 * object will be incremented.
 *
 * RETURN:
 * [success] - pointer on segment object.
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
struct ssdfs_segment_info *
ssdfs_grab_segment(struct ssdfs_fs_info *fsi, int seg_type, u64 seg_id)
{
	struct ssdfs_segment_info *si;
	int seg_state = SSDFS_SEG_STATE_MAX;
	struct completion *init_end;
	unsigned long rest;
	int err, res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(seg_type != SSDFS_LEAF_NODE_SEG_TYPE &&
		seg_type != SSDFS_HYBRID_NODE_SEG_TYPE &&
		seg_type != SSDFS_INDEX_NODE_SEG_TYPE &&
		seg_type != SSDFS_USER_DATA_SEG_TYPE);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, seg_type %#x, seg_id %llu\n",
		  fsi, seg_type, seg_id);

	if (seg_id == U64_MAX) {
		int new_state;

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

		res = ssdfs_segbmap_find_and_set(fsi->segbmap,
						 0, fsi->nsegs,
						 SSDFS_SEG_CLEAN,
						 SEG_TYPE2MASK(seg_type),
						 new_state,
						 &seg_id, &init_end);
		if (res >= 0) {
			/* Define segment state */
			seg_state = res;
		} else if (res == -EAGAIN) {
			rest = wait_for_completion_timeout(init_end,
						SSDFS_DEFAULT_TIMEOUT);
			if (rest == 0) {
				err = -ERANGE;
				SSDFS_ERR("segbmap init failed: "
					  "err %d\n", err);
				return ERR_PTR(err);
			}

			res = ssdfs_segbmap_find_and_set(fsi->segbmap,
							0, fsi->nsegs,
							SSDFS_SEG_CLEAN,
							SEG_TYPE2MASK(seg_type),
							new_state,
							&seg_id, &init_end);
			if (res >= 0) {
				/* Define segment state */
				seg_state = res;
			} else
				goto fail_find_segment;
		} else {
fail_find_segment:
			SSDFS_ERR("fail to find segment number: "
				  "err %d\n",
				  res);
			return ERR_PTR(res);
		}
	}

	si = ssdfs_segment_tree_find(fsi, seg_id);
	if (IS_ERR_OR_NULL(si)) {
		err = PTR_ERR(si);

		if (err == -ENODATA) {
			u16 log_pages;
			u8 create_threads;

			if (seg_state != SSDFS_SEG_STATE_MAX)
				goto create_segment_object;

			seg_state = ssdfs_segbmap_get_state(fsi->segbmap,
							    seg_id, &init_end);
			if (seg_state == -EAGAIN) {
				rest = wait_for_completion_timeout(init_end,
							SSDFS_DEFAULT_TIMEOUT);
				if (rest == 0) {
					err = -ERANGE;
					SSDFS_ERR("segbmap init failed: "
						  "err %d\n", err);
					return ERR_PTR(err);
				}

				seg_state =
					ssdfs_segbmap_get_state(fsi->segbmap,
								seg_id,
								&init_end);
				if (seg_state < 0)
					goto fail_define_seg_state;
			} else if (seg_state < 0) {
fail_define_seg_state:
				SSDFS_ERR("fail to define segment state: "
					  "seg %llu\n",
					  seg_id);
				return ERR_PTR(seg_state);
			}

			switch (seg_state) {
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
					  seg_id, seg_state);
				return ERR_PTR(err);
			};

create_segment_object:
			switch (seg_type) {
			case SSDFS_USER_DATA_SEG_TYPE:
				log_pages =
					fsi->segs_tree->user_data_log_pages;
				break;

			case SSDFS_LEAF_NODE_SEG_TYPE:
				log_pages =
					fsi->segs_tree->lnodes_seg_log_pages;
				break;

			case SSDFS_HYBRID_NODE_SEG_TYPE:
				log_pages =
					fsi->segs_tree->hnodes_seg_log_pages;
				break;

			case SSDFS_INDEX_NODE_SEG_TYPE:
				log_pages =
					fsi->segs_tree->inodes_seg_log_pages;
				break;

			default:
				log_pages =
					fsi->segs_tree->default_log_pages;
				break;
			};

			/* TODO: make final desicion later */
			create_threads = SSDFS_CREATE_THREADS_DEFAULT;

			si = ssdfs_segment_create_object(fsi, seg_id,
							 seg_state, seg_type,
							 log_pages,
							 create_threads);
			if (IS_ERR_OR_NULL(si)) {
				SSDFS_ERR("fail to create segment: "
					  "seg %llu, err %ld\n",
					  seg_id, PTR_ERR(si));
				return si;
			}

			err = ssdfs_segment_tree_add(fsi, si);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add segment into tree: "
					  "seg %llu, err %d\n",
					  seg_id, err);
				return ERR_PTR(err);
			}
		} else if (err == 0) {
			SSDFS_ERR("segment tree returns NULL\n");
			return ERR_PTR(-ERANGE);
		} else {
			SSDFS_ERR("segment tree fail to find segment: "
				  "seg %llu, err %d\n",
				  seg_id, err);
			return ERR_PTR(err);
		}
	}

	ssdfs_segment_get_object(si);
	return si;
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
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	table = si->blk2off_table;
	logical_blk = req->place.start.blk_index;

	po_desc = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index, NULL);
	if (IS_ERR(po_desc) && PTR_ERR(po_desc) == -EAGAIN) {
		struct completion *end;
		unsigned long res;

		end = &table->full_init_end;
		res = wait_for_completion_timeout(end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		po_desc = ssdfs_blk2off_table_convert(table, logical_blk,
							&peb_index, NULL);
	}

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    SSDFS_READ_PAGE,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_read_block(si, req);
}

/*
 * ssdfs_segment_read_block_async() - read segment's block asynchronously
 * @si: segment info
 * @req: segment request [in|out]
 */
int ssdfs_segment_read_block_async(struct ssdfs_segment_info *si,
				   struct ssdfs_segment_request *req)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    SSDFS_READ_PAGE,
					    SSDFS_REQ_ASYNC,
					    req);
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu\n", si->seg_id);

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
 * ssdfs_segment_change_state() - change segment state
 * @si: pointer on segment object
 */
static
int ssdfs_segment_change_state(struct ssdfs_segment_info *si)
{
	struct ssdfs_segment_bmap *segbmap;
	struct ssdfs_blk2off_table *blk2off_tbl;
	u32 pages_per_seg;
	u16 used_logical_blks;
	int free_pages, invalid_pages;
	bool need_change_state = false;
	int seg_state, old_seg_state;
	int new_seg_state = SSDFS_SEG_STATE_MAX;
	u64 seg_id;
	struct completion *init_end;
	unsigned long res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_id = si->seg_id;

	SSDFS_DBG("si %p, seg_id %llu\n",
		  si, seg_id);

	blk2off_tbl = si->blk2off_table;
	segbmap = si->fsi->segbmap;

	err = ssdfs_blk2off_table_get_used_logical_blks(blk2off_tbl,
							&used_logical_blks);
	if (err == -EAGAIN) {
		init_end = &blk2off_tbl->partial_init_end;

		res = wait_for_completion_timeout(init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_blk2off_table_get_used_logical_blks(blk2off_tbl,
							    &used_logical_blks);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to get used logical blocks count: "
			  "err %d\n",
			  err);
		return err;
	} else if (used_logical_blks == U16_MAX) {
		SSDFS_ERR("invalid used logical blocks count\n");
		return -ERANGE;
	}

	pages_per_seg = si->fsi->pages_per_seg;
	seg_state = atomic_read(&si->seg_state);
	free_pages = ssdfs_segment_blk_bmap_get_free_pages(&si->blk_bmap);
	invalid_pages = ssdfs_segment_blk_bmap_get_invalid_pages(&si->blk_bmap);

	if (free_pages > pages_per_seg) {
		SSDFS_ERR("free_pages %d > pages_per_seg %u\n",
			  free_pages, pages_per_seg);
		return -ERANGE;
	}

	switch (seg_state) {
	case SSDFS_SEG_CLEAN:
		if (free_pages > 0 && free_pages != pages_per_seg) {
			need_change_state = true;
			new_seg_state = SEG_TYPE_TO_USING_STATE(si->seg_type);
			if (new_seg_state < 0 ||
			    new_seg_state == SSDFS_SEG_STATE_MAX) {
				SSDFS_ERR("invalid seg_type %#x\n",
					  si->seg_type);
				return -ERANGE;
			}
		} else if (free_pages == 0) {
			need_change_state = true;

			if (invalid_pages == 0)
				new_seg_state = SSDFS_SEG_USED;
			else if (used_logical_blks == 0)
				new_seg_state = SSDFS_SEG_DIRTY;
			else
				new_seg_state = SSDFS_SEG_PRE_DIRTY;
		}
		break;

	case SSDFS_SEG_DATA_USING:
	case SSDFS_SEG_LEAF_NODE_USING:
	case SSDFS_SEG_HYBRID_NODE_USING:
	case SSDFS_SEG_INDEX_NODE_USING:
		if (free_pages == 0) {
			need_change_state = true;

			if (invalid_pages == 0)
				new_seg_state = SSDFS_SEG_USED;
			else if (used_logical_blks == 0)
				new_seg_state = SSDFS_SEG_DIRTY;
			else
				new_seg_state = SSDFS_SEG_PRE_DIRTY;
		}
		break;

	case SSDFS_SEG_USED:
		if (free_pages == pages_per_seg) {
			SSDFS_ERR("free_pages %d == pages_per_seg %u\n",
				  free_pages, pages_per_seg);
			return -ERANGE;
		} else if (free_pages > 0) {
			need_change_state = true;
			new_seg_state = SEG_TYPE_TO_USING_STATE(si->seg_type);
			if (new_seg_state < 0 ||
			    new_seg_state == SSDFS_SEG_STATE_MAX) {
				SSDFS_ERR("invalid seg_type %#x\n",
					  si->seg_type);
				return -ERANGE;
			}
		} else if (invalid_pages > 0 && used_logical_blks > 0) {
			need_change_state = true;
			new_seg_state = SSDFS_SEG_PRE_DIRTY;
		} else if (invalid_pages > 0 && used_logical_blks == 0) {
			need_change_state = true;
			new_seg_state = SSDFS_SEG_DIRTY;
		}
		break;

	case SSDFS_SEG_PRE_DIRTY:
		if (free_pages == pages_per_seg) {
			SSDFS_ERR("free_pages %d == pages_per_seg %u\n",
				  free_pages, pages_per_seg);
			return -ERANGE;
		} else if (free_pages > 0) {
			need_change_state = true;
			new_seg_state = SEG_TYPE_TO_USING_STATE(si->seg_type);
			if (new_seg_state < 0 ||
			    new_seg_state == SSDFS_SEG_STATE_MAX) {
				SSDFS_ERR("invalid seg_type %#x\n",
					  si->seg_type);
				return -ERANGE;
			}
		} else if (invalid_pages > 0 && used_logical_blks == 0) {
			need_change_state = true;
			new_seg_state = SSDFS_SEG_DIRTY;
		}
		break;

	case SSDFS_SEG_DIRTY:
		if (free_pages == pages_per_seg) {
			need_change_state = true;
			new_seg_state = SSDFS_SEG_CLEAN;
		} else {
			SSDFS_ERR("free_pages %d, pages_per_seg %u, "
				  "invalid_pages %d, used_logical_blks %u\n",
				  free_pages, pages_per_seg,
				  invalid_pages, used_logical_blks);
			return -ERANGE;
		}
		break;

	case SSDFS_SEG_BAD:
	case SSDFS_SEG_RESERVED:
		/* do nothing */
		break;

	default:
		break;
	}

	if (!need_change_state)
		return 0;

	err = ssdfs_segbmap_change_state(segbmap, seg_id,
					 new_seg_state, &init_end);
	if (err == -EAGAIN) {
		res = wait_for_completion_timeout(init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("segbmap init failed: "
				  "err %d\n", err);
			return err;
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
		return err;
	}

	old_seg_state = atomic_cmpxchg(&si->seg_state,
					seg_state, new_seg_state);
	if (old_seg_state != seg_state) {
		SSDFS_WARN("old_seg_state %#x != seg_state %#x\n",
			   old_seg_state, seg_state);
	}

	return 0;
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
	BUG_ON(!cur_seg || !cur_seg->real_seg);
	BUG_ON(!mutex_is_locked(&cur_seg->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	si = cur_seg->real_seg;
	seg_id = si->seg_id;
	seg_state = atomic_read(&cur_seg->real_seg->seg_state);

	SSDFS_DBG("cur_seg %p, si %p, seg_id %llu, seg_state %#x\n",
		  cur_seg, si, seg_id, seg_state);

	switch (seg_state) {
	case SSDFS_SEG_CLEAN:
	case SSDFS_SEG_DATA_USING:
	case SSDFS_SEG_LEAF_NODE_USING:
	case SSDFS_SEG_HYBRID_NODE_USING:
	case SSDFS_SEG_INDEX_NODE_USING:
		err = ssdfs_segment_change_state(si);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change segment's state: "
				  "seg_id %llu, err %d\n",
				  seg_id, err);
			return err;
		}
		break;

	case SSDFS_SEG_USED:
	case SSDFS_SEG_PRE_DIRTY:
	case SSDFS_SEG_DIRTY:
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
 * __ssdfs_segment_add_block() - add new block into segment
 * @cur_seg: current segment container
 * @req: segment request [in|out]
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
			       struct ssdfs_segment_request *req)
{
	struct ssdfs_segment_info *si;
	int seg_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	ssdfs_current_segment_lock(cur_seg);

	seg_type = SEG_TYPE(req->private.class);

try_current_segment:
	if (is_ssdfs_current_segment_empty(cur_seg)) {
add_new_current_segment:
		si = ssdfs_grab_segment(cur_seg->fsi, seg_type, U64_MAX);
		if (IS_ERR_OR_NULL(si)) {
			err = (si == NULL ? -ENOMEM : PTR_ERR(si));
			SSDFS_ERR("fail to create segment object: "
				  "err %d\n",
				  err);
			goto finish_add_block;
		}

		err = ssdfs_current_segment_add(cur_seg, si);
		ssdfs_segment_put_object(si);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add segment %llu as current: "
				  "err %d\n",
				  si->seg_id, err);
			goto finish_add_block;
		}

		goto try_current_segment;
	} else {
		si = cur_seg->real_seg;

		if (ssdfs_segment_blk_bmap_get_free_pages(&si->blk_bmap) == 0) {
			SSDFS_DBG("segment %llu hasn't free pages\n",
				  cur_seg->real_seg->seg_id);

			ssdfs_current_segment_remove(cur_seg);
			goto add_new_current_segment;
		} else {
			struct ssdfs_blk2off_table *table;
			struct ssdfs_requests_queue *create_rq;
			wait_queue_head_t *wait;
			u16 blk;

			table = si->blk2off_table;

			ssdfs_request_define_segment(si->seg_id, req);

			err = ssdfs_blk2off_table_allocate_block(table, &blk);
			if (err == -EAGAIN) {
				struct completion *end;
				unsigned long res;

				end = &table->partial_init_end;
				res = wait_for_completion_timeout(end,
							SSDFS_DEFAULT_TIMEOUT);
				if (res == 0) {
					err = -ERANGE;
					SSDFS_ERR("blk2off init failed: "
						  "err %d\n", err);
					goto finish_add_block;
				}

				err = ssdfs_blk2off_table_allocate_block(table,
									 &blk);
			}

			if (unlikely(err)) {
				SSDFS_ERR("fail to allocate logical block\n");
				goto finish_add_block;
			}

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(blk > U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_request_define_volume_extent(blk, 1, req);

			atomic_dec(&si->blk_bmap.free_logical_blks);
			atomic_inc(&si->blk_bmap.valid_logical_blks);

			err = ssdfs_current_segment_change_state(cur_seg);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change segment state: "
					  "seg %llu, err %d\n",
					  cur_seg->real_seg->seg_id, err);
				goto finish_add_block;
			}

			create_rq = &si->create_rq;
			ssdfs_requests_queue_add_tail(create_rq, req);

			wait = &si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
			wake_up_all(wait);
		}
	}

finish_add_block:
	ssdfs_current_segment_unlock(cur_seg);

	if (err) {
		SSDFS_ERR("fail to add block: "
			  "ino %llu, logical_offset %llu, err %d\n",
			  req->extent.ino, req->extent.logical_offset, err);
		return err;
	}

	return 0;
}

/*
 * __ssdfs_segment_add_extent() - add new extent into segment
 * @cur_seg: current segment container
 * @req: segment request [in|out]
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
			       struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	int seg_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!cur_seg || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	fsi = cur_seg->fsi;

	ssdfs_current_segment_lock(cur_seg);

	seg_type = SEG_TYPE(req->private.class);

try_current_segment:
	if (is_ssdfs_current_segment_empty(cur_seg)) {
add_new_current_segment:
		si = ssdfs_grab_segment(fsi, seg_type, U64_MAX);
		if (IS_ERR_OR_NULL(si)) {
			err = (si == NULL ? -ENOMEM : PTR_ERR(si));
			SSDFS_ERR("fail to create segment object: "
				  "err %d\n",
				  err);
			goto finish_add_extent;
		}

		err = ssdfs_current_segment_add(cur_seg, si);
		ssdfs_segment_put_object(si);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add segment %llu as current: "
				  "err %d\n",
				  si->seg_id, err);
			goto finish_add_extent;
		}

		goto try_current_segment;
	} else {
		struct ssdfs_segment_blk_bmap *blk_bmap;
		u32 extent_bytes = req->extent.data_bytes;
		u16 blks_count;

		if (fsi->pagesize > PAGE_SIZE)
			extent_bytes += fsi->pagesize - 1;
		else if (fsi->pagesize <= PAGE_SIZE)
			extent_bytes += PAGE_SIZE - 1;

		si = cur_seg->real_seg;
		blk_bmap = &si->blk_bmap;
		blks_count = extent_bytes >> fsi->log_pagesize;

		if (atomic_read(&blk_bmap->free_logical_blks) < blks_count) {
			SSDFS_DBG("segment %llu hasn't enough free pages: "
				  "free_pages %u, requested_pages %u\n",
				  si->seg_id,
				  atomic_read(&blk_bmap->free_logical_blks),
				  blks_count);

			ssdfs_current_segment_remove(cur_seg);
			goto add_new_current_segment;
		} else {
			struct ssdfs_blk2off_table *table;
			struct ssdfs_requests_queue *create_rq;
			struct ssdfs_blk2off_range extent;

			table = si->blk2off_table;

			ssdfs_request_define_segment(si->seg_id, req);

			err = ssdfs_blk2off_table_allocate_extent(table,
								  blks_count,
								  &extent);
			if (err == -EAGAIN) {
				struct completion *end;
				unsigned long res;

				end = &table->partial_init_end;
				res = wait_for_completion_timeout(end,
							SSDFS_DEFAULT_TIMEOUT);
				if (res == 0) {
					err = -ERANGE;
					SSDFS_ERR("blk2off init failed: "
						  "err %d\n", err);
					goto finish_add_extent;
				}

				err = ssdfs_blk2off_table_allocate_extent(table,
								     blks_count,
								     &extent);
			}

			if (unlikely(err)) {
				SSDFS_ERR("fail to allocate logical extent\n");
				goto finish_add_extent;
			}

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(extent.start_lblk >= U16_MAX);
			BUG_ON(extent.len != blks_count);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_request_define_volume_extent(extent.start_lblk,
							   extent.len, req);

			if (atomic_sub_return(extent.len,
					&blk_bmap->free_logical_blks) < 0) {
				err = -ERANGE;
				SSDFS_WARN("invalid free pages management\n");
				goto finish_add_extent;
			}

			err = ssdfs_current_segment_change_state(cur_seg);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change segment state: "
					  "seg %llu, err %d\n",
					  cur_seg->real_seg->seg_id, err);
				goto finish_add_extent;
			}

			create_rq = &si->create_rq;
			ssdfs_requests_queue_add_tail(create_rq, req);
			wake_up_all(&si->wait_queue[SSDFS_PEB_FLUSH_THREAD]);
		}
	}

finish_add_extent:
	ssdfs_current_segment_unlock(cur_seg);

	if (err) {
		SSDFS_ERR("fail to add extent: "
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
 * @req: segment request [in|out]
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
				   struct ssdfs_segment_request *req)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON(req_class <= SSDFS_PEB_READ_REQ ||
		req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_CREATE_BLOCK,
					    SSDFS_REQ_SYNC,
					    req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_block(cur_seg, req);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * __ssdfs_segment_add_block_async() - add new block asynchronously
 * @fsi: pointer on shared file system object
 * @req_class: request class
 * @req: segment request [in|out]
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
				    struct ssdfs_segment_request *req)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON(req_class <= SSDFS_PEB_READ_REQ ||
		req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_CREATE_BLOCK,
					    SSDFS_REQ_ASYNC,
					    req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_block(cur_seg, req);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_pre_alloc_data_block_sync() - synchronous pre-alloc data block
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 *
 * This function tries to pre-allocate a new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_data_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_sync(fsi,
					      SSDFS_PEB_PRE_ALLOCATE_DATA_REQ,
					      req);
}

/*
 * ssdfs_segment_pre_alloc_data_block_async() - async pre-alloc data block
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 *
 * This function tries to pre-allocate a new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_data_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_async(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_DATA_REQ,
					       req);
}

/*
 * ssdfs_segment_pre_alloc_leaf_node_block_sync() - sync pre-alloc leaf node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					   struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_sync(fsi,
					      SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ,
					      req);
}

/*
 * ssdfs_segment_pre_alloc_leaf_node_block_async() - async pre-alloc leaf node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					    struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_async(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ,
					       req);
}

/*
 * ssdfs_segment_pre_alloc_hybrid_node_block_sync() - sync pre-alloc hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					     struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_sync(fsi,
					      SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ,
					      req);
}

/*
 * ssdfs_segment_pre_alloc_hybrid_node_block_async() - pre-alloc hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					     struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_async(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ,
					       req);
}

/*
 * ssdfs_segment_pre_alloc_index_node_block_sync() - sync pre-alloc index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					    struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_sync(fsi,
					     SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ,
					     req);
}

/*
 * ssdfs_segment_pre_alloc_index_node_block_async() - pre-alloc index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					     struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_async(fsi,
					     SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ,
					     req);
}

/*
 * ssdfs_segment_add_data_block_sync() - add new data block synchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 *
 * This function tries to add new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_data_block_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_sync(fsi,
						SSDFS_PEB_CREATE_DATA_REQ,
						req);
}

/*
 * ssdfs_segment_add_data_block_async() - add new data block asynchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 *
 * This function tries to add new data block into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_data_block_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_async(fsi,
						SSDFS_PEB_CREATE_DATA_REQ,
						req);
}

/*
 * ssdfs_segment_add_leaf_node_block_sync() - add new leaf node synchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					    struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_sync(fsi,
						SSDFS_PEB_CREATE_LNODE_REQ,
						req);
}

/*
 * ssdfs_segment_add_leaf_node_block_async() - add new leaf node asynchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					    struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_async(fsi,
						SSDFS_PEB_CREATE_LNODE_REQ,
						req);
}

/*
 * ssdfs_segment_add_hybrid_node_block_sync() - add new hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					     struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_sync(fsi,
						SSDFS_PEB_CREATE_HNODE_REQ,
						req);
}

/*
 * ssdfs_segment_add_hybrid_node_block_async() - add new hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					      struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_async(fsi,
						SSDFS_PEB_CREATE_HNODE_REQ,
						req);
}

/*
 * ssdfs_segment_add_index_node_block_sync() - add new index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					    struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_sync(fsi,
						SSDFS_PEB_CREATE_IDXNODE_REQ,
						req);
}

/*
 * ssdfs_segment_add_index_node_block_async() - add new index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					     struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_block_async(fsi,
						SSDFS_PEB_CREATE_IDXNODE_REQ,
						req);
}

/*
 * __ssdfs_segment_add_extent_sync() - add new extent synchronously
 * @fsi: pointer on shared file system object
 * @req_class: request class
 * @req: segment request [in|out]
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
				    struct ssdfs_segment_request *req)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON(req_class <= SSDFS_PEB_READ_REQ ||
		req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_CREATE_EXTENT,
					    SSDFS_REQ_SYNC,
					    req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_extent(cur_seg, req);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * __ssdfs_segment_add_extent_async() - add new extent asynchronously
 * @fsi: pointer on shared file system object
 * @req_class: request class
 * @req: segment request [in|out]
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
				     struct ssdfs_segment_request *req)
{
	struct ssdfs_current_segment *cur_seg;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON(req_class <= SSDFS_PEB_READ_REQ ||
		req_class > SSDFS_PEB_CREATE_IDXNODE_REQ);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	ssdfs_request_prepare_internal_data(req_class,
					    SSDFS_CREATE_EXTENT,
					    SSDFS_REQ_ASYNC,
					    req);

	down_read(&fsi->cur_segs->lock);
	cur_seg = fsi->cur_segs->objects[CUR_SEG_TYPE(req_class)];
	err = __ssdfs_segment_add_extent(cur_seg, req);
	up_read(&fsi->cur_segs->lock);

	return err;
}

/*
 * ssdfs_segment_pre_alloc_data_extent_sync() - sync pre-alloc a data extent
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 *
 * This function tries to pre-allocate a new data extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_data_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_sync(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_DATA_REQ,
					       req);
}

/*
 * ssdfs_segment_pre_alloc_data_extent_async() - async pre-alloc a data extent
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 *
 * This function tries to pre-allocate a new data extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_pre_alloc_data_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_async(fsi,
						SSDFS_PEB_PRE_ALLOCATE_DATA_REQ,
						req);
}

/*
 * ssdfs_segment_pre_alloc_leaf_node_extent_sync() - pre-alloc a leaf node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					   struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_sync(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ,
					       req);
}

/*
 * ssdfs_segment_pre_alloc_leaf_node_extent_async() - pre-alloc a leaf node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					    struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_async(fsi,
					    SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ,
					    req);
}

/*
 * ssdfs_segment_pre_alloc_hybrid_node_extent_sync() - pre-alloc a hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					     struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_sync(fsi,
					       SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ,
					       req);
}

/*
 * ssdfs_segment_pre_alloc_hybrid_node_extent_sync() - pre-alloc a hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					     struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_async(fsi,
					    SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ,
					    req);
}

/*
 * ssdfs_segment_pre_alloc_index_node_extent_sync() - pre-alloc an index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					    struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_sync(fsi,
					    SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ,
					    req);
}

/*
 * ssdfs_segment_pre_alloc_index_node_extent_sync() - pre-alloc an index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					     struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_async(fsi,
					    SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ,
					    req);
}

/*
 * ssdfs_segment_add_data_extent_sync() - add new data extent synchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 *
 * This function tries to add new data extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_data_extent_sync(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_sync(fsi,
						SSDFS_PEB_CREATE_DATA_REQ,
						req);
}

/*
 * ssdfs_segment_add_data_extent_async() - add new data extent asynchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
 *
 * This function tries to add new data extent into segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - segment hasn't free pages.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_add_data_extent_async(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_async(fsi,
						SSDFS_PEB_CREATE_DATA_REQ,
						req);
}

/*
 * ssdfs_segment_add_leaf_node_extent_sync() - add new leaf node synchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					    struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_sync(fsi,
						SSDFS_PEB_CREATE_LNODE_REQ,
						req);
}

/*
 * ssdfs_segment_add_leaf_node_extent_async() - add new leaf node asynchronously
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					    struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_async(fsi,
						SSDFS_PEB_CREATE_LNODE_REQ,
						req);
}

/*
 * ssdfs_segment_add_hybrid_node_extent_sync() - add new hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					     struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_sync(fsi,
						SSDFS_PEB_CREATE_HNODE_REQ,
						req);
}

/*
 * ssdfs_segment_add_hybrid_node_extent_async() - add new hybrid node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					      struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_async(fsi,
						SSDFS_PEB_CREATE_HNODE_REQ,
						req);
}

/*
 * ssdfs_segment_add_index_node_extent_sync() - add new index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					    struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_sync(fsi,
						SSDFS_PEB_CREATE_IDXNODE_REQ,
						req);
}

/*
 * ssdfs_segment_add_index_node_extent_async() - add new index node
 * @fsi: pointer on shared file system object
 * @req: segment request [in|out]
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
					     struct ssdfs_segment_request *req)
{
	return __ssdfs_segment_add_extent_async(fsi,
						SSDFS_PEB_CREATE_IDXNODE_REQ,
						req);
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
	u16 peb_index = U16_MAX;
	u16 logical_blk;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	table = si->blk2off_table;
	logical_blk = req->place.start.blk_index;

	po_desc = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index, NULL);
	if (IS_ERR(po_desc) && PTR_ERR(po_desc) == -EAGAIN) {
		struct completion *end;
		unsigned long res;

		end = &table->full_init_end;
		res = wait_for_completion_timeout(end,
					SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		po_desc = ssdfs_blk2off_table_convert(table, logical_blk,
							&peb_index, NULL);
	}

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
	ssdfs_requests_queue_add_tail(rq, req);
	wait = &si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
	wake_up_all(wait);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
							NULL);
		if (IS_ERR(po_desc) && PTR_ERR(po_desc) == -EAGAIN) {
			struct completion *end;
			unsigned long res;

			end = &table->full_init_end;
			res = wait_for_completion_timeout(end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("blk2off init failed: "
					  "err %d\n", err);
				return err;
			}

			po_desc = ssdfs_blk2off_table_convert(table, blk + i,
								&cur_peb_index,
								NULL);
		}

		if (IS_ERR_OR_NULL(po_desc)) {
			err = (po_desc == NULL ? -ERANGE : PTR_ERR(po_desc));
			SSDFS_ERR("fail to convert: "
				  "logical_blk %u, err %d\n",
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
	ssdfs_requests_queue_add_tail(rq, req);
	wait = &si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
	wake_up_all(wait);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
	struct ssdfs_blk2off_table *blk2off_tbl;
	struct ssdfs_phys_offset_descriptor *off_desc = NULL;
	u32 blk;
	u32 upper_blk = start_off + blks_count;
	struct completion *init_end;
	unsigned long res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("si %p, seg %llu, start_off %u, blks_count %u\n",
		  si, si->seg_id, start_off, blks_count);

	blk2off_tbl = si->blk2off_table;

	for (blk = start_off; blk < upper_blk; blk++) {
		struct ssdfs_peb_container *pebc;
		u16 peb_index = U16_MAX;
		u16 peb_page;

		if (blk >= U16_MAX) {
			SSDFS_ERR("invalid logical block number: %u\n",
				  blk);
			return -ERANGE;
		}

		off_desc = ssdfs_blk2off_table_convert(blk2off_tbl,
							(u16)blk,
							&peb_index,
							NULL);
		if (PTR_ERR(off_desc) == -EAGAIN) {
			init_end = &blk2off_tbl->full_init_end;

			res = wait_for_completion_timeout(init_end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("blk2off init failed: "
					  "err %d\n", err);
				return err;
			}

			off_desc = ssdfs_blk2off_table_convert(blk2off_tbl,
								(u16)blk,
								&peb_index,
								NULL);
		}

		if (IS_ERR_OR_NULL(off_desc)) {
			err = !off_desc ? -ERANGE : PTR_ERR(off_desc);
			SSDFS_ERR("fail to convert logical block: "
				  "blk %u, err %d\n",
				  blk, err);
			return err;
		}

		peb_page = le16_to_cpu(off_desc->page_desc.peb_page);

		if (peb_index >= si->pebs_count) {
			SSDFS_ERR("peb_index %u >= pebs_count %u\n",
				  peb_index, si->pebs_count);
			return -ERANGE;
		}

		pebc = &si->peb_array[peb_index];
		err = ssdfs_peb_container_invalidate_block(pebc, off_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate: "
				  "logical_blk %u, peb_index %u, "
				  "err %d\n",
				  blk, peb_index, err);
			return err;
		}

		err = ssdfs_blk2off_table_free_block(blk2off_tbl, (u16)blk);
		if (err == -EAGAIN) {
			init_end = &blk2off_tbl->full_init_end;

			res = wait_for_completion_timeout(init_end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("blk2off init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_blk2off_table_free_block(blk2off_tbl,
							     (u16)blk);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to free logical block: "
				  "blk %u, err %d\n",
				  blk, err);
			return err;
		}

		if (atomic_dec_and_test(&si->blk_bmap.valid_logical_blks)) {
			SSDFS_ERR("negative count of valid_pages: "
				  "seg %llu\n",
				  si->seg_id);
			return -ERANGE;
		}

		atomic_inc(&si->blk_bmap.invalid_logical_blks);
	}

	err = ssdfs_segment_change_state(si);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change segment state: "
			  "seg %llu, err %d\n",
			  si->seg_id, err);
		return err;
	}

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("si %p, seg %llu, blk_offset %u\n",
		  si, si->seg_id, blk_offset);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu\n",
		  si->seg_id, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot);

	ssdfs_request_prepare_internal_data(SSDFS_PEB_COLLECT_GARBAGE_REQ,
					    SSDFS_MIGRATE_FRAGMENT,
					    SSDFS_REQ_ASYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	return __ssdfs_segment_update_extent(si, req);
}
