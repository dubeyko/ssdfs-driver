/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_block_bitmap.c - segment's block bitmap implementation.
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
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_seg_blk_folio_leaks;
atomic64_t ssdfs_seg_blk_memory_leaks;
atomic64_t ssdfs_seg_blk_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_seg_blk_cache_leaks_increment(void *kaddr)
 * void ssdfs_seg_blk_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_seg_blk_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_seg_blk_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_seg_blk_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_seg_blk_kfree(void *kaddr)
 * struct folio *ssdfs_seg_blk_alloc_folio(gfp_t gfp_mask,
 *                                         unsigned int order)
 * struct folio *ssdfs_seg_blk_add_batch_folio(struct folio_batch *batch,
 *                                             unsigned int order)
 * void ssdfs_seg_blk_free_folio(struct folio *folio)
 * void ssdfs_seg_blk_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(seg_blk)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(seg_blk)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_seg_blk_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_seg_blk_folio_leaks, 0);
	atomic64_set(&ssdfs_seg_blk_memory_leaks, 0);
	atomic64_set(&ssdfs_seg_blk_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_seg_blk_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_seg_blk_folio_leaks) != 0) {
		SSDFS_ERR("SEGMENT BLOCK BITMAP: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_seg_blk_folio_leaks));
	}

	if (atomic64_read(&ssdfs_seg_blk_memory_leaks) != 0) {
		SSDFS_ERR("SEGMENT BLOCK BITMAP: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_seg_blk_memory_leaks));
	}

	if (atomic64_read(&ssdfs_seg_blk_cache_leaks) != 0) {
		SSDFS_ERR("SEGMENT BLOCK BITMAP: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_seg_blk_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

#define SSDFS_SEG_BLK_BMAP_STATE_FNS(value, name)			\
static inline								\
bool is_seg_block_bmap_##name(struct ssdfs_segment_blk_bmap *bmap)	\
{									\
	return atomic_read(&bmap->state) == SSDFS_SEG_BLK_BMAP_##value;	\
}									\
static inline								\
void set_seg_block_bmap_##name(struct ssdfs_segment_blk_bmap *bmap)	\
{									\
	atomic_set(&bmap->state, SSDFS_SEG_BLK_BMAP_##value);		\
}									\

/*
 * is_seg_block_bmap_created()
 * set_seg_block_bmap_created()
 */
SSDFS_SEG_BLK_BMAP_STATE_FNS(CREATED, created)

/*
 * ssdfs_segment_blk_bmap_create() - create segment block bitmap
 * @si: segment object
 * @init_flag: definition of block bitmap's creation state
 * @init_state: block state is used during initialization
 *
 * This method tries to create segment block bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_blk_bmap_create(struct ssdfs_segment_info *si,
				  int init_flag, int init_state)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_blk_bmap *bmap;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("si %p, seg_id %llu, "
		  "init_flag %#x, init_state %#x\n",
		  si, si->seg_id,
		  init_flag, init_state);
#else
	SSDFS_DBG("si %p, seg_id %llu, "
		  "init_flag %#x, init_state %#x\n",
		  si, si->seg_id,
		  init_flag, init_state);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = si->fsi;
	bmap = &si->blk_bmap;

	bmap->parent_si = si;
	atomic_set(&bmap->state, SSDFS_SEG_BLK_BMAP_STATE_UNKNOWN);

	bmap->pages_per_peb = fsi->pages_per_peb;
	bmap->pages_per_seg = fsi->pages_per_seg;

	init_rwsem(&bmap->modification_lock);
	atomic_set(&bmap->seg_valid_blks, 0);
	atomic_set(&bmap->seg_invalid_blks, 0);
	atomic_set(&bmap->seg_free_blks, 0);
	atomic_set(&bmap->seg_reserved_metapages, 0);

	bmap->pebs_count = si->pebs_count;

	bmap->peb = ssdfs_seg_blk_kcalloc(bmap->pebs_count,
				  sizeof(struct ssdfs_peb_blk_bmap),
				  GFP_KERNEL);
	if (!bmap->peb) {
		SSDFS_ERR("fail to allocate PEBs' block bitmaps\n");
		return -ENOMEM;
	}

	for (i = 0; i < bmap->pebs_count; i++) {
		err = ssdfs_peb_blk_bmap_create(bmap, i, fsi->pages_per_seg,
						init_flag, init_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create PEB's block bitmap: "
				  "peb_index %u, err %d\n",
				  i, err);
			goto fail_create_seg_blk_bmap;
		}
	}

	set_seg_block_bmap_created(bmap);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

fail_create_seg_blk_bmap:
	ssdfs_segment_blk_bmap_destroy(bmap);
	return err;
}

/*
 * ssdfs_segment_blk_bmap_destroy() - destroy segment block bitmap
 * @ptr: segment block bitmap pointer
 */
void ssdfs_segment_blk_bmap_destroy(struct ssdfs_segment_blk_bmap *ptr)
{
	int err;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!ptr->parent_si) {
		/* object is not created yet */
		return;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, state %#x\n",
		  ptr->parent_si->seg_id,
		  atomic_read(&ptr->state));
#else
	SSDFS_DBG("seg_id %llu, state %#x\n",
		  ptr->parent_si->seg_id,
		  atomic_read(&ptr->state));
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	atomic_set(&ptr->seg_valid_blks, 0);
	atomic_set(&ptr->seg_invalid_blks, 0);
	atomic_set(&ptr->seg_free_blks, 0);
	atomic_set(&ptr->seg_reserved_metapages, 0);

	for (i = 0; i < ptr->pebs_count; i++) {
		err = ssdfs_peb_blk_bmap_destroy(&ptr->peb[i]);
		if (unlikely(err)) {
			SSDFS_ERR("block bitmap destroy failure: "
				  "seg_id %llu, peb_index %d, err %d\n",
				  ptr->parent_si->seg_id, i, err);
		}
	}

	ssdfs_seg_blk_kfree(ptr->peb);
	ptr->peb = NULL;

	atomic_set(&ptr->state, SSDFS_SEG_BLK_BMAP_STATE_UNKNOWN);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
}

/*
 * ssdfs_segment_blk_bmap_partial_init() - partial init of segment bitmap
 * @bmap: pointer on segment block bitmap
 * @peb_index: PEB's index
 * @source: pointer on folio vector with bitmap state
 * @hdr: header of block bitmap fragment
 * @peb_free_pages: number of available clean/unused pages in the PEB
 * @cno: log's checkpoint
 */
int ssdfs_segment_blk_bmap_partial_init(struct ssdfs_segment_blk_bmap *bmap,
					u16 peb_index,
					struct ssdfs_folio_vector *source,
					struct ssdfs_block_bitmap_fragment *hdr,
					u32 peb_free_pages, u64 cno)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->peb || !bmap->parent_si);
	BUG_ON(!source || !hdr);
	BUG_ON(ssdfs_folio_vector_count(source) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u, "
		  "peb_free_pages %u, cno %llu\n",
		  bmap->parent_si->seg_id, peb_index,
		  peb_free_pages, cno);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u, "
		  "peb_free_pages %u, cno %llu\n",
		  bmap->parent_si->seg_id, peb_index,
		  peb_free_pages, cno);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (atomic_read(&bmap->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&bmap->state));
		return -ERANGE;
	}

	if (peb_index >= bmap->pebs_count) {
		SSDFS_ERR("peb_index %u >= seg_blkbmap->pebs_count %u\n",
			  peb_index, bmap->pebs_count);
		return -ERANGE;
	}

	err = ssdfs_peb_blk_bmap_init(&bmap->peb[peb_index],
					source, hdr,
					peb_free_pages, cno);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_segment_blk_bmap_partial_inflate() - partial inflate of segment bitmap
 * @bmap: pointer on segment block bitmap
 * @peb_index: PEB's index
 * @free_items: free items for inflation of block bitmap
 */
int ssdfs_segment_blk_bmap_partial_inflate(struct ssdfs_segment_blk_bmap *bmap,
					   u16 peb_index, u32 free_items)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->peb || !bmap->parent_si);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u, free_items %u\n",
		  bmap->parent_si->seg_id, peb_index, free_items);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u, free_items %u\n",
		  bmap->parent_si->seg_id, peb_index, free_items);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (atomic_read(&bmap->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&bmap->state));
		return -ERANGE;
	}

	if (peb_index >= bmap->pebs_count) {
		SSDFS_ERR("peb_index %u >= seg_blkbmap->pebs_count %u\n",
			  peb_index, bmap->pebs_count);
		return -ERANGE;
	}

	err = ssdfs_peb_blk_bmap_inflate(&bmap->peb[peb_index],
					 free_items);
	if (unlikely(err)) {
		SSDFS_ERR("fail to inflate PEB block bitmap: "
			  "seg_id %llu, peb_index %u, "
			  "free_items %u, err %d\n",
			  bmap->parent_si->seg_id, peb_index,
			  free_items, err);
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_segment_blk_bmap_partial_clean_init() - partial init of segment bitmap
 * @bmap: pointer on segment block bitmap
 * @peb_index: PEB's index
 */
int
ssdfs_segment_blk_bmap_partial_clean_init(struct ssdfs_segment_blk_bmap *bmap,
					  u16 peb_index)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->peb || !bmap->parent_si);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u",
		  bmap->parent_si->seg_id, peb_index);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  bmap->parent_si->seg_id, peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (atomic_read(&bmap->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&bmap->state));
		return -ERANGE;
	}

	if (peb_index >= bmap->pebs_count) {
		SSDFS_ERR("peb_index %u >= seg_blkbmap->pebs_count %u\n",
			  peb_index, bmap->pebs_count);
		return -ERANGE;
	}

	err = ssdfs_peb_blk_bmap_clean_init(&bmap->peb[peb_index]);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_segment_blk_bmap_init_failed() - process failure of segment bitmap init
 * @bmap: pointer on segment block bitmap
 * @peb_index: PEB's index
 */
void ssdfs_segment_blk_bmap_init_failed(struct ssdfs_segment_blk_bmap *bmap,
					u16 peb_index)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->peb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_index >= bmap->pebs_count) {
		SSDFS_WARN("peb_index %u >= seg_blkbmap->pebs_count %u\n",
			  peb_index, bmap->pebs_count);
		return;
	}

	ssdfs_peb_blk_bmap_init_failed(&bmap->peb[peb_index]);
}

/*
 * is_ssdfs_segment_blk_bmap_dirty() - check that PEB block bitmap is dirty
 * @bmap: pointer on segment block bitmap
 * @peb_index: PEB's index
 */
bool is_ssdfs_segment_blk_bmap_dirty(struct ssdfs_segment_blk_bmap *bmap,
					u16 peb_index)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->peb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_index >= bmap->pebs_count) {
		SSDFS_WARN("peb_index %u >= seg_blkbmap->pebs_count %u\n",
			  peb_index, bmap->pebs_count);
		return false;
	}

	return is_ssdfs_peb_blk_bmap_dirty(&bmap->peb[peb_index]);
}

/*
 * ssdfs_define_bmap_index() - define block bitmap for operation
 * @pebi: pointer on PEB object
 * @bmap_index: pointer on block bitmap index value [out]
 * @peb_index: pointer on PEB's index [out]
 *
 * This method tries to define bitmap index and PEB's index
 * for operation with block bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_define_bmap_index(struct ssdfs_peb_info *pebi,
			    int *bmap_index, u16 *peb_index)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *pebc;
	int migration_state, items_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!bmap_index || !peb_index);
	BUG_ON(!is_ssdfs_peb_container_locked(pebi->pebc));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebi->pebc->parent_si;
	pebc = pebi->pebc;
	*bmap_index = -1;
	*peb_index = U16_MAX;

try_define_bmap_index:
	migration_state = atomic_read(&pebc->migration_state);
	items_state = atomic_read(&pebc->items_state);
	switch (migration_state) {
	case SSDFS_PEB_NOT_MIGRATING:
		*bmap_index = SSDFS_PEB_BLK_BMAP_SOURCE;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebc->src_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		*peb_index = pebc->src_peb->peb_index;
		break;

	case SSDFS_PEB_UNDER_MIGRATION:
		switch (items_state) {
		case SSDFS_PEB1_DST_CONTAINER:
		case SSDFS_PEB2_DST_CONTAINER:
		case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
		case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
			*bmap_index = SSDFS_PEB_BLK_BMAP_SOURCE;
			break;

		case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
		case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
			switch (atomic_read(&pebc->migration_phase)) {
			case SSDFS_SRC_PEB_NOT_EXHAUSTED:
				*bmap_index = SSDFS_PEB_BLK_BMAP_SOURCE;
				break;

			default:
				*bmap_index = SSDFS_PEB_BLK_BMAP_DESTINATION;
				break;
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_WARN("invalid items_state %#x\n",
				   items_state);
			goto finish_define_bmap_index;
		};

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		*peb_index = pebc->dst_peb->peb_index;
		break;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
	case SSDFS_PEB_FINISHING_MIGRATION:
#ifdef CONFIG_SSDFS_DEBUG
		/* unexpected situation */
		SSDFS_WARN("unexpected situation\n");
#endif /* CONFIG_SSDFS_DEBUG */
		err = -EAGAIN;
		goto finish_define_bmap_index;
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid migration_state %#x\n",
			   migration_state);
		goto finish_define_bmap_index;
	}

finish_define_bmap_index:
	if (err == -EAGAIN) {
		DEFINE_WAIT(wait);

		err = 0;

		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_peb_container_unlock(pebc);

		prepare_to_wait(&pebc->migration_wq, &wait,
				TASK_UNINTERRUPTIBLE);
		schedule();
		finish_wait(&pebc->migration_wq, &wait);

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			return err;
		}
		ssdfs_peb_current_log_lock(pebi);
		goto try_define_bmap_index;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

	return 0;
}

bool has_ssdfs_segment_blk_bmap_initialized(struct ssdfs_segment_blk_bmap *ptr,
					    struct ssdfs_peb_container *pebc)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	u16 peb_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebc);

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  ptr->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return false;
	}

	ssdfs_peb_container_lock(pebc);
	if (pebc->dst_peb)
		peb_index = pebc->dst_peb->peb_index;
	else
		peb_index = pebc->src_peb->peb_index;
	ssdfs_peb_container_unlock(pebc);

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return false;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	return has_ssdfs_peb_blk_bmap_initialized(peb_blkbmap);
}

int ssdfs_segment_blk_bmap_wait_init_end(struct ssdfs_segment_blk_bmap *ptr,
					 struct ssdfs_peb_container *pebc)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	u16 peb_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebc);

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  ptr->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	ssdfs_peb_container_lock(pebc);
	if (pebc->dst_peb)
		peb_index = pebc->dst_peb->peb_index;
	else
		peb_index = pebc->src_peb->peb_index;
	ssdfs_peb_container_unlock(pebc);

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	return ssdfs_peb_blk_bmap_wait_init_end(peb_blkbmap);
}

/*
 * ssdfs_segment_blk_bmap_get_block_state() - get logical block's state
 * @ptr: segment block bitmap object
 * @pebi: pointer on PEB object
 * @blk: logical block index
 *
 * This method tries to detect the state of logical block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_blk_bmap_get_block_state(struct ssdfs_segment_blk_bmap *ptr,
					   struct ssdfs_peb_info *pebi,
					   u32 blk)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebi);
	BUG_ON(!is_ssdfs_peb_container_locked(pebi->pebc));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg_id %llu, peb_index %u, blk %u\n",
		  ptr->parent_si->seg_id,
		  pebi->pebc->peb_index, blk);
	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->seg_free_blks),
		  atomic_read(&ptr->seg_valid_blks),
		  atomic_read(&ptr->seg_invalid_blks),
		  ptr->pages_per_seg);

	BUG_ON(atomic_read(&ptr->seg_free_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_valid_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_invalid_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	err = ssdfs_define_bmap_index(pebi, &bmap_index, &peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  ptr->parent_si->seg_id,
			  pebi->pebc->peb_index, err);
		return err;
	}

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	return ssdfs_peb_blk_bmap_get_block_state(peb_blkbmap,
						  bmap_index,
						  blk);
}

/*
 * ssdfs_segment_blk_bmap_reserve_metapages() - reserve metapages
 * @ptr: segment block bitmap object
 * @pebi: pointer on PEB object
 * @count: amount of metadata pages for reservation
 *
 * This method tries to reserve @count metadata pages into
 * block bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_blk_bmap_reserve_metapages(struct ssdfs_segment_blk_bmap *ptr,
					     struct ssdfs_peb_info *pebi,
					     u32 count)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebi);
	BUG_ON(!is_ssdfs_peb_container_locked(pebi->pebc));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg_id %llu, peb_index %u, count %u\n",
		  ptr->parent_si->seg_id,
		  pebi->pebc->peb_index, count);
	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->seg_free_blks),
		  atomic_read(&ptr->seg_valid_blks),
		  atomic_read(&ptr->seg_invalid_blks),
		  ptr->pages_per_seg);

	BUG_ON(atomic_read(&ptr->seg_free_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_valid_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_invalid_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	err = ssdfs_define_bmap_index(pebi, &bmap_index, &peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  ptr->parent_si->seg_id,
			  pebi->pebc->peb_index, err);
		return err;
	}

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	err = ssdfs_peb_blk_bmap_reserve_metapages(peb_blkbmap,
						    bmap_index,
						    count);

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(!is_pages_balance_correct(ptr));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_segment_blk_bmap_free_metapages() - free metapages
 * @ptr: segment block bitmap object
 * @pebi: pointer on PEB object
 * @count: amount of metadata pages for freeing
 *
 * This method tries to free @count metadata pages into
 * block bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_blk_bmap_free_metapages(struct ssdfs_segment_blk_bmap *ptr,
					  struct ssdfs_peb_info *pebi,
					  u32 count)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebi);
	BUG_ON(!is_ssdfs_peb_container_locked(pebi->pebc));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg_id %llu, peb_index %u, count %u\n",
		  ptr->parent_si->seg_id,
		  pebi->pebc->peb_index, count);
	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->seg_free_blks),
		  atomic_read(&ptr->seg_valid_blks),
		  atomic_read(&ptr->seg_invalid_blks),
		  ptr->pages_per_seg);

	BUG_ON(atomic_read(&ptr->seg_free_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_valid_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_invalid_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	err = ssdfs_define_bmap_index(pebi, &bmap_index, &peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  ptr->parent_si->seg_id,
			  pebi->pebc->peb_index, err);
		return err;
	}

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	err = ssdfs_peb_blk_bmap_free_metapages(peb_blkbmap,
						 bmap_index,
						 count);

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(!is_pages_balance_correct(ptr));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_segment_blk_bmap_reserve_extent() - reserve free extent
 * @ptr: segment block bitmap object
 * @count: number of logical blocks
 * @reserved_blks: number of reserved logical blocks [out]
 *
 * This function tries to reserve some number of free blocks.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - extent has been reserved partially.
 * %-E2BIG      - segment hasn't enough free space.
 */
int ssdfs_segment_blk_bmap_reserve_extent(struct ssdfs_segment_blk_bmap *ptr,
					  u32 count, u32 *reserved_blks)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	u32 reserved_threshold;
	int free_blks = 0;
	int invalid_blks = 0;
	int vacant_blks = 0;
	int reserved_metapages;
	int err = 0, err1 = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !reserved_blks);

	SSDFS_DBG("seg_id %llu, count %u\n",
		  ptr->parent_si->seg_id, count);
	SSDFS_DBG("BEFORE: free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->seg_free_blks),
		  atomic_read(&ptr->seg_valid_blks),
		  atomic_read(&ptr->seg_invalid_blks),
		  ptr->pages_per_seg);

	BUG_ON(atomic_read(&ptr->seg_free_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_valid_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_invalid_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	*reserved_blks = 0;
	si = ptr->parent_si;
	fsi = si->fsi;

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	reserved_threshold = (u32)ptr->pebs_count *
				SSDFS_RESERVED_FREE_PAGE_THRESHOLD_PER_PEB;

	down_write(&ptr->modification_lock);

	free_blks = atomic_read(&ptr->seg_free_blks);
	invalid_blks = atomic_read(&ptr->seg_invalid_blks);
	vacant_blks = free_blks + invalid_blks;
	reserved_metapages = atomic_read(&ptr->seg_reserved_metapages);

	if (reserved_threshold < reserved_metapages)
		reserved_threshold = 0;
	else
		reserved_threshold -= reserved_metapages;

	if (vacant_blks <= reserved_threshold) {
		err = -E2BIG;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu hasn't enough free pages: "
			  "free_pages %d, invalid_pages %d, "
			  "vacant_pages %d, reserved_threshold %u\n",
			  ptr->parent_si->seg_id, free_blks,
			  invalid_blks, vacant_blks,
			  reserved_threshold);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
		vacant_blks -= reserved_threshold;

		if (vacant_blks < count) {
			if (si->seg_type == SSDFS_USER_DATA_SEG_TYPE) {
				err = -EAGAIN;
				*reserved_blks = vacant_blks;
			} else {
				err = -E2BIG;
				*reserved_blks = vacant_blks;
			}

			if (free_blks >= vacant_blks) {
				atomic_sub(*reserved_blks, &ptr->seg_free_blks);
#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(atomic_read(&ptr->seg_free_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
				atomic_set(&ptr->seg_free_blks, 0);
				atomic_sub(vacant_blks - free_blks,
					   &ptr->seg_invalid_blks);
#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(atomic_read(&ptr->seg_invalid_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */
			}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu hasn't enough free pages: "
			  "free_pages %d, invalid_pages %d,"
			  "vacant_pages %d, requested_pages %u, "
			  "reserved_blks %u\n",
			  ptr->parent_si->seg_id, free_blks,
			  invalid_blks, vacant_blks,
			  count, *reserved_blks);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			*reserved_blks = count;

			if (free_blks >= count) {
				atomic_sub(*reserved_blks, &ptr->seg_free_blks);
#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(atomic_read(&ptr->seg_free_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
				atomic_set(&ptr->seg_free_blks, 0);
				atomic_sub(count - free_blks,
					   &ptr->seg_invalid_blks);
#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(atomic_read(&ptr->seg_invalid_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */
			}
		}
	}

	up_write(&ptr->modification_lock);

	if (err == -EAGAIN) {
		/*
		 * Continue logic
		 */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("extent has been allocated partially: "
			  "free_pages %d, invalid_pages %d, "
			  "vacant_pages %d, requested_pages %u, "
			  "reserved_blks %u\n",
			  free_blks, invalid_blks, vacant_blks,
			  count, *reserved_blks);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (err)
		goto finish_reserve_extent;

	if (si->seg_type == SSDFS_USER_DATA_SEG_TYPE) {
		u64 reserved = 0;
		u32 pending = 0;
		u32 mem_pages;

		mem_pages = SSDFS_MEM_PAGES_PER_LOGICAL_BLOCK(fsi);
		mem_pages *= *reserved_blks;

		spin_lock(&fsi->volume_state_lock);
		reserved = fsi->reserved_new_user_data_pages;
		if (fsi->reserved_new_user_data_pages >= mem_pages) {
			fsi->reserved_new_user_data_pages -= mem_pages;
		} else
			err1 = -ERANGE;
		spin_unlock(&fsi->volume_state_lock);

		if (err1) {
			err = err1;
			SSDFS_WARN("count %u is bigger than reserved %llu, "
				   "seg_id %llu\n",
				   mem_pages, reserved, si->seg_id);
			goto finish_reserve_extent;
		}

		spin_lock(&si->pending_lock);
		si->pending_new_user_data_pages += mem_pages;
		pending = si->pending_new_user_data_pages;
		spin_unlock(&si->pending_lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_id %llu, reserved_blks %u, "
			  "reserved_pages %llu, mem_pages %u, "
			  "pending %u\n",
			  si->seg_id, *reserved_blks, reserved,
			  mem_pages, pending);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, count %u, reserved_blks %u\n",
		  ptr->parent_si->seg_id, count, *reserved_blks);
	SSDFS_DBG("AFTER: free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->seg_free_blks),
		  atomic_read(&ptr->seg_valid_blks),
		  atomic_read(&ptr->seg_invalid_blks),
		  ptr->pages_per_seg);
#endif /* CONFIG_SSDFS_DEBUG */

finish_reserve_extent:
#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(!is_pages_balance_correct(ptr));
#endif /* CONFIG_SSDFS_DEBUG */
	return err;
}

/*
 * ssdfs_segment_blk_bmap_reserve_block() - reserve free block
 * @ptr: segment block bitmap object
 * @count: number of logical blocks
 *
 * This function tries to reserve a free block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-E2BIG      - segment hasn't enough free space.
 */
int ssdfs_segment_blk_bmap_reserve_block(struct ssdfs_segment_blk_bmap *ptr)
{
	u32 reserved_blks;

	return ssdfs_segment_blk_bmap_reserve_extent(ptr, 1, &reserved_blks);
}

/*
 * ssdfs_segment_blk_bmap_release_extent() - release the reserved extent
 * @ptr: segment block bitmap object
 * @count: number of logical blocks
 *
 * This function tries to release the reserved extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_blk_bmap_release_extent(struct ssdfs_segment_blk_bmap *ptr,
					  u32 count)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si);

	SSDFS_DBG("seg_id %llu, count %u\n",
		  ptr->parent_si->seg_id, count);
	SSDFS_DBG("BEFORE: free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->seg_free_blks),
		  atomic_read(&ptr->seg_valid_blks),
		  atomic_read(&ptr->seg_invalid_blks),
		  ptr->pages_per_seg);

	BUG_ON(atomic_read(&ptr->seg_free_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_valid_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_invalid_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	down_write(&ptr->modification_lock);
	atomic_add(count, &ptr->seg_free_blks);
	up_write(&ptr->modification_lock);

	si = ptr->parent_si;
	fsi = si->fsi;

	if (si->seg_type == SSDFS_USER_DATA_SEG_TYPE) {
		u64 reserved = 0;
		u32 pending = 0;
		u32 mem_pages;

		mem_pages = SSDFS_MEM_PAGES_PER_LOGICAL_BLOCK(fsi);
		mem_pages *= count;

		spin_lock(&fsi->volume_state_lock);
		reserved = fsi->reserved_new_user_data_pages;
		fsi->reserved_new_user_data_pages += mem_pages;
		spin_unlock(&fsi->volume_state_lock);

		spin_lock(&si->pending_lock);
		pending = si->pending_new_user_data_pages;
		if (si->pending_new_user_data_pages >= mem_pages) {
			si->pending_new_user_data_pages -= mem_pages;
		} else
			err = -ERANGE;
		spin_unlock(&si->pending_lock);

		if (err) {
			SSDFS_WARN("count %u is bigger than pending %u, "
				   "seg_id %llu\n",
				   mem_pages, pending, si->seg_id);
			goto finish_release_extent;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_id %llu, count %u, "
			  "reserved_pages %llu, mem_pages %u, "
			  "pending %u\n",
			  si->seg_id, count, reserved,
			  mem_pages, pending);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, count %u\n",
		  ptr->parent_si->seg_id, count);
	SSDFS_DBG("AFTER: free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->seg_free_blks),
		  atomic_read(&ptr->seg_valid_blks),
		  atomic_read(&ptr->seg_invalid_blks),
		  ptr->pages_per_seg);

	WARN_ON(!is_pages_balance_correct(ptr));
#endif /* CONFIG_SSDFS_DEBUG */

finish_release_extent:
	return err;
}

/*
 * ssdfs_segment_blk_bmap_pre_allocate() - pre-allocate range of blocks
 * @ptr: segment block bitmap object
 * @pebi: pointer on PEB object
 * @range: pointer on blocks' range [in | out]
 *
 * This function tries to find contiguous range of free blocks and
 * to set the found range in pre-allocated state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_blk_bmap_pre_allocate(struct ssdfs_segment_blk_bmap *ptr,
					struct ssdfs_peb_info *pebi,
					struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebi);
	BUG_ON(!is_ssdfs_peb_container_locked(pebi->pebc));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  ptr->parent_si->seg_id,
		  pebi->pebc->peb_index);
	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->seg_free_blks),
		  atomic_read(&ptr->seg_valid_blks),
		  atomic_read(&ptr->seg_invalid_blks),
		  ptr->pages_per_seg);

	BUG_ON(atomic_read(&ptr->seg_free_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_valid_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_invalid_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	err = ssdfs_define_bmap_index(pebi, &bmap_index, &peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  ptr->parent_si->seg_id,
			  pebi->pebc->peb_index, err);
		return err;
	}

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	err = ssdfs_peb_blk_bmap_pre_allocate(peb_blkbmap, bmap_index, range);

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(!is_pages_balance_correct(ptr));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_segment_blk_bmap_allocate() - allocate range of blocks
 * @ptr: segment block bitmap object
 * @pebi: pointer on PEB object
 * @range: pointer on blocks' range [in | out]
 *
 * This function tries to find contiguous range of free blocks and
 * to set the found range in allocated state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_blk_bmap_allocate(struct ssdfs_segment_blk_bmap *ptr,
				    struct ssdfs_peb_info *pebi,
				    struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebi);
	BUG_ON(!is_ssdfs_peb_container_locked(pebi->pebc));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  ptr->parent_si->seg_id,
		  pebi->pebc->peb_index);
	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->seg_free_blks),
		  atomic_read(&ptr->seg_valid_blks),
		  atomic_read(&ptr->seg_invalid_blks),
		  ptr->pages_per_seg);

	BUG_ON(atomic_read(&ptr->seg_free_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_valid_blks) < 0);
	BUG_ON(atomic_read(&ptr->seg_invalid_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	err = ssdfs_define_bmap_index(pebi, &bmap_index, &peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  ptr->parent_si->seg_id,
			  pebi->pebc->peb_index, err);
		return err;
	}

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	err = ssdfs_peb_blk_bmap_allocate(peb_blkbmap, bmap_index, range);

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(!is_pages_balance_correct(ptr));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_segment_blk_bmap_update_range() - update range of blocks' state
 * @ptr: segment block bitmap object
 * @pebi: pointer on PEB object
 * @peb_migration_id: migration_id of PEB
 * @range_state: new state of range
 * @range: pointer on blocks' range [in | out]
 *
 * This function tries to change state of @range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_segment_blk_bmap_update_range(struct ssdfs_segment_blk_bmap *bmap,
				    struct ssdfs_peb_info *pebi,
				    u8 peb_migration_id,
				    int range_state,
				    struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_peb_container *dst_pebc;
	struct ssdfs_peb_blk_bmap *dst_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int migration_state, migration_phase, items_state;
	bool need_migrate = false;
	bool need_move = false;
	int src_migration_id = -1, dst_migration_id = -1;
	int next_id = -1;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->peb || !bmap->parent_si);
	BUG_ON(!pebi || !range);
	BUG_ON(!is_ssdfs_peb_container_locked(pebi->pebc));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_migration_id %u, "
		  "range (start %u, len %u)\n",
		  bmap->parent_si->seg_id, pebi->pebc->peb_index,
		  peb_migration_id, range->start, range->len);

	BUG_ON(atomic_read(&bmap->seg_free_blks) < 0);
	BUG_ON(atomic_read(&bmap->seg_valid_blks) < 0);
	BUG_ON(atomic_read(&bmap->seg_invalid_blks) < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	pebc = pebi->pebc;
	si = pebc->parent_si;

try_define_bmap_index:
	migration_state = atomic_read(&pebc->migration_state);
	migration_phase = atomic_read(&pebc->migration_phase);
	items_state = atomic_read(&pebc->items_state);
	switch (migration_state) {
	case SSDFS_PEB_NOT_MIGRATING:
		need_migrate = false;
		need_move = false;
		bmap_index = SSDFS_PEB_BLK_BMAP_SOURCE;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebc->src_peb);
#endif /* CONFIG_SSDFS_DEBUG */

		src_migration_id =
			ssdfs_get_peb_migration_id_checked(pebc->src_peb);
		if (unlikely(src_migration_id < 0)) {
			err = src_migration_id;
			SSDFS_ERR("invalid peb_migration_id: "
				  "err %d\n",
				  err);
			goto finish_define_bmap_index;
		}

		peb_index = pebc->src_peb->peb_index;
		break;

	case SSDFS_PEB_UNDER_MIGRATION:
		switch (items_state) {
		case SSDFS_PEB1_DST_CONTAINER:
		case SSDFS_PEB2_DST_CONTAINER:
			need_migrate = false;
			need_move = false;
			bmap_index = SSDFS_PEB_BLK_BMAP_SOURCE;
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

			dst_migration_id =
			    ssdfs_get_peb_migration_id_checked(pebc->dst_peb);
			if (unlikely(dst_migration_id < 0)) {
				err = dst_migration_id;
				SSDFS_ERR("invalid peb_migration_id: "
					  "err %d\n",
					  err);
				goto finish_define_bmap_index;
			}

			if (peb_migration_id != dst_migration_id) {
				err = -ERANGE;
				SSDFS_ERR("migration_id %u != "
					  "dst_migration_id %u\n",
					  peb_migration_id,
					  dst_migration_id);
				goto finish_define_bmap_index;
			}
			peb_index = pebc->dst_peb->peb_index;
			break;

		case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
		case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!pebc->src_peb || !pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

			src_migration_id =
			    ssdfs_get_peb_migration_id_checked(pebc->src_peb);
			if (unlikely(src_migration_id < 0)) {
				err = src_migration_id;
				SSDFS_ERR("invalid peb_migration_id: "
					  "err %d\n",
					  err);
				goto finish_define_bmap_index;
			}

			dst_migration_id =
			    ssdfs_get_peb_migration_id_checked(pebc->dst_peb);
			if (unlikely(dst_migration_id < 0)) {
				err = dst_migration_id;
				SSDFS_ERR("invalid peb_migration_id: "
					  "err %d\n",
					  err);
				goto finish_define_bmap_index;
			}

			if (src_migration_id == dst_migration_id) {
				err = -ERANGE;
				SSDFS_ERR("src_migration_id %u == "
					  "dst_migration_id %u\n",
					  src_migration_id,
					  dst_migration_id);
				goto finish_define_bmap_index;
			}

			if (peb_migration_id == src_migration_id) {
				int state;

				need_migrate = true;
				need_move = false;

				dst_pebc = pebc->dst_peb->pebc;
				state = atomic_read(&dst_pebc->items_state);
				switch (state) {
				case SSDFS_PEB1_DST_CONTAINER:
				case SSDFS_PEB2_DST_CONTAINER:
					bmap_index = SSDFS_PEB_BLK_BMAP_SOURCE;
					break;

				case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
				case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
					bmap_index =
					    SSDFS_PEB_BLK_BMAP_DESTINATION;
					break;

				default:
					BUG();
				}

				peb_index = U16_MAX;
			} else if (peb_migration_id == dst_migration_id) {
				err = -ERANGE;
				SSDFS_WARN("invalid request: "
					   "peb_migration_id %u, "
					   "dst_migration_id %u\n",
					   peb_migration_id,
					   dst_migration_id);
				goto finish_define_bmap_index;
			} else {
				err = -ERANGE;
				SSDFS_ERR("fail to select PEB: "
					  "peb_migration_id %u, "
					  "src_migration_id %u, "
					  "dst_migration_id %u\n",
					  peb_migration_id,
					  src_migration_id,
					  dst_migration_id);
				goto finish_define_bmap_index;
			}
			break;

		case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
		case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!pebc->src_peb || !pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

			src_migration_id =
			    ssdfs_get_peb_migration_id_checked(pebc->src_peb);
			if (unlikely(src_migration_id < 0)) {
				err = src_migration_id;
				SSDFS_ERR("invalid peb_migration_id: "
					  "err %d\n",
					  err);
				goto finish_define_bmap_index;
			}

			dst_migration_id =
			    ssdfs_get_peb_migration_id_checked(pebc->dst_peb);
			if (unlikely(dst_migration_id < 0)) {
				err = dst_migration_id;
				SSDFS_ERR("invalid peb_migration_id: "
					  "err %d\n",
					  err);
				goto finish_define_bmap_index;
			}

			if (src_migration_id == dst_migration_id) {
				err = -ERANGE;
				SSDFS_ERR("src_migration_id %u == "
					  "dst_migration_id %u\n",
					  src_migration_id,
					  dst_migration_id);
				goto finish_define_bmap_index;
			}

			if (!is_peb_migration_id_valid(peb_migration_id)) {
				err = -ERANGE;
				SSDFS_ERR("fail to select PEB: "
					  "peb_migration_id %u, "
					  "src_migration_id %u, "
					  "dst_migration_id %u\n",
					  peb_migration_id,
					  src_migration_id,
					  dst_migration_id);
				goto finish_define_bmap_index;
			}

			next_id = peb_migration_id;
			next_id = __ssdfs_define_next_peb_migration_id(next_id);

			if (peb_migration_id == src_migration_id) {
				switch (migration_phase) {
				case SSDFS_SRC_PEB_NOT_EXHAUSTED:
					need_migrate = false;
					need_move = false;
					bmap_index =
						SSDFS_PEB_BLK_BMAP_SOURCE;
					peb_index = pebc->src_peb->peb_index;
					break;

				default:
					need_migrate = true;
					need_move = false;
					bmap_index =
						SSDFS_PEB_BLK_BMAP_INDEX_MAX;
					peb_index = pebc->src_peb->peb_index;
					break;
				}
			} else if (peb_migration_id == dst_migration_id) {
				need_migrate = false;
				need_move = false;
				bmap_index = SSDFS_PEB_BLK_BMAP_DESTINATION;
				peb_index = pebc->dst_peb->peb_index;
			} else if (next_id == src_migration_id) {
				switch (migration_phase) {
				case SSDFS_SRC_PEB_NOT_EXHAUSTED:
					need_migrate = false;
					need_move = false;
					bmap_index =
						SSDFS_PEB_BLK_BMAP_SOURCE;
					peb_index = pebc->src_peb->peb_index;
					break;

				default:
					need_migrate = false;
					need_move = true;
					bmap_index =
					    SSDFS_PEB_BLK_BMAP_DESTINATION;
					peb_index = pebc->dst_peb->peb_index;
					break;
				}
			} else {
				need_migrate = false;
				need_move = true;
				bmap_index = SSDFS_PEB_BLK_BMAP_DESTINATION;
				peb_index = pebc->dst_peb->peb_index;
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_WARN("invalid items_state %#x\n",
				   items_state);
			goto finish_define_bmap_index;
		};
		break;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
	case SSDFS_PEB_FINISHING_MIGRATION:
#ifdef CONFIG_SSDFS_DEBUG
		/* unexpected situation */
		SSDFS_WARN("unexpected situation\n");
#endif /* CONFIG_SSDFS_DEBUG */
		err = -EAGAIN;
		goto finish_define_bmap_index;
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid migration_state %#x\n",
			   migration_state);
		goto finish_define_bmap_index;
	}

finish_define_bmap_index:
	if (err == -EAGAIN) {
		DEFINE_WAIT(wait);

		err = 0;

		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_peb_container_unlock(pebc);

		prepare_to_wait(&pebc->migration_wq, &wait,
				TASK_UNINTERRUPTIBLE);
		schedule();
		finish_wait(&pebc->migration_wq, &wait);

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			return err;
		}
		ssdfs_peb_current_log_lock(pebi);
		goto try_define_bmap_index;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(need_migrate && need_move);

	SSDFS_DBG("seg_id %llu, migration_state %#x, items_state %#x, "
		  "peb_migration_id %u, src_migration_id %d, "
		  "dst_migration_id %d, migration_phase %#x\n",
		  si->seg_id, migration_state, items_state,
		  peb_migration_id, src_migration_id,
		  dst_migration_id, migration_phase);
	SSDFS_DBG("seg_id %llu, need_migrate %#x, "
		  "need_move %#x, bmap_index %#x\n",
		  si->seg_id, need_migrate,
		  need_move, bmap_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (need_migrate) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(peb_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		if (peb_index >= bmap->pebs_count) {
			SSDFS_ERR("peb_index %u >= pebs_count %u\n",
				  peb_index, bmap->pebs_count);
			return -ERANGE;
		}

		dst_blkbmap = &bmap->peb[peb_index];

		err = ssdfs_peb_blk_bmap_migrate(dst_blkbmap,
						 range_state,
						 range);
		if (unlikely(err)) {
			SSDFS_ERR("fail to migrate: "
				  "range (start %u, len %u), "
				  "range_state %#x, "
				  "err %d\n",
				  range->start, range->len,
				  range_state, err);
			SSDFS_ERR("seg_id %llu, peb_index %u, "
				  "peb_migration_id %u, "
				  "range (start %u, len %u)\n",
				  bmap->parent_si->seg_id,
				  pebc->peb_index,
				  peb_migration_id,
				  range->start, range->len);
			SSDFS_ERR("seg_id %llu, migration_state %#x, "
				  "items_state %#x, "
				  "peb_migration_id %u, src_migration_id %d, "
				  "dst_migration_id %d, migration_phase %#x\n",
				  si->seg_id, migration_state, items_state,
				  peb_migration_id, src_migration_id,
				  dst_migration_id, migration_phase);
			SSDFS_ERR("seg_id %llu, need_migrate %#x, "
				  "need_move %#x\n",
				  si->seg_id, need_migrate, need_move);
			return err;
		}
	} else if (need_move) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

		peb_index = pebc->dst_peb->peb_index;

		if (peb_index >= bmap->pebs_count) {
			SSDFS_ERR("peb_index %u >= pebs_count %u\n",
				  peb_index, bmap->pebs_count);
			return -ERANGE;
		}

		dst_blkbmap = &bmap->peb[peb_index];

		if (range_state == SSDFS_BLK_PRE_ALLOCATED) {
			err = ssdfs_peb_blk_bmap_pre_allocate(dst_blkbmap,
							      bmap_index,
							      range);
		} else {
			err = ssdfs_peb_blk_bmap_allocate(dst_blkbmap,
							  bmap_index,
							  range);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to move: "
				  "range (start %u, len %u), "
				  "range_state %#x, "
				  "err %d\n",
				  range->start, range->len,
				  range_state, err);
			SSDFS_ERR("seg_id %llu, peb_index %u, "
				  "peb_migration_id %u, "
				  "range (start %u, len %u)\n",
				  bmap->parent_si->seg_id,
				  pebc->peb_index,
				  peb_migration_id,
				  range->start, range->len);
			SSDFS_ERR("seg_id %llu, migration_state %#x, "
				  "items_state %#x, "
				  "peb_migration_id %u, src_migration_id %d, "
				  "dst_migration_id %d, migration_phase %#x\n",
				  si->seg_id, migration_state, items_state,
				  peb_migration_id, src_migration_id,
				  dst_migration_id, migration_phase);
			SSDFS_ERR("seg_id %llu, need_migrate %#x, "
				  "need_move %#x\n",
				  si->seg_id, need_migrate, need_move);
			return err;
		}
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(peb_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		if (peb_index >= bmap->pebs_count) {
			SSDFS_ERR("peb_index %u >= pebs_count %u\n",
				  peb_index, bmap->pebs_count);
			return -ERANGE;
		}

		dst_blkbmap = &bmap->peb[peb_index];

		err = ssdfs_peb_blk_bmap_update_range(dst_blkbmap,
						      bmap_index,
						      range_state,
						      range);
		if (unlikely(err)) {
			SSDFS_ERR("fail to update range: "
				  "range (start %u, len %u), "
				  "range_state %#x, "
				  "err %d\n",
				  range->start, range->len,
				  range_state, err);
			SSDFS_ERR("seg_id %llu, peb_index %u, "
				  "peb_migration_id %u, "
				  "range (start %u, len %u)\n",
				  bmap->parent_si->seg_id,
				  pebc->peb_index,
				  peb_migration_id,
				  range->start, range->len);
			SSDFS_ERR("seg_id %llu, migration_state %#x, "
				  "items_state %#x, "
				  "peb_migration_id %u, src_migration_id %d, "
				  "dst_migration_id %d, migration_phase %#x\n",
				  si->seg_id, migration_state, items_state,
				  peb_migration_id, src_migration_id,
				  dst_migration_id, migration_phase);
			SSDFS_ERR("seg_id %llu, need_migrate %#x, "
				  "need_move %#x\n",
				  si->seg_id, need_migrate, need_move);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(!is_pages_balance_correct(bmap));
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}
