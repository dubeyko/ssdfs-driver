//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_block_bitmap.c - segment's block bitmap implementation.
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
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "page_array.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "page_array.h"
#include "segment.h"

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
 * @pages_per_peb: count of pages per PEB
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
				  u32 pages_per_peb,
				  int init_flag, int init_state)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_blk_bmap *bmap;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("si %p, seg_id %llu, "
		  "pages_per_peb %u, "
		  "init_flag %#x, init_state %#x\n",
		  si, si->seg_id, pages_per_peb,
		  init_flag, init_state);

	fsi = si->fsi;
	bmap = &si->blk_bmap;

	bmap->parent_si = si;
	atomic_set(&bmap->state, SSDFS_SEG_BLK_BMAP_STATE_UNKNOWN);

	bmap->pages_per_peb = fsi->pages_per_peb;
	bmap->pages_per_seg = fsi->pages_per_seg;

	atomic_set(&bmap->valid_logical_blks, 0);
	atomic_set(&bmap->invalid_logical_blks, 0);
	atomic_set(&bmap->free_logical_blks, 0);

	bmap->pebs_count = si->pebs_count;

	bmap->peb = kcalloc(bmap->pebs_count,
			    sizeof(struct ssdfs_peb_blk_bmap),
			    GFP_KERNEL);
	if (!bmap->peb) {
		SSDFS_ERR("fail to allocate PEBs' block bitmaps\n");
		return -ENOMEM;
	}

	for (i = 0; i < bmap->pebs_count; i++) {
		err = ssdfs_peb_blk_bmap_create(bmap, i, pages_per_peb,
						init_flag, init_state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create PEB's block bitmap: "
				  "peb_index %u, err %d\n",
				  i, err);
			goto fail_create_seg_blk_bmap;
		}
	}

	set_seg_block_bmap_created(bmap);
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
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->parent_si);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, state %#x\n",
		  ptr->parent_si->seg_id,
		  atomic_read(&ptr->state));

	atomic_set(&ptr->valid_logical_blks, 0);
	atomic_set(&ptr->invalid_logical_blks, 0);
	atomic_set(&ptr->free_logical_blks, 0);

	for (i = 0; i < ptr->pebs_count; i++)
		ssdfs_peb_blk_bmap_destroy(&ptr->peb[i]);

	kfree(ptr->peb);
	ptr->peb = NULL;

	atomic_set(&ptr->state, SSDFS_SEG_BLK_BMAP_STATE_UNKNOWN);
}

/*
 * ssdfs_segment_blk_bmap_partial_init() - partial init of segment bitmap
 * @bmap: pointer on segment block bitmap
 * @peb_index: PEB's index
 * @source: pointer on pagevec with bitmap state
 * @hdr: header of block bitmap fragment
 * @cno: log's checkpoint
 */
int ssdfs_segment_blk_bmap_partial_init(struct ssdfs_segment_blk_bmap *bmap,
					u16 peb_index,
					struct pagevec *source,
					struct ssdfs_block_bitmap_fragment *hdr,
					u64 cno)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->peb || !bmap->parent_si);
	BUG_ON(!source || !hdr);
	BUG_ON(pagevec_count(source) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, cno %llu\n",
		  bmap->parent_si->seg_id, peb_index, cno);

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

	return ssdfs_peb_blk_bmap_init(&bmap->peb[peb_index],
					source, hdr, cno);
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
 * ssdfs_define_bmap_index() - define block bitmap for operation
 * @pebc: pointer on PEB container
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
int ssdfs_define_bmap_index(struct ssdfs_peb_container *pebc,
			    int *bmap_index, u16 *peb_index)
{
	struct ssdfs_segment_info *si;
	int migration_state, items_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
	BUG_ON(!bmap_index || !peb_index);
	BUG_ON(!rwsem_is_locked(&pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);

	si = pebc->parent_si;
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
		prepare_to_wait(&si->migration.wait, &wait,
				TASK_UNINTERRUPTIBLE);
		schedule();
		finish_wait(&si->migration.wait, &wait);
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

/*
 * ssdfs_segment_blk_bmap_reserve_metapages() - reserve metapages
 * @ptr: segment block bitmap object
 * @pebc: pointer on PEB container
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
					     struct ssdfs_peb_container *pebc,
					     u16 count)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebc);
	BUG_ON(!rwsem_is_locked(&pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, count %u\n",
		  ptr->parent_si->seg_id,
		  pebc->peb_index, count);

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	err = ssdfs_define_bmap_index(pebc, &bmap_index, &peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  ptr->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	return ssdfs_peb_blk_bmap_reserve_metapages(peb_blkbmap,
						    bmap_index,
						    count);
}

/*
 * ssdfs_segment_blk_bmap_free_metapages() - free metapages
 * @ptr: segment block bitmap object
 * @pebc: pointer on PEB container
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
					  struct ssdfs_peb_container *pebc,
					  u16 count)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebc);
	BUG_ON(!rwsem_is_locked(&pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, count %u\n",
		  ptr->parent_si->seg_id,
		  pebc->peb_index, count);

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	err = ssdfs_define_bmap_index(pebc, &bmap_index, &peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  ptr->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	return ssdfs_peb_blk_bmap_free_metapages(peb_blkbmap,
						 bmap_index,
						 count);
}

/*
 * ssdfs_segment_blk_bmap_pre_allocate() - pre-allocate range of blocks
 * @ptr: segment block bitmap object
 * @pebc: pointer on PEB container
 * @len: pointer on variable with requested length of range
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
					struct ssdfs_peb_container *pebc,
					u32 *len,
					struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebc);
	BUG_ON(!rwsem_is_locked(&pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  ptr->parent_si->seg_id,
		  pebc->peb_index);

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	err = ssdfs_define_bmap_index(pebc, &bmap_index, &peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  ptr->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	return ssdfs_peb_blk_bmap_pre_allocate(peb_blkbmap, bmap_index,
						len, range);
}

/*
 * ssdfs_segment_blk_bmap_allocate() - allocate range of blocks
 * @ptr: segment block bitmap object
 * @pebc: pointer on PEB container
 * @len: pointer on variable with requested length of range
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
				    struct ssdfs_peb_container *pebc,
				    u32 *len,
				    struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->peb || !ptr->parent_si || !pebc);
	BUG_ON(!rwsem_is_locked(&pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  ptr->parent_si->seg_id,
		  pebc->peb_index);

	if (atomic_read(&ptr->state) != SSDFS_SEG_BLK_BMAP_CREATED) {
		SSDFS_ERR("invalid segment block bitmap state %#x\n",
			  atomic_read(&ptr->state));
		return -ERANGE;
	}

	err = ssdfs_define_bmap_index(pebc, &bmap_index, &peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define bmap_index: "
			  "seg %llu, peb_index %u, err %d\n",
			  ptr->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

	if (peb_index >= ptr->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  peb_index, ptr->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &ptr->peb[peb_index];

	return ssdfs_peb_blk_bmap_allocate(peb_blkbmap, bmap_index,
					   len, range);
}

/*
 * ssdfs_segment_blk_bmap_update_range() - update range of blocks' state
 * @ptr: segment block bitmap object
 * @pebc: pointer on PEB container
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
				    struct ssdfs_peb_container *pebc,
				    u8 peb_migration_id,
				    int range_state,
				    struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *dst_pebc;
	struct ssdfs_peb_blk_bmap *src_blkbmap, *dst_blkbmap;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	u16 peb_index;
	int migration_state, migration_phase, items_state;
	bool need_migrate = false;
	bool need_move = false;
	int src_migration_id = -1, dst_migration_id = -1;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->peb || !bmap->parent_si);
	BUG_ON(!pebc || !range);
	BUG_ON(!rwsem_is_locked(&pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_migration_id %u\n",
		  bmap->parent_si->seg_id, pebc->peb_index,
		  peb_migration_id);

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

		if (peb_migration_id != src_migration_id) {
			err = -ERANGE;
			SSDFS_ERR("migration_id %u != src_migration_id %u\n",
				  peb_migration_id,
				  src_migration_id);
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

				need_migrate = false;
				need_move = true;

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
			} else if ((peb_migration_id + 1) == src_migration_id) {
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
					need_move = false;
					bmap_index =
					    SSDFS_PEB_BLK_BMAP_DESTINATION;
					peb_index = pebc->dst_peb->peb_index;
					break;
				}
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

		default:
			err = -ERANGE;
			SSDFS_WARN("invalid items_state %#x\n",
				   items_state);
			goto finish_define_bmap_index;
		};
		break;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
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
		prepare_to_wait(&si->migration.wait, &wait,
				TASK_UNINTERRUPTIBLE);
		schedule();
		finish_wait(&si->migration.wait, &wait);
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, migration_state %#x, items_state %#x, "
		  "peb_migration_id %u, src_migration_id %d, "
		  "dst_migration_id %d\n",
		  si->seg_id, migration_state, items_state,
		  peb_migration_id, src_migration_id, dst_migration_id);
	SSDFS_DBG("seg_id %llu, need_migrate %#x, need_move %#x\n",
		  si->seg_id, need_migrate, need_move);

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
			return err;
		}
	} else if (need_move) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebc->src_peb || !pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

		peb_index = pebc->src_peb->peb_index;

		if (peb_index >= bmap->pebs_count) {
			SSDFS_ERR("peb_index %u >= pebs_count %u\n",
				  peb_index, bmap->pebs_count);
			return -ERANGE;
		}

		src_blkbmap = &bmap->peb[peb_index];

		err = ssdfs_peb_blk_bmap_invalidate(src_blkbmap,
						    SSDFS_PEB_BLK_BMAP_SOURCE,
						    range);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate: "
				  "range (start %u, len %u), "
				  "err %d\n",
				  range->start, range->len,
				  err);
			return err;
		}

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
							      NULL,
							      range);
		} else {
			err = ssdfs_peb_blk_bmap_allocate(dst_blkbmap,
							  bmap_index,
							  NULL,
							  range);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to move: "
				  "range (start %u, len %u), "
				  "range_state %#x, "
				  "err %d\n",
				  range->start, range->len,
				  range_state, err);
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
			return err;
		}
	}

	return 0;
}
