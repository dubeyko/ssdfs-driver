//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_block_bitmap.c - PEB's block bitmap implementation.
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
#include "segment.h"

#define SSDFS_PEB_BLK_BMAP_STATE_FNS(value, name)			\
static inline								\
bool is_peb_block_bmap_##name(struct ssdfs_peb_blk_bmap *bmap)		\
{									\
	return atomic_read(&bmap->state) == SSDFS_PEB_BLK_BMAP_##value;	\
}									\
static inline								\
void set_peb_block_bmap_##name(struct ssdfs_peb_blk_bmap *bmap)		\
{									\
	atomic_set(&bmap->state, SSDFS_PEB_BLK_BMAP_##value);		\
}									\

/*
 * is_peb_block_bmap_created()
 * set_peb_block_bmap_created()
 */
SSDFS_PEB_BLK_BMAP_STATE_FNS(CREATED, created)

/*
 * is_peb_block_bmap_initialized()
 * set_peb_block_bmap_initialized()
 */
SSDFS_PEB_BLK_BMAP_STATE_FNS(INITIALIZED, initialized)

bool ssdfs_peb_blk_bmap_initialized(struct ssdfs_peb_blk_bmap *ptr)
{
	return is_peb_block_bmap_initialized(ptr);
}

/*
 * ssdfs_peb_blk_bmap_create() - construct PEB's block bitmap
 * @parent: parent segment's block bitmap
 * @peb_index: PEB's index in segment's array
 * @items_count: count of described items
 * @flag: define necessity to allocate memory
 * @init_flag: definition of block bitmap's creation state
 * @init_state: block state is used during initialization
 *
 * This function tries to create the source and destination block
 * bitmap objects.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_blk_bmap_create(struct ssdfs_segment_blk_bmap *parent,
			      u16 peb_index, u32 items_count,
			      int init_flag, int init_state)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_blk_bmap *bmap;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!parent || !parent->peb);
	BUG_ON(peb_index >= parent->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("parent %p, peb_index %u, "
		  "items_count %u, init_flag %#x, init_state %#x\n",
		  parent, peb_index,
		  items_count, init_flag, init_state);

	fsi = parent->parent_si->fsi;
	bmap = &parent->peb[peb_index];
	atomic_set(&bmap->state, SSDFS_PEB_BLK_BMAP_STATE_UNKNOWN);

	if (items_count > parent->pages_per_peb) {
		SSDFS_ERR("items_count %u > pages_per_peb %u\n",
			  items_count, parent->pages_per_peb);
		return -ERANGE;
	}

	bmap->parent = parent;
	bmap->peb_index = peb_index;
	bmap->pages_per_peb = parent->pages_per_peb;

	atomic_set(&bmap->valid_logical_blks, 0);
	atomic_set(&bmap->invalid_logical_blks, 0);
	atomic_set(&bmap->free_logical_blks, 0);

	atomic_set(&bmap->buffers_state, SSDFS_PEB_BMAP_BUFFERS_EMPTY);
	init_rwsem(&bmap->lock);
	bmap->init_cno = U64_MAX;

	err = ssdfs_block_bmap_create(fsi,
				      &bmap->buffer[SSDFS_PEB_BLK_BMAP1],
				      items_count, init_flag, init_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create source block bitmap: "
			  "peb_index %u, items_count %u, "
			  "init_flag %#x, init_state %#x\n",
			  peb_index, items_count,
			  init_flag, init_state);
		goto fail_create_peb_bmap;
	}

	err = ssdfs_block_bmap_create(fsi,
				      &bmap->buffer[SSDFS_PEB_BLK_BMAP2],
				      items_count,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create destination block bitmap: "
			  "peb_index %u, items_count %u\n",
			  peb_index, items_count);
		goto fail_create_peb_bmap;
	}

	if (init_flag == SSDFS_BLK_BMAP_CREATE) {
		atomic_set(&bmap->free_logical_blks, items_count);
		atomic_add(items_count, &parent->free_logical_blks);
	}

	bmap->src = &bmap->buffer[SSDFS_PEB_BLK_BMAP1];
	bmap->dst = NULL;

	init_completion(&bmap->init_end);

	atomic_set(&bmap->buffers_state, SSDFS_PEB_BMAP1_SRC);
	atomic_set(&bmap->state, SSDFS_PEB_BLK_BMAP_CREATED);
	return 0;

fail_create_peb_bmap:
	ssdfs_peb_blk_bmap_destroy(bmap);
	return err;
}

/*
 * ssdfs_peb_blk_bmap_destroy() - destroy PEB's block bitmap
 * @ptr: PEB's block bitmap object
 *
 * This function tries to destroy PEB's block bitmap object.
 */
void ssdfs_peb_blk_bmap_destroy(struct ssdfs_peb_blk_bmap *ptr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
	BUG_ON(rwsem_is_locked(&ptr->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "state %#x, valid_logical_blks %d, "
		  "invalid_logical_blks %d, "
		  "free_logical_blks %d\n",
		  ptr, ptr->peb_index,
		  atomic_read(&ptr->state),
		  atomic_read(&ptr->valid_logical_blks),
		  atomic_read(&ptr->invalid_logical_blks),
		  atomic_read(&ptr->free_logical_blks));

	if (!is_peb_block_bmap_initialized(ptr))
		SSDFS_WARN("PEB's block bitmap hasn't been initialized\n");

	atomic_set(&ptr->valid_logical_blks, 0);
	atomic_set(&ptr->invalid_logical_blks, 0);
	atomic_set(&ptr->free_logical_blks, 0);

	ptr->src = NULL;
	ptr->dst = NULL;
	atomic_set(&ptr->buffers_state, SSDFS_PEB_BMAP_BUFFERS_EMPTY);

	ssdfs_block_bmap_destroy(&ptr->buffer[SSDFS_PEB_BLK_BMAP1]);
	ssdfs_block_bmap_destroy(&ptr->buffer[SSDFS_PEB_BLK_BMAP2]);

	atomic_set(&ptr->state, SSDFS_PEB_BLK_BMAP_STATE_UNKNOWN);
}

/*
 * ssdfs_peb_blk_bmap_init() - init PEB's block bitmap
 * @bmap: pointer on PEB's block bitmap object
 * @source: pointer on pagevec with bitmap state
 * @hdr: header of block bitmap fragment
 * @cno: log's checkpoint
 *
 * This function tries to init PEB's block bitmap.
 *
 * RETURN:
 * [success] - count of free pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 */
int ssdfs_peb_blk_bmap_init(struct ssdfs_peb_blk_bmap *bmap,
			    struct pagevec *source,
			    struct ssdfs_block_bitmap_fragment *hdr,
			    u64 cno)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_block_bmap *blk_bmap = NULL;
	int bmap_state = SSDFS_PEB_BLK_BMAP_STATE_UNKNOWN;
	bool is_dst_peb_clean = false;
	u16 flags;
	u16 type;
	bool under_migration = false;
	bool has_ext_ptr = false;
	bool has_relation = false;
	u64 old_cno = U64_MAX;
	u16 last_free_blk;
	u16 metadata_blks;
	u16 free_blks;
	u16 used_blks;
	u16 invalid_blks;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->parent || !bmap->parent->parent_si);
	BUG_ON(!bmap->parent->parent_si->peb_array);
	BUG_ON(!source || !hdr);
	BUG_ON(pagevec_count(source) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = bmap->parent->parent_si->fsi;
	si = bmap->parent->parent_si;

	SSDFS_DBG("seg_id %llu, peb_index %u, cno %llu\n",
		  si->seg_id, bmap->peb_index, cno);

	bmap_state = atomic_read(&bmap->state);
	switch (bmap_state) {
	case SSDFS_PEB_BLK_BMAP_CREATED:
		/* regular init */
		break;

	case SSDFS_PEB_BLK_BMAP_HAS_CLEAN_DST:
		/*
		 * PEB container is under migration.
		 * But the destination PEB is clean.
		 * It means that destination PEB doesn't need
		 * in init operation.
		 */
		is_dst_peb_clean = true;
		break;

	default:
		SSDFS_ERR("invalid PEB block bitmap state %#x\n",
			  atomic_read(&bmap->state));
		return -ERANGE;
	}

	if (bmap->peb_index >= si->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  bmap->peb_index, si->pebs_count);
		return -ERANGE;
	}

	pebc = &si->peb_array[bmap->peb_index];

	flags = le16_to_cpu(hdr->flags);
	type = le16_to_cpu(hdr->type);

	if (flags & ~SSDFS_FRAG_BLK_BMAP_FLAG_MASK) {
		SSDFS_ERR("invalid flags set: %#x\n", flags);
		return -EIO;
	}

	if (type >= SSDFS_FRAG_BLK_BMAP_TYPE_MAX) {
		SSDFS_ERR("invalid type: %#x\n", type);
		return -EIO;
	}

	if (is_dst_peb_clean) {
		under_migration = true;
		has_relation = true;
	} else {
		under_migration = flags & SSDFS_MIGRATING_BLK_BMAP;
		has_ext_ptr = flags & SSDFS_PEB_HAS_EXT_PTR;
		has_relation = flags & SSDFS_PEB_HAS_RELATION;
	}

	if (type == SSDFS_SRC_BLK_BMAP && (has_ext_ptr && has_relation)) {
		SSDFS_ERR("invalid flags set: %#x\n", flags);
		return -EIO;
	}

	down_write(&bmap->lock);

	old_cno = bmap->init_cno;
	if (bmap->init_cno == U64_MAX)
		bmap->init_cno = cno;
	else if (bmap->init_cno != cno) {
		err = -ERANGE;
		SSDFS_ERR("invalid bmap state: "
			  "bmap->init_cno %llu, cno %llu\n",
			  bmap->init_cno, cno);
		goto fail_init_blk_bmap;
	}

	switch (type) {
	case SSDFS_SRC_BLK_BMAP:
		if (under_migration && has_relation) {
			if (is_dst_peb_clean)
				bmap->dst = &bmap->buffer[SSDFS_PEB_BLK_BMAP2];
			bmap->src = &bmap->buffer[SSDFS_PEB_BLK_BMAP1];
			blk_bmap = bmap->src;
			atomic_set(&bmap->buffers_state,
				    SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST);
		} else if (under_migration && has_ext_ptr) {
			bmap->src = &bmap->buffer[SSDFS_PEB_BLK_BMAP1];
			blk_bmap = bmap->src;
			atomic_set(&bmap->buffers_state,
				    SSDFS_PEB_BMAP1_SRC);
		} else if (under_migration) {
			err = -EIO;
			SSDFS_ERR("invalid flags set: %#x\n", flags);
			goto fail_init_blk_bmap;
		} else {
			bmap->src = &bmap->buffer[SSDFS_PEB_BLK_BMAP1];
			blk_bmap = bmap->src;
			atomic_set(&bmap->buffers_state,
				    SSDFS_PEB_BMAP1_SRC);
		}
		break;

	case SSDFS_DST_BLK_BMAP:
		if (under_migration && has_relation) {
			bmap->dst = &bmap->buffer[SSDFS_PEB_BLK_BMAP2];
			blk_bmap = bmap->dst;
			atomic_set(&bmap->buffers_state,
				    SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST);
		} else if (under_migration && has_ext_ptr) {
			bmap->src = &bmap->buffer[SSDFS_PEB_BLK_BMAP1];
			blk_bmap = bmap->src;
			atomic_set(&bmap->buffers_state,
				    SSDFS_PEB_BMAP1_SRC);
		} else {
			err = -EIO;
			SSDFS_ERR("invalid flags set: %#x\n", flags);
			goto fail_init_blk_bmap;
		}
		break;

	default:
		BUG();
	}

	last_free_blk = le16_to_cpu(hdr->last_free_blk);
	metadata_blks = le16_to_cpu(hdr->metadata_blks);
	invalid_blks = le16_to_cpu(hdr->invalid_blks);

	SSDFS_DBG("last_free_blk %u, metadata_blks %u, invalid_blks %u\n",
		  last_free_blk, metadata_blks, invalid_blks);

	err = ssdfs_block_bmap_lock(blk_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock bitmap: err %d\n", err);
		goto fail_init_blk_bmap;
	}

	err = ssdfs_block_bmap_init(blk_bmap, source, last_free_blk,
				    metadata_blks, invalid_blks);
	if (unlikely(err)) {
		SSDFS_ERR("fail to initialize block bitmap: "
			  "err %d\n", err);
		goto fail_define_pages_count;
	}

	err = ssdfs_block_bmap_get_free_pages(blk_bmap);
	if (unlikely(err < 0)) {
		SSDFS_ERR("fail to get free pages: err %d\n", err);
		goto fail_define_pages_count;
	} else if (unlikely(err >= U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("fail to get free pages: err %d\n", err);
		goto fail_define_pages_count;
	} else {
		free_blks = (u16)err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_used_pages(blk_bmap);
	if (unlikely(err < 0)) {
		SSDFS_ERR("fail to get used pages: err %d\n", err);
		goto fail_define_pages_count;
	} else if (unlikely(err >= U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("fail to get used pages: err %d\n", err);
		goto fail_define_pages_count;
	} else {
		used_blks = (u16)err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_invalid_pages(blk_bmap);
	if (unlikely(err < 0)) {
		SSDFS_ERR("fail to get invalid pages: err %d\n", err);
		goto fail_define_pages_count;
	} else if (unlikely(err >= U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("fail to get invalid pages: err %d\n", err);
		goto fail_define_pages_count;
	} else {
		invalid_blks = (u16)err;
		err = 0;
	}

fail_define_pages_count:
	ssdfs_block_bmap_unlock(blk_bmap);

	if (unlikely(err))
		goto fail_init_blk_bmap;

	SSDFS_DBG("type %#x, under_migration %#x, has_relation %#x, "
		  "last_free_blk %u, metadata_blks %u, "
		  "free_blks %u, used_blks %u, "
		  "invalid_blks %u, shared_free_dst_blks %d\n",
		  type, under_migration, has_relation,
		  last_free_blk, metadata_blks,
		  free_blks, used_blks, invalid_blks,
		  atomic_read(&pebc->shared_free_dst_blks));

	SSDFS_DBG("free_blks %d, valid_blks %d, invalid_blks %d\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks));

	switch (type) {
	case SSDFS_SRC_BLK_BMAP:
		if (is_dst_peb_clean && !(flags & SSDFS_MIGRATING_BLK_BMAP)) {
			atomic_set(&bmap->valid_logical_blks, used_blks);
			atomic_set(&bmap->free_logical_blks, free_blks);

			atomic_add(fsi->pages_per_peb - used_blks,
					&bmap->free_logical_blks);
			atomic_set(&pebc->shared_free_dst_blks,
					fsi->pages_per_peb - used_blks);

			atomic_add(atomic_read(&bmap->valid_logical_blks),
				   &bmap->parent->valid_logical_blks);
			atomic_add(atomic_read(&bmap->free_logical_blks),
				   &bmap->parent->free_logical_blks);
		} else if (under_migration && has_relation) {
			atomic_add(used_blks, &bmap->valid_logical_blks);
			atomic_sub(used_blks, &bmap->free_logical_blks);
			atomic_sub(used_blks, &pebc->shared_free_dst_blks);
			atomic_sub(used_blks,
				   &bmap->parent->free_logical_blks);
		} else if (under_migration && has_ext_ptr) {
			atomic_add(used_blks, &bmap->valid_logical_blks);
			atomic_add(invalid_blks, &bmap->invalid_logical_blks);
			atomic_add(free_blks, &bmap->free_logical_blks);
		} else if (under_migration) {
			err = -EIO;
			SSDFS_ERR("invalid flags set: %#x\n", flags);
			goto fail_init_blk_bmap;
		} else {
			atomic_set(&bmap->valid_logical_blks, used_blks);
			atomic_set(&bmap->invalid_logical_blks, invalid_blks);
			atomic_set(&bmap->free_logical_blks, free_blks);

			atomic_add(atomic_read(&bmap->valid_logical_blks),
				   &bmap->parent->valid_logical_blks);
			atomic_add(atomic_read(&bmap->invalid_logical_blks),
				   &bmap->parent->invalid_logical_blks);
			atomic_add(atomic_read(&bmap->free_logical_blks),
				   &bmap->parent->free_logical_blks);
		}
		break;

	case SSDFS_DST_BLK_BMAP:
		if (under_migration) {
			atomic_add(used_blks, &bmap->valid_logical_blks);
			atomic_add(invalid_blks, &bmap->invalid_logical_blks);
			atomic_add(free_blks, &bmap->free_logical_blks);
			atomic_add(free_blks, &pebc->shared_free_dst_blks);

			atomic_add(used_blks,
				   &bmap->parent->valid_logical_blks);
			atomic_add(invalid_blks,
				   &bmap->parent->invalid_logical_blks);
			atomic_add(free_blks,
				   &bmap->parent->free_logical_blks);
		} else {
			err = -EIO;
			SSDFS_ERR("invalid flags set: %#x\n", flags);
			goto fail_init_blk_bmap;
		}
		break;

	default:
		BUG();
	}

	switch (type) {
	case SSDFS_SRC_BLK_BMAP:
		if (under_migration && has_relation) {
			if (!bmap->dst)
				goto finish_init_blk_bmap;
			else if (!ssdfs_block_bmap_initialized(bmap->dst))
				goto finish_init_blk_bmap;
		}
		break;

	case SSDFS_DST_BLK_BMAP:
		if (under_migration && has_relation) {
			if (!bmap->src)
				goto finish_init_blk_bmap;
			else if (!ssdfs_block_bmap_initialized(bmap->src))
				goto finish_init_blk_bmap;
		}
		break;

	default:
		BUG();
	}

	if (atomic_read(&pebc->shared_free_dst_blks) < 0) {
		SSDFS_WARN("type %#x, under_migration %#x, has_relation %#x, "
			   "last_free_blk %u, metadata_blks %u, "
			   "free_blks %u, used_blks %u, "
			   "invalid_blks %u, shared_free_dst_blks %d\n",
			   type, under_migration, has_relation,
			   last_free_blk, metadata_blks,
			   free_blks, used_blks, invalid_blks,
			   atomic_read(&pebc->shared_free_dst_blks));
	}

	SSDFS_DBG("free_blks %d, used_blks %d, invalid_blks %d\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks));

	atomic_set(&bmap->state, SSDFS_PEB_BLK_BMAP_INITIALIZED);
	complete_all(&bmap->init_end);

fail_init_blk_bmap:
	if (unlikely(err)) {
		bmap->init_cno = old_cno;
		complete_all(&bmap->init_end);
	}

finish_init_blk_bmap:
	up_write(&bmap->lock);

	return err;
}

/*
 * ssdfs_peb_blk_bmap_init_failed() - process failure of block bitmap init
 * @bmap: pointer on PEB's block bitmap object
 */
void ssdfs_peb_blk_bmap_init_failed(struct ssdfs_peb_blk_bmap *bmap)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	complete_all(&bmap->init_end);
}

/*
 * ssdfs_peb_define_reserved_pages_per_log() - estimate reserved pages per log
 * @bmap: pointer on PEB's block bitmap object
 */
int ssdfs_peb_define_reserved_pages_per_log(struct ssdfs_peb_blk_bmap *bmap)
{
	struct ssdfs_segment_blk_bmap *parent = bmap->parent;
	struct ssdfs_segment_info *si = parent->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	u32 page_size = fsi->pagesize;
	u32 pages_per_peb = parent->pages_per_peb;
	u32 pebs_per_seg = fsi->pebs_per_seg;
	u16 log_pages = si->log_pages;
	bool is_migrating = false;

	switch (atomic_read(&bmap->buffers_state)) {
	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		is_migrating = true;
		break;

	default:
		is_migrating = false;
		break;
	}

	return ssdfs_peb_estimate_reserved_metapages(page_size,
						     pages_per_peb,
						     log_pages,
						     pebs_per_seg,
						     is_migrating);
}

/*
 * ssdfs_peb_blk_bmap_get_free_pages() - determine PEB's free pages count
 * @bmap: pointer on PEB's block bitmap object
 *
 * This function tries to detect PEB's free pages count.
 *
 * RETURN:
 * [success] - count of free pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 */
int ssdfs_peb_blk_bmap_get_free_pages(struct ssdfs_peb_blk_bmap *bmap)
{
	int free_pages;
	int log_pages;
	int created_logs;
	int reserved_pages_per_log;
	int used_pages;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->parent || !bmap->parent->parent_si);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_index %u\n", bmap->peb_index);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_logical_blks %u, valid_logical_blks %u, "
		  "invalid_logical_blks %u, pages_per_peb %u\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks),
		  bmap->pages_per_peb);

	if ((atomic_read(&bmap->free_logical_blks) +
	    atomic_read(&bmap->valid_logical_blks) +
	    atomic_read(&bmap->invalid_logical_blks)) > bmap->pages_per_peb) {
		SSDFS_WARN("seg_id %llu, peb_index %u, "
			   "free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   bmap->parent->parent_si->seg_id,
			   bmap->peb_index,
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	log_pages = bmap->parent->parent_si->log_pages;
	reserved_pages_per_log = ssdfs_peb_define_reserved_pages_per_log(bmap);
	free_pages = atomic_read(&bmap->free_logical_blks);

	if (free_pages > 0) {
		int upper_threshold, lower_threshold;

		created_logs = (bmap->pages_per_peb - free_pages) / log_pages;
		used_pages = bmap->pages_per_peb - free_pages;

		if (created_logs == 0) {
			upper_threshold = log_pages;
			lower_threshold = reserved_pages_per_log;
		} else {
			upper_threshold = (created_logs + 1) * log_pages;
			lower_threshold = ((created_logs - 1) * log_pages) +
					    reserved_pages_per_log;
		}

		BUG_ON(used_pages > upper_threshold);

		if (used_pages == upper_threshold)
			free_pages -= reserved_pages_per_log;
		else if (used_pages < lower_threshold)
			free_pages -= (lower_threshold - used_pages);

		if (free_pages < 0)
			free_pages = 0;
	}

	return free_pages;
}

/*
 * ssdfs_peb_blk_bmap_get_used_pages() - determine PEB's used data pages count
 * @bmap: pointer on PEB's block bitmap object
 *
 * This function tries to detect PEB's used data pages count.
 *
 * RETURN:
 * [success] - count of used data pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 */
int ssdfs_peb_blk_bmap_get_used_pages(struct ssdfs_peb_blk_bmap *bmap)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_index %u\n", bmap->peb_index);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_logical_blks %u, valid_logical_blks %u, "
		  "invalid_logical_blks %u, pages_per_peb %u\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks),
		  bmap->pages_per_peb);

	if ((atomic_read(&bmap->free_logical_blks) +
	    atomic_read(&bmap->valid_logical_blks) +
	    atomic_read(&bmap->invalid_logical_blks)) > bmap->pages_per_peb) {
		SSDFS_WARN("seg_id %llu, peb_index %u, "
			   "free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   bmap->parent->parent_si->seg_id,
			   bmap->peb_index,
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return atomic_read(&bmap->valid_logical_blks);
}

/*
 * ssdfs_peb_blk_bmap_get_invalid_pages() - determine PEB's invalid pages count
 * @bmap: pointer on PEB's block bitmap object
 *
 * This function tries to detect PEB's invalid pages count.
 *
 * RETURN:
 * [success] - count of invalid pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 */
int ssdfs_peb_blk_bmap_get_invalid_pages(struct ssdfs_peb_blk_bmap *bmap)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_index %u\n", bmap->peb_index);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_logical_blks %u, valid_logical_blks %u, "
		  "invalid_logical_blks %u, pages_per_peb %u\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks),
		  bmap->pages_per_peb);

	if ((atomic_read(&bmap->free_logical_blks) +
	    atomic_read(&bmap->valid_logical_blks) +
	    atomic_read(&bmap->invalid_logical_blks)) > bmap->pages_per_peb) {
		SSDFS_WARN("seg_id %llu, peb_index %u, "
			   "free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   bmap->parent->parent_si->seg_id,
			   bmap->peb_index,
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return atomic_read(&bmap->invalid_logical_blks);
}

/*
 * ssdfs_src_blk_bmap_get_free_pages() - determine free pages count
 * @bmap: pointer on PEB's block bitmap object
 *
 * This function tries to detect the free pages count
 * in the source bitmap.
 *
 * RETURN:
 * [success] - count of free pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 */
int ssdfs_src_blk_bmap_get_free_pages(struct ssdfs_peb_blk_bmap *bmap)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_index %u\n", bmap->peb_index);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	down_read(&bmap->lock);

	if (bmap->src == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_get_src_free_pages;
	}

	err = ssdfs_block_bmap_lock(bmap->src);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_get_src_free_pages;
	}

	err = ssdfs_block_bmap_get_free_pages(bmap->src);
	ssdfs_block_bmap_unlock(bmap->src);

finish_get_src_free_pages:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_src_blk_bmap_get_used_pages() - determine used pages count
 * @bmap: pointer on PEB's block bitmap object
 *
 * This function tries to detect the used pages count
 * in the source bitmap.
 *
 * RETURN:
 * [success] - count of used pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 */
int ssdfs_src_blk_bmap_get_used_pages(struct ssdfs_peb_blk_bmap *bmap)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_index %u\n", bmap->peb_index);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	down_read(&bmap->lock);

	if (bmap->src == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_get_src_used_pages;
	}

	err = ssdfs_block_bmap_lock(bmap->src);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_get_src_used_pages;
	}

	err = ssdfs_block_bmap_get_used_pages(bmap->src);
	ssdfs_block_bmap_unlock(bmap->src);

finish_get_src_used_pages:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_src_blk_bmap_get_invalid_pages() - determine invalid pages count
 * @bmap: pointer on PEB's block bitmap object
 *
 * This function tries to detect the invalid pages count
 * in the source bitmap.
 *
 * RETURN:
 * [success] - count of invalid pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 */
int ssdfs_src_blk_bmap_get_invalid_pages(struct ssdfs_peb_blk_bmap *bmap)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_index %u\n", bmap->peb_index);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	down_read(&bmap->lock);

	if (bmap->src == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_get_src_invalid_pages;
	}

	err = ssdfs_block_bmap_lock(bmap->src);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_get_src_invalid_pages;
	}

	err = ssdfs_block_bmap_get_invalid_pages(bmap->src);
	ssdfs_block_bmap_unlock(bmap->src);

finish_get_src_invalid_pages:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_dst_blk_bmap_get_free_pages() - determine free pages count
 * @bmap: pointer on PEB's block bitmap object
 *
 * This function tries to detect the free pages count
 * in the destination bitmap.
 *
 * RETURN:
 * [success] - count of free pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 */
int ssdfs_dst_blk_bmap_get_free_pages(struct ssdfs_peb_blk_bmap *bmap)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_index %u\n", bmap->peb_index);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	down_read(&bmap->lock);

	if (bmap->dst == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_get_dst_free_pages;
	}

	err = ssdfs_block_bmap_lock(bmap->dst);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_get_dst_free_pages;
	}

	err = ssdfs_block_bmap_get_free_pages(bmap->dst);
	ssdfs_block_bmap_unlock(bmap->dst);

finish_get_dst_free_pages:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_dst_blk_bmap_get_used_pages() - determine used pages count
 * @bmap: pointer on PEB's block bitmap object
 *
 * This function tries to detect the used pages count
 * in the destination bitmap.
 *
 * RETURN:
 * [success] - count of used pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 */
int ssdfs_dst_blk_bmap_get_used_pages(struct ssdfs_peb_blk_bmap *bmap)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_index %u\n", bmap->peb_index);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	down_read(&bmap->lock);

	if (bmap->dst == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_get_dst_used_pages;
	}

	err = ssdfs_block_bmap_lock(bmap->dst);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_get_dst_used_pages;
	}

	err = ssdfs_block_bmap_get_used_pages(bmap->dst);
	ssdfs_block_bmap_unlock(bmap->dst);

finish_get_dst_used_pages:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_dst_blk_bmap_get_invalid_pages() - determine invalid pages count
 * @bmap: pointer on PEB's block bitmap object
 *
 * This function tries to detect the invalid pages count
 * in the destination bitmap.
 *
 * RETURN:
 * [success] - count of invalid pages.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - invalid internal calculations.
 */
int ssdfs_dst_blk_bmap_get_invalid_pages(struct ssdfs_peb_blk_bmap *bmap)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_index %u\n", bmap->peb_index);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	down_read(&bmap->lock);

	if (bmap->dst == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_get_dst_invalid_pages;
	}

	err = ssdfs_block_bmap_lock(bmap->dst);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_get_dst_invalid_pages;
	}

	err = ssdfs_block_bmap_get_invalid_pages(bmap->dst);
	ssdfs_block_bmap_unlock(bmap->dst);

finish_get_dst_invalid_pages:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_peb_blk_bmap_reserve_metapages() - reserve metadata pages
 * @bmap: PEB's block bitmap object
 * @bmap_index: source or destination block bitmap?
 * @count: amount of metadata pages
 *
 * This function tries to reserve some amount of metadata pages.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_blk_bmap_reserve_metapages(struct ssdfs_peb_blk_bmap *bmap,
					 int bmap_index,
					 u16 count)
{
	struct ssdfs_block_bmap *cur_bmap = NULL;
	int reserving_blks = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, bmap_index %u, count %u, "
		  "free_logical_blks %u, valid_logical_blks %u, "
		  "invalid_logical_blks %u\n",
		  bmap, bmap_index, count,
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks));

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	if (bmap_index < 0 || bmap_index >= SSDFS_PEB_BLK_BMAP_INDEX_MAX) {
		SSDFS_WARN("invalid bmap_index %u\n",
			   bmap_index);
		return -ERANGE;
	}

	reserving_blks = min_t(int, (int)count,
				atomic_read(&bmap->free_logical_blks));

	if (count > atomic_read(&bmap->free_logical_blks) ||
	    count > atomic_read(&bmap->parent->free_logical_blks)) {
		err = -ENOSPC;
		SSDFS_DBG("unable to reserve: "
			  "count %u, free_logical_blks %d, "
			  "parent->free_logical_blks %d\n",
			  count,
			  atomic_read(&bmap->free_logical_blks),
			  atomic_read(&bmap->parent->free_logical_blks));
		SSDFS_DBG("try to reserve: "
			  "reserving_blks %d\n",
			  reserving_blks);
	}

	down_read(&bmap->lock);

	if (bmap_index == SSDFS_PEB_BLK_BMAP_SOURCE)
		cur_bmap = bmap->src;
	else if (bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION)
		cur_bmap = bmap->dst;
	else
		cur_bmap = NULL;

	if (cur_bmap == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_reserve_metapages;
	}

	err = ssdfs_block_bmap_lock(cur_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_reserve_metapages;
	}

	err = ssdfs_block_bmap_reserve_metadata_pages(cur_bmap,
							reserving_blks);
	ssdfs_block_bmap_unlock(cur_bmap);

	if (unlikely(err)) {
		SSDFS_ERR("fail to reserve metadata pages: "
			  "reserving_blks %u, err %d\n",
			  reserving_blks, err);
		goto finish_reserve_metapages;
	}

	atomic_sub(reserving_blks, &bmap->free_logical_blks);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_logical_blks %u, valid_logical_blks %u, "
		  "invalid_logical_blks %u, pages_per_peb %u\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks),
		  bmap->pages_per_peb);

	if (atomic_read(&bmap->free_logical_blks) < 0) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}

	if ((atomic_read(&bmap->free_logical_blks) +
	     atomic_read(&bmap->valid_logical_blks) +
	     atomic_read(&bmap->invalid_logical_blks)) >
					bmap->pages_per_peb) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	atomic_sub(reserving_blks, &bmap->parent->free_logical_blks);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("parent->free_logical_blks %u, "
		  "parent->valid_logical_blks %u, "
		  "parent->invalid_logical_blks %u, "
		  "pages_per_peb %u\n",
		  atomic_read(&bmap->parent->free_logical_blks),
		  atomic_read(&bmap->parent->valid_logical_blks),
		  atomic_read(&bmap->parent->invalid_logical_blks),
		  bmap->parent->pages_per_peb);

	if (atomic_read(&bmap->free_logical_blks) < 0) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}

	if ((atomic_read(&bmap->free_logical_blks) +
	     atomic_read(&bmap->valid_logical_blks) +
	     atomic_read(&bmap->invalid_logical_blks)) >
					bmap->pages_per_peb) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

finish_reserve_metapages:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_peb_blk_bmap_free_metapages() - free metadata pages
 * @bmap: PEB's block bitmap object
 * @bmap_index: source or destination block bitmap?
 * @count: amount of metadata pages
 *
 * This function tries to free some amount of metadata pages.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_blk_bmap_free_metapages(struct ssdfs_peb_blk_bmap *bmap,
				      int bmap_index,
				      u16 count)
{
	struct ssdfs_block_bmap *cur_bmap = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, bmap_index %u, count %u, "
		  "free_logical_blks %u, valid_logical_blks %u, "
		  "invalid_logical_blks %u\n",
		  bmap, bmap_index, count,
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks));

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	if (bmap_index < 0 || bmap_index >= SSDFS_PEB_BLK_BMAP_INDEX_MAX) {
		SSDFS_WARN("invalid bmap_index %u\n",
			   bmap_index);
		return -ERANGE;
	}

	down_read(&bmap->lock);

	if (bmap_index == SSDFS_PEB_BLK_BMAP_SOURCE)
		cur_bmap = bmap->src;
	else if (bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION)
		cur_bmap = bmap->dst;
	else
		cur_bmap = NULL;

	if (cur_bmap == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_free_metapages;
	}

	err = ssdfs_block_bmap_lock(cur_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_free_metapages;
	}

	err = ssdfs_block_bmap_free_metadata_pages(cur_bmap, count);
	ssdfs_block_bmap_unlock(cur_bmap);

	if (unlikely(err)) {
		SSDFS_ERR("fail to free metadata pages: "
			  "count %u, err %d\n",
			  count, err);
		goto finish_free_metapages;
	}

	atomic_add(count, &bmap->free_logical_blks);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_logical_blks %u, valid_logical_blks %u, "
		  "invalid_logical_blks %u, pages_per_peb %u\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks),
		  bmap->pages_per_peb);

	if ((atomic_read(&bmap->free_logical_blks) +
	     atomic_read(&bmap->valid_logical_blks) +
	     atomic_read(&bmap->invalid_logical_blks)) >
					bmap->pages_per_peb) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	atomic_add(count, &bmap->parent->free_logical_blks);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("parent->free_logical_blks %u, "
		  "parent->valid_logical_blks %u, "
		  "parent->invalid_logical_blks %u, "
		  "pages_per_peb %u\n",
		  atomic_read(&bmap->parent->free_logical_blks),
		  atomic_read(&bmap->parent->valid_logical_blks),
		  atomic_read(&bmap->parent->invalid_logical_blks),
		  bmap->parent->pages_per_peb);

	if ((atomic_read(&bmap->free_logical_blks) +
	     atomic_read(&bmap->valid_logical_blks) +
	     atomic_read(&bmap->invalid_logical_blks)) >
					bmap->pages_per_peb) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

finish_free_metapages:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_peb_blk_bmap_pre_allocate() - pre-allocate a range of blocks
 * @bmap: PEB's block bitmap object
 * @bmap_index: source or destination block bitmap?
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
int ssdfs_peb_blk_bmap_pre_allocate(struct ssdfs_peb_blk_bmap *bmap,
				    int bmap_index,
				    u32 *len,
				    struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_block_bmap *cur_bmap = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !len || !range || !bmap->src);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, bmap_index %u, len %u\n",
		  bmap, bmap_index, *len);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	if (bmap_index < 0 || bmap_index >= SSDFS_PEB_BLK_BMAP_INDEX_MAX) {
		SSDFS_WARN("invalid bmap_index %u\n",
			   bmap_index);
		return -ERANGE;
	}

	si = bmap->parent->parent_si;

	if (bmap->peb_index >= si->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  bmap->peb_index, si->pebs_count);
		return -ERANGE;
	}

	pebc = &si->peb_array[bmap->peb_index];

	switch (atomic_read(&bmap->buffers_state)) {
	case SSDFS_PEB_BMAP1_SRC:
	case SSDFS_PEB_BMAP2_SRC:
		BUG_ON(bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION);
		break;

	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid buffers_state %#x\n",
			   atomic_read(&bmap->buffers_state));
		return -ERANGE;
	}

	down_read(&bmap->lock);

	if (bmap_index == SSDFS_PEB_BLK_BMAP_SOURCE)
		cur_bmap = bmap->src;
	else if (bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION)
		cur_bmap = bmap->dst;
	else
		cur_bmap = NULL;

	if (cur_bmap == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_pre_allocate;
	}

	err = ssdfs_block_bmap_lock(cur_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_pre_allocate;
	}

	err = ssdfs_block_bmap_pre_allocate(cur_bmap, len, range);

	ssdfs_block_bmap_unlock(cur_bmap);

	if (err == -ENOSPC) {
		SSDFS_DBG("unable to pre-allocate blocks: "
			  "len %u, err %d\n",
			  *len, err);
		goto finish_pre_allocate;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-allocate blocks: "
			  "len %u, err %d\n",
			  *len, err);
		goto finish_pre_allocate;
	}

	if (range->len > atomic_read(&bmap->free_logical_blks)) {
		err = -ERANGE;
		SSDFS_ERR("range %u > free_logical_blks %d\n",
			  range->len,
			  atomic_read(&bmap->free_logical_blks));
		goto finish_pre_allocate;
	}

	atomic_sub(range->len, &bmap->free_logical_blks);
	atomic_add(range->len, &bmap->valid_logical_blks);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_logical_blks %u, valid_logical_blks %u, "
		  "invalid_logical_blks %u, pages_per_peb %u\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks),
		  bmap->pages_per_peb);

	if (atomic_read(&bmap->free_logical_blks) < 0) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}

	if ((atomic_read(&bmap->free_logical_blks) +
	     atomic_read(&bmap->valid_logical_blks) +
	     atomic_read(&bmap->invalid_logical_blks)) >
					bmap->pages_per_peb) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION) {
		int shared_free_blks;

		shared_free_blks =
			atomic_sub_return(range->len,
					  &pebc->shared_free_dst_blks);
		WARN_ON(shared_free_blks < 0);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("parent->free_logical_blks %u, "
		  "parent->valid_logical_blks %u, "
		  "parent->invalid_logical_blks %u, "
		  "pages_per_peb %u\n",
		  atomic_read(&bmap->parent->free_logical_blks),
		  atomic_read(&bmap->parent->valid_logical_blks),
		  atomic_read(&bmap->parent->invalid_logical_blks),
		  bmap->parent->pages_per_peb);

	if (atomic_read(&bmap->free_logical_blks) < 0) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}

	if ((atomic_read(&bmap->free_logical_blks) +
	     atomic_read(&bmap->valid_logical_blks) +
	     atomic_read(&bmap->invalid_logical_blks)) >
					bmap->pages_per_peb) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

finish_pre_allocate:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_peb_blk_bmap_allocate() - allocate a range of blocks
 * @bmap: PEB's block bitmap object
 * @bmap_index: source or destination block bitmap?
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
int ssdfs_peb_blk_bmap_allocate(struct ssdfs_peb_blk_bmap *bmap,
				int bmap_index,
				u32 *len,
				struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_block_bmap *cur_bmap = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !len || !range || !bmap->src);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, bmap_index %u, len %u\n",
		  bmap, bmap_index, *len);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	if (bmap_index < 0 || bmap_index >= SSDFS_PEB_BLK_BMAP_INDEX_MAX) {
		SSDFS_WARN("invalid bmap_index %u\n",
			   bmap_index);
		return -ERANGE;
	}

	si = bmap->parent->parent_si;

	if (bmap->peb_index >= si->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  bmap->peb_index, si->pebs_count);
		return -ERANGE;
	}

	pebc = &si->peb_array[bmap->peb_index];

	switch (atomic_read(&bmap->buffers_state)) {
	case SSDFS_PEB_BMAP1_SRC:
	case SSDFS_PEB_BMAP2_SRC:
		BUG_ON(bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION);
		break;

	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invlaid buffers_state %#x\n",
			   atomic_read(&bmap->buffers_state));
		return -ERANGE;
	}

	down_read(&bmap->lock);

	if (bmap_index == SSDFS_PEB_BLK_BMAP_SOURCE)
		cur_bmap = bmap->src;
	else if (bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION)
		cur_bmap = bmap->dst;
	else
		cur_bmap = NULL;

	if (cur_bmap == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_allocate;
	}

	err = ssdfs_block_bmap_lock(cur_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_allocate;
	}

	err = ssdfs_block_bmap_allocate(cur_bmap, len, range);

	ssdfs_block_bmap_unlock(cur_bmap);

	if (err == -ENOSPC) {
		SSDFS_DBG("unable to allocate blocks: "
			  "len %u, err %d\n",
			  *len, err);
		goto finish_allocate;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to allocate blocks: "
			  "len %u, err %d\n",
			  *len, err);
		goto finish_allocate;
	}

	if (range->len > atomic_read(&bmap->free_logical_blks)) {
		err = -ERANGE;
		SSDFS_ERR("range %u > free_logical_blks %d\n",
			  range->len,
			  atomic_read(&bmap->free_logical_blks));
		goto finish_allocate;
	}

	atomic_sub(range->len, &bmap->free_logical_blks);
	atomic_add(range->len, &bmap->valid_logical_blks);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_logical_blks %u, valid_logical_blks %u, "
		  "invalid_logical_blks %u, pages_per_peb %u\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks),
		  bmap->pages_per_peb);

	if (atomic_read(&bmap->free_logical_blks) < 0) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}

	if ((atomic_read(&bmap->free_logical_blks) +
	     atomic_read(&bmap->valid_logical_blks) +
	     atomic_read(&bmap->invalid_logical_blks)) >
					bmap->pages_per_peb) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION) {
		int shared_free_blks;

		shared_free_blks =
			atomic_sub_return(range->len,
					  &pebc->shared_free_dst_blks);
		WARN_ON(shared_free_blks < 0);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("parent->free_logical_blks %u, "
		  "parent->valid_logical_blks %u, "
		  "parent->invalid_logical_blks %u, "
		  "pages_per_peb %u\n",
		  atomic_read(&bmap->parent->free_logical_blks),
		  atomic_read(&bmap->parent->valid_logical_blks),
		  atomic_read(&bmap->parent->invalid_logical_blks),
		  bmap->parent->pages_per_peb);

	if (atomic_read(&bmap->free_logical_blks) < 0) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}

	if ((atomic_read(&bmap->free_logical_blks) +
	     atomic_read(&bmap->valid_logical_blks) +
	     atomic_read(&bmap->invalid_logical_blks)) >
					bmap->pages_per_peb) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

finish_allocate:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_peb_blk_bmap_invalidate() - invalidate a range of blocks
 * @bmap: PEB's block bitmap object
 * @bmap_index: source or destination block bitmap?
 * @range: pointer on blocks' range [in | out]
 *
 * This function tries to set the requested range of blocks in
 * invalid state. At first, it checks that requested range contains
 * valid blocks only. And, then, it sets the requested range of blocks
 * in invalid state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_blk_bmap_invalidate(struct ssdfs_peb_blk_bmap *bmap,
				  int bmap_index,
				  struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_block_bmap *cur_bmap = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !range || !bmap->src);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, bmap_index %u, range (start %u, len %u)\n",
		  bmap, bmap_index, range->start, range->len);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	if (bmap_index < 0 || bmap_index >= SSDFS_PEB_BLK_BMAP_INDEX_MAX) {
		SSDFS_WARN("invalid bmap_index %u\n",
			   bmap_index);
		return -ERANGE;
	}

	switch (atomic_read(&bmap->buffers_state)) {
	case SSDFS_PEB_BMAP1_SRC:
	case SSDFS_PEB_BMAP2_SRC:
		BUG_ON(bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION);
		break;

	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid buffers_state %#x\n",
			   atomic_read(&bmap->buffers_state));
		return -ERANGE;
	}

	down_read(&bmap->lock);

	if (bmap_index == SSDFS_PEB_BLK_BMAP_SOURCE)
		cur_bmap = bmap->src;
	else if (bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION)
		cur_bmap = bmap->dst;
	else
		cur_bmap = NULL;

	if (cur_bmap == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_invalidate;
	}

	err = ssdfs_block_bmap_lock(cur_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_invalidate;
	}

	err = ssdfs_block_bmap_invalidate(cur_bmap, range);

	ssdfs_block_bmap_unlock(cur_bmap);

	if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate blocks: "
			  "len %u, err %d\n",
			  range->len, err);
		goto finish_invalidate;
	}

	if (range->len > atomic_read(&bmap->valid_logical_blks)) {
		err = -ERANGE;
		SSDFS_ERR("range %u > valid_logical_blks %d\n",
			  range->len,
			  atomic_read(&bmap->valid_logical_blks));
		goto finish_invalidate;
	}

	atomic_sub(range->len, &bmap->valid_logical_blks);
	atomic_add(range->len, &bmap->invalid_logical_blks);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_logical_blks %u, valid_logical_blks %u, "
		  "invalid_logical_blks %u, pages_per_peb %u\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks),
		  bmap->pages_per_peb);

	if (atomic_read(&bmap->free_logical_blks) < 0) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}

	if ((atomic_read(&bmap->free_logical_blks) +
	     atomic_read(&bmap->valid_logical_blks) +
	     atomic_read(&bmap->invalid_logical_blks)) >
					bmap->pages_per_peb) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("parent->free_logical_blks %u, "
		  "parent->valid_logical_blks %u, "
		  "parent->invalid_logical_blks %u, "
		  "pages_per_peb %u\n",
		  atomic_read(&bmap->parent->free_logical_blks),
		  atomic_read(&bmap->parent->valid_logical_blks),
		  atomic_read(&bmap->parent->invalid_logical_blks),
		  bmap->parent->pages_per_peb);

	if (atomic_read(&bmap->free_logical_blks) < 0) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}

	if ((atomic_read(&bmap->free_logical_blks) +
	     atomic_read(&bmap->valid_logical_blks) +
	     atomic_read(&bmap->invalid_logical_blks)) >
					bmap->pages_per_peb) {
		SSDFS_WARN("free_logical_blks %u, valid_logical_blks %u, "
			   "invalid_logical_blks %u, pages_per_peb %u\n",
			   atomic_read(&bmap->free_logical_blks),
			   atomic_read(&bmap->valid_logical_blks),
			   atomic_read(&bmap->invalid_logical_blks),
			   bmap->pages_per_peb);
	}
#endif /* CONFIG_SSDFS_DEBUG */

finish_invalidate:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_peb_blk_bmap_update_range() - update a range of blocks' state
 * @bmap: PEB's block bitmap object
 * @bmap_index: source or destination block bitmap?
 * @new_range_state: new state of the range
 * @range: pointer on blocks' range [in | out]
 *
 * This function tries to change a range of blocks' state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_blk_bmap_update_range(struct ssdfs_peb_blk_bmap *bmap,
				    int bmap_index,
				    int new_range_state,
				    struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_block_bmap *cur_bmap = NULL;
	int range_state;
#ifdef CONFIG_SSDFS_DEBUG
	int free_blks, used_blks, invalid_blks;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !range);
	BUG_ON(!(new_range_state == SSDFS_BLK_PRE_ALLOCATED ||
		 new_range_state == SSDFS_BLK_VALID));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, peb_index %u, state %#x, "
		  "range (start %u, len %u)\n",
		  bmap, bmap->peb_index,
		  atomic_read(&bmap->state),
		  range->start, range->len);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	if (bmap_index < 0 || bmap_index >= SSDFS_PEB_BLK_BMAP_INDEX_MAX) {
		SSDFS_WARN("invalid bmap_index %u\n",
			   bmap_index);
		return -ERANGE;
	}

	switch (atomic_read(&bmap->buffers_state)) {
	case SSDFS_PEB_BMAP1_SRC:
	case SSDFS_PEB_BMAP2_SRC:
		BUG_ON(bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION);
		break;

	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid buffers_state %#x\n",
			   atomic_read(&bmap->buffers_state));
		return -ERANGE;
	}

	down_read(&bmap->lock);

	if (bmap_index == SSDFS_PEB_BLK_BMAP_SOURCE)
		cur_bmap = bmap->src;
	else if (bmap_index == SSDFS_PEB_BLK_BMAP_DESTINATION)
		cur_bmap = bmap->dst;
	else
		cur_bmap = NULL;

	if (cur_bmap == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_update_range;
	}

	err = ssdfs_block_bmap_lock(cur_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_update_range;
	}

	range_state = ssdfs_get_range_state(cur_bmap, range);
	if (range_state < 0) {
		err = range_state;
		SSDFS_ERR("fail to detect range state: "
			  "range (start %u, len %u), err %d\n",
			  range->start, range->len, err);
		goto finish_process_bmap;
	}

	switch (range_state) {
	case SSDFS_BLK_FREE:
		/* valid block state */
		break;

	case SSDFS_BLK_PRE_ALLOCATED:
		if (new_range_state == SSDFS_BLK_PRE_ALLOCATED) {
			/* do nothing */
			goto finish_process_bmap;
		}
		break;

	case SSDFS_BLK_VALID:
		if (new_range_state == SSDFS_BLK_PRE_ALLOCATED) {
			err = -ERANGE;
			SSDFS_WARN("fail to change state: "
				   "range_state %#x, "
				   "new_range_state %#x\n",
				   range_state, new_range_state);
			goto finish_process_bmap;
		} else if (new_range_state == SSDFS_BLK_VALID) {
			/* do nothing */
			goto finish_process_bmap;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid range state: %#x\n",
			  range_state);
		goto finish_process_bmap;
	};

	if (new_range_state == SSDFS_BLK_PRE_ALLOCATED)
		err = ssdfs_block_bmap_pre_allocate(cur_bmap, NULL, range);
	else
		err = ssdfs_block_bmap_allocate(cur_bmap, NULL, range);

finish_process_bmap:
	ssdfs_block_bmap_unlock(cur_bmap);

	if (unlikely(err)) {
		SSDFS_ERR("fail to update range: "
			  "range (start %u, len %u), "
			  "new_range_state %#x, err %d\n",
			  range->start, range->len,
			  new_range_state, err);
		goto finish_update_range;
	}

#ifdef CONFIG_SSDFS_DEBUG
	err = ssdfs_block_bmap_lock(cur_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_update_range;
	}

	err = ssdfs_block_bmap_get_free_pages(cur_bmap);
	if (err < 0) {
		SSDFS_ERR("fail to get free pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_bmap;
	} else {
		free_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_used_pages(cur_bmap);
	if (err < 0) {
		SSDFS_ERR("fail to get used pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_bmap;
	} else {
		used_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_invalid_pages(cur_bmap);
	if (err < 0) {
		SSDFS_ERR("fail to get invalid pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_bmap;
	} else {
		invalid_blks = err;
		err = 0;
	}

unlock_bmap:
	ssdfs_block_bmap_unlock(cur_bmap);

	if (unlikely(err))
		goto finish_update_range;

	SSDFS_DBG("free_blks %d, used_blks %d, invalid_blks %d\n",
		  free_blks, used_blks, invalid_blks);
#endif /* CONFIG_SSDFS_DEBUG */

finish_update_range:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_peb_blk_bmap_collect_garbage() - find range of valid blocks for GC
 * @bmap: PEB's block bitmap object
 * @start: starting position for search
 * @max_len: maximum requested length of valid blocks' range
 * @blk_state: requested block state (pre-allocated or valid)
 * @range: pointer on blocks' range [out]
 *
 * This function tries to find range of valid or pre_allocated blocks
 * for GC in source block bitmap. The length of requested range is
 * limited by @max_len.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_blk_bmap_collect_garbage(struct ssdfs_peb_blk_bmap *bmap,
					u32 start, u32 max_len,
					int blk_state,
					struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_block_bmap *src = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !range || !bmap->src);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, start %u, max_len %u\n",
		  bmap, start, max_len);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	switch (atomic_read(&bmap->buffers_state)) {
	case SSDFS_PEB_BMAP1_SRC:
	case SSDFS_PEB_BMAP2_SRC:
	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid buffers_state %#x\n",
			   atomic_read(&bmap->buffers_state));
		return -ERANGE;
	}

	down_read(&bmap->lock);

	src = bmap->src;

	if (src == NULL) {
		err = -ERANGE;
		SSDFS_WARN("bmap pointer is empty\n");
		goto finish_collect_garbage;
	}

	err = ssdfs_block_bmap_lock(src);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_collect_garbage;
	}

	err = ssdfs_block_bmap_collect_garbage(src, start, max_len,
						blk_state, range);

	ssdfs_block_bmap_unlock(src);

	if (err == -ENODATA) {
		SSDFS_DBG("range (start %u, len %u) hasn't valid blocks\n",
			  range->start, range->len);
		goto finish_collect_garbage;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find valid blocks: "
			  "len %u, err %d\n",
			  range->len, err);
		goto finish_collect_garbage;
	}

finish_collect_garbage:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_peb_blk_bmap_start_migration() - prepare migration environment
 * @bmap: PEB's block bitmap object
 *
 * This method tries to prepare PEB's environment for migration.
 * The destination block bitmap is cleaned in buffer and pointer
 * is set. Also valid/invalid/free block counters are prepared
 * for migration operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_blk_bmap_start_migration(struct ssdfs_peb_blk_bmap *bmap)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *pebc;
	int buffers_state, new_buffers_state;
	int buffer_index;
	int free_blks = 0;
	int invalid_blks;
	int used_blks;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->src);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, peb_index %u, state %#x\n",
		  bmap, bmap->peb_index,
		  atomic_read(&bmap->state));

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	SSDFS_DBG("free_logical_blocks %d, valid_logical_block %d, "
		  "invalid_logical_block %d\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks));

	si = bmap->parent->parent_si;

	if (bmap->peb_index >= si->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  bmap->peb_index, si->pebs_count);
		return -ERANGE;
	}

	pebc = &si->peb_array[bmap->peb_index];

	down_write(&bmap->lock);

	buffers_state = atomic_read(&bmap->buffers_state);

	switch (buffers_state) {
	case SSDFS_PEB_BMAP1_SRC:
		new_buffers_state = SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST;
		buffer_index = SSDFS_PEB_BLK_BMAP2;
		break;

	case SSDFS_PEB_BMAP2_SRC:
		new_buffers_state = SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST;
		buffer_index = SSDFS_PEB_BLK_BMAP1;
		break;

	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		err = -ENOENT;
		SSDFS_WARN("bmap is under migration: "
			   "peb_index %u, state %#x\n",
			   bmap->peb_index, buffers_state);
		goto finish_migration_start;

	default:
		err = -ERANGE;
		SSDFS_WARN("fail to start migration: "
			   "buffers_state %#x\n",
			   buffers_state);
		goto finish_migration_start;
	}

	err = ssdfs_block_bmap_lock(&bmap->buffer[buffer_index]);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_migration_start;
	}

	switch (atomic_read(&bmap->buffers_state)) {
	case SSDFS_PEB_BMAP1_SRC:
#ifdef CONFIG_SSDFS_DEBUG
		WARN_ON(buffers_state != SSDFS_PEB_BMAP1_SRC);
		BUG_ON(!bmap->src || bmap->dst);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	case SSDFS_PEB_BMAP2_SRC:
#ifdef CONFIG_SSDFS_DEBUG
		WARN_ON(buffers_state != SSDFS_PEB_BMAP2_SRC);
		BUG_ON(!bmap->src || bmap->dst);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	default:
		err = -ENOENT;
		SSDFS_DBG("block bitmap has been prepared: "
			  "peb_index %u\n",
			  bmap->peb_index);
		goto finish_block_bitmap_preparation;
	}

	err = ssdfs_block_bmap_clean(&bmap->buffer[buffer_index]);
	if (unlikely(err == -ENOENT)) {
		err = -ERANGE;
		SSDFS_WARN("unable to clean block bitmap: "
			   "peb_index %u\n",
			   bmap->peb_index);
		goto finish_block_bitmap_preparation;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to clean block bitmap: "
			  "peb_index %u\n",
			  bmap->peb_index);
		goto finish_block_bitmap_preparation;
	}

	bmap->dst = &bmap->buffer[buffer_index];
	atomic_set(&bmap->buffers_state, new_buffers_state);

	invalid_blks = atomic_xchg(&bmap->invalid_logical_blks, 0);
	atomic_sub(invalid_blks, &bmap->parent->invalid_logical_blks);
	atomic_add(invalid_blks, &bmap->free_logical_blks);
	atomic_set(&pebc->shared_free_dst_blks, invalid_blks);
	atomic_add(invalid_blks, &bmap->parent->free_logical_blks);

	used_blks = atomic_read(&bmap->valid_logical_blks);

	err = ssdfs_block_bmap_get_free_pages(bmap->dst);
	if (err < 0) {
		SSDFS_ERR("fail to get free pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto finish_block_bitmap_preparation;
	} else {
		free_blks = err;
		err = 0;
	}

	if (free_blks < (invalid_blks + used_blks)) {
		err = -ERANGE;
		SSDFS_ERR("free_blks %d < (invalid_blks %d + used_blks %d)\n",
			  free_blks, invalid_blks, used_blks);
		goto finish_block_bitmap_preparation;
	}

	free_blks -= invalid_blks + used_blks;

	atomic_add(free_blks, &bmap->free_logical_blks);
	atomic_add(free_blks, &bmap->parent->free_logical_blks);

finish_block_bitmap_preparation:
	ssdfs_block_bmap_unlock(&bmap->buffer[buffer_index]);

	if (unlikely(err))
		goto finish_migration_start;

#ifdef CONFIG_SSDFS_DEBUG
	err = ssdfs_block_bmap_lock(bmap->dst);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_migration_start;
	}

	err = ssdfs_block_bmap_get_free_pages(bmap->dst);
	if (err < 0) {
		SSDFS_ERR("fail to get free pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_dst_bmap;
	} else {
		free_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_used_pages(bmap->dst);
	if (err < 0) {
		SSDFS_ERR("fail to get used pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_dst_bmap;
	} else {
		used_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_invalid_pages(bmap->dst);
	if (err < 0) {
		SSDFS_ERR("fail to get invalid pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_dst_bmap;
	} else {
		invalid_blks = err;
		err = 0;
	}

unlock_dst_bmap:
	ssdfs_block_bmap_unlock(bmap->dst);

	if (unlikely(err))
		goto finish_migration_start;

	SSDFS_DBG("DST: free_blks %d, used_blks %d, invalid_blks %d\n",
		  free_blks, used_blks, invalid_blks);

	err = ssdfs_block_bmap_lock(bmap->src);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_migration_start;
	}

	err = ssdfs_block_bmap_get_free_pages(bmap->src);
	if (err < 0) {
		SSDFS_ERR("fail to get free pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_src_bmap;
	} else {
		free_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_used_pages(bmap->src);
	if (err < 0) {
		SSDFS_ERR("fail to get used pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_src_bmap;
	} else {
		used_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_invalid_pages(bmap->src);
	if (err < 0) {
		SSDFS_ERR("fail to get invalid pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_src_bmap;
	} else {
		invalid_blks = err;
		err = 0;
	}

unlock_src_bmap:
	ssdfs_block_bmap_unlock(bmap->src);

	if (unlikely(err))
		goto finish_migration_start;

	SSDFS_DBG("SRC: free_blks %d, used_blks %d, invalid_blks %d\n",
		  free_blks, used_blks, invalid_blks);
#endif /* CONFIG_SSDFS_DEBUG */

finish_migration_start:
	up_write(&bmap->lock);

	SSDFS_DBG("free_logical_blocks %d, valid_logical_block %d, "
		  "invalid_logical_block %d\n",
		  atomic_read(&bmap->free_logical_blks),
		  atomic_read(&bmap->valid_logical_blks),
		  atomic_read(&bmap->invalid_logical_blks));

	if (err == -ENOENT)
		return 0;
	else if (unlikely(err))
		return err;

	return 0;
}

/*
 * ssdfs_peb_blk_bmap_migrate() - migrate valid blocks
 * @bmap: PEB's block bitmap object
 * @new_range_state: new state of range
 * @range: pointer on blocks' range
 *
 * This method tries to move @range of blocks from source
 * block bitmap into destination block bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_blk_bmap_migrate(struct ssdfs_peb_blk_bmap *bmap,
				int new_range_state,
				struct ssdfs_block_bmap_range *range)
{
	int buffers_state;
	int range_state;
	struct ssdfs_block_bmap *src;
	struct ssdfs_block_bmap *dst;
#ifdef CONFIG_SSDFS_DEBUG
	int free_blks, used_blks, invalid_blks;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !range);
	BUG_ON(!(new_range_state == SSDFS_BLK_PRE_ALLOCATED ||
		 new_range_state == SSDFS_BLK_VALID));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, peb_index %u, state %#x, "
		  "range (start %u, len %u)\n",
		  bmap, bmap->peb_index,
		  atomic_read(&bmap->state),
		  range->start, range->len);

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	down_read(&bmap->lock);

	buffers_state = atomic_read(&bmap->buffers_state);

	switch (buffers_state) {
	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		src = bmap->src;
		dst = bmap->dst;
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("fail to migrate: "
			   "buffers_state %#x, "
			   "range (start %u, len %u)\n",
			   buffers_state,
			   range->start, range->len);
		goto finish_migrate;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (!src || !dst) {
		err = -ERANGE;
		SSDFS_WARN("empty pointers\n");
		goto finish_migrate;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_block_bmap_lock(src);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_migrate;
	}

	range_state = ssdfs_get_range_state(src, range);
	if (range_state < 0) {
		err = range_state;
		SSDFS_ERR("fail to detect range state: "
			  "range (start %u, len %u), err %d\n",
			  range->start, range->len, err);
		goto finish_process_source_bmap;
	}

	switch (range_state) {
	case SSDFS_BLK_PRE_ALLOCATED:
		/* valid block state */
		break;

	case SSDFS_BLK_VALID:
		if (new_range_state == SSDFS_BLK_PRE_ALLOCATED) {
			err = -ERANGE;
			SSDFS_WARN("fail to change state: "
				   "range_state %#x, "
				   "new_range_state %#x\n",
				   range_state, new_range_state);
			goto finish_process_source_bmap;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid range state: %#x\n",
			  range_state);
		goto finish_process_source_bmap;
	};

	err = ssdfs_block_bmap_invalidate(src, range);

finish_process_source_bmap:
	ssdfs_block_bmap_unlock(src);

	if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate blocks: "
			  "start %u, len %u, err %d\n",
			  range->start, range->len, err);
		goto finish_migrate;
	}

	err = ssdfs_block_bmap_lock(dst);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_migrate;
	}

	if (new_range_state == SSDFS_BLK_PRE_ALLOCATED)
		err = ssdfs_block_bmap_pre_allocate(dst, NULL, range);
	else
		err = ssdfs_block_bmap_allocate(dst, NULL, range);

	ssdfs_block_bmap_unlock(dst);

	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate blocks: "
			  "start %u, len %u, err %d\n",
			  range->start, range->len, err);
		goto finish_migrate;
	}

#ifdef CONFIG_SSDFS_DEBUG
	err = ssdfs_block_bmap_lock(src);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_migrate;
	}

	err = ssdfs_block_bmap_get_free_pages(src);
	if (err < 0) {
		SSDFS_ERR("fail to get free pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_src_bmap;
	} else {
		free_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_used_pages(src);
	if (err < 0) {
		SSDFS_ERR("fail to get used pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_src_bmap;
	} else {
		used_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_invalid_pages(src);
	if (err < 0) {
		SSDFS_ERR("fail to get invalid pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_src_bmap;
	} else {
		invalid_blks = err;
		err = 0;
	}

unlock_src_bmap:
	ssdfs_block_bmap_unlock(src);

	if (unlikely(err))
		goto finish_migrate;

	SSDFS_DBG("SRC: free_blks %d, used_blks %d, invalid_blks %d\n",
		  free_blks, used_blks, invalid_blks);

	err = ssdfs_block_bmap_lock(dst);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_migrate;
	}

	err = ssdfs_block_bmap_get_free_pages(dst);
	if (err < 0) {
		SSDFS_ERR("fail to get free pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_dst_bmap;
	} else {
		free_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_used_pages(dst);
	if (err < 0) {
		SSDFS_ERR("fail to get used pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_dst_bmap;
	} else {
		used_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_invalid_pages(dst);
	if (err < 0) {
		SSDFS_ERR("fail to get invalid pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_dst_bmap;
	} else {
		invalid_blks = err;
		err = 0;
	}

unlock_dst_bmap:
	ssdfs_block_bmap_unlock(dst);

	if (unlikely(err))
		goto finish_migrate;

	SSDFS_DBG("DST: free_blks %d, used_blks %d, invalid_blks %d\n",
		  free_blks, used_blks, invalid_blks);
#endif /* CONFIG_SSDFS_DEBUG */

finish_migrate:
	up_read(&bmap->lock);

	return err;
}

/*
 * ssdfs_peb_blk_bmap_finish_migration() - stop migration
 * @bmap: PEB's block bitmap object
 *
 * This method tries to make destination block bitmap as
 * source and to forget about old source block bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_blk_bmap_finish_migration(struct ssdfs_peb_blk_bmap *bmap)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *pebc;
	int buffers_state, new_buffers_state;
	int buffer_index;
#ifdef CONFIG_SSDFS_DEBUG
	int free_blks, used_blks, invalid_blks;
#endif /* CONFIG_SSDFS_DEBUG */
	int shared_free_dst_blks;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !bmap->src);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("bmap %p, peb_index %u, state %#x\n",
		  bmap, bmap->peb_index,
		  atomic_read(&bmap->state));

	if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
		unsigned long res;

		res = wait_for_completion_timeout(&bmap->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
init_failed:
			SSDFS_ERR("PEB block bitmap init failed: "
				  "err %d\n", err);
			return err;
		}

		if (!ssdfs_peb_blk_bmap_initialized(bmap)) {
			err = -ERANGE;
			goto init_failed;
		}
	}

	si = bmap->parent->parent_si;

	if (bmap->peb_index >= si->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  bmap->peb_index, si->pebs_count);
		return -ERANGE;
	}

	pebc = &si->peb_array[bmap->peb_index];

	down_write(&bmap->lock);

	buffers_state = atomic_read(&bmap->buffers_state);

	switch (buffers_state) {
	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!bmap->src || !bmap->dst);
#endif /* CONFIG_SSDFS_DEBUG */
		new_buffers_state = SSDFS_PEB_BMAP2_SRC;
		buffer_index = SSDFS_PEB_BLK_BMAP2;
		break;

	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!bmap->src || !bmap->dst);
#endif /* CONFIG_SSDFS_DEBUG */
		new_buffers_state = SSDFS_PEB_BMAP1_SRC;
		buffer_index = SSDFS_PEB_BLK_BMAP1;
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("fail to start migration: "
			   "buffers_state %#x\n",
			   buffers_state);
		goto finish_migration_stop;
	}

#ifdef CONFIG_SSDFS_DEBUG
	err = ssdfs_block_bmap_lock(bmap->dst);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_migration_stop;
	}

	err = ssdfs_block_bmap_get_free_pages(bmap->dst);
	if (err < 0) {
		SSDFS_ERR("fail to get free pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_dst_bmap;
	} else {
		free_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_used_pages(bmap->dst);
	if (err < 0) {
		SSDFS_ERR("fail to get used pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_dst_bmap;
	} else {
		used_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_invalid_pages(bmap->dst);
	if (err < 0) {
		SSDFS_ERR("fail to get invalid pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_dst_bmap;
	} else {
		invalid_blks = err;
		err = 0;
	}

unlock_dst_bmap:
	ssdfs_block_bmap_unlock(bmap->dst);

	if (unlikely(err))
		goto finish_migration_stop;

	SSDFS_DBG("DST: free_blks %d, used_blks %d, invalid_blks %d\n",
		  free_blks, used_blks, invalid_blks);

	err = ssdfs_block_bmap_lock(bmap->src);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_migration_stop;
	}

	err = ssdfs_block_bmap_get_free_pages(bmap->src);
	if (err < 0) {
		SSDFS_ERR("fail to get free pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_src_bmap;
	} else {
		free_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_used_pages(bmap->src);
	if (err < 0) {
		SSDFS_ERR("fail to get used pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_src_bmap;
	} else {
		used_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_invalid_pages(bmap->src);
	if (err < 0) {
		SSDFS_ERR("fail to get invalid pages count: "
			  "peb_index %u, err %d\n",
			  bmap->peb_index, err);
		goto unlock_src_bmap;
	} else {
		invalid_blks = err;
		err = 0;
	}

unlock_src_bmap:
	ssdfs_block_bmap_unlock(bmap->src);

	if (unlikely(err))
		goto finish_migration_stop;

	SSDFS_DBG("SRC: free_blks %d, used_blks %d, invalid_blks %d\n",
		  free_blks, used_blks, invalid_blks);

	if ((free_blks + used_blks + invalid_blks) > bmap->pages_per_peb) {
		SSDFS_WARN("free_blks %d, used_blks %d, "
			   "invalid_blks %d, pages_per_peb %u\n",
			   free_blks, used_blks, invalid_blks,
			   bmap->pages_per_peb);
		err = -ERANGE;
		goto finish_migration_stop;
	}

	if (used_blks != 0) {
		SSDFS_ERR("PEB contains valid blocks %d\n",
			  used_blks);
		err = -ERANGE;
		goto finish_migration_stop;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	shared_free_dst_blks = atomic_read(&pebc->shared_free_dst_blks);

	if (shared_free_dst_blks < 0 ||
	    shared_free_dst_blks > bmap->pages_per_peb) {
		SSDFS_WARN("invalid shared_free_dst_blks %d\n",
			   shared_free_dst_blks);
	}

	bmap->src = &bmap->buffer[buffer_index];
	bmap->dst = NULL;
	atomic_set(&bmap->buffers_state, new_buffers_state);

finish_migration_stop:
	up_write(&bmap->lock);

	return err;
}
