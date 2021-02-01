//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_migration_scheme.c - Implementation of PEBs' migration scheme.
 *
 * Copyright (c) 2014-2021 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2021, HGST, Inc., All rights reserved.
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
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "offset_translation_table.h"
#include "page_array.h"
#include "peb.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_migration_page_leaks;
atomic64_t ssdfs_migration_memory_leaks;
atomic64_t ssdfs_migration_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_migration_cache_leaks_increment(void *kaddr)
 * void ssdfs_migration_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_migration_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_migration_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_migration_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_migration_kfree(void *kaddr)
 * struct page *ssdfs_migration_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_migration_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_migration_free_page(struct page *page)
 * void ssdfs_migration_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(migration)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(migration)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_migration_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_migration_page_leaks, 0);
	atomic64_set(&ssdfs_migration_memory_leaks, 0);
	atomic64_set(&ssdfs_migration_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_migration_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_migration_page_leaks) != 0) {
		SSDFS_ERR("MIGRATION SCHEME: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_migration_page_leaks));
	}

	if (atomic64_read(&ssdfs_migration_memory_leaks) != 0) {
		SSDFS_ERR("MIGRATION SCHEME: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_migration_memory_leaks));
	}

	if (atomic64_read(&ssdfs_migration_cache_leaks) != 0) {
		SSDFS_ERR("MIGRATION SCHEME: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_migration_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_peb_start_migration() - prepare and start PEB's migration
 * @pebc: pointer on PEB container
 */
int ssdfs_peb_start_migration(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_type %#x, "
		  "migration_state %#x, items_state %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  atomic_read(&pebc->migration_state),
		  atomic_read(&pebc->items_state));

	fsi = pebc->parent_si->fsi;
	si = pebc->parent_si;

	mutex_lock(&pebc->migration_lock);

check_migration_state:
	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_NOT_MIGRATING:
		/* valid state */
		break;

	case SSDFS_PEB_UNDER_MIGRATION:
		err = 0;
		SSDFS_DBG("PEB is under migration already: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
		goto start_migration_done;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
	case SSDFS_PEB_FINISHING_MIGRATION: {
			DEFINE_WAIT(wait);

			mutex_unlock(&pebc->migration_lock);
			prepare_to_wait(&si->migration.wait, &wait,
					TASK_UNINTERRUPTIBLE);
			schedule();
			finish_wait(&si->migration.wait, &wait);
			mutex_lock(&pebc->migration_lock);
			goto check_migration_state;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid migration_state %#x\n",
			   atomic_read(&pebc->migration_state));
		goto start_migration_done;
	}

	err = ssdfs_peb_container_create_destination(pebc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to start PEB migration: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  err);
		goto start_migration_done;
	}

	for (i = 0; i < SSDFS_GC_THREAD_TYPE_MAX; i++) {
		atomic_inc(&fsi->gc_should_act[i]);
		wake_up_all(&fsi->gc_wait_queue[i]);
	}

start_migration_done:
	mutex_unlock(&pebc->migration_lock);

	SSDFS_DBG("finished\n");

	return err;
}

/*
 * is_peb_under_migration() - check that PEB is under migration
 * @pebc: pointer on PEB container
 */
bool is_peb_under_migration(struct ssdfs_peb_container *pebc)
{
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&pebc->migration_state);

	SSDFS_DBG("migration state %#x\n", state);

	switch (state) {
	case SSDFS_PEB_NOT_MIGRATING:
		return false;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
	case SSDFS_PEB_UNDER_MIGRATION:
	case SSDFS_PEB_FINISHING_MIGRATION:
		return true;

	default:
		SSDFS_WARN("invalid migration_state %#x\n",
			   atomic_read(&pebc->migration_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return false;
}

/*
 * is_pebs_relation_alive() - check PEBs' relation validity
 * @pebc: pointer on PEB container
 */
bool is_pebs_relation_alive(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *dst_pebc;
	int shared_free_dst_blks = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;

	SSDFS_DBG("items_state %#x\n",
		  atomic_read(&pebc->items_state));

try_define_items_state:
	switch (atomic_read(&pebc->items_state)) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
		return false;

	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		if (atomic_read(&pebc->shared_free_dst_blks) <= 0)
			return false;
		else
			return true;

	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		return true;

	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		switch (atomic_read(&pebc->migration_state)) {
		case SSDFS_PEB_UNDER_MIGRATION:
			/* valid state */
			break;

		case SSDFS_PEB_RELATION_PREPARATION: {
				DEFINE_WAIT(wait);

				prepare_to_wait(&si->migration.wait, &wait,
						TASK_UNINTERRUPTIBLE);
				schedule();
				finish_wait(&si->migration.wait, &wait);
				goto try_define_items_state;
			}
			break;

		default:
			SSDFS_WARN("invalid migration_state %#x\n",
				   atomic_read(&pebc->migration_state));
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
			return false;
		}

		down_read(&pebc->lock);

		if (!pebc->dst_peb) {
			err = -ERANGE;
			SSDFS_WARN("dst_peb is NULL\n");
			goto finish_relation_check;
		}

		dst_pebc = pebc->dst_peb->pebc;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!dst_pebc);
#endif /* CONFIG_SSDFS_DEBUG */

		shared_free_dst_blks =
			atomic_read(&dst_pebc->shared_free_dst_blks);

finish_relation_check:
		up_read(&pebc->lock);

		if (unlikely(err))
			return false;

		if (shared_free_dst_blks > 0)
			return true;
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   atomic_read(&pebc->items_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		break;
	}

	return false;
}

/*
 * has_peb_migration_done() - check that PEB's migration has been done
 * @pebc: pointer on PEB container
 */
bool has_peb_migration_done(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_block_bmap *blk_bmap;
	u16 valid_blks = U16_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("migration_state %#x\n",
		  atomic_read(&pebc->migration_state));

	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_NOT_MIGRATING:
	case SSDFS_PEB_FINISHING_MIGRATION:
		return true;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
		return false;

	case SSDFS_PEB_UNDER_MIGRATION:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid migration_state %#x\n",
			   atomic_read(&pebc->migration_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return true;
	}

	si = pebc->parent_si;
	seg_blkbmap = &si->blk_bmap;

	if (pebc->peb_index >= seg_blkbmap->pebs_count) {
		SSDFS_WARN("peb_index %u >= pebs_count %u\n",
			   pebc->peb_index,
			   seg_blkbmap->pebs_count);
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!seg_blkbmap->peb);
#endif /* CONFIG_SSDFS_DEBUG */

	peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];

	down_read(&peb_blkbmap->lock);

	switch (atomic_read(&peb_blkbmap->buffers_state)) {
	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		/* valid state */
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid buffers_state %#x\n",
			   atomic_read(&peb_blkbmap->buffers_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_define_bmap_state;
		break;
	}

	blk_bmap = peb_blkbmap->src;

	if (!blk_bmap) {
		err = -ERANGE;
		SSDFS_WARN("source block bitmap is NULL\n");
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_define_bmap_state;
	}

	err = ssdfs_block_bmap_lock(blk_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap\n");
		goto finish_define_bmap_state;
	}

	err = ssdfs_block_bmap_get_used_pages(blk_bmap);

	ssdfs_block_bmap_unlock(blk_bmap);

	if (unlikely(err < 0)) {
		SSDFS_ERR("fail to define valid blocks count: "
			  "err %d\n", err);
		goto finish_define_bmap_state;
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(err >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
		valid_blks = (u16)err;
		err = 0;
	}

finish_define_bmap_state:
	up_read(&peb_blkbmap->lock);

	if (unlikely(err))
		return false;

	return valid_blks == 0 ? true : false;
}

/*
 * should_migration_be_finished() - check that migration should be finished
 * @pebc: pointer on PEB container
 */
bool should_migration_be_finished(struct ssdfs_peb_container *pebc)
{
	return !is_pebs_relation_alive(pebc) || has_peb_migration_done(pebc);
}

/*
 * ssdfs_peb_migrate_valid_blocks_range() - migrate valid blocks
 * @si: segment object
 * @pebc: pointer on PEB container
 * @peb_blkbmap: PEB container's block bitmap
 * @range: range of valid blocks
 */
static
int ssdfs_peb_migrate_valid_blocks_range(struct ssdfs_segment_info *si,
					 struct ssdfs_peb_container *pebc,
					 struct ssdfs_peb_blk_bmap *peb_blkbmap,
					 struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_segment_request *req;
	struct ssdfs_block_bmap_range copy_range;
	struct ssdfs_block_bmap_range sub_range;
	bool need_repeat = false;
	int processed_blks;
	struct page *page;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !pebc || !peb_blkbmap || !range);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_type %#x, "
		  "range (start %u, len %u)\n",
		  si->seg_id, pebc->peb_index, pebc->peb_type,
		  range->start, range->len);

	if (range->len == 0) {
		SSDFS_ERR("empty range\n");
		return -EINVAL;
	}

	memcpy(&copy_range, range, sizeof(struct ssdfs_block_bmap_range));

repeat_valid_blocks_processing:
	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate request: err %d\n",
			  err);
		return err;
	}

	need_repeat = false;
	ssdfs_request_init(req);
	ssdfs_get_request(req);

	ssdfs_request_prepare_internal_data(SSDFS_PEB_COLLECT_GARBAGE_REQ,
					    SSDFS_COPY_PAGE,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	err = ssdfs_peb_copy_pages_range(pebc, &copy_range, req);
	if (err == -EAGAIN) {
		err = 0;
		need_repeat = true;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to copy range: err %d\n",
			  err);
		goto fail_process_valid_blocks;
	}

	processed_blks = req->result.processed_blks;

	if (copy_range.len < processed_blks) {
		err = -ERANGE;
		SSDFS_ERR("range1 %u <= range2 %d\n",
			  copy_range.len, processed_blks);
		goto fail_process_valid_blocks;
	}

	for (i = 0; i < processed_blks; i++)
		ssdfs_peb_mark_request_block_uptodate(pebc, req, i);

	for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
		page = req->result.pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		set_page_writeback(page);
	}

	req->result.err = 0;
	req->result.processed_blks = 0;
	atomic_set(&req->result.state, SSDFS_UNKNOWN_REQ_RESULT);

	err = ssdfs_segment_migrate_range_async(si, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to migrate range: err %d\n",
			  err);
		goto fail_process_valid_blocks;
	}

	sub_range.start = copy_range.start;
	sub_range.len = processed_blks;

	err = ssdfs_peb_blk_bmap_invalidate(peb_blkbmap,
					    SSDFS_PEB_BLK_BMAP_SOURCE,
					    &sub_range);
	if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate range: "
			  "(start %u, len %u), err %d\n",
			  sub_range.start, sub_range.len, err);
		goto finish_valid_blocks_processing;
	}

	if (need_repeat) {
		copy_range.start += processed_blks;
		copy_range.len -= processed_blks;
		goto repeat_valid_blocks_processing;
	}

	return 0;

fail_process_valid_blocks:
	ssdfs_migration_pagevec_release(&req->result.pvec);
	ssdfs_put_request(req);
	ssdfs_request_free(req);

finish_valid_blocks_processing:
	return err;
}

/*
 * ssdfs_peb_migrate_pre_alloc_blocks_range() - migrate pre-allocated blocks
 * @si: segment object
 * @pebc: pointer on PEB container
 * @peb_blkbmap: PEB container's block bitmap
 * @range: range of pre-allocated blocks
 */
static
int ssdfs_peb_migrate_pre_alloc_blocks_range(struct ssdfs_segment_info *si,
					struct ssdfs_peb_container *pebc,
					struct ssdfs_peb_blk_bmap *peb_blkbmap,
					struct ssdfs_block_bmap_range *range)
{
	struct ssdfs_segment_request *req;
	struct ssdfs_block_bmap_range sub_range;
	int processed_blks = 0;
	u32 logical_blk;
	bool has_data = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !pebc || !peb_blkbmap || !range);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_type %#x, "
		  "range (start %u, len %u)\n",
		  si->seg_id, pebc->peb_index, pebc->peb_type,
		  range->start, range->len);

	if (range->len == 0) {
		SSDFS_ERR("empty range\n");
		return -EINVAL;
	}

	while (processed_blks < range->len) {
		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate request: err %d\n",
				  err);
			return err;
		}

		ssdfs_request_init(req);
		ssdfs_get_request(req);

		ssdfs_request_prepare_internal_data(SSDFS_PEB_COLLECT_GARBAGE_REQ,
						    SSDFS_COPY_PRE_ALLOC_PAGE,
						    SSDFS_REQ_SYNC,
						    req);
		ssdfs_request_define_segment(si->seg_id, req);

		logical_blk = range->start + processed_blks;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(logical_blk >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		req->place.start.blk_index = (u16)logical_blk;
		req->place.len = 1;

		req->extent.ino = U64_MAX;
		req->extent.logical_offset = U64_MAX;
		req->extent.data_bytes = 0;

		req->result.processed_blks = 0;

		err = ssdfs_peb_copy_pre_alloc_page(pebc, logical_blk, req);
		if (err == -ENODATA) {
			/* pre-allocated page hasn't content */
			err = 0;
			has_data = false;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to copy pre-alloc page: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			goto fail_process_pre_alloc_blocks;
		} else {
			int i;
			u32 pages_count = pagevec_count(&req->result.pvec);
			struct page *page;

			ssdfs_peb_mark_request_block_uptodate(pebc, req, 0);

			for (i = 0; i < pages_count; i++) {
				page = req->result.pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

				set_page_writeback(page);
			}

			has_data = true;
		}

		req->result.err = 0;
		req->result.processed_blks = 0;
		atomic_set(&req->result.state, SSDFS_UNKNOWN_REQ_RESULT);

		if (has_data) {
			err = ssdfs_segment_migrate_fragment_async(si, req);
		} else {
			err = ssdfs_segment_migrate_pre_alloc_page_async(si,
									 req);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to migrate pre-alloc page: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			goto fail_process_pre_alloc_blocks;
		}

		sub_range.start = logical_blk;
		sub_range.len = 1;

		err = ssdfs_peb_blk_bmap_invalidate(peb_blkbmap,
						    SSDFS_PEB_BLK_BMAP_SOURCE,
						    &sub_range);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate range: "
				  "(start %u, len %u), err %d\n",
				  sub_range.start, sub_range.len, err);
			goto finish_pre_alloc_blocks_processing;
		}

		processed_blks++;
	}

	return 0;

fail_process_pre_alloc_blocks:
	ssdfs_migration_pagevec_release(&req->result.pvec);
	ssdfs_put_request(req);
	ssdfs_request_free(req);

finish_pre_alloc_blocks_processing:
	return err;
}

/*
 * has_ssdfs_source_peb_valid_blocks() - check that source PEB has valid blocks
 * @pebc: pointer on PEB container
 */
bool has_ssdfs_source_peb_valid_blocks(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int used_pages;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_type %#x, "
		  "migration_state %#x, items_state %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  atomic_read(&pebc->migration_state),
		  atomic_read(&pebc->items_state));

	si = pebc->parent_si;
	seg_blkbmap = &si->blk_bmap;
	peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];

	used_pages = ssdfs_src_blk_bmap_get_used_pages(peb_blkbmap);
	if (used_pages < 0) {
		err = used_pages;
		SSDFS_ERR("fail to get used pages: err %d\n",
			  err);
		return false;
	}

	if (used_pages > 0)
		return true;

	return false;
}

/*
 * ssdfs_peb_prepare_range_migration() - prepare blocks' range migration
 * @pebc: pointer on PEB container
 * @range_len: required range length
 * @blk_type: type of migrating block
 *
 * This method tries to prepare range of blocks for migration.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL    - invalid input.
 * %-ERANGE    - internal error.
 * %-ENODATA   - no blocks for migration has been found.
 */
int ssdfs_peb_prepare_range_migration(struct ssdfs_peb_container *pebc,
				      u32 range_len, int blk_type)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_block_bmap_range range = {0, 0};
	u32 pages_per_peb;
	int used_pages;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
	BUG_ON(!mutex_is_locked(&pebc->migration_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_type %#x, "
		  "migration_state %#x, migration_phase %#x, "
		  "items_state %#x, range_len %u, blk_type %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  atomic_read(&pebc->migration_state),
		  atomic_read(&pebc->migration_phase),
		  atomic_read(&pebc->items_state),
		  range_len, blk_type);

	if (range_len == 0) {
		SSDFS_ERR("invalid range_len %u\n", range_len);
		return -EINVAL;
	}

	switch (blk_type) {
	case SSDFS_BLK_VALID:
	case SSDFS_BLK_PRE_ALLOCATED:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected blk_type %#x\n",
			  blk_type);
		return -EINVAL;
	}

	si = pebc->parent_si;
	seg_blkbmap = &si->blk_bmap;
	peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];
	pages_per_peb = si->fsi->pages_per_peb;

	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_UNDER_MIGRATION:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid migration_state %#x\n",
			   atomic_read(&pebc->migration_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	switch (atomic_read(&pebc->migration_phase)) {
	case SSDFS_SRC_PEB_NOT_EXHAUSTED:
		SSDFS_DBG("SRC PEB is not exausted\n");
		return -ENODATA;

	case SSDFS_DST_PEB_RECEIVES_DATA:
		/* continue logic */
		break;

	default:
		SSDFS_ERR("unexpected migration phase %#x\n",
			  atomic_read(&pebc->migration_phase));
		return -ERANGE;
	}

	used_pages = ssdfs_src_blk_bmap_get_used_pages(peb_blkbmap);
	if (used_pages < 0) {
		err = used_pages;
		SSDFS_ERR("fail to get used pages: err %d\n",
			  err);
		return err;
	}

	SSDFS_DBG("used_pages %d\n", used_pages);

	if (used_pages > 0) {
		err = ssdfs_peb_blk_bmap_collect_garbage(peb_blkbmap,
							 0, pages_per_peb,
							 blk_type,
							 &range);

		SSDFS_DBG("found range: (start %u, len %u), err %d\n",
			  range.start, range.len, err);

		if (err == -ENODATA) {
			/* no valid blocks */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to collect garbage: "
				  "seg_id %llu, err %d\n",
				  si->seg_id, err);
			return err;
		} else if (range.len == 0) {
			SSDFS_ERR("invalid found range "
				  "(start %u, len %u)\n",
				  range.start, range.len);
			return -ERANGE;
		}

		range.len = min_t(u32, range_len, (u32)range.len);

		SSDFS_DBG("final range: (start %u, len %u)\n",
			  range.start, range.len);

		switch (blk_type) {
		case SSDFS_BLK_VALID:
			err = ssdfs_peb_migrate_valid_blocks_range(si, pebc,
								   peb_blkbmap,
								   &range);
			if (unlikely(err)) {
				SSDFS_ERR("fail to migrate valid blocks: "
					  "range (start %u, len %u), err %d\n",
					  range.start, range.len, err);
				return err;
			}
			break;

		case SSDFS_BLK_PRE_ALLOCATED:
			err = ssdfs_peb_migrate_pre_alloc_blocks_range(si,
								    pebc,
								    peb_blkbmap,
								    &range);
			if (unlikely(err)) {
				SSDFS_ERR("fail to migrate pre-alloc blocks: "
					  "range (start %u, len %u), err %d\n",
					  range.start, range.len, err);
				return err;
			}
			break;

		default:
			BUG();
		}
	} else {
		SSDFS_DBG("unable to find blocks for migration\n");
		return -ENODATA;
	}

	return 0;
}

/*
 * ssdfs_peb_finish_migration() - finish PEB migration
 * @pebc: pointer on PEB container
 */
int ssdfs_peb_finish_migration(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_info *pebi;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int used_pages;
	u32 pages_per_peb;
	int old_migration_state;
	bool is_peb_exhausted = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_type %#x, "
		  "migration_state %#x, items_state %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  atomic_read(&pebc->migration_state),
		  atomic_read(&pebc->items_state));

	si = pebc->parent_si;
	fsi = pebc->parent_si->fsi;
	pages_per_peb = fsi->pages_per_peb;
	seg_blkbmap = &si->blk_bmap;
	peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];

	mutex_lock(&pebc->migration_lock);

check_migration_state:
	old_migration_state = atomic_read(&pebc->migration_state);

	used_pages = ssdfs_src_blk_bmap_get_used_pages(peb_blkbmap);
	if (used_pages < 0) {
		err = used_pages;
		SSDFS_ERR("fail to get used pages: err %d\n",
			  err);
		goto finish_migration_done;
	}

	switch (old_migration_state) {
	case SSDFS_PEB_NOT_MIGRATING:
	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
		err = 0;
		SSDFS_DBG("PEB is not migrating: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
		goto finish_migration_done;

	case SSDFS_PEB_UNDER_MIGRATION:
		pebi = pebc->dst_peb;
		if (!pebi) {
			err = -ERANGE;
			SSDFS_ERR("PEB pointer is NULL: "
				  "seg_id %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
			goto finish_migration_done;
		}

		ssdfs_peb_current_log_lock(pebi);
		is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
		ssdfs_peb_current_log_unlock(pebi);

		if (is_peb_exhausted)
			goto try_finish_migration_now;
		else if (has_peb_migration_done(pebc))
			goto try_finish_migration_now;
		else if (used_pages <= SSDFS_GC_FINISH_MIGRATION)
			goto try_finish_migration_now;
		else {
			err = 0;
			SSDFS_DBG("Don't finish migration: "
				  "seg_id %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
			goto finish_migration_done;
		}
		break;

	case SSDFS_PEB_FINISHING_MIGRATION: {
			DEFINE_WAIT(wait);

			mutex_unlock(&pebc->migration_lock);
			prepare_to_wait(&si->migration.wait, &wait,
					TASK_UNINTERRUPTIBLE);
			schedule();
			finish_wait(&si->migration.wait, &wait);
			mutex_lock(&pebc->migration_lock);
			goto check_migration_state;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid migration_state %#x\n",
			   atomic_read(&pebc->migration_state));
		goto finish_migration_done;
	}

try_finish_migration_now:
	atomic_set(&pebc->migration_state, SSDFS_PEB_FINISHING_MIGRATION);

	while (used_pages > 0) {
		struct ssdfs_block_bmap_range range1 = {0, 0};
		struct ssdfs_block_bmap_range range2 = {0, 0};

		SSDFS_DBG("used_pages %d\n", used_pages);

		err = ssdfs_peb_blk_bmap_collect_garbage(peb_blkbmap,
							 0, pages_per_peb,
							 SSDFS_BLK_VALID,
							 &range1);

		SSDFS_DBG("range1.start %u, range1.len %u, err %d\n",
			  range1.start, range1.len, err);

		if (err == -ENODATA) {
			/* no valid blocks */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to collect garbage: "
				  "seg_id %llu, err %d\n",
				  si->seg_id, err);
			goto finish_migration_done;
		}

		err = ssdfs_peb_blk_bmap_collect_garbage(peb_blkbmap,
							0, pages_per_peb,
							SSDFS_BLK_PRE_ALLOCATED,
							&range2);

		SSDFS_DBG("range2.start %u, range2.len %u, err %d\n",
			  range2.start, range2.len, err);

		if (err == -ENODATA) {
			/* no valid blocks */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to collect garbage: "
				  "seg_id %llu, err %d\n",
				  si->seg_id, err);
			goto finish_migration_done;
		}

		if (range1.len == 0 && range2.len == 0) {
			err = -ERANGE;
			SSDFS_ERR("no valid blocks were found\n");
			goto finish_migration_done;
		}

		if (range1.len > 0) {
			err = ssdfs_peb_migrate_valid_blocks_range(si, pebc,
								   peb_blkbmap,
								   &range1);
			if (unlikely(err)) {
				SSDFS_ERR("fail to migrate valid blocks: "
					  "range (start %u, len %u), err %d\n",
					  range1.start, range1.len, err);
				goto finish_migration_done;
			}
		}

		if (range2.len > 0) {
			err = ssdfs_peb_migrate_pre_alloc_blocks_range(si,
								    pebc,
								    peb_blkbmap,
								    &range2);
			if (unlikely(err)) {
				SSDFS_ERR("fail to migrate pre-alloc blocks: "
					  "range (start %u, len %u), err %d\n",
					  range2.start, range2.len, err);
				goto finish_migration_done;
			}
		}

		used_pages -= range1.len;
		used_pages -= range2.len;

		if (used_pages < 0) {
			err = -ERANGE;
			SSDFS_ERR("invalid used_pages %d\n",
				  used_pages);
			goto finish_migration_done;
		}
	}

	used_pages = ssdfs_src_blk_bmap_get_used_pages(peb_blkbmap);
	if (used_pages != 0) {
		err = -ERANGE;
		SSDFS_ERR("source PEB has valid blocks: "
			  "used_pages %d\n",
			  used_pages);
		goto finish_migration_done;
	}

	switch (atomic_read(&pebc->items_state)) {
	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		err = ssdfs_peb_container_forget_relation(pebc);
		break;

	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		err = ssdfs_peb_container_forget_source(pebc);
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid items_state %#x\n",
			   atomic_read(&pebc->items_state));
		goto finish_migration_done;
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to break relation: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		goto finish_migration_done;
	}

finish_migration_done:
	if (err) {
		switch (atomic_read(&pebc->migration_state)) {
		case SSDFS_PEB_FINISHING_MIGRATION:
			atomic_set(&pebc->migration_state,
				   old_migration_state);
			break;

		default:
			/* do nothing */
			break;
		}
	}

	mutex_unlock(&pebc->migration_lock);

	SSDFS_DBG("finished\n");

	return err;
}
