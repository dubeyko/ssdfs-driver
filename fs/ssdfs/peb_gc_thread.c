// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_gc_thread.c - GC thread functionality.
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

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "ssdfs.h"
#include "page_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "compression.h"
#include "block_bitmap.h"
#include "peb_container.h"
#include "peb_mapping_table.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "segment_tree.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_gc_page_leaks;
atomic64_t ssdfs_gc_folio_leaks;
atomic64_t ssdfs_gc_memory_leaks;
atomic64_t ssdfs_gc_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_gc_cache_leaks_increment(void *kaddr)
 * void ssdfs_gc_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_gc_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_gc_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_gc_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_gc_kfree(void *kaddr)
 * struct page *ssdfs_gc_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_gc_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_gc_free_page(struct page *page)
 * void ssdfs_gc_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(gc)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(gc)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_gc_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_gc_page_leaks, 0);
	atomic64_set(&ssdfs_gc_folio_leaks, 0);
	atomic64_set(&ssdfs_gc_memory_leaks, 0);
	atomic64_set(&ssdfs_gc_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_gc_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_gc_page_leaks) != 0) {
		SSDFS_ERR("GC: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_gc_page_leaks));
	}

	if (atomic64_read(&ssdfs_gc_folio_leaks) != 0) {
		SSDFS_ERR("GC: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_gc_folio_leaks));
	}

	if (atomic64_read(&ssdfs_gc_memory_leaks) != 0) {
		SSDFS_ERR("GC: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_gc_memory_leaks));
	}

	if (atomic64_read(&ssdfs_gc_cache_leaks) != 0) {
		SSDFS_ERR("GC: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_gc_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/******************************************************************************
 *                           GC THREAD FUNCTIONALITY                          *
 ******************************************************************************/

static
struct ssdfs_thread_descriptor thread_desc[SSDFS_GC_THREAD_TYPE_MAX] = {
	{.threadfn = ssdfs_using_seg_gc_thread_func,
	 .fmt = "ssdfs-gc-using-seg",},
	{.threadfn = ssdfs_used_seg_gc_thread_func,
	 .fmt = "ssdfs-gc-used-seg",},
	{.threadfn = ssdfs_pre_dirty_seg_gc_thread_func,
	 .fmt = "ssdfs-gc-pre-dirty-seg",},
	{.threadfn = ssdfs_dirty_seg_gc_thread_func,
	 .fmt = "ssdfs-gc-dirty-seg",},
};

/*
 * __ssdfs_peb_define_extent() - define extent for request
 * @fsi: pointer on shared file system object
 * @pebi: pointer on PEB object
 * @desc_off: physical offset descriptor
 * @desc_array: array of metadata descriptors
 * @pos: position offset
 * @req: request
 *
 * This function tries to define extent for request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to extract the whole range.
 */
static
int __ssdfs_peb_define_extent(struct ssdfs_fs_info *fsi,
			      struct ssdfs_peb_info *pebi,
			      struct ssdfs_phys_offset_descriptor *desc_off,
			      struct ssdfs_metadata_descriptor *desc_array,
			      struct ssdfs_offset_position *pos,
			      struct ssdfs_segment_request *req)
{
	struct ssdfs_block_descriptor *blk_desc = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !desc_off || !req);
	BUG_ON(!desc_array);

	SSDFS_DBG("peb %llu, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->peb_id,
		  req->private.class, req->private.cmd, req->private.type);
	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id,
		  pebi->peb_id,
		  req->extent.logical_offset,
		  req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_blk_desc_buffer_init(pebi->pebc, req, desc_off, pos,
					 desc_array,
					 SSDFS_SEG_HDR_DESC_MAX);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init blk desc buffer: err %d\n",
			  err);
		goto finish_define_extent;
	}

	blk_desc = &pos->blk_desc.buf;

	if (req->extent.ino >= U64_MAX) {
		req->extent.ino = le64_to_cpu(blk_desc->ino);
		req->extent.logical_offset =
			le32_to_cpu(blk_desc->logical_offset);
		req->extent.logical_offset *= fsi->pagesize;
	} else if (req->extent.ino != le64_to_cpu(blk_desc->ino)) {
		err = -EAGAIN;
		req->place.len = req->result.processed_blks;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("OFFSET DESCRIPTOR: "
			  "logical_offset %u, logical_blk %u, "
			  "peb_page %u, log_start_page %u, "
			  "log_area %u, peb_migration_id %u, "
			  "byte_offset %u\n",
			  le32_to_cpu(desc_off->page_desc.logical_offset),
			  le16_to_cpu(desc_off->page_desc.logical_blk),
			  le16_to_cpu(desc_off->page_desc.peb_page),
			  le16_to_cpu(desc_off->blk_state.log_start_page),
			  desc_off->blk_state.log_area,
			  desc_off->blk_state.peb_migration_id,
			  le32_to_cpu(desc_off->blk_state.byte_offset));
		SSDFS_DBG("BLOCK DECRIPTOR: "
			  "ino %llu, logical_offset %u, "
			  "peb_index %u, peb_page %u, "
			  "log_start_page %u, "
			  "log_area %u, peb_migration_id %u, "
			  "byte_offset %u\n",
			  le64_to_cpu(blk_desc->ino),
			  le32_to_cpu(blk_desc->logical_offset),
			  le16_to_cpu(blk_desc->peb_index),
			  le16_to_cpu(blk_desc->peb_page),
			  le16_to_cpu(blk_desc->state[0].log_start_page),
			  blk_desc->state[0].log_area,
			  blk_desc->state[0].peb_migration_id,
			  le32_to_cpu(blk_desc->state[0].byte_offset));
		SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
			  "processed_blks %d, logical_block %u, "
			  "data_bytes %u, blks %u, "
			  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
			  req->extent.ino, req->place.start.seg_id,
			  pebi->peb_id,
			  req->extent.logical_offset,
			  req->result.processed_blks,
			  req->place.start.blk_index,
			  req->place.len,
			  req->extent.data_bytes, req->extent.cno,
			  req->extent.parent_snapshot,
			  req->private.cmd, req->private.type);
		SSDFS_DBG("ino1 %llu != ino2 %llu, peb %llu\n",
			   req->extent.ino,
			   le64_to_cpu(blk_desc->ino),
			   pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

		goto finish_define_extent;
	}

	req->extent.data_bytes += fsi->pagesize;

finish_define_extent:
	return err;
}

/*
 * __ssdfs_peb_copy_page() - copy page from PEB into buffer
 * @pebc: pointer on PEB container
 * @desc_off: physical offset descriptor
 * @pos: position offset
 * @req: request
 *
 * This function tries to copy PEB's page into the buffer.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to extract the whole range.
 */
static
int __ssdfs_peb_copy_page(struct ssdfs_peb_container *pebc,
			  struct ssdfs_phys_offset_descriptor *desc_off,
			  struct ssdfs_offset_position *pos,
			  struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_info *pebi = NULL;
	struct ssdfs_metadata_descriptor desc_array[SSDFS_SEG_HDR_DESC_MAX];
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!desc_off || !pos || !req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;

	down_read(&pebc->lock);

	pebi = pebc->src_peb;

	if (!pebi) {
		err = -ERANGE;
		SSDFS_ERR("invalid source peb: "
			  "src_peb %p, dst_peb %p\n",
			  pebc->src_peb, pebc->dst_peb);
		goto finish_copy_page;
	}

	if (pagevec_space(&req->result.pvec) == 0) {
		err = -EAGAIN;
		SSDFS_DBG("request's pagevec is full\n");
		goto finish_copy_page;
	}

	err = __ssdfs_peb_define_extent(fsi, pebi, desc_off,
					desc_array, pos, req);
	if (err == -EAGAIN) {
		SSDFS_DBG("unable to add block of another inode\n");
		goto finish_copy_page;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to define extent: "
			  "seg %llu, peb_index %u, peb %llu, err %d\n",
			  pebc->parent_si->seg_id, pebc->peb_index,
			  pebi->peb_id, err);
		goto finish_copy_page;
	}

	err = ssdfs_request_add_allocated_page_locked(req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate memory page: "
			  "err %d\n", err);
		goto finish_copy_page;
	}

	err = ssdfs_peb_read_block_state(pebc, req, desc_off, pos,
					 desc_array,
					 SSDFS_SEG_HDR_DESC_MAX);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block state: err %d\n",
			  err);
		goto finish_copy_page;
	}

finish_copy_page:
	up_read(&pebc->lock);

	return err;
}

/*
 * ssdfs_peb_define_extent() - define extent for request
 * @pebc: pointer on PEB container
 * @desc_off: physical offset descriptor
 * @req: request
 *
 * This function tries to define extent for request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to extract the whole range.
 */
#ifdef CONFIG_SSDFS_UNDER_DEVELOPMENT_FUNC
static
int ssdfs_peb_define_extent(struct ssdfs_peb_container *pebc,
			    struct ssdfs_phys_offset_descriptor *desc_off,
			    struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_info *pebi = NULL;
	struct ssdfs_metadata_descriptor desc_array[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_block_descriptor blk_desc = {0};
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!desc_off || !req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;

	down_read(&pebc->lock);

	pebi = pebc->src_peb;

	if (!pebi) {
		err = -ERANGE;
		SSDFS_ERR("invalid source peb: "
			  "src_peb %p, dst_peb %p\n",
			  pebc->src_peb, pebc->dst_peb);
		goto finish_define_extent;
	}

	err = __ssdfs_peb_define_extent(fsi, pebi, desc_off,
					desc_array, &blk_desc, req);
	if (err == -EAGAIN) {
		SSDFS_DBG("unable to add block of another inode\n");
		goto finish_define_extent;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to define extent: "
			  "seg %llu, peb_index %u, peb %llu, err %d\n",
			  pebc->parent_si->seg_id, pebc->peb_index,
			  pebi->peb_id, err);
		goto finish_define_extent;
	}

finish_define_extent:
	up_read(&pebc->lock);

	return err;
}
#endif /* CONFIG_SSDFS_UNDER_DEVELOPMENT_FUNC */

/*
 * ssdfs_peb_copy_pre_alloc_page() - copy pre-alloc page into buffer
 * @pebc: pointer on PEB container
 * @logical_blk: logical block
 * @req: request
 *
 * This function tries to copy PEB's page into the buffer.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA     - pre-allocated block hasn't content.
 * %-EAGAIN     - unable to extract the whole range.
 */
int ssdfs_peb_copy_pre_alloc_page(struct ssdfs_peb_container *pebc,
				  u32 logical_blk,
				  struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *desc_off = NULL;
	struct ssdfs_offset_position pos = {0};
	u16 peb_index;
	bool has_data = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "logical_blk %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;

	if (logical_blk >= U32_MAX) {
		SSDFS_ERR("invalid logical_blk %u\n",
			  logical_blk);
		return -EINVAL;
	}

	table = pebc->parent_si->blk2off_table;

	desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index, NULL,
						&pos);
	if (IS_ERR(desc_off) && PTR_ERR(desc_off) == -EAGAIN) {
		struct completion *end = &table->full_init_end;

		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
							&peb_index, NULL,
							&pos);
	}

	if (IS_ERR_OR_NULL(desc_off)) {
		err = (desc_off == NULL ? -ERANGE : PTR_ERR(desc_off));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

	has_data = (desc_off->blk_state.log_area < SSDFS_LOG_AREA_MAX) &&
		    (le32_to_cpu(desc_off->blk_state.byte_offset) < U32_MAX);

	if (has_data) {
		ssdfs_peb_read_request_cno(pebc);

		err = __ssdfs_peb_copy_page(pebc, desc_off, &pos, req);
		if (err == -EAGAIN) {
			SSDFS_DBG("unable to add block of another inode\n");
			goto finish_copy_page;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to copy page: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			goto finish_copy_page;
		}

		err = ssdfs_blk2off_table_set_block_migration(table,
							      logical_blk,
							      peb_index,
							      req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set migration state: "
				  "logical_blk %u, peb_index %u, err %d\n",
				  logical_blk, peb_index, err);
			goto finish_copy_page;
		}

finish_copy_page:
		ssdfs_peb_finish_read_request_cno(pebc);
	} else {
		if (req->extent.logical_offset >= U64_MAX)
			req->extent.logical_offset = 0;

		req->extent.data_bytes += fsi->pagesize;

		err = -ENODATA;
		req->result.processed_blks = 1;
		req->result.err = err;
	}

	return err;
}

/*
 * ssdfs_peb_copy_page() - copy valid page from PEB into buffer
 * @pebc: pointer on PEB container
 * @logical_blk: logical block
 * @req: request
 *
 * This function tries to copy PEB's page into the buffer.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to extract the whole range.
 */
int ssdfs_peb_copy_page(struct ssdfs_peb_container *pebc,
			u32 logical_blk,
			struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *desc_off = NULL;
	struct ssdfs_offset_position pos = {0};
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "logical_blk %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;

	if (logical_blk >= U32_MAX) {
		SSDFS_ERR("invalid logical_blk %u\n",
			  logical_blk);
		return -EINVAL;
	}

	table = pebc->parent_si->blk2off_table;

	desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index, NULL,
						&pos);
	if (IS_ERR(desc_off) && PTR_ERR(desc_off) == -EAGAIN) {
		struct completion *end = &table->full_init_end;

		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
							&peb_index, NULL,
							&pos);
	}

	if (IS_ERR_OR_NULL(desc_off)) {
		err = (desc_off == NULL ? -ERANGE : PTR_ERR(desc_off));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

	ssdfs_peb_read_request_cno(pebc);

	err = __ssdfs_peb_copy_page(pebc, desc_off, &pos, req);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to copy the whole range: "
			  "logical_blk %u, peb_index %u\n",
			  logical_blk, peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_copy_page;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to copy page: "
			  "logical_blk %u, peb_index %u, err %d\n",
			  logical_blk, peb_index, err);
		goto finish_copy_page;
	}

	err = ssdfs_blk2off_table_set_block_migration(table,
						      logical_blk,
						      peb_index,
						      req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set migration state: "
			  "logical_blk %u, peb_index %u, err %d\n",
			  logical_blk, peb_index, err);
		goto finish_copy_page;
	}

finish_copy_page:
	ssdfs_peb_finish_read_request_cno(pebc);

	return err;
}

/*
 * ssdfs_peb_copy_pages_range() - copy pages' range into buffer
 * @pebc: pointer on PEB container
 * @range: range of logical blocks
 * @req: request
 *
 * This function tries to copy PEB's page into the buffer.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to extract the whole range.
 */
int ssdfs_peb_copy_pages_range(struct ssdfs_peb_container *pebc,
				struct ssdfs_block_bmap_range *range,
				struct ssdfs_segment_request *req)
{
	u32 logical_blk;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!range || !req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "range->start %u, range->len %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  range->start, range->len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (range->len == 0) {
		SSDFS_WARN("empty pages range request\n");
		return 0;
	}

	req->extent.ino = U64_MAX;
	req->extent.logical_offset = U64_MAX;
	req->extent.data_bytes = 0;

	req->place.start.seg_id = pebc->parent_si->seg_id;
	req->place.start.blk_index = range->start;
	req->place.len = 0;

	req->result.processed_blks = 0;

	for (i = 0; i < range->len; i++) {
		logical_blk = range->start + i;
		req->place.len++;

		err = ssdfs_peb_copy_page(pebc, logical_blk, req);
		if (err == -EAGAIN) {
			req->place.len = req->result.processed_blks;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to copy the whole range: "
				  "seg %llu, logical_blk %u, len %u\n",
				  pebc->parent_si->seg_id,
				  logical_blk, req->place.len);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to copy page: "
				  "seg %llu, logical_blk %u, err %d\n",
				  pebc->parent_si->seg_id,
				  logical_blk, err);
			return err;
		}
	}

	return 0;
}

/* TODO: add condition of presence of items for processing  */
#define GC_THREAD_WAKE_CONDITION(pebi) \
	(kthread_should_stop())

/*
 * ssdfs_peb_gc_thread_func() - main fuction of GC thread
 * @data: pointer on data object
 *
 * This function is main fuction of GC thread.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_peb_gc_thread_func(void *data)
{
	struct ssdfs_peb_container *pebc = data;
	wait_queue_head_t *wait_queue;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -EINVAL;
	}

	SSDFS_DBG("GC thread: seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	wait_queue = &pebc->parent_si->wait_queue[SSDFS_PEB_GC_THREAD];

repeat:
	if (kthread_should_stop()) {
		complete_all(&pebc->thread[SSDFS_PEB_GC_THREAD].full_stop);
		return 0;
	}

	/* TODO: collect garbage */
	SSDFS_DBG("TODO: implement %s\n", __func__);
	goto sleep_gc_thread;
	/*return -ENOSYS;*/

sleep_gc_thread:
	wait_event_interruptible(*wait_queue, GC_THREAD_WAKE_CONDITION(pebi));
	goto repeat;
}

/*
 * ssdfs_gc_find_next_seg_id() - find next victim segment ID
 * @fsi: pointer on shared file system object
 * @start_seg_id: starting segment ID
 * @max_seg_id: upper bound value for the search
 * @seg_type: type of segment
 * @type_mask: segment types' mask
 * @seg_id: found segment ID [out]
 *
 * This function tries to find the next victim
 * segement ID for the requested type.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - no segment for requested state was found.
 */
static
int ssdfs_gc_find_next_seg_id(struct ssdfs_fs_info *fsi,
			      u64 start_seg_id, u64 max_seg_id,
			      int seg_type, int type_mask,
			      u64 *seg_id)
{
	struct ssdfs_segment_bmap *segbmap;
	struct completion *init_end;
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->segbmap || !seg_id);

	SSDFS_DBG("fsi %p, start_seg_id %llu, max_seg_id %llu, "
		  "seg_type %#x, type_mask %#x\n",
		  fsi, start_seg_id, max_seg_id,
		  seg_type, type_mask);
#endif /* CONFIG_SSDFS_DEBUG */

	segbmap = fsi->segbmap;
	*seg_id = U64_MAX;

try_to_find_victim:
	res = ssdfs_segbmap_find(segbmap,
				 start_seg_id, max_seg_id,
				 seg_type, type_mask,
				 seg_id, &init_end);
	if (res >= 0) {
check_segment_state:
		switch (res) {
		case SSDFS_SEG_DATA_USING:
		case SSDFS_SEG_LEAF_NODE_USING:
		case SSDFS_SEG_HYBRID_NODE_USING:
		case SSDFS_SEG_INDEX_NODE_USING:
			/* do nothing */
			break;

		default:
			if (res != seg_type) {
				if (*seg_id >= max_seg_id) {
					res = -ENODATA;
					goto finish_search_segments;
				} else {
					start_seg_id = *seg_id + 1;
					*seg_id = U64_MAX;
#ifdef CONFIG_SSDFS_DEBUG
					SSDFS_DBG("res %#x != seg_type %#x\n",
						  res, seg_type);
#endif /* CONFIG_SSDFS_DEBUG */
					goto try_to_find_victim;
				}
			}
			break;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found segment: "
			  "seg_id %llu, state %#x\n",
			  *seg_id, res);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (res == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(init_end);
		if (unlikely(err)) {
			SSDFS_ERR("segbmap init failed: "
				  "err %d\n", err);
			return err;
		}

		res = ssdfs_segbmap_find(segbmap,
					 start_seg_id, max_seg_id,
					 seg_type, type_mask,
					 seg_id, &init_end);
		if (res >= 0)
			goto check_segment_state;
		else if (res == -ENODATA)
			goto finish_search_segments;
		else if (res == -EAGAIN) {
			res = -ENODATA;
			goto finish_search_segments;
		} else
			goto fail_find_segment;
	} else if (res == -ENODATA) {
finish_search_segments:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no more victim segments: "
			  "start_seg_id %llu, max_seg_id %llu\n",
			  start_seg_id, max_seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return res;
	} else {
fail_find_segment:
		SSDFS_ERR("fail to find segment number: "
			  "start_seg_id %llu, max_seg_id %llu, "
			  "err %d\n",
			  start_seg_id, max_seg_id, res);
		return res;
	}

	return 0;
}

/*
 * ssdfs_gc_convert_leb2peb() - convert LEB ID into PEB ID
 * @fsi: pointer on shared file system object
 * @leb_id: LEB ID number
 * @pebr: pointer on PEBs association container [out]
 *
 * This method tries to convert LEB ID into PEB ID.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - can't convert LEB to PEB.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_gc_convert_leb2peb(struct ssdfs_fs_info *fsi,
			     u64 leb_id,
			     struct ssdfs_maptbl_peb_relation *pebr)
{
	struct completion *init_end;
#ifdef CONFIG_SSDFS_DEBUG
	struct ssdfs_maptbl_peb_descriptor *ptr;
#endif /* CONFIG_SSDFS_DEBUG */
	u8 peb_type = SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebr);

	SSDFS_DBG("fsi %p, leb_id %llu, pebr %p\n",
		  fsi, leb_id, pebr);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id,
					   peb_type, pebr,
					   &init_end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(init_end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id,
						   peb_type, pebr,
						   &init_end);
	}

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("LEB is not mapped: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to convert LEB to PEB: "
			  "leb_id %llu, peb_type %#x, err %d\n",
			  leb_id, peb_type, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("LEB %llu\n", leb_id);

	ptr = &pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX];
	SSDFS_DBG("MAIN: peb_id %llu, shared_peb_index %u, "
		  "erase_cycles %u, type %#x, state %#x, "
		  "flags %#x\n",
		  ptr->peb_id, ptr->shared_peb_index,
		  ptr->erase_cycles, ptr->type,
		  ptr->state, ptr->flags);
	ptr = &pebr->pebs[SSDFS_MAPTBL_RELATION_INDEX];
	SSDFS_DBG("RELATION: peb_id %llu, shared_peb_index %u, "
		  "erase_cycles %u, type %#x, state %#x, "
		  "flags %#x\n",
		  ptr->peb_id, ptr->shared_peb_index,
		  ptr->erase_cycles, ptr->type,
		  ptr->state, ptr->flags);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * should_ssdfs_segment_be_destroyed() - check necessity to destroy a segment
 * @si: pointer on segment object
 *
 * This method tries to check the necessity to destroy
 * a segment object.
 */
static
bool should_ssdfs_segment_be_destroyed(struct ssdfs_segment_info *si)
{
	struct ssdfs_peb_container *pebc;
	struct ssdfs_peb_info *pebi;
	u64 peb_id;
	bool is_rq_empty;
	bool is_fq_empty;
	bool peb_has_dirty_pages = false;
	bool is_blk_bmap_dirty = false;
	bool dont_touch = false;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("seg_id %llu, refs_count %d\n",
		  si->seg_id,
		  atomic_read(&si->refs_count));
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&si->refs_count) > 0)
		return false;

	dont_touch = should_gc_doesnt_touch_segment(si);
	if (dont_touch)
		return false;

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
		peb_has_dirty_pages = ssdfs_peb_has_dirty_pages(pebi);
		peb_id = pebi->peb_id;
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_id %llu, peb_id %llu, refs_count %d, "
			  "peb_has_dirty_pages %#x, "
			  "not empty: (read %#x, flush %#x), "
			  "dont_touch %#x, is_blk_bmap_dirty %#x\n",
			  si->seg_id, peb_id,
			  atomic_read(&si->refs_count),
			  peb_has_dirty_pages,
			  !is_rq_empty, !is_fq_empty,
			  dont_touch, is_blk_bmap_dirty);
#endif /* CONFIG_SSDFS_DEBUG */

		if (!is_rq_empty || !is_fq_empty ||
		    peb_has_dirty_pages || is_blk_bmap_dirty)
			return false;
	}

	return true;
}

/*
 * should_gc_work() - check that GC should fulfill some activity
 * @fsi: pointer on shared file system object
 * @type: thread type
 */
static inline
bool should_gc_work(struct ssdfs_fs_info *fsi, int type)
{
	return atomic_read(&fsi->gc_should_act[type]) > 0;
}

#define GLOBAL_GC_THREAD_WAKE_CONDITION(fsi, type) \
	(kthread_should_stop() || should_gc_work(fsi, type))
#define GLOBAL_GC_FAILED_THREAD_WAKE_CONDITION() \
	(kthread_should_stop())

/*
 * is_time_collect_garbage() - check that it's good time for GC activity
 * @fsi: pointer on shared file system object
 * @io_stats: I/O load estimation [in|out]
 *
 * This method tries to estimate the I/O load with
 * the goal to define the good time for GC activity.
 */
int is_time_collect_garbage(struct ssdfs_fs_info *fsi,
			    struct ssdfs_io_load_stats *io_stats)
{
	int state;
	s64 reqs_count;
	s64 average_diff;
	s64 cur_diff;
	u64 distance;
	u32 i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !io_stats);

	SSDFS_DBG("fsi %p, io_stats %p, measurements %u\n",
		  fsi, io_stats, io_stats->measurements);
#endif /* CONFIG_SSDFS_DEBUG */

	if (io_stats->measurements > SSDFS_MEASUREMENTS_MAX) {
		SSDFS_ERR("invalid count: "
			  "measurements %u\n",
			  io_stats->measurements);
		return SSDFS_UNDEFINED_GC_STATE;
	}

	reqs_count = atomic64_read(&fsi->flush_reqs);

	if (reqs_count < 0) {
		SSDFS_WARN("unexpected reqs_count %lld\n",
			   reqs_count);
	}

	if (io_stats->measurements < SSDFS_MEASUREMENTS_MAX) {
		io_stats->reqs_count[io_stats->measurements] = reqs_count;
		io_stats->measurements++;
	}

	state = atomic_read(&fsi->global_fs_state);
	switch (state) {
	case SSDFS_METADATA_GOING_FLUSHING:
	case SSDFS_METADATA_UNDER_FLUSH:
		/*
		 * Thread that is trying to flush metadata
		 * waits the end of user data flush requests.
		 * So, GC should not add any requests,
		 * otherwise, the metadata flush could
		 * never happened.
		 */
		SSDFS_DBG("don't add request before metadata flush\n");
		return SSDFS_WAIT_IDLE_STATE;

	default:
		/* continue logic */
		break;
	}

	if (reqs_count <= SSDFS_GC_LOW_BOUND_THRESHOLD) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("reqs_count %lld\n", reqs_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return SSDFS_COLLECT_GARBAGE_NOW;
	}

	if (reqs_count >= SSDFS_GC_UPPER_BOUND_THRESHOLD) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("reqs_count %lld\n", reqs_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return SSDFS_STOP_GC_ACTIVITY_NOW;
	}

	if (io_stats->measurements < 3) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("measurement %u, reqs_count %lld\n",
			  io_stats->measurements,
			  reqs_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return SSDFS_WAIT_IDLE_STATE;
	}

	average_diff = 0;

	for (i = 1; i < io_stats->measurements; i++) {
		cur_diff = io_stats->reqs_count[i] -
				io_stats->reqs_count[i - 1];
		average_diff += cur_diff;
	}

	if (average_diff < 0) {
		/*
		 * I/O load is decreasing.
		 */
		cur_diff = io_stats->reqs_count[io_stats->measurements - 1];
		distance = div_u64((u64)cur_diff, abs(average_diff));

		if (distance < SSDFS_GC_DISTANCE_THRESHOLD) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("I/O load is decreasing: "
				  "average_diff %lld : "
				  "Start GC activity.\n",
				  average_diff);
#endif /* CONFIG_SSDFS_DEBUG */
			return SSDFS_COLLECT_GARBAGE_NOW;
		}
	} else {
		/*
		 * I/O load is increasing.
		 */
		if (io_stats->measurements >= SSDFS_MEASUREMENTS_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("I/O load is increasing: "
				  "average_diff %lld : "
				  "Stop GC activity.\n",
				  average_diff);
#endif /* CONFIG_SSDFS_DEBUG */
			return SSDFS_STOP_GC_ACTIVITY_NOW;
		}
	}

	return SSDFS_WAIT_IDLE_STATE;
}

#define SSDFS_SEG2REQ_PAIR_CAPACITY	(10)

/*
 * struct ssdfs_seg2req_pair_array - segment/request pairs array
 * @items_count: items count in the array
 * @pairs: pairs array
 */
struct ssdfs_seg2req_pair_array {
	u32 items_count;
	struct ssdfs_seg2req_pair pairs[SSDFS_SEG2REQ_PAIR_CAPACITY];
};

/*
 * is_seg2req_pair_array_exhausted() - is seg2req pairs array exhausted?
 * @array: pairs array
 */
static inline
bool is_seg2req_pair_array_exhausted(struct ssdfs_seg2req_pair_array *array)
{
	bool is_exhausted;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	is_exhausted = array->items_count >= SSDFS_SEG2REQ_PAIR_CAPACITY;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("is_exhausted %#x\n", is_exhausted);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_exhausted;
}

/*
 * ssdfs_gc_check_request() - check request
 * @req: segment request
 *
 * This method tries to check the state of request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_gc_check_request(struct ssdfs_segment_request *req)
{
	wait_queue_head_t *wq = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);

	SSDFS_DBG("req %p\n", req);
#endif /* CONFIG_SSDFS_DEBUG */

check_req_state:
	switch (atomic_read(&req->result.state)) {
	case SSDFS_REQ_CREATED:
	case SSDFS_REQ_STARTED:
		wq = &req->private.wait_queue;

		err = wait_event_killable_timeout(*wq,
					has_request_been_executed(req),
					SSDFS_DEFAULT_TIMEOUT);
		if (err < 0)
			WARN_ON(err < 0);
		else
			err = 0;

		goto check_req_state;
		break;

	case SSDFS_REQ_FINISHED:
		/* do nothing */
		break;

	case SSDFS_REQ_FAILED:
		err = req->result.err;

		if (!err) {
			SSDFS_ERR("error code is absent: "
				  "req %p, err %d\n",
				  req, err);
			err = -ERANGE;
		}

		SSDFS_ERR("flush request is failed: "
			  "err %d\n", err);
		return err;

	default:
		SSDFS_ERR("invalid result's state %#x\n",
		    atomic_read(&req->result.state));
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_gc_wait_commit_logs_end() - wait commit logs ending
 * @fsi: pointer on shared file system object
 * @array: seg2req pairs array
 *
 * This method is waiting the end of commit logs operation.
 */
static
void ssdfs_gc_wait_commit_logs_end(struct ssdfs_fs_info *fsi,
				   struct ssdfs_seg2req_pair_array *array)
{
	u32 items_count;
	int refs_count;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!array);

	SSDFS_DBG("items_count %u\n", array->items_count);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = min_t(u32, array->items_count,
			    SSDFS_SEG2REQ_PAIR_CAPACITY);

	for (i = 0; i < items_count; i++) {
		struct ssdfs_seg2req_pair *pair;

		pair = &array->pairs[i];

		if (pair->req != NULL) {
			err = ssdfs_gc_check_request(pair->req);
			if (unlikely(err)) {
				SSDFS_ERR("flush request failed: "
					  "err %d\n", err);
			}

			refs_count =
				atomic_read(&pair->req->private.refs_count);
			if (refs_count != 0) {
				SSDFS_WARN("unexpected refs_count %d\n",
					   refs_count);
			}

			ssdfs_request_free(pair->req);
		} else {
			SSDFS_ERR("request is NULL: "
				  "item_index %d\n", i);
		}

		if (pair->si != NULL) {
			struct ssdfs_segment_info *si = pair->si;

			ssdfs_segment_put_object(si);

			if (should_ssdfs_segment_be_destroyed(si)) {
				err = ssdfs_segment_tree_remove(fsi, si);
				if (unlikely(err)) {
					SSDFS_WARN("fail to remove segment: "
						   "seg %llu, err %d\n",
						   si->seg_id, err);
				} else {
					err = ssdfs_segment_destroy_object(si);
					if (err) {
						SSDFS_WARN("fail to destroy: "
							   "seg %llu, err %d\n",
							   si->seg_id, err);
					}
				}
			}
		} else {
			SSDFS_ERR("segment is NULL: "
				  "item_index %d\n", i);
		}
	}

	memset(array, 0, sizeof(struct ssdfs_seg2req_pair_array));
}

/*
 * ssdfs_gc_stimulate_migration() - stimulate migration
 * @si: pointer on segment object
 * @pebc: pointer on PEB container object
 * @array: seg2req pairs array
 *
 * This method tries to stimulate the PEB's migration.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_gc_stimulate_migration(struct ssdfs_segment_info *si,
				 struct ssdfs_peb_container *pebc,
				 struct ssdfs_seg2req_pair_array *array)
{
	struct ssdfs_peb_info *pebi;
	struct ssdfs_seg2req_pair *pair;
	u32 index;
	int count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !pebc || !array);

	SSDFS_DBG("seg %llu, peb_index %u\n",
		  si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (have_flush_requests(pebc)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("Do nothing: request queue is not empty: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	if (is_seg2req_pair_array_exhausted(array)) {
		SSDFS_ERR("seg2req pair array is exhausted\n");
		return -ERANGE;
	}

	index = array->items_count;
	pair = &array->pairs[index];

	if (pair->req || pair->si) {
		SSDFS_ERR("invalid pair state: index %u\n",
			  index);
		return -ERANGE;
	}

	if (!is_peb_under_migration(pebc)) {
		SSDFS_ERR("invalid PEB state: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, pebc->peb_index);
		return -ERANGE;
	}

	pebi = ssdfs_get_current_peb_locked(pebc);
	if (IS_ERR_OR_NULL(pebi)) {
		err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
		SSDFS_ERR("fail to get PEB object: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

	/*
	 * The ssdfs_get_current_peb_locked() defines
	 * migration phase. It should be set properly
	 * before the ssdfs_peb_prepare_range_migration()
	 * call.
	 */

	ssdfs_unlock_current_peb(pebc);

	mutex_lock(&pebc->migration_lock);

	for (count = 0; count < 2; count++) {
		int err1, err2;

		err1 = ssdfs_peb_prepare_range_migration(pebc, 1,
						SSDFS_BLK_PRE_ALLOCATED);
		if (err1 && err1 != -ENODATA) {
			err = err1;
			break;
		}

		err2 = ssdfs_peb_prepare_range_migration(pebc, 1,
						SSDFS_BLK_VALID);
		if (err2 && err2 != -ENODATA) {
			err = err2;
			break;
		}

		if (err1 == -ENODATA && err2 == -ENODATA) {
			err = 0;
			break;
		}
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare range migration: "
			  "err %d\n", err);
	} else if (count == 0) {
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no data for migration: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	mutex_unlock(&pebc->migration_lock);

	if (unlikely(err))
		return err;

	pair->req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(pair->req)) {
		err = (pair->req == NULL ? -ENOMEM : PTR_ERR(pair->req));
		SSDFS_ERR("fail to allocate request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(pair->req);
	ssdfs_get_request(pair->req);

	err = ssdfs_segment_commit_log_async2(si, SSDFS_REQ_ASYNC_NO_FREE,
					      pebc->peb_index, pair->req);
	if (unlikely(err)) {
		SSDFS_ERR("commit log request failed: "
			  "err %d\n", err);
		ssdfs_put_request(pair->req);
		ssdfs_request_free(pair->req);
		pair->req = NULL;
		return err;
	}

	pair->si = si;
	array->items_count++;

	return 0;
}

/*
 * ssdfs_gc_finish_migration() - finish migration
 * @si: pointer on segment object
 * @pebc: pointer on PEB container object
 * @array: seg2req pairs array
 *
 * This method tries to finish the PEB's migration.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_gc_finish_migration(struct ssdfs_segment_info *si,
			      struct ssdfs_peb_container *pebc,
			      struct ssdfs_seg2req_pair_array *array)
{
	struct ssdfs_seg2req_pair *pair;
	struct ssdfs_peb_info *pebi;
	u32 index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si || !pebc || !array);

	SSDFS_DBG("seg %llu, peb_index %u\n",
		  si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (have_flush_requests(pebc)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("Do nothing: request queue is not empty: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	if (is_seg2req_pair_array_exhausted(array)) {
		SSDFS_ERR("seg2req pair array is exhausted\n");
		return -ERANGE;
	}

	index = array->items_count;
	pair = &array->pairs[index];

	if (pair->req || pair->si) {
		SSDFS_ERR("invalid pair state: index %u\n",
			  index);
		return -ERANGE;
	}

	if (!is_peb_under_migration(pebc)) {
		SSDFS_ERR("invalid PEB state: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, pebc->peb_index);
		return -ERANGE;
	}

	err = ssdfs_peb_finish_migration(pebc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to finish migration: "
			  "seg %llu, peb_index %u, "
			  "err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

	pebi = ssdfs_get_current_peb_locked(pebc);
	if (IS_ERR_OR_NULL(pebi)) {
		err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
		SSDFS_ERR("fail to get PEB object: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

	if (is_ssdfs_maptbl_going_to_be_destroyed(si->fsi->maptbl)) {
		SSDFS_WARN("seg %llu, peb_index %u\n",
			   si->seg_id, pebc->peb_index);
	}

	err = ssdfs_peb_container_change_state(pebc);
	if (unlikely(err)) {
		ssdfs_unlock_current_peb(pebc);
		SSDFS_ERR("fail to change peb state: "
			  "err %d\n", err);
		return err;
	}

	ssdfs_unlock_current_peb(pebc);

	pair->req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(pair->req)) {
		err = (pair->req == NULL ? -ENOMEM : PTR_ERR(pair->req));
		SSDFS_ERR("fail to allocate request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(pair->req);
	ssdfs_get_request(pair->req);

	err = ssdfs_segment_commit_log_async2(si, SSDFS_REQ_ASYNC_NO_FREE,
					      pebc->peb_index, pair->req);
	if (unlikely(err)) {
		SSDFS_ERR("commit log request failed: "
			  "err %d\n", err);
		ssdfs_put_request(pair->req);
		ssdfs_request_free(pair->req);
		pair->req = NULL;
		return err;
	}

	pair->si = si;
	array->items_count++;

	return 0;
}

static inline
int ssdfs_mark_segment_under_gc_activity(struct ssdfs_segment_info *si)
{
	int activity_type;

	activity_type = atomic_cmpxchg(&si->activity_type,
				SSDFS_SEG_OBJECT_REGULAR_ACTIVITY,
				SSDFS_SEG_UNDER_GC_ACTIVITY);
	if (activity_type < SSDFS_SEG_OBJECT_REGULAR_ACTIVITY ||
	    activity_type >= SSDFS_SEG_UNDER_GC_ACTIVITY) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu is busy under activity %#x\n",
			   si->seg_id, activity_type);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EBUSY;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segment %llu is under GC activity\n",
		  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

static inline
int ssdfs_revert_segment_to_regular_activity(struct ssdfs_segment_info *si)
{
	int activity_type;

	activity_type = atomic_cmpxchg(&si->activity_type,
				SSDFS_SEG_UNDER_GC_ACTIVITY,
				SSDFS_SEG_OBJECT_REGULAR_ACTIVITY);
	if (activity_type != SSDFS_SEG_UNDER_GC_ACTIVITY) {
		SSDFS_WARN("segment %llu is under activity %#x\n",
			   si->seg_id, activity_type);
		return -EFAULT;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segment %llu has been reverted from GC activity\n",
		  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_generic_seg_gc_thread_func() - generic function of GC thread
 * @fsi: pointer on shared file system object
 * @thread_type: thread type
 * @seg_state: type of segment
 * @seg_state_mask: segment types' mask
 *
 * This function is the key logic of GC thread.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_generic_seg_gc_thread_func(struct ssdfs_fs_info *fsi,
				     int thread_type,
				     int seg_state, int seg_state_mask)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_maptbl_peb_relation pebr;
	struct ssdfs_maptbl_peb_descriptor *pebd;
	struct ssdfs_io_load_stats io_stats;
	size_t io_stats_size = sizeof(struct ssdfs_io_load_stats);
	wait_queue_head_t *wq;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_seg2req_pair_array reqs_array;
	u8 peb_type = SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;
	int seg_type = SSDFS_UNKNOWN_SEG_TYPE;
	u64 seg_id = 0;
	u64 max_seg_id;
	u64 seg_id_step = SSDFS_GC_DEFAULT_SEARCH_STEP;
	u64 nsegs;
	u64 cur_leb_id;
	u32 lebs_per_segment;
	int gc_strategy;
	int used_pages;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("GC thread: thread_type %#x, "
		  "seg_state %#x, seg_state_mask %#x\n",
		  thread_type, seg_state, seg_state_mask);
#endif /* CONFIG_SSDFS_DEBUG */

	wq = &fsi->gc_wait_queue[thread_type];
	lebs_per_segment = fsi->pebs_per_seg;
	memset(&reqs_array, 0, sizeof(struct ssdfs_seg2req_pair_array));

repeat:
	if (kthread_should_stop()) {
		complete_all(&fsi->gc_thread[thread_type].full_stop);
		return err;
	} else if (unlikely(err))
		goto sleep_failed_gc_thread;

	mutex_lock(&fsi->resize_mutex);
	nsegs = fsi->nsegs;
	mutex_unlock(&fsi->resize_mutex);

	if (seg_id >= nsegs)
		seg_id = 0;

	while (seg_id < nsegs) {
		peb_type = SSDFS_MAPTBL_UNKNOWN_PEB_TYPE;
		seg_type = SSDFS_UNKNOWN_SEG_TYPE;

		max_seg_id = seg_id + seg_id_step;
		max_seg_id = min_t(u64, max_seg_id, nsegs);

		err = ssdfs_gc_find_next_seg_id(fsi, seg_id, max_seg_id,
						seg_state, seg_state_mask,
						&seg_id);
		if (err == -ENODATA) {
			err = 0;

			if (max_seg_id >= nsegs) {
				seg_id = 0;
				SSDFS_DBG("GC hasn't found any victim\n");
				goto finish_seg_processing;
			}

			seg_id = max_seg_id;

			wait_event_interruptible_timeout(*wq,
					kthread_should_stop(), HZ);

			if (kthread_should_stop())
				goto finish_seg_processing;
			else
				continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find segment: "
				  "seg_id %llu, nsegs %llu, err %d\n",
				  seg_id, nsegs, err);
			goto sleep_failed_gc_thread;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found segment: "
			  "seg_id %llu, seg_state %#x\n",
			  seg_id, seg_state);
#endif /* CONFIG_SSDFS_DEBUG */

		if (kthread_should_stop())
			goto finish_seg_processing;

		i = 0;

		for (; i < lebs_per_segment; i++) {
			cur_leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
								    seg_id,
								    i);
			if (cur_leb_id >= U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unexpected leb_id: "
					  "seg_id %llu, peb_index %u\n",
					  seg_id, i);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			if (kthread_should_stop())
				goto finish_seg_processing;

			err = ssdfs_gc_convert_leb2peb(fsi, cur_leb_id, &pebr);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB is not mapped: leb_id %llu\n",
					  cur_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, peb_type %#x, err %d\n",
					  cur_leb_id, peb_type, err);
				goto sleep_failed_gc_thread;
			}

			pebd = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];

			switch (pebd->state) {
			case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
				/* PEB is under migration */
				break;

			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("SRC PEB %llu is dirty\n",
					  pebd->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;

			default:
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB %llu is not migrating\n",
					  cur_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			pebd = &pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX];

			switch (pebd->state) {
			case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
				/* stimulate migration */
				break;

			default:
				continue;
			}

			if (kthread_should_stop())
				goto finish_seg_processing;

			peb_type = pebd->type;
			seg_type = PEB2SEG_TYPE(peb_type);

			goto try_to_find_seg_object;
		}

		if (i >= lebs_per_segment) {
			/* segment hasn't valid blocks for migration */
			goto check_next_segment;
		}

try_to_find_seg_object:
		si = ssdfs_segment_tree_find(fsi, seg_id);
		if (IS_ERR_OR_NULL(si)) {
			err = PTR_ERR(si);

			if (err == -ENODATA) {
				/*
				 * It needs to create the segment.
				 */
				err = 0;
				goto try_create_seg_object;
			} else if (err == 0) {
				err = -ERANGE;
				SSDFS_ERR("seg tree returns NULL\n");
				goto finish_seg_processing;
			} else {
				SSDFS_ERR("fail to find segment: "
					  "seg %llu, err %d\n",
					  seg_id, err);
				goto sleep_failed_gc_thread;
			}
		} else if (should_ssdfs_segment_be_destroyed(si)) {
			/*
			 * Segment hasn't requests in the queues.
			 * But it is under migration.
			 * Try to collect the garbage.
			 */
			ssdfs_segment_get_object(si);
			goto try_collect_garbage;
		} else
			goto check_next_segment;

try_create_seg_object:
		si = ssdfs_grab_segment(fsi, seg_type, seg_id, U64_MAX);
		if (unlikely(IS_ERR_OR_NULL(si))) {
			err = PTR_ERR(si);
			SSDFS_ERR("fail to grab segment object: "
				  "seg %llu, err %d\n",
				  seg_id, err);
			goto sleep_failed_gc_thread;
		}

try_collect_garbage:
		for (; i < lebs_per_segment; i++) {
			cur_leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
								    seg_id,
								    i);
			if (cur_leb_id >= U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unexpected leb_id: "
					  "seg_id %llu, peb_index %u\n",
					  seg_id, i);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			if (kthread_should_stop()) {
				ssdfs_segment_put_object(si);
				goto finish_seg_processing;
			}

			err = ssdfs_gc_convert_leb2peb(fsi, cur_leb_id, &pebr);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB is not mapped: leb_id %llu\n",
					  cur_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, peb_type %#x, err %d\n",
					  cur_leb_id, peb_type, err);
				ssdfs_segment_put_object(si);
				goto sleep_failed_gc_thread;
			}

			pebd = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];

			switch (pebd->state) {
			case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
			case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
				/* PEB is under migration */
				break;

			default:
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB %llu is not migrating\n",
					  cur_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			pebd = &pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX];

			switch (pebd->state) {
			case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
			case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
				/* stimulate migration */
				break;

			default:
				continue;
			}

			memset(&io_stats, 0, io_stats_size);
			gc_strategy = SSDFS_UNDEFINED_GC_STATE;

			do {
				gc_strategy = is_time_collect_garbage(fsi,
								    &io_stats);

				switch (gc_strategy) {
				case SSDFS_COLLECT_GARBAGE_NOW:
					goto collect_garbage_now;

				case SSDFS_STOP_GC_ACTIVITY_NOW:
					ssdfs_segment_put_object(si);
					goto finish_seg_processing;

				case SSDFS_WAIT_IDLE_STATE:
					wait_event_interruptible_timeout(*wq,
							kthread_should_stop(),
							HZ);

					if (kthread_should_stop()) {
						ssdfs_segment_put_object(si);
						goto finish_seg_processing;
					}
					break;

				default:
					err = -ERANGE;
					SSDFS_ERR("unexpected strategy %#x\n",
						  gc_strategy);
					ssdfs_segment_put_object(si);
					goto finish_seg_processing;
				}
			} while (gc_strategy == SSDFS_WAIT_IDLE_STATE);

collect_garbage_now:
			if (kthread_should_stop()) {
				ssdfs_segment_put_object(si);
				goto finish_seg_processing;
			}

			pebc = &si->peb_array[i];

			seg_blkbmap = &si->blk_bmap;
			peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];

			if (is_seg2req_pair_array_exhausted(&reqs_array))
				ssdfs_gc_wait_commit_logs_end(fsi, &reqs_array);

			used_pages =
				ssdfs_src_blk_bmap_get_used_pages(peb_blkbmap);
			if (used_pages < 0) {
				err = used_pages;
				SSDFS_ERR("fail to get used pages: err %d\n",
					  err);
				ssdfs_segment_put_object(si);
				goto sleep_failed_gc_thread;
			}

			err = ssdfs_mark_segment_under_gc_activity(si);
			if (err) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("segment %llu is busy\n",
					  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
				goto check_next_segment;
			}

			if (used_pages == 0) {
				SSDFS_WARN("needs to finish migration: "
					   "seg %llu, leb_id %llu, "
					   "used_pages %d\n",
					   seg_id, cur_leb_id, used_pages);
			} else if (used_pages <= SSDFS_GC_FINISH_MIGRATION) {
				ssdfs_segment_get_object(si);

				err = ssdfs_gc_finish_migration(si, pebc,
								&reqs_array);
				if (unlikely(err)) {
					SSDFS_ERR("fail to finish migration: "
						  "seg %llu, leb_id %llu, "
						  "err %d\n",
						  seg_id, cur_leb_id, err);
					err = 0;
					ssdfs_segment_put_object(si);
				}
			} else {
				ssdfs_segment_get_object(si);

				err = ssdfs_gc_stimulate_migration(si, pebc,
								   &reqs_array);
				if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
					SSDFS_DBG("no data for migration: "
						  "seg %llu, leb_id %llu, "
						  "err %d\n",
						  seg_id, cur_leb_id, err);
#endif /* CONFIG_SSDFS_DEBUG */
					err = 0;
					ssdfs_segment_put_object(si);
				} else if (unlikely(err)) {
					SSDFS_ERR("fail to stimulate migration: "
						  "seg %llu, leb_id %llu, "
						  "err %d\n",
						  seg_id, cur_leb_id, err);
					err = 0;
					ssdfs_segment_put_object(si);
				}
			}
		}

		ssdfs_segment_put_object(si);

		if (is_seg2req_pair_array_exhausted(&reqs_array))
			ssdfs_gc_wait_commit_logs_end(fsi, &reqs_array);

		err = ssdfs_revert_segment_to_regular_activity(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment %llu is under unexpected activity\n",
				  si->seg_id);
			goto sleep_failed_gc_thread;
		}

		if (should_ssdfs_segment_be_destroyed(si)) {
			err = ssdfs_segment_tree_remove(fsi, si);
			if (unlikely(err)) {
				SSDFS_WARN("fail to remove segment: "
					   "seg %llu, err %d\n",
					   si->seg_id, err);
			} else {
				err = ssdfs_segment_destroy_object(si);
				if (err) {
					SSDFS_WARN("fail to destroy: "
						   "seg %llu, err %d\n",
						   si->seg_id, err);
				}
			}
		}

check_next_segment:
		seg_id++;

		atomic_dec(&fsi->gc_should_act[thread_type]);

		if (kthread_should_stop())
			goto finish_seg_processing;

		if (atomic_read(&fsi->gc_should_act[thread_type]) > 0) {
			wait_event_interruptible_timeout(*wq,
						kthread_should_stop(),
						HZ);
		} else
			goto finish_seg_processing;

		if (kthread_should_stop())
			goto finish_seg_processing;
	}

finish_seg_processing:
	atomic_set(&fsi->gc_should_act[thread_type], 0);

	ssdfs_gc_wait_commit_logs_end(fsi, &reqs_array);

	wait_event_interruptible(*wq,
		GLOBAL_GC_THREAD_WAKE_CONDITION(fsi, thread_type));
	goto repeat;

sleep_failed_gc_thread:
	atomic_set(&fsi->gc_should_act[thread_type], 0);

	ssdfs_gc_wait_commit_logs_end(fsi, &reqs_array);

	wait_event_interruptible(*wq,
		GLOBAL_GC_FAILED_THREAD_WAKE_CONDITION());
	goto repeat;
}

/*
 * should_continue_processing() - should continue processing?
 */
static inline
bool should_continue_processing(int mandatory_ops)
{
	if (kthread_should_stop()) {
		if (mandatory_ops > 0)
			return true;
		else
			return false;
	} else
		return true;
}

/*
 * __ssdfs_dirty_seg_gc_thread_func() - GC thread's function for dirty segments
 * @fsi: pointer on shared file system object
 * @thread_type: thread type
 * @seg_state: type of segment
 * @seg_state_mask: segment types' mask
 *
 * This function is the logic of GC thread for dirty segments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_dirty_seg_gc_thread_func(struct ssdfs_fs_info *fsi,
				     int thread_type,
				     int seg_state, int seg_state_mask)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_maptbl_peb_relation pebr;
	struct ssdfs_maptbl_peb_descriptor *pebd;
	struct ssdfs_segment_bmap *segbmap;
	struct completion *end = NULL;
	wait_queue_head_t *wq;
	u64 seg_id = 0;
	u64 max_seg_id;
	u64 nsegs;
	u64 cur_leb_id;
	u32 lebs_per_segment;
	int mandatory_ops = SSDFS_GC_DIRTY_SEG_DEFAULT_OPS;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("GC thread: thread_type %#x, "
		  "seg_state %#x, seg_state_mask %#x\n",
		  thread_type, seg_state, seg_state_mask);
#endif /* CONFIG_SSDFS_DEBUG */

	segbmap = fsi->segbmap;
	wq = &fsi->gc_wait_queue[thread_type];
	lebs_per_segment = fsi->pebs_per_seg;

repeat:
	if (kthread_should_stop()) {
		complete_all(&fsi->gc_thread[thread_type].full_stop);
		return err;
	} else if (unlikely(err))
		goto sleep_failed_gc_thread;

	mutex_lock(&fsi->resize_mutex);
	nsegs = fsi->nsegs;
	mutex_unlock(&fsi->resize_mutex);

	if (seg_id >= nsegs)
		seg_id = 0;

	while (seg_id < nsegs) {
		max_seg_id = nsegs;

		err = ssdfs_gc_find_next_seg_id(fsi, seg_id, max_seg_id,
						seg_state, seg_state_mask,
						&seg_id);
		if (err == -ENODATA) {
			err = 0;
			seg_id = 0;
			SSDFS_DBG("GC hasn't found any victim\n");
			goto finish_seg_processing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find segment: "
				  "seg_id %llu, nsegs %llu, err %d\n",
				  seg_id, nsegs, err);
			goto sleep_failed_gc_thread;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found segment: "
			  "seg_id %llu, seg_state %#x\n",
			  seg_id, seg_state);
#endif /* CONFIG_SSDFS_DEBUG */

		if (!should_continue_processing(mandatory_ops))
			goto finish_seg_processing;

		i = 0;

		for (; i < lebs_per_segment; i++) {
			cur_leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
								    seg_id,
								    i);
			if (cur_leb_id >= U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unexpected leb_id: "
					  "seg_id %llu, peb_index %u\n",
					  seg_id, i);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			err = ssdfs_gc_convert_leb2peb(fsi, cur_leb_id, &pebr);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB doesn't mapped: leb_id %llu\n",
					  cur_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, err %d\n",
					  cur_leb_id, err);
				goto sleep_failed_gc_thread;
			}

			pebd = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];

			switch (pebd->state) {
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				/* PEB is dirty */
				break;

			default:
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB %llu is not dirty: "
					  "pebd->state %u\n",
					  cur_leb_id, pebd->state);
#endif /* CONFIG_SSDFS_DEBUG */
				goto check_next_segment;
			}

			if (!should_continue_processing(mandatory_ops))
				goto finish_seg_processing;

			goto try_to_find_seg_object;
		}

try_to_find_seg_object:
		si = ssdfs_segment_tree_find(fsi, seg_id);
		if (IS_ERR_OR_NULL(si)) {
			err = PTR_ERR(si);

			if (err == -ENODATA) {
				err = 0;
				goto try_set_pre_erase_state;
			} else if (err == 0) {
				err = -ERANGE;
				SSDFS_ERR("seg tree returns NULL\n");
				goto finish_seg_processing;
			} else {
				SSDFS_ERR("fail to find segment: "
					  "seg %llu, err %d\n",
					  seg_id, err);
				goto sleep_failed_gc_thread;
			}
		} else if (should_ssdfs_segment_be_destroyed(si)) {
			err = ssdfs_segment_tree_remove(fsi, si);
			if (unlikely(err)) {
				SSDFS_WARN("fail to remove segment: "
					   "seg %llu, err %d\n",
					   si->seg_id, err);
			} else {
				err = ssdfs_segment_destroy_object(si);
				if (err) {
					SSDFS_WARN("fail to destroy: "
						   "seg %llu, err %d\n",
						   si->seg_id, err);
				}
			}
		} else
			goto check_next_segment;

try_set_pre_erase_state:
		for (; i < lebs_per_segment; i++) {
			cur_leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
								    seg_id,
								    i);
			if (cur_leb_id >= U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unexpected leb_id: "
					  "seg_id %llu, peb_index %u\n",
					  seg_id, i);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			err = ssdfs_gc_convert_leb2peb(fsi, cur_leb_id, &pebr);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB doesn't mapped: leb_id %llu\n",
					  cur_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, err %d\n",
					  cur_leb_id, err);
				goto sleep_failed_gc_thread;
			}

			pebd = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];

			switch (pebd->state) {
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				/* PEB is dirty */
				break;

			default:
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB %llu is not dirty: "
					  "pebd->state %u\n",
					  cur_leb_id, pebd->state);
#endif /* CONFIG_SSDFS_DEBUG */
				goto check_next_segment;
			}

			err = ssdfs_maptbl_prepare_pre_erase_state(fsi,
								   cur_leb_id,
								   pebd->type,
								   &end);
			if (err == -EAGAIN) {
				err = SSDFS_WAIT_COMPLETION(end);
				if (unlikely(err)) {
					SSDFS_ERR("maptbl init failed: "
						  "err %d\n", err);
					goto sleep_failed_gc_thread;
				}

				err = ssdfs_maptbl_prepare_pre_erase_state(fsi,
								    cur_leb_id,
								    pebd->type,
								    &end);
			}

			if (err == -EBUSY) {
				err = 0;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to prepare pre-erase state: "
					  "leb_id %llu\n",
					  cur_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_seg_processing;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to prepare pre-erase state: "
					  "leb_id %llu, err %d\n",
					  cur_leb_id, err);
				goto sleep_failed_gc_thread;
			}
		}

		err = ssdfs_segbmap_change_state(segbmap, seg_id,
						 SSDFS_SEG_CLEAN, &end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("segbmap init failed: "
					  "err %d\n", err);
				goto sleep_failed_gc_thread;
			}

			err = ssdfs_segbmap_change_state(segbmap, seg_id,
							 SSDFS_SEG_CLEAN, &end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to change segment state: "
				  "seg %llu, state %#x, err %d\n",
				  seg_id, SSDFS_SEG_CLEAN, err);
			goto sleep_failed_gc_thread;
		}

check_next_segment:
		mandatory_ops--;
		seg_id++;

		if (!should_continue_processing(mandatory_ops))
			goto finish_seg_processing;
	}

finish_seg_processing:
	atomic_set(&fsi->gc_should_act[thread_type], 0);

	wait_event_interruptible(*wq,
		GLOBAL_GC_THREAD_WAKE_CONDITION(fsi, thread_type));
	goto repeat;

sleep_failed_gc_thread:
	atomic_set(&fsi->gc_should_act[thread_type], 0);

	wait_event_interruptible(*wq,
		GLOBAL_GC_FAILED_THREAD_WAKE_CONDITION());
	goto repeat;
}

/*
 * ssdfs_collect_dirty_segments_now() - collect dirty segments now
 * @fsi: pointer on shared file system object
 *
 * This function tries to collect the dirty segments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_collect_dirty_segments_now(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_maptbl_peb_relation pebr;
	struct ssdfs_maptbl_peb_descriptor *pebd;
	struct ssdfs_segment_bmap *segbmap;
	struct completion *end = NULL;
	int seg_state = SSDFS_SEG_DIRTY;
	int seg_state_mask = SSDFS_SEG_DIRTY_STATE_FLAG;
	u64 seg_id = 0;
	u64 max_seg_id;
	u64 nsegs;
	u64 cur_leb_id;
	u32 lebs_per_segment;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif  /* CONFIG_SSDFS_DEBUG */

	segbmap = fsi->segbmap;
	lebs_per_segment = fsi->pebs_per_seg;

	mutex_lock(&fsi->resize_mutex);
	nsegs = fsi->nsegs;
	mutex_unlock(&fsi->resize_mutex);

	while (seg_id < nsegs) {
		max_seg_id = nsegs;

		err = ssdfs_gc_find_next_seg_id(fsi, seg_id, max_seg_id,
						seg_state, seg_state_mask,
						&seg_id);
		if (err == -ENODATA) {
			SSDFS_DBG("GC hasn't found any victim\n");
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find segment: "
				  "seg_id %llu, nsegs %llu, err %d\n",
				  seg_id, nsegs, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found segment: "
			  "seg_id %llu, seg_state %#x\n",
			  seg_id, seg_state);
#endif /* CONFIG_SSDFS_DEBUG */

		i = 0;

		for (; i < lebs_per_segment; i++) {
			cur_leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
								    seg_id,
								    i);
			if (cur_leb_id >= U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unexpected leb_id: "
					  "seg_id %llu, peb_index %u\n",
					  seg_id, i);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			err = ssdfs_gc_convert_leb2peb(fsi, cur_leb_id, &pebr);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB is not mapped: leb_id %llu\n",
					  cur_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, err %d\n",
					  cur_leb_id, err);
				return err;
			}

			pebd = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];

			switch (pebd->state) {
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				/* PEB is dirty */
				break;

			default:
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB %llu is not dirty: "
					  "pebd->state %u\n",
					  cur_leb_id, pebd->state);
#endif /* CONFIG_SSDFS_DEBUG */
				goto check_next_segment;
			}

			goto try_to_find_seg_object;
		}

try_to_find_seg_object:
		si = ssdfs_segment_tree_find(fsi, seg_id);
		if (IS_ERR_OR_NULL(si)) {
			err = PTR_ERR(si);

			if (err == -ENODATA) {
				err = 0;
				goto try_set_pre_erase_state;
			} else if (err == 0) {
				err = -ERANGE;
				SSDFS_ERR("seg tree returns NULL\n");
				return err;
			} else {
				SSDFS_ERR("fail to find segment: "
					  "seg %llu, err %d\n",
					  seg_id, err);
				return err;
			}
		} else if (should_ssdfs_segment_be_destroyed(si)) {
			err = ssdfs_segment_tree_remove(fsi, si);
			if (unlikely(err)) {
				SSDFS_WARN("fail to remove segment: "
					   "seg %llu, err %d\n",
					   si->seg_id, err);
			} else {
				err = ssdfs_segment_destroy_object(si);
				if (err) {
					SSDFS_WARN("fail to destroy: "
						   "seg %llu, err %d\n",
						   si->seg_id, err);
				}
			}
		} else
			goto check_next_segment;

try_set_pre_erase_state:
		for (; i < lebs_per_segment; i++) {
			cur_leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
								    seg_id,
								    i);
			if (cur_leb_id >= U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unexpected leb_id: "
					  "seg_id %llu, peb_index %u\n",
					  seg_id, i);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			err = ssdfs_gc_convert_leb2peb(fsi, cur_leb_id, &pebr);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB is not mapped: leb_id %llu\n",
					  cur_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, err %d\n",
					  cur_leb_id, err);
				return err;
			}

			pebd = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];

			switch (pebd->state) {
			case SSDFS_MAPTBL_DIRTY_PEB_STATE:
				/* PEB is dirty */
				break;

			default:
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("LEB %llu is not dirty: "
					  "pebd->state %u\n",
					  cur_leb_id, pebd->state);
#endif /* CONFIG_SSDFS_DEBUG */
				goto check_next_segment;
			}

			err = ssdfs_maptbl_prepare_pre_erase_state(fsi,
								   cur_leb_id,
								   pebd->type,
								   &end);
			if (err == -EAGAIN) {
				err = SSDFS_WAIT_COMPLETION(end);
				if (unlikely(err)) {
					SSDFS_ERR("maptbl init failed: "
						  "err %d\n", err);
					return err;
				}

				err = ssdfs_maptbl_prepare_pre_erase_state(fsi,
								    cur_leb_id,
								    pebd->type,
								    &end);
			}

			if (err == -EBUSY) {
				err = 0;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to prepare pre-erase state: "
					  "leb_id %llu\n",
					  cur_leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				goto check_next_segment;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to prepare pre-erase state: "
					  "leb_id %llu, err %d\n",
					  cur_leb_id, err);
				return err;
			}
		}

		err = ssdfs_segbmap_change_state(segbmap, seg_id,
						 SSDFS_SEG_CLEAN, &end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("segbmap init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_segbmap_change_state(segbmap, seg_id,
							 SSDFS_SEG_CLEAN, &end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to change segment state: "
				  "seg %llu, state %#x, err %d\n",
				  seg_id, SSDFS_SEG_CLEAN, err);
			return err;
		}

check_next_segment:
		seg_id++;
	}

	return 0;
}

int ssdfs_using_seg_gc_thread_func(void *data)
{
	struct ssdfs_fs_info *fsi = data;

#ifdef CONFIG_SSDFS_DEBUG
	if (!fsi) {
		SSDFS_ERR("invalid shared FS object\n");
		return -EINVAL;
	}

	SSDFS_DBG("GC thread: using segments\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_generic_seg_gc_thread_func(fsi,
				SSDFS_SEG_USING_GC_THREAD,
				SSDFS_SEG_DATA_USING,
				SSDFS_SEG_DATA_USING_STATE_FLAG |
				SSDFS_SEG_LEAF_NODE_USING_STATE_FLAG |
				SSDFS_SEG_HYBRID_NODE_USING_STATE_FLAG |
				SSDFS_SEG_INDEX_NODE_USING_STATE_FLAG);
}

int ssdfs_used_seg_gc_thread_func(void *data)
{
	struct ssdfs_fs_info *fsi = data;

#ifdef CONFIG_SSDFS_DEBUG
	if (!fsi) {
		SSDFS_ERR("invalid shared FS object\n");
		return -EINVAL;
	}

	SSDFS_DBG("GC thread: used segments\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_generic_seg_gc_thread_func(fsi,
				SSDFS_SEG_USED_GC_THREAD,
				SSDFS_SEG_USED,
				SSDFS_SEG_USED_STATE_FLAG);
}

int ssdfs_pre_dirty_seg_gc_thread_func(void *data)
{
	struct ssdfs_fs_info *fsi = data;

#ifdef CONFIG_SSDFS_DEBUG
	if (!fsi) {
		SSDFS_ERR("invalid shared FS object\n");
		return -EINVAL;
	}

	SSDFS_DBG("GC thread: pre-dirty segments\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_generic_seg_gc_thread_func(fsi,
				SSDFS_SEG_PRE_DIRTY_GC_THREAD,
				SSDFS_SEG_PRE_DIRTY,
				SSDFS_SEG_PRE_DIRTY_STATE_FLAG);
}

int ssdfs_dirty_seg_gc_thread_func(void *data)
{
	struct ssdfs_fs_info *fsi = data;

#ifdef CONFIG_SSDFS_DEBUG
	if (!fsi) {
		SSDFS_ERR("invalid shared FS object\n");
		return -EINVAL;
	}

	SSDFS_DBG("GC thread: dirty segments\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_dirty_seg_gc_thread_func(fsi,
				SSDFS_SEG_DIRTY_GC_THREAD,
				SSDFS_SEG_DIRTY,
				SSDFS_SEG_DIRTY_STATE_FLAG);
}

/*
 * ssdfs_start_gc_thread() - start GC thread
 * @fsi: pointer on shared file system object
 * @type: thread type
 *
 * This function tries to start GC thread of @type.
 *
 * RETURN:
 * [success] - GC thread has been started.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_start_gc_thread(struct ssdfs_fs_info *fsi, int type)
{
	ssdfs_threadfn threadfn;
	const char *fmt;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	if (type >= SSDFS_GC_THREAD_TYPE_MAX) {
		SSDFS_ERR("invalid GC thread type %d\n", type);
		return -EINVAL;
	}

	SSDFS_DBG("thread_type %d\n", type);
#endif /* CONFIG_SSDFS_DEBUG */

	threadfn = thread_desc[type].threadfn;
	fmt = thread_desc[type].fmt;

	fsi->gc_thread[type].task = kthread_create(threadfn, fsi, fmt);
	if (IS_ERR_OR_NULL(fsi->gc_thread[type].task)) {
		err = PTR_ERR(fsi->gc_thread[type].task);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			if (err == 0)
				err = -ERANGE;
		SSDFS_ERR("fail to start GC thread: "
			  "thread_type %d, err %d\n",
			  type, err);
		}

		return err;
	}

	init_waitqueue_entry(&fsi->gc_thread[type].wait,
				fsi->gc_thread[type].task);
	add_wait_queue(&fsi->gc_wait_queue[type],
			&fsi->gc_thread[type].wait);
	init_completion(&fsi->gc_thread[type].full_stop);

	wake_up_process(fsi->gc_thread[type].task);

	return 0;
}

/*
 * ssdfs_stop_gc_thread() - stop GC thread
 * @fsi: pointer on shared file system object
 * @type: thread type
 *
 * This function tries to stop GC thread of @type.
 *
 * RETURN:
 * [success] - GC thread has been stopped.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_stop_gc_thread(struct ssdfs_fs_info *fsi, int type)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	if (type >= SSDFS_GC_THREAD_TYPE_MAX) {
		SSDFS_ERR("invalid GC thread type %d\n", type);
		return -EINVAL;
	}

	SSDFS_DBG("type %#x, task %p\n",
		  type, fsi->gc_thread[type].task);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!fsi->gc_thread[type].task)
		return 0;

	err = kthread_stop(fsi->gc_thread[type].task);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 * The wake_up_process() was never called.
		 */
		return 0;
	} else if (unlikely(err)) {
		SSDFS_WARN("thread function had some issue: err %d\n",
			    err);
		return err;
	}

	finish_wait(&fsi->gc_wait_queue[type],
			&fsi->gc_thread[type].wait);

	fsi->gc_thread[type].task = NULL;

	err = SSDFS_WAIT_COMPLETION(&fsi->gc_thread[type].full_stop);
	if (unlikely(err)) {
		SSDFS_ERR("stop thread fails: err %d\n", err);
		return err;
	}

	return 0;
}
