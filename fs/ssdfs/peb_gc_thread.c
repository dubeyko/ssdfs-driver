//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_gc_thread.c - GC thread functionality.
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
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "offset_translation_table.h"
#include "compression.h"
#include "block_bitmap.h"
#include "page_array.h"
#include "peb.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"

#include <trace/events/ssdfs.h>

/******************************************************************************
 *                           GC THREAD FUNCTIONALITY                          *
 ******************************************************************************/

/*
 * __ssdfs_peb_copy_page() - copy page from PEB into buffer
 * @pebc: pointer on PEB container
 * @desc_off: physical offset descriptor
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
			  struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk_state_offset *blk_state = NULL;
	struct ssdfs_peb_info *pebi = NULL;
	u8 peb_migration_id;
	u16 log_start_page;
	struct ssdfs_metadata_descriptor desc_array[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_block_descriptor blk_desc = {0};
	int area_index;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	u32 area_offset;
	u32 blk_desc_off;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!desc_off || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type);

	fsi = pebc->parent_si->fsi;
	peb_migration_id = desc_off->blk_state.peb_migration_id;

	down_read(&pebc->lock);

	pebi = pebc->src_peb;

	if (!pebi) {
		err = -ERANGE;
		SSDFS_ERR("invalid peb_migration_id: "
			  "src_peb %p, dst_peb %p, peb_migration_id %u\n",
			  pebc->src_peb, pebc->dst_peb,
			  peb_migration_id);
		goto finish_copy_page;
	}

	if (peb_migration_id != ssdfs_get_peb_migration_id_checked(pebi)) {
		err = -ERANGE;
		SSDFS_ERR("migration_id1 %u != migration_id2 %u\n",
			  peb_migration_id,
			  ssdfs_get_peb_migration_id(pebi));
		goto finish_copy_page;
	}

	blk_state = &desc_off->blk_state;
	log_start_page = le16_to_cpu(blk_state->log_start_page);

	if (log_start_page >= fsi->pages_per_peb) {
		err = -ERANGE;
		SSDFS_ERR("invalid log start page %u\n", log_start_page);
		goto finish_copy_page;
	}

	err = ssdfs_peb_read_log_hdr_desc_array(pebi, log_start_page,
						desc_array,
						SSDFS_SEG_HDR_DESC_MAX);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read log's header desc array: "
			  "seg %llu, peb %llu, log_start_page %u, err %d\n",
			  pebc->parent_si->seg_id, pebi->peb_id,
			  log_start_page, err);
		goto finish_copy_page;
	}

	area_index = SSDFS_AREA_TYPE2INDEX(blk_state->log_area);

	if (area_index >= SSDFS_SEG_HDR_DESC_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid area index %#x\n", area_index);
		goto finish_copy_page;
	}

	area_offset = le32_to_cpu(desc_array[area_index].offset);
	blk_desc_off = le32_to_cpu(blk_state->byte_offset);

	err = ssdfs_unaligned_read_cache(pebi,
					 area_offset + blk_desc_off,
					 blk_desc_size,
					 &blk_desc);
	if (err) {
		err = ssdfs_unaligned_read_buffer(fsi, pebi->peb_id,
						  area_offset + blk_desc_off,
						  &blk_desc, blk_desc_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read buffer: "
				  "peb %llu, area_offset %u, byte_offset %u, "
				  "buf_size %zu, err %d\n",
				  pebi->peb_id, area_offset, blk_desc_off,
				  blk_desc_size, err);
			goto finish_copy_page;
		}
	}

	if (req->extent.ino >= U64_MAX) {
		req->extent.ino = le64_to_cpu(blk_desc.ino);
		req->extent.logical_offset =
			le32_to_cpu(blk_desc.logical_offset);
		req->extent.logical_offset *= fsi->pagesize;
	} else if (req->extent.ino != le64_to_cpu(blk_desc.ino)) {
		err = -EAGAIN;
		SSDFS_DBG("ino1 %llu != ino2 %llu\n",
			  req->extent.ino,
			  le64_to_cpu(blk_desc.ino));
		goto finish_copy_page;
	}

	req->extent.data_bytes += fsi->pagesize;

	err = ssdfs_request_add_allocated_page_locked(req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate memory page: "
			  "err %d\n", err);
		goto finish_copy_page;
	}

	err = ssdfs_peb_read_block_state(pebi, req,
					 desc_array,
					 SSDFS_SEG_HDR_DESC_MAX,
					 &blk_desc, 0);
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
 */
int ssdfs_peb_copy_pre_alloc_page(struct ssdfs_peb_container *pebc,
				  u32 logical_blk,
				  struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *desc_off = NULL;
	u16 peb_index;
	bool has_data = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "logical_blk %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  logical_blk);

	fsi = pebc->parent_si->fsi;

	if (logical_blk >= U32_MAX) {
		SSDFS_ERR("invalid logical_blk %u\n",
			  logical_blk);
		return -EINVAL;
	}

	table = pebc->parent_si->blk2off_table;

	desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index, NULL);
	if (IS_ERR(desc_off) && PTR_ERR(desc_off) == -EAGAIN) {
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

		desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
							&peb_index, NULL);
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
		err = __ssdfs_peb_copy_page(pebc, desc_off, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy page: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			return err;
		}

		err = ssdfs_blk2off_table_set_block_migration(table,
							    logical_blk,
							    peb_index,
							    &req->result.pvec);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set migration state: "
				  "logical_blk %u, peb_index %u, err %d\n",
				  logical_blk, peb_index, err);
			return err;
		}
	} else {
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
static
int ssdfs_peb_copy_page(struct ssdfs_peb_container *pebc,
			u32 logical_blk,
			struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *desc_off = NULL;
	u16 peb_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "logical_blk %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  logical_blk);

	fsi = pebc->parent_si->fsi;

	if (logical_blk >= U32_MAX) {
		SSDFS_ERR("invalid logical_blk %u\n",
			  logical_blk);
		return -EINVAL;
	}

	table = pebc->parent_si->blk2off_table;

	desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index, NULL);
	if (IS_ERR(desc_off) && PTR_ERR(desc_off) == -EAGAIN) {
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

		desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
							&peb_index, NULL);
	}

	if (IS_ERR_OR_NULL(desc_off)) {
		err = (desc_off == NULL ? -ERANGE : PTR_ERR(desc_off));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

	err = __ssdfs_peb_copy_page(pebc, desc_off, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy page: "
			  "logical_blk %u, peb_index %u, err %d\n",
			  logical_blk, peb_index, err);
		return err;
	}

	err = ssdfs_blk2off_table_set_block_migration(table,
						    logical_blk,
						    peb_index,
						    &req->result.pvec);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set migration state: "
			  "logical_blk %u, peb_index %u, err %d\n",
			  logical_blk, peb_index, err);
		return err;
	}

	return 0;
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "range->start %u, range->len %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  range->start, range->len);

	if (range->len == 0) {
		SSDFS_WARN("empty pages range request\n");
		return 0;
	}

	logical_blk = range->start;

	req->extent.ino = U64_MAX;
	req->extent.logical_offset = U64_MAX;
	req->extent.data_bytes = 0;

	req->place.start.seg_id = pebc->parent_si->seg_id;
	req->place.start.blk_index = logical_blk;
	req->place.len = 0;

	req->result.processed_blks = 0;

	for (i = 0; i < range->len; i++) {
		logical_blk += i;

		err = ssdfs_peb_copy_page(pebc, logical_blk, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy page: "
				  "seg %llu, logical_blk %u, err %d\n",
				  pebc->parent_si->seg_id,
				  logical_blk, err);
			return err;
		}

		req->place.len++;
	}

	return 0;
}

/* TODO: add condition of presence of items for processing  */
#define GC_THREAD_WAKE_CONDITION(pebi) \
	(kthread_should_stop())
	/*(kthread_should_stop() || kthread_should_park())*/

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("GC thread: seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	wait_queue = &pebc->parent_si->wait_queue[SSDFS_PEB_GC_THREAD];

repeat:
	if (kthread_should_stop()) {
		complete_all(&pebc->thread[SSDFS_PEB_GC_THREAD].full_stop);
		return 0;
	}

	/*
	 * TODO: It is possible to use the concept of "parking" in the future.
	 *       Currently, there is compilation issue with
	 *       kthread_should_park(), kthread_parkme() on linking stage
	 *       when SSDFS file system driver is compiled as Linux
	 *       kernel module:
	 *
	 *       ERROR: "kthread_should_park" [fs/ssdfs/ssdfs.ko] undefined!
	 *       ERROR: "kthread_parkme" [fs/ssdfs/ssdfs.ko] undefined!
	 */

	/*if (kthread_should_park())
		kthread_parkme();*/

	/* TODO: collect garbage */
	SSDFS_DBG("TODO: implement %s\n", __func__);
	goto sleep_gc_thread;
	/*return -ENOSYS;*/

sleep_gc_thread:
	wait_event_interruptible(*wait_queue, GC_THREAD_WAKE_CONDITION(pebi));
	goto repeat;
}
