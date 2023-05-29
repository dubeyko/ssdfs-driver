// SPDX-License-Identifier: BSD-3-Clause-Clear
 /*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_container.c - PEB container implementation.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * Copyright (c) 2022-2023 Bytedance Ltd. and/or its affiliates.
 *              https://www.bytedance.com/
 *
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot
 *                  Zvonimir Bandic
 *                  Cong Wang
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
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "current_segment.h"
#include "peb_mapping_table.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "invalidated_extents_tree.h"

enum {
	SSDFS_SRC_PEB,
	SSDFS_DST_PEB,
	SSDFS_SRC_AND_DST_PEB
};

static
struct ssdfs_thread_descriptor thread_desc[SSDFS_PEB_THREAD_TYPE_MAX] = {
	{.threadfn = ssdfs_peb_read_thread_func,
	 .fmt = "ssdfs-r%llu-%u",},
	{.threadfn = ssdfs_peb_flush_thread_func,
	 .fmt = "ssdfs-f%llu-%u",},
	{.threadfn = ssdfs_peb_gc_thread_func,
	 .fmt = "ssdfs-gc%llu-%u",},
#ifdef CONFIG_SSDFS_ONLINE_FSCK
	{.threadfn = ssdfs_peb_fsck_thread_func,
	 .fmt = "ssdfs-fsck%llu-%u",},
#endif /* CONFIG_SSDFS_ONLINE_FSCK */
};

/*
 * ssdfs_peb_mark_request_block_uptodate() - mark block uptodate
 * @pebc: pointer on PEB container
 * @req: request
 * @blk_index: index of block in request's sequence
 *
 * This function mark memory pages of request as uptodate and
 * not dirty. Page should be locked.
 */
void ssdfs_peb_mark_request_block_uptodate(struct ssdfs_peb_container *pebc,
					   struct ssdfs_segment_request *req,
					   int blk_index)
{
	u32 pagesize;
	u32 mem_pages;
	pgoff_t page_index;
	u32 page_off;
	u32 i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);

	SSDFS_DBG("blk_index %d, processed_blocks %d\n",
		  blk_index, req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(&req->result.pvec) == 0) {
		SSDFS_DBG("pagevec is empty\n");
		return;
	}

	BUG_ON(blk_index >= req->result.processed_blks);

	pagesize = pebc->parent_si->fsi->pagesize;
	mem_pages = (pagesize + PAGE_SIZE - 1) >> PAGE_SHIFT;
	page_index = ssdfs_phys_page_to_mem_page(pebc->parent_si->fsi,
						 blk_index);
	page_off = (page_index * pagesize) % PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(mem_pages > 1 && page_off != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < mem_pages; i++) {
		if ((page_off + pagesize) != PAGE_SIZE)
			return;
		else {
			struct page *page;

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(i >= pagevec_count(&req->result.pvec));
#endif /* CONFIG_SSDFS_DEBUG */

			page = req->result.pvec.pages[i];

			if (!PageLocked(page)) {
				SSDFS_WARN("failed to mark block uptodate: "
					   "page %d is not locked\n",
					   i);
			} else {
				if (!PageError(page)) {
					ClearPageDirty(page);
					SetPageUptodate(page);
				}
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
			SSDFS_DBG("page_index %ld, flags %#lx\n",
				  page->index, page->flags);
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}
}

/*
 * ssdfs_peb_start_thread() - start PEB's thread
 * @pebc: pointer on PEB container
 * @type: thread type
 *
 * This function tries to start PEB's thread of @type.
 *
 * RETURN:
 * [success] - PEB's thread has been started.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_peb_start_thread(struct ssdfs_peb_container *pebc, int type)
{
	struct ssdfs_segment_info *si;
	ssdfs_threadfn threadfn;
	const char *fmt;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);

	if (type >= SSDFS_PEB_THREAD_TYPE_MAX) {
		SSDFS_ERR("invalid thread type %d\n", type);
		return -EINVAL;
	}

	SSDFS_DBG("seg_id %llu, peb_index %u, thread_type %d\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  type);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	threadfn = thread_desc[type].threadfn;
	fmt = thread_desc[type].fmt;

	pebc->thread[type].task = kthread_create(threadfn, pebc, fmt,
						 pebc->parent_si->seg_id,
						 pebc->peb_index);
	if (IS_ERR_OR_NULL(pebc->thread[type].task)) {
		err = PTR_ERR(pebc->thread[type].task);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			if (err == 0)
				err = -ERANGE;
			SSDFS_ERR("fail to start thread: "
				  "seg_id %llu, peb_index %u, thread_type %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, type);
		}

		return err;
	}

	init_waitqueue_entry(&pebc->thread[type].wait,
				pebc->thread[type].task);
	add_wait_queue(&si->wait_queue[type],
			&pebc->thread[type].wait);
	init_completion(&pebc->thread[type].full_stop);

	wake_up_process(pebc->thread[type].task);

	return 0;
}

/*
 * ssdfs_peb_stop_thread() - stop PEB's thread
 * @pebc: pointer on PEB container
 * @type: thread type
 *
 * This function tries to stop PEB's thread of @type.
 *
 * RETURN:
 * [success] - PEB's thread has been stopped.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_peb_stop_thread(struct ssdfs_peb_container *pebc, int type)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);

	if (type >= SSDFS_PEB_THREAD_TYPE_MAX) {
		SSDFS_ERR("invalid thread type %d\n", type);
		return -EINVAL;
	}

	SSDFS_DBG("type %#x, task %p\n",
		  type, pebc->thread[type].task);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!pebc->thread[type].task)
		return 0;

	err = kthread_stop(pebc->thread[type].task);
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

	finish_wait(&pebc->parent_si->wait_queue[type],
			&pebc->thread[type].wait);

	pebc->thread[type].task = NULL;

	err = SSDFS_WAIT_COMPLETION(&pebc->thread[type].full_stop);
	if (unlikely(err)) {
		SSDFS_ERR("stop thread fails: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_map_leb2peb() - map LEB ID into PEB ID
 * @fsi: pointer on shared file system object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
 * @pebr: pointer on PEBs association container [out]
 *
 * This method tries to map LEB ID into PEB ID.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - can't map LEB to PEB.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_map_leb2peb(struct ssdfs_fs_info *fsi,
			  u64 leb_id, int peb_type,
			  struct ssdfs_maptbl_peb_relation *pebr)
{
	struct completion *end;
#ifdef CONFIG_SSDFS_DEBUG
	struct ssdfs_maptbl_peb_descriptor *ptr;
#endif /* CONFIG_SSDFS_DEBUG */
	u64 peb_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->maptbl || !pebr);
	BUG_ON(leb_id == U64_MAX);

	SSDFS_DBG("leb_id %llu, peb_type %#x\n",
		  leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_map_leb2peb(fsi, leb_id, peb_type,
					pebr, &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_maptbl_map_leb2peb(fsi, leb_id, peb_type,
						pebr, &end);
	}

	if (err == -EACCES || err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("can't map LEB to PEB: "
			  "leb_id %llu, peb_type %#x, err %d\n",
			  leb_id, peb_type, err);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	} else if (err == -EEXIST) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("LEB is mapped already: "
			  "leb_id %llu, peb_type %#x\n",
			  leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id,
						   peb_type,
						   pebr, &end);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB to PEB: "
				  "leb_id %llu, peb_type %#x, err %d\n",
				  leb_id, peb_type, err);
			return err;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to map LEB to PEB: "
			  "leb_id %llu, peb_type %#x, err %d\n",
			  leb_id, peb_type, err);
		return err;
	}

	peb_id = pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;

	if (peb_id == U64_MAX) {
		SSDFS_ERR("invalid peb_id\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("LEB %llu, PEB %llu\n", leb_id, peb_id);

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
 * ssdfs_peb_convert_leb2peb() - convert LEB ID into PEB ID
 * @fsi: pointer on shared file system object
 * @leb_id: LEB ID number
 * @peb_type: PEB type
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
int ssdfs_peb_convert_leb2peb(struct ssdfs_fs_info *fsi,
			      u64 leb_id, int peb_type,
			      struct ssdfs_maptbl_peb_relation *pebr)
{
	struct completion *end;
#ifdef CONFIG_SSDFS_DEBUG
	struct ssdfs_maptbl_peb_descriptor *ptr;
#endif /* CONFIG_SSDFS_DEBUG */
	u64 peb_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->maptbl || !pebr);
	BUG_ON(leb_id == U64_MAX);

	SSDFS_DBG("leb_id %llu, peb_type %#x\n",
		  leb_id, peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id,
					   peb_type,
					   pebr, &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id, peb_type,
						   pebr, &end);
	}

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("LEB doesn't mapped: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to convert LEB to PEB: "
			  "leb_id %llu, peb_type %#x, err %d\n",
			  leb_id, peb_type, err);
		return err;
	}

	peb_id = pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id;
	if (peb_id == U64_MAX) {
		SSDFS_ERR("invalid peb_id\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("LEB %llu, PEB %llu\n", leb_id, peb_id);

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
 * ssdfs_create_clean_peb_container() - create "clean" PEB container
 * @pebc: pointer on PEB container
 * @selected_peb: source or destination PEB?
 *
 * This function tries to initialize PEB container for "clean"
 * state of the PEB.
 *
 * RETURN:
 * [success] - PEB container has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_create_clean_peb_container(struct ssdfs_peb_container *pebc,
				     int selected_peb)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_segment_request *req;
	int command;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);

	SSDFS_DBG("peb_index %u, peb_type %#x, "
		  "selected_peb %d\n",
		  pebc->peb_index, pebc->peb_type,
		  selected_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	command = SSDFS_READ_BLK_BMAP_INIT_CLEAN_PEB;

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		req = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto fail_create_clean_peb_obj;
	}

	ssdfs_request_init(req);
	/* read thread puts request */
	ssdfs_get_request(req);
	/* it needs to be sure that request will be not freed */
	ssdfs_get_request(req);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req);

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_READ_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto fail_create_clean_peb_obj;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start read thread: "
			  "peb_index %u, err %d\n",
			  pebc->peb_index, err);
		goto fail_create_clean_peb_obj;
	}

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_FLUSH_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto stop_read_thread;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start flush thread: "
			  "peb_index %u, err %d\n",
			  pebc->peb_index, err);
		goto stop_read_thread;
	}

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_FSCK_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto stop_flush_thread;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start fsck thread: "
			  "peb_index %u, err %d\n",
			  pebc->peb_index, err);
		goto stop_flush_thread;
	}
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	peb_blkbmap = &pebc->parent_si->blk_bmap.peb[pebc->peb_index];

	if (!ssdfs_peb_blk_bmap_initialized(peb_blkbmap)) {
		err = SSDFS_WAIT_COMPLETION(&req->result.wait);
		if (unlikely(err)) {
			SSDFS_ERR("read thread fails: err %d\n",
				  err);
#ifdef CONFIG_SSDFS_ONLINE_FSCK
			goto stop_fsck_thread;
#else
			goto stop_flush_thread;
#endif /* CONFIG_SSDFS_ONLINE_FSCK */
		}
	}

	ssdfs_put_request(req);

	if (selected_peb == SSDFS_SRC_PEB) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebc->src_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		ssdfs_set_peb_migration_id(pebc->src_peb,
					   SSDFS_PEB_MIGRATION_ID_START);
		atomic_set(&pebc->src_peb->state,
			   SSDFS_PEB_OBJECT_INITIALIZED);
		complete_all(&pebc->src_peb->init_end);
	} else if (selected_peb == SSDFS_DST_PEB) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		ssdfs_set_peb_migration_id(pebc->dst_peb,
					   SSDFS_PEB_MIGRATION_ID_START);
		atomic_set(&pebc->dst_peb->state,
			   SSDFS_PEB_OBJECT_INITIALIZED);
		complete_all(&pebc->dst_peb->init_end);
	} else
		BUG();

	return 0;

#ifdef CONFIG_SSDFS_ONLINE_FSCK
stop_fsck_thread:
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_FSCK_THREAD);
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

stop_flush_thread:
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_FLUSH_THREAD);

stop_read_thread:
	ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_READ_THREAD);

fail_create_clean_peb_obj:
	return err;
}

/*
 * ssdfs_create_using_peb_container() - create "using" PEB container
 * @pebc: pointer on PEB container
 * @selected_peb: source or destination PEB?
 *
 * This function tries to initialize PEB conatiner for "using"
 * state of the PEB.
 *
 * RETURN:
 * [success] - PEB object has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_create_using_peb_container(struct ssdfs_peb_container *pebc,
				     int selected_peb)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_segment_request *req1, *req2, *req3, *req4, *req5;
	int command;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);
	BUG_ON(selected_peb < SSDFS_SRC_PEB ||
		selected_peb > SSDFS_SRC_AND_DST_PEB);

	SSDFS_DBG("seg %llu, peb_index %u, peb_type %#x, "
		  "selected_peb %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  selected_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (selected_peb == SSDFS_SRC_PEB)
		command = SSDFS_READ_SRC_ALL_LOG_HEADERS;
	else if (selected_peb == SSDFS_DST_PEB)
		command = SSDFS_READ_DST_ALL_LOG_HEADERS;
	else if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_DST_ALL_LOG_HEADERS;
	else
		BUG();

	req1 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req1)) {
		err = (req1 == NULL ? -ENOMEM : PTR_ERR(req1));
		req1 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto fail_create_using_peb_obj;
	}

	ssdfs_request_init(req1);
	/* read thread puts request */
	ssdfs_get_request(req1);
	/* it needs to be sure that request will be not freed */
	ssdfs_get_request(req1);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req1);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req1);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req1);

	if (selected_peb == SSDFS_SRC_PEB)
		command = SSDFS_READ_BLK_BMAP_SRC_USING_PEB;
	else if (selected_peb == SSDFS_DST_PEB)
		command = SSDFS_READ_BLK_BMAP_DST_USING_PEB;
	else if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_BLK_BMAP_DST_USING_PEB;
	else
		BUG();

	req2 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req2)) {
		err = (req2 == NULL ? -ENOMEM : PTR_ERR(req2));
		req2 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_using_peb_obj;
	}

	ssdfs_request_init(req2);
	ssdfs_get_request(req2);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req2);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req2);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req2);

	if (selected_peb == SSDFS_SRC_AND_DST_PEB) {
		command = SSDFS_READ_SRC_LAST_LOG_FOOTER;

		req3 = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req3)) {
			err = (req3 == NULL ? -ENOMEM : PTR_ERR(req3));
			req1 = NULL;
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			ssdfs_requests_queue_remove_all(&pebc->read_rq,
							-ERANGE);
			goto fail_create_using_peb_obj;
		}

		ssdfs_request_init(req3);
		ssdfs_get_request(req3);
		ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
						    command,
						    SSDFS_REQ_ASYNC,
						    req3);
		ssdfs_request_define_segment(pebc->parent_si->seg_id, req3);
		ssdfs_peb_read_request_cno(pebc);
		ssdfs_requests_queue_add_tail(&pebc->read_rq, req3);

		command = SSDFS_READ_SRC_ALL_LOG_HEADERS;

		req4 = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req4)) {
			err = (req4 == NULL ? -ENOMEM : PTR_ERR(req4));
			req4 = NULL;
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			ssdfs_requests_queue_remove_all(&pebc->read_rq,
							-ERANGE);
			goto fail_create_using_peb_obj;
		}

		ssdfs_request_init(req4);
		ssdfs_get_request(req4);
		ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
						    command,
						    SSDFS_REQ_ASYNC,
						    req4);
		ssdfs_request_define_segment(pebc->parent_si->seg_id, req4);
		ssdfs_peb_read_request_cno(pebc);
		ssdfs_requests_queue_add_tail(&pebc->read_rq, req4);
	}

	if (selected_peb == SSDFS_SRC_PEB)
		command = SSDFS_READ_BLK2OFF_TABLE_SRC_PEB;
	else if (selected_peb == SSDFS_DST_PEB)
		command = SSDFS_READ_BLK2OFF_TABLE_DST_PEB;
	else if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_BLK2OFF_TABLE_DST_PEB;
	else
		BUG();

	req5 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req5)) {
		err = (req5 == NULL ? -ENOMEM : PTR_ERR(req5));
		req5 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_using_peb_obj;
	}

	ssdfs_request_init(req5);
	ssdfs_get_request(req5);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req5);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req5);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req5);

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_READ_THREAD);
	if (unlikely(err)) {
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to start read thread: "
				  "peb_index %u, err %d\n",
				  pebc->peb_index, err);
		}

		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_using_peb_obj;
	}

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_FLUSH_THREAD);
	if (unlikely(err)) {
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to start flush thread: "
				  "peb_index %u, err %d\n",
				  pebc->peb_index, err);
		}

		goto stop_read_thread;
	}

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_FSCK_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto stop_flush_thread;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start fsck thread: "
			  "peb_index %u, err %d\n",
			  pebc->peb_index, err);
		goto stop_flush_thread;
	}
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	peb_blkbmap = &pebc->parent_si->blk_bmap.peb[pebc->peb_index];

	if (!ssdfs_peb_blk_bmap_initialized(peb_blkbmap)) {
		err = SSDFS_WAIT_COMPLETION(&req1->result.wait);
		if (unlikely(err)) {
			SSDFS_ERR("read thread fails: err %d\n",
				  err);
#ifdef CONFIG_SSDFS_ONLINE_FSCK
			goto stop_fsck_thread;
#else
			goto stop_flush_thread;
#endif /* CONFIG_SSDFS_ONLINE_FSCK */
		}

		/*
		 * Block bitmap has been locked for initialization.
		 * Now it isn't initialized yet. It should check
		 * block bitmap initialization state during first
		 * request about free pages count.
		 */
	}

	ssdfs_put_request(req1);

	/*
	 * Current log start_page and data_free_pages count was defined
	 * in the read thread during searching last actual state of block
	 * bitmap.
	 */

	/*
	 * Wake up read request if it waits zeroing
	 * of reference counter.
	 */
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);

	return 0;

#ifdef CONFIG_SSDFS_ONLINE_FSCK
stop_fsck_thread:
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_FSCK_THREAD);
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

stop_flush_thread:
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_FLUSH_THREAD);

stop_read_thread:
	ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_READ_THREAD);

fail_create_using_peb_obj:
	return err;
}

/*
 * ssdfs_create_used_peb_container() - create "used" PEB container
 * @pebi: pointer on PEB container
 * @selected_peb: source or destination PEB?
 *
 * This function tries to initialize PEB container for "used"
 * state of the PEB.
 *
 * RETURN:
 * [success] - PEB container has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_create_used_peb_container(struct ssdfs_peb_container *pebc,
				    int selected_peb)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_segment_request *req1, *req2, *req3;
	int command;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);
	BUG_ON(selected_peb < SSDFS_SRC_PEB || selected_peb > SSDFS_DST_PEB);

	SSDFS_DBG("seg %llu, peb_index %u, peb_type %#x, "
		  "selected_peb %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  selected_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (selected_peb == SSDFS_SRC_PEB)
		command = SSDFS_READ_SRC_ALL_LOG_HEADERS;
	else if (selected_peb == SSDFS_DST_PEB)
		command = SSDFS_READ_DST_ALL_LOG_HEADERS;
	else
		BUG();

	req1 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req1)) {
		err = (req1 == NULL ? -ENOMEM : PTR_ERR(req1));
		req1 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto fail_create_used_peb_obj;
	}

	ssdfs_request_init(req1);
	/* read thread puts request */
	ssdfs_get_request(req1);
	/* it needs to be sure that request will be not freed */
	ssdfs_get_request(req1);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req1);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req1);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req1);

	if (selected_peb == SSDFS_SRC_PEB)
		command = SSDFS_READ_BLK_BMAP_SRC_USED_PEB;
	else if (selected_peb == SSDFS_DST_PEB)
		command = SSDFS_READ_BLK_BMAP_DST_USED_PEB;
	else
		BUG();

	req2 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req2)) {
		err = (req2 == NULL ? -ENOMEM : PTR_ERR(req2));
		req2 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_used_peb_obj;
	}

	ssdfs_request_init(req2);
	ssdfs_get_request(req2);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req2);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req2);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req2);

	if (selected_peb == SSDFS_SRC_PEB)
		command = SSDFS_READ_BLK2OFF_TABLE_SRC_PEB;
	else if (selected_peb == SSDFS_DST_PEB)
		command = SSDFS_READ_BLK2OFF_TABLE_DST_PEB;
	else
		BUG();

	req3 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req3)) {
		err = (req3 == NULL ? -ENOMEM : PTR_ERR(req3));
		req3 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_used_peb_obj;
	}

	ssdfs_request_init(req3);
	ssdfs_get_request(req3);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req3);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req3);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req3);

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_READ_THREAD);
	if (unlikely(err)) {
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to start read thread: "
				  "peb_index %u, err %d\n",
				  pebc->peb_index, err);
		}

		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_used_peb_obj;
	}

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_FLUSH_THREAD);
	if (unlikely(err)) {
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to start flush thread: "
				  "peb_index %u, err %d\n",
				  pebc->peb_index, err);
		}

		goto stop_read_thread;
	}

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_FSCK_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto stop_flush_thread;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start fsck thread: "
			  "peb_index %u, err %d\n",
			  pebc->peb_index, err);
		goto stop_flush_thread;
	}
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	peb_blkbmap = &pebc->parent_si->blk_bmap.peb[pebc->peb_index];

	if (!ssdfs_peb_blk_bmap_initialized(peb_blkbmap)) {
		err = SSDFS_WAIT_COMPLETION(&req1->result.wait);
		if (unlikely(err)) {
			SSDFS_ERR("read thread fails: err %d\n",
				  err);
#ifdef CONFIG_SSDFS_ONLINE_FSCK
			goto stop_fsck_thread;
#else
			goto stop_flush_thread;
#endif /* CONFIG_SSDFS_ONLINE_FSCK */
		}

		/*
		 * Block bitmap has been locked for initialization.
		 * Now it isn't initialized yet. It should check
		 * block bitmap initialization state during first
		 * request about free pages count.
		 */
	}

	ssdfs_put_request(req1);

	/*
	 * Current log start_page and data_free_pages count was defined
	 * in the read thread during searching last actual state of block
	 * bitmap.
	 */

	/*
	 * Wake up read request if it waits zeroing
	 * of reference counter.
	 */
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);

	return 0;

#ifdef CONFIG_SSDFS_ONLINE_FSCK
stop_fsck_thread:
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_FSCK_THREAD);
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

stop_flush_thread:
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_FLUSH_THREAD);

stop_read_thread:
	ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_READ_THREAD);

fail_create_used_peb_obj:
	return err;
}

/*
 * ssdfs_create_pre_dirty_peb_container() - create "pre-dirty" PEB container
 * @pebi: pointer on PEB container
 * @selected_peb: source or destination PEB?
 *
 * This function tries to initialize PEB container for "pre-dirty"
 * state of the PEB.
 *
 * RETURN:
 * [success] - PEB container has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_create_pre_dirty_peb_container(struct ssdfs_peb_container *pebc,
					 int selected_peb)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);
	BUG_ON(selected_peb < SSDFS_SRC_PEB || selected_peb > SSDFS_DST_PEB);

	SSDFS_DBG("seg %llu, peb_index %u, peb_type %#x, "
		  "selected_peb %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  selected_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_create_used_peb_container(pebc, selected_peb);
}

/*
 * ssdfs_create_dirty_peb_container() - create "dirty" PEB container
 * @pebi: pointer on PEB container
 * @selected_peb: source or destination PEB?
 *
 * This function tries to initialize PEB container for "dirty"
 * state of the PEB.
 *
 * RETURN:
 * [success] - PEB container has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_create_dirty_peb_container(struct ssdfs_peb_container *pebc,
				     int selected_peb)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_blk2off_table *blk2off_table;
	struct ssdfs_segment_request *req;
	int command;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);
	BUG_ON(selected_peb < SSDFS_SRC_PEB || selected_peb > SSDFS_DST_PEB);

	SSDFS_DBG("seg %llu, peb_index %u, peb_type %#x, "
		  "selected_peb %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  selected_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	blk2off_table = si->blk2off_table;

	command = SSDFS_READ_SRC_LAST_LOG_FOOTER;

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		req = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto fail_create_dirty_peb_obj;
	}

	ssdfs_request_init(req);
	/* read thread puts request */
	ssdfs_get_request(req);
	/* it needs to be sure that request will be not freed */
	ssdfs_get_request(req);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req);

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_READ_THREAD);
	if (unlikely(err)) {
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to start read thread: "
				  "peb_index %u, err %d\n",
				  pebc->peb_index, err);
		}

		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_dirty_peb_obj;
	}

	err = SSDFS_WAIT_COMPLETION(&req->result.wait);
	if (unlikely(err)) {
		SSDFS_ERR("read thread fails: err %d\n",
			  err);
		goto stop_read_thread;
	}

	ssdfs_put_request(req);

	/*
	 * Wake up read request if it waits zeroing
	 * of reference counter.
	 */
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);

	atomic_set(&blk2off_table->peb[pebc->peb_index].state,
		   SSDFS_BLK2OFF_TABLE_COMPLETE_INIT);

	return 0;

stop_read_thread:
	ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_READ_THREAD);

fail_create_dirty_peb_obj:
	return err;
}

/*
 * ssdfs_create_dirty_using_container() - create "dirty" + "using" PEB container
 * @pebc: pointer on PEB container
 * @selected_peb: source or destination PEB?
 *
 * This function tries to initialize PEB conatiner for "dirty" + "using"
 * state of the PEBs.
 *
 * RETURN:
 * [success] - PEB object has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_create_dirty_using_container(struct ssdfs_peb_container *pebc,
					int selected_peb)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_segment_request *req1, *req2, *req3, *req4;
	int command;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);
	BUG_ON(selected_peb != SSDFS_SRC_AND_DST_PEB);

	SSDFS_DBG("seg %llu, peb_index %u, peb_type %#x, "
		  "selected_peb %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  selected_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_SRC_LAST_LOG_FOOTER;
	else
		BUG();

	req1 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req1)) {
		err = (req1 == NULL ? -ENOMEM : PTR_ERR(req1));
		req1 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto fail_create_dirty_using_peb_obj;
	}

	ssdfs_request_init(req1);
	ssdfs_get_request(req1);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req1);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req1);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req1);

	if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_DST_ALL_LOG_HEADERS;
	else
		BUG();

	req2 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req2)) {
		err = (req2 == NULL ? -ENOMEM : PTR_ERR(req2));
		req2 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto fail_create_dirty_using_peb_obj;
	}

	ssdfs_request_init(req2);
	/* read thread puts request */
	ssdfs_get_request(req2);
	/* it needs to be sure that request will be not freed */
	ssdfs_get_request(req2);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req2);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req2);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req2);

	if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_BLK_BMAP_DST_USING_PEB;
	else
		BUG();

	req3 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req3)) {
		err = (req3 == NULL ? -ENOMEM : PTR_ERR(req3));
		req3 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_dirty_using_peb_obj;
	}

	ssdfs_request_init(req3);
	ssdfs_get_request(req3);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req3);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req3);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req3);

	if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_BLK2OFF_TABLE_DST_PEB;
	else
		BUG();

	req4 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req4)) {
		err = (req4 == NULL ? -ENOMEM : PTR_ERR(req4));
		req4 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_dirty_using_peb_obj;
	}

	ssdfs_request_init(req4);
	ssdfs_get_request(req4);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req4);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req4);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req4);

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_READ_THREAD);
	if (unlikely(err)) {
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to start read thread: "
				  "peb_index %u, err %d\n",
				  pebc->peb_index, err);
		}

		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_dirty_using_peb_obj;
	}

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_FLUSH_THREAD);
	if (unlikely(err)) {
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to start flush thread: "
				  "peb_index %u, err %d\n",
				  pebc->peb_index, err);
		}

		goto stop_read_thread;
	}

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_FSCK_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto stop_flush_thread;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start fsck thread: "
			  "peb_index %u, err %d\n",
			  pebc->peb_index, err);
		goto stop_flush_thread;
	}
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	peb_blkbmap = &pebc->parent_si->blk_bmap.peb[pebc->peb_index];

	if (!ssdfs_peb_blk_bmap_initialized(peb_blkbmap)) {
		err = SSDFS_WAIT_COMPLETION(&req2->result.wait);
		if (unlikely(err)) {
			SSDFS_ERR("read thread fails: err %d\n",
				  err);
#ifdef CONFIG_SSDFS_ONLINE_FSCK
			goto stop_fsck_thread;
#else
			goto stop_flush_thread;
#endif /* CONFIG_SSDFS_ONLINE_FSCK */
		}

		/*
		 * Block bitmap has been locked for initialization.
		 * Now it isn't initialized yet. It should check
		 * block bitmap initialization state during first
		 * request about free pages count.
		 */
	}

	ssdfs_put_request(req2);

	/*
	 * Current log start_page and data_free_pages count was defined
	 * in the read thread during searching last actual state of block
	 * bitmap.
	 */

	/*
	 * Wake up read request if it waits zeroing
	 * of reference counter.
	 */
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);

	return 0;

#ifdef CONFIG_SSDFS_ONLINE_FSCK
stop_fsck_thread:
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_FSCK_THREAD);
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

stop_flush_thread:
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_FLUSH_THREAD);

stop_read_thread:
	ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_READ_THREAD);

fail_create_dirty_using_peb_obj:
	return err;
}

/*
 * ssdfs_create_dirty_used_container() - create "dirty" + "used" PEB container
 * @pebi: pointer on PEB container
 * @selected_peb: source or destination PEB?
 *
 * This function tries to initialize PEB container for "dirty" + "used"
 * state of the PEBs.
 *
 * RETURN:
 * [success] - PEB container has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_create_dirty_used_container(struct ssdfs_peb_container *pebc,
				      int selected_peb)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_segment_request *req1, *req2, *req3, *req4;
	int command;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);
	BUG_ON(selected_peb != SSDFS_SRC_AND_DST_PEB);

	SSDFS_DBG("seg %llu, peb_index %u, peb_type %#x, "
		  "selected_peb %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  selected_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_SRC_LAST_LOG_FOOTER;
	else
		BUG();

	req1 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req1)) {
		err = (req1 == NULL ? -ENOMEM : PTR_ERR(req1));
		req1 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto fail_create_dirty_used_peb_obj;
	}

	ssdfs_request_init(req1);
	ssdfs_get_request(req1);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req1);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req1);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req1);

	if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_DST_ALL_LOG_HEADERS;
	else
		BUG();

	req2 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req2)) {
		err = (req2 == NULL ? -ENOMEM : PTR_ERR(req2));
		req2 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto fail_create_dirty_used_peb_obj;
	}

	ssdfs_request_init(req2);
	/* read thread puts request */
	ssdfs_get_request(req2);
	/* it needs to be sure that request will be not freed */
	ssdfs_get_request(req2);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req2);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req2);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req2);

	if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_BLK_BMAP_DST_USED_PEB;
	else
		BUG();

	req3 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req3)) {
		err = (req3 == NULL ? -ENOMEM : PTR_ERR(req3));
		req3 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_dirty_used_peb_obj;
	}

	ssdfs_request_init(req3);
	ssdfs_get_request(req3);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req3);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req3);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req3);

	if (selected_peb == SSDFS_SRC_AND_DST_PEB)
		command = SSDFS_READ_BLK2OFF_TABLE_DST_PEB;
	else
		BUG();

	req4 = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req4)) {
		err = (req4 == NULL ? -ENOMEM : PTR_ERR(req4));
		req4 = NULL;
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_dirty_used_peb_obj;
	}

	ssdfs_request_init(req4);
	ssdfs_get_request(req4);
	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    command,
					    SSDFS_REQ_ASYNC,
					    req4);
	ssdfs_request_define_segment(pebc->parent_si->seg_id, req4);
	ssdfs_peb_read_request_cno(pebc);
	ssdfs_requests_queue_add_tail(&pebc->read_rq, req4);

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_READ_THREAD);
	if (unlikely(err)) {
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to start read thread: "
				  "peb_index %u, err %d\n",
				  pebc->peb_index, err);
		}

		ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
		goto fail_create_dirty_used_peb_obj;
	}

	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_FLUSH_THREAD);
	if (unlikely(err)) {
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to start flush thread: "
				  "peb_index %u, err %d\n",
				  pebc->peb_index, err);
		}

		goto stop_read_thread;
	}

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	err = ssdfs_peb_start_thread(pebc, SSDFS_PEB_FSCK_THREAD);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto stop_flush_thread;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start fsck thread: "
			  "peb_index %u, err %d\n",
			  pebc->peb_index, err);
		goto stop_flush_thread;
	}
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	peb_blkbmap = &pebc->parent_si->blk_bmap.peb[pebc->peb_index];

	if (!ssdfs_peb_blk_bmap_initialized(peb_blkbmap)) {
		err = SSDFS_WAIT_COMPLETION(&req2->result.wait);
		if (unlikely(err)) {
			SSDFS_ERR("read thread fails: err %d\n",
				  err);
#ifdef CONFIG_SSDFS_ONLINE_FSCK
			goto stop_fsck_thread;
#else
			goto stop_flush_thread;
#endif /* CONFIG_SSDFS_ONLINE_FSCK */
		}

		/*
		 * Block bitmap has been locked for initialization.
		 * Now it isn't initialized yet. It should check
		 * block bitmap initialization state during first
		 * request about free pages count.
		 */
	}

	ssdfs_put_request(req2);

	/*
	 * Current log start_page and data_free_pages count was defined
	 * in the read thread during searching last actual state of block
	 * bitmap.
	 */

	/*
	 * Wake up read request if it waits zeroing
	 * of reference counter.
	 */
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);

	return 0;

#ifdef CONFIG_SSDFS_ONLINE_FSCK
stop_fsck_thread:
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_FSCK_THREAD);
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

stop_flush_thread:
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_FLUSH_THREAD);

stop_read_thread:
	ssdfs_requests_queue_remove_all(&pebc->read_rq, -ERANGE);
	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD]);
	ssdfs_peb_stop_thread(pebc, SSDFS_PEB_READ_THREAD);

fail_create_dirty_used_peb_obj:
	return err;
}

/*
 * ssdfs_peb_container_get_peb_relation() - get description of relation
 * @fsi: file system info object
 * @seg: segment identification number
 * @peb_index: PEB's index
 * @peb_type: PEB's type
 * @seg_state: segment state
 * @pebr: description of PEBs relation [out]
 *
 * This function tries to retrieve PEBs' relation description.
 *
 * RETURN:
 * [success].
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENODATA    - cannott map LEB to PEB.
 */
static
int ssdfs_peb_container_get_peb_relation(struct ssdfs_fs_info *fsi,
					 u64 seg, u32 peb_index,
					 u8 peb_type, int seg_state,
					 struct ssdfs_maptbl_peb_relation *pebr)
{
	u64 leb_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebr);

	SSDFS_DBG("fsi %p, seg %llu, peb_index %u, "
		  "peb_type %#x, seg_state %#x\n",
		  fsi, seg, peb_index, peb_type, seg_state);
#endif /* CONFIG_SSDFS_DEBUG */

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi, seg, peb_index);
	if (leb_id == U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  seg, peb_index);
		return -EINVAL;
	}

	switch (seg_state) {
	case SSDFS_SEG_CLEAN:
		err = ssdfs_peb_map_leb2peb(fsi, leb_id, peb_type,
					    pebr);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("can't map LEB to PEB: "
				  "leb_id %llu, peb_type %#x, err %d\n",
				  leb_id, peb_type, err);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to map LEB to PEB: "
				  "leb_id %llu, peb_type %#x, err %d\n",
				  leb_id, peb_type, err);
			return err;
		}
		break;

	case SSDFS_SEG_DATA_USING:
	case SSDFS_SEG_LEAF_NODE_USING:
	case SSDFS_SEG_HYBRID_NODE_USING:
	case SSDFS_SEG_INDEX_NODE_USING:
	case SSDFS_SEG_USED:
	case SSDFS_SEG_PRE_DIRTY:
	case SSDFS_SEG_DIRTY:
		err = ssdfs_peb_convert_leb2peb(fsi, leb_id, peb_type,
						pebr);
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
		break;

	default:
		SSDFS_ERR("invalid segment state\n");
		return -EINVAL;
	};

	return 0;
}

/*
 * ssdfs_peb_container_start_threads() - start PEB container's threads
 * @pebc: pointer on PEB container
 * @src_peb_state: source PEB's state
 * @dst_peb_state: destination PEB's state
 * @src_peb_flags: source PEB's flags
 *
 * This function tries to start PEB's container threads.
 *
 * RETURN:
 * [success].
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_peb_container_start_threads(struct ssdfs_peb_container *pebc,
				      int src_peb_state,
				      int dst_peb_state,
				      u8 src_peb_flags)
{
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	bool peb_has_ext_ptr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);

	SSDFS_DBG("seg %llu, peb_index %u, src_peb_state %#x, "
		  "dst_peb_state %#x, src_peb_flags %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, src_peb_state,
		  dst_peb_state, src_peb_flags);
#endif /* CONFIG_SSDFS_DEBUG */

	peb_has_ext_ptr = src_peb_flags & SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR;

	switch (src_peb_state) {
	case SSDFS_MAPTBL_UNKNOWN_PEB_STATE:
		switch (dst_peb_state) {
		case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
			err = ssdfs_create_clean_peb_container(pebc,
								SSDFS_DST_PEB);
			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create clean PEB container: "
					  "err %d\n", err);
				goto fail_start_threads;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			err = ssdfs_create_using_peb_container(pebc,
								SSDFS_DST_PEB);
			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create using PEB container: "
					  "err %d\n", err);
				goto fail_start_threads;
			}
			break;
		case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			err = ssdfs_create_used_peb_container(pebc,
							      SSDFS_DST_PEB);
			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create used PEB container: "
					  "err %d\n", err);
				goto fail_start_threads;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			err = ssdfs_create_pre_dirty_peb_container(pebc,
								SSDFS_DST_PEB);
			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create pre-dirty PEB "
					  "container: err %d\n", err);
				goto fail_start_threads;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
			err = ssdfs_create_dirty_peb_container(pebc,
								SSDFS_DST_PEB);
			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create dirty PEB container: "
					  "err %d\n", err);
				goto fail_start_threads;
			}
			break;

		default:
			SSDFS_ERR("invalid PEB state: "
				  "source %#x, destination %#x\n",
				  src_peb_state, dst_peb_state);
			err = -ERANGE;
			goto fail_start_threads;
		}
		break;

	case SSDFS_MAPTBL_CLEAN_PEB_STATE:
		err = ssdfs_create_clean_peb_container(pebc,
							SSDFS_SRC_PEB);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			goto fail_start_threads;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create clean PEB container: "
				  "err %d\n", err);
			goto fail_start_threads;
		}
		break;

	case SSDFS_MAPTBL_USING_PEB_STATE:
		err = ssdfs_create_using_peb_container(pebc,
							SSDFS_SRC_PEB);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			goto fail_start_threads;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create using PEB container: "
				  "err %d\n", err);
			goto fail_start_threads;
		}
		break;

	case SSDFS_MAPTBL_USED_PEB_STATE:
		err = ssdfs_create_used_peb_container(pebc,
							SSDFS_SRC_PEB);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			goto fail_start_threads;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create used PEB container: "
				  "err %d\n", err);
			goto fail_start_threads;
		}
		break;

	case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
		err = ssdfs_create_pre_dirty_peb_container(pebc,
							   SSDFS_SRC_PEB);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			goto fail_start_threads;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create pre-dirty PEB container: "
				  "err %d\n", err);
			goto fail_start_threads;
		}
		break;

	case SSDFS_MAPTBL_DIRTY_PEB_STATE:
		err = ssdfs_create_dirty_peb_container(pebc,
							SSDFS_SRC_PEB);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
			goto fail_start_threads;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create dirty PEB container: "
				  "err %d\n", err);
			goto fail_start_threads;
		}
		break;

	case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
		switch (dst_peb_state) {
		case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
			peb_blkbmap =
			    &pebc->parent_si->blk_bmap.peb[pebc->peb_index];
			atomic_set(&peb_blkbmap->state,
					SSDFS_PEB_BLK_BMAP_HAS_CLEAN_DST);

			err = ssdfs_create_used_peb_container(pebc,
							      SSDFS_SRC_PEB);
			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create used PEB container: "
					  "err %d\n", err);
				goto fail_start_threads;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			if (peb_has_ext_ptr) {
				err = ssdfs_create_used_peb_container(pebc,
								SSDFS_SRC_PEB);
			} else {
				err = ssdfs_create_using_peb_container(pebc,
							SSDFS_SRC_AND_DST_PEB);
			}

			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create using PEB container: "
					  "err %d\n", err);
				goto fail_start_threads;
			}
			break;

		default:
			SSDFS_ERR("invalid PEB state: "
				  "source %#x, destination %#x\n",
				  src_peb_state, dst_peb_state);
			err = -ERANGE;
			goto fail_start_threads;
		}
		break;

	case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
		switch (dst_peb_state) {
		case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
			peb_blkbmap =
			    &pebc->parent_si->blk_bmap.peb[pebc->peb_index];
			atomic_set(&peb_blkbmap->state,
					SSDFS_PEB_BLK_BMAP_HAS_CLEAN_DST);

			err = ssdfs_create_pre_dirty_peb_container(pebc,
								SSDFS_SRC_PEB);
			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create pre-dirty PEB "
					  "container: err %d\n", err);
				goto fail_start_threads;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			if (peb_has_ext_ptr) {
				err = ssdfs_create_pre_dirty_peb_container(pebc,
								SSDFS_SRC_PEB);
			} else {
				err = ssdfs_create_using_peb_container(pebc,
							SSDFS_SRC_AND_DST_PEB);
			}

			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create using PEB container: "
					  "err %d\n", err);
				goto fail_start_threads;
			}
			break;

		default:
			SSDFS_ERR("invalid PEB state: "
				  "source %#x, destination %#x\n",
				  src_peb_state, dst_peb_state);
			err = -ERANGE;
			goto fail_start_threads;
		}
		break;

	case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
		switch (dst_peb_state) {
		case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
			if (peb_has_ext_ptr) {
				err = ssdfs_create_dirty_peb_container(pebc,
								SSDFS_SRC_PEB);
			} else {
				err = ssdfs_create_dirty_using_container(pebc,
							SSDFS_SRC_AND_DST_PEB);
			}

			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create using PEB container: "
					  "err %d\n", err);
				goto fail_start_threads;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
			if (peb_has_ext_ptr) {
				err = ssdfs_create_dirty_peb_container(pebc,
								SSDFS_SRC_PEB);
			} else {
				err = ssdfs_create_dirty_used_container(pebc,
							SSDFS_SRC_AND_DST_PEB);
			}

			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create used PEB container: "
					  "err %d\n", err);
				goto fail_start_threads;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
			if (peb_has_ext_ptr) {
				err = ssdfs_create_dirty_peb_container(pebc,
								SSDFS_SRC_PEB);
			} else {
				err = ssdfs_create_dirty_used_container(pebc,
							SSDFS_SRC_AND_DST_PEB);
			}

			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create pre-dirty PEB "
					  "container: err %d\n", err);
				goto fail_start_threads;
			}
			break;

		case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
			if (peb_has_ext_ptr) {
				err = ssdfs_create_dirty_peb_container(pebc,
								SSDFS_SRC_PEB);
			} else {
				err = ssdfs_create_dirty_peb_container(pebc,
								SSDFS_DST_PEB);
			}

			if (err == -EINTR) {
				/*
				 * Ignore this error.
				 */
				goto fail_start_threads;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to create dirty PEB container: "
					  "err %d\n", err);
				goto fail_start_threads;
			}
			break;

		default:
			SSDFS_ERR("invalid PEB state: "
				  "source %#x, destination %#x\n",
				  src_peb_state, dst_peb_state);
			err = -ERANGE;
			goto fail_start_threads;
		}
		break;

	default:
		SSDFS_ERR("invalid PEB state: "
			  "source %#x, destination %#x\n",
			  src_peb_state, dst_peb_state);
		err = -ERANGE;
		goto fail_start_threads;
	};

fail_start_threads:
	return err;
}

/*
 * ssdfs_peb_container_create() - create PEB's container object
 * @fsi: pointer on shared file system object
 * @seg: segment number
 * @peb_index: index of PEB object in array
 * @log_pages: count of pages in log
 * @si: pointer on parent segment object
 *
 * This function tries to create PEB object(s) for @seg
 * identification number and for @peb_index in array.
 *
 * RETURN:
 * [success] - PEB object(s) has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_peb_container_create(struct ssdfs_fs_info *fsi,
				u64 seg, u32 peb_index,
				u8 peb_type,
				u32 log_pages,
				struct ssdfs_segment_info *si)
{
	struct ssdfs_peb_container *pebc;
	struct ssdfs_peb_info *pebi;
	struct ssdfs_maptbl_peb_relation pebr;
	struct ssdfs_maptbl_peb_descriptor *mtblpd;
	int src_peb_state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;
	int dst_peb_state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;
	u8 src_peb_flags = 0;
	u8 dst_peb_flags = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !si || !si->peb_array);

	if (seg >= fsi->nsegs) {
		SSDFS_ERR("requested seg %llu >= nsegs %llu\n",
			  seg, fsi->nsegs);
		return -EINVAL;
	}

	if (peb_index >= si->pebs_count) {
		SSDFS_ERR("requested peb_index %u >= pebs_count %u\n",
			  peb_index, si->pebs_count);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p, seg %llu, peb_index %u, "
		  "peb_type %#x, si %p\n",
		  fsi, seg, peb_index, peb_type, si);
#else
	SSDFS_DBG("fsi %p, seg %llu, peb_index %u, "
		  "peb_type %#x, si %p\n",
		  fsi, seg, peb_index, peb_type, si);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	pebc = &si->peb_array[peb_index];

	memset(pebc, 0, sizeof(struct ssdfs_peb_container));
	mutex_init(&pebc->migration_lock);
	atomic_set(&pebc->migration_state, SSDFS_PEB_UNKNOWN_MIGRATION_STATE);
	atomic_set(&pebc->migration_phase, SSDFS_PEB_MIGRATION_STATUS_UNKNOWN);
	atomic_set(&pebc->items_state, SSDFS_PEB_CONTAINER_EMPTY);
	atomic_set(&pebc->shared_free_dst_blks, 0);
	init_waitqueue_head(&pebc->migration_wq);
	init_rwsem(&pebc->lock);
	atomic_set(&pebc->dst_peb_refs, 0);

	for (i = 0; i < SSDFS_PEB_THREAD_TYPE_MAX; i++) {
		SSDFS_THREAD_STATE_INIT(&pebc->thread_state[i]);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("shared_free_dst_blks %d\n",
		  atomic_read(&pebc->shared_free_dst_blks));
	SSDFS_DBG("dst_peb_refs %d\n",
		  atomic_read(&pebc->dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */

	pebc->peb_type = peb_type;
	if (peb_type >= SSDFS_MAPTBL_PEB_TYPE_MAX) {
		SSDFS_ERR("invalid seg_type %#x\n", si->seg_type);
		return -EINVAL;
	}

	pebc->peb_index = peb_index;
	pebc->log_pages = log_pages;
	pebc->parent_si = si;

	ssdfs_requests_queue_init(&pebc->read_rq);
	ssdfs_requests_queue_init(&pebc->update_rq);
	spin_lock_init(&pebc->pending_lock);
	pebc->pending_updated_user_data_pages = 0;
	spin_lock_init(&pebc->crq_ptr_lock);
	pebc->create_rq = NULL;

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	ssdfs_requests_queue_init(&pebc->fsck_rq);
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	spin_lock_init(&pebc->cache_protection.cno_lock);
	pebc->cache_protection.create_cno = ssdfs_current_cno(fsi->sb);
	pebc->cache_protection.last_request_cno =
					pebc->cache_protection.create_cno;
	pebc->cache_protection.reqs_count = 0;
	pebc->cache_protection.protected_range = 0;
	pebc->cache_protection.future_request_cno =
					pebc->cache_protection.create_cno;

	err = ssdfs_peb_container_get_peb_relation(fsi, seg, peb_index,
						   peb_type,
						   atomic_read(&si->seg_state),
						   &pebr);
	if (err == -ENODATA) {
		struct ssdfs_peb_blk_bmap *peb_blkbmap;

		err = 0;

		peb_blkbmap = &pebc->parent_si->blk_bmap.peb[pebc->peb_index];
		ssdfs_set_block_bmap_initialized(peb_blkbmap->src);
		atomic_set(&peb_blkbmap->state, SSDFS_PEB_BLK_BMAP_INITIALIZED);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("can't map LEB to PEB: "
			  "seg %llu, peb_index %u, "
			  "peb_type %#x, err %d\n",
			  seg, peb_index, peb_type, err);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_init_peb_container;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to map LEB to PEB: "
			  "seg %llu, peb_index %u, "
			  "peb_type %#x, err %d\n",
			  seg, peb_index, peb_type, err);
		goto fail_init_peb_container;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("MAIN_INDEX: peb_id %llu, type %#x, "
		  "state %#x, consistency %#x; "
		  "RELATION_INDEX: peb_id %llu, type %#x, "
		  "state %#x, consistency %#x\n",
		  pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].peb_id,
		  pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].type,
		  pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].state,
		  pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX].consistency,
		  pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id,
		  pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].type,
		  pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].state,
		  pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].consistency);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&pebc->lock);

	mtblpd = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];

	if (mtblpd->peb_id == U64_MAX)
		goto try_process_relation;

	pebi = &pebc->items[SSDFS_SEG_PEB1];

	err = ssdfs_peb_object_create(pebi, pebc,
					mtblpd->peb_id,
					mtblpd->state,
					SSDFS_PEB_UNKNOWN_MIGRATION_ID);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create PEB object: "
			  "seg %llu, peb_index %u, "
			  "peb_id %llu, peb_state %#x\n",
			  seg, peb_index,
			  mtblpd->peb_id,
			  mtblpd->state);
		goto fail_create_peb_objects;
	}

	pebc->src_peb = pebi;
	src_peb_state = mtblpd->state;
	src_peb_flags = mtblpd->flags;

	if (mtblpd->flags & SSDFS_MAPTBL_SHARED_DESTINATION_PEB ||
	    (mtblpd->flags & SSDFS_MAPTBL_SHARED_DESTINATION_PEB &&
	     mtblpd->flags & SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR)) {
		SSDFS_ERR("invalid set of flags %#x\n",
			  mtblpd->flags);
		err = -EIO;
		goto fail_create_peb_objects;
	}

	atomic_set(&pebc->migration_state, SSDFS_PEB_NOT_MIGRATING);
	atomic_set(&pebc->items_state, SSDFS_PEB1_SRC_CONTAINER);

	switch (mtblpd->state) {
	case SSDFS_MAPTBL_CLEAN_PEB_STATE:
	case SSDFS_MAPTBL_USING_PEB_STATE:
	case SSDFS_MAPTBL_USED_PEB_STATE:
	case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
	case SSDFS_MAPTBL_DIRTY_PEB_STATE:
		/* PEB container has been created */
		goto start_container_threads;
		break;

	case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
		/*
		 * Do nothing here.
		 * Follow to create second PEB object.
		 */
		break;

	default:
		SSDFS_WARN("invalid PEB state: "
			   "seg %llu, peb_index %u, "
			   "peb_id %llu, peb_state %#x\n",
			   seg, peb_index,
			   mtblpd->peb_id,
			   mtblpd->state);
		err = -ERANGE;
		goto fail_create_peb_objects;
	}

try_process_relation:
	mtblpd = &pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX];

	if (mtblpd->peb_id == U64_MAX) {
		SSDFS_ERR("invalid peb_id\n");
		err = -ERANGE;
		goto fail_create_peb_objects;
	}

	switch (mtblpd->state) {
	case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
		/*
		 * Do nothing here.
		 * Follow to create second PEB object.
		 */
		break;

	default:
		SSDFS_WARN("invalid PEB state: "
			   "seg %llu, peb_index %u, "
			   "peb_id %llu, peb_state %#x\n",
			   seg, peb_index,
			   mtblpd->peb_id,
			   mtblpd->state);
		err = -ERANGE;
		goto fail_create_peb_objects;
	}

	if (mtblpd->flags & SSDFS_MAPTBL_SHARED_DESTINATION_PEB) {
		u8 shared_peb_index = mtblpd->shared_peb_index;

		if (!pebc->src_peb) {
			SSDFS_ERR("source PEB is absent\n");
			err = -ERANGE;
			goto fail_create_peb_objects;
		}

		if (shared_peb_index >= si->pebs_count) {
			SSDFS_ERR("shared_peb_index %u >= si->pebs_count %u\n",
				  shared_peb_index, si->pebs_count);
			err = -ERANGE;
			goto fail_create_peb_objects;
		}

		pebi = &si->peb_array[shared_peb_index].items[SSDFS_SEG_PEB2];
		pebc->dst_peb = pebi;
		atomic_set(&pebc->items_state,
				SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER);
		atomic_inc(&si->peb_array[shared_peb_index].dst_peb_refs);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_id %llu, dst_peb_refs %d\n",
		    pebi->peb_id,
		    atomic_read(&si->peb_array[shared_peb_index].dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
		pebi = &pebc->items[SSDFS_SEG_PEB2];

		err = ssdfs_peb_object_create(pebi, pebc,
						mtblpd->peb_id,
						mtblpd->state,
						SSDFS_PEB_UNKNOWN_MIGRATION_ID);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create PEB object: "
				  "seg %llu, peb_index %u, "
				  "peb_id %llu, peb_state %#x\n",
				  seg, peb_index,
				  mtblpd->peb_id,
				  mtblpd->state);
			goto fail_create_peb_objects;
		}

		pebc->dst_peb = pebi;

		if (!pebc->src_peb) {
			atomic_set(&pebc->items_state,
				    SSDFS_PEB2_DST_CONTAINER);
		} else {
			atomic_set(&pebc->items_state,
				    SSDFS_PEB1_SRC_PEB2_DST_CONTAINER);
			atomic_inc(&pebc->dst_peb_refs);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("peb_id %llu, dst_peb_refs %d\n",
				  mtblpd->peb_id,
				  atomic_read(&pebc->dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}

	dst_peb_state = mtblpd->state;
	dst_peb_flags = mtblpd->flags;

	if (mtblpd->flags & SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR ||
	    (mtblpd->flags & SSDFS_MAPTBL_SHARED_DESTINATION_PEB &&
	     mtblpd->flags & SSDFS_MAPTBL_SOURCE_PEB_HAS_EXT_PTR)) {
		SSDFS_ERR("invalid set of flags %#x\n",
			  mtblpd->flags);
		err = -EIO;
		goto fail_create_peb_objects;
	}

	atomic_set(&pebc->migration_state, SSDFS_PEB_UNDER_MIGRATION);
	atomic_inc(&si->migration.migrating_pebs);

start_container_threads:
	up_write(&pebc->lock);

	err = ssdfs_peb_container_start_threads(pebc, src_peb_state,
						dst_peb_state,
						src_peb_flags);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto fail_init_peb_container;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start PEB's threads: "
			  "err %d\n", err);
		goto fail_init_peb_container;
	}

finish_init_peb_container:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("PEB has been created: "
		  "seg %llu, peb_index %u\n",
		  seg, peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

fail_create_peb_objects:
	up_write(&pebc->lock);

fail_init_peb_container:
	ssdfs_peb_container_destroy(pebc);
	return err;
}

/*
 * ssdfs_peb_container_destroy() - destroy PEB's container object
 * @ptr: pointer on container placement
 */
void ssdfs_peb_container_destroy(struct ssdfs_peb_container *ptr)
{
	int migration_state;
	int items_state;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	migration_state = atomic_read(&ptr->migration_state);
	items_state = atomic_read(&ptr->items_state);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("ptr %p, migration_state %#x, items_state %#x\n",
		  ptr, migration_state, items_state);
#else
	SSDFS_DBG("ptr %p, migration_state %#x, items_state %#x\n",
		  ptr, migration_state, items_state);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!is_ssdfs_requests_queue_empty(&ptr->read_rq)) {
		ssdfs_fs_error(ptr->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"read requests queue isn't empty\n");
		err = -EIO;
		ssdfs_requests_queue_remove_all(&ptr->read_rq, err);
	}

	if (!is_ssdfs_requests_queue_empty(&ptr->update_rq)) {
		ssdfs_fs_error(ptr->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"flush requests queue isn't empty\n");
		err = -EIO;
		ssdfs_requests_queue_remove_all(&ptr->update_rq, err);
	}

#ifdef CONFIG_SSDFS_ONLINE_FSCK
	if (!is_ssdfs_requests_queue_empty(&ptr->fsck_rq)) {
		ssdfs_fs_error(ptr->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"FSCK requests queue isn't empty\n");
		err = -EIO;
		ssdfs_requests_queue_remove_all(&ptr->fsck_rq, err);
	}
#endif /* CONFIG_SSDFS_ONLINE_FSCK */

	if (is_peb_container_empty(ptr)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("PEB container is empty: "
			  "peb_type %#x, peb_index %u\n",
			  ptr->peb_type, ptr->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return;
	}

	if (migration_state <= SSDFS_PEB_UNKNOWN_MIGRATION_STATE ||
	    migration_state >= SSDFS_PEB_MIGRATION_STATE_MAX) {
		SSDFS_WARN("invalid migration_state %#x\n",
			   migration_state);
	}

	if (items_state < SSDFS_PEB_CONTAINER_EMPTY ||
	    items_state >= SSDFS_PEB_CONTAINER_STATE_MAX) {
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
	}

	for (i = 0; i < SSDFS_PEB_THREAD_TYPE_MAX; i++) {
		int err2;

		err2 = ssdfs_peb_stop_thread(ptr, i);
		if (err2 == -EIO) {
			ssdfs_fs_error(ptr->parent_si->fsi->sb,
					__FILE__, __func__, __LINE__,
					"thread I/O issue: "
					"peb_index %u, thread type %#x\n",
					ptr->peb_index, i);
		} else if (unlikely(err2)) {
			SSDFS_WARN("thread stopping issue: "
				   "peb_index %u, thread type %#x, err %d\n",
				   ptr->peb_index, i, err2);
		}
	}

	down_write(&ptr->lock);

	switch (atomic_read(&ptr->items_state)) {
	case SSDFS_PEB_CONTAINER_EMPTY:
#ifdef CONFIG_SSDFS_DEBUG
		WARN_ON(ptr->src_peb);
		WARN_ON(ptr->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		ptr->src_peb = NULL;
		ptr->dst_peb = NULL;
		break;

	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!ptr->src_peb);
		WARN_ON(ptr->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = ssdfs_peb_object_destroy(ptr->src_peb);
		if (unlikely(err)) {
			SSDFS_WARN("fail to destroy PEB object: "
				   "err %d\n",
				   err);
		}
		ptr->src_peb = NULL;
		ptr->dst_peb = NULL;
		break;

	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!ptr->dst_peb);
		WARN_ON(ptr->src_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = ssdfs_peb_object_destroy(ptr->dst_peb);
		if (unlikely(err)) {
			SSDFS_WARN("fail to destroy PEB object: "
				   "err %d\n",
				   err);
		}

		ptr->src_peb = NULL;
		ptr->dst_peb = NULL;
		break;

	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!ptr->src_peb);
		BUG_ON(!ptr->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = ssdfs_peb_object_destroy(ptr->src_peb);
		if (unlikely(err)) {
			SSDFS_WARN("fail to destroy PEB object: "
				   "err %d\n",
				   err);
		}
		ptr->src_peb = NULL;
		ptr->dst_peb = NULL;
		break;

	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!ptr->src_peb);
		BUG_ON(!ptr->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */
		err = ssdfs_peb_object_destroy(ptr->src_peb);
		if (unlikely(err)) {
			SSDFS_WARN("fail to destroy PEB object: "
				   "err %d\n",
				   err);
		}
		err = ssdfs_peb_object_destroy(ptr->dst_peb);
		if (unlikely(err)) {
			SSDFS_WARN("fail to destroy PEB object: "
				   "err %d\n",
				   err);
		}
		ptr->src_peb = NULL;
		ptr->dst_peb = NULL;
		break;

	default:
		BUG();
	}

	memset(ptr->items, 0,
		sizeof(struct ssdfs_peb_info) * SSDFS_SEG_PEB_ITEMS_MAX);

	up_write(&ptr->lock);

	atomic_set(&ptr->migration_state, SSDFS_PEB_UNKNOWN_MIGRATION_STATE);
	atomic_set(&ptr->items_state, SSDFS_PEB_CONTAINER_EMPTY);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
}

/*
 * ssdfs_peb_container_prepare_relation() - prepare relation with destination
 * @ptr: pointer on PEB container
 *
 * This method tries to create the relation between source of @ptr
 * and existing destination in another PEB container.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_container_prepare_relation(struct ssdfs_peb_container *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_mapping_table *maptbl;
	struct ssdfs_migration_destination *destination;
	struct ssdfs_peb_container *relation;
	int shared_index;
	int destination_state;
	u16 peb_index, dst_peb_index;
	u64 leb_id, dst_leb_id;
	struct completion *end;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->src_peb);
	BUG_ON(!ptr->parent_si || !ptr->parent_si->fsi);
	BUG_ON(!mutex_is_locked(&ptr->migration_lock));

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  ptr,
		  ptr->peb_index,
		  ptr->peb_type,
		  ptr->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = ptr->parent_si->fsi;
	maptbl = fsi->maptbl;
	si = ptr->parent_si;
	peb_index = ptr->peb_index;

try_define_relation:
	destination = &si->migration.array[SSDFS_LAST_DESTINATION];

	spin_lock(&si->migration.lock);
	destination_state = destination->state;
	shared_index = destination->shared_peb_index;
	spin_unlock(&si->migration.lock);

	switch (destination_state) {
	case SSDFS_VALID_DESTINATION:
		/* do nothing here */
		break;

	case SSDFS_DESTINATION_UNDER_CREATION:
		/* FALLTHRU */
		fallthrough;
	case SSDFS_OBSOLETE_DESTINATION: {
			DEFINE_WAIT(wait);

			mutex_unlock(&ptr->migration_lock);
			prepare_to_wait(&ptr->migration_wq, &wait,
					TASK_UNINTERRUPTIBLE);
			schedule();
			finish_wait(&ptr->migration_wq, &wait);
			mutex_lock(&ptr->migration_lock);
			goto try_define_relation;
		}
		break;

	case SSDFS_EMPTY_DESTINATION:
		SSDFS_ERR("destination is empty\n");
		return -ERANGE;

	default:
		BUG();
	}

	if (shared_index < 0 || shared_index >= si->pebs_count) {
		SSDFS_ERR("invalid shared_index %d\n",
			  shared_index);
		return -ERANGE;
	}

	relation = &si->peb_array[shared_index];

	destination_state = atomic_read(&relation->migration_state);
	switch (destination_state) {
	case SSDFS_PEB_MIGRATION_PREPARATION:
		SSDFS_ERR("destination PEB is under preparation: "
			  "shared_index %d\n",
			  shared_index);
		return -ERANGE;

	case SSDFS_PEB_UNDER_MIGRATION:
		switch (atomic_read(&relation->items_state)) {
		case SSDFS_PEB1_DST_CONTAINER:
		case SSDFS_PEB2_DST_CONTAINER:
		case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
		case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
			/* do nothing */
			break;

		default:
			SSDFS_WARN("invalid relation state: "
				   "shared_index %d\n",
				   shared_index);
			return -ERANGE;
		}

		down_read(&relation->lock);

		if (!relation->dst_peb) {
			err = -ERANGE;
			SSDFS_ERR("dst_peb is NULL\n");
			goto finish_define_relation;
		}

		ptr->dst_peb = relation->dst_peb;
		atomic_inc(&relation->dst_peb_refs);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_id %llu, dst_peb_refs %d\n",
			  relation->dst_peb->peb_id,
			  atomic_read(&relation->dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */

finish_define_relation:
		up_read(&relation->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to define relation: "
				  "shared_index %d\n",
				  shared_index);
			return err;
		}

		leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
							si->seg_id,
							peb_index);
		if (leb_id >= U64_MAX) {
			SSDFS_ERR("fail to convert PEB index into LEB ID: "
				  "seg %llu, peb_index %u\n",
				  si->seg_id, peb_index);
			return -ERANGE;
		}

		dst_peb_index = ptr->dst_peb->peb_index;

		dst_leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
							    si->seg_id,
							    dst_peb_index);
		if (dst_leb_id >= U64_MAX) {
			SSDFS_ERR("fail to convert PEB index into LEB ID: "
				  "seg %llu, peb_index %u\n",
				  si->seg_id, peb_index);
			return -ERANGE;
		}

		err = ssdfs_maptbl_set_indirect_relation(maptbl,
							 leb_id,
							 ptr->peb_type,
							 dst_leb_id,
							 dst_peb_index,
							 &end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				ptr->dst_peb = NULL;
				atomic_dec(&relation->dst_peb_refs);
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("dst_peb_refs %d\n",
					  atomic_read(&relation->dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */
				return err;
			}

			err = ssdfs_maptbl_set_indirect_relation(maptbl,
								 leb_id,
								 ptr->peb_type,
								 dst_leb_id,
								 dst_peb_index,
								 &end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to set relation LEB to PEB: "
				  "leb_id %llu, dst_peb_index %u"
				  "err %d\n",
				  leb_id, dst_peb_index, err);
			ptr->dst_peb = NULL;
			atomic_dec(&relation->dst_peb_refs);
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("dst_peb_refs %d\n",
				  atomic_read(&relation->dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		}

		switch (atomic_read(&ptr->items_state)) {
		case SSDFS_PEB1_SRC_CONTAINER:
			atomic_set(&ptr->items_state,
				SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER);
			break;

		case SSDFS_PEB2_SRC_CONTAINER:
			atomic_set(&ptr->items_state,
				SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER);
			break;

		default:
			BUG();
		}
		break;

	case SSDFS_PEB_RELATION_PREPARATION:
		SSDFS_WARN("peb not migrating: "
			   "shared_index %d\n",
			   shared_index);
		return -ERANGE;

	case SSDFS_PEB_NOT_MIGRATING:
		SSDFS_WARN("peb not migrating: "
			   "shared_index %d\n",
			   shared_index);
		return -ERANGE;

	default:
		BUG();
	}

	return 0;
}

/*
 * __ssdfs_peb_container_prepare_destination() - prepare destination
 * @ptr: pointer on PEB container
 *
 * This method tries to create the destination PEB in requested
 * container.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - try to create a relation.
 */
static
int __ssdfs_peb_container_prepare_destination(struct ssdfs_peb_container *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_migration_destination *destination;
	struct ssdfs_maptbl_peb_relation pebr;
	struct ssdfs_peb_info *pebi;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int shared_index;
	int destination_state;
	int items_state;
	u16 peb_index;
	u64 leb_id;
	u64 peb_id;
	u64 seg;
	u32 log_pages;
	u8 peb_migration_id;
	struct completion *end;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->src_peb);
	BUG_ON(!ptr->parent_si || !ptr->parent_si->fsi);

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  ptr,
		  ptr->peb_index,
		  ptr->peb_type,
		  ptr->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = ptr->parent_si->fsi;
	si = ptr->parent_si;
	seg = si->seg_id;
	peb_index = ptr->peb_index;
	log_pages = ptr->log_pages;

	spin_lock(&si->migration.lock);
	destination = &si->migration.array[SSDFS_CREATING_DESTINATION];
	destination_state = destination->state;
	shared_index = destination->shared_peb_index;
	spin_unlock(&si->migration.lock);

	if (destination_state != SSDFS_DESTINATION_UNDER_CREATION &&
	    shared_index != ptr->peb_index) {
		SSDFS_ERR("destination_state %#x, "
			  "shared_index %d, "
			  "peb_index %u\n",
			  destination_state,
			  shared_index,
			  ptr->peb_index);
		return -ERANGE;
	}

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi, si->seg_id, peb_index);
	if (leb_id >= U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, peb_index);
		return -ERANGE;
	}

	err = ssdfs_maptbl_add_migration_peb(fsi, leb_id, ptr->peb_type,
					     &pebr, &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			goto fail_prepare_destination;
		}

		err = ssdfs_maptbl_add_migration_peb(fsi, leb_id,
						     ptr->peb_type,
						     &pebr, &end);
	}

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find PEB for migration: "
			  "leb_id %llu, peb_type %#x\n",
			  leb_id, ptr->peb_type);
#endif /* CONFIG_SSDFS_DEBUG */
		goto fail_prepare_destination;
	} else if (err == -EBUSY) {
		DEFINE_WAIT(wait);

wait_erase_operation_end:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("wait_erase_operation_end: "
			  "leb_id %llu, peb_type %#x\n",
			  leb_id, ptr->peb_type);
#endif /* CONFIG_SSDFS_DEBUG */

		wake_up_all(&fsi->maptbl->wait_queue);

		mutex_unlock(&ptr->migration_lock);
		prepare_to_wait(&fsi->maptbl->erase_ops_end_wq, &wait,
				TASK_UNINTERRUPTIBLE);
		schedule();
		finish_wait(&fsi->maptbl->erase_ops_end_wq, &wait);
		mutex_lock(&ptr->migration_lock);

		err = ssdfs_maptbl_add_migration_peb(fsi, leb_id, ptr->peb_type,
						     &pebr, &end);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find PEB for migration: "
				  "leb_id %llu, peb_type %#x\n",
				  leb_id, ptr->peb_type);
#endif /* CONFIG_SSDFS_DEBUG */
			goto fail_prepare_destination;
		} else if (err == -EBUSY) {
			/*
			 * We still have pre-erased PEBs.
			 * Let's wait more.
			 */
			goto wait_erase_operation_end;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add migration PEB: "
				  "leb_id %llu, peb_type %#x, "
				  "err %d\n",
				  leb_id, ptr->peb_type, err);
			goto fail_prepare_destination;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to add migration PEB: "
			  "leb_id %llu, peb_type %#x, "
			  "err %d\n",
			  leb_id, ptr->peb_type, err);
		goto fail_prepare_destination;
	}

	down_write(&ptr->lock);

	items_state = atomic_read(&ptr->items_state);

	switch (items_state) {
	case SSDFS_PEB1_SRC_CONTAINER:
		pebi = &ptr->items[SSDFS_SEG_PEB2];
		break;

	case SSDFS_PEB_CONTAINER_EMPTY:
	case SSDFS_PEB2_SRC_CONTAINER:
		pebi = &ptr->items[SSDFS_SEG_PEB1];
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid container state: %#x\n",
			  atomic_read(&ptr->items_state));
		goto finish_prepare_destination;
		break;
	};

	peb_id = pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX].peb_id;
	peb_migration_id = ssdfs_define_next_peb_migration_id(ptr->src_peb);
	if (!is_peb_migration_id_valid(peb_migration_id)) {
		err = -ERANGE;
		SSDFS_ERR("fail to define peb_migration_id\n");
		goto finish_prepare_destination;
	}

	err = ssdfs_peb_object_create(pebi, ptr, peb_id,
				      SSDFS_MAPTBL_CLEAN_PEB_STATE,
				      peb_migration_id);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create PEB object: "
			  "seg %llu, peb_index %u, "
			  "peb_id %llu\n",
			  seg, peb_index,
			  peb_id);
		goto finish_prepare_destination;
	}

	ptr->dst_peb = pebi;
	atomic_inc(&ptr->dst_peb_refs);

	atomic_set(&pebi->state,
		   SSDFS_PEB_OBJECT_INITIALIZED);
	complete_all(&pebi->init_end);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, dst_peb_refs %d\n",
		  pebi->peb_id,
		  atomic_read(&ptr->dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (items_state) {
	case SSDFS_PEB_CONTAINER_EMPTY:
		atomic_set(&ptr->items_state,
			   SSDFS_PEB1_DST_CONTAINER);
		break;

	case SSDFS_PEB1_SRC_CONTAINER:
		atomic_set(&ptr->items_state,
			   SSDFS_PEB1_SRC_PEB2_DST_CONTAINER);
		break;

	case SSDFS_PEB2_SRC_CONTAINER:
		atomic_set(&ptr->items_state,
			   SSDFS_PEB2_SRC_PEB1_DST_CONTAINER);
		break;

	default:
		BUG();
	}

	if (atomic_read(&ptr->items_state) == SSDFS_PEB1_DST_CONTAINER) {
		int free_blks;

		free_blks = ssdfs_peb_get_free_pages(ptr);
		if (unlikely(free_blks < 0)) {
			err = free_blks;
			SSDFS_ERR("fail to get free_blks: "
				  "peb_index %u, err %d\n",
				  ptr->peb_index, err);
			goto finish_prepare_destination;
		} else if (free_blks == 0) {
			err = -ERANGE;
			SSDFS_ERR("PEB hasn't free blocks\n");
			goto finish_prepare_destination;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(free_blks >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		atomic_set(&ptr->shared_free_dst_blks, (u16)free_blks);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("shared_free_dst_blks %d\n",
			  atomic_read(&ptr->shared_free_dst_blks));
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
		if (ptr->peb_index >= si->blk_bmap.pebs_count) {
			err = -ERANGE;
			SSDFS_ERR("peb_index %u >= pebs_count %u\n",
				  ptr->peb_index,
				  si->blk_bmap.pebs_count);
			goto finish_prepare_destination;
		}

		peb_blkbmap = &si->blk_bmap.peb[ptr->peb_index];
		err = ssdfs_peb_blk_bmap_start_migration(peb_blkbmap);
		if (unlikely(err)) {
			SSDFS_ERR("fail to start PEB's block bitmap migration: "
				  "seg %llu, peb_index %u, err %d\n",
				  si->seg_id, ptr->peb_index, err);
			goto finish_prepare_destination;
		}
	}

finish_prepare_destination:
	up_write(&ptr->lock);

	if (unlikely(err))
		goto fail_prepare_destination;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_container_prepare_destination: "
		  "seg_id %llu, leb_id %llu, peb_id %llu, "
		  "free_blks %d, used_blks %d, invalid_blks %d\n",
		  si->seg_id, leb_id, peb_id,
		  ssdfs_peb_get_free_pages(ptr),
		  ssdfs_peb_get_used_data_pages(ptr),
		  ssdfs_peb_get_invalid_pages(ptr));
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&si->migration.lock);
	ssdfs_memcpy(&si->migration.array[SSDFS_LAST_DESTINATION],
		     0, sizeof(struct ssdfs_migration_destination),
		     &si->migration.array[SSDFS_CREATING_DESTINATION],
		     0, sizeof(struct ssdfs_migration_destination),
		     sizeof(struct ssdfs_migration_destination));
	destination = &si->migration.array[SSDFS_LAST_DESTINATION];
	destination->state = SSDFS_VALID_DESTINATION;
	memset(&si->migration.array[SSDFS_CREATING_DESTINATION],
		0xFF, sizeof(struct ssdfs_migration_destination));
	destination = &si->migration.array[SSDFS_CREATING_DESTINATION];
	destination->state = SSDFS_EMPTY_DESTINATION;
	spin_unlock(&si->migration.lock);

	return 0;

fail_prepare_destination:
	spin_lock(&si->migration.lock);

	destination = &si->migration.array[SSDFS_CREATING_DESTINATION];
	destination->state = SSDFS_EMPTY_DESTINATION;
	destination->shared_peb_index = -1;

	destination = &si->migration.array[SSDFS_LAST_DESTINATION];
	switch (destination->state) {
	case SSDFS_OBSOLETE_DESTINATION:
		destination->state = SSDFS_VALID_DESTINATION;
		break;

	case SSDFS_EMPTY_DESTINATION:
		/* do nothing */
		break;

	case SSDFS_VALID_DESTINATION:
		SSDFS_DBG("old destination is valid\n");
		break;

	default:
		BUG();
	};

	spin_unlock(&si->migration.lock);

	return err;
}

/*
 * ssdfs_peb_container_prepare_zns_destination() - prepare ZNS destination
 * @ptr: pointer on PEB container
 *
 * This method tries to create relation with shared segment for
 * user data updates.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - try to create a relation.
 */
static
int ssdfs_peb_container_prepare_zns_destination(struct ssdfs_peb_container *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_current_segment *cur_seg;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_info *dest_si = NULL;
	struct ssdfs_peb_mapping_table *maptbl;
	u64 start = U64_MAX;
	int seg_type = SSDFS_USER_DATA_SEG_TYPE;
	u16 peb_index, dst_peb_index;
	u64 leb_id, dst_leb_id;
	struct completion *end;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->src_peb);
	BUG_ON(!ptr->parent_si || !ptr->parent_si->fsi);
	BUG_ON(!mutex_is_locked(&ptr->migration_lock));

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  ptr,
		  ptr->peb_index,
		  ptr->peb_type,
		  ptr->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = ptr->parent_si->fsi;
	maptbl = fsi->maptbl;
	si = ptr->parent_si;
	peb_index = ptr->peb_index;

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi, si->seg_id, peb_index);
	if (leb_id >= U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, peb_index);
		return -ERANGE;
	}

	down_read(&fsi->cur_segs->lock);

	cur_seg = fsi->cur_segs->objects[SSDFS_CUR_DATA_UPDATE_SEG];

	ssdfs_current_segment_lock(cur_seg);

	if (is_ssdfs_current_segment_empty(cur_seg)) {
		start = cur_seg->seg_id;
		dest_si = ssdfs_grab_segment(fsi, seg_type, U64_MAX, start);
		if (IS_ERR_OR_NULL(dest_si)) {
			err = (dest_si == NULL ? -ENOMEM : PTR_ERR(dest_si));
			if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to create segment object: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
				SSDFS_ERR("fail to create segment object: "
					  "err %d\n", err);
			}

			goto finish_get_current_segment;
		}

		err = ssdfs_current_segment_add(cur_seg, dest_si);
		/*
		 * ssdfs_grab_segment() has got object already.
		 */
		ssdfs_segment_put_object(dest_si);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add segment %llu as current: "
				  "err %d\n",
				  dest_si->seg_id, err);
			goto finish_get_current_segment;
		}
	}

	dst_peb_index = 0;
	dst_leb_id = ssdfs_get_leb_id_for_peb_index(fsi, dest_si->seg_id, dst_peb_index);
	if (leb_id >= U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  dest_si->seg_id, dst_peb_index);
		return -ERANGE;
	}

finish_get_current_segment:
	ssdfs_current_segment_unlock(cur_seg);
	up_read(&fsi->cur_segs->lock);

	if (unlikely(err))
		return err;

	err = ssdfs_maptbl_set_zns_indirect_relation(maptbl,
						     leb_id,
						     ptr->peb_type,
						     &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			ptr->dst_peb = NULL;
			return err;
		}

		err = ssdfs_maptbl_set_zns_indirect_relation(maptbl,
							     leb_id,
							     ptr->peb_type,
							     &end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to set relation LEB to PEB: "
			  "leb_id %llu, dst leb_id %llu"
			  "err %d\n",
			  leb_id, dst_leb_id, err);
		ptr->dst_peb = NULL;
		return err;
	}

	switch (atomic_read(&ptr->items_state)) {
	case SSDFS_PEB1_SRC_CONTAINER:
		atomic_set(&ptr->items_state,
			SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER);
		break;

	case SSDFS_PEB2_SRC_CONTAINER:
		atomic_set(&ptr->items_state,
			SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER);
		break;

	default:
		BUG();
	}

	return 0;
}

/*
 * ssdfs_peb_container_prepare_destination() - prepare destination
 * @ptr: pointer on PEB container
 *
 * This method tries to create the destination PEB in requested
 * container.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - try to create a relation.
 */
static
int ssdfs_peb_container_prepare_destination(struct ssdfs_peb_container *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->src_peb);
	BUG_ON(!ptr->parent_si || !ptr->parent_si->fsi);

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  ptr,
		  ptr->peb_index,
		  ptr->peb_type,
		  ptr->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = ptr->parent_si->fsi;
	si = ptr->parent_si;

	if (fsi->is_zns_device && is_ssdfs_peb_containing_user_data(ptr))
		err = ssdfs_peb_container_prepare_zns_destination(ptr);
	else
		err = __ssdfs_peb_container_prepare_destination(ptr);

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to prepare destination: "
			  "seg %llu, peb_index %u, err %d\n",
			  si->seg_id, ptr->peb_index, err);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to prepare destination: "
			  "seg %llu, peb_index %u, err %d\n",
			  si->seg_id, ptr->peb_index, err);
	}

	return err;
}

/*
 * ssdfs_peb_container_create_destination() - create destination
 * @ptr: pointer on PEB container
 *
 * This method tries to create the destination or relation
 * with another PEB container.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_container_create_destination(struct ssdfs_peb_container *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *relation;
	struct ssdfs_migration_destination *destination;
	bool need_create_relation = false;
	u16 migration_threshold;
	u16 pebs_per_destination;
	u16 destination_index;
	int migration_state;
	int items_state;
	int destination_pebs;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->src_peb);
	BUG_ON(!ptr->parent_si || !ptr->parent_si->fsi);
	BUG_ON(!mutex_is_locked(&ptr->migration_lock));

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  ptr,
		  ptr->peb_index,
		  ptr->peb_type,
		  ptr->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = ptr->parent_si->fsi;
	si = ptr->parent_si;

	spin_lock(&fsi->volume_state_lock);
	migration_threshold = fsi->migration_threshold;
	spin_unlock(&fsi->volume_state_lock);

	migration_state = atomic_read(&ptr->migration_state);

	if (migration_state != SSDFS_PEB_NOT_MIGRATING) {
		err = -ERANGE;
		SSDFS_ERR("invalid migration_state %#x\n",
			  migration_state);
		goto finish_create_destination;
	}

	items_state = atomic_read(&ptr->items_state);

	if (items_state != SSDFS_PEB1_SRC_CONTAINER &&
	    items_state != SSDFS_PEB2_SRC_CONTAINER) {
		err = -ERANGE;
		SSDFS_ERR("invalid items_state %#x\n",
			  items_state);
		goto finish_create_destination;
	}

	pebs_per_destination = fsi->pebs_per_seg / migration_threshold;
	destination_index =
		atomic_inc_return(&si->migration.migrating_pebs) - 1;
	destination_index /= pebs_per_destination;

try_start_preparation_again:
	spin_lock(&si->migration.lock);

	destination = &si->migration.array[SSDFS_LAST_DESTINATION];

	switch (destination->state) {
	case SSDFS_EMPTY_DESTINATION:
		need_create_relation = false;
		destination = &si->migration.array[SSDFS_CREATING_DESTINATION];
		destination->state = SSDFS_DESTINATION_UNDER_CREATION;
		destination->destination_pebs++;
		destination->shared_peb_index = ptr->peb_index;
		break;

	case SSDFS_VALID_DESTINATION:
		destination_pebs = destination->destination_pebs;
		need_create_relation = destination_index < destination_pebs;

		if (need_create_relation) {
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(destination_index >= si->pebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

			relation = &si->peb_array[destination_index];
			if (atomic_read(&relation->shared_free_dst_blks) <= 0) {
				/* destination hasn't free room */
				need_create_relation = false;
			}
		}

		if (!need_create_relation) {
			destination =
			    &si->migration.array[SSDFS_CREATING_DESTINATION];
			destination->state = SSDFS_DESTINATION_UNDER_CREATION;
			destination->destination_pebs++;
			destination->shared_peb_index = ptr->peb_index;
		}
		break;

	case SSDFS_OBSOLETE_DESTINATION:
		destination = &si->migration.array[SSDFS_CREATING_DESTINATION];

		if (destination->state != SSDFS_DESTINATION_UNDER_CREATION) {
			err = -ERANGE;
			SSDFS_WARN("invalid destination state %#x\n",
				   destination->state);
			goto finish_check_destination;
		}

		destination_pebs = destination->destination_pebs;
		need_create_relation = destination_index < destination_pebs;

		if (!need_create_relation)
			err = -EAGAIN;
		break;

	default:
		BUG();
	};

finish_check_destination:
	spin_unlock(&si->migration.lock);

	if (err == -EAGAIN) {
		DEFINE_WAIT(wait);

		mutex_unlock(&ptr->migration_lock);
		prepare_to_wait(&ptr->migration_wq, &wait,
				TASK_UNINTERRUPTIBLE);
		schedule();
		finish_wait(&ptr->migration_wq, &wait);
		mutex_lock(&ptr->migration_lock);
		err = 0;
		goto try_start_preparation_again;
	} else if (unlikely(err))
		goto finish_create_destination;

	if (need_create_relation) {
create_relation:
		atomic_set(&ptr->migration_state,
			    SSDFS_PEB_RELATION_PREPARATION);

		err = ssdfs_peb_container_prepare_relation(ptr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare relation: "
				  "err %d\n",
				  err);
			goto finish_create_destination;
		}

		atomic_set(&ptr->migration_state,
			    SSDFS_PEB_UNDER_MIGRATION);
	} else {
		atomic_set(&ptr->migration_state,
			    SSDFS_PEB_MIGRATION_PREPARATION);

		err = ssdfs_peb_container_prepare_destination(ptr);
		if (err == -ENODATA) {
			err = 0;
			goto create_relation;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to prepare destination: "
				  "err %d\n",
				  err);
			goto finish_create_destination;
		}

		atomic_set(&ptr->migration_state,
			    SSDFS_PEB_UNDER_MIGRATION);
	}

finish_create_destination:
	if (unlikely(err)) {
		atomic_set(&ptr->migration_state, migration_state);
		atomic_dec(&si->migration.migrating_pebs);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("migration_state %d\n",
		  atomic_read(&ptr->migration_state));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_peb_container_move_dest2source() - convert destination into source
 * @ptr: pointer on PEB container
 * @state: current state of items
 *
 * This method tries to transform destination PEB
 * into source PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - destination PEB has references.
 */
static
int ssdfs_peb_container_move_dest2source(struct ssdfs_peb_container *ptr,
					 int state)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_migration_info *mi;
	struct ssdfs_migration_destination *mdest;
	int new_state;
	u64 leb_id;
	u64 peb_create_time = U64_MAX;
	u64 last_log_time = U64_MAX;
	struct completion *end;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->src_peb);
	BUG_ON(!ptr->parent_si || !ptr->parent_si->fsi);
	BUG_ON(!rwsem_is_locked(&ptr->lock));

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "peb_type %#x, log_pages %u, "
		  "state %#x\n",
		  ptr,
		  ptr->peb_index,
		  ptr->peb_type,
		  ptr->log_pages,
		  state);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = ptr->parent_si->fsi;
	si = ptr->parent_si;

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
						si->seg_id,
						ptr->peb_index);
	if (leb_id >= U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, ptr->peb_index);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, dst_peb_refs %d\n",
		  ptr->dst_peb->peb_id,
		  atomic_read(&ptr->dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&ptr->dst_peb_refs) > 1) {
		/* wait of absence of references */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("leb_id %llu, peb_index %u, "
			  "refs_count %u\n",
			  leb_id, ptr->peb_index,
			  atomic_read(&ptr->dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	switch (state) {
	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		new_state = SSDFS_PEB1_SRC_CONTAINER;
		break;

	case SSDFS_PEB2_DST_CONTAINER:
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
		new_state = SSDFS_PEB2_SRC_CONTAINER;
		break;

	default:
		SSDFS_WARN("invalid state: %#x\n",
			   state);
		return -ERANGE;
	}

	if (ptr->src_peb) {
		peb_create_time = ptr->src_peb->peb_create_time;

		ssdfs_peb_current_log_lock(ptr->src_peb);
		last_log_time = ptr->src_peb->current_log.last_log_time;
		ssdfs_peb_current_log_unlock(ptr->src_peb);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg %llu, peb %llu, "
			  "peb_create_time %llx, last_log_time %llx\n",
			  si->seg_id,
			  ptr->src_peb->peb_id,
			  peb_create_time,
			  last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
		peb_create_time = ptr->dst_peb->peb_create_time;

		ssdfs_peb_current_log_lock(ptr->dst_peb);
		last_log_time = ptr->dst_peb->current_log.last_log_time;
		ssdfs_peb_current_log_unlock(ptr->dst_peb);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg %llu, peb %llu, "
			  "peb_create_time %llx, last_log_time %llx\n",
			  si->seg_id,
			  ptr->dst_peb->peb_id,
			  peb_create_time,
			  last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	err = ssdfs_maptbl_exclude_migration_peb(fsi, leb_id,
						 ptr->peb_type,
						 peb_create_time,
						 last_log_time,
						 &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_maptbl_exclude_migration_peb(fsi, leb_id,
							 ptr->peb_type,
							 peb_create_time,
							 last_log_time,
							 &end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to exclude migration PEB: "
			  "leb_id %llu, peb_type %#x, err %d\n",
			  leb_id, ptr->peb_type, err);
		return err;
	}

	atomic_dec(&si->peb_array[ptr->dst_peb->peb_index].dst_peb_refs);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, leb_id %llu, "
		  "peb_id %llu, dst_peb_refs %d\n",
	    si->seg_id, leb_id,
	    ptr->dst_peb->peb_id,
	    atomic_read(&si->peb_array[ptr->dst_peb->peb_index].dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */

	if (ptr->src_peb) {
		err = ssdfs_peb_object_destroy(ptr->src_peb);
		WARN_ON(err);
		err = 0;
	}

	memset(ptr->src_peb, 0, sizeof(struct ssdfs_peb_info));
	ptr->src_peb = ptr->dst_peb;
	ptr->dst_peb = NULL;

	atomic_set(&ptr->items_state, new_state);
	atomic_set(&ptr->migration_state, SSDFS_PEB_NOT_MIGRATING);

	mi = &ptr->parent_si->migration;
	spin_lock(&mi->lock);
	atomic_dec(&mi->migrating_pebs);
	mdest = &mi->array[SSDFS_LAST_DESTINATION];
	switch (mdest->state) {
	case SSDFS_VALID_DESTINATION:
	case SSDFS_OBSOLETE_DESTINATION:
		mdest->destination_pebs--;
		break;
	};
	mdest = &mi->array[SSDFS_CREATING_DESTINATION];
	switch (mdest->state) {
	case SSDFS_DESTINATION_UNDER_CREATION:
		mdest->destination_pebs--;
		break;
	};
	spin_unlock(&mi->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_peb_container_break_relation() - break relation with PEB
 * @ptr: pointer on PEB container
 * @state: current state of items
 * @new_state: new state of items
 *
 * This method tries to break relation with destination PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_container_break_relation(struct ssdfs_peb_container *ptr,
					int state, int new_state)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_mapping_table *maptbl;
	u64 leb_id, dst_leb_id;
	u16 dst_peb_index;
	int dst_peb_refs;
	struct completion *end;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->src_peb || !ptr->dst_peb);
	BUG_ON(!ptr->parent_si || !ptr->parent_si->fsi);
	BUG_ON(!rwsem_is_locked(&ptr->lock));

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "peb_type %#x, log_pages %u, "
		  "state %#x, new_state %#x\n",
		  ptr,
		  ptr->peb_index,
		  ptr->peb_type,
		  ptr->log_pages,
		  state, new_state);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = ptr->parent_si->fsi;
	si = ptr->parent_si;
	maptbl = fsi->maptbl;

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
						si->seg_id,
						ptr->peb_index);
	if (leb_id >= U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, ptr->peb_index);
		return -ERANGE;
	}

	dst_peb_index = ptr->dst_peb->peb_index;

	dst_leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
						    si->seg_id,
						    dst_peb_index);
	if (dst_leb_id >= U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, dst_peb_index);
		return -ERANGE;
	}

	dst_peb_refs = atomic_read(&si->peb_array[dst_peb_index].dst_peb_refs);

	err = ssdfs_maptbl_break_indirect_relation(maptbl,
						   leb_id,
						   ptr->peb_type,
						   dst_leb_id,
						   dst_peb_refs,
						   &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_maptbl_break_indirect_relation(maptbl,
							   leb_id,
							   ptr->peb_type,
							   dst_leb_id,
							   dst_peb_refs,
							   &end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to break relation: "
			  "leb_id %llu, peb_index %u, err %d\n",
			  leb_id, ptr->peb_index, err);
		return err;
	}

	atomic_dec(&si->peb_array[ptr->dst_peb->peb_index].dst_peb_refs);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, dst_peb_refs %d\n",
	    ptr->dst_peb->peb_id,
	    atomic_read(&si->peb_array[ptr->dst_peb->peb_index].dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */

	if (new_state == SSDFS_PEB_CONTAINER_EMPTY) {
		err = ssdfs_peb_object_destroy(ptr->src_peb);
		WARN_ON(err);
		err = 0;

		memset(ptr->src_peb, 0, sizeof(struct ssdfs_peb_info));
	} else
		ptr->dst_peb = NULL;

	atomic_set(&ptr->items_state, new_state);
	atomic_set(&ptr->migration_state, SSDFS_PEB_NOT_MIGRATING);
	atomic_dec(&ptr->parent_si->migration.migrating_pebs);

	return 0;
}

/*
 * ssdfs_peb_container_break_zns_relation() - break relation with PEB
 * @ptr: pointer on PEB container
 * @state: current state of items
 * @new_state: new state of items
 *
 * This method tries to break relation with shared zone.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_container_break_zns_relation(struct ssdfs_peb_container *ptr,
					   int state, int new_state)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_mapping_table *maptbl;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_invextree_info *invextree;
	struct ssdfs_btree_search *search;
	struct ssdfs_raw_extent extent;
	u64 leb_id;
	int invalid_blks;
	struct completion *end;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->src_peb || !ptr->dst_peb);
	BUG_ON(!ptr->parent_si || !ptr->parent_si->fsi);
	BUG_ON(!rwsem_is_locked(&ptr->lock));

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "peb_type %#x, log_pages %u, "
		  "state %#x, new_state %#x\n",
		  ptr,
		  ptr->peb_index,
		  ptr->peb_type,
		  ptr->log_pages,
		  state, new_state);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = ptr->parent_si->fsi;
	si = ptr->parent_si;
	maptbl = fsi->maptbl;
	seg_blkbmap = &si->blk_bmap;

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
						si->seg_id,
						ptr->peb_index);
	if (leb_id >= U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, ptr->peb_index);
		return -ERANGE;
	}

	err = ssdfs_maptbl_break_zns_indirect_relation(maptbl,
						       leb_id,
						       ptr->peb_type,
						       &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_maptbl_break_zns_indirect_relation(maptbl,
								leb_id,
								ptr->peb_type,
								&end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to break relation: "
			  "leb_id %llu, peb_index %u, err %d\n",
			  leb_id, ptr->peb_index, err);
		return err;
	}

	invextree = fsi->invextree;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!invextree);
#endif /* CONFIG_SSDFS_DEBUG */

	invalid_blks = ssdfs_segment_blk_bmap_get_invalid_pages(seg_blkbmap);
	if (invalid_blks <= 0) {
		SSDFS_ERR("invalid state: "
			  "leb_id %llu, invalid_blks %d\n",
			  leb_id, invalid_blks);
		return -ERANGE;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	extent.seg_id = cpu_to_le64(si->seg_id);
	extent.logical_blk = cpu_to_le32(0);
	extent.len = cpu_to_le32(invalid_blks);

	ssdfs_btree_search_init(search);
	err = ssdfs_invextree_delete(invextree, &extent, search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to delete invalidated extent: "
			  "leb_id %llu, len %d, err %d\n",
			  leb_id, invalid_blks, err);
		return err;
	}

	if (new_state == SSDFS_PEB_CONTAINER_EMPTY) {
		err = ssdfs_peb_object_destroy(ptr->src_peb);
		WARN_ON(err);
		err = 0;

		memset(ptr->src_peb, 0, sizeof(struct ssdfs_peb_info));
	} else
		ptr->dst_peb = NULL;

	atomic_set(&ptr->items_state, new_state);
	atomic_set(&ptr->migration_state, SSDFS_PEB_NOT_MIGRATING);
	atomic_dec(&ptr->parent_si->migration.migrating_pebs);

	return 0;
}

/*
 * ssdfs_peb_container_forget_source() - forget about dirty source PEB
 * @ptr: pointer on PEB container
 *
 * This method tries to forget about dirty source PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_container_forget_source(struct ssdfs_peb_container *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_migration_info *mi;
	struct ssdfs_migration_destination *mdest;
	struct ssdfs_peb_mapping_table *maptbl;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	int migration_state;
	int items_state;
	u64 leb_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->src_peb);
	BUG_ON(!ptr->parent_si || !ptr->parent_si->fsi);
	BUG_ON(!mutex_is_locked(&ptr->migration_lock));

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  ptr,
		  ptr->peb_index,
		  ptr->peb_type,
		  ptr->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = ptr->parent_si->fsi;
	si = ptr->parent_si;
	maptbl = fsi->maptbl;

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
						si->seg_id,
						ptr->peb_index);
	if (leb_id >= U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, ptr->peb_index);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (rwsem_is_locked(&ptr->lock)) {
		SSDFS_DBG("PEB is locked: "
			  "leb_id %llu\n", leb_id);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&ptr->lock);

	migration_state = atomic_read(&ptr->migration_state);
	if (migration_state != SSDFS_PEB_FINISHING_MIGRATION) {
		err = -ERANGE;
		SSDFS_WARN("invalid migration_state %#x\n",
			   migration_state);
		goto finish_forget_source;
	}

	items_state = atomic_read(&ptr->items_state);
	switch (items_state) {
	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		/* valid state */
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		goto finish_forget_source;
	};

/*
 *       You cannot move destination into source PEB and
 *       try to create another one destination for existing
 *       relations. Otherwise, you will have two full PEBs
 *       for the same peb_index. So, in the case of full
 *       destination PEB and presence of relation with another
 *       source PEB it needs to wake up all threads and to wait
 *       decreasing the dst_peb_refs counter.
 */

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_state %#x\n", items_state);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (items_state) {
	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(ptr->src_peb);
		BUG_ON(!ptr->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_peb_container_move_dest2source(ptr,
							   items_state);
		if (err == -ENODATA)
			goto finish_forget_source;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to transform destination: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_forget_source;
		}

		WARN_ON(atomic_read(&ptr->shared_free_dst_blks) > 0);
		break;

	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!ptr->src_peb);
		BUG_ON(!ptr->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_peb_container_move_dest2source(ptr,
							   items_state);
		if (err == -ENODATA)
			goto finish_forget_source;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to transform destination: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			goto finish_forget_source;
		}

		if (ptr->peb_index >= si->blk_bmap.pebs_count) {
			err = -ERANGE;
			SSDFS_ERR("peb_index %u >= pebs_count %u\n",
				  ptr->peb_index,
				  si->blk_bmap.pebs_count);
			goto finish_forget_source;
		}

		peb_blkbmap = &si->blk_bmap.peb[ptr->peb_index];
		err = ssdfs_peb_blk_bmap_finish_migration(peb_blkbmap);
		if (unlikely(err)) {
			SSDFS_ERR("fail to finish bmap migration: "
				  "seg %llu, peb_index %u, err %d\n",
				  ptr->parent_si->seg_id,
				  ptr->peb_index, err);
			goto finish_forget_source;
		}
		break;

	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER: {
		int new_state = SSDFS_PEB_CONTAINER_STATE_MAX;
		int used_blks;
		bool has_valid_blks = true;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!ptr->src_peb);
		BUG_ON(!ptr->dst_peb);
		BUG_ON(atomic_read(&ptr->dst_peb_refs) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

		used_blks = ssdfs_peb_get_used_data_pages(ptr);
		if (used_blks < 0) {
			err = used_blks;
			SSDFS_ERR("fail to get used_blks: "
				  "seg %llu, peb_index %u, err %d\n",
				  ptr->parent_si->seg_id,
				  ptr->peb_index, err);
			goto finish_forget_source;
		}

		has_valid_blks = used_blks > 0;

		switch (items_state) {
		case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
			if (has_valid_blks)
				new_state = SSDFS_PEB1_SRC_CONTAINER;
			else
				new_state = SSDFS_PEB_CONTAINER_EMPTY;
			break;

		case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
			if (has_valid_blks)
				new_state = SSDFS_PEB2_SRC_CONTAINER;
			else
				new_state = SSDFS_PEB_CONTAINER_EMPTY;
			break;

		default:
			err = -ERANGE;
			SSDFS_WARN("invalid state: %#x\n",
				   new_state);
			goto finish_forget_source;
		}

		if (fsi->is_zns_device) {
			err = ssdfs_peb_container_break_zns_relation(ptr,
								 items_state,
								 new_state);
		} else {
			err = ssdfs_peb_container_break_relation(ptr,
								 items_state,
								 new_state);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to break relation: "
				  "leb_id %llu, items_state %#x"
				  "new_state %#x\n",
				  leb_id, items_state, new_state);
			goto finish_forget_source;
		}

		if (new_state != SSDFS_PEB_CONTAINER_EMPTY) {
			/* try create new destination */
			err = -ENOENT;
			goto finish_forget_source;
		}
		break;
	}

	default:
		BUG();
	};

finish_forget_source:
	up_write(&ptr->lock);

	if (err == -ENOENT) { /* create new destination or relation */
		err = ssdfs_peb_container_create_destination(ptr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create destination: "
				  "leb_id %llu, err %d\n",
				  leb_id, err);
			return err;
		}
	} else if (err == -ENODATA) {
		wake_up_all(&si->wait_queue[SSDFS_PEB_FLUSH_THREAD]);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("dst_peb_refs %d\n",
			  atomic_read(&ptr->dst_peb_refs));
#endif /* CONFIG_SSDFS_DEBUG */

		while (atomic_read(&ptr->dst_peb_refs) > 1) {
			DEFINE_WAIT(wait);

			mutex_unlock(&ptr->migration_lock);
			prepare_to_wait(&ptr->migration_wq, &wait,
					TASK_UNINTERRUPTIBLE);
			schedule();
			finish_wait(&ptr->migration_wq, &wait);
			mutex_lock(&ptr->migration_lock);
		};

		down_write(&ptr->lock);

		ptr->src_peb = ptr->dst_peb;
		ptr->dst_peb = NULL;

		switch (items_state) {
		case SSDFS_PEB1_DST_CONTAINER:
		case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
			atomic_set(&ptr->items_state, SSDFS_PEB1_SRC_CONTAINER);
			break;

		case SSDFS_PEB2_DST_CONTAINER:
		case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
			atomic_set(&ptr->items_state, SSDFS_PEB2_SRC_CONTAINER);
			break;

		default:
			BUG();
		};

		atomic_set(&ptr->migration_state, SSDFS_PEB_NOT_MIGRATING);

		up_write(&ptr->lock);

		mi = &ptr->parent_si->migration;
		spin_lock(&mi->lock);
		atomic_dec(&mi->migrating_pebs);
		mdest = &mi->array[SSDFS_LAST_DESTINATION];
		switch (mdest->state) {
		case SSDFS_VALID_DESTINATION:
		case SSDFS_OBSOLETE_DESTINATION:
			mdest->destination_pebs--;
			break;
		};
		mdest = &mi->array[SSDFS_CREATING_DESTINATION];
		switch (mdest->state) {
		case SSDFS_DESTINATION_UNDER_CREATION:
			mdest->destination_pebs--;
			break;
		};
		spin_unlock(&mi->lock);
	} else if (unlikely(err))
		return err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_peb_container_forget_relation() - forget about relation
 * @ptr: pointer on PEB container
 *
 * This method tries to forget about relation with
 * destination PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_container_forget_relation(struct ssdfs_peb_container *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_mapping_table *maptbl;
	int migration_state;
	int items_state;
	u64 leb_id;
	int new_state = SSDFS_PEB_CONTAINER_STATE_MAX;
	int used_blks;
	bool has_valid_blks = true;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ptr->src_peb);
	BUG_ON(!ptr->parent_si || !ptr->parent_si->fsi);
	BUG_ON(!ptr->dst_peb);
	BUG_ON(atomic_read(&ptr->dst_peb_refs) != 0);

	SSDFS_DBG("ptr %p, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  ptr,
		  ptr->peb_index,
		  ptr->peb_type,
		  ptr->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = ptr->parent_si->fsi;
	si = ptr->parent_si;
	maptbl = fsi->maptbl;

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
						si->seg_id,
						ptr->peb_index);
	if (leb_id >= U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, ptr->peb_index);
		return -ERANGE;
	}

	down_write(&ptr->lock);

	migration_state = atomic_read(&ptr->migration_state);
	if (migration_state != SSDFS_PEB_FINISHING_MIGRATION) {
		err = -ERANGE;
		SSDFS_WARN("invalid migration_state %#x\n",
			   migration_state);
		goto finish_forget_relation;
	}

	used_blks = ssdfs_peb_get_used_data_pages(ptr);
	if (used_blks < 0) {
		err = used_blks;
		SSDFS_ERR("fail to get used_blks: "
			  "seg %llu, peb_index %u, err %d\n",
			  ptr->parent_si->seg_id,
			  ptr->peb_index, err);
		goto finish_forget_relation;
	}

	has_valid_blks = used_blks > 0;

	items_state = atomic_read(&ptr->items_state);
	switch (items_state) {
	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
		if (has_valid_blks)
			new_state = SSDFS_PEB1_SRC_CONTAINER;
		else
			new_state = SSDFS_PEB_CONTAINER_EMPTY;
		break;

	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		if (has_valid_blks)
			new_state = SSDFS_PEB2_SRC_CONTAINER;
		else
			new_state = SSDFS_PEB_CONTAINER_EMPTY;
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		goto finish_forget_relation;
	};

	err = ssdfs_peb_container_break_relation(ptr,
						 items_state,
						 new_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to break relation: "
			  "leb_id %llu, items_state %#x"
			  "new_state %#x\n",
			  leb_id, items_state, new_state);
	}

finish_forget_relation:
	up_write(&ptr->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_get_current_peb_locked() - lock PEB container and get PEB object
 * @pebc: pointer on PEB container
 */
struct ssdfs_peb_info *
ssdfs_get_current_peb_locked(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_info *pebi = NULL;
	bool is_peb_exhausted;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;

try_get_current_peb:
	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_NOT_MIGRATING:
		down_read(&pebc->lock);
		pebi = pebc->src_peb;
		if (!pebi) {
			err = -ERANGE;
			SSDFS_WARN("source PEB is NULL\n");
			goto fail_to_get_current_peb;
		}

		atomic_set(&pebc->migration_phase,
				SSDFS_PEB_MIGRATION_STATUS_UNKNOWN);
		break;

	case SSDFS_PEB_UNDER_MIGRATION:
		down_read(&pebc->lock);

		pebi = pebc->src_peb;
		if (!pebi) {
			err = -ERANGE;
			SSDFS_WARN("source PEB is NULL\n");
			goto fail_to_get_current_peb;
		}

		ssdfs_peb_current_log_lock(pebi);
		is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
		ssdfs_peb_current_log_unlock(pebi);

		if (is_peb_exhausted) {
			if (fsi->is_zns_device &&
			    is_ssdfs_peb_containing_user_data(pebc)) {
				atomic_set(&pebc->migration_phase,
					    SSDFS_SHARED_ZONE_RECEIVES_DATA);
			} else {
				pebi = pebc->dst_peb;
				if (!pebi) {
					err = -ERANGE;
					SSDFS_WARN("destination PEB is NULL\n");
					goto fail_to_get_current_peb;
				}

				atomic_set(&pebc->migration_phase,
						SSDFS_DST_PEB_RECEIVES_DATA);
			}
		} else {
			atomic_set(&pebc->migration_phase,
					SSDFS_SRC_PEB_NOT_EXHAUSTED);
		}
		break;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
	case SSDFS_PEB_FINISHING_MIGRATION: {
			DEFINE_WAIT(wait);

			prepare_to_wait(&pebc->migration_wq, &wait,
					TASK_UNINTERRUPTIBLE);
			schedule();
			finish_wait(&pebc->migration_wq, &wait);
			goto try_get_current_peb;
		}
		break;

	default:
		SSDFS_WARN("invalid state: %#x\n",
			   atomic_read(&pebc->migration_state));
		return ERR_PTR(-ERANGE);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, "
		  "migration_state %#x, migration_phase %#x\n",
		  pebc->parent_si->seg_id,
		  pebi->peb_id,
		  atomic_read(&pebc->migration_state),
		  atomic_read(&pebc->migration_phase));
#endif /* CONFIG_SSDFS_DEBUG */

	return pebi;

fail_to_get_current_peb:
	up_read(&pebc->lock);
	return ERR_PTR(err);
}

/*
 * ssdfs_unlock_current_peb() - unlock source and destination PEB objects
 * @pebc: pointer on PEB container
 */
void ssdfs_unlock_current_peb(struct ssdfs_peb_container *pebc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!rwsem_is_locked(&pebc->lock)) {
		SSDFS_WARN("PEB container hasn't been locked: "
			   "seg %llu, peb_index %u\n",
			   pebc->parent_si->seg_id,
			   pebc->peb_index);
	} else
		up_read(&pebc->lock);
}

/*
 * ssdfs_get_peb_for_migration_id() - get PEB object for migration ID
 * @pebc: pointer on PEB container
 */
struct ssdfs_peb_info *
ssdfs_get_peb_for_migration_id(struct ssdfs_peb_container *pebc,
			       u8 migration_id)
{
	struct ssdfs_peb_info *pebi = NULL;
	int known_migration_id;
	u64 src_peb_id, dst_peb_id;
	int src_migration_id, dst_migration_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!rwsem_is_locked(&pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_NOT_MIGRATING:
		pebi = pebc->src_peb;
		if (!pebi) {
			err = -ERANGE;
			SSDFS_WARN("source PEB is NULL\n");
			goto fail_to_get_peb;
		}

		known_migration_id = ssdfs_get_peb_migration_id_checked(pebi);

		if (migration_id != known_migration_id) {
			err = -ERANGE;
			SSDFS_WARN("peb %llu, "
				   "migration_id %u != known_migration_id %d\n",
				   pebi->peb_id, migration_id,
				   known_migration_id);
			goto fail_to_get_peb;
		}
		break;

	case SSDFS_PEB_UNDER_MIGRATION:
	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
	case SSDFS_PEB_FINISHING_MIGRATION:
		pebi = pebc->src_peb;
		if (!pebi) {
			err = -ERANGE;
			SSDFS_WARN("source PEB is NULL\n");
			goto fail_to_get_peb;
		}

		known_migration_id = ssdfs_get_peb_migration_id_checked(pebi);

		if (migration_id != known_migration_id) {
			src_peb_id = pebi->peb_id;
			src_migration_id = known_migration_id;

			pebi = pebc->dst_peb;
			if (!pebi) {
				err = -ERANGE;
				SSDFS_WARN("destination PEB is NULL\n");
				goto fail_to_get_peb;
			}

			known_migration_id =
				ssdfs_get_peb_migration_id_checked(pebi);

			if (migration_id != known_migration_id) {
				dst_peb_id = pebi->peb_id;
				dst_migration_id = known_migration_id;

				err = -ERANGE;
				SSDFS_WARN("fail to find PEB: "
					   "src_peb_id %llu, "
					   "src_migration_id %d, "
					   "dst_peb_id %llu, "
					   "dst_migration_id %d, "
					   "migration_id %u\n",
					   src_peb_id, src_migration_id,
					   dst_peb_id, dst_migration_id,
					   migration_id);
				goto fail_to_get_peb;
			}
		}
		break;

	default:
		SSDFS_WARN("invalid state: %#x\n",
			   atomic_read(&pebc->migration_state));
		return ERR_PTR(-ERANGE);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, migration_state %#x, "
		  "migration_phase %#x, migration_id %u\n",
		  pebc->parent_si->seg_id,
		  pebi->peb_id,
		  atomic_read(&pebc->migration_state),
		  atomic_read(&pebc->migration_phase),
		  migration_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return pebi;

fail_to_get_peb:
	return ERR_PTR(err);
}

/*
 * ssdfs_peb_get_free_pages() - get PEB's free pages count
 * @ptr: pointer on PEB container
 */
int ssdfs_peb_get_free_pages(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);

	SSDFS_DBG("pebc %p, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  pebc, pebc->peb_index,
		  pebc->peb_type, pebc->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	seg_blkbmap = &si->blk_bmap;

	if (pebc->peb_index >= seg_blkbmap->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  pebc->peb_index,
			  seg_blkbmap->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];

	return ssdfs_peb_blk_bmap_get_free_pages(peb_blkbmap);
}

/*
 * ssdfs_peb_get_used_pages() - get PEB's valid pages count
 * @ptr: pointer on PEB container
 */
int ssdfs_peb_get_used_data_pages(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);

	SSDFS_DBG("pebc %p, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  pebc, pebc->peb_index,
		  pebc->peb_type, pebc->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	seg_blkbmap = &si->blk_bmap;

	if (pebc->peb_index >= seg_blkbmap->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  pebc->peb_index,
			  seg_blkbmap->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];

	return ssdfs_peb_blk_bmap_get_used_pages(peb_blkbmap);
}

/*
 * ssdfs_peb_get_invalid_pages() - get PEB's invalid pages count
 * @ptr: pointer on PEB container
 */
int ssdfs_peb_get_invalid_pages(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);

	SSDFS_DBG("pebc %p, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  pebc, pebc->peb_index,
		  pebc->peb_type, pebc->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	seg_blkbmap = &si->blk_bmap;

	if (pebc->peb_index >= seg_blkbmap->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  pebc->peb_index,
			  seg_blkbmap->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];

	return ssdfs_peb_blk_bmap_get_invalid_pages(peb_blkbmap);
}

/*
 * ssdfs_peb_container_invalidate_block() - invalidate PEB's block
 * @pebc: pointer on PEB container
 * @desc: physical offset descriptor
 *
 * This method tries to invalidate PEB's block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_container_invalidate_block(struct ssdfs_peb_container *pebc,
				    struct ssdfs_phys_offset_descriptor *desc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_info *pebi;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_block_bmap_range range;
	u16 peb_index;
	u32 peb_page;
	u8 peb_migration_id;
	int id;
	int items_state;
	int bmap_index = SSDFS_PEB_BLK_BMAP_INDEX_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !desc);
	BUG_ON(!pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->blk_bmap.peb);

	SSDFS_DBG("seg %llu, peb_index %u, peb_migration_id %u, "
		  "logical_offset %u, logical_blk %u, peb_page %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  desc->blk_state.peb_migration_id,
		  le32_to_cpu(desc->page_desc.logical_offset),
		  le16_to_cpu(desc->page_desc.logical_blk),
		  le16_to_cpu(desc->page_desc.peb_page));
#endif /* CONFIG_SSDFS_DEBUG */

	peb_index = pebc->peb_index;
	peb_page = le16_to_cpu(desc->page_desc.peb_page);
	peb_migration_id = desc->blk_state.peb_migration_id;

	down_read(&pebc->lock);

	items_state = atomic_read(&pebc->items_state);
	switch (items_state) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
		pebi = pebc->src_peb;
		if (!pebi) {
			SSDFS_ERR("PEB pointer is NULL: items_state %#x\n",
				  items_state);
			err = -ERANGE;
			goto finish_invalidate_block;
		}
		bmap_index = SSDFS_PEB_BLK_BMAP_SOURCE;
		break;

	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		pebi = pebc->dst_peb;
		if (!pebi) {
			SSDFS_ERR("PEB pointer is NULL: items_state %#x\n",
				  items_state);
			err = -ERANGE;
			goto finish_invalidate_block;
		}
		bmap_index = SSDFS_PEB_BLK_BMAP_DESTINATION;
		break;

	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		pebi = pebc->src_peb;
		if (!pebi) {
			SSDFS_ERR("PEB pointer is NULL: items_state %#x\n",
				  items_state);
			err = -ERANGE;
			goto finish_invalidate_block;
		}

		bmap_index = SSDFS_PEB_BLK_BMAP_SOURCE;
		id = ssdfs_get_peb_migration_id_checked(pebi);

		if (peb_migration_id != id) {
			pebi = pebc->dst_peb;
			if (!pebi) {
				SSDFS_ERR("PEB pointer is NULL: "
					  "items_state %#x\n",
					  items_state);
				err = -ERANGE;
				goto finish_invalidate_block;
			}
			bmap_index = SSDFS_PEB_BLK_BMAP_DESTINATION;
		}
		break;

	default:
		SSDFS_ERR("invalid PEB container's items_state: "
			  "%#x\n",
			  items_state);
		err = -ERANGE;
		goto finish_invalidate_block;
	};

	id = ssdfs_get_peb_migration_id_checked(pebi);

	if (peb_migration_id != id) {
		SSDFS_ERR("peb_migration_id %u != pebi->peb_migration_id %u\n",
			  peb_migration_id,
			  ssdfs_get_peb_migration_id(pebi));
		err = -ERANGE;
		goto finish_invalidate_block;
	}

	si = pebc->parent_si;
	seg_blkbmap = &si->blk_bmap;

	if (pebc->peb_index >= seg_blkbmap->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  pebc->peb_index,
			  seg_blkbmap->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];

	range.start = peb_page;
	range.len = 1;

	err = ssdfs_peb_blk_bmap_invalidate(peb_blkbmap,
					    bmap_index,
					    &range);
	if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate range: "
			  "peb %llu, "
			  "range (start %u, len %u), err %d\n",
			  pebi->peb_id,
			  range.start, range.len, err);
		goto finish_invalidate_block;
	}

finish_invalidate_block:
	up_read(&pebc->lock);

	return err;
}

/*
 * is_peb_joined_into_create_requests_queue() - is PEB joined into create queue?
 * @pebc: pointer on PEB container
 */
bool is_peb_joined_into_create_requests_queue(struct ssdfs_peb_container *pebc)
{
	bool is_joined;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&pebc->crq_ptr_lock);
	is_joined = pebc->create_rq != NULL;
	spin_unlock(&pebc->crq_ptr_lock);

	return is_joined;
}

/*
 * ssdfs_peb_join_create_requests_queue() - join to process new page requests
 * @pebc: pointer on PEB container
 * @create_rq: pointer on shared new page requests queue
 * @wait: wait queue of threads that process new pages
 *
 * This function select PEB's flush thread for processing new page
 * requests. Namely, selected PEB object keeps pointer on shared
 * new page requests queue and to join into wait queue of another
 * flush threads.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 */
int ssdfs_peb_join_create_requests_queue(struct ssdfs_peb_container *pebc,
					 struct ssdfs_requests_queue *create_rq)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
	BUG_ON(!create_rq);

	SSDFS_DBG("seg %llu, peb_index %u, create_rq %p\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, create_rq);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_peb_joined_into_create_requests_queue(pebc)) {
		SSDFS_ERR("PEB is joined into create requests queue yet: "
			  "seg %llu, peb_index %u\n",
			  pebc->parent_si->seg_id, pebc->peb_index);
		return -EINVAL;
	}

	if (pebc->thread[SSDFS_PEB_FLUSH_THREAD].task == NULL) {
		SSDFS_ERR("PEB hasn't flush thread: "
			  "seg %llu, peb_index %u\n",
			  pebc->parent_si->seg_id, pebc->peb_index);
		return -EINVAL;
	}

	spin_lock(&pebc->crq_ptr_lock);
	pebc->create_rq = create_rq;
	spin_unlock(&pebc->crq_ptr_lock);

	wake_up_all(&pebc->parent_si->wait_queue[SSDFS_PEB_FLUSH_THREAD]);

	return 0;
}

/*
 * ssdfs_peb_forget_create_requests_queue() - forget create requests queue
 * @pebc: pointer on PEB container
 */
void ssdfs_peb_forget_create_requests_queue(struct ssdfs_peb_container *pebc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
	WARN_ON(!is_peb_joined_into_create_requests_queue(pebc));
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&pebc->crq_ptr_lock);
	pebc->create_rq = NULL;
	spin_unlock(&pebc->crq_ptr_lock);
}

/*
 * ssdfs_peb_container_change_state() - change PEB's state in mapping table
 * @pebc: pointer on PEB container
 *
 * This method tries to change PEB's state in the mapping table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_container_change_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_peb_info *pebi;
	struct ssdfs_peb_mapping_table *maptbl;
	struct completion *end;
	int items_state;
	int used_pages, free_pages, invalid_pages;
	int new_peb_state = SSDFS_MAPTBL_UNKNOWN_PEB_STATE;
	u64 leb_id;
	bool is_peb_exhausted = false;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!rwsem_is_locked(&pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	fsi = pebc->parent_si->fsi;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("pebc %p, seg %llu, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  pebc, si->seg_id, pebc->peb_index,
		  pebc->peb_type, pebc->log_pages);
#else
	SSDFS_DBG("pebc %p, seg %llu, peb_index %u, "
		  "peb_type %#x, log_pages %u\n",
		  pebc, si->seg_id, pebc->peb_index,
		  pebc->peb_type, pebc->log_pages);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	seg_blkbmap = &si->blk_bmap;
	maptbl = fsi->maptbl;

	if (pebc->peb_index >= seg_blkbmap->pebs_count) {
		SSDFS_ERR("peb_index %u >= pebs_count %u\n",
			  pebc->peb_index,
			  seg_blkbmap->pebs_count);
		return -ERANGE;
	}

	peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi, si->seg_id,
						pebc->peb_index);
	if (leb_id == U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  si->seg_id, pebc->peb_index);
		return -EINVAL;
	}

	items_state = atomic_read(&pebc->items_state);
	switch (items_state) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
		pebi = pebc->src_peb;
		if (!pebi) {
			SSDFS_ERR("PEB pointer is NULL: items_state %#x\n",
				  items_state);
			return -ERANGE;
		}

		free_pages = ssdfs_peb_blk_bmap_get_free_pages(peb_blkbmap);
		if (free_pages < 0) {
			err = free_pages;
			SSDFS_ERR("fail to get free pages: err %d\n",
				  err);
			return err;
		}

		used_pages = ssdfs_peb_blk_bmap_get_used_pages(peb_blkbmap);
		if (used_pages < 0) {
			err = used_pages;
			SSDFS_ERR("fail to get used pages: err %d\n",
				  err);
			return err;
		}

		invalid_pages =
			ssdfs_peb_blk_bmap_get_invalid_pages(peb_blkbmap);
		if (invalid_pages < 0) {
			err = invalid_pages;
			SSDFS_ERR("fail to get invalid pages: err %d\n",
				  err);
			return err;
		}

		ssdfs_peb_current_log_lock(pebi);
		is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
		ssdfs_peb_current_log_unlock(pebi);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free_pages %d, used_pages %d, "
			  "invalid_pages %d, is_peb_exhausted %#x\n",
			  free_pages, used_pages,
			  invalid_pages, is_peb_exhausted);
#endif /* CONFIG_SSDFS_DEBUG */

		if (free_pages == 0) {
			if (!is_peb_exhausted) {
				new_peb_state =
					SSDFS_MAPTBL_USING_PEB_STATE;
			} else if (invalid_pages == 0) {
				if (used_pages == 0) {
					SSDFS_ERR("invalid state: "
						  "free_pages %d, "
						  "used_pages %d, "
						  "invalid_pages %d\n",
						  free_pages,
						  used_pages,
						  invalid_pages);
					return -ERANGE;
				}

				new_peb_state =
					SSDFS_MAPTBL_USED_PEB_STATE;
			} else if (used_pages == 0) {
				if (invalid_pages == 0) {
					SSDFS_ERR("invalid state: "
						  "free_pages %d, "
						  "used_pages %d, "
						  "invalid_pages %d\n",
						  free_pages,
						  used_pages,
						  invalid_pages);
					return -ERANGE;
				}

				new_peb_state =
					SSDFS_MAPTBL_DIRTY_PEB_STATE;
			} else {
				new_peb_state =
					SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE;
			}
		} else if (used_pages == 0) {
			if (invalid_pages == 0) {
				new_peb_state =
					SSDFS_MAPTBL_CLEAN_PEB_STATE;
			} else {
				new_peb_state =
					SSDFS_MAPTBL_USING_PEB_STATE;
			}
		} else {
			new_peb_state =
				SSDFS_MAPTBL_USING_PEB_STATE;
		}

		err = ssdfs_maptbl_change_peb_state(fsi, leb_id,
						    pebc->peb_type,
						    new_peb_state, &end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_change_peb_state(fsi,
							    leb_id,
							    pebc->peb_type,
							    new_peb_state,
							    &end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to change the PEB state: "
				  "peb_id %llu, new_state %#x, err %d\n",
				  pebi->peb_id, new_peb_state, err);
			return err;
		}
		break;

	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		pebi = pebc->dst_peb;
		if (!pebi) {
			SSDFS_ERR("PEB pointer is NULL: items_state %#x\n",
				  items_state);
			return -ERANGE;
		}

		free_pages = ssdfs_peb_blk_bmap_get_free_pages(peb_blkbmap);
		if (free_pages < 0) {
			err = free_pages;
			SSDFS_ERR("fail to get free pages: err %d\n",
				  err);
			return err;
		}

		used_pages = ssdfs_peb_blk_bmap_get_used_pages(peb_blkbmap);
		if (used_pages < 0) {
			err = used_pages;
			SSDFS_ERR("fail to get used pages: err %d\n",
				  err);
			return err;
		}

		invalid_pages =
			ssdfs_peb_blk_bmap_get_invalid_pages(peb_blkbmap);
		if (invalid_pages < 0) {
			err = invalid_pages;
			SSDFS_ERR("fail to get invalid pages: err %d\n",
				  err);
			return err;
		}

		ssdfs_peb_current_log_lock(pebi);
		is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
		ssdfs_peb_current_log_unlock(pebi);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free_pages %d, used_pages %d, "
			  "invalid_pages %d, is_peb_exhausted %#x\n",
			  free_pages, used_pages,
			  invalid_pages, is_peb_exhausted);
#endif /* CONFIG_SSDFS_DEBUG */

		if (free_pages == 0) {
			if (!is_peb_exhausted) {
				new_peb_state =
					SSDFS_MAPTBL_USING_PEB_STATE;
			} else if (invalid_pages == 0) {
				if (used_pages == 0) {
					SSDFS_ERR("invalid state: "
						  "free_pages %d, "
						  "used_pages %d, "
						  "invalid_pages %d\n",
						  free_pages,
						  used_pages,
						  invalid_pages);
					return -ERANGE;
				}

				new_peb_state =
					SSDFS_MAPTBL_USED_PEB_STATE;
			} else if (used_pages == 0) {
				if (invalid_pages == 0) {
					SSDFS_ERR("invalid state: "
						  "free_pages %d, "
						  "used_pages %d, "
						  "invalid_pages %d\n",
						  free_pages,
						  used_pages,
						  invalid_pages);
					return -ERANGE;
				}

				new_peb_state =
					SSDFS_MAPTBL_DIRTY_PEB_STATE;
			} else {
				new_peb_state =
					SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE;
			}
		} else if (used_pages == 0) {
			if (invalid_pages == 0) {
				new_peb_state =
					SSDFS_MAPTBL_CLEAN_PEB_STATE;
			} else {
				new_peb_state =
					SSDFS_MAPTBL_USING_PEB_STATE;
			}
		} else {
			new_peb_state =
				SSDFS_MAPTBL_USING_PEB_STATE;
		}

		err = ssdfs_maptbl_change_peb_state(fsi, leb_id,
						    pebc->peb_type,
						    new_peb_state, &end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_change_peb_state(fsi, leb_id,
							    pebc->peb_type,
							    new_peb_state,
							    &end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to change the PEB state: "
				  "peb_id %llu, new_state %#x, err %d\n",
				  pebi->peb_id, new_peb_state, err);
			return err;
		}
		break;

	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		pebi = pebc->src_peb;
		if (!pebi) {
			SSDFS_ERR("PEB pointer is NULL: items_state %#x\n",
				  items_state);
			return -ERANGE;
		}

		free_pages = ssdfs_src_blk_bmap_get_free_pages(peb_blkbmap);
		if (free_pages < 0) {
			err = free_pages;
			SSDFS_ERR("fail to get free pages: err %d\n",
				  err);
			return err;
		}

		used_pages = ssdfs_src_blk_bmap_get_used_pages(peb_blkbmap);
		if (used_pages < 0) {
			err = used_pages;
			SSDFS_ERR("fail to get used pages: err %d\n",
				  err);
			return err;
		}

		invalid_pages =
			ssdfs_src_blk_bmap_get_invalid_pages(peb_blkbmap);
		if (invalid_pages < 0) {
			err = invalid_pages;
			SSDFS_ERR("fail to get invalid pages: err %d\n",
				  err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("source PEB: free_pages %d, used_pages %d, "
			  "invalid_pages %d\n",
			  free_pages, used_pages, invalid_pages);
#endif /* CONFIG_SSDFS_DEBUG */

		if (invalid_pages == 0) {
			if (used_pages == 0) {
				SSDFS_ERR("invalid state: "
					  "used_pages %d, "
					  "invalid_pages %d\n",
					  used_pages,
					  invalid_pages);
				return -ERANGE;
			}

			new_peb_state =
				SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE;
		} else if (used_pages == 0) {
			new_peb_state =
				SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE;
		} else {
			new_peb_state =
				SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE;
		}

		err = ssdfs_maptbl_change_peb_state(fsi, leb_id,
						    pebc->peb_type,
						    new_peb_state, &end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_change_peb_state(fsi, leb_id,
							    pebc->peb_type,
							    new_peb_state,
							    &end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to change the PEB state: "
				  "peb_id %llu, new_state %#x, err %d\n",
				  pebi->peb_id, new_peb_state, err);
			return err;
		}

		pebi = pebc->dst_peb;
		if (!pebi) {
			SSDFS_ERR("PEB pointer is NULL: "
				  "items_state %#x\n",
				  items_state);
			return -ERANGE;
		}

		free_pages = ssdfs_dst_blk_bmap_get_free_pages(peb_blkbmap);
		if (free_pages < 0) {
			err = free_pages;
			SSDFS_ERR("fail to get free pages: err %d\n",
				  err);
			return err;
		}

		used_pages = ssdfs_dst_blk_bmap_get_used_pages(peb_blkbmap);
		if (used_pages < 0) {
			err = used_pages;
			SSDFS_ERR("fail to get used pages: err %d\n",
				  err);
			return err;
		}

		invalid_pages =
			ssdfs_dst_blk_bmap_get_invalid_pages(peb_blkbmap);
		if (invalid_pages < 0) {
			err = invalid_pages;
			SSDFS_ERR("fail to get invalid pages: err %d\n",
				  err);
			return err;
		}

		ssdfs_peb_current_log_lock(pebi);
		is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
		ssdfs_peb_current_log_unlock(pebi);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("destination PEB: free_pages %d, used_pages %d, "
			  "invalid_pages %d, is_peb_exhausted %#x\n",
			  free_pages, used_pages,
			  invalid_pages, is_peb_exhausted);
#endif /* CONFIG_SSDFS_DEBUG */

		if (free_pages == 0) {
			if (!is_peb_exhausted) {
				new_peb_state =
					SSDFS_MAPTBL_MIGRATION_DST_USING_STATE;
			} else if (invalid_pages == 0) {
				if (used_pages == 0) {
					SSDFS_ERR("invalid state: "
						  "free_pages %d, "
						  "used_pages %d, "
						  "invalid_pages %d\n",
						  free_pages,
						  used_pages,
						  invalid_pages);
					return -ERANGE;
				}

				new_peb_state =
					SSDFS_MAPTBL_MIGRATION_DST_USED_STATE;
			} else if (used_pages == 0) {
				if (invalid_pages == 0) {
					SSDFS_ERR("invalid state: "
						  "free_pages %d, "
						  "used_pages %d, "
						  "invalid_pages %d\n",
						  free_pages,
						  used_pages,
						  invalid_pages);
					return -ERANGE;
				}

				new_peb_state =
					SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE;
			} else {
				new_peb_state =
				    SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE;
			}
		} else if (used_pages == 0) {
			if (invalid_pages == 0) {
				new_peb_state =
					SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE;
			} else {
				new_peb_state =
					SSDFS_MAPTBL_MIGRATION_DST_USING_STATE;
			}
		} else {
			new_peb_state =
				SSDFS_MAPTBL_MIGRATION_DST_USING_STATE;
		}

		err = ssdfs_maptbl_change_peb_state(fsi, leb_id,
						    pebc->peb_type,
						    new_peb_state, &end);
		if (err == -EAGAIN) {
			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_change_peb_state(fsi, leb_id,
							    pebc->peb_type,
							    new_peb_state,
							    &end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to change the PEB state: "
				  "peb_id %llu, new_state %#x, err %d\n",
				  pebi->peb_id, new_peb_state, err);
			return err;
		}
		break;

	default:
		SSDFS_ERR("invalid PEB container's items_state: "
			  "%#x\n",
			  items_state);
		return -ERANGE;
	};

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}
