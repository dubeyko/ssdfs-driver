/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/file.c - file operations.
 *
 * Copyright (c) 2019-2025 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "request_queue.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "inodes_tree.h"
#include "extents_tree.h"
#include "xattr.h"
#include "acl.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_file_folio_leaks;
atomic64_t ssdfs_file_memory_leaks;
atomic64_t ssdfs_file_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_file_cache_leaks_increment(void *kaddr)
 * void ssdfs_file_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_file_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_file_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_file_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_file_kfree(void *kaddr)
 * struct folio *ssdfs_file_alloc_folio(gfp_t gfp_mask,
 *                                      unsigned int order)
 * struct folio *ssdfs_file_add_batch_folio(struct folio_batch *batch,
 *                                          unsigned int order)
 * void ssdfs_file_free_folio(struct folio *folio)
 * void ssdfs_file_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(file)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(file)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_file_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_file_folio_leaks, 0);
	atomic64_set(&ssdfs_file_memory_leaks, 0);
	atomic64_set(&ssdfs_file_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_file_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_file_folio_leaks) != 0) {
		SSDFS_ERR("FILE: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_file_folio_leaks));
	}

	if (atomic64_read(&ssdfs_file_memory_leaks) != 0) {
		SSDFS_ERR("FILE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_file_memory_leaks));
	}

	if (atomic64_read(&ssdfs_file_cache_leaks) != 0) {
		SSDFS_ERR("FILE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_file_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

enum {
	SSDFS_BLOCK_BASED_REQUEST,
	SSDFS_EXTENT_BASED_REQUEST,
};

enum {
	SSDFS_CURRENT_THREAD_READ,
	SSDFS_DELEGATE_TO_READ_THREAD,
};

static inline
bool can_file_be_inline(struct inode *inode, loff_t new_size)
{
	size_t capacity = ssdfs_inode_inline_file_capacity(inode);

	if (capacity == 0)
		return false;

	if (capacity < new_size)
		return false;

	return true;
}

static inline
size_t ssdfs_inode_size_threshold(void)
{
	return sizeof(struct ssdfs_inode) -
			offsetof(struct ssdfs_inode, internal);
}

int ssdfs_allocate_inline_file_buffer(struct inode *inode)
{
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	size_t threshold = ssdfs_inode_size_threshold();
	size_t inline_capacity;

	if (ii->inline_file)
		return 0;

	inline_capacity = ssdfs_inode_inline_file_capacity(inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("inline_capacity %zu, threshold %zu\n",
		  inline_capacity, threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	if (inline_capacity < threshold) {
		SSDFS_ERR("inline_capacity %zu < threshold %zu\n",
			  inline_capacity, threshold);
		return -ERANGE;
	} else if (inline_capacity == threshold) {
		ii->inline_file = ii->raw_inode.internal;
	} else {
		ii->inline_file =
			ssdfs_file_kzalloc(inline_capacity, GFP_KERNEL);
		if (!ii->inline_file) {
			SSDFS_ERR("fail to allocate inline buffer: "
				  "ino %lu, inline_capacity %zu\n",
				  inode->i_ino, inline_capacity);
			return -ENOMEM;
		}
	}

	return 0;
}

void ssdfs_destroy_inline_file_buffer(struct inode *inode)
{
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	size_t threshold = ssdfs_inode_size_threshold();
	size_t inline_capacity;

	if (!ii->inline_file)
		return;

	inline_capacity = ssdfs_inode_inline_file_capacity(inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("inline_capacity %zu, threshold %zu\n",
		  inline_capacity, threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	if (inline_capacity <= threshold) {
		ii->inline_file = NULL;
	} else {
		ssdfs_file_kfree(ii->inline_file);
		ii->inline_file = NULL;
	}
}

/*
 * ssdfs_read_block_async() - read block async
 * @fsi: pointer on shared file system object
 * @req: request object
 */
static
int ssdfs_read_block_async(struct ssdfs_fs_info *fsi,
			   struct ssdfs_segment_request *req)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_search_state seg_search;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON((req->extent.logical_offset >> fsi->log_pagesize) >= U32_MAX);

	SSDFS_DBG("fsi %p, req %p\n", fsi, req);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_prepare_volume_extent(fsi, req);
	if (err == -EAGAIN) {
		err = 0;
		SSDFS_DBG("logical extent processed partially\n");
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to prepare volume extent: "
			  "ino %llu, logical_offset %llu, "
			  "data_bytes %u, cno %llu, "
			  "parent_snapshot %llu, err %d\n",
			  req->extent.ino,
			  req->extent.logical_offset,
			  req->extent.data_bytes,
			  req->extent.cno,
			  req->extent.parent_snapshot,
			  err);
		return err;
	}

	req->place.len = 1;

	ssdfs_segment_search_state_init(&seg_search,
					SSDFS_USER_DATA_SEG_TYPE,
					req->place.start.seg_id, U64_MAX);

	si = ssdfs_grab_segment(fsi, &seg_search);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		SSDFS_ERR("fail to grab segment object: "
			  "seg %llu, err %ld\n",
			  req->place.start.seg_id,
			  PTR_ERR(si));
		return PTR_ERR(si);
	}

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, ino %llu, err %d\n",
				  si->seg_id, req->extent.ino, err);
			return err;
		}
	}

	err = ssdfs_segment_read_block_async(si, SSDFS_REQ_ASYNC, req);
	if (unlikely(err)) {
		SSDFS_ERR("read request failed: "
			  "ino %llu, logical_offset %llu, size %u, err %d\n",
			  req->extent.ino, req->extent.logical_offset,
			  req->extent.data_bytes, err);
		return err;
	}

	ssdfs_segment_put_object(si);

	return 0;
}

/*
 * ssdfs_read_block_by_current_thread() - read block by current thread
 * @fsi: pointer on shared file system object
 * @req: request object
 */
static
int ssdfs_read_block_by_current_thread(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_offset_position pos;
	struct ssdfs_segment_search_state seg_search;
	u16 logical_blk;
	struct completion *end;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON((req->extent.logical_offset >> fsi->log_pagesize) >= U32_MAX);

	SSDFS_DBG("fsi %p, req %p\n", fsi, req);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_prepare_volume_extent(fsi, req);
	if (err == -EAGAIN) {
		err = 0;
		SSDFS_DBG("logical extent processed partially\n");
	} else if (err == -ENOENT) {
		SSDFS_DBG("fork is absent: "
			  "ino %llu, logical_offset %llu, "
			  "data_bytes %u, cno %llu, "
			  "parent_snapshot %llu, err %d\n",
			  req->extent.ino,
			  req->extent.logical_offset,
			  req->extent.data_bytes,
			  req->extent.cno,
			  req->extent.parent_snapshot,
			  err);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to prepare volume extent: "
			  "ino %llu, logical_offset %llu, "
			  "data_bytes %u, cno %llu, "
			  "parent_snapshot %llu, err %d\n",
			  req->extent.ino,
			  req->extent.logical_offset,
			  req->extent.data_bytes,
			  req->extent.cno,
			  req->extent.parent_snapshot,
			  err);
		return err;
	}

	req->place.len = 1;

	ssdfs_segment_search_state_init(&seg_search,
					SSDFS_USER_DATA_SEG_TYPE,
					req->place.start.seg_id, U64_MAX);

	si = ssdfs_grab_segment(fsi, &seg_search);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		SSDFS_ERR("fail to grab segment object: "
			  "seg %llu, err %d\n",
			  req->place.start.seg_id, err);
		return PTR_ERR(si);
	}

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, err %d\n",
				  si->seg_id, err);
			goto finish_read_block;
		}
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    SSDFS_READ_PAGE,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	table = si->blk2off_table;
	logical_blk = req->place.start.blk_index;

	err = ssdfs_blk2off_table_get_offset_position(table, logical_blk, &pos);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		goto finish_read_block;
	}

	pebc = &si->peb_array[pos.peb_index];

	ssdfs_peb_read_request_cno(pebc);

	err = ssdfs_peb_read_page(pebc, req, &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("PEB init failed: "
				  "err %d\n", err);
			goto forget_request_cno;
		}

		err = ssdfs_peb_read_page(pebc, req, &end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to read block: err %d\n",
			  err);
		goto forget_request_cno;
	}

	for (i = 0; i < req->result.processed_blks; i++)
		ssdfs_peb_mark_request_block_uptodate(pebc, req, i);

forget_request_cno:
	ssdfs_peb_finish_read_request_cno(pebc);

finish_read_block:
	req->result.err = err;
	complete(&req->result.wait);
	ssdfs_segment_put_object(si);

	return 0;
}

static
int ssdfs_read_block_nolock(struct file *file, struct folio_batch *batch,
			    int read_mode)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(file_inode(file)->i_sb);
	struct inode *inode = file_inode(file);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct folio *folio;
	struct ssdfs_segment_request *req = NULL;
	ino_t ino = file_inode(file)->i_ino;
	loff_t logical_offset;
	loff_t data_bytes = 0;
	loff_t file_size;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, read_mode %#x\n",
		  ino, read_mode);

	BUG_ON(folio_batch_count(batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	folio = batch->folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_offset = (loff_t)folio->index << PAGE_SHIFT;

	for (i = 0; i < folio_batch_count(batch); i++) {
		folio = batch->folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		__ssdfs_memzero_folio(folio, 0, folio_size(folio),
				      folio_size(folio));

		data_bytes += folio_size(folio);
	}

	file_size = i_size_read(file_inode(file));
	data_bytes = min_t(loff_t, file_size - logical_offset, data_bytes);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(data_bytes > U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (logical_offset >= file_size) {
		/* Reading beyond inode */
		for (i = 0; i < folio_batch_count(batch); i++) {
			folio = batch->folios[i];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			folio_mark_uptodate(folio);
			flush_dcache_folio(folio);
		}

		goto finish_read_block;
	} else if (is_ssdfs_file_inline(ii)) {
		loff_t byte_offset = 0;
		loff_t iter_bytes;
		size_t inline_capacity =
				ssdfs_inode_inline_file_capacity(inode);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("inline_capacity %zu, file_size %llu\n",
			  inline_capacity, file_size);
#endif /* CONFIG_SSDFS_DEBUG */

		if (file_size > inline_capacity) {
			err = -E2BIG;
			SSDFS_ERR("file_size %llu is greater than capacity %zu\n",
				  file_size, inline_capacity);
			goto fail_read_block;
		} else if (data_bytes > inline_capacity) {
			err = -ERANGE;
			SSDFS_ERR("data_bytes %llu is greater than capacity %zu\n",
				  data_bytes, inline_capacity);
			goto fail_read_block;
		}

		for (i = 0; i < folio_batch_count(batch); i++) {
			folio = batch->folios[i];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			if (byte_offset < inline_capacity) {
#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(data_bytes <= byte_offset);
#endif /* CONFIG_SSDFS_DEBUG */

				iter_bytes = min_t(loff_t, folio_size(folio),
						   data_bytes - byte_offset);

				err = __ssdfs_memcpy_to_folio(folio,
							      0,
							      folio_size(folio),
							      ii->inline_file,
							      byte_offset,
							      inline_capacity,
							      iter_bytes);
				if (unlikely(err)) {
					SSDFS_ERR("fail to copy file's content: "
						  "err %d\n", err);
					goto fail_read_block;
				}
			}

			folio_mark_uptodate(folio);
			flush_dcache_folio(folio);

			byte_offset += folio_size(folio);
		}

		goto finish_read_block;
	}

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req, fsi->pagesize);
	ssdfs_get_request(req);

	ssdfs_request_prepare_logical_extent(ino,
					     (u64)logical_offset,
					     (u32)data_bytes,
					     0, 0, req);

	for (i = 0; i < folio_batch_count(batch); i++) {
		folio = batch->folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_request_add_folio(folio, 0, req);
		if (err) {
			SSDFS_ERR("fail to add folio into request: "
				  "ino %lu, folio_index %lu, err %d\n",
				  ino, folio->index, err);
			goto fail_read_block;
		}
	}

	switch (read_mode) {
	case SSDFS_CURRENT_THREAD_READ:
		err = ssdfs_read_block_by_current_thread(fsi, req);
		if (err == -ENOENT) {
			SSDFS_DBG("empty block has been prepared\n");

			for (i = 0; i < folio_batch_count(batch); i++) {
				folio = batch->folios[i];

#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

				folio_mark_uptodate(folio);
				flush_dcache_folio(folio);
			}

			ssdfs_put_request(req);
			ssdfs_request_free(req, NULL);
			goto finish_read_block;
		} else if (err) {
			SSDFS_ERR("fail to read block: err %d\n", err);
			goto fail_read_block;
		}

		err = SSDFS_WAIT_COMPLETION(&req->result.wait);
		if (unlikely(err)) {
			SSDFS_ERR("read request failed: "
				  "ino %lu, logical_offset %llu, "
				  "size %u, err %d\n",
				  ino, (u64)logical_offset,
				  (u32)data_bytes, err);
			goto fail_read_block;
		}

		if (req->result.err) {
			SSDFS_ERR("read request failed: "
				  "ino %lu, logical_offset %llu, "
				  "size %u, err %d\n",
				  ino, (u64)logical_offset,
				  (u32)data_bytes,
				  req->result.err);
			goto fail_read_block;
		}

		ssdfs_put_request(req);
		ssdfs_request_free(req, NULL);
		break;

	case SSDFS_DELEGATE_TO_READ_THREAD:
		err = ssdfs_read_block_async(fsi, req);
		if (err) {
			SSDFS_ERR("fail to read block: err %d\n", err);
			goto fail_read_block;
		}
		break;

	default:
		BUG();
	}

finish_read_block:
	return 0;

fail_read_block:
	for (i = 0; i < folio_batch_count(batch); i++) {
		folio = batch->folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		folio_clear_uptodate(folio);
		ssdfs_clear_folio_private(folio, 0);
	}

	if (req) {
		ssdfs_put_request(req);
		ssdfs_request_free(req, NULL);
	}

	return err;
}

static
int ssdfs_read_block(struct file *file, struct folio *folio)
{
	struct inode *inode = file_inode(file);
	struct address_space *mapping = file->f_mapping;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct folio_batch fbatch;
	struct folio *cur_folio;
	loff_t logical_offset;
	pgoff_t index;
	fgf_t fgp_flags = FGP_CREAT | FGP_LOCK;
	u32 processed_bytes = 0;
	bool need_read_block = false;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, folio_index %lu, "
		  "folio_size %zu\n",
		  file_inode(file)->i_ino, folio->index,
		  folio_size(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	folio_batch_init(&fbatch);

	logical_offset = (loff_t)folio->index << PAGE_SHIFT;
	logical_offset >>= fsi->log_pagesize;
	logical_offset <<= fsi->log_pagesize;

	index = logical_offset >> PAGE_SHIFT;

	while (processed_bytes < fsi->pagesize) {
		if (index == folio->index) {
			cur_folio = folio;
			ssdfs_account_locked_folio(folio);
		} else {
			fgp_flags |= fgf_set_order(fsi->pagesize -
						   processed_bytes);

			cur_folio = __filemap_get_folio(mapping,
						    index,
						    fgp_flags,
						    mapping_gfp_mask(mapping));
			if (!folio) {
				SSDFS_ERR("fail to grab folio: page_index %lu\n",
					  index);
				return -ENOMEM;
			} else if (IS_ERR(cur_folio)) {
				SSDFS_ERR("fail to grab folio: "
					  "page_index %lu, err %ld\n",
					  index, PTR_ERR(cur_folio));
				return PTR_ERR(cur_folio);
			}

			ssdfs_account_locked_folio(cur_folio);
		}

		folio_batch_add(&fbatch, cur_folio);

		if (!folio_test_uptodate(cur_folio))
			need_read_block = true;

		index += folio_size(cur_folio) >> PAGE_SHIFT;
		processed_bytes += folio_size(cur_folio);
	}

	if (need_read_block) {
		err = ssdfs_read_block_nolock(file, &fbatch,
						SSDFS_CURRENT_THREAD_READ);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read folio: "
				  "index %lu, err %d\n",
				  folio->index, err);
		}
	}

	for (i = 0; i < folio_batch_count(&fbatch); i++) {
		cur_folio = fbatch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!cur_folio);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_unlock(cur_folio);
	}

	return err;
}

static
int ssdfs_check_read_request(struct ssdfs_segment_request *req)
{
	wait_queue_head_t *wq = NULL;
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);

	SSDFS_DBG("req %p\n", req);
#endif /* CONFIG_SSDFS_DEBUG */

check_req_state:
	switch (atomic_read(&req->result.state)) {
	case SSDFS_REQ_CREATED:
	case SSDFS_REQ_STARTED:
		wq = &req->private.wait_queue;

		res = wait_event_killable_timeout(*wq,
					has_request_been_executed(req),
					SSDFS_DEFAULT_TIMEOUT);
		if (res < 0) {
			err = res;
			WARN_ON(1);
		} else if (res > 1) {
			/*
			 * Condition changed before timeout
			 */
			goto check_req_state;
		} else {
			/* timeout is elapsed */
			err = -ERANGE;
			WARN_ON(1);
		}
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

		SSDFS_ERR("read request is failed: "
			  "err %d\n", err);
		goto finish_check;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid result's state %#x\n",
			  atomic_read(&req->result.state));
		goto finish_check;
	}

finish_check:
	return err;
}

static
int ssdfs_wait_read_request_end(struct ssdfs_fs_info *fsi,
				struct ssdfs_segment_request *req)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_search_state seg_search;
	wait_queue_head_t *wait;
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("req %p\n", req);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!req)
		return 0;

	err = ssdfs_check_read_request(req);
	if (unlikely(err)) {
		SSDFS_ERR("read request failed: "
			  "err %d\n", err);
		goto free_request;
	}

	ssdfs_segment_search_state_init(&seg_search,
					SSDFS_USER_DATA_SEG_TYPE,
					req->place.start.seg_id, U64_MAX);

	si = ssdfs_grab_segment(fsi, &seg_search);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		err = (si == NULL ? -ENOMEM : PTR_ERR(si));
		SSDFS_ERR("fail to grab segment object: "
			  "seg %llu, err %d\n",
			  req->place.start.seg_id,
			  err);
		goto finish_wait;
	}

	wait = &si->wait_queue[SSDFS_PEB_READ_THREAD];

	if (atomic_read(&req->private.refs_count) != 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start waiting: refs_count %d\n",
			   atomic_read(&req->private.refs_count));
#endif /* CONFIG_SSDFS_DEBUG */

		res = wait_event_killable_timeout(*wait,
			    atomic_read(&req->private.refs_count) == 0,
			    SSDFS_DEFAULT_TIMEOUT);
		if (res < 0) {
			err = res;
			WARN_ON(1);
		} else if (res > 1) {
			/*
			 * Condition changed before timeout
			 */
		} else {
			/* timeout is elapsed */
			err = -ERANGE;
			WARN_ON(1);
		}
	}

	ssdfs_segment_put_object(si);

free_request:
	ssdfs_request_free(req, si);

finish_wait:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */
	return err;
}

struct ssdfs_readahead_env {
	struct file *file;
	struct ssdfs_segment_request **reqs;
	unsigned count;
	unsigned capacity;

	struct folio_batch batch;
	struct ssdfs_logical_extent requested;
	struct ssdfs_volume_extent place;
	struct ssdfs_volume_extent cur_extent;
};

static
struct ssdfs_segment_request *
ssdfs_issue_read_request(struct ssdfs_readahead_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_request *req = NULL;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_search_state seg_search;
	loff_t data_bytes = 0;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env);

	SSDFS_DBG("requested (ino %llu, logical_offset %llu, "
		  "cno %llu, parent_snapshot %llu), "
		  "current extent (seg_id %llu, logical_blk %u, len %u)\n",
		  env->requested.ino,
		  env->requested.logical_offset,
		  env->requested.cno,
		  env->requested.parent_snapshot,
		  env->cur_extent.start.seg_id,
		  env->cur_extent.start.blk_index,
		  env->cur_extent.len);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(file_inode(env->file)->i_sb);

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return req;
	}

	ssdfs_request_init(req, fsi->pagesize);
	ssdfs_get_request(req);

	for (i = 0; i < folio_batch_count(&env->batch); i++) {
		struct folio *folio;

		folio = env->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		data_bytes += folio_size(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio_index %d, folio_size %zu, "
			  "data_bytes %llu\n",
			  i, folio_size(folio),
			  (u64)data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(data_bytes == 0);
	BUG_ON(data_bytes > fsi->pagesize);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_prepare_logical_extent(env->requested.ino,
					     env->requested.logical_offset,
					     (u32)data_bytes,
					     env->requested.cno,
					     env->requested.parent_snapshot,
					     req);

	ssdfs_request_define_segment(env->cur_extent.start.seg_id, req);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(env->cur_extent.start.blk_index >= U16_MAX);
	BUG_ON(env->cur_extent.len >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	ssdfs_request_define_volume_extent(env->cur_extent.start.blk_index,
					   env->cur_extent.len,
					   req);

	for (i = 0; i < folio_batch_count(&env->batch); i++) {
		err = ssdfs_request_add_folio(env->batch.folios[i], 0, req);
		if (err) {
			SSDFS_ERR("fail to add folio into request: "
				  "ino %llu, err %d\n",
				  env->requested.ino, err);
			goto fail_issue_read_request;
		}
	}

	ssdfs_segment_search_state_init(&seg_search,
					SSDFS_USER_DATA_SEG_TYPE,
					req->place.start.seg_id, U64_MAX);

	si = ssdfs_grab_segment(fsi, &seg_search);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		err = (si == NULL ? -ENOMEM : PTR_ERR(si));
		SSDFS_ERR("fail to grab segment object: "
			  "seg %llu, err %d\n",
			  req->place.start.seg_id,
			  err);
		goto fail_issue_read_request;
	}

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, ino %llu, err %d\n",
				  si->seg_id, req->extent.ino, err);
			goto fail_issue_read_request;
		}
	}

	err = ssdfs_segment_read_block_async(si, SSDFS_REQ_ASYNC_NO_FREE, req);
	if (unlikely(err)) {
		SSDFS_ERR("read request failed: "
			  "ino %llu, logical_offset %llu, size %u, err %d\n",
			  req->extent.ino, req->extent.logical_offset,
			  req->extent.data_bytes, err);
		goto fail_issue_read_request;
	}

	ssdfs_segment_put_object(si);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return req;

fail_issue_read_request:
	ssdfs_put_request(req);
	ssdfs_request_free(req, si);

	return ERR_PTR(err);
}

static
int ssdfs_readahead_block(struct ssdfs_readahead_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct inode *inode;
	struct folio *folio;
	ino_t ino;
	pgoff_t index;
	loff_t logical_offset;
	loff_t data_bytes;
	loff_t file_size;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env);

	SSDFS_DBG("folios_count %u\n",
		  folio_batch_count(&env->batch));
#endif /* CONFIG_SSDFS_DEBUG */

	inode = file_inode(env->file);
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;

	if (folio_batch_count(&env->batch) == 0) {
		SSDFS_ERR("empty batch\n");
		return -ERANGE;
	}

	folio = env->batch.folios[0];

	index = folio->index;
	logical_offset = (loff_t)index << PAGE_SHIFT;

	file_size = i_size_read(inode);
	data_bytes = file_size - logical_offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(data_bytes > U32_MAX);

	SSDFS_DBG("folio_index %llu, logical_offset %llu, "
		  "file_size %llu, data_bytes %llu\n",
		  (u64)index, (u64)logical_offset,
		  (u64)file_size, (u64)data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	env->requested.ino = ino;
	env->requested.logical_offset = logical_offset;
	env->requested.data_bytes = data_bytes;
	env->requested.cno = 0;
	env->requested.parent_snapshot = 0;

	if (env->place.len == 0) {
		err = __ssdfs_prepare_volume_extent(fsi, inode,
						    &env->requested,
						    &env->place);
		if (err == -EAGAIN) {
			err = 0;
			SSDFS_DBG("logical extent processed partially\n");
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to prepare volume extent: "
				  "ino %llu, logical_offset %llu, "
				  "data_bytes %u, cno %llu, "
				  "parent_snapshot %llu, err %d\n",
				  env->requested.ino,
				  env->requested.logical_offset,
				  env->requested.data_bytes,
				  env->requested.cno,
				  env->requested.parent_snapshot,
				  err);
			goto fail_readahead_block;
		}
	}

	if (env->place.len == 0) {
		err = -ERANGE;
		SSDFS_ERR("found empty extent\n");
		goto fail_readahead_block;
	}

	env->cur_extent.start.seg_id = env->place.start.seg_id;
	env->cur_extent.start.blk_index = env->place.start.blk_index;
	env->cur_extent.len = 1;

	env->place.start.blk_index++;
	env->place.len--;

	env->reqs[env->count] = ssdfs_issue_read_request(env);
	if (IS_ERR_OR_NULL(env->reqs[env->count])) {
		err = (env->reqs[env->count] == NULL ? -ENOMEM :
					PTR_ERR(env->reqs[env->count]));
		env->reqs[env->count] = NULL;

		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("no data for the block: "
				  "index %d\n", env->count);
#endif /* CONFIG_SSDFS_DEBUG */
			goto fail_readahead_block;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to issue request: "
				  "index %d, err %d\n",
				  env->count, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto fail_readahead_block;
		}
	} else
		env->count++;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

fail_readahead_block:
	for (i = 0; i < folio_batch_count(&env->batch); i++) {
		folio = env->batch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

		__ssdfs_memzero_folio(folio, 0, folio_size(folio),
					folio_size(folio));

		folio_clear_uptodate(folio);
		ssdfs_clear_folio_private(folio, 0);
		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);
	}

	return err;
}

/*
 * The ssdfs_readahead() is called by the VM to read pages
 * associated with the address_space object. The pages are
 * consecutive in the page cache and are locked.
 * The implementation should decrement the page refcount
 * after starting I/O on each page. Usually the page will be
 * unlocked by the I/O completion handler. The ssdfs_readahead()
 * is only used for read-ahead, so read errors are ignored.
 */
static
void ssdfs_readahead(struct readahead_control *rac)
{
	struct inode *inode = file_inode(rac->file);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_readahead_env env;
	struct folio *folio;
	pgoff_t index;
	loff_t logical_offset;
	loff_t file_size;
	unsigned i;
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, nr_pages %u\n",
		  file_inode(rac->file)->i_ino,
		  readahead_count(rac));
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_ssdfs_file_inline(ii)) {
		/* do nothing */
		return;
	}

	env.file = rac->file;
	env.count = 0;
	env.capacity = readahead_count(rac);

	env.reqs = ssdfs_file_kcalloc(env.capacity,
				  sizeof(struct ssdfs_segment_request *),
				  GFP_KERNEL);
	if (!env.reqs) {
		SSDFS_ERR("fail to allocate requests array\n");
		return;
	}

	folio_batch_init(&env.batch);
	memset(&env.requested, 0, sizeof(struct ssdfs_logical_extent));
	memset(&env.place, 0, sizeof(struct ssdfs_volume_extent));
	memset(&env.cur_extent, 0, sizeof(struct ssdfs_volume_extent));

	for (i = 0; i < env.capacity; i++) {
		u32 processed_bytes = 0;

		folio_batch_reinit(&env.batch);

		while (processed_bytes < fsi->pagesize) {
			folio = readahead_folio(rac);
			if (!folio) {
				SSDFS_DBG("no more folios\n");

				if (processed_bytes > 0)
					goto try_readahead_block;
				else
					goto finish_requests_processing;
			}

			prefetchw(&folio->flags);

			index = folio->index;
			logical_offset = (loff_t)index << PAGE_SHIFT;
			file_size = i_size_read(file_inode(env.file));

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("index %lu, folio_size %zu, "
				  "logical_offset %llu, file_size %llu\n",
				  index, folio_size(folio),
				  logical_offset, file_size);
#endif /* CONFIG_SSDFS_DEBUG */

			if (logical_offset >= file_size) {
				/* Reading beyond inode */
				err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("Reading beyond inode: "
					  "logical_offset %llu, file_size %llu\n",
					  logical_offset, file_size);
#endif /* CONFIG_SSDFS_DEBUG */
				folio_mark_uptodate(folio);
				flush_dcache_folio(folio);

				if (processed_bytes > 0)
					goto try_readahead_block;
				else
					goto finish_requests_processing;
			}

			ssdfs_folio_get(folio);
			ssdfs_account_locked_folio(folio);

			__ssdfs_memzero_folio(folio, 0, folio_size(folio),
					      folio_size(folio));

			folio_batch_add(&env.batch, folio);

			processed_bytes += folio_size(folio);
		}

try_readahead_block:
		err = ssdfs_readahead_block(&env);
		if (unlikely(err)) {
			SSDFS_ERR("fail to process block: "
				  "index %u, err %d\n",
				  env.count, err);
			break;
		}
	}

finish_requests_processing:
	for (i = 0; i < env.count; i++) {
		res = ssdfs_wait_read_request_end(fsi, env.reqs[i]);
		if (res) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("waiting has finished with issue: "
				  "index %u, err %d\n",
				  i, res);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		if (err == 0)
			err = res;

		env.reqs[i] = NULL;
	}

	if (env.reqs)
		ssdfs_file_kfree(env.reqs);

#ifdef CONFIG_SSDFS_DEBUG
	if (err) {
		SSDFS_DBG("readahead fails: "
			  "ino %lu, nr_pages %u, err %d\n",
			  file_inode(rac->file)->i_ino,
			  readahead_count(rac), err);
	} else {
		SSDFS_DBG("readahead finished: "
			  "ino %lu, nr_pages %u, err %d\n",
			  file_inode(rac->file)->i_ino,
			  readahead_count(rac), err);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return;
}

static ssize_t ssdfs_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct folio *folio;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct address_space *mapping = file->f_mapping;
	pgoff_t start_index = iocb->ki_pos >> PAGE_SHIFT;
	size_t iter_bytes = iov_iter_count(iter);
	u32 processed_bytes;
	size_t folios_count;
	int pages_per_folio = fsi->pagesize >> PAGE_SHIFT;
	fgf_t fgp_flags = FGP_CREAT | FGP_LOCK;
	int i;
	ssize_t res = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, pos %llu, iter_bytes %zu\n",
		  inode->i_ino, iocb->ki_pos, iter_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!iter_bytes)
		return 0;

	if (iocb->ki_pos >= i_size_read(inode))
		return 0;

	iter_bytes = min_t(size_t,
			   iter_bytes, i_size_read(inode) - iocb->ki_pos);
	folios_count = (iter_bytes + fsi->pagesize - 1) >> fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("iter_bytes %zu, folios_count %zu\n",
		  iter_bytes, folios_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!mapping_large_folio_support(mapping))
		goto read_file_content_now;

	if (iter_bytes == 0) {
		SSDFS_DBG("nothing to read: iter_bytes %zu\n",
			  iter_bytes);
		return 0;
	}

	for (i = 0; i < folios_count; i++) {
		pgoff_t cur_index = start_index + (i * pages_per_folio);
		processed_bytes = 0;

		while (processed_bytes < fsi->pagesize) {
			pgoff_t page_index = cur_index +
						(processed_bytes >> PAGE_SHIFT);
			fgp_flags |= fgf_set_order(fsi->pagesize -
						   processed_bytes);

			folio = __filemap_get_folio(mapping,
						    page_index,
						    fgp_flags,
						    mapping_gfp_mask(mapping));
			if (!folio) {
				SSDFS_ERR("fail to grab folio: page_index %lu\n",
					  page_index);
				return -ENOMEM;
			} else if (IS_ERR(folio)) {
				SSDFS_ERR("fail to grab folio: "
					  "page_index %lu, err %ld\n",
					  page_index, PTR_ERR(folio));
				return PTR_ERR(folio);
			}

			ssdfs_account_locked_folio(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, page_index %lu, count %d, "
				  "folio_size %zu, page_size %u, "
				  "fgp_flags %#x, order %u\n",
				  folio, page_index,
				  folio_ref_count(folio),
				  folio_size(folio),
				  fsi->pagesize,
				  fgp_flags,
				  FGF_GET_ORDER(fgp_flags));
#endif /* CONFIG_SSDFS_DEBUG */

			processed_bytes += folio_size(folio);

			ssdfs_folio_unlock(folio);
			ssdfs_folio_put(folio);
		}
	}

read_file_content_now:
	res = generic_file_read_iter(iocb, iter);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished: res %zd\n", res);
#endif /* CONFIG_SSDFS_DEBUG */

	return res;
}

/*
 * ssdfs_check_async_write_request() - check user data write request
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
int ssdfs_check_async_write_request(struct ssdfs_segment_request *req)
{
	wait_queue_head_t *wq = NULL;
	int res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);

	SSDFS_DBG("req %p\n", req);
#endif /* CONFIG_SSDFS_DEBUG */

check_req_state:
	switch (atomic_read(&req->result.state)) {
	case SSDFS_REQ_CREATED:
	case SSDFS_REQ_STARTED:
		wq = &req->private.wait_queue;

		res = wait_event_killable_timeout(*wq,
					has_request_been_executed(req),
					SSDFS_DEFAULT_TIMEOUT);
		if (res < 0) {
			err = res;
			WARN_ON(1);
		} else if (res > 1) {
			/*
			 * Condition changed before timeout
			 */
			goto check_req_state;
		} else {
			/* timeout is elapsed */
			err = -ERANGE;
			WARN_ON(1);
		}
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

		SSDFS_ERR("write request is failed: "
			  "err %d\n", err);
		goto finish_check;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid result's state %#x\n",
			  atomic_read(&req->result.state));
		goto finish_check;
	}

finish_check:
	return err;
}

/*
 * ssdfs_check_sync_write_request() - check user data write request
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
int ssdfs_check_sync_write_request(struct ssdfs_fs_info *fsi,
				   struct ssdfs_segment_request *req)
{
	int i, j;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);

	SSDFS_DBG("req %p\n", req);
#endif /* CONFIG_SSDFS_DEBUG */

	err = SSDFS_WAIT_COMPLETION(&req->result.wait);
	if (unlikely(err)) {
		SSDFS_ERR("write request failed: err %d\n",
			  err);
		return err;
	}

	switch (atomic_read(&req->result.state)) {
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

		SSDFS_ERR("write request is failed: "
			  "err %d\n", err);
		return err;

	default:
		SSDFS_ERR("unexpected result state %#x\n",
			  atomic_read(&req->result.state));
		return -ERANGE;
	}

	if (req->result.err) {
		err = req->result.err;
		SSDFS_ERR("write request failed: err %d\n",
			  req->result.err);
		return req->result.err;
	}

	for (i = 0; i < req->result.content.count; i++) {
		struct ssdfs_request_content_block *block;
		struct ssdfs_content_block *blk_state;

		block = &req->result.content.blocks[i];
		blk_state = &block->new_state;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folio_batch_count(&blk_state->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		for (j = 0; j < folio_batch_count(&blk_state->batch); j++) {
			struct folio *folio = blk_state->batch.folios[j];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			clear_folio_new(folio);
			folio_mark_uptodate(folio);
			ssdfs_clear_dirty_folio(folio);

			ssdfs_folio_unlock(folio);
			ssdfs_folio_end_writeback(fsi, U64_MAX, 0, folio);
			ssdfs_request_writeback_folios_dec(req);
		}
	}

	return 0;
}

static
int ssdfs_wait_write_pool_requests_end(struct ssdfs_fs_info *fsi,
					struct ssdfs_segment_request_pool *pool)
{
	struct ssdfs_segment_request *req;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_search_state seg_search;
	wait_queue_head_t *wait;
	bool has_request_failed = false;
	int i;
	int res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pool %p\n", pool);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!pool)
		return 0;

	if (pool->count == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("request pool is empty\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	switch (pool->req_class) {
	case SSDFS_PEB_CREATE_DATA_REQ:
	case SSDFS_PEB_UPDATE_REQ:
		/* expected class */
		break;

	default:
		SSDFS_ERR("unexpected class of request %#x\n",
			  pool->req_class);
		return -ERANGE;
	}

	switch (pool->req_command) {
	case SSDFS_CREATE_BLOCK:
	case SSDFS_CREATE_EXTENT:
	case SSDFS_UPDATE_BLOCK:
	case SSDFS_UPDATE_EXTENT:
		/* expected class */
		break;

	default:
		SSDFS_ERR("unexpected command of request %#x\n",
			  pool->req_command);
		return -ERANGE;
	}

	switch (pool->req_type) {
	case SSDFS_REQ_SYNC:
		for (i = 0; i < pool->count; i++) {
			req = pool->pointers[i];

			if (!req) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("request %d is empty\n", i);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			err = ssdfs_check_sync_write_request(fsi, req);
			if (unlikely(err)) {
				SSDFS_ERR("request %d is failed: err %d\n",
					  i, err);
				has_request_failed = true;
			}

			ssdfs_put_request(req);
			ssdfs_request_free(req, NULL);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("request %d is freed\n", i);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		ssdfs_segment_request_pool_init(pool);
		break;

	case SSDFS_REQ_ASYNC_NO_FREE:
		for (i = 0; i < pool->count; i++) {
			req = pool->pointers[i];

			if (!req) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("request %d is empty\n", i);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			err = ssdfs_check_async_write_request(req);
			if (unlikely(err)) {
				SSDFS_ERR("request %d is failed: err %d\n",
					  i, err);
				has_request_failed = true;
			}

			ssdfs_put_request(req);

			ssdfs_segment_search_state_init(&seg_search,
						SSDFS_USER_DATA_SEG_TYPE,
						req->place.start.seg_id,
						U64_MAX);

			si = ssdfs_grab_segment(fsi, &seg_search);
			if (unlikely(IS_ERR_OR_NULL(si))) {
				err = (si == NULL ? -ENOMEM : PTR_ERR(si));
				SSDFS_ERR("fail to grab segment object: "
					  "seg %llu, err %d\n",
					  req->place.start.seg_id,
					  err);
				continue;
			}

			wait = &si->wait_queue[SSDFS_PEB_READ_THREAD];

			if (atomic_read(&req->private.refs_count) != 0) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("start waiting: refs_count %d\n",
					   atomic_read(&req->private.refs_count));
#endif /* CONFIG_SSDFS_DEBUG */

				res = wait_event_killable_timeout(*wait,
				    atomic_read(&req->private.refs_count) == 0,
				    SSDFS_DEFAULT_TIMEOUT);
				if (res < 0) {
					err = res;
					WARN_ON(1);
				} else if (res > 1) {
					/*
					 * Condition changed before timeout
					 */
				} else {
					/* timeout is elapsed */
					err = -ERANGE;
					WARN_ON(1);
				}
			}

			ssdfs_segment_put_object(si);

			ssdfs_request_free(req, si);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("request %d is freed\n", i);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		ssdfs_segment_request_pool_init(pool);
		break;

	case SSDFS_REQ_ASYNC:
		ssdfs_segment_request_pool_init(pool);
		break;

	default:
		SSDFS_ERR("unknown request type %#x\n",
			  pool->req_type);
		return -ERANGE;
	}

	if (has_request_failed)
		return -ERANGE;

	return 0;
}

static
void ssdfs_clean_failed_request_pool(struct ssdfs_segment_request_pool *pool)
{
	struct ssdfs_segment_request *req;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pool %p\n", pool);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!pool)
		return;

	if (pool->count == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("request pool is empty\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return;
	}

	switch (pool->req_type) {
	case SSDFS_REQ_SYNC:
	case SSDFS_REQ_ASYNC_NO_FREE:
		for (i = 0; i < pool->count; i++) {
			req = pool->pointers[i];

			if (!req) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("request %d is empty\n", i);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			ssdfs_request_free(req, NULL);
		}
		break;

	case SSDFS_REQ_ASYNC:
		/* do nothing */
		break;

	default:
		SSDFS_ERR("unknown request type %#x\n",
			  pool->req_type);
	}
}

/*
 * ssdfs_update_block() - update block.
 * @fsi: pointer on shared file system object
 * @pool: segment request pool
 * @batch: dirty memory folios batch
 */
static
int ssdfs_update_block(struct ssdfs_fs_info *fsi,
		       struct ssdfs_segment_request_pool *pool,
		       struct ssdfs_dirty_folios_batch *batch,
		       struct writeback_control *wbc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_search_state seg_search;
	struct folio *folio;
	struct inode *inode;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pool || !batch);

	if (batch->content.count == 0) {
		SSDFS_ERR("batch is empty\n");
		return -ERANGE;
	}

	SSDFS_DBG("fsi %p, pool %p, batch %p\n",
		  fsi, pool, batch);
#endif /* CONFIG_SSDFS_DEBUG */

	if (batch->processed_blks >= batch->content.count) {
		SSDFS_ERR("processed_blks %u >= batch_size %u\n",
			  batch->processed_blks,
			  batch->content.count);
		return -ERANGE;
	}

	folio = batch->content.blocks[batch->processed_blks].batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = folio->mapping->host;

	err = __ssdfs_prepare_volume_extent(fsi, inode,
					    &batch->requested_extent,
					    &batch->place);
	if (err == -EAGAIN) {
		err = 0;
		SSDFS_DBG("logical extent processed partially\n");
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to prepare volume extent: "
			  "ino %llu, logical_offset %llu, "
			  "data_bytes %u, cno %llu, "
			  "parent_snapshot %llu, err %d\n",
			  batch->requested_extent.ino,
			  batch->requested_extent.logical_offset,
			  batch->requested_extent.data_bytes,
			  batch->requested_extent.cno,
			  batch->requested_extent.parent_snapshot,
			  err);
		return err;
	}

	ssdfs_segment_search_state_init(&seg_search,
					SSDFS_USER_DATA_SEG_TYPE,
					batch->place.start.seg_id,
					U64_MAX);

	si = ssdfs_grab_segment(fsi, &seg_search);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		SSDFS_ERR("fail to grab segment object: "
			  "seg %llu, err %d\n",
			  batch->place.start.seg_id, err);
		return PTR_ERR(si);
	}

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, err %d\n",
				  si->seg_id, err);
			return err;
		}
	}

	if (wbc->sync_mode == WB_SYNC_NONE) {
		err = ssdfs_segment_update_data_block_async(si,
						       SSDFS_REQ_ASYNC,
						       pool, batch);
	} else if (wbc->sync_mode == WB_SYNC_ALL)
		err = ssdfs_segment_update_data_block_sync(si, pool, batch);
	else
		BUG();

	if (err == -EAGAIN) {
		SSDFS_DBG("wait finishing requests in pool\n");
	} else if (unlikely(err)) {
		SSDFS_ERR("update request failed: "
			  "ino %llu, logical_offset %llu, size %u, err %d\n",
			  batch->requested_extent.ino,
			  batch->requested_extent.logical_offset,
			  batch->requested_extent.data_bytes,
			  err);
	}

	ssdfs_segment_put_object(si);

	return err;
}

/*
 * ssdfs_update_extent() - update extent.
 * @fsi: pointer on shared file system object
 * @pool: segment request pool
 * @batch: dirty memory folios batch
 */
static
int ssdfs_update_extent(struct ssdfs_fs_info *fsi,
			struct ssdfs_segment_request_pool *pool,
			struct ssdfs_dirty_folios_batch *batch,
			struct writeback_control *wbc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_search_state seg_search;
	struct folio *folio;
	struct inode *inode;
	u32 batch_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pool || !batch);

	if (batch->content.count == 0) {
		SSDFS_ERR("batch is empty\n");
		return -ERANGE;
	}

	SSDFS_DBG("fsi %p, pool %p, batch %p\n",
		  fsi, pool, batch);
#endif /* CONFIG_SSDFS_DEBUG */

	batch_size = batch->content.count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("batch_size %u, batch->processed_blks %u\n",
		  batch_size,
		  batch->processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	if (batch->processed_blks >= batch_size) {
		SSDFS_ERR("processed_blks %u >= batch_size %u\n",
			  batch->processed_blks, batch_size);
		return -ERANGE;
	}

	folio = batch->content.blocks[batch->processed_blks].batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = folio->mapping->host;

	while (batch->processed_blks < batch_size) {
		err = __ssdfs_prepare_volume_extent(fsi, inode,
						    &batch->requested_extent,
						    &batch->place);
		if (err == -EAGAIN) {
			err = 0;
			SSDFS_DBG("logical extent processed partially\n");
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to prepare volume extent: "
				  "ino %llu, logical_offset %llu, "
				  "data_bytes %u, cno %llu, "
				  "parent_snapshot %llu, err %d\n",
				  batch->requested_extent.ino,
				  batch->requested_extent.logical_offset,
				  batch->requested_extent.data_bytes,
				  batch->requested_extent.cno,
				  batch->requested_extent.parent_snapshot,
				  err);
			return err;
		}

		ssdfs_segment_search_state_init(&seg_search,
						SSDFS_USER_DATA_SEG_TYPE,
						batch->place.start.seg_id,
						U64_MAX);

		si = ssdfs_grab_segment(fsi, &seg_search);
		if (unlikely(IS_ERR_OR_NULL(si))) {
			SSDFS_ERR("fail to grab segment object: "
				  "seg %llu, err %d\n",
				  batch->place.start.seg_id, err);
			return PTR_ERR(si);
		}

		if (!is_ssdfs_segment_ready_for_requests(si)) {
			err = ssdfs_wait_segment_init_end(si);
			if (unlikely(err)) {
				SSDFS_ERR("segment initialization failed: "
					  "seg %llu, err %d\n",
					  si->seg_id, err);
				return err;
			}
		}

		if (wbc->sync_mode == WB_SYNC_NONE) {
			err = ssdfs_segment_update_data_extent_async(si,
							    SSDFS_REQ_ASYNC,
							    pool, batch);
		} else if (wbc->sync_mode == WB_SYNC_ALL)
			err = ssdfs_segment_update_data_extent_sync(si,
							    pool, batch);
		else
			BUG();

		ssdfs_segment_put_object(si);

		if (err == -EAGAIN) {
			if (batch->processed_blks >= batch_size) {
				err = -ERANGE;
				SSDFS_ERR("processed_blks %u >= batch_size %u\n",
					  batch->processed_blks, batch_size);
				goto finish_update_extent;
			} else {
				err = 0;
				/* process the rest of memory pages */
				continue;
			}
		} else if (err == -ENOSPC) {
			err = -EAGAIN;
			SSDFS_DBG("wait finishing requests in pool\n");
			goto finish_update_extent;
		} else if (unlikely(err)) {
			SSDFS_ERR("update request failed: "
				  "ino %llu, logical_offset %llu, "
				  "size %u, err %d\n",
				  batch->requested_extent.ino,
				  batch->requested_extent.logical_offset,
				  batch->requested_extent.data_bytes,
				  err);
			goto finish_update_extent;
		}
	}

finish_update_extent:
	return err;
}

static
int ssdfs_issue_async_block_write_request(struct writeback_control *wbc,
					  struct ssdfs_segment_request_pool *pool,
					  struct ssdfs_dirty_folios_batch *batch)
{
	struct folio *folio;
	struct inode *inode;
	struct ssdfs_inode_info *ii;
	struct ssdfs_fs_info *fsi;
	ino_t ino;
	u64 logical_offset;
	u32 data_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !pool || !batch);

	if (batch->content.count == 0) {
		SSDFS_ERR("batch is empty\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (batch->processed_blks >= batch->content.count) {
		SSDFS_ERR("processed_blks %u >= batch_size %u\n",
			  batch->processed_blks,
			  batch->content.count);
		return -ERANGE;
	}

	folio = batch->content.blocks[batch->processed_blks].batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = folio->mapping->host;
	ii = SSDFS_I(inode);
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;
	logical_offset = batch->requested_extent.logical_offset;
	data_bytes = batch->requested_extent.data_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "data_bytes %u, sync_mode %#x\n",
		  ino, logical_offset, data_bytes, wbc->sync_mode);
#endif /* CONFIG_SSDFS_DEBUG */

	if (need_add_block(folio)) {
		err = ssdfs_segment_add_data_block_async(fsi, pool, batch);
		if (err == -EAGAIN) {
			SSDFS_DBG("wait finishing requests in pool\n");
			return err;
		}
	} else {
		err = ssdfs_update_block(fsi, pool, batch, wbc);
		if (err == -EAGAIN) {
			SSDFS_DBG("wait finishing requests in pool\n");
			return err;
		}
	}

	if (err) {
		SSDFS_ERR("fail to write folio async: "
			  "ino %lu, folio_index %llu, err %d\n",
			  ino, (u64)folio->index, err);
		return err;
	}

	return 0;
}

static
int ssdfs_issue_sync_block_write_request(struct writeback_control *wbc,
					 struct ssdfs_segment_request_pool *pool,
					 struct ssdfs_dirty_folios_batch *batch)
{
	struct folio *folio;
	struct inode *inode;
	struct ssdfs_inode_info *ii;
	struct ssdfs_fs_info *fsi;
	ino_t ino;
	u64 logical_offset;
	u32 data_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !pool || !batch);

	if (batch->content.count == 0) {
		SSDFS_ERR("batch is empty\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (batch->processed_blks >= batch->content.count) {
		SSDFS_ERR("processed_blks %u >= batch_size %u\n",
			  batch->processed_blks,
			  batch->content.count);
		return -ERANGE;
	}

	folio = batch->content.blocks[batch->processed_blks].batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = folio->mapping->host;
	ii = SSDFS_I(inode);
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;
	logical_offset = batch->requested_extent.logical_offset;
	data_bytes = batch->requested_extent.data_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "data_bytes %u, sync_mode %#x\n",
		  ino, logical_offset, data_bytes, wbc->sync_mode);
#endif /* CONFIG_SSDFS_DEBUG */

	if (need_add_block(folio)) {
		err = ssdfs_segment_add_data_block_sync(fsi, pool, batch);
		if (err == -EAGAIN) {
			SSDFS_DBG("wait finishing requests in pool\n");
			return err;
		}
	} else {
		err = ssdfs_update_block(fsi, pool, batch, wbc);
		if (err == -EAGAIN) {
			SSDFS_DBG("wait finishing requests in pool\n");
			return err;
		}
	}

	if (err) {
		SSDFS_ERR("fail to write folio sync: "
			  "ino %lu, folio_index %llu, err %d\n",
			  ino, (u64)folio->index, err);
		return err;
	}

	return 0;
}

static
int ssdfs_issue_async_extent_write_request(struct writeback_control *wbc,
					   struct ssdfs_segment_request_pool *pool,
					   struct ssdfs_dirty_folios_batch *batch)
{
	struct folio *folio;
	struct inode *inode;
	struct ssdfs_inode_info *ii;
	struct ssdfs_fs_info *fsi;
	ino_t ino;
	u64 logical_offset;
	u32 data_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !pool || !batch);

	if (batch->content.count == 0) {
		SSDFS_ERR("batch is empty\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (batch->processed_blks >= batch->content.count) {
		SSDFS_ERR("processed_blks %u >= batch_size %u\n",
			  batch->processed_blks,
			  batch->content.count);
		return -ERANGE;
	}

	folio = batch->content.blocks[batch->processed_blks].batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = folio->mapping->host;
	ii = SSDFS_I(inode);
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;
	logical_offset = batch->requested_extent.logical_offset;
	data_bytes = batch->requested_extent.data_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "data_bytes %u, sync_mode %#x\n",
		  ino, logical_offset, data_bytes, wbc->sync_mode);
#endif /* CONFIG_SSDFS_DEBUG */

	if (need_add_block(folio)) {
		err = ssdfs_segment_add_data_extent_async(fsi, pool, batch);
		if (err == -EAGAIN) {
			SSDFS_DBG("wait finishing requests in pool\n");
			return err;
		}
	} else {
		err = ssdfs_update_extent(fsi, pool, batch, wbc);
		if (err == -EAGAIN) {
			SSDFS_DBG("wait finishing requests in pool\n");
			return err;
		}
	}

	if (err) {
		SSDFS_ERR("fail to write extent async: "
			  "ino %lu, folio_index %llu, err %d\n",
			  ino, (u64)folio->index, err);
		return err;
	}

	return 0;
}

static
int ssdfs_issue_sync_extent_write_request(struct writeback_control *wbc,
					struct ssdfs_segment_request_pool *pool,
					struct ssdfs_dirty_folios_batch *batch)
{
	struct folio *folio;
	struct inode *inode;
	struct ssdfs_inode_info *ii;
	struct ssdfs_fs_info *fsi;
	ino_t ino;
	u64 logical_offset;
	u32 data_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !pool || !batch);

	if (batch->content.count == 0) {
		SSDFS_ERR("batch is empty\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (batch->processed_blks >= batch->content.count) {
		SSDFS_ERR("processed_blks %u >= batch_size %u\n",
			  batch->processed_blks,
			  batch->content.count);
		return -ERANGE;
	}

	folio = batch->content.blocks[batch->processed_blks].batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = folio->mapping->host;
	ii = SSDFS_I(inode);
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;
	logical_offset = batch->requested_extent.logical_offset;
	data_bytes = batch->requested_extent.data_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "data_bytes %u, sync_mode %#x\n",
		  ino, logical_offset, data_bytes, wbc->sync_mode);
#endif /* CONFIG_SSDFS_DEBUG */

	if (need_add_block(folio)) {
		err = ssdfs_segment_add_data_extent_sync(fsi, pool, batch);
		if (err == -EAGAIN) {
			SSDFS_DBG("wait finishing requests in pool\n");
			return err;
		}
	} else {
		err = ssdfs_update_extent(fsi, pool, batch, wbc);
		if (err == -EAGAIN) {
			SSDFS_DBG("wait finishing requests in pool\n");
			return err;
		}
	}

	if (err) {
		SSDFS_ERR("fail to write folio sync: "
			  "ino %lu, folio_index %llu, err %d\n",
			  ino, (u64)folio->index, err);
		return err;
	}

	return 0;
}

static
int ssdfs_issue_async_write_request(struct ssdfs_fs_info *fsi,
			      struct writeback_control *wbc,
			      struct ssdfs_segment_request_pool *pool,
			      struct ssdfs_dirty_folios_batch *batch,
			      int req_type)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !pool || !batch);
#endif /* CONFIG_SSDFS_DEBUG */

	if (req_type == SSDFS_BLOCK_BASED_REQUEST) {
		err = ssdfs_issue_async_block_write_request(wbc, pool, batch);
		if (err == -EAGAIN) {
			wake_up_all(&fsi->pending_wq);

			err = ssdfs_wait_write_pool_requests_end(fsi, pool);
			if (unlikely(err)) {
				SSDFS_ERR("write request failed: err %d\n",
					  err);
				return err;
			}

			err = ssdfs_issue_async_block_write_request(wbc,
								pool, batch);
		}
	} else if (req_type == SSDFS_EXTENT_BASED_REQUEST) {
		err = ssdfs_issue_async_extent_write_request(wbc, pool, batch);
		if (err == -EAGAIN) {
			wake_up_all(&fsi->pending_wq);

			err = ssdfs_wait_write_pool_requests_end(fsi, pool);
			if (unlikely(err)) {
				SSDFS_ERR("write request failed: err %d\n",
					  err);
				return err;
			}

			err = ssdfs_issue_async_extent_write_request(wbc,
								pool, batch);
		}
	} else
		BUG();

	if (err) {
		SSDFS_ERR("fail to write async: err %d\n",
			  err);
	}

	wake_up_all(&fsi->pending_wq);

	return err;
}

static
int ssdfs_issue_sync_write_request(struct ssdfs_fs_info *fsi,
				   struct writeback_control *wbc,
				   struct ssdfs_segment_request_pool *pool,
				   struct ssdfs_dirty_folios_batch *batch,
				   int req_type)
{
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !pool || !batch);
#endif /* CONFIG_SSDFS_DEBUG */

	if (req_type == SSDFS_BLOCK_BASED_REQUEST) {
		err = ssdfs_issue_sync_block_write_request(wbc, pool, batch);
		if (err == -EAGAIN) {
			wake_up_all(&fsi->pending_wq);

			err = ssdfs_wait_write_pool_requests_end(fsi, pool);
			if (unlikely(err)) {
				SSDFS_ERR("write request failed: err %d\n",
					  err);
				return err;
			}

			err = ssdfs_issue_sync_block_write_request(wbc,
								pool, batch);
		}
	} else if (req_type == SSDFS_EXTENT_BASED_REQUEST) {
		err = ssdfs_issue_sync_extent_write_request(wbc, pool, batch);
		if (err == -EAGAIN) {
			wake_up_all(&fsi->pending_wq);

			err = ssdfs_wait_write_pool_requests_end(fsi, pool);
			if (unlikely(err)) {
				SSDFS_ERR("write request failed: err %d\n",
					  err);
				return err;
			}

			err = ssdfs_issue_sync_extent_write_request(wbc,
								pool, batch);
		}
	} else
		BUG();

	if (err) {
		SSDFS_ERR("fail to write sync: err %d\n",
			  err);

		for (i = 0; i < batch->content.count; i++) {
			struct ssdfs_content_block *blk_state;
			u32 batch_size;

			blk_state = &batch->content.blocks[i];
			batch_size = folio_batch_count(&blk_state->batch);

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(batch_size == 0);
#endif /* CONFIG_SSDFS_DEBUG */

			for (j = 0; j < batch_size; j++) {
				struct folio *folio;

				folio = blk_state->batch.folios[j];

#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

				if (!folio_test_locked(folio)) {
					SSDFS_WARN("folio %p, folio_test_locked %#x\n",
						   folio, folio_test_locked(folio));
					ssdfs_folio_lock(folio);
				}

				clear_folio_new(folio);
				folio_mark_uptodate(folio);
				folio_clear_dirty(folio);

				ssdfs_folio_unlock(folio);
				ssdfs_folio_end_writeback(fsi, U64_MAX, 0, folio);
			}
		}
	}

	wake_up_all(&fsi->pending_wq);

	return err;
}

static
int ssdfs_issue_write_request(struct writeback_control *wbc,
			      struct ssdfs_segment_request_pool *pool,
			      struct ssdfs_dirty_folios_batch *batch,
			      int req_type)
{
	struct ssdfs_fs_info *fsi;
	struct inode *inode;
	struct address_space *mapping;
	struct folio *folio;
	struct ssdfs_content_block *blk_state;
	ino_t ino;
	u64 logical_offset;
	u32 data_bytes;
	u64 start_index;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !pool || !batch);

	if (batch->content.count == 0) {
		SSDFS_WARN("batch is empty\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	folio = batch->content.blocks[0].batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = folio->mapping->host;
	mapping = folio->mapping;
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;
	logical_offset = batch->requested_extent.logical_offset;
	data_bytes = batch->requested_extent.data_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "data_bytes %u, sync_mode %#x\n",
		  ino, logical_offset, data_bytes, wbc->sync_mode);

	if (logical_offset % fsi->pagesize) {
		SSDFS_ERR("logical_offset %llu, pagesize %u\n",
			  logical_offset, fsi->pagesize);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < batch->content.count; i++) {
		size_t block_bytes = 0;
		pgoff_t index;
		pgoff_t last_folio_index;

		blk_state = &batch->content.blocks[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folio_batch_count(&blk_state->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		for (j = 0; j < folio_batch_count(&blk_state->batch); j++) {
			folio = blk_state->batch.folios[j];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);

			SSDFS_DBG("folio_index %llu\n",
				  (u64)folio->index);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_folio_start_writeback(fsi, U64_MAX,
						    logical_offset, folio);
			ssdfs_clear_dirty_folio(folio);

			block_bytes += folio_size(folio);
		}

		if (block_bytes != fsi->pagesize) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("ino %lu, logical_offset %llu, "
				  "data_bytes %u, blk_index %d, "
				  "block_bytes %zu, pagesize %u\n",
				  ino, logical_offset, data_bytes, i,
				  block_bytes, fsi->pagesize);
#endif /* CONFIG_SSDFS_DEBUG */

			last_folio_index = folio_batch_count(&blk_state->batch);

			if (last_folio_index == 0) {
				err = -ERANGE;
				SSDFS_ERR("empty block: blk_index %d\n", i);
				goto finish_issue_write_request;
			}

			folio = blk_state->batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			start_index = logical_offset + (i * fsi->pagesize);
			start_index >>= PAGE_SHIFT;
			index = folio->index;

			if (start_index != index) {
				err = -ERANGE;
				SSDFS_WARN("block batch hasn't first folio: "
					   "ino %lu, logical_offset %llu, "
					   "data_bytes %u, blk_index %d, "
					   "block_bytes %zu, pagesize %u, "
					   "start_index %llu, index %lu\n",
					   ino, logical_offset, data_bytes, i,
					   block_bytes, fsi->pagesize,
					   start_index, index);
				goto finish_issue_write_request;
			}

			last_folio_index--;

			folio = blk_state->batch.folios[last_folio_index];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			while (block_bytes < fsi->pagesize) {
				pgoff_t mem_pages_per_folio =
						folio_size(folio) / PAGE_SIZE;

				last_folio_index = folio->index;
				last_folio_index += mem_pages_per_folio;

				folio = filemap_get_folio(mapping,
							   last_folio_index);
				if (IS_ERR(folio) && PTR_ERR(folio) == -ENOENT) {
					folio = filemap_grab_folio(mapping,
							    last_folio_index);
					if (!folio) {
						err = -ERANGE;
						SSDFS_ERR("empty folio: "
							  "folio_index %lu\n",
							  last_folio_index);
						goto finish_issue_write_request;
					} else if (IS_ERR(folio)) {
						err = PTR_ERR(folio);
						SSDFS_ERR("fail to grab folio: "
							  "folio_index %lu, err %d\n",
							  last_folio_index,
							  err);
						goto finish_issue_write_request;
					}

					__ssdfs_memzero_folio(folio, 0,
							      folio_size(folio),
							      folio_size(folio));

					ssdfs_account_locked_folio(folio);
					folio_mark_uptodate(folio);
					folio_mark_dirty(folio);
					ssdfs_folio_start_writeback(fsi, U64_MAX,
								    logical_offset, folio);
					ssdfs_clear_dirty_folio(folio);
					folio_batch_add(&blk_state->batch,
							folio);
				} else if (IS_ERR(folio)) {
					err = PTR_ERR(folio);
					SSDFS_ERR("fail to get folio: "
						  "folio_index %lu, err %d\n",
						  last_folio_index, err);
					goto finish_issue_write_request;
				} else {
					if (!folio_test_locked(folio))
						ssdfs_folio_lock(folio);
					else
						ssdfs_account_locked_folio(folio);

					folio_mark_uptodate(folio);
					folio_mark_dirty(folio);
					ssdfs_folio_start_writeback(fsi, U64_MAX,
								    logical_offset, folio);
					ssdfs_clear_dirty_folio(folio);
					folio_batch_add(&blk_state->batch,
							folio);
				}

				block_bytes += folio_size(folio);
			}
		}
	}

	if (wbc->sync_mode == WB_SYNC_NONE) {
		err = ssdfs_issue_async_write_request(fsi, wbc, pool,
							batch, req_type);
		if (err) {
			SSDFS_ERR("fail to write async: "
				  "ino %lu, err %d\n",
				  ino, err);
			goto finish_issue_write_request;
		}
	} else if (wbc->sync_mode == WB_SYNC_ALL) {
		err = ssdfs_issue_sync_write_request(fsi, wbc, pool,
						     batch, req_type);
		if (err) {
			SSDFS_ERR("fail to write sync: "
				  "ino %lu, err %d\n",
				  ino, err);
			goto finish_issue_write_request;
		}
	} else
		BUG();

finish_issue_write_request:
	if (unlikely(err)) {
		for (i = 0; i < batch->content.count; i++) {
			blk_state = &batch->content.blocks[i];

			for (j = 0; j < folio_batch_count(&blk_state->batch); j++) {
				folio = blk_state->batch.folios[j];

				if (!folio)
					continue;

				SSDFS_ERR("BLK[%d][%d] folio_index %llu, folio_size %zu\n",
					  i, j,
					  (u64)folio->index,
					  folio_size(folio));
			}

		}
	}

	ssdfs_dirty_folios_batch_init(batch);

	return err;
}

static
int __ssdfs_writepages(struct folio *folio, u32 len,
			struct writeback_control *wbc,
			struct ssdfs_segment_request_pool *pool,
			struct ssdfs_dirty_folios_batch *batch)
{
	struct inode *inode = folio->mapping->host;
	struct address_space *mapping = folio->mapping;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	ino_t ino = inode->i_ino;
	pgoff_t start_index;
	pgoff_t index = folio->index;
	loff_t logical_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, folio_index %llu, len %u, sync_mode %#x\n",
		  ino, (u64)index, len, wbc->sync_mode);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_offset = (loff_t)index << PAGE_SHIFT;

try_add_folio_into_request:
	if (is_ssdfs_logical_extent_invalid(&batch->requested_extent)) {
		if (logical_offset % fsi->pagesize) {
			struct folio *cur_folio;
			pgoff_t cur_blk;
			pgoff_t cur_index;
			pgoff_t mem_pages_per_folio;
			u32 processed_bytes = 0;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("logical_offset %llu, pagesize %u\n",
				  logical_offset, fsi->pagesize);
#endif /* CONFIG_SSDFS_DEBUG */

			cur_blk = batch->content.count;

			start_index = logical_offset >> fsi->log_pagesize;
			start_index <<= fsi->log_pagesize;
			start_index >>= PAGE_SHIFT;

			cur_index = start_index;
			while (cur_index < index) {
				cur_folio = filemap_get_folio(mapping,
							      cur_index);
				if (IS_ERR_OR_NULL(cur_folio)) {
					err = IS_ERR(cur_folio) ?
						PTR_ERR(cur_folio) : -ERANGE;
					SSDFS_ERR("fail to get folio: "
						  "folio_index %lu, err %d\n",
						  cur_index, err);
					goto fail_write_folios;
				}

				if (!folio_test_locked(cur_folio))
					ssdfs_folio_lock(cur_folio);
				else
					ssdfs_account_locked_folio(cur_folio);

#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(!folio_test_uptodate(cur_folio));
#endif /* CONFIG_SSDFS_DEBUG */

				folio_mark_dirty(cur_folio);
				ssdfs_folio_start_writeback(fsi, U64_MAX,
						    logical_offset, cur_folio);
				ssdfs_clear_dirty_folio(cur_folio);

				err =
				    ssdfs_dirty_folios_batch_add_folio(cur_folio,
									cur_blk,
									batch);
				if (err) {
					SSDFS_ERR("fail to add folio into batch: "
						  "ino %lu, folio_index %lu, err %d\n",
						  ino, index, err);
					goto fail_write_folios;
				}

				mem_pages_per_folio =
					folio_size(cur_folio) >> PAGE_SHIFT;
				cur_index = cur_folio->index;
				cur_index += mem_pages_per_folio;

				processed_bytes += folio_size(cur_folio);

#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(cur_index > index);
#endif /* CONFIG_SSDFS_DEBUG */
			}

			logical_offset = (loff_t)start_index << PAGE_SHIFT;
			len += processed_bytes;

			err = ssdfs_dirty_folios_batch_add_folio(folio,
								 cur_blk,
								 batch);
			if (err) {
				SSDFS_ERR("fail to add folio into batch: "
					  "ino %lu, folio_index %lu, err %d\n",
					  ino, index, err);
				goto fail_write_folios;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("logical_offset %llu, len %u\n",
				  (u64)logical_offset, len);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_dirty_folios_batch_prepare_logical_extent(ino,
							(u64)logical_offset,
							len, 0, 0,
							batch);

			err = ssdfs_issue_write_request(wbc, pool, batch,
						    SSDFS_EXTENT_BASED_REQUEST);
			if (err)
				goto fail_write_folios;
		} else {
			err = ssdfs_dirty_folios_batch_add_folio(folio,
							 batch->content.count,
							 batch);
			if (err) {
				SSDFS_ERR("fail to add folio into batch: "
					  "ino %lu, folio_index %lu, err %d\n",
					  ino, index, err);
				goto fail_write_folios;
			}

			ssdfs_dirty_folios_batch_prepare_logical_extent(ino,
							(u64)logical_offset,
							len, 0, 0,
							batch);
		}
	} else {
		struct ssdfs_content_block *blk_state;
		struct folio *last_folio;
		u64 upper_bound = batch->requested_extent.logical_offset +
					batch->requested_extent.data_bytes;
		u32 last_blk;
		u32 last_index;

		if (batch->content.count == 0) {
			err = -ERANGE;
			SSDFS_WARN("batch is empty\n");
			goto fail_write_folios;
		}

		last_blk = batch->content.count - 1;
		blk_state = &batch->content.blocks[last_blk];

		last_index = folio_batch_count(&blk_state->batch);
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(last_index == 0);
#endif /* CONFIG_SSDFS_DEBUG */
		last_index -= 1;

		last_folio = blk_state->batch.folios[last_index];

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("logical_offset %llu, upper_bound %llu, "
			  "last_index %u\n",
			  (u64)logical_offset, upper_bound, last_index);

		BUG_ON(!last_folio);
#endif /* CONFIG_SSDFS_DEBUG */

		last_index = last_folio->index;

		if (last_index == index) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("last_index %u == index %lu\n",
				  last_index, index);
#endif /* CONFIG_SSDFS_DEBUG */
			return 0;
		}

		if (logical_offset == upper_bound &&
		    can_be_merged_into_extent(last_folio, folio)) {
			pgoff_t logical_blk1, logical_blk2;
			pgoff_t cur_blk;

			logical_blk1 = last_folio->index;
			logical_blk1 <<= PAGE_SHIFT;
			logical_blk1 >>= fsi->log_pagesize;

			logical_blk2 = folio->index;
			logical_blk2 <<= PAGE_SHIFT;
			logical_blk2 >>= fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio can be merged into extent: "
				  "LAST FOLIO: (folio_index %lu, "
				  "logical_blk %lu), "
				  "CURRENT FOLIO: (folio_index %lu, "
				  "logical_blk %lu)\n",
				  last_folio->index,
				  logical_blk1,
				  folio->index,
				  logical_blk2);
#endif /* CONFIG_SSDFS_DEBUG */

			if (logical_blk1 == logical_blk2)
				cur_blk = last_blk;
			else
				cur_blk = batch->content.count;

			err = ssdfs_dirty_folios_batch_add_folio(folio,
								 cur_blk,
								 batch);
			if (err) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to add folio: "
					  "cur_blk %lu, folio_index %lu, "
					  "err %d\n",
					  cur_blk,
					  folio->index,
					  err);
#endif /* CONFIG_SSDFS_DEBUG */

				err = ssdfs_issue_write_request(wbc,
						    pool, batch,
						    SSDFS_EXTENT_BASED_REQUEST);
				if (err)
					goto fail_write_folios;
				else
					goto try_add_folio_into_request;
			}

			batch->requested_extent.data_bytes += len;
		} else {
			err = ssdfs_issue_write_request(wbc, pool, batch,
						    SSDFS_EXTENT_BASED_REQUEST);
			if (err)
				goto fail_write_folios;
			else
				goto try_add_folio_into_request;
		}
	}

	return 0;

fail_write_folios:
	return err;
}

/* writepage function prototype */
typedef int (*ssdfs_writepagefn)(struct folio *folio, u32 len,
				 struct writeback_control *wbc,
				 struct ssdfs_segment_request_pool *pool,
				 struct ssdfs_dirty_folios_batch *batch);

static
int ssdfs_writepage_wrapper(struct folio *folio,
			    struct writeback_control *wbc,
			    struct ssdfs_segment_request_pool *pool,
			    struct ssdfs_dirty_folios_batch *batch,
			    ssdfs_writepagefn writepage)
{
	struct inode *inode = folio->mapping->host;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	ino_t ino = inode->i_ino;
	pgoff_t index = folio->index;
	loff_t i_size = i_size_read(inode);
	pgoff_t end_index = i_size >> PAGE_SHIFT;
	int len = i_size & (folio_size(folio) - 1);
	loff_t cur_blk;
	u32 offset_inside_block;
	bool is_new_blk = false;
#ifdef CONFIG_SSDFS_DEBUG
	u32 folio_processed_bytes = 0;
	void *kaddr;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, page_index %llu, "
		  "i_size %llu, len %d\n",
		  ino, (u64)index,
		  (u64)i_size, len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (inode->i_sb->s_flags & SB_RDONLY) {
		/*
		 * It means that filesystem was remounted in read-only
		 * mode because of error or metadata corruption. But we
		 * have dirty pages that try to be flushed in background.
		 * So, here we simply discard this dirty page.
		 */
		err = -EROFS;
		goto discard_folio;
	}

	/* Is the page fully outside @i_size? (truncate in progress) */
	if (index > end_index) {
		err = 0;
		goto finish_write_folio;
	}

	if (is_ssdfs_file_inline(ii)) {
		size_t inline_capacity =
				ssdfs_inode_inline_file_capacity(inode);

		if (len > inline_capacity) {
			err = -ENOSPC;
			SSDFS_ERR("len %d is greater capacity %zu\n",
				  len, inline_capacity);
			goto discard_folio;
		}

		ssdfs_folio_start_writeback(fsi, U64_MAX, 0, folio);

		err = __ssdfs_memcpy_from_folio(ii->inline_file,
						0, inline_capacity,
						folio,
						0, folio_size(folio),
						len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy file's content: "
				  "err %d\n", err);
			goto discard_folio;
		}

		inode_add_bytes(inode, len);

		clear_folio_new(folio);
		folio_mark_uptodate(folio);
		folio_clear_dirty(folio);

		ssdfs_folio_unlock(folio);
		ssdfs_folio_end_writeback(fsi, U64_MAX, 0, folio);

		return 0;
	}

	cur_blk = ((u64)index << PAGE_SHIFT) >> fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_blk %llu\n", (u64)cur_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!need_add_block(folio)) {
		is_new_blk = !ssdfs_extents_tree_has_logical_block(cur_blk,
								   inode);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_blk %llu, is_new_blk %#x\n",
			  (u64)cur_blk, is_new_blk);
#endif /* CONFIG_SSDFS_DEBUG */

		if (is_new_blk)
			set_folio_new(folio);
	}

#ifdef CONFIG_SSDFS_DEBUG
	do {
		kaddr = kmap_local_folio(folio, folio_processed_bytes);
		SSDFS_DBG("PAGE DUMP: "
			  "folio_processed_bytes %u\n",
			  folio_processed_bytes);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr,
				     PAGE_SIZE);
		SSDFS_DBG("\n");
		kunmap_local(kaddr);

		folio_processed_bytes += PAGE_SIZE;
	} while (folio_processed_bytes < folio_size(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	/* Is the page fully inside @i_size? */
	if (index < end_index) {
		err = (*writepage)(folio, folio_size(folio), wbc, pool, batch);
		if (unlikely(err)) {
			ssdfs_fs_error(inode->i_sb, __FILE__,
					__func__, __LINE__,
					"fail to write block: "
					"ino %lu, page_index %llu, err %d\n",
					ino, (u64)index, err);
			goto discard_folio;
		}
	} else if (len > 0) {
		/*
		 * The page straddles @i_size. It must be zeroed out on each and every
		 * writepage invocation because it may be mmapped. "A file is mapped
		 * in multiples of the page size. For a file that is not a multiple of
		 * the page size, the remaining memory is zeroed when mapped, and
		 * writes to that region are not written out to the file."
		 */
		folio_zero_segment(folio, len, folio_size(folio));

		err = (*writepage)(folio, len, wbc, pool, batch);
		if (unlikely(err)) {
			ssdfs_fs_error(inode->i_sb, __FILE__,
					__func__, __LINE__,
					"fail to write block: "
					"ino %lu, page_index %llu, err %d\n",
					ino, (u64)index, err);
			goto discard_folio;
		}
	} else {
		/* Write out the whole last folio (len == 0) */
		err = (*writepage)(folio, folio_size(folio), wbc, pool, batch);
		if (unlikely(err)) {
			ssdfs_fs_error(inode->i_sb, __FILE__,
					__func__, __LINE__,
					"fail to write block: "
					"ino %lu, page_index %llu, err %d\n",
					ino, (u64)index, err);
			goto discard_folio;
		}
	}

	offset_inside_block = index << PAGE_SHIFT;
	offset_inside_block %= fsi->pagesize;

	if ((offset_inside_block + folio_size(folio)) < fsi->pagesize) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("NOT WHOLE BLOCK IS PROCESSED: "
			  "ino %lu, cur_blk %llu, "
			  "page_index %llu, "
			  "offset_inside_block %u, "
			  "folio_size %zu, block_size %u\n",
			  ino, (u64)cur_blk, (u64)index,
			  offset_inside_block,
			  folio_size(folio),
			  fsi->pagesize);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EAGAIN;
	}

	return 0;

finish_write_folio:
	ssdfs_folio_unlock(folio);

discard_folio:
	return err;
}

/*
 * The ssdfs_writepages() is called by the VM to write out pages associated
 * with the address_space object. If wbc->sync_mode is WBC_SYNC_ALL, then
 * the writeback_control will specify a range of pages that must be
 * written out.  If it is WBC_SYNC_NONE, then a nr_to_write is given
 * and that many pages should be written if possible.
 * If no ->writepages is given, then mpage_writepages is used
 * instead.  This will choose pages from the address space that are
 * tagged as DIRTY and will pass them to ->writepage.
 */
static
int ssdfs_writepages(struct address_space *mapping,
		     struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	ino_t ino = inode->i_ino;
	struct ssdfs_segment_request_pool pool;
	struct ssdfs_dirty_folios_batch *batch;
	struct folio_batch fvec;
	struct folio_batch block_vec;
	int folios_count;
	pgoff_t index = 0;
	pgoff_t end;		/* Inclusive */
	pgoff_t done_index = 0;
	int range_whole = 0;
	int tag;
	int i;
	int done = 0;
	int ret = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, nr_to_write %lu, "
		  "range_start %llu, range_end %llu, "
		  "writeback_index %llu, "
		  "wbc->range_cyclic %#x\n",
		  ino, wbc->nr_to_write,
		  (u64)wbc->range_start,
		  (u64)wbc->range_end,
		  (u64)mapping->writeback_index,
		  wbc->range_cyclic);
#endif /* CONFIG_SSDFS_DEBUG */

	batch = ssdfs_dirty_folios_batch_alloc();
	if (IS_ERR_OR_NULL(batch)) {
		ret = (batch == NULL ? -ENOMEM : PTR_ERR(batch));
		SSDFS_ERR("unable to allocate dirty folios batch\n");
		return ret;
	}

	ssdfs_segment_request_pool_init(&pool);
	ssdfs_dirty_folios_batch_init(batch);

	/*
	 * No folios to write?
	 */
	if (!mapping->nrpages || !mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
		goto out_writepages;

	folio_batch_init(&fvec);
	folio_batch_init(&block_vec);

	if (wbc->range_cyclic) {
		index = mapping->writeback_index; /* prev offset */
		end = -1;
	} else {
		index = wbc->range_start >> PAGE_SHIFT;
		end = wbc->range_end >> PAGE_SHIFT;

		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = 1;
	}

	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages) {
		tag = PAGECACHE_TAG_TOWRITE;
		tag_pages_for_writeback(mapping, index, end);
	} else
		tag = PAGECACHE_TAG_DIRTY;

	done_index = index;

	while (!done && (index <= end)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %llu, end %llu, done_index %llu, "
			  "done %#x, tag %#x\n",
			  (u64)index, (u64)end, (u64)done_index, done, tag);
#endif /* CONFIG_SSDFS_DEBUG */

		folios_count = filemap_get_folios_tag(mapping, &index, end,
							tag, &fvec);
		if (folios_count == 0) {
			if (!is_ssdfs_file_inline(ii) &&
			    is_ssdfs_dirty_batch_not_processed(batch)) {
				ret = ssdfs_issue_write_request(wbc,
						&pool, batch,
						SSDFS_EXTENT_BASED_REQUEST);
				if (ret < 0) {
					SSDFS_ERR("ino %lu, nr_to_write %lu, "
						  "range_start %llu, "
						  "range_end %llu, "
						  "writeback_index %llu, "
						  "wbc->range_cyclic %#x, "
						  "index %llu, end %llu, "
						  "done_index %llu\n",
						  ino, wbc->nr_to_write,
						  (u64)wbc->range_start,
						  (u64)wbc->range_end,
						  (u64)mapping->writeback_index,
						  wbc->range_cyclic,
						  (u64)index, (u64)end,
						  (u64)done_index);
					goto out_writepages;
				}
			}

			break;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("FOUND: folios_count %d\n", folios_count);
#endif /* CONFIG_SSDFS_DEBUG */

		for (i = 0; i < folios_count; i++) {
			struct folio *folio = fvec.folios[i];
			unsigned long nr;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, index %d, "
				  "folio->index %ld, end %llu\n",
				  folio, i, folio->index, (u64)end);
#endif /* CONFIG_SSDFS_DEBUG */

			ret = 0;

			/*
			 * At this point, the page may be truncated or
			 * invalidated (changing page->mapping to NULL), or
			 * even swizzled back from swapper_space to tmpfs file
			 * mapping. However, page->index will not change
			 * because we have a reference on the page.
			 */
			if (folio->index > end) {
				/*
				 * can't be range_cyclic (1st pass) because
				 * end == -1 in that case.
				 */
				done = 1;
				break;
			}

			done_index = folio->index + 1;

			ssdfs_folio_lock(folio);

			/*
			 * Page truncated or invalidated. We can freely skip it
			 * then, even for data integrity operations: the page
			 * has disappeared concurrently, so there could be no
			 * real expectation of this data interity operation
			 * even if there is now a new, dirty page at the same
			 * pagecache address.
			 */
			if (unlikely(folio->mapping != mapping)) {
continue_unlock:
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("UNLOCK FOLIO: index %ld\n",
					  folio->index);
#endif /* CONFIG_SSDFS_DEBUG */
				ssdfs_folio_unlock(folio);
				continue;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, index %d, folio->index %ld, "
				  "folio_test_locked %#x, "
				  "folio_test_dirty %#x, "
				  "folio_test_writeback %#x\n",
				  folio, i, folio->index,
				  folio_test_locked(folio),
				  folio_test_dirty(folio),
				  folio_test_writeback(folio));
#endif /* CONFIG_SSDFS_DEBUG */

			if (!folio_test_dirty(folio)) {
				/* someone wrote it for us */
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("FOLIO IS NOT DIRTY: index %ld\n",
					  folio->index);
#endif /* CONFIG_SSDFS_DEBUG */
				goto continue_unlock;
			}

			if (folio_test_writeback(folio)) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("FOLIO IS UNDER WRITEBACK: "
					  "index %ld\n",
					  folio->index);
#endif /* CONFIG_SSDFS_DEBUG */

				if (wbc->sync_mode != WB_SYNC_NONE) {
#ifdef CONFIG_SSDFS_DEBUG
					SSDFS_DBG("WAIT WRITEBACK: "
						  "folio_index %ld\n",
						  folio->index);
#endif /* CONFIG_SSDFS_DEBUG */
					folio_wait_writeback(folio);
				} else
					goto continue_unlock;
			}

			BUG_ON(folio_test_writeback(folio));
			if (!folio_clear_dirty_for_io(folio))
				goto continue_unlock;

			ret = ssdfs_writepage_wrapper(folio, wbc,
						      &pool, batch,
						      __ssdfs_writepages);
			nr = folio_nr_pages(folio);

			if (ret) {
				if (ret == -EAGAIN) {
					/*
					 * Not all folios of the logical block
					 * is processed: continue processing folios
					 */
				} else if (ret == -EROFS) {
					/*
					 * continue to discard folios
					 */
				} else {
					/*
					 * done_index is set past this page,
					 * so media errors will not choke
					 * background writeout for the entire
					 * file. This has consequences for
					 * range_cyclic semantics (ie. it may
					 * not be suitable for data integrity
					 * writeout).
					 */
					done_index = folio->index + nr;
					done = 1;
					break;
				}
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, index %d, folio->index %ld, "
				  "folio_test_locked %#x, "
				  "folio_test_dirty %#x, "
				  "folio_test_writeback %#x\n",
				  folio, i, folio->index,
				  folio_test_locked(folio),
				  folio_test_dirty(folio),
				  folio_test_writeback(folio));
#endif /* CONFIG_SSDFS_DEBUG */

			/*
			 * We stop writing back only if we are not doing
			 * integrity sync. In case of integrity sync we have to
			 * keep going until we have written all the pages
			 * we tagged for writeback prior to entering this loop.
			 */
			wbc->nr_to_write -= nr;
			if (wbc->nr_to_write <= 0 &&
			    wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("wbc->nr_to_write %lu, "
				  "wbc->sync_mode %#x, "
				  "done_index %llu, "
				  "done %#x\n",
				  wbc->nr_to_write,
				  wbc->sync_mode,
				  (u64)done_index,
				  done);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		if (ret != -EAGAIN &&
		    !is_ssdfs_file_inline(ii) &&
		    is_ssdfs_dirty_batch_not_processed(batch)) {
			ret = ssdfs_issue_write_request(wbc, &pool, batch,
						SSDFS_EXTENT_BASED_REQUEST);
			if (ret < 0) {
				SSDFS_ERR("ino %lu, nr_to_write %lu, "
					  "range_start %llu, range_end %llu, "
					  "writeback_index %llu, "
					  "wbc->range_cyclic %#x, "
					  "index %llu, end %llu, "
					  "done_index %llu\n",
					  ino, wbc->nr_to_write,
					  (u64)wbc->range_start,
					  (u64)wbc->range_end,
					  (u64)mapping->writeback_index,
					  wbc->range_cyclic,
					  (u64)index, (u64)end,
					  (u64)done_index);
				goto out_writepages;
			}
		}

		index = done_index;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %llu, end %llu, nr_to_write %lu\n",
			  (u64)index, (u64)end, wbc->nr_to_write);
#endif /* CONFIG_SSDFS_DEBUG */

		folio_batch_reinit(&fvec);
		cond_resched();
	};

	if (!ret) {
		ret = ssdfs_wait_write_pool_requests_end(fsi, &pool);
		if (unlikely(ret)) {
			SSDFS_ERR("finish write request failed: "
				  "err %d\n", ret);
		}
	} else
		ssdfs_clean_failed_request_pool(&pool);

	/*
	 * If we hit the last page and there is more work to be done: wrap
	 * back the index back to the start of the file for the next
	 * time we are called.
	 */
	if (wbc->range_cyclic && !done)
		done_index = 0;

out_writepages:
	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = done_index;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, nr_to_write %lu, "
		  "range_whole %d, done_index %llu, done %#x, "
		  "range_start %llu, range_end %llu, "
		  "writeback_index %llu\n",
		  ino, wbc->nr_to_write,
		  range_whole, (u64)done_index, done,
		  (u64)wbc->range_start,
		  (u64)wbc->range_end,
		  (u64)mapping->writeback_index);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_dirty_folios_batch_free(batch);

	return ret;
}

static void ssdfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size)
		truncate_pagecache(inode, inode->i_size);
}

static inline
struct folio *ssdfs_get_block_folio(struct file *file,
				    struct address_space *mapping,
				    pgoff_t index)
{
	struct inode *inode = mapping->host;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct folio *folio = NULL;
	fgf_t fgp_flags = FGP_WRITEBEGIN;
	unsigned int nofs_flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, index %lu\n",
		  inode->i_ino, index);
#endif /* CONFIG_SSDFS_DEBUG */

	fgp_flags |= fgf_set_order(fsi->pagesize);

	nofs_flags = memalloc_nofs_save();
	folio = __filemap_get_folio(mapping, index, fgp_flags,
				    mapping_gfp_mask(mapping));
	memalloc_nofs_restore(nofs_flags);

	if (!folio) {
		SSDFS_ERR("fail to grab folio: index %lu\n",
			  index);
		return ERR_PTR(-ENOMEM);
	} else if (IS_ERR(folio)) {
		SSDFS_ERR("fail to grab folio: index %lu, err %ld\n",
			  index, PTR_ERR(folio));
		return folio;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d, folio_index %lu, "
		  "folio_size %zu, page_size %u, "
		  "fgp_flags %#x, order %u\n",
		  folio, folio_ref_count(folio),
		  folio->index, folio_size(folio),
		  fsi->pagesize, fgp_flags,
		  FGF_GET_ORDER(fgp_flags));

	SSDFS_DBG("folio->index %ld, "
		  "folio_test_locked %#x, "
		  "folio_test_uptodate %#x, "
		  "folio_test_dirty %#x, "
		  "folio_test_writeback %#x\n",
		  folio->index,
		  folio_test_locked(folio),
		  folio_test_uptodate(folio),
		  folio_test_dirty(folio),
		  folio_test_writeback(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_account_locked_folio(folio);

	return folio;
}

static inline
void ssdfs_folio_test_and_set_if_new(struct inode *inode,
				     struct folio *folio)
{
	pgoff_t last_folio;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!inode || !folio);

	SSDFS_DBG("ino %lu, folio_index %lu\n",
		  inode->i_ino, folio->index);
#endif /* CONFIG_SSDFS_DEBUG */

	last_folio = (i_size_read(inode) - 1) >> PAGE_SHIFT;

	if (i_size_read(inode) == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("SET NEW FOLIO: "
			  "file_size %llu, last_folio %lu, "
			  "folio_index %lu\n",
			  (u64)i_size_read(inode),
			  last_folio,
			  folio->index);
#endif /* CONFIG_SSDFS_DEBUG */

		set_folio_new(folio);
	} else {
		if (folio->index > last_folio ||
		    !folio_test_uptodate(folio)) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("SET NEW FOLIO: "
				  "file_size %llu, last_folio %lu, "
				  "folio_index %lu\n",
				  (u64)i_size_read(inode),
				  last_folio,
				  folio->index);
#endif /* CONFIG_SSDFS_DEBUG */

			set_folio_new(folio);
		}
	}
}

static
int ssdfs_process_whole_block(struct file *file,
			      struct address_space *mapping,
			      struct folio *requested_folio,
			      loff_t pos, u32 len,
			      bool is_new_blk)
{
	struct inode *inode = mapping->host;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct folio *cur_folio;
	struct folio_batch fbatch;
	pgoff_t index;
	unsigned start;
	unsigned end;
	loff_t logical_offset;
	u32 processed_bytes = 0;
	bool need_read_block = false;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!requested_folio);

	SSDFS_DBG("ino %lu, pos %llu, len %u\n",
		  inode->i_ino, pos, len);
#endif /* CONFIG_SSDFS_DEBUG */

	folio_batch_init(&fbatch);

	logical_offset = (loff_t)requested_folio->index << PAGE_SHIFT;
	logical_offset >>= fsi->log_pagesize;
	logical_offset <<= fsi->log_pagesize;

	index = logical_offset >> PAGE_SHIFT;

	while (processed_bytes < fsi->pagesize) {
		if (index == requested_folio->index) {
			cur_folio = requested_folio;
		} else {
			cur_folio = ssdfs_get_block_folio(file, mapping, index);
			if (unlikely(IS_ERR_OR_NULL(cur_folio))) {
				err = IS_ERR(cur_folio) ?
						PTR_ERR(cur_folio) : -ERANGE;
				SSDFS_ERR("fail to get block's folio: "
					  "index %lu, err %d\n",
					  index, err);
				return err;
			}

			if (is_new_blk) {
				ssdfs_folio_test_and_set_if_new(inode,
								cur_folio);
			}
		}

		if (folio_test_uptodate(cur_folio)) {
			folio_batch_add(&fbatch, cur_folio);
			goto check_next_folio;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("logical_offset %llu, inode_size %llu\n",
			  logical_offset, (u64)i_size_read(inode));
#endif /* CONFIG_SSDFS_DEBUG */

		start = offset_in_folio(cur_folio, logical_offset);
		end = folio_size(cur_folio) - start;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start %u, end %u, "
			  "len %u, processed_bytes %u, "
			  "folio_size %zu\n",
			  start, end, len, processed_bytes,
			  folio_size(cur_folio));

		BUG_ON(processed_bytes > fsi->pagesize);
#endif /* CONFIG_SSDFS_DEBUG */

		if ((logical_offset & PAGE_MASK) >= i_size_read(inode)) {
			/* Reading beyond i_size is simple: memset to zero */
			folio_zero_segments(cur_folio, 0, start, end,
					    folio_size(cur_folio));
			folio_mark_uptodate(cur_folio);
			flush_dcache_folio(cur_folio);
		} else if (len >= (folio_size(cur_folio) + processed_bytes)) {
			folio_zero_segments(cur_folio, 0, start, end,
					    folio_size(cur_folio));
			folio_mark_uptodate(cur_folio);
			flush_dcache_folio(cur_folio);
		} else {
			need_read_block = true;
		}

		folio_batch_add(&fbatch, cur_folio);

check_next_folio:
		processed_bytes += folio_size(cur_folio);
		index += folio_size(cur_folio) >> PAGE_SHIFT;
	}

	if (need_read_block) {
		err = ssdfs_read_block_nolock(file, &fbatch,
						SSDFS_CURRENT_THREAD_READ);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read folio: "
				  "index %lu, err %d\n",
				  index, err);
			return err;
		}
	}

	for (i = 0; i < folio_batch_count(&fbatch); i++) {
		cur_folio = fbatch.folios[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!cur_folio);
#endif /* CONFIG_SSDFS_DEBUG */

		if (cur_folio != requested_folio)
			ssdfs_folio_unlock(cur_folio);
	}

	return 0;
}

static
int ssdfs_write_begin_inline_file(struct file *file,
				  struct address_space *mapping,
				  loff_t pos, unsigned len,
				  struct folio **foliop, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct folio *first_folio;
	pgoff_t index = pos >> PAGE_SHIFT;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, pos %llu, len %u\n",
		  inode->i_ino, pos, len);

	if (!can_file_be_inline(inode, i_size_read(inode))) {
		SSDFS_ERR("not inline file: "
			  "ino %lu, pos %llu, "
			  "len %u, file size %llu\n",
			  inode->i_ino, pos, len,
			  (u64)i_size_read(inode));
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (!ii->inline_file) {
		err = ssdfs_allocate_inline_file_buffer(inode);
		if (unlikely(err)) {
			SSDFS_ERR("fail to allocate inline buffer\n");
			return -EAGAIN;
		}

		/*
		 * TODO: pre-fetch file's content in buffer
		 *       (if inode size > 256 bytes)
		 */
	}

	atomic_or(SSDFS_INODE_HAS_INLINE_FILE,
		  &SSDFS_I(inode)->private_flags);

	first_folio = ssdfs_get_block_folio(file, mapping, index);
	if (!first_folio) {
		SSDFS_ERR("fail to grab folio: index %lu\n",
			  index);
		return -ENOMEM;
	} else if (IS_ERR(first_folio)) {
		SSDFS_ERR("fail to grab folio: index %lu, err %ld\n",
			  index, PTR_ERR(first_folio));
		return PTR_ERR(first_folio);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  first_folio, folio_ref_count(first_folio));
#endif /* CONFIG_SSDFS_DEBUG */

	*foliop = first_folio;

	if ((len == fsi->pagesize) || folio_test_uptodate(first_folio))
		return 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pos %llu, inode_size %llu\n",
		  pos, (u64)i_size_read(inode));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_process_whole_block(file, mapping, first_folio,
					pos, len, false);
	if (unlikely(err)) {
		SSDFS_ERR("fail to process thw whole block: "
			  "ino %lu, pos %llu, len %u, err %d\n",
			  inode->i_ino, pos, len, err);
		return err;
	}

	return 0;
}

static
struct folio *ssdfs_write_begin_logical_block(struct file *file,
					      struct address_space *mapping,
					      loff_t pos, u32 len)
{
	struct inode *inode = mapping->host;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct folio *first_folio;
	pgoff_t index = pos >> PAGE_SHIFT;
	loff_t cur_blk;
	u64 last_blk = U64_MAX;
	bool is_new_blk = false;
#ifdef CONFIG_SSDFS_DEBUG
	u64 free_blocks = 0;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, pos %llu, len %u\n",
		  inode->i_ino, pos, len);
#endif /* CONFIG_SSDFS_DEBUG */

	atomic_and(~SSDFS_INODE_HAS_INLINE_FILE,
		   &SSDFS_I(inode)->private_flags);

	if (can_file_be_inline(inode, i_size_read(inode))) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("change from inline to regular file\n");
#endif /* CONFIG_SSDFS_DEBUG */

		last_blk = U64_MAX;
	} else if (i_size_read(inode) > 0) {
		last_blk = (i_size_read(inode) - 1) >>
					fsi->log_pagesize;
	}

	cur_blk = pos >> fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_blk %llu, last_blk %llu\n",
		  (u64)cur_blk, (u64)last_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	first_folio = ssdfs_get_block_folio(file, mapping, index);
	if (!first_folio) {
		SSDFS_ERR("fail to grab folio: index %lu\n",
			  index);
		return ERR_PTR(-ENOMEM);
	} else if (IS_ERR(first_folio)) {
		SSDFS_ERR("fail to grab folio: index %lu, err %ld\n",
			  index, PTR_ERR(first_folio));
		return first_folio;
	}

	if (pos % fsi->pagesize) {
		if (folio_test_uptodate(first_folio))
			return first_folio;
		else {
			SSDFS_ERR("invalid request: "
				  "pos %llu, pagesize %u\n",
				  pos, fsi->pagesize);
			ssdfs_folio_unlock(first_folio);
			ssdfs_folio_put(first_folio);
			return ERR_PTR(-ERANGE);
		}
	}

	if (last_blk >= U64_MAX) {
		is_new_blk = true;
	} else if (cur_blk > last_blk) {
		is_new_blk = true;
	} else if (!folio_test_uptodate(first_folio)) {
		is_new_blk = !ssdfs_extents_tree_has_logical_block(cur_blk,
								   inode);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_blk %llu, is_new_blk %#x\n",
		  (u64)cur_blk, is_new_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_new_blk) {
		if (!need_add_block(first_folio)) {
			err = ssdfs_reserve_free_pages(fsi, 1,
						SSDFS_USER_DATA_PAGES);
		}

#ifdef CONFIG_SSDFS_DEBUG
		spin_lock(&fsi->volume_state_lock);
		free_blocks = fsi->free_pages;
		spin_unlock(&fsi->volume_state_lock);

		SSDFS_DBG("free_blocks %llu, err %d\n",
			  free_blocks, err);
#endif /* CONFIG_SSDFS_DEBUG */

		if (err) {
			ssdfs_increase_volume_free_pages(fsi, 1);

			ssdfs_folio_unlock(first_folio);
			ssdfs_folio_put(first_folio);

			ssdfs_write_failed(mapping, pos);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  first_folio, folio_ref_count(first_folio));
			SSDFS_DBG("volume hasn't free space\n");
#endif /* CONFIG_SSDFS_DEBUG */

			return ERR_PTR(err);
		}

		ssdfs_folio_test_and_set_if_new(inode, first_folio);
	}

	err = ssdfs_process_whole_block(file, mapping, first_folio,
					pos, len, is_new_blk);
	if (unlikely(err)) {
		SSDFS_ERR("fail to process thw whole block: "
			  "ino %lu, pos %llu, len %u, err %d\n",
			  inode->i_ino, pos, len, err);
		return ERR_PTR(err);
	}

	return first_folio;
}

/*
 * The ssdfs_write_begin() is called by the generic
 * buffered write code to ask the filesystem to prepare
 * to write len bytes at the given offset in the file.
 */
static
int ssdfs_write_begin(const struct kiocb *iocb,
		      struct address_space *mapping,
		      loff_t pos, unsigned len,
		      struct folio **foliop, void **fsdata)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = mapping->host;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct folio *first_folio = NULL;
	loff_t cur_pos, next_pos;
	loff_t start_blk, end_blk, cur_blk;
	u32 processed_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, pos %llu, len %u\n",
		  inode->i_ino, pos, len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (inode->i_sb->s_flags & SB_RDONLY)
		return -EROFS;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, large_folios_support %#x\n",
		  inode->i_ino,
		  mapping_large_folio_support(mapping));
#endif /* CONFIG_SSDFS_DEBUG */

	if (!can_file_be_inline(inode, i_size_read(inode))) {
		/*
		 * Process as regular file
		 */
		goto try_regular_write;
	} else if (can_file_be_inline(inode, pos + len)) {
		err = ssdfs_write_begin_inline_file(file, mapping,
						    pos, len,
						    foliop, fsdata);
		if (err == -EAGAIN) {
			/*
			 * Process as regular file
			 */
			err = 0;
			goto try_regular_write;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to process inline file: "
				  "ino %lu, pos %llu, len %u, err %d\n",
				  inode->i_ino, pos, len, err);
			goto finish_write_begin;
		} else
			goto finish_write_begin;
	} else {
try_regular_write:
		cur_pos = pos;
		start_blk = pos >> fsi->log_pagesize;
		end_blk = (pos + len + fsi->pagesize - 1) >> fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(start_blk == end_blk);
#endif /* CONFIG_SSDFS_DEBUG */

		for (cur_blk = start_blk; cur_blk < end_blk; cur_blk++) {
			struct folio *folio;
			u32 cur_len;

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(processed_bytes > len);
#endif /* CONFIG_SSDFS_DEBUG */

			next_pos = (cur_blk + 1) << fsi->log_pagesize;
			cur_len = min_t(u32, len - processed_bytes,
						next_pos - cur_pos);

			folio = ssdfs_write_begin_logical_block(file,
								mapping,
								cur_pos,
								cur_len);
			if (IS_ERR_OR_NULL(folio)) {
				err = IS_ERR(folio) ? PTR_ERR(folio) : -ERANGE;
				SSDFS_ERR("fail to process folio: "
					  "ino %lu, pos %llu, err %d\n",
					  inode->i_ino, cur_pos, err);
				goto finish_write_begin;
			}

			if (!first_folio)
				first_folio = folio;

			processed_bytes += next_pos - cur_pos;
			cur_pos = next_pos;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  first_folio,
			  folio_ref_count(first_folio));
#endif /* CONFIG_SSDFS_DEBUG */

		*foliop = first_folio;
	}

finish_write_begin:
	return err;
}

/*
 * After a successful ssdfs_write_begin(), and data copy,
 * ssdfs_write_end() must be called.
 */
static
int ssdfs_write_end(const struct kiocb *iocb,
		    struct address_space *mapping,
		    loff_t pos, unsigned len, unsigned copied,
		    struct folio *folio, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	pgoff_t index = folio->index;
	unsigned start = offset_in_folio(folio, pos);
	unsigned end = start + copied;
	loff_t old_size = i_size_read(inode);
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, pos %llu, len %u, copied %u, "
		  "index %lu, start %u, end %u, old_size %llu, "
		  "folio_size %zu, need_add_block %#x, "
		  "folio_test_dirty %#x\n",
		  inode->i_ino, pos, len, copied,
		  index, start, end, old_size,
		  folio_size(folio),
		  need_add_block(folio),
		  folio_test_dirty(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	if (copied < len) {
		/*
		 * VFS copied less data to the folio that it intended and
		 * declared in its '->write_begin()' call via the @len
		 * argument. Just tell userspace to retry the entire block.
		 */
		if (!folio_test_uptodate(folio)) {
			copied = 0;
			goto out;
		}
	}

	if (!need_add_block(folio) && !folio_test_dirty(folio)) {
		u64 folio_offset;
		u32 offset_inside_folio;

		folio_offset = (u64)folio->index << PAGE_SHIFT;
		div_u64_rem(folio_offset, fsi->pagesize, &offset_inside_folio);

		if (offset_inside_folio == 0) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("ACCOUNT UPDATED USER DATA PAGES: "
				  "ino %lu, pos %llu, len %u, "
				  "folio_index %lu\n",
				  inode->i_ino, pos, len,
				  folio->index);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_account_updated_user_data_pages(fsi,
					SSDFS_MEM_PAGES_PER_LOGICAL_BLOCK(fsi));
		}
	}

	if (old_size < (index << PAGE_SHIFT) + end) {
		i_size_write(inode, (index << PAGE_SHIFT) + end);
		mark_inode_dirty_sync(inode);
	}

	flush_dcache_folio(folio);

	folio_mark_uptodate(folio);
	if (!folio_test_dirty(folio))
		filemap_dirty_folio(mapping, folio);

out:
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d, "
		  "folio_test_dirty %#x\n",
		  folio, folio_ref_count(folio),
		  folio_test_dirty(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	return err ? err : copied;
}

/*
 * The ssdfs_direct_IO() is called by the generic read/write
 * routines to perform direct_IO - that is IO requests which
 * bypass the page cache and transfer data directly between
 * the storage and the application's address space.
 */
static ssize_t ssdfs_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	/* TODO: implement */
	return -ERANGE;
}

/*
 * The ssdfs_fsync() is called by the fsync(2) system call.
 */
int ssdfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, start %llu, end %llu, datasync %#x\n",
		  (unsigned long)inode->i_ino, (unsigned long long)start,
		  (unsigned long long)end, datasync);
#endif /* CONFIG_SSDFS_DEBUG */

	trace_ssdfs_sync_file_enter(inode);

	err = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (err) {
		trace_ssdfs_sync_file_exit(file, datasync, err);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fsync failed: ino %lu, start %llu, "
			  "end %llu, err %d\n",
			  (unsigned long)inode->i_ino,
			  (unsigned long long)start,
			  (unsigned long long)end,
			  err);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	}

	inode_lock(inode);
	sync_inode_metadata(inode, 1);
	blkdev_issue_flush(inode->i_sb->s_bdev);
	inode_unlock(inode);

	trace_ssdfs_sync_file_exit(file, datasync, err);

	return err;
}

const struct file_operations ssdfs_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= ssdfs_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.unlocked_ioctl	= ssdfs_ioctl,
	.mmap		= generic_file_mmap,
	.open		= generic_file_open,
	.fsync		= ssdfs_fsync,
	.splice_read	= filemap_splice_read,
	.splice_write	= iter_file_splice_write,
};

const struct inode_operations ssdfs_file_inode_operations = {
	.getattr	= ssdfs_getattr,
	.setattr	= ssdfs_setattr,
	.listxattr	= ssdfs_listxattr,
	.get_inode_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,
};

const struct inode_operations ssdfs_special_inode_operations = {
	.setattr	= ssdfs_setattr,
	.listxattr	= ssdfs_listxattr,
	.get_inode_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,
};

const struct inode_operations ssdfs_symlink_inode_operations = {
	.get_link	= page_get_link,
	.getattr	= ssdfs_getattr,
	.setattr	= ssdfs_setattr,
	.listxattr	= ssdfs_listxattr,
};

const struct address_space_operations ssdfs_aops = {
	.read_folio		= ssdfs_read_block,
	.readahead		= ssdfs_readahead,
	.writepages		= ssdfs_writepages,
	.write_begin		= ssdfs_write_begin,
	.write_end		= ssdfs_write_end,
	.migrate_folio		= filemap_migrate_folio,
	.dirty_folio		= filemap_dirty_folio,
	.direct_IO		= ssdfs_direct_IO,
};
