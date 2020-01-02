//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/file.c - file operations.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "ssdfs.h"
#include "request_queue.h"
#include "offset_translation_table.h"
#include "page_array.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"
#include "xattr.h"
#include "acl.h"

#include <trace/events/ssdfs.h>

enum {
	SSDFS_BLOCK_BASED_REQUEST,
	SSDFS_EXTENT_BASED_REQUEST,
};

enum {
	SSDFS_CURRENT_THREAD_READ,
	SSDFS_DELEGATE_TO_READ_THREAD,
};

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
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON((req->extent.logical_offset >> fsi->log_pagesize) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, req %p\n", fsi, req);

	err = ssdfs_prepare_volume_extent(fsi, req);
	if (unlikely(err)) {
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

	si = ssdfs_grab_segment(fsi, SSDFS_USER_DATA_SEG_TYPE,
				req->place.start.seg_id);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		SSDFS_ERR("fail to grab segment object: "
			  "seg %llu, err %d\n",
			  req->place.start.seg_id, err);
		return PTR_ERR(si);
	}

	err = ssdfs_segment_read_block_async(si, req);
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
	u16 logical_blk;
	struct completion *end;
	unsigned long res;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON((req->extent.logical_offset >> fsi->log_pagesize) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, req %p\n", fsi, req);

	err = ssdfs_prepare_volume_extent(fsi, req);
	if (unlikely(err)) {
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

	si = ssdfs_grab_segment(fsi, SSDFS_USER_DATA_SEG_TYPE,
				req->place.start.seg_id);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		SSDFS_ERR("fail to grab segment object: "
			  "seg %llu, err %d\n",
			  req->place.start.seg_id, err);
		return PTR_ERR(si);
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    SSDFS_READ_PAGE,
					    SSDFS_REQ_SYNC,
					    req);
	ssdfs_request_define_segment(si->seg_id, req);

	table = si->blk2off_table;
	logical_blk = req->place.start.blk_index;

	err = ssdfs_blk2off_table_get_offset_position(table, logical_blk, &pos);
	if (err == -EAGAIN) {
		end = &table->full_init_end;
		res = wait_for_completion_timeout(end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			goto finish_read_block;
		}

		err = ssdfs_blk2off_table_get_offset_position(table,
							      logical_blk,
							      &pos);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		goto finish_read_block;
	}

	pebc = &si->peb_array[pos.peb_index];

	err = ssdfs_peb_read_page(pebc, req, &end);
	if (err == -EAGAIN) {
		res = wait_for_completion_timeout(end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("PEB init failed: "
				  "err %d\n", err);
			goto finish_read_block;
		}

		err = ssdfs_peb_read_page(pebc, req, &end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: err %d\n",
			  err);
		goto finish_read_block;
	}

	for (i = 0; i < req->result.processed_blks; i++)
		ssdfs_peb_mark_request_block_uptodate(pebc, req, i);

finish_read_block:
	req->result.err = err;
	complete(&req->result.wait);
	ssdfs_segment_put_object(si);

	return 0;
}

static
int ssdfs_readpage_nolock(struct file *file, struct page *page,
			  int read_mode)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(file_inode(file)->i_sb);
	ino_t ino = file_inode(file)->i_ino;
	pgoff_t index = page_index(page);
	struct ssdfs_segment_request *req;
	loff_t logical_offset;
	loff_t data_bytes;
	loff_t file_size;
	void *kaddr;
	unsigned long res;
	int err;

	SSDFS_DBG("ino %lu, page_index %llu, read_mode %#x\n",
		  ino, (u64)index, read_mode);

	logical_offset = (loff_t)index << PAGE_SHIFT;

	file_size = i_size_read(file_inode(file));
	data_bytes = file_size - logical_offset;
	data_bytes = min_t(loff_t, PAGE_SIZE, data_bytes);

	BUG_ON(data_bytes > U32_MAX);

	kaddr = kmap_atomic(page);
	memset(kaddr, 0, PAGE_SIZE);
	kunmap_atomic(kaddr);

	if (logical_offset >= file_size) {
		/* Reading beyond inode */
		SetPageUptodate(page);
		ClearPageError(page);
		flush_dcache_page(page);
		return 0;
	}

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req);
	ssdfs_get_request(req);

	ssdfs_request_prepare_logical_extent(ino,
					     (u64)logical_offset,
					     (u32)data_bytes,
					     0, 0, req);

	err = ssdfs_request_add_page(page, req);
	if (err) {
		SSDFS_ERR("fail to add page into request: "
			  "ino %lu, page_index %lu, err %d\n",
			  ino, index, err);
		goto fail_read_page;
	}

	switch (read_mode) {
	case SSDFS_CURRENT_THREAD_READ:
		err = ssdfs_read_block_by_current_thread(fsi, req);
		if (err) {
			SSDFS_ERR("fail to read block: err %d\n", err);
			goto fail_read_page;
		}

		res = wait_for_completion_timeout(&req->result.wait,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("read request failed: "
				  "ino %lu, logical_offset %llu, "
				  "size %u, err %d\n",
				  ino, (u64)logical_offset,
				  (u32)data_bytes, err);
			goto fail_read_page;
		}

		if (req->result.err) {
			SSDFS_ERR("read request failed: "
				  "ino %lu, logical_offset %llu, "
				  "size %u, err %d\n",
				  ino, (u64)logical_offset,
				  (u32)data_bytes,
				  req->result.err);
			goto fail_read_page;
		}

		ssdfs_put_request(req);
		ssdfs_request_free(req);
		break;

	case SSDFS_DELEGATE_TO_READ_THREAD:
		err = ssdfs_read_block_async(fsi, req);
		if (err) {
			SSDFS_ERR("fail to read block: err %d\n", err);
			goto fail_read_page;
		}
		break;

	default:
		BUG();
	}

	return 0;

fail_read_page:
	ClearPageUptodate(page);
	SetPageError(page);
	ssdfs_put_request(req);
	ssdfs_request_free(req);

	return err;
}

/*
 * The ssdfs_readpage() is called by the VM
 * to read a page from backing store.
 */
static inline
int ssdfs_readpage(struct file *file, struct page *page)
{
	int err;

	SSDFS_DBG("ino %lu, page_index %lu\n",
		  file_inode(file)->i_ino, page_index(page));

	err = ssdfs_readpage_nolock(file, page, SSDFS_CURRENT_THREAD_READ);
	unlock_page(page);
	return err;
}

static inline
int ssdfs_readahead_page(struct file *file, struct page *page)
{
	int err;

	SSDFS_DBG("ino %lu, page_index %lu\n",
		  file_inode(file)->i_ino, page_index(page));

	err = ssdfs_readpage_nolock(file, page, SSDFS_DELEGATE_TO_READ_THREAD);
	return err;
}

/*
 * The ssdfs_readpages() is called by the VM to read pages
 * associated with the address_space object. This is essentially
 * just a vector version of ssdfs_readpage(). Instead of just one
 * page, several pages are requested. The ssdfs_readpages() is only
 * used for read-ahead, so read errors are ignored.
 */
static
int ssdfs_readpages(struct file *file, struct address_space *mapping,
		    struct list_head *pages, unsigned nr_pages)
{
	SSDFS_DBG("ino %lu, nr_pages %u\n",
		  file_inode(file)->i_ino, nr_pages);

	return read_cache_pages(mapping, pages,
				(void *)ssdfs_readahead_page, file);
}

/*
 * ssdfs_update_block() - update block.
 * @fsi: pointer on shared file system object
 * @req: request object
 */
static
int ssdfs_update_block(struct ssdfs_fs_info *fsi,
		       struct ssdfs_segment_request *req,
		       struct writeback_control *wbc)
{
	struct ssdfs_segment_info *si;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON((req->extent.logical_offset >> fsi->log_pagesize) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, req %p\n", fsi, req);

	err = ssdfs_prepare_volume_extent(fsi, req);
	if (unlikely(err)) {
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

	si = ssdfs_grab_segment(fsi, SSDFS_USER_DATA_SEG_TYPE,
				req->place.start.seg_id);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		SSDFS_ERR("fail to grab segment object: "
			  "seg %llu, err %d\n",
			  req->place.start.seg_id, err);
		return PTR_ERR(si);
	}

	if (wbc->sync_mode == WB_SYNC_NONE) {
		err = ssdfs_segment_update_block_async(si,
						       SSDFS_REQ_ASYNC,
						       req);
	} else if (wbc->sync_mode == WB_SYNC_ALL)
		err = ssdfs_segment_update_block_sync(si, req);
	else
		BUG();

	if (unlikely(err)) {
		SSDFS_ERR("update request failed: "
			  "ino %llu, logical_offset %llu, size %u, err %d\n",
			  req->extent.ino, req->extent.logical_offset,
			  req->extent.data_bytes, err);
		return err;
	}

	ssdfs_segment_put_object(si);

	return 0;
}

/*
 * ssdfs_update_extent() - update extent.
 * @fsi: pointer on shared file system object
 * @req: request object
 */
static
int ssdfs_update_extent(struct ssdfs_fs_info *fsi,
			struct ssdfs_segment_request *req,
			struct writeback_control *wbc)
{
	struct ssdfs_segment_info *si;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON((req->extent.logical_offset >> fsi->log_pagesize) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, req %p\n", fsi, req);

	err = ssdfs_prepare_volume_extent(fsi, req);
	if (unlikely(err)) {
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

	si = ssdfs_grab_segment(fsi, SSDFS_USER_DATA_SEG_TYPE,
				req->place.start.seg_id);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		SSDFS_ERR("fail to grab segment object: "
			  "seg %llu, err %d\n",
			  req->place.start.seg_id, err);
		return PTR_ERR(si);
	}

	if (wbc->sync_mode == WB_SYNC_NONE) {
		err = ssdfs_segment_update_extent_async(si,
							SSDFS_REQ_ASYNC,
							req);
	} else if (wbc->sync_mode == WB_SYNC_ALL)
		err = ssdfs_segment_update_extent_sync(si, req);
	else
		BUG();

	if (unlikely(err)) {
		SSDFS_ERR("update request failed: "
			  "ino %llu, logical_offset %llu, size %u, err %d\n",
			  req->extent.ino, req->extent.logical_offset,
			  req->extent.data_bytes, err);
		return err;
	}

	ssdfs_segment_put_object(si);

	return 0;
}

static
int ssdfs_issue_async_block_write_request(struct writeback_control *wbc,
					  struct ssdfs_segment_request **req)
{
	struct page *page;
	struct inode *inode;
	struct ssdfs_fs_info *fsi;
	ino_t ino;
	u64 logical_offset;
	u32 data_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !req || !*req);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(&(*req)->result.pvec) == 0) {
		SSDFS_ERR("pagevec is empty\n");
		return -ERANGE;
	}

	page = (*req)->result.pvec.pages[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = page->mapping->host;
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;
	logical_offset = (*req)->extent.logical_offset;
	data_bytes = (*req)->extent.data_bytes;

	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "data_bytes %u, sync_mode %#x\n",
		  ino, logical_offset, data_bytes, wbc->sync_mode);

	if (need_add_block(page)) {
		err = ssdfs_segment_add_data_block_async(fsi, *req);
		if (!err) {
			err = ssdfs_extents_tree_add_block(inode, *req);
			if (err) {
				SSDFS_ERR("fail to add extent: "
					  "ino %lu, page_index %llu, "
					  "err %d\n",
					  ino, (u64)page_index(page),
					  err);
				return err;
			}

			inode_add_bytes(inode, fsi->pagesize);
		}
	} else
		err = ssdfs_update_block(fsi, *req, wbc);

	if (err) {
		SSDFS_ERR("fail to write page async: "
			  "ino %lu, page_index %llu, err %d\n",
			  ino, (u64)page_index(page), err);
		return err;
	}

	return 0;
}

static
int ssdfs_issue_sync_block_write_request(struct writeback_control *wbc,
					 struct ssdfs_segment_request **req)
{
	struct page *page;
	struct inode *inode;
	struct ssdfs_fs_info *fsi;
	ino_t ino;
	u64 logical_offset;
	u32 data_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !req || !*req);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(&(*req)->result.pvec) == 0) {
		SSDFS_ERR("pagevec is empty\n");
		return -ERANGE;
	}

	page = (*req)->result.pvec.pages[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = page->mapping->host;
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;
	logical_offset = (*req)->extent.logical_offset;
	data_bytes = (*req)->extent.data_bytes;

	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "data_bytes %u, sync_mode %#x\n",
		  ino, logical_offset, data_bytes, wbc->sync_mode);

	if (need_add_block(page)) {
		err = ssdfs_segment_add_data_block_sync(fsi, *req);
		if (!err) {
			err = ssdfs_extents_tree_add_block(inode, *req);
			if (!err)
				inode_add_bytes(inode, fsi->pagesize);
		}
	} else
		err = ssdfs_update_block(fsi, *req, wbc);

	if (err) {
		SSDFS_ERR("fail to write page sync: "
			  "ino %lu, page_index %llu, err %d\n",
			  ino, (u64)page_index(page), err);
		return err;
	}

	return 0;
}

static
int ssdfs_issue_async_extent_write_request(struct writeback_control *wbc,
					   struct ssdfs_segment_request **req)
{
	struct page *page;
	struct inode *inode;
	struct ssdfs_fs_info *fsi;
	ino_t ino;
	u64 logical_offset;
	u32 data_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !req || !*req);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(&(*req)->result.pvec) == 0) {
		SSDFS_ERR("pagevec is empty\n");
		return -ERANGE;
	}

	page = (*req)->result.pvec.pages[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = page->mapping->host;
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;
	logical_offset = (*req)->extent.logical_offset;
	data_bytes = (*req)->extent.data_bytes;

	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "data_bytes %u, sync_mode %#x\n",
		  ino, logical_offset, data_bytes, wbc->sync_mode);

	if (need_add_block(page)) {
		err = ssdfs_segment_add_data_extent_async(fsi, *req);
		if (!err) {
			u32 extent_bytes = data_bytes;

			err = ssdfs_extents_tree_add_block(inode, *req);
			if (err) {
				SSDFS_ERR("fail to add extent: "
					  "ino %lu, page_index %llu, "
					  "err %d\n",
					  ino, (u64)page_index(page), err);
				return err;
			}

			if (fsi->pagesize > PAGE_SIZE)
				extent_bytes += fsi->pagesize - 1;
			else if (fsi->pagesize <= PAGE_SIZE)
				extent_bytes += PAGE_SIZE - 1;

			extent_bytes >>= fsi->log_pagesize;
			extent_bytes <<= fsi->log_pagesize;

			inode_add_bytes(inode, extent_bytes);
		}
	} else
		err = ssdfs_update_extent(fsi, *req, wbc);

	if (err) {
		SSDFS_ERR("fail to write extent async: "
			  "ino %lu, page_index %llu, err %d\n",
			  ino, (u64)page_index(page), err);
		return err;
	}

	return 0;
}

static
int ssdfs_issue_sync_extent_write_request(struct writeback_control *wbc,
					  struct ssdfs_segment_request **req)
{
	struct page *page;
	struct inode *inode;
	struct ssdfs_fs_info *fsi;
	ino_t ino;
	u64 logical_offset;
	u32 data_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !req || !*req);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(&(*req)->result.pvec) == 0) {
		SSDFS_ERR("pagevec is empty\n");
		return -ERANGE;
	}

	page = (*req)->result.pvec.pages[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = page->mapping->host;
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;
	logical_offset = (*req)->extent.logical_offset;
	data_bytes = (*req)->extent.data_bytes;

	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "data_bytes %u, sync_mode %#x\n",
		  ino, logical_offset, data_bytes, wbc->sync_mode);

	if (need_add_block(page)) {
		err = ssdfs_segment_add_data_extent_sync(fsi, *req);
		if (!err) {
			u32 extent_bytes = data_bytes;

			err = ssdfs_extents_tree_add_block(inode, *req);
			if (err) {
				SSDFS_ERR("fail to add extent: "
					  "ino %lu, page_index %llu, "
					  "err %d\n",
					  ino, (u64)page_index(page), err);
				return err;
			}

			if (fsi->pagesize > PAGE_SIZE)
				extent_bytes += fsi->pagesize - 1;
			else if (fsi->pagesize <= PAGE_SIZE)
				extent_bytes += PAGE_SIZE - 1;

			extent_bytes >>= fsi->log_pagesize;
			extent_bytes <<= fsi->log_pagesize;

			inode_add_bytes(inode, extent_bytes);
		}
	} else
		err = ssdfs_update_extent(fsi, *req, wbc);

	if (err) {
		SSDFS_ERR("fail to write page sync: "
			  "ino %lu, page_index %llu, err %d\n",
			  ino, (u64)page_index(page), err);
		return err;
	}

	return 0;
}

static
int ssdfs_issue_write_request(struct writeback_control *wbc,
			      struct ssdfs_segment_request **req,
			      int req_type)
{
	struct page *page;
	struct inode *inode;
	struct ssdfs_fs_info *fsi;
	ino_t ino;
	u64 logical_offset;
	u32 data_bytes;
	int i;
	unsigned long res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!wbc || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!*req) {
		SSDFS_ERR("empty segment request\n");
		return -ERANGE;
	}

	if (pagevec_count(&(*req)->result.pvec) == 0) {
		SSDFS_ERR("pagevec is empty\n");
		return -ERANGE;
	}

	page = (*req)->result.pvec.pages[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = page->mapping->host;
	fsi = SSDFS_FS_I(inode->i_sb);
	ino = inode->i_ino;
	logical_offset = (*req)->extent.logical_offset;
	data_bytes = (*req)->extent.data_bytes;

	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "data_bytes %u, sync_mode %#x\n",
		  ino, logical_offset, data_bytes, wbc->sync_mode);

	for (i = 0; i < pagevec_count(&(*req)->result.pvec); i++) {
		page = (*req)->result.pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		set_page_writeback(page);
	}

	if (wbc->sync_mode == WB_SYNC_NONE) {
		if (req_type == SSDFS_BLOCK_BASED_REQUEST)
			err = ssdfs_issue_async_block_write_request(wbc, req);
		else if (req_type == SSDFS_EXTENT_BASED_REQUEST)
			err = ssdfs_issue_async_extent_write_request(wbc, req);
		else
			BUG();

		if (err) {
			SSDFS_ERR("fail to write async: "
				  "ino %lu, err %d\n",
				  ino, err);
				goto fail_issue_write_request;
		}
	} else if (wbc->sync_mode == WB_SYNC_ALL) {
		if (req_type == SSDFS_BLOCK_BASED_REQUEST)
			err = ssdfs_issue_sync_block_write_request(wbc, req);
		else if (req_type == SSDFS_EXTENT_BASED_REQUEST)
			err = ssdfs_issue_sync_extent_write_request(wbc, req);
		else
			BUG();

		if (err) {
			SSDFS_ERR("fail to write sync: "
				  "ino %lu, err %d\n",
				  ino, err);
				goto fail_issue_write_request;
		}

		res = wait_for_completion_timeout(&(*req)->result.wait,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("write request failed: "
				  "ino %lu, logical_offset %llu, size %u, "
				  "err %d\n",
				  ino, (u64)logical_offset,
				  (u32)data_bytes, err);
			goto fail_issue_write_request;
		}

		if ((*req)->result.err) {
			err = (*req)->result.err;
			SSDFS_ERR("write request failed: "
				  "ino %lu, logical_offset %llu, size %u, "
				  "err %d\n",
				  ino, (u64)logical_offset, (u32)data_bytes,
				  (*req)->result.err);
			goto fail_issue_write_request;
		}

		for (i = 0; i < pagevec_count(&(*req)->result.pvec); i++) {
			page = (*req)->result.pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

			clear_page_new(page);
			ClearPageDirty(page);
			SetPageUptodate(page);
			ClearPageError(page);

			unlock_page(page);
			end_page_writeback(page);
		}

		ssdfs_put_request(*req);
		ssdfs_request_free(*req);
	} else
		BUG();

	return 0;

fail_issue_write_request:
	for (i = 0; i < pagevec_count(&(*req)->result.pvec); i++) {
		page = (*req)->result.pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		SetPageError(page);

		if (wbc->sync_mode == WB_SYNC_ALL)
			unlock_page(page);

		end_page_writeback(page);
	}

	ssdfs_put_request(*req);
	ssdfs_request_free(*req);

	return err;
}

static
int __ssdfs_writepage(struct page *page, u32 len,
		      struct writeback_control *wbc,
		      struct ssdfs_segment_request **req)
{
	struct inode *inode = page->mapping->host;
	ino_t ino = inode->i_ino;
	pgoff_t index = page_index(page);
	loff_t logical_offset;
	int err;

	SSDFS_DBG("ino %lu, page_index %llu, len %u, sync_mode %#x\n",
		  ino, (u64)index, len, wbc->sync_mode);

	*req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(*req)) {
		err = (*req == NULL ? -ENOMEM : PTR_ERR(*req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(*req);
	ssdfs_get_request(*req);

	logical_offset = (loff_t)index << PAGE_SHIFT;
	ssdfs_request_prepare_logical_extent(ino, (u64)logical_offset,
					     len, 0, 0, *req);

	err = ssdfs_request_add_page(page, *req);
	if (err) {
		SSDFS_ERR("fail to add page into request: "
			  "ino %lu, page_index %lu, err %d\n",
			  ino, index, err);
		goto free_request;
	}

	return ssdfs_issue_write_request(wbc, req, SSDFS_BLOCK_BASED_REQUEST);

free_request:
	ssdfs_put_request(*req);
	ssdfs_request_free(*req);

	return err;
}

static
int __ssdfs_writepages(struct page *page, u32 len,
			struct writeback_control *wbc,
			struct ssdfs_segment_request **req)
{
	struct inode *inode = page->mapping->host;
	ino_t ino = inode->i_ino;
	pgoff_t index = page_index(page);
	loff_t logical_offset;
	bool need_create_request;
	int err;

	SSDFS_DBG("ino %lu, page_index %llu, len %u, sync_mode %#x\n",
		  ino, (u64)index, len, wbc->sync_mode);

	logical_offset = (loff_t)index << PAGE_SHIFT;

try_add_page_into_request:
	need_create_request = *req == NULL;

	if (need_create_request) {
		*req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(*req)) {
			err = (*req == NULL ? -ENOMEM : PTR_ERR(*req));
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			goto fail_write_pages;
		}

		ssdfs_request_init(*req);
		ssdfs_get_request(*req);

		err = ssdfs_request_add_page(page, *req);
		if (err) {
			SSDFS_ERR("fail to add page into request: "
				  "ino %lu, page_index %lu, err %d\n",
				  ino, index, err);
			goto free_request;
		}

		ssdfs_request_prepare_logical_extent(ino, (u64)logical_offset,
						     len, 0, 0, *req);
	} else {
		u64 upper_bound = (*req)->extent.logical_offset +
					(*req)->extent.data_bytes;
		u32 last_index;
		struct page *last_page;

		if (pagevec_count(&(*req)->result.pvec) == 0) {
			err = -ERANGE;
			SSDFS_WARN("pagevec is empty\n");
			goto free_request;
		}

		last_index = pagevec_count(&(*req)->result.pvec) - 1;
		last_page = (*req)->result.pvec.pages[last_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!last_page);
#endif /* CONFIG_SSDFS_DEBUG */

		if (logical_offset == upper_bound &&
		    can_be_merged_into_extent(last_page, page)) {
			err = ssdfs_request_add_page(page, *req);
			if (err) {
				err = ssdfs_issue_write_request(wbc, req,
						    SSDFS_EXTENT_BASED_REQUEST);
				if (err)
					goto fail_write_pages;

				*req = NULL;
				goto try_add_page_into_request;
			}

			(*req)->extent.data_bytes += len;
		} else {
			err = ssdfs_issue_write_request(wbc, req,
						    SSDFS_EXTENT_BASED_REQUEST);
			if (err)
				goto fail_write_pages;

			*req = NULL;
			goto try_add_page_into_request;
		}
	}

	return 0;

free_request:
	ssdfs_put_request(*req);
	ssdfs_request_free(*req);

fail_write_pages:
	return err;
}

/* writepage function prototype */
typedef int (*ssdfs_writepagefn)(struct page *page, u32 len,
				 struct writeback_control *wbc,
				 struct ssdfs_segment_request **req);

static
int ssdfs_writepage_wrapper(struct page *page,
			    struct writeback_control *wbc,
			    struct ssdfs_segment_request **req,
			    ssdfs_writepagefn writepage)
{
	struct inode *inode = page->mapping->host;
	ino_t ino = inode->i_ino;
	pgoff_t index = page_index(page);
	loff_t i_size =  i_size_read(inode);
	pgoff_t end_index = i_size >> PAGE_SHIFT;
	int len = i_size & (PAGE_SIZE - 1);
	int err = 0;

	SSDFS_DBG("ino %lu, page_index %llu, "
		  "i_size %llu, len %d\n",
		  ino, (u64)index,
		  (u64)i_size, len);

	if (inode->i_sb->s_flags & SB_RDONLY) {
		/*
		 * It means that filesystem was remounted in read-only
		 * mode because of error or metadata corruption. But we
		 * have dirty pages that try to be flushed in background.
		 * So, here we simply discard this dirty page.
		 */
		err = -EROFS;
		goto discard_page;
	}

	/* Is the page fully outside @i_size? (truncate in progress) */
	if (index > end_index || (index == end_index && !len)) {
		err = 0;
		goto finish_write_page;
	}

	/* Is the page fully inside @i_size? */
	if (index < end_index) {
		err = (*writepage)(page, PAGE_SIZE, wbc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(inode->i_sb, __FILE__,
					__func__, __LINE__,
					"fail to write page: "
					"ino %lu, page_index %llu, err %d\n",
					ino, (u64)index, err);
			goto discard_page;
		}

		return 0;
	}

	/*
	 * The page straddles @i_size. It must be zeroed out on each and every
	 * writepage invocation because it may be mmapped. "A file is mapped
	 * in multiples of the page size. For a file that is not a multiple of
	 * the page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	zero_user_segment(page, len, PAGE_SIZE);

	err = (*writepage)(page, len, wbc, req);
	if (unlikely(err)) {
		ssdfs_fs_error(inode->i_sb, __FILE__,
				__func__, __LINE__,
				"fail to write page: "
				"ino %lu, page_index %llu, err %d\n",
				ino, (u64)index, err);
		goto discard_page;
	}

	return 0;

discard_page:
	ClearPageUptodate(page);
	ClearPageMappedToDisk(page);
	ssdfs_clear_dirty_page(page);

finish_write_page:
	unlock_page(page);
	return err;
}

/*
 * The ssdfs_writepage() is called by the VM to write
 * a dirty page to backing store. This may happen for data
 * integrity reasons (i.e. 'sync'), or to free up memory
 * (flush). The difference can be seen in wbc->sync_mode.
 */
static
int ssdfs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	ino_t ino = inode->i_ino;
	pgoff_t index = page_index(page);
	struct ssdfs_segment_request *req = NULL;

	SSDFS_DBG("ino %lu, page_index %llu\n",
		  ino, (u64)index);

	return ssdfs_writepage_wrapper(page, wbc, &req,
					__ssdfs_writepage);
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
	ino_t ino = inode->i_ino;
	struct ssdfs_segment_request *req = NULL;
	struct pagevec pvec;
	int nr_pages;
	pgoff_t uninitialized_var(writeback_index);
	pgoff_t index;
	pgoff_t end;		/* Inclusive */
	pgoff_t done_index;
	int cycled;
	int range_whole = 0;
	int tag;
	int done = 0;
	int ret = 0;

	SSDFS_DBG("ino %lu, nr_to_write %lu, "
		  "range_start %llu, range_end %llu\n",
		  ino, wbc->nr_to_write,
		  (u64)wbc->range_start,
		  (u64)wbc->range_end);

	/*
	 * No pages to write?
	 */
	if (!mapping->nrpages || !mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
		goto out_writepages;

	pagevec_init(&pvec);

	if (wbc->range_cyclic) {
		writeback_index = mapping->writeback_index; /* prev offset */
		index = writeback_index;
		if (index == 0)
			cycled = 1;
		else
			cycled = 0;
		end = -1;
	} else {
		index = wbc->range_start >> PAGE_SHIFT;
		end = wbc->range_end >> PAGE_SHIFT;
		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = 1;
		cycled = 1; /* ignore range_cyclic tests */
	}

	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag = PAGECACHE_TAG_TOWRITE;
	else
		tag = PAGECACHE_TAG_DIRTY;

retry:
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag_pages_for_writeback(mapping, index, end);

	done_index = index;

	while (!done && (index <= end)) {
		int i;

		nr_pages = (int)min_t(pgoff_t, end - index,
					(pgoff_t)PAGEVEC_SIZE-1) + 1;
		nr_pages = pagevec_lookup_range_nr_tag(&pvec, mapping, &index,
							end, tag, nr_pages);
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/*
			 * At this point, the page may be truncated or
			 * invalidated (changing page->mapping to NULL), or
			 * even swizzled back from swapper_space to tmpfs file
			 * mapping. However, page->index will not change
			 * because we have a reference on the page.
			 */
			if (page->index > end) {
				/*
				 * can't be range_cyclic (1st pass) because
				 * end == -1 in that case.
				 */
				done = 1;
				break;
			}

			done_index = page->index;

			lock_page(page);

			/*
			 * Page truncated or invalidated. We can freely skip it
			 * then, even for data integrity operations: the page
			 * has disappeared concurrently, so there could be no
			 * real expectation of this data interity operation
			 * even if there is now a new, dirty page at the same
			 * pagecache address.
			 */
			if (unlikely(page->mapping != mapping)) {
continue_unlock:
				unlock_page(page);
				continue;
			}

			if (!PageDirty(page)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if (PageWriteback(page)) {
				if (wbc->sync_mode != WB_SYNC_NONE)
					wait_on_page_writeback(page);
				else
					goto continue_unlock;
			}

			BUG_ON(PageWriteback(page));
			if (!clear_page_dirty_for_io(page))
				goto continue_unlock;

			ret = ssdfs_writepage_wrapper(page, wbc, &req,
						      __ssdfs_writepages);
			if (unlikely(ret)) {
				if (ret == -EROFS) {
					/*
					 * continue to discard pages
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
					done_index = page->index + 1;
					done = 1;
					break;
				}
			}

			/*
			 * We stop writing back only if we are not doing
			 * integrity sync. In case of integrity sync we have to
			 * keep going until we have written all the pages
			 * we tagged for writeback prior to entering this loop.
			 */
			if (--wbc->nr_to_write <= 0 &&
			    wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}
		}

		pagevec_release(&pvec);
		cond_resched();
	};

	ret = ssdfs_issue_write_request(wbc, &req, SSDFS_EXTENT_BASED_REQUEST);
	if (ret < 0)
		goto out_writepages;

	if (!cycled && !done) {
		/*
		 * range_cyclic:
		 * We hit the last page and there is more work to be done: wrap
		 * back to the start of the file
		 */
		cycled = 1;
		index = 0;
		end = writeback_index - 1;
		goto retry;
	}

	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = done_index;

out_writepages:
	return ret;
}

/*
 * The ssdfs_write_begin() is called by the generic
 * buffered write code to ask the filesystem to prepare
 * to write len bytes at the given offset in the file.
 */
static
int ssdfs_write_begin(struct file *file, struct address_space *mapping,
		      loff_t pos, unsigned len, unsigned flags,
		      struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct page *page;
	pgoff_t index = pos >> PAGE_SHIFT;
	unsigned blks = 0;
	loff_t start_blk, end_blk, cur_blk;
	bool is_new_blk = false;
	int err = 0;

	SSDFS_DBG("ino %lu, pos %llu, len %u, flags %#x\n",
		  inode->i_ino, pos, len, flags);

	if (inode->i_sb->s_flags & SB_RDONLY)
		return -EROFS;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		SSDFS_ERR("fail to grab page: index %lu, flags %#x\n",
			  index, flags);
		return -ENOMEM;
	}

	start_blk = pos >> fsi->log_pagesize;
	end_blk = (pos + len) >> fsi->log_pagesize;

	cur_blk = start_blk;
	do {
		is_new_blk = !ssdfs_extents_tree_has_logical_block(cur_blk,
								   inode);

		if (is_new_blk) {
			spin_lock(&fsi->volume_state_lock);
			if (fsi->free_pages > 0) {
				fsi->free_pages--;
				blks++;
			} else
				err = -ENOSPC;
			spin_unlock(&fsi->volume_state_lock);

			if (err) {
				spin_lock(&fsi->volume_state_lock);
				fsi->free_pages += blks;
				spin_unlock(&fsi->volume_state_lock);

				unlock_page(page);
				put_page(page);

				SSDFS_DBG("volume hasn't free space\n");
				return err;
			}

			if (!need_add_block(page))
				set_page_new(page);
		}

		cur_blk++;
	} while (cur_blk < end_blk);

	*pagep = page;

	if ((len == PAGE_SIZE) || PageUptodate(page))
		return 0;

	if ((pos & PAGE_MASK) >= i_size_read(inode)) {
		unsigned start = pos & (PAGE_SIZE - 1);
		unsigned end = start + len;

		/* Reading beyond i_size is simple: memset to zero */
		zero_user_segments(page, 0, start, end, PAGE_SIZE);
		return 0;
	}

	return ssdfs_readpage_nolock(file, page, SSDFS_CURRENT_THREAD_READ);
}

/*
 * After a successful ssdfs_write_begin(), and data copy,
 * ssdfs_write_end() must be called.
 */
static
int ssdfs_write_end(struct file *file, struct address_space *mapping,
		    loff_t pos, unsigned len, unsigned copied,
		    struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	pgoff_t index = page->index;
	unsigned start = pos & (PAGE_SIZE - 1);
	unsigned end = start + copied;
	loff_t old_size = i_size_read(inode);
	int err = 0;

	SSDFS_DBG("ino %lu, pos %llu, len %u, copied %u, "
		  "index %lu, start %u, end %u, old_size %llu\n",
		  inode->i_ino, pos, len, copied,
		  index, start, end, old_size);

	if (copied < len) {
		/*
		 * VFS copied less data to the page that it intended and
		 * declared in its '->write_begin()' call via the @len
		 * argument. Just tell userspace to retry the entire page.
		 */
		if (!PageUptodate(page)) {
			copied = 0;
			goto out;
		}
	}

	if (old_size < (index << PAGE_SHIFT) + end) {
		i_size_write(inode, (index << PAGE_SHIFT) + end);
		mark_inode_dirty_sync(inode);
	}

	flush_dcache_page(page);

	SetPageUptodate(page);
	if (!PageDirty(page))
		__set_page_dirty_nobuffers(page);

out:
	unlock_page(page);
	put_page(page);
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

	SSDFS_DBG("ino %lu, start %llu, end %llu, datasync %#x\n",
		  (unsigned long)inode->i_ino, (unsigned long long)start,
		  (unsigned long long)end, datasync);

	trace_ssdfs_sync_file_enter(inode);

	err = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (err) {
		trace_ssdfs_sync_file_exit(file, datasync, err);
		SSDFS_DBG("fsync failed: ino %lu, start %llu, "
			  "end %llu, err %d\n",
			  (unsigned long)inode->i_ino,
			  (unsigned long long)start,
			  (unsigned long long)end,
			  err);
		return err;
	}

	inode_lock(inode);
	sync_inode_metadata(inode, 1);
	blkdev_issue_flush(inode->i_sb->s_bdev, GFP_KERNEL, NULL);
	inode_unlock(inode);

	trace_ssdfs_sync_file_exit(file, datasync, err);

	return err;
}

const struct file_operations ssdfs_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.unlocked_ioctl	= ssdfs_ioctl,
	.mmap		= generic_file_mmap,
	.open		= generic_file_open,
	.fsync		= ssdfs_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
};

const struct inode_operations ssdfs_file_inode_operations = {
	.getattr	= ssdfs_getattr,
	.setattr	= ssdfs_setattr,
	.listxattr	= ssdfs_listxattr,
	.get_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,
};

const struct inode_operations ssdfs_special_inode_operations = {
	.setattr	= ssdfs_setattr,
	.listxattr	= ssdfs_listxattr,
	.get_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,
};

const struct inode_operations ssdfs_symlink_inode_operations = {
	.get_link	= page_get_link,
	.getattr	= ssdfs_getattr,
	.setattr	= ssdfs_setattr,
	.listxattr	= ssdfs_listxattr,
};

const struct address_space_operations ssdfs_aops = {
	.readpage		= ssdfs_readpage,
	.readpages		= ssdfs_readpages,
	.writepage		= ssdfs_writepage,
	.writepages		= ssdfs_writepages,
	.write_begin		= ssdfs_write_begin,
	.write_end		= ssdfs_write_end,
	.direct_IO		= ssdfs_direct_IO,
};
