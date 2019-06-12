//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 *  SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/file.c - file operations.
 *
 * Copyright (c) 2019 Viacheslav Dubeyko <slava@dubeyko.com>
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

#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "segment.h"
#include "xattr.h"
#include "acl.h"
#include "request_queue.h"

#include <trace/events/ssdfs.h>

/*
 * ssdfs_prepare_volume_extent() - convert requested byte stream into extent
 * @fsi: pointer on shared file system object
 * @req: request object
 *
 * This method tries to convert logical byte stream into extent of blocks.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA     - unable to convert byte stream into extent.
 */
static
int ssdfs_prepare_volume_extent(struct ssdfs_fs_info *fsi,
				struct ssdfs_segment_request *req)
{
	struct ssdfs_inode_info *ii;
	struct ssdfs_raw_fork *fork = NULL;
	struct ssdfs_raw_extent *extent = NULL;
	u32 pagesize = fsi->pagesize;
	u64 seg_id;
	u32 logical_blk = U32_MAX, len;
	u64 start_blk;
	u64 blks_count;
	u32 requested_blk, requested_len;
	u64 processed_blks = 0;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON((req->extent.logical_offset >> fsi->log_pagesize) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, req %p, ino %llu, "
		  "logical_offset %llu, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu\n",
		  fsi, req, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes,
		  req->extent.cno,
		  req->extent.parent_snapshot);

	ii = SSDFS_I(req->result.pvec.pages[0]->mapping->host);

	requested_blk = req->extent.logical_offset >> fsi->log_pagesize;
	requested_len = (req->extent.data_bytes + pagesize - 1) >>
				fsi->log_pagesize;

	if (ii->forks_count == 0) {
		SSDFS_ERR("extents tree hasn't any fork\n");
		return -ENODATA;
	}

	for (i = 0; i < ii->forks_count; fork = NULL, i++) {
		fork = &ii->forks[i];

		start_blk = le64_to_cpu(fork->start_offset);
		blks_count = le64_to_cpu(fork->blks_count);

		if (start_blk == U64_MAX || blks_count == U64_MAX) {
			SSDFS_ERR("corrupted fork\n");
			return -ERANGE;
		}

		if (blks_count == 0) {
			SSDFS_ERR("empty extent\n");
			return -ERANGE;
		}

		if (start_blk <= requested_blk &&
		    requested_blk < (start_blk + blks_count)) {
			/* fork is found */
			break;
		} else if (requested_blk < start_blk) {
			fork = NULL;
			break;
		}
	}

	if (!fork) {
		SSDFS_DBG("fork hasn't been found\n");
		return -ENODATA;
	}

	for (i = 0; i < SSDFS_INLINE_EXTENTS_COUNT; extent = NULL, i++) {
		if (processed_blks >= blks_count)
			break;

		extent = &fork->extents[i];

		seg_id = le64_to_cpu(extent->seg_id);
		logical_blk = le32_to_cpu(extent->logical_blk);
		len = le32_to_cpu(extent->len);

		if (seg_id == U64_MAX || logical_blk == U32_MAX ||
		    len == U32_MAX) {
			SSDFS_ERR("corrupted extent: index %d\n", i);
			return -ERANGE;
		}

		if (len == 0) {
			SSDFS_ERR("corrupted extent: index %d\n", i);
			return -ERANGE;
		}

		if ((start_blk + processed_blks) <= requested_blk &&
		    requested_blk < (start_blk + processed_blks + len)) {
			u64 diff = requested_blk - (start_blk + processed_blks);

			logical_blk += (u32)diff;
			len -= (u32)diff;
			len = min_t(u32, len, requested_len);
			break;
		}

		processed_blks += len;
	}

	if (!extent) {
		SSDFS_DBG("extent hasn't been found\n");
		return -ENODATA;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_blk >= U16_MAX);
	BUG_ON(len >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_define_segment(seg_id, req);
	ssdfs_request_define_volume_extent((u16)logical_blk, (u16)len, req);

	return 0;
}

/*
 * ssdfs_read_block_sync() - read block synchronously.
 * @fsi: pointer on shared file system object
 * @req: request object
 */
static
int ssdfs_read_block_sync(struct ssdfs_fs_info *fsi,
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

	err = ssdfs_segment_read_block_sync(si, req);
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

static
int ssdfs_readpage_nolock(struct file *file, struct page *page)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(file_inode(file)->i_sb);
	ino_t ino = file_inode(file)->i_ino;
	pgoff_t index = page_index(page);
	struct ssdfs_segment_request *req;
	loff_t logical_offset;
	loff_t data_bytes;
	loff_t file_size;
	void *kaddr;
	int err;

	SSDFS_DBG("ino %lu, page_index %llu\n",
		  ino, (u64)index);

	logical_offset = (loff_t)index << PAGE_CACHE_SHIFT;

	file_size = i_size_read(file_inode(file));
	data_bytes = file_size - logical_offset;
	data_bytes = min_t(loff_t, PAGE_CACHE_SIZE, data_bytes);

	BUG_ON(data_bytes > U32_MAX);

	kaddr = kmap_atomic(page);
	memset(kaddr, 0, PAGE_CACHE_SIZE);
	kunmap_atomic(kaddr);

	if (logical_offset >= file_size) {
		/* Reading beyond inode */
		goto finish_read_page;
	}

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req);

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

	err = ssdfs_read_block_sync(fsi, req);
	if (err) {
		SSDFS_ERR("fail to read block: err %d\n", err);
		goto fail_read_page;
	}

	err = wait_for_completion_killable(&req->result.wait);
	if (unlikely(err)) {
		SSDFS_ERR("read request failed: "
			  "ino %lu, logical_offset %llu, size %u, err %d\n",
			  ino, (u64)logical_offset, (u32)data_bytes, err);
		goto fail_read_page;
	}

	if (req->result.err) {
		SSDFS_ERR("read request failed: "
			  "ino %lu, logical_offset %llu, size %u, err %d\n",
			  ino, (u64)logical_offset, (u32)data_bytes,
			  req->result.err);
		goto fail_read_page;
	}

	ssdfs_request_free(req);

finish_read_page:
	SetPageUptodate(page);
	ClearPageError(page);
	flush_dcache_page(page);

	return 0;

fail_read_page:
	ClearPageUptodate(page);
	SetPageError(page);
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

	err = ssdfs_readpage_nolock(file, page);
	unlock_page(page);
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
	/* TODO: implement ssdfs_readpages() */
	SSDFS_WARN("TODO: implement ssdfs_readpages()\n");
	return -EIO;
}

static
struct ssdfs_raw_fork *ssdfs_find_fork_in_extents_tree(u64 blk_offset,
						struct ssdfs_inode_info *ii,
						int *fork_index)
{
	struct ssdfs_raw_fork *fork = NULL;
	u64 start_offset;
	u64 blks_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ii);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_offset %llu, ii %p\n",
		  blk_offset, ii);

	if (ii->forks_count >= SSDFS_INLINE_FORKS_COUNT) {
		SSDFS_ERR("invalid forks count: forks_count %u\n",
			  ii->forks_count);
		return ERR_PTR(-ERANGE);
	}

	if (*fork_index >= SSDFS_INLINE_FORKS_COUNT) {
		SSDFS_DBG("all forks were used\n");
		return ERR_PTR(-ENOSPC);
	}

	for (; *fork_index < SSDFS_INLINE_FORKS_COUNT; ++(*fork_index)) {
		fork = &ii->forks[*fork_index];
		start_offset = le64_to_cpu(fork->start_offset);
		blks_count = le64_to_cpu(fork->blks_count);

		if (start_offset == U64_MAX)
			break;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(start_offset >= (U64_MAX - blks_count));
#endif /* CONFIG_SSDFS_DEBUG */

		if (blk_offset <= start_offset) {
			SSDFS_ERR("holes are not supported yet\n");
			return ERR_PTR(-EOPNOTSUPP);
		}

		if ((start_offset + blks_count) == blk_offset)
			break;
	}

	if (*fork_index >= SSDFS_INLINE_FORKS_COUNT) {
		SSDFS_ERR("not enough extents\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	return fork;
}

static
struct ssdfs_raw_extent *ssdfs_find_extent_in_fork(u64 blk_offset,
					    struct ssdfs_raw_fork *fork,
					    struct ssdfs_segment_request *req)
{
	struct ssdfs_raw_extent *extent = NULL;
	u64 start_offset;
	u64 blks_count;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fork);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk_offset %llu, fork %p\n",
		  blk_offset, fork);

	start_offset = le64_to_cpu(fork->start_offset);
	blks_count = le64_to_cpu(fork->blks_count);

	if (start_offset == U64_MAX)
		return &fork->extents[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(start_offset >= (U64_MAX - blks_count));
#endif /* CONFIG_SSDFS_DEBUG */

	if ((start_offset + blks_count) != blk_offset) {
		SSDFS_ERR("start_offset %llu + blks_count %llu "
			  "!= blk_offset %llu\n",
			  start_offset, blks_count, blk_offset);
		return ERR_PTR(-ERANGE);
	}

	seg_id = le64_to_cpu(fork->extents[0].seg_id);
	logical_blk = le32_to_cpu(fork->extents[0].logical_blk);
	len = le32_to_cpu(fork->extents[0].len);

	if (seg_id == U64_MAX || logical_blk == U32_MAX || len == U32_MAX) {
		SSDFS_ERR("corrupted fork: "
			  "start_offset %llu, blks_count %llu\n",
			  start_offset, blks_count);
		return ERR_PTR(-ERANGE);
	}

	for (i = 0; i < SSDFS_INLINE_EXTENTS_COUNT; i++) {
		extent = &fork->extents[i];

		if (le64_to_cpu(extent->seg_id) == U64_MAX)
			break;
	}

	i--;

	if (i < 0) {
		SSDFS_ERR("fork is corrupted: "
			  "start_offset %llu, blks_count %llu\n",
			  start_offset, blks_count);
		return ERR_PTR(-ERANGE);
	}

	extent = &fork->extents[i];

	seg_id = le64_to_cpu(extent->seg_id);
	logical_blk = le32_to_cpu(extent->logical_blk);
	len = le32_to_cpu(extent->len);

	if (seg_id == U64_MAX || logical_blk == U32_MAX || len == U32_MAX) {
		SSDFS_ERR("corrupted fork: "
			  "start_offset %llu, blks_count %llu\n",
			  start_offset, blks_count);
		return ERR_PTR(-ERANGE);
	}

	if (seg_id != req->place.start.seg_id) {
		i++;

		if (i >= SSDFS_INLINE_EXTENTS_COUNT) {
			SSDFS_DBG("fork hasn't unused extents\n");
			return ERR_PTR(-ENOSPC);
		}

		return &fork->extents[i];
	}

	if (logical_blk <= req->place.start.blk_index &&
	    req->place.start.blk_index < (logical_blk + len)) {
		SSDFS_ERR("intersection takes place: "
			  "extent1 (new_block %u, len %u), "
			  "extent2 (start %u, len %u)\n",
			  req->place.start.blk_index,
			  req->place.len,
			  logical_blk, len);
		return ERR_PTR(-ERANGE);
	}

	if (req->place.start.blk_index <= logical_blk &&
	    logical_blk < (req->place.start.blk_index +
			    req->place.len)) {
		SSDFS_ERR("intersection takes place: "
			  "extent1 (new_block %u, len %u), "
			  "extent2 (start %u, len %u)\n",
			  req->place.start.blk_index,
			  req->place.len,
			  logical_blk, len);
		return ERR_PTR(-ERANGE);
	}

	if (logical_blk + len == req->place.start.blk_index)
		return extent;

	i++;

	if (i >= SSDFS_INLINE_EXTENTS_COUNT) {
		SSDFS_DBG("fork hasn't unused extents\n");
		return ERR_PTR(-ENOSPC);
	}

	return &fork->extents[i];
}

static
int ssdfs_add_block_in_extents_tree(struct inode *inode,
				    struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_inode_info *ii;
	struct ssdfs_raw_fork *fork = NULL;
	struct ssdfs_raw_extent *extent = NULL;
	ino_t ino;
	u64 blk_offset;
	u64 start_offset;
	u64 blks_count;
	int fork_index = 0;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!inode || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(inode->i_sb);
	ii = SSDFS_I(inode);
	ino = inode->i_ino;

	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "seg_id %llu, start_blk %u, len %u\n",
		  ino, req->extent.logical_offset,
		  req->place.start.seg_id,
		  req->place.start.blk_index, req->place.len);

	blk_offset = req->extent.logical_offset >> fsi->log_pagesize;

try_fork:
	fork = ssdfs_find_fork_in_extents_tree(blk_offset, ii, &fork_index);
	if (IS_ERR_OR_NULL(fork)) {
		err = fork == NULL ? -ERANGE : PTR_ERR(fork);
		SSDFS_ERR("fail to find fork: "
			  "blk_offset %llu, err %d\n",
			  blk_offset, err);
		return err;
	}

	extent = ssdfs_find_extent_in_fork(blk_offset, fork, req);
	if (IS_ERR_OR_NULL(extent)) {
		if (PTR_ERR(extent) == -ENOSPC) {
			fork_index++;
			goto try_fork;
		}

		err = extent == NULL ? -ERANGE : PTR_ERR(extent);
		SSDFS_ERR("fail to find extent: "
			  "blk_offset %llu, err %d\n",
			  blk_offset, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fork || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

	start_offset = le64_to_cpu(fork->start_offset);
	blks_count = le64_to_cpu(fork->blks_count);

	seg_id = le64_to_cpu(extent->seg_id);
	logical_blk = le32_to_cpu(extent->logical_blk);
	len = le32_to_cpu(extent->len);

	if (seg_id == U64_MAX) {
		if (logical_blk != U32_MAX || len != U32_MAX) {
			SSDFS_ERR("corrupted extent: "
				  "logical_blk %u, len %u\n",
				  logical_blk, len);
			return -ERANGE;
		}

		extent->seg_id = cpu_to_le64(req->place.start.seg_id);
		extent->logical_blk = cpu_to_le32(req->place.start.blk_index);
		extent->len = cpu_to_le32(req->place.len);
	} else {
		if (seg_id != req->place.start.seg_id ||
		    (logical_blk + len) != req->place.start.blk_index) {
			SSDFS_ERR("invalid extent: "
				  "found (seg %llu, start %u, len %u), "
				  "requested (seg %llu, start %u, len %u)\n",
				  seg_id, logical_blk, len,
				  req->place.start.seg_id,
				  req->place.start.blk_index,
				  req->place.len);
			return -ERANGE;
		}

		extent->len = cpu_to_le32(len + req->place.len);
	}

	if (start_offset == U64_MAX) {
		if (blks_count != U64_MAX) {
			SSDFS_ERR("corrupted fork: "
				  "blks_count %llu\n",
				  blks_count);
			return -ERANGE;
		}

		fork->start_offset = cpu_to_le64(blk_offset);
		fork->blks_count = cpu_to_le64(req->place.len);

		ii->forks_count++;
	} else
		le64_add_cpu(&fork->blks_count, req->place.len);

	return 0;
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

	if (wbc->sync_mode == WB_SYNC_NONE)
		err = ssdfs_segment_update_block_async(si, req);
	else if (wbc->sync_mode == WB_SYNC_ALL)
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

static
int __ssdfs_writepage(struct page *page, u32 len,
		      struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	ino_t ino = inode->i_ino;
	pgoff_t index = page_index(page);
	struct ssdfs_segment_request *req;
	loff_t logical_offset;
	int err;

	SSDFS_DBG("ino %lu, page_index %llu, len %u, sync_mode %#x\n",
		  ino, (u64)index, len, wbc->sync_mode);

	set_page_writeback(page);

	logical_offset = (loff_t)index << PAGE_CACHE_SHIFT;

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto fail_write_page;
	}

	ssdfs_request_init(req);

	ssdfs_request_prepare_logical_extent(ino, (u64)logical_offset,
					     len, 0, 0, req);

	err = ssdfs_request_add_page(page, req);
	if (err) {
		SSDFS_ERR("fail to add page into request: "
			  "ino %lu, page_index %lu, err %d\n",
			  ino, index, err);
		goto free_request;
	}

	if (wbc->sync_mode == WB_SYNC_NONE) {
		if (need_add_block(page)) {
			err = ssdfs_segment_add_data_block_async(fsi, req);
			if (!err) {
				err = ssdfs_add_block_in_extents_tree(inode,
									req);
				if (err) {
					SSDFS_ERR("fail to add extent: "
						  "ino %lu, page_index %llu, "
						  "len %u, err %d\n",
						  ino, (u64)index, len, err);
					ssdfs_request_free(req);
					SetPageError(page);
					return err;
				}
			}
		} else
			err = ssdfs_update_block(fsi, req, wbc);

		if (err) {
			SSDFS_ERR("fail to write page async: "
				  "ino %lu, page_index %llu, len %u, err %d\n",
				  ino, (u64)index, len, err);
				goto free_request;
		}
	} else if (wbc->sync_mode == WB_SYNC_ALL) {
		if (need_add_block(page)) {
			err = ssdfs_segment_add_data_block_sync(fsi, req);
			if (!err) {
				err = ssdfs_add_block_in_extents_tree(inode,
									req);
			}
		} else
			err = ssdfs_update_block(fsi, req, wbc);

		if (err) {
			SSDFS_ERR("fail to write page sync: "
				  "ino %lu, page_index %llu, len %u, err %d\n",
				  ino, (u64)index, len, err);
				goto free_request;
		}

		err = wait_for_completion_killable(&req->result.wait);
		if (unlikely(err)) {
			SSDFS_ERR("write request failed: "
				  "ino %lu, logical_offset %llu, size %u, "
				  "err %d\n",
				  ino, (u64)logical_offset, (u32)len, err);
			goto free_request;
		}

		if (req->result.err) {
			err = req->result.err;
			SSDFS_ERR("write request failed: "
				  "ino %lu, logical_offset %llu, size %u, "
				  "err %d\n",
				  ino, (u64)logical_offset, (u32)len,
				  req->result.err);
			goto free_request;
		}

		ssdfs_request_free(req);

		clear_page_new(page);
		ClearPageDirty(page);
		SetPageUptodate(page);
		ClearPageError(page);

		unlock_page(page);
		end_page_writeback(page);
	} else
		BUG();

	return 0;

free_request:
	ssdfs_request_free(req);

fail_write_page:
	SetPageError(page);
	end_page_writeback(page);

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
	loff_t i_size =  i_size_read(inode);
	pgoff_t end_index = i_size >> PAGE_CACHE_SHIFT;
	int len = i_size & (PAGE_CACHE_SIZE - 1);
	int err = 0;

	SSDFS_DBG("ino %lu, page_index %llu, "
		  "i_size %llu, len %d\n",
		  ino, (u64)index,
		  (u64)i_size, len);

	if (inode->i_sb->s_flags & MS_RDONLY) {
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
		/*err = inode->i_sb->s_op->write_inode(inode, NULL);
		if (err)
			goto finish_write_page;*/

		err = __ssdfs_writepage(page, PAGE_CACHE_SIZE, wbc);
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
	zero_user_segment(page, len, PAGE_CACHE_SIZE);

	/*err = inode->i_sb->s_op->write_inode(inode, NULL);
	if (err)
		goto finish_write_page;*/

	err = __ssdfs_writepage(page, len, wbc);
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
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	unsigned pages = 0;
	int err = 0;

	SSDFS_DBG("ino %lu, pos %llu, len %u, flags %#x\n",
		  inode->i_ino, pos, len, flags);

	if (inode->i_sb->s_flags & MS_RDONLY)
		return -EROFS;

	if ((pos & PAGE_CACHE_MASK) >= i_size_read(inode)) {
		unsigned pagesize = fsi->pagesize;
		unsigned start = pos & (PAGE_CACHE_SIZE - 1);
		unsigned end = start + len;

		pages = (end - start + pagesize - 1) / pagesize;

		spin_lock(&fsi->volume_state_lock);
		if (fsi->free_pages >= pages)
			fsi->free_pages -= pages;
		else
			err = -ENOSPC;
		spin_unlock(&fsi->volume_state_lock);
	}

	if (err) {
		SSDFS_ERR("volume hasn't free pages\n");
		return err;
	}

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		SSDFS_ERR("fail to grab page: index %lu, flags %#x\n",
			  index, flags);
		if (pages > 0) {
			spin_lock(&fsi->volume_state_lock);
			fsi->free_pages += pages;
			spin_unlock(&fsi->volume_state_lock);
		}
		return -ENOMEM;
	}

	*pagep = page;

	if ((len == PAGE_CACHE_SIZE) || PageUptodate(page))
		return 0;

	if ((pos & PAGE_CACHE_MASK) >= i_size_read(inode)) {
		unsigned start = pos & (PAGE_CACHE_SIZE - 1);
		unsigned end = start + len;

		/* Reading beyond i_size is simple: memset to zero */
		zero_user_segments(page, 0, start, end, PAGE_CACHE_SIZE);
		return 0;
	}

	return ssdfs_readpage_nolock(file, page);
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
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	pgoff_t index = page->index;
	unsigned start = pos & (PAGE_CACHE_SIZE - 1);
	unsigned end = start + copied;
	loff_t old_size = i_size_read(inode);
	u32 block_size;
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

	if (old_size < (index << PAGE_CACHE_SHIFT) + end) {
		u32 remainder;

		if (fsi->pagesize < PAGE_CACHE_SIZE)
			block_size = PAGE_CACHE_SIZE;
		else
			block_size = fsi->pagesize;

		div_u64_rem(old_size, block_size, &remainder);

		if (remainder == 0)
			set_page_new(page);

		i_size_write(inode, (index << PAGE_CACHE_SHIFT) + end);
		mark_inode_dirty_sync(inode);
	}

	SetPageUptodate(page);
	if (!PageDirty(page))
		__set_page_dirty_nobuffers(page);

out:
	unlock_page(page);
	page_cache_release(page);
	return err ? err : copied;
}

/*
 * The ssdfs_direct_IO() is called by the generic read/write
 * routines to perform direct_IO - that is IO requests which
 * bypass the page cache and transfer data directly between
 * the storage and the application's address space.
 */
static ssize_t ssdfs_direct_IO(int rw, struct kiocb *iocb,
				const struct iovec *iov,
				loff_t offset, unsigned long nr_segs)
{
	/* TODO: implement ssdfs_direct_IO() */
	SSDFS_WARN("TODO: implement ssdfs_direct_IO()\n");
	return 0;
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

	/* mutex_lock(&inode->i_mutex); */
	/* TODO: implement core logic of ssdfs_fsync() */
	SSDFS_WARN("TODO: implement ssdfs_fsync()\n");
	/* mutex_unlock(&inode->i_mutex); */

	err = -EIO;
	trace_ssdfs_sync_file_exit(file, datasync, err);

	return err;
}

const struct file_operations ssdfs_file_operations = {
	.llseek		= generic_file_llseek,
	.open		= generic_file_open,
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= generic_file_aio_read,
	.aio_write	= generic_file_aio_write,
	.unlocked_ioctl	= ssdfs_ioctl,
	.mmap		= generic_file_readonly_mmap,
	.fsync		= ssdfs_fsync,
	.splice_read	= generic_file_splice_read,
};

const struct inode_operations ssdfs_file_inode_operations = {
	.getattr	= ssdfs_getattr,
	.setattr	= ssdfs_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ssdfs_listxattr,
	.removexattr	= generic_removexattr,
	.get_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,
};

const struct inode_operations ssdfs_special_inode_operations = {
	/*.getattr	= ssdfs_getattr,*/
	.setattr	= ssdfs_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ssdfs_listxattr,
	.removexattr	= generic_removexattr,
	.get_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,
};

const struct inode_operations ssdfs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.getattr	= ssdfs_getattr,
	.setattr	= ssdfs_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ssdfs_listxattr,
	.removexattr	= generic_removexattr,
};

const struct address_space_operations ssdfs_aops = {
	.readpage		= ssdfs_readpage,
	.readpages		= ssdfs_readpages,
	.writepage		= ssdfs_writepage,
	.writepages		= generic_writepages,
	.write_begin		= ssdfs_write_begin,
	.write_end		= ssdfs_write_end,
	.direct_IO		= ssdfs_direct_IO,
};
