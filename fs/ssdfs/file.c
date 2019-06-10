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

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>

#include "ssdfs.h"
#include "segment.h"
#include "xattr.h"
#include "acl.h"
#include "request_queue.h"

#include <trace/events/ssdfs.h>

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

	/* TODO: now we have one segment only!!!! */
	ssdfs_segment_read_block_sync(fsi->seg_info, req);

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

	logical_offset = (loff_t)index << PAGE_CACHE_SHIFT;

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req);

	ssdfs_request_prepare_logical_extent(ino, (u64)logical_offset,
					     len, 0, 0, req);

	err = ssdfs_request_add_page(page, req);
	if (err) {
		SSDFS_ERR("fail to add page into request: "
			  "ino %lu, page_index %lu, err %d\n",
			  ino, index, err);
		goto fail_write_page;
	}

	/*
	 * TODO: Temporary we only create pages.
	 *       It needs to differentiate created and updated pages.
	 *       I suppose that it needs to add special flag for page.
	 */
	if (wbc->sync_mode == WB_SYNC_NONE) {
		err = ssdfs_segment_add_block_async(fsi->cur_seg, req);
		if (err) {
			SSDFS_ERR("fail to write page async: "
				  "ino %lu, page_index %llu, len %u, err %d\n",
				  ino, (u64)index, len, err);
				goto fail_write_page;
		}
	} else if (wbc->sync_mode == WB_SYNC_ALL) {
		err = ssdfs_segment_add_block_sync(fsi->cur_seg, req);
		if (err) {
			SSDFS_ERR("fail to write page sync: "
				  "ino %lu, page_index %llu, len %u, err %d\n",
				  ino, (u64)index, len, err);
				goto fail_write_page;
		}

		err = wait_for_completion_killable(&req->result.wait);
		if (unlikely(err)) {
			SSDFS_ERR("write request failed: "
				  "ino %lu, logical_offset %llu, size %u, "
				  "err %d\n",
				  ino, (u64)logical_offset, (u32)len, err);
			goto fail_write_page;
		}

		if (req->result.err) {
			err = req->result.err;
			SSDFS_ERR("write request failed: "
				  "ino %lu, logical_offset %llu, size %u, "
				  "err %d\n",
				  ino, (u64)logical_offset, (u32)len,
				  req->result.err);
			goto fail_write_page;
		}

		ssdfs_request_free(req);

		ClearPageDirty(page);
		SetPageUptodate(page);
		ClearPageError(page);

		unlock_page(page);
	} else
		BUG();

	return 0;

fail_write_page:
	SetPageDirty(page);
	SetPageError(page);
	ssdfs_request_free(req);

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
	struct page *page;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;

	SSDFS_DBG("ino %lu, pos %llu, len %u, flags %#x\n",
		  inode->i_ino, pos, len, flags);

	if (inode->i_sb->s_flags & MS_RDONLY)
		return -EROFS;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		SSDFS_ERR("fail to grab page: index %lu, flags %#x\n",
			  index, flags);
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
	pgoff_t index = page->index;
	unsigned start = pos & (PAGE_CACHE_SIZE - 1);
	unsigned end = start + copied;
	int err = 0;

	SSDFS_DBG("ino %lu, pos %llu, len %u, copied %u\n",
		  inode->i_ino, pos, len, copied);

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

	if (i_size_read(inode) < (index << PAGE_CACHE_SHIFT) + end) {
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
	.setattr	= ssdfs_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ssdfs_listxattr,
	.removexattr	= generic_removexattr,
	.get_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,
};

const struct inode_operations ssdfs_special_inode_operations = {
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
