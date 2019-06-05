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

#include "ssdfs.h"
#include "xattr.h"
#include "acl.h"

#include <trace/events/ssdfs.h>

/*
 * The ssdfs_readpage() is called by the VM
 * to read a page from backing store.
 */
static int ssdfs_readpage(struct file *file, struct page *page)
{
	/* TODO: implement ssdfs_readpage() */
	SSDFS_WARN("TODO: implement ssdfs_readpage()\n");
	return -EIO;
}

/*
 * The ssdfs_readpages() is called by the VM to read pages
 * associated with the address_space object. This is essentially
 * just a vector version of ssdfs_readpage(). Instead of just one
 * page, several pages are requested. The ssdfs_readpages() is only
 * used for read-ahead, so read errors are ignored.
 */
static int ssdfs_readpages(struct file *file, struct address_space *mapping,
			   struct list_head *pages, unsigned nr_pages)
{
	/* TODO: implement ssdfs_readpages() */
	SSDFS_WARN("TODO: implement ssdfs_readpages()\n");
	return -EIO;
}

/*
 * The ssdfs_writepage() is called by the VM to write
 * a dirty page to backing store. This may happen for data
 * integrity reasons (i.e. 'sync'), or to free up memory
 * (flush). The difference can be seen in wbc->sync_mode.
 */
static int ssdfs_writepage(struct page *page, struct writeback_control *wbc)
{
	/* TODO: implement ssdfs_writepage() */
	SSDFS_WARN("TODO: implement ssdfs_writepage()\n");
	return -EIO;
}

/*
 * The ssdfs_writepages() is called by the VM to write out
 * pages associated with the address_space object.
 */
static int ssdfs_writepages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	/* TODO: implement ssdfs_writepages() */
	SSDFS_WARN("TODO: implement ssdfs_writepages()\n");
	return -EIO;
}

/* TODO: implement ssdfs_write_failed() */
/*static void ssdfs_write_failed(struct address_space *mapping, loff_t to)
{
	SSDFS_WARN("TODO: implement ssdfs_write_failed()\n");
}*/

/*
 * The ssdfs_write_begin() is called by the generic
 * buffered write code to ask the filesystem to prepare
 * to write len bytes at the given offset in the file.
 */
static int ssdfs_write_begin(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned flags,
			     struct page **pagep, void **fsdata)

{
	/* TODO: implement ssdfs_write_begin() */
	SSDFS_WARN("TODO: implement ssdfs_write_begin()\n");
	return -EIO;
}

/*
 * After a successful ssdfs_write_begin(), and data copy,
 * ssdfs_write_end() must be called.
 */
static int ssdfs_write_end(struct file *file, struct address_space *mapping,
			   loff_t pos, unsigned len, unsigned copied,
			   struct page *page, void *fsdata)
{
	/* TODO: implement ssdfs_write_end() */
	SSDFS_WARN("TODO: implement ssdfs_write_end()\n");
	return -EIO;
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
	.writepages		= ssdfs_writepages,
	.write_begin		= ssdfs_write_begin,
	.write_end		= ssdfs_write_end,
	.direct_IO		= ssdfs_direct_IO,
};
