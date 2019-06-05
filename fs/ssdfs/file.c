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

	/* trace_ssdfs_sync_file(file, datasync); */

	err = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (err)
		return err;

	/* mutex_lock(&inode->i_mutex); */
	/* TODO: implement core logic of ssdfs_fsync() */
	SSDFS_WARN("TODO: implement ssdfs_fsync()\n");
	/* mutex_unlock(&inode->i_mutex); */

	return -EIO;
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
/*	.setxattr	= ssdfs_setxattr,
	.getxattr	= ssdfs_getxattr,
	.listxattr	= ssdfs_listxattr,
	.removexattr	= generic_removexattr,*/
/*	.get_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,*/
};

const struct inode_operations ssdfs_special_inode_operations = {
	.setattr	= ssdfs_setattr,
/*	.setxattr	= ssdfs_setxattr,
	.getxattr	= ssdfs_getxattr,
	.listxattr	= ssdfs_listxattr,
	.removexattr	= generic_removexattr,*/
/*	.get_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,*/
};

const struct inode_operations ssdfs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.setattr	= ssdfs_setattr,
/*	.setxattr	= ssdfs_setxattr,
	.getxattr	= ssdfs_getxattr,
	.listxattr	= ssdfs_listxattr,
	.removexattr	= generic_removexattr,*/
};
