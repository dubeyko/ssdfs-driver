//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ioctl.c - IOCTL operations.
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

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/pagevec.h>
#include <linux/mount.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"

static int ssdfs_ioctl_getflags(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	unsigned int flags;

	flags = ii->flags & SSDFS_FL_USER_VISIBLE;
	return put_user(flags, (int __user *) arg);
}

static int ssdfs_ioctl_setflags(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	unsigned int flags, oldflags;
	int err = 0;

	err = mnt_want_write_file(file);
	if (err)
		return err;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (get_user(flags, (int __user *)arg))
		return -EFAULT;

	flags = ssdfs_mask_flags(inode->i_mode, flags);

	inode_lock(inode);
	down_write(&ii->lock);

	oldflags = ii->flags;

	/*
	 * The IMMUTABLE and APPEND_ONLY flags can only be changed by the
	 * relevant capability.
	 */
	if ((flags ^ oldflags) & (SSDFS_APPEND_FL | SSDFS_IMMUTABLE_FL)) {
		if (!capable(CAP_LINUX_IMMUTABLE)) {
			err = -EPERM;
			goto out_unlock_inode;
		}
	}

	flags = flags & SSDFS_FL_USER_MODIFIABLE;
	flags |= oldflags & ~SSDFS_FL_USER_MODIFIABLE;
	ii->flags = flags;

	ssdfs_set_inode_flags(inode);
	inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);

out_unlock_inode:
	up_write(&ii->lock);
	inode_unlock(inode);
	mnt_drop_write_file(file);
	return err;
}

/*
 * The ssdfs_ioctl() is called by the ioctl(2) system call.
 */
long ssdfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		return ssdfs_ioctl_getflags(file, argp);
	case FS_IOC_SETFLAGS:
		return ssdfs_ioctl_setflags(file, argp);
	}

	return -ENOTTY;
}
