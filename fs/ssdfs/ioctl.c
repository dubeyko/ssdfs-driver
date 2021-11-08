//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ioctl.c - IOCTL operations.
 *
 * Copyright (c) 2014-2021 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2021, HGST, Inc., All rights reserved.
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
#include "testing.h"
#include "ioctl.h"

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

static int ssdfs_ioctl_do_testing(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_testing_environment env;

	if (copy_from_user(&env, arg, sizeof(env)))
		return -EFAULT;

	return ssdfs_do_testing(fsi, &env);
}

static int ssdfs_ioctl_create_snapshot(struct file *file, void __user *arg)
{
//	struct inode *inode = file_inode(file);
//	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_info *info = NULL;
	int err = 0;

	info = kzalloc(sizeof(struct ssdfs_snapshot_info), GFP_KERNEL);
	if (!info) {
		SSDFS_ERR("fail to allocate snaphot info\n");
		return -ENOMEM;
	}

	if (copy_from_user(info, arg, sizeof(struct ssdfs_snapshot_info))) {
		err = -EFAULT;
		goto finish_create_snapshot;
	}

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", info->name);
	SSDFS_ERR("UUID %pUb, ", info->uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  info->mode, info->type, info->expiration,
		  info->frequency, info->existing_snapshots,
		  info->time_range.day,
		  info->time_range.month,
		  info->time_range.year);

finish_create_snapshot:
	if (!info)
		kfree(info);

	return err;
}

static int ssdfs_ioctl_list_snapshots(struct file *file, void __user *arg)
{
//	struct inode *inode = file_inode(file);
//	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_info *info = NULL;
	int err = 0;

	info = kzalloc(sizeof(struct ssdfs_snapshot_info), GFP_KERNEL);
	if (!info) {
		SSDFS_ERR("fail to allocate snaphot info\n");
		return -ENOMEM;
	}

	if (copy_from_user(info, arg, sizeof(struct ssdfs_snapshot_info))) {
		err = -EFAULT;
		goto finish_list_snapshots;
	}

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", info->name);
	SSDFS_ERR("UUID %pUb, ", info->uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  info->mode, info->type, info->expiration,
		  info->frequency, info->existing_snapshots,
		  info->time_range.day,
		  info->time_range.month,
		  info->time_range.year);

finish_list_snapshots:
	if (!info)
		kfree(info);

	return err;
}

static int ssdfs_ioctl_modify_snapshot(struct file *file, void __user *arg)
{
//	struct inode *inode = file_inode(file);
//	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_info *info = NULL;
	int err = 0;

	info = kzalloc(sizeof(struct ssdfs_snapshot_info), GFP_KERNEL);
	if (!info) {
		SSDFS_ERR("fail to allocate snaphot info\n");
		return -ENOMEM;
	}

	if (copy_from_user(info, arg, sizeof(struct ssdfs_snapshot_info))) {
		err = -EFAULT;
		goto finish_modify_snapshot;
	}

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", info->name);
	SSDFS_ERR("UUID %pUb, ", info->uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  info->mode, info->type, info->expiration,
		  info->frequency, info->existing_snapshots,
		  info->time_range.day,
		  info->time_range.month,
		  info->time_range.year);

finish_modify_snapshot:
	if (!info)
		kfree(info);

	return err;
}

static int ssdfs_ioctl_remove_snapshot(struct file *file, void __user *arg)
{
//	struct inode *inode = file_inode(file);
//	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_info *info = NULL;
	int err = 0;

	info = kzalloc(sizeof(struct ssdfs_snapshot_info), GFP_KERNEL);
	if (!info) {
		SSDFS_ERR("fail to allocate snaphot info\n");
		return -ENOMEM;
	}

	if (copy_from_user(info, arg, sizeof(struct ssdfs_snapshot_info))) {
		err = -EFAULT;
		goto finish_remove_snapshot;
	}

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", info->name);
	SSDFS_ERR("UUID %pUb, ", info->uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  info->mode, info->type, info->expiration,
		  info->frequency, info->existing_snapshots,
		  info->time_range.day,
		  info->time_range.month,
		  info->time_range.year);

finish_remove_snapshot:
	if (!info)
		kfree(info);

	return err;
}

static int ssdfs_ioctl_remove_range(struct file *file, void __user *arg)
{
//	struct inode *inode = file_inode(file);
//	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_info *info = NULL;
	int err = 0;

	info = kzalloc(sizeof(struct ssdfs_snapshot_info), GFP_KERNEL);
	if (!info) {
		SSDFS_ERR("fail to allocate snaphot info\n");
		return -ENOMEM;
	}

	if (copy_from_user(info, arg, sizeof(struct ssdfs_snapshot_info))) {
		err = -EFAULT;
		goto finish_remove_range;
	}

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", info->name);
	SSDFS_ERR("UUID %pUb, ", info->uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  info->mode, info->type, info->expiration,
		  info->frequency, info->existing_snapshots,
		  info->time_range.day,
		  info->time_range.month,
		  info->time_range.year);

finish_remove_range:
	if (!info)
		kfree(info);

	return err;
}

static int ssdfs_ioctl_show_snapshot_details(struct file *file,
					     void __user *arg)
{
//	struct inode *inode = file_inode(file);
//	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_info *info = NULL;
	int err = 0;

	info = kzalloc(sizeof(struct ssdfs_snapshot_info), GFP_KERNEL);
	if (!info) {
		SSDFS_ERR("fail to allocate snaphot info\n");
		return -ENOMEM;
	}

	if (copy_from_user(info, arg, sizeof(struct ssdfs_snapshot_info))) {
		err = -EFAULT;
		goto finish_show_snapshot_details;
	}

/* TODO: implement */
	err = -EOPNOTSUPP;

	SSDFS_ERR("SNAPSHOT INFO: ");
	SSDFS_ERR("name %s, ", info->name);
	SSDFS_ERR("UUID %pUb, ", info->uuid);
	SSDFS_ERR("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, existing_snapshots %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  info->mode, info->type, info->expiration,
		  info->frequency, info->existing_snapshots,
		  info->time_range.day,
		  info->time_range.month,
		  info->time_range.year);

finish_show_snapshot_details:
	if (!info)
		kfree(info);

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
	case SSDFS_IOC_DO_TESTING:
		return ssdfs_ioctl_do_testing(file, argp);
	case SSDFS_IOC_CREATE_SNAPSHOT:
		return ssdfs_ioctl_create_snapshot(file, argp);
	case SSDFS_IOC_LIST_SNAPSHOTS:
		return ssdfs_ioctl_list_snapshots(file, argp);
	case SSDFS_IOC_MODIFY_SNAPSHOT:
		return ssdfs_ioctl_modify_snapshot(file, argp);
	case SSDFS_IOC_REMOVE_SNAPSHOT:
		return ssdfs_ioctl_remove_snapshot(file, argp);
	case SSDFS_IOC_REMOVE_RANGE:
		return ssdfs_ioctl_remove_range(file, argp);
	case SSDFS_IOC_SHOW_DETAILS:
		return ssdfs_ioctl_show_snapshot_details(file, argp);
	}

	return -ENOTTY;
}
