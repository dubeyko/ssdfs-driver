// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ioctl.c - IOCTL operations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 *
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot
 *                  Zvonimir Bandic
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/pagevec.h>
#include <linux/mount.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
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
	struct mnt_idmap *idmap = file_mnt_idmap(file);
	struct inode *inode = file_inode(file);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	unsigned int flags, oldflags;
	int err = 0;

	err = mnt_want_write_file(file);
	if (err)
		return err;

	if (!inode_owner_or_capable(idmap, inode))
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
	inode_set_ctime_to_ts(inode, current_time(inode));
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
	struct inode *inode = file_inode(file);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_request *snr = NULL;
	size_t info_size = sizeof(struct ssdfs_snapshot_info);
	int err = 0;

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_CREATE_SNAPSHOT;
	snr->ino = inode->i_ino;

	if (copy_from_user(&snr->info, arg, info_size)) {
		err = -EFAULT;
		ssdfs_snapshot_request_free(snr);
		goto finish_create_snapshot;
	}

	ssdfs_snapshot_reqs_queue_add_tail(&fsi->snapshots.reqs_queue, snr);

finish_create_snapshot:
	return err;
}

static int ssdfs_ioctl_list_snapshots(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_request *snr = NULL;
	size_t info_size = sizeof(struct ssdfs_snapshot_info);
	int err = 0;

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_LIST_SNAPSHOTS;
	snr->ino = inode->i_ino;

	if (copy_from_user(&snr->info, arg, info_size)) {
		err = -EFAULT;
		goto finish_list_snapshots;
	}

	err = ssdfs_execute_list_snapshots_request(&fsi->snapshots, snr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get the snapshots list: "
			  "err %d\n", err);
		goto finish_list_snapshots;
	}

	if (copy_to_user((struct ssdfs_snapshot_info __user *)arg,
			 &snr->info, info_size)) {
		err = -EFAULT;
		goto finish_list_snapshots;
	}

finish_list_snapshots:
	if (!snr)
		ssdfs_snapshot_request_free(snr);

	return err;
}

static int ssdfs_ioctl_modify_snapshot(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_request *snr = NULL;
	size_t info_size = sizeof(struct ssdfs_snapshot_info);
	int err = 0;

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_MODIFY_SNAPSHOT;
	snr->ino = inode->i_ino;

	if (copy_from_user(&snr->info, arg, info_size)) {
		err = -EFAULT;
		goto finish_modify_snapshot;
	}

	err = ssdfs_execute_modify_snapshot_request(fsi, snr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to modify snapshot: "
			  "err %d\n", err);
		goto finish_modify_snapshot;
	}

finish_modify_snapshot:
	if (!snr)
		ssdfs_snapshot_request_free(snr);

	return err;
}

static int ssdfs_ioctl_remove_snapshot(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_request *snr = NULL;
	size_t info_size = sizeof(struct ssdfs_snapshot_info);
	int err = 0;

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_REMOVE_SNAPSHOT;
	snr->ino = inode->i_ino;

	if (copy_from_user(&snr->info, arg, info_size)) {
		err = -EFAULT;
		goto finish_remove_snapshot;
	}

	err = ssdfs_execute_remove_snapshot_request(&fsi->snapshots, snr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete snapshot: "
			  "err %d\n", err);
		goto finish_remove_snapshot;
	}

finish_remove_snapshot:
	if (!snr)
		ssdfs_snapshot_request_free(snr);

	return err;
}

static int ssdfs_ioctl_remove_range(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_request *snr = NULL;
	size_t info_size = sizeof(struct ssdfs_snapshot_info);
	int err = 0;

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_REMOVE_RANGE;
	snr->ino = inode->i_ino;

	if (copy_from_user(&snr->info, arg, info_size)) {
		err = -EFAULT;
		goto finish_remove_range;
	}

	err = ssdfs_execute_remove_range_request(&fsi->snapshots, snr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to remove range of snapshots: "
			  "err %d\n", err);
		goto finish_remove_range;
	}

finish_remove_range:
	if (!snr)
		ssdfs_snapshot_request_free(snr);

	return err;
}

static int ssdfs_ioctl_show_snapshot_details(struct file *file,
					     void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_request *snr = NULL;
	size_t info_size = sizeof(struct ssdfs_snapshot_info);
	int err = 0;

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_SHOW_SNAPSHOT_DETAILS;
	snr->ino = inode->i_ino;

	if (copy_from_user(&snr->info, arg, info_size)) {
		err = -EFAULT;
		goto finish_show_snapshot_details;
	}

	err = ssdfs_execute_show_details_request(&fsi->snapshots, snr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to show snapshot's details: "
			  "err %d\n", err);
		goto finish_show_snapshot_details;
	}

	if (copy_to_user((struct ssdfs_snapshot_info __user *)arg,
			 &snr->info, info_size)) {
		err = -EFAULT;
		goto finish_show_snapshot_details;
	}

finish_show_snapshot_details:
	if (!snr)
		ssdfs_snapshot_request_free(snr);

	return err;
}

static int ssdfs_ioctl_list_snapshot_rules(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_snapshot_request *snr = NULL;
	size_t info_size = sizeof(struct ssdfs_snapshot_info);
	int err = 0;

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_LIST_SNAPSHOT_RULES;
	snr->ino = inode->i_ino;

	if (copy_from_user(&snr->info, arg, info_size)) {
		err = -EFAULT;
		goto finish_list_snapshot_rules;
	}

	err = ssdfs_execute_list_snapshot_rules_request(fsi, snr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get the snapshot rules list: "
			  "err %d\n", err);
		goto finish_list_snapshot_rules;
	}

	if (copy_to_user((struct ssdfs_snapshot_info __user *)arg,
			 &snr->info, info_size)) {
		err = -EFAULT;
		goto finish_list_snapshot_rules;
	}

finish_list_snapshot_rules:
	if (!snr)
		ssdfs_snapshot_request_free(snr);

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
	case SSDFS_IOC_LIST_SNAPSHOT_RULES:
		return ssdfs_ioctl_list_snapshot_rules(file, argp);
	}

	return -ENOTTY;
}
