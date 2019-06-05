//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 *  SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dir.c - folder operations.
 *
 * Copyright (c) 2019 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include "ssdfs.h"

static int __ssdfs_create(struct inode *dir, struct dentry *dentry,
			  struct inode *inode, const char *dest, long destlen)
{
	/* TODO: implement core functionality of ssdfs_create() */
	SSDFS_WARN("TODO: implement __ssdfs_create()\n");
	return -ENOMEM;

	SSDFS_DBG("Created ino %lu with mode %o, nlink %d, nrpages %ld\n",
		  (unsigned long)inode->i_ino, inode->i_mode,
		  inode->i_nlink, inode->i_mapping->nrpages);

	d_instantiate(dentry, inode);

	return 0;
}

/*
 * The ssdfs_create() is called by the open(2) and
 * creat(2) system calls.
 */
static int ssdfs_create(struct inode *dir, struct dentry *dentry,
			umode_t mode, bool excl)
{
	struct inode *inode;
	int err;

	SSDFS_DBG("dir %lu, mode %o\n", (unsigned long)dir->i_ino, mode);

	inode = ssdfs_new_inode(dir, mode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto failed_create;
	}

	/*err = ssdfs_init_inode_security(inode, dir, &dentry->d_name);
	if (err)
		goto out_unlock;*/

	/* TODO: implement core functionality of ssdfs_create() */
	return __ssdfs_create(dir, dentry, inode, NULL, 0);

failed_create:
	return err;
}

static ino_t ssdfs_inode_by_name(struct inode *dir, const struct qstr *qstr)
{
	/* TODO: implement ssdfs_inode_by_name() */
	SSDFS_WARN("TODO: implement ssdfs_inode_by_name()\n");
	return 0;
}

/*
 * The ssdfs_lookup() is called when the VFS needs
 * to look up an inode in a parent directory.
 */
static struct inode *ssdfs_lookup(struct inode *dir, struct dentry *target,
				  unsigned int flags)
{
	struct inode *inode;
	ino_t ino;

	SSDFS_DBG("dir %lu, flags %#u\n", (unsigned long)dir->i_ino, flags);

	if (target->d_name.len > SSDFS_MAX_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = ssdfs_inode_by_name(dir, &target->d_name);

	inode = ino ? ssdfs_iget(dir->i_sb, ino) : NULL;
	return d_splice_alias(inode, target);
}

/*
 * The ssdfs_mknod() is called by the mknod(2) system call
 * to create a device (char, block) inode or a named pipe
 * (FIFO) or socket.
 */
static int ssdfs_mknod(struct inode *dir, struct dentry *dentry,
			umode_t mode, dev_t rdev)
{
	struct inode *inode;

	SSDFS_DBG("dir %lu, mode %o, rdev %#u\n",
		  (unsigned long)dir->i_ino, mode, rdev);

	if (dentry->d_name.len > SSDFS_MAX_NAME_LEN)
		return -ENAMETOOLONG;

	if (!new_valid_dev(rdev))
		return -EINVAL;

	inode = ssdfs_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	init_special_inode(inode, mode, rdev);

	return __ssdfs_create(dir, dentry, inode, NULL, 0);
}

/*
 * Create symlink.
 * The ssdfs_symlink() is called by the symlink(2) system call.
 */
static int ssdfs_symlink(struct inode *dir, struct dentry *dentry,
			 const char *target)
{
	struct inode *inode;
	size_t target_len = strlen(target) + 1;

	SSDFS_DBG("dir %lu, target_len %zu\n",
		  (unsigned long)dir->i_ino, target_len);

	if (target_len > dir->i_sb->s_blocksize)
		return -ENAMETOOLONG;

	inode = ssdfs_new_inode(dir, S_IFLNK | S_IRWXUGO);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	return __ssdfs_create(dir, dentry, inode, target, target_len);
}

/*
 * Create hardlink.
 * The ssdfs_link() is called by the link(2) system call.
 */
static int ssdfs_link(struct dentry *old_dentry, struct inode *dir,
			struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;

	SSDFS_DBG("dir %lu, inode %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);

	if (inode->i_nlink >= SSDFS_LINK_MAX)
		return -EMLINK;

	if (!S_ISREG(inode->i_mode))
		return -EPERM;

	inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	inode_inc_link_count(inode);
	ihold(inode);

	return __ssdfs_create(dir, dentry, inode, NULL, 0);
}

/*
 * Create subdirectory.
 * The ssdfs_mkdir() is called by the mkdir(2) system call.
 */
static int ssdfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;

	SSDFS_DBG("dir %lu, mode %o\n",
		  (unsigned long)dir->i_ino, mode);

	if (dentry->d_name.len > SSDFS_MAX_NAME_LEN)
		return -ENAMETOOLONG;

	inode = ssdfs_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	return __ssdfs_create(dir, dentry, inode, NULL, 0);
}

static int ssdfs_do_unlink(struct inode *dir, struct dentry *dentry)
{
	/* TODO: implement ssdfs_do_unlink() */
	SSDFS_WARN("TODO: implement ssdfs_do_unlink()\n");
	return -ENOMEM;
}

/*
 * Delete inode.
 * The ssdfs_unlink() is called by the unlink(2) system call.
 */
static int ssdfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int err;

	SSDFS_DBG("dir %lu, inode %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);

	err = ssdfs_do_unlink(dir, dentry);
	if (!err) {
		mark_inode_dirty(dir);
		mark_inode_dirty(inode);
		inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	}

	return err;
}

static inline bool logfs_empty_dir(struct inode *dir)
{
	/* TODO: implement logfs_empty_dir() */
	SSDFS_WARN("TODO: implement logfs_empty_dir()\n");
	return false;
}

/*
 * Delete subdirectory.
 * The ssdfs_rmdir() is called by the rmdir(2) system call.
 */
static int ssdfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	SSDFS_DBG("dir %lu, subdir %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);

	if (!ssdfs_empty_dir(inode))
		return -ENOTEMPTY;

	return ssdfs_unlink(dir, dentry);
}

/*
 * Target dentry exists.
 */
static int ssdfs_rename_target(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry)
{
	/* TODO: implement ssdfs_rename_target() */
	SSDFS_WARN("TODO: implement ssdfs_rename_target()\n");
	return -ENOMEM;
}

/*
 * Cross-directory rename, target does not exist.
 */
static int ssdfs_cross_rename(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry)
{
	/* TODO: implement ssdfs_cross_rename() */
	SSDFS_WARN("TODO: implement ssdfs_cross_rename()\n");
	return -ENOMEM;
}

/*
 * The ssdfs_rename() is called by the rename(2) system call
 * to rename the object to have the parent and name given by
 * the second inode and dentry.
 */
static int ssdfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry)
{
	SSDFS_DBG("old_dir %lu, old_inode %lu, new_dir %lu\n",
		  (unsigned long)old_dir->i_ino,
		  (unsigned long)old_dentry->d_inode->i_ino,
		  (unsigned long)new_dir->i_ino);

	if (new_dentry->d_inode)
		return ssdfs_rename_target(old_dir, old_dentry,
					   new_dir, new_dentry);
	return ssdfs_cross_rename(old_dir, old_dentry, new_dir, new_dentry);
}

/*
 * The ssdfs_readdir() is called when the VFS needs
 * to read the directory contents.
 */
static int ssdfs_readdir(struct file *file, struct dir_context *ctx)
{
	/* TODO: implement ssdfs_readdir() */
	SSDFS_WARN("TODO: implement ssdfs_readdir()\n");
	return -EIO;
}

const struct inode_operations ssdfs_dir_inode_operations = {
	.create		= ssdfs_create,
	.lookup		= ssdfs_lookup,
	.link		= ssdfs_link,
	.unlink		= ssdfs_unlink,
	.symlink	= ssdfs_symlink,
	.mkdir		= ssdfs_mkdir,
	.rmdir		= ssdfs_rmdir,
	.mknod		= ssdfs_mknod,
	.rename		= ssdfs_rename,
	.setattr	= ssdfs_setattr,
/*	.setxattr	= ssdfs_setxattr,
	.getxattr	= ssdfs_getxattr,
	.listxattr	= ssdfs_listxattr,
	.removexattr	= generic_removexattr,*/
/*	.get_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,*/
};

const struct file_operations ssdfs_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= ssdfs_readdir,
	.unlocked_ioctl	= ssdfs_ioctl,
	.fsync		= ssdfs_fsync,
	.llseek		= generic_file_llseek,
};
