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

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "xattr.h"
#include "acl.h"

#include <trace/events/ssdfs.h>

int ssdfs_inode_by_name(struct inode *dir,
			const struct qstr *child,
			ino_t *ino)
{
	struct ssdfs_inode_info *ii = SSDFS_I(dir);
	struct ssdfs_btree_search *search;
	struct ssdfs_dir_entry *raw_dentry;
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);
	int private_flags;
	int err = 0;

	SSDFS_DBG("dir_ino %lu, target_name %s\n",
		  (unsigned long)dir->i_ino,
		  child->name);

	*ino = 0;
	private_flags = atomic_read(&ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		down_read(&ii->lock);

		if (!ii->dentries_tree) {
			err = -ERANGE;
			SSDFS_WARN("dentries tree absent!!!\n");
			goto finish_search_dentry;
		}

		search = ssdfs_btree_search_alloc();
		if (!search) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate btree search object\n");
			goto finish_search_dentry;
		}

		ssdfs_btree_search_init(search);

		err = ssdfs_dentries_tree_find(ii->dentries_tree,
						child->name,
						child->len,
						search);
		if (err == -ENODATA) {
			err = -ENOENT;
			SSDFS_DBG("dir %lu hasn't child %s\n",
				  (unsigned long)dir->i_ino,
				  child->name);
			goto dentry_is_not_available;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the dentry: "
				  "dir %lu, child %s\n",
				  (unsigned long)dir->i_ino,
				  child->name);
			goto dentry_is_not_available;
		}

		if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
			err = -ERANGE;
			SSDFS_ERR("invalid result's state %#x\n",
				  search->result.state);
			goto dentry_is_not_available;
		}

		switch (search->result.buf_state) {
		case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
			/* expected state */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid buffer state %#x\n");
			goto dentry_is_not_available;
		}

		if (!search->result.buf) {
			err = -ERANGE;
			SSDFS_ERR("buffer is absent\n");
			goto dentry_is_not_available;
		}

		if (search->result.buf_size < dentry_size) {
			err = -ERANGE;
			SSDFS_ERR("buf_size %zu < dentry_size %zu\n",
				  search->result.buf_size,
				  dentry_size);
			goto dentry_is_not_available;
		}

		raw_dentry = (struct ssdfs_dir_entry *)search->result.buf;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(le64_to_cpu(raw_dentry->ino) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		*ino = (ino_t)le64_to_cpu(raw_dentry->ino);

dentry_is_not_available:
		ssdfs_btree_search_free(search);

finish_search_dentry:
		up_read(&ii->lock);
	} else {
		err = -ENOENT;
		SSDFS_DBG("dentries tree is absent: "
			  "ino %lu\n",
			  (unsigned long)dir->i_ino);
	}

	return err;
}

/*
 * The ssdfs_lookup() is called when the VFS needs
 * to look up an inode in a parent directory.
 */
static struct dentry *ssdfs_lookup(struct inode *dir, struct dentry *target,
				  unsigned int flags)
{
	struct inode *inode = NULL;
	ino_t ino;
	int err;

	SSDFS_DBG("dir %lu, flags %#x\n", (unsigned long)dir->i_ino, flags);

	if (target->d_name.len > SSDFS_MAX_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	err = ssdfs_inode_by_name(dir, &target->d_name, &ino);
	if (err == -ENOENT) {
		err = 0;
		ino = 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the inode: "
			  "err %d\n",
			  err);
		return ERR_PTR(err);
	}

	if (ino) {
		inode = ssdfs_iget(dir->i_sb, ino);
		if (inode == ERR_PTR(-ESTALE)) {
			SSDFS_ERR("deleted inode referenced: %lu\n",
				  (unsigned long)ino);
			return ERR_PTR(-EIO);
		}
	}

	return d_splice_alias(inode, target);
}

static int ssdfs_add_link(struct inode *dir, struct dentry *dentry,
			  struct inode *inode)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(dir->i_sb);
	struct ssdfs_inode_info *dir_ii = SSDFS_I(dir);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_btree_search *search;
	int private_flags;
	int err = 0;

	SSDFS_DBG("Created ino %lu with mode %o, nlink %d, nrpages %ld\n",
		  (unsigned long)inode->i_ino, inode->i_mode,
		  inode->i_nlink, inode->i_mapping->nrpages);

	private_flags = atomic_read(&dir_ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		down_read(&dir->lock);

		if (!dir_ii->dentries_tree) {
			err = -ERANGE;
			SSDFS_WARN("dentries tree absent!!!\n");
			goto finish_add_link;
		}
	} else {
		down_write(&dir_ii->lock);

		if (dir_ii->dentries_tree) {
			err = -ERANGE;
			SSDFS_WARN("dentries tree exists unexpectedly!!!\n");
			goto finish_create_dentries_tree;
		} else {
			err = ssdfs_dentries_tree_create(fsi, dir_ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to create the dentries tree: "
					  "ino %lu, err %d\n",
					  dir->i_ino, err);
				goto finish_create_dentries_tree;
			}

			atomic_or(SSDFS_INODE_HAS_DENTRIES_BTREE,
				  &dir_ii->private_flags);
		}

finish_create_dentries_tree:
		downgrade_write(&dir_ii->lock);

		if (unlikely(err))
			goto finish_add_link;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_add_link;
	}

	ssdfs_btree_search_init(search);

	err = ssdfs_dentries_tree_add(dir_ii->dentries_tree,
				      &dentry->d_name,
				      ii, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add the dentry: "
			  "ino %lu, err %d\n",
			  inode->i_ino, err);
	} else {
		dir->i_mtime = dir->i_ctime = current_time(dir);
		mark_inode_dirty(dir);
	}

	ssdfs_btree_search_free(search);

finish_add_link:
	up_read(&dir_ii->lock);

	return err;
}

static int ssdfs_add_nondir(struct inode *dir, struct dentry *dentry,
			    struct inode *inode)
{
	int err;

	SSDFS_DBG("Created ino %lu with mode %o, nlink %d, nrpages %ld\n",
		  (unsigned long)inode->i_ino, inode->i_mode,
		  inode->i_nlink, inode->i_mapping->nrpages);

	err = ssdfs_add_link(dir, dentry, inode);
	if (err) {
		inode_dec_link_count(inode);
		iget_failed(inode);
		return err;
	}

	unlock_new_inode(inode);
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

	inode = ssdfs_new_inode(dir, mode, dentry->d_name);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto failed_create;
	}

	mark_inode_dirty(inode);
	return ssdfs_add_nondir(dir, dentry, inode);

failed_create:
	return err;
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

	SSDFS_DBG("dir %lu, mode %o, rdev %#x\n",
		  (unsigned long)dir->i_ino, mode, rdev);

	if (dentry->d_name.len > SSDFS_MAX_NAME_LEN)
		return -ENAMETOOLONG;

	inode = ssdfs_new_inode(dir, mode, dentry->d_name);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	init_special_inode(inode, mode, rdev);

	mark_inode_dirty(inode);
	return ssdfs_add_nondir(dir, dentry, inode);
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
	size_t raw_inode_size;
	size_t inline_len;
	int err = 0;

	SSDFS_DBG("dir %lu, target_len %zu\n",
		  (unsigned long)dir->i_ino, target_len);

	if (target_len > dir->i_sb->s_blocksize)
		return -ENAMETOOLONG;

	down_read(&fsi->volume_sem);
	raw_inode_size = le16_to_cpu(fsi->vs->inodes_btree.desc.item_size);
	up_read(&fsi->volume_sem);

	inline_len = offsetof(struct ssdfs_inode, internal);

	if (raw_inode_size <= inline_len) {
		SSDFS_ERR("invalid raw inode size %zu\n",
			  raw_inode_size);
		return -EFAULT;
	}

	inline_len = raw_inode_size - inline_len;

	inode = ssdfs_new_inode(dir, S_IFLNK | S_IRWXUGO, dentry->d_name);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	if (target_len > inline_len) {
		/* slow symlink */
		inode_nohighmem(inode);

		err = page_symlink(inode, target, target_len);
		if (err)
			goto out_fail;
	} else {
		/* fast symlink */
		down_write(&SSDFS_I(inode)->lock);
		inode->i_link = (char *)SSDFS_I(inode)->raw_inode.internal;
		memcpy(inode->i_link, target, target_len);
		inode->i_size = target_len - 1;
		atomic_or(SSDFS_INODE_HAS_INLINE_FILE,
			  &SSDFS_I(inode)->private_flags);
		up_write(&SSDFS_I(inode)->lock);
	}

	mark_inode_dirty(inode);
	return ssdfs_add_nondir(dir, dentry, inode);

out_fail:
	inode_dec_link_count(inode);
	iget_failed(inode);
	return err;
}

/*
 * Create hardlink.
 * The ssdfs_link() is called by the link(2) system call.
 */
static int ssdfs_link(struct dentry *old_dentry, struct inode *dir,
			struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);
	int err;

	SSDFS_DBG("dir %lu, inode %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);

	if (inode->i_nlink >= SSDFS_LINK_MAX)
		return -EMLINK;

	if (!S_ISREG(inode->i_mode))
		return -EPERM;

	inode->i_ctime = current_time(inode);
	inode_inc_link_count(inode);
	ihold(inode);

	err = ssdfs_add_link(dir, dentry, inode);
	if (err) {
		inode_dec_link_count(inode);
		iput(inode);
		return err;
	}

	d_instantiate(dentry, inode);
	return 0;
}

/*
 * Set the first fragment of directory.
 */
static int ssdfs_make_empty(struct inode *inode, struct inode *parent)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_inode_info *parent_ii = SSDFS_I(parent);
	struct ssdfs_btree_search *search;
	int private_flags;
	struct qstr dot = QSTR_INIT(".", 1);
	struct qstr dotdot = QSTR_INIT("..", 2);
	int err = 0;

	SSDFS_DBG("Created ino %lu with mode %o, nlink %d, nrpages %ld\n",
		  (unsigned long)inode->i_ino, inode->i_mode,
		  inode->i_nlink, inode->i_mapping->nrpages);

	private_flags = atomic_read(&ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		down_read(&inode->lock);

		if (!ii->dentries_tree) {
			err = -ERANGE;
			SSDFS_WARN("dentries tree absent!!!\n");
			goto finish_make_empty_dir;
		}
	} else {
		down_write(&ii->lock);

		if (ii->dentries_tree) {
			err = -ERANGE;
			SSDFS_WARN("dentries tree exists unexpectedly!!!\n");
			goto finish_create_dentries_tree;
		} else {
			err = ssdfs_dentries_tree_create(fsi, ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to create the dentries tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				goto finish_create_dentries_tree;
			}

			atomic_or(SSDFS_INODE_HAS_DENTRIES_BTREE,
				  &ii->private_flags);
		}

finish_create_dentries_tree:
		downgrade_write(&ii->lock);

		if (unlikely(err))
			goto finish_make_empty_dir;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_make_empty_dir;
	}

	ssdfs_btree_search_init(search);

	err = ssdfs_dentries_tree_add(ii->dentries_tree,
				      &dot, ii, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add dentry: "
			  "ino %lu, err %d\n",
			  inode->i_ino, err);
		goto free_search_object;
	}

	err = ssdfs_dentries_tree_add(ii->dentries_tree,
				      &dotdot, parent_ii,
				      search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add dentry: "
			  "ino %lu, err %d\n",
			  parent->i_ino, err);
		goto free_search_object;
	}

free_search_object:
	ssdfs_btree_search_free(search);

finish_make_empty_dir:
	up_read(&ii->lock);

	return err;
}

/*
 * Create subdirectory.
 * The ssdfs_mkdir() is called by the mkdir(2) system call.
 */
static int ssdfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	int err = 0;

	SSDFS_DBG("dir %lu, mode %o\n",
		  (unsigned long)dir->i_ino, mode);

	if (dentry->d_name.len > SSDFS_MAX_NAME_LEN)
		return -ENAMETOOLONG;

	inode_inc_link_count(dir);

	inode = ssdfs_new_inode(dir, S_IFDIR | mode, &dentry->d_name);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_dir;

	inode_inc_link_count(inode);

	err = ssdfs_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = ssdfs_add_link(dir, dentry, inode);
	if (err)
		goto out_fail;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);
	return 0;

out_fail:
	inode_dec_link_count(inode);
	inode_dec_link_count(inode);
	unlock_new_inode(inode);
	iput(inode);
out_dir:
	inode_dec_link_count(dir);
	return err;
}

/*
 * Delete inode.
 * The ssdfs_unlink() is called by the unlink(2) system call.
 */
static int ssdfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct ssdfs_inode_info *ii = SSDFS_I(dir);
	struct inode *inode = d_inode(dentry);
	struct ssdfs_btree_search *search;
	int private_flags;
	u64 name_hash;
	int err = 0;

	SSDFS_DBG("dir %lu, inode %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);

	trace_ssdfs_unlink_enter(dir, dentry);

	private_flags = atomic_read(&ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		down_read(&ii->lock);

		if (!ii->dentries_tree) {
			err = -ERANGE;
			SSDFS_WARN("dentries tree absent!!!\n");
			goto finish_delete_dentry;
		}

		search = ssdfs_btree_search_alloc();
		if (!search) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate btree search object\n");
			goto finish_delete_dentry;
		}

		ssdfs_btree_search_init(search);

		name_hash = ssdfs_generate_name_hash(&dentry->d_name);
		if (name_hash >= U64_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid name hash\n");
			goto dentry_is_not_available;
		}

		err = ssdfs_dentries_tree_delete(ii->dentries_tree,
						 name_hash,
						 inode->i_ino,
						 search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to delete the dentry: "
				  "name_hash %llu, ino %lu, err %d\n",
				  name_hash, inode->i_ino, err);
			goto dentry_is_not_available;
		}

dentry_is_not_available:
		ssdfs_btree_search_free(search);

finish_delete_dentry:
		up_read(&ii->lock);

		if (unlikely(err))
			goto finish_unlink;
	} else {
		err = -ENOENT;
		SSDFS_ERR("dentries tree is absent\n");
		goto finish_unlink;
	}

	mark_inode_dirty(dir);
	mark_inode_dirty(inode);
	inode->i_ctime = dir->i_ctime = dir->i_mtime = current_time(dir);
	inode_dec_link_count(inode);

finish_unlink:
	trace_ssdfs_unlink_exit(inode, err);
	return err;
}

static inline bool ssdfs_empty_dir(struct inode *dir)
{
	struct ssdfs_inode_info *ii = SSDFS_I(dir);
	bool is_empty = flase;
	int private_flags;
	u64 dentries_count;
	u64 threshold = 2; /* . and .. */

	private_flags = atomic_read(&ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		down_read(&ii->lock);

		if (!ii->dentries_tree) {
			SSDFS_WARN("dentries tree absent!!!\n");
			is_empty = true;
		} else {
			dentries_count =
			    atomic64_read(&ii->dentries_tree->dentries_count);

			if (dentries_count > threshold) {
				/* not empty folder */
				is_empty = false;
			} else if (dentries_count < threshold) {
				SSDFS_WARN("unexpected dentries count %llu\n",
					   dentries_count);
				is_empty = true;
			} else
				is_empty = true;
		}

		up_read(&ii->lock);
	} else {
		/* dentries tree is absent */
		is_empty = true;
	}

	return is_empty;
}

/*
 * Delete subdirectory.
 * The ssdfs_rmdir() is called by the rmdir(2) system call.
 */
static int ssdfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	int err = -ENOTEMPTY;

	SSDFS_DBG("dir %lu, subdir %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);

	if (ssdfs_empty_dir(inode)) {
		err = ssdfs_unlink(dir, dentry);
		if (!err) {
			inode->i_size = 0;
			inode_dec_link_count(inode);
			inode_dec_link_count(dir);
		}
	}

	return err;
}

static void lock_4_inodes(struct inode *inode1, struct inode *inode2,
			  struct inode *inode3, struct inode *inode4)
{
	down_write(&SSDFS_I(inode1)->lock);
	if (inode2 != inode1)
		down_write(&SSDFS_I(inode2)->lock);
	if (inode3)
		down_write(&SSDFS_I(inode3)->lock);
	if (inode4)
		down_write(&SSDFS_I(inode4)->lock);
}

static void unlock_4_inodes(struct inode *inode1, struct inode *inode2,
			    struct inode *inode3, struct inode *inode4)
{
	if (inode4)
		up_write(&SSDFS_I(inode4)->lock);
	if (inode3)
		up_write(&SSDFS_I(inode3)->lock);
	if (inode1 != inode2)
		up_write(&SSDFS_I(inode2)->lock);
	up_write(&SSDFS_I(inode1)->lock);
}

/*
 * Regular rename.
 */
static int ssdfs_rename_target(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry,
				unsigned int flags)
{
	struct ssdfs_inode_info *old_dir_ii = SSDFS_I(old_dir);
	struct ssdfs_inode_info *new_dir_ii = SSDFS_I(new_dir);
	struct inode *old_inode = d_inode(old_dentry);
	struct ssdfs_inode_info *old_ii = SSDFS_I(old_inode);
	struct inode *new_inode = d_inode(new_dentry);
	struct ssdfs_btree_search *search;
	struct qstr dotdot = QSTR_INIT("..", 2);
	bool is_dir = S_ISDIR(old_inode->i_mode);
	bool move = (new_dir != old_dir);
	bool unlink = new_inode == NULL;
	ino_t old_ino, old_parent_ino, new_ino;
	struct timespec time;
	u64 name_hash;
	int err = -ENOENT;

	SSDFS_DBG("old_dir %lu, old_inode %lu, new_dir %lu\n",
		  (unsigned long)old_dir->i_ino,
		  (unsigned long)old_inode->i_ino,
		  (unsigned long)new_dir->i_ino);

	err = ssdfs_inode_by_name(old_dir, &old_dentry->d_name, &old_ino);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find old dentry: err %d\n", err);
		goto out;
	} else if (old_ino != old_inode->i_ino) {
		err = -ERANGE;
		SSDFS_ERR("invalid ino: found ino %lu != requested ino %lu\n",
			  old_ino, old_inode->i_ino);
		goto out;
	}

	if (S_ISDIR(old_inode->i_mode)) {
		err = ssdfs_inode_by_name(old_inode, &dotdot, &old_parent_ino);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find parent dentry: err %d\n", err);
			goto out;
		} else if (old_parent_ino != old_dir->i_ino) {
			err = -ERANGE;
			SSDFS_ERR("invalid ino: "
				  "found ino %lu != requested ino %lu\n",
				  old_parent_ino, old_dir->i_ino);
			goto out;
		}
	}

	if (!old_dir_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("old dir hasn't dentries tree\n");
		goto out;
	}

	if (!new_dir_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("new dir hasn't dentries tree\n");
		goto out;
	}

	if (S_ISDIR(old_inode->i_mode) && !old_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("old inode hasn't dentries tree\n");
		goto out;
	}

	if (flags & RENAME_WHITEOUT) {
		/* TODO: implement support */
		SSDFS_WARN("TODO: implement support of RENAME_WHITEOUT\n");
		/*err = -EOPNOTSUPP;
		goto out;*/
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto out;
	}

	ssdfs_btree_search_init(search);

	lock_4_inodes(old_dir, new_dir, old_inode, new_inode);

	if (new_inode) {
		err = -ENOTEMPTY;
		if (is_dir && !ssdfs_empty_dir(new_inode))
			goto finish_target_rename;

		err = ssdfs_inode_by_name(new_dir, &new_dentry->d_name,
					  &new_ino);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find new dentry: err %d\n", err);
			goto finish_target_rename;
		} else if (new_ino != new_inode->i_ino) {
			err = -ERANGE;
			SSDFS_ERR("invalid ino: "
				  "found ino %lu != requested ino %lu\n",
				  new_ino, new_inode->i_ino);
			goto finish_target_rename;
		}

		name_hash = ssdfs_generate_name_hash(&new_dentry->d_name);

		err = ssdfs_dentries_tree_change(new_dir_ii->dentries_tree,
						 name_hash,
						 new_inode->i_ino,
						 &old_dentry->d_name,
						 old_ii,
						 search);
		if (unlikely(err)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"fail to update dentry: err %d\n",
					err);
			goto finish_target_rename;
		}
	} else {
		err = ssdfs_add_link(new_dir, new_dentry, old_inode);
		if (unlikely(err)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"fail to add the link: err %d\n",
					err);
			goto finish_target_rename;
		}
	}

	name_hash = ssdfs_generate_name_hash(&old_dentry->d_name);

	err = ssdfs_dentries_tree_delete(old_dir_ii->dentries_tree,
					 name_hash,
					 old_inode->i_ino,
					 search);
	if (unlikely(err)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"fail to delete the dentry: "
				"name_hash %llu, ino %lu, err %d\n",
				name_hash, old_inode->i_ino, err);
		goto finish_target_rename;
	}

	if (is_dir && move) {
		/* update ".." directory entry info of old dentry */
		name_hash = ssdfs_generate_name_hash(&dotdot);
		err = ssdfs_dentries_tree_change(old_ii->dentries_tree,
						 name_hash, old_dir->i_ino,
						 &dotdot, new_dir_ii,
						 search);
		if (unlikely(err)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"fail to update dentry: err %d\n",
					err);
			goto finish_target_rename;
		}
	}

	old_ii->parent_ino = new_dir->i_ino;

	/*
	 * Like most other Unix systems, set the @i_ctime for inodes on a
	 * rename.
	 */
	time = current_time(old_dir);
	old_inode->i_ctime = time;
	mark_inode_dirty(old_inode);

	/* We must adjust parent link count when renaming directories */
	if (is_dir) {
		if (move) {
			/*
			 * @old_dir loses a link because we are moving
			 * @old_inode to a different directory.
			 */
			inode_dec_link_count(old_dir);
			/*
			 * @new_dir only gains a link if we are not also
			 * overwriting an existing directory.
			 */
			if (!unlink)
				inode_inc_link_count(new_dir);
		} else {
			/*
			 * @old_inode is not moving to a different directory,
			 * but @old_dir still loses a link if we are
			 * overwriting an existing directory.
			 */
			if (unlink)
				inode_dec_link_count(old_dir);
		}
	}

	old_dir->i_mtime = old_dir->i_ctime = time;
	new_dir->i_mtime = new_dir->i_ctime = time;

	/*
	 * And finally, if we unlinked a direntry which happened to have the
	 * same name as the moved direntry, we have to decrement @i_nlink of
	 * the unlinked inode and change its ctime.
	 */
	if (unlink) {
		/*
		 * Directories cannot have hard-links, so if this is a
		 * directory, just clear @i_nlink.
		 */
		if (is_dir) {
			clear_nlink(new_inode);
			mark_inode_dirty(new_inode);
		} else
			inode_dec_link_count(new_inode);
		new_inode->i_ctime = time;
	}

finish_target_rename:
	unlock_4_inodes(old_dir, new_dir, old_inode, new_inode);
	ssdfs_btree_search_free(search);

out:
	return err;
}

/*
 * Cross-directory rename.
 */
static int ssdfs_cross_rename(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry)
{
	struct ssdfs_inode_info *old_dir_ii = SSDFS_I(old_dir);
	struct ssdfs_inode_info *new_dir_ii = SSDFS_I(new_dir);
	struct inode *old_inode = d_inode(old_dentry);
	struct ssdfs_inode_info *old_ii = SSDFS_I(old_inode);
	struct inode *new_inode = d_inode(new_dentry);
	struct ssdfs_inode_info *new_ii = SSDFS_I(new_inode);
	struct ssdfs_btree_search *search;
	struct qstr dotdot = QSTR_INIT("..", 2);
	ino_t old_ino, new_ino;
	struct timespec time;
	u64 name_hash;
	int err = -ENOENT;

	SSDFS_DBG("old_dir %lu, old_inode %lu, new_dir %lu\n",
		  (unsigned long)old_dir->i_ino,
		  (unsigned long)old_inode->i_ino,
		  (unsigned long)new_dir->i_ino);

	err = ssdfs_inode_by_name(old_dir, &old_dentry->d_name, &old_ino);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find old dentry: err %d\n", err);
		goto out;
	} else if (old_ino != old_inode->i_ino) {
		err = -ERANGE;
		SSDFS_ERR("invalid ino: found ino %lu != requested ino %lu\n",
			  old_ino, old_inode->i_ino);
		goto out;
	}

	err = ssdfs_inode_by_name(new_dir, &new_dentry->d_name, &new_ino);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find new dentry: err %d\n", err);
		goto out;
	} else if (new_ino != new_inode->i_ino) {
		err = -ERANGE;
		SSDFS_ERR("invalid ino: found ino %lu != requested ino %lu\n",
			  new_ino, new_inode->i_ino);
		goto out;
	}

	if (!old_dir_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("old dir hasn't dentries tree\n");
		goto out;
	}

	if (!new_dir_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("new dir hasn't dentries tree\n");
		goto out;
	}

	if (S_ISDIR(old_inode->i_mode) && !old_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("old inode hasn't dentries tree\n");
		goto out;
	}

	if (S_ISDIR(new_inode->i_mode) && !new_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("new inode hasn't dentries tree\n");
		goto out;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto out;
	}

	ssdfs_btree_search_init(search);
	name_hash = ssdfs_generate_name_hash(&dotdot);

	lock_4_inodes(old_dir, new_dir, old_inode, new_inode);

	/* update ".." directory entry info of old dentry */
	if (S_ISDIR(old_inode->i_mode)) {
		err = ssdfs_dentries_tree_change(old_ii->dentries_tree,
						 name_hash, old_dir->i_ino,
						 &dotdot, new_dir_ii,
						 search);
		if (unlikely(err)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"fail to update dentry: err %d\n",
					err);
			goto finish_cross_rename;
		}
	}

	/* update ".." directory entry info of new dentry */
	if (S_ISDIR(new_inode->i_mode)) {
		err = ssdfs_dentries_tree_change(new_ii->dentries_tree,
						 name_hash, new_dir->i_ino,
						 &dotdot, old_dir_ii,
						 search);
		if (unlikely(err)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"fail to update dentry: err %d\n",
					err);
			goto finish_cross_rename;
		}
	}

	/* update directory entry info of old dir inode */
	name_hash = ssdfs_generate_name_hash(&old_dentry->d_name);

	err = ssdfs_dentries_tree_change(old_dir_ii->dentries_tree,
					 name_hash, old_inode->i_ino,
					 &new_dentry->d_name, new_ii,
					 search);
	if (unlikely(err)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"fail to update dentry: err %d\n",
				err);
		goto finish_cross_rename;
	}

	/* update directory entry info of new dir inode */
	name_hash = ssdfs_generate_name_hash(&new_dentry->d_name);

	err = ssdfs_dentries_tree_change(new_dir_ii->dentries_tree,
					 name_hash, new_inode->i_ino,
					 &old_dentry->d_name, old_ii,
					 search);
	if (unlikely(err)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"fail to update dentry: err %d\n",
				err);
		goto finish_cross_rename;
	}

	old_ii->parent_ino = new_dir->i_ino;
	new_ii->parent_ino = old_dir->i_ino;

	time = current_time(old_dir);
	old_inode->i_ctime = time;
	new_inode->i_ctime = time;
	old_dir->i_mtime = old_dir->i_ctime = time;
	new_dir->i_mtime = new_dir->i_ctime = time;

	if (old_dir != new_dir) {
		if (S_ISDIR(old_inode->i_mode) &&
		    !S_ISDIR(new_inode->i_mode)) {
			inode_inc_link_count(new_dir);
			inode_dec_link_count(old_dir);
		}
		else if (!S_ISDIR(old_inode->i_mode) &&
			 S_ISDIR(new_inode->i_mode)) {
			inode_dec_link_count(new_dir);
			inode_inc_link_count(old_dir);
		}
	}

	mark_inode_dirty(old_inode);
	mark_inode_dirty(new_inode);

finish_cross_rename:
	unlock_4_inodes(old_dir, new_dir, old_inode, new_inode);
	ssdfs_btree_search_free(search);

out:
	return err;
}

/*
 * The ssdfs_rename() is called by the rename(2) system call
 * to rename the object to have the parent and name given by
 * the second inode and dentry.
 */
static int ssdfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
	SSDFS_DBG("old_dir %lu, old_inode %lu, new_dir %lu\n",
		  (unsigned long)old_dir->i_ino,
		  (unsigned long)old_dentry->d_inode->i_ino,
		  (unsigned long)new_dir->i_ino);

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;

	if (flags & RENAME_EXCHANGE) {
		return ssdfs_cross_rename(old_dir, old_dentry,
					  new_dir, new_dentry);
	}

	return ssdfs_rename_target(old_dir, old_dentry, new_dir, new_dentry,
				   flags);
}

/*
 * The ssdfs_readdir() is called when the VFS needs
 * to read the directory contents.
 */
static int ssdfs_readdir(struct file *file, struct dir_context *ctx)
{
	loff_t pos;

	/* TODO: implement */
	SSDFS_WARN("TODO: implement %s\n", __func__);

	if (ctx->pos < 0)
		return -EINVAL;

	if (!dir_emit_dots(file, ctx))
		return 0;

	/* TODO: temporary solution */
	if (ctx->pos >= 3)
		return 0;

	pos = ctx->pos - 2;
	BUG_ON(pos < 0);

	dir_emit(ctx, SSDFS_TEMP_FILE_NAME, strlen(SSDFS_TEMP_FILE_NAME) + 1,
		 SSDFS_TEMP_FILE_INO, DT_REG);
	ctx->pos += 1;

	return 0;
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
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ssdfs_listxattr,
	.removexattr	= generic_removexattr,
	.get_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,
};

const struct file_operations ssdfs_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= ssdfs_readdir,
	.unlocked_ioctl	= ssdfs_ioctl,
	.fsync		= ssdfs_fsync,
	.llseek		= generic_file_llseek,
};
