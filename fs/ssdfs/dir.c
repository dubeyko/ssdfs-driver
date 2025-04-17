/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dir.c - folder operations.
 *
 * Copyright (c) 2019-2025 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/pagevec.h>
#include <linux/sched/signal.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "dentries_tree.h"
#include "shared_dictionary.h"
#include "xattr.h"
#include "acl.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_dir_folio_leaks;
atomic64_t ssdfs_dir_memory_leaks;
atomic64_t ssdfs_dir_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_dir_cache_leaks_increment(void *kaddr)
 * void ssdfs_dir_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_dir_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_dir_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_dir_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_dir_kfree(void *kaddr)
 * struct folio *ssdfs_dir_alloc_folio(gfp_t gfp_mask,
 *                                     unsigned int order)
 * struct folio *ssdfs_dir_add_batch_folio(struct folio_batch *batch,
 *                                         unsigned int order)
 * void ssdfs_dir_free_folio(struct folio *folio)
 * void ssdfs_dir_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(dir)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(dir)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_dir_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_dir_folio_leaks, 0);
	atomic64_set(&ssdfs_dir_memory_leaks, 0);
	atomic64_set(&ssdfs_dir_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_dir_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_dir_folio_leaks) != 0) {
		SSDFS_ERR("DIR: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_dir_folio_leaks));
	}

	if (atomic64_read(&ssdfs_dir_memory_leaks) != 0) {
		SSDFS_ERR("DIR: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dir_memory_leaks));
	}

	if (atomic64_read(&ssdfs_dir_cache_leaks) != 0) {
		SSDFS_ERR("DIR: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dir_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static unsigned char
ssdfs_filetype_table[SSDFS_FT_MAX] = {
	[SSDFS_FT_UNKNOWN]	= DT_UNKNOWN,
	[SSDFS_FT_REG_FILE]	= DT_REG,
	[SSDFS_FT_DIR]		= DT_DIR,
	[SSDFS_FT_CHRDEV]	= DT_CHR,
	[SSDFS_FT_BLKDEV]	= DT_BLK,
	[SSDFS_FT_FIFO]		= DT_FIFO,
	[SSDFS_FT_SOCK]		= DT_SOCK,
	[SSDFS_FT_SYMLINK]	= DT_LNK,
};

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

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rwsem_is_locked(&ii->lock));

	SSDFS_DBG("dir_ino %lu, target_name %s\n",
		  (unsigned long)dir->i_ino,
		  child->name);
#endif /* CONFIG_SSDFS_DEBUG */

	*ino = 0;
	private_flags = atomic_read(&ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES ||
	    private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
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
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("dir %lu hasn't child %s\n",
				  (unsigned long)dir->i_ino,
				  child->name);
#endif /* CONFIG_SSDFS_DEBUG */
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
			SSDFS_ERR("invalid buffer state %#x\n",
				  search->result.buf_state);
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
	} else {
		err = -ENOENT;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("dentries tree is absent: "
			  "ino %lu\n",
			  (unsigned long)dir->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */
	}

finish_search_dentry:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir %lu, flags %#x\n", (unsigned long)dir->i_ino, flags);
#endif /* CONFIG_SSDFS_DEBUG */

	if (target->d_name.len > SSDFS_MAX_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	down_read(&SSDFS_I(dir)->lock);
	err = ssdfs_inode_by_name(dir, &target->d_name, &ino);
	up_read(&SSDFS_I(dir)->lock);

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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

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
	struct timespec64 cur_time;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rwsem_is_locked(&dir_ii->lock));

	SSDFS_DBG("Created ino %lu with mode %o, nlink %d, nrpages %ld\n",
		  (unsigned long)inode->i_ino, inode->i_mode,
		  inode->i_nlink, inode->i_mapping->nrpages);
#endif /* CONFIG_SSDFS_DEBUG */

	private_flags = atomic_read(&dir_ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES ||
	    private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		if (!dir_ii->dentries_tree) {
			err = -ERANGE;
			SSDFS_WARN("dentries tree absent!!!\n");
			goto finish_add_link;
		}
	} else {
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

			atomic_or(SSDFS_INODE_HAS_INLINE_DENTRIES,
				  &dir_ii->private_flags);
		}

finish_create_dentries_tree:
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
		cur_time = current_time(dir);
		inode_set_mtime_to_ts(dir, cur_time);
		inode_set_ctime_to_ts(dir, cur_time);
		mark_inode_dirty(dir);
	}

	ssdfs_btree_search_free(search);

finish_add_link:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */
	return err;
}

static int ssdfs_add_nondir(struct inode *dir, struct dentry *dentry,
			    struct inode *inode)
{
	struct ssdfs_inode_info *dir_ii = SSDFS_I(dir);
	int private_flags;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("Created ino %lu with mode %o, nlink %d, nrpages %ld\n",
		  (unsigned long)inode->i_ino, inode->i_mode,
		  inode->i_nlink, inode->i_mapping->nrpages);
#endif /* CONFIG_SSDFS_DEBUG */

	private_flags = atomic_read(&dir_ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES ||
	    private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		down_read(&dir_ii->lock);
		err = ssdfs_add_link(dir, dentry, inode);
		up_read(&dir_ii->lock);
	} else {
		down_write(&dir_ii->lock);
		err = ssdfs_add_link(dir, dentry, inode);
		up_write(&dir_ii->lock);
	}

	if (err) {
		inode_dec_link_count(inode);
		iget_failed(inode);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

		return err;
	}

	unlock_new_inode(inode);
	d_instantiate(dentry, inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * The ssdfs_create() is called by the open(2) and
 * creat(2) system calls.
 */
int ssdfs_create(struct mnt_idmap *idmap,
		 struct inode *dir, struct dentry *dentry,
		 umode_t mode, bool excl)
{
	struct inode *inode;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir %lu, mode %o\n", (unsigned long)dir->i_ino, mode);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = ssdfs_new_inode(idmap, dir, mode, &dentry->d_name);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto failed_create;
	}

	mark_inode_dirty(inode);
	err = ssdfs_add_nondir(dir, dentry, inode);

failed_create:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */
	return err;
}

/*
 * The ssdfs_mknod() is called by the mknod(2) system call
 * to create a device (char, block) inode or a named pipe
 * (FIFO) or socket.
 */
static int ssdfs_mknod(struct mnt_idmap *idmap,
			struct inode *dir, struct dentry *dentry,
			umode_t mode, dev_t rdev)
{
	struct inode *inode;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir %lu, mode %o, rdev %#x\n",
		  (unsigned long)dir->i_ino, mode, rdev);
#endif /* CONFIG_SSDFS_DEBUG */

	if (dentry->d_name.len > SSDFS_MAX_NAME_LEN)
		return -ENAMETOOLONG;

	inode = ssdfs_new_inode(idmap, dir, mode, &dentry->d_name);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	init_special_inode(inode, mode, rdev);

	mark_inode_dirty(inode);
	err = ssdfs_add_nondir(dir, dentry, inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * Create symlink.
 * The ssdfs_symlink() is called by the symlink(2) system call.
 */
static int ssdfs_symlink(struct mnt_idmap *idmap,
			 struct inode *dir, struct dentry *dentry,
			 const char *target)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(dir->i_sb);
	struct inode *inode;
	size_t target_len = strlen(target) + 1;
	size_t raw_inode_size;
	size_t inline_len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir %lu, target_len %zu\n",
		  (unsigned long)dir->i_ino, target_len);
#endif /* CONFIG_SSDFS_DEBUG */

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

	inode = ssdfs_new_inode(idmap, dir, S_IFLNK | S_IRWXUGO, &dentry->d_name);
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
	err = ssdfs_add_nondir(dir, dentry, inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;

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
	struct ssdfs_inode_info *dir_ii = SSDFS_I(dir);
	int private_flags;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir %lu, inode %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	if (inode->i_nlink >= SSDFS_LINK_MAX)
		return -EMLINK;

	if (!S_ISREG(inode->i_mode))
		return -EPERM;

	inode_set_ctime_to_ts(inode, current_time(inode));
	inode_inc_link_count(inode);
	ihold(inode);

	private_flags = atomic_read(&dir_ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES ||
	    private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		down_read(&dir_ii->lock);
		err = ssdfs_add_link(dir, dentry, inode);
		up_read(&dir_ii->lock);
	} else {
		down_write(&dir_ii->lock);
		err = ssdfs_add_link(dir, dentry, inode);
		up_write(&dir_ii->lock);
	}

	if (err) {
		inode_dec_link_count(inode);
		iput(inode);
		return err;
	}

	d_instantiate(dentry, inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("Created ino %lu with mode %o, nlink %d, nrpages %ld\n",
		  (unsigned long)inode->i_ino, inode->i_mode,
		  inode->i_nlink, inode->i_mapping->nrpages);
#endif /* CONFIG_SSDFS_DEBUG */

	private_flags = atomic_read(&ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES ||
	    private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		down_read(&ii->lock);

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

			atomic_or(SSDFS_INODE_HAS_INLINE_DENTRIES,
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

static int __ssdfs_mkdir(struct mnt_idmap *idmap,
			 struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	struct ssdfs_inode_info *dir_ii = SSDFS_I(dir);
	int private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir %lu, mode %o\n",
		  (unsigned long)dir->i_ino, mode);
#endif /* CONFIG_SSDFS_DEBUG */

	if (dentry->d_name.len > SSDFS_MAX_NAME_LEN)
		return -ENAMETOOLONG;

	inode_inc_link_count(dir);

	inode = ssdfs_new_inode(idmap, dir, S_IFDIR | mode, &dentry->d_name);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_dir;

	inode_inc_link_count(inode);

	err = ssdfs_make_empty(inode, dir);
	if (err)
		goto out_fail;

	private_flags = atomic_read(&dir_ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES ||
	    private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		down_read(&dir_ii->lock);
		err = ssdfs_add_link(dir, dentry, inode);
		up_read(&dir_ii->lock);
	} else {
		down_write(&dir_ii->lock);
		err = ssdfs_add_link(dir, dentry, inode);
		up_write(&dir_ii->lock);
	}

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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * Create subdirectory.
 * The ssdfs_mkdir() is called by the mkdir(2) system call.
 */
static struct dentry *ssdfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
				  struct dentry *dentry, umode_t mode)
{
	return ERR_PTR(__ssdfs_mkdir(idmap, dir, dentry, mode));
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
	struct timespec64 cur_time;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir %lu, inode %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	trace_ssdfs_unlink_enter(dir, dentry);

	private_flags = atomic_read(&ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES ||
	    private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
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
				  "name_hash %llx, ino %lu, err %d\n",
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

	cur_time = current_time(dir);
	inode_set_ctime_to_ts(inode, cur_time);
	inode_set_mtime_to_ts(dir, cur_time);
	inode_set_ctime_to_ts(dir, cur_time);

	inode_dec_link_count(inode);

finish_unlink:
	trace_ssdfs_unlink_exit(inode, err);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

static inline bool ssdfs_empty_dir(struct inode *dir)
{
	struct ssdfs_inode_info *ii = SSDFS_I(dir);
	bool is_empty = false;
	int private_flags;
	u64 dentries_count;
	u64 threshold = 2; /* . and .. */

	private_flags = atomic_read(&ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES ||
	    private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir %lu, subdir %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ssdfs_empty_dir(inode)) {
		err = ssdfs_unlink(dir, dentry);
		if (!err) {
			inode->i_size = 0;
			inode_dec_link_count(inode);
			inode_dec_link_count(dir);
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

enum {
	SSDFS_FIRST_INODE_LOCK = 0,
	SSDFS_SECOND_INODE_LOCK,
	SSDFS_THIRD_INODE_LOCK,
	SSDFS_FOURTH_INODE_LOCK,
};

static void lock_4_inodes(struct inode *inode1, struct inode *inode2,
			  struct inode *inode3, struct inode *inode4)
{
	down_write_nested(&SSDFS_I(inode1)->lock, SSDFS_FIRST_INODE_LOCK);

	if (inode2 != inode1) {
		down_write_nested(&SSDFS_I(inode2)->lock,
					SSDFS_SECOND_INODE_LOCK);
	}

	if (inode3) {
		down_write_nested(&SSDFS_I(inode3)->lock,
					SSDFS_THIRD_INODE_LOCK);
	}

	if (inode4) {
		down_write_nested(&SSDFS_I(inode4)->lock,
					SSDFS_FOURTH_INODE_LOCK);
	}
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
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(old_dir->i_sb);
	struct ssdfs_inode_info *old_dir_ii = SSDFS_I(old_dir);
	struct ssdfs_inode_info *new_dir_ii = SSDFS_I(new_dir);
	struct inode *old_inode = d_inode(old_dentry);
	struct ssdfs_inode_info *old_ii = SSDFS_I(old_inode);
	struct inode *new_inode = d_inode(new_dentry);
	struct ssdfs_btree_search *search;
	struct qstr dotdot = QSTR_INIT("..", 2);
	bool is_dir = S_ISDIR(old_inode->i_mode);
	bool move = (new_dir != old_dir);
	bool unlink = new_inode != NULL;
	ino_t old_ino, old_parent_ino, new_ino;
	struct timespec64 time;
	u64 name_hash;
	int err = -ENOENT;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("old_dir %lu, old_inode %lu, "
		  "new_dir %lu, new_inode %p\n",
		  (unsigned long)old_dir->i_ino,
		  (unsigned long)old_inode->i_ino,
		  (unsigned long)new_dir->i_ino,
		  new_inode);
#endif /* CONFIG_SSDFS_DEBUG */

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto out;
	}

	ssdfs_btree_search_init(search);

	lock_4_inodes(old_dir, new_dir, old_inode, new_inode);

	err = ssdfs_inode_by_name(old_dir, &old_dentry->d_name, &old_ino);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find old dentry: err %d\n", err);
		goto finish_target_rename;
	} else if (old_ino != old_inode->i_ino) {
		err = -ERANGE;
		SSDFS_ERR("invalid ino: found ino %lu != requested ino %lu\n",
			  old_ino, old_inode->i_ino);
		goto finish_target_rename;
	}

	if (S_ISDIR(old_inode->i_mode)) {
		err = ssdfs_inode_by_name(old_inode, &dotdot, &old_parent_ino);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find parent dentry: err %d\n", err);
			goto finish_target_rename;
		} else if (old_parent_ino != old_dir->i_ino) {
			err = -ERANGE;
			SSDFS_ERR("invalid ino: "
				  "found ino %lu != requested ino %lu\n",
				  old_parent_ino, old_dir->i_ino);
			goto finish_target_rename;
		}
	}

	if (!old_dir_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("old dir hasn't dentries tree\n");
		goto finish_target_rename;
	}

	if (!new_dir_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("new dir hasn't dentries tree\n");
		goto finish_target_rename;
	}

	if (S_ISDIR(old_inode->i_mode) && !old_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("old inode hasn't dentries tree\n");
		goto finish_target_rename;
	}

	if (flags & RENAME_WHITEOUT) {
		/* TODO: implement support */
		SSDFS_WARN("TODO: implement support of RENAME_WHITEOUT\n");
	}

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
				"name_hash %llx, ino %lu, err %d\n",
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
	inode_set_ctime_to_ts(old_inode, time);
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

	inode_set_mtime_to_ts(old_dir, time);
	inode_set_ctime_to_ts(old_dir, time);
	inode_set_mtime_to_ts(new_dir, time);
	inode_set_ctime_to_ts(new_dir, time);

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
		inode_set_ctime_to_ts(new_inode, time);
	}

finish_target_rename:
	unlock_4_inodes(old_dir, new_dir, old_inode, new_inode);
	ssdfs_btree_search_free(search);

out:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */
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
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(old_dir->i_sb);
	struct ssdfs_inode_info *old_dir_ii = SSDFS_I(old_dir);
	struct ssdfs_inode_info *new_dir_ii = SSDFS_I(new_dir);
	struct inode *old_inode = d_inode(old_dentry);
	struct ssdfs_inode_info *old_ii = SSDFS_I(old_inode);
	struct inode *new_inode = d_inode(new_dentry);
	struct ssdfs_inode_info *new_ii = SSDFS_I(new_inode);
	struct ssdfs_btree_search *search;
	struct qstr dotdot = QSTR_INIT("..", 2);
	ino_t old_ino, new_ino;
	struct timespec64 time;
	u64 name_hash;
	int err = -ENOENT;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("old_dir %lu, old_inode %lu, new_dir %lu\n",
		  (unsigned long)old_dir->i_ino,
		  (unsigned long)old_inode->i_ino,
		  (unsigned long)new_dir->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto out;
	}

	ssdfs_btree_search_init(search);

	lock_4_inodes(old_dir, new_dir, old_inode, new_inode);

	err = ssdfs_inode_by_name(old_dir, &old_dentry->d_name, &old_ino);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find old dentry: err %d\n", err);
		goto finish_cross_rename;
	} else if (old_ino != old_inode->i_ino) {
		err = -ERANGE;
		SSDFS_ERR("invalid ino: found ino %lu != requested ino %lu\n",
			  old_ino, old_inode->i_ino);
		goto finish_cross_rename;
	}

	err = ssdfs_inode_by_name(new_dir, &new_dentry->d_name, &new_ino);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find new dentry: err %d\n", err);
		goto finish_cross_rename;
	} else if (new_ino != new_inode->i_ino) {
		err = -ERANGE;
		SSDFS_ERR("invalid ino: found ino %lu != requested ino %lu\n",
			  new_ino, new_inode->i_ino);
		goto finish_cross_rename;
	}

	if (!old_dir_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("old dir hasn't dentries tree\n");
		goto finish_cross_rename;
	}

	if (!new_dir_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("new dir hasn't dentries tree\n");
		goto finish_cross_rename;
	}

	if (S_ISDIR(old_inode->i_mode) && !old_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("old inode hasn't dentries tree\n");
		goto finish_cross_rename;
	}

	if (S_ISDIR(new_inode->i_mode) && !new_ii->dentries_tree) {
		err = -ERANGE;
		SSDFS_ERR("new inode hasn't dentries tree\n");
		goto finish_cross_rename;
	}

	name_hash = ssdfs_generate_name_hash(&dotdot);

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
	inode_set_ctime_to_ts(old_inode, time);
	inode_set_ctime_to_ts(new_inode, time);
	inode_set_mtime_to_ts(old_dir, time);
	inode_set_ctime_to_ts(old_dir, time);
	inode_set_mtime_to_ts(new_dir, time);
	inode_set_ctime_to_ts(new_dir, time);

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
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * The ssdfs_rename() is called by the rename(2) system call
 * to rename the object to have the parent and name given by
 * the second inode and dentry.
 */
static int ssdfs_rename(struct mnt_idmap *idmap,
			struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("old_dir %lu, old_inode %lu, new_dir %lu\n",
		  (unsigned long)old_dir->i_ino,
		  (unsigned long)old_dentry->d_inode->i_ino,
		  (unsigned long)new_dir->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT)) {
		SSDFS_ERR("invalid flags %#x\n", flags);
		return -EINVAL;
	}

	if (flags & RENAME_EXCHANGE) {
		return ssdfs_cross_rename(old_dir, old_dentry,
					  new_dir, new_dentry);
	}

	return ssdfs_rename_target(old_dir, old_dentry, new_dir, new_dentry,
				   flags);
}

static
int ssdfs_dentries_tree_get_start_hash(struct ssdfs_dentries_btree_info *tree,
					u64 *start_hash)
{
	struct ssdfs_btree_index *index;
	struct ssdfs_dir_entry *cur_dentry;
	u64 dentries_count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !start_hash);

	SSDFS_DBG("tree %p, start_hash %p\n",
		  tree, start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	*start_hash = U64_MAX;

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	dentries_count = atomic64_read(&tree->dentries_count);

	if (dentries_count < 2) {
		SSDFS_WARN("folder is corrupted: "
			   "dentries_count %llu\n",
			   dentries_count);
		return -ERANGE;
	} else if (dentries_count == 2)
		return -ENOENT;

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		down_read(&tree->lock);

		if (!tree->inline_dentries) {
			err = -ERANGE;
			SSDFS_ERR("inline tree's pointer is empty\n");
			goto finish_process_inline_tree;
		}

		cur_dentry = &tree->inline_dentries[0];
		*start_hash = le64_to_cpu(cur_dentry->hash_code);

finish_process_inline_tree:
		up_read(&tree->lock);

		if (*start_hash >= U64_MAX) {
			/* warn about invalid hash code */
			SSDFS_WARN("inline array: hash_code is invalid\n");
		}
		break;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
		down_read(&tree->lock);

		if (!tree->root) {
			err = -ERANGE;
			SSDFS_ERR("root node pointer is NULL\n");
			goto finish_get_start_hash;
		}

		index = &tree->root->indexes[SSDFS_ROOT_NODE_LEFT_LEAF_NODE];
		*start_hash = le64_to_cpu(index->hash);

finish_get_start_hash:
		up_read(&tree->lock);

		if (*start_hash >= U64_MAX) {
			/* warn about invalid hash code */
			SSDFS_WARN("private dentry: hash_code is invalid\n");
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

static
int ssdfs_dentries_tree_get_next_hash(struct ssdfs_dentries_btree_info *tree,
					struct ssdfs_btree_search *search,
					u64 *next_hash)
{
	u64 old_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !next_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	old_hash = le64_to_cpu(search->node.found_index.index.hash);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search %p, next_hash %p, old (node %u, hash %llx)\n",
		  search, next_hash, search->node.id, old_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		SSDFS_DBG("inline dentries array is unsupported\n");
		return -ENOENT;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
		/* expected tree type */
		break;

	default:
		SSDFS_ERR("invalid tree type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	down_read(&tree->lock);
	err = ssdfs_btree_get_next_hash(tree->generic_tree, search, next_hash);
	up_read(&tree->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

static
int ssdfs_dentries_tree_node_hash_range(struct ssdfs_dentries_btree_info *tree,
					struct ssdfs_btree_search *search,
					u64 *start_hash, u64 *end_hash,
					u16 *items_count)
{
	struct ssdfs_dir_entry *cur_dentry;
	u64 dentries_count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !start_hash || !end_hash || !items_count);

	SSDFS_DBG("search %p, start_hash %p, "
		  "end_hash %p, items_count %p\n",
		  search, start_hash, end_hash, items_count);
#endif /* CONFIG_SSDFS_DEBUG */

	*start_hash = *end_hash = U64_MAX;
	*items_count = 0;

	switch (atomic_read(&tree->state)) {
	case SSDFS_DENTRIES_BTREE_CREATED:
	case SSDFS_DENTRIES_BTREE_INITIALIZED:
	case SSDFS_DENTRIES_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dentries tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_DENTRIES_ARRAY:
		dentries_count = atomic64_read(&tree->dentries_count);
		if (dentries_count >= U16_MAX) {
			err = -ERANGE;
			SSDFS_ERR("unexpected dentries count %llu\n",
				  dentries_count);
			goto finish_extract_hash_range;
		}

		*items_count = (u16)dentries_count;

		if (*items_count == 0)
			goto finish_extract_hash_range;

		down_read(&tree->lock);

		if (!tree->inline_dentries) {
			err = -ERANGE;
			SSDFS_ERR("inline tree's pointer is empty\n");
			goto finish_process_inline_tree;
		}

		cur_dentry = &tree->inline_dentries[0];
		*start_hash = le64_to_cpu(cur_dentry->hash_code);

		if (dentries_count > SSDFS_INLINE_DENTRIES_COUNT) {
			err = -ERANGE;
			SSDFS_ERR("dentries_count %llu > max_value %u\n",
				  dentries_count,
				  SSDFS_INLINE_DENTRIES_COUNT);
			goto finish_process_inline_tree;
		}

		cur_dentry = &tree->inline_dentries[dentries_count - 1];
		*end_hash = le64_to_cpu(cur_dentry->hash_code);

finish_process_inline_tree:
		up_read(&tree->lock);
		break;

	case SSDFS_PRIVATE_DENTRIES_BTREE:
		err = ssdfs_btree_node_get_hash_range(search,
						      start_hash,
						      end_hash,
						      items_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get hash range: err %d\n",
				  err);
			goto finish_extract_hash_range;
		}
		break;

	default:
		SSDFS_ERR("invalid tree type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, items_count %u\n",
		  *start_hash, *end_hash, *items_count);
#endif /* CONFIG_SSDFS_DEBUG */

finish_extract_hash_range:
	return err;
}

static
int ssdfs_dentries_tree_check_search_result(struct ssdfs_btree_search *search)
{
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);
	u16 items_count;
	size_t buf_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected result's state %#x\n",
			  search->result.state);
		return  -ERANGE;
	}

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		if (!search->result.buf) {
			SSDFS_ERR("buffer pointer is NULL\n");
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("unexpected buffer's state\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.items_in_buffer >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = (u16)search->result.items_in_buffer;

	if (items_count == 0) {
		SSDFS_ERR("items_in_buffer %u\n",
			  items_count);
		return -ENOENT;
	} else if (items_count != search->result.count) {
		SSDFS_ERR("items_count %u != search->result.count %u\n",
			  items_count, search->result.count);
		return -ERANGE;
	}

	buf_size = dentry_size * items_count;

	if (buf_size != search->result.buf_size) {
		SSDFS_ERR("buf_size %zu != search->result.buf_size %zu\n",
			  buf_size,
			  search->result.buf_size);
		return -ERANGE;
	}

	return 0;
}

static
bool is_invalid_dentry(struct ssdfs_dir_entry *dentry)
{
	u8 name_len;
	bool is_invalid = false;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!dentry);

	SSDFS_DBG("dentry_type %#x, file_type %#x, "
		  "flags %#x, name_len %u, "
		  "hash_code %llx, ino %llu\n",
		  dentry->dentry_type, dentry->file_type,
		  dentry->flags, dentry->name_len,
		  le64_to_cpu(dentry->hash_code),
		  le64_to_cpu(dentry->ino));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (dentry->dentry_type) {
	case SSDFS_INLINE_DENTRY:
	case SSDFS_REGULAR_DENTRY:
		/* expected dentry type */
		break;

	default:
		is_invalid = true;
		SSDFS_ERR("invalid dentry type %#x\n",
			  dentry->dentry_type);
		goto finish_check;
	}

	if (dentry->file_type <= SSDFS_FT_UNKNOWN ||
	    dentry->file_type >= SSDFS_FT_MAX) {
		is_invalid = true;
		SSDFS_ERR("invalid file type %#x\n",
			  dentry->file_type);
		goto finish_check;
	}

	if (dentry->flags & ~SSDFS_DENTRY_FLAGS_MASK) {
		is_invalid = true;
		SSDFS_ERR("invalid set of flags %#x\n",
			  dentry->flags);
		goto finish_check;
	}

	name_len = dentry->name_len;

	if (name_len > SSDFS_MAX_NAME_LEN) {
		is_invalid = true;
		SSDFS_ERR("invalid name_len %u\n",
			  name_len);
		goto finish_check;
	}

	if (le64_to_cpu(dentry->hash_code) >= U64_MAX) {
		is_invalid = true;
		SSDFS_ERR("invalid hash_code\n");
		goto finish_check;
	}

	if (le64_to_cpu(dentry->ino) >= U32_MAX) {
		is_invalid = true;
		SSDFS_ERR("ino %llu is too huge\n",
			  le64_to_cpu(dentry->ino));
		goto finish_check;
	}

finish_check:
	if (is_invalid) {
		SSDFS_ERR("dentry_type %#x, file_type %#x, "
			  "flags %#x, name_len %u, "
			  "hash_code %llx, ino %llu\n",
			  dentry->dentry_type, dentry->file_type,
			  dentry->flags, dentry->name_len,
			  le64_to_cpu(dentry->hash_code),
			  le64_to_cpu(dentry->ino));
	}

	return is_invalid;
}

/*
 * The ssdfs_readdir() is called when the VFS needs
 * to read the directory contents.
 */
static int ssdfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct qstr dot = QSTR_INIT(".", 1);
	u64 dot_hash;
	struct qstr dotdot = QSTR_INIT("..", 2);
	u64 dotdot_hash;
	struct ssdfs_shared_dict_btree_info *dict;
	struct ssdfs_btree_search *search;
	struct ssdfs_dir_entry *dentry;
	size_t dentry_size = sizeof(struct ssdfs_dir_entry);
	int private_flags;
	u64 start_hash = U64_MAX;
	u64 end_hash = U64_MAX;
	u64 hash = U64_MAX;
	u64 start_pos;
	u16 items_count;
	ino_t ino;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("file %p, ctx %p\n", file, ctx);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ctx->pos < 0) {
		SSDFS_DBG("ctx->pos %lld\n", ctx->pos);
		return 0;
	}

	dict = fsi->shdictree;
	if (!dict) {
		SSDFS_ERR("shared dictionary is absent\n");
		return -ERANGE;
	}

	dot_hash = ssdfs_generate_name_hash(&dot);
	dotdot_hash = ssdfs_generate_name_hash(&dotdot);

	private_flags = atomic_read(&ii->private_flags);

	if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES ||
	    private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
		down_read(&ii->lock);
		if (!ii->dentries_tree)
			err = -ERANGE;
		up_read(&ii->lock);

		if (unlikely(err)) {
			SSDFS_WARN("dentries tree is absent\n");
			return -ERANGE;
		}
	} else {
		if (!S_ISDIR(inode->i_mode)) {
			SSDFS_WARN("this is not folder!!!\n");
			return -EINVAL;
		}

		down_read(&ii->lock);
		if (ii->dentries_tree)
			err = -ERANGE;
		up_read(&ii->lock);

		if (unlikely(err)) {
			SSDFS_WARN("dentries tree exists!!!!\n");
			return err;
		}
	}

	start_pos = ctx->pos;

	if (ctx->pos == 0) {
		down_read(&ii->lock);
		err = ssdfs_inode_by_name(inode, &dot, &ino);
		up_read(&ii->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to find dentry: err %d\n", err);
			goto out;
		}

		if (!dir_emit_dot(file, ctx)) {
			err = -ERANGE;
			SSDFS_ERR("fail to emit dentry\n");
			goto out;
		}

		ctx->pos = 1;
	}

	if (ctx->pos == 1) {
		down_read(&ii->lock);
		err = ssdfs_inode_by_name(inode, &dotdot, &ino);
		up_read(&ii->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to find dentry: err %d\n", err);
			goto out;
		}

		if (!dir_emit_dotdot(file, ctx)) {
			err = -ERANGE;
			SSDFS_ERR("fail to emit dentry\n");
			goto out;
		}

		ctx->pos = 2;
	}

	if (ctx->pos >= 2) {
		down_read(&ii->lock);
		err = ssdfs_dentries_tree_get_start_hash(ii->dentries_tree,
							 &start_hash);
		up_read(&ii->lock);

		if (err == -ENOENT) {
			err = 0;
			ctx->pos = 2;
			goto out;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get start root hash: err %d\n", err);
			goto out;
		} else if (start_hash >= U64_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid hash value\n");
			goto out;
		}

		ctx->pos = 2;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto out;
	}

	do {
		ssdfs_btree_search_init(search);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("ctx->pos %llu, start_hash %llx\n",
			  (u64)ctx->pos, start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

		/* allow readdir() to be interrupted */
		if (fatal_signal_pending(current)) {
			err = -ERESTARTSYS;
			goto out_free;
		}
		cond_resched();

		down_read(&ii->lock);

		err = ssdfs_dentries_tree_find_leaf_node(ii->dentries_tree,
							 start_hash,
							 search);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find a leaf node: "
				  "hash %llx, err %d\n",
				  start_hash, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_tree_processing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a leaf node: "
				  "hash %llx, err %d\n",
				  start_hash, err);
			goto finish_tree_processing;
		}

		err = ssdfs_dentries_tree_node_hash_range(ii->dentries_tree,
							  search,
							  &start_hash,
							  &end_hash,
							  &items_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get node's hash range: "
				  "err %d\n", err);
			goto finish_tree_processing;
		}

		if (items_count == 0) {
			err = -ENOENT;
			SSDFS_DBG("empty leaf node\n");
			goto finish_tree_processing;
		}

		if (start_hash > end_hash) {
			err = -ENOENT;
			goto finish_tree_processing;
		}

		err = ssdfs_dentries_tree_extract_range(ii->dentries_tree,
							0, items_count,
							search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the range: "
				  "items_count %u, err %d\n",
				  items_count, err);
			goto finish_tree_processing;
		}

finish_tree_processing:
		up_read(&ii->lock);

		if (err == -ENODATA) {
			err = 0;
			goto out_free;
		} else if (unlikely(err))
			goto out_free;

		err = ssdfs_dentries_tree_check_search_result(search);
		if (unlikely(err)) {
			SSDFS_ERR("corrupted search result: "
				  "err %d\n", err);
			goto out_free;
		}

		items_count = search->result.count;

		for (i = 0; i < items_count; i++) {
			u8 *start_ptr = (u8 *)search->result.buf;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("start_pos %llu, ctx->pos %llu\n",
				  start_pos, ctx->pos);
#endif /* CONFIG_SSDFS_DEBUG */

			dentry = (struct ssdfs_dir_entry *)(start_ptr +
							(i * dentry_size));
			hash = le64_to_cpu(dentry->hash_code);

			if (ctx->pos < start_pos) {
				if (dot_hash == hash || dotdot_hash == hash) {
					/* skip counting */
					continue;
				} else {
					ctx->pos++;
					continue;
				}
			}

			if (is_invalid_dentry(dentry)) {
				err = -EIO;
				SSDFS_ERR("found corrupted dentry\n");
				goto out_free;
			}

			if (dot_hash == hash || dotdot_hash == hash) {
				/*
				 * These items were created already.
				 * Simply skip the case.
				 */
			} else if (dentry->flags & SSDFS_DENTRY_HAS_EXTERNAL_STRING) {
				err = ssdfs_shared_dict_get_name(dict, hash,
								 &search->name);
				if (unlikely(err)) {
					SSDFS_ERR("fail to extract the name: "
						  "hash %llx, err %d\n",
						  hash, err);
					goto out_free;
				}

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("ctx->pos %llu, name %s, "
					  "name_len %zu, "
					  "ino %llu, hash %llx\n",
					  ctx->pos,
					  search->name.str,
					  search->name.len,
					  le64_to_cpu(dentry->ino),
					  hash);
#endif /* CONFIG_SSDFS_DEBUG */

				if (!dir_emit(ctx,
				    search->name.str,
				    search->name.len,
				    (ino_t)le64_to_cpu(dentry->ino),
				    ssdfs_filetype_table[dentry->file_type])) {
					/* stopped by some reason */
					err = 1;
					goto out_free;
				} else
					ctx->pos++;
			} else {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("ctx->pos %llu, name %s, "
					  "name_len %u, "
					  "ino %llu, hash %llx\n",
					  ctx->pos,
					  dentry->inline_string,
					  dentry->name_len,
					  le64_to_cpu(dentry->ino),
					  hash);
				SSDFS_DBG("dentry %p, name %p\n",
					  dentry, dentry->inline_string);
#endif /* CONFIG_SSDFS_DEBUG */

				if (!dir_emit(ctx,
				    dentry->inline_string,
				    dentry->name_len,
				    (ino_t)le64_to_cpu(dentry->ino),
				    ssdfs_filetype_table[dentry->file_type])) {
					/* stopped by some reason */
					err = 1;
					goto out_free;
				} else
					ctx->pos++;
			}
		}

		if (hash != end_hash) {
			err = -ERANGE;
			SSDFS_ERR("hash %llx < end_hash %llx\n",
				  hash, end_hash);
			goto out_free;
		}

		start_hash = end_hash + 1;

		down_read(&ii->lock);
		err = ssdfs_dentries_tree_get_next_hash(ii->dentries_tree,
							search,
							&start_hash);
		up_read(&ii->lock);

		ssdfs_btree_search_forget_parent_node(search);
		ssdfs_btree_search_forget_child_node(search);

		if (err == -ENOENT) {
			err = 0;
			ctx->pos = U64_MAX;
			SSDFS_DBG("no more items in the folder\n");
			goto out_free;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get next hash: err %d\n",
				  err);
			goto out_free;
		}
	} while (start_hash < U64_MAX);

out_free:
	ssdfs_btree_search_free(search);

out:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */
	return err;
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
	.listxattr	= ssdfs_listxattr,
	.get_inode_acl	= ssdfs_get_acl,
	.set_acl	= ssdfs_set_acl,
};

const struct file_operations ssdfs_dir_operations = {
	.read		= generic_read_dir,
	.iterate_shared	= ssdfs_readdir,
	.unlocked_ioctl	= ssdfs_ioctl,
	.fsync		= ssdfs_fsync,
	.llseek		= generic_file_llseek,
};
