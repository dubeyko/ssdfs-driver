// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/inode.c - inode handling routines.
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

#include <linux/mtd/mtd.h>
#include <linux/mm.h>
#include <linux/statfs.h>
#include <linux/pagevec.h>
#include <linux/dcache.h>
#include <linux/random.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "request_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"
#include "inodes_tree.h"
#include "dentries_tree.h"
#include "xattr_tree.h"
#include "acl.h"
#include "xattr.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_inode_page_leaks;
atomic64_t ssdfs_inode_folio_leaks;
atomic64_t ssdfs_inode_memory_leaks;
atomic64_t ssdfs_inode_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_inode_cache_leaks_increment(void *kaddr)
 * void ssdfs_inode_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_inode_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_inode_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_inode_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_inode_kfree(void *kaddr)
 * struct page *ssdfs_inode_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_inode_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_inode_free_page(struct page *page)
 * void ssdfs_inode_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(inode)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(inode)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_inode_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_inode_page_leaks, 0);
	atomic64_set(&ssdfs_inode_folio_leaks, 0);
	atomic64_set(&ssdfs_inode_memory_leaks, 0);
	atomic64_set(&ssdfs_inode_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_inode_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_inode_page_leaks) != 0) {
		SSDFS_ERR("INODE: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_inode_page_leaks));
	}

	if (atomic64_read(&ssdfs_inode_folio_leaks) != 0) {
		SSDFS_ERR("INODE: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_inode_folio_leaks));
	}

	if (atomic64_read(&ssdfs_inode_memory_leaks) != 0) {
		SSDFS_ERR("INODE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_inode_memory_leaks));
	}

	if (atomic64_read(&ssdfs_inode_cache_leaks) != 0) {
		SSDFS_ERR("INODE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_inode_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

bool is_raw_inode_checksum_correct(struct ssdfs_fs_info *fsi,
				   void *buf, size_t size)
{
	struct ssdfs_inode *raw_inode;
	size_t raw_inode_size;
	__le32 old_checksum;
	bool is_valid = false;

	spin_lock(&fsi->inodes_tree->lock);
	raw_inode_size = fsi->inodes_tree->raw_inode_size;
	spin_unlock(&fsi->inodes_tree->lock);

	if (raw_inode_size != size) {
		SSDFS_WARN("raw_inode_size %zu != size %zu\n",
			   raw_inode_size, size);
		return false;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("RAW INODE DUMP:\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     buf, size);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	raw_inode = (struct ssdfs_inode *)buf;

	old_checksum = raw_inode->checksum;
	raw_inode->checksum = 0;
	raw_inode->checksum = ssdfs_crc32_le(buf, size);

	is_valid = old_checksum == raw_inode->checksum;

	if (!is_valid) {
		SSDFS_WARN("invalid inode's checksum: "
			   "stored %#x != calculated %#x\n",
			   le32_to_cpu(old_checksum),
			   le32_to_cpu(raw_inode->checksum));
		raw_inode->checksum = old_checksum;
	}

	return is_valid;
}

void ssdfs_set_inode_flags(struct inode *inode)
{
	unsigned int flags = SSDFS_I(inode)->flags;
	unsigned int new_fl = 0;

	if (flags & FS_SYNC_FL)
		new_fl |= S_SYNC;
	if (flags & FS_APPEND_FL)
		new_fl |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		new_fl |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		new_fl |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		new_fl |= S_DIRSYNC;
	inode_set_flags(inode, new_fl, S_SYNC | S_APPEND | S_IMMUTABLE |
			S_NOATIME | S_DIRSYNC);
}

static int ssdfs_inode_setops(struct inode *inode)
{
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &ssdfs_file_inode_operations;
		inode->i_fop = &ssdfs_file_operations;
		inode->i_mapping->a_ops = &ssdfs_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &ssdfs_dir_inode_operations;
		inode->i_fop = &ssdfs_dir_operations;
		inode->i_mapping->a_ops = &ssdfs_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &ssdfs_symlink_inode_operations;
		inode->i_mapping->a_ops = &ssdfs_aops;
		inode_nohighmem(inode);
	} else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		   S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		inode->i_op = &ssdfs_special_inode_operations;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	} else {
		SSDFS_ERR("bogus i_mode %o for ino %lu\n",
			  inode->i_mode, (unsigned long)inode->i_ino);
		return -EINVAL;
	}

	return 0;
}

static int ssdfs_read_inode(struct inode *inode)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_btree_search *search;
	struct ssdfs_inode *raw_inode;
	size_t raw_inode_size;
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	u16 private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);

	err = ssdfs_inodes_btree_find(fsi->inodes_tree, inode->i_ino, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the raw inode: "
			  "ino %lu, err %d\n",
			  inode->i_ino, err);
		goto finish_read_inode;
	}

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		/* expected state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid result state %#x\n",
			  search->result.state);
		goto finish_read_inode;
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
		goto finish_read_inode;
	}

	if (!search->result.buf) {
		err = -ERANGE;
		SSDFS_ERR("empty result buffer pointer\n");
		goto finish_read_inode;
	}

	if (search->result.items_in_buffer == 0) {
		err = -ERANGE;
		SSDFS_ERR("items_in_buffer %u\n",
			  search->result.items_in_buffer);
		goto finish_read_inode;
	}

	raw_inode = (struct ssdfs_inode *)search->result.buf;
	raw_inode_size =
		search->result.buf_size / search->result.items_in_buffer;

	if (!is_raw_inode_checksum_correct(fsi, raw_inode, raw_inode_size)) {
		err = -EIO;
		SSDFS_ERR("invalid inode's checksum: ino %lu\n",
			  inode->i_ino);
		goto finish_read_inode;
	}

	if (le16_to_cpu(raw_inode->magic) != SSDFS_INODE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid inode magic %#x\n",
			  le16_to_cpu(raw_inode->magic));
		goto finish_read_inode;
	}

	if (le64_to_cpu(raw_inode->ino) != inode->i_ino) {
		err = -EIO;
		SSDFS_ERR("raw_inode->ino %llu != i_ino %lu\n",
			  le64_to_cpu(raw_inode->ino),
			  inode->i_ino);
		goto finish_read_inode;
	}

	inode->i_mode = le16_to_cpu(raw_inode->mode);
	ii->flags = le32_to_cpu(raw_inode->flags);
	i_uid_write(inode, le32_to_cpu(raw_inode->uid));
	i_gid_write(inode, le32_to_cpu(raw_inode->gid));
	set_nlink(inode, le32_to_cpu(raw_inode->refcount));

	inode->i_atime.tv_sec = le64_to_cpu(raw_inode->atime);
	inode->i_ctime.tv_sec = le64_to_cpu(raw_inode->ctime);
	inode->i_mtime.tv_sec = le64_to_cpu(raw_inode->mtime);
	inode->i_atime.tv_nsec = le32_to_cpu(raw_inode->atime_nsec);
	inode->i_ctime.tv_nsec = le32_to_cpu(raw_inode->ctime_nsec);
	inode->i_mtime.tv_nsec = le32_to_cpu(raw_inode->mtime_nsec);

	ii->birthtime.tv_sec = le64_to_cpu(raw_inode->birthtime);
	ii->birthtime.tv_nsec = le32_to_cpu(raw_inode->birthtime_nsec);
	ii->raw_inode_size = fsi->raw_inode_size;

	inode->i_generation = (u32)le64_to_cpu(raw_inode->generation);

	inode->i_size = le64_to_cpu(raw_inode->size);
	inode->i_blkbits = fsi->log_pagesize;
	inode->i_blocks = le64_to_cpu(raw_inode->blocks);

	private_flags = le16_to_cpu(raw_inode->private_flags);
	atomic_set(&ii->private_flags, private_flags);
	if (private_flags & ~SSDFS_INODE_PRIVATE_FLAGS_MASK) {
		err = -EIO;
		SSDFS_ERR("invalid set of private_flags %#x\n",
			  private_flags);
		goto finish_read_inode;
	}

	err = ssdfs_inode_setops(inode);
	if (unlikely(err))
		goto finish_read_inode;

	down_write(&ii->lock);

	ii->parent_ino = le64_to_cpu(raw_inode->parent_ino);
	ssdfs_set_inode_flags(inode);
	ii->name_hash = le64_to_cpu(raw_inode->hash_code);
	ii->name_len = le16_to_cpu(raw_inode->name_len);

	ssdfs_memcpy(&ii->raw_inode,
		     0, sizeof(struct ssdfs_inode),
		     raw_inode,
		     0, sizeof(struct ssdfs_inode),
		     sizeof(struct ssdfs_inode));

	if (S_ISREG(inode->i_mode)) {
		if (private_flags & ~SSDFS_IFREG_PRIVATE_FLAG_MASK) {
			err = -EIO;
			SSDFS_ERR("regular file: invalid private flags %#x\n",
				  private_flags);
			goto unlock_mutable_fields;
		}

		if (is_ssdfs_file_inline(ii)) {
			err = ssdfs_allocate_inline_file_buffer(inode);
			if (unlikely(err)) {
				SSDFS_ERR("fail to allocate inline buffer\n");
				goto unlock_mutable_fields;
			}

			/*
			 * TODO: pre-fetch file's content in buffer
			 *       (if inode size > 256 bytes)
			 */
		} else if (private_flags & SSDFS_INODE_HAS_INLINE_EXTENTS ||
			   private_flags & SSDFS_INODE_HAS_EXTENTS_BTREE) {
			err = ssdfs_extents_tree_create(fsi, ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to create the extents tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				goto unlock_mutable_fields;
			}

			err = ssdfs_extents_tree_init(fsi, ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to init the extents tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				goto unlock_mutable_fields;
			}
		}

		if (private_flags & SSDFS_INODE_HAS_INLINE_XATTR ||
		    private_flags & SSDFS_INODE_HAS_XATTR_BTREE) {
			err = ssdfs_xattrs_tree_create(fsi, ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to create the xattrs tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				goto unlock_mutable_fields;
			}

			err = ssdfs_xattrs_tree_init(fsi, ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to init the xattrs tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				goto unlock_mutable_fields;
			}
		}
	} else if (S_ISDIR(inode->i_mode)) {
		if (private_flags & ~SSDFS_IFDIR_PRIVATE_FLAG_MASK) {
			err = -EIO;
			SSDFS_ERR("folder: invalid private flags %#x\n",
				  private_flags);
			goto unlock_mutable_fields;
		}

		if (private_flags & SSDFS_INODE_HAS_INLINE_DENTRIES ||
		    private_flags & SSDFS_INODE_HAS_DENTRIES_BTREE) {
			err = ssdfs_dentries_tree_create(fsi, ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to create the dentries tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				goto unlock_mutable_fields;
			}

			err = ssdfs_dentries_tree_init(fsi, ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to init the dentries tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				goto unlock_mutable_fields;
			}
		}

		if (private_flags & SSDFS_INODE_HAS_INLINE_XATTR ||
		    private_flags & SSDFS_INODE_HAS_XATTR_BTREE) {
			err = ssdfs_xattrs_tree_create(fsi, ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to create the xattrs tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				goto unlock_mutable_fields;
			}

			err = ssdfs_xattrs_tree_init(fsi, ii);
			if (unlikely(err)) {
				SSDFS_ERR("fail to init the xattrs tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				goto unlock_mutable_fields;
			}
		}
	} else if (S_ISLNK(inode->i_mode) ||
		   S_ISCHR(inode->i_mode) ||
		   S_ISBLK(inode->i_mode) ||
		   S_ISFIFO(inode->i_mode) ||
		   S_ISSOCK(inode->i_mode)) {
		/* do nothing */
	} else {
		err = -EINVAL;
		SSDFS_ERR("bogus i_mode %o for ino %lu\n",
			  inode->i_mode, (unsigned long)inode->i_ino);
		goto unlock_mutable_fields;
	}

unlock_mutable_fields:
	up_write(&ii->lock);

finish_read_inode:
	ssdfs_btree_search_free(search);
	return err;
}

struct inode *ssdfs_iget(struct super_block *sb, ino_t ino)
{
	struct inode *inode;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", (unsigned long)ino);
#endif /* CONFIG_SSDFS_DEBUG */

	inode = iget_locked(sb, ino);
	if (unlikely(!inode)) {
		err = -ENOMEM;
		SSDFS_ERR("unable to obtain or to allocate inode %lu, err %d\n",
			  (unsigned long)ino, err);
		return ERR_PTR(err);
	}

	if (!(inode->i_state & I_NEW)) {
		trace_ssdfs_iget(inode);
		return inode;
	}

	err = ssdfs_read_inode(inode);
	if (unlikely(err)) {
		SSDFS_ERR("unable to read inode %lu, err %d\n",
			  (unsigned long)ino, err);
		goto bad_inode;
	}

	unlock_new_inode(inode);
	trace_ssdfs_iget(inode);
	return inode;

bad_inode:
	iget_failed(inode);
	trace_ssdfs_iget_exit(inode, err);
	return ERR_PTR(err);
}

static void ssdfs_init_raw_inode(struct ssdfs_inode_info *ii)
{
	struct ssdfs_inode *ri = &ii->raw_inode;

	ri->magic = cpu_to_le16(SSDFS_INODE_MAGIC);
	ri->mode = cpu_to_le16(ii->vfs_inode.i_mode);
	ri->flags = cpu_to_le32(ii->flags);
	ri->uid = cpu_to_le32(i_uid_read(&ii->vfs_inode));
	ri->gid = cpu_to_le32(i_gid_read(&ii->vfs_inode));
	ri->atime = cpu_to_le64(ii->vfs_inode.i_atime.tv_sec);
	ri->ctime = cpu_to_le64(ii->vfs_inode.i_ctime.tv_sec);
	ri->mtime = cpu_to_le64(ii->vfs_inode.i_mtime.tv_sec);
	ri->atime_nsec = cpu_to_le32(ii->vfs_inode.i_atime.tv_nsec);
	ri->ctime_nsec = cpu_to_le32(ii->vfs_inode.i_ctime.tv_nsec);
	ri->mtime_nsec = cpu_to_le32(ii->vfs_inode.i_mtime.tv_nsec);
	ri->birthtime = cpu_to_le64(ii->birthtime.tv_sec);
	ri->birthtime_nsec = cpu_to_le32(ii->birthtime.tv_nsec);
	ri->generation = cpu_to_le64(ii->vfs_inode.i_generation);
	ri->size = cpu_to_le64(i_size_read(&ii->vfs_inode));
	ri->blocks = cpu_to_le64(ii->vfs_inode.i_blocks);
	ri->parent_ino = cpu_to_le64(ii->parent_ino);
	ri->refcount = cpu_to_le32(ii->vfs_inode.i_nlink);
	ri->checksum = 0;
	ri->ino = cpu_to_le64(ii->vfs_inode.i_ino);
	ri->hash_code = cpu_to_le64(ii->name_hash);
	ri->name_len = cpu_to_le16(ii->name_len);
}

static void ssdfs_init_inode(struct inode *dir,
			     struct inode *inode,
			     umode_t mode,
			     ino_t ino,
			     const struct qstr *qstr)
{
	struct super_block *sb = dir->i_sb;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);

	inode->i_ino = ino;
	ii->parent_ino = dir->i_ino;
	ii->birthtime = current_time(inode);
	ii->raw_inode_size = fsi->raw_inode_size;
	inode->i_mtime = inode->i_atime = inode->i_ctime = ii->birthtime;
	inode_init_owner(&init_user_ns, inode, dir, mode);
	ii->flags = ssdfs_mask_flags(mode,
			 SSDFS_I(dir)->flags & SSDFS_FL_INHERITED);
	ssdfs_set_inode_flags(inode);
	inode->i_generation = get_random_u32();
	inode->i_blkbits = fsi->log_pagesize;
	i_size_write(inode, 0);
	inode->i_blocks = 0;
	set_nlink(inode, 1);

	down_write(&ii->lock);
	ii->name_hash = ssdfs_generate_name_hash(qstr);
	ii->name_len = (u16)qstr->len;
	ssdfs_init_raw_inode(ii);
	up_write(&ii->lock);
}

struct inode *ssdfs_new_inode(struct inode *dir, umode_t mode,
			      const struct qstr *qstr)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(dir->i_sb);
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct ssdfs_btree_search *search;
	struct ssdfs_inodes_btree_info *itree;
	ino_t ino;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir_ino %lu, mode %o\n",
		  (unsigned long)dir->i_ino, mode);
#endif /* CONFIG_SSDFS_DEBUG */

	itree = fsi->inodes_tree;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto failed_new_inode;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_inodes_btree_allocate(itree, &ino, search);
	ssdfs_btree_search_free(search);

	if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to allocate an inode: "
			  "dir_ino %lu, err %d\n",
			  (unsigned long)dir->i_ino, err);
#endif /* CONFIG_SSDFS_DEBUG */
		goto failed_new_inode;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to allocate an inode: "
			  "dir_ino %lu, err %d\n",
			  (unsigned long)dir->i_ino, err);
		goto failed_new_inode;
	}

	inode = new_inode(sb);
	if (unlikely(!inode)) {
		err = -ENOMEM;
		SSDFS_ERR("unable to allocate inode: err %d\n", err);
		goto failed_new_inode;
	}

	ssdfs_init_inode(dir, inode, mode, ino, qstr);

	err = ssdfs_inode_setops(inode);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set inode's operations: "
			  "err %d\n", err);
		goto bad_inode;
	}

	if (insert_inode_locked(inode) < 0) {
		err = -EIO;
		SSDFS_ERR("inode number already in use: "
			  "ino %lu\n",
			  (unsigned long) ino);
		goto bad_inode;
	}

	err = ssdfs_init_acl(inode, dir);
	if (err) {
		SSDFS_ERR("fail to init ACL: "
			  "err %d\n", err);
		goto fail_drop;
	}

	err = ssdfs_init_security(inode, dir, qstr);
	if (err) {
		SSDFS_ERR("fail to init security xattr: "
			  "err %d\n", err);
		goto fail_drop;
	}

	mark_inode_dirty(inode);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("new inode %lu is created\n",
		  ino);
#endif /* CONFIG_SSDFS_DEBUG */

	trace_ssdfs_inode_new(inode);
	return inode;

fail_drop:
	trace_ssdfs_inode_new_exit(inode, err);
	clear_nlink(inode);
	unlock_new_inode(inode);
	iput(inode);
	return ERR_PTR(err);

bad_inode:
	trace_ssdfs_inode_new_exit(inode, err);
	make_bad_inode(inode);
	iput(inode);

failed_new_inode:
	return ERR_PTR(err);
}

int ssdfs_getattr(struct user_namespace *mnt_userns,
		  const struct path *path, struct kstat *stat,
		  u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	unsigned int flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	flags = ii->flags & SSDFS_FL_USER_VISIBLE;
	if (flags & SSDFS_APPEND_FL)
		stat->attributes |= STATX_ATTR_APPEND;
	if (flags & SSDFS_COMPR_FL)
		stat->attributes |= STATX_ATTR_COMPRESSED;
	if (flags & SSDFS_IMMUTABLE_FL)
		stat->attributes |= STATX_ATTR_IMMUTABLE;
	if (flags & SSDFS_NODUMP_FL)
		stat->attributes |= STATX_ATTR_NODUMP;

	stat->attributes_mask |= (STATX_ATTR_APPEND |
				  STATX_ATTR_COMPRESSED |
				  STATX_ATTR_ENCRYPTED |
				  STATX_ATTR_IMMUTABLE |
				  STATX_ATTR_NODUMP);

	generic_fillattr(&init_user_ns, inode, stat);
	return 0;
}

static int ssdfs_truncate(struct inode *inode)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_extents_btree_info *tree = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	      S_ISLNK(inode->i_mode)))
		return -EINVAL;

	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;

	if (is_ssdfs_file_inline(ii)) {
		loff_t newsize = i_size_read(inode);
		size_t inline_capacity =
				ssdfs_inode_inline_file_capacity(inode);

		if (newsize > inline_capacity) {
			SSDFS_ERR("newsize %llu > inline_capacity %zu\n",
				  (u64)newsize, inline_capacity);
			return -E2BIG;
		} else if (newsize == inline_capacity) {
			/* do nothing */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("newsize %llu == inline_capacity %zu\n",
				  (u64)newsize, inline_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			loff_t size = inline_capacity - newsize;

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!ii->inline_file);
#endif /* CONFIG_SSDFS_DEBUG */

			memset((u8 *)ii->inline_file + newsize, 0, size);
		}
	} else {
		tree = SSDFS_EXTREE(ii);
		if (!tree) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("extents tree is absent: ino %lu\n",
				  ii->vfs_inode.i_ino);
#endif /* CONFIG_SSDFS_DEBUG */
			return -ENOENT;
		}

		switch (atomic_read(&tree->state)) {
		case SSDFS_EXTENTS_BTREE_DIRTY:
			down_write(&ii->lock);
			err = ssdfs_extents_tree_flush(fsi, ii);
			up_write(&ii->lock);

			if (unlikely(err)) {
				SSDFS_ERR("fail to flush extents tree: "
					  "ino %lu, err %d\n",
					  inode->i_ino, err);
				return err;
			}
			break;

		default:
			/* do nothing */
			break;
		}

		err = ssdfs_extents_tree_truncate(inode);
		if (unlikely(err)) {
			SSDFS_ERR("fail to truncate extents tree: "
				  "err %d\n",
				  err);
			return err;
		}
	}

	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);

	return 0;
}

int ssdfs_setsize(struct inode *inode, struct iattr *attr)
{
	loff_t oldsize = i_size_read(inode);
	loff_t newsize = attr->ia_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	    S_ISLNK(inode->i_mode)))
		return -EINVAL;

	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;

	inode_dio_wait(inode);

	if (newsize > oldsize) {
		i_size_write(inode, newsize);
		pagecache_isize_extended(inode, oldsize, newsize);
	} else {
		truncate_setsize(inode, newsize);

		err = ssdfs_truncate(inode);
		if (err)
			return err;
	}

	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);
	return 0;
}

int ssdfs_setattr(struct user_namespace *mnt_userns,
		  struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	err = setattr_prepare(&init_user_ns, dentry, attr);
	if (err)
		return err;

	if (S_ISREG(inode->i_mode) &&
	    attr->ia_valid & ATTR_SIZE &&
	    attr->ia_size != inode->i_size) {
		err = ssdfs_setsize(inode, attr);
		if (err)
			return err;
	}

	if (attr->ia_valid) {
		setattr_copy(&init_user_ns, inode, attr);
		mark_inode_dirty(inode);

		if (attr->ia_valid & ATTR_MODE) {
			err = posix_acl_chmod(&init_user_ns,
					      dentry, inode->i_mode);
		}
	}

	return err;
}

/*
 * This method does all fs work to be done when in-core inode
 * is about to be gone, for whatever reason.
 */
void ssdfs_evict_inode(struct inode *inode)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_xattrs_btree_info *xattrs_tree;
	ino_t ino = inode->i_ino;
	bool want_delete = false;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu mode %o count %d nlink %u\n",
		  ino, inode->i_mode,
		  atomic_read(&inode->i_count),
		  inode->i_nlink);
#endif /* CONFIG_SSDFS_DEBUG */

	xattrs_tree = SSDFS_XATTREE(SSDFS_I(inode));

	if (!inode->i_nlink) {
		err = filemap_flush(inode->i_mapping);
		if (err) {
			SSDFS_WARN("inode %lu flush error: %d\n",
				   ino, err);
		}
	}

	err = filemap_fdatawait(inode->i_mapping);
	if (err) {
		SSDFS_WARN("inode %lu fdatawait error: %d\n",
			   ino, err);
		ssdfs_clear_dirty_pages(inode->i_mapping);
	}

	if (!inode->i_nlink && !is_bad_inode(inode))
		want_delete = true;
	else
		want_delete = false;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu mode %o count %d nlink %u, "
		  "is_bad_inode %#x, want_delete %#x\n",
		  ino, inode->i_mode,
		  atomic_read(&inode->i_count),
		  inode->i_nlink,
		  is_bad_inode(inode),
		  want_delete);
#endif /* CONFIG_SSDFS_DEBUG */

	trace_ssdfs_inode_evict(inode);

	truncate_inode_pages_final(&inode->i_data);

	if (want_delete) {
		sb_start_intwrite(inode->i_sb);

		i_size_write(inode, 0);

		err = ssdfs_truncate(inode);
		if (err == -ENOENT) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("extents tree is absent: ino %lu\n",
				  ino);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (err) {
			SSDFS_WARN("fail to truncate inode: "
				   "ino %lu, err %d\n",
				   ino, err);
		}

		if (xattrs_tree) {
			err = ssdfs_xattrs_tree_delete_all(xattrs_tree);
			if (err) {
				SSDFS_WARN("fail to truncate xattrs tree: "
					   "ino %lu, err %d\n",
					   ino, err);
			}
		}
	}

	clear_inode(inode);

	if (want_delete) {
		err = ssdfs_inodes_btree_delete(fsi->inodes_tree, ino);
		if (err) {
			SSDFS_WARN("fail to deallocate raw inode: "
				   "ino %lu, err %d\n",
				   ino, err);
		}

		sb_end_intwrite(inode->i_sb);
	}
}

/*
 * This method is called when the VFS needs to write an
 * inode to disc
 */
int ssdfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(inode->i_sb);
	struct ssdfs_inode_info *ii = SSDFS_I(inode);
	struct ssdfs_inode *ri = &ii->raw_inode;
	struct ssdfs_inodes_btree_info *itree;
	struct ssdfs_btree_search *search;
	struct ssdfs_dentries_btree_descriptor dentries_btree;
	bool has_save_dentries_desc = true;
	size_t dentries_desc_size =
		sizeof(struct ssdfs_dentries_btree_descriptor);
	struct ssdfs_extents_btree_descriptor extents_btree;
	bool has_save_extents_desc = true;
	size_t extents_desc_size =
		sizeof(struct ssdfs_extents_btree_descriptor);
	struct ssdfs_xattr_btree_descriptor xattr_btree;
	bool has_save_xattrs_desc = true;
	size_t xattr_desc_size =
		sizeof(struct ssdfs_xattr_btree_descriptor);
	int private_flags;
	size_t raw_inode_size;
	ino_t ino;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&fsi->volume_sem);
	raw_inode_size = le16_to_cpu(fsi->vs->inodes_btree.desc.item_size);
	ssdfs_memcpy(&dentries_btree, 0, dentries_desc_size,
		     &fsi->vh->dentries_btree, 0, dentries_desc_size,
		     dentries_desc_size);
	ssdfs_memcpy(&extents_btree, 0, extents_desc_size,
		     &fsi->vh->extents_btree, 0, extents_desc_size,
		     extents_desc_size);
	ssdfs_memcpy(&xattr_btree, 0, xattr_desc_size,
		     &fsi->vh->xattr_btree, 0, xattr_desc_size,
		     xattr_desc_size);
	up_read(&fsi->volume_sem);

	if (raw_inode_size != sizeof(struct ssdfs_inode)) {
		SSDFS_WARN("raw_inode_size %zu != size %zu\n",
			   raw_inode_size,
			   sizeof(struct ssdfs_inode));
		return -ERANGE;
	}

	itree = fsi->inodes_tree;
	ino = inode->i_ino;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);

	err = ssdfs_inodes_btree_find(itree, ino, search);
	if (unlikely(err)) {
#ifdef CONFIG_SSDFS_TESTING
		err = 0;
		SSDFS_DBG("fail to find inode: "
			  "ino %lu, err %d\n",
			  ino, err);
#else
		SSDFS_ERR("fail to find inode: "
			  "ino %lu, err %d\n",
			  ino, err);
#endif /* CONFIG_SSDFS_TESTING */
		goto free_search_object;
	}

	down_write(&ii->lock);

	ssdfs_init_raw_inode(ii);

	if (S_ISREG(inode->i_mode) && ii->extents_tree) {
		err = ssdfs_extents_tree_flush(fsi, ii);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush extents tree: "
				  "ino %lu, err %d\n",
				  inode->i_ino, err);
			goto finish_write_inode;
		}

		if (memcmp(&extents_btree, &ii->extents_tree->desc,
						extents_desc_size) != 0) {
			ssdfs_memcpy(&extents_btree,
				     0, extents_desc_size,
				     &ii->extents_tree->desc,
				     0, extents_desc_size,
				     extents_desc_size);
			has_save_extents_desc = true;
		} else
			has_save_extents_desc = false;
	} else if (S_ISDIR(inode->i_mode) && ii->dentries_tree) {
		err = ssdfs_dentries_tree_flush(fsi, ii);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush dentries tree: "
				  "ino %lu, err %d\n",
				  inode->i_ino, err);
			goto finish_write_inode;
		}

		if (memcmp(&dentries_btree, &ii->dentries_tree->desc,
						dentries_desc_size) != 0) {
			ssdfs_memcpy(&dentries_btree,
				     0, dentries_desc_size,
				     &ii->dentries_tree->desc,
				     0, dentries_desc_size,
				     dentries_desc_size);
			has_save_dentries_desc = true;
		} else
			has_save_dentries_desc = false;
	}

	if (ii->xattrs_tree) {
		err = ssdfs_xattrs_tree_flush(fsi, ii);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush xattrs tree: "
				  "ino %lu, err %d\n",
				  inode->i_ino, err);
			goto finish_write_inode;
		}

		if (memcmp(&xattr_btree, &ii->xattrs_tree->desc,
						xattr_desc_size) != 0) {
			ssdfs_memcpy(&xattr_btree,
				     0, xattr_desc_size,
				     &ii->xattrs_tree->desc,
				     0, xattr_desc_size,
				     xattr_desc_size);
			has_save_xattrs_desc = true;
		} else
			has_save_xattrs_desc = false;
	}

	private_flags = atomic_read(&ii->private_flags);
	if (private_flags & ~SSDFS_INODE_PRIVATE_FLAGS_MASK) {
		err = -ERANGE;
		SSDFS_WARN("invalid set of private_flags %#x\n",
			   private_flags);
		goto finish_write_inode;
	} else
		ri->private_flags = cpu_to_le16((u16)private_flags);

	ri->checksum = ssdfs_crc32_le(ri, raw_inode_size);

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid result's buffer state: "
			  "%#x\n",
			  search->result.buf_state);
		goto finish_write_inode;
	}

	if (!search->result.buf) {
		err = -ERANGE;
		SSDFS_ERR("invalid buffer\n");
		goto finish_write_inode;
	}

	if (search->result.buf_size < raw_inode_size) {
		err = -ERANGE;
		SSDFS_ERR("buf_size %zu < raw_inode_size %zu\n",
			  search->result.buf_size,
			  raw_inode_size);
		goto finish_write_inode;
	}

	if (search->result.items_in_buffer != 1) {
		SSDFS_WARN("unexpected value: "
			   "items_in_buffer %u\n",
			   search->result.items_in_buffer);
	}

	ssdfs_memcpy(search->result.buf, 0, search->result.buf_size,
		     ri, 0, raw_inode_size,
		     raw_inode_size);

finish_write_inode:
	up_write(&ii->lock);

	if (unlikely(err))
		goto free_search_object;

	if (has_save_dentries_desc || has_save_extents_desc ||
						has_save_xattrs_desc) {
		down_write(&fsi->volume_sem);
		ssdfs_memcpy(&fsi->vh->dentries_btree,
			     0, dentries_desc_size,
			     &dentries_btree,
			     0, dentries_desc_size,
			     dentries_desc_size);
		ssdfs_memcpy(&fsi->vh->extents_btree,
			     0, extents_desc_size,
			     &extents_btree,
			     0, extents_desc_size,
			     extents_desc_size);
		ssdfs_memcpy(&fsi->vh->xattr_btree,
			     0, xattr_desc_size,
			     &xattr_btree,
			     0, xattr_desc_size,
			     xattr_desc_size);
		up_write(&fsi->volume_sem);
	}

	err = ssdfs_inodes_btree_change(itree, ino, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change inode: "
			  "ino %lu, err %d\n",
			  ino, err);
		goto free_search_object;
	}

free_search_object:
	ssdfs_btree_search_free(search);

	return err;
}

/*
 * This method is called when the VFS needs
 * to get filesystem statistics
 */
int ssdfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
#ifdef CONFIG_SSDFS_BLOCK_DEVICE
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);
#endif
	u64 nsegs;
	u32 pages_per_seg;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu\n", (unsigned long)dentry->d_inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	buf->f_type = SSDFS_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_frsize = buf->f_bsize;

	mutex_lock(&fsi->resize_mutex);
	nsegs = fsi->nsegs;
	mutex_unlock(&fsi->resize_mutex);

	pages_per_seg = fsi->pages_per_seg;
	buf->f_blocks = nsegs * pages_per_seg;

	spin_lock(&fsi->volume_state_lock);
	buf->f_bfree = fsi->free_pages;
	spin_unlock(&fsi->volume_state_lock);

	buf->f_bavail = buf->f_bfree;

	spin_lock(&fsi->inodes_tree->lock);
	buf->f_files = fsi->inodes_tree->allocated_inodes;
	buf->f_ffree = fsi->inodes_tree->free_inodes;
	spin_unlock(&fsi->inodes_tree->lock);

	buf->f_namelen = SSDFS_MAX_NAME_LEN;

#ifdef CONFIG_SSDFS_MTD_DEVICE
	buf->f_fsid.val[0] = SSDFS_SUPER_MAGIC;
	buf->f_fsid.val[1] = fsi->mtd->index;
#elif defined(CONFIG_SSDFS_BLOCK_DEVICE)
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
#else
	BUILD_BUG();
#endif

	return 0;
}
