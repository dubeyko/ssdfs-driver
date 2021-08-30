//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/testing.c - testing infrastructure.
 *
 * Copyright (c) 2019-2021 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/slab.h>
#include <linux/pagevec.h>
#include <linux/wait.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "offset_translation_table.h"
#include "page_array.h"
#include "peb.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"
#include "dentries_tree.h"
#include "inodes_tree.h"
#include "testing.h"

static
void ssdfs_testing_invalidatepage(struct page *page, unsigned int offset,
				  unsigned int length)
{
	SSDFS_DBG("do nothing: page_index %llu, offset %u, length %u\n",
		  (u64)page_index(page), offset, length);
}

static
int ssdfs_testing_releasepage(struct page *page, gfp_t mask)
{
	SSDFS_DBG("do nothing: page_index %llu, mask %#x\n",
		  (u64)page_index(page), mask);

	return 0;
}

const struct address_space_operations ssdfs_testing_aops = {
	.invalidatepage	= ssdfs_testing_invalidatepage,
	.releasepage	= ssdfs_testing_releasepage,
	.set_page_dirty	= __set_page_dirty_nobuffers,
};

/*
 * ssdfs_testing_mapping_init() - mapping init
 */
static inline
void ssdfs_testing_mapping_init(struct address_space *mapping,
				struct inode *inode)
{
	address_space_init_once(mapping);
	mapping->a_ops = &ssdfs_testing_aops;
	mapping->host = inode;
	mapping->flags = 0;
	atomic_set(&mapping->i_mmap_writable, 0);
	mapping_set_gfp_mask(mapping, GFP_KERNEL);
	mapping->private_data = NULL;
	mapping->writeback_index = 0;
	inode->i_mapping = mapping;
}

static const struct inode_operations def_testing_ino_iops;
static const struct file_operations def_testing_ino_fops;
static const struct address_space_operations def_testing_ino_aops;

/*
 * ssdfs_testing_get_inode() - create testing inode object
 * @fsi: file system info object
 */
static
int ssdfs_testing_get_inode(struct ssdfs_fs_info *fsi)
{
	struct inode *inode;
	struct ssdfs_inode_info *ii;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	inode = iget_locked(fsi->sb, SSDFS_TESTING_INO);
	if (unlikely(!inode)) {
		err = -ENOMEM;
		SSDFS_ERR("unable to allocate testing inode: "
			  "err %d\n",
			  err);
		return err;
	}

	BUG_ON(!(inode->i_state & I_NEW));

	inode->i_mode = S_IFREG;
	mapping_set_gfp_mask(inode->i_mapping, GFP_KERNEL);

	inode->i_op = &def_testing_ino_iops;
	inode->i_fop = &def_testing_ino_fops;
	inode->i_mapping->a_ops = &def_testing_ino_aops;

	ii = SSDFS_I(inode);
	ii->birthtime = current_time(inode);
	ii->parent_ino = U64_MAX;

	unlock_new_inode(inode);

	fsi->testing_inode = inode;

	return 0;
}

static
int ssdfs_testing_extents_tree_add_block(struct ssdfs_fs_info *fsi,
					 u64 logical_offset,
					 u64 seg_id,
					 u64 logical_blk,
					 u32 page_size)
{
	struct ssdfs_segment_request *req;
	ino_t ino;
	int err = 0;

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto finish_add_block;
	}

	ssdfs_request_init(req);
	ssdfs_get_request(req);

	(req)->private.flags |= SSDFS_REQ_DONT_FREE_PAGES;

	ino = fsi->testing_inode->i_ino;

	ssdfs_request_prepare_logical_extent(ino, (u64)logical_offset,
					     page_size, 0, 0, req);

	ssdfs_request_define_segment(seg_id, req);
	ssdfs_request_define_volume_extent(logical_blk, 1, req);

	err = ssdfs_extents_tree_add_extent(fsi->testing_inode, req);
	if (err) {
		SSDFS_ERR("fail to add extent: "
			  "ino %lu, logical_offset %llu, "
			  "seg_id %llu, logical_blk %llu, err %d\n",
			  ino, (u64)logical_offset,
			  seg_id, (u64)logical_blk, err);
		goto free_request;
	}

	inode_add_bytes(fsi->testing_inode, page_size);

free_request:
	ssdfs_put_request(req);
	ssdfs_request_free(req);

finish_add_block:
	return err;
}

static
int ssdfs_do_extents_tree_testing(struct ssdfs_fs_info *fsi,
				  struct ssdfs_testing_environment *env)
{
	struct ssdfs_inode_info *ii;
	u64 seg_id = 1;
	u64 logical_blk = 0;
	s64 logical_offset = 0;
	u64 threshold = env->file_size_threshold;
	u32 page_size = env->page_size;
	u16 extent_len_max = env->extent_len_threshold;
	u32 extent_len = 1;
	u64 per_1_percent = 0;
	u64 message_threshold = 0;
	u64 processed_bytes = 0;
	int err = 0;

	fsi->do_fork_invalidation = false;

	ii = SSDFS_I(fsi->testing_inode);

	down_write(&ii->lock);
	err = ssdfs_extents_tree_create(fsi, ii);
	up_write(&ii->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to create the extents tree: "
			  "err %d\n", err);
		goto finish_testing;
	}

	per_1_percent = div_u64(threshold, 100);
	message_threshold = per_1_percent;

	SSDFS_ERR("ADD LOGICAL BLOCK: 0%%\n");

	for (logical_offset = 0; logical_offset < threshold;
					logical_offset += page_size) {
		SSDFS_DBG("ADD LOGICAL BLOCK: "
			  "logical_offset %lld, seg_id %llu, "
			  "logical_blk %llu\n",
			  logical_offset, seg_id, logical_blk);

		if (logical_offset >= message_threshold) {
			SSDFS_ERR("ADD LOGICAL BLOCK: %llu%%\n",
				  div64_u64(logical_offset, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_extents_tree_add_block(fsi,
							   logical_offset,
							   seg_id,
							   logical_blk,
							   page_size);
		if (err) {
			SSDFS_ERR("fail to add logical block: "
				  "err %d\n", err);
			goto destroy_tree;
		}

		if (extent_len < extent_len_max) {
			logical_blk++;
			extent_len++;
		} else {
			seg_id++;
			logical_blk = 0;
			extent_len = 1;
		}
	}

	SSDFS_ERR("ADD LOGICAL BLOCK: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	message_threshold = per_1_percent;

	SSDFS_ERR("CHECK LOGICAL BLOCK: 0%%\n");

	for (logical_offset = 0; logical_offset < threshold;
					logical_offset += page_size) {
		SSDFS_DBG("CHECK LOGICAL BLOCK: "
			  "logical_offset %lld\n",
			  logical_offset);

		if (logical_offset >= message_threshold) {
			SSDFS_ERR("CHECK LOGICAL BLOCK: %llu%%\n",
				  div64_u64(logical_offset, per_1_percent));

			message_threshold += per_1_percent;
		}

		logical_blk = div_u64(logical_offset, page_size);

		if (!ssdfs_extents_tree_has_logical_block(logical_blk,
							  fsi->testing_inode)) {
			err = -ENOENT;
			SSDFS_ERR("fail to find: "
				  "logical_offset %lld, "
				  "logical_blk %llx\n",
				  logical_offset,
				  logical_blk);
			goto destroy_tree;
		}
	}

	SSDFS_ERR("CHECK LOGICAL BLOCK: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	message_threshold = per_1_percent;

	SSDFS_ERR("TRUNCATE LOGICAL BLOCK: 0%%\n");

	for (logical_offset = threshold - page_size;
			logical_offset >= 0; logical_offset -= page_size,
					     processed_bytes += page_size) {
		SSDFS_DBG("TRUNCATE LOGICAL BLOCK: "
			  "logical_offset %lld\n",
			  logical_offset);

		if (processed_bytes >= message_threshold) {
			SSDFS_ERR("TRUNCATE LOGICAL BLOCK: %llu%%\n",
				  div64_u64(processed_bytes, per_1_percent));

			message_threshold += per_1_percent;
		}

		truncate_setsize(fsi->testing_inode, logical_offset);

		down_write(&SSDFS_I(fsi->testing_inode)->lock);
		err = ssdfs_extents_tree_truncate(fsi->testing_inode);
		up_write(&SSDFS_I(fsi->testing_inode)->lock);

		if (err) {
			SSDFS_ERR("fail to truncate logical block: "
				  "err %d\n", err);
			goto destroy_tree;
		}
	}

	SSDFS_ERR("TRUNCATE LOGICAL BLOCK: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

destroy_tree:
	ssdfs_extents_tree_destroy(ii);

finish_testing:
	fsi->do_fork_invalidation = true;
	return err;
}

static inline
int ssdfs_testing_prepare_file_name(u64 file_index,
				    unsigned char *name_buf,
				    size_t *name_len)
{
	memset(name_buf, 0, SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
	*name_len = snprintf(name_buf, SSDFS_DENTRY_INLINE_NAME_MAX_LEN,
			     "%llu.txt", file_index + 1);

	if (*name_len <= 0 || *name_len > SSDFS_DENTRY_INLINE_NAME_MAX_LEN) {
		SSDFS_ERR("fail to prepare file name: "
			  "file_index %llu\n",
			  file_index);
		return -ERANGE;
	}

	return 0;
}

static
int ssdfs_testing_dentries_tree_add_file(struct ssdfs_fs_info *fsi,
					 struct inode *root_i,
					 u64 file_index,
					 unsigned char *name_buf)
{
	struct ssdfs_inode_info *ii;
	struct dentry *dentry_dir = NULL, *dentry_inode = NULL;
	struct qstr qstr_dname;
	size_t name_len = 0;
	int err = 0;

	ii = SSDFS_I(root_i);

	err = ssdfs_testing_prepare_file_name(file_index, name_buf,
					      &name_len);
	if (err) {
		SSDFS_ERR("fail to prepare name: "
			  "file_index %llu, err %d\n",
			  file_index, err);
		return err;
	}

	dentry_dir = d_find_alias(root_i);
	if (!dentry_dir) {
		SSDFS_ERR("fail to find root alias\n");
		goto finish_add_file;
	}

	qstr_dname.name = name_buf;
	qstr_dname.len = name_len;
	qstr_dname.hash = full_name_hash(dentry_dir, qstr_dname.name, qstr_dname.len);

	dentry_inode = d_alloc(dentry_dir, &qstr_dname);
	if (!dentry_inode) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate dentry: "
			  "file_index %llu\n",
			  file_index);
		goto finish_add_file;
	}

	SSDFS_DBG("hash %llx, parent %p\n",
		  (u64)dentry_inode->d_name.hash,
		  dentry_inode->d_parent);

	err = ssdfs_create(root_i, dentry_inode, S_IFREG | S_IRWXU, false);
	if (err) {
		SSDFS_ERR("fail to create file: "
			  "file_index %llu\n",
			  file_index);
		goto finish_add_file;
	}

	d_drop(dentry_inode);
	dput(dentry_inode);
	iput(d_inode(dentry_inode));

	dput(dentry_dir);

	return 0;

finish_add_file:
	if (dentry_inode) {
		d_drop(dentry_inode);
		dput(dentry_inode);
		iput(d_inode(dentry_inode));

		dput(dentry_dir);
	}

	return err;
}

static
int ssdfs_testing_dentries_tree_check_file(struct ssdfs_fs_info *fsi,
					   struct inode *root_i,
					   u64 file_index,
					   unsigned char *name_buf)
{
	struct qstr qstr_dname;
	size_t name_len = 0;
	ino_t ino;
	int err = 0;

	err = ssdfs_testing_prepare_file_name(file_index, name_buf,
					      &name_len);
	if (err) {
		SSDFS_ERR("fail to prepare name: "
			  "file_index %llu, err %d\n",
			  file_index, err);
		return err;
	}

	qstr_dname.name = name_buf;
	qstr_dname.len = name_len;
	qstr_dname.hash = full_name_hash(fsi->sb->s_root,
					 qstr_dname.name,
					 qstr_dname.len);

	err = ssdfs_inode_by_name(root_i,
				  &qstr_dname, &ino);
	if (err) {
		SSDFS_ERR("fail to find file: "
			  "file_index %llu\n",
			  file_index);
		return err;
	}

	return 0;
}

static
int ssdfs_testing_dentries_tree_delete_file(struct ssdfs_fs_info *fsi,
					    struct inode *root_i,
					    u64 file_index,
					    unsigned char *name_buf)
{
	struct qstr qstr_dname;
	struct dentry *dir;
	struct ssdfs_inode_info *ii;
	struct ssdfs_btree_search *search;
	size_t name_len = 0;
	u64 name_hash;
	ino_t ino;
	int err = 0;

	ii = SSDFS_I(root_i);

	err = ssdfs_testing_prepare_file_name(file_index, name_buf,
					      &name_len);
	if (err) {
		SSDFS_ERR("fail to prepare name: "
			  "file_index %llu, err %d\n",
			  file_index, err);
		return err;
	}

	dir = d_find_alias(root_i);
	if (!dir) {
		SSDFS_ERR("fail to find root alias\n");
		return -ENOENT;
	}

	qstr_dname.name = name_buf;
	qstr_dname.len = name_len;
	qstr_dname.hash = full_name_hash(dir, qstr_dname.name, qstr_dname.len);

	name_hash = ssdfs_generate_name_hash((struct qstr *)&qstr_dname);
	if (name_hash >= U64_MAX) {
		SSDFS_ERR("invalid name hash\n");
		return -ERANGE;
	}

	err = ssdfs_inode_by_name(root_i,
				  &qstr_dname, &ino);
	if (err) {
		SSDFS_ERR("fail to find file: "
			  "file_index %llu\n",
			  file_index);
		return err;
	}

	down_read(&ii->lock);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_delete_dentry;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_dentries_tree_delete(ii->dentries_tree,
					 name_hash,
					 ino,
					 search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to delete the dentry: "
			  "name_hash %llx, ino %lu, err %d\n",
			  name_hash, ino, err);
	}

finish_delete_dentry:
	up_read(&ii->lock);

	dput(dir);

	if (unlikely(err))
		return err;

	err = ssdfs_inodes_btree_delete(fsi->inodes_tree, ino);
	if (err) {
		SSDFS_ERR("fail to deallocate raw inode: "
			   "ino %lu, err %d\n",
			   ino, err);
	}

	return err;
}

static
int ssdfs_do_dentries_tree_testing(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env)
{
	struct inode *root_i;
	struct ssdfs_inode_info *ii;
	u64 threshold;
	u64 per_1_percent = 0;
	u64 message_threshold = 0;
	u64 file_index;
	unsigned char name[SSDFS_DENTRY_INLINE_NAME_MAX_LEN];
	int err = 0;

	root_i = ssdfs_iget(fsi->sb, SSDFS_ROOT_INO);
	if (IS_ERR(root_i)) {
		SSDFS_ERR("getting root inode failed\n");
		err = PTR_ERR(root_i);
		goto finish_testing;
	}

	ii = SSDFS_I(root_i);

	threshold = env->files_number_threshold;
	per_1_percent = div_u64(threshold, 100);
	message_threshold = per_1_percent;

	SSDFS_ERR("ADD FILE: 0%%\n");

	for (file_index = 0; file_index < threshold; file_index++) {
		SSDFS_DBG("ADD FILE: file_index %llu\n",
			  file_index);

		if (file_index >= message_threshold) {
			SSDFS_ERR("ADD FILE: %llu%%\n",
				  div64_u64(file_index, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_dentries_tree_add_file(fsi, root_i,
							   file_index,
							   name);
		if (err) {
			SSDFS_ERR("fail to create file: "
				  "err %d\n", err);
			goto put_root_inode;
		}
	}

	SSDFS_ERR("ADD FILE: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	message_threshold = per_1_percent;

	SSDFS_ERR("CHECK FILE: 0%%\n");

	for (file_index = 0; file_index < threshold; file_index++) {
		SSDFS_DBG("CHECK FILE: file_index %llu\n",
			  file_index);

		if (file_index >= message_threshold) {
			SSDFS_ERR("CHECK FILE: %llu%%\n",
				  div64_u64(file_index, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_dentries_tree_check_file(fsi, root_i,
							     file_index,
							     name);
		if (err) {
			SSDFS_ERR("fail to check file: "
				  "err %d\n", err);
			goto put_root_inode;
		}
	}

	SSDFS_ERR("CHECK FILE: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	SSDFS_ERR("FLUSH DENTRIES BTREE: starting...\n");

	down_write(&ii->lock);
	err = ssdfs_dentries_tree_flush(fsi, ii);
	up_write(&ii->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to flush dentries tree: "
			  "ino %lu, err %d\n",
			  root_i->i_ino, err);
		goto put_root_inode;
	}

	SSDFS_ERR("FLUSH DENTRIES BTREE: finished\n");

	message_threshold = per_1_percent;

	SSDFS_ERR("DELETE FILE: 0%%\n");

	for (file_index = 0; file_index < threshold; file_index++) {
		SSDFS_DBG("DELETE FILE: file_index %llu\n",
			  file_index);

		if (file_index >= message_threshold) {
			SSDFS_ERR("DELETE FILE: %llu%%\n",
				  div64_u64(file_index, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_dentries_tree_delete_file(fsi, root_i,
							      file_index,
							      name);
		if (err) {
			SSDFS_ERR("fail to delete file: "
				  "err %d\n", err);
			goto put_root_inode;
		}
	}

	SSDFS_ERR("DELETE FILE: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

put_root_inode:
	iput(root_i);

finish_testing:
	return err;
}

int ssdfs_do_testing(struct ssdfs_fs_info *fsi,
		     struct ssdfs_testing_environment *env)
{
	int err = 0;

	SSDFS_ERR("TESTING STARTING...\n");

	err = ssdfs_testing_get_inode(fsi);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create testing inode: "
			  "err %d\n", err);
		goto finish_testing;
	}

	ssdfs_testing_mapping_init(&fsi->testing_pages,
				   fsi->testing_inode);

	if (env->subsystems & SSDFS_ENABLE_EXTENTS_TREE_TESTING) {
		SSDFS_ERR("START EXTENTS TREE TESTING...\n");

		err = ssdfs_do_extents_tree_testing(fsi, env);
		if (err)
			goto free_inode;

		SSDFS_ERR("EXTENTS TREE TESTING FINISHED\n");
	}

	if (env->subsystems & SSDFS_ENABLE_DENTRIES_TREE_TESTING) {
		SSDFS_ERR("START DENTRIES TREE TESTING...\n");

		err = ssdfs_do_dentries_tree_testing(fsi, env);
		if (err)
			goto free_inode;

		SSDFS_ERR("DENTRIES TREE TESTING FINISHED\n");
	}

free_inode:
	iput(fsi->testing_inode);

finish_testing:
	if (err)
		SSDFS_ERR("TESTING FAILED\n");
	else
		SSDFS_ERR("TESTING FINISHED\n");

	return err;
}
