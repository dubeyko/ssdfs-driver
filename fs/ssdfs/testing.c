//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/testing.c - testing infrastructure.
 *
 * Copyright (c) 2019-2022 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "extents_queue.h"
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
#include "peb_mapping_table.h"
#include "shared_dictionary.h"
#include "xattr_tree.h"
#include "shared_extents_tree.h"
#include "snapshots_tree.h"
#include "xattr.h"
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
	u64 threshold = env->extents_tree.file_size_threshold;
	u32 page_size = env->page_size;
	u16 extent_len_max = env->extents_tree.extent_len_threshold;
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
	if (per_1_percent == 0)
		per_1_percent = 1;

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

	threshold = env->dentries_tree.files_number_threshold;
	per_1_percent = div_u64(threshold, 100);
	if (per_1_percent == 0)
		per_1_percent = 1;

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

static
int ssdfs_testing_check_block_bitmap_nolock(struct ssdfs_block_bmap *bmap,
					struct ssdfs_testing_environment *env,
					struct ssdfs_block_bmap_range *range,
					int blk_state)
{
	int free_blks;
	int used_blks;
	int invalid_blks;
	int reserved_metadata_blks;
	int calculated;
	int err;

	if (!ssdfs_block_bmap_test_range(bmap, range, blk_state)) {
		SSDFS_ERR("invalid state: "
			  "range (start %u, len %u), "
			  "blk_state %#x\n",
			  range->start, range->len, blk_state);
		return -ERANGE;
	}

	err = ssdfs_block_bmap_get_free_pages(bmap);
	if (unlikely(err < 0)) {
		SSDFS_ERR("fail to get free pages: err %d\n", err);
		return err;
	} else if (unlikely(err >= U16_MAX)) {
		SSDFS_ERR("fail to get free pages: err %d\n", err);
		return -ERANGE;
	} else {
		free_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_used_pages(bmap);
	if (unlikely(err < 0)) {
		SSDFS_ERR("fail to get used pages: err %d\n", err);
		return err;
	} else if (unlikely(err >= U16_MAX)) {
		SSDFS_ERR("fail to get used pages: err %d\n", err);
		return -ERANGE;
	} else {
		used_blks = err;
		err = 0;
	}

	err = ssdfs_block_bmap_get_invalid_pages(bmap);
	if (unlikely(err < 0)) {
		SSDFS_ERR("fail to get invalid pages: err %d\n", err);
		return err;
	} else if (unlikely(err >= U16_MAX)) {
		SSDFS_ERR("fail to get invalid pages: err %d\n", err);
		return -ERANGE;
	} else {
		invalid_blks = err;
		err = 0;
	}

	reserved_metadata_blks = bmap->metadata_items;

	calculated = free_blks + used_blks + invalid_blks;
	calculated += reserved_metadata_blks;

	if (calculated != env->block_bitmap.capacity) {
		SSDFS_ERR("invalid state: "
			  "calculated %d != capacity %u\n",
			  calculated,
			  env->block_bitmap.capacity);
		return -ERANGE;
	}

	return 0;
}

static
int ssdfs_testing_block_bmap_pre_allocation(struct ssdfs_block_bmap *bmap,
					struct ssdfs_testing_environment *env)
{
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err = 0;

	SSDFS_ERR("BLOCK BMAP: try to pre-allocate %u blocks\n",
		  env->block_bitmap.pre_alloc_blks_per_iteration);

	if (env->block_bitmap.pre_alloc_blks_per_iteration >= U32_MAX) {
		err = -EINVAL;
		SSDFS_ERR("invalid pre-alloc blocks %u\n",
			  env->block_bitmap.pre_alloc_blks_per_iteration);
		goto finish_check;
	}

	len = env->block_bitmap.pre_alloc_blks_per_iteration;
	err = ssdfs_block_bmap_pre_allocate(bmap, 0, &len, &range);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre_allocate: err %d\n", err);
		goto finish_check;
	}

	err = ssdfs_testing_check_block_bitmap_nolock(bmap, env, &range,
						      SSDFS_BLK_PRE_ALLOCATED);
	if (unlikely(err)) {
		SSDFS_ERR("pre_allocation check failed: err %d\n", err);
		goto finish_check;
	}

	SSDFS_ERR("BLOCK BMAP: range (start %u, len %u) "
		  "has been pre-allocated\n",
		  range.start, range.len);

finish_check:
	return err;
}

static
int ssdfs_testing_block_bmap_allocation(struct ssdfs_block_bmap *bmap,
					struct ssdfs_testing_environment *env)
{
	struct ssdfs_block_bmap_range range;
	u32 len;
	int err = 0;

	SSDFS_ERR("BLOCK BMAP: try to allocate %u blocks\n",
		  env->block_bitmap.alloc_blks_per_iteration);

	if (env->block_bitmap.alloc_blks_per_iteration >= U32_MAX) {
		err = -EINVAL;
		SSDFS_ERR("invalid alloc blocks %u\n",
			  env->block_bitmap.alloc_blks_per_iteration);
		goto finish_check;
	}

	len = env->block_bitmap.alloc_blks_per_iteration;
	err = ssdfs_block_bmap_allocate(bmap, 0, &len, &range);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate: err %d\n", err);
		goto finish_check;
	}

	err = ssdfs_testing_check_block_bitmap_nolock(bmap, env, &range,
						      SSDFS_BLK_VALID);
	if (unlikely(err)) {
		SSDFS_ERR("allocation check failed: err %d\n", err);
		goto finish_check;
	}

	SSDFS_ERR("BLOCK BMAP: range (start %u, len %u) "
		  "has been allocated\n",
		  range.start, range.len);

finish_check:
	return err;
}

static
int ssdfs_testing_block_bmap_invalidation(struct ssdfs_block_bmap *bmap,
					struct ssdfs_testing_environment *env)
{
	struct ssdfs_block_bmap_range range;
	u32 capacity = env->block_bitmap.capacity;
	u32 start;
	u32 len;
	u32 i;
	int err = 0;

	SSDFS_ERR("BLOCK BMAP: try to invalidate %u blocks\n",
		  env->block_bitmap.invalidate_blks_per_iteration);

	if (env->block_bitmap.invalidate_blks_per_iteration >= U32_MAX) {
		err = -EINVAL;
		SSDFS_ERR("invalid request: "
			  "invalidate_blks_per_iteration %u\n",
			  env->block_bitmap.invalidate_blks_per_iteration);
		goto finish_check;
	}

	start = 0;
	len = env->block_bitmap.invalidate_blks_per_iteration;
	range.start = U32_MAX;
	range.len = 0;

	while (len > 0) {
		for (i = 0; i < len; i++) {
			if (ssdfs_block_bmap_test_block(bmap, start + i,
						    SSDFS_BLK_PRE_ALLOCATED)) {
				if (range.start >= U32_MAX) {
					range.start = start + i;
					range.len = 1;
				} else {
					range.len++;
				}
			} else if (ssdfs_block_bmap_test_block(bmap, start + i,
							    SSDFS_BLK_VALID)) {
				if (range.start >= U32_MAX) {
					range.start = start + i;
					range.len = 1;
				} else {
					range.len++;
				}
			} else
				break;
		}

		if (range.len == 0) {
			start += len;
			continue;
		}

		err = ssdfs_block_bmap_invalidate(bmap, &range);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate: err %d\n", err);
			goto finish_check;
		}

		err = ssdfs_testing_check_block_bitmap_nolock(bmap, env,
							    &range,
							    SSDFS_BLK_INVALID);
		if (unlikely(err)) {
			SSDFS_ERR("invalidation check failed: err %d\n", err);
			goto finish_check;
		}

		SSDFS_ERR("BLOCK BMAP: range (start %u, len %u) "
			  "has been invalidated\n",
			  range.start, range.len);

		start = range.start + range.len;
		len -= range.len;
		range.start = U32_MAX;
		range.len = 0;

		if (start >= capacity)
			break;
	}

finish_check:
	return err;
}

static
int ssdfs_testing_block_bmap_collect_garbage(struct ssdfs_block_bmap *bmap,
					struct ssdfs_testing_environment *env)
{
	struct ssdfs_block_bmap_range range1, range2;
	u32 capacity = env->block_bitmap.capacity;
	int used_blks;
	u32 start1, start2;
	int err = 0;

	err = ssdfs_block_bmap_get_used_pages(bmap);
	if (unlikely(err < 0)) {
		SSDFS_ERR("fail to get used pages: err %d\n", err);
		return err;
	} else if (unlikely(err >= U16_MAX)) {
		SSDFS_ERR("fail to get used pages: err %d\n", err);
		return -ERANGE;
	} else {
		used_blks = err;
		err = 0;
	}

	start1 = 0;
	start2 = 0;
	range1.start = U32_MAX;
	range1.len = 0;
	range2.start = U32_MAX;
	range2.len = 0;

	while (used_blks > 0) {
		SSDFS_DBG("BLOCK BMAP: collect garbage: start1 %u\n",
			  start1);

		err = ssdfs_block_bmap_collect_garbage(bmap, start1, capacity,
							SSDFS_BLK_PRE_ALLOCATED,
							&range1);
		if (err == -ENODATA) {
			err = 0;
			range1.start = U32_MAX;
			range1.len = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to collect garbage: err %d\n", err);
			goto finish_check;
		} else {
			if (!ssdfs_block_bmap_test_range(bmap, &range1,
						SSDFS_BLK_PRE_ALLOCATED)) {
				err = -ERANGE;
				SSDFS_ERR("invalid state: "
					  "range (start %u, len %u), "
					  "blk_state %#x\n",
					  range1.start, range1.len,
					  SSDFS_BLK_PRE_ALLOCATED);
				goto finish_check;
			}

			SSDFS_ERR("BLOCK BMAP: found pre_allocated "
				  "range (start %u, len %u)\n",
				  range1.start, range1.len);
		}

		SSDFS_DBG("BLOCK BMAP: collect garbage: start2 %u\n",
			  start2);

		err = ssdfs_block_bmap_collect_garbage(bmap, start2, capacity,
							SSDFS_BLK_VALID,
							&range2);
		if (err == -ENODATA) {
			err = 0;
			range2.start = U32_MAX;
			range2.len = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to collect garbage: err %d\n", err);
			goto finish_check;
		} else {
			if (!ssdfs_block_bmap_test_range(bmap, &range2,
							SSDFS_BLK_VALID)) {
				err = -ERANGE;
				SSDFS_ERR("invalid state: "
					  "range (start %u, len %u), "
					  "blk_state %#x\n",
					  range2.start, range2.len,
					  SSDFS_BLK_VALID);
				goto finish_check;
			}

			SSDFS_ERR("BLOCK BMAP: found allocated "
				  "range (start %u, len %u)\n",
				  range2.start, range2.len);
		}

		if (range1.len > used_blks) {
			err = -ERANGE;
			SSDFS_ERR("range1.len %u > used_blks %d\n",
				  range1.len, used_blks);
			goto finish_check;
		} else if (range1.len > 0) {
			start1 = range1.start + range1.len;
			used_blks -= range1.len;
		}

		if (range2.len > used_blks) {
			err = -ERANGE;
			SSDFS_ERR("range2.len %u > used_blks %d\n",
				  range2.len, used_blks);
			goto finish_check;
		} else if (range2.len > 0) {
			start2 = range2.start + range2.len;
			used_blks -= range2.len;
		}

		SSDFS_DBG("BLOCK BMAP: start1 %u, start2 %u, used_blks %d\n",
			  start1, start2, used_blks);

		if (range1.len == 0 && range2.len == 0)
			break;

		range1.start = U32_MAX;
		range1.len = 0;
		range2.start = U32_MAX;
		range2.len = 0;

		if (start1 >= capacity && start2 >= capacity)
			break;
	};

	if (used_blks > 0) {
		err = -ERANGE;
		SSDFS_ERR("collect garbage failed: used_blks %d\n",
			  used_blks);
		goto finish_check;
	}

finish_check:
	return err;
}

static
int ssdfs_do_block_bitmap_testing_iteration(struct ssdfs_fs_info *fsi,
					struct ssdfs_block_bmap *bmap,
					struct ssdfs_testing_environment *env)
{
	int err = 0;

	err = ssdfs_block_bmap_lock(bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock bitmap: err %d\n", err);
		goto finish_iteration;
	}

	if (env->block_bitmap.reserved_metadata_blks_per_iteration >= U16_MAX) {
		err = -EINVAL;
		SSDFS_ERR("invalid metadata reservation %u\n",
			env->block_bitmap.reserved_metadata_blks_per_iteration);
		goto unlock_block_bitmap;
	}

	err = ssdfs_block_bmap_reserve_metadata_pages(bmap,
			env->block_bitmap.reserved_metadata_blks_per_iteration);
	if (unlikely(err)) {
		SSDFS_ERR("fail to reserve metadata pages: err %d\n", err);
		goto unlock_block_bitmap;
	}

	err = ssdfs_testing_block_bmap_pre_allocation(bmap, env);
	if (unlikely(err)) {
		SSDFS_ERR("pre_allocation check failed: err %d\n", err);
		goto unlock_block_bitmap;
	}

	err = ssdfs_testing_block_bmap_allocation(bmap, env);
	if (unlikely(err)) {
		SSDFS_ERR("allocation check failed: err %d\n", err);
		goto unlock_block_bitmap;
	}

	err = ssdfs_testing_block_bmap_invalidation(bmap, env);
	if (unlikely(err)) {
		SSDFS_ERR("invalidation check failed: err %d\n", err);
		goto unlock_block_bitmap;
	}

	err = ssdfs_testing_block_bmap_collect_garbage(bmap, env);
	if (unlikely(err)) {
		SSDFS_ERR("collect garbage check failed: err %d\n", err);
		goto unlock_block_bitmap;
	}

unlock_block_bitmap:
	ssdfs_block_bmap_unlock(bmap);

finish_iteration:
	return err;
}

static
int ssdfs_do_block_bitmap_testing(struct ssdfs_fs_info *fsi,
				  struct ssdfs_testing_environment *env)
{
	struct ssdfs_block_bmap bmap;
	int free_blks = 0;
	int err = 0;

	err = ssdfs_block_bmap_create(fsi, &bmap,
				      env->block_bitmap.capacity,
				      SSDFS_BLK_BMAP_CREATE,
				      SSDFS_BLK_FREE);
	if (err) {
		SSDFS_ERR("fail to create file: "
			  "err %d\n", err);
		goto finish_block_bitmap_testing;
	}

	do {
		err = ssdfs_block_bmap_lock(&bmap);
		if (unlikely(err)) {
			SSDFS_ERR("fail to lock bitmap: err %d\n", err);
			goto destroy_block_bitmap;
		}

		err = ssdfs_block_bmap_get_free_pages(&bmap);
		if (unlikely(err < 0)) {
			SSDFS_ERR("fail to get free pages: err %d\n", err);
			goto fail_define_free_pages_count;
		} else if (unlikely(err >= U16_MAX)) {
			err = -ERANGE;
			SSDFS_ERR("fail to get free pages: err %d\n", err);
			goto fail_define_free_pages_count;
		} else {
			free_blks = err;
			err = 0;
		}

		SSDFS_ERR("FREE BLOCKS: %d\n", free_blks);

fail_define_free_pages_count:
		ssdfs_block_bmap_unlock(&bmap);

		if (unlikely(err))
			goto destroy_block_bitmap;

		if (free_blks <= 0)
			break;

		err = ssdfs_do_block_bitmap_testing_iteration(fsi, &bmap, env);
		if (unlikely(err)) {
			SSDFS_ERR("block bitmap testing iteration failed: "
				  "free_blks %d, err %d\n",
				  free_blks, err);
			goto destroy_block_bitmap;
		}
	} while (free_blks > 0);

	err = ssdfs_block_bmap_lock(&bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock bitmap: err %d\n", err);
		goto destroy_block_bitmap;
	}

	err = ssdfs_block_bmap_clean(&bmap);
	ssdfs_block_bmap_clear_dirty_state(&bmap);
	ssdfs_block_bmap_unlock(&bmap);

	if (unlikely(err)) {
		SSDFS_ERR("fail to clean block bitmap: err %d\n",
			  err);
		goto destroy_block_bitmap;
	}

destroy_block_bitmap:
	ssdfs_block_bmap_destroy(&bmap);

finish_block_bitmap_testing:
	return err;
}

static
int ssdfs_do_blk2off_table_testing(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env)
{
	struct ssdfs_blk2off_table *blk2off_tbl;
	u32 capacity = env->blk2off_table.capacity;
	u16 logical_blk;
	s64 sequence_id;
	struct completion *end;
	unsigned long res;
	int err = 0;

	blk2off_tbl = ssdfs_blk2off_table_create(fsi, capacity,
					SSDFS_SEG_OFF_TABLE,
					SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT);
	if (!blk2off_tbl) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory for translation table\n");
		goto finish_blk2off_table_testing;
	}

	logical_blk = 0;
	while ((logical_blk + 1) < capacity) {
		err = ssdfs_blk2off_table_allocate_block(blk2off_tbl,
							 &logical_blk);
		if (err == -EAGAIN) {
			end = &blk2off_tbl->partial_init_end;
			res = wait_for_completion_timeout(end,
							SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("blk2off init failed: "
					  "err %d\n", err);
				goto destroy_blk2off_table;
			}

			err = ssdfs_blk2off_table_allocate_block(blk2off_tbl,
								 &logical_blk);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to allocate logical block\n");
			goto destroy_blk2off_table;
		}

		SSDFS_ERR("ALLOCATED: logical_blk %u, capacity %u\n",
			  logical_blk, capacity);
	}

	for (logical_blk = 0; logical_blk < capacity; logical_blk++) {
		struct ssdfs_block_descriptor blk_desc;
		struct ssdfs_phys_offset_descriptor blk_desc_off;

		SSDFS_ERR("CHANGE OFFSET: logical_blk %u, capacity %u\n",
			  logical_blk, capacity);

		SSDFS_BLK_DESC_INIT(&blk_desc);

		blk_desc.ino = cpu_to_le64(0);
		blk_desc.logical_offset = cpu_to_le32((u32)logical_blk);
		blk_desc.peb_index = cpu_to_le16(0);
		blk_desc.peb_page = cpu_to_le16(0);

		blk_desc.state[0].log_start_page = cpu_to_le16(0);
		blk_desc.state[0].log_area = 0;
		blk_desc.state[0].byte_offset = cpu_to_le32(0);
		blk_desc.state[0].peb_migration_id = 0;

		blk_desc_off.page_desc.logical_offset =
					cpu_to_le32(logical_blk);
		blk_desc_off.page_desc.logical_blk =
					cpu_to_le16(logical_blk);
		blk_desc_off.page_desc.peb_page =
					cpu_to_le16(logical_blk);

		blk_desc_off.blk_state.log_start_page =
					cpu_to_le16(logical_blk);
		blk_desc_off.blk_state.log_area = 0;
		blk_desc_off.blk_state.peb_migration_id = 0;
		blk_desc_off.blk_state.byte_offset =
					cpu_to_le32(logical_blk * PAGE_SIZE);

		err = ssdfs_blk2off_table_change_offset(blk2off_tbl,
							logical_blk,
							0,
							&blk_desc,
							&blk_desc_off);
		if (err == -EAGAIN) {
			end = &blk2off_tbl->full_init_end;

			res = wait_for_completion_timeout(end,
						  SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("blk2off init failed: "
					  "err %d\n", err);
				goto destroy_blk2off_table;
			}

			err = ssdfs_blk2off_table_change_offset(blk2off_tbl,
								logical_blk,
								0,
								&blk_desc,
								&blk_desc_off);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to change offset: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			goto destroy_blk2off_table;
		}
	}

	for (logical_blk = 0; logical_blk < capacity; logical_blk++) {
		struct ssdfs_phys_offset_descriptor *ptr;
		struct ssdfs_offset_position pos = {0};
		u16 peb_index;
		int migration_state;
		u32 logical_offset;
		u16 blk;
		u16 peb_page;
		u16 log_start_page;
		u8 log_area;
		u8 peb_migration_id;
		u32 byte_offset;
		u32 calculated = logical_blk * PAGE_SIZE;

		SSDFS_ERR("CHECK LOGICAL BLOCK: logical_blk %u, capacity %u\n",
			  logical_blk, capacity);

		ptr = ssdfs_blk2off_table_convert(blk2off_tbl,
						  logical_blk,
						  &peb_index,
						  &migration_state,
						  &pos);
		if (IS_ERR(ptr) && PTR_ERR(ptr) == -EAGAIN) {
			end = &blk2off_tbl->full_init_end;

			res = wait_for_completion_timeout(end,
						  SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("blk2off init failed: "
					  "err %d\n", err);
				goto destroy_blk2off_table;
			}

			ptr = ssdfs_blk2off_table_convert(blk2off_tbl,
							  logical_blk,
							  &peb_index,
							  &migration_state,
							  &pos);
		}

		if (IS_ERR_OR_NULL(ptr)) {
			err = (ptr == NULL ? -ERANGE : PTR_ERR(ptr));
			SSDFS_ERR("fail to convert: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			goto destroy_blk2off_table;
		}

		logical_offset = le32_to_cpu(ptr->page_desc.logical_offset);
		if (logical_offset != logical_blk) {
			err = -ERANGE;
			SSDFS_ERR("logical_offset %u != logical_blk %u\n",
				  logical_offset, logical_blk);
			goto destroy_blk2off_table;
		}

		blk = le16_to_cpu(ptr->page_desc.logical_blk);
		if (blk != logical_blk) {
			err = -ERANGE;
			SSDFS_ERR("blk %u != logical_blk %u\n",
				  blk, logical_blk);
			goto destroy_blk2off_table;
		}

		peb_page = le16_to_cpu(ptr->page_desc.peb_page);
		if (peb_page != logical_blk) {
			err = -ERANGE;
			SSDFS_ERR("peb_page %u != logical_blk %u\n",
				  peb_page, logical_blk);
			goto destroy_blk2off_table;
		}

		log_start_page = le16_to_cpu(ptr->blk_state.log_start_page);
		if (log_start_page != logical_blk) {
			err = -ERANGE;
			SSDFS_ERR("log_start_page %u != logical_blk %u\n",
				  log_start_page, logical_blk);
			goto destroy_blk2off_table;
		}

		log_area = ptr->blk_state.log_area;
		if (log_area != 0) {
			err = -ERANGE;
			SSDFS_ERR("log_area %u != 0\n",
				  log_area);
			goto destroy_blk2off_table;
		}

		peb_migration_id = ptr->blk_state.peb_migration_id;
		if (peb_migration_id != 0) {
			err = -ERANGE;
			SSDFS_ERR("peb_migration_id %u != 0\n",
				  peb_migration_id);
			goto destroy_blk2off_table;
		}

		byte_offset = le32_to_cpu(ptr->blk_state.byte_offset);
		if (byte_offset != calculated) {
			err = -ERANGE;
			SSDFS_ERR("byte_offset %u != calculated %u\n",
				  byte_offset, calculated);
			goto destroy_blk2off_table;
		}
	}

	for (logical_blk = 0; logical_blk < capacity; logical_blk++) {
		SSDFS_ERR("FREE LOGICAL BLOCK: logical_blk %u, capacity %u\n",
			  logical_blk, capacity);

		err = ssdfs_blk2off_table_free_block(blk2off_tbl,
						     0, logical_blk);
		if (err == -EAGAIN) {
			end = &blk2off_tbl->full_init_end;

			res = wait_for_completion_timeout(end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("blk2off init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_blk2off_table_free_block(blk2off_tbl,
							     0, logical_blk);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to free logical block: "
				  "blk %u, err %d\n",
				  logical_blk, err);
			goto destroy_blk2off_table;
		}
	}

destroy_blk2off_table:
	spin_lock(&blk2off_tbl->peb[0].sequence->lock);
	sequence_id = blk2off_tbl->peb[0].sequence->last_allocated_id;
	spin_unlock(&blk2off_tbl->peb[0].sequence->lock);

	BUG_ON(sequence_id >= U16_MAX);

	down_write(&blk2off_tbl->translation_lock);

	for (; sequence_id >= 0; --sequence_id) {
		err = ssdfs_blk2off_table_fragment_set_clean(blk2off_tbl, 0,
							     (u16)sequence_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set fragment clean: "
				  "sequence_id %llx, err %d\n",
				  sequence_id, err);
			goto finish_set_clean;
		}
	}

finish_set_clean:
	up_write(&blk2off_tbl->translation_lock);

	ssdfs_blk2off_table_destroy(blk2off_tbl);

finish_blk2off_table_testing:
	return err;
}

static inline
bool is_found_requested_peb_type(struct ssdfs_maptbl_peb_relation *pebr,
				 u8 peb_type)
{
	return pebr->pebs[SSDFS_MAPTBL_MAIN_INDEX].type == peb_type;
}

static
int ssdfs_define_current_mapping_leb(struct ssdfs_fs_info *fsi,
				     u64 *cur_leb)
{
	struct completion *init_end;
	u64 end_leb;
	int err;

try_next_range:
	if (SSDFS_PEB2SEG(fsi, *cur_leb) >= fsi->nsegs) {
		return -ENOENT;
	}

	err = ssdfs_maptbl_recommend_search_range(fsi, cur_leb,
						  &end_leb, &init_end);
	if (err == -EAGAIN) {
		unsigned long res;

		res = wait_for_completion_timeout(init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			return -ERANGE;
		}

		err = ssdfs_maptbl_recommend_search_range(fsi, cur_leb,
							  &end_leb, &init_end);
	}

	if (err == -ENOENT) {
		SSDFS_DBG("unable to find search range: leb_id %llu\n",
			  *cur_leb);
		*cur_leb = end_leb;
		goto try_next_range;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find search range: "
			  "leb_id %llu, err %d\n",
			  *cur_leb, err);
		return err;
	}

	return 0;
}

static
int ssdfs_do_leb_mapping_testing(struct ssdfs_fs_info *fsi,
				 struct ssdfs_testing_environment *env,
				 int iteration)
{
	struct completion *end;
	struct ssdfs_maptbl_peb_relation pebr;
	u64 cur_leb = iteration * env->mapping_table.peb_mappings_per_iteration;
	int i;
	int err;

	for (i = 0; i < env->mapping_table.peb_mappings_per_iteration; i++) {
		err = ssdfs_define_current_mapping_leb(fsi, &cur_leb);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find LEB for mapping\n");
			return -ENOSPC;
		}

try_next_leb:
		err = ssdfs_maptbl_map_leb2peb(fsi, cur_leb,
						SSDFS_MAPTBL_DATA_PEB_TYPE,
						&pebr, &end);
		if (err == -EAGAIN) {
			unsigned long res;

			res = wait_for_completion_timeout(end,
						  SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_map_leb2peb(fsi, cur_leb,
						SSDFS_MAPTBL_DATA_PEB_TYPE,
						&pebr, &end);
		}

		if (err == -EEXIST) {
			err = 0;
			cur_leb++;
			goto try_next_leb;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to map LEB to PEB: "
				  "leb_id %llu, err %d\n",
				  cur_leb, err);
			return err;
		}

		SSDFS_DBG("MAPPING TABLE: LEB %llu has been mapped\n",
			  cur_leb);

		cur_leb++;
	}

	return 0;
}

static
int ssdfs_do_migration_add_testing(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env,
				   int iteration)
{
	struct completion *init_end;
	struct ssdfs_maptbl_peb_relation pebr;
	struct ssdfs_maptbl_peb_descriptor *ptr1;
	struct ssdfs_maptbl_peb_descriptor *ptr2;
	u8 peb_type = SSDFS_MAPTBL_DATA_PEB_TYPE;
	u64 cur_leb = 0;
	int i;
	unsigned long res;
	int err;

	for (i = 0; i < env->mapping_table.add_migrations_per_iteration; i++) {
		do {
			err = ssdfs_maptbl_convert_leb2peb(fsi, cur_leb,
							   peb_type, &pebr,
							   &init_end);
			if (err == -EAGAIN) {
				res = wait_for_completion_timeout(init_end,
							SSDFS_DEFAULT_TIMEOUT);
				if (res == 0) {
					err = -ERANGE;
					SSDFS_ERR("maptbl init failed: "
						  "err %d\n", err);
					return err;
				}

				err = ssdfs_maptbl_convert_leb2peb(fsi, cur_leb,
								   peb_type,
								   &pebr,
								   &init_end);
			}

			if (err == -ENODATA) {
				cur_leb++;
				continue;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, peb_type %#x, err %d\n",
					  cur_leb, peb_type, err);
				return err;
			}

			ptr1 = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];
			ptr2 = &pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX];

			SSDFS_DBG("MAIN_INDEX: peb_id %llu, type %#x, "
				  "state %#x, consistency %#x; "
				  "RELATION_INDEX: peb_id %llu, type %#x, "
				  "state %#x, consistency %#x\n",
				  ptr1->peb_id, ptr1->type,
				  ptr1->state, ptr1->consistency,
				  ptr2->peb_id, ptr2->type,
				  ptr2->state, ptr2->consistency);

			if (ptr1->state != SSDFS_MAPTBL_CLEAN_PEB_STATE ||
			    ptr1->type != SSDFS_MAPTBL_DATA_PEB_TYPE) {
				cur_leb++;
				continue;
			} else
				break;
		} while (SSDFS_PEB2SEG(fsi, cur_leb) < fsi->nsegs);

		if (SSDFS_PEB2SEG(fsi, cur_leb) >= fsi->nsegs) {
			return -ENOENT;
		}

		SSDFS_DBG("MAPPING TABLE: leb %llu starting to migrate\n",
			  cur_leb);

		err = ssdfs_maptbl_change_peb_state(fsi, cur_leb, peb_type,
						SSDFS_MAPTBL_DIRTY_PEB_STATE,
						&init_end);
		if (err == -EAGAIN) {
			res = wait_for_completion_timeout(init_end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_change_peb_state(fsi,
						cur_leb, peb_type,
						SSDFS_MAPTBL_DIRTY_PEB_STATE,
						&init_end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to change the PEB state: "
				  "leb_id %llu, new_state %#x, err %d\n",
				  cur_leb, SSDFS_MAPTBL_DIRTY_PEB_STATE, err);
			return err;
		}

		err = ssdfs_maptbl_add_migration_peb(fsi, cur_leb, peb_type,
						     &pebr, &init_end);
		if (err == -EAGAIN) {
			res = wait_for_completion_timeout(init_end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_add_migration_peb(fsi, cur_leb,
							     peb_type,
							     &pebr, &init_end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to add migration PEB: "
				  "leb_id %llu, peb_type %#x, "
				  "err %d\n",
				  cur_leb, peb_type, err);
			return err;
		}
	}

	return 0;
}

static
int ssdfs_do_finish_migration_testing(struct ssdfs_fs_info *fsi,
				      struct ssdfs_testing_environment *env,
				      int iteration)
{
	struct completion *init_end;
	struct ssdfs_maptbl_peb_relation pebr;
	struct ssdfs_maptbl_peb_descriptor *ptr;
	u8 peb_type = SSDFS_MAPTBL_DATA_PEB_TYPE;
	u32 count = env->mapping_table.exclude_migrations_per_iteration;
	u64 cur_leb = 0;
	int i;
	unsigned long res;
	int err;

	for (i = 0; i < count; i++) {
		while (SSDFS_PEB2SEG(fsi, cur_leb) < fsi->nsegs) {
			err = ssdfs_maptbl_convert_leb2peb(fsi, cur_leb,
							   peb_type, &pebr,
							   &init_end);
			if (err == -EAGAIN) {
				res = wait_for_completion_timeout(init_end,
							SSDFS_DEFAULT_TIMEOUT);
				if (res == 0) {
					err = -ERANGE;
					SSDFS_ERR("maptbl init failed: "
						  "err %d\n", err);
					return err;
				}

				err = ssdfs_maptbl_convert_leb2peb(fsi, cur_leb,
								   peb_type,
								   &pebr,
								   &init_end);
			}

			if (err == -ENODATA) {
				cur_leb++;
				continue;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to convert LEB to PEB: "
					  "leb_id %llu, peb_type %#x, err %d\n",
					  cur_leb, peb_type, err);
				return err;
			}

			ptr = &pebr.pebs[SSDFS_MAPTBL_RELATION_INDEX];

			switch (ptr->state) {
			case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
				switch (ptr->type) {
				case SSDFS_MAPTBL_DATA_PEB_TYPE:
					goto finish_search;
					break;

				default:
					cur_leb++;
					break;
				}
				break;

			default:
				cur_leb++;
				break;
			}
		};

finish_search:
		if (SSDFS_PEB2SEG(fsi, cur_leb) >= fsi->nsegs) {
			return -ENOENT;
		}

		SSDFS_DBG("MAPPING TABLE: leb %llu has finished migration\n",
			  cur_leb);

		err = ssdfs_maptbl_exclude_migration_peb(fsi, cur_leb,
							 peb_type,
							 &init_end);
		if (err == -EAGAIN) {
			res = wait_for_completion_timeout(init_end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_exclude_migration_peb(fsi, cur_leb,
								 peb_type,
								 &init_end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to exclude migration PEB: "
				  "leb_id %llu, peb_type %#x, err %d\n",
				  cur_leb, peb_type, err);
			return err;
		}
	}

	ssdfs_maptbl_erase_dirty_pebs_now(fsi->maptbl);

	return 0;
}

static
int ssdfs_do_check_leb2peb_mapping(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env)
{
	struct completion *init_end;
	struct ssdfs_maptbl_peb_relation pebr;
	u8 peb_type = SSDFS_MAPTBL_DATA_PEB_TYPE;
	u64 count = (u64)env->mapping_table.iterations_number *
			env->mapping_table.peb_mappings_per_iteration;
	u64 calculated = 0;
	u64 cur_leb = 0;
	unsigned long res;
	int err;

	do {
		err = ssdfs_maptbl_convert_leb2peb(fsi, cur_leb,
						   peb_type, &pebr,
						   &init_end);
		if (err == -EAGAIN) {
			res = wait_for_completion_timeout(init_end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("maptbl init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_maptbl_convert_leb2peb(fsi, cur_leb,
							   peb_type,
							   &pebr,
							   &init_end);
		}

		if (err == -ENODATA) {
			/* do nothing */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to convert LEB to PEB: "
				  "leb_id %llu, peb_type %#x, err %d\n",
				  cur_leb, peb_type, err);
			return err;
		} else if (!is_found_requested_peb_type(&pebr, peb_type)) {
			/* ignore the current LEB */
			goto check_next_leb;
		} else {
			err = ssdfs_maptbl_change_peb_state(fsi,
						cur_leb, peb_type,
						SSDFS_MAPTBL_DIRTY_PEB_STATE,
						&init_end);
			if (err == -EAGAIN) {
				res = wait_for_completion_timeout(init_end,
							SSDFS_DEFAULT_TIMEOUT);
				if (res == 0) {
					err = -ERANGE;
					SSDFS_ERR("maptbl init failed: "
						  "err %d\n", err);
					return err;
				}

				err = ssdfs_maptbl_change_peb_state(fsi,
						cur_leb, peb_type,
						SSDFS_MAPTBL_DIRTY_PEB_STATE,
						&init_end);
			}

			if (unlikely(err)) {
				SSDFS_ERR("fail to change the PEB state: "
					  "leb_id %llu, new_state %#x, "
					  "err %d\n",
					  cur_leb, SSDFS_MAPTBL_DIRTY_PEB_STATE,
					  err);
				return err;
			}

			err = ssdfs_maptbl_prepare_pre_erase_state(fsi,
								   cur_leb,
								   peb_type,
								   &init_end);
			if (err == -EAGAIN) {
				res = wait_for_completion_timeout(init_end,
							SSDFS_DEFAULT_TIMEOUT);
				if (res == 0) {
					err = -ERANGE;
					SSDFS_ERR("maptbl init failed: "
						  "err %d\n", err);
					return err;
				}

				err = ssdfs_maptbl_prepare_pre_erase_state(fsi,
								    cur_leb,
								    peb_type,
								    &init_end);
			}

			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare pre-erase state: "
					  "leb_id %llu, err %d\n",
					  cur_leb, err);
				return err;
			}

			ssdfs_maptbl_erase_dirty_pebs_now(fsi->maptbl);

			calculated++;
		}

check_next_leb:
		cur_leb++;
	} while (SSDFS_PEB2SEG(fsi, cur_leb) < fsi->nsegs);

	if (calculated != count) {
		SSDFS_ERR("calculated %llu != count %llu\n",
			  calculated, count);
		return -ERANGE;
	}

	return 0;
}

static
int ssdfs_do_peb_mapping_table_testing(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env)
{
	int i;
	u64 mapped = 0;
	u64 migrating = 0;
	int err = 0;

	SSDFS_ERR("START LEB2PEB mapping...\n");

	for (i = 0; i < env->mapping_table.iterations_number; i++) {
		err = ssdfs_do_leb_mapping_testing(fsi, env, i);
		if (err) {
			SSDFS_ERR("LEB2PEB mapping failed: "
				  "iteration %d, err %d\n",
				  i, err);
			return err;
		}

		mapped += env->mapping_table.peb_mappings_per_iteration;

		SSDFS_ERR("MAPPED: lebs number %llu\n",
			  mapped);

		err = ssdfs_do_migration_add_testing(fsi, env, i);
		if (err) {
			SSDFS_ERR("add migration failed: "
				  "iteration %d, err %d\n",
				  i, err);
			return err;
		}

		migrating += env->mapping_table.add_migrations_per_iteration;

		SSDFS_ERR("MIGRATING: lebs number %llu\n",
			  migrating);

		err = ssdfs_do_finish_migration_testing(fsi, env, i);
		if (err) {
			SSDFS_ERR("finish migration failed: "
				  "iteration %d, err %d\n",
				  i, err);
			return err;
		}

		migrating -= env->mapping_table.exclude_migrations_per_iteration;

		SSDFS_ERR("MIGRATING (after finishing): lebs number %llu\n",
			  migrating);
	}

	SSDFS_ERR("FINISH LEB2PEB mapping...\n");

	SSDFS_ERR("CHECK LEB2PEB mapping...\n");

	err = ssdfs_do_check_leb2peb_mapping(fsi, env);
	if (err) {
		SSDFS_ERR("Check LEB2PEB mapping failed: "
			  "err %d\n",
			  err);
		return err;
	}

	SSDFS_ERR("CHECK LEB2PEB mapping: all LEBs has been checked\n");

	return 0;
}

static
int ssdfs_do_segment_using_testing(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env,
				   int iteration)
{
	u32 count = env->segment_bitmap.using_segs_per_iteration;
	int new_state = SSDFS_SEG_DATA_USING;
	u64 start_seg = 0;
	u64 end_seg = U64_MAX;
	u64 found_seg;
	int check_state;
	struct completion *init_end;
	unsigned long rest;
	int res = 0;
	u32 i;
	int err;

	for (i = 0; i < count; i++) {
		res = ssdfs_segbmap_find_and_set(fsi->segbmap,
						 start_seg, end_seg,
						 SSDFS_SEG_CLEAN,
						 SSDFS_SEG_CLEAN_STATE_FLAG,
						 new_state,
						 &found_seg, &init_end);
		if (res >= 0) {
			if (res != SSDFS_SEG_CLEAN) {
				SSDFS_ERR("invalid segment state: "
					  "seg %llu, state %#x, iter %u\n",
					  found_seg, res, i);
				return -ERANGE;
			}

			check_state = ssdfs_segbmap_check_state(fsi->segbmap,
								found_seg,
								new_state,
								&init_end);
			if (new_state != check_state) {
				SSDFS_ERR("invalid segment state: "
					  "seg %llu, state %#x, iter %u\n",
					  found_seg, check_state, i);
				return -ERANGE;
			}
		} else if (res == -EAGAIN) {
			rest = wait_for_completion_timeout(init_end,
						SSDFS_DEFAULT_TIMEOUT);
			if (rest == 0) {
				err = -ERANGE;
				SSDFS_ERR("segbmap init failed: "
					  "err %d\n", err);
				return err;
			}

			res = ssdfs_segbmap_find_and_set(fsi->segbmap,
						start_seg, end_seg,
						SSDFS_SEG_CLEAN,
						SSDFS_SEG_CLEAN_STATE_FLAG,
						new_state,
						&found_seg, &init_end);
			if (res >= 0) {
				if (res != SSDFS_SEG_CLEAN) {
					SSDFS_ERR("invalid segment state: "
						  "seg %llu, state %#x, "
						  "iter %u\n",
						  found_seg, res, i);
					return -ERANGE;
				}

				check_state =
					ssdfs_segbmap_check_state(fsi->segbmap,
								  found_seg,
								  new_state,
								  &init_end);
				if (new_state != check_state) {
					SSDFS_ERR("invalid segment state: "
						  "seg %llu, state %#x, "
						  "iter %u\n",
						  found_seg, check_state, i);
					return -ERANGE;
				}
			} else if (res == -ENODATA) {
				err = -ENOENT;
				SSDFS_ERR("unable to find segment in range: "
					  "start_seg %llu, end_seg %llu\n",
					  start_seg, end_seg);
				return err;
			} else {
				err = res;
				SSDFS_ERR("fail to find segment in range: "
					  "start_seg %llu, end_seg %llu, "
					  "err %d\n",
					  start_seg, end_seg, res);
				return err;
			}
		} else if (res == -ENODATA) {
			err = -ENOENT;
			SSDFS_ERR("unable to find segment in range: "
				  "start_seg %llu, end_seg %llu\n",
				  start_seg, end_seg);
			return err;
		} else {
			err = res;
			SSDFS_ERR("fail to find segment in range: "
				  "start_seg %llu, end_seg %llu, err %d\n",
				 start_seg, end_seg, res);
			return err;
		}
	}

	return 0;
}

static
int ssdfs_do_segment_state_testing(struct ssdfs_fs_info *fsi,
				   u32 segs_per_iteration,
				   int cur_state,
				   int new_state)
{
	u64 cur_seg = 0;
	u64 nsegs;
	u32 count = segs_per_iteration;
	int seg_state = SSDFS_SEG_STATE_MAX;
	bool is_expected_state;
	struct completion *init_end;
	unsigned long rest;
	int res;
	u32 i;
	int err;

	mutex_lock(&fsi->resize_mutex);
	nsegs = fsi->nsegs;
	mutex_unlock(&fsi->resize_mutex);

	for (i = 0; i < count; i++) {
		while (cur_seg < nsegs) {
			seg_state = ssdfs_segbmap_get_state(fsi->segbmap,
							    cur_seg, &init_end);
			if (seg_state == -EAGAIN) {
				rest = wait_for_completion_timeout(init_end,
							SSDFS_DEFAULT_TIMEOUT);
				if (rest == 0) {
					err = -ERANGE;
					SSDFS_ERR("segbmap init failed: "
						  "err %d\n", err);
					return err;
				}

				seg_state =
					ssdfs_segbmap_get_state(fsi->segbmap,
								cur_seg,
								&init_end);
				if (seg_state < 0)
					goto fail_define_seg_state;
			} else if (seg_state < 0) {
fail_define_seg_state:
				SSDFS_ERR("fail to define segment state: "
					  "seg %llu\n",
					  cur_seg);
				return seg_state;
			} else if (seg_state == cur_state)
				break;

			cur_seg++;
		}

		if (cur_seg >= nsegs) {
			SSDFS_ERR("cur_seg %llu >= nsegs %llu\n",
				  cur_seg, nsegs);
			return -ENOSPC;
		}

		err = ssdfs_segbmap_change_state(fsi->segbmap, cur_seg,
						 new_state, &init_end);
		if (err == -EAGAIN) {
			res = wait_for_completion_timeout(init_end,
						SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("segbmap init failed: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_segbmap_change_state(fsi->segbmap, cur_seg,
							 new_state, &init_end);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to change segment state: "
				  "seg %llu, state %#x, err %d\n",
				  cur_seg, new_state, err);
			return err;
		}

		is_expected_state = ssdfs_segbmap_check_state(fsi->segbmap,
								cur_seg,
								new_state,
								&init_end);
		if (!is_expected_state) {
			SSDFS_ERR("invalid segment state: "
				  "seg %llu\n",
				  cur_seg);
			return -ERANGE;
		}
	}

	return 0;
}

static
int ssdfs_do_segment_used_testing(struct ssdfs_fs_info *fsi,
				  struct ssdfs_testing_environment *env,
				  int iteration)
{
	return ssdfs_do_segment_state_testing(fsi,
			env->segment_bitmap.used_segs_per_iteration,
			SSDFS_SEG_DATA_USING, SSDFS_SEG_USED);
}

static
int ssdfs_do_segment_pre_dirty_testing(struct ssdfs_fs_info *fsi,
				       struct ssdfs_testing_environment *env,
				       int iteration)
{
	return ssdfs_do_segment_state_testing(fsi,
			env->segment_bitmap.pre_dirty_segs_per_iteration,
			SSDFS_SEG_USED, SSDFS_SEG_PRE_DIRTY);
}

static
int ssdfs_do_segment_dirty_testing(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env,
				   int iteration)
{
	return ssdfs_do_segment_state_testing(fsi,
			env->segment_bitmap.dirty_segs_per_iteration,
			SSDFS_SEG_PRE_DIRTY, SSDFS_SEG_DIRTY);
}

static
int ssdfs_do_segment_clean_testing(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env,
				   int iteration)
{
	return ssdfs_do_segment_state_testing(fsi,
			env->segment_bitmap.cleaned_segs_per_iteration,
			SSDFS_SEG_DIRTY, SSDFS_SEG_CLEAN);
}

static
int ssdfs_check_segment_bitmap_testing(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env)
{
	u64 cur_seg = 0;
	u64 nsegs;
	int seg_state = SSDFS_SEG_STATE_MAX;
	struct completion *init_end;
	unsigned long rest;
	u64 clean_segs = 0;
	u64 using_segs = 0;
	u64 used_segs = 0;
	u64 pre_dirty_segs = 0;
	u64 dirty_segs = 0;
	u64 calculated;
	int err;

	mutex_lock(&fsi->resize_mutex);
	nsegs = fsi->nsegs;
	mutex_unlock(&fsi->resize_mutex);

	for (cur_seg = 0; cur_seg < nsegs; cur_seg++) {
		seg_state = ssdfs_segbmap_get_state(fsi->segbmap,
						    cur_seg, &init_end);
		if (seg_state == -EAGAIN) {
			rest = wait_for_completion_timeout(init_end,
						SSDFS_DEFAULT_TIMEOUT);
			if (rest == 0) {
				err = -ERANGE;
				SSDFS_ERR("segbmap init failed: "
					  "err %d\n", err);
				return err;
			}

			seg_state = ssdfs_segbmap_get_state(fsi->segbmap,
							    cur_seg,
							    &init_end);
			if (seg_state < 0)
				goto fail_define_seg_state;
		} else if (seg_state < 0) {
fail_define_seg_state:
			SSDFS_ERR("fail to define segment state: "
				  "seg %llu\n",
				  cur_seg);
			return seg_state;
		}

		switch (seg_state) {
		case SSDFS_SEG_CLEAN:
			clean_segs++;
			break;

		case SSDFS_SEG_DATA_USING:
			using_segs++;
			break;

		case SSDFS_SEG_USED:
			used_segs++;
			break;

		case SSDFS_SEG_PRE_DIRTY:
			pre_dirty_segs++;
			break;

		case SSDFS_SEG_DIRTY:
			dirty_segs++;
			break;

		default:
			/* do nothing */
			break;
		}
	}

	SSDFS_ERR("CLEAN SEGS: %llu\n", clean_segs);
	SSDFS_ERR("USING SEGS: %llu\n", using_segs);
	SSDFS_ERR("USED SEGS: %llu\n", used_segs);
	SSDFS_ERR("PRE-DIRTY SEGS: %llu\n", pre_dirty_segs);
	SSDFS_ERR("DIRTY SEGS: %llu\n", dirty_segs);

	calculated = clean_segs + using_segs +
			used_segs + pre_dirty_segs + dirty_segs;

	if (calculated > nsegs) {
		SSDFS_ERR("calculated %llu > nsegs %llu\n",
			  calculated, nsegs);
		return -ERANGE;
	}

	SSDFS_ERR("calculated %llu, nsegs %llu\n",
		  calculated, nsegs);

	return 0;
}

static
int ssdfs_do_segment_bitmap_testing(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env)
{
	u64 using_segs = 0;
	u64 used_segs = 0;
	u64 pre_dirty_segs = 0;
	u64 dirty_segs = 0;
	u64 cleaned_segs = 0;
	int i;
	int err;

	for (i = 0; i < env->segment_bitmap.iterations_number; i++) {
		err = ssdfs_do_segment_using_testing(fsi, env, i);
		if (err) {
			SSDFS_ERR("mark segment as using failed: "
				  "iteration %d, err %d\n",
				  i, err);
			return err;
		}

		using_segs += env->segment_bitmap.using_segs_per_iteration;

		SSDFS_ERR("USING SEGS: segs number %llu\n", using_segs);

		err = ssdfs_do_segment_used_testing(fsi, env, i);
		if (err) {
			SSDFS_ERR("mark segment as used failed: "
				  "iteration %d, err %d\n",
				  i, err);
			return err;
		}

		used_segs += env->segment_bitmap.used_segs_per_iteration;

		SSDFS_ERR("USED SEGS: segs number %llu\n", used_segs);

		err = ssdfs_do_segment_pre_dirty_testing(fsi, env, i);
		if (err) {
			SSDFS_ERR("mark segment as pre-dirty failed: "
				  "iteration %d, err %d\n",
				  i, err);
			return err;
		}

		pre_dirty_segs +=
			env->segment_bitmap.pre_dirty_segs_per_iteration;

		SSDFS_ERR("PRE-DIRTY SEGS: segs number %llu\n", pre_dirty_segs);

		err = ssdfs_do_segment_dirty_testing(fsi, env, i);
		if (err) {
			SSDFS_ERR("mark segment as dirty failed: "
				  "iteration %d, err %d\n",
				  i, err);
			return err;
		}

		dirty_segs += env->segment_bitmap.dirty_segs_per_iteration;

		SSDFS_ERR("DIRTY SEGS: segs number %llu\n", dirty_segs);

		err = ssdfs_do_segment_clean_testing(fsi, env, i);
		if (err) {
			SSDFS_ERR("mark segment as clean failed: "
				  "iteration %d, err %d\n",
				  i, err);
			return err;
		}

		cleaned_segs += env->segment_bitmap.cleaned_segs_per_iteration;

		SSDFS_ERR("CLEANED SEGS: segs number %llu\n", cleaned_segs);
	}

	SSDFS_ERR("FINAL CHECK SEGMENT BITMAP\n");

	err = ssdfs_check_segment_bitmap_testing(fsi, env);
	if (err) {
		SSDFS_ERR("segment bitmap check is failed: "
			  "err %d\n",
			  err);
		return err;
	}

	return 0;
}

static
unsigned char ssdfs_generate_next_symbol(unsigned char symbol,
					 u32 step)
{
	unsigned char first = 'a';
	unsigned char last = 'z';
	u32 range_len = ((u8)last + 1) - (u8)first;
	u32 next_symbol;

	if (step > range_len)
		step %= range_len;

	next_symbol = (u32)symbol + step;

	if (next_symbol > (u32)last)
		next_symbol = (u32)first + (next_symbol - (u32)last);

	return (unsigned char)next_symbol;
}

static
unsigned char * ssdfs_generate_long_name(struct ssdfs_testing_environment *env,
					 unsigned char *table,
					 unsigned char *name_buf,
					 u32 name_len,
					 u32 step_factor)
{
	u32 i;

	memset(name_buf, 0, SSDFS_MAX_NAME_LEN);

	for (i = 0; i < name_len; i++) {
		u32 step = (u32)1 + (i * step_factor);

		table[i] = ssdfs_generate_next_symbol(table[i], step);
		name_buf[i] = table[i];
	}

	return name_buf;
}

static
int ssdfs_do_shared_dictionary_testing(struct ssdfs_fs_info *fsi,
				       struct ssdfs_testing_environment *env)
{
	unsigned char table[SSDFS_MAX_NAME_LEN];
	unsigned char name[SSDFS_MAX_NAME_LEN];
	u64 name_hash;
	u32 i;
	int err = 0;

	memset(table, 'a', SSDFS_MAX_NAME_LEN);

	for (i = 0; i < env->shared_dictionary.names_number; i++) {
		struct qstr str =
			QSTR_INIT(ssdfs_generate_long_name(env, table, name,
					env->shared_dictionary.name_len,
					env->shared_dictionary.step_factor),
				  env->shared_dictionary.name_len);

		name_hash = __ssdfs_generate_name_hash(name,
					env->shared_dictionary.name_len,
					SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
		if (name_hash == U64_MAX) {
			SSDFS_ERR("fail to generate name hash\n");
			return -ERANGE;
		}

		err = ssdfs_shared_dict_save_name(fsi->shdictree,
						  name_hash,
						  &str);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store name: "
				  "hash %llx, err %d\n",
				  name_hash, err);
			return err;
		}
	}

	memset(table, 'a', SSDFS_MAX_NAME_LEN);

	for (i = 0; i < env->shared_dictionary.names_number; i++) {
		struct ssdfs_name_string found_name;

		ssdfs_generate_long_name(env, table, name,
					 env->shared_dictionary.name_len,
					 env->shared_dictionary.step_factor);

		name_hash = __ssdfs_generate_name_hash(name,
					env->shared_dictionary.name_len,
					SSDFS_DENTRY_INLINE_NAME_MAX_LEN);
		if (name_hash == U64_MAX) {
			SSDFS_ERR("fail to generate name hash\n");
			return -ERANGE;
		}

		err = ssdfs_shared_dict_get_name(fsi->shdictree,
						 name_hash,
						 &found_name);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get name: "
				  "hash %llx, err %d\n",
				  name_hash, err);
			return err;
		}
	}

	return 0;
}

static
void ssdfs_testing_generate_blob(void *blob, u32 len, u64 pattern)
{
	u32 cur_len;
	u32 i;

	memset(blob, 0, len);

	for (i = 0; i < len; i += sizeof(u64)) {
		cur_len = min_t(u32, len - i, sizeof(u64));
		memcpy((u8 *)blob + i, &pattern, cur_len);
	}
}

static
int ssdfs_testing_xattr_tree_add(struct ssdfs_fs_info *fsi,
				 struct ssdfs_testing_environment *env,
				 unsigned char *table)
{
	struct ssdfs_inode_info *ii;
	struct ssdfs_btree_search *search;
	unsigned char name[SSDFS_MAX_NAME_LEN];
	ino_t ino;
	void *blob = NULL;
	int err = 0;

	ii = SSDFS_I(fsi->testing_inode);
	ino = ii->vfs_inode.i_ino;

	down_read(&ii->lock);

	ssdfs_generate_long_name(env, table, name,
				 env->xattr_tree.name_len,
				 env->xattr_tree.step_factor);

	blob = kzalloc(env->xattr_tree.blob_len, GFP_KERNEL);
	if (!blob) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate blob\n");
		goto finish_add_xattr;
	}

	ssdfs_testing_generate_blob(blob,
				    env->xattr_tree.blob_len,
				    env->xattr_tree.blob_pattern);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto free_blob;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_xattrs_tree_add(ii->xattrs_tree,
				    SSDFS_USER_XATTR_ID,
				    name, env->xattr_tree.name_len,
				    blob, env->xattr_tree.blob_len,
				    ii,
				    search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to create xattr: "
			  "ino %lu, name %s, err %d\n",
			  ino, name, err);
		goto free_blob;
	}

free_blob:
	kfree(blob);

finish_add_xattr:
	up_read(&ii->lock);

	return err;
}

static
int ssdfs_testing_xattr_tree_check(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env,
				   unsigned char *table)
{
	struct ssdfs_inode_info *ii;
	struct ssdfs_btree_search *search;
	unsigned char name[SSDFS_MAX_NAME_LEN];
	ino_t ino;
	int err = 0;

	ii = SSDFS_I(fsi->testing_inode);
	ino = ii->vfs_inode.i_ino;

	down_read(&ii->lock);

	ssdfs_generate_long_name(env, table, name,
				 env->xattr_tree.name_len,
				 env->xattr_tree.step_factor);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_check_xattr;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_xattrs_tree_find(ii->xattrs_tree,
				     name, env->xattr_tree.name_len,
				    search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to check xattr: "
			  "ino %lu, name %s, err %d\n",
			  ino, name, err);
		goto finish_check_xattr;
	}

finish_check_xattr:
	up_read(&ii->lock);

	return err;
}

static
int ssdfs_testing_xattr_tree_resize_blob(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env,
				   unsigned char *table,
				   u32 blob_len)
{
	struct ssdfs_inode_info *ii;
	struct ssdfs_btree_search *search;
	unsigned char name[SSDFS_MAX_NAME_LEN];
	ino_t ino;
	void *blob = NULL;
	u64 name_hash;
	int err = 0;

	ii = SSDFS_I(fsi->testing_inode);
	ino = ii->vfs_inode.i_ino;

	down_read(&ii->lock);

	ssdfs_generate_long_name(env, table, name,
				 env->xattr_tree.name_len,
				 env->xattr_tree.step_factor);

	blob = kzalloc(env->xattr_tree.blob_len, GFP_KERNEL);
	if (!blob) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate blob\n");
		goto finish_resize_xattr;
	}

	ssdfs_testing_generate_blob(blob,
				    env->xattr_tree.blob_len,
				    env->xattr_tree.blob_pattern);

	name_hash = __ssdfs_generate_name_hash(name, env->xattr_tree.name_len,
					       SSDFS_XATTR_INLINE_NAME_MAX_LEN);
	if (name_hash == U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to generate name hash\n");
		goto free_blob;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto free_blob;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_xattrs_tree_change(ii->xattrs_tree,
					SSDFS_USER_XATTR_ID,
					name_hash,
					name, env->xattr_tree.name_len,
					blob, env->xattr_tree.blob_len,
					search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to change xattr: "
			  "ino %lu, name %s, err %d\n",
			  ino, name, err);
		goto free_blob;
	}

free_blob:
	kfree(blob);

finish_resize_xattr:
	up_read(&ii->lock);

	return err;
}

static
int ssdfs_testing_xattr_tree_increase_blob(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env,
				   unsigned char *table)
{
	return ssdfs_testing_xattr_tree_resize_blob(fsi, env, table,
					env->xattr_tree.blob_len * 2);
}

static
int ssdfs_testing_xattr_tree_shrink_blob(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env,
				   unsigned char *table)
{
	return ssdfs_testing_xattr_tree_resize_blob(fsi, env, table,
					env->xattr_tree.blob_len / 2);
}

static
int ssdfs_testing_xattr_tree_delete(struct ssdfs_fs_info *fsi,
				   struct ssdfs_testing_environment *env,
				   unsigned char *table)
{
	struct ssdfs_inode_info *ii;
	struct ssdfs_btree_search *search;
	unsigned char name[SSDFS_MAX_NAME_LEN];
	ino_t ino;
	u64 name_hash;
	int err = 0;

	ii = SSDFS_I(fsi->testing_inode);
	ino = ii->vfs_inode.i_ino;

	down_read(&ii->lock);

	ssdfs_generate_long_name(env, table, name,
				 env->xattr_tree.name_len,
				 env->xattr_tree.step_factor);

	name_hash = __ssdfs_generate_name_hash(name, env->xattr_tree.name_len,
					       SSDFS_XATTR_INLINE_NAME_MAX_LEN);
	if (name_hash == U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("fail to generate name hash\n");
		goto finish_delete_xattr;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_delete_xattr;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_xattrs_tree_delete(ii->xattrs_tree,
					name_hash,
					name,
					env->xattr_tree.name_len,
					search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to delete xattr: "
			  "ino %lu, name %s, err %d\n",
			  ino, name, err);
		goto finish_delete_xattr;
	}

finish_delete_xattr:
	up_read(&ii->lock);

	return err;
}

static
int ssdfs_do_xattr_tree_testing(struct ssdfs_fs_info *fsi,
				struct ssdfs_testing_environment *env)
{
	struct ssdfs_inode_info *ii;
	u64 threshold = env->xattr_tree.xattrs_number;
	u64 per_1_percent = 0;
	u64 message_threshold = 0;
	unsigned char table[SSDFS_MAX_NAME_LEN];
	u64 i;
	int err = 0;

	ii = SSDFS_I(fsi->testing_inode);

	down_write(&ii->lock);
	err = ssdfs_xattrs_tree_create(fsi, ii);
	up_write(&ii->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to create the xattr tree: "
			  "err %d\n", err);
		goto finish_testing;
	}

	memset(table, 'a', SSDFS_MAX_NAME_LEN);

	per_1_percent = div_u64(threshold, 100);
	if (per_1_percent == 0)
		per_1_percent = 1;

	message_threshold = per_1_percent;

	SSDFS_ERR("ADD XATTRs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("ADD XATTRs: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_xattr_tree_add(fsi, env, table);
		if (err) {
			SSDFS_ERR("fail to add extended attribute: "
				  "err %d\n", err);
			goto destroy_tree;
		}
	}

	SSDFS_ERR("ADD XATTRs: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	memset(table, 'a', SSDFS_MAX_NAME_LEN);

	message_threshold = per_1_percent;

	SSDFS_ERR("CHECK XATTRs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("CHECK XATTRs: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_xattr_tree_check(fsi, env, table);
		if (err) {
			SSDFS_ERR("fail to check extended attribute: "
				  "err %d\n", err);
			goto destroy_tree;
		}
	}

	SSDFS_ERR("CHECK XATTRs: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	memset(table, 'a', SSDFS_MAX_NAME_LEN);

	message_threshold = per_1_percent;

	SSDFS_ERR("INCREASE XATTR BLOBs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("INCREASE XATTR BLOBs: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_xattr_tree_increase_blob(fsi, env, table);
		if (err) {
			SSDFS_ERR("fail to increase extended attribute: "
				  "err %d\n", err);
			goto destroy_tree;
		}
	}

	SSDFS_ERR("INCREASE XATTR BLOBs: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	memset(table, 'a', SSDFS_MAX_NAME_LEN);

	message_threshold = per_1_percent;

	SSDFS_ERR("CHECK XATTRs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("CHECK XATTRs: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_xattr_tree_check(fsi, env, table);
		if (err) {
			SSDFS_ERR("fail to check extended attribute: "
				  "err %d\n", err);
			goto destroy_tree;
		}
	}

	SSDFS_ERR("CHECK XATTRs: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	memset(table, 'a', SSDFS_MAX_NAME_LEN);

	message_threshold = per_1_percent;

	SSDFS_ERR("SHRINK XATTR BLOBs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("SHRINK XATTR BLOBs: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_xattr_tree_shrink_blob(fsi, env, table);
		if (err) {
			SSDFS_ERR("fail to shrink extended attribute: "
				  "err %d\n", err);
			goto destroy_tree;
		}
	}

	SSDFS_ERR("SHRINK XATTR BLOBs: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	memset(table, 'a', SSDFS_MAX_NAME_LEN);

	message_threshold = per_1_percent;

	SSDFS_ERR("CHECK XATTRs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("CHECK XATTRs: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_xattr_tree_check(fsi, env, table);
		if (err) {
			SSDFS_ERR("fail to check extended attribute: "
				  "err %d\n", err);
			goto destroy_tree;
		}
	}

	SSDFS_ERR("CHECK XATTRs: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	SSDFS_ERR("FLUSH XATTRS BTREE: starting...\n");

	down_write(&ii->lock);
	err = ssdfs_xattrs_tree_flush(fsi, ii);
	up_write(&ii->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to flush xattrs tree: "
			  "ino %lu, err %d\n",
			  ii->vfs_inode.i_ino, err);
		goto destroy_tree;
	}

	SSDFS_ERR("FLUSH XATTRS BTREE: finished\n");

	memset(table, 'a', SSDFS_MAX_NAME_LEN);

	message_threshold = per_1_percent;

	SSDFS_ERR("DELETE XATTRs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("DELETE XATTRs: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_xattr_tree_delete(fsi, env, table);
		if (err) {
			SSDFS_ERR("fail to delete extended attribute: "
				  "err %d\n", err);
			goto destroy_tree;
		}
	}

	SSDFS_ERR("DELETE XATTRs: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

destroy_tree:
	ssdfs_xattrs_tree_destroy(ii);

finish_testing:
	return err;
}

static
int ssdfs_testing_shextree_add(struct ssdfs_fs_info *fsi,
			       struct ssdfs_testing_environment *env,
			       u64 id)
{
	struct ssdfs_shared_extents_tree *tree;
	struct ssdfs_fingerprint fingerprint;
	struct ssdfs_shared_extent shared_extent;
	struct ssdfs_btree_search *search;
	__le64 fingerprint_value = cpu_to_le64(id);
	u32 extent_len = env->shextree.extent_len;
	int err;

	tree = fsi->shextree;

	memset(&shared_extent, 0x0, sizeof(struct ssdfs_shared_extent));

	shared_extent.extent.seg_id = cpu_to_le64(id);
	shared_extent.extent.logical_blk = cpu_to_le32(id);
	shared_extent.extent.len = cpu_to_le32(extent_len);
	ssdfs_memcpy(shared_extent.fingerprint,
		     0, SSDFS_FINGERPRINT_LENGTH_MAX,
		     &fingerprint_value, 0, sizeof(__le64),
		     sizeof(__le64));
	shared_extent.fingerprint_len = sizeof(u64);
	shared_extent.ref_count = cpu_to_le64(extent_len);

	SSDFS_DBG("fingerprint %pUb, type %#x, len %#x\n",
		  shared_extent.fingerprint,
		  shared_extent.fingerprint_type,
		  shared_extent.fingerprint_len);

	memset(&fingerprint, 0, sizeof(struct ssdfs_fingerprint));
	ssdfs_memcpy(fingerprint.buf,
		     0, SSDFS_FINGERPRINT_LENGTH_MAX,
		     &fingerprint_value, 0, sizeof(__le64),
		     sizeof(__le64));
	fingerprint.len = sizeof(u64);

	SSDFS_DBG("fingerprint %pUb, type %#x, len %#x\n",
		  fingerprint.buf,
		  fingerprint.type,
		  fingerprint.len);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_shextree_add(tree, &fingerprint, &shared_extent, search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to add shared extent: "
			  "id %llu, err %d\n",
			  id, err);
		return err;
	}

	return 0;
}

static
int ssdfs_testing_shextree_check(struct ssdfs_fs_info *fsi,
				 struct ssdfs_testing_environment *env,
				 u64 id)
{
	struct ssdfs_shared_extents_tree *tree;
	struct ssdfs_fingerprint fingerprint;
	struct ssdfs_btree_search *search;
	__le64 fingerprint_value = cpu_to_le64(id);
	int err;

	tree = fsi->shextree;

	memset(&fingerprint, 0, sizeof(struct ssdfs_fingerprint));
	ssdfs_memcpy(fingerprint.buf,
		     0, SSDFS_FINGERPRINT_LENGTH_MAX,
		     &fingerprint_value, 0, sizeof(__le64),
		     sizeof(__le64));
	fingerprint.len = sizeof(u64);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_shextree_find(tree, &fingerprint, search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to find shared extent: "
			  "id %llu, err %d\n",
			  id, err);
		return err;
	}

	return 0;
}

static
int ssdfs_testing_shextree_change(struct ssdfs_fs_info *fsi,
				  struct ssdfs_testing_environment *env,
				  u64 id)
{
	struct ssdfs_shared_extents_tree *tree;
	struct ssdfs_shared_extent shared_extent;
	struct ssdfs_fingerprint fingerprint;
	struct ssdfs_btree_search *search;
	__le64 fingerprint_value = cpu_to_le64(id);
	u32 extent_len = env->shextree.extent_len;
	int err;

	tree = fsi->shextree;

	memset(&shared_extent, 0x0, sizeof(struct ssdfs_shared_extent));

	shared_extent.extent.seg_id = cpu_to_le64(id * 2);
	shared_extent.extent.logical_blk = cpu_to_le32(id * 2);
	shared_extent.extent.len = cpu_to_le32(extent_len);
	ssdfs_memcpy(shared_extent.fingerprint,
		     0, SSDFS_FINGERPRINT_LENGTH_MAX,
		     &fingerprint_value, 0, sizeof(__le64),
		     sizeof(__le64));
	shared_extent.fingerprint_len = sizeof(u64);
	shared_extent.ref_count = cpu_to_le64(extent_len);

	memset(&fingerprint, 0, sizeof(struct ssdfs_fingerprint));
	ssdfs_memcpy(fingerprint.buf,
		     0, SSDFS_FINGERPRINT_LENGTH_MAX,
		     &fingerprint_value, 0, sizeof(__le64),
		     sizeof(__le64));
	fingerprint.len = sizeof(u64);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_shextree_change(tree, &fingerprint,
				    &shared_extent, search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to change shared extent: "
			  "id %llu, err %d\n",
			  id, err);
		return err;
	}

	return 0;
}

static
int ssdfs_testing_shextree_inc_ref_count(struct ssdfs_fs_info *fsi,
					 struct ssdfs_testing_environment *env,
					 u64 id)
{
	struct ssdfs_shared_extents_tree *tree;
	struct ssdfs_fingerprint fingerprint;
	struct ssdfs_btree_search *search;
	__le64 fingerprint_value = cpu_to_le64(id);
	int err;

	tree = fsi->shextree;

	memset(&fingerprint, 0, sizeof(struct ssdfs_fingerprint));
	ssdfs_memcpy(fingerprint.buf,
		     0, SSDFS_FINGERPRINT_LENGTH_MAX,
		     &fingerprint_value, 0, sizeof(__le64),
		     sizeof(__le64));
	fingerprint.len = sizeof(u64);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_shextree_ref_count_inc(tree, &fingerprint, search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to increment reference count: "
			  "id %llu, err %d\n",
			  id, err);
		return err;
	}

	return 0;
}

static
int ssdfs_testing_shextree_dec_ref_count(struct ssdfs_fs_info *fsi,
					 struct ssdfs_testing_environment *env,
					 u64 id)
{
	struct ssdfs_shared_extents_tree *tree;
	struct ssdfs_fingerprint fingerprint;
	struct ssdfs_btree_search *search;
	__le64 fingerprint_value = cpu_to_le64(id);
	u32 extent_len = env->shextree.extent_len;
	u32 i;
	int err;

	tree = fsi->shextree;

	memset(&fingerprint, 0, sizeof(struct ssdfs_fingerprint));
	ssdfs_memcpy(fingerprint.buf,
		     0, SSDFS_FINGERPRINT_LENGTH_MAX,
		     &fingerprint_value, 0, sizeof(__le64),
		     sizeof(__le64));
	fingerprint.len = sizeof(u64);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	for (i = 0; i < extent_len; i++) {
		ssdfs_btree_search_init(search);
		err = ssdfs_shextree_ref_count_dec(tree, &fingerprint, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to decrement reference count: "
				  "id %llu, err %d\n",
				  id, err);
			goto finish_dec_ref_count;
		}
	}

finish_dec_ref_count:
	ssdfs_btree_search_free(search);

	return err;
}

static
int ssdfs_testing_shextree_delete(struct ssdfs_fs_info *fsi,
				  struct ssdfs_testing_environment *env,
				  u64 id)
{
	struct ssdfs_shared_extents_tree *tree;
	struct ssdfs_fingerprint fingerprint;
	struct ssdfs_btree_search *search;
	__le64 fingerprint_value = cpu_to_le64(id);
	int err;

	tree = fsi->shextree;

	memset(&fingerprint, 0, sizeof(struct ssdfs_fingerprint));
	ssdfs_memcpy(fingerprint.buf,
		     0, SSDFS_FINGERPRINT_LENGTH_MAX,
		     &fingerprint_value, 0, sizeof(__le64),
		     sizeof(__le64));
	fingerprint.len = sizeof(u64);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_shextree_delete(tree, &fingerprint, search);
	ssdfs_btree_search_free(search);

	if (err == -ENOENT) {
		err = 0;
		SSDFS_DBG("tree is empty\n");
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to delete shared extent: "
			  "id %llu, err %d\n",
			  id, err);
		return err;
	}

	return 0;
}

static
int ssdfs_do_shextree_testing(struct ssdfs_fs_info *fsi,
			      struct ssdfs_testing_environment *env)
{
	u64 threshold = env->shextree.extents_number_threshold;
	u64 per_1_percent = 0;
	u64 message_threshold = 0;
	u64 i;
	int err = 0;

	per_1_percent = div_u64(threshold, 100);
	if (per_1_percent == 0)
		per_1_percent = 1;

	message_threshold = per_1_percent;

	SSDFS_ERR("ADD SHARED EXTENTs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("ADD SHARED EXTENTS: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_shextree_add(fsi, env, i + 1);
		if (err) {
			SSDFS_ERR("fail to add shared extent: "
				  "err %d\n", err);
			return err;
		}
	}

	SSDFS_ERR("ADD SHARED EXTENTS: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	message_threshold = per_1_percent;

	SSDFS_ERR("CHECK SHARED EXTENTs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("CHECK SHARED EXTENTS: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_shextree_check(fsi, env, i + 1);
		if (err) {
			SSDFS_ERR("fail to check shared extent: "
				  "err %d\n", err);
			return err;
		}
	}

	SSDFS_ERR("CHECK SHARED EXTENTS: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	message_threshold = per_1_percent;

	SSDFS_ERR("CHANGE SHARED EXTENTs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("CHANGE SHARED EXTENTS: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_shextree_change(fsi, env, i + 1);
		if (err) {
			SSDFS_ERR("fail to change shared extent: "
				  "err %d\n", err);
			return err;
		}
	}

	SSDFS_ERR("CHANGE SHARED EXTENTS: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	message_threshold = per_1_percent;

	SSDFS_ERR("INCREMENT REFERENCE COUNT: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("INCREMENT REFERENCE COUNT: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_shextree_inc_ref_count(fsi, env, i + 1);
		if (err) {
			SSDFS_ERR("fail to increment reference count: "
				  "err %d\n", err);
			return err;
		}
	}

	SSDFS_ERR("INCREMENT REFERENCE COUNT: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	message_threshold = per_1_percent;

	SSDFS_ERR("DECREMENT REFERENCE COUNT: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("DECREMENT REFERENCE COUNT: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_shextree_dec_ref_count(fsi, env, i + 1);
		if (err) {
			SSDFS_ERR("fail to decrement reference count: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_testing_shextree_dec_ref_count(fsi, env, i + 1);
		if (err) {
			SSDFS_ERR("fail to decrement reference count: "
				  "err %d\n", err);
			return err;
		}
	}

	SSDFS_ERR("DECREMENT REFERENCE COUNT: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	SSDFS_ERR("FLUSH SHARED EXTENTS BTREE: starting...\n");

	down_write(&fsi->volume_sem);
	err = ssdfs_shextree_flush(fsi);
	up_write(&fsi->volume_sem);

	if (unlikely(err)) {
		SSDFS_ERR("fail to flush shared extents tree: "
			  "err %d\n", err);
		return err;
	}

	SSDFS_ERR("FLUSH SHARED EXTENTS BTREE: finished\n");

	message_threshold = per_1_percent;

	SSDFS_ERR("DELETE SHARED EXTENTs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("DELETE SHARED EXTENTS: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_shextree_delete(fsi, env, i + 1);
		if (err == -ENOENT) {
			err = 0;
			SSDFS_DBG("tree is empty\n");
		} else if (err) {
			SSDFS_ERR("fail to delete shared extent: "
				  "err %d\n", err);
			return err;
		}
	}

	SSDFS_ERR("DELETE SHARED EXTENTS: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	return 0;
}

static
int ssdfs_testing_snapshots_tree_add(struct ssdfs_fs_info *fsi,
				     struct ssdfs_testing_environment *env,
				     u64 id)
{
	struct ssdfs_snapshots_btree_info *tree;
	struct ssdfs_snapshot_request *snr = NULL;
	struct ssdfs_btree_search *search;
	__le64 uuid_value = cpu_to_le64(id);
	int err = 0;

	tree = fsi->snapshots.tree;

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_CREATE_SNAPSHOT;
	snr->ino = id;

	ssdfs_memcpy(snr->info.uuid,
		     0, SSDFS_UUID_SIZE,
		     &uuid_value, 0, sizeof(__le64),
		     sizeof(__le64));

	snr->info.mode = SSDFS_READ_ONLY_SNAPSHOT;
	snr->info.type = SSDFS_ONE_TIME_SNAPSHOT;
	snr->info.expiration = SSDFS_NEVER_EXPIRED;
	snr->info.frequency = SSDFS_HOUR_FREQUENCY;
	snr->info.snapshots_threshold = 1;

	SSDFS_DBG("SNAPSHOT INFO: ");
	SSDFS_DBG("name %s, ", snr->info.name);
	SSDFS_DBG("UUID %pUb, ", snr->info.uuid);
	SSDFS_DBG("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, snapshots_threshold %u, "
		  "TIME_RANGE (day %u, month %u, year %u)\n",
		  snr->info.mode, snr->info.type, snr->info.expiration,
		  snr->info.frequency, snr->info.snapshots_threshold,
		  snr->info.time_range.day,
		  snr->info.time_range.month,
		  snr->info.time_range.year);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_create_snapshot;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_snapshots_btree_add(tree, snr, search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to create snapshot: "
			  "id %llu, err %d\n",
			  id, err);
		goto finish_create_snapshot;
	}

finish_create_snapshot:
	if (snr)
		ssdfs_snapshot_request_free(snr);

	return err;
}

static
int ssdfs_testing_snapshots_tree_check(struct ssdfs_fs_info *fsi,
					struct ssdfs_testing_environment *env,
					u64 create_time,
					u64 id)
{
	struct ssdfs_snapshots_btree_info *tree;
	struct ssdfs_btree_search *search;
	struct ssdfs_snapshot_id snapshot_id = {0};
	u8 uuid[SSDFS_UUID_SIZE];
	__le64 uuid_value = cpu_to_le64(id);
	int err = 0;

	tree = fsi->snapshots.tree;

	ssdfs_memcpy(uuid,
		     0, SSDFS_UUID_SIZE,
		     &uuid_value, 0, sizeof(__le64),
		     sizeof(__le64));
	snapshot_id.uuid = uuid;
	snapshot_id.timestamp = create_time;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_check_snapshot;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_snapshots_btree_find(tree, &snapshot_id, search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to check snapshot: "
			  "id %llu, err %d\n",
			  id, err);
		goto finish_check_snapshot;
	}

finish_check_snapshot:
	return err;
}

static
int ssdfs_testing_snapshots_tree_change(struct ssdfs_fs_info *fsi,
					struct ssdfs_testing_environment *env,
					u64 create_time,
					u64 id)
{
	struct ssdfs_snapshots_btree_info *tree;
	struct ssdfs_snapshot_request *snr = NULL;
	struct ssdfs_btree_search *search;
	__le64 uuid_value = cpu_to_le64(id);
	struct timespec64 timestamp;
	struct tm tm;
	int err = 0;

	tree = fsi->snapshots.tree;

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_MODIFY_SNAPSHOT;
	snr->ino = id;

	ssdfs_memcpy(snr->info.uuid,
		     0, SSDFS_UUID_SIZE,
		     &uuid_value, 0, sizeof(__le64),
		     sizeof(__le64));

	snr->info.mode = SSDFS_READ_ONLY_SNAPSHOT;
	snr->info.type = SSDFS_PERIODIC_SNAPSHOT;
	snr->info.expiration = SSDFS_EXPIRATION_IN_WEEK;
	snr->info.frequency = SSDFS_SYNCFS_FREQUENCY;
	snr->info.snapshots_threshold = 111;

	timestamp = ns_to_timespec64(create_time);
	time64_to_tm(timestamp.tv_sec, 0, &tm);

	snr->info.time_range.year = tm.tm_year + 1900;
	snr->info.time_range.month = tm.tm_mon + 1;
	snr->info.time_range.day = tm.tm_mday;
	snr->info.time_range.hour = tm.tm_hour;
	snr->info.time_range.minute = tm.tm_min;

	SSDFS_DBG("SNAPSHOT INFO: ");
	SSDFS_DBG("name %s, ", snr->info.name);
	SSDFS_DBG("UUID %pUb, ", snr->info.uuid);
	SSDFS_DBG("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, snapshots_threshold %u, "
		  "TIME_RANGE (minute %u, hour %u, "
		  "day %u, month %u, year %u)\n",
		  snr->info.mode, snr->info.type, snr->info.expiration,
		  snr->info.frequency, snr->info.snapshots_threshold,
		  snr->info.time_range.minute,
		  snr->info.time_range.hour,
		  snr->info.time_range.day,
		  snr->info.time_range.month,
		  snr->info.time_range.year);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_change_snapshot;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_snapshots_btree_change(tree, snr, search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to change snapshot: "
			  "id %llu, err %d\n",
			  id, err);
		goto finish_change_snapshot;
	}

finish_change_snapshot:
	if (snr)
		ssdfs_snapshot_request_free(snr);

	return err;
}

static
int ssdfs_testing_snapshots_tree_delete(struct ssdfs_fs_info *fsi,
					struct ssdfs_testing_environment *env,
					u64 create_time,
					u64 id)
{
	struct ssdfs_snapshots_btree_info *tree;
	struct ssdfs_snapshot_request *snr = NULL;
	struct ssdfs_btree_search *search;
	__le64 uuid_value = cpu_to_le64(id);
	struct timespec64 timestamp;
	struct tm tm;
	int err = 0;

	tree = fsi->snapshots.tree;

	snr = ssdfs_snapshot_request_alloc();
	if (!snr) {
		SSDFS_ERR("fail to allocate snaphot request\n");
		return -ENOMEM;
	}

	snr->operation = SSDFS_REMOVE_SNAPSHOT;
	snr->ino = id;

	ssdfs_memcpy(snr->info.uuid,
		     0, SSDFS_UUID_SIZE,
		     &uuid_value, 0, sizeof(__le64),
		     sizeof(__le64));

	timestamp = ns_to_timespec64(create_time);
	time64_to_tm(timestamp.tv_sec, 0, &tm);

	snr->info.time_range.year = tm.tm_year + 1900;
	snr->info.time_range.month = tm.tm_mon + 1;
	snr->info.time_range.day = tm.tm_mday;
	snr->info.time_range.hour = tm.tm_hour;
	snr->info.time_range.minute = tm.tm_min;

	SSDFS_DBG("SNAPSHOT INFO: ");
	SSDFS_DBG("name %s, ", snr->info.name);
	SSDFS_DBG("UUID %pUb, ", snr->info.uuid);
	SSDFS_DBG("mode %#x, type %#x, expiration %#x, "
		  "frequency %#x, snapshots_threshold %u, "
		  "TIME_RANGE (minute %u, hour %u, "
		  "day %u, month %u, year %u)\n",
		  snr->info.mode, snr->info.type, snr->info.expiration,
		  snr->info.frequency, snr->info.snapshots_threshold,
		  snr->info.time_range.minute,
		  snr->info.time_range.hour,
		  snr->info.time_range.day,
		  snr->info.time_range.month,
		  snr->info.time_range.year);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto finish_delete_snapshot;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_snapshots_btree_delete(tree, snr, search);
	ssdfs_btree_search_free(search);

	if (err == -ENOENT) {
		err = 0;
		SSDFS_DBG("tree is empty\n");
		goto finish_delete_snapshot;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to delete snapshot: "
			  "id %llu, err %d\n",
			  id, err);
		goto finish_delete_snapshot;
	}

finish_delete_snapshot:
	if (snr)
		ssdfs_snapshot_request_free(snr);

	return err;
}

typedef int (*ssdfs_snapshot_testfn)(struct ssdfs_fs_info *fsi,
				     struct ssdfs_testing_environment *env,
				     u64 create_time,
				     u64 id);

static
int ssdfs_traverse_snapshots_tree(struct ssdfs_fs_info *fsi,
				  struct ssdfs_testing_environment *env,
				  u64 per_1_percent,
				  u64 message_threshold,
				  const char *message_string,
				  ssdfs_snapshot_testfn execute_test)
{
	struct ssdfs_btree_search *search;
	size_t desc_size = sizeof(struct ssdfs_snapshot);
	u64 start_hash = U64_MAX;
	u64 end_hash = U64_MAX;
	u64 create_time = U64_MAX;
	u16 items_count;
	u64 i, j;
	int err = 0;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	err = ssdfs_snapshots_tree_get_start_hash(fsi->snapshots.tree,
						  &start_hash);
	if (err == -ENOENT) {
		SSDFS_ERR("snapshots tree is empty\n");
		goto finish_snapshots_tree_testing;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get start root hash: err %d\n", err);
		goto finish_snapshots_tree_testing;
	} else if (start_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid start hash value\n");
		goto finish_snapshots_tree_testing;
	}

	i = 0;

	do {
		struct ssdfs_timestamp_range range;
		range.start = range.end = start_hash;

		ssdfs_btree_search_init(search);

		SSDFS_DBG("start_hash %llx\n",
			  start_hash);

		err = ssdfs_snapshots_tree_find_leaf_node(fsi->snapshots.tree,
							  &range,
							  search);
		if (err == -ENODATA) {
			SSDFS_DBG("unable to find a leaf node: "
				  "hash %llx, err %d\n",
				  start_hash, err);
			goto finish_tree_processing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find a leaf node: "
				  "hash %llx, err %d\n",
				  start_hash, err);
			goto finish_tree_processing;
		}

		err = ssdfs_snapshots_tree_node_hash_range(fsi->snapshots.tree,
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

		err = ssdfs_snapshots_tree_extract_range(fsi->snapshots.tree,
							 0, items_count,
							 search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the range: "
				  "items_count %u, err %d\n",
				  items_count, err);
			goto finish_tree_processing;
		}

finish_tree_processing:
		if (unlikely(err))
			goto finish_snapshots_tree_testing;

		err = ssdfs_snapshots_tree_check_search_result(search);
		if (unlikely(err)) {
			SSDFS_ERR("corrupted search result: "
				  "err %d\n", err);
			goto finish_snapshots_tree_testing;
		}

		items_count = search->result.count;

		ssdfs_btree_search_forget_child_node(search);

		for (j = 0; j < items_count; j++) {
			struct ssdfs_snapshot *snapshot = NULL;
			u8 *start_ptr = (u8 *)search->result.buf;

			snapshot = (struct ssdfs_snapshot *)(start_ptr +
							(j * desc_size));
			create_time = le64_to_cpu(snapshot->create_time);

			if (i >= message_threshold) {
				SSDFS_ERR("%s: %llu%%\n",
					  message_string,
					  div64_u64(i, per_1_percent));

				message_threshold += per_1_percent;
			}

			err = execute_test(fsi, env, create_time, i + 1);
			if (err) {
				SSDFS_ERR("fail to check snapshot: "
					  "err %d\n", err);
				goto finish_snapshots_tree_testing;
			}

			i++;
		}

		if (create_time != end_hash) {
			err = -ERANGE;
			SSDFS_ERR("hash %llx < end_hash %llx\n",
				  create_time, end_hash);
			goto finish_snapshots_tree_testing;
		}

		start_hash = end_hash + 1;

		err = ssdfs_snapshots_tree_get_next_hash(fsi->snapshots.tree,
							 search,
							 &start_hash);

		ssdfs_btree_search_forget_parent_node(search);
		ssdfs_btree_search_forget_child_node(search);

		if (err == -ENOENT || err == -ENODATA) {
			err = 0;
			SSDFS_DBG("no more items in the tree\n");
			goto finish_snapshots_tree_testing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get next hash: err %d\n",
				  err);
			goto finish_snapshots_tree_testing;
		}
	} while (start_hash < U64_MAX);

finish_snapshots_tree_testing:
	if (err) {
		SSDFS_ERR("fail to execute test: err %d\n",
			  err);
	}

	ssdfs_btree_search_free(search);

	return err;
}

static
int ssdfs_do_snapshots_tree_testing(struct ssdfs_fs_info *fsi,
				    struct ssdfs_testing_environment *env)
{
	u64 threshold = env->snapshots_tree.snapshots_number_threshold;
	u64 per_1_percent = 0;
	u64 message_threshold = 0;
	u64 i;
	int err = 0;

	per_1_percent = div_u64(threshold, 100);
	if (per_1_percent == 0)
		per_1_percent = 1;

	message_threshold = per_1_percent;

	SSDFS_ERR("ADD SNAPSHOTs: 0%%\n");

	for (i = 0; i < threshold; i++) {
		if (i >= message_threshold) {
			SSDFS_ERR("ADD SNAPSHOTS: %llu%%\n",
				  div64_u64(i, per_1_percent));

			message_threshold += per_1_percent;
		}

		err = ssdfs_testing_snapshots_tree_add(fsi, env, i + 1);
		if (err) {
			SSDFS_ERR("fail to add snapshot: "
				  "err %d\n", err);
			return err;
		}
	}

	SSDFS_ERR("ADD SNAPSHOTS: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	message_threshold = per_1_percent;

	SSDFS_ERR("CHECK SNAPSHOTs: 0%%\n");

	err = ssdfs_traverse_snapshots_tree(fsi, env, per_1_percent,
					    message_threshold,
					    "CHECK SNAPSHOTs",
					    ssdfs_testing_snapshots_tree_check);
	if (err) {
		SSDFS_ERR("fail to check snapshot: err %d\n",
			  err);
		return err;
	}

	SSDFS_ERR("CHECK SNAPSHOTS: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	message_threshold = per_1_percent;

	SSDFS_ERR("CHANGE SNAPSHOTs: 0%%\n");

	err = ssdfs_traverse_snapshots_tree(fsi, env, per_1_percent,
					    message_threshold,
					    "CHANGE SNAPSHOTs",
					    ssdfs_testing_snapshots_tree_change);
	if (err) {
		SSDFS_ERR("fail to change snapshot: err %d\n",
			  err);
		return err;
	}

	SSDFS_ERR("CHANGE SNAPSHOTS: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

	SSDFS_ERR("FLUSH SNAPSHOTS BTREE: starting...\n");

	down_write(&fsi->volume_sem);
	err = ssdfs_snapshots_btree_flush(fsi);
	up_write(&fsi->volume_sem);

	if (unlikely(err)) {
		SSDFS_ERR("fail to flush snapshots tree: "
			  "err %d\n", err);
		return err;
	}

	SSDFS_ERR("FLUSH SNAPSHOTS BTREE: finished\n");

	message_threshold = per_1_percent;

	SSDFS_ERR("DELETE SNAPSHOTs: 0%%\n");

	err = ssdfs_traverse_snapshots_tree(fsi, env, per_1_percent,
					    message_threshold,
					    "DELETE SNAPSHOTs",
					    ssdfs_testing_snapshots_tree_delete);
	if (err == -ENOENT) {
		err = 0;
		SSDFS_DBG("tree is empty\n");
	} else if (err) {
		SSDFS_ERR("fail to delete snapshot: "
			  "err %d\n", err);
		return err;
	}

	SSDFS_ERR("DELETE SNAPSHOTS: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

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

	if (env->subsystems & SSDFS_ENABLE_BLOCK_BMAP_TESTING) {
		SSDFS_ERR("START BLOCK BITMAP TESTING...\n");

		err = ssdfs_do_block_bitmap_testing(fsi, env);
		if (err)
			goto free_inode;

		SSDFS_ERR("BLOCK BITMAP TESTING FINISHED\n");
	}

	if (env->subsystems & SSDFS_ENABLE_BLK2OFF_TABLE_TESTING) {
		SSDFS_ERR("START BLK2OFF TABLE TESTING...\n");

		err = ssdfs_do_blk2off_table_testing(fsi, env);
		if (err)
			goto free_inode;

		SSDFS_ERR("BLK2OFF TABLE TESTING FINISHED\n");
	}

	if (env->subsystems & SSDFS_ENABLE_PEB_MAPPING_TABLE_TESTING) {
		SSDFS_ERR("START PEB MAPPING TABLE TESTING...\n");

		err = ssdfs_do_peb_mapping_table_testing(fsi, env);
		if (err)
			goto free_inode;

		SSDFS_ERR("PEB MAPPING TABLE TESTING FINISHED\n");
	}

	if (env->subsystems & SSDFS_ENABLE_SEGMENT_BITMAP_TESTING) {
		SSDFS_ERR("START SEGMENT BITMAP TESTING...\n");

		err = ssdfs_do_segment_bitmap_testing(fsi, env);
		if (err)
			goto free_inode;

		SSDFS_ERR("SEGMENT BITMAP TESTING FINISHED\n");
	}

	if (env->subsystems & SSDFS_ENABLE_SHARED_DICTIONARY_TESTING) {
		SSDFS_ERR("START SHARED DICTIONARY TESTING...\n");

		err = ssdfs_do_shared_dictionary_testing(fsi, env);
		if (err)
			goto free_inode;

		SSDFS_ERR("SHARED DICTIONARY TESTING FINISHED\n");
	}

	if (env->subsystems & SSDFS_ENABLE_XATTR_TREE_TESTING) {
		SSDFS_ERR("START XATTR TREE TESTING...\n");

		err = ssdfs_do_xattr_tree_testing(fsi, env);
		if (err)
			goto free_inode;

		SSDFS_ERR("XATTR TREE TESTING FINISHED\n");
	}

	if (env->subsystems & SSDFS_ENABLE_SHEXTREE_TESTING) {
		SSDFS_ERR("START SHARED EXTENTS TREE TESTING...\n");

		err = ssdfs_do_shextree_testing(fsi, env);
		if (err)
			goto free_inode;

		SSDFS_ERR("SHARED EXTENTS TREE TESTING FINISHED\n");
	}

	if (env->subsystems & SSDFS_ENABLE_SNAPSHOTS_TREE_TESTING) {
		SSDFS_ERR("START SNAPSHOTS TREE TESTING...\n");

		err = ssdfs_do_snapshots_tree_testing(fsi, env);
		if (err)
			goto free_inode;

		SSDFS_ERR("SNAPSHOTS TREE TESTING FINISHED\n");
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
