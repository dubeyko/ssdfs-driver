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

	down_write(&ii->lock);
	err = ssdfs_extents_tree_create(fsi, ii);
	up_write(&ii->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to create the extents tree: "
			  "err %d\n", err);
		unlock_new_inode(inode);
		iput(inode);
		return -ERANGE;
	}

	unlock_new_inode(inode);

	fsi->testing_inode = inode;

	return 0;
}

static
int ssdfs_testing_extents_tree_add_block(struct ssdfs_fs_info *fsi,
					 u64 logical_offset,
					 u64 seg_id,
					 u64 logical_blk)
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
					     PAGE_SIZE, 0, 0, req);

	ssdfs_request_define_segment(seg_id, req);
	ssdfs_request_define_volume_extent(logical_blk, 1, req);

	err = ssdfs_extents_tree_add_block(fsi->testing_inode, req);
	if (err) {
		SSDFS_ERR("fail to add extent: "
			  "ino %lu, logical_offset %llu, "
			  "seg_id %llu, logical_blk %llu, err %d\n",
			  ino, (u64)logical_offset,
			  seg_id, (u64)logical_blk, err);
		goto free_request;
	}

	inode_add_bytes(fsi->testing_inode, PAGE_SIZE);

free_request:
	ssdfs_put_request(req);
	ssdfs_request_free(req);

finish_add_block:
	return err;
}

static
int ssdfs_do_extents_tree_testing(struct ssdfs_fs_info *fsi)
{
	u64 seg_id = 1;
	u64 logical_blk = 0;
	u64 logical_offset = 0;
	u64 threshold;
	u32 extent_len = 1;
	u64 per_1_percent = 0;
	u64 message_threshold = 0;
	int err = 0;

	err = ssdfs_testing_get_inode(fsi);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create testing inode: "
			  "err %d\n", err);
		goto finish_testing;
	}

	ssdfs_testing_mapping_init(&fsi->testing_pages,
				   fsi->testing_inode);

	threshold = (u64)1000 * SSDFS_FILE_SIZE_MAX_TESTING_THRESHOLD;
	per_1_percent = div_u64(threshold, 100);
	message_threshold = per_1_percent;

	SSDFS_ERR("ADD LOGICAL BLOCK: 0%%\n");

	for (logical_offset = 0; logical_offset < threshold;
					logical_offset += PAGE_SIZE) {
		SSDFS_DBG("ADD LOGICAL BLOCK: "
			  "logical_offset %llu, seg_id %llu, "
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
							   logical_blk);
		if (err) {
			SSDFS_ERR("fail to add logical block: "
				  "err %d\n", err);
			goto free_inode;
		}

		if (extent_len < SSDFS_EXTENT_LEN_TESTING_MAX) {
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
					logical_offset += PAGE_SIZE) {
		SSDFS_DBG("CHECK LOGICAL BLOCK: "
			  "logical_offset %llu\n",
			  logical_offset);

		if (logical_offset >= message_threshold) {
			SSDFS_ERR("CHECK LOGICAL BLOCK: %llu%%\n",
				  div64_u64(logical_offset, per_1_percent));

			message_threshold += per_1_percent;
		}

		logical_blk = div_u64(logical_offset, PAGE_SIZE);

		if (!ssdfs_extents_tree_has_logical_block(logical_blk,
							  fsi->testing_inode)) {
			err = -ENOENT;
			SSDFS_ERR("fail to find: "
				  "logical_offset %llu, "
				  "logical_blk %llx\n",
				  logical_offset,
				  logical_blk);
			goto free_inode;
		}
	}

	SSDFS_ERR("CHECK LOGICAL BLOCK: %llu%%\n",
		  div64_u64(threshold, per_1_percent));

free_inode:
	iput(fsi->testing_inode);

finish_testing:
	return err;
}

int ssdfs_do_testing(struct ssdfs_fs_info *fsi, u64 flags)
{
	int err = 0;

	SSDFS_ERR("TESTING STARTING...\n");

	if (flags & SSDFS_ENABLE_EXTENTS_TREE_TESTING) {
		SSDFS_ERR("START EXTENTS TREE TESTING...\n");

		err = ssdfs_do_extents_tree_testing(fsi);
		if (err)
			goto finish_testing;

		SSDFS_ERR("EXTENTS TREE TESTING FINISHED\n");
	}

finish_testing:
	if (err)
		SSDFS_ERR("TESTING FAILED\n");
	else
		SSDFS_ERR("TESTING FINISHED\n");

	return err;
}
