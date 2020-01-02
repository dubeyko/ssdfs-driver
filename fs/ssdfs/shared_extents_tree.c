//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/shared_extents_tree.c - Shared extents tree implementation.
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

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "extents_queue.h"
#include "shared_extents_tree.h"

/*
 * ssdfs_shextree_create() - create shared extents tree object
 * @fsi: file system info object
 */
int ssdfs_shextree_create(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_shared_extents_tree *ptr;
	size_t shextree_obj_size = sizeof(struct ssdfs_shared_extents_tree);
	void *kaddr;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	kaddr = kzalloc(shextree_obj_size, GFP_KERNEL);
	if (!kaddr) {
		SSDFS_ERR("fail to allocate shared extents tree's object\n");
		return -ENOMEM;
	}

	fsi->shextree = ptr = (struct ssdfs_shared_extents_tree *)kaddr;

	ptr->fsi = fsi;
	init_waitqueue_head(&ptr->wait_queue);

	for (i = 0; i < SSDFS_INVALIDATION_QUEUE_NUMBER; i++) {
		ssdfs_extents_queue_init(&ptr->array[i].queue);

		err = ssdfs_shextree_start_thread(ptr, i);
		if (unlikely(err)) {
			SSDFS_ERR("fail to start shared extent tree's thread: "
				  "ID %d, err %d\n",
				  i, err);
			goto destroy_shextree_object;
		}
	}

	SSDFS_DBG("DONE: create shared extents tree\n");

	return 0;

destroy_shextree_object:
	for (; i >= 0; i--)
		ssdfs_shextree_stop_thread(ptr, i);

	kfree(fsi->shextree);
	fsi->shextree = NULL;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(err == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_shextree_destroy() - destroy shared extents tree object
 * @fsi: file system info object
 */
void ssdfs_shextree_destroy(struct ssdfs_fs_info *fsi)
{
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("shextree %p\n", fsi->shextree);

	if (!fsi->shextree)
		return;

	for (i = 0; i < SSDFS_INVALIDATION_QUEUE_NUMBER; i++) {
		err = ssdfs_shextree_stop_thread(fsi->shextree, i);
		if (err == -EIO) {
			ssdfs_fs_error(fsi->sb,
					__FILE__, __func__, __LINE__,
					"thread I/O issue\n");
		} else if (unlikely(err)) {
			SSDFS_WARN("thread stopping issue: ID %d, err %d\n",
				   i, err);
		}

		ssdfs_extents_queue_remove_all(&fsi->shextree->array[i].queue);
	}

	kfree(fsi->shextree);
	fsi->shextree = NULL;
}

/*
 * ssdfs_shextree_add_pre_invalid_extent() - add pre-invalid extent into queue
 * @tree: shared extents tree
 * @owner_ino: btree's owner inode id
 * @extent: pre-invalid extent
 *
 * This method tries to add pre-invalid extent into
 * invalidation queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_shextree_add_pre_invalid_extent(struct ssdfs_shared_extents_tree *tree,
					  u64 owner_ino,
					  struct ssdfs_raw_extent *extent)
{
	struct ssdfs_extents_queue *queue;
	struct ssdfs_extent_info *ei;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_id = le64_to_cpu(extent->seg_id);
	logical_blk = le32_to_cpu(extent->logical_blk);
	len = le32_to_cpu(extent->len);

	SSDFS_DBG("tree %p, extent %p, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  tree, extent, seg_id, logical_blk, len);

	if (seg_id == U64_MAX || logical_blk == U32_MAX || len == U32_MAX) {
		SSDFS_ERR("invalid extent\n");
		return -ERANGE;
	}

	ei = ssdfs_extent_info_alloc();
	if (IS_ERR_OR_NULL(ei)) {
		err = !ei ? -ENOMEM : PTR_ERR(ei);
		SSDFS_ERR("fail to allocate extent info: "
			  "err %d\n",
			  err);
		return err;
	}

	queue = &tree->array[SSDFS_EXTENT_INVALIDATION_QUEUE].queue;
	ssdfs_extent_info_init(SSDFS_EXTENT_INFO_RAW_EXTENT, extent,
				owner_ino, ei);
	ssdfs_extents_queue_add_tail(queue, ei);

	wake_up_all(&tree->wait_queue);
	return 0;
}

/*
 * ssdfs_shextree_add_pre_invalid_fork() - add fork's extents into queue
 * @tree: shared extents tree
 * @owner_ino: btree's owner inode id
 * @fork: pre-invalid fork
 *
 * This method tries to add pre-invalid fork's extent into
 * invalidation queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_shextree_add_pre_invalid_fork(struct ssdfs_shared_extents_tree *tree,
					u64 owner_ino,
					struct ssdfs_raw_fork *fork)
{
	u64 start_offset;
	u64 blks_count;
	u64 processed_blks = 0;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !fork);
#endif /* CONFIG_SSDFS_DEBUG */

	start_offset = le64_to_cpu(fork->start_offset);
	blks_count = le64_to_cpu(fork->blks_count);

	SSDFS_DBG("tree %p, fork %p, "
		  "start_offset %llu, blks_count %llu\n",
		  tree, fork, start_offset, blks_count);

	if (start_offset == U64_MAX || blks_count == U64_MAX) {
		SSDFS_WARN("invalid fork: "
			   "start_offset %llu, blks_count %llu\n",
			   start_offset, blks_count);
		return -ERANGE;
	}

	if (blks_count == 0) {
		SSDFS_WARN("empty fork\n");
		return 0;
	}

	for (i = 0; i < SSDFS_INLINE_EXTENTS_COUNT; i++) {
		struct ssdfs_raw_extent *ptr = &fork->extents[i];
		u32 len = le32_to_cpu(ptr->len);

		err = ssdfs_shextree_add_pre_invalid_extent(tree, owner_ino,
							    ptr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add pre-invalid extent: "
				  "err %d\n",
				  err);
			return err;
		}

		processed_blks += len;
	}

	if (processed_blks != blks_count) {
		SSDFS_WARN("processed_blks %llu != blks_count %llu\n",
			   processed_blks, blks_count);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_shextree_add_pre_invalid_index() - add pre-invalid index into queue
 * @tree: shared extents tree
 * @owner_ino: btree's owner inode id
 * @index: pre-invalid index
 *
 * This method tries to add pre-invalid index into
 * invalidation queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_shextree_add_pre_invalid_index(struct ssdfs_shared_extents_tree *tree,
					 u64 owner_ino,
					 int index_type,
					 struct ssdfs_btree_index_key *index)
{
	struct ssdfs_extents_queue *queue;
	struct ssdfs_extent_info *ei;
	u32 node_id;
	u8 node_type;
	u8 height;
	u16 flags;
	u64 hash;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !index);
#endif /* CONFIG_SSDFS_DEBUG */

	node_id = le32_to_cpu(index->node_id);
	node_type = index->node_type;
	height = index->height;
	flags = le16_to_cpu(index->flags);
	hash = le64_to_cpu(index->index.hash);
	seg_id = le64_to_cpu(index->index.extent.seg_id);
	logical_blk = le32_to_cpu(index->index.extent.logical_blk);
	len = le32_to_cpu(index->index.extent.len);

	SSDFS_DBG("tree %p, owner_ino %llu, index_type %#x, "
		  "node_id %u, node_type %#x, height %u, flags %#x, "
		  "hash %llx, seg_id %llu, logical_blk %u, len %u\n",
		  tree, owner_ino, index_type,
		  node_id, node_type, height, flags,
		  hash, seg_id, logical_blk, len);

	switch (index_type) {
	case SSDFS_EXTENT_INFO_INDEX_DESCRIPTOR:
	case SSDFS_EXTENT_INFO_DENTRY_INDEX_DESCRIPTOR:
	case SSDFS_EXTENT_INFO_SHDICT_INDEX_DESCRIPTOR:
	case SSDFS_EXTENT_INFO_XATTR_INDEX_DESCRIPTOR:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid index_type %#x\n",
			  index_type);
		return -ERANGE;
	}

	if (node_id >= SSDFS_BTREE_NODE_INVALID_ID) {
		SSDFS_ERR("invalid node_id\n");
		return -ERANGE;
	}

	switch (node_type) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected node type */
		break;

	default:
		SSDFS_ERR("invalid node_type %#x\n",
			  node_type);
		return -ERANGE;
	}

	if (height >= U8_MAX) {
		SSDFS_ERR("invalid node's height\n");
		return -ERANGE;
	}

	if (flags & ~SSDFS_BTREE_INDEX_FLAGS_MASK) {
		SSDFS_ERR("invalid flags set %#x\n",
			  flags);
		return -ERANGE;
	}

	if (hash >= U64_MAX) {
		SSDFS_ERR("invalid hash\n");
		return -ERANGE;
	}

	if (seg_id == U64_MAX || logical_blk == U32_MAX || len == U32_MAX) {
		SSDFS_ERR("invalid extent\n");
		return -ERANGE;
	}

	ei = ssdfs_extent_info_alloc();
	if (IS_ERR_OR_NULL(ei)) {
		err = !ei ? -ENOMEM : PTR_ERR(ei);
		SSDFS_ERR("fail to allocate extent info: "
			  "err %d\n",
			  err);
		return err;
	}

	queue = &tree->array[SSDFS_INDEX_INVALIDATION_QUEUE].queue;
	ssdfs_extent_info_init(index_type, index,
				owner_ino, ei);
	ssdfs_extents_queue_add_tail(queue, ei);

	wake_up_all(&tree->wait_queue);
	return 0;
}
