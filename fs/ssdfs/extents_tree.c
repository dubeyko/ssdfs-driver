//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/extents_tree.c - extents tree functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "request_queue.h"
#include "segment_bitmap.h"
#include "page_array.h"
#include "segment.h"
#include "extents_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "shared_extents_tree.h"
#include "segment_tree.h"
#include "extents_tree.h"

#include <trace/events/ssdfs.h>

/*
 * ssdfs_init_inline_root_node() - initialize inline root node
 * @fsi: pointer on shared file system object
 * @root: pointer on inline root node [out]
 */
static inline
void ssdfs_init_inline_root_node(struct ssdfs_fs_info *fsi,
				 struct ssdfs_btree_inline_root_node *root)
{
	size_t index_size = sizeof(struct ssdfs_btree_index);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!root);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("root %p\n", root);

	root->header.height = SSDFS_BTREE_LEAF_NODE_HEIGHT;
	root->header.items_count = 0;
	root->header.flags = 0;
	root->header.type = 0;
	root->header.upper_node_id = cpu_to_le32(SSDFS_BTREE_ROOT_NODE_ID);
	memset(root->header.node_ids, 0xFF,
		sizeof(__le32) * SSDFS_BTREE_ROOT_NODE_INDEX_COUNT);
	memset(root->indexes, 0xFF,
		index_size * SSDFS_BTREE_ROOT_NODE_INDEX_COUNT);
}

/*
 * ssdfs_extents_tree_create() - create extents tree of a new inode
 * @fsi: pointer on shared file system object
 * @ii: pointer on in-core SSDFS inode
 *
 * This method tries to create extents btree for a new inode.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 */
int ssdfs_extents_tree_create(struct ssdfs_fs_info *fsi,
				struct ssdfs_inode_info *ii)
{
	struct ssdfs_extents_btree_info *ptr;
	size_t fork_size = sizeof(struct ssdfs_raw_fork);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii);
	BUG_ON(!rwsem_is_locked(&ii->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ii %p, ino %lu\n",
		  ii, ii->vfs_inode.i_ino);

	if (S_ISDIR(ii->vfs_inode.i_mode)) {
		SSDFS_WARN("folder cannot have extents tree\n");
		return -ERANGE;
	} else
		ii->extents_tree = NULL;

	ptr = kzalloc(sizeof(struct ssdfs_extents_btree_info),
			GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate extents tree\n");
		return -ENOMEM;
	}

	atomic_set(&ptr->state, SSDFS_EXTENTS_BTREE_UNKNOWN_STATE);
	atomic_set(&ptr->type, SSDFS_INLINE_FORKS_ARRAY);
	atomic64_set(&ptr->forks_count, 0);
	init_rwsem(&ptr->lock);
	ptr->generic_tree = NULL;
	memset(ptr->buffer.forks, 0xFF, fork_size * SSDFS_INLINE_FORKS_COUNT);
	ptr->inline_forks = ptr->buffer.forks;
	memset(&ptr->root_buffer, 0xFF,
		sizeof(struct ssdfs_btree_inline_root_node));
	ptr->root = NULL;
	memcpy(&ptr->desc, &fsi->segs_tree->extents_btree,
		sizeof(struct ssdfs_extents_btree_descriptor));
	ptr->owner = ii;
	ptr->fsi = fsi;
	atomic_set(&ptr->state, SSDFS_EXTENTS_BTREE_CREATED);

	ssdfs_debug_extents_btree_object(ptr);

	ii->extents_tree = ptr;

	return 0;
}

/*
 * ssdfs_extents_tree_destroy() - destroy extents tree
 * @ii: pointer on in-core SSDFS inode
 */
void ssdfs_extents_tree_destroy(struct ssdfs_inode_info *ii)
{
	size_t fork_size = sizeof(struct ssdfs_raw_fork);
	struct ssdfs_extents_btree_info *tree;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ii);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ii %p, ino %lu\n",
		  ii, ii->vfs_inode.i_ino);

	tree = SSDFS_EXTREE(ii);

	if (!tree) {
		SSDFS_DBG("extents tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
		/* expected state*/
		break;

	case SSDFS_EXTENTS_BTREE_CORRUPTED:
		SSDFS_WARN("extents tree is corrupted: "
			   "ino %lu\n",
			   ii->vfs_inode.i_ino);
		break;

	case SSDFS_EXTENTS_BTREE_DIRTY:
		SSDFS_WARN("extents tree is dirty: "
			   "ino %lu\n",
			   ii->vfs_inode.i_ino);
		break;

	default:
		SSDFS_WARN("invalid state of extents tree: "
			   "ino %lu, state %#x\n",
			   ii->vfs_inode.i_ino,
			   atomic_read(&tree->state));
		return;
	}

	if (rwsem_is_locked(&tree->lock)) {
		/* inform about possible trouble */
		SSDFS_WARN("tree is locked under destruction\n");
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		if (!tree->inline_forks) {
			SSDFS_WARN("empty inline_forks pointer\n");
			memset(tree->buffer.forks, 0xFF,
				fork_size * SSDFS_INLINE_FORKS_COUNT);
		} else {
			memset(tree->inline_forks, 0xFF,
				fork_size * SSDFS_INLINE_FORKS_COUNT);
		}
		tree->inline_forks = NULL;
		break;

	case SSDFS_PRIVATE_EXTENTS_BTREE:
		if (!tree->generic_tree) {
			SSDFS_WARN("empty generic_tree pointer\n");
			ssdfs_btree_destroy(&tree->buffer.tree);
		} else {
			/* destroy tree via pointer */
			ssdfs_btree_destroy(tree->generic_tree);
		}
		tree->generic_tree = NULL;
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid extents btree state %#x\n",
			   atomic_read(&tree->state));
#endif /* CONFIG_SSDFS_DEBUG */
		break;
	}

	memset(&tree->root_buffer, 0xFF,
		sizeof(struct ssdfs_btree_inline_root_node));
	tree->root = NULL;

	tree->owner = NULL;
	tree->fsi = NULL;

	atomic_set(&tree->type, SSDFS_EXTENTS_BTREE_UNKNOWN_TYPE);
	atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_UNKNOWN_STATE);

	kfree(ii->extents_tree);
	ii->extents_tree = NULL;
}

/*
 * ssdfs_extents_tree_init() - init extents tree for existing inode
 * @fsi: pointer on shared file system object
 * @ii: pointer on in-core SSDFS inode
 *
 * This method tries to create the extents tree and to initialize
 * the root node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 * %-EIO        - corrupted raw on-disk inode.
 */
int ssdfs_extents_tree_init(struct ssdfs_fs_info *fsi,
			    struct ssdfs_inode_info *ii)
{
	struct ssdfs_inode raw_inode;
	struct ssdfs_btree_node *node;
	struct ssdfs_extents_btree_info *tree;
	struct ssdfs_btree_inline_root_node *root_node;
	size_t fork_size = sizeof(struct ssdfs_raw_fork);
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii);
	BUG_ON(!rwsem_is_locked(&ii->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("si %p, ii %p, ino %lu\n",
		  fsi, ii, ii->vfs_inode.i_ino);

	tree = SSDFS_EXTREE(ii);
	if (!tree) {
		SSDFS_DBG("extents tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return -ERANGE;
	}

	memcpy(&raw_inode, &ii->raw_inode, sizeof(struct ssdfs_inode));

	flags = le16_to_cpu(raw_inode.private_flags);

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
		/* expected tree state */
		break;

	default:
		SSDFS_WARN("unexpected state of tree %#x\n",
			   atomic_read(&tree->state));
		return -ERANGE;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		/* expected tree type */
		break;

	case SSDFS_PRIVATE_EXTENTS_BTREE:
		SSDFS_WARN("unexpected type of tree %#x\n",
			   atomic_read(&tree->type));
		return -ERANGE;

	default:
		SSDFS_WARN("invalid type of tree %#x\n",
			   atomic_read(&tree->type));
		return -ERANGE;
	}

	down_write(&tree->lock);

	if (flags & SSDFS_INODE_HAS_EXTENTS_BTREE) {
		atomic64_set(&tree->forks_count,
			     le32_to_cpu(raw_inode.count_of.forks));

		if (tree->generic_tree) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_WARN("generic tree exists\n");
			goto finish_tree_init;
		}

		tree->generic_tree = &tree->buffer.tree;
		tree->inline_forks = NULL;

		err = ssdfs_btree_create(fsi,
					 ii->vfs_inode.i_ino,
					 &ssdfs_extents_btree_desc_ops,
					 &ssdfs_extents_btree_ops,
					 tree->generic_tree);
		if (unlikely(err)) {
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_ERR("fail to create extents tree: err %d\n",
				  err);
			goto finish_tree_init;
		}

		err = ssdfs_btree_radix_tree_find(tree->generic_tree,
						  SSDFS_BTREE_ROOT_NODE_ID,
						  &node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get the root node: err %d\n",
				  err);
			goto fail_create_generic_tree;
		} else if (unlikely(!node)) {
			err = -ERANGE;
			SSDFS_WARN("empty node pointer\n");
			goto fail_create_generic_tree;
		}

		root_node = &raw_inode.internal[0].area1.extents_root;
		err = ssdfs_btree_create_root_node(node, root_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init the root node: err %d\n",
				  err);
			goto fail_create_generic_tree;
		}

		tree->root = &tree->root_buffer;
		memcpy(tree->root, root_node,
			sizeof(struct ssdfs_btree_inline_root_node));

		atomic_set(&tree->type, SSDFS_PRIVATE_EXTENTS_BTREE);
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_INITIALIZED);

fail_create_generic_tree:
		if (unlikely(err)) {
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			ssdfs_btree_destroy(tree->generic_tree);
			tree->generic_tree = NULL;
			goto finish_tree_init;
		}
	} else if (flags & SSDFS_INODE_HAS_XATTR_BTREE) {
		atomic64_set(&tree->forks_count,
			     le32_to_cpu(raw_inode.count_of.forks));

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(atomic64_read(&tree->forks_count) > 1);
#else
		if (atomic64_read(&tree->forks_count) > 1) {
			err = -EIO;
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_ERR("corrupted on-disk raw inode: "
				  "forks_count %llu\n",
				  (u64)atomic64_read(&tree->forks_count));
			goto finish_tree_init;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		if (!tree->inline_forks) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_WARN("undefined inline forks pointer\n");
			goto finish_tree_init;
		} else {
			memcpy(tree->inline_forks, &raw_inode.internal,
				fork_size * SSDFS_INLINE_FORKS_COUNT);
		}

		atomic_set(&tree->type, SSDFS_INLINE_FORKS_ARRAY);
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_INITIALIZED);
	} else if (flags & SSDFS_INODE_HAS_INLINE_EXTENTS) {
		atomic64_set(&tree->forks_count,
			     le32_to_cpu(raw_inode.count_of.forks));

		if (!tree->inline_forks) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_WARN("undefined inline forks pointer\n");
			goto finish_tree_init;
		} else {
			memcpy(tree->inline_forks, &raw_inode.internal,
				fork_size * SSDFS_INLINE_FORKS_COUNT);
		}

		atomic_set(&tree->type, SSDFS_INLINE_FORKS_ARRAY);
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_INITIALIZED);
	} else
		BUG();

finish_tree_init:
	up_write(&tree->lock);

	ssdfs_debug_extents_btree_object(tree);

	return err;
}

/*
 * ssdfs_migrate_inline2generic_tree() - convert inline tree into generic
 * @tree: extents tree
 *
 * This method tries to convert the inline tree into generic one.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - the tree is empty.
 */
static
int ssdfs_migrate_inline2generic_tree(struct ssdfs_extents_btree_info *tree)
{
	struct ssdfs_raw_fork inline_forks[SSDFS_INLINE_FORKS_COUNT];
	struct ssdfs_btree_search *search;
	s64 forks_count, forks_capacity;
	int private_flags;
	u64 start_hash, end_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	forks_count = atomic64_read(&tree->forks_count);

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	private_flags = atomic_read(&tree->owner->private_flags);

	forks_capacity = SSDFS_INLINE_FORKS_COUNT;
	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE)
		forks_capacity--;
	if (private_flags & SSDFS_INODE_HAS_EXTENTS_BTREE) {
		SSDFS_ERR("the extents tree is generic\n");
		return -ERANGE;
	}

	if (forks_count > forks_capacity) {
		SSDFS_WARN("extents tree is corrupted: "
			   "forks_count %lld, forks_capacity %lld\n",
			   forks_count, forks_capacity);
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_CORRUPTED);
		return -ERANGE;
	} else if (forks_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -EFAULT;
	} else if (forks_count < forks_capacity) {
		SSDFS_WARN("forks_count %lld, forks_capacity %lld\n",
			   forks_count, forks_capacity);
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree->inline_forks || tree->generic_tree);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(inline_forks, 0xFF,
		sizeof(struct ssdfs_raw_fork) * SSDFS_INLINE_FORKS_COUNT);
	memcpy(inline_forks, tree->inline_forks,
		sizeof(struct ssdfs_raw_fork) * forks_capacity);
	tree->inline_forks = NULL;

	err = ssdfs_btree_create(tree->fsi,
				 tree->owner->vfs_inode.i_ino,
				 &ssdfs_extents_btree_desc_ops,
				 &ssdfs_extents_btree_ops,
				 &tree->buffer.tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create generic tree: err %d\n",
			  err);
		goto recover_inline_tree;
	}

	start_hash = le64_to_cpu(inline_forks[0].start_offset);
	if (forks_count > 1) {
		end_hash =
		    le64_to_cpu(inline_forks[forks_count - 1].start_offset);
	} else
		end_hash = start_hash;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto destroy_generic_tree;
	}

	ssdfs_btree_search_init(search);
	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
	search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
	search->request.start.hash = start_hash;
	search->request.end.hash = end_hash;
	search->request.count = forks_count;

	err = ssdfs_btree_find_item(&tree->buffer.tree, search);
	if (err == -ENODATA) {
		/* expected error */
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find item: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  start_hash, end_hash, err);
		goto finish_add_range;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND) {
		err = -ERANGE;
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		goto finish_add_range;
	}

	if (search->result.buf) {
		err = -ERANGE;
		SSDFS_ERR("search->result.buf %p\n",
			  search->result.buf);
		goto finish_add_range;
	}

	if (forks_count == 1) {
		search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		search->result.buf_size = sizeof(struct ssdfs_raw_fork);
		search->result.items_in_buffer = forks_count;
		search->result.buf = &search->raw.fork;
		memcpy(&search->raw.fork, inline_forks,
			search->result.buf_size);
	} else {
		search->result.buf_state = SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
		search->result.buf_size =
			forks_count * sizeof(struct ssdfs_raw_fork);
		search->result.items_in_buffer = forks_count;
		search->result.buf = kmalloc(search->result.buf_size,
					     GFP_KERNEL);
		if (!search->result.buf) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate memory for buffer\n");
			goto finish_add_range;
		}
		memcpy(search->result.buf, inline_forks,
			search->result.buf_size);
	}

	err = ssdfs_btree_add_range(&tree->buffer.tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add the range into tree: "
			   "start_hash %llx, end_hash %llx, err %d\n",
			   start_hash, end_hash, err);
		goto finish_add_range;
	}

finish_add_range:
	ssdfs_btree_search_free(search);

	if (unlikely(err))
		goto destroy_generic_tree;

	atomic_set(&tree->type, SSDFS_PRIVATE_EXTENTS_BTREE);
	atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_DIRTY);
	tree->generic_tree = &tree->buffer.tree;

	atomic_or(SSDFS_INODE_HAS_EXTENTS_BTREE,
		  &tree->owner->private_flags);
	atomic_and(~SSDFS_INODE_HAS_INLINE_EXTENTS,
		  &tree->owner->private_flags);
	return 0;

destroy_generic_tree:
	ssdfs_btree_destroy(&tree->buffer.tree);

recover_inline_tree:
	memcpy(tree->buffer.forks, inline_forks,
		sizeof(struct ssdfs_raw_fork) * SSDFS_INLINE_FORKS_COUNT);
	tree->inline_forks = tree->buffer.forks;
	return err;
}

/*
 * ssdfs_extents_tree_flush() - save modified extents tree
 * @fsi: pointer on shared file system object
 * @ii: pointer on in-core SSDFS inode
 *
 * This method tries to flush inode's extents btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_extents_tree_flush(struct ssdfs_fs_info *fsi,
			     struct ssdfs_inode_info *ii)
{
	struct ssdfs_extents_btree_info *tree;
	size_t fork_size = sizeof(struct ssdfs_raw_fork);
	int flags;
	u64 forks_count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ii);
	BUG_ON(!rwsem_is_locked(&ii->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, ii %p, ino %lu\n",
		  fsi, ii, ii->vfs_inode.i_ino);

	tree = SSDFS_EXTREE(ii);
	if (!tree) {
		SSDFS_DBG("extents tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return -ERANGE;
	}

	flags = atomic_read(&ii->private_flags);

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* need to flush */
		break;

	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
		/* do nothing */
		return 0;

	case SSDFS_EXTENTS_BTREE_CORRUPTED:
		SSDFS_DBG("extents btree corrupted: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return -EOPNOTSUPP;

	default:
		SSDFS_WARN("unexpected state of tree %#x\n",
			   atomic_read(&tree->state));
		return -ERANGE;
	}

	down_write(&tree->lock);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		forks_count = atomic64_read(&tree->forks_count);

		if (!tree->inline_forks) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_WARN("undefined inline forks pointer\n");
			goto finish_extents_tree_flush;
		}

		if (forks_count == 0) {
			flags = atomic_read(&ii->private_flags);

			if (flags & SSDFS_INODE_HAS_XATTR_BTREE) {
				memset(&ii->raw_inode.internal, 0xFF,
					fork_size);
			} else {
				memset(&ii->raw_inode.internal, 0xFF,
					fork_size * SSDFS_INLINE_FORKS_COUNT);
			}
		} else if (forks_count == 1) {
			flags = atomic_read(&ii->private_flags);

			if (flags & SSDFS_INODE_HAS_XATTR_BTREE) {
				memcpy(&ii->raw_inode.internal,
					tree->inline_forks,
					fork_size);
			} else {
				memcpy(&ii->raw_inode.internal,
					tree->inline_forks,
					fork_size * SSDFS_INLINE_FORKS_COUNT);
			}
		} else if (forks_count == SSDFS_INLINE_FORKS_COUNT) {
			flags = atomic_read(&ii->private_flags);

			if (flags & SSDFS_INODE_HAS_XATTR_BTREE) {
				err = -EAGAIN;
				SSDFS_DBG("tree should be converted: "
					  "ino %lu\n",
					  ii->vfs_inode.i_ino);
			} else {
				memcpy(&ii->raw_inode.internal,
					tree->inline_forks,
					fork_size * SSDFS_INLINE_FORKS_COUNT);
			}

			if (err == -EAGAIN) {
				err = ssdfs_migrate_inline2generic_tree(tree);
				if (unlikely(err)) {
					atomic_set(&tree->state,
						SSDFS_EXTENTS_BTREE_CORRUPTED);
					SSDFS_ERR("fail to convert tree: "
						  "err %d\n", err);
					goto finish_extents_tree_flush;
				} else
					goto try_generic_tree_flush;
			}
		} else {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_WARN("invalid forks_count %llu\n",
				   (u64)atomic64_read(&tree->forks_count));
			goto finish_extents_tree_flush;
		}

		atomic_or(SSDFS_INODE_HAS_INLINE_EXTENTS,
			  &ii->private_flags);
		break;

	case SSDFS_PRIVATE_EXTENTS_BTREE:
try_generic_tree_flush:
		if (!tree->generic_tree) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_WARN("undefined generic tree pointer\n");
			goto finish_extents_tree_flush;
		}

		err = ssdfs_btree_flush(tree->generic_tree);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush extents btree: "
				  "ino %lu, err %d\n",
				  ii->vfs_inode.i_ino, err);
			goto finish_generic_tree_flush;
		}

		if (!tree->root) {
			err = -ERANGE;
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_WARN("undefined root node pointer\n");
			goto finish_generic_tree_flush;
		}

		memcpy(&ii->raw_inode.internal[0].area1.extents_root,
			tree->root,
			sizeof(struct ssdfs_btree_inline_root_node));

		atomic_or(SSDFS_INODE_HAS_EXTENTS_BTREE,
			  &ii->private_flags);

finish_generic_tree_flush:
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid type of tree %#x\n",
			   atomic_read(&tree->type));
		goto finish_extents_tree_flush;
	}

finish_extents_tree_flush:
	up_write(&tree->lock);

	return err;
}

/*
 * ssdfs_prepare_volume_extent() - convert requested byte stream into extent
 * @fsi: pointer on shared file system object
 * @req: request object
 *
 * This method tries to convert logical byte stream into extent of blocks.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE      - internal error.
 * %-ENOMEM      - fail to allocate memory.
 * %-ENODATA     - unable to convert byte stream into extent.
 */
int ssdfs_prepare_volume_extent(struct ssdfs_fs_info *fsi,
				struct ssdfs_segment_request *req)
{
	struct ssdfs_inode_info *ii;
	struct ssdfs_extents_btree_info *tree;
	struct ssdfs_btree_search *search;
	struct ssdfs_raw_fork *fork = NULL;
	struct ssdfs_raw_extent *extent = NULL;
	u32 pagesize = fsi->pagesize;
	u64 seg_id;
	u32 logical_blk = U32_MAX, len;
	u64 start_blk;
	u64 blks_count;
	u64 requested_blk, requested_len;
	u64 processed_blks = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);
	BUG_ON((req->extent.logical_offset >> fsi->log_pagesize) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, req %p, ino %llu, "
		  "logical_offset %llu, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu\n",
		  fsi, req, req->extent.ino,
		  req->extent.logical_offset,
		  req->extent.data_bytes,
		  req->extent.cno,
		  req->extent.parent_snapshot);

	ii = SSDFS_I(req->result.pvec.pages[0]->mapping->host);

	tree = SSDFS_EXTREE(ii);
	if (!tree) {
		down_write(&ii->lock);
		err = ssdfs_extents_tree_create(fsi, ii);
		up_write(&ii->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to create extents tree: "
				  "err %d\n", err);
			return err;
		} else
			return -ENODATA;
	}

	requested_blk = req->extent.logical_offset >> fsi->log_pagesize;
	requested_len = (req->extent.data_bytes + pagesize - 1) >>
				fsi->log_pagesize;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);

	err = ssdfs_extents_tree_find_fork(tree, requested_blk, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the fork: "
			  "blk %llu, err %d\n",
			  requested_blk, err);
		goto finish_prepare_volume_extent;
	}

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		/* expected state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid result state %#x\n",
			  search->result.state);
		goto finish_prepare_volume_extent;
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
		goto finish_prepare_volume_extent;
	}

	if (!search->result.buf) {
		err = -ERANGE;
		SSDFS_ERR("empty result buffer pointer\n");
		goto finish_prepare_volume_extent;
	}

	if (search->result.items_in_buffer == 0) {
		err = -ERANGE;
		SSDFS_ERR("items_in_buffer %u\n",
			  search->result.items_in_buffer);
		goto finish_prepare_volume_extent;
	}

	fork = (struct ssdfs_raw_fork *)search->result.buf;
	start_blk = le64_to_cpu(fork->start_offset);
	blks_count = le64_to_cpu(fork->blks_count);

	for (i = 0; i < SSDFS_INLINE_EXTENTS_COUNT; extent = NULL, i++) {
		if (processed_blks >= blks_count)
			break;

		extent = &fork->extents[i];

		seg_id = le64_to_cpu(extent->seg_id);
		logical_blk = le32_to_cpu(extent->logical_blk);
		len = le32_to_cpu(extent->len);

		if (seg_id == U64_MAX || logical_blk == U32_MAX ||
		    len == U32_MAX) {
			err = -ERANGE;
			SSDFS_ERR("corrupted extent: index %d\n", i);
			goto finish_prepare_volume_extent;
		}

		if (len == 0) {
			err = -ERANGE;
			SSDFS_ERR("corrupted extent: index %d\n", i);
			goto finish_prepare_volume_extent;
		}

		if ((start_blk + processed_blks) <= requested_blk &&
		    requested_blk < (start_blk + processed_blks + len)) {
			u64 diff = requested_blk - (start_blk + processed_blks);

			logical_blk += (u32)diff;
			len -= (u32)diff;
			len = min_t(u32, len, requested_len);
			break;
		}

		processed_blks += len;
	}

	if (!extent) {
		err = -ENODATA;
		SSDFS_DBG("extent hasn't been found\n");
		goto finish_prepare_volume_extent;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_blk >= U16_MAX);
	BUG_ON(len >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_define_segment(seg_id, req);
	ssdfs_request_define_volume_extent((u16)logical_blk, (u16)len, req);

finish_prepare_volume_extent:
	ssdfs_btree_search_free(search);
	return err;
}

/*
 * ssdfs_extents_tree_has_logical_block() - check that block exists
 * @blk_offset: offset of logical block into file
 * @inode: pointer on VFS inode
 */
bool ssdfs_extents_tree_has_logical_block(u64 blk_offset, struct inode *inode)
{
	struct ssdfs_inode_info *ii;
	struct ssdfs_extents_btree_info *tree;
	struct ssdfs_btree_search *search;
	ino_t ino;
	bool is_found = false;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!inode);
#endif /* CONFIG_SSDFS_DEBUG */

	ii = SSDFS_I(inode);
	ino = inode->i_ino;

	SSDFS_DBG("ino %lu, blk_offset %llu\n",
		  ino, blk_offset);

	tree = SSDFS_EXTREE(ii);
	if (!tree) {
		SSDFS_DBG("extents tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return false;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return false;
	}

	ssdfs_btree_search_init(search);

	err = ssdfs_extents_tree_find_fork(tree, blk_offset, search);
	if (err == -ENODATA)
		is_found = false;
	else if (unlikely(err)) {
		is_found = false;
		SSDFS_ERR("fail to find the fork: "
			  "blk %llu, err %d\n",
			  blk_offset, err);
	} else
		is_found = true;

	ssdfs_btree_search_free(search);

	return is_found;
}

/*
 * ssdfs_extents_tree_add_block() - add block into extents tree
 * @inode: pointer on VFS inode
 * @req: pointer on segment request [in]
 *
 * This method tries to add a logical block into extents tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - extents tree is unable to add requested block(s).
 * %-EEXIST     - extent exists in the tree.
 */
int ssdfs_extents_tree_add_block(struct inode *inode,
				 struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_inode_info *ii;
	struct ssdfs_extents_btree_info *tree;
	struct ssdfs_btree_search *search;
	struct ssdfs_raw_extent extent;
	ino_t ino;
	u64 requested_blk;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!inode || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(inode->i_sb);
	ii = SSDFS_I(inode);
	ino = inode->i_ino;

	SSDFS_DBG("ino %lu, logical_offset %llu, "
		  "seg_id %llu, start_blk %u, len %u\n",
		  ino, req->extent.logical_offset,
		  req->place.start.seg_id,
		  req->place.start.blk_index, req->place.len);

	tree = SSDFS_EXTREE(ii);
	if (!tree) {
		down_write(&ii->lock);
		err = ssdfs_extents_tree_create(fsi, ii);
		up_write(&ii->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to create extents tree: "
				  "err %d\n", err);
			return err;
		}
	}

	requested_blk = req->extent.logical_offset >> fsi->log_pagesize;
	extent.seg_id = cpu_to_le64(req->place.start.seg_id);
	extent.logical_blk = cpu_to_le32(req->place.start.blk_index);
	extent.len = cpu_to_le32(req->place.len);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ERANGE;
	}

	ssdfs_btree_search_init(search);

	err = ssdfs_extents_tree_add_extent(tree, requested_blk,
					    &extent, search);

	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to add block into the tree: "
			  "blk %llu, err %d\n",
			  requested_blk, err);
	}

	return err;
}

/*
 * ssdfs_extents_tree_truncate() - truncate extents tree
 * @inode: pointer on VFS inode
 *
 * This method tries to truncate extents tree.
 *
 *       The key trick with truncate operation that it is possible
 *       to store inline forks in the inode and to place the whole
 *       heirarchy into the shared extents tree. This is the case
 *       of deletion the whole file or practically the whole
 *       file. The shared tree's thread will be responsible for
 *       the real invalidation in the background. If we truncate
 *       the file partially then we could simply correct the whole
 *       length of the file and to delegate the responsibility
 *       to truncate all invalidated extents of the tree to the
 *       thread of shared extents tree.
 *
 *       Usually, if we need to truncate some file then we need to find
 *       the position of the extent that will be truncated. Finally,
 *       we will know the whole hierarchy path from the root node
 *       till the leaf one. So, all forks/extents after truncated one
 *       should be added into the pre-invalidated list and to be
 *       deleted or to be obsolete into the leaf node. Also all index
 *       records should be deleted from all parent nodes and needs
 *       to be placed into pre-invalidated list of the shared extents tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_extents_tree_truncate(struct inode *inode)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_inode_info *ii;
	struct ssdfs_extents_btree_info *tree;
	struct ssdfs_btree_search *search;
	ino_t ino;
	loff_t size;
	u64 blk_offset;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!inode);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(inode->i_sb);
	ii = SSDFS_I(inode);
	ino = inode->i_ino;
	size = i_size_read(inode);

	SSDFS_DBG("ino %lu, size %llu\n",
		  ino, size);

	tree = SSDFS_EXTREE(ii);
	if (!tree) {
		SSDFS_DBG("extents tree is absent: ino %lu\n",
			  ii->vfs_inode.i_ino);
		return -ENOENT;
	}

	blk_offset = (u64)size + fsi->log_pagesize - 1;
	blk_offset >>= fsi->log_pagesize;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ERANGE;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_extents_tree_truncate_extent(tree, blk_offset, 0, search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to truncate the tree: "
			  "blk %llu, err %d\n",
			  blk_offset, err);
	}

	return err;
}

/******************************************************************************
 *                     EXTENTS TREE OBJECT FUNCTIONALITY                      *
 ******************************************************************************/

/*
 * need_initialize_extent_btree_search() - check necessity to init the search
 * @blk: logical block number
 * @search: search object
 */
static inline
bool need_initialize_extent_btree_search(u64 blk,
					 struct ssdfs_btree_search *search)
{
	return need_initialize_btree_search(search) ||
		search->request.start.hash != blk;
}

/*
 * ssdfs_extents_tree_find_inline_fork() - find an inline fork in the tree
 * @tree: extents tree
 * @blk: logical block number
 * @search: search object
 *
 * This method tries to find a fork for the requested @blk.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - item hasn't been found
 */
static
int ssdfs_extents_tree_find_inline_fork(struct ssdfs_extents_btree_info *tree,
					u64 blk,
					struct ssdfs_btree_search *search)
{
	u64 forks_count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, blk %llu, search %p\n",
		  tree, blk, search);

	if (atomic_read(&tree->type) != SSDFS_INLINE_FORKS_ARRAY) {
		SSDFS_ERR("invalid tree type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	forks_count = (u64)atomic64_read(&tree->forks_count);

	if (forks_count < 0) {
		SSDFS_ERR("invalid forks_count %llu\n",
			  forks_count);
		return -ERANGE;
	} else if (forks_count == 0) {
		SSDFS_DBG("empty tree\n");
		search->result.state = SSDFS_BTREE_SEARCH_OUT_OF_RANGE;
		search->result.err = -ENODATA;
		search->result.start_index = U16_MAX;
		search->result.count = 0;
		search->result.search_cno = ssdfs_current_cno(tree->fsi->sb);
		search->result.buf_state =
				SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
		search->result.buf = NULL;
		search->result.buf_size = 0;
		search->result.items_in_buffer = 0;
		return -ENODATA;
	} else if (forks_count > SSDFS_INLINE_FORKS_COUNT) {
		SSDFS_ERR("invalid forks_count %llu\n",
			  forks_count);
		return -ERANGE;
	}

	if (!tree->inline_forks) {
		SSDFS_ERR("inline forks haven't been initialized\n");
		return -ERANGE;
	}

	for (i = 0; i < forks_count; i++) {
		struct ssdfs_raw_fork *fork;
		u64 start;
		u64 blks_count;

		search->result.state = SSDFS_BTREE_SEARCH_UNKNOWN_RESULT;

		fork = &tree->inline_forks[i];
		start = le64_to_cpu(fork->start_offset);
		blks_count = le64_to_cpu(fork->blks_count);

		if (start >= U64_MAX || blks_count >= U64_MAX) {
			SSDFS_ERR("invalid fork state: "
				  "start_offset %llu, blks_count %llu\n",
				  start, blks_count);
			return -ERANGE;
		}

		memcpy(&search->raw.fork, fork, sizeof(struct ssdfs_raw_fork));

		search->result.err = 0;
		search->result.start_index = (u16)i;
		search->result.count = 1;
		search->result.search_cno = ssdfs_current_cno(tree->fsi->sb);
		search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
		search->result.buf = &search->raw.fork;
		search->result.buf_size = sizeof(struct ssdfs_raw_fork);
		search->result.items_in_buffer = 1;

		if (blk < start) {
			err = -ENODATA;
			search->result.err = -ENODATA;
			search->result.state =
				SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
			goto finish_search_inline_fork;
		} else if (start <= blk && blk < (start + blks_count)) {
			search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;
			goto finish_search_inline_fork;
		}
	}

	err = -ENODATA;
	search->result.err = -ENODATA;
	search->result.state = SSDFS_BTREE_SEARCH_OUT_OF_RANGE;

finish_search_inline_fork:
	return err;
}

/*
 * ssdfs_extents_tree_find_fork() - find a fork in the tree
 * @tree: extents tree
 * @blk: logical block number
 * @search: search object
 *
 * This method tries to find a fork for the requested @blk.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - item hasn't been found
 */
int ssdfs_extents_tree_find_fork(struct ssdfs_extents_btree_info *tree,
				 u64 blk,
				 struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, blk %llu, search %p\n",
		  tree, blk, search);

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_extent_btree_search(blk, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = blk;
		search->request.end.hash = blk;
		search->request.count = 1;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		down_read(&tree->lock);
		err = ssdfs_extents_tree_find_inline_fork(tree, blk, search);
		up_read(&tree->lock);

		if (err == -ENODATA) {
			SSDFS_ERR("unable to find the inline fork: "
				  "blk %llu\n",
				  blk);
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline fork: "
				  "blk %llu, err %d\n",
				  blk, err);
		}
		break;

	case SSDFS_PRIVATE_EXTENTS_BTREE:
		down_read(&tree->lock);
		err = ssdfs_btree_find_item(tree->generic_tree, search);
		up_read(&tree->lock);

		if (err == -ENODATA) {
			SSDFS_ERR("unable to find the fork: "
				  "blk %llu\n",
				  blk);
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the fork: "
				  "blk %llu, err %d\n",
				  blk, err);
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid extents tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/*
 * ssdfs_add_head_extent_into_fork() - add head extent into the fork
 * @blk: logical block number
 * @extent: raw extent
 * @fork: raw fork
 *
 * This method tries to add @extent into the head of fork.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - need to add a new fork in the tree.
 */
static
int ssdfs_add_head_extent_into_fork(u64 blk,
				    struct ssdfs_raw_extent *extent,
				    struct ssdfs_raw_fork *fork)
{
	struct ssdfs_raw_extent *cur;
	u64 seg1, seg2;
	u32 lblk1, lblk2;
	u32 len1, len2;
	u64 blks_count, counted_blks;
	int valid_extents;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent || !fork);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk %llu, extent %p, fork %p\n",
		  blk, extent, fork);

	if (blk >= U64_MAX) {
		SSDFS_ERR("invalid blk %llu\n", blk);
		return -EINVAL;
	}

	blks_count = le64_to_cpu(fork->blks_count);

	seg2 = le64_to_cpu(extent->seg_id);
	lblk2 = le32_to_cpu(extent->logical_blk);
	len2 = le32_to_cpu(extent->len);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg2 >= U64_MAX);
	BUG_ON(lblk2 >= U32_MAX);
	BUG_ON(len2 >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (blks_count == 0 || blks_count >= U64_MAX) {
		fork->start_offset = cpu_to_le64(blk);
		fork->blks_count = cpu_to_le64(len2);
		memcpy(cur, extent, sizeof(struct ssdfs_raw_extent));
		return 0;
	} else if (le64_to_cpu(fork->start_offset) >= U64_MAX) {
		SSDFS_ERR("corrupted fork: "
			  "start_offset %llu, blks_count %llu\n",
			  le64_to_cpu(fork->start_offset),
			  blks_count);
		return -ERANGE;
	}

	if ((blk + len2) != le64_to_cpu(fork->start_offset)) {
		SSDFS_DBG("unable to add the hole into fork: "
			  "blk %llu, len %u, start_offset %llu\n",
			  blk, len2,
			  le64_to_cpu(fork->start_offset));
		return -ENOSPC;
	}

	counted_blks = 0;
	valid_extents = 0;
	for (i = 0; i < SSDFS_INLINE_EXTENTS_COUNT; i++) {
		u32 len;

		cur = &fork->extents[i];
		len = le32_to_cpu(cur->len);

		if (len >= U32_MAX)
			break;
		else {
			counted_blks += len;
			valid_extents++;
		}
	}

	if (counted_blks != blks_count) {
		SSDFS_ERR("corrupted fork: "
			  "counted_blks %llu, blks_count %llu\n",
			  counted_blks, blks_count);
		return -ERANGE;
	}

	if (valid_extents > SSDFS_INLINE_EXTENTS_COUNT ||
	    valid_extents == 0) {
		SSDFS_ERR("invalid valid_extents count %d\n",
			  valid_extents);
		return -ERANGE;
	}

	cur = &fork->extents[0];

	seg1 = le64_to_cpu(cur->seg_id);
	lblk1 = le32_to_cpu(cur->logical_blk);
	len1 = le32_to_cpu(cur->len);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg1 >= U64_MAX);
	BUG_ON(lblk1 >= U32_MAX);
	BUG_ON(len1 >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (seg1 == seg2 && (lblk2 + len2) == lblk1) {
		if ((U32_MAX - len2) <= len1) {
			SSDFS_DBG("unable to merge to extents: "
				  "len1 %u, len2 %u\n",
				  len1, len2);
			goto add_extent_into_fork;
		}

		cur->logical_blk = cpu_to_le32(lblk2);
		le32_add_cpu(&cur->len, len2);
	} else {
add_extent_into_fork:
		if (valid_extents == SSDFS_INLINE_EXTENTS_COUNT) {
			SSDFS_DBG("unable to add extent: "
				  "valid_extents %u\n",
				  valid_extents);
			return -ENOSPC;
		}

		memmove(&fork->extents[1],
			&fork->extents[0],
			valid_extents * sizeof(struct ssdfs_raw_extent));
		memcpy(cur, extent, sizeof(struct ssdfs_raw_extent));
	}

	fork->start_offset = cpu_to_le64(blk);
	le64_add_cpu(&fork->blks_count, len2);

	return 0;
}

/*
 * ssdfs_add_tail_extent_into_fork() - add tail extent into the fork
 * @blk: logical block number
 * @extent: raw extent
 * @fork: raw fork
 *
 * This method tries to add @extent into the tail of fork.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - need to add a new fork in the tree.
 */
static
int ssdfs_add_tail_extent_into_fork(u64 blk,
				    struct ssdfs_raw_extent *extent,
				    struct ssdfs_raw_fork *fork)
{
	struct ssdfs_raw_extent *cur;
	u64 seg1, seg2;
	u32 lblk1, lblk2;
	u32 len1, len2;
	u64 start_offset;
	u64 blks_count, counted_blks;
	int valid_extents;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent || !fork);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk %llu, extent %p, fork %p\n",
		  blk, extent, fork);

	if (blk >= U64_MAX) {
		SSDFS_ERR("invalid blk %llu\n", blk);
		return -EINVAL;
	}

	blks_count = le64_to_cpu(fork->blks_count);

	seg2 = le64_to_cpu(extent->seg_id);
	lblk2 = le32_to_cpu(extent->logical_blk);
	len2 = le32_to_cpu(extent->len);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg2 >= U64_MAX);
	BUG_ON(lblk2 >= U32_MAX);
	BUG_ON(len2 >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	start_offset = le64_to_cpu(fork->start_offset);

	if (blks_count == 0 || blks_count >= U64_MAX) {
		fork->start_offset = cpu_to_le64(blk);
		fork->blks_count = cpu_to_le64(len2);
		memcpy(cur, extent, sizeof(struct ssdfs_raw_extent));
		return 0;
	} else if (start_offset >= U64_MAX) {
		SSDFS_ERR("corrupted fork: "
			  "start_offset %llu, blks_count %llu\n",
			  start_offset, blks_count);
		return -ERANGE;
	}

	if ((start_offset + blks_count) != blk) {
		SSDFS_DBG("unable to add the hole into fork: "
			  "blk %llu, len %u, start_offset %llu\n",
			  blk, len2, start_offset);
		return -ENOSPC;
	}

	counted_blks = 0;
	valid_extents = 0;
	for (i = 0; i < SSDFS_INLINE_EXTENTS_COUNT; i++) {
		u32 len;

		cur = &fork->extents[i];
		len = le32_to_cpu(cur->len);

		if (len >= U32_MAX)
			break;
		else {
			counted_blks += len;
			valid_extents++;
		}
	}

	if (counted_blks != blks_count) {
		SSDFS_ERR("corrupted fork: "
			  "counted_blks %llu, blks_count %llu\n",
			  counted_blks, blks_count);
		return -ERANGE;
	}

	if (valid_extents > SSDFS_INLINE_EXTENTS_COUNT ||
	    valid_extents == 0) {
		SSDFS_ERR("invalid valid_extents count %d\n",
			  valid_extents);
		return -ERANGE;
	}

	cur = &fork->extents[valid_extents - 1];

	seg1 = le64_to_cpu(cur->seg_id);
	lblk1 = le32_to_cpu(cur->logical_blk);
	len1 = le32_to_cpu(cur->len);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg1 >= U64_MAX);
	BUG_ON(lblk1 >= U32_MAX);
	BUG_ON(len1 >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (seg1 == seg2 && (lblk1 + len1) == lblk2) {
		if ((U32_MAX - len2) <= len1) {
			SSDFS_DBG("unable to merge to extents: "
				  "len1 %u, len2 %u\n",
				  len1, len2);
			goto add_extent_into_fork;
		}

		le32_add_cpu(&cur->len, len2);
	} else {
add_extent_into_fork:
		if (valid_extents == SSDFS_INLINE_EXTENTS_COUNT) {
			SSDFS_DBG("unable to add extent: "
				  "valid_extents %u\n",
				  valid_extents);
			return -ENOSPC;
		}

		cur = &fork->extents[valid_extents];
		memcpy(cur, extent, sizeof(struct ssdfs_raw_extent));
	}

	le64_add_cpu(&fork->blks_count, len2);

	return 0;
}

/*
 * ssdfs_add_extent_into_fork() - add extent into the fork
 * @blk: logical block number
 * @extent: raw extent
 * @search: search object
 *
 * This method tries to add @extent into the fork.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - fork doesn't exist.
 * %-ENOSPC     - need to add a new fork in the tree.
 * %-EEXIST     - extent exists in the fork.
 */
static
int ssdfs_add_extent_into_fork(u64 blk,
				struct ssdfs_raw_extent *extent,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_fork *fork;
	u64 start_offset;
	u64 blks_count;
	u32 len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk %llu, extent %p, search %p\n",
		  blk, extent, search);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_EMPTY_RESULT:
		SSDFS_DBG("no fork in search object\n");
		return -ENODATA;

	case SSDFS_BTREE_SEARCH_VALID_ITEM:
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid search object state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid search buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	if (search->result.buf_size != sizeof(struct ssdfs_raw_fork) ||
	    search->result.items_in_buffer != 1) {
		SSDFS_ERR("invalid search buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	fork = &search->raw.fork;
	start_offset = le64_to_cpu(fork->start_offset);
	blks_count = le64_to_cpu(fork->blks_count);
	len = le32_to_cpu(extent->len);

	if (start_offset >= U64_MAX || blks_count >= U64_MAX) {
		SSDFS_ERR("invalid fork state: "
			  "start_offset %llu, blks_count %llu\n",
			  start_offset, blks_count);
		return -ERANGE;
	}

	if (blk >= U64_MAX || len >= U32_MAX) {
		SSDFS_ERR("invalid extent: "
			  "blk %llu, len %u\n",
			  blk, len);
		return -ERANGE;
	}

	if (start_offset <= blk && blk < (start_offset + blks_count)) {
		SSDFS_ERR("extent exists in the fork: "
			  "fork (start %llu, blks_count %llu), "
			  "extent (blk %llu, len %u)\n",
			  start_offset, blks_count,
			  blk, len);
		return -EEXIST;
	}

	if (start_offset < (blk + len) &&
	    (blk + len) < (start_offset + blks_count)) {
		SSDFS_ERR("extent exists in the fork: "
			  "fork (start %llu, blks_count %llu), "
			  "extent (blk %llu, len %u)\n",
			  start_offset, blks_count,
			  blk, len);
		return -EEXIST;
	}

	if (blk < start_offset && (blk + len) < start_offset) {
		SSDFS_DBG("need to add the fork: "
			  "fork (start %llu, blks_count %llu), "
			  "extent (blk %llu, len %u)\n",
			  start_offset, blks_count,
			  blk, len);
		return -ENOSPC;
	}

	if (blk > (start_offset + blks_count)) {
		SSDFS_DBG("need to add the fork: "
			  "fork (start %llu, blks_count %llu), "
			  "extent (blk %llu, len %u)\n",
			  start_offset, blks_count,
			  blk, len);
		return -ENOSPC;
	}

	if ((blk + len) == start_offset) {
		err = ssdfs_add_head_extent_into_fork(blk, extent, fork);
		if (err == -ENOSPC) {
			SSDFS_DBG("need to add the fork: "
				  "fork (start %llu, blks_count %llu), "
				  "extent (blk %llu, len %u)\n",
				  start_offset, blks_count,
				  blk, len);
			return err;
		} else {
			SSDFS_ERR("fail to add the head extent into fork: "
				  "fork (start %llu, blks_count %llu), "
				  "extent (blk %llu, len %u)\n",
				  start_offset, blks_count,
				  blk, len);
			return err;
		}
	} else if ((start_offset + blks_count) == blk) {
		err = ssdfs_add_tail_extent_into_fork(blk, extent, fork);
		if (err == -ENOSPC) {
			SSDFS_DBG("need to add the fork: "
				  "fork (start %llu, blks_count %llu), "
				  "extent (blk %llu, len %u)\n",
				  start_offset, blks_count,
				  blk, len);
			return err;
		} else {
			SSDFS_ERR("fail to add the tail extent into fork: "
				  "fork (start %llu, blks_count %llu), "
				  "extent (blk %llu, len %u)\n",
				  start_offset, blks_count,
				  blk, len);
			return err;
		}
	} else {
		SSDFS_ERR("invalid extent: "
			  "fork (start %llu, blks_count %llu), "
			  "extent (blk %llu, len %u)\n",
			  start_offset, blks_count,
			  blk, len);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_prepare_empty_fork() - prepare empty fork
 * @blk: block number
 * @search: search object
 *
 * This method tries to prepare empty fork for @blk into
 * @search object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_prepare_empty_fork(u64 blk,
			     struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk %llu, search %p\n",
		  blk, search);

	search->result.state = SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
	search->result.err = 0;
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.start_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	search->result.start_index++;
	search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
	search->result.buf = &search->raw.fork;
	search->result.buf_size = sizeof(struct ssdfs_raw_fork);
	search->result.items_in_buffer = 1;

	memset(&search->raw.fork, 0xFF, sizeof(struct ssdfs_raw_fork));
	return 0;
}

/*
 * ssdfs_extents_tree_add_inline_fork() - add the inline fork into the tree
 * @tree: extents tree
 * @search: search object
 *
 * This method tries to add the inline fork into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - inline tree hasn't room for the new fork.
 * %-EEXIST     - fork exists in the tree.
 */
static
int ssdfs_extents_tree_add_inline_fork(struct ssdfs_extents_btree_info *tree,
				       struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_fork *cur;
	s64 forks_count, forks_capacity;
	int private_flags;
	u64 start_hash;
	u16 start_index;
	u64 hash1, hash2;
	u64 len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->inline_forks) {
		SSDFS_ERR("empty inline tree %p\n",
			  tree->inline_forks);
		return -ERANGE;
	}

	forks_count = atomic64_read(&tree->forks_count);

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	private_flags = atomic_read(&tree->owner->private_flags);

	forks_capacity = SSDFS_INLINE_FORKS_COUNT;
	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE)
		forks_capacity--;
	if (private_flags & SSDFS_INODE_HAS_EXTENTS_BTREE) {
		SSDFS_ERR("the extents tree is generic\n");
		return -ERANGE;
	}

	if (forks_count > forks_capacity) {
		SSDFS_WARN("extents tree is corrupted: "
			   "forks_count %llu, forks_capacity %llu\n",
			   (u64)forks_count, (u64)forks_capacity);
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_CORRUPTED);
		return -ERANGE;
	} else if (forks_count == forks_capacity) {
		SSDFS_DBG("inline tree hasn't room for the new fork: "
			  "forks_count %llu, forks_capacity %llu\n",
			  (u64)forks_count, (u64)forks_capacity);
		return -ENOSPC;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND) {
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	if (start_hash != le64_to_cpu(search->raw.fork.start_offset)) {
		SSDFS_ERR("corrupted fork: "
			  "start_hash %llx, "
			  "fork (start %llu, blks_count %llu)\n",
			  start_hash,
			  le64_to_cpu(search->raw.fork.start_offset),
			  le64_to_cpu(search->raw.fork.blks_count));
		return -ERANGE;
	}

	start_index = search->result.start_index;

	if (forks_count == 0) {
		if (start_index != 0) {
			SSDFS_ERR("invalid start_index %u\n",
				  start_index);
			return -ERANGE;
		}

		cur = &tree->inline_forks[start_index];

		memcpy(cur, &search->raw.fork,
			sizeof(struct ssdfs_raw_fork));
	} else {
		if (start_index >= forks_capacity) {
			SSDFS_ERR("start_index %u >= forks_capacity %llu\n",
				  start_index, (u64)forks_capacity);
			return -ERANGE;
		}

		cur = &tree->inline_forks[start_index];

		if ((start_index + 1) <= forks_count) {
			memmove(&tree->inline_forks[start_index + 1],
				cur,
				(forks_count - start_index) *
					sizeof(struct ssdfs_raw_fork));
			memcpy(cur, &search->raw.fork,
				sizeof(struct ssdfs_raw_fork));

			hash1 = le64_to_cpu(search->raw.fork.start_offset);
			len = le64_to_cpu(search->raw.fork.blks_count);

			cur = &tree->inline_forks[start_index + 1];
			hash2 = le64_to_cpu(cur->start_offset);

			if (!((hash1 + len) <= hash2)) {
				SSDFS_WARN("fork is corrupted: "
					   "hash1 %llu, len %llu, "
					   "hash2 %llu\n",
					   hash1, len, hash2);
				atomic_set(&tree->state,
					SSDFS_EXTENTS_BTREE_CORRUPTED);
				return -ERANGE;
			}
		} else {
			memcpy(cur, &search->raw.fork,
				sizeof(struct ssdfs_raw_fork));

			if (start_index > 0) {
				cur = &tree->inline_forks[start_index - 1];

				hash1 = le64_to_cpu(cur->start_offset);
				len = le64_to_cpu(cur->blks_count);
				hash2 =
				    le64_to_cpu(search->raw.fork.start_offset);

				if (!((hash1 + len) <= hash2)) {
					SSDFS_WARN("fork is corrupted: "
						   "hash1 %llu, len %llu, "
						   "hash2 %llu\n",
						   hash1, len, hash2);
					atomic_set(&tree->state,
						SSDFS_EXTENTS_BTREE_CORRUPTED);
					return -ERANGE;
				}
			}
		}
	}

	forks_count = atomic64_inc_return(&tree->forks_count);
	if (forks_count > forks_capacity) {
		SSDFS_WARN("forks_count is too much: "
			   "count %lld, capacity %lld\n",
			   forks_count, forks_capacity);
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_CORRUPTED);
		return -ERANGE;
	}

	atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_extents_tree_add_fork() - add the fork into the tree
 * @tree: extents tree
 * @search: search object
 *
 * This method tries to add the generic fork into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - fork exists in the tree.
 */
static
int ssdfs_extents_tree_add_fork(struct ssdfs_extents_btree_info *tree,
				struct ssdfs_btree_search *search)
{
	s64 forks_count;
	u64 start_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_EXTENTS_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->generic_tree) {
		SSDFS_ERR("empty generic tree %p\n",
			  tree->generic_tree);
		return -ERANGE;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND) {
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	if (start_hash != le64_to_cpu(search->raw.fork.start_offset)) {
		SSDFS_ERR("corrupted fork: "
			  "start_hash %llx, "
			  "fork (start %llu, blks_count %llu)\n",
			  start_hash,
			  le64_to_cpu(search->raw.fork.start_offset),
			  le64_to_cpu(search->raw.fork.blks_count));
		return -ERANGE;
	}

	err = ssdfs_btree_add_item(tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add the fork into the tree: "
			  "err %d\n", err);
		return err;
	}

	forks_count = atomic64_inc_return(&tree->forks_count);
	if (forks_count >= S64_MAX) {
		SSDFS_WARN("forks_count is too much\n");
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_CORRUPTED);
		return -ERANGE;
	}

	atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_extents_tree_change_inline_fork() - change inline fork
 * @tree: extents tree
 * @search: search object
 *
 * This method tries to change the existing inline fork.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - fork doesn't exist in the tree.
 */
static
int ssdfs_extents_tree_change_inline_fork(struct ssdfs_extents_btree_info *tree,
					  struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shared_extents_tree *shextree;
	struct ssdfs_raw_fork *cur;
	ino_t ino;
	u64 start_hash;
	int private_flags;
	s64 forks_count, forks_capacity;
	u16 start_index;
	int lower_bound, upper_bound;
	int i, j;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	fsi = tree->fsi;
	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	ino = tree->owner->vfs_inode.i_ino;

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->inline_forks) {
		SSDFS_ERR("empty inline tree %p\n",
			  tree->inline_forks);
		return -ERANGE;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	if (start_hash != le64_to_cpu(search->raw.fork.start_offset)) {
		SSDFS_ERR("corrupted fork: "
			  "start_hash %llx, "
			  "fork (start %llu, blks_count %llu)\n",
			  start_hash,
			  le64_to_cpu(search->raw.fork.start_offset),
			  le64_to_cpu(search->raw.fork.blks_count));
		return -ERANGE;
	}

	forks_count = atomic64_read(&tree->forks_count);

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	private_flags = atomic_read(&tree->owner->private_flags);

	forks_capacity = SSDFS_INLINE_FORKS_COUNT;
	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE)
		forks_capacity--;
	if (private_flags & SSDFS_INODE_HAS_EXTENTS_BTREE) {
		SSDFS_ERR("the extents tree is generic\n");
		return -ERANGE;
	}

	if (forks_count > forks_capacity) {
		SSDFS_WARN("extents tree is corrupted: "
			   "forks_count %lld, forks_capacity %lld\n",
			   forks_count, forks_capacity);
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_CORRUPTED);
		return -ERANGE;
	} else if (forks_count == 0) {
		SSDFS_ERR("empty tree\n");
		return -ENODATA;
	}

	start_index = search->result.start_index;

	if (start_index >= forks_count) {
		SSDFS_ERR("start_index %u >= forks_count %lld\n",
			  start_index, forks_count);
		return -ENODATA;
	}

	cur = &tree->inline_forks[start_index];
	memcpy(cur, &search->raw.fork, sizeof(struct ssdfs_raw_fork));
	atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_DIRTY);

	if (search->request.type == SSDFS_BTREE_SEARCH_INVALIDATE_TAIL) {
		lower_bound = search->result.start_index;
		upper_bound = forks_count - 1;

		for (i = upper_bound; i >= lower_bound; i--) {
			u64 calculated = 0;
			u64 blks_count;

			cur = &tree->inline_forks[i];

			if (atomic64_read(&tree->forks_count) == 0) {
				SSDFS_ERR("invalid forks_count\n");
				return -ERANGE;
			} else
				atomic64_dec(&tree->forks_count);

			blks_count = le64_to_cpu(cur->blks_count);
			if (blks_count == 0 || blks_count >= U64_MAX) {
				memset(cur, 0xFF,
					sizeof(struct ssdfs_raw_fork));
				continue;
			}

			for (j = SSDFS_INLINE_EXTENTS_COUNT - 1; j >= 0; j--) {
				struct ssdfs_raw_extent *extent;
				u32 len;

				extent = &cur->extents[j];
				len = le32_to_cpu(extent->len);

				if (len == 0 || len >= U32_MAX) {
					memset(extent, 0xFF,
					    sizeof(struct ssdfs_raw_extent));
					continue;
				}

				if ((calculated + len) > blks_count) {
					atomic_set(&tree->state,
						SSDFS_EXTENTS_BTREE_CORRUPTED);
					SSDFS_ERR("corrupted extent: "
						  "calculated %llu, len %u, "
						  "blks %llu\n",
						  calculated, len, blks_count);
					return -ERANGE;
				}

				err =
				 ssdfs_shextree_add_pre_invalid_extent(shextree,
									ino,
									extent);
				if (unlikely(err)) {
					SSDFS_ERR("fail to add pre-invalid "
						  "(seg_id %llu, blk %u, "
						  "len %u), err %d\n",
					    le64_to_cpu(extent->seg_id),
					    le32_to_cpu(extent->logical_blk),
					    len, err);
					return err;
				}

				calculated += len;

				memset(extent, 0xFF,
					sizeof(struct ssdfs_raw_extent));
			}

			if (calculated != blks_count) {
				atomic_set(&tree->state,
					   SSDFS_EXTENTS_BTREE_CORRUPTED);
				SSDFS_ERR("calculated %llu != blks %llu\n",
					  calculated, blks_count);
				return -ERANGE;
			}
		}
	}

	return 0;
}

/*
 * ssdfs_extents_tree_change_fork() - change the fork
 * @tree: extents tree
 * @search: search object
 *
 * This method tries to change the existing generic fork.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - fork doesn't exist in the tree.
 */
static
int ssdfs_extents_tree_change_fork(struct ssdfs_extents_btree_info *tree,
				   struct ssdfs_btree_search *search)
{
	u64 start_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_EXTENTS_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->generic_tree) {
		SSDFS_ERR("empty generic tree %p\n",
			  tree->generic_tree);
		return -ERANGE;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	if (start_hash != le64_to_cpu(search->raw.fork.start_offset)) {
		SSDFS_ERR("corrupted fork: "
			  "start_hash %llx, "
			  "fork (start %llu, blks_count %llu)\n",
			  start_hash,
			  le64_to_cpu(search->raw.fork.start_offset),
			  le64_to_cpu(search->raw.fork.blks_count));
		return -ERANGE;
	}

	err = ssdfs_btree_change_item(tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change the fork into the tree: "
			  "err %d\n", err);
		return err;
	}

	atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_extents_tree_add_extent() - add extent into the tree
 * @tree: extents tree
 * @blk: logical block number
 * @extent: new extent
 * @search: search object
 *
 * This method tries to add @extent into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - extent exists in the tree.
 */
int ssdfs_extents_tree_add_extent(struct ssdfs_extents_btree_info *tree,
				  u64 blk,
				  struct ssdfs_raw_extent *extent,
				  struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !extent || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p, blk %llu\n",
		  tree, search, blk);

	down_write(&tree->lock);

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_extent_btree_search(blk, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = blk;
		search->request.end.hash = blk;
		search->request.count = 1;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		goto finish_add_extent;
	};

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		err = ssdfs_extents_tree_find_inline_fork(tree, blk, search);
		if (err == -ENODATA) {
			/*
			 * Fork doesn't exist for requested extent.
			 * It needs to create a new fork.
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline fork: "
				  "blk %llu, err %d\n",
				  blk, err);
			goto finish_add_extent;
		}

		if (err == -ENODATA) {
add_new_inline_fork:
			err = ssdfs_prepare_empty_fork(blk, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare empty fork: "
					  "err %d\n",
					  err);
				goto finish_add_extent;
			}

			err = ssdfs_add_extent_into_fork(blk, extent, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add extent into fork: "
					  "err %d\n",
					  err);
				goto finish_add_extent;
			}

			search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;
			err = ssdfs_extents_tree_add_inline_fork(tree, search);
			if (err == -ENOSPC) {
				err = ssdfs_migrate_inline2generic_tree(tree);
				if (unlikely(err)) {
					SSDFS_ERR("fail to migrate the tree: "
						  "err %d\n",
						  err);
					goto finish_add_extent;
				} else {
					search->request.type =
						SSDFS_BTREE_SEARCH_FIND_ITEM;
					goto try_to_add_into_generic_tree;
				}
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to add fork: err %d\n", err);
				goto finish_add_extent;
			}
		} else {
			err = ssdfs_add_extent_into_fork(blk, extent, search);
			if (err == -ENOSPC) {
				/* try to add a new fork */
				goto add_new_inline_fork;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to add extent into fork: "
					  "err %d\n",
					  err);
				goto finish_add_extent;
			}

			search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;
			err = ssdfs_extents_tree_change_inline_fork(tree,
								   search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change fork: err %d\n", err);
				goto finish_add_extent;
			}
		}
		break;

	case SSDFS_PRIVATE_EXTENTS_BTREE:
try_to_add_into_generic_tree:
		err = ssdfs_btree_find_item(tree->generic_tree, search);
		if (err == -ENODATA) {
			/*
			 * Fork doesn't exist for requested extent.
			 * It needs to create a new fork.
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the fork: "
				  "blk %llu, err %d\n",
				  blk, err);
			goto finish_add_extent;
		}

		if (err == -ENODATA) {
add_new_generic_fork:
			err = ssdfs_prepare_empty_fork(blk, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare empty fork: "
					  "err %d\n",
					  err);
				goto finish_add_extent;
			}

			err = ssdfs_add_extent_into_fork(blk, extent, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add extent into fork: "
					  "err %d\n",
					  err);
				goto finish_add_extent;
			}

			search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;
			err = ssdfs_extents_tree_add_fork(tree, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add fork: err %d\n", err);
				goto finish_add_extent;
			}
		} else {
			err = ssdfs_add_extent_into_fork(blk, extent, search);
			if (err == -ENOSPC) {
				/* try to add a new fork */
				goto add_new_generic_fork;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to add extent into fork: "
					  "err %d\n",
					  err);
				goto finish_add_extent;
			}

			search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;
			err = ssdfs_extents_tree_change_fork(tree, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change fork: err %d\n", err);
				goto finish_add_extent;
			}
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid extents tree type %#x\n",
			  atomic_read(&tree->type));
		goto finish_add_extent;
	}

finish_add_extent:
	up_write(&tree->lock);

	return err;
}

/*
 * ssdfs_change_extent_in_fork() - change extent in the fork
 * @blk: logical block number
 * @extent: extent object
 * @search: search object
 *
 * This method tries to change @extent in the fork.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - extent doesn't exist in the fork.
 */
static
int ssdfs_change_extent_in_fork(u64 blk,
				struct ssdfs_raw_extent *extent,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_fork *fork;
	struct ssdfs_raw_extent *cur_extent = NULL;
	struct ssdfs_raw_extent buf;
	u64 start_offset;
	u64 blks_count;
	u32 len1, len2, len_diff;
	u64 cur_blk;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk %llu, extent %p, search %p\n",
		  blk, extent, search);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_EMPTY_RESULT:
		SSDFS_DBG("no fork in search object\n");
		return -ENODATA;

	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid search object state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid search buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	if (search->result.buf_size != sizeof(struct ssdfs_raw_fork) ||
	    search->result.items_in_buffer != 1) {
		SSDFS_ERR("invalid search buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	fork = &search->raw.fork;
	start_offset = le64_to_cpu(fork->start_offset);
	blks_count = le64_to_cpu(fork->blks_count);
	len1 = le32_to_cpu(extent->len);

	if (start_offset >= U64_MAX || blks_count >= U64_MAX) {
		SSDFS_ERR("invalid fork state: "
			  "start_offset %llu, blks_count %llu\n",
			  start_offset, blks_count);
		return -ERANGE;
	}

	if (blk >= U64_MAX || len1 >= U32_MAX) {
		SSDFS_ERR("invalid extent: "
			  "blk %llu, len %u\n",
			  blk, len1);
		return -ERANGE;
	}

	if (start_offset <= blk && blk < (start_offset + blks_count)) {
		/*
		 * Expected state
		 */
	} else {
		SSDFS_ERR("extent is out of fork: \n"
			  "fork (start %llu, blks_count %llu), "
			  "extent (blk %llu, len %u)\n",
			  start_offset, blks_count,
			  blk, len1);
		return -ENODATA;
	}

	cur_blk = le64_to_cpu(fork->start_offset);
	for (i = 0; i < SSDFS_INLINE_EXTENTS_COUNT; i++) {
		len2 = le32_to_cpu(fork->extents[i].len);

		if (cur_blk == blk) {
			/* extent is found */
			cur_extent = &fork->extents[i];
			break;
		} else if (blk < cur_blk) {
			SSDFS_ERR("invalid extent: "
				  "blk %llu, cur_blk %llu\n",
				  blk, cur_blk);
			return -ERANGE;
		} else if (len2 >= U32_MAX || len2 == 0) {
			/* empty extent */
			break;
		} else {
			/* it needs to check the next extent */
			cur_blk += len2;
		}
	}

	if (!cur_extent) {
		SSDFS_ERR("fail to find the extent: blk %llu\n",
			  blk);
		return -ENODATA;
	}

	if (le32_to_cpu(extent->len) == 0) {
		SSDFS_ERR("empty extent: "
			  "seg_id %llu, logical_blk %u, len %u\n",
			  le64_to_cpu(extent->seg_id),
			  le32_to_cpu(extent->logical_blk),
			  le32_to_cpu(extent->len));
		return -ERANGE;
	}

	memcpy(&buf, cur_extent, sizeof(struct ssdfs_raw_extent));
	memcpy(cur_extent, extent, sizeof(struct ssdfs_raw_extent));

	len2 = le32_to_cpu(buf.len);

	if (len2 < len1) {
		/* old extent is shorter */
		len_diff = len1 - len2;
		blks_count += len_diff;
		fork->blks_count = cpu_to_le64(blks_count);
	} else if (len2 > len1) {
		/* old extent is larger */
		len_diff = len2 - len1;

		if (blks_count <= len_diff) {
			SSDFS_ERR("blks_count %llu <= len_diff %u\n",
				  blks_count, len_diff);
			return -ERANGE;
		}

		blks_count -= len_diff;
		fork->blks_count = cpu_to_le64(blks_count);
	}

	return 0;
}

/*
 * ssdfs_extents_tree_change_extent() - change extent in the tree
 * @tree: extents tree
 * @blk: logical block number
 * @extent: extent object
 * @search: search object
 *
 * This method tries to change @extent in the @tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - extent doesn't exist in the tree.
 */
int ssdfs_extents_tree_change_extent(struct ssdfs_extents_btree_info *tree,
				     u64 blk,
				     struct ssdfs_raw_extent *extent,
				     struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !extent || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p, blk %llu\n",
		  tree, search, blk);

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_extent_btree_search(blk, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = blk;
		search->request.end.hash = blk;
		search->request.count = 1;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		down_write(&tree->lock);

		err = ssdfs_extents_tree_find_inline_fork(tree, blk, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline fork: "
				  "blk %llu, err %d\n",
				  blk, err);
			goto finish_change_inline_fork;
		}

		err = ssdfs_change_extent_in_fork(blk, extent, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change extent in fork: err %d\n",
				  err);
			goto finish_change_inline_fork;
		}

		search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;

		err = ssdfs_extents_tree_change_inline_fork(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change inline fork: err %d\n", err);
			goto finish_change_inline_fork;
		}

finish_change_inline_fork:
		up_write(&tree->lock);
		break;

	case SSDFS_PRIVATE_EXTENTS_BTREE:
		down_read(&tree->lock);

		err = ssdfs_btree_find_item(tree->generic_tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the fork: "
				  "blk %llu, err %d\n",
				  blk, err);
			goto finish_change_generic_fork;
		}

		err = ssdfs_change_extent_in_fork(blk, extent, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change extent in fork: err %d\n",
				  err);
			goto finish_change_generic_fork;
		}

		search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;

		err = ssdfs_extents_tree_change_fork(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change fork: err %d\n", err);
			goto finish_change_generic_fork;
		}

finish_change_generic_fork:
		up_read(&tree->lock);
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid extents tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/*
 * ssdfs_truncate_extent_in_fork() - truncate the extent in the fork
 * @blk: logical block number
 * @new_len: new length of the extent
 * @search: search object
 * @fork: truncated fork [out]
 *
 * This method tries to truncate the extent in the fork.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - no extents in the fork.
 * %-ENOSPC     - invalid @new_len of the extent.
 * %-EFAULT     - extent doesn't exist in the fork.
 */
static
int ssdfs_truncate_extent_in_fork(u64 blk, u32 new_len,
				  struct ssdfs_btree_search *search,
				  struct ssdfs_raw_fork *fork)
{
	struct ssdfs_raw_fork *cur_fork;
	struct ssdfs_raw_extent *cur_extent = NULL;
	u64 start_offset;
	u64 blks_count;
	u32 len, len_diff;
	u64 cur_blk;
	u64 rest_len;
	u32 logical_blk;
	int i, j;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON( !search || !fork);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk %llu, new_len %u, search %p\n",
		  blk, new_len, search);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_EMPTY_RESULT:
		SSDFS_DBG("no fork in search object\n");
		return -EFAULT;

	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid search object state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid search buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	if (search->result.buf_size != sizeof(struct ssdfs_raw_fork) ||
	    search->result.items_in_buffer != 1) {
		SSDFS_ERR("invalid search buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	memset(fork, 0xFF, sizeof(struct ssdfs_raw_fork));

	cur_fork = &search->raw.fork;
	start_offset = le64_to_cpu(cur_fork->start_offset);
	blks_count = le64_to_cpu(cur_fork->blks_count);

	if (start_offset >= U64_MAX || blks_count >= U64_MAX) {
		SSDFS_ERR("invalid fork state: "
			  "start_offset %llu, blks_count %llu\n",
			  start_offset, blks_count);
		return -ERANGE;
	}

	if (blks_count == 0) {
		SSDFS_ERR("empty fork: blks_count %llu\n",
			  blks_count);
		return -ENODATA;
	}

	if (blk >= U64_MAX) {
		SSDFS_ERR("invalid extent: blk %llu\n",
			  blk);
		return -ERANGE;
	}

	if (start_offset <= blk && blk < (start_offset + blks_count)) {
		/*
		 * Expected state
		 */
	} else {
		SSDFS_ERR("extent is out of fork: \n"
			  "fork (start %llu, blks_count %llu), "
			  "extent (blk %llu, len %u)\n",
			  start_offset, blks_count,
			  blk, new_len);
		return -EFAULT;
	}

	cur_blk = le64_to_cpu(cur_fork->start_offset);
	for (i = 0; i < SSDFS_INLINE_EXTENTS_COUNT; i++) {
		len = le32_to_cpu(cur_fork->extents[i].len);

		if (len >= U32_MAX || len == 0) {
			/* empty extent */
			break;
		} else if (cur_blk <= blk && blk < (cur_blk + len)) {
			/* extent is found */
			cur_extent = &cur_fork->extents[i];
			break;
		} else if (blk < cur_blk) {
			SSDFS_ERR("invalid extent: "
				  "blk %llu, cur_blk %llu\n",
				  blk, cur_blk);
			return -EFAULT;
		} else {
			/* it needs to check the next extent */
			cur_blk += len;
		}
	}

	if (!cur_extent) {
		SSDFS_ERR("fail to find the extent: blk %llu\n",
			  blk);
		return -EFAULT;
	}

	rest_len = blks_count - (blk - start_offset);

	if (new_len > rest_len) {
		SSDFS_ERR("fail to grow extent's size: "
			  "rest_len %llu, new_len %u\n",
			  rest_len, new_len);
		return -ENOSPC;
	} else if (new_len == rest_len) {
		SSDFS_WARN("nothing should be done: "
			   "rest_len %llu, new_len %u\n",
			   rest_len, new_len);
		return 0;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(i >= SSDFS_INLINE_EXTENTS_COUNT);
#endif /* CONFIG_SSDFS_DEBUG */

	fork->start_offset = cpu_to_le64(0);
	fork->blks_count = cpu_to_le64(0);

	for (j = 0; i < SSDFS_INLINE_EXTENTS_COUNT; i++) {
		cur_extent = &cur_fork->extents[i];
		len = le32_to_cpu(cur_extent->len);

		if ((cur_blk + len) < blk) {
			/* pass on this extent */
			continue;
		} else if (cur_blk < blk && (cur_blk + len) > blk) {
			/* current extent has intersection */
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON((blk - cur_blk) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

			len_diff = len - (u32)(blk - cur_blk);

			if (len_diff <= new_len) {
				/*
				 * leave the extent unchanged
				 */
			} else {
				len_diff = (cur_blk + len) - (blk + new_len);

				fork->extents[j].seg_id = cur_extent->seg_id;
				logical_blk =
					le32_to_cpu(cur_extent->logical_blk);
				logical_blk += len - len_diff;
				fork->extents[j].logical_blk =
						cpu_to_le32(logical_blk);
				fork->extents[j].len = cpu_to_le32(len_diff);
				le64_add_cpu(&fork->blks_count, len_diff);
				j++;

				/* shrink extent */
				cur_extent->len = cpu_to_le32(len - len_diff);
			}
		} else if (blk <= cur_blk && cur_blk < (blk + new_len)) {
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON((cur_blk - blk) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

			len_diff = new_len - (u32)(cur_blk - blk);

			if (len_diff >= len) {
				/*
				 * leave the extent unchanged
				 */
			} else {
				len_diff = (cur_blk + len) - (blk + new_len);

				fork->extents[j].seg_id = cur_extent->seg_id;
				logical_blk =
					le32_to_cpu(cur_extent->logical_blk);
				logical_blk += len - len_diff;
				fork->extents[j].logical_blk =
						cpu_to_le32(logical_blk);
				fork->extents[j].len = cpu_to_le32(len_diff);
				le64_add_cpu(&fork->blks_count, len_diff);
				j++;

				/* shrink extent */
				cur_extent->len = cpu_to_le32(len - len_diff);
			}
		} else if ((blk + new_len) <= cur_blk) {
			memcpy(&fork->extents[j], cur_extent,
				sizeof(struct ssdfs_raw_extent));
			le64_add_cpu(&fork->blks_count, len);
			j++;

			/* clear extent */
			memset(cur_extent, 0xFF,
				sizeof(struct ssdfs_raw_extent));
		}

		cur_blk += len;
	}

	blks_count -= rest_len - new_len;

	if (blks_count == 0) {
		fork->start_offset = cpu_to_le64(U64_MAX);
		fork->blks_count = cpu_to_le64(U64_MAX);

		SSDFS_ERR("empty fork: blks_count %llu\n",
			  blks_count);
		return -ENODATA;
	} else
		fork->blks_count = cpu_to_le64(blks_count);

	return 0;
}

/*
 * ssdfs_extents_tree_delete_inline_fork() - delete inline fork
 * @tree: extents tree
 * @search: search object
 *
 * This method tries to delete the inline fork from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - fork doesn't exist in the tree.
 * %-ENOENT     - no more forks in the tree.
 */
static
int ssdfs_extents_tree_delete_inline_fork(struct ssdfs_extents_btree_info *tree,
					  struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shared_extents_tree *shextree;
	struct ssdfs_raw_fork *fork1, *fork2;
	ino_t ino;
	u64 start_hash;
	s64 forks_count;
	u64 blks_count;
	int lower_bound = 0;
	int upper_bound = 0;
	int i, j;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	fsi = tree->fsi;
	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	ino = tree->owner->vfs_inode.i_ino;

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->inline_forks) {
		SSDFS_ERR("empty inline tree %p\n",
			  tree->inline_forks);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	if (!search->result.buf) {
		SSDFS_ERR("empty buffer pointer\n");
		return -ERANGE;
	}

	start_hash = search->request.start.hash;

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		if (start_hash != le64_to_cpu(search->raw.fork.start_offset)) {
			SSDFS_ERR("corrupted fork: "
				  "start_hash %llx, "
				  "fork (start %llu, blks_count %llu)\n",
				  start_hash,
				  le64_to_cpu(search->raw.fork.start_offset),
				  le64_to_cpu(search->raw.fork.blks_count));
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		if (start_hash >= le64_to_cpu(search->raw.fork.start_offset)) {
			SSDFS_ERR("corrupted fork: "
				  "start_hash %llx, "
				  "fork (start %llu, blks_count %llu)\n",
				  start_hash,
				  le64_to_cpu(search->raw.fork.start_offset),
				  le64_to_cpu(search->raw.fork.blks_count));
			return -ERANGE;
		}
		break;

	default:
		SSDFS_WARN("unexpected result state %#x\n",
			   search->result.state);
		return -ERANGE;
	}

	forks_count = atomic64_read(&tree->forks_count);
	if (forks_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -ENOENT;
	} else if (forks_count > SSDFS_INLINE_FORKS_COUNT) {
		SSDFS_ERR("invalid forks count %lld\n",
			  forks_count);
		return -ERANGE;
	}

	if (search->result.start_index >= forks_count) {
		SSDFS_ERR("invalid search result: "
			  "start_index %u, forks_count %lld\n",
			  search->result.start_index,
			  forks_count);
		return -ENODATA;
	}

	if (search->request.type == SSDFS_BTREE_SEARCH_INVALIDATE_TAIL) {
		lower_bound = search->result.start_index;
		upper_bound = forks_count - 1;
	} else {
		lower_bound = search->result.start_index;
		upper_bound = search->result.start_index;
	}

	for (i = upper_bound; i >= lower_bound; i--) {
		u64 calculated = 0;

		fork1 = &tree->inline_forks[i];

		if (atomic64_read(&tree->forks_count) == 0) {
			SSDFS_ERR("invalid forks_count\n");
			return -ERANGE;
		} else
			atomic64_dec(&tree->forks_count);

		blks_count = le64_to_cpu(fork1->blks_count);
		if (blks_count == 0 || blks_count >= U64_MAX) {
			memset(fork1, 0xFF, sizeof(struct ssdfs_raw_fork));
			continue;
		}

		for (j = SSDFS_INLINE_EXTENTS_COUNT - 1; j >= 0; j--) {
			struct ssdfs_raw_extent *extent;
			u32 len;

			extent = &fork1->extents[j];
			len = le32_to_cpu(extent->len);

			if (len == 0 || len >= U32_MAX) {
				memset(extent, 0xFF,
					sizeof(struct ssdfs_raw_extent));
				continue;
			}

			if ((calculated + len) > blks_count) {
				atomic_set(&tree->state,
					   SSDFS_EXTENTS_BTREE_CORRUPTED);
				SSDFS_ERR("corrupted extent: "
					  "calculated %llu, len %u, "
					  "blks %llu\n",
					  calculated, len, blks_count);
				return -ERANGE;
			}

			err = ssdfs_shextree_add_pre_invalid_extent(shextree,
								    ino,
								    extent);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add pre-invalid extent "
					  "(seg_id %llu, blk %u, len %u), "
					  "err %d\n",
					  le64_to_cpu(extent->seg_id),
					  le32_to_cpu(extent->logical_blk),
					  len, err);
				return err;
			}

			calculated += len;

			memset(extent, 0xFF, sizeof(struct ssdfs_raw_extent));
		}

		if (calculated != blks_count) {
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_ERR("calculated %llu != blks_count %llu\n",
				  calculated, blks_count);
			return -ERANGE;
		}
	}

	if (search->result.start_index < (forks_count - 1)) {
		u16 index = search->result.start_index;

		fork1 = &tree->inline_forks[index];
		fork2 = &tree->inline_forks[index + 1];
		memmove(fork1, fork2,
			(forks_count - search->result.start_index) *
			sizeof(struct ssdfs_raw_fork));

		index = forks_count - 1;
		fork2 = &tree->inline_forks[index];
		memset(fork2, 0xFF, sizeof(struct ssdfs_raw_fork));
	}

	atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_DIRTY);

	forks_count = atomic64_dec_return(&tree->forks_count);
	if (forks_count == 0) {
		SSDFS_DBG("tree is empty now\n");
		return -ENOENT;
	} else if (forks_count < 0) {
		SSDFS_WARN("invalid forks_count %lld\n",
			   forks_count);
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_CORRUPTED);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_extents_tree_delete_fork() - delete generic fork
 * @tree: extents tree
 * @search: search object
 *
 * This method tries to delete the generic fork from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - fork doesn't exist in the tree.
 * %-ENOENT     - no more forks in the tree.
 */
static
int ssdfs_extents_tree_delete_fork(struct ssdfs_extents_btree_info *tree,
				   struct ssdfs_btree_search *search)
{
	u64 start_hash;
	s64 forks_count;
	u64 blks_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_EXTENTS_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->generic_tree) {
		SSDFS_ERR("empty generic tree %p\n",
			  tree->generic_tree);
		return -ERANGE;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	if (start_hash != le64_to_cpu(search->raw.fork.start_offset)) {
		SSDFS_ERR("corrupted fork: "
			  "start_hash %llx, "
			  "fork (start %llu, blks_count %llu)\n",
			  start_hash,
			  le64_to_cpu(search->raw.fork.start_offset),
			  le64_to_cpu(search->raw.fork.blks_count));
		return -ERANGE;
	}

	forks_count = atomic64_read(&tree->forks_count);
	if (forks_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -ENOENT;
	}

	if (search->result.start_index >= forks_count) {
		SSDFS_ERR("invalid search result: "
			  "start_index %u, forks_count %lld\n",
			  search->result.start_index,
			  forks_count);
		return -ENODATA;
	}

	blks_count = le64_to_cpu(search->raw.fork.blks_count);
	if (!(blks_count == 0 || blks_count >= U64_MAX)) {
		SSDFS_ERR("fork is empty: "
			  "blks_count %llu\n",
			  blks_count);
		return -ERANGE;
	}

	err = ssdfs_btree_delete_item(tree->generic_tree,
				      search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete the fork from the tree: "
			  "err %d\n", err);
		return err;
	}

	forks_count = atomic64_dec_return(&tree->forks_count);

	if (forks_count == 0) {
		SSDFS_DBG("tree is empty now\n");
		return -ENOENT;
	} else if (forks_count < 0) {
		SSDFS_WARN("invalid forks_count %lld\n",
			   forks_count);
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_CORRUPTED);
		return -ERANGE;
	}

	atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_extents_tree_truncate_extent() - truncate the extent in the tree
 * @tree: extent tree
 * @blk: logical block number
 * @new_len: new length of the extent
 * @search: search object
 *
 * This method tries to truncate the extent in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - extent doesn't exist in the tree.
 * %-ENOSPC     - invalid @new_len of the extent.
 * %-EFAULT     - fail to create the hole in the fork.
 */
int ssdfs_extents_tree_truncate_extent(struct ssdfs_extents_btree_info *tree,
					u64 blk, u32 new_len,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shared_extents_tree *shextree;
	struct ssdfs_raw_fork fork;
	u64 blks_count;
	u64 hash;
	ino_t ino;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p, blk %llu, new_len %u\n",
		  tree, search, blk, new_len);

	fsi = tree->fsi;
	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	ino = tree->owner->vfs_inode.i_ino;

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_extent_btree_search(blk, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = blk;
		search->request.end.hash = blk;
		search->request.count = 1;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		down_write(&tree->lock);

		err = ssdfs_extents_tree_find_inline_fork(tree, blk, search);
		if (err == -ENODATA) {
			switch (search->result.state) {
			case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
				/* hole case -> continue truncation */
				break;

			case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
				/* inflation case -> nothing has to be done */
				err = 0;
				goto finish_truncate_inline_fork;

			default:
				SSDFS_ERR("fail to find the inline fork: "
					  "blk %llu, err %d\n",
					  blk, err);
				goto finish_truncate_inline_fork;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline fork: "
				  "blk %llu, err %d\n",
				  blk, err);
			goto finish_truncate_inline_fork;
		}

		switch (search->result.state) {
		case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
			search->request.type =
				SSDFS_BTREE_SEARCH_INVALIDATE_TAIL;
			err = ssdfs_extents_tree_delete_inline_fork(tree,
								   search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to delete fork: err %d\n", err);
				goto finish_truncate_inline_fork;
			}
			break;

		case SSDFS_BTREE_SEARCH_VALID_ITEM:
			err = ssdfs_truncate_extent_in_fork(blk, new_len,
							    search, &fork);
			if (err == -ENODATA) {
				/*
				 * The fork doesn't contain any extents.
				 */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to change extent in fork: "
					  "err %d\n",
					  err);
				goto finish_truncate_inline_fork;
			}

			if (err == -ENODATA) {
				search->request.type =
					SSDFS_BTREE_SEARCH_INVALIDATE_TAIL;
				err =
				    ssdfs_extents_tree_delete_inline_fork(tree,
									search);
				if (unlikely(err)) {
					SSDFS_ERR("fail to delete fork: "
						  "err %d\n", err);
					goto finish_truncate_inline_fork;
				}
			} else {
				search->request.type =
					SSDFS_BTREE_SEARCH_INVALIDATE_TAIL;
				err =
				    ssdfs_extents_tree_change_inline_fork(tree,
									search);
				if (unlikely(err)) {
					SSDFS_ERR("fail to change fork: "
						  "err %d\n", err);
					goto finish_truncate_inline_fork;
				}
			}

			blks_count = le64_to_cpu(fork.blks_count);

			if (blks_count == 0 || blks_count >= U64_MAX) {
				/*
				 * empty fork -> do nothing
				 */
			} else {
				err =
				    ssdfs_shextree_add_pre_invalid_fork(shextree,
									ino,
									&fork);
				if (unlikely(err)) {
					SSDFS_ERR("fail to pre-invalidate: "
						  "(start_offset %llu, "
						  "blks_count %llu), err %d\n",
						le64_to_cpu(fork.start_offset),
						le64_to_cpu(fork.blks_count),
						err);
					goto finish_truncate_inline_fork;
				}
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid result state %#x\n",
				  search->result.state);
			goto finish_truncate_inline_fork;
		}

finish_truncate_inline_fork:
		up_write(&tree->lock);
		break;

	case SSDFS_PRIVATE_EXTENTS_BTREE:
		down_read(&tree->lock);

		err = ssdfs_btree_find_item(tree->generic_tree, search);
		if (err == -ENODATA) {
			switch (search->result.state) {
			case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
				/* hole case -> continue truncation */
				break;

			case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
			case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
				if (is_last_leaf_node_found(search)) {
					/*
					 * inflation case
					 * nothing has to be done
					 */
					err = 0;
					goto finish_truncate_generic_fork;
				} else {
					/*
					 * hole case
					 * continue truncation
					 */
				}
				break;

			default:
				SSDFS_ERR("fail to find the fork: "
					  "blk %llu, err %d\n",
					  blk, err);
				goto finish_truncate_generic_fork;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find the fork: "
				  "blk %llu, err %d\n",
				  blk, err);
			goto finish_truncate_generic_fork;
		}

		switch (search->result.state) {
		case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
			search->request.type =
				SSDFS_BTREE_SEARCH_INVALIDATE_TAIL;
			err = ssdfs_extents_tree_delete_fork(tree, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to delete fork: err %d\n", err);
				goto finish_truncate_generic_fork;
			}
			break;

		case SSDFS_BTREE_SEARCH_VALID_ITEM:
			err = ssdfs_truncate_extent_in_fork(blk, new_len,
							    search, &fork);
			if (err == -ENODATA) {
				/*
				 * The fork doesn't contain any extents.
				 */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to change extent in fork: "
					  "err %d\n", err);
				goto finish_truncate_generic_fork;
			}

			if (err == -ENODATA) {
				search->request.type =
					SSDFS_BTREE_SEARCH_INVALIDATE_TAIL;
				err = ssdfs_extents_tree_delete_fork(tree,
								     search);
				if (unlikely(err)) {
					SSDFS_ERR("fail to delete fork: "
						  "err %d\n", err);
					goto finish_truncate_generic_fork;
				}
			} else {
				search->request.type =
					SSDFS_BTREE_SEARCH_INVALIDATE_TAIL;
				err = ssdfs_extents_tree_change_fork(tree,
								     search);
				if (unlikely(err)) {
					SSDFS_ERR("fail to change fork: "
						  "err %d\n", err);
					goto finish_truncate_generic_fork;
				}
			}

			blks_count = le64_to_cpu(fork.blks_count);

			if (blks_count == 0 || blks_count >= U64_MAX) {
				/*
				 * empty fork -> do nothing
				 */
			} else {
				err =
				 ssdfs_shextree_add_pre_invalid_fork(shextree,
								     ino,
								     &fork);
				if (unlikely(err)) {
					SSDFS_ERR("fail to pre-invalidate: "
						  "(start_offset %llu, "
						  "blks_count %llu), err %d\n",
						le64_to_cpu(fork.start_offset),
						le64_to_cpu(fork.blks_count),
						err);
					goto finish_truncate_generic_fork;
				}
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid result state %#x\n",
				  search->result.state);
			goto finish_truncate_generic_fork;
		}

finish_truncate_generic_fork:
		up_read(&tree->lock);

		if (unlikely(err))
			return err;

		down_write(&tree->lock);
		hash = blk + new_len;
		err = ssdfs_btree_destroy_node_range(&tree->buffer.tree,
						     hash);
		up_write(&tree->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to destroy nodes' range: err %d\n",
				  err);
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid extents tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/*
 * ssdfs_delete_extent_in_fork() - delete extent from the fork
 * @blk: logical block number
 * @search: search object
 *
 * This method tries to delete extent from the fork.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - extent doesn't exist in the tree.
 * %-EFAULT     - fail to create the hole in the fork.
 */
static
int ssdfs_delete_extent_in_fork(u64 blk,
				struct ssdfs_btree_search *search,
				struct ssdfs_raw_extent *extent)
{
	struct ssdfs_raw_fork *fork;
	struct ssdfs_raw_extent *cur_extent = NULL;
	u64 start_offset;
	u64 blks_count;
	u64 cur_blk;
	u32 len;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("blk %llu, search %p\n",
		  blk, search);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_EMPTY_RESULT:
		SSDFS_DBG("no fork in search object\n");
		return -ENODATA;

	case SSDFS_BTREE_SEARCH_VALID_ITEM:
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid search object state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		SSDFS_ERR("invalid search buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	if (search->result.buf_size != sizeof(struct ssdfs_raw_fork) ||
	    search->result.items_in_buffer != 1) {
		SSDFS_ERR("invalid search buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	fork = &search->raw.fork;
	start_offset = le64_to_cpu(fork->start_offset);
	blks_count = le64_to_cpu(fork->blks_count);

	if (start_offset >= U64_MAX || blks_count >= U64_MAX) {
		SSDFS_ERR("invalid fork state: "
			  "start_offset %llu, blks_count %llu\n",
			  start_offset, blks_count);
		return -ENODATA;
	}

	if (blk >= U64_MAX) {
		SSDFS_ERR("invalid request: blk %llu\n",
			  blk);
		return -ERANGE;
	}

	if (start_offset <= blk && blk < (start_offset + blks_count)) {
		/*
		 * Expected state
		 */
	} else {
		SSDFS_ERR("blk %llu is out of fork\n",
			  blk);
		return -ERANGE;
	}

	cur_blk = le64_to_cpu(fork->start_offset);
	for (i = 0; i < SSDFS_INLINE_EXTENTS_COUNT; i++) {
		len = le32_to_cpu(fork->extents[i].len);

		if (cur_blk == blk) {
			/* extent is found */
			cur_extent = &fork->extents[i];
			break;
		} else if (blk < cur_blk) {
			SSDFS_ERR("invalid extent: "
				  "blk %llu, cur_blk %llu\n",
				  blk, cur_blk);
			return -ERANGE;
		} else if (len >= U32_MAX || len == 0) {
			/* empty extent */
			break;
		} else {
			/* it needs to check the next extent */
			cur_blk += len;
		}
	}

	if (!cur_extent) {
		SSDFS_ERR("fail to find the extent: blk %llu\n",
			  blk);
		return -ERANGE;
	}

	memcpy(extent, cur_extent, sizeof(struct ssdfs_raw_extent));

	len = le32_to_cpu(fork->extents[i].len);

	if (i < (SSDFS_INLINE_EXTENTS_COUNT - 1)) {
		memmove(cur_extent, &fork->extents[i + 1],
			(SSDFS_INLINE_EXTENTS_COUNT - i) *
			sizeof(struct ssdfs_raw_extent));
	} else {
		memset(&fork->extents[i], 0xFF,
			sizeof(struct ssdfs_raw_extent));
	}

	if (len >= U32_MAX || len == 0) {
		/*
		 * Do nothing. Empty extent.
		 */
	} else if (blks_count < len) {
		SSDFS_ERR("blks_count %llu < len %u\n",
			  blks_count, len);
		return -ERANGE;
	}

	blks_count -= len;
	fork->blks_count = cpu_to_le64(blks_count);

	if (blks_count == 0) {
		fork->start_offset = cpu_to_le64(U64_MAX);
		SSDFS_DBG("empty fork\n");
		return -ENODATA;
	}

	return 0;
}

/*
 * ssdfs_migrate_generic2inline_tree() - convert generic tree into inline
 * @tree: extents tree
 *
 * This method tries to convert the generic tree into inline one.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - the tree cannot be converted into inline again.
 */
static
int ssdfs_migrate_generic2inline_tree(struct ssdfs_extents_btree_info *tree)
{
	struct ssdfs_raw_fork inline_forks[SSDFS_INLINE_FORKS_COUNT];
	struct ssdfs_btree_search *search;
	size_t fork_size = sizeof(struct ssdfs_raw_fork);
	s64 forks_count, forks_capacity;
	int private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	switch (atomic_read(&tree->type)) {
	case SSDFS_PRIVATE_EXTENTS_BTREE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	forks_count = atomic64_read(&tree->forks_count);

	if (!tree->owner) {
		SSDFS_ERR("empty owner inode\n");
		return -ERANGE;
	}

	private_flags = atomic_read(&tree->owner->private_flags);

	forks_capacity = SSDFS_INLINE_FORKS_COUNT;
	if (private_flags & SSDFS_INODE_HAS_XATTR_BTREE)
		forks_capacity--;

	if (private_flags & SSDFS_INODE_HAS_INLINE_EXTENTS) {
		SSDFS_ERR("the extents tree is not generic\n");
		return -ERANGE;
	}

	if (forks_count > forks_capacity) {
		SSDFS_DBG("forks_count %lld > forks_capacity %lld\n",
			  forks_count, forks_capacity);
		return -ENOSPC;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(tree->inline_forks || !tree->generic_tree);
#endif /* CONFIG_SSDFS_DEBUG */

	tree->generic_tree = NULL;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);
	search->request.type = SSDFS_BTREE_SEARCH_FIND_RANGE;
	search->request.flags = 0;
	search->request.start.hash = U64_MAX;
	search->request.end.hash = U64_MAX;
	search->request.count = 0;

	err = ssdfs_btree_get_head_range(&tree->buffer.tree,
					 forks_count, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract forks: "
			  "forks_count %lld, err %d\n",
			  forks_count, err);
		goto finish_process_range;
	} else if (forks_count != search->result.items_in_buffer) {
		err = -ERANGE;
		SSDFS_ERR("forks_count %lld != items_in_buffer %u\n",
			  forks_count,
			  search->result.items_in_buffer);
		goto finish_process_range;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		err = -ERANGE;
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		goto finish_process_range;
	}

	memset(inline_forks, 0xFF, fork_size * SSDFS_INLINE_FORKS_COUNT);

	if (search->result.buf_size != (fork_size * forks_count) ||
	    search->result.items_in_buffer != forks_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid search result: "
			  "buf_size %zu, items_in_buffer %u, "
			  "forks_count %lld\n",
			  search->result.buf_size,
			  search->result.items_in_buffer,
			  forks_count);
		goto finish_process_range;
	}

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		memcpy(inline_forks, &search->raw.fork, fork_size);
		break;

	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		if (!search->result.buf) {
			err = -ERANGE;
			SSDFS_ERR("empty buffer\n");
			goto finish_process_range;
		}

		memcpy(inline_forks, search->result.buf,
			fork_size * forks_count);
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid buffer's state %#x\n",
			  search->result.buf_state);
		goto finish_process_range;
	}

	search->request.type = SSDFS_BTREE_SEARCH_DELETE_RANGE;
	search->request.flags = SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
				SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
	search->request.start.hash =
		le64_to_cpu(inline_forks[0].start_offset);
	search->request.end.hash =
		le64_to_cpu(inline_forks[forks_count - 1].start_offset);
	search->request.count = forks_count;

	err = ssdfs_btree_delete_range(&tree->buffer.tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete range: "
			  "start_hash %llx, end_hash %llx, count %u, "
			  "err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  search->request.count,
			  err);
		goto finish_process_range;
	}

	if (!is_ssdfs_btree_empty(&tree->buffer.tree)) {
		err = -ERANGE;
		SSDFS_WARN("extents tree is not empty\n");
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_CORRUPTED);
		goto finish_process_range;
	}

	search->result.state = SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE;

	err = ssdfs_btree_delete_node(&tree->buffer.tree, search);
	if (unlikely(err)) {
		SSDFS_WARN("fail to delete node %u\n",
			   search->node.id);
		atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_CORRUPTED);
		goto finish_process_range;
	}

	err = ssdfs_btree_destroy_node_range(&tree->buffer.tree,
					     0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to destroy nodes' range: err %d\n",
			  err);
		goto finish_process_range;
	}

finish_process_range:
	ssdfs_btree_search_free(search);

	if (unlikely(err))
		return err;

	ssdfs_btree_destroy(&tree->buffer.tree);
	memcpy(tree->buffer.forks, inline_forks, fork_size * forks_count);

	atomic_set(&tree->type, SSDFS_INLINE_FORKS_ARRAY);
	atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_DIRTY);
	tree->inline_forks = tree->buffer.forks;

	atomic_and(~SSDFS_INODE_HAS_EXTENTS_BTREE,
		   &tree->owner->private_flags);
	atomic_or(SSDFS_INODE_HAS_INLINE_EXTENTS,
		  &tree->owner->private_flags);

	return 0;
}

/*
 * ssdfs_extents_tree_delete_extent() - delete extent from the tree
 * @tree: extents tree
 * @blk: logical block number
 * @search: search object
 *
 * This method tries to delete extent from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - extent doesn't exist in the tree.
 * %-EFAULT     - fail to create the hole in the fork.
 */
int ssdfs_extents_tree_delete_extent(struct ssdfs_extents_btree_info *tree,
				     u64 blk,
				     struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shared_extents_tree *shextree;
	struct ssdfs_raw_extent extent;
	ino_t ino;
	u32 len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p, blk %llu\n",
		  tree, search, blk);

	fsi = tree->fsi;
	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	ino = tree->owner->vfs_inode.i_ino;

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_extent_btree_search(blk, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = blk;
		search->request.end.hash = blk;
		search->request.count = 1;
	}

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		down_write(&tree->lock);

		err = ssdfs_extents_tree_find_inline_fork(tree, blk, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the inline fork: "
				  "blk %llu, err %d\n",
				  blk, err);
			goto finish_delete_inline_extent;
		}

		err = ssdfs_delete_extent_in_fork(blk, search,
						  &extent);
		if (err == -ENODATA) {
			/*
			 * The fork doesn't contain any extents.
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to delete extent in fork: err %d\n",
				  err);
			goto finish_delete_inline_extent;
		}

		if (err == -ENODATA) {
			search->request.type = SSDFS_BTREE_SEARCH_DELETE_ITEM;
			err = ssdfs_extents_tree_delete_inline_fork(tree,
								   search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to delete fork: err %d\n", err);
				goto finish_delete_inline_extent;
			}
		} else {
			search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;
			err = ssdfs_extents_tree_change_inline_fork(tree,
								   search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change fork: err %d\n", err);
				goto finish_delete_inline_extent;
			}
		}

		len = le32_to_cpu(extent.len);

		if (len == 0 || len >= U32_MAX) {
			/*
			 * empty extent -> do nothing
			 */
		} else {
			err = ssdfs_shextree_add_pre_invalid_extent(shextree,
								    ino,
								    &extent);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add pre-invalid extent "
					  "(seg_id %llu, blk %u, len %u), "
					  "err %d\n",
					  le64_to_cpu(extent.seg_id),
					  le32_to_cpu(extent.logical_blk),
					  len, err);
				goto finish_delete_inline_extent;
			}
		}

finish_delete_inline_extent:
		up_write(&tree->lock);
		break;

	case SSDFS_PRIVATE_EXTENTS_BTREE:
		down_read(&tree->lock);

		err = ssdfs_btree_find_item(tree->generic_tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the fork: "
				  "blk %llu, err %d\n",
				  blk, err);
			goto finish_delete_generic_extent;
		}

		err = ssdfs_delete_extent_in_fork(blk, search,
						  &extent);
		if (err == -ENODATA) {
			/*
			 * The fork doesn't contain any extents.
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to delete extent in fork: err %d\n",
				  err);
			goto finish_delete_generic_extent;
		}

		if (err == -ENODATA) {
			search->request.type = SSDFS_BTREE_SEARCH_DELETE_ITEM;
			err = ssdfs_extents_tree_delete_fork(tree, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to delete fork: err %d\n", err);
				goto finish_delete_generic_extent;
			}
		} else {
			search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;
			err = ssdfs_extents_tree_change_fork(tree, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change fork: err %d\n", err);
				goto finish_delete_generic_extent;
			}
		}

finish_delete_generic_extent:
		up_read(&tree->lock);

		if (!err && atomic64_read(&tree->forks_count) <= 1) {
			down_write(&tree->lock);
			err = ssdfs_migrate_generic2inline_tree(tree);
			up_write(&tree->lock);

			if (err == -ENOSPC) {
				/* continue to use the generic tree */
				err = 0;
				SSDFS_DBG("unable to re-create inline tree\n");
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to re-create inline tree: "
					  "err %d\n",
					  err);
			}
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid extents tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/*
 * ssdfs_delete_all_inline_forks() - delete all inline forks
 * @tree: extents tree
 *
 * This method tries to delete all inline forks in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - empty tree.
 */
static
int ssdfs_delete_all_inline_forks(struct ssdfs_extents_btree_info *tree)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shared_extents_tree *shextree;
	struct ssdfs_raw_fork *fork;
	struct ssdfs_raw_extent *extent;
	u64 forks_count;
	ino_t ino;
	int i, j;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	fsi = tree->fsi;
	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	ino = tree->owner->vfs_inode.i_ino;

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's type %#x\n",
			  atomic_read(&tree->type));
		return -ERANGE;
	}

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	if (!tree->inline_forks) {
		SSDFS_ERR("empty inline forks %p\n",
			  tree->inline_forks);
		return -ERANGE;
	}

	forks_count = atomic64_read(&tree->forks_count);
	if (forks_count == 0) {
		SSDFS_DBG("empty tree\n");
		return -ENOENT;
	} else if (forks_count > SSDFS_INLINE_FORKS_COUNT) {
		atomic_set(&tree->state,
			   SSDFS_EXTENTS_BTREE_CORRUPTED);
		SSDFS_ERR("extents tree is corupted: "
			  "forks_count %llu",
			  forks_count);
		return -ERANGE;
	}

	for (i = 0; i < forks_count; i++) {
		u64 blks_count;
		u64 calculated = 0;

		fork = &tree->inline_forks[i];
		blks_count = le64_to_cpu(fork->blks_count);

		if (blks_count == 0 || blks_count >= U64_MAX) {
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_ERR("corrupted fork: blks_count %llu\n",
				  blks_count);
			return -ERANGE;
		}

		for (j = SSDFS_INLINE_EXTENTS_COUNT - 1; j >= 0; j--) {
			u32 len;

			extent = &fork->extents[j];
			len = le32_to_cpu(extent->len);

			if (len == 0 || len >= U32_MAX)
				continue;

			if ((calculated + len) > blks_count) {
				atomic_set(&tree->state,
					   SSDFS_EXTENTS_BTREE_CORRUPTED);
				SSDFS_ERR("corrupted extent: "
					  "calculated %llu, len %u, "
					  "blks %llu\n",
					  calculated, len, blks_count);
				return -ERANGE;
			}

			err = ssdfs_shextree_add_pre_invalid_extent(shextree,
								    ino,
								    extent);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add pre-invalid extent "
					  "(seg_id %llu, blk %u, len %u), "
					  "err %d\n",
					  le64_to_cpu(extent->seg_id),
					  le32_to_cpu(extent->logical_blk),
					  len, err);
				return err;
			}
		}

		if (calculated != blks_count) {
			atomic_set(&tree->state,
				   SSDFS_EXTENTS_BTREE_CORRUPTED);
			SSDFS_ERR("calculated %llu != blks_count %llu\n",
				  calculated, blks_count);
			return -ERANGE;
		}
	}

	memset(tree->inline_forks, 0xFF,
		sizeof(struct ssdfs_raw_fork) * SSDFS_INLINE_FORKS_COUNT);

	atomic_set(&tree->state, SSDFS_EXTENTS_BTREE_DIRTY);
	return 0;
}

/*
 * ssdfs_extents_tree_delete_all() - delete all forks in the tree
 * @tree: extents tree
 *
 * This method tries to delete all forks in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_extents_tree_delete_all(struct ssdfs_extents_btree_info *tree)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	switch (atomic_read(&tree->state)) {
	case SSDFS_EXTENTS_BTREE_CREATED:
	case SSDFS_EXTENTS_BTREE_INITIALIZED:
	case SSDFS_EXTENTS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid extent tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	switch (atomic_read(&tree->type)) {
	case SSDFS_INLINE_FORKS_ARRAY:
		down_write(&tree->lock);
		err = ssdfs_delete_all_inline_forks(tree);
		if (!err)
			atomic64_set(&tree->forks_count, 0);
		up_write(&tree->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to delete all inline forks: "
				  "err %d\n",
				  err);
		}
		break;

	case SSDFS_PRIVATE_EXTENTS_BTREE:
		down_write(&tree->lock);
		err = ssdfs_btree_delete_all(tree->generic_tree);
		if (!err) {
			atomic64_set(&tree->forks_count, 0);
			err = ssdfs_migrate_generic2inline_tree(tree);
			if (err == -ENOSPC) {
				/* continue to use the generic tree */
				err = 0;
				SSDFS_DBG("unable to re-create inline tree\n");
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to re-create inline tree: "
					  "err %d\n",
					  err);
			}
		}
		up_write(&tree->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to delete the all forks: "
				  "err %d\n",
				  err);
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid extents tree type %#x\n",
			  atomic_read(&tree->type));
		break;
	}

	return err;
}

/******************************************************************************
 *             SPECIALIZED EXTENTS BTREE DESCRIPTOR OPERATIONS                *
 ******************************************************************************/

/*
 * ssdfs_extents_btree_desc_init() - specialized btree descriptor init
 * @fsi: pointer on shared file system object
 * @tree: pointer on btree object
 */
static
int ssdfs_extents_btree_desc_init(struct ssdfs_fs_info *fsi,
				  struct ssdfs_btree *tree)
{
	struct ssdfs_extents_btree_info *tree_info = NULL;
	struct ssdfs_btree_descriptor *desc;
	u32 erasesize;
	u32 node_size;
	size_t fork_size = sizeof(struct ssdfs_raw_fork);
	u16 item_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, tree %p\n",
		  fsi, tree);

	tree_info = container_of(tree,
				 struct ssdfs_extents_btree_info,
				 buffer.tree);

	erasesize = fsi->erasesize;

	desc = &tree_info->desc.desc;

	if (le32_to_cpu(desc->magic) != SSDFS_EXTENTS_BTREE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic %#x\n",
			  le32_to_cpu(desc->magic));
		goto finish_btree_desc_init;
	}

	/* TODO: check flags */

	if (desc->type != SSDFS_EXTENTS_BTREE) {
		err = -EIO;
		SSDFS_ERR("invalid btree type %#x\n",
			  desc->type);
		goto finish_btree_desc_init;
	}

	node_size = 1 << desc->log_node_size;
	if (node_size < SSDFS_4KB || node_size > erasesize) {
		err = -EIO;
		SSDFS_ERR("invalid node size: "
			  "log_node_size %u, node_size %u, erasesize %u\n",
			  desc->log_node_size,
			  node_size, erasesize);
		goto finish_btree_desc_init;
	}

	item_size = le16_to_cpu(desc->item_size);

	if (item_size != fork_size) {
		err = -EIO;
		SSDFS_ERR("invalid item size %u\n",
			  item_size);
		goto finish_btree_desc_init;
	}

	if (le16_to_cpu(desc->index_area_min_size) != fork_size) {
		err = -EIO;
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc->index_area_min_size));
		goto finish_btree_desc_init;
	}

	err = ssdfs_btree_desc_init(fsi, tree, desc, 0, item_size);

finish_btree_desc_init:
	if (unlikely(err)) {
		SSDFS_ERR("fail to init btree descriptor: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_extents_btree_desc_flush() - specialized btree's descriptor flush
 * @tree: pointer on btree object
 */
static
int ssdfs_extents_btree_desc_flush(struct ssdfs_btree *tree)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_extents_btree_info *tree_info = NULL;
	struct ssdfs_btree_descriptor desc;
	size_t fork_size = sizeof(struct ssdfs_raw_fork);
	u32 erasesize;
	u32 node_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("owner_ino %llu, type %#x, state %#x\n",
		  tree->owner_ino, tree->type,
		  atomic_read(&tree->state));

	fsi = tree->fsi;

	if (tree->type != SSDFS_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_extents_btree_info,
					 buffer.tree);
	}

	memset(&desc, 0xFF, sizeof(struct ssdfs_btree_descriptor));

	desc.magic = cpu_to_le32(SSDFS_EXTENTS_BTREE_MAGIC);
	desc.item_size = cpu_to_le16(fork_size);

	err = ssdfs_btree_desc_flush(tree, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("invalid btree descriptor: err %d\n",
			  err);
		return err;
	}

	if (desc.type != SSDFS_EXTENTS_BTREE) {
		SSDFS_ERR("invalid btree type %#x\n",
			  desc.type);
		return -ERANGE;
	}

	erasesize = fsi->erasesize;
	node_size = 1 << desc.log_node_size;

	if (node_size < SSDFS_4KB || node_size > erasesize) {
		SSDFS_ERR("invalid node size: "
			  "log_node_size %u, node_size %u, erasesize %u\n",
			  desc.log_node_size,
			  node_size, erasesize);
		return -ERANGE;
	}

	if (le16_to_cpu(desc.index_area_min_size) != fork_size) {
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc.index_area_min_size));
		return -ERANGE;
	}

	memcpy(&tree_info->desc.desc, &desc,
		sizeof(struct ssdfs_btree_descriptor));

	return 0;
}

/******************************************************************************
 *                   SPECIALIZED EXTENTS BTREE OPERATIONS                     *
 ******************************************************************************/

/*
 * ssdfs_extents_btree_create_root_node() - specialized root node creation
 * @fsi: pointer on shared file system object
 * @node: pointer on node object [out]
 */
static
int ssdfs_extents_btree_create_root_node(struct ssdfs_fs_info *fsi,
					 struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_extents_btree_info *tree_info = NULL;
	struct ssdfs_btree_inline_root_node tmp_buffer;
	struct ssdfs_inode *raw_inode = NULL;
	int private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, node %p\n",
		  fsi, node);

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (atomic_read(&tree->state) != SSDFS_BTREE_UNKNOWN_STATE) {
		SSDFS_ERR("unexpected tree state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	}

	if (tree->type != SSDFS_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_extents_btree_info,
					 buffer.tree);
	}

	if (!tree_info->owner) {
		SSDFS_ERR("empty inode pointer\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rwsem_is_locked(&tree_info->owner->lock));
	BUG_ON(!rwsem_is_locked(&tree_info->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	private_flags = atomic_read(&tree_info->owner->private_flags);

	if (private_flags & SSDFS_INODE_HAS_EXTENTS_BTREE) {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_PRIVATE_EXTENTS_BTREE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid tree type %#x\n",
				  atomic_read(&tree_info->type));
			return -ERANGE;
		}

		raw_inode = &tree_info->owner->raw_inode;
		memcpy(&tmp_buffer,
			&raw_inode->internal[0].area1.extents_root,
			sizeof(struct ssdfs_btree_inline_root_node));
	} else {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_INLINE_FORKS_ARRAY:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid tree type %#x\n",
				  atomic_read(&tree_info->type));
			return -ERANGE;
		}

		memset(&tmp_buffer, 0xFF,
			sizeof(struct ssdfs_btree_inline_root_node));

		tmp_buffer.header.height = SSDFS_BTREE_LEAF_NODE_HEIGHT + 1;
		tmp_buffer.header.items_count = 0;
		tmp_buffer.header.flags = 0;
		tmp_buffer.header.type = SSDFS_BTREE_ROOT_NODE;
		tmp_buffer.header.upper_node_id =
				cpu_to_le32(SSDFS_BTREE_ROOT_NODE_ID);
	}

	memcpy(&tree_info->root_buffer, &tmp_buffer,
		sizeof(struct ssdfs_btree_inline_root_node));
	tree_info->root = &tree_info->root_buffer;
	err = ssdfs_btree_create_root_node(node, tree_info->root);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create root node: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_extents_btree_pre_flush_root_node() - specialized root node pre-flush
 * @node: pointer on node object
 */
static
int ssdfs_extents_btree_pre_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_state_bitmap *bmap;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
		SSDFS_DBG("node %u is clean\n",
			  node->node_id);
		return 0;

	case SSDFS_BTREE_NODE_CORRUPTED:
		SSDFS_WARN("node %u is corrupted\n",
			   node->node_id);
		down_read(&node->bmap_array.lock);
		bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
		spin_lock(&bmap->lock);
		bitmap_clear(bmap->ptr, 0, node->bmap_array.bits_count);
		spin_unlock(&bmap->lock);
		up_read(&node->bmap_array.lock);
		clear_ssdfs_btree_node_dirty(node);
		return -EFAULT;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	}

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	err = ssdfs_btree_pre_flush_root_node(node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre-flush root node: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
	}

	up_write(&node->header_lock);
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_extents_btree_flush_root_node() - specialized root node flush
 * @node: pointer on node object
 */
static
int ssdfs_extents_btree_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_extents_btree_info *tree_info = NULL;
	struct ssdfs_btree_inline_root_node tmp_buffer;
	struct ssdfs_inode *raw_inode = NULL;
	int private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node %p, node_id %u\n",
		  node, node->node_id);

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_extents_btree_info,
					 buffer.tree);
	}

	if (!tree_info->owner) {
		SSDFS_ERR("empty inode pointer\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rwsem_is_locked(&tree_info->owner->lock));
	BUG_ON(!rwsem_is_locked(&tree_info->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	private_flags = atomic_read(&tree_info->owner->private_flags);

	if (private_flags & SSDFS_INODE_HAS_EXTENTS_BTREE) {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_PRIVATE_EXTENTS_BTREE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid tree type %#x\n",
				  atomic_read(&tree_info->type));
			return -ERANGE;
		}

		if (!tree_info->root) {
			SSDFS_ERR("root node pointer is NULL\n");
			return -ERANGE;
		}

		ssdfs_btree_flush_root_node(node, tree_info->root);
		memcpy(&tmp_buffer, tree_info->root,
			sizeof(struct ssdfs_btree_inline_root_node));

		raw_inode = &tree_info->owner->raw_inode;
		memcpy(&raw_inode->internal[0].area1.extents_root,
			&tmp_buffer,
			sizeof(struct ssdfs_btree_inline_root_node));
	} else {
		err = -ERANGE;
		SSDFS_ERR("extents tree is inline forks array\n");
	}

	return err;
}

/*
 * ssdfs_extents_btree_create_node() - specialized node creation
 * @node: pointer on node object
 */
static
int ssdfs_extents_btree_create_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct page *page;
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	size_t hdr_size = sizeof(struct ssdfs_extents_btree_node_header);
	u32 node_size;
	u32 items_area_size = 0;
	u16 item_size = 0;
	u16 index_size = 0;
	u16 index_area_min_size;
	u16 items_capacity = 0;
	u16 index_capacity = 0;
	u32 index_area_size = 0;
	size_t bmap_bytes;
	u32 pages_count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
	WARN_ON(atomic_read(&node->state) != SSDFS_BTREE_NODE_CREATED);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	tree = node->tree;
	node_size = tree->node_size;
	index_area_min_size = tree->index_area_min_size;

	node->node_ops = &ssdfs_extents_btree_node_ops;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid items area's state %#x\n",
			  atomic_read(&node->items_area.state));
		return -ERANGE;
	}

	down_write(&node->header_lock);
	down_write(&node->bmap_array.lock);

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
		node->index_area.offset = (u32)hdr_size;
		node->index_area.area_size = node_size - hdr_size;

		index_area_size = node->index_area.area_size;
		index_size = node->index_area.index_size;

		node->index_area.index_capacity = index_area_size / index_size;
		index_capacity = node->index_area.index_capacity;

		node->bmap_array.index_start_bit =
			SSDFS_BTREE_NODE_HEADER_INDEX + 1;
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		node->index_area.offset = (u32)hdr_size;

		if (index_area_min_size == 0 ||
		    index_area_min_size >= (node_size - hdr_size)) {
			err = -ERANGE;
			SSDFS_ERR("invalid index area desc: "
				  "index_area_min_size %u, "
				  "node_size %u, hdr_size %zu\n",
				  index_area_min_size,
				  node_size, hdr_size);
			goto finish_create_node;
		}

		node->index_area.area_size = index_area_min_size;

		index_area_size = node->index_area.area_size;
		index_size = node->index_area.index_size;
		node->index_area.index_capacity = index_area_size / index_size;
		index_capacity = node->index_area.index_capacity;

		node->items_area.offset = node->index_area.offset +
						node->index_area.area_size;

		if (node->items_area.offset >= node_size) {
			err = -ERANGE;
			SSDFS_ERR("invalid items area desc: "
				  "area_offset %u, node_size %u\n",
				  node->items_area.offset,
				  node_size);
			goto finish_create_node;
		}

		node->items_area.area_size = node_size -
						node->items_area.offset;
		node->items_area.free_space = node->items_area.area_size;
		node->items_area.item_size = tree->item_size;
		node->items_area.min_item_size = tree->min_item_size;
		node->items_area.max_item_size = tree->max_item_size;

		items_area_size = node->items_area.area_size;
		item_size = node->items_area.item_size;

		node->items_area.items_count = 0;
		node->items_area.items_capacity = items_area_size / item_size;
		items_capacity = node->items_area.items_capacity;

		if (node->items_area.items_capacity == 0) {
			err = -ERANGE;
			SSDFS_ERR("items area's capacity %u\n",
				  node->items_area.items_capacity);
			goto finish_create_node;
		}

		node->items_area.end_hash = node->items_area.start_hash +
					    node->items_area.items_capacity - 1;

		node->bmap_array.index_start_bit =
			SSDFS_BTREE_NODE_HEADER_INDEX + 1;
		node->bmap_array.item_start_bit =
			node->bmap_array.index_start_bit + index_capacity;
		break;

	case SSDFS_BTREE_LEAF_NODE:
		node->items_area.offset = (u32)hdr_size;
		node->items_area.area_size = node_size - hdr_size;
		node->items_area.free_space = node->items_area.area_size;
		node->items_area.item_size = tree->item_size;
		node->items_area.min_item_size = tree->min_item_size;
		node->items_area.max_item_size = tree->max_item_size;

		items_area_size = node->items_area.area_size;
		item_size = node->items_area.item_size;

		node->items_area.items_count = 0;
		node->items_area.items_capacity = items_area_size / item_size;
		items_capacity = node->items_area.items_capacity;

		node->items_area.end_hash = node->items_area.start_hash +
					    node->items_area.items_capacity - 1;

		node->bmap_array.item_start_bit =
				SSDFS_BTREE_NODE_HEADER_INDEX + 1;
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid node type %#x\n",
			   atomic_read(&node->type));
		goto finish_create_node;
	}

	node->bmap_array.bits_count = index_capacity + items_capacity + 1;

	if (item_size > 0)
		items_capacity = node_size / item_size;
	else
		items_capacity = 0;

	if (index_size > 0)
		index_capacity = node_size / index_size;
	else
		index_capacity = 0;

	bmap_bytes = index_capacity + items_capacity + 1;
	bmap_bytes += BITS_PER_LONG;
	bmap_bytes /= BITS_PER_BYTE;

	node->bmap_array.bmap_bytes = bmap_bytes;

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_EXTENT_MAX_BMAP_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bmap_bytes %zu\n",
			  bmap_bytes);
		goto finish_create_node;
	}

finish_create_node:
	up_write(&node->bmap_array.lock);
	up_write(&node->header_lock);

	if (unlikely(err))
		return err;

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		addr[i] = kzalloc(bmap_bytes, GFP_KERNEL);
		if (!addr[i]) {
			SSDFS_ERR("fail to allocate node's bmap: index %d\n",
				  i);
			for (; i >= 0; i--)
				kfree(addr[i]);
			return -ENOMEM;
		}
	}

	down_write(&node->bmap_array.lock);
	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		spin_lock(&node->bmap_array.bmap[i].lock);
		node->bmap_array.bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&node->bmap_array.bmap[i].lock);
	}
	up_write(&node->bmap_array.lock);

	pages_count = node_size / PAGE_SIZE;

	if (pages_count == 0 || pages_count > PAGEVEC_SIZE) {
		SSDFS_ERR("invalid pages_count %u\n",
			  pages_count);
		return -ERANGE;
	}

	down_write(&node->full_lock);

	pagevec_init(&node->content.pvec);
	for (i = 0; i < pages_count; i++) {
		page = alloc_page(GFP_KERNEL | GFP_NOFS | __GFP_ZERO);
		if (unlikely(!page)) {
			err = -ENOMEM;
			SSDFS_ERR("unable to allocate memory page\n");
			goto finish_init_pvec;
		}

		get_page(page);

		pagevec_add(&node->content.pvec, page);
	}

finish_init_pvec:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_extents_btree_init_node() - init extents tree's node
 * @node: pointer on node object
 *
 * This method tries to init the node of extents btree.
 *
 *       It makes sense to allocate the bitmap with taking into
 *       account that we will resize the node. So, it needs
 *       to allocate the index area in bitmap is equal to
 *       the whole node and items area is equal to the whole node.
 *       This technique provides opportunity not to resize or
 *       to shift the content of the bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 * %-EIO        - invalid node's header content
 */
static
int ssdfs_extents_btree_init_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_extents_btree_info *tree_info = NULL;
	struct ssdfs_extents_btree_node_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_extents_btree_node_header);
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	struct page *page;
	void *kaddr;
	u64 start_hash, end_hash;
	u32 node_size;
	u16 item_size;
	u16 parent_ino;
	u32 forks_count;
	u16 items_capacity;
	u32 allocated_extents, valid_extents;
	u64 calculated_extents;
	u32 max_extent_blks;
	u64 calculated_blks;
	u64 blks_count;
	u32 items_count;
	u16 flags;
	u8 index_size;
	u16 index_capacity = 0;
	size_t bmap_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_extents_btree_info,
					 buffer.tree);
	}

	if (atomic_read(&node->state) != SSDFS_BTREE_NODE_CONTENT_PREPARED) {
		SSDFS_WARN("fail to init node: id %u, state %#x\n",
			   node->node_id, atomic_read(&node->state));
		return -ERANGE;
	}

	down_write(&node->full_lock);

	if (pagevec_count(&node->content.pvec) == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty node's content: id %u\n",
			  node->node_id);
		goto finish_init_node;
	}

	page = node->content.pvec.pages[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = kmap(page);

	hdr = (struct ssdfs_extents_btree_node_header *)kaddr;

	if (!is_csum_valid(&hdr->node.check, hdr, hdr_size)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum: node_id %u\n",
			  node->node_id);
		goto finish_init_operation;
	}

	if (le32_to_cpu(hdr->node.magic.common) != SSDFS_SUPER_MAGIC ||
	    le16_to_cpu(hdr->node.magic.key) != SSDFS_EXTENTS_BNODE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic: common %#x, key %#x\n",
			  le32_to_cpu(hdr->node.magic.common),
			  le16_to_cpu(hdr->node.magic.key));
		goto finish_init_operation;
	}

	down_write(&node->header_lock);

	memcpy(&node->raw.extents_header, hdr, hdr_size);

	err = ssdfs_btree_init_node(node, &hdr->node,
				    hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init node: id %u, err %d\n",
			  node->node_id, err);
		goto finish_header_init;
	}

	start_hash = le64_to_cpu(hdr->node.start_hash);
	end_hash = le64_to_cpu(hdr->node.end_hash);
	node_size = 1 << hdr->node.log_node_size;
	index_size = hdr->node.index_size;
	item_size = hdr->node.min_item_size;
	items_capacity = le16_to_cpu(hdr->node.items_capacity);
	parent_ino = le64_to_cpu(hdr->parent_ino);
	forks_count = le32_to_cpu(hdr->forks_count);
	allocated_extents = le32_to_cpu(hdr->allocated_extents);
	valid_extents = le32_to_cpu(hdr->valid_extents);
	max_extent_blks = le32_to_cpu(hdr->max_extent_blks);
	blks_count = le64_to_cpu(hdr->blks_count);

	if (parent_ino != tree_info->owner->vfs_inode.i_ino) {
		err = -EIO;
		SSDFS_ERR("parent_ino %u != ino %lu\n",
			  parent_ino,
			  tree_info->owner->vfs_inode.i_ino);
		goto finish_header_init;
	}

	if (item_size == 0 || node_size % item_size) {
		err = -EIO;
		SSDFS_ERR("invalid size: item_size %u, node_size %u\n",
			  item_size, node_size);
		goto finish_header_init;
	}

	if (item_size != sizeof(struct ssdfs_raw_fork)) {
		err = -EIO;
		SSDFS_ERR("invalid item_size: "
			  "size %u, expected size %zu\n",
			  item_size,
			  sizeof(struct ssdfs_raw_fork));
		goto finish_header_init;
	}

	if (items_capacity == 0 ||
	    items_capacity > (node_size / item_size)) {
		err = -EIO;
		SSDFS_ERR("invalid items_capacity %u\n",
			  items_capacity);
		goto finish_header_init;
	}

	if (forks_count > items_capacity) {
		err = -EIO;
		SSDFS_ERR("items_capacity %u != forks_count %u\n",
			  items_capacity,
			  forks_count);
		goto finish_header_init;
	}

	if (valid_extents > allocated_extents) {
		err = -EIO;
		SSDFS_ERR("valid_extents %u > allocated_extents %u\n",
			  valid_extents, allocated_extents);
		goto finish_header_init;
	}

	calculated_extents = (u64)forks_count * SSDFS_INLINE_EXTENTS_COUNT;
	if (calculated_extents != allocated_extents) {
		err = -EIO;
		SSDFS_ERR("calculated_extents %llu != allocated_extents %u\n",
			  calculated_extents, allocated_extents);
		goto finish_header_init;
	}

	calculated_blks = (u64)valid_extents * max_extent_blks;
	if (calculated_blks < blks_count) {
		err = -EIO;
		SSDFS_ERR("calculated_blks %llu < blks_count %llu\n",
			  calculated_blks, blks_count);
		goto finish_header_init;
	}

	node->items_area.items_count = (u16)forks_count;
	node->items_area.items_capacity = items_capacity;

finish_header_init:
	up_write(&node->header_lock);

	if (unlikely(err))
		goto finish_init_operation;

	items_count = node_size / item_size;

	if (item_size > 0)
		items_capacity = node_size / item_size;
	else
		items_capacity = 0;

	if (index_size > 0)
		index_capacity = node_size / index_size;
	else
		index_capacity = 0;

	bmap_bytes = index_capacity + items_capacity + 1;
	bmap_bytes += BITS_PER_LONG;
	bmap_bytes /= BITS_PER_BYTE;

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_EXTENT_MAX_BMAP_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bmap_bytes %zu\n",
			  bmap_bytes);
		goto finish_init_operation;
	}

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		addr[i] = kzalloc(bmap_bytes, GFP_KERNEL);
		if (!addr[i]) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate node's bmap: index %d\n",
				  i);
			for (; i >= 0; i--)
				kfree(addr[i]);
			goto finish_init_operation;
		}
	}

	down_write(&node->bmap_array.lock);

	flags = atomic_read(&node->flags);
	if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
		node->bmap_array.index_start_bit =
			SSDFS_BTREE_NODE_HEADER_INDEX + 1;
		/*
		 * Reserve the whole node space as
		 * potential space for indexes.
		 */
		index_capacity = node_size / index_size;
		node->bmap_array.item_start_bit =
			node->bmap_array.index_start_bit + index_capacity;
	} else if (flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA) {
		node->bmap_array.item_start_bit =
				SSDFS_BTREE_NODE_HEADER_INDEX + 1;
	} else
		BUG();

	node->bmap_array.bits_count = index_capacity + items_capacity + 1;
	node->bmap_array.bmap_bytes = bmap_bytes;

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		spin_lock(&node->bmap_array.bmap[i].lock);
		node->bmap_array.bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&node->bmap_array.bmap[i].lock);
	}

	spin_lock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);
	bitmap_set(node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].ptr,
		   0, forks_count);
	spin_unlock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);

	up_write(&node->bmap_array.lock);
finish_init_operation:
	kunmap(page);

	if (unlikely(err))
		goto finish_init_node;

	atomic64_add((u64)forks_count, &tree_info->forks_count);

finish_init_node:
	up_write(&node->full_lock);

	return err;
}

static
void ssdfs_extents_btree_destroy_node(struct ssdfs_btree_node *node)
{
	SSDFS_DBG("operation is unavailable\n");
}

/*
 * ssdfs_extents_btree_add_node() - add node into extents btree
 * @node: pointer on node object
 *
 * This method tries to finish addition of node into extents btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extents_btree_add_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_index_key key;
	int type;
	u16 items_capacity = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected states */
		break;

	default:
		SSDFS_WARN("invalid node: id %u, state %#x\n",
			   node->node_id, atomic_read(&node->state));
		return -ERANGE;
	}

	type = atomic_read(&node->type);

	switch (type) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		/* expected states */
		break;

	default:
		SSDFS_WARN("invalid node type %#x\n", type);
		return -ERANGE;
	};

	down_write(&node->header_lock);

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		items_capacity = node->items_area.items_capacity;
		break;
	default:
		items_capacity = 0;
		break;
	};

	if (items_capacity == 0) {
		if (type == SSDFS_BTREE_LEAF_NODE ||
		    type == SSDFS_BTREE_HYBRID_NODE) {
			err = -ERANGE;
			SSDFS_ERR("invalid node state: "
				  "type %#x, items_capacity %u\n",
				  type, items_capacity);
			goto finish_add_node;
		}
	} else {
		node->raw.extents_header.blks_count = cpu_to_le64(0);
		node->raw.extents_header.forks_count = cpu_to_le32(0);
		node->raw.extents_header.allocated_extents = cpu_to_le32(0);
		node->raw.extents_header.valid_extents = cpu_to_le32(0);
		node->raw.extents_header.max_extent_blks = cpu_to_le32(0);
	}

finish_add_node:
	up_write(&node->header_lock);

	if (err)
		return err;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		spin_lock(&node->descriptor_lock);
		memcpy(&key, &node->node_index,
			sizeof(struct ssdfs_btree_index_key));
		spin_unlock(&node->descriptor_lock);

		SSDFS_DBG("node_id %u, node_type %#x, "
			  "node_height %u, hash %llx\n",
			  le32_to_cpu(key.node_id),
			  key.node_type,
			  key.height,
			  le64_to_cpu(key.index.hash));

		err = ssdfs_btree_node_add_index(node, &key);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add index: err %d\n", err);
			return err;
		}
		break;

	default:
		/* do nothing */
		break;
	}

	return 0;
}


static
int ssdfs_extents_btree_delete_node(struct ssdfs_btree_node *node)
{
	/* TODO: implement */
	SSDFS_WARN("TODO: implement %s\n", __func__);
	return -EOPNOTSUPP;


/*
 * TODO: it needs to add special free space descriptor in the
 *       index area for the case of deleted nodes. Code of
 *       allocation of new items should create empty node
 *       with completely free items during passing through
 *       index level.
 */



/*
 * TODO: node can be really deleted/invalidated. But index
 *       area should contain index for deleted node with
 *       special flag. In this case it will be clear that
 *       we have some capacity without real node allocation.
 *       If some item will be added in the node then node
 *       has to be allocated. It means that if you delete
 *       a node then index hierachy will be the same without
 *       necessity to delete or modify it.
 */



	/* TODO:  decrement nodes_count and/or leaf_nodes counters */
	/* TODO:  decrease inodes_capacity and/or free_inodes */
}

/*
 * ssdfs_extents_btree_pre_flush_node() - pre-flush node's header
 * @node: pointer on node object
 *
 * This method tries to flush node's header.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_extents_btree_pre_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_extents_btree_node_header extents_header;
	size_t hdr_size = sizeof(struct ssdfs_extents_btree_node_header);
	struct ssdfs_btree *tree;
	struct ssdfs_extents_btree_info *tree_info = NULL;
	struct ssdfs_state_bitmap *bmap;
	struct page *page;
	void *kaddr;
	u16 items_count;
	u32 forks_count;
	u32 allocated_extents;
	u32 valid_extents;
	u32 max_extent_blks;
	u64 blks_count;
	u64 calculated_extents;
	u64 calculated_blks;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
		SSDFS_DBG("node %u is clean\n",
			  node->node_id);
		return 0;

	case SSDFS_BTREE_NODE_CORRUPTED:
		SSDFS_WARN("node %u is corrupted\n",
			   node->node_id);
		down_read(&node->bmap_array.lock);
		bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
		spin_lock(&bmap->lock);
		bitmap_clear(bmap->ptr, 0, node->bmap_array.bits_count);
		spin_unlock(&bmap->lock);
		up_read(&node->bmap_array.lock);
		clear_ssdfs_btree_node_dirty(node);
		return -EFAULT;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_extents_btree_info,
					 buffer.tree);
	}

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	memcpy(&extents_header, &node->raw.extents_header, hdr_size);

	extents_header.node.magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	extents_header.node.magic.key = cpu_to_le16(SSDFS_EXTENTS_BNODE_MAGIC);
	extents_header.node.magic.version.major = SSDFS_MAJOR_REVISION;
	extents_header.node.magic.version.minor = SSDFS_MINOR_REVISION;

	err = ssdfs_btree_node_pre_flush_header(node, &extents_header.node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush generic header: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_extents_header_preparation;
	}

	if (!tree_info->owner) {
		err = -ERANGE;
		SSDFS_WARN("fail to extract parent_ino\n");
		goto finish_extents_header_preparation;
	}

	extents_header.parent_ino =
		cpu_to_le64(tree_info->owner->vfs_inode.i_ino);

	items_count = node->items_area.items_count;
	forks_count = le32_to_cpu(extents_header.forks_count);
	allocated_extents = le32_to_cpu(extents_header.allocated_extents);
	valid_extents = le32_to_cpu(extents_header.valid_extents);
	max_extent_blks = le32_to_cpu(extents_header.max_extent_blks);
	blks_count = le64_to_cpu(extents_header.blks_count);

	if (forks_count != items_count) {
		err = -ERANGE;
		SSDFS_ERR("forks_count %u != items_count %u\n",
			  forks_count, items_count);
		goto finish_extents_header_preparation;
	}

	if (valid_extents > allocated_extents) {
		err = -ERANGE;
		SSDFS_ERR("valid_extents %u > allocated_extents %u\n",
			  valid_extents, allocated_extents);
		goto finish_extents_header_preparation;
	}

	calculated_extents = (u64)forks_count * SSDFS_INLINE_EXTENTS_COUNT;
	if (calculated_extents != allocated_extents) {
		err = -ERANGE;
		SSDFS_ERR("calculated_extents %llu != allocated_extents %u\n",
			  calculated_extents, allocated_extents);
		goto finish_extents_header_preparation;
	}

	calculated_blks = (u64)valid_extents * max_extent_blks;
	if (calculated_blks < blks_count) {
		err = -ERANGE;
		SSDFS_ERR("calculated_blks %llu < blks_count %llu\n",
			  calculated_blks, blks_count);
		goto finish_extents_header_preparation;
	}

	extents_header.node.check.bytes = cpu_to_le16((u16)hdr_size);
	extents_header.node.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&extents_header.node.check,
				   &extents_header, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto finish_extents_header_preparation;
	}

	memcpy(&node->raw.extents_header, &extents_header,
		sizeof(struct ssdfs_extents_btree_node_header));

finish_extents_header_preparation:
	up_write(&node->header_lock);

	if (unlikely(err))
		goto finish_node_pre_flush;

	if (pagevec_count(&node->content.pvec) < 1) {
		err = -ERANGE;
		SSDFS_ERR("pagevec is empty\n");
		goto finish_node_pre_flush;
	}

	page = node->content.pvec.pages[0];
	kaddr = kmap_atomic(page);
	memcpy(kaddr, &extents_header,
		sizeof(struct ssdfs_extents_btree_node_header));
	kunmap_atomic(kaddr);

finish_node_pre_flush:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_extents_btree_flush_node() - flush node
 * @node: pointer on node object
 *
 * This method tries to flush node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_extents_btree_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_extents_btree_info *tree_info = NULL;
	int private_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node %p, node_id %u\n",
		  node, node->node_id);

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_extents_btree_info,
					 buffer.tree);
	}

	private_flags = atomic_read(&tree_info->owner->private_flags);

	if (private_flags & SSDFS_INODE_HAS_EXTENTS_BTREE) {
		switch (atomic_read(&tree_info->type)) {
		case SSDFS_PRIVATE_EXTENTS_BTREE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid tree type %#x\n",
				  atomic_read(&tree_info->type));
			return -ERANGE;
		}

		err = ssdfs_btree_common_node_flush(node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush node: "
				  "node_id %u, height %u, err %d\n",
				  node->node_id,
				  atomic_read(&node->height),
				  err);
		}
	} else {
		err = -ERANGE;
		SSDFS_ERR("extents tree is inline forks array\n");
	}

	return err;
}

/******************************************************************************
 *               SPECIALIZED EXTENTS BTREE NODE OPERATIONS                    *
 ******************************************************************************/

/*
 * ssdfs_convert_lookup2item_index() - convert lookup into item index
 * @node_size: size of the node in bytes
 * @lookup_index: lookup index
 */
static inline
u16 ssdfs_convert_lookup2item_index(u32 node_size, u16 lookup_index)
{
	SSDFS_DBG("node_size %u, lookup_index %u\n",
		  node_size, lookup_index);

	return __ssdfs_convert_lookup2item_index(lookup_index, node_size,
					sizeof(struct ssdfs_raw_fork),
					SSDFS_EXTENTS_BTREE_LOOKUP_TABLE_SIZE);
}

/*
 * ssdfs_convert_item2lookup_index() - convert item into lookup index
 * @node_size: size of the node in bytes
 * @item_index: item index
 */
static inline
u16 ssdfs_convert_item2lookup_index(u32 node_size, u16 item_index)
{
	SSDFS_DBG("node_size %u, item_index %u\n",
		  node_size, item_index);

	return __ssdfs_convert_item2lookup_index(item_index, node_size,
					sizeof(struct ssdfs_raw_fork),
					SSDFS_EXTENTS_BTREE_LOOKUP_TABLE_SIZE);
}

/*
 * is_hash_for_lookup_table() - should item's hash be into lookup table?
 * @node_size: size of the node in bytes
 * @item_index: item index
 */
static inline
bool is_hash_for_lookup_table(u32 node_size, u16 item_index)
{
	u16 lookup_index;
	u16 calculated;

	lookup_index = ssdfs_convert_item2lookup_index(node_size, item_index);
	calculated = ssdfs_convert_lookup2item_index(node_size, lookup_index);

	return calculated == item_index;
}

/*
 * ssdfs_extents_btree_node_find_lookup_index() - find lookup index
 * @node: node object
 * @search: search object
 * @lookup_index: lookup index [out]
 *
 * This method tries to find a lookup index for requested items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - lookup index doesn't exist for requested hash.
 */
static
int ssdfs_extents_btree_node_find_lookup_index(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search,
					    u16 *lookup_index)
{
	__le64 *lookup_table;
	int array_size = SSDFS_EXTENTS_BTREE_LOOKUP_TABLE_SIZE;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search || !lookup_index);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	down_read(&node->header_lock);
	lookup_table = node->raw.extents_header.lookup_table;
	err = ssdfs_btree_node_find_lookup_index_nolock(search,
							lookup_table,
							array_size,
							lookup_index);
	up_read(&node->header_lock);

	return err;
}

/*
 * ssdfs_get_fork_hash_range() - get fork's hash range
 * @kaddr: pointer on the fork object
 * @start_hash: pointer on the value of starting hash [out]
 * @end_hash: pointer on the value of ending hash [out]
 */
static
void ssdfs_get_fork_hash_range(void *kaddr,
				u64 *start_hash,
				u64 *end_hash)
{
	struct ssdfs_raw_fork *fork;
	u64 blks_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !start_hash || !end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p\n", kaddr);

	fork = (struct ssdfs_raw_fork *)kaddr;
	*start_hash = le64_to_cpu(fork->start_offset);
	blks_count = le64_to_cpu(fork->blks_count);
	*end_hash = *start_hash + blks_count;
}

/*
 * ssdfs_check_found_fork() - check found fork
 * @fsi: pointer on shared file system object
 * @search: search object
 * @kaddr: pointer on the fork object
 * @item_index: index of the item
 * @start_hash: pointer on the value of starting hash [out]
 * @end_hash: pointer on the value of ending hash [out]
 * @found_index: pointer on the avlue with found index [out]
 *
 * This method tries to check the found fork.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - possible place was found.
 */
static
int ssdfs_check_found_fork(struct ssdfs_fs_info *fsi,
			   struct ssdfs_btree_search *search,
			   void *kaddr,
			   u16 item_index,
			   u64 *start_hash,
			   u64 *end_hash,
			   u16 *found_index)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !kaddr || !found_index);
	BUG_ON(!start_hash || !end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("item_index %u\n", item_index);

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;
	*found_index = U16_MAX;

	ssdfs_get_fork_hash_range(kaddr, start_hash, end_hash);

	if (search->request.end.hash < *start_hash) {
		err = -ENODATA;
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = err;
		search->result.start_index = item_index;
		search->result.count = 1;
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
		search->result.buf = NULL;
		search->result.buf_size = 0;
		search->result.items_in_buffer = 0;
	} else if (*start_hash <= search->request.start.hash &&
	    search->request.start.hash < *end_hash) {
		/* start_hash is inside the fork */
		*found_index = item_index;
	} else if (*start_hash <= search->request.end.hash &&
		   search->request.end.hash < *end_hash) {
		err = -ERANGE;
		SSDFS_ERR("requested range exists partially\n");
	}

	return err;
}

/*
 * ssdfs_prepare_forks_buffer() - prepare buffer for the forks
 * @search: search object
 * @found_index: found index of the item
 * @start_hash: starting hash of the range
 * @end_hash: ending hash of the range
 * @items_count: count of items in the range
 * @item_size: size of the item in bytes
 *
 * This method tries to prepare the buffers for the forks' range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate the memory.
 */
static
int ssdfs_prepare_forks_buffer(struct ssdfs_btree_search *search,
				u16 found_index,
				u64 start_hash,
				u64 end_hash,
				u16 items_count,
				size_t item_size)
{
	u16 found_forks = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("found_index %u, start_hash %llx, end_hash %llx, "
		  "items_count %u, item_size %zu\n",
		   found_index, start_hash, end_hash,
		   items_count, item_size);

	if (start_hash <= search->request.end.hash &&
	    search->request.end.hash <= end_hash) {
		/* use inline buffer */
		found_forks = 1;
	} else {
		/* use external buffer */
		if (found_index >= items_count) {
			SSDFS_ERR("found_index %u >= items_count %u\n",
				  found_index, items_count);
			return -ERANGE;
		}
		found_forks = items_count - found_index;
	}

	if (found_forks == 1) {
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		search->result.buf = &search->raw.fork;
		search->result.buf_size = item_size;
		search->result.items_in_buffer = 0;
	} else {
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
		search->result.buf_size = item_size;
		search->result.buf_size *= found_forks;
		search->result.buf = kzalloc(search->result.buf_size,
					     GFP_KERNEL);
		if (!search->result.buf) {
			SSDFS_ERR("fail to allocate buffer: "
				  "size %zu\n",
				  search->result.buf_size);
			return -ENOMEM;
		}
		search->result.items_in_buffer = 0;
	}

	return 0;
}

/*
 * ssdfs_extract_found_fork() - extract found fork
 * @fsi: pointer on shared file system object
 * @search: search object
 * @item_size: size of the item in bytes
 * @kaddr: pointer on the fork object
 * @start_hash: pointer on the value of starting hash [out]
 * @end_hash: pointer on the value of ending hash [out]
 *
 * This method tries to extract the found fork.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extract_found_fork(struct ssdfs_fs_info *fsi,
			     struct ssdfs_btree_search *search,
			     size_t item_size,
			     void *kaddr,
			     u64 *start_hash,
			     u64 *end_hash)
{
	u32 calculated;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !kaddr);
	BUG_ON(!start_hash || !end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p\n", kaddr);

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;

	calculated = search->result.items_in_buffer * item_size;
	if (calculated >= search->result.buf_size) {
		SSDFS_ERR("calculated %u >= buf_size %zu\n",
			  calculated, search->result.buf_size);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_get_fork_hash_range(kaddr, start_hash, end_hash);
	memcpy((u8 *)search->result.buf + calculated,
		kaddr, item_size);
	search->result.items_in_buffer++;
	search->result.count++;
	search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;

	return 0;
}

/*
 * ssdfs_extract_range_by_lookup_index() - extract a range of items
 * @node: pointer on node object
 * @lookup_index: lookup index for requested range
 * @search: pointer on search request object
 *
 * This method tries to extract a range of items from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - requested range is out of the node.
 */
static
int ssdfs_extract_range_by_lookup_index(struct ssdfs_btree_node *node,
					u16 lookup_index,
					struct ssdfs_btree_search *search)
{
	int capacity = SSDFS_EXTENTS_BTREE_LOOKUP_TABLE_SIZE;
	size_t item_size = sizeof(struct ssdfs_raw_fork);

	return __ssdfs_extract_range_by_lookup_index(node, lookup_index,
						     capacity, item_size,
						     search,
						     ssdfs_check_found_fork,
						     ssdfs_prepare_forks_buffer,
						     ssdfs_extract_found_fork);
}

/*
 * ssdfs_extents_btree_node_find_range() - find a range of items into the node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to find a range of items into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - requested range is out of the node.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_extents_btree_node_find_range(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	int state;
	u16 items_count;
	u16 items_capacity;
	u64 start_hash;
	u64 end_hash;
	u16 lookup_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	down_read(&node->header_lock);
	state = atomic_read(&node->items_area.state);
	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	up_read(&node->header_lock);

	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	if (items_capacity == 0 || items_count > items_capacity) {
		SSDFS_ERR("corrupted node description: "
			  "items_count %u, items_capacity %u\n",
			  items_count,
			  items_capacity);
		return -ERANGE;
	}

	if (search->request.count == 0 ||
	    search->request.count > items_capacity) {
		SSDFS_ERR("invalid request: "
			  "count %u, items_capacity %u\n",
			  search->request.count,
			  items_capacity);
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_hash_range(node,
						items_count,
						items_capacity,
						start_hash,
						end_hash,
						search);
	if (err)
		return err;

	err = ssdfs_extents_btree_node_find_lookup_index(node, search,
							 &lookup_index);
	if (err == -ENODATA) {
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = -ENODATA;
		search->result.start_index =
			ssdfs_convert_lookup2item_index(node->node_size,
							lookup_index);
		search->result.count = search->request.count;
		search->result.search_cno =
			ssdfs_current_cno(node->tree->fsi->sb);

		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_ADD_ITEM:
		case SSDFS_BTREE_SEARCH_ADD_RANGE:
		case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
			/* do nothing */
			break;

		default:
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */

			search->result.buf_state =
				SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
			search->result.buf = NULL;
			search->result.buf_size = 0;
			search->result.items_in_buffer = 0;
			break;
		}

		return -ENODATA;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the index: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(lookup_index >= SSDFS_EXTENTS_BTREE_LOOKUP_TABLE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_extract_range_by_lookup_index(node, lookup_index,
						  search);
	search->result.search_cno = ssdfs_current_cno(node->tree->fsi->sb);

	if (err == -EAGAIN) {
		SSDFS_DBG("node contains not all requested blocks: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx)\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to extract range: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_extents_btree_node_find_item() - find item into node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to find an item into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extents_btree_node_find_item(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	if (search->request.count != 1 ||
	    search->request.start.hash != search->request.end.hash) {
		SSDFS_ERR("invalid request state: "
			  "count %d, start_hash %llx, end_hash %llx\n",
			  search->request.count,
			  search->request.start.hash,
			  search->request.end.hash);
		return -ERANGE;
	}

	return ssdfs_extents_btree_node_find_range(node, search);
}

static
int ssdfs_extents_btree_node_allocate_item(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

static
int ssdfs_extents_btree_node_allocate_range(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

/*
 * __ssdfs_extents_btree_node_get_fork() - extract the fork from pagevec
 * @pvec: pointer on pagevec
 * @area_offset: area offset from the node's beginning
 * @area_size: area size
 * @node_size: size of the node
 * @item_index: index of the fork in the node
 * @fork: pointer on fork's buffer [out]
 *
 * This method tries to extract the fork from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int __ssdfs_extents_btree_node_get_fork(struct pagevec *pvec,
					u32 area_offset,
					u32 area_size,
					u32 node_size,
					u16 item_index,
					struct ssdfs_raw_fork *fork)
{
	struct ssdfs_raw_fork *found_fork;
	size_t item_size = sizeof(struct ssdfs_raw_fork);
	u32 item_offset;
	int page_index;
	struct page *page;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec || !fork);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("area_offset %u, area_size %u, item_index %u\n",
		  area_offset, area_size, item_index);

	item_offset = (u32)item_index * item_size;
	if (item_offset >= area_size) {
		SSDFS_ERR("item_offset %u >= area_size %u\n",
			  item_offset, area_size);
		return -ERANGE;
	}

	item_offset += area_offset;
	if (item_offset >= node_size) {
		SSDFS_ERR("item_offset %u >= node_size %u\n",
			  item_offset, node_size);
		return -ERANGE;
	}

	page_index = item_offset >> PAGE_SHIFT;

	if (page_index > 0)
		item_offset %= page_index * PAGE_SIZE;

	if (page_index >= pagevec_count(pvec)) {
		SSDFS_ERR("invalid page_index: "
			  "index %d, pvec_size %u\n",
			  page_index,
			  pagevec_count(pvec));
		return -ERANGE;
	}

	page = pvec->pages[page_index];

	kaddr = kmap_atomic(page);
	found_fork = (struct ssdfs_raw_fork *)((u8 *)kaddr + item_offset);
	memcpy(fork, found_fork, item_size);
	kunmap_atomic(kaddr);

	return 0;
}

/*
 * ssdfs_extents_btree_node_get_fork() - extract fork from the node
 * @node: pointer on node object
 * @area: items area descriptor
 * @item_index: index of the fork
 * @fork: pointer on extracted fork [out]
 *
 * This method tries to extract the fork from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extents_btree_node_get_fork(struct ssdfs_btree_node *node,
				  struct ssdfs_btree_node_items_area *area,
				  u16 item_index,
				  struct ssdfs_raw_fork *fork)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !fork);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, item_index);

	return __ssdfs_extents_btree_node_get_fork(&node->content.pvec,
						   area->offset,
						   area->area_size,
						   node->node_size,
						   item_index,
						   fork);
}

/*
 * is_requested_position_correct() - check that requested position is correct
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to check that requested position of a fork
 * into the node is correct.
 *
 * RETURN:
 * [success]
 *
 * %SSDFS_CORRECT_POSITION        - requested position is correct.
 * %SSDFS_SEARCH_LEFT_DIRECTION   - correct position from the left.
 * %SSDFS_SEARCH_RIGHT_DIRECTION  - correct position from the right.
 *
 * [failure] - error code:
 *
 * %SSDFS_CHECK_POSITION_FAILURE  - internal error.
 */
static
int is_requested_position_correct(struct ssdfs_btree_node *node,
				  struct ssdfs_btree_node_items_area *area,
				  struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_fork fork;
	u16 item_index;
	u64 start_offset;
	u64 blks_count;
	u64 end_offset;
	int direction = SSDFS_CHECK_POSITION_FAILURE;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	if (item_index >= area->items_count) {
		if (area->items_count == 0)
			item_index = area->items_count;
		else
			item_index = area->items_count - 1;

		search->result.start_index = item_index;
	}

	if (item_index == 0)
		return SSDFS_CORRECT_POSITION;

	err = ssdfs_extents_btree_node_get_fork(node, area,
						item_index, &fork);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the fork: "
			  "item_index %u, err %d\n",
			  item_index, err);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	start_offset = le64_to_cpu(fork.start_offset);
	blks_count = le64_to_cpu(fork.blks_count);

	if (start_offset >= U64_MAX || blks_count >= U64_MAX) {
		SSDFS_ERR("invalid fork\n");
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	end_offset = start_offset + blks_count;

	if (start_offset <= search->request.start.hash &&
	    search->request.start.hash < end_offset)
		direction = SSDFS_CORRECT_POSITION;
	else if (search->request.start.hash < start_offset)
		direction = SSDFS_SEARCH_LEFT_DIRECTION;
	else
		direction = SSDFS_SEARCH_RIGHT_DIRECTION;

	return direction;
}

/*
 * ssdfs_find_correct_position_from_left() - find position from the left
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to find a correct position of the fork
 * from the left side of forks' sequence in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_find_correct_position_from_left(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_items_area *area,
				    struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_fork fork;
	int item_index;
	u64 start_offset;
	u64 blks_count;
	u64 end_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %d, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	if (item_index >= area->items_count) {
		if (area->items_count == 0)
			item_index = area->items_count;
		else
			item_index = area->items_count - 1;

		search->result.start_index = (u16)item_index;
	}

	if (item_index == 0)
		return 0;

	for (; item_index >= 0; item_index--) {
		err = ssdfs_extents_btree_node_get_fork(node, area,
							(u16)item_index,
							&fork);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the fork: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		start_offset = le64_to_cpu(fork.start_offset);
		blks_count = le64_to_cpu(fork.blks_count);
		end_offset = start_offset + blks_count;

		if (start_offset <= search->request.start.hash &&
		    search->request.start.hash < end_offset) {
			search->result.start_index = (u16)item_index;
			return 0;
		} else if (end_offset <= search->request.start.hash) {
			search->result.start_index = (u16)(item_index + 1);
			return 0;
		}
	}

	search->result.start_index = 0;
	return 0;
}

/*
 * ssdfs_find_correct_position_from_right() - find position from the right
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to find a correct position of the fork
 * from the right side of forks' sequence in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_find_correct_position_from_right(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_items_area *area,
				    struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_fork fork;
	int item_index;
	u64 start_offset;
	u64 blks_count;
	u64 end_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %d, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	if (item_index >= area->items_count) {
		if (area->items_count == 0)
			item_index = area->items_count;
		else
			item_index = area->items_count - 1;

		search->result.start_index = (u16)item_index;
	}

	if (item_index == 0)
		return 0;

	for (; item_index < area->items_count; item_index++) {
		err = ssdfs_extents_btree_node_get_fork(node, area,
							(u16)item_index,
							&fork);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the fork: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		start_offset = le64_to_cpu(fork.start_offset);
		blks_count = le64_to_cpu(fork.blks_count);
		end_offset = start_offset + blks_count;

		if (start_offset <= search->request.start.hash &&
		    search->request.start.hash < end_offset) {
			search->result.start_index = (u16)item_index;
			return 0;
		} else if (search->request.end.hash < start_offset) {
			if (item_index == 0) {
				search->result.start_index =
						(u16)item_index;
			} else {
				search->result.start_index =
						(u16)(item_index - 1);
			}
			return 0;
		}
	}

	search->result.start_index = area->items_count - 1;
	return 0;
}

/*
 * ssdfs_correct_lookup_table() - correct lookup table of the node
 * @node: pointer on node object
 * @area: items area descriptor
 * @start_index: starting index of the range
 * @range_len: number of items in the range
 *
 * This method tries to correct the lookup table of the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_correct_lookup_table(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *area,
				u16 start_index, u16 range_len)
{
	__le64 *lookup_table;
	struct ssdfs_raw_fork fork;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u\n", node->node_id);

	if (range_len == 0) {
		SSDFS_WARN("search->request.count == 0\n");
		return -ERANGE;
	}

	lookup_table = node->raw.extents_header.lookup_table;

	for (i = 0; i < range_len; i++) {
		int item_index = start_index + i;
		u16 lookup_index;

		if (is_hash_for_lookup_table(node->node_size, item_index)) {
			lookup_index =
				ssdfs_convert_item2lookup_index(node->node_size,
								item_index);

			err = ssdfs_extents_btree_node_get_fork(node, area,
								item_index,
								&fork);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract fork: "
					  "item_index %d, err %d\n",
					  item_index, err);
				return err;
			}

			lookup_table[lookup_index] = fork.start_offset;
		}
	}

	return 0;
}

/*
 * ssdfs_initialize_lookup_table() - initialize lookup table
 * @node: pointer on node object
 */
static
void ssdfs_initialize_lookup_table(struct ssdfs_btree_node *node)
{
	__le64 *lookup_table;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->header_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u\n", node->node_id);

	lookup_table = node->raw.extents_header.lookup_table;
	memset(lookup_table, 0xFF,
		sizeof(__le64) * SSDFS_EXTENTS_BTREE_LOOKUP_TABLE_SIZE);
}

/*
 * ssdfs_calculate_range_blocks() - calculate number of blocks in range
 * @search: search object
 * @valid_extents: number of valid extents in the range [out]
 * @blks_count: number of blocks in the range [out]
 * @max_extent_blks: maximal number of blocks in one extent [out]
 *
 * This method tries to calculate the @valid_extents,
 * @blks_count, @max_extent_blks in the range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_calculate_range_blocks(struct ssdfs_btree_search *search,
				 u32 *valid_extents,
				 u64 *blks_count,
				 u32 *max_extent_blks)
{
	struct ssdfs_raw_fork *fork;
	size_t item_size = sizeof(struct ssdfs_raw_fork);
	u32 items;
	int i, j;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !valid_extents || !blks_count || !max_extent_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u\n", search->node.id);

	*valid_extents = 0;
	*blks_count = 0;
	*max_extent_blks = 0;

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	if (!search->result.buf) {
		SSDFS_ERR("buffer pointer is NULL\n");
		return -ERANGE;
	}

	items = search->result.items_in_buffer;
	if (search->result.buf_size != (items * item_size)) {
		SSDFS_ERR("buf_size %zu, items_in_buffer %u, "
			  "item_size %zu\n",
			  search->result.buf_size,
			  items, item_size);
		return -ERANGE;
	}

	for (i = 0; i < items; i++) {
		u64 blks;
		u64 calculated = 0;

		fork = (struct ssdfs_raw_fork *)((u8 *)search->result.buf +
							(i * item_size));

		blks = le64_to_cpu(fork->blks_count);
		if (blks >= U64_MAX || blks == 0) {
			SSDFS_ERR("corrupted fork: blks_count %llu\n",
				  blks);
			return -ERANGE;
		}

		*blks_count += blks;

		for (j = 0; j < SSDFS_INLINE_EXTENTS_COUNT; j++) {
			struct ssdfs_raw_extent *extent;
			u32 len;

			extent = &fork->extents[j];
			len = le32_to_cpu(extent->len);

			if (len == 0 || len >= U32_MAX)
				break;

			calculated += len;
			*valid_extents += 1;

			if (*max_extent_blks < len)
				*max_extent_blks = len;
		}

		if (calculated != blks) {
			SSDFS_ERR("calculated %llu != blks %llu\n",
				  calculated, blks);
			return -ERANGE;
		}
	}

	return 0;
}

/*
 * ssdfs_calculate_range_blocks_in_node() - calculate number of blocks in range
 * @node: pointer on node object
 * @area: items area descriptor
 * @start_index: starting index of the range
 * @range_len: number of items in the range
 * @valid_extents: number of valid extents in the range [out]
 * @blks_count: number of blocks in the range [out]
 * @max_extent_blks: maximal number of blocks in one extent [out]
 *
 * This method tries to calculate the @valid_extents,
 * @blks_count, @max_extent_blks in the range inside the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_calculate_range_blocks_in_node(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_items_area *area,
				    u16 start_index, u16 range_len,
				    u32 *valid_extents,
				    u64 *blks_count,
				    u32 *max_extent_blks)
{
	struct ssdfs_raw_fork fork;
	int i, j;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!valid_extents || !blks_count || !max_extent_blks);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);

	*valid_extents = 0;
	*blks_count = 0;
	*max_extent_blks = 0;

	if (range_len == 0) {
		SSDFS_WARN("search->request.count == 0\n");
		return -ERANGE;
	}

	if ((start_index + range_len) > area->items_count) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, range_len %u, items_count %u\n",
			  start_index, range_len, area->items_count);
		return -ERANGE;
	}

	for (i = 0; i < range_len; i++) {
		int item_index = (int)start_index + i;
		u64 blks;
		u64 calculated = 0;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(item_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_extents_btree_node_get_fork(node, area,
							(u16)item_index,
							&fork);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract fork: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		blks = le64_to_cpu(fork.blks_count);
		if (blks >= U64_MAX || blks == 0) {
			SSDFS_ERR("corrupted fork: blks_count %llu\n",
				  blks);
			return -ERANGE;
		}

		*blks_count += blks;

		for (j = 0; j < SSDFS_INLINE_EXTENTS_COUNT; j++) {
			struct ssdfs_raw_extent *extent;
			u32 len;

			extent = &fork.extents[j];
			len = le32_to_cpu(extent->len);

			if (len == 0 || len >= U32_MAX)
				break;

			calculated += len;
			*valid_extents += 1;

			if (*max_extent_blks < len)
				*max_extent_blks = len;
		}

		if (calculated != blks) {
			SSDFS_ERR("calculated %llu != blks %llu\n",
				  calculated, blks);
			return -ERANGE;
		}
	}

	return 0;
}

/*
 * __ssdfs_extents_btree_node_insert_range() - insert range of forks into node
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to insert the range of forks into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int __ssdfs_extents_btree_node_insert_range(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	struct ssdfs_btree *tree;
	struct ssdfs_extents_btree_info *etree;
	struct ssdfs_extents_btree_node_header *hdr;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_raw_fork fork;
	size_t item_size = sizeof(struct ssdfs_raw_fork);
	u16 item_index;
	int free_items;
	int direction;
	u16 range_len;
	u16 forks_count = 0;
	u32 used_space;
	u64 start_hash, end_hash;
	u64 blks_count;
	u32 valid_extents;
	u32 max_extent_blks;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid items_area state %#x\n",
			  atomic_read(&node->items_area.state));
		return -ERANGE;
	}

	tree = node->tree;

	switch (tree->type) {
	case SSDFS_EXTENTS_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	etree = container_of(tree, struct ssdfs_extents_btree_info,
			     buffer.tree);

	down_read(&node->header_lock);
	memcpy(&items_area, &node->items_area,
		sizeof(struct ssdfs_btree_node_items_area));
	up_read(&node->header_lock);

	if (items_area.items_capacity == 0 ||
	    items_area.items_capacity < items_area.items_count) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid items accounting: "
			  "node_id %u, items_capacity %u, items_count %u\n",
			  node->node_id, items_area.items_capacity,
			  items_area.items_count);
		return -EFAULT;
	}

	if (items_area.min_item_size != item_size ||
	    items_area.max_item_size != item_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("min_item_size %u, max_item_size %u, "
			  "item_size %zu\n",
			  items_area.min_item_size, items_area.max_item_size,
			  item_size);
		return -EFAULT;
	}

	if (items_area.area_size == 0 ||
	    items_area.area_size >= node->node_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid area_size %u\n",
			  items_area.area_size);
		return -EFAULT;
	}

	if (items_area.free_space > items_area.area_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("free_space %u > area_size %u\n",
			  items_area.free_space, items_area.area_size);
		return -EFAULT;
	}

	free_items = items_area.items_capacity - items_area.items_count;
	if (unlikely(free_items < 0)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_WARN("invalid free_items %d\n",
			   free_items);
		return -EFAULT;
	} else if (free_items == 0) {
		SSDFS_DBG("node hasn't free items\n");
		return -ENOSPC;
	}

	if (((u64)free_items * item_size) > items_area.free_space) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid free_items: "
			  "free_items %d, item_size %zu, free_space %u\n",
			  free_items, item_size, items_area.free_space);
		return -EFAULT;
	}

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= items_area.items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	down_write(&node->full_lock);

	direction = is_requested_position_correct(node, &items_area,
						  search);
	switch (direction) {
	case SSDFS_CORRECT_POSITION:
		/* do nothing */
		break;

	case SSDFS_SEARCH_LEFT_DIRECTION:
		err = ssdfs_find_correct_position_from_left(node, &items_area,
							    search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_detect_affected_items;
		}
		break;

	case SSDFS_SEARCH_RIGHT_DIRECTION:
		err = ssdfs_find_correct_position_from_right(node, &items_area,
							     search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_detect_affected_items;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("fail to check requested position\n");
		goto finish_detect_affected_items;
	}

	range_len = items_area.items_count - search->result.start_index;
	forks_count = range_len + search->request.count;

	item_index = search->result.start_index;
	if ((item_index + forks_count) > items_area.items_capacity) {
		err = -ERANGE;
		SSDFS_ERR("invalid forks_count: "
			  "item_index %u, forks_count %u, items_capacity %u\n",
			  item_index, forks_count,
			  items_area.items_capacity);
		goto finish_detect_affected_items;
	}

	err = ssdfs_lock_items_range(node, item_index, forks_count);
	if (err == -ENOENT) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (err == -ENODATA) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (unlikely(err))
		BUG();

finish_detect_affected_items:
	downgrade_write(&node->full_lock);

	if (unlikely(err))
		goto finish_insert_range;

	err = ssdfs_shift_range_right(node, &items_area, item_size,
				      item_index, range_len,
				      search->request.count);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to shift forks range: "
			  "start %u, count %u, err %d\n",
			  item_index, search->request.count,
			  err);
		goto unlock_items_range;
	}

	err = ssdfs_generic_insert_range(node, &items_area,
					 item_size, search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to insert range: err %d\n",
			  err);
		goto unlock_items_range;
	}

	down_write(&node->header_lock);

	node->items_area.items_count += search->request.count;
	if (node->items_area.items_count > node->items_area.items_capacity) {
		err = -ERANGE;
		SSDFS_ERR("items_count %u > items_capacity %u\n",
			  node->items_area.items_count,
			  node->items_area.items_capacity);
		goto finish_items_area_correction;
	}

	used_space = (u32)search->request.count * item_size;
	if (used_space > node->items_area.free_space) {
		err = -ERANGE;
		SSDFS_ERR("used_space %u > free_space %u\n",
			  used_space,
			  node->items_area.free_space);
		goto finish_items_area_correction;
	}
	node->items_area.free_space -= used_space;

	err = ssdfs_extents_btree_node_get_fork(node, &node->items_area,
						0, &fork);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get fork: err %d\n", err);
		goto finish_items_area_correction;
	}
	start_hash = le64_to_cpu(fork.start_offset);

	err = ssdfs_extents_btree_node_get_fork(node,
					&node->items_area,
					node->items_area.items_count - 1,
					&fork);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get fork: err %d\n", err);
		goto finish_items_area_correction;
	}
	end_hash = le64_to_cpu(fork.start_offset);

	if (start_hash >= U64_MAX || end_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		goto finish_items_area_correction;
	}

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	err = ssdfs_correct_lookup_table(node, &node->items_area,
					 item_index, forks_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

	hdr = &node->raw.extents_header;

	le32_add_cpu(&hdr->forks_count, search->request.count);
	le32_add_cpu(&hdr->allocated_extents,
		     search->request.count * SSDFS_INLINE_EXTENTS_COUNT);

	err = ssdfs_calculate_range_blocks(search, &valid_extents,
					   &blks_count, &max_extent_blks);
	if (unlikely(err)) {
		SSDFS_ERR("fail to calculate range blocks: err %d\n",
			  err);
		goto finish_items_area_correction;
	}

	le32_add_cpu(&hdr->valid_extents, valid_extents);
	le64_add_cpu(&hdr->blks_count, blks_count);

	if (le32_to_cpu(hdr->max_extent_blks) < max_extent_blks)
		hdr->max_extent_blks = cpu_to_le32(max_extent_blks);

	atomic64_add(search->request.count, &etree->forks_count);

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		goto unlock_items_range;
	}

	err = ssdfs_set_node_header_dirty(node, items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto unlock_items_range;
	}

	err = ssdfs_set_dirty_items_range(node, items_area.items_capacity,
					  item_index, forks_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  item_index, forks_count, err);
		goto unlock_items_range;
	}

unlock_items_range:
	ssdfs_unlock_items_range(node, item_index, forks_count);

finish_insert_range:
	up_read(&node->full_lock);

	return err;
}

/*
 * ssdfs_extents_btree_node_insert_item() - insert item in the node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to insert an item in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't free items.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_extents_btree_node_insert_item(struct ssdfs_btree_node *node,
					 struct ssdfs_btree_search *search)
{
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	if (search->result.state != SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND) {
		SSDFS_ERR("invalid result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err == -ENODATA) {
		search->result.err = 0;
		/*
		 * Node doesn't contain an item.
		 */
	} else if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count != 1);
	BUG_ON(!search->result.buf);
	BUG_ON(search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = __ssdfs_extents_btree_node_insert_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert range: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_extents_btree_node_insert_range() - insert range of items
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to insert a range of items in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't free items.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_extents_btree_node_insert_range(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search)
{
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	if (search->result.state != SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND) {
		SSDFS_ERR("invalid result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err == -ENODATA) {
		search->result.err = 0;
		/*
		 * Node doesn't contain an item.
		 */
	} else if (search->result.err) {
		SSDFS_WARN("invalid serach result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count <= 1);
	BUG_ON(!search->result.buf);
	BUG_ON(search->result.buf_state != SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = __ssdfs_extents_btree_node_insert_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert range: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_change_item_only() - change fork in the node
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @search: pointer on search request object
 *
 * This method tries to change an item in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_change_item_only(struct ssdfs_btree_node *node,
			   struct ssdfs_btree_node_items_area *area,
			   struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_fork fork;
	size_t item_size = sizeof(struct ssdfs_raw_fork);
	struct ssdfs_extents_btree_node_header *hdr;
	u16 item_index;
	u16 range_len;
	u64 start_hash, end_hash;
	u64 old_blks_count, blks_count, diff_blks_count;
	u32 old_valid_extents, valid_extents, diff_valid_extents;
	u32 old_max_extent_blks, max_extent_blks;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	range_len = search->request.count;

	if (range_len == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty range\n");
		return err;
	}

	item_index = search->result.start_index;
	if ((item_index + range_len) > area->items_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid request: "
			  "item_index %u, range_len %u, items_count %u\n",
			  item_index, range_len,
			  area->items_count);
		return err;
	}

	err = ssdfs_calculate_range_blocks_in_node(node, area,
						   item_index, range_len,
						   &old_valid_extents,
						   &old_blks_count,
						   &old_max_extent_blks);
	if (unlikely(err)) {
		SSDFS_ERR("fail to calculate range's blocks: "
			  "node_id %u, item_index %u, range_len %u\n",
			  node->node_id, item_index, range_len);
		return err;
	}

	err = ssdfs_generic_insert_range(node, area,
					 item_size, search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to insert range: err %d\n",
			  err);
		return err;
	}

	down_write(&node->header_lock);

	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;

	if (item_index == 0) {
		err = ssdfs_extents_btree_node_get_fork(node,
							&node->items_area,
							item_index, &fork);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get fork: err %d\n", err);
			goto finish_items_area_correction;
		}
		start_hash = le64_to_cpu(fork.start_offset);
	}

	if ((item_index + range_len) == node->items_area.items_count) {
		err = ssdfs_extents_btree_node_get_fork(node,
						&node->items_area,
						item_index + range_len - 1,
						&fork);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get fork: err %d\n", err);
			goto finish_items_area_correction;
		}
		end_hash = le64_to_cpu(fork.start_offset);
	} else if ((item_index + range_len) > node->items_area.items_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid range_len: "
			  "item_index %u, range_len %u, items_count %u\n",
			  item_index, range_len,
			  node->items_area.items_count);
		goto finish_items_area_correction;
	}

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	err = ssdfs_correct_lookup_table(node, &node->items_area,
					 item_index, range_len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

	err = ssdfs_calculate_range_blocks(search, &valid_extents,
					   &blks_count, &max_extent_blks);
	if (unlikely(err)) {
		SSDFS_ERR("fail to calculate range blocks: err %d\n",
			  err);
		goto finish_items_area_correction;
	}

	hdr = &node->raw.extents_header;

	if (old_valid_extents < valid_extents) {
		diff_valid_extents = valid_extents - old_valid_extents;
		valid_extents = le32_to_cpu(hdr->valid_extents);

		if (valid_extents >= (U32_MAX - diff_valid_extents)) {
			err = -ERANGE;
			SSDFS_ERR("valid_extents %u, diff_valid_extents %u\n",
				  valid_extents, diff_valid_extents);
			goto finish_items_area_correction;
		}

		valid_extents += diff_valid_extents;
		hdr->valid_extents = cpu_to_le32(valid_extents);
	} else if (old_valid_extents > valid_extents) {
		diff_valid_extents = old_valid_extents - valid_extents;
		valid_extents = le32_to_cpu(hdr->valid_extents);

		if (valid_extents < diff_valid_extents) {
			err = -ERANGE;
			SSDFS_ERR("valid_extents %u < diff_valid_extents %u\n",
				  valid_extents, diff_valid_extents);
			goto finish_items_area_correction;
		}

		valid_extents -= diff_valid_extents;
		hdr->valid_extents = cpu_to_le32(valid_extents);
	}

	if (old_blks_count < blks_count) {
		diff_blks_count = blks_count - old_blks_count;
		blks_count = le64_to_cpu(hdr->blks_count);

		if (blks_count >= (U64_MAX - diff_blks_count)) {
			err = -ERANGE;
			SSDFS_ERR("blks_count %llu, diff_blks_count %llu\n",
				  blks_count, diff_blks_count);
			goto finish_items_area_correction;
		}

		blks_count += diff_blks_count;
		hdr->blks_count = cpu_to_le64(blks_count);
	} else if (old_blks_count > blks_count) {
		diff_blks_count = old_blks_count - blks_count;
		blks_count = le32_to_cpu(hdr->blks_count);

		if (blks_count < diff_blks_count) {
			err = -ERANGE;
			SSDFS_ERR("blks_count %llu < diff_blks_count %llu\n",
				  blks_count, diff_blks_count);
			goto finish_items_area_correction;
		}

		blks_count -= diff_blks_count;
		hdr->blks_count = cpu_to_le64(blks_count);
	}

	if (le32_to_cpu(hdr->max_extent_blks) < max_extent_blks)
		hdr->max_extent_blks = cpu_to_le32(max_extent_blks);

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

	return err;
}

/*
 * ssdfs_invalidate_forks_range() - invalidate range of forks
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @start_index: starting index of the fork
 * @range_len: number of forks in the range
 *
 * This method tries to add the range of forks into
 * pre-invalid queue of the shared extents tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_invalidate_forks_range(struct ssdfs_btree_node *node,
				 struct ssdfs_btree_node_items_area *area,
				 u16 start_index, u16 range_len)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shared_extents_tree *shextree;
	struct ssdfs_raw_fork fork;
	u64 ino;
	u16 cur_index;
	u16 i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);

	fsi = node->tree->fsi;
	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	ino = node->tree->owner_ino;

	if ((start_index + range_len) >= area->items_count) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, range_len %u\n",
			  start_index, range_len);
		return -ERANGE;
	}

	for (i = 0; i < range_len; i++) {
		cur_index = start_index + i;

		err = ssdfs_extents_btree_node_get_fork(node, area,
							cur_index,
							&fork);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get fork: "
				  "cur_index %u, err %d\n",
				  cur_index, err);
			return err;
		}

		err = ssdfs_shextree_add_pre_invalid_fork(shextree, ino, &fork);
		if (unlikely(err)) {
			SSDFS_ERR("fail to make the fork pre-invalid: "
				  "cur_index %u, err %d\n",
				  cur_index, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_define_first_invalid_index() - find the first index for hash
 * @node: pointer on node object
 * @hash: searching hash
 * @start_index: found index [out]
 *
 * The method tries to find the index for the hash.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to find an index.
 */
static
int ssdfs_define_first_invalid_index(struct ssdfs_btree_node *node,
				     u64 hash, u16 *start_index)
{
	bool node_locked_outside = false;
	struct ssdfs_btree_node_index_area area;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, hash %llx\n",
		  node->node_id, hash);

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
		SSDFS_ERR("index area is absent\n");
		return -ERANGE;
	}

	node_locked_outside = rwsem_is_locked(&node->full_lock);

	if (!node_locked_outside) {
		/* lock node locally */
		down_read(&node->full_lock);
	}

	down_read(&node->header_lock);
	memcpy(&area, &node->index_area,
		sizeof(struct ssdfs_btree_node_index_area));
	up_read(&node->header_lock);

	err = ssdfs_find_index_by_hash(node, &area, hash,
					start_index);
	if (err == -ENODATA) {
		err = -EAGAIN;
		SSDFS_DBG("unable to find an index: "
			  "node_id %u, hash %llx\n",
			  node->node_id, hash);
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find an index: "
			  "node_id %u, hash %llx, err %d\n",
			  node->node_id, hash, err);
	}

	if (!node_locked_outside) {
		/* unlock node locally */
		up_read(&node->full_lock);
	}

	return err;
}

/*
 * ssdfs_invalidate_index_tail() - invalidate the tail of index sequence
 * @node: pointer on node object
 * @start_index: starting index
 *
 * The method tries to invalidate the tail of index sequence.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_invalidate_index_tail(struct ssdfs_btree_node *node,
				u16 start_index)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shared_extents_tree *shextree;
	struct ssdfs_btree *tree;
	bool node_locked_outside = false;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_btree_node_index_area index_area;
	struct ssdfs_btree_index_key index;
	int node_type;
	int index_type = SSDFS_EXTENT_INFO_UNKNOWN_TYPE;
	u64 ino;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u\n",
		  node->node_id, start_index);

	fsi = node->tree->fsi;
	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	ino = node->tree->owner_ino;

	tree = node->tree;
	switch (tree->type) {
	case SSDFS_EXTENTS_BTREE:
		index_type = SSDFS_EXTENT_INFO_INDEX_DESCRIPTOR;
		break;

	case SSDFS_DENTRIES_BTREE:
		index_type = SSDFS_EXTENT_INFO_DENTRY_INDEX_DESCRIPTOR;
		break;

	default:
		SSDFS_ERR("unsupported tree type %#x\n",
			  tree->type);
		return -ERANGE;
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
		SSDFS_ERR("index area is absent\n");
		return -ERANGE;
	}

	if (!node_locked_outside) {
		/* lock node locally */
		down_write(&node->full_lock);
	}

	down_read(&node->header_lock);
	memcpy(&items_area, &node->items_area,
		sizeof(struct ssdfs_btree_node_items_area));
	memcpy(&index_area, &node->index_area,
		sizeof(struct ssdfs_btree_node_index_area));
	up_read(&node->header_lock);

	if (is_ssdfs_btree_node_items_area_exist(node)) {
		err = ssdfs_invalidate_forks_range(node, &items_area,
						   0, items_area.items_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate forks range: "
				  "node_id %u, range (start %u, count %u), "
				  "err %d\n",
				  node->node_id, 0, items_area.items_count,
				  err);
			goto finish_invalidate_index_tail;
		}
	}

	err = ssdfs_lock_whole_index_area(node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock source's index area: err %d\n",
			  err);
		goto finish_invalidate_index_tail;
	}

	if (start_index >= index_area.index_count) {
		err = -ERANGE;
		SSDFS_ERR("start_index %u >= index_count %u\n",
			  start_index, index_area.index_count);
		goto finish_process_index_area;
	}

	node_type = atomic_read(&node->type);

	for (i = start_index; i < index_area.index_count; i++) {
		if (node_type == SSDFS_BTREE_ROOT_NODE) {
			err = __ssdfs_btree_root_node_extract_index(node,
								    (u16)i,
								    &index);
		} else {
			err = ssdfs_btree_node_get_index(&node->content.pvec,
							 index_area.offset,
							 index_area.area_size,
							 node->node_size,
							 (u16)i, &index);
		}

		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to extract index: "
				  "node_id %u, index %d, err %d\n",
				  node->node_id, i, err);
			goto finish_process_index_area;
		}

		err = ssdfs_shextree_add_pre_invalid_index(shextree,
							   ino,
							   index_type,
							   &index);
		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to pre-invalid index: "
				  "index_id %d, err %d\n",
				  i, err);
			goto finish_process_index_area;
		}
	}

	down_write(&node->header_lock);

	for (i = index_area.index_count - 1; i >= start_index; i--) {
		if (node_type == SSDFS_BTREE_ROOT_NODE) {
			err = ssdfs_btree_root_node_delete_index(node,
								 (u16)i);
		} else {
			err = ssdfs_btree_common_node_delete_index(node,
								   (u16)i);
		}

		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to delete index: "
				  "node_id %u, index %d, err %d\n",
				  node->node_id, i, err);
			goto finish_index_deletion;
		}
	}

finish_index_deletion:
	down_write(&node->header_lock);

finish_process_index_area:
	ssdfs_unlock_whole_index_area(node);

finish_invalidate_index_tail:
	if (!node_locked_outside) {
		/* unlock node locally */
		up_write(&node->full_lock);
	}

	return err;
}

/*
 * __ssdfs_invalidate_items_area() - invalidate the items area
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @start_index: starting index of the fork
 * @range_len: number of forks in the range
 * @search: pointer on search request object
 *
 * The method tries to invalidate the items area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_invalidate_items_area(struct ssdfs_btree_node *node,
				  struct ssdfs_btree_node_items_area *area,
				  u16 start_index, u16 range_len,
				  struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *parent = NULL, *found = NULL;
	struct ssdfs_extents_btree_node_header *hdr;
	size_t item_size = sizeof(struct ssdfs_raw_fork);
	bool is_hybrid = false;
	bool has_index_area = false;
	bool index_area_empty = false;
	int parent_type = SSDFS_BTREE_LEAF_NODE;
	u64 hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);

	if (((u32)start_index + range_len) > area->items_count) {
		SSDFS_ERR("start_index %u, range_len %u, items_count %u\n",
			  start_index, range_len,
			  area->items_count);
		return -ERANGE;
	}

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		is_hybrid = true;
		break;

	case SSDFS_BTREE_LEAF_NODE:
		is_hybrid = false;
		break;

	default:
		SSDFS_WARN("invalid node type %#x\n",
			   atomic_read(&node->type));
		return -ERANGE;
	}

	err = ssdfs_invalidate_forks_range(node, area,
					   start_index, range_len);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to invalidate range of forks: "
			  "node_id %u, start_index %u, "
			  "range_len %u, err %d\n",
			  node->node_id, start_index,
			  range_len, err);
		return err;
	}

	down_write(&node->header_lock);

	hdr = &node->raw.extents_header;
	if (node->items_area.items_count == range_len) {
		node->items_area.items_count =
			node->items_area.items_count - range_len;
		node->items_area.free_space =
			node->items_area.area_size -
				(node->items_area.items_count * item_size);
		node->items_area.start_hash = U64_MAX;
		node->items_area.end_hash = U64_MAX;
		ssdfs_initialize_lookup_table(node);
		hdr->forks_count = cpu_to_le32(0);
		hdr->allocated_extents = cpu_to_le32(0);
		hdr->valid_extents = cpu_to_le32(0);
		hdr->blks_count = cpu_to_le64(0);
		hdr->max_extent_blks = cpu_to_le32(0);
	}

	switch (atomic_read(&node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		has_index_area = true;
		if (node->index_area.index_count == 0)
			index_area_empty = true;
		else
			index_area_empty = false;
		break;

	default:
		has_index_area = false;
		index_area_empty = false;
		break;
	}

	up_write(&node->header_lock);

	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		return err;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
		if (is_hybrid && has_index_area && !index_area_empty) {
			search->result.state =
				SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;
		} else {
			search->result.state =
				SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_ALL:
		search->result.state =
			SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;

		parent = node;

		do {
			parent = parent->parent_node;

			if (!parent) {
				SSDFS_ERR("node %u hasn't parent\n",
					  node->node_id);
				return -ERANGE;
			}

			parent_type = atomic_read(&parent->type);
			switch (parent_type) {
			case SSDFS_BTREE_ROOT_NODE:
			case SSDFS_BTREE_INDEX_NODE:
			case SSDFS_BTREE_HYBRID_NODE:
				/* expected state */
				break;

			default:
				SSDFS_ERR("invalid parent node's type %#x\n",
					  parent_type);
				return -ERANGE;
			}
		} while (parent_type != SSDFS_BTREE_ROOT_NODE);

		err = ssdfs_invalidate_root_node_hierarchy(parent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate root node hierarchy: "
				  "err %d\n", err);
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
		search->result.state =
			SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;

		hash = search->request.start.hash;

		switch (atomic_read(&node->index_area.state)) {
		case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
			err = ssdfs_define_first_invalid_index(node, hash,
								&start_index);
			if (err == -EAGAIN) {
				err = 0;
				/* continue to search */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to define first index: "
					  "err %d\n", err);
				return err;
			} else if (start_index >= U16_MAX) {
				SSDFS_ERR("invalid start index\n");
				return -ERANGE;
			} else {
				found = node;
				goto try_invalidate_tail;
			}
			break;

		case SSDFS_BTREE_NODE_AREA_ABSENT:
			/* need to check the parent */
			break;

		default:
			SSDFS_ERR("invalid index area: "
				  "node_id %u, state %#x\n",
				  node->node_id,
				  atomic_read(&node->index_area.state));
			return -ERANGE;
		}

		parent = node;

		do {
			parent = parent->parent_node;

			if (!parent) {
				SSDFS_ERR("node %u hasn't parent\n",
					  node->node_id);
				return -ERANGE;
			}

			parent_type = atomic_read(&parent->type);
			switch (parent_type) {
			case SSDFS_BTREE_ROOT_NODE:
			case SSDFS_BTREE_INDEX_NODE:
			case SSDFS_BTREE_HYBRID_NODE:
				/* expected state */
				break;

			default:
				SSDFS_ERR("invalid parent node's type %#x\n",
					  parent_type);
				return -ERANGE;
			}

			switch (atomic_read(&parent->index_area.state)) {
			case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
				err = ssdfs_define_first_invalid_index(parent,
								hash,
								&start_index);
				if (err == -EAGAIN) {
					err = 0;
					/* continue to search */
				} else if (unlikely(err)) {
					SSDFS_ERR("fail to define first index: "
						  "err %d\n", err);
					return err;
				} else if (start_index >= U16_MAX) {
					SSDFS_ERR("invalid start index\n");
					return -ERANGE;
				} else {
					found = parent;
					goto try_invalidate_tail;
				}
				break;

			default:
				SSDFS_ERR("index area is absent: "
					  "node_id %u, height %d\n",
					  parent->node_id,
					  atomic_read(&parent->height));
				return -ERANGE;
			}
		} while (parent_type != SSDFS_BTREE_ROOT_NODE);

		if (found == NULL) {
			SSDFS_ERR("fail to find start index\n");
			return -ERANGE;
		}

try_invalidate_tail:
		err = ssdfs_invalidate_index_tail(found, start_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate the index tail: "
				  "node_id %u, start_index %u, err %d\n",
				  found->node_id, start_index, err);
			return err;
		}
		break;

	default:
		atomic_set(&node->state,
			   SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_invalidate_whole_items_area() - invalidate the whole items area
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @search: pointer on search request object
 *
 * The method tries to invalidate the items area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_invalidate_whole_items_area(struct ssdfs_btree_node *node,
				      struct ssdfs_btree_node_items_area *area,
				      struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, area %p, search %p\n",
		  node->node_id, area, search);

	return __ssdfs_invalidate_items_area(node, area,
					     0, area->items_count,
					     search);
}

/*
 * ssdfs_invalidate_items_area_partially() - invalidate the items area
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @start_index: starting index of the fork
 * @range_len: number of forks in the range
 * @search: pointer on search request object
 *
 * The method tries to invalidate the items area partially.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_invalidate_items_area_partially(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_items_area *area,
				    u16 start_index, u16 range_len,
				    struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);

	return __ssdfs_invalidate_items_area(node, area,
					     start_index, range_len,
					     search);
}

/*
 * ssdfs_change_item_and_invalidate_tail() - change fork and invalidate tail
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @search: pointer on search request object
 *
 * This method tries to change an item in the node and invalidate
 * the tail forks sequence.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_change_item_and_invalidate_tail(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_items_area *area,
				    struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_fork fork;
	size_t item_size = sizeof(struct ssdfs_raw_fork);
	struct ssdfs_extents_btree_node_header *hdr;
	u16 item_index;
	u16 range_len;
	u64 start_hash, end_hash;
	u64 old_blks_count, blks_count, diff_blks_count;
	u32 old_valid_extents, valid_extents, diff_valid_extents;
	u32 old_max_extent_blks, max_extent_blks;
	u16 invalidate_index, invalidate_range;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	range_len = search->request.count;

	if (range_len == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty range\n");
		return err;
	}

	item_index = search->result.start_index;
	if ((item_index + range_len) > area->items_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid request: "
			  "item_index %u, range_len %u, items_count %u\n",
			  item_index, range_len,
			  area->items_count);
		return err;
	}

	err = ssdfs_calculate_range_blocks_in_node(node, area,
						   item_index, range_len,
						   &old_valid_extents,
						   &old_blks_count,
						   &old_max_extent_blks);
	if (unlikely(err)) {
		SSDFS_ERR("fail to calculate range's blocks: "
			  "node_id %u, item_index %u, range_len %u\n",
			  node->node_id, item_index, range_len);
		return err;
	}

	err = ssdfs_generic_insert_range(node, area,
					 item_size, search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to insert range: err %d\n",
			  err);
		return err;
	}

	invalidate_index = item_index + range_len;
	invalidate_range = area->items_count - invalidate_index;

	err = ssdfs_invalidate_items_area_partially(node, area,
						    invalidate_index,
						    invalidate_range,
						    search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to invalidate items range: err %d\n",
			  err);
		return err;
	}

	down_write(&node->header_lock);

	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;

	err = ssdfs_extents_btree_node_get_fork(node,
						&node->items_area,
						item_index,
						&fork);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get fork: err %d\n", err);
		goto finish_items_area_correction;
	}

	if (item_index == 0)
		start_hash = le64_to_cpu(fork.start_offset);

	end_hash = le64_to_cpu(fork.start_offset);

	err = ssdfs_correct_lookup_table(node, &node->items_area,
					 item_index, range_len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

	err = ssdfs_calculate_range_blocks(search, &valid_extents,
					   &blks_count, &max_extent_blks);
	if (unlikely(err)) {
		SSDFS_ERR("fail to calculate range blocks: err %d\n",
			  err);
		goto finish_items_area_correction;
	}

	hdr = &node->raw.extents_header;

	if (old_valid_extents < valid_extents) {
		diff_valid_extents = valid_extents - old_valid_extents;
		valid_extents = le32_to_cpu(hdr->valid_extents);

		if (valid_extents >= (U32_MAX - diff_valid_extents)) {
			err = -ERANGE;
			SSDFS_ERR("valid_extents %u, diff_valid_extents %u\n",
				  valid_extents, diff_valid_extents);
			goto finish_items_area_correction;
		}

		valid_extents += diff_valid_extents;
		hdr->valid_extents = cpu_to_le32(valid_extents);
	} else if (old_valid_extents > valid_extents) {
		diff_valid_extents = old_valid_extents - valid_extents;
		valid_extents = le32_to_cpu(hdr->valid_extents);

		if (valid_extents < diff_valid_extents) {
			err = -ERANGE;
			SSDFS_ERR("valid_extents %u < diff_valid_extents %u\n",
				  valid_extents, diff_valid_extents);
			goto finish_items_area_correction;
		}

		valid_extents -= diff_valid_extents;
		hdr->valid_extents = cpu_to_le32(valid_extents);
	}

	if (old_blks_count < blks_count) {
		diff_blks_count = blks_count - old_blks_count;
		blks_count = le64_to_cpu(hdr->blks_count);

		if (blks_count >= (U64_MAX - diff_blks_count)) {
			err = -ERANGE;
			SSDFS_ERR("blks_count %llu, diff_blks_count %llu\n",
				  blks_count, diff_blks_count);
			goto finish_items_area_correction;
		}

		blks_count += diff_blks_count;
		hdr->blks_count = cpu_to_le64(blks_count);
	} else if (old_blks_count > blks_count) {
		diff_blks_count = old_blks_count - blks_count;
		blks_count = le32_to_cpu(hdr->blks_count);

		if (blks_count < diff_blks_count) {
			err = -ERANGE;
			SSDFS_ERR("blks_count %llu < diff_blks_count %llu\n",
				  blks_count, diff_blks_count);
			goto finish_items_area_correction;
		}

		blks_count -= diff_blks_count;
		hdr->blks_count = cpu_to_le64(blks_count);
	}

	if (le32_to_cpu(hdr->max_extent_blks) < max_extent_blks)
		hdr->max_extent_blks = cpu_to_le32(max_extent_blks);

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

	return err;
}

/*
 * ssdfs_extents_btree_node_change_item() - change item in the node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to change an item in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_extents_btree_node_change_item(struct ssdfs_btree_node *node,
					 struct ssdfs_btree_search *search)
{
	size_t item_size = sizeof(struct ssdfs_raw_fork);
	struct ssdfs_btree_node_items_area items_area;
	u16 item_index;
	int direction;
	u16 range_len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		SSDFS_ERR("invalid result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count != 1);
	BUG_ON(!search->result.buf);
	BUG_ON(search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER);
	BUG_ON(search->result.items_in_buffer != 1);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid items_area state %#x\n",
			  atomic_read(&node->items_area.state));
		return -ERANGE;
	}

	down_read(&node->header_lock);
	memcpy(&items_area, &node->items_area,
		sizeof(struct ssdfs_btree_node_items_area));
	up_read(&node->header_lock);

	if (items_area.items_capacity == 0 ||
	    items_area.items_capacity < items_area.items_count) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid items accounting: "
			  "node_id %u, items_capacity %u, items_count %u\n",
			  node->node_id, items_area.items_capacity,
			  items_area.items_count);
		return -EFAULT;
	}

	if (items_area.min_item_size != item_size ||
	    items_area.max_item_size != item_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("min_item_size %u, max_item_size %u, "
			  "item_size %zu\n",
			  items_area.min_item_size, items_area.max_item_size,
			  item_size);
		return -EFAULT;
	}

	if (items_area.area_size == 0 ||
	    items_area.area_size >= node->node_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid area_size %u\n",
			  items_area.area_size);
		return -EFAULT;
	}

	down_write(&node->full_lock);

	direction = is_requested_position_correct(node, &items_area,
						  search);
	switch (direction) {
	case SSDFS_CORRECT_POSITION:
		/* do nothing */
		break;

	case SSDFS_SEARCH_LEFT_DIRECTION:
		err = ssdfs_find_correct_position_from_left(node, &items_area,
							    search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_define_changing_items;
		}
		break;

	case SSDFS_SEARCH_RIGHT_DIRECTION:
		err = ssdfs_find_correct_position_from_right(node, &items_area,
							     search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_define_changing_items;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("fail to check requested position\n");
		goto finish_define_changing_items;
	}

	range_len = search->request.count;

	if (range_len == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty range\n");
		goto finish_define_changing_items;
	}

	item_index = search->result.start_index;
	if ((item_index + range_len) > items_area.items_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid request: "
			  "item_index %u, range_len %u, items_count %u\n",
			  item_index, range_len,
			  items_area.items_count);
		goto finish_define_changing_items;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
		/* range_len doesn't need to be changed */
		break;

	case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
		range_len = items_area.items_count - item_index;
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid request type: %#x\n",
			  search->request.type);
		goto finish_define_changing_items;
	}

	err = ssdfs_lock_items_range(node, item_index, range_len);
	if (err == -ENOENT) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (err == -ENODATA) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (unlikely(err))
		BUG();

finish_define_changing_items:
	downgrade_write(&node->full_lock);

	if (unlikely(err))
		goto finish_change_item;

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
		err = ssdfs_change_item_only(node, &items_area, search);
		break;

	case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
		err = ssdfs_change_item_and_invalidate_tail(node, &items_area,
							    search);
		break;

	default:
		BUG();
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to change item: err %d\n",
			  err);
		goto unlock_items_range;
	}

	err = ssdfs_set_node_header_dirty(node, items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto unlock_items_range;
	}

	err = ssdfs_set_dirty_items_range(node, items_area.items_capacity,
					  item_index, range_len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  item_index, range_len, err);
		goto unlock_items_range;
	}

unlock_items_range:
	ssdfs_unlock_items_range(node, item_index, range_len);

finish_change_item:
	up_read(&node->full_lock);

	return err;
}

/*
 * __ssdfs_extents_btree_node_delete_range() - delete range of items
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to delete a range of items in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 * %-EAGAIN     - continue deletion in the next node.
 */
static
int __ssdfs_extents_btree_node_delete_range(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	struct ssdfs_btree *tree;
	struct ssdfs_extents_btree_info *etree;
	struct ssdfs_extents_btree_node_header *hdr;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_raw_fork fork;
	size_t item_size = sizeof(struct ssdfs_raw_fork);
	int free_items;
	u16 item_index;
	int direction;
	u16 range_len;
	u16 locked_len = 0;
	u32 deleted_space, free_space;
	u64 start_hash, end_hash;
	u32 old_forks_count = 0, forks_count = 0;
	u32 forks_diff;
	u32 allocated_extents;
	u32 valid_extents;
	u64 blks_count;
	u32 max_extent_blks;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid result state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid items_area state %#x\n",
			  atomic_read(&node->items_area.state));
		return -ERANGE;
	}

	tree = node->tree;

	switch (tree->type) {
	case SSDFS_EXTENTS_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	etree = container_of(tree, struct ssdfs_extents_btree_info,
			     buffer.tree);

	down_read(&node->header_lock);
	memcpy(&items_area, &node->items_area,
		sizeof(struct ssdfs_btree_node_items_area));
	up_read(&node->header_lock);

	if (items_area.items_capacity == 0 ||
	    items_area.items_capacity < items_area.items_count) {
		SSDFS_ERR("invalid items accounting: "
			  "node_id %u, items_capacity %u, items_count %u\n",
			  search->node.id,
			  items_area.items_capacity,
			  items_area.items_count);
		return -ERANGE;
	}

	if (items_area.min_item_size != item_size ||
	    items_area.max_item_size != item_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("min_item_size %u, max_item_size %u, "
			  "item_size %zu\n",
			  items_area.min_item_size, items_area.max_item_size,
			  item_size);
		return -EFAULT;
	}

	if (items_area.area_size == 0 ||
	    items_area.area_size >= node->node_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid area_size %u\n",
			  items_area.area_size);
		return -EFAULT;
	}

	if (items_area.free_space > items_area.area_size) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("free_space %u > area_size %u\n",
			  items_area.free_space, items_area.area_size);
		return -EFAULT;
	}

	free_items = items_area.items_capacity - items_area.items_count;
	if (unlikely(free_items < 0)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_WARN("invalid free_items %d\n",
			   free_items);
		return -EFAULT;
	}

	if (((u64)free_items * item_size) > items_area.free_space) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid free_items: "
			  "free_items %d, item_size %zu, free_space %u\n",
			  free_items, item_size, items_area.free_space);
		return -EFAULT;
	}

	forks_count = items_area.items_count;
	item_index = search->result.start_index;

	range_len = search->request.count;
	if (range_len == 0) {
		SSDFS_ERR("range_len == 0\n");
		return -ERANGE;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		if ((item_index + range_len) >= items_area.items_count) {
			SSDFS_ERR("invalid request: "
				  "item_index %d, count %u\n",
				  item_index, range_len);
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
	case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
		/* request can be distributed between several nodes */
		break;

	default:
		atomic_set(&node->state,
			   SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -ERANGE;
	}

	down_write(&node->full_lock);

	direction = is_requested_position_correct(node, &items_area,
						  search);
	switch (direction) {
	case SSDFS_CORRECT_POSITION:
		/* do nothing */
		break;

	case SSDFS_SEARCH_LEFT_DIRECTION:
		err = ssdfs_find_correct_position_from_left(node, &items_area,
							    search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_detect_affected_items;
		}
		break;

	case SSDFS_SEARCH_RIGHT_DIRECTION:
		err = ssdfs_find_correct_position_from_right(node, &items_area,
							     search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find the correct position: "
				  "err %d\n",
				  err);
			goto finish_detect_affected_items;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("fail to check requested position\n");
		goto finish_detect_affected_items;
	}

	item_index = search->result.start_index;

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		if ((item_index + range_len) > items_area.items_count) {
			err = -ERANGE;
			SSDFS_ERR("invalid forks_count: "
				  "item_index %u, forks_count %u, "
				  "items_count %u\n",
				  item_index, range_len,
				  items_area.items_count);
			goto finish_detect_affected_items;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
	case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
		/* request can be distributed between several nodes */
		range_len = min_t(unsigned int, range_len,
				  items_area.items_count - item_index);
		SSDFS_DBG("node_id %u, item_index %u, "
			  "request.count %u, items_count %u\n",
			  node->node_id, item_index,
			  search->request.count,
			  items_area.items_count);
		break;

	default:
		BUG();
	}

	locked_len = items_area.items_count - item_index;

	err = ssdfs_lock_items_range(node, item_index, locked_len);
	if (err == -ENOENT) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (err == -ENODATA) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (unlikely(err))
		BUG();

finish_detect_affected_items:
	downgrade_write(&node->full_lock);

	if (unlikely(err))
		goto finish_delete_range;

	if (range_len == items_area.items_count) {
		/* items area is empty */
		err = ssdfs_invalidate_whole_items_area(node, &items_area,
							search);
	} else {
		err = ssdfs_invalidate_items_area_partially(node, &items_area,
							    item_index,
							    range_len,
							    search);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate items area: "
			  "node_id %u, start_index %u, "
			  "range_len %u, err %d\n",
			  node->node_id, item_index,
			  range_len, err);
		goto finish_delete_range;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
		/* continue to shift rest forks to left */
		break;

	case SSDFS_BTREE_SEARCH_DELETE_ALL:
	case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
		err = ssdfs_set_node_header_dirty(node,
						  items_area.items_capacity);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set header dirty: err %d\n",
				  err);
		}
		goto finish_delete_range;

	default:
		BUG();
	}

	err = ssdfs_shift_range_left(node, &items_area, item_size,
				     item_index, range_len,
				     range_len);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to shift forks range: "
			  "start %u, count %u, err %d\n",
			  item_index, search->request.count,
			  err);
		goto finish_delete_range;
	}

	down_write(&node->header_lock);

	if (node->items_area.items_count < search->request.count)
		node->items_area.items_count = 0;
	else
		node->items_area.items_count -= search->request.count;

	deleted_space = (u32)search->request.count * item_size;
	free_space = node->items_area.free_space;
	if ((free_space + deleted_space) > node->items_area.area_size) {
		err = -ERANGE;
		SSDFS_ERR("deleted_space %u, free_space %u, area_size %u\n",
			  deleted_space,
			  node->items_area.free_space,
			  node->items_area.area_size);
		goto finish_items_area_correction;
	}
	node->items_area.free_space += deleted_space;

	if (node->items_area.items_count == 0) {
		start_hash = U64_MAX;
		end_hash = U64_MAX;
	} else {
		err = ssdfs_extents_btree_node_get_fork(node,
							&node->items_area,
							0, &fork);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get fork: err %d\n", err);
			goto finish_items_area_correction;
		}
		start_hash = le64_to_cpu(fork.start_offset);

		err = ssdfs_extents_btree_node_get_fork(node,
					&node->items_area,
					node->items_area.items_count - 1,
					&fork);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get fork: err %d\n", err);
			goto finish_items_area_correction;
		}
		end_hash = le64_to_cpu(fork.start_offset);
	}

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	if (node->items_area.items_count == 0)
		ssdfs_initialize_lookup_table(node);
	else {
		range_len = node->items_area.items_count - item_index;
		err = ssdfs_correct_lookup_table(node,
						 &node->items_area,
						 item_index, range_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct lookup table: "
				  "err %d\n", err);
			goto finish_items_area_correction;
		}
	}

	hdr = &node->raw.extents_header;
	old_forks_count = le32_to_cpu(hdr->forks_count);

	if (node->items_area.items_count == 0) {
		hdr->forks_count = cpu_to_le32(0);
		hdr->allocated_extents = cpu_to_le32(0);
		hdr->valid_extents = cpu_to_le32(0);
		hdr->blks_count = cpu_to_le64(0);
		hdr->max_extent_blks = cpu_to_le32(0);
	} else {
		if (old_forks_count < search->request.count) {
			hdr->forks_count = cpu_to_le32(0);
			hdr->allocated_extents = cpu_to_le32(0);
			hdr->valid_extents = cpu_to_le32(0);
			hdr->blks_count = cpu_to_le64(0);
			hdr->max_extent_blks = cpu_to_le32(0);
		} else {
			forks_count = le32_to_cpu(hdr->forks_count);
			forks_count -= search->request.count;
			hdr->forks_count = cpu_to_le32(forks_count);

			allocated_extents = le32_to_cpu(hdr->allocated_extents);
			allocated_extents -=
				search->request.count *
				SSDFS_INLINE_EXTENTS_COUNT;
			hdr->allocated_extents = cpu_to_le32(allocated_extents);

			err = ssdfs_calculate_range_blocks_in_node(node,
							&node->items_area,
							0, forks_count,
							&valid_extents,
							&blks_count,
							&max_extent_blks);
			if (unlikely(err)) {
				SSDFS_ERR("fail to calculate range's blocks: "
					  "node_id %u, item_index %u, "
					  "range_len %u\n",
					  node->node_id, 0, forks_count);
				goto finish_items_area_correction;
			}

			hdr->valid_extents = cpu_to_le32(valid_extents);
			hdr->blks_count = cpu_to_le64(blks_count);
			hdr->max_extent_blks = cpu_to_le32(max_extent_blks);
		}
	}

	forks_count = le32_to_cpu(hdr->forks_count);
	forks_diff = old_forks_count - forks_count;
	atomic64_sub(forks_diff, &etree->forks_count);

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		goto finish_delete_range;
	}

	err = ssdfs_set_node_header_dirty(node, items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto finish_delete_range;
	}

	if (forks_count != 0) {
		err = ssdfs_set_dirty_items_range(node,
						  items_area.items_capacity,
						  item_index,
						  old_forks_count - item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set items range as dirty: "
				  "start %u, count %u, err %d\n",
				  item_index,
				  old_forks_count - item_index,
				  err);
			goto finish_delete_range;
		}
	}

finish_delete_range:
	ssdfs_unlock_items_range(node, item_index, locked_len);
	up_read(&node->full_lock);

	if (unlikely(err))
		return err;

	if (forks_count == 0)
		search->result.state = SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE;
	else
		search->result.state = SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;

	if (search->request.type == SSDFS_BTREE_SEARCH_DELETE_RANGE) {
		if (search->request.count > range_len) {
			search->request.start.hash = items_area.end_hash;
			search->request.count -= range_len;
			return -EAGAIN;
		}
	}

	return 0;
}

/*
 * ssdfs_extents_btree_node_delete_item() - delete an item from node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to delete an item from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_extents_btree_node_delete_item(struct ssdfs_btree_node *node,
					 struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count != 1);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_extents_btree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete fork: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_extents_btree_node_delete_range() - delete range of items from node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to delete a range of items from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_extents_btree_node_delete_range(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	err = __ssdfs_extents_btree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete forks range: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_extents_btree_node_extract_range() - extract range of items from node
 * @node: pointer on node object
 * @start_index: starting index of the range
 * @count: count of items in the range
 * @search: pointer on search request object
 *
 * This method tries to extract a range of items from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - no such range in the node.
 */
static
int ssdfs_extents_btree_node_extract_range(struct ssdfs_btree_node *node,
					    u16 start_index, u16 count,
					    struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_index %u, count %u, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  start_index, count,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

	return __ssdfs_btree_node_extract_range(node, start_index, count,
						sizeof(struct ssdfs_raw_fork),
						search);
}

/*
 * ssdfs_extents_btree_resize_items_area() - resize items area of the node
 * @node: node object
 * @new_size: new size of the items area
 *
 * This method tries to resize the items area of the node.
 *
 * TODO: It makes sense to allocate the bitmap with taking into
 *       account that we will resize the node. So, it needs
 *       to allocate the index area in bitmap is equal to
 *       the whole node and items area is equal to the whole node.
 *       This technique provides opportunity not to resize or
 *       to shift the content of the bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_extents_btree_resize_items_area(struct ssdfs_btree_node *node,
					  u32 new_size)
{
	struct ssdfs_fs_info *fsi;
	size_t item_size = sizeof(struct ssdfs_raw_fork);
	size_t index_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, new_size %u\n",
		  node->node_id, new_size);

	fsi = node->tree->fsi;
	index_size = le16_to_cpu(fsi->vh->extents_btree.desc.index_size);

	return __ssdfs_btree_node_resize_items_area(node,
						    item_size,
						    index_size,
						    new_size);
}

void ssdfs_debug_extents_btree_object(struct ssdfs_extents_btree_info *tree)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i, j;

	BUG_ON(!tree);

	SSDFS_DBG("EXTENTS TREE: type %#x, state %#x, "
		  "forks_count %llu, is_locked %d, "
		  "generic_tree %p, inline_forks %p, "
		  "root %p, owner %p, fsi %p\n",
		  atomic_read(&tree->type),
		  atomic_read(&tree->state),
		  (u64)atomic64_read(&tree->forks_count),
		  rwsem_is_locked(&tree->lock),
		  tree->generic_tree,
		  tree->inline_forks,
		  tree->root,
		  tree->owner,
		  tree->fsi);

	if (tree->generic_tree) {
		/* debug dump of generic tree */
		ssdfs_debug_btree_object(tree->generic_tree);
	}

	if (tree->inline_forks) {
		for (i = 0; i < SSDFS_INLINE_FORKS_COUNT; i++) {
			struct ssdfs_raw_fork *fork;

			fork = &tree->inline_forks[i];

			SSDFS_DBG("INLINE FORK: index %d, "
				  "start_offset %llu, blks_count %llu\n",
				  i,
				  le64_to_cpu(fork->start_offset),
				  le64_to_cpu(fork->blks_count));

			for (j = 0; j < SSDFS_INLINE_EXTENTS_COUNT; j++) {
				struct ssdfs_raw_extent *extent;

				extent = &fork->extents[j];

				SSDFS_DBG("EXTENT: index %d, "
					  "seg_id %llu, logical_blk %u, "
					  "len %u\n",
					  j,
					  le64_to_cpu(extent->seg_id),
					  le32_to_cpu(extent->logical_blk),
					  le32_to_cpu(extent->len));
			}
		}
	}

	if (tree->root) {
		SSDFS_DBG("ROOT NODE HEADER: height %u, items_count %u, "
			  "flags %#x, type %#x, upper_node_id %u, "
			  "node_ids (left %u, right %u)\n",
			  tree->root->header.height,
			  tree->root->header.items_count,
			  tree->root->header.flags,
			  tree->root->header.type,
			  le32_to_cpu(tree->root->header.upper_node_id),
			  le32_to_cpu(tree->root->header.node_ids[0]),
			  le32_to_cpu(tree->root->header.node_ids[1]));

		for (i = 0; i < SSDFS_BTREE_ROOT_NODE_INDEX_COUNT; i++) {
			struct ssdfs_btree_index *index;

			index = &tree->root->indexes[i];

			SSDFS_DBG("NODE_INDEX: index %d, hash %llx, "
				  "seg_id %llu, logical_blk %u, len %u\n",
				  i,
				  le64_to_cpu(index->hash),
				  le64_to_cpu(index->extent.seg_id),
				  le32_to_cpu(index->extent.logical_blk),
				  le32_to_cpu(index->extent.len));
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */
}

const struct ssdfs_btree_descriptor_operations ssdfs_extents_btree_desc_ops = {
	.init		= ssdfs_extents_btree_desc_init,
	.flush		= ssdfs_extents_btree_desc_flush,
};

const struct ssdfs_btree_operations ssdfs_extents_btree_ops = {
	.create_root_node	= ssdfs_extents_btree_create_root_node,
	.create_node		= ssdfs_extents_btree_create_node,
	.init_node		= ssdfs_extents_btree_init_node,
	.destroy_node		= ssdfs_extents_btree_destroy_node,
	.add_node		= ssdfs_extents_btree_add_node,
	.delete_node		= ssdfs_extents_btree_delete_node,
	.pre_flush_root_node	= ssdfs_extents_btree_pre_flush_root_node,
	.flush_root_node	= ssdfs_extents_btree_flush_root_node,
	.pre_flush_node		= ssdfs_extents_btree_pre_flush_node,
	.flush_node		= ssdfs_extents_btree_flush_node,
};

const struct ssdfs_btree_node_operations ssdfs_extents_btree_node_ops = {
	.find_item		= ssdfs_extents_btree_node_find_item,
	.find_range		= ssdfs_extents_btree_node_find_range,
	.extract_range		= ssdfs_extents_btree_node_extract_range,
	.allocate_item		= ssdfs_extents_btree_node_allocate_item,
	.allocate_range		= ssdfs_extents_btree_node_allocate_range,
	.insert_item		= ssdfs_extents_btree_node_insert_item,
	.insert_range		= ssdfs_extents_btree_node_insert_range,
	.change_item		= ssdfs_extents_btree_node_change_item,
	.delete_item		= ssdfs_extents_btree_node_delete_item,
	.delete_range		= ssdfs_extents_btree_node_delete_range,
	.resize_items_area	= ssdfs_extents_btree_resize_items_area,
};
