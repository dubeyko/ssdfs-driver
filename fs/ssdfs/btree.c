//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/btree.c - generalized btree functionality implementation.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "request_queue.h"
#include "segment_bitmap.h"
#include "page_array.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree_hierarchy.h"
#include "btree.h"

/*
 * ssdfs_btree_radix_tree_insert() - insert node into the radix tree
 * @tree: btree pointer
 * @node_id: node ID number
 * @node: pointer on btree node
 */
static
int ssdfs_btree_radix_tree_insert(struct ssdfs_btree *tree,
				  unsigned long node_id,
				  struct ssdfs_btree_node *node)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, node_id %llu, node %p\n",
		  tree, (u64)node_id, node);

	err = radix_tree_preload(GFP_NOFS);
	if (unlikely(err)) {
		SSDFS_ERR("fail to preload radix tree: err %d\n",
			  err);
		return err;
	}

	spin_lock(&tree->nodes_lock);
	err = radix_tree_insert(&tree->nodes, node_id, node);
	spin_unlock(&tree->nodes_lock);

	radix_tree_preload_end();

	if (unlikely(err)) {
		SSDFS_ERR("fail to add node into radix tree: "
			  "node_id %llu, node %p, err %d\n",
			  (u64)node_id, node, err);
	}

	return err;
}

/*
 * ssdfs_btree_radix_tree_delete() - delete node from the radix tree
 * @tree: btree pointer
 * @node_id: node ID number
 *
 * This method tries to delete the node from the radix tree.
 *
 * RETURN:
 * pointer of the node object is deleted from the radix tree
 */
static
struct ssdfs_btree_node *ssdfs_btree_radix_tree_delete(struct ssdfs_btree *tree,
							unsigned long node_id)
{
	struct ssdfs_btree_node *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, node_id %llu\n",
		  tree, (u64)node_id);

	spin_lock(&tree->nodes_lock);
	ptr = radix_tree_delete(&tree->nodes, node_id);
	spin_unlock(&tree->nodes_lock);

	return ptr;
}

/*
 * ssdfs_btree_radix_tree_find() - find the node into the radix tree
 * @tree: btree pointer
 * @node_id: node ID number
 * @node: pointer on btree node pointer [out]
 *
 * This method tries to find node in the radix tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOENT     - tree doesn't contain the requested node.
 */
int ssdfs_btree_radix_tree_find(struct ssdfs_btree *tree,
				unsigned long node_id,
				struct ssdfs_btree_node **node)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, node_id %llu\n",
		  tree, (u64)node_id);

	spin_lock(&tree->nodes_lock);
	*node = radix_tree_lookup(&tree->nodes, node_id);
	spin_unlock(&tree->nodes_lock);

	if (!*node) {
		SSDFS_DBG("unable to find the node: id %llu\n",
			  (u64)node_id);
		return -ENOENT;
	}

	return 0;
}

static
int __ssdfs_btree_find_item(struct ssdfs_btree *tree,
			    struct ssdfs_btree_search *search);

/*
 * ssdfs_btree_desc_init() - init the btree's descriptor
 * @fsi: pointer on shared file system object
 * @tree: pointer on inodes btree object
 * @desc: pointer on btree's descriptor
 * @min_item_size: minimal possible item size
 * @max_item_size: maximal possible item size
 */
int ssdfs_btree_desc_init(struct ssdfs_fs_info *fsi,
			  struct ssdfs_btree *tree,
			  struct ssdfs_btree_descriptor *desc,
			  u8 min_item_size,
			  u16 max_item_size)
{
	u32 pagesize;
	u32 node_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, desc %p\n",
		  tree, desc);

	pagesize = fsi->pagesize;
	node_size = 1 << desc->log_node_size;

	if (node_size != (pagesize * desc->pages_per_node)) {
		SSDFS_ERR("invalid pages_per_node: "
			  "node_size %u, page_size %u, pages_per_node %u\n",
			  node_size, pagesize, desc->pages_per_node);
		return -EIO;
	}

	if (desc->node_ptr_size != sizeof(struct ssdfs_btree_index_key)) {
		SSDFS_ERR("invalid node_ptr_size %u\n",
			  desc->node_ptr_size);
		return -EIO;
	}

	if (le16_to_cpu(desc->index_size) != sizeof(struct ssdfs_btree_index)) {
		SSDFS_ERR("invalid index_size %u\n",
			  le16_to_cpu(desc->index_size));
		return -EIO;
	}

	tree->type = desc->type;
	atomic_set(&tree->flags, le16_to_cpu(desc->flags));
	tree->node_size = node_size;
	tree->pages_per_node = desc->pages_per_node;
	tree->node_ptr_size = desc->node_ptr_size;
	tree->index_size = le16_to_cpu(desc->index_size);
	tree->item_size = le16_to_cpu(desc->item_size);
	tree->min_item_size = min_item_size;
	tree->max_item_size = max_item_size;
	tree->index_area_min_size = le16_to_cpu(desc->index_area_min_size);

	SSDFS_DBG("type %#x, node_size %u, "
		  "index_size %u, item_size %u\n",
		  tree->type, tree->node_size,
		  tree->index_size, tree->item_size);

	return 0;
}

/*
 * ssdfs_btree_create() - create generalized btree object
 * @fsi: pointer on shared file system object
 * @desc_ops: pointer on btree descriptor operations
 * @btree_ops: pointer on btree operations
 * @tree: pointer on memory for btree creation
 *
 * This method tries to create inodes btree object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_create(struct ssdfs_fs_info *fsi,
		    u64 owner_ino,
		    const struct ssdfs_btree_descriptor_operations *desc_ops,
		    const struct ssdfs_btree_operations *btree_ops,
		    struct ssdfs_btree *tree)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !desc_ops || !tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, owner_ino %llu, "
		  "desc_ops %p, btree_ops %p, tree %p\n",
		  fsi, owner_ino, desc_ops, btree_ops, tree);

	atomic_set(&tree->state, SSDFS_BTREE_UNKNOWN_STATE);

	tree->owner_ino = owner_ino;

	tree->fsi = fsi;
	tree->desc_ops = desc_ops;
	tree->btree_ops = btree_ops;

	if (!desc_ops->init) {
		SSDFS_ERR("empty btree descriptor init operation\n");
		return -ERANGE;
	}

	err = desc_ops->init(fsi, tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init btree descriptor: err %d\n",
			  err);
		return err;
	}

	atomic_set(&tree->height, U8_MAX);

	init_rwsem(&tree->lock);
	spin_lock_init(&tree->nodes_lock);
	tree->upper_node_id = SSDFS_BTREE_ROOT_NODE_ID;
	INIT_RADIX_TREE(&tree->nodes, GFP_ATOMIC);

	if (!btree_ops && !btree_ops->create_root_node)
		SSDFS_WARN("empty create_root_node method\n");
	else {
		struct ssdfs_btree_node *node;

		node = ssdfs_btree_node_create(tree,
						SSDFS_BTREE_ROOT_NODE_ID,
						NULL,
						SSDFS_BTREE_LEAF_NODE_HEIGHT,
						SSDFS_BTREE_ROOT_NODE,
						U64_MAX);
		if (unlikely(IS_ERR_OR_NULL(node))) {
			err = !node ? -ENOMEM : PTR_ERR(node);
			SSDFS_ERR("fail to create root node: err %d\n",
				  err);
			return err;
		}

		err = btree_ops->create_root_node(fsi, node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init the root node\n");
			goto finish_root_node_creation;
		}

		err = ssdfs_btree_radix_tree_insert(tree,
						    SSDFS_BTREE_ROOT_NODE_ID,
						    node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert node into radix tree: "
				  "err %d\n",
				  err);
			goto finish_root_node_creation;
		}

finish_root_node_creation:
		if (unlikely(err)) {
			ssdfs_btree_node_destroy(node);
			return err;
		}
	}

	atomic_set(&tree->state, SSDFS_BTREE_CREATED);
	return 0;
}

/*
 * ssdfs_btree_destroy() - destroy generalized btree object
 * @tree: btree object
 */
void ssdfs_btree_destroy(struct ssdfs_btree *tree)
{
	int tree_state;
	struct radix_tree_iter iter;
	void **slot;
	struct ssdfs_btree_node *node;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x\n",
		  tree, tree->type, tree_state);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
		/* expected state */
		break;

	case SSDFS_BTREE_DIRTY:
		SSDFS_WARN("tree is dirty\n");
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return;
	}

	if (rwsem_is_locked(&tree->lock)) {
		/* inform about possible trouble */
		SSDFS_WARN("tree is locked under destruction\n");
	}

	spin_lock(&tree->nodes_lock);
	radix_tree_for_each_slot(slot, &tree->nodes, &iter,
				 SSDFS_BTREE_ROOT_NODE_ID) {
		node =
		    (struct ssdfs_btree_node *)radix_tree_delete(&tree->nodes,
								 iter.index);

		spin_unlock(&tree->nodes_lock);
		if (!node) {
			SSDFS_WARN("empty node pointer: "
				   "index %llu\n",
				   (u64)iter.index);
		} else {
			if (tree->btree_ops && tree->btree_ops->destroy_node)
				tree->btree_ops->destroy_node(node);

			ssdfs_btree_node_destroy(node);
		}
		spin_lock(&tree->nodes_lock);
	}
	spin_unlock(&tree->nodes_lock);

	memset(tree, 0, sizeof(struct ssdfs_btree));
}

/*
 * ssdfs_btree_desc_flush() - generalized btree's descriptor flush method
 * @tree: btree object
 * @desc: pointer on btree's descriptor [out]
 */
int ssdfs_btree_desc_flush(struct ssdfs_btree *tree,
			   struct ssdfs_btree_descriptor *desc)
{
	u32 pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("owner_ino %llu, type %#x, state %#x\n",
		  tree->owner_ino, tree->type,
		  atomic_read(&tree->state));

	pagesize = tree->fsi->pagesize;

	if (tree->node_size != (pagesize * tree->pages_per_node)) {
		SSDFS_ERR("invalid pages_per_node: "
			  "node_size %u, page_size %u, pages_per_node %u\n",
			  tree->node_size, pagesize, tree->pages_per_node);
		return -ERANGE;
	}

	if (tree->node_ptr_size != sizeof(struct ssdfs_btree_index_key)) {
		SSDFS_ERR("invalid node_ptr_size %u\n",
			  tree->node_ptr_size);
		return -ERANGE;
	}

	if (tree->index_size != sizeof(struct ssdfs_btree_index)) {
		SSDFS_ERR("invalid index_size %u\n",
			  tree->index_size);
		return -ERANGE;
	}

	desc->flags = cpu_to_le16(atomic_read(&tree->flags));
	desc->type = tree->type;
	desc->log_node_size = ilog2(tree->node_size);
	desc->pages_per_node = tree->pages_per_node;
	desc->node_ptr_size = tree->node_ptr_size;
	desc->index_size = cpu_to_le16(tree->index_size);
	desc->index_area_min_size = cpu_to_le16(tree->index_area_min_size);

	return 0;
}

/*
 * ssdfs_btree_flush_nolock() - flush the current state of btree object
 * @tree: btree object
 *
 * This method tries to flush dirty nodes of the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_flush_nolock(struct ssdfs_btree *tree)
{
	struct radix_tree_iter iter;
	void **slot;
	struct ssdfs_btree_node *node;
	int tree_height, cur_height;
	atomic_t *refs_count;
	wait_queue_head_t *wq = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	cur_height = SSDFS_BTREE_LEAF_NODE_HEIGHT;
	tree_height = atomic_read(&tree->height);

	for (; cur_height < tree_height; cur_height++) {
		rcu_read_lock();

		spin_lock(&tree->nodes_lock);
		radix_tree_for_each_tagged(slot, &tree->nodes, &iter,
					   SSDFS_BTREE_ROOT_NODE_ID,
					   SSDFS_BTREE_NODE_DIRTY_TAG) {

			node = SSDFS_BTN(radix_tree_deref_slot(slot));
			if (unlikely(!node)) {
				SSDFS_WARN("empty node ptr: node_id %llu\n",
					   (u64)iter.index);
				radix_tree_tag_clear(&tree->nodes, iter.index,
						SSDFS_BTREE_NODE_DIRTY_TAG);
				continue;
			}
			spin_unlock(&tree->nodes_lock);

			ssdfs_btree_node_get(node);

			rcu_read_unlock();

			if (atomic_read(&node->height) != cur_height) {
				ssdfs_btree_node_put(node);
				rcu_read_lock();
				spin_lock(&tree->nodes_lock);
				continue;
			}

			err = ssdfs_btree_node_pre_flush(node);
			if (unlikely(err)) {
				ssdfs_btree_node_put(node);
				SSDFS_ERR("fail to pre-flush node: "
					  "node_id %llu, err %d\n",
					  (u64)iter.index, err);
				goto finish_flush_tree_nodes;
			}

			err = ssdfs_btree_node_flush(node);
			if (unlikely(err)) {
				ssdfs_btree_node_put(node);
				SSDFS_ERR("fail to flush node: "
					  "node_id %llu, err %d\n",
					  (u64)iter.index, err);
				goto finish_flush_tree_nodes;
			}

			rcu_read_lock();

			spin_lock(&tree->nodes_lock);
			radix_tree_tag_clear(&tree->nodes, iter.index,
					     SSDFS_BTREE_NODE_DIRTY_TAG);
			radix_tree_tag_set(&tree->nodes, iter.index,
					   SSDFS_BTREE_NODE_TOWRITE_TAG);

			ssdfs_btree_node_put(node);
		}
		spin_unlock(&tree->nodes_lock);

		rcu_read_unlock();
	}

	cur_height = SSDFS_BTREE_LEAF_NODE_HEIGHT;

	for (; cur_height < tree_height; cur_height++) {
		rcu_read_lock();

		spin_lock(&tree->nodes_lock);
		radix_tree_for_each_tagged(slot, &tree->nodes, &iter,
					   SSDFS_BTREE_ROOT_NODE_ID,
					   SSDFS_BTREE_NODE_TOWRITE_TAG) {

			node = SSDFS_BTN(radix_tree_deref_slot(slot));
			if (unlikely(!node)) {
				SSDFS_WARN("empty node ptr: node_id %llu\n",
					   (u64)iter.index);
				radix_tree_tag_clear(&tree->nodes, iter.index,
						SSDFS_BTREE_NODE_TOWRITE_TAG);
				continue;
			}
			spin_unlock(&tree->nodes_lock);

			ssdfs_btree_node_get(node);

			rcu_read_unlock();

			if (atomic_read(&node->height) != cur_height) {
				ssdfs_btree_node_put(node);
				rcu_read_lock();
				spin_lock(&tree->nodes_lock);
				continue;
			}

check_flush_result_state:
			switch (atomic_read(&node->flush_req.result.state)) {
			case SSDFS_REQ_CREATED:
			case SSDFS_REQ_STARTED:
				refs_count =
					&node->flush_req.private.refs_count;
				wq = &node->flush_req.private.wait_queue;

				if (atomic_read(refs_count) != 0) {
					err = wait_event_killable_timeout(*wq,
						atomic_read(refs_count) == 0,
						SSDFS_DEFAULT_TIMEOUT);
					if (err < 0)
						WARN_ON(err < 0);
					else
						err = 0;

					goto check_flush_result_state;
				} else {
					ssdfs_btree_node_put(node);
					err = -ERANGE;
					SSDFS_ERR("invalid refs_count %d\n",
						  atomic_read(refs_count));
					goto finish_flush_tree_nodes;
				}
				break;

			case SSDFS_REQ_FINISHED:
				/* do nothing */
				break;

			case SSDFS_REQ_FAILED:
				ssdfs_btree_node_put(node);
				err = node->flush_req.result.err;

				if (!err) {
					err = -ERANGE;
					SSDFS_ERR("error code is absent\n");
				}

				SSDFS_ERR("flush request is failed: "
					  "err %d\n", err);
				goto finish_flush_tree_nodes;

			default:
				ssdfs_btree_node_put(node);
				err = -ERANGE;
				SSDFS_ERR("invalid result's state %#x\n",
				    atomic_read(&node->flush_req.result.state));
				goto finish_flush_tree_nodes;
			}

			rcu_read_lock();

			spin_lock(&tree->nodes_lock);
			ssdfs_btree_node_put(node);
		}
		spin_unlock(&tree->nodes_lock);

		rcu_read_unlock();
	}

	cur_height = SSDFS_BTREE_LEAF_NODE_HEIGHT;

	for (; cur_height < tree_height; cur_height++) {
		rcu_read_lock();

		spin_lock(&tree->nodes_lock);
		radix_tree_for_each_tagged(slot, &tree->nodes, &iter,
					   SSDFS_BTREE_ROOT_NODE_ID,
					   SSDFS_BTREE_NODE_TOWRITE_TAG) {

			node = SSDFS_BTN(radix_tree_deref_slot(slot));
			if (unlikely(!node)) {
				SSDFS_WARN("empty node ptr: node_id %llu\n",
					   (u64)iter.index);
				radix_tree_tag_clear(&tree->nodes, iter.index,
						SSDFS_BTREE_NODE_TOWRITE_TAG);
				continue;
			}
			spin_unlock(&tree->nodes_lock);

			ssdfs_btree_node_get(node);

			rcu_read_unlock();

			if (atomic_read(&node->height) != cur_height) {
				ssdfs_btree_node_put(node);
				rcu_read_lock();
				spin_lock(&tree->nodes_lock);
				continue;
			}

			if (atomic_read(&node->type) == SSDFS_BTREE_ROOT_NODE) {
				/*
				 * Root node is inline.
				 * Commit log operation is not necessary.
				 */
			} else {
				err = ssdfs_btree_node_commit_log(node);
				if (unlikely(err)) {
					ssdfs_btree_node_put(node);
					SSDFS_ERR("fail to request commit log: "
						  "node_id %llu, err %d\n",
						  (u64)iter.index, err);
					goto finish_flush_tree_nodes;
				}
			}

			rcu_read_lock();

			spin_lock(&tree->nodes_lock);
			ssdfs_btree_node_put(node);
		}
		spin_unlock(&tree->nodes_lock);

		rcu_read_unlock();
	}

	cur_height = SSDFS_BTREE_LEAF_NODE_HEIGHT;

	for (; cur_height < tree_height; cur_height++) {
		rcu_read_lock();

		spin_lock(&tree->nodes_lock);
		radix_tree_for_each_tagged(slot, &tree->nodes, &iter,
					   SSDFS_BTREE_ROOT_NODE_ID,
					   SSDFS_BTREE_NODE_TOWRITE_TAG) {

			node = SSDFS_BTN(radix_tree_deref_slot(slot));
			if (unlikely(!node)) {
				SSDFS_WARN("empty node ptr: node_id %llu\n",
					   (u64)iter.index);
				radix_tree_tag_clear(&tree->nodes, iter.index,
						SSDFS_BTREE_NODE_TOWRITE_TAG);
				continue;
			}
			spin_unlock(&tree->nodes_lock);

			ssdfs_btree_node_get(node);

			rcu_read_unlock();

			if (atomic_read(&node->height) != cur_height) {
				ssdfs_btree_node_put(node);
				rcu_read_lock();
				spin_lock(&tree->nodes_lock);
				continue;
			}

			if (atomic_read(&node->type) == SSDFS_BTREE_ROOT_NODE) {
				/*
				 * Root node is inline.
				 * Commit log operation is not necessary.
				 */
				goto clear_towrite_tag;
			}

check_commit_log_result_state:
			switch (atomic_read(&node->flush_req.result.state)) {
			case SSDFS_REQ_CREATED:
			case SSDFS_REQ_STARTED:
				refs_count =
					&node->flush_req.private.refs_count;
				wq = &node->flush_req.private.wait_queue;

				if (atomic_read(refs_count) != 0) {
					err = wait_event_killable_timeout(*wq,
						atomic_read(refs_count) == 0,
						SSDFS_DEFAULT_TIMEOUT);
					if (err < 0)
						WARN_ON(err < 0);
					else
						err = 0;
					goto check_commit_log_result_state;
				} else {
					ssdfs_btree_node_put(node);
					err = -ERANGE;
					SSDFS_ERR("invalid refs_count %d\n",
						  atomic_read(refs_count));
					goto finish_flush_tree_nodes;
				}
				break;

			case SSDFS_REQ_FINISHED:
				/* do nothing */
				break;

			case SSDFS_REQ_FAILED:
				ssdfs_btree_node_put(node);
				err = node->flush_req.result.err;

				if (!err) {
					err = -ERANGE;
					SSDFS_ERR("error code is absent\n");
				}

				SSDFS_ERR("flush request is failed: "
					  "err %d\n", err);
				goto finish_flush_tree_nodes;

			default:
				ssdfs_btree_node_put(node);
				err = -ERANGE;
				SSDFS_ERR("invalid result's state %#x\n",
				    atomic_read(&node->flush_req.result.state));
				goto finish_flush_tree_nodes;
			}

clear_towrite_tag:
			rcu_read_lock();

			spin_lock(&tree->nodes_lock);
			radix_tree_tag_clear(&tree->nodes, iter.index,
					     SSDFS_BTREE_NODE_TOWRITE_TAG);

			ssdfs_btree_node_put(node);
		}
		spin_unlock(&tree->nodes_lock);

		rcu_read_unlock();
	}

finish_flush_tree_nodes:
	if (unlikely(err))
		goto finish_btree_flush;

	if (tree->desc_ops && tree->desc_ops->flush) {
		err = tree->desc_ops->flush(tree);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush tree descriptor: "
				  "err %d\n",
				  err);
			goto finish_btree_flush;
		}
	}

	atomic_set(&tree->state, SSDFS_BTREE_CREATED);

finish_btree_flush:
	return err;
}

/*
 * ssdfs_btree_flush() - flush the current state of btree object
 * @tree: btree object
 *
 * This method tries to flush dirty nodes of the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_flush(struct ssdfs_btree *tree)
{
	int tree_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x\n",
		  tree, tree->type, tree_state);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
		/* do nothing */
		SSDFS_DBG("btree %#x is not dirty\n",
			  tree->type);
		return 0;

	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	down_write(&tree->lock);
	err = ssdfs_btree_flush_nolock(tree);
	up_write(&tree->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to flush btree: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_btree_destroy_node_range() - destroy nodes from radix tree
 * @tree: btree object
 * @hash: starting hash for nodes destruction
 *
 * This method tries to flush and destroy
 * some nodes from radix tree
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_destroy_node_range(struct ssdfs_btree *tree,
				   u64 hash)
{
	int tree_state;
	u64 start_hash, end_hash;
	struct radix_tree_iter iter;
	void **slot;
	struct ssdfs_btree_node *node;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x\n",
		  tree, tree->type, tree_state);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
		return -ERANGE;
	}

	down_write(&tree->lock);

	err = ssdfs_btree_flush_nolock(tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush btree: err %d\n",
			  err);
		goto finish_destroy_node_range;
	}

	rcu_read_lock();

	spin_lock(&tree->nodes_lock);
	radix_tree_for_each_slot(slot, &tree->nodes, &iter,
				 SSDFS_BTREE_ROOT_NODE_ID) {

		node = (struct ssdfs_btree_node *)radix_tree_deref_slot(slot);
		if (unlikely(!node)) {
			SSDFS_WARN("empty node ptr: node_id %llu\n",
				   (u64)iter.index);
			continue;
		}

		spin_unlock(&tree->nodes_lock);

		ssdfs_btree_node_get(node);

		rcu_read_unlock();

		down_read(&node->header_lock);
		start_hash = node->items_area.start_hash;
		end_hash = node->items_area.end_hash;
		up_read(&node->header_lock);

		ssdfs_btree_node_put(node);

		if (hash < start_hash ||
		    (start_hash < hash && hash < end_hash)) {
			/* node contains valid items */
			rcu_read_lock();
			spin_lock(&tree->nodes_lock);
			continue;
		}

		if (is_ssdfs_node_shared(node)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_INVALID);
			rcu_read_lock();
			spin_lock(&tree->nodes_lock);
			continue;
		}

		rcu_read_lock();
		spin_lock(&tree->nodes_lock);

		node =
		    (struct ssdfs_btree_node *)radix_tree_delete(&tree->nodes,
								 iter.index);

		spin_unlock(&tree->nodes_lock);
		rcu_read_unlock();
		if (!node) {
			/* impossible case */
			BUG();
		} else {
			if (tree->btree_ops && tree->btree_ops->destroy_node)
				tree->btree_ops->destroy_node(node);

			ssdfs_btree_node_destroy(node);
		}
		rcu_read_lock();
		spin_lock(&tree->nodes_lock);
	}
	spin_unlock(&tree->nodes_lock);

	rcu_read_unlock();

finish_destroy_node_range:
	up_write(&tree->lock);

	return err;
}

/*
 * ssdfs_check_leaf_node_absence() - check that node is absent in the tree
 * @tree: btree object
 * @search: search object
 *
 * This method tries to detect that node is really absent before
 * starting to add a new node. The tree should be exclusively locked
 * for this operation in caller method.
 *
 * RETURN:
 * [success] - tree hasn't requested node.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - tree is corrupted.
 * %-EEXIST     - node exists in the tree.
 */
static
int ssdfs_check_leaf_node_absence(struct ssdfs_btree *tree,
				  struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, height %u\n",
		  search->node.id, search->node.height);

	switch (search->node.state) {
	case SSDFS_BTREE_SEARCH_ROOT_NODE_DESC:
	case SSDFS_BTREE_SEARCH_FOUND_INDEX_NODE_DESC:
	case SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid search object state: "
			  "search->node.state %#x\n",
			  search->node.state);
		return -ERANGE;
	}

	if (!search->node.parent) {
		SSDFS_ERR("parent node is NULL\n");
		return -ERANGE;
	}

	err = __ssdfs_btree_find_item(tree, search);
	if (err == -ENODATA) {
		switch (search->result.state) {
		case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
			/*
			 * node doesn't exist in the tree
			 */
			err = 0;
			break;

		default:
			/*
			 * existing node has free space
			 */
			err = -EEXIST;
			break;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find index: "
			  "start_hash %llx, err %d\n",
			  search->request.start.hash,
			  err);
	} else
		err = -EEXIST;

	return err;
}

/*
 * ssdfs_btree_define_new_node_type() - define the type of creating node
 * @tree: btree object
 * @search: search object
 *
 * This method tries to define the type of creating node.
 *
 * RETURN:
 * [success] - type of creating node.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - tree is corrupted.
 */
static
int ssdfs_btree_define_new_node_type(struct ssdfs_btree *tree,
				     struct ssdfs_btree_node *parent)
{
	int tree_height;
	int parent_height;
	int parent_type;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, parent %p\n",
		  tree, parent);

	tree_height = atomic_read(&tree->height);

	if (tree_height <= SSDFS_BTREE_PARENT2LEAF_HEIGHT) {
		/* btree contains root node only */
		return SSDFS_BTREE_LEAF_NODE;
	}

	if (!parent) {
		SSDFS_ERR("parent node is NULL\n");
		return -ERANGE;
	}

	parent_height = atomic_read(&parent->height);

	if (parent_height == 0) {
		SSDFS_ERR("invalid parent height %u\n",
			  parent_height);
		return -ERANGE;
	}


	parent_type = atomic_read(&parent->type);
	switch (parent_type) {
	case SSDFS_BTREE_ROOT_NODE:
		switch (parent_height) {
		case SSDFS_BTREE_LEAF_NODE_HEIGHT:
		case SSDFS_BTREE_PARENT2LEAF_HEIGHT:
			if (can_add_new_index(parent))
				return SSDFS_BTREE_LEAF_NODE;
			else
				return SSDFS_BTREE_HYBRID_NODE;

		case SSDFS_BTREE_PARENT2HYBRID_HEIGHT:
			if (can_add_new_index(parent))
				return SSDFS_BTREE_HYBRID_NODE;
			else
				return SSDFS_BTREE_INDEX_NODE;

		default:
			return SSDFS_BTREE_INDEX_NODE;
		}

	case SSDFS_BTREE_INDEX_NODE:
		switch (parent_height) {
		case SSDFS_BTREE_PARENT2HYBRID_HEIGHT:
			if (can_add_new_index(parent))
				return SSDFS_BTREE_HYBRID_NODE;
			else
				return SSDFS_BTREE_INDEX_NODE;

		default:
			return SSDFS_BTREE_INDEX_NODE;
		}

	case SSDFS_BTREE_HYBRID_NODE:
		return SSDFS_BTREE_LEAF_NODE;
	}

	SSDFS_ERR("invalid btree node's type %#x\n",
		  parent_type);
	return -ERANGE;
}

/*
 * ssdfs_current_segment_pre_allocate_node() - pre-allocate the node
 * @node_type: type of the node
 * @node: node object
 *
 * This method tries to pre-allocate the node
 * in the current segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - tree is corrupted.
 * %-ENOSPC     - volume hasn't free space.
 */
static
int ssdfs_current_segment_pre_allocate_node(int node_type,
					    struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_request *req;
	struct ssdfs_segment_info *si;
	u64 ino;
	u64 logical_offset;
	u64 seg_id;
	int seg_type;
	int err = 0;

	SSDFS_DBG("node_type %#x\n", node_type);

	if (!node) {
		SSDFS_ERR("node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req);
	ssdfs_get_request(req);

	ino = node->tree->owner_ino;
	logical_offset = (u64)node->node_id * node->node_size;
	ssdfs_request_prepare_logical_extent(ino,
					     logical_offset,
					     node->node_size,
					     0, 0, req);

	switch (node_type) {
	case SSDFS_BTREE_INDEX_NODE:
		err = ssdfs_segment_pre_alloc_index_node_extent_async(fsi, req);
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		err = ssdfs_segment_pre_alloc_hybrid_node_extent_async(fsi,
									req);
		break;

	case SSDFS_BTREE_LEAF_NODE:
		err = ssdfs_segment_pre_alloc_leaf_node_extent_async(fsi, req);
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid node_type %#x\n", node_type);
		goto finish_pre_allocate_node;
	}

	if (err == -ENOSPC) {
		SSDFS_DBG("unable to pre-allocate node: "
			  "free space is absent\n");
		goto free_segment_request;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-allocate node: err %d\n",
			  err);
		goto free_segment_request;
	}

	if (req->result.err) {
		err = req->result.err;
		SSDFS_ERR("request finished with err %d\n",
			  err);
		goto free_segment_request;
	}

	if (node->pages_per_node != req->place.len) {
		err = -ERANGE;
		SSDFS_ERR("invalid request result: "
			  "pages_per_node %u != len %u\n",
			  node->pages_per_node,
			  req->place.len);
		goto finish_pre_allocate_node;
	}

	seg_id = req->place.start.seg_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_type = SEG_TYPE(req->private.class);

	si = ssdfs_grab_segment(fsi, seg_type, seg_id);
	if (IS_ERR_OR_NULL(si)) {
		err = (si == NULL ? -ERANGE : PTR_ERR(si));
		SSDFS_ERR("fail to grab segment object: "
			  "err %d\n",
			  err);
		goto finish_pre_allocate_node;
	}

	spin_lock(&node->descriptor_lock);
	node->seg = si;
	node->extent.seg_id = cpu_to_le64(seg_id);
	node->extent.logical_blk = cpu_to_le32(req->place.start.blk_index);
	node->extent.len = cpu_to_le32(req->place.len);
	memcpy(&node->node_index.index.extent, &node->extent,
		sizeof(struct ssdfs_raw_extent));
	spin_unlock(&node->descriptor_lock);

	SSDFS_DBG("tree_type %#x, node_id %u, node_type %#x, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  node->tree->type, node->node_id, node_type,
		  seg_id, req->place.start.blk_index,
		  req->place.len);

	return 0;

finish_pre_allocate_node:
	ssdfs_put_request(req);
	return err;

free_segment_request:
	ssdfs_put_request(req);
	ssdfs_request_free(req);
	return err;
}

/*
 * ssdfs_check_leaf_node_state() - check the leaf node's state
 * @search: search object
 *
 * This method checks the leaf node's state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EEXIST     - node exists.
 */
static
int ssdfs_check_leaf_node_state(struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node;
	int state;
	unsigned long res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, height %u\n",
		  search->node.id, search->node.height);

	state = search->node.state;
	if (state != SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC) {
		SSDFS_ERR("invalid node state %#x\n", state);
		return -ERANGE;
	}

	if (!search->node.child) {
		SSDFS_ERR("child node is NULL\n");
		return -ERANGE;
	}

check_leaf_node_state:
	switch (atomic_read(&search->node.child->state)) {
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		err = -EEXIST;
		break;

	case SSDFS_BTREE_NODE_CREATED:
	case SSDFS_BTREE_NODE_CONTENT_PREPARED:
		node = search->node.child;
		res = wait_for_completion_timeout(&node->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("node init failed: "
				  "err %d\n", err);
		} else {
			err = -EEXIST;
			goto check_leaf_node_state;
		}
		break;

	default:
		BUG();
	}

	return err;
}

/*
 * ssdfs_prepare_empty_btree_for_add() - prepare empty btree for adding
 * @tree: btree object
 * @search: search object
 * @hierarchy: hierarchy object
 *
 * This method prepares empty btree for adding a new node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_prepare_empty_btree_for_add(struct ssdfs_btree *tree,
				      struct ssdfs_btree_search *search,
				      struct ssdfs_btree_hierarchy *hierarchy)
{
	struct ssdfs_btree_level *level;
	struct ssdfs_btree_node *parent_node;
	int cur_height, tree_height;
	u64 start_hash, end_hash;
	int parent_node_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !hierarchy);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);

	tree_height = atomic_read(&tree->height);
	if (tree_height <= 0) {
		SSDFS_ERR("invalid tree_height %u\n",
			  tree_height);
		return -ERANGE;
	}

	parent_node = search->node.parent;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	cur_height = search->node.height;
	if (cur_height >= tree_height) {
		SSDFS_ERR("cur_height %u >= tree_height %u\n",
			  cur_height, tree_height);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	parent_node_type = atomic_read(&parent_node->type);

	if (parent_node_type != SSDFS_BTREE_ROOT_NODE) {
		SSDFS_ERR("corrupted hierarchy: "
			  "expected parent root node\n");
		return -ERANGE;
	}

	if ((tree_height + 1) != hierarchy->desc.height) {
		SSDFS_ERR("corrupted hierarchy: "
			  "tree_height %u, "
			  "hierarchy->desc.height %u\n",
			  tree_height,
			  hierarchy->desc.height);
		return -ERANGE;
	}

	if (!can_add_new_index(parent_node)) {
		SSDFS_ERR("unable add index into the root\n");
		return -ERANGE;
	}

	level = &hierarchy->array[cur_height];
	ssdfs_btree_prepare_add_node(tree, SSDFS_BTREE_LEAF_NODE,
				     start_hash, end_hash,
				     level, NULL);

	level = &hierarchy->array[cur_height + 1];
	err = ssdfs_btree_prepare_add_index(level,
					    start_hash,
					    end_hash,
					    parent_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare level: "
			  "node_id %u, height %u\n",
			  parent_node->node_id,
			  atomic_read(&parent_node->height));
		return err;
	}

	return 0;
}

/*
 * __ssdfs_btree_read_node() - create and initialize the node
 * @tree: btree object
 * @parent: parent node
 * @node_index: index key of preparing node
 * @node_type: type of the node
 * @node_id: node ID
 *
 * This method tries to read the node's content from the disk.
 *
 * RETURN:
 * [success] - pointer on created node object.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - node exists already.
 */
static
struct ssdfs_btree_node *
__ssdfs_btree_read_node(struct ssdfs_btree *tree,
			struct ssdfs_btree_node *parent,
			struct ssdfs_btree_index_key *node_index,
			u8 node_type, u32 node_id)
{
	struct ssdfs_btree_node *ptr, *node;
	int height;
	u64 start_hash;
	int err = 0;

	SSDFS_DBG("tree %p, parent %p, "
		  "node_index %p, node_type %#x, node_id %llu\n",
		  tree, parent, node_index,
		  node_type, (u64)node_id);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !parent || !node_index);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	if (node_type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    node_type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_WARN("invalid node type %#x\n",
			   node_type);
		return ERR_PTR(-ERANGE);
	}

	height = atomic_read(&parent->height);
	if (height <= 0) {
		SSDFS_ERR("invalid height %u, node_id %u\n",
			  height, parent->node_id);
		return ERR_PTR(-ERANGE);
	} else
		height -= 1;

	start_hash = le64_to_cpu(node_index->index.hash);
	ptr = ssdfs_btree_node_create(tree, node_id, parent,
				      height, node_type, start_hash);
	if (unlikely(IS_ERR_OR_NULL(ptr))) {
		err = !ptr ? -ENOMEM : PTR_ERR(ptr);
		SSDFS_ERR("fail to create node: err %d\n",
			  err);
		return ptr;
	}

	if (tree->btree_ops && tree->btree_ops->create_node) {
		err = tree->btree_ops->create_node(ptr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create the node: "
				  "err %d\n", err);
			ssdfs_btree_node_destroy(ptr);
			return ERR_PTR(err);
		}
	}

	spin_lock(&ptr->descriptor_lock);
	memcpy(&ptr->node_index, node_index,
		sizeof(struct ssdfs_btree_index_key));
	spin_unlock(&ptr->descriptor_lock);

try_find_node:
	spin_lock(&tree->nodes_lock);
	node = radix_tree_lookup(&tree->nodes, node_id);
	spin_unlock(&tree->nodes_lock);

	if (!node) {
		err = radix_tree_preload(GFP_NOFS);
		if (unlikely(err)) {
			SSDFS_ERR("fail to preload radix tree: err %d\n",
				  err);
			goto finish_insert_node;
		}

		spin_lock(&tree->nodes_lock);
		err = radix_tree_insert(&tree->nodes, node_id, ptr);
		spin_unlock(&tree->nodes_lock);

		radix_tree_preload_end();

		if (err == -EEXIST)
			goto try_find_node;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to add node into radix tree: "
				  "node_id %llu, node %p, err %d\n",
				  (u64)node_id, ptr, err);
			goto finish_insert_node;
		}
	} else {
		switch (atomic_read(&node->state)) {
		case SSDFS_BTREE_NODE_CREATED:
			err = -EAGAIN;
			goto finish_insert_node;

		case SSDFS_BTREE_NODE_INITIALIZED:
		case SSDFS_BTREE_NODE_DIRTY:
			err = -EEXIST;
			SSDFS_DBG("node %u has been found\n",
				  node_id);
			goto finish_insert_node;

		default:
			err = -ERANGE;
			SSDFS_WARN("invalid node state %#x\n",
				   atomic_read(&node->state));
			goto finish_insert_node;
		}
	}

finish_insert_node:
	if (err == -EAGAIN) {
		unsigned long res;

		res = wait_for_completion_timeout(&node->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("node init failed: "
				  "err %d\n", err);
			ssdfs_btree_node_destroy(ptr);
			return ERR_PTR(err);
		}
		goto try_find_node;
	} else if (err == -EEXIST) {
		ssdfs_btree_node_destroy(ptr);
		return node;
	} else if (unlikely(err)) {
		ssdfs_btree_node_destroy(ptr);
		return ERR_PTR(err);
	}

	err = ssdfs_btree_node_prepare_content(ptr, node_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare btree node's content: "
			  "err %d\n", err);
		goto fail_read_node;
	}

	if (tree->btree_ops && tree->btree_ops->init_node) {
		err = tree->btree_ops->init_node(ptr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init btree node: "
				  "err %d\n", err);
			goto fail_read_node;
		}
	}

	atomic_set(&ptr->state, SSDFS_BTREE_NODE_INITIALIZED);
	complete_all(&ptr->init_end);
	return ptr;

fail_read_node:
	ssdfs_btree_radix_tree_delete(tree, node_id);
	if (tree->btree_ops && tree->btree_ops->delete_node)
		tree->btree_ops->delete_node(ptr);
	if (tree->btree_ops && tree->btree_ops->destroy_node)
		tree->btree_ops->destroy_node(ptr);
	ssdfs_btree_node_destroy(ptr);
	complete_all(&ptr->init_end);
	return ERR_PTR(err);
}

/*
 * ssdfs_btree_read_node() - create and initialize the node
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to read the node's content from the disk.
 *
 * RETURN:
 * [success] - pointer on created node object.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
struct ssdfs_btree_node *
ssdfs_btree_read_node(struct ssdfs_btree *tree,
			struct ssdfs_btree_search *search)
{
	u8 node_type;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, id %u, node_id %u, "
		  "hash %llx, "
		  "extent (seg %u, logical_blk %u, len %u)\n",
		tree,
		search->node.id,
		le32_to_cpu(search->node.found_index.node_id),
		le64_to_cpu(search->node.found_index.index.hash),
		le32_to_cpu(search->node.found_index.index.extent.seg_id),
		le32_to_cpu(search->node.found_index.index.extent.logical_blk),
		le32_to_cpu(search->node.found_index.index.extent.len));

	node_type = search->node.found_index.node_type;
	return __ssdfs_btree_read_node(tree, search->node.parent,
					&search->node.found_index,
					node_type, search->node.id);
}

/*
 * ssdfs_btree_get_child_node_for_hash() - get child node for hash
 * @tree: btree object
 * @parent: parent node
 * @upper_hash: upper value of the hash
 *
 * This method tries to extract child node for the hash value.
 *
 * RETURN:
 * [success] - pointer on the child node.
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EACCES     - node is under initialization.
 * %-ENOENT     - index area is absent.
 */
struct ssdfs_btree_node *
ssdfs_btree_get_child_node_for_hash(struct ssdfs_btree *tree,
				    struct ssdfs_btree_node *parent,
				    u64 upper_hash)
{
	struct ssdfs_btree_node *child = ERR_PTR(-ERANGE);
	struct ssdfs_btree_node_index_area area;
	struct ssdfs_btree_index_key index_key;
	int parent_type;
	u16 found_index = U16_MAX;
	u32 node_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !parent);
	BUG_ON(upper_hash >= U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, upper_hash %llx\n",
		  parent->node_id, upper_hash);

	switch (atomic_read(&parent->state)) {
	case SSDFS_BTREE_NODE_CREATED:
		err = -EACCES;
		SSDFS_DBG("node %u is under initialization\n",
			  parent->node_id);
		return ERR_PTR(err);

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&parent->state));
		return ERR_PTR(err);
	}

	if (!is_ssdfs_btree_node_index_area_exist(parent)) {
		err = -ENOENT;
		SSDFS_DBG("node %u hasn't index area\n",
			  parent->node_id);
		return ERR_PTR(err);
	}

	down_read(&parent->full_lock);

	parent_type = atomic_read(&parent->type);
	if (parent_type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    parent_type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		child = ERR_PTR(-ERANGE);
		SSDFS_ERR("invalid node type %#x\n",
			  parent_type);
		goto finish_child_search;
	}

	down_read(&parent->header_lock);
	memcpy(&area, &parent->index_area,
		sizeof(struct ssdfs_btree_node_index_area));
	up_read(&parent->header_lock);

	err = ssdfs_find_index_by_hash(parent, &area, upper_hash,
					&found_index);
	if (err == -ENODATA) {
		child = ERR_PTR(err);
		SSDFS_DBG("unable to find an index: "
			  "node_id %u, hash %llx\n",
			  parent->node_id, upper_hash);
		goto finish_child_search;
	} else if (unlikely(err)) {
		child = ERR_PTR(err);
		SSDFS_ERR("fail to find an index: "
			  "node_id %u, hash %llx, err %d\n",
			  parent->node_id, upper_hash,
			  err);
		goto finish_child_search;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(found_index == U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type == SSDFS_BTREE_ROOT_NODE) {
		err = __ssdfs_btree_root_node_extract_index(parent,
							    found_index,
							    &index_key);
	} else {
		err = __ssdfs_btree_common_node_extract_index(parent, &area,
							      found_index,
							      &index_key);
	}

	if (unlikely(err)) {
		child = ERR_PTR(err);
		SSDFS_ERR("fail to extract index: "
			  "node_id %u, node_type %#x, "
			  "found_index %u, err %d\n",
			  parent->node_id, parent_type,
			  found_index, err);
		goto finish_child_search;
	}

	node_id = le32_to_cpu(index_key.node_id);

	err = ssdfs_btree_radix_tree_find(tree, node_id, &child);
	if (err == -ENOENT) {
		child = __ssdfs_btree_read_node(tree, parent,
						&index_key,
						index_key.node_type,
						node_id);
		if (unlikely(IS_ERR_OR_NULL(child))) {
			err = !child ? -ENOMEM : PTR_ERR(child);
			SSDFS_ERR("fail to read: "
				  "node %llu, err %d\n",
				  (u64)node_id, err);
			goto finish_child_search;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find node in radix tree: "
			  "node_id %llu, err %d\n",
			  (u64)node_id, err);
		goto finish_child_search;
	} else if (!child) {
		err = -ERANGE;
		SSDFS_WARN("empty node pointer\n");
		goto finish_child_search;
	}

finish_child_search:
	up_read(&parent->full_lock);

	return child;
}

/*
 * ssdfs_btree_generate_node_id() - generate new node ID
 * @tree: btree object
 *
 * It is possible to use the simple technique. The upper node ID will
 * be the latest allocated ID number. Generating the node ID means
 * simply increasing the upper node ID value. In the case of node deletion
 * it needs to leave the empty node till the whole branch of tree will
 * be deleted. The goal is to keep the upper node ID in valid state.
 * And the upper node ID can be decreased if the whold branch of empty
 * nodes will be deleted.
 *
 * <Currently node deletion is simple operation. Any node can be deleted.
 * The implementation should be changed if u32 will be not enough for
 * the node ID representation.>
 *
 * RETURN:
 * [success] - new node ID
 * [failure] - U32_MAX
 */
u32 ssdfs_btree_generate_node_id(struct ssdfs_btree *tree)
{
	struct ssdfs_btree_node *node;
	u32 node_id = U32_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	spin_lock(&tree->nodes_lock);
	node_id = tree->upper_node_id;
	if (node_id < U32_MAX) {
		node_id++;
		tree->upper_node_id = node_id;
	}
	spin_unlock(&tree->nodes_lock);

	if (node_id == U32_MAX) {
		SSDFS_DBG("node IDs are completely used\n");
		return node_id;
	}

	err = ssdfs_btree_radix_tree_find(tree,
					  SSDFS_BTREE_ROOT_NODE_ID,
					  &node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find root node in radix tree: "
			  "err %d\n", err);
		return U32_MAX;
	} else if (!node) {
		SSDFS_WARN("empty node pointer\n");
		return U32_MAX;
	}

	set_ssdfs_btree_node_dirty(node);

	return node_id;
}

/*
 * ssdfs_btree_destroy_empty_node() - destroy the empty node.
 * @tree: btree object
 * @node: node object
 *
 * This method tries to destroy the empty node.
 */
static inline
void ssdfs_btree_destroy_empty_node(struct ssdfs_btree *tree,
				    struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!node)
		return;

	SSDFS_DBG("node_id %u, height %u\n",
		  node->node_id,
		  atomic_read(&node->height));

	if (tree->btree_ops && tree->btree_ops->destroy_node)
		tree->btree_ops->destroy_node(node);

	ssdfs_btree_node_destroy(node);
}

/*
 * ssdfs_btree_create_empty_node() - create empty node.
 * @tree: btree object
 * @cur_height: height for node creation
 * @hierarchy: hierarchy object
 *
 * This method tries to create the empty node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_create_empty_node(struct ssdfs_btree *tree,
				  int cur_height,
				  struct ssdfs_btree_hierarchy *hierarchy)
{
	struct ssdfs_btree_level *level;
	struct ssdfs_btree_node *parent = NULL, *ptr = NULL;
	u32 node_id;
	int node_type;
	int tree_height;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !hierarchy);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, cur_height %d\n",
		  tree, cur_height);

	tree_height = atomic_read(&tree->height);

	if (cur_height > tree_height) {
		SSDFS_ERR("cur_height %d > tree_height %d\n",
			  cur_height, tree_height);
		return -ERANGE;
	}

	level = &hierarchy->array[cur_height];

	if (!(level->flags & SSDFS_BTREE_LEVEL_ADD_NODE))
		return 0;

	node_id = ssdfs_btree_generate_node_id(tree);
	if (node_id == SSDFS_BTREE_NODE_INVALID_ID) {
		SSDFS_ERR("fail to generate node_id: err %d\n",
			  err);
		return -ERANGE;
	}

	level = &hierarchy->array[cur_height + 1];
	if (level->nodes.old_node.ptr)
		parent = level->nodes.old_node.ptr;
	else
		parent = level->nodes.new_node.ptr;

	node_type = ssdfs_btree_define_new_node_type(tree, parent);
	switch (node_type) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		/* expected state */
		break;

	default:
		if (node_type < 0) {
			SSDFS_ERR("fail to define the new node type: "
				  "err %d\n", err);
		} else {
			SSDFS_ERR("invalid node type %#x\n",
				  node_type);
		}
		return node_type < 0 ? node_type : -ERANGE;
	}

	if (!parent) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	level = &hierarchy->array[cur_height];
	ptr = ssdfs_btree_node_create(tree, node_id, parent, cur_height,
					node_type,
					level->items_area.hash.start);
	if (unlikely(IS_ERR_OR_NULL(ptr))) {
		err = !ptr ? -ENOMEM : PTR_ERR(ptr);
		SSDFS_ERR("fail to create node: err %d\n",
			  err);
		return err;
	}

	if (tree->btree_ops && tree->btree_ops->create_node) {
		err = tree->btree_ops->create_node(ptr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create the node: "
				  "err %d\n", err);
			goto finish_create_node;
		}
	}

	err = ssdfs_current_segment_pre_allocate_node(node_type, ptr);
	if (err == -ENOSPC) {
		SSDFS_DBG("unable to preallocate node: id %u\n",
			  node_id);
		goto finish_create_node;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to preallocate node: id %u, err %d\n",
			  node_id, err);
		goto finish_create_node;
	}

	atomic_or(SSDFS_BTREE_NODE_PRE_ALLOCATED,
		  &ptr->flags);

	flags = le16_to_cpu(ptr->node_index.flags);
	flags |= SSDFS_BTREE_INDEX_SHOW_PREALLOCATED_CHILD;
	ptr->node_index.flags = cpu_to_le16(flags);

	level->nodes.new_node.type = node_type;
	level->nodes.new_node.ptr = ptr;
	return 0;

finish_create_node:
	ssdfs_btree_destroy_empty_node(tree, ptr);
	return err;
}

/*
 * __ssdfs_btree_add_node() - add a node into the btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to add a node into the tree with the goal
 * to increase capacity of items in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-EEXIST     - node exists already.
 */
static
int __ssdfs_btree_add_node(struct ssdfs_btree *tree,
			   struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_hierarchy *hierarchy;
	struct ssdfs_btree_level *level;
	struct ssdfs_btree_node *node;
	int cur_height, tree_height;
	u32 node_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, start_hash %llx\n",
		  tree, search->request.start.hash);

	switch (search->node.state) {
	case SSDFS_BTREE_SEARCH_ROOT_NODE_DESC:
	case SSDFS_BTREE_SEARCH_FOUND_INDEX_NODE_DESC:
	case SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  search->node.state);
		return -ERANGE;
	}

	if (!search->node.parent) {
		SSDFS_ERR("parent node is NULL\n");
		return -ERANGE;
	}

	tree_height = atomic_read(&tree->height);
	if (tree_height <= 0) {
		SSDFS_ERR("invalid tree_height %d\n",
			  tree_height);
		return -ERANGE;
	}

	hierarchy = ssdfs_btree_hierarchy_allocate(tree);
	if (IS_ERR_OR_NULL(hierarchy)) {
		err = !hierarchy ? -ENOMEM : PTR_ERR(hierarchy);
		SSDFS_ERR("fail to allocate tree levels' array: "
			  "err %d\n", err);
		return err;
	}

	down_write(&tree->lock);

	err = ssdfs_check_leaf_node_absence(tree, search);
	if (err == -EEXIST) {
		up_write(&tree->lock);
		SSDFS_DBG("new node has been added\n");
		return ssdfs_check_leaf_node_state(search);
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check leaf node absence: "
			  "err %d\n", err);
		goto finish_create_node;
	}

	err = ssdfs_btree_check_hierarchy_for_add(tree, search, hierarchy);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare information about hierarchy: "
			  "err %d\n",
			  err);
		goto finish_create_node;
	}

	for (cur_height = tree_height; cur_height >= 0; cur_height--) {
		level = &hierarchy->array[cur_height];

		if (!need_add_node(level))
			continue;

		err = ssdfs_btree_create_empty_node(tree, cur_height,
						    hierarchy);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create empty node: "
				  "err %d\n",
				  err);

			for (; cur_height < tree_height; cur_height++) {
				if (!need_add_node(level))
					continue;

				node = level->nodes.new_node.ptr;
				node_id = node->node_id;
				ssdfs_btree_radix_tree_delete(tree, node_id);
				ssdfs_btree_destroy_empty_node(tree, node);
			}

			goto finish_create_node;
		}

		node = level->nodes.new_node.ptr;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_btree_radix_tree_insert(tree, node->node_id,
						    node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert node %u into radix tree: "
				  "err %d\n",
				  node->node_id, err);

			for (; cur_height < tree_height; cur_height++) {
				level = &hierarchy->array[cur_height];

				if (!need_add_node(level))
					continue;

				node = level->nodes.new_node.ptr;
				node_id = node->node_id;
				ssdfs_btree_radix_tree_delete(tree, node_id);
				ssdfs_btree_destroy_empty_node(tree, node);
			}

			goto finish_create_node;
		}
	}

	cur_height = 0;
	for (; cur_height < hierarchy->desc.height; cur_height++) {
		err = ssdfs_btree_process_level_for_add(hierarchy, cur_height,
							search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to process the tree's level: "
				  "cur_height %u, err %d\n",
				  cur_height, err);
			goto finish_create_node;
		}
	}

	for (cur_height = tree_height; cur_height >= 0; cur_height--) {
		level = &hierarchy->array[cur_height];

		if (!need_add_node(level))
			continue;

		node = level->nodes.new_node.ptr;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

		if (tree->btree_ops && tree->btree_ops->add_node) {
			err = tree->btree_ops->add_node(node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add the node: "
					  "err %d\n", err);

				for (; cur_height < tree_height; cur_height++) {
					level = &hierarchy->array[cur_height];

					if (!need_add_node(level))
						continue;

					node = level->nodes.new_node.ptr;
					node_id = node->node_id;
					ssdfs_btree_radix_tree_delete(tree,
								      node_id);
					if (tree->btree_ops &&
						tree->btree_ops->delete_node) {
					    tree->btree_ops->delete_node(node);
					}
					ssdfs_btree_destroy_empty_node(tree,
									node);
				}

				goto finish_create_node;
			}
		}

		atomic_set(&node->state, SSDFS_BTREE_NODE_DIRTY);
	}

	if (hierarchy->desc.increment_height) {
		/* increase tree's height */
		atomic_inc(&tree->height);
	}

	atomic_set(&tree->state, SSDFS_BTREE_DIRTY);
	up_write(&tree->lock);

	if (search->node.parent)
		complete_all(&search->node.parent->init_end);

	tree_height = atomic_read(&tree->height);
	for (cur_height = 0; cur_height < tree_height; cur_height++) {
		level = &hierarchy->array[cur_height];

		if (!need_add_node(level))
			continue;

		node = level->nodes.new_node.ptr;
		complete_all(&node->init_end);
	}

	ssdfs_btree_hierarchy_free(hierarchy);

	search->result.err = 0;
	search->result.state = SSDFS_BTREE_SEARCH_UNKNOWN_RESULT;
	return 0;

finish_create_node:
	up_write(&tree->lock);

	if (search->node.parent)
		complete_all(&search->node.parent->init_end);

	ssdfs_btree_hierarchy_free(hierarchy);

	search->result.err = err;
	search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
	return err;
}

/*
 * ssdfs_btree_node_convert_index2id() - convert index into node ID
 * @tree: btree object
 * @search: search object [in|out]
 */
static inline
int ssdfs_btree_node_convert_index2id(struct ssdfs_btree *tree,
				      struct ssdfs_btree_search *search)
{
	u32 id;
	u8 height;
	u8 tree_height;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	id = le32_to_cpu(search->node.found_index.node_id);
	height = search->node.found_index.height;

	SSDFS_DBG("node_id %u, height %u\n",
		  id, height);

	if (id == SSDFS_BTREE_NODE_INVALID_ID) {
		SSDFS_ERR("invalid node_id\n");
		return -ERANGE;
	}

	tree_height = atomic_read(&tree->height);

	if (height >= tree_height) {
		SSDFS_ERR("height %u >= tree->height %u\n",
			  height, tree_height);
		return -ERANGE;
	}

	search->node.id = id;
	search->node.height = height;
	return 0;
}

/*
 * ssdfs_btree_find_leaf_node() - find a leaf node in the tree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to find a leaf node for the requested
 * start hash and end hash pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - try the old search result.
 * %-ENOENT     - leaf node hasn't been found.
 */
static
int ssdfs_btree_find_leaf_node(struct ssdfs_btree *tree,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node;
	u8 upper_height;
	u8 prev_height;
	u64 start_hash = U64_MAX, end_hash = U64_MAX;
	u16 items_count, items_capacity;
	bool is_found = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, start_hash %llx\n",
		  tree, search->request.start.hash);

	if (search->node.state == SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC) {
		SSDFS_DBG("try to use old search result: "
			  "node_id %llu, height %u\n",
			  (u64)search->node.id, search->node.height);
		return -EEXIST;
	}

	if (search->request.start.hash == U64_MAX ||
	    search->request.end.hash == U64_MAX) {
		SSDFS_ERR("invalid hash range in the request: "
			  "start_hash %llx, end_hash %llx\n",
			  search->request.start.hash,
			  search->request.end.hash);
		return -ERANGE;
	}

	upper_height = atomic_read(&tree->height);
	if (upper_height <= 0) {
		SSDFS_ERR("invalid tree height %u\n",
			  upper_height);
		return -ERANGE;
	} else
		upper_height--;

	search->node.id = SSDFS_BTREE_ROOT_NODE_ID;
	search->node.height = upper_height;
	search->node.state = SSDFS_BTREE_SEARCH_ROOT_NODE_DESC;

	do {
		unsigned long prev_id = search->node.id;
		int node_height;
		int node_type;
		prev_height = search->node.height;

		SSDFS_DBG("node_id %u, hash %llx\n",
			  search->node.id,
			  search->request.start.hash);

		ssdfs_btree_search_define_parent_node(search,
							search->node.child);

		err = ssdfs_btree_radix_tree_find(tree, search->node.id,
						  &node);
		if (err == -ENOENT) {
			err = 0;
			node = ssdfs_btree_read_node(tree, search);
			if (unlikely(IS_ERR_OR_NULL(node))) {
				err = !node ? -ENOMEM : PTR_ERR(node);
				SSDFS_ERR("fail to read: "
					  "node %llu, err %d\n",
					  (u64)search->node.id, err);
				goto finish_search_leaf_node;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find node in radix tree: "
				  "node_id %llu, err %d\n",
				  (u64)search->node.id, err);
			goto finish_search_leaf_node;
		} else if (!node) {
			err = -ERANGE;
			SSDFS_WARN("empty node pointer\n");
			goto finish_search_leaf_node;
		}

		ssdfs_btree_search_define_child_node(search, node);
		node_height = atomic_read(&node->height);

		if (search->node.height != node_height) {
			err = -ERANGE;
			SSDFS_WARN("search->height %u != height %u\n",
				   search->node.height,
				   node_height);
			goto finish_search_leaf_node;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(node_height >= U8_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		search->node.height = (u8)node_height;

		if (node_height == SSDFS_BTREE_LEAF_NODE_HEIGHT) {
			if (upper_height == SSDFS_BTREE_LEAF_NODE_HEIGHT) {
				/* there is only root node */
				search->node.state =
				    SSDFS_BTREE_SEARCH_ROOT_NODE_DESC;
			} else {
				search->node.state =
				    SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC;
			}
			break;
		}

		node_type = atomic_read(&node->type);
		if (node_type == SSDFS_BTREE_HYBRID_NODE) {
			switch (atomic_read(&node->items_area.state)) {
			case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
				/* expected state */
				break;

			default:
				err = -ERANGE;
				SSDFS_WARN("corrupted node %u\n",
					   node->node_id);
				goto finish_search_leaf_node;
			}

			switch (atomic_read(&node->index_area.state)) {
			case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
				/* expected state */
				break;

			default:
				err = -ERANGE;
				SSDFS_WARN("corrupted node %u\n",
					   node->node_id);
				goto finish_search_leaf_node;
			}

			down_read(&node->header_lock);
			start_hash = node->items_area.start_hash;
			end_hash = node->items_area.end_hash;
			is_found = start_hash <= search->request.start.hash &&
				   search->request.start.hash <= end_hash;
			up_read(&node->header_lock);

			SSDFS_DBG("start_hash %llx, end_hash %llx, "
				  "is_found %#x\n",
				  start_hash, end_hash, is_found);

			if (start_hash < U64_MAX && end_hash == U64_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid items area's hash range: "
					  "start_hash %llx, end_hash %llx\n",
					  start_hash, end_hash);
				goto finish_search_leaf_node;
			}

			if (is_found) {
				search->node.state =
					SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC;
				goto check_found_node;
			} else if (search->request.start.hash > end_hash) {
				/*
				 * Hybrid node is exausted already.
				 * It needs to use this node as
				 * starting point for adding a new node.
				 */
				search->node.state =
					SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC;
				goto check_found_node;
			}
		}

try_find_index:
		err = ssdfs_btree_node_find_index(search);
		if (err == -ENODATA) {
			err = 0;
			SSDFS_DBG("unable to find node index: "
				  "node_state %#x, node_id %llu, "
				  "height %u\n",
				  search->node.state,
				  (u64)search->node.id,
				  search->node.height);
			if (upper_height == 0) {
				search->node.state =
					SSDFS_BTREE_SEARCH_ROOT_NODE_DESC;
			} else {
				search->node.state =
					SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC;
			}
			break;
		} else if (err == -EACCES) {
			unsigned long res;

			res = wait_for_completion_timeout(&node->init_end,
							SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("node init failed: "
					  "err %d\n", err);
				goto finish_search_leaf_node;
			}
			goto try_find_index;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find index: "
				  "start_hash %llx, err %d\n",
				  search->request.start.hash,
				  err);
			goto finish_search_leaf_node;
		}

		err = ssdfs_btree_node_convert_index2id(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert index to ID: "
				  "err %d\n", err);
			goto finish_search_leaf_node;
		}

		search->node.state = SSDFS_BTREE_SEARCH_FOUND_INDEX_NODE_DESC;

		if (!is_btree_index_search_request_valid(search,
							 prev_id,
							 prev_height)) {
			err = -ERANGE;
			SSDFS_ERR("invalid index search request: "
				  "prev_id %llu, prev_height %u, "
				  "id %llu, height %u\n",
				  (u64)prev_id, prev_height,
				  (u64)search->node.id,
				  search->node.height);
			goto finish_search_leaf_node;
		}
	} while (prev_height > SSDFS_BTREE_LEAF_NODE_HEIGHT);

check_found_node:
	if (search->node.state == SSDFS_BTREE_SEARCH_ROOT_NODE_DESC) {
		err = -ENOENT;
		ssdfs_btree_search_define_parent_node(search,
						      search->node.child);
		ssdfs_btree_search_define_child_node(search, NULL);
		SSDFS_DBG("btree has empty root node\n");
		goto finish_search_leaf_node;
	} else if (is_btree_leaf_node_found(search)) {
		switch (atomic_read(&node->items_area.state)) {
		case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
			/* expected state */
			break;

		default:
			err = -ERANGE;
			SSDFS_WARN("corrupted node %u\n",
				   node->node_id);
			goto finish_search_leaf_node;
		}

		down_read(&node->header_lock);
		start_hash = node->items_area.start_hash;
		end_hash = node->items_area.end_hash;
		items_count = node->items_area.items_count;
		items_capacity = node->items_area.items_capacity;
		up_read(&node->header_lock);

		if (start_hash == U64_MAX || end_hash == U64_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid items area's hash range: "
				  "start_hash %llx, end_hash %llx\n",
				  start_hash, end_hash);
			goto finish_search_leaf_node;
		}

		is_found = start_hash <= search->request.start.hash &&
			   search->request.start.hash <= end_hash;

		if (!is_found && items_count >= items_capacity) {
			err = -ENOENT;
			search->node.state =
				SSDFS_BTREE_SEARCH_FOUND_INDEX_NODE_DESC;
			SSDFS_DBG("unable to find a leaf node: "
				  "search_hash %llx\n",
				  search->request.start.hash);
			goto finish_search_leaf_node;
		}
	} else {
		err = -ENOENT;
		SSDFS_DBG("invalid leaf node descriptor: "
			   "node_state %#x, node_id %llu, "
			   "height %u\n",
			   search->node.state,
			   (u64)search->node.id,
			   search->node.height);
	}

finish_search_leaf_node:
	return err;
}

/*
 * ssdfs_btree_add_node() - add a node into the btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to add a node into the tree with the goal
 * to increase capacity of items in the tree. It means that
 * the new leaf node should be added into the tail of leaf
 * nodes' chain.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - tree is corrupted.
 * %-ENOSPC     - unable to add the new node.
 */
int ssdfs_btree_add_node(struct ssdfs_btree *tree,
			 struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	u64 free_pages;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, start_hash %llx\n",
		  tree, search->request.start.hash);

	switch (atomic_read(&tree->state)) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   atomic_read(&tree->state));
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	fsi = tree->fsi;

	spin_lock(&fsi->volume_state_lock);
	free_pages = fsi->free_pages;
	if (tree->pages_per_node > free_pages)
		err = -ENOSPC;
	spin_unlock(&fsi->volume_state_lock);

	if (err) {
		SSDFS_DBG("unable to add the new node: "
			  "pages_per_node %u, free_pages %llu, "
			  "err %d\n",
			  tree->pages_per_node,
			  free_pages, err);
		return err;
	}

	down_read(&tree->lock);
	err = ssdfs_btree_find_leaf_node(tree, search);
	up_read(&tree->lock);

	if (!err) {
		SSDFS_DBG("found leaf node %u\n",
			  search->node.id);
		return ssdfs_check_leaf_node_state(search);
	} else if (err == -ENOENT) {
		/*
		 * Parent node was found.
		 */
		err = 0;
	} else {
		err = -ERANGE;
		SSDFS_ERR("fail to define the parent node: "
			  "hash %llx, err %d\n",
			  search->request.start.hash,
			  err);
		return err;
	}

	err = __ssdfs_btree_add_node(tree, search);
	if (err == -EEXIST)
		SSDFS_DBG("node has been added\n");
	else if (unlikely(err)) {
		SSDFS_ERR("fail to add a new node: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_btree_insert_node() - insert a node into the btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to insert a node into the tree for
 * the requested hash value.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - tree is corrupted.
 * %-ENOSPC     - unable to insert the new node.
 */
int ssdfs_btree_insert_node(struct ssdfs_btree *tree,
			    struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	u64 free_pages;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, start_hash %llx\n",
		  tree, search->request.start.hash);

	switch (atomic_read(&tree->state)) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   atomic_read(&tree->state));
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	fsi = tree->fsi;

	spin_lock(&fsi->volume_state_lock);
	free_pages = fsi->free_pages;
	if (tree->pages_per_node > free_pages)
		err = -ENOSPC;
	spin_unlock(&fsi->volume_state_lock);

	if (err) {
		SSDFS_DBG("unable to add the new node: "
			  "pages_per_node %u, free_pages %llu, "
			  "err %d\n",
			  tree->pages_per_node,
			  free_pages, err);
		return err;
	}

	err = __ssdfs_btree_add_node(tree, search);
	if (err == -EEXIST)
		SSDFS_DBG("node has been added\n");
	else if (unlikely(err)) {
		SSDFS_ERR("fail to add a new node: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_segment_invalidate_node() - invalidate the node in the segment
 * @node: node object
 *
 * This method tries to invalidate the node
 * in the current segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - tree is corrupted.
 */
static
int ssdfs_segment_invalidate_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_segment_info *seg;
	u32 start_blk;
	u32 len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&node->descriptor_lock);
	start_blk = le32_to_cpu(node->extent.logical_blk);
	len = le32_to_cpu(node->extent.len);
	seg = node->seg;
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!seg);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, seg_id %llu, start_blk %u, len %u\n",
		  node->node_id, seg->seg_id, start_blk, len);

	err = ssdfs_segment_invalidate_logical_extent(seg, start_blk, len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate node: "
			  "node_id %u, seg_id %llu, "
			  "start_blk %u, len %u\n",
			  node->node_id, seg->seg_id,
			  start_blk, len);
	}

	return 0;
}

/*
 * ssdfs_btree_delete_index_in_parent_node() - delete index in parent node
 * @tree: btree object
 * @search: search object
 *
 * This method tries to delete teh index records in all parent nodes.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - tree is corrupted.
 */
static
int ssdfs_btree_delete_index_in_parent_node(struct ssdfs_btree *tree,
					    struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_hierarchy *hierarchy;
	struct ssdfs_btree_level *level;
	struct ssdfs_btree_node *node;
	int cur_height, tree_height;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, start_hash %llx\n",
		  tree, search->request.start.hash);

	switch (atomic_read(&tree->state)) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   atomic_read(&tree->state));
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	switch (search->node.state) {
	case SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  search->node.state);
		return -ERANGE;
	}

	if (!search->node.child) {
		SSDFS_ERR("child node is NULL\n");
		return -ERANGE;
	}

	if (!search->node.parent) {
		SSDFS_ERR("parent node is NULL\n");
		return -ERANGE;
	}

	tree_height = atomic_read(&tree->height);
	if (tree_height <= 0) {
		SSDFS_ERR("invalid tree_height %u\n",
			  tree_height);
		return -ERANGE;
	}

	hierarchy = ssdfs_btree_hierarchy_allocate(tree);
	if (IS_ERR_OR_NULL(hierarchy)) {
		err = !hierarchy ? -ENOMEM : PTR_ERR(hierarchy);
		SSDFS_ERR("fail to allocate tree levels' array: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_btree_check_hierarchy_for_delete(tree, search, hierarchy);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare information about hierarchy: "
			  "err %d\n",
			  err);
		goto finish_delete_index;
	}

	for (cur_height = 0; cur_height < tree_height; cur_height++) {
		err = ssdfs_btree_process_level_for_delete(hierarchy,
							   cur_height,
							   search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to process the tree's level: "
				  "cur_height %u, err %d\n",
				  cur_height, err);
			goto finish_delete_index;
		}
	}

	for (cur_height = 0; cur_height < tree_height; cur_height++) {
		level = &hierarchy->array[cur_height];

		if (!need_delete_node(level))
			continue;

		node = level->nodes.old_node.ptr;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_btree_radix_tree_delete(tree, node->node_id);

		if (tree->btree_ops && tree->btree_ops->delete_node) {
			err = tree->btree_ops->delete_node(node);
			if (unlikely(err)) {
				SSDFS_ERR("delete node failure: err %d\n",
					  err);
			}
		}

		err = ssdfs_segment_invalidate_node(node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate node: id %u, err %d\n",
				  node->node_id, err);
		}

		if (tree->btree_ops && tree->btree_ops->destroy_node)
			tree->btree_ops->destroy_node(node);

		ssdfs_btree_node_destroy(node);
	}

	atomic_set(&tree->state, SSDFS_BTREE_DIRTY);
	ssdfs_btree_hierarchy_free(hierarchy);

	ssdfs_btree_search_define_child_node(search, NULL);
	search->result.err = 0;
	search->result.state = SSDFS_BTREE_SEARCH_UNKNOWN_RESULT;
	return 0;

finish_delete_index:
	ssdfs_btree_hierarchy_free(hierarchy);

	search->result.err = err;
	search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
	return err;
}

/*
 * ssdfs_btree_delete_node() - delete the node from the btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to delete a node from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - cannot delete the node.
 * %-EBUSY      - node has several owners.
 */
int ssdfs_btree_delete_node(struct ssdfs_btree *tree,
			    struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node;
	bool cannot_delete = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, start_hash %llx\n",
		  tree, search->request.start.hash);

	switch (atomic_read(&tree->state)) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   atomic_read(&tree->state));
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE) {
		SSDFS_ERR("invalid search->result.state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	switch (search->node.state) {
	case SSDFS_BTREE_SEARCH_FOUND_INDEX_NODE_DESC:
	case SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC:
		/* expected state */
		break;

	case SSDFS_BTREE_SEARCH_ROOT_NODE_DESC:
		SSDFS_ERR("fail to delete root node\n");
		return -ERANGE;

	default:
		BUG();
	}

	if (!search->node.child) {
		SSDFS_ERR("child node pointer is NULL\n");
		return -ERANGE;
	}

	if (!search->node.parent) {
		SSDFS_ERR("parent node pointer is NULL\n");
		return -ERANGE;
	}

	node = search->node.child;

	if (node->node_id != search->node.id ||
	    atomic_read(&node->height) != search->node.height) {
		SSDFS_ERR("corrupted search object: "
			  "node->node_id %u, search->node.id %u, "
			  "node->height %u, search->node.height %u\n",
			  node->node_id, search->node.id,
			  atomic_read(&node->height),
			  search->node.height);
		return -ERANGE;
	}

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state: id %u, state %#x\n",
			  node->node_id,
			  atomic_read(&node->state));
		return -ERANGE;
	}

	down_read(&node->header_lock);
	if (node->items_area.items_count != 0)
		cannot_delete = true;
	if (node->index_area.index_count != 0)
		cannot_delete = true;
	up_read(&node->header_lock);

	if (cannot_delete) {
		SSDFS_ERR("node has content in index/items area\n");
		return -EFAULT;
	}

	if (is_ssdfs_node_shared(node)) {
		SSDFS_DBG("node %u has several owners %d\n",
			  node->node_id,
			  atomic_read(&node->refs_count));
		return -EBUSY;
	}

	down_write(&tree->lock);
	err = ssdfs_btree_delete_index_in_parent_node(tree, search);
	up_write(&tree->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to delete index from parent node: "
			  "err %d\n", err);
	}

	return err;
}

/*
 * node_needs_in_additional_check() - does it need to check the node?
 * @err: error code
 * @search: search object
 */
static inline
bool node_needs_in_additional_check(int err,
				    struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	return err == -ENODATA &&
		search->result.state == SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE;
}

/*
 * ssdfs_btree_switch_on_hybrid_parent_node() - change current node
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to change the current node on hybrid parent one.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - nothing can be done.
 */
static
int ssdfs_btree_switch_on_hybrid_parent_node(struct ssdfs_btree *tree,
					     struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node;
	int state;
	u64 start_hash, end_hash;
	u16 items_count, items_capacity;
	u16 free_items;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, type %#x, "
		  "request->type %#x, request->flags %#x, "
		  "result->err %d, result->state %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type,
		  search->request.type, search->request.flags,
		  search->result.err,
		  search->result.state,
		  search->request.start.hash,
		  search->request.end.hash);

	if (search->result.err != -ENODATA) {
		SSDFS_ERR("unexpected result's error %d\n",
			  search->result.err);
		return -ERANGE;
	}

	if (search->result.state != SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE) {
		SSDFS_ERR("unexpected result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->request.start.hash == U64_MAX ||
	    search->request.end.hash == U64_MAX) {
		SSDFS_ERR("invalid request: "
			  "start_hash %llx, end_hash %llx\n",
			  search->request.start.hash,
			  search->request.end.hash);
		return -ERANGE;
	}

	node = search->node.child;
	if (!node) {
		SSDFS_ERR("corrupted search request: child node is NULL\n");
		return -ERANGE;
	}

	if (atomic_read(&node->type) == SSDFS_BTREE_ROOT_NODE)
		return -ENODATA;

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid items area's state %#x\n",
			  state);
		return -ERANGE;
	}

	down_read(&node->header_lock);
	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	up_read(&node->header_lock);

	if (start_hash == U64_MAX || end_hash == U64_MAX) {
		SSDFS_ERR("corrupted items area: "
			  "start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		return -ERANGE;
	}

	if (start_hash > end_hash) {
		SSDFS_ERR("corrupted items area: "
			  "start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		return -ERANGE;
	}

	if (search->request.start.hash < start_hash) {
		if (search->request.end.hash < start_hash) {
			SSDFS_DBG("request (start_hash %llx, end_hash %llx), "
				  "area (start_hash %llx, end_hash %llx)\n",
				  search->request.start.hash,
				  search->request.end.hash,
				  start_hash, end_hash);
			return -ENODATA;
		} else {
			SSDFS_ERR("invalid request: "
				  "request (start_hash %llx, end_hash %llx), "
				  "area (start_hash %llx, end_hash %llx)\n",
				  search->request.start.hash,
				  search->request.end.hash,
				  start_hash, end_hash);
			return -ERANGE;
		}
	}

	if (items_count > items_capacity) {
		SSDFS_ERR("corrupted items area: "
			  "items_count %u, items_capacity %u\n",
			  items_count, items_capacity);
		return -ERANGE;
	}

	free_items = items_capacity - items_count;

	if (free_items != 0) {
		SSDFS_WARN("invalid free_items %u, "
			   "items_count %u, items_capacity %u\n",
			   free_items, items_count, items_capacity);
		return -ERANGE;
	}

	node = search->node.parent;
	if (!node) {
		SSDFS_ERR("corrupted search request: parent node is NULL\n");
		return -ERANGE;
	}

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_INDEX_NODE:
		/* nothing can be done */
		return -ENODATA;

	case SSDFS_BTREE_HYBRID_NODE:
		/* it needs to check the node's state */
		break;

	case SSDFS_BTREE_LEAF_NODE:
		SSDFS_WARN("btree is corrupted: "
			   "leaf node %u cannot be the parent\n",
			   node->node_id);
		return -ERANGE;

	default:
		SSDFS_ERR("invalid node's type %#x\n",
			  atomic_read(&node->type));
		return -ERANGE;
	}

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_WARN("invalid node's %u state %#x\n",
			   node->node_id,
			   atomic_read(&node->state));
		return -ERANGE;
	}

	flags = atomic_read(&node->flags);

	if (!(flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA)) {
		SSDFS_WARN("hybrid node %u hasn't items area\n",
			   node->node_id);
		return -ENODATA;
	}

	ssdfs_btree_search_define_child_node(search, node);
	ssdfs_btree_search_define_parent_node(search, node->parent_node);
	memcpy(&search->node.found_index, &node->node_index,
		sizeof(struct ssdfs_btree_index_key));

	err = ssdfs_btree_node_convert_index2id(tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert index to ID: "
			  "node %u, height %u\n",
			  node->node_id,
			  atomic_read(&node->height));
		return err;
	}

	return 0;
}

/*
 * __ssdfs_btree_find_item() - find item into btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to find an item into the tree.
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
int __ssdfs_btree_find_item(struct ssdfs_btree *tree,
			    struct ssdfs_btree_search *search)
{
	int tree_state;
	unsigned long res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type, tree_state,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (!is_btree_search_request_valid(search)) {
		SSDFS_ERR("invalid search object\n");
		return -EINVAL;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_FIND_ITEM:
	case SSDFS_BTREE_SEARCH_ALLOCATE_ITEM:
	case SSDFS_BTREE_SEARCH_ALLOCATE_RANGE:
	case SSDFS_BTREE_SEARCH_ADD_ITEM:
	case SSDFS_BTREE_SEARCH_ADD_RANGE:
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -EINVAL;
	}

try_next_search:
	err = ssdfs_btree_find_leaf_node(tree, search);
	if (err == -EEXIST) {
		err = 0;
		/* try to find an item */
	} else if (err == -ENOENT) {
		err = -ENODATA;
		search->result.state = SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE;
		SSDFS_DBG("index node was found\n");
		goto finish_search_item;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find leaf node: err %d\n",
			  err);
		goto finish_search_item;
	}

	if (search->request.type == SSDFS_BTREE_SEARCH_ADD_ITEM) {
try_another_node:
		err = ssdfs_btree_node_find_item(search);
		if (node_needs_in_additional_check(err, search)) {
			err = ssdfs_btree_switch_on_hybrid_parent_node(tree,
									search);
			if (err == -ENODATA)
				goto finish_search_item;
			else if (unlikely(err)) {
				SSDFS_ERR("fail to switch on parent node: "
					  "err %d\n", err);
				goto finish_search_item;
			} else
				goto try_another_node;
		} else if (err == -EACCES) {
			struct ssdfs_btree_node *node = search->node.child;

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

			res = wait_for_completion_timeout(&node->init_end,
							SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("node init failed: "
					  "err %d\n", err);
				goto finish_search_item;
			} else
				goto try_another_node;
		}
	} else {
try_find_item_again:
		err = ssdfs_btree_node_find_item(search);
		if (err == -EACCES) {
			struct ssdfs_btree_node *node = search->node.child;

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

			res = wait_for_completion_timeout(&node->init_end,
							SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("node init failed: "
					  "err %d\n", err);
				goto finish_search_item;
			} else
				goto try_find_item_again;
		}
	}

	if (err == -EAGAIN) {
		err = 0;
		search->node.state = SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY;
		goto try_next_search;
	} else if (err == -ENODATA) {
		SSDFS_DBG("unable to find item: "
			  "start_hash %llx, end_hash %llx\n",
			  search->request.start.hash,
			  search->request.end.hash);
		goto finish_search_item;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find item: "
			  "start_hash %llx, end_hash %llx, "
			  "err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_search_item;
	}

finish_search_item:
	return err;
}

/*
 * ssdfs_btree_find_item() - find item into btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to find an item into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - item hasn't been found
 */
int ssdfs_btree_find_item(struct ssdfs_btree *tree,
			  struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, type %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	down_read(&tree->lock);
	err = __ssdfs_btree_find_item(tree, search);
	up_read(&tree->lock);

	return err;
}

/*
 * __ssdfs_btree_find_range() - find a range of items into btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to find a range of item into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_btree_find_range(struct ssdfs_btree *tree,
			     struct ssdfs_btree_search *search)
{
	int tree_state;
	unsigned long res;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type, tree_state,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (!is_btree_search_request_valid(search)) {
		SSDFS_ERR("invalid search object\n");
		return -EINVAL;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_FIND_RANGE:
	case SSDFS_BTREE_SEARCH_ADD_RANGE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -EINVAL;
	}

try_next_search:
	err = ssdfs_btree_find_leaf_node(tree, search);
	if (err == -EEXIST) {
		err = 0;
		/* try to find an item */
	} else if (err == -ENOENT) {
		err = -ENODATA;
		search->result.state = SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE;
		SSDFS_DBG("index node was found\n");
		goto finish_search_range;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find leaf node: err %d\n",
			  err);
		goto finish_search_range;
	}

	if (search->request.type == SSDFS_BTREE_SEARCH_ADD_RANGE) {
try_another_node:
		err = ssdfs_btree_node_find_range(search);

		if (node_needs_in_additional_check(err, search)) {
			err = ssdfs_btree_switch_on_hybrid_parent_node(tree,
									search);
			if (err == -ENODATA)
				goto finish_search_range;
			else if (unlikely(err)) {
				SSDFS_ERR("fail to switch on parent node: "
					  "err %d\n", err);
				goto finish_search_range;
			} else
				goto try_another_node;
		} else if (err == -EACCES) {
			struct ssdfs_btree_node *node = search->node.child;

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

			res = wait_for_completion_timeout(&node->init_end,
							SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("node init failed: "
					  "err %d\n", err);
				goto finish_search_range;
			} else
				goto try_another_node;
		}
	} else {
try_find_range_again:
		err = ssdfs_btree_node_find_range(search);
		if (err == -EACCES) {
			struct ssdfs_btree_node *node = search->node.child;

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

			res = wait_for_completion_timeout(&node->init_end,
							SSDFS_DEFAULT_TIMEOUT);
			if (res == 0) {
				err = -ERANGE;
				SSDFS_ERR("node init failed: "
					  "err %d\n", err);
				goto finish_search_range;
			} else
				goto try_find_range_again;
		}
	}

	if (err == -EAGAIN) {
		err = 0;
		search->node.state = SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY;
		goto try_next_search;
	} else if (err == -ENODATA) {
		SSDFS_DBG("unable to find range: "
			  "start_hash %llx, end_hash %llx\n",
			  search->request.start.hash,
			  search->request.end.hash);
		goto finish_search_range;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find range: "
			  "start_hash %llx, end_hash %llx, "
			  "err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_search_range;
	}

finish_search_range:
	return err;
}

/*
 * ssdfs_btree_find_range() - find a range of items into btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to find a range of item into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_find_range(struct ssdfs_btree *tree,
			   struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, type %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	down_read(&tree->lock);
	err = __ssdfs_btree_find_range(tree, search);
	up_read(&tree->lock);

	return err;
}

/*
 * ssdfs_btree_allocate_item() - allocate item into btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to allocate the item into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_allocate_item(struct ssdfs_btree *tree,
			      struct ssdfs_btree_search *search)
{
	int tree_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type, tree_state,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (!is_btree_search_request_valid(search)) {
		SSDFS_ERR("invalid search object\n");
		return -EINVAL;
	}

	if (search->request.type != SSDFS_BTREE_SEARCH_ALLOCATE_ITEM) {
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -EINVAL;
	}

	down_read(&tree->lock);

try_next_search:
	err = ssdfs_btree_find_leaf_node(tree, search);
	if (err == -EEXIST) {
		err = 0;
		/* try the old search result */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find leaf node: err %d\n",
			  err);
		goto finish_allocate_item;
	}

try_allocate_item:
	err = ssdfs_btree_node_allocate_item(search);
	if (err == -EAGAIN) {
		err = 0;
		search->node.state = SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY;
		goto try_next_search;
	} else if (err == -EACCES) {
		struct ssdfs_btree_node *node = search->node.child;
		unsigned long res;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

		res = wait_for_completion_timeout(&node->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("node init failed: "
				  "err %d\n", err);
			goto finish_allocate_item;
		} else
			goto try_allocate_item;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to allocate item: "
			  "start_hash %llx, end_hash %llx, "
			  "err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_allocate_item;
	}

	atomic_set(&tree->state, SSDFS_BTREE_DIRTY);

finish_allocate_item:
	up_read(&tree->lock);
	return err;
}

/*
 * ssdfs_btree_allocate_range() - allocate range of items into btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to allocate the range of items into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_allocate_range(struct ssdfs_btree *tree,
				struct ssdfs_btree_search *search)
{
	int tree_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type, tree_state,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (!is_btree_search_request_valid(search)) {
		SSDFS_ERR("invalid search object\n");
		return -EINVAL;
	}

	if (search->request.type != SSDFS_BTREE_SEARCH_ALLOCATE_RANGE) {
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -EINVAL;
	}

	down_read(&tree->lock);

try_next_search:
	err = ssdfs_btree_find_leaf_node(tree, search);
	if (err == -EEXIST) {
		err = 0;
		/* try the old search result */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find leaf node: err %d\n",
			  err);
		goto finish_allocate_range;
	}

try_allocate_range:
	err = ssdfs_btree_node_allocate_range(search);
	if (err == -EAGAIN) {
		err = 0;
		search->node.state = SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY;
		goto try_next_search;
	} else if (err == -EACCES) {
		struct ssdfs_btree_node *node = search->node.child;
		unsigned long res;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

		res = wait_for_completion_timeout(&node->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("node init failed: "
				  "err %d\n", err);
			goto finish_allocate_range;
		} else
			goto try_allocate_range;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to allocate range: "
			  "start_hash %llx, end_hash %llx, "
			  "err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_allocate_range;
	}

	atomic_set(&tree->state, SSDFS_BTREE_DIRTY);

finish_allocate_range:
	up_read(&tree->lock);
	return err;
}

/*
 * ssdfs_btree_add_item() - add item into btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to add the item into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - item exists in the tree.
 */
int ssdfs_btree_add_item(struct ssdfs_btree *tree,
			 struct ssdfs_btree_search *search)
{
	int tree_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type, tree_state,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (!is_btree_search_request_valid(search)) {
		SSDFS_ERR("invalid search object\n");
		return -EINVAL;
	}

	if (search->request.type != SSDFS_BTREE_SEARCH_ADD_ITEM) {
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -EINVAL;
	}

	down_read(&tree->lock);

try_find_item:
	err = __ssdfs_btree_find_item(tree, search);
	if (!err) {
		err = -EEXIST;
		SSDFS_ERR("item exists in the tree: "
			  "start_hash %llx, end_hash %llx\n",
			  search->request.start.hash,
			  search->request.end.hash);
		goto finish_add_item;
	} else if (err == -ENODATA) {
		err = 0;
		switch (search->result.state) {
		case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
			/* position in node was found */
			break;
		case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
			/* none node is able to store the new item */
			break;
		default:
			err = -ERANGE;
			SSDFS_ERR("invalid search result: "
				  "start_hash %llx, end_hash %llx, "
				  "state %#x\n",
				  search->request.start.hash,
				  search->request.end.hash,
				  search->result.state);
			goto finish_add_item;
		};
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find item: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_add_item;
	}

	if (search->result.state == SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE) {
		up_read(&tree->lock);
		err = ssdfs_btree_insert_node(tree, search);
		down_read(&tree->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to insert node: err %d\n",
				  err);
			goto finish_add_item;
		}

		err = __ssdfs_btree_find_item(tree, search);
		if (!err) {
			err = -EEXIST;
			SSDFS_ERR("item exists in the tree: "
				  "start_hash %llx, end_hash %llx\n",
				  search->request.start.hash,
				  search->request.end.hash);
			goto finish_add_item;
		} else if (err == -ENODATA) {
			err = 0;
			switch (search->result.state) {
			case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
				/* position in node was found */
				break;
			default:
				err = -ERANGE;
				SSDFS_ERR("invalid search result: "
					  "start_hash %llx, end_hash %llx, "
					  "state %#x\n",
					  search->request.start.hash,
					  search->request.end.hash,
					  search->result.state);
				goto finish_add_item;
			};
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find item: "
				  "start_hash %llx, end_hash %llx, err %d\n",
				  search->request.start.hash,
				  search->request.end.hash,
				  err);
			goto finish_add_item;
		}
	}

try_insert_item:
	err = ssdfs_btree_node_insert_item(search);
	if (err == -EACCES) {
		struct ssdfs_btree_node *node = search->node.child;
		unsigned long res;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

		res = wait_for_completion_timeout(&node->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("node init failed: "
				  "err %d\n", err);
			goto finish_add_item;
		} else
			goto try_insert_item;
	} else if (err == -EFBIG) {
		int state = search->result.state;

		err = 0;

		if (state != SSDFS_BTREE_SEARCH_PLEASE_MOVE_BUF_CONTENT) {
			err = -ERANGE;
			SSDFS_WARN("invalid search's result state %#x\n",
				   state);
			goto finish_add_item;
		} else
			goto try_find_item;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to insert item: "
			  "start_hash %llx, end_hash %llx, "
			  "err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_add_item;
	}

	atomic_set(&tree->state, SSDFS_BTREE_DIRTY);

finish_add_item:
	up_read(&tree->lock);
	return err;
}

/*
 * ssdfs_btree_add_range() - add a range of items into btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to add the range of items into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - range exists in the tree.
 */
int ssdfs_btree_add_range(struct ssdfs_btree *tree,
			  struct ssdfs_btree_search *search)
{
	int tree_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type, tree_state,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (!is_btree_search_request_valid(search)) {
		SSDFS_ERR("invalid search object\n");
		return -EINVAL;
	}

	if (search->request.type != SSDFS_BTREE_SEARCH_ADD_RANGE) {
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -EINVAL;
	}

	down_read(&tree->lock);

try_find_range:
	err = __ssdfs_btree_find_range(tree, search);
	if (!err) {
		err = -EEXIST;
		SSDFS_ERR("range exists in the tree: "
			  "start_hash %llx, end_hash %llx\n",
			  search->request.start.hash,
			  search->request.end.hash);
		goto finish_add_range;
	} else if (err == -ENODATA) {
		err = 0;
		switch (search->result.state) {
		case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
			/* position in node was found */
			break;
		case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
			/* none node is able to store the new range */
			break;
		default:
			err = -ERANGE;
			SSDFS_ERR("invalid search result: "
				  "start_hash %llx, end_hash %llx, "
				  "state %#x\n",
				  search->request.start.hash,
				  search->request.end.hash,
				  search->result.state);
			goto finish_add_range;
		};
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find range: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_add_range;
	}

	if (search->result.state == SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE) {
		up_read(&tree->lock);
		err = ssdfs_btree_insert_node(tree, search);
		down_read(&tree->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to insert node: err %d\n",
				  err);
			goto finish_add_range;
		}

		err = __ssdfs_btree_find_range(tree, search);
		if (!err) {
			err = -EEXIST;
			SSDFS_ERR("range exists in the tree: "
				  "start_hash %llx, end_hash %llx\n",
				  search->request.start.hash,
				  search->request.end.hash);
			goto finish_add_range;
		} else if (err == -ENODATA) {
			err = 0;
			switch (search->result.state) {
			case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
			case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
				/* position in node was found */
				break;
			default:
				err = -ERANGE;
				SSDFS_ERR("invalid search result: "
					  "start_hash %llx, end_hash %llx, "
					  "state %#x\n",
					  search->request.start.hash,
					  search->request.end.hash,
					  search->result.state);
				goto finish_add_range;
			};
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find range: "
				  "start_hash %llx, end_hash %llx, err %d\n",
				  search->request.start.hash,
				  search->request.end.hash,
				  err);
			goto finish_add_range;
		}
	}

try_insert_range:
	err = ssdfs_btree_node_insert_range(search);
	if (err == -EAGAIN) {
		err = 0;
		goto try_find_range;
	} else if (err == -EACCES) {
		struct ssdfs_btree_node *node = search->node.child;
		unsigned long res;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

		res = wait_for_completion_timeout(&node->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("node init failed: "
				  "err %d\n", err);
			goto finish_add_range;
		} else
			goto try_insert_range;
	} else if (err == -EFBIG) {
		int state = search->result.state;

		err = 0;

		if (state != SSDFS_BTREE_SEARCH_PLEASE_MOVE_BUF_CONTENT) {
			err = -ERANGE;
			SSDFS_WARN("invalid search's result state %#x\n",
				   state);
			goto finish_add_range;
		} else
			goto try_find_range;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to insert item: "
			  "start_hash %llx, end_hash %llx, "
			  "err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_add_range;
	}

	atomic_set(&tree->state, SSDFS_BTREE_DIRTY);

finish_add_range:
	up_read(&tree->lock);
	return err;
}

/*
 * need_update_parent_node() - check necessity to update index in parent node
 * @search: search object
 */
static inline
bool need_update_parent_node(struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *parent;
	u64 start_hash;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	start_hash = search->request.start.hash;

	parent = search->node.parent;
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!parent);
#endif /* CONFIG_SSDFS_DEBUG */

	return need_update_parent_index_area(start_hash, parent);
}

/*
 * ssdfs_btree_update_index_in_parent_node() - update index in parent node
 * @tree: btree object
 * @search: search object [in|out]
 * @ptr: hierarchy object
 *
 * This method tries to update an index in parent nodes.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_update_index_in_parent_node(struct ssdfs_btree *tree,
					    struct ssdfs_btree_search *search,
					    struct ssdfs_btree_hierarchy *ptr)
{
	int cur_height, tree_height;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !ptr);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, hierarchy %p\n",
		  tree, ptr);

	tree_height = atomic_read(&tree->height);
	if (tree_height <= 0) {
		SSDFS_ERR("invalid tree_height %u\n",
			  tree_height);
		return -ERANGE;
	}

	for (cur_height = 0; cur_height < tree_height; cur_height++) {
		err = ssdfs_btree_process_level_for_update(ptr,
							   cur_height,
							   search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to process the tree's level: "
				  "cur_height %u, err %d\n",
				  cur_height, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_change_item() - change an existing item in the btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to change the existing item in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_change_item(struct ssdfs_btree *tree,
			    struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_hierarchy *hierarchy = NULL;
	int tree_state;
	int tree_height;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type, tree_state,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (!is_btree_search_request_valid(search)) {
		SSDFS_ERR("invalid search object\n");
		return -EINVAL;
	}

	if (search->request.type != SSDFS_BTREE_SEARCH_CHANGE_ITEM) {
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -EINVAL;
	}

	tree_height = atomic_read(&tree->height);
	if (tree_height <= 0) {
		SSDFS_ERR("invalid tree_height %u\n",
			  tree_height);
		return -ERANGE;
	}

	hierarchy = ssdfs_btree_hierarchy_allocate(tree);
	if (!hierarchy) {
		SSDFS_ERR("fail to allocate tree levels' array\n");
		return -ENOMEM;
	}

	down_read(&tree->lock);

try_next_search:
	err = ssdfs_btree_find_leaf_node(tree, search);
	if (err == -EEXIST) {
		err = 0;
		/* try the old search result */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find leaf node: err %d\n",
			  err);
		goto finish_change_item;
	}

try_change_item:
	err = ssdfs_btree_node_change_item(search);
	if (err == -EAGAIN) {
		err = 0;
		search->node.state = SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY;
		goto try_next_search;
	} else if (err == -EACCES) {
		struct ssdfs_btree_node *node = search->node.child;
		unsigned long res;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

		res = wait_for_completion_timeout(&node->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("node init failed: "
				  "err %d\n", err);
			goto finish_change_item;
		} else
			goto try_change_item;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to change item: "
			  "start_hash %llx, end_hash %llx, "
			  "err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_change_item;
	}

	if (need_update_parent_node(search)) {
		err = ssdfs_btree_check_hierarchy_for_update(tree, search,
								hierarchy);
		if (unlikely(err)) {
			atomic_set(&search->node.child->state,
				    SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to prepare hierarchy information : "
				  "err %d\n",
				  err);
			goto finish_change_item;
		}

		err = ssdfs_btree_update_index_in_parent_node(tree, search,
							      hierarchy);
		if (unlikely(err)) {
			SSDFS_ERR("fail to update index records: "
				  "err %d\n",
				  err);
			goto finish_change_item;
		}
	}

	atomic_set(&tree->state, SSDFS_BTREE_DIRTY);

finish_change_item:
	up_read(&tree->lock);
	ssdfs_btree_hierarchy_free(hierarchy);
	return err;
}

/*
 * ssdfs_btree_delete_item() - delete an existing item in the btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to delete the existing item in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_delete_item(struct ssdfs_btree *tree,
			    struct ssdfs_btree_search *search)
{
	int tree_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type, tree_state,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (!is_btree_search_request_valid(search)) {
		SSDFS_ERR("invalid search object\n");
		return -EINVAL;
	}

	if (search->request.type != SSDFS_BTREE_SEARCH_DELETE_ITEM) {
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -EINVAL;
	}

	down_read(&tree->lock);

	err = __ssdfs_btree_find_item(tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find item: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_delete_item;
	}

try_delete_item:
	err = ssdfs_btree_node_delete_item(search);
	if (err == -EACCES) {
		struct ssdfs_btree_node *node = search->node.child;
		unsigned long res;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

		res = wait_for_completion_timeout(&node->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("node init failed: "
				  "err %d\n", err);
			goto finish_delete_item;
		} else
			goto try_delete_item;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to delete item: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		goto finish_delete_item;
	}

finish_delete_item:
	up_read(&tree->lock);

	if (unlikely(err))
		return err;

	if (search->result.state == SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE) {
		err = ssdfs_btree_delete_node(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to delete btree node: "
				  "node_id %llu, err %d\n",
				  (u64)search->node.id, err);
			return err;
		}
	}

	atomic_set(&tree->state, SSDFS_BTREE_DIRTY);

	return 0;
}

/*
 * ssdfs_btree_delete_range() - delete a range of items in the btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to delete a range of existing items in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_delete_range(struct ssdfs_btree *tree,
			     struct ssdfs_btree_search *search)
{
	int tree_state;
	bool need_continue_deletion = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "request->type %#x, request->flags %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, tree->type, tree_state,
		  search->request.type, search->request.flags,
		  search->request.start.hash,
		  search->request.end.hash);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (!is_btree_search_request_valid(search)) {
		SSDFS_ERR("invalid search object\n");
		return -EINVAL;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid request type %#x\n",
			  search->request.type);
		return -EINVAL;
	}

try_delete_next_range:
	down_read(&tree->lock);

	err = __ssdfs_btree_find_range(tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find range: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		up_read(&tree->lock);
		return err;
	}

try_delete_range_again:
	err = ssdfs_btree_node_delete_range(search);
	if (err == -EACCES) {
		struct ssdfs_btree_node *node = search->node.child;
		unsigned long res;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

		res = wait_for_completion_timeout(&node->init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("node init failed: "
				  "err %d\n", err);
			goto finish_delete_range;
		} else
			goto try_delete_range_again;
	}

finish_delete_range:
	up_read(&tree->lock);

	if (err == -EAGAIN) {
		/* the range have to be deleted in the next node */
		err = 0;
		need_continue_deletion = true;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to delete range: "
			  "start_hash %llx, end_hash %llx, err %d\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
		return err;
	}

	if (search->result.state == SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE) {
		err = ssdfs_btree_delete_node(tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to delete btree node: "
				  "node_id %llu, err %d\n",
				  (u64)search->node.id, err);
			return err;
		}
	}

	if (need_continue_deletion) {
		need_continue_deletion = false;
		goto try_delete_next_range;
	}

	atomic_set(&tree->state, SSDFS_BTREE_DIRTY);

	return 0;
}

/*
 * ssdfs_btree_delete_all() - delete all items in the btree
 * @tree: btree object
 * @search: search object [in|out]
 *
 * This method tries to delete all items in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_delete_all(struct ssdfs_btree *tree)
{
	struct ssdfs_btree_search *search;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);

	search->request.type = SSDFS_BTREE_SEARCH_DELETE_ALL;
	search->request.start.hash = 0;
	search->request.end.hash = U64_MAX;

	err = ssdfs_btree_delete_range(tree, search);
	if (unlikely(err))
		SSDFS_ERR("fail to delete all items: err %d\n", err);

	ssdfs_btree_search_free(search);
	return err;
}

/*
 * ssdfs_btree_get_head_range() - extract head range of the tree
 * @tree: btree object
 * @expected_len: expected length of the range
 * @search: search object
 *
 * This method tries to extract a head range of items from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_get_head_range(struct ssdfs_btree *tree,
				u32 expected_len,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node;
	struct ssdfs_btree_index_key key;
	int tree_state;
	u64 hash;
	u32 buf_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "expected_len %u\n",
		  tree, tree->type, tree_state,
		  expected_len);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	down_read(&tree->lock);

	err = ssdfs_btree_radix_tree_find(tree,
					  SSDFS_BTREE_ROOT_NODE_ID,
					  &node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find root node: err %d\n",
			  err);
		goto finish_get_range;
	} else if (!node) {
		err = -ERANGE;
		SSDFS_ERR("node is NULL\n");
		goto finish_get_range;
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
		err = -ERANGE;
		SSDFS_WARN("root node hasn't index area\n");
		goto finish_get_range;
	}

	if (is_ssdfs_btree_node_index_area_empty(node))
		goto finish_get_range;

	err = __ssdfs_btree_root_node_extract_index(node,
						SSDFS_ROOT_NODE_LEFT_LEAF_NODE,
						&key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get index: err %d\n",
			  err);
		goto finish_get_range;
	}

	hash = le64_to_cpu(key.index.hash);
	if (hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid hash\n");
		goto finish_get_range;
	}

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
	search->request.flags = SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
				SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
	search->request.start.hash = hash;
	search->request.end.hash = hash;
	search->request.count = 1;

	err = __ssdfs_btree_find_item(tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the item: "
			  "hash %llx, err %d\n",
			  hash, err);
		goto finish_get_range;
	}

	buf_size = expected_len * tree->max_item_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(expected_len >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_node_extract_range(search->result.start_index,
					     (u16)expected_len,
					     search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the range: "
			  "start_index %u, expected_len %u, err %d\n",
			  search->result.start_index,
			  expected_len, err);
		goto finish_get_range;
	}

	if (expected_len != search->result.count) {
		err = -ERANGE;
		SSDFS_ERR("expected_len %u != search->result.count %u\n",
			  expected_len, search->result.count);
		goto finish_get_range;
	}

finish_get_range:
	up_read(&tree->lock);

	return err;
}

/*
 * ssdfs_btree_extract_range() - extract range from the node
 * @tree: btree object
 * @start_index: start index in the node
 * @count: count of items in the range
 * @search: search object
 *
 * This method tries to extract a range of items from the found node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_extract_range(struct ssdfs_btree *tree,
				u16 start_index, u16 count,
				struct ssdfs_btree_search *search)
{
	int tree_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x, "
		  "start_index %u, count %u\n",
		  tree, tree->type, tree_state,
		  start_index, count);

	ssdfs_debug_btree_object(tree);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	down_read(&tree->lock);

	err = ssdfs_btree_node_extract_range(start_index, count,
					     search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the range: "
			  "start_index %u, count %u, err %d\n",
			  start_index, count, err);
		goto finish_get_range;
	}

finish_get_range:
	up_read(&tree->lock);

	return err;
}

/*
 * is_ssdfs_btree_empty() - check that btree is empty
 * @tree: btree object
 */
bool is_ssdfs_btree_empty(struct ssdfs_btree *tree)
{
	struct ssdfs_btree_node *node;
	struct ssdfs_btree_index_key key1, key2;
	int tree_state;
	u32 node_id1, node_id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, type %#x, state %#x\n",
		  tree, tree->type, tree_state);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	down_read(&tree->lock);

	err = ssdfs_btree_radix_tree_find(tree,
					  SSDFS_BTREE_ROOT_NODE_ID,
					  &node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find root node: err %d\n",
			  err);
		goto finish_check_tree;
	} else if (!node) {
		err = -ERANGE;
		SSDFS_ERR("node is NULL\n");
		goto finish_check_tree;
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
		err = -ERANGE;
		SSDFS_WARN("root node hasn't index area\n");
		goto finish_check_tree;
	}

	if (is_ssdfs_btree_node_index_area_empty(node))
		goto finish_check_tree;

	err = __ssdfs_btree_root_node_extract_index(node,
						SSDFS_ROOT_NODE_LEFT_LEAF_NODE,
						&key1);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get index: err %d\n",
			  err);
		goto finish_check_tree;
	}

	node_id1 = le32_to_cpu(key1.node_id);
	if (node_id1 == SSDFS_BTREE_NODE_INVALID_ID) {
		SSDFS_WARN("index is invalid\n");
		goto finish_check_tree;
	}

	err = __ssdfs_btree_root_node_extract_index(node,
						SSDFS_ROOT_NODE_RIGHT_LEAF_NODE,
						&key2);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get index: err %d\n",
			  err);
		goto finish_check_tree;
	}

	node_id2 = le32_to_cpu(key2.node_id);
	if (node_id2 != SSDFS_BTREE_NODE_INVALID_ID) {
		err = -EEXIST;
		goto finish_check_tree;
	}

	err = ssdfs_btree_radix_tree_find(tree, node_id1, &node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find node: node_id %u, err %d\n",
			  node_id1, err);
		goto finish_check_tree;
	} else if (!node) {
		err = -ERANGE;
		SSDFS_ERR("node is NULL\n");
		goto finish_check_tree;
	}

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_LEAF_NODE:
		if (!is_ssdfs_btree_node_items_area_empty(node)) {
			err = -EEXIST;
			goto finish_check_tree;
		} else {
			/* empty node */
			goto finish_check_tree;
		}
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		if (!is_ssdfs_btree_node_items_area_empty(node)) {
			err = -EEXIST;
			goto finish_check_tree;
		} else if (!is_ssdfs_btree_node_index_area_empty(node)) {
			err = -EEXIST;
			goto finish_check_tree;
		} else {
			/* empty node */
			goto finish_check_tree;
		}
		break;

	case SSDFS_BTREE_INDEX_NODE:
		err = -EEXIST;
		goto finish_check_tree;

	case SSDFS_BTREE_ROOT_NODE:
		err = -ERANGE;
		SSDFS_WARN("node %u has root node type\n",
			   node_id1);
		goto finish_check_tree;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid node type %#x\n",
			  atomic_read(&node->type));
		goto finish_check_tree;
	}

finish_check_tree:
	up_read(&tree->lock);

	return err ? false : true;
}

/*
 * ssdfs_btree_synchronize_root_node() - synchronize root node state
 * @tree: btree object
 * @root: root node
 */
int ssdfs_btree_synchronize_root_node(struct ssdfs_btree *tree,
				struct ssdfs_btree_inline_root_node *root)
{
	int tree_state;
	struct ssdfs_btree_node *node;
	u16 items_count;
	int height;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !root);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_state = atomic_read(&tree->state);

	SSDFS_DBG("tree %p, root %p, type %#x, state %#x\n",
		  tree, root, tree->type, tree_state);

	switch (tree_state) {
	case SSDFS_BTREE_CREATED:
	case SSDFS_BTREE_DIRTY:
		/* expected state */
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid tree state %#x\n",
			   tree_state);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	down_read(&tree->lock);

	err = ssdfs_btree_radix_tree_find(tree,
					  SSDFS_BTREE_ROOT_NODE_ID,
					  &node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find root node: err %d\n",
			  err);
		goto finish_synchronize_root;
	} else if (!node) {
		err = -ERANGE;
		SSDFS_ERR("node is NULL\n");
		goto finish_synchronize_root;
	}

	down_read(&node->header_lock);
	height = atomic_read(&node->tree->height);
	root->header.height = (u8)height;
	items_count = node->index_area.index_count;
	root->header.items_count = cpu_to_le16(items_count);
	root->header.flags = (u8)atomic_read(&node->flags);
	root->header.type = (u8)atomic_read(&node->type);
	memcpy(root->header.node_ids,
		node->raw.root_node.header.node_ids,
		sizeof(__le32) * SSDFS_BTREE_ROOT_NODE_INDEX_COUNT);
	memcpy(root->indexes, node->raw.root_node.indexes,
		sizeof(struct ssdfs_btree_index) *
		SSDFS_BTREE_ROOT_NODE_INDEX_COUNT);
	up_read(&node->header_lock);

	spin_lock(&node->tree->nodes_lock);
	root->header.upper_node_id =
		cpu_to_le32(node->tree->upper_node_id);
	spin_unlock(&node->tree->nodes_lock);

finish_synchronize_root:
	up_read(&tree->lock);

	return err;
}

void ssdfs_debug_btree_object(struct ssdfs_btree *tree)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct radix_tree_iter iter;
	void **slot;
	struct ssdfs_btree_node *node;

	BUG_ON(!tree);

	SSDFS_DBG("STATIC DATA: "
		  "type %#x, owner_ino %llu, node_size %u, "
		  "pages_per_node %u, node_ptr_size %u, "
		  "index_size %u, item_size %u, "
		  "min_item_size %u, max_item_size %u, "
		  "index_area_min_size %u, create_cno %llu, "
		  "fsi %p\n",
		  tree->type, tree->owner_ino,
		  tree->node_size, tree->pages_per_node,
		  tree->node_ptr_size, tree->index_size,
		  tree->item_size, tree->min_item_size,
		  tree->max_item_size, tree->index_area_min_size,
		  tree->create_cno, tree->fsi);

	SSDFS_DBG("OPERATIONS: "
		  "desc_ops %p, btree_ops %p\n",
		  tree->desc_ops, tree->btree_ops);

	SSDFS_DBG("MUTABLE DATA: "
		  "state %#x, flags %#x, height %d, "
		  "upper_node_id %u\n",
		  atomic_read(&tree->state),
		  atomic_read(&tree->flags),
		  atomic_read(&tree->height),
		  tree->upper_node_id);

	SSDFS_DBG("tree->lock %d, nodes_lock %d\n",
		  rwsem_is_locked(&tree->lock),
		  spin_is_locked(&tree->nodes_lock));

	rcu_read_lock();
	radix_tree_for_each_slot(slot, &tree->nodes, &iter,
				 SSDFS_BTREE_ROOT_NODE_ID) {
		node =
		    (struct ssdfs_btree_node *)radix_tree_deref_slot(slot);

		if (node) {
			SSDFS_DBG("NODE: node_id %u, state %#x, "
				  "type %#x, height %d, refs_count %d\n",
				  node->node_id,
				  atomic_read(&node->state),
				  atomic_read(&node->type),
				  atomic_read(&node->height),
				  atomic_read(&node->refs_count));
		}
	}
	rcu_read_unlock();
#endif /* CONFIG_SSDFS_DEBUG */
}
