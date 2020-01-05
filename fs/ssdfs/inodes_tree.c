//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/inodes_tree.c - inodes btree implementation.
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
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "inodes_tree.h"

static struct kmem_cache *ssdfs_free_ino_desc_cachep;

static
void ssdfs_init_free_ino_desc_once(void *obj)
{
	struct ssdfs_inodes_btree_range *range_desc = obj;

	memset(range_desc, 0, sizeof(struct ssdfs_inodes_btree_range));
}

void ssdfs_destroy_free_ino_desc_cache(void)
{
	if (ssdfs_free_ino_desc_cachep)
		kmem_cache_destroy(ssdfs_free_ino_desc_cachep);
}

int ssdfs_init_free_ino_desc_cache(void)
{
	ssdfs_free_ino_desc_cachep =
			kmem_cache_create("ssdfs_free_ino_desc_cache",
				sizeof(struct ssdfs_inodes_btree_range), 0,
				SLAB_RECLAIM_ACCOUNT |
				SLAB_MEM_SPREAD |
				SLAB_ACCOUNT,
				ssdfs_init_free_ino_desc_once);
	if (!ssdfs_free_ino_desc_cachep) {
		SSDFS_ERR("unable to create free inode descriptors cache\n");
		return -ENOMEM;
	}

	return 0;
}

/******************************************************************************
 *                      FREE INODES RANGE FUNCTIONALITY                       *
 ******************************************************************************/

/*
 * ssdfs_free_inodes_range_alloc() - allocate memory for free inodes range
 */
struct ssdfs_inodes_btree_range *ssdfs_free_inodes_range_alloc(void)
{
	struct ssdfs_inodes_btree_range *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_free_ino_desc_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = kmem_cache_alloc(ssdfs_free_ino_desc_cachep, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for free inodes range\n");
		return ERR_PTR(-ENOMEM);
	}

	return ptr;
}

/*
 * ssdfs_free_inodes_range_free() - free memory for free inodes range
 */
void ssdfs_free_inodes_range_free(struct ssdfs_inodes_btree_range *range)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_free_ino_desc_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!range)
		return;

	kmem_cache_free(ssdfs_free_ino_desc_cachep, range);
}

/*
 * ssdfs_free_inodes_range_init() - init free inodes range
 * @range: free inodes range object [out]
 */
void ssdfs_free_inodes_range_init(struct ssdfs_inodes_btree_range *range)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!range);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(range, 0, sizeof(struct ssdfs_inodes_btree_range));

	INIT_LIST_HEAD(&range->list);
	range->node_id = SSDFS_BTREE_NODE_INVALID_ID;
	range->area.start_hash = SSDFS_INODES_RANGE_INVALID_START;
	range->area.start_index = SSDFS_INODES_RANGE_INVALID_INDEX;
}

/******************************************************************************
 *                      FREE INODES QUEUE FUNCTIONALITY                       *
 ******************************************************************************/

/*
 * ssdfs_free_inodes_queue_init() - initialize free inodes queue
 * @q: free inodes queue [out]
 */
static
void ssdfs_free_inodes_queue_init(struct ssdfs_free_inode_range_queue *q)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!q);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->list);
}

/*
 * is_ssdfs_free_inodes_queue_empty() - check that free inodes queue is empty
 * @q: free inodes queue
 */
static
bool is_ssdfs_free_inodes_queue_empty(struct ssdfs_free_inode_range_queue *q)
{
	bool is_empty;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!q);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&q->lock);
	is_empty = list_empty_careful(&q->list);
	spin_unlock(&q->lock);

	return is_empty;
}

/*
 * ssdfs_free_inodes_queue_add_head() - add range at the head of queue
 * @q: free inodes queue
 * @range: free inodes range
 */
static void
ssdfs_free_inodes_queue_add_head(struct ssdfs_free_inode_range_queue *q,
				 struct ssdfs_inodes_btree_range *range)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!q || !range);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&q->lock);
	list_add(&range->list, &q->list);
	spin_unlock(&q->lock);
}

/*
 * ssdfs_free_inodes_queue_add_tail() - add range at the tail of queue
 * @q: free inodes queue
 * @range: free inodes range
 */
static void
ssdfs_free_inodes_queue_add_tail(struct ssdfs_free_inode_range_queue *q,
				 struct ssdfs_inodes_btree_range *range)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!q || !range);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&q->lock);
	list_add_tail(&range->list, &q->list);
	spin_unlock(&q->lock);
}

/*
 * ssdfs_free_inodes_queue_get_first() - get first free inodes range
 * @q: free inodes queue
 * @range: pointer on value that stores range pointer [out]
 *
 * This method tries to retrieve the first free inode's index from
 * queue of free inode ranges.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - queue is empty.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_free_inodes_queue_get_first(struct ssdfs_free_inode_range_queue *q,
				      struct ssdfs_inodes_btree_range **range)
{
	struct ssdfs_inodes_btree_range *first = NULL, *tmp = NULL;
	bool is_empty = true;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!q || !range);
#endif /* CONFIG_SSDFS_DEBUG */

	tmp = ssdfs_free_inodes_range_alloc();
	if (!tmp) {
		SSDFS_ERR("fail to allocate free inodes range\n");
		return -ERANGE;
	}

	ssdfs_free_inodes_range_init(tmp);

	spin_lock(&q->lock);

	is_empty = list_empty_careful(&q->list);
	if (!is_empty) {
		first = list_first_entry_or_null(&q->list,
						struct ssdfs_inodes_btree_range,
						list);
		if (!first) {
			err = -ENOENT;
			SSDFS_WARN("first entry is NULL\n");
			goto finish_get_first;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			if (first->node_id == SSDFS_BTREE_NODE_INVALID_ID) {
				err = -ERANGE;
				SSDFS_ERR("invalid node ID\n");
				goto finish_get_first;
			}

			if (first->area.start_hash ==
					SSDFS_INODES_RANGE_INVALID_START) {
				err = -ERANGE;
				SSDFS_ERR("invalid start index\n");
				goto finish_get_first;
			}

			if (first->area.count == 0) {
				err = -ERANGE;
				SSDFS_ERR("empty range\n");
				goto finish_get_first;
			}
#endif /* CONFIG_SSDFS_DEBUG */

			tmp->node_id = first->node_id;
			tmp->area.start_hash = first->area.start_hash;
			tmp->area.start_index = first->area.start_index;
			tmp->area.count = 1;

			first->area.start_hash += 1;
			first->area.start_index += 1;
			first->area.count -= 1;

			if (first->area.count == 0)
				list_del(&first->list);
		}
	}

finish_get_first:
	spin_unlock(&q->lock);

	if (unlikely(err)) {
		ssdfs_free_inodes_range_free(tmp);
		return err;
	} else if (is_empty) {
		SSDFS_DBG("free inodes queue is empty\n");
		return -ENODATA;
	}

	*range = tmp;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!first);
#endif /* CONFIG_SSDFS_DEBUG */

	if (first->area.count == 0)
		ssdfs_free_inodes_range_free(first);

	return 0;
}

/*
 * ssdfs_free_inodes_queue_remove_first() - remove first free inodes range
 * @q: free inodes queue
 * @range: pointer on value that stores range pointer [out]
 *
 * This method tries to remove the first free inodes' range from
 * queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - queue is empty.
 * %-ERANGE     - internal error.
 */
int ssdfs_free_inodes_queue_remove_first(struct ssdfs_free_inode_range_queue *q,
					struct ssdfs_inodes_btree_range **range)
{
	bool is_empty;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!q || !range);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&q->lock);
	is_empty = list_empty_careful(&q->list);
	if (!is_empty) {
		*range = list_first_entry_or_null(&q->list,
						struct ssdfs_inodes_btree_range,
						list);
		if (!*range) {
			SSDFS_WARN("first entry is NULL\n");
			err = -ENOENT;
		} else
			list_del(&(*range)->list);
	}
	spin_unlock(&q->lock);

	if (is_empty) {
		SSDFS_WARN("requests queue is empty\n");
		return -ENODATA;
	} else if (err)
		return err;

	return 0;
}

/*
 * ssdfs_free_inodes_queue_remove_all() - remove all ranges from the queue
 * @q: free inodes queue
 */
static
void ssdfs_free_inodes_queue_remove_all(struct ssdfs_free_inode_range_queue *q)
{
	bool is_empty;
	LIST_HEAD(tmp_list);
	struct list_head *this, *next;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!q);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&q->lock);
	is_empty = list_empty_careful(&q->list);
	if (!is_empty)
		list_replace_init(&q->list, &tmp_list);
	spin_unlock(&q->lock);

	if (is_empty)
		return;

	list_for_each_safe(this, next, &tmp_list) {
		struct ssdfs_inodes_btree_range *range;

		range = list_entry(this, struct ssdfs_inodes_btree_range, list);

		if (range) {
			list_del(&range->list);
			ssdfs_free_inodes_range_free(range);
		}
	}
}

/******************************************************************************
 *                     INODES TREE OBJECT FUNCTIONALITY                       *
 ******************************************************************************/

/*
 * ssdfs_inodes_btree_create() - create inodes btree
 * @fsi: pointer on shared file system object
 *
 * This method tries to create inodes btree object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_inodes_btree_create(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_inodes_btree_info *ptr;
	struct ssdfs_inodes_btree *raw_btree;
	struct ssdfs_btree_search *search;
	size_t raw_inode_size = sizeof(struct ssdfs_inode);
	u32 vs_flags;
	bool is_tree_inline = true;
	ino_t ino;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	ptr = kzalloc(sizeof(struct ssdfs_inodes_btree_info),
			GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate inodes tree\n");
		return -ENOMEM;
	}

	fsi->inodes_tree = ptr;

	err = ssdfs_btree_create(fsi,
				 SSDFS_INODES_BTREE_INO,
				 &ssdfs_inodes_btree_desc_ops,
				 &ssdfs_inodes_btree_ops,
				 &ptr->generic_tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create inodes tree: err %d\n",
			  err);
		goto fail_create_inodes_tree;
	}

	spin_lock(&fsi->volume_state_lock);
	vs_flags = fsi->fs_flags;
	spin_unlock(&fsi->volume_state_lock);

	is_tree_inline = vs_flags & SSDFS_HAS_INLINE_INODES_TREE;

	spin_lock_init(&ptr->lock);
	raw_btree = &fsi->vs->inodes_btree;
	ptr->upper_allocated_ino = le64_to_cpu(raw_btree->upper_allocated_ino);
	ptr->allocated_inodes = le64_to_cpu(raw_btree->allocated_inodes);
	ptr->free_inodes = le64_to_cpu(raw_btree->free_inodes);
	ptr->inodes_capacity = le64_to_cpu(raw_btree->inodes_capacity);
	ptr->leaf_nodes = le32_to_cpu(raw_btree->leaf_nodes);
	ptr->nodes_count = le32_to_cpu(raw_btree->nodes_count);
	ptr->raw_inode_size = le16_to_cpu(raw_btree->desc.item_size);

	memcpy(&ptr->root_folder, &fsi->vs->root_folder, raw_inode_size);
	if (!is_raw_inode_checksum_correct(fsi,
					   &ptr->root_folder,
					   raw_inode_size)) {
		err = -EIO;
		SSDFS_ERR("root folder inode is corrupted\n");
		goto fail_create_inodes_tree;
	}

	ssdfs_free_inodes_queue_init(&ptr->free_inodes_queue);

	if (is_tree_inline) {
		search = ssdfs_btree_search_alloc();
		if (!search) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate btree search object\n");
			goto fail_create_inodes_tree;
		}

		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_ALLOCATE_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = 0;
		search->request.end.hash = 0;
		search->request.count = 1;

		err = ssdfs_btree_add_node(&ptr->generic_tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add the node: err %d\n",
				  err);
			goto free_search_object;
		}

		/* allocate all reserved inodes */
		ino = 0;
		do {
			search->request.start.hash = ino;
			search->request.end.hash = ino;
			search->request.count = 1;

			err = ssdfs_inodes_btree_allocate(ptr, &ino, search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to allocate an inode: err %d\n",
					  err);
				goto free_search_object;
			} else if (search->request.start.hash != ino) {
				err = -ERANGE;
				SSDFS_ERR("invalid ino %lu\n",
					  ino);
				goto free_search_object;
			}

			ino++;
		} while (ino <= SSDFS_ROOT_INO);

		if (ino > SSDFS_ROOT_INO)
			ino = SSDFS_ROOT_INO;
		else {
			err = -ERANGE;
			SSDFS_ERR("unexpected ino %lu\n", ino);
			goto free_search_object;
		}

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
			goto free_search_object;
		}

		if (!search->result.buf) {
			err = -ERANGE;
			SSDFS_ERR("invalid buffer\n");
			goto free_search_object;
		}

		if (search->result.buf_size < raw_inode_size) {
			err = -ERANGE;
			SSDFS_ERR("buf_size %zu < raw_inode_size %zu\n",
				  search->result.buf_size,
				  raw_inode_size);
			goto free_search_object;
		}

		if (search->result.items_in_buffer != 1) {
			SSDFS_WARN("unexpected value: "
				   "items_in_buffer %u\n",
				   search->result.items_in_buffer);
		}

		memcpy(search->result.buf, &ptr->root_folder,
			raw_inode_size);

		err = ssdfs_inodes_btree_change(ptr, ino, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change inode: "
				  "ino %lu, err %d\n",
				  ino, err);
			goto free_search_object;
		}

free_search_object:
		ssdfs_btree_search_free(search);

		if (unlikely(err))
			goto fail_create_inodes_tree;

		spin_lock(&fsi->volume_state_lock);
		vs_flags = fsi->fs_flags;
		vs_flags &= ~SSDFS_HAS_INLINE_INODES_TREE;
		fsi->fs_flags = vs_flags;
		spin_unlock(&fsi->volume_state_lock);
	} else {
		search = ssdfs_btree_search_alloc();
		if (!search) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate btree search object\n");
			goto fail_create_inodes_tree;
		}

		ssdfs_btree_search_init(search);
		err = ssdfs_inodes_btree_find(ptr, ptr->upper_allocated_ino,
						search);
		ssdfs_btree_search_free(search);

		if (err == -ENODATA) {
			err = 0;
			/*
			 * It doesn't need to find the inode.
			 * The goal is to pass through the tree.
			 * Simply ignores the no data error.
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to prepare free inodes queue: "
				  "upper_allocated_ino %llu, err %d\n",
				  ptr->upper_allocated_ino, err);
			goto fail_create_inodes_tree;
		}
	}

	SSDFS_DBG("DONE: create inodes btree\n");

	return 0;

fail_create_inodes_tree:
	fsi->inodes_tree = NULL;
	kfree(ptr);
	return err;
}

/*
 * ssdfs_inodes_btree_destroy - destroy inodes btree
 * @fsi: pointer on shared file system object
 */
void ssdfs_inodes_btree_destroy(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_inodes_btree_info *tree;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", fsi->inodes_tree);

	if (!fsi->inodes_tree)
		return;

	ssdfs_debug_inodes_btree_object(fsi->inodes_tree);

	tree = fsi->inodes_tree;
	ssdfs_btree_destroy(&tree->generic_tree);
	ssdfs_free_inodes_queue_remove_all(&tree->free_inodes_queue);
}

/*
 * ssdfs_inodes_btree_flush() - flush dirty inodes btree
 * @tree: pointer on inodes btree object
 *
 * This method tries to flush the dirty inodes btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_inodes_btree_flush(struct ssdfs_inodes_btree_info *tree)
{
	struct ssdfs_fs_info *fsi;
	u64 upper_allocated_ino;
	u64 allocated_inodes;
	u64 free_inodes;
	u64 inodes_capacity;
	u32 leaf_nodes;
	u32 nodes_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	fsi = tree->generic_tree.fsi;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_flush(&tree->generic_tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush inodes btree: err %d\n",
			  err);
		return err;
	}

	spin_lock(&tree->lock);
	memcpy(&fsi->vs->root_folder, &tree->root_folder,
		sizeof(struct ssdfs_inode));
	upper_allocated_ino = tree->upper_allocated_ino;
	allocated_inodes = tree->allocated_inodes;
	free_inodes = tree->free_inodes;
	inodes_capacity = tree->inodes_capacity;
	leaf_nodes = tree->leaf_nodes;
	nodes_count = tree->nodes_count;
	spin_unlock(&tree->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("allocated_inodes %llu, free_inodes %llu, "
		  "inodes_capacity %llu\n",
		  allocated_inodes, free_inodes, inodes_capacity);
	WARN_ON((allocated_inodes + free_inodes) != inodes_capacity);

	SSDFS_DBG("leaf_nodes %u, nodes_count %u\n",
		  leaf_nodes, nodes_count);
	WARN_ON(leaf_nodes >= nodes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->vs->inodes_btree.allocated_inodes = cpu_to_le64(allocated_inodes);
	fsi->vs->inodes_btree.free_inodes = cpu_to_le64(free_inodes);
	fsi->vs->inodes_btree.inodes_capacity = cpu_to_le64(inodes_capacity);
	fsi->vs->inodes_btree.leaf_nodes = cpu_to_le32(leaf_nodes);
	fsi->vs->inodes_btree.nodes_count = cpu_to_le32(nodes_count);
	fsi->vs->inodes_btree.upper_allocated_ino =
				cpu_to_le64(upper_allocated_ino);

	ssdfs_debug_inodes_btree_object(fsi->inodes_tree);

	return 0;
}

static inline
bool need_initialize_inodes_btree_search(ino_t ino,
					 struct ssdfs_btree_search *search)
{
	return need_initialize_btree_search(search) ||
		search->request.start.hash != ino;
}

/*
 * ssdfs_inodes_btree_find() - find raw inode
 * @tree: pointer on inodes btree object
 * @ino: inode ID value
 * @search: pointer on search request object
 *
 * This method tries to find the raw inode for @ino.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_inodes_btree_find(struct ssdfs_inodes_btree_info *tree,
			    ino_t ino,
			    struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, ino %lu, search %p\n",
		  tree, ino, search);

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_inodes_btree_search(ino, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = ino;
		search->request.end.hash = ino;
		search->request.count = 1;
	}

	return ssdfs_btree_find_item(&tree->generic_tree, search);
}

/*
 * ssdfs_inodes_btree_allocate() - allocate a new raw inode
 * @tree: pointer on inodes btree object
 * @ino: pointer on inode ID value [out]
 * @search: pointer on search request object
 *
 * This method tries to allocate a new raw inode into
 * the inodes btree. The @ino contains inode ID number.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_inodes_btree_allocate(struct ssdfs_inodes_btree_info *tree,
				ino_t *ino,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_inodes_btree_range *range = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !ino || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, ino %p, search %p\n",
		  tree, ino, search);

	*ino = ULONG_MAX;

	err = ssdfs_free_inodes_queue_get_first(&tree->free_inodes_queue,
						&range);
	if (err == -ENODATA) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_ALLOCATE_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		spin_lock(&tree->lock);
		search->request.start.hash = tree->upper_allocated_ino + 1;
		search->request.end.hash = tree->upper_allocated_ino + 1;
		spin_unlock(&tree->lock);
		search->request.count = 1;

		err = ssdfs_btree_add_node(&tree->generic_tree, search);
		if (err == -EEXIST)
			err = 0;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to add the node: err %d\n",
				  err);
			return err;
		}

		err =
		    ssdfs_free_inodes_queue_get_first(&tree->free_inodes_queue,
							&range);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to get first free inode hash from the queue: "
			  "err %d\n",
			  err);
		return err;
	}

	if (is_free_inodes_range_invalid(range)) {
		err = -ERANGE;
		SSDFS_WARN("invalid free inodes range\n");
		goto finish_inode_allocation;
	}

	if (range->area.start_hash >= ULONG_MAX) {
		err = -EOPNOTSUPP;
		SSDFS_WARN("start_hash %llx is too huge\n",
			   range->area.start_hash);
		goto finish_inode_allocation;
	}

	if (range->area.count != 1)
		SSDFS_WARN("invalid free inodes range\n");

	*ino = (ino_t)range->area.start_hash;
	search->request.type = SSDFS_BTREE_SEARCH_ALLOCATE_ITEM;

	if (need_initialize_inodes_btree_search(*ino, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_ALLOCATE_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = *ino;
		search->request.end.hash = *ino;
		search->request.count = 1;
	}

	search->result.state = SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
	search->result.start_index = range->area.start_index;

	err = ssdfs_btree_allocate_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate item: ino %llu, err %d\n",
			  search->request.start.hash, err);
		goto finish_inode_allocation;
	}

finish_inode_allocation:
	ssdfs_free_inodes_range_free(range);

	return err;
}

/*
 * ssdfs_inodes_btree_change() - change raw inode
 * @tree: pointer on inodes btree object
 * @ino: inode ID value
 * @search: pointer on search request object
 *
 * This method tries to change the raw inode for @ino.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_inodes_btree_change(struct ssdfs_inodes_btree_info *tree,
				ino_t ino,
				struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, ino %lu, search %p\n",
		  tree, ino, search);

	search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;

	if (need_initialize_inodes_btree_search(ino, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = ino;
		search->request.end.hash = ino;
		search->request.count = 1;
	}

	err = ssdfs_btree_change_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change inode: ino %lu, err %d\n",
			  ino, err);
		return err;
	}

	if (ino == SSDFS_ROOT_INO) {
		spin_lock(&tree->lock);
		memcpy(&tree->root_folder, search->result.buf,
			sizeof(struct ssdfs_inode));
		spin_unlock(&tree->lock);
	}

	return 0;
}

/*
 * ssdfs_inodes_btree_delete_range() - delete a range of raw inodes
 * @tree: pointer on inodes btree object
 * @ino: starting inode ID value
 * @count: count of raw inodes in the range
 *
 * This method tries to delete the @count of raw inodes
 * that are starting from @ino.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_inodes_btree_delete_range(struct ssdfs_inodes_btree_info *tree,
				    ino_t ino, u16 count)
{
	struct ssdfs_btree_search *search;
	struct ssdfs_inodes_btree_range *range;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, ino %lu, count %u\n",
		  tree, ino, count);

	if (count == 0) {
		SSDFS_WARN("count == 0\n");
		return 0;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);

	if (count == 1)
		err = ssdfs_inodes_btree_find(tree, ino, search);
	else {
		search->request.type = SSDFS_BTREE_SEARCH_FIND_RANGE;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
		search->request.start.hash = ino;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(ino >= U64_MAX - count);
#endif /* CONFIG_SSDFS_DEBUG */
		search->request.end.hash = (u64)ino + count;
		search->request.count = count;

		err = ssdfs_btree_find_range(&tree->generic_tree, search);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to find inodes range: "
			  "ino %lu, count %u, err %d\n",
			  ino, count, err);
		goto finish_delete_inodes_range;
	}

	if (count == 1) {
		search->request.type = SSDFS_BTREE_SEARCH_DELETE_ITEM;
		err = ssdfs_btree_delete_item(&tree->generic_tree, search);
	} else {
		search->request.type = SSDFS_BTREE_SEARCH_DELETE_RANGE;
		err = ssdfs_btree_delete_range(&tree->generic_tree, search);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to delete raw inodes range: "
			  "ino %lu, count %u, err %d\n",
			  ino, count, err);
		goto finish_delete_inodes_range;
	}

	range = ssdfs_free_inodes_range_alloc();
	if (!range) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate free inodes range object\n");
		goto finish_delete_inodes_range;
	}

	ssdfs_free_inodes_range_init(range);

	range->node_id = search->node.id;
	range->area.start_hash = search->request.start.hash;
	range->area.start_index = search->result.start_index;
	range->area.count = count;

	ssdfs_free_inodes_queue_add_head(&tree->free_inodes_queue, range);

finish_delete_inodes_range:
	ssdfs_btree_search_free(search);

	return err;
}

/*
 * ssdfs_inodes_btree_delete() - delete raw inode
 * @tree: pointer on inodes btree object
 * @ino: inode ID value
 *
 * This method tries to delete the raw inode for @ino.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_inodes_btree_delete(struct ssdfs_inodes_btree_info *tree,
				ino_t ino)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, ino %lu\n",
		  tree, ino);

	return ssdfs_inodes_btree_delete_range(tree, ino, 1);
}

/******************************************************************************
 *             SPECIALIZED INODES BTREE DESCRIPTOR OPERATIONS                 *
 ******************************************************************************/

/*
 * ssdfs_inodes_btree_desc_init() - specialized btree descriptor init
 * @fsi: pointer on shared file system object
 * @tree: pointer on inodes btree object
 */
static
int ssdfs_inodes_btree_desc_init(struct ssdfs_fs_info *fsi,
				 struct ssdfs_btree *tree)
{
	struct ssdfs_btree_descriptor *desc;
	u32 erasesize;
	u32 node_size;
	size_t inode_size = sizeof(struct ssdfs_inode);
	u16 item_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !tree);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, tree %p\n",
		  fsi, tree);

	erasesize = fsi->erasesize;

	desc = &fsi->vs->inodes_btree.desc;

	if (le32_to_cpu(desc->magic) != SSDFS_INODES_BTREE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic %#x\n",
			  le32_to_cpu(desc->magic));
		goto finish_btree_desc_init;
	}

	/* TODO: check flags */

	if (desc->type != SSDFS_INODES_BTREE) {
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

	if (item_size != inode_size) {
		err = -EIO;
		SSDFS_ERR("invalid item size %u\n",
			  item_size);
		goto finish_btree_desc_init;
	}

	if (le16_to_cpu(desc->index_area_min_size) != inode_size) {
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
 * ssdfs_inodes_btree_desc_flush() - specialized btree's descriptor flush
 * @tree: pointer on inodes btree object
 */
static
int ssdfs_inodes_btree_desc_flush(struct ssdfs_btree *tree)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_descriptor desc;
	size_t inode_size = sizeof(struct ssdfs_inode);
	u32 erasesize;
	u32 node_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi);
	BUG_ON(!rwsem_is_locked(&tree->fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("owner_ino %llu, type %#x, state %#x\n",
		  tree->owner_ino, tree->type,
		  atomic_read(&tree->state));

	fsi = tree->fsi;

	memset(&desc, 0xFF, sizeof(struct ssdfs_btree_descriptor));

	desc.magic = cpu_to_le32(SSDFS_INODES_BTREE_MAGIC);
	desc.item_size = cpu_to_le16(inode_size);

	err = ssdfs_btree_desc_flush(tree, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("invalid btree descriptor: err %d\n",
			  err);
		return err;
	}

	if (desc.type != SSDFS_INODES_BTREE) {
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

	if (le16_to_cpu(desc.index_area_min_size) != inode_size) {
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc.index_area_min_size));
		return -ERANGE;
	}

	memcpy(&fsi->vs->inodes_btree.desc, &desc,
		sizeof(struct ssdfs_btree_descriptor));

	return 0;
}

/******************************************************************************
 *                   SPECIALIZED INODES BTREE OPERATIONS                      *
 ******************************************************************************/

/*
 * ssdfs_inodes_btree_create_root_node() - specialized root node creation
 * @fsi: pointer on shared file system object
 * @node: pointer on node object [out]
 */
static
int ssdfs_inodes_btree_create_root_node(struct ssdfs_fs_info *fsi,
					struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_inline_root_node *root_node;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->vs || !node);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, node %p\n",
		  fsi, node);

	root_node = &fsi->vs->inodes_btree.root_node;
	err = ssdfs_btree_create_root_node(node, root_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create root node: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_inodes_btree_pre_flush_root_node() - specialized root node pre-flush
 * @node: pointer on node object
 */
static
int ssdfs_inodes_btree_pre_flush_root_node(struct ssdfs_btree_node *node)
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

	if (tree->type != SSDFS_INODES_BTREE) {
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
 * ssdfs_inodes_btree_flush_root_node() - specialized root node flush
 * @node: pointer on node object
 */
static
int ssdfs_inodes_btree_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_inline_root_node *root_node;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	if (!is_ssdfs_btree_node_dirty(node)) {
		SSDFS_WARN("node %u is not dirty\n",
			   node->node_id);
		return 0;
	}

	root_node = &node->tree->fsi->vs->inodes_btree.root_node;
	ssdfs_btree_flush_root_node(node, root_node);

	return 0;
}

/*
 * ssdfs_inodes_btree_create_node() - specialized node creation
 * @node: pointer on node object
 */
static
int ssdfs_inodes_btree_create_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct page *page;
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	size_t hdr_size = sizeof(struct ssdfs_inodes_btree_node_header);
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

	node->node_ops = &ssdfs_inodes_btree_node_ops;

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

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_INODE_BMAP_SIZE) {
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

	ssdfs_debug_btree_node_object(node);

	return err;
}

/*
 * ssdfs_inodes_btree_init_node() - init inodes tree's node
 * @node: pointer on node object
 *
 * This method tries to init the node of inodes btree.
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
int ssdfs_inodes_btree_init_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_inodes_btree_info *tree;
	struct ssdfs_inodes_btree_node_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_inodes_btree_node_header);
	struct ssdfs_free_inode_range_queue q;
	struct ssdfs_inodes_btree_range *range;
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	struct page *page;
	void *kaddr;
	u32 node_size;
	u16 flags;
	u16 item_size;
	u32 items_count;
	u8 index_size;
	u16 items_capacity;
	u32 index_area_size;
	u16 index_capacity = 0;
	u16 inodes_count;
	u16 valid_inodes;
	size_t bmap_bytes;
	u64 start_hash, end_hash;
	unsigned long start, end;
	unsigned long size, upper_bound;
	signed long count;
	unsigned long free_inodes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	if (node->tree->type == SSDFS_INODES_BTREE)
		tree = (struct ssdfs_inodes_btree_info *)node->tree;
	else {
		SSDFS_ERR("invalid tree type %#x\n",
			  node->tree->type);
		return -ERANGE;
	}

	if (atomic_read(&node->state) != SSDFS_BTREE_NODE_CONTENT_PREPARED) {
		SSDFS_WARN("fail to init node: id %u, state %#x\n",
			   node->node_id, atomic_read(&node->state));
		return -ERANGE;
	}

	down_read(&node->full_lock);

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

	hdr = (struct ssdfs_inodes_btree_node_header *)kaddr;

	if (!is_csum_valid(&hdr->node.check, hdr, hdr_size)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum: node_id %u\n",
			  node->node_id);
		goto finish_init_operation;
	}

	if (le32_to_cpu(hdr->node.magic.common) != SSDFS_SUPER_MAGIC ||
	    le16_to_cpu(hdr->node.magic.key) != SSDFS_INODES_BNODE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic: common %#x, key %#x\n",
			  le32_to_cpu(hdr->node.magic.common),
			  le16_to_cpu(hdr->node.magic.key));
		goto finish_init_operation;
	}

	down_write(&node->header_lock);

	memcpy(&node->raw.inodes_header, hdr, hdr_size);

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
	item_size = node->tree->item_size;
	items_capacity = le16_to_cpu(hdr->node.items_capacity);
	inodes_count = le16_to_cpu(hdr->inodes_count);
	valid_inodes = le16_to_cpu(hdr->valid_inodes);

	if (item_size == 0 || node_size % item_size) {
		err = -EIO;
		SSDFS_ERR("invalid size: item_size %u, node_size %u\n",
			  item_size, node_size);
		goto finish_header_init;
	}

	if (item_size != sizeof(struct ssdfs_inode)) {
		err = -EIO;
		SSDFS_ERR("invalid item_size: "
			  "size %u, expected size %zu\n",
			  item_size,
			  sizeof(struct ssdfs_inode));
		goto finish_header_init;
	}

	if (items_capacity == 0 ||
	    items_capacity > (node_size / item_size)) {
		err = -EIO;
		SSDFS_ERR("invalid items_capacity %u\n",
			  items_capacity);
		goto finish_header_init;
	}

	if (items_capacity != inodes_count) {
		err = -EIO;
		SSDFS_ERR("items_capacity %u != inodes_count %u\n",
			  items_capacity,
			  inodes_count);
		goto finish_header_init;
	}

	if (valid_inodes > inodes_count) {
		err = -EIO;
		SSDFS_ERR("valid_inodes %u > inodes_count %u\n",
			  valid_inodes, inodes_count);
		goto finish_header_init;
	}

	node->items_area.items_count = valid_inodes;
	node->items_area.items_capacity = inodes_count;

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

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_INODE_BMAP_SIZE) {
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
		index_area_size = 1 << hdr->node.log_index_area_size;
		index_area_size += index_size - 1;
		index_capacity = index_area_size / index_size;
		node->bmap_array.item_start_bit =
			node->bmap_array.index_start_bit + index_capacity;
	} else if (flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA) {
		node->bmap_array.item_start_bit =
				SSDFS_BTREE_NODE_HEADER_INDEX + 1;
	} else
		BUG();

	node->bmap_array.bits_count = index_capacity + items_capacity + 1;

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		spin_lock(&node->bmap_array.bmap[i].lock);
		node->bmap_array.bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&node->bmap_array.bmap[i].lock);
	}

	spin_lock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);
	memcpy(node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].ptr,
		hdr->bmap, bmap_bytes);
	spin_unlock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);

	start = node->bmap_array.item_start_bit;

	up_write(&node->bmap_array.lock);
finish_init_operation:
	kunmap(page);

	if (unlikely(err))
		goto finish_init_node;

	ssdfs_free_inodes_queue_init(&q);
	size = inodes_count;
	upper_bound = node->bmap_array.item_start_bit + size;
	free_inodes = 0;

	do {
		start = find_next_zero_bit((unsigned long *)hdr->bmap,
					   upper_bound, start);
		if (start >= upper_bound)
			break;

		end = find_next_bit((unsigned long *)hdr->bmap,
				    upper_bound, start);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(start >= U16_MAX);
		BUG_ON((end - start) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		count = end - start;
		start -= node->bmap_array.item_start_bit;

		if (count <= 0) {
			err = -ERANGE;
			SSDFS_WARN("invalid count %ld\n", count);
			break;
		}

		range = ssdfs_free_inodes_range_alloc();
		if (unlikely(!range)) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate inodes range\n");
			break;
		}

		ssdfs_free_inodes_range_init(range);
		range->node_id = node->node_id;
		range->area.start_hash = start_hash + start;
		range->area.start_index = (u16)start;
		range->area.count = (u16)count;

		SSDFS_DBG("start_hash %llx, end_hash %llx, "
			  "range->area.start_hash %llx\n",
			  start_hash, end_hash,
			  range->area.start_hash);

		if (range->area.start_hash > end_hash) {
			err = -EIO;
			SSDFS_ERR("start_hash %llx > end_hash %llx\n",
				  range->area.start_hash, end_hash);
			ssdfs_free_inodes_range_free(range);
			break;
		}

		free_inodes += count;
		if ((valid_inodes + free_inodes) > inodes_count) {
			err = -EIO;
			SSDFS_ERR("invalid free_inodes: "
				  "valid_inodes %u, free_inodes %lu, "
				  "inodes_count %u\n",
				  valid_inodes, free_inodes,
				  inodes_count);
			ssdfs_free_inodes_range_free(range);
			break;
		}

		ssdfs_free_inodes_queue_add_tail(&q, range);
		start = end;
	} while (start < size);

	if (unlikely(err)) {
		ssdfs_free_inodes_queue_remove_all(&q);
		goto finish_init_node;
	}

	while (!is_ssdfs_free_inodes_queue_empty(&q)) {
		err = ssdfs_free_inodes_queue_remove_first(&q, &range);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get range: err %d\n", err);
			goto finish_init_node;
		}

		ssdfs_free_inodes_queue_add_tail(&tree->free_inodes_queue,
						 range);
	};

finish_init_node:
	up_read(&node->full_lock);

	ssdfs_debug_btree_node_object(node);

	return err;
}

static
void ssdfs_inodes_btree_destroy_node(struct ssdfs_btree_node *node)
{
	SSDFS_DBG("operation is unavailable\n");
}

/*
 * ssdfs_inodes_btree_node_correct_hash_range() - correct node's hash range
 * @node: pointer on node object
 *
 * This method tries to correct node's hash range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_inodes_btree_node_correct_hash_range(struct ssdfs_btree_node *node,
						u64 start_hash)
{
	struct ssdfs_inodes_btree_info *itree;
	u16 items_count;
	u16 items_capacity;
	u16 free_items;
	struct ssdfs_inodes_btree_range *range = NULL;
	struct ssdfs_btree_index_key key;
	int type;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(start_hash >= U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x, "
		  "node_type %#x, start_hash %llx\n",
		  node->node_id, atomic_read(&node->state),
		  atomic_read(&node->type), start_hash);

	itree = (struct ssdfs_inodes_btree_info *)node->tree;
	type = atomic_read(&node->type);

	switch (type) {
	case SSDFS_BTREE_LEAF_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected state */
		break;

	default:
		/* do nothing */
		return 0;
	}

	down_write(&node->header_lock);

	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;

	switch (type) {
	case SSDFS_BTREE_LEAF_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(items_capacity == 0);
#endif /* CONFIG_SSDFS_DEBUG */
		node->items_area.start_hash = start_hash;
		node->items_area.end_hash = start_hash + items_capacity - 1;
		break;

	default:
		/* do nothing */
		break;
	}

	up_write(&node->header_lock);

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		spin_lock(&node->descriptor_lock);
		memcpy(&key, &node->node_index,
			sizeof(struct ssdfs_btree_index_key));
		spin_unlock(&node->descriptor_lock);

		key.index.hash = cpu_to_le64(start_hash);

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

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(items_count > items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	free_items = items_capacity - items_count;

	if (items_capacity == 0) {
		if (type == SSDFS_BTREE_LEAF_NODE ||
		    type == SSDFS_BTREE_HYBRID_NODE) {
			SSDFS_ERR("invalid node state: "
				  "type %#x, items_capacity %u\n",
				  type, items_capacity);
			return -ERANGE;
		}
	} else {
		range = ssdfs_free_inodes_range_alloc();
		if (unlikely(!range)) {
			SSDFS_ERR("fail to allocate inodes range\n");
			return -ENOMEM;
		}

		ssdfs_free_inodes_range_init(range);
		range->node_id = node->node_id;
		range->area.start_hash = start_hash + items_count;
		range->area.start_index = items_count;
		range->area.count = free_items;

		ssdfs_free_inodes_queue_add_tail(&itree->free_inodes_queue,
						 range);
	}

	ssdfs_debug_btree_node_object(node);

	return 0;
}

/*
 * ssdfs_inodes_btree_add_node() - add node into inodes btree
 * @node: pointer on node object
 *
 * This method tries to finish addition of node into inodes btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_inodes_btree_add_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_inodes_btree_info *itree;
	struct ssdfs_btree_node *parent_node;
	int type;
	u64 start_hash = U64_MAX;
	u64 end_hash = U64_MAX;
	u16 items_capacity;
	int err;

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

	itree = (struct ssdfs_inodes_btree_info *)node->tree;
	type = atomic_read(&node->type);

	down_read(&node->header_lock);
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	items_capacity = node->items_area.items_capacity;
	up_read(&node->header_lock);

	switch (type) {
	case SSDFS_BTREE_INDEX_NODE:
		ssdfs_debug_btree_node_object(node);
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		err = ssdfs_inodes_btree_node_correct_hash_range(node,
								 start_hash);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct hash range: "
				  "err %d\n", err);
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			return err;
		}
		break;

	case SSDFS_BTREE_LEAF_NODE:
		err = ssdfs_inodes_btree_node_correct_hash_range(node,
								 start_hash);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct hash range: "
				  "err %d\n", err);
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(end_hash >= U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		parent_node = node->parent_node;
		start_hash = end_hash + 1;

		err = ssdfs_inodes_btree_node_correct_hash_range(parent_node,
								 start_hash);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct hash range: "
				  "err %d\n", err);
			atomic_set(&parent_node->state,
					SSDFS_BTREE_NODE_CORRUPTED);
			return err;
		}
		break;

	default:
		SSDFS_WARN("invalid node type %#x\n", type);
		return -ERANGE;
	};

	spin_lock(&itree->lock);
	itree->nodes_count++;
	if (type == SSDFS_BTREE_LEAF_NODE)
		itree->leaf_nodes++;
	itree->inodes_capacity += items_capacity;
	itree->free_inodes += items_capacity;
	spin_unlock(&itree->lock);

	return 0;
}

static
int ssdfs_inodes_btree_delete_node(struct ssdfs_btree_node *node)
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
 * ssdfs_inodes_btree_pre_flush_node() - pre-flush node's header
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
int ssdfs_inodes_btree_pre_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_inodes_btree_node_header inodes_header;
	struct ssdfs_state_bitmap *bmap;
	size_t hdr_size = sizeof(struct ssdfs_inodes_btree_node_header);
	u32 bmap_bytes;
	struct page *page;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	ssdfs_debug_btree_node_object(node);

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

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	memcpy(&inodes_header, &node->raw.inodes_header,
		sizeof(struct ssdfs_inodes_btree_node_header));

	inodes_header.node.magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	inodes_header.node.magic.key = cpu_to_le16(SSDFS_INODES_BNODE_MAGIC);
	inodes_header.node.magic.version.major = SSDFS_MAJOR_REVISION;
	inodes_header.node.magic.version.minor = SSDFS_MINOR_REVISION;

	err = ssdfs_btree_node_pre_flush_header(node, &inodes_header.node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush generic header: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_inodes_header_preparation;
	}

	inodes_header.valid_inodes =
		cpu_to_le16(node->items_area.items_count);
	inodes_header.inodes_count =
		cpu_to_le16(node->items_area.items_capacity);

	down_read(&node->bmap_array.lock);
	bmap_bytes = node->bmap_array.bmap_bytes;
	spin_lock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);
	memcpy(inodes_header.bmap,
		node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].ptr,
		bmap_bytes);
	spin_unlock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);
	up_read(&node->bmap_array.lock);

	inodes_header.node.check.bytes = cpu_to_le16((u16)hdr_size);
	inodes_header.node.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&inodes_header.node.check,
				   &inodes_header, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto finish_inodes_header_preparation;
	}

	memcpy(&node->raw.inodes_header, &inodes_header,
		sizeof(struct ssdfs_inodes_btree_node_header));

finish_inodes_header_preparation:
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
	memcpy(kaddr, &inodes_header,
		sizeof(struct ssdfs_inodes_btree_node_header));
	kunmap_atomic(kaddr);

finish_node_pre_flush:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_inodes_btree_flush_node() - flush node
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
int ssdfs_inodes_btree_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree *tree;
	u64 fs_feature_compat;
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

	if (tree->type != SSDFS_INODES_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	}

	fsi = node->tree->fsi;

	spin_lock(&fsi->volume_state_lock);
	fs_feature_compat = fsi->fs_feature_compat;
	spin_unlock(&fsi->volume_state_lock);

	if (fs_feature_compat & SSDFS_HAS_INODES_TREE_COMPAT_FLAG) {
		err = ssdfs_btree_common_node_flush(node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to flush node: "
				  "node_id %u, height %u, err %d\n",
				  node->node_id,
				  atomic_read(&node->height),
				  err);
		}
	} else {
		err = -EFAULT;
		SSDFS_CRIT("inodes tree is absent\n");
	}

	ssdfs_debug_btree_node_object(node);

	return err;
}

/******************************************************************************
 *               SPECIALIZED INODES BTREE NODE OPERATIONS                     *
 ******************************************************************************/

/*
 * ssdfs_inodes_btree_node_find_range() - find a range of items into the node
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
int ssdfs_inodes_btree_node_find_range(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	size_t item_size = sizeof(struct ssdfs_inode);
	int state;
	u16 items_count;
	u16 items_capacity;
	u64 start_hash;
	u64 end_hash;
	u64 found_index, start_index = U64_MAX;
	u64 found_bit = U64_MAX;
	struct ssdfs_state_bitmap *bmap;
	unsigned long item_start_bit;
	bool is_allocated = false;
	int i;
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

	ssdfs_debug_btree_search_object(search);

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

	found_index = search->request.start.hash - start_hash;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(found_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if ((found_index + search->request.count) > items_capacity) {
		SSDFS_ERR("invalid request: "
			  "found_index %llu, count %u, "
			  "items_capacity %u\n",
			  found_index, search->request.count,
			  items_capacity);
		return -ERANGE;
	}

	down_read(&node->bmap_array.lock);
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP];
	item_start_bit = node->bmap_array.item_start_bit;
	if (item_start_bit == ULONG_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid items_area_start\n");
		goto finish_bmap_operation;
	}
	start_index = found_index + item_start_bit;

	spin_lock(&bmap->lock);

	found_bit = bitmap_find_next_zero_area(bmap->ptr,
						items_capacity + item_start_bit,
						start_index,
						search->request.count,
						0);

	if (start_index == found_bit) {
		/* item isn't allocated yet */
		is_allocated = false;
	} else {
		/* item has been allocated already */
		is_allocated = true;
	}
	spin_unlock(&bmap->lock);
finish_bmap_operation:
	up_read(&node->bmap_array.lock);

	if (is_allocated) {
		if (search->request.count == 1) {
			search->result.buf_state =
				SSDFS_BTREE_SEARCH_INLINE_BUFFER;
			search->result.buf = &search->raw.inode;
			search->result.buf_size = item_size;
			search->result.items_in_buffer = 0;
		} else {
			search->result.buf_state =
				SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
			search->result.buf_size = item_size;
			search->result.buf_size *= search->request.count;

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

		for (i = 0; i < search->request.count; i++) {
			err = ssdfs_copy_item_in_buffer(node,
							(u16)found_index + i,
							item_size,
							search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy item in buffer: "
					  "index %d, err %d\n",
					  i, err);
				return err;
			}
		}

		err = 0;
		search->result.state =
			SSDFS_BTREE_SEARCH_VALID_ITEM;
		search->result.err = 0;
		search->result.start_index = (u16)found_index;
		search->result.count = search->request.count;
		search->result.search_cno =
			ssdfs_current_cno(node->tree->fsi->sb);
	} else {
		err = -ENODATA;
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = -ENODATA;
		search->result.start_index = (u16)found_index;
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
	}

	SSDFS_DBG("search result: "
		  "state %#x, err %d, "
		  "start_index %u, count %u, "
		  "search_cno %llu, "
		  "buf_state %#x, buf %p\n",
		  search->result.state,
		  search->result.err,
		  search->result.start_index,
		  search->result.count,
		  search->result.search_cno,
		  search->result.buf_state,
		  search->result.buf);

	ssdfs_debug_btree_node_object(node);

	return err;
}

/*
 * ssdfs_inodes_btree_node_find_item() - find item into node
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
int ssdfs_inodes_btree_node_find_item(struct ssdfs_btree_node *node,
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

	return ssdfs_inodes_btree_node_find_range(node, search);
}

/*
 * ssdfs_define_allocated_range() - define range for allocation
 * @search: pointer on search request object
 * @start_hash: requested starting hash
 * @end_hash: requested ending hash
 * @start: pointer on start index value [out]
 * @count: pointer on count items in the range [out]
 *
 * This method checks request in the search object and
 * to define the range's start index and count of items
 * in the range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_define_allocated_range(struct ssdfs_btree_search *search,
				 u64 start_hash, u64 end_hash,
				 unsigned long *start, unsigned int *count)
{
	unsigned int calculated_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !start || !count);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("start_hash %llx, end_hash %llx, flags %#x\n",
		  start_hash, end_hash, search->request.flags);

	*start = ULONG_MAX;
	*count = 0;

	if (search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE) {
		if (search->request.start.hash < start_hash ||
		    search->request.start.hash > end_hash) {
			SSDFS_ERR("invalid hash range: "
				  "node (id %u, start_hash %llx, "
				  "end_hash %llx), "
				  "request (start_hash %llx, "
				  "end_hash %llx)\n",
				  search->node.id, start_hash, end_hash,
				  search->request.start.hash,
				  search->request.end.hash);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON((search->request.start.hash - start_hash) >= ULONG_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		*start = (unsigned long)(search->request.start.hash -
				start_hash);
		calculated_count = search->request.end.hash -
					search->request.start.hash + 1;
	} else {
		*start = 0;
		calculated_count = search->request.count;
	}

	if (search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_COUNT) {
		*count = search->request.count;

		if (*count < 0 || *count >= UINT_MAX) {
			SSDFS_WARN("invalid count %u\n", *count);
			return -ERANGE;
		}

		if (*count != calculated_count) {
			SSDFS_ERR("invalid count: count %u, "
				  "calculated_count %u\n",
				  *count, calculated_count);
			return -ERANGE;
		}
	}

	if (*start >= ULONG_MAX || *count >= UINT_MAX) {
		SSDFS_WARN("invalid range (start %lu, count %u)\n",
			   *start, *count);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_copy_item_into_node_unlocked() - copy item from buffer into the node
 * @node: pointer on node object
 * @search: pointer on search request object
 * @item_index: index of item in the node
 * @buf_index: index of item into the buffer
 *
 * This method tries to copy an item from the buffer into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_copy_item_into_node_unlocked(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search,
					u16 item_index, u16 buf_index)
{
	size_t item_size = sizeof(struct ssdfs_inode);
	u32 area_offset;
	u32 area_size;
	u32 item_offset;
	u32 buf_offset;
	int page_index;
	struct page *page;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u, buf_index %u\n",
		  node->node_id, item_index, buf_index);

	down_read(&node->header_lock);
	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	up_read(&node->header_lock);

	item_offset = (u32)item_index * item_size;
	if (item_offset >= area_size) {
		SSDFS_ERR("item_offset %u >= area_size %u\n",
			  item_offset, area_size);
		return -ERANGE;
	}

	item_offset += area_offset;
	if (item_offset >= node->node_size) {
		SSDFS_ERR("item_offset %u >= node_size %u\n",
			  item_offset, node->node_size);
		return -ERANGE;
	}

	page_index = item_offset >> PAGE_SHIFT;

	if (page_index > 0)
		item_offset %= page_index * PAGE_SIZE;

	if (page_index >= pagevec_count(&node->content.pvec)) {
		SSDFS_ERR("invalid page_index: "
			  "index %d, pvec_size %u\n",
			  page_index,
			  pagevec_count(&node->content.pvec));
		return -ERANGE;
	}

	page = node->content.pvec.pages[page_index];

	if (!search->result.buf) {
		SSDFS_ERR("buffer is not created\n");
		return -ERANGE;
	}

	if (buf_index >= search->result.items_in_buffer) {
		SSDFS_ERR("buf_index %u >= items_in_buffer %u\n",
			  buf_index, search->result.items_in_buffer);
		return -ERANGE;
	}

	buf_offset = buf_index * item_size;

	if ((buf_offset + item_size) > search->result.buf_size) {
		SSDFS_ERR("fail to copy item: "
			  "buf_offset %u, item_size %zu, "
			  "buf_size %zu\n",
			  buf_offset, item_size,
			  search->result.buf_size);
		return -ERANGE;
	}

	kaddr = kmap_atomic(page);
	memcpy((u8 *)kaddr + item_offset,
		(u8 *)search->result.buf + buf_offset,
		item_size);
	kunmap_atomic(kaddr);

	return 0;
}

/*
 * __ssdfs_btree_node_allocate_range() - allocate range of items in the node
 * @node: pointer on node object
 * @search: pointer on search request object
 * @start_index: start index of the range
 * @count: count of items in the range
 *
 * This method tries to allocate range of items in the node.
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
int __ssdfs_btree_node_allocate_range(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search,
					u16 start, u16 count)
{
	struct ssdfs_inodes_btree_info *itree;
	struct ssdfs_inodes_btree_node_header *hdr;
	size_t inode_size = sizeof(struct ssdfs_inode);
	struct ssdfs_state_bitmap *bmap;
	struct timespec64 cur_time;
	u16 item_size;
	u16 max_item_size;
	u16 item_index;
	u16 items_count;
	u16 items_capacity;
	int free_items;
	u64 start_hash;
	u64 end_hash;
	u32 bmap_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("start %u, count %u\n", start, count);

	down_read(&node->header_lock);
	item_size = node->items_area.item_size;
	max_item_size = node->items_area.max_item_size;
	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	up_read(&node->header_lock);

	if (items_capacity == 0 || items_capacity < items_count) {
		SSDFS_ERR("invalid items accounting: "
			  "node_id %u, items_capacity %u, items_count %u\n",
			  search->node.id, items_capacity, items_count);
		return -ERANGE;
	}

	if (item_size != inode_size || max_item_size != item_size) {
		SSDFS_ERR("item_size %u, max_item_size %u, "
			  "inode_size %zu\n",
			  item_size, max_item_size, inode_size);
		return -ERANGE;
	}

	free_items = items_capacity - items_count;
	if (unlikely(free_items < 0)) {
		SSDFS_WARN("invalid free_items %d\n",
			   free_items);
		return -ERANGE;
	} else if (free_items == 0) {
		SSDFS_DBG("node hasn't free items\n");
		return -ENOSPC;
	}

	item_index = search->result.start_index;
	if ((item_index + search->request.count) > items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u, "
			  "items_capacity %u\n",
			  item_index, search->request.count,
			  items_capacity);
		return -ERANGE;
	}

	if ((start_hash + item_index) != search->request.start.hash) {
		SSDFS_WARN("node (start_hash %llx, index %u), "
			   "request (start_hash %llx, end_hash %llx)\n",
			   start_hash, item_index,
			   search->request.start.hash,
			   search->request.end.hash);
		return -ERANGE;
	}

	if (start != item_index) {
		SSDFS_WARN("start %u != item_index %u\n",
			   start, item_index);
		return -ERANGE;
	}

	down_write(&node->full_lock);

	err = ssdfs_lock_items_range(node, start, count);
	if (err == -ENOENT) {
		up_write(&node->full_lock);
		return -ERANGE;
	} else if (err == -ENODATA) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (unlikely(err))
		BUG();

	downgrade_write(&node->full_lock);

	err = ssdfs_allocate_items_range(node, search,
					 items_capacity,
					 start, count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate: "
			  "start %u, count %u, err %d\n",
			  start, count, err);
		goto finish_allocate_item;
	}

	search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;
	search->result.start_index = start;
	search->result.count = count;

	if (count > 1) {
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
		search->result.buf_size = item_size;
		search->result.buf_size *= count;

		search->result.buf = kzalloc(search->result.buf_size,
					     GFP_KERNEL);
		if (!search->result.buf) {
			err = -ENOMEM;
			SSDFS_ERR("fail to allocate buffer: "
				  "size %zu\n",
				  search->result.buf_size);
			goto finish_allocate_item;
		}
		search->result.items_in_buffer = count;
	} else if (count == 1) {
		search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		search->result.buf = &search->raw.inode;
		search->result.buf_size = item_size;
		search->result.items_in_buffer = 1;
	} else
		BUG();

	memset(search->result.buf, 0, search->result.buf_size);

	for (i = 0; i < count; i++) {
		struct ssdfs_inode *inode;
		u32 item_offset = i * item_size;

		inode = (struct ssdfs_inode *)(search->result.buf +
						item_offset);

		ktime_get_coarse_real_ts64(&cur_time);

		inode->magic = cpu_to_le16(SSDFS_INODE_MAGIC);
		inode->birthtime = cpu_to_le64(cur_time.tv_sec);
		inode->birthtime_nsec = cpu_to_le32(cur_time.tv_nsec);
		inode->ino = cpu_to_le64(search->request.start.hash);

		err = ssdfs_copy_item_into_node_unlocked(node, search,
							 start + i, i);
		if (unlikely(err)) {
			SSDFS_ERR("fail to initialized allocated item: "
				  "index %d, err %d\n",
				  start + i, err);
			goto finish_allocate_item;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count == 0 || search->result.count >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&node->header_lock);
	hdr = &node->raw.inodes_header;
	le16_add_cpu(&hdr->valid_inodes, (u16)count);
	down_read(&node->bmap_array.lock);
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP];
	bmap_bytes = node->bmap_array.bmap_bytes;
	spin_lock(&bmap->lock);
	memcpy(hdr->bmap, bmap->ptr, bmap_bytes);
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);
	node->items_area.items_count += count;
	up_write(&node->header_lock);

	err = ssdfs_set_node_header_dirty(node, items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto finish_allocate_item;
	}

	err = ssdfs_set_dirty_items_range(node, items_capacity,
					  start, count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  start, count, err);
		goto finish_allocate_item;
	}

finish_allocate_item:
	ssdfs_unlock_items_range(node, (u16)start, (u16)count);
	up_read(&node->full_lock);

	if (unlikely(err))
		return err;

	itree = (struct ssdfs_inodes_btree_info *)node->tree;

	spin_lock(&itree->lock);
	if (itree->free_inodes < count)
		err = -ERANGE;
	else {
		u64 upper_bound = start_hash + start + count - 1;

		itree->allocated_inodes += count;
		itree->free_inodes -= count;
		if (itree->upper_allocated_ino < upper_bound)
			itree->upper_allocated_ino = upper_bound;
	}
	spin_unlock(&itree->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to correct free_inodes count: "
			  "err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_inodes_btree_node_allocate_item() - allocate item in the node
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to allocate an item in the node.
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
int ssdfs_inodes_btree_node_allocate_item(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search)
{
	int state;
	u64 start_hash;
	u64 end_hash;
	unsigned long start = ULONG_MAX;
	unsigned int count = 0;
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

	ssdfs_debug_btree_search_object(search);

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
	BUG_ON(search->request.count != 1);
	BUG_ON(search->result.buf);
	BUG_ON(search->result.buf_state !=
		SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	state = atomic_read(&node->items_area.state);
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	up_read(&node->header_lock);

	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = ssdfs_define_allocated_range(search,
					   start_hash, end_hash,
					   &start, &count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define allocated range: err %d\n",
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(start >= U16_MAX);
	BUG_ON(count >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (count != 1) {
		SSDFS_ERR("invalid count %u\n",
			  count);
		return -ERANGE;
	}

	err = __ssdfs_btree_node_allocate_range(node, search,
						start, count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate range "
			  "(start %lu, count %u), err %d\n",
			  start, count, err);
		return err;
	}

	ssdfs_debug_btree_node_object(node);

	return 0;
}

/*
 * ssdfs_inodes_btree_node_allocate_range() - allocate range of items
 * @node: pointer on node object
 * @search: pointer on search request object
 *
 * This method tries to allocate a range of items in the node.
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
int ssdfs_inodes_btree_node_allocate_range(struct ssdfs_btree_node *node,
					   struct ssdfs_btree_search *search)
{
	int state;
	u64 start_hash;
	u64 end_hash;
	unsigned long start = ULONG_MAX;
	unsigned int count = 0;
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
	BUG_ON(search->result.buf);
	BUG_ON(search->result.buf_state !=
		SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	state = atomic_read(&node->items_area.state);
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	up_read(&node->header_lock);

	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = ssdfs_define_allocated_range(search,
					   start_hash, end_hash,
					   &start, &count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define allocated range: err %d\n",
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(start >= U16_MAX);
	BUG_ON(count >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_btree_node_allocate_range(node, search,
						start, count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate range "
			  "(start %lu, count %u), err %d\n",
			  start, count, err);
		return err;
	}

	return 0;
}

static
int ssdfs_inodes_btree_node_insert_item(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

/*
 * __ssdfs_inodes_btree_node_insert_range() - insert range into node
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to insert the range of inodes into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int __ssdfs_inodes_btree_node_insert_range(struct ssdfs_btree_node *node,
					   struct ssdfs_btree_search *search)
{
	struct ssdfs_btree *tree;
	struct ssdfs_inodes_btree_info *itree;
	struct ssdfs_btree_node_items_area items_area;
	size_t item_size = sizeof(struct ssdfs_inode);
	u16 item_index;
	int free_items;
	u16 inodes_count = 0;
	u32 used_space;
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
	case SSDFS_INODES_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	itree = (struct ssdfs_inodes_btree_info *)node->tree;

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

	if (items_area.min_item_size != 0 ||
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

	SSDFS_DBG("items_capacity %u, items_count %u\n",
		  items_area.items_capacity,
		  items_area.items_count);

	SSDFS_DBG("area_size %u, free_space %u\n",
		  items_area.area_size,
		  items_area.free_space);

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

	if (free_items != items_area.items_capacity) {
		SSDFS_WARN("free_items %d != items_capacity %u\n",
			   free_items, items_area.items_capacity);
		return -ERANGE;
	}

	if (((u64)free_items * item_size) > items_area.free_space) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid free_items: "
			  "free_items %d, item_size %zu, free_space %u\n",
			  free_items, item_size, items_area.free_space);
		return -EFAULT;
	}

	item_index = search->result.start_index;
	if (item_index != 0) {
		SSDFS_ERR("start_index != 0\n");
		return -ERANGE;
	} else if ((item_index + search->request.count) >= items_area.items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	down_write(&node->full_lock);

	inodes_count = search->request.count;

	if ((item_index + inodes_count) > items_area.items_capacity) {
		err = -ERANGE;
		SSDFS_ERR("invalid inodes_count: "
			  "item_index %u, inodes_count %u, "
			  "items_capacity %u\n",
			  item_index, inodes_count,
			  items_area.items_capacity);
		goto finish_detect_affected_items;
	}

	err = ssdfs_lock_items_range(node, item_index, inodes_count);
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
		goto finish_insert_item;

	err = ssdfs_generic_insert_range(node, &items_area,
					 item_size, search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to insert item: err %d\n",
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

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		goto unlock_items_range;
	}

	err = ssdfs_allocate_items_range(node, search,
					 items_area.items_capacity,
					 item_index, inodes_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate range: "
			  "start %u, len %u, err %d\n",
			  item_index, inodes_count, err);
		goto unlock_items_range;
	}

	err = ssdfs_set_node_header_dirty(node, items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto unlock_items_range;
	}

	err = ssdfs_set_dirty_items_range(node, items_area.items_capacity,
					  item_index, inodes_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  item_index, inodes_count, err);
		goto unlock_items_range;
	}

unlock_items_range:
	ssdfs_unlock_items_range(node, item_index, inodes_count);

finish_insert_item:
	up_read(&node->full_lock);

	ssdfs_debug_btree_node_object(node);

	return err;
}

/*
 * ssdfs_inodes_btree_node_insert_range() - insert range of items
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
int ssdfs_inodes_btree_node_insert_range(struct ssdfs_btree_node *node,
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

	SSDFS_DBG("free_space %u\n", node->items_area.free_space);

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid result's state %#x\n",
			  search->result.state);
		return -ERANGE;
	}

	if (search->result.err == -ENODATA) {
		/*
		 * Node doesn't contain inserting items.
		 */
	} else if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count <= 1);
	BUG_ON(!search->result.buf);
	BUG_ON(search->result.buf_state != SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->state);
	if (state != SSDFS_BTREE_NODE_CREATED) {
		SSDFS_ERR("invalid node's state %#x\n",
			  state);
		return -ERANGE;
	}

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = __ssdfs_inodes_btree_node_insert_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert range: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	SSDFS_DBG("free_space %u\n", node->items_area.free_space);

	return 0;
}

/*
 * ssdfs_inodes_btree_node_change_item() - change an item in the node
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
 */
static
int ssdfs_inodes_btree_node_change_item(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	int state;
	u16 item_index;
	u16 items_count;
	u16 items_capacity;
	u64 start_hash;
	u64 end_hash;
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

	ssdfs_debug_btree_search_object(search);

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

	if (items_capacity == 0 || items_capacity < items_count) {
		SSDFS_ERR("invalid items accounting: "
			  "node_id %u, items_capacity %u, items_count %u\n",
			  search->node.id, items_capacity, items_count);
		return -ERANGE;
	}

	item_index = search->result.start_index;
	if ((item_index + search->request.count) > items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u, "
			  "items_capacity %u\n",
			  item_index, search->request.count,
			  items_capacity);
		return -ERANGE;
	}

	if ((start_hash + item_index) != search->request.start.hash) {
		SSDFS_WARN("node (start_hash %llx, index %u), "
			   "request (start_hash %llx, end_hash %llx)\n",
			   start_hash, item_index,
			   search->request.start.hash,
			   search->request.end.hash);
		return -ERANGE;
	}

	down_write(&node->full_lock);

	err = ssdfs_lock_items_range(node, item_index, search->result.count);
	if (err == -ENOENT) {
		up_write(&node->full_lock);
		return -ERANGE;
	} else if (err == -ENODATA) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (unlikely(err))
		BUG();

	downgrade_write(&node->full_lock);

	if (!is_ssdfs_node_items_range_allocated(node, items_capacity,
						 item_index,
						 search->result.count)) {
		err = -ERANGE;
		SSDFS_WARN("range wasn't be allocated: "
			   "start %u, count %u\n",
			   item_index, search->result.count);
		goto finish_change_item;
	}

	err = ssdfs_copy_item_into_node_unlocked(node, search, item_index, 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy item into the node: "
			  "item_index %u, err %d\n",
			  item_index, err);
		goto finish_change_item;
	}

	err = ssdfs_set_dirty_items_range(node, items_capacity,
					  item_index,
					  search->result.count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  item_index, search->result.count, err);
		goto finish_change_item;
	}

	ssdfs_unlock_items_range(node, item_index, search->result.count);

finish_change_item:
	up_read(&node->full_lock);

	ssdfs_debug_btree_node_object(node);

	return err;
}

/*
 * ssdfs_inodes_btree_node_clear_range() - clear range of deleted items
 * @node: pointer on node object
 * @area: items area descriptor
 * @item_size: size of item in bytes
 * @search: search object
 *
 * This method tries to clear the range of deleted items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_inodes_btree_node_clear_range(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *area,
				size_t item_size,
				struct ssdfs_btree_search *search)
{
	int page_index;
	int dst_index;
	struct page *page;
	u32 item_offset;
	void *kaddr;
	u16 cleared_items = 0;
	u16 start_index;
	unsigned int range_len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_size %zu\n",
		  node->node_id, item_size);

	start_index = search->result.start_index;
	range_len = search->request.count;

	SSDFS_DBG("start_index %u, range_len %u\n",
		  start_index, range_len);

	if (range_len == 0) {
		SSDFS_WARN("search->request.count == 0\n");
		return -ERANGE;
	}

	if (start_index > area->items_count) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, items_count %u\n",
			  start_index, area->items_count);
		return -ERANGE;
	} else if ((start_index + range_len) > area->items_capacity) {
		SSDFS_ERR("range is out of capacity: "
			  "start_index %u, range_len %u, items_capacity %u\n",
			  start_index, range_len, area->items_capacity);
		return -ERANGE;
	}

	dst_index = start_index;

	do {
		u32 clearing_items;
		u32 vacant_positions;

		SSDFS_DBG("start_index %u, dst_index %d\n",
			  start_index, dst_index);

		item_offset = (u32)dst_index * item_size;
		if (item_offset >= area->area_size) {
			SSDFS_ERR("item_offset %u >= area_size %u\n",
				  item_offset, area->area_size);
			return -ERANGE;
		}

		item_offset += area->offset;
		if (item_offset >= node->node_size) {
			SSDFS_ERR("item_offset %u >= node_size %u\n",
				  item_offset, node->node_size);
			return -ERANGE;
		}

		page_index = item_offset >> PAGE_SHIFT;
		if (page_index >= pagevec_count(&node->content.pvec)) {
			SSDFS_ERR("invalid page_index: "
				  "index %d, pvec_size %u\n",
				  page_index,
				  pagevec_count(&node->content.pvec));
			return -ERANGE;
		}

		if (page_index > 0)
			item_offset %= page_index * PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(start_index > dst_index);
#endif /* CONFIG_SSDFS_DEBUG */

		clearing_items = dst_index - start_index;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(clearing_items > range_len);
#endif /* CONFIG_SSDFS_DEBUG */

		clearing_items = range_len - clearing_items;

		if (clearing_items == 0) {
			SSDFS_WARN("no items for clearing\n");
			return -ERANGE;
		}

		vacant_positions = PAGE_SIZE - item_offset;
		vacant_positions /= item_size;

		if (vacant_positions == 0) {
			SSDFS_WARN("invalid vacant_positions %u\n",
				   vacant_positions);
			return -ERANGE;
		}

		clearing_items = min_t(u32, clearing_items, vacant_positions);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(clearing_items >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		SSDFS_DBG("clearing_items %u, item_offset %u\n",
			  clearing_items, item_offset);

		page = node->content.pvec.pages[page_index];
		kaddr = kmap_atomic(page);
		memset((u8 *)kaddr + item_offset,
			0x0,
			clearing_items * item_size);
		kunmap_atomic(kaddr);

		dst_index += clearing_items;
		cleared_items += clearing_items;
	} while (cleared_items < range_len);

	if (cleared_items != range_len) {
		SSDFS_ERR("cleared_items %u != range_len %u\n",
			  cleared_items, range_len);
		return -ERANGE;
	}

	return 0;
}

/*
 * __ssdfs_inodes_btree_node_delete_range() - delete range of items
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
 */
static
int __ssdfs_inodes_btree_node_delete_range(struct ssdfs_btree_node *node,
					    struct ssdfs_btree_search *search)
{
	struct ssdfs_inodes_btree_info *itree;
	struct ssdfs_inodes_btree_node_header *hdr;
	struct ssdfs_state_bitmap *bmap;
	int state;
	u16 item_index;
	u16 item_size;
	u16 items_count;
	u16 items_capacity;
	int free_items;
	u64 start_hash;
	u64 end_hash;
	u32 bmap_bytes;
	u16 valid_inodes;
	u64 free_inodes;
	u64 inodes_capacity;
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

	down_read(&node->header_lock);
	state = atomic_read(&node->items_area.state);
	item_size = node->items_area.item_size;
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

	if (items_capacity == 0 || items_capacity < items_count) {
		SSDFS_ERR("invalid items accounting: "
			  "node_id %u, items_capacity %u, items_count %u\n",
			  search->node.id, items_capacity, items_count);
		return -ERANGE;
	}

	free_items = items_capacity - items_count;
	if (unlikely(free_items < 0 || free_items > items_capacity)) {
		SSDFS_WARN("invalid free_items %d\n",
			   free_items);
		return -ERANGE;
	} else if (free_items == items_capacity) {
		SSDFS_DBG("node hasn't any items\n");
		return 0;
	}

	item_index = search->result.start_index;
	if ((item_index + search->request.count) > items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u, "
			  "items_capacity %u\n",
			  item_index, search->request.count,
			  items_capacity);
		return -ERANGE;
	}

	if ((start_hash + item_index) != search->request.start.hash) {
		SSDFS_WARN("node (start_hash %llx, index %u), "
			   "request (start_hash %llx, end_hash %llx)\n",
			   start_hash, item_index,
			   search->request.start.hash,
			   search->request.end.hash);
		return -ERANGE;
	}

	down_write(&node->full_lock);

	err = ssdfs_lock_items_range(node, item_index, search->request.count);
	if (err == -ENOENT) {
		up_write(&node->full_lock);
		return -ERANGE;
	} else if (err == -ENODATA) {
		up_write(&node->full_lock);
		wake_up_all(&node->wait_queue);
		return -ERANGE;
	} else if (unlikely(err))
		BUG();

	downgrade_write(&node->full_lock);

	if (!is_ssdfs_node_items_range_allocated(node, items_capacity,
						 item_index,
						 search->result.count)) {
		err = -ERANGE;
		SSDFS_WARN("range wasn't be allocated: "
			   "start %u, count %u\n",
			   item_index, search->result.count);
		goto finish_delete_range;
	}

	err = ssdfs_free_items_range(node, item_index, search->result.count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to free range: "
			  "start %u, count %u, err %d\n",
			  item_index, search->result.count, err);
		goto finish_delete_range;
	}

	err = ssdfs_inodes_btree_node_clear_range(node, &node->items_area,
						  item_size, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to clear items range: err %d\n",
			  err);
		goto finish_delete_range;
	}

	ssdfs_clear_dirty_items_range_state(node, item_index,
					    search->result.count);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count == 0 || search->result.count >= U16_MAX);
	BUG_ON(search->request.count != search->result.count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&node->header_lock);
	hdr = &node->raw.inodes_header;
	valid_inodes = le16_to_cpu(hdr->valid_inodes);
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(valid_inodes < search->result.count);
#endif /* CONFIG_SSDFS_DEBUG */
	hdr->valid_inodes = cpu_to_le16(valid_inodes - search->result.count);
	down_read(&node->bmap_array.lock);
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP];
	bmap_bytes = node->bmap_array.bmap_bytes;
	spin_lock(&bmap->lock);
	memcpy(hdr->bmap, bmap->ptr, bmap_bytes);
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);
	node->items_area.items_count -= search->result.count;
	up_write(&node->header_lock);

	err = ssdfs_set_node_header_dirty(node, items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto finish_delete_range;
	}

finish_delete_range:
	ssdfs_unlock_items_range(node, item_index, search->request.count);
	up_read(&node->full_lock);

	if (unlikely(err))
		return err;

	itree = (struct ssdfs_inodes_btree_info *)node->tree;

	spin_lock(&itree->lock);
	free_inodes = itree->free_inodes;
	inodes_capacity = itree->inodes_capacity;
	if (itree->allocated_inodes < search->request.count)
		err = -ERANGE;
	else if ((free_inodes + search->request.count) > inodes_capacity)
		err = -ERANGE;
	else {
		itree->allocated_inodes -= search->request.count;
		itree->free_inodes += search->request.count;
	}
	spin_unlock(&itree->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to correct allocated_inodes count: "
			  "err %d\n",
			  err);
		return err;
	}

	if (valid_inodes == 0)
		search->result.state = SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE;
	else
		search->result.state = SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;

	return 0;
}

/*
 * ssdfs_inodes_btree_node_delete_item() - delete an item from the node
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
 */
static
int ssdfs_inodes_btree_node_delete_item(struct ssdfs_btree_node *node,
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

	err = __ssdfs_inodes_btree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete inode: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_inodes_btree_node_delete_range() - delete a range of items
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
 */
static
int ssdfs_inodes_btree_node_delete_range(struct ssdfs_btree_node *node,
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

	err = __ssdfs_inodes_btree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete inodes range: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_inodes_btree_node_extract_range() - extract range of items from node
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
int ssdfs_inodes_btree_node_extract_range(struct ssdfs_btree_node *node,
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
						sizeof(struct ssdfs_inode),
						search);
}

static
int ssdfs_inodes_btree_resize_items_area(struct ssdfs_btree_node *node,
					 u32 new_size)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

void ssdfs_debug_inodes_btree_object(struct ssdfs_inodes_btree_info *tree)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct list_head *this, *next;

	BUG_ON(!tree);

	SSDFS_DBG("INODES TREE: is_locked %d, upper_allocated_ino %llu, "
		  "allocated_inodes %llu, free_inodes %llu, "
		  "inodes_capacity %llu, leaf_nodes %u, "
		  "nodes_count %u\n",
		  spin_is_locked(&tree->lock),
		  tree->upper_allocated_ino,
		  tree->allocated_inodes,
		  tree->free_inodes,
		  tree->inodes_capacity,
		  tree->leaf_nodes,
		  tree->nodes_count);

	ssdfs_debug_btree_object(&tree->generic_tree);

	SSDFS_DBG("ROOT FOLDER: magic %#x, mode %#x, flags %#x, "
		  "uid %u, gid %u, atime %llu, ctime %llu, "
		  "mtime %llu, birthtime %llu, "
		  "atime_nsec %u, ctime_nsec %u, mtime_nsec %u, "
		  "birthtime_nsec %u, generation %llu, "
		  "size %llu, blocks %llu, parent_ino %llu, "
		  "refcount %u, checksum %#x, ino %llu, "
		  "hash_code %llu, name_len %u, "
		  "private_flags %#x, dentries %u\n",
		  le16_to_cpu(tree->root_folder.magic),
		  le16_to_cpu(tree->root_folder.mode),
		  le32_to_cpu(tree->root_folder.flags),
		  le32_to_cpu(tree->root_folder.uid),
		  le32_to_cpu(tree->root_folder.gid),
		  le64_to_cpu(tree->root_folder.atime),
		  le64_to_cpu(tree->root_folder.ctime),
		  le64_to_cpu(tree->root_folder.mtime),
		  le64_to_cpu(tree->root_folder.birthtime),
		  le32_to_cpu(tree->root_folder.atime_nsec),
		  le32_to_cpu(tree->root_folder.ctime_nsec),
		  le32_to_cpu(tree->root_folder.mtime_nsec),
		  le32_to_cpu(tree->root_folder.birthtime_nsec),
		  le64_to_cpu(tree->root_folder.generation),
		  le64_to_cpu(tree->root_folder.size),
		  le64_to_cpu(tree->root_folder.blocks),
		  le64_to_cpu(tree->root_folder.parent_ino),
		  le32_to_cpu(tree->root_folder.refcount),
		  le32_to_cpu(tree->root_folder.checksum),
		  le64_to_cpu(tree->root_folder.ino),
		  le64_to_cpu(tree->root_folder.hash_code),
		  le16_to_cpu(tree->root_folder.name_len),
		  le16_to_cpu(tree->root_folder.private_flags),
		  le32_to_cpu(tree->root_folder.count_of.dentries));

	SSDFS_DBG("PRIVATE AREA DUMP:\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     &tree->root_folder.internal[0],
			     sizeof(struct ssdfs_inode_private_area));
	SSDFS_DBG("\n");

	if (!list_empty_careful(&tree->free_inodes_queue.list)) {
		SSDFS_DBG("FREE INODES RANGES:\n");

		list_for_each_safe(this, next, &tree->free_inodes_queue.list) {
			struct ssdfs_inodes_btree_range *range;

			range = list_entry(this,
					   struct ssdfs_inodes_btree_range,
					   list);

			if (range) {
				SSDFS_DBG("[node_id %u, start_hash %llx, "
					  "start_index %u, count %u], ",
					  range->node_id,
					  range->area.start_hash,
					  range->area.start_index,
					  range->area.count);
			}
		}

		SSDFS_DBG("\n");
	}
#endif /* CONFIG_SSDFS_DEBUG */
}

const struct ssdfs_btree_descriptor_operations ssdfs_inodes_btree_desc_ops = {
	.init		= ssdfs_inodes_btree_desc_init,
	.flush		= ssdfs_inodes_btree_desc_flush,
};

const struct ssdfs_btree_operations ssdfs_inodes_btree_ops = {
	.create_root_node	= ssdfs_inodes_btree_create_root_node,
	.create_node		= ssdfs_inodes_btree_create_node,
	.init_node		= ssdfs_inodes_btree_init_node,
	.destroy_node		= ssdfs_inodes_btree_destroy_node,
	.add_node		= ssdfs_inodes_btree_add_node,
	.delete_node		= ssdfs_inodes_btree_delete_node,
	.pre_flush_root_node	= ssdfs_inodes_btree_pre_flush_root_node,
	.flush_root_node	= ssdfs_inodes_btree_flush_root_node,
	.pre_flush_node		= ssdfs_inodes_btree_pre_flush_node,
	.flush_node		= ssdfs_inodes_btree_flush_node,
};

const struct ssdfs_btree_node_operations ssdfs_inodes_btree_node_ops = {
	.find_item		= ssdfs_inodes_btree_node_find_item,
	.find_range		= ssdfs_inodes_btree_node_find_range,
	.extract_range		= ssdfs_inodes_btree_node_extract_range,
	.allocate_item		= ssdfs_inodes_btree_node_allocate_item,
	.allocate_range		= ssdfs_inodes_btree_node_allocate_range,
	.insert_item		= ssdfs_inodes_btree_node_insert_item,
	.insert_range		= ssdfs_inodes_btree_node_insert_range,
	.change_item		= ssdfs_inodes_btree_node_change_item,
	.delete_item		= ssdfs_inodes_btree_node_delete_item,
	.delete_range		= ssdfs_inodes_btree_node_delete_range,
	.resize_items_area	= ssdfs_inodes_btree_resize_items_area,
};
