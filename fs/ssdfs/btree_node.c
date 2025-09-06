/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/btree_node.c - generalized btree node implementation.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2025 Viacheslav Dubeyko <slava@dubeyko.com>
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "extents_queue.h"
#include "btree.h"
#include "shared_extents_tree.h"
#include "diff_on_write.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_btree_node_folio_leaks;
atomic64_t ssdfs_btree_node_memory_leaks;
atomic64_t ssdfs_btree_node_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_btree_node_cache_leaks_increment(void *kaddr)
 * void ssdfs_btree_node_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_btree_node_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_btree_node_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_btree_node_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_btree_node_kfree(void *kaddr)
 * struct folio *ssdfs_btree_node_alloc_folio(gfp_t gfp_mask,
 *                                            unsigned int order)
 * struct folio *ssdfs_btree_node_add_batch_folio(struct folio_batch *batch,
 *                                                unsigned int order)
 * void ssdfs_btree_node_free_folio(struct folio *folio)
 * void ssdfs_btree_node_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(btree_node)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(btree_node)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_btree_node_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_btree_node_folio_leaks, 0);
	atomic64_set(&ssdfs_btree_node_memory_leaks, 0);
	atomic64_set(&ssdfs_btree_node_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_btree_node_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_btree_node_folio_leaks) != 0) {
		SSDFS_ERR("BTREE NODE: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_btree_node_folio_leaks));
	}

	if (atomic64_read(&ssdfs_btree_node_memory_leaks) != 0) {
		SSDFS_ERR("BTREE NODE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_btree_node_memory_leaks));
	}

	if (atomic64_read(&ssdfs_btree_node_cache_leaks) != 0) {
		SSDFS_ERR("BTREE NODE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_btree_node_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_btree_node_forget_folio_batch(struct folio_batch *batch)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	int i;

	for (i = 0; i < folio_batch_count(batch); i++) {
		ssdfs_btree_node_forget_folio(batch->folios[i]);
	}

#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/******************************************************************************
 *                            BTREE NODE CACHE                                *
 ******************************************************************************/

static struct kmem_cache *ssdfs_btree_node_obj_cachep;

void ssdfs_zero_btree_node_obj_cache_ptr(void)
{
	ssdfs_btree_node_obj_cachep = NULL;
}

static void ssdfs_init_btree_node_object_once(void *obj)
{
	struct ssdfs_btree_node *node_obj = obj;

	memset(node_obj, 0, sizeof(struct ssdfs_btree_node));
}

void ssdfs_shrink_btree_node_obj_cache(void)
{
	if (ssdfs_btree_node_obj_cachep)
		kmem_cache_shrink(ssdfs_btree_node_obj_cachep);
}

void ssdfs_destroy_btree_node_obj_cache(void)
{
	if (ssdfs_btree_node_obj_cachep)
		kmem_cache_destroy(ssdfs_btree_node_obj_cachep);
}

int ssdfs_init_btree_node_obj_cache(void)
{
	ssdfs_btree_node_obj_cachep =
			kmem_cache_create("ssdfs_btree_node_obj_cache",
					sizeof(struct ssdfs_btree_node), 0,
					SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
					ssdfs_init_btree_node_object_once);
	if (!ssdfs_btree_node_obj_cachep) {
		SSDFS_ERR("unable to create btree node objects cache\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_btree_node_alloc() - allocate memory for btree node object
 */
static
struct ssdfs_btree_node *ssdfs_btree_node_alloc(void)
{
	struct ssdfs_btree_node *ptr;
	unsigned int nofs_flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_btree_node_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	nofs_flags = memalloc_nofs_save();
	ptr = kmem_cache_alloc(ssdfs_btree_node_obj_cachep, GFP_KERNEL);
	memalloc_nofs_restore(nofs_flags);

	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for btree node object\n");
		return ERR_PTR(-ENOMEM);
	}

	ssdfs_btree_node_cache_leaks_increment(ptr);

	return ptr;
}

/*
 * ssdfs_btree_node_free() - free memory for btree node object
 */
static
void ssdfs_btree_node_free(struct ssdfs_btree_node *ptr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_btree_node_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!ptr)
		return;

	ssdfs_btree_node_cache_leaks_decrement(ptr);
	kmem_cache_free(ssdfs_btree_node_obj_cachep, ptr);
}

/******************************************************************************
 *                            BTREE NODES LIST                                *
 ******************************************************************************/

/*
 * ssdfs_btree_nodes_list_init() - initialize btree nodes list
 * @bnl: btree nodes list
 */
void ssdfs_btree_nodes_list_init(struct ssdfs_btree_nodes_list *bnl)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bnl);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock_init(&bnl->lock);
	INIT_LIST_HEAD(&bnl->list);
}

/*
 * is_ssdfs_btree_nodes_list_empty() - check that btree nodes list is empty
 * @bnl: btree nodes list
 */
bool is_ssdfs_btree_nodes_list_empty(struct ssdfs_btree_nodes_list *bnl)
{
	bool is_empty;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bnl);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&bnl->lock);
	is_empty = list_empty_careful(&bnl->list);
	spin_unlock(&bnl->lock);

	return is_empty;
}

/*
 * ssdfs_btree_nodes_list_add() - add node at the tail of list
 * @bnl: btree nodes list
 * @node: node object
 */
void ssdfs_btree_nodes_list_add(struct ssdfs_btree_nodes_list *bnl,
				struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bnl || !node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));

	spin_lock(&bnl->lock);
	list_add_tail(&node->list, &bnl->list);
	spin_unlock(&bnl->lock);
}

/*
 * ssdfs_btree_nodes_list_delete() - remove node from the list
 * @bnl: btree nodes list
 * @node: node object
 */
void ssdfs_btree_nodes_list_delete(struct ssdfs_btree_nodes_list *bnl,
				   struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bnl || !node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));

	spin_lock(&bnl->lock);
	list_del(&node->list);
	spin_unlock(&bnl->lock);
}

/******************************************************************************
 *                     BTREE NODE PROTECTION WINDOW                           *
 ******************************************************************************/

void ssdfs_btree_node_start_request_cno(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_protection_account_request(&node->content.protection,
			ssdfs_current_cno(node->tree->fsi->sb));
}

void ssdfs_btree_node_finish_request_cno(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_protection_forget_request(&node->content.protection,
			ssdfs_current_cno(node->tree->fsi->sb));
}

bool is_it_time_free_btree_node_content(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	u64 create_cno;
	u64 last_request_cno;
	u32 reqs_count;
	u64 protected_range;
	u64 future_request_cno;
#endif /* CONFIG_SSDFS_DEBUG */
	u64 cur_cno;
	bool dont_touch = false;

	if (atomic_read(&node->type) == SSDFS_BTREE_ROOT_NODE)
		return false;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_UNKNOWN_STATE:
	case SSDFS_BTREE_NODE_CREATED:
	case SSDFS_BTREE_NODE_NONE_CONTENT:
	case SSDFS_BTREE_NODE_CONTENT_PREPARED:
	case SSDFS_BTREE_NODE_DIRTY:
	case SSDFS_BTREE_NODE_PRE_DELETED:
	case SSDFS_BTREE_NODE_INVALID:
	case SSDFS_BTREE_NODE_CORRUPTED:
		return false;

	case SSDFS_BTREE_NODE_INITIALIZED:
		/* continue logic */
		break;

	default:
		BUG();
	}

	spin_lock(&node->content.protection.cno_lock);

	if (node->content.protection.reqs_count > 0) {
		/* node has pending requests */
		dont_touch = true;
	} else {
		cur_cno = ssdfs_current_cno(node->tree->fsi->sb);
		if (cur_cno <= node->content.protection.future_request_cno) {
			/* node is under protection window yet */
			dont_touch = true;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	create_cno = node->content.protection.create_cno;
	last_request_cno = node->content.protection.last_request_cno;
	reqs_count = node->content.protection.reqs_count;
	protected_range = node->content.protection.protected_range;
	future_request_cno = node->content.protection.future_request_cno;
#endif /* CONFIG_SSDFS_DEBUG */

	spin_unlock(&node->content.protection.cno_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, create_cno %llu, "
		  "last_request_cno %llu, reqs_count %u, "
		  "protected_range %llu, future_request_cno %llu, "
		  "dont_touch %#x\n",
		  node->node_id, create_cno,
		  last_request_cno, reqs_count,
		  protected_range, future_request_cno,
		  dont_touch);
#endif /* CONFIG_SSDFS_DEBUG */

	return !dont_touch;
}

/******************************************************************************
 *                        BTREE NODE OBJECT FUNCTIONALITY                     *
 ******************************************************************************/

/*
 * ssdfs_btree_node_create_empty_index_area() - create empty index area
 * @tree: btree object
 * @node: node object
 * @type: node's type
 * @start_hash: starting hash of the node
 *
 * This method tries to create the empty index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_btree_node_create_empty_index_area(struct ssdfs_btree *tree,
					     struct ssdfs_btree_node *node,
					     int type,
					     u64 start_hash)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !node);

	if (type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_WARN("invalid node type %#x\n", type);
		return -EINVAL;
	}

	SSDFS_DBG("tree %p, node %p, "
		  "type %#x, start_hash %llx\n",
		  tree, node, type, start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(&node->index_area, 0xFF,
		sizeof(struct ssdfs_btree_node_index_area));

	atomic_set(&node->index_area.flags, 0);

	switch (type) {
	case SSDFS_BTREE_ROOT_NODE:
		atomic_set(&node->index_area.state,
				SSDFS_BTREE_NODE_INDEX_AREA_EXIST);
		node->index_area.offset =
			offsetof(struct ssdfs_btree_inline_root_node, indexes);
		node->index_area.index_size = sizeof(struct ssdfs_btree_index);
		node->index_area.index_capacity =
					SSDFS_BTREE_ROOT_NODE_INDEX_COUNT;
		node->index_area.area_size = node->index_area.index_size;
		node->index_area.area_size *= node->index_area.index_capacity;
		node->index_area.index_count = 0;
		node->index_area.start_hash = start_hash;
		node->index_area.end_hash = U64_MAX;
		break;

	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_INDEX_NODE:
		/*
		 * Partial preliminary initialization.
		 * The final creation should be done in specialized
		 * tree->btree_ops->create_node() and
		 * tree->btree_ops->init_node() methods.
		 */
		atomic_set(&node->index_area.state,
				SSDFS_BTREE_NODE_INDEX_AREA_EXIST);
		atomic_or(SSDFS_BTREE_NODE_HAS_INDEX_AREA, &node->flags);
		node->index_area.index_size =
					sizeof(struct ssdfs_btree_index_key);
		node->index_area.index_count = 0;
		node->index_area.start_hash = start_hash;
		node->index_area.end_hash = U64_MAX;
		break;

	case SSDFS_BTREE_LEAF_NODE:
		atomic_set(&node->index_area.state,
				SSDFS_BTREE_NODE_AREA_ABSENT);
		node->index_area.index_size = 0;
		node->index_area.index_capacity = 0;
		node->index_area.area_size = 0;
		node->index_area.index_count = 0;
		break;

	default:
		SSDFS_WARN("invalid node type %#x\n", type);
		return -EINVAL;
	}

	return 0;
}

/*
 * ssdfs_btree_node_create_empty_items_area() - create empty items area
 * @tree: btree object
 * @node: node object
 * @type: node's type
 * @start_hash: starting hash of the node
 *
 * This method tries to create the empty index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_btree_node_create_empty_items_area(struct ssdfs_btree *tree,
					     struct ssdfs_btree_node *node,
					     int type,
					     u64 start_hash)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !node);

	if (type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_WARN("invalid node type %#x\n", type);
		return -EINVAL;
	}

	SSDFS_DBG("tree %p, node %p, "
		  "type %#x, start_hash %llx\n",
		  tree, node, type, start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(&node->items_area, 0xFF,
		sizeof(struct ssdfs_btree_node_items_area));

	atomic_set(&node->items_area.flags, 0);

	switch (type) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_INDEX_NODE:
		atomic_set(&node->items_area.state,
				SSDFS_BTREE_NODE_AREA_ABSENT);
		node->items_area.area_size = 0;
		node->items_area.item_size = 0;
		node->items_area.min_item_size = 0;
		node->items_area.max_item_size = 0;
		node->items_area.items_count = 0;
		node->items_area.items_capacity = 0;
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		/*
		 * Partial preliminary initialization.
		 * The final creation should be done in specialized
		 * tree->btree_ops->create_node() and
		 * tree->btree_ops->init_node() methods.
		 */
		atomic_set(&node->items_area.state,
				SSDFS_BTREE_NODE_ITEMS_AREA_EXIST);
		atomic_or(SSDFS_BTREE_NODE_HAS_ITEMS_AREA, &node->flags);
		node->items_area.item_size = tree->item_size;
		node->items_area.min_item_size = tree->min_item_size;
		node->items_area.max_item_size = tree->max_item_size;
		node->items_area.start_hash = start_hash;
		node->items_area.end_hash = start_hash;
		break;

	case SSDFS_BTREE_LEAF_NODE:
		atomic_set(&node->items_area.state,
				SSDFS_BTREE_NODE_ITEMS_AREA_EXIST);
		atomic_or(SSDFS_BTREE_NODE_HAS_ITEMS_AREA, &node->flags);
		node->items_area.item_size = tree->item_size;
		node->items_area.min_item_size = tree->min_item_size;
		node->items_area.max_item_size = tree->max_item_size;
		node->items_area.start_hash = start_hash;
		node->items_area.end_hash = start_hash;
		break;

	default:
		SSDFS_WARN("invalid node type %#x\n", type);
		return -EINVAL;
	}

	return 0;
}

/*
 * ssdfs_btree_node_create_empty_lookup_table() - create empty lookup table
 * @node: node object
 *
 * This method tries to create the empty lookup table area.
 */
static
void ssdfs_btree_node_create_empty_lookup_table(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node %p\n", node);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(&node->lookup_tbl_area, 0xFF,
		sizeof(struct ssdfs_btree_node_index_area));

	atomic_set(&node->lookup_tbl_area.state,
			SSDFS_BTREE_NODE_AREA_ABSENT);
	node->lookup_tbl_area.index_size = 0;
	node->lookup_tbl_area.index_capacity = 0;
	node->lookup_tbl_area.area_size = 0;
	node->lookup_tbl_area.index_count = 0;
}

/*
 * ssdfs_btree_node_create_empty_hash_table() - create empty hash table
 * @node: node object
 *
 * This method tries to create the empty hash table area.
 */
static
void ssdfs_btree_node_create_empty_hash_table(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node %p\n", node);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(&node->hash_tbl_area, 0xFF,
		sizeof(struct ssdfs_btree_node_index_area));

	atomic_set(&node->hash_tbl_area.state,
			SSDFS_BTREE_NODE_AREA_ABSENT);
	node->hash_tbl_area.index_size = 0;
	node->hash_tbl_area.index_capacity = 0;
	node->hash_tbl_area.area_size = 0;
	node->hash_tbl_area.index_count = 0;
}

/*
 * ssdfs_btree_node_create() - create btree node object
 * @tree: btree object
 * @node_id: node ID number
 * @parent: parent node
 * @height: node's height
 * @type: node's type
 * @start_hash: starting hash of the node
 *
 * This method tries to create a btree node object.
 *
 * RETURN:
 * [success] - pointer on created btree node object.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - cannot allocate memory.
 * %-ERANGE     - internal error.
 */
struct ssdfs_btree_node *
ssdfs_btree_node_create(struct ssdfs_btree *tree,
			u32 node_id,
			struct ssdfs_btree_node *parent,
			u8 height, int type,
			u64 start_hash)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_node *ptr;
	u8 tree_height;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi);

	if (type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_WARN("invalid node type %#x\n", type);
		return ERR_PTR(-EINVAL);
	}

	if (type != SSDFS_BTREE_ROOT_NODE && !parent) {
		SSDFS_WARN("node %u should have parent\n",
			   node_id);
		return ERR_PTR(-EINVAL);
	}
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, parent %p, node_id %u, "
		  "height %u, type %#x, start_hash %llx\n",
		  tree, parent, node_id, height,
		  type, start_hash);
#else
	SSDFS_DBG("tree %p, parent %p, node_id %u, "
		  "height %u, type %#x, start_hash %llx\n",
		  tree, parent, node_id, height,
		  type, start_hash);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = tree->fsi;

	ptr = ssdfs_btree_node_alloc();
	if (!ptr) {
		SSDFS_ERR("fail to allocate btree node object\n");
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&ptr->list);

	spin_lock_init(&ptr->content.protection.cno_lock);
	ptr->content.protection.create_cno = ssdfs_current_cno(fsi->sb);
	ptr->content.protection.last_request_cno =
					ptr->content.protection.create_cno;
	ptr->content.protection.reqs_count = 0;
	ptr->content.protection.protected_range =
					SSDFS_DEFAULT_PROTECTION_RANGE;
	ptr->content.protection.future_request_cno =
					ptr->content.protection.create_cno +
					SSDFS_DEFAULT_PROTECTION_RANGE;

	ptr->parent_node = parent;
	ptr->tree = tree;

	if (node_id == SSDFS_BTREE_NODE_INVALID_ID) {
		err = -EINVAL;
		SSDFS_WARN("invalid node_id\n");
		goto fail_create_node;
	}
	ptr->node_id = node_id;

	tree_height = atomic_read(&tree->height);
	if (height > tree_height) {
		err = -EINVAL;
		SSDFS_WARN("height %u > tree->height %u\n",
			   height, tree_height);
		goto fail_create_node;
	}

	atomic_set(&ptr->height, height);

#ifdef CONFIG_SSDFS_DEBUG
	if (tree->node_size < fsi->pagesize ||
	    tree->node_size > fsi->erasesize) {
		err = -EINVAL;
		SSDFS_WARN("invalid node_size %u, "
			   "pagesize %u, erasesize %u\n",
			   tree->node_size,
			   fsi->pagesize,
			   fsi->erasesize);
		goto fail_create_node;
	}
#endif /* CONFIG_SSDFS_DEBUG */
	ptr->node_size = tree->node_size;

#ifdef CONFIG_SSDFS_DEBUG
	if (tree->pages_per_node != (ptr->node_size / fsi->pagesize)) {
		err = -EINVAL;
		SSDFS_WARN("invalid pages_per_node %u, "
			   "node_size %u, pagesize %u\n",
			   tree->pages_per_node,
			   ptr->node_size,
			   fsi->pagesize);
		goto fail_create_node;
	}
#endif /* CONFIG_SSDFS_DEBUG */
	ptr->pages_per_node = tree->pages_per_node;

	ptr->create_cno = ssdfs_current_cno(fsi->sb);
	ptr->node_ops = NULL;

	atomic_set(&ptr->refs_count, 0);
	atomic_set(&ptr->flags, 0);
	atomic_set(&ptr->type, type);

	init_rwsem(&ptr->header_lock);
	memset(&ptr->raw, 0xFF, sizeof(ptr->raw));

	err = ssdfs_btree_node_create_empty_index_area(tree, ptr,
							type,
							start_hash);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create empty index area: err %d\n",
			  err);
		goto fail_create_node;
	}

	err = ssdfs_btree_node_create_empty_items_area(tree, ptr,
							type,
							start_hash);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create empty items area: err %d\n",
			  err);
		goto fail_create_node;
	}

	ssdfs_btree_node_create_empty_lookup_table(ptr);
	ssdfs_btree_node_create_empty_hash_table(ptr);

	spin_lock_init(&ptr->descriptor_lock);
	ptr->update_cno = ptr->create_cno;

	/*
	 * Partial preliminary initialization.
	 * The final creation should be done in specialized
	 * tree->btree_ops->create_node() and
	 * tree->btree_ops->init_node() methods.
	 */
	memset(&ptr->extent, 0xFF, sizeof(struct ssdfs_raw_extent));
	ptr->seg = NULL;

	ptr->node_index.node_id = cpu_to_le32(node_id);
	ptr->node_index.node_type = (u8)type;
	ptr->node_index.height = height;
	ptr->node_index.flags = cpu_to_le16(SSDFS_BTREE_INDEX_SHOW_EMPTY_NODE);
	ptr->node_index.index.hash = cpu_to_le64(start_hash);

	init_completion(&ptr->init_end);

	/*
	 * Partial preliminary initialization.
	 * The final creation should be done in specialized
	 * tree->btree_ops->create_node() and
	 * tree->btree_ops->init_node() methods.
	 */
	init_rwsem(&ptr->bmap_array.lock);
	ptr->bmap_array.bits_count = 0;
	ptr->bmap_array.bmap_bytes = 0;
	ptr->bmap_array.index_start_bit = ULONG_MAX;
	ptr->bmap_array.item_start_bit = ULONG_MAX;
	atomic_set(&ptr->bmap_array.locks_count, 0);
	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		spin_lock_init(&ptr->bmap_array.bmap[i].lock);
		ptr->bmap_array.bmap[i].flags = 0;
		ptr->bmap_array.bmap[i].ptr = NULL;
	}

	init_waitqueue_head(&ptr->wait_queue);
	init_rwsem(&ptr->full_lock);
	ssdfs_btree_node_content_init(&ptr->content);

	atomic_set(&ptr->state, SSDFS_BTREE_NODE_CREATED);

	ssdfs_btree_nodes_list_add(&fsi->btree_nodes, ptr);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return ptr;

fail_create_node:
	ptr->parent_node = NULL;
	ptr->tree = NULL;
	ssdfs_btree_node_free(ptr);
	return ERR_PTR(err);
}

/*
 * ssdfs_btree_create_root_node() - create root node
 * @node: node object
 * @root_node: pointer on the on-disk root node object
 *
 * This method tries to create the root node of the btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - corrupted root node object.
 */
int ssdfs_btree_create_root_node(struct ssdfs_btree_node *node,
				 struct ssdfs_btree_inline_root_node *root_node)
{
	struct ssdfs_btree_root_node_header *hdr;
	struct ssdfs_btree_index *index1, *index2;
	size_t rnode_size = sizeof(struct ssdfs_btree_inline_root_node);
	u8 height;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !root_node);

	SSDFS_DBG("node %p, root_node %p\n",
		  node, root_node);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr = &root_node->header;

	if (hdr->type != SSDFS_BTREE_ROOT_NODE) {
		SSDFS_ERR("invalid node type %#x\n",
			  hdr->type);
		return -EIO;
	}

	if (hdr->items_count > SSDFS_BTREE_ROOT_NODE_INDEX_COUNT) {
		SSDFS_ERR("invalid items_count %u\n",
			  hdr->items_count);
		return -EIO;
	}

	height = hdr->height;

	if (height >= U8_MAX) {
		SSDFS_ERR("invalid height %u\n",
			  height);
		return -EIO;
	}

	if (le32_to_cpu(hdr->upper_node_id) == 0) {
		height = 1;
		atomic_set(&node->tree->height, height);
		atomic_set(&node->height, height - 1);
	} else {
		if (height == 0) {
			SSDFS_ERR("invalid height %u\n",
				  height);
			return -EIO;
		}

		atomic_set(&node->tree->height, height);
		atomic_set(&node->height, height - 1);
	}

	node->node_size = rnode_size;
	node->pages_per_node = 0;
	node->create_cno = le64_to_cpu(0);
	node->tree->create_cno = node->create_cno;
	node->node_id = SSDFS_BTREE_ROOT_NODE_ID;

	node->parent_node = NULL;
	node->node_ops = NULL;

	atomic_set(&node->flags, hdr->flags);
	atomic_set(&node->type, hdr->type);

	down_write(&node->header_lock);
	ssdfs_memcpy(&node->raw.root_node, 0, rnode_size,
		     root_node, 0, rnode_size,
		     rnode_size);
	node->index_area.index_count = hdr->items_count;
	node->index_area.start_hash = U64_MAX;
	node->index_area.end_hash = U64_MAX;
	if (hdr->items_count > 0) {
		index1 = &root_node->indexes[SSDFS_ROOT_NODE_LEFT_LEAF_NODE];
		node->index_area.start_hash = le64_to_cpu(index1->hash);
	}
	if (hdr->items_count > 1) {
		index2 = &root_node->indexes[SSDFS_ROOT_NODE_RIGHT_LEAF_NODE];
		node->index_area.end_hash = le64_to_cpu(index2->hash);
	}
	up_write(&node->header_lock);

	spin_lock(&node->tree->nodes_lock);
	node->tree->upper_node_id =
		le32_to_cpu(root_node->header.upper_node_id);
	spin_unlock(&node->tree->nodes_lock);

	ssdfs_btree_node_content_init(&node->content);

	atomic_set(&node->state, SSDFS_BTREE_NODE_INITIALIZED);
	return 0;
}

/*
 * ssdfs_btree_node_allocate_content_space() - allocate content space
 * @node: node object
 * @node_size: node size
 */
int ssdfs_btree_node_allocate_content_space(struct ssdfs_btree_node *node,
					    u32 node_size)
{
	struct ssdfs_fs_info *fsi;
	struct folio_batch *batch;
	struct folio *folio;
	u32 blocks_count;
	u32 allocated_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);

	SSDFS_DBG("node_id %u, node_size %u\n",
		  node->node_id, node_size);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (node_size < fsi->pagesize) {
		SSDFS_ERR("invalid node size: "
			  "node_size %u < fsi->pagesize %u\n",
			  node_size, fsi->pagesize);
		return -EINVAL;
	}

	if (node_size % fsi->pagesize) {
		SSDFS_ERR("invalid node size: "
			  "node_size %u, fsi->pagesize %u\n",
			  node_size, fsi->pagesize);
		return -EINVAL;
	}

	blocks_count = node_size / fsi->pagesize;

	if (blocks_count == 0 ||
	    blocks_count > SSDFS_BTREE_NODE_EXTENT_LEN_MAX) {
		SSDFS_ERR("invalid blocks_count %u\n",
			  blocks_count);
		return -ERANGE;
	}

	down_write(&node->full_lock);

	for (i = 0; i < blocks_count; i++) {
		allocated_bytes = 0;

		batch = &node->content.blocks[i].batch;
		folio_batch_init(batch);

		while (allocated_bytes < fsi->pagesize) {
			u32 rest_bytes = fsi->pagesize - allocated_bytes;

			folio = ssdfs_btree_node_add_batch_folio(batch,
							get_order(rest_bytes));
			if (IS_ERR_OR_NULL(folio)) {
				err = (folio == NULL ? -ENOMEM : PTR_ERR(folio));
				SSDFS_ERR("unable to allocate memory folio\n");
				goto finish_init_batch;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

			allocated_bytes += folio_size(folio);
		}

		node->content.count++;
	}

finish_init_batch:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_btree_node_free_content_space() - free content space
 * @node: node object
 */
void ssdfs_btree_node_free_content_space(struct ssdfs_btree_node *node)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);

	SSDFS_DBG("node_id %u, node_size %u\n",
		  node->node_id, node->node_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_read(&node->type) != SSDFS_BTREE_ROOT_NODE) {
		for (i = 0; i < node->content.count; i++) {
			struct folio_batch *batch;

			batch = &node->content.blocks[i].batch;
			ssdfs_btree_node_folio_batch_release(batch);
		}

		node->content.count = 0;
	}
}

/*
 * ssdfs_btree_node_allocate_bmaps() - allocate node's bitmaps
 * @addr: array of pointers
 * @bmap_bytes: size of the bitmap in bytes
 */
int ssdfs_btree_node_allocate_bmaps(void *addr[SSDFS_BTREE_NODE_BMAP_COUNT],
				    size_t bmap_bytes)
{
	int i;

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		addr[i] = ssdfs_btree_node_kzalloc(bmap_bytes, GFP_KERNEL);
		if (!addr[i]) {
			SSDFS_ERR("fail to allocate node's bmap: index %d\n",
				  i);
			for (; i >= 0; i--) {
				ssdfs_btree_node_kfree(addr[i]);
				addr[i] = NULL;
			}
			return -ENOMEM;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_node_init_bmaps() - init node's bitmaps
 * @node: node object
 * @addr: array of pointers
 */
void ssdfs_btree_node_init_bmaps(struct ssdfs_btree_node *node,
				 void *addr[SSDFS_BTREE_NODE_BMAP_COUNT])
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->bmap_array.lock));
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		void *tmp_addr = NULL;

		spin_lock(&node->bmap_array.bmap[i].lock);
		tmp_addr = node->bmap_array.bmap[i].ptr;
		node->bmap_array.bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&node->bmap_array.bmap[i].lock);

		if (tmp_addr)
			ssdfs_btree_node_kfree(tmp_addr);
	}
}

/*
 * ssdfs_btree_node_destroy() - destroy the btree node
 * @node: node object
 */
void ssdfs_btree_node_destroy(struct ssdfs_btree_node *node)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#else
	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_btree_nodes_list_delete(&node->tree->fsi->btree_nodes, node);

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_DIRTY:
		switch (atomic_read(&node->type)) {
		case SSDFS_BTREE_ROOT_NODE:
			/* ignore root node dirty state */
			break;

		default:
			SSDFS_WARN("node %u is dirty\n", node->node_id);
			break;
		}
		/* FALLTHRU */
		fallthrough;
	case SSDFS_BTREE_NODE_CREATED:
		/* FALLTHRU */
		fallthrough;
	case SSDFS_BTREE_NODE_INITIALIZED:
		atomic_set(&node->state, SSDFS_BTREE_NODE_UNKNOWN_STATE);
		wake_up_all(&node->wait_queue);
		complete_all(&node->init_end);

		spin_lock(&node->descriptor_lock);
		if (node->seg) {
			ssdfs_segment_put_object(node->seg);
			node->seg = NULL;
		}
		spin_unlock(&node->descriptor_lock);

		if (rwsem_is_locked(&node->bmap_array.lock)) {
			/* inform about possible trouble */
			SSDFS_WARN("node is locked under destruction\n");
		}

		node->bmap_array.bits_count = 0;
		node->bmap_array.bmap_bytes = 0;
		node->bmap_array.index_start_bit = ULONG_MAX;
		node->bmap_array.item_start_bit = ULONG_MAX;
		for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
			spin_lock(&node->bmap_array.bmap[i].lock);
			ssdfs_btree_node_kfree(node->bmap_array.bmap[i].ptr);
			node->bmap_array.bmap[i].ptr = NULL;
			spin_unlock(&node->bmap_array.bmap[i].lock);
		}

		if (rwsem_is_locked(&node->full_lock)) {
			/* inform about possible trouble */
			SSDFS_WARN("node is locked under destruction\n");
		}

		ssdfs_btree_node_free_content_space(node);
		break;

	default:
		SSDFS_WARN("invalid node state: "
			   "node %u, state %#x\n",
			   node->node_id,
			   atomic_read(&node->state));
		break;
	}

	ssdfs_btree_node_free(node);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
}

/*
 * ssdfs_btree_node_show_node_content() - show btree node's content
 */
#ifdef CONFIG_SSDFS_DEBUG
static inline
void ssdfs_btree_node_show_node_content(struct ssdfs_segment_request *req)
{
	struct ssdfs_request_content_block *block;
	struct ssdfs_content_block *blk_state;
	int i, j;

	for (i = 0; i < req->result.content.count; i++) {
		block = &req->result.content.blocks[i];
		blk_state = &block->new_state;

		for (j = 0; j < folio_batch_count(&blk_state->batch); j++) {
			struct folio *folio;
			void *kaddr;
			u32 processed_bytes = 0;
			u32 page_index = 0;

			folio = blk_state->batch.folios[j];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			do {
				kaddr = kmap_local_folio(folio,
							 processed_bytes);
				SSDFS_DBG("PAGE DUMP: blk_index %d, "
					  "folio_index %d, page_index %u\n",
					  i, j, page_index);
				print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						     kaddr,
						     PAGE_SIZE);
				SSDFS_DBG("\n");
				kunmap_local(kaddr);

				processed_bytes += PAGE_SIZE;
				page_index++;
			} while (processed_bytes < folio_size(folio));

			WARN_ON(!folio_test_locked(folio));
		}
	}
}
#endif /* CONFIG_SSDFS_DEBUG */

/*
 * __ssdfs_btree_node_prepare_content() - prepare the btree node's content
 * @fsi: pointer on shared file system object
 * @ptr: btree node's index
 * @node_size: size of the node
 * @owner_ino: owner inode ID
 * @si: segment object [out]
 * @content: node's content [out]
 *
 * This method tries to read the raw node from the volume.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
int __ssdfs_btree_node_prepare_content(struct ssdfs_fs_info *fsi,
					struct ssdfs_btree_index_key *ptr,
					u32 node_size,
					u64 owner_ino,
					struct ssdfs_segment_info **si,
					struct ssdfs_btree_node_content *content)
{
	struct ssdfs_segment_request *req;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_request_content_block *block;
	struct ssdfs_content_block *blk_state;
	struct ssdfs_offset_position pos;
	struct ssdfs_segment_search_state seg_search;
	struct folio_batch *batch;
	u32 node_id;
	u8 node_type;
	u8 height;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u32 blks_count;
	u64 logical_offset;
	u32 data_bytes;
	struct completion *end;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !ptr || !si || !content);
#endif /* CONFIG_SSDFS_DEBUG */

	node_id = le32_to_cpu(ptr->node_id);
	node_type = ptr->node_type;
	height = ptr->height;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, node_size %u, height %u, type %#x\n",
		  node_id, node_size, height, node_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (node_type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    node_type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_WARN("invalid node type %#x\n",
			   node_type);
		return -ERANGE;
	}

	if (node_type == SSDFS_BTREE_ROOT_NODE) {
		SSDFS_WARN("root node should be initialize during creation\n");
		return -ERANGE;
	}

	seg_id = le64_to_cpu(ptr->index.extent.seg_id);
	logical_blk = le32_to_cpu(ptr->index.extent.logical_blk);
	len = le32_to_cpu(ptr->index.extent.len);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, logical_blk %u, len %u\n",
		  seg_id, logical_blk, len);

	BUG_ON(seg_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_segment_search_state_init(&seg_search,
					NODE2SEG_TYPE(node_type),
					seg_id, U64_MAX);

	*si = ssdfs_grab_segment(fsi, &seg_search);
	if (unlikely(IS_ERR_OR_NULL(*si))) {
		err = !*si ? -ENOMEM : PTR_ERR(*si);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			SSDFS_ERR("fail to grab segment object: "
				  "seg %llu, err %d\n",
				  seg_id, err);
		}
		goto fail_get_segment;
	}

	blks_count = node_size >> fsi->log_pagesize;

	if (blks_count == 0 || blks_count > SSDFS_BTREE_NODE_EXTENT_LEN_MAX) {
		err = -ERANGE;
		SSDFS_WARN("invalid memory folios count: "
			   "node_size %u, blks_count %u\n",
			   node_size, blks_count);
		goto finish_prepare_content;
	}

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		goto finish_prepare_content;
	}

	ssdfs_request_init(req, fsi->pagesize);
	ssdfs_get_request(req);

	logical_offset = (u64)node_id * node_size;
	data_bytes = node_size;
	ssdfs_request_prepare_logical_extent(owner_ino,
					     (u64)logical_offset,
					     (u32)data_bytes,
					     0, 0, req);

	for (i = 0; i < blks_count; i++) {
		err = ssdfs_request_add_allocated_folio_locked(i, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add folio into request: "
				  "err %d\n",
				  err);
			goto fail_read_node;
		}
	}

	ssdfs_request_define_segment(seg_id, req);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_blk >= U16_MAX);
	BUG_ON(len >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	ssdfs_request_define_volume_extent((u16)logical_blk, (u16)len, req);

	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    SSDFS_READ_PAGES_READAHEAD,
					    SSDFS_REQ_SYNC,
					    req);

	table = (*si)->blk2off_table;

	err = ssdfs_blk2off_table_get_offset_position(table, logical_blk, &pos);
	if (err == -EAGAIN) {
		end = &table->full_init_end;

		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("blk2off init failed: "
				  "seg_id %llu, logical_blk %u, "
				  "len %u, err %d\n",
				  seg_id, logical_blk, len, err);

			for (i = 0; i < (*si)->pebs_count; i++) {
				u64 peb_id1 = U64_MAX;
				u64 peb_id2 = U64_MAX;

				pebc = &(*si)->peb_array[i];

				if (pebc->src_peb)
					peb_id1 = pebc->src_peb->peb_id;

				if (pebc->dst_peb)
					peb_id2 = pebc->dst_peb->peb_id;

				SSDFS_ERR("seg_id %llu, peb_index %u, "
					  "src_peb %llu, dst_peb %llu\n",
					  seg_id, i, peb_id1, peb_id2);
			}

#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */

			goto fail_read_node;
		}

		err = ssdfs_blk2off_table_get_offset_position(table,
							      logical_blk,
							      &pos);
	}

	if (err == -ENODATA) {
		SSDFS_DBG("unable to convert: "
			  "seg_id %llu, logical_blk %u, len %u, err %d\n",
			  seg_id, logical_blk, len, err);
		goto fail_read_node;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to convert: "
			  "seg_id %llu, logical_blk %u, len %u, err %d\n",
			  seg_id, logical_blk, len, err);
		goto fail_read_node;
	}

	pebc = &(*si)->peb_array[pos.peb_index];

	err = ssdfs_peb_readahead_pages(pebc, req, &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("PEB init failed: "
				  "err %d\n", err);
			goto fail_read_node;
		}

		err = ssdfs_peb_readahead_pages(pebc, req, &end);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: err %d\n",
			  err);
		goto fail_read_node;
	}

	for (i = 0; i < req->result.processed_blks; i++)
		ssdfs_peb_mark_request_block_uptodate(pebc, req, i);

#ifdef CONFIG_SSDFS_DEBUG
	ssdfs_btree_node_show_node_content(req);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_BTREE_NODE_EXTENT_LEN_MAX; i++) {
		batch = &content->blocks[i].batch;
		ssdfs_btree_node_folio_batch_release(batch);
	}

	for (i = 0; i < req->result.content.count; i++) {
		block = &req->result.content.blocks[i];
		blk_state = &block->new_state;

#ifdef CONFIG_SSDFS_DEBUG
		if (i >= content->count) {
			SSDFS_ERR("i %d, req->result.content.count %d, "
				  "content->count %d\n",
				  i,
				  req->result.content.count,
				  content->count);
			BUG();
		}
#endif /* CONFIG_SSDFS_DEBUG */

		batch = &content->blocks[i].batch;

		for (j = 0; j < folio_batch_count(&blk_state->batch); j++) {
			struct folio *folio;

			folio = blk_state->batch.folios[j];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			if (folio_batch_space(batch) == 0) {
				err = -ENOSPC;
				SSDFS_ERR("batch is completely full\n");
				goto fail_read_node;
			}

			folio_batch_add(batch, folio);
			ssdfs_btree_node_account_folio(folio);
		}

		ssdfs_request_unlock_and_forget_block(i, req);
	}

	ssdfs_reinit_request_content(req);

	ssdfs_request_unlock_and_remove_diffs(req);

	ssdfs_put_request(req);
	ssdfs_request_free(req, *si);

	return 0;

fail_read_node:
	ssdfs_request_unlock_and_remove_folios(req);
	ssdfs_put_request(req);
	ssdfs_request_free(req, *si);

finish_prepare_content:
	ssdfs_segment_put_object(*si);

fail_get_segment:
	return err;
}

/*
 * ssdfs_btree_node_prepare_content() - prepare the btree node's content
 * @node: node object
 * @ptr: btree node's index
 *
 * This method tries to read the raw node from the volume.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_node_prepare_content(struct ssdfs_btree_node *node,
				     struct ssdfs_btree_index_key *ptr)
{
	struct ssdfs_segment_info *si = NULL;
	size_t extent_size = sizeof(struct ssdfs_raw_extent);
	u32 node_id;
	u8 node_type;
	u8 height;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !ptr);

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */

	node_id = le32_to_cpu(ptr->node_id);
	node_type = ptr->node_type;
	height = ptr->height;

#ifdef CONFIG_SSDFS_DEBUG
	if (node->node_id != node_id) {
		SSDFS_WARN("node->node_id %u != node_id %u\n",
			   node->node_id, node_id);
		return -EINVAL;
	}

	if (atomic_read(&node->type) != node_type) {
		SSDFS_WARN("node->type %#x != node_type %#x\n",
			   atomic_read(&node->type), node_type);
		return -EINVAL;
	}

	if (atomic_read(&node->height) != height) {
		SSDFS_WARN("node->height %u != height %u\n",
			   atomic_read(&node->height), height);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&node->full_lock);
	err = __ssdfs_btree_node_prepare_content(node->tree->fsi, ptr,
						 node->node_size,
						 node->tree->owner_ino,
						 &si,
						 &node->content);
	up_write(&node->full_lock);

	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 */
		goto finish_prepare_node_content;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to prepare node's content: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_prepare_node_content;
	}

	spin_lock(&node->descriptor_lock);
	ssdfs_memcpy(&node->extent, 0, extent_size,
		     &ptr->index.extent, 0, extent_size,
		     extent_size);
	node->seg = si;
	spin_unlock(&node->descriptor_lock);

	atomic_set(&node->state, SSDFS_BTREE_NODE_CONTENT_PREPARED);

finish_prepare_node_content:
	return err;
}

/*
 * __ssdfs_define_memory_folio() - define memory folio for the position
 * @fsi: pointer on shared file system object
 * @area_offset: area offset from the node's beginning
 * @area_size: size of the area
 * @node_size: node size in bytes
 * @item_size: size of the item in bytes
 * @position: position of index record in the node
 * @desc: offset to folio descriptor [out]
 *
 * This method tries to define a memory folio's index and byte
 * offset to the index record.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int __ssdfs_define_memory_folio(struct ssdfs_fs_info *fsi,
				u32 area_offset, u32 area_size,
				u32 node_size, size_t item_size,
				u16 position,
				struct ssdfs_offset2folio *desc)
{
	u32 item_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !desc);

	SSDFS_DBG("area_offset %u, area_size %u, "
		  "node_size %u, item_size %zu, position %u\n",
		  area_offset, area_size,
		  node_size, item_size, position);
#endif /* CONFIG_SSDFS_DEBUG */

	item_offset = position * item_size;
	if (item_offset >= area_size) {
		SSDFS_ERR("item_offset %u >= area_size %u\n",
			  item_offset, area_size);
		return -ERANGE;
	}

	item_offset += area_offset;

#ifdef CONFIG_SSDFS_DEBUG
	if (item_offset >= (area_offset + area_size)) {
		SSDFS_ERR("invalid item offset: "
			  "item_offset %u, area_offset %u, "
			  "area_size %u\n",
			  item_offset, area_offset, area_size);
		return -ERANGE;
	}

	if (item_offset >= node_size) {
		SSDFS_ERR("invalid item offset: "
			  "item_offset %u, node_size %u\n",
			  item_offset, node_size);
		return -ERANGE;
	}

	if (fsi->pagesize == 0 || node_size < fsi->pagesize) {
		SSDFS_ERR("invalid block size: "
			  "block_size %u, node_size %u\n",
			  fsi->pagesize, node_size);
		return -ERANGE;
	}

	if (node_size % fsi->pagesize) {
		SSDFS_ERR("invalid node size: "
			  "block_size %u, node_size %u\n",
			  fsi->pagesize, node_size);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "offset %u, err %d\n",
			  item_offset, err);
		return err;
	}

	if ((desc->offset_inside_page + item_size) > PAGE_SIZE) {
		SSDFS_ERR("invalid request: "
			  "offset_inside_page %u, item_size %zu\n",
			  desc->offset_inside_page, item_size);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_define_memory_folio() - define memory folio for the position
 * @node: node object
 * @area: pointer on index area descriptor
 * @position: position of index record in the node
 * @desc: offset to folio descriptor [out]
 *
 * This method tries to define a memory folio's index and byte
 * offset to the index record.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_define_memory_folio(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_node_index_area *area,
			     u16 position,
			     struct ssdfs_offset2folio *desc)
{
	struct ssdfs_fs_info *fsi;
	size_t index_size = sizeof(struct ssdfs_btree_index_key);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !desc);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->tree->lock));

	SSDFS_DBG("node_id %u, node_type %#x, position %u\n",
		  node->node_id, atomic_read(&node->type),
		  position);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (atomic_read(&area->state) != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  atomic_read(&area->state));
		return -ERANGE;
	}

	if (area->index_capacity == 0 ||
	    area->index_count > area->index_capacity) {
		SSDFS_ERR("invalid area: "
			  "index_count %u, index_capacity %u\n",
			  area->index_count,
			  area->index_capacity);
		return -ERANGE;
	}

	if (position > area->index_count) {
		SSDFS_ERR("position %u > index_count %u\n",
			  position, area->index_count);
		return -ERANGE;
	}

	if ((area->offset + area->area_size) > node->node_size) {
		SSDFS_ERR("invalid area: "
			  "offset %u, area_size %u, node_size %u\n",
			  area->offset,
			  area->area_size,
			  node->node_size);
		return -ERANGE;
	}

	if (area->index_size != index_size) {
		SSDFS_ERR("invalid index size %u\n",
			  area->index_size);
		return -ERANGE;
	}

	err = __ssdfs_define_memory_folio(fsi,
					 area->offset, area->area_size,
					 node->node_size, index_size,
					 position, desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define folio index: err %d\n",
			  err);
		return err;
	}

	if ((desc->offset_inside_page + area->index_size) > PAGE_SIZE) {
		SSDFS_ERR("invalid offset into the page: "
			  "offset %u, index_size %u\n",
			  desc->offset_inside_page, area->index_size);
		return -ERANGE;
	}

	if (desc->folio_index >= node->content.count) {
		SSDFS_ERR("invalid folio index: "
			  "folio_index %u, blocks_count %u\n",
			  desc->folio_index,
			  node->content.count);
		return -ERANGE;
	}

	return 0;
}

/*
 * __ssdfs_init_index_area_hash_range() - extract hash range of index area
 * @node: node object
 * @index_count: count of indexes in the node
 * @start_hash: starting hash of index area [out]
 * @end_hash: ending hash of index area [out]
 *
 * This method tries to extract start and end hash from
 * the raw index area.
 *

 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_init_index_area_hash_range(struct ssdfs_btree_node *node,
					u16 index_count,
					u64 *start_hash, u64 *end_hash)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_index_key *ptr;
	struct ssdfs_smart_folio folio;
	void *kaddr;
	u16 position;
	u32 page_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
	BUG_ON(!start_hash || !end_hash);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, height %u\n",
		  node->node_id,
		  atomic_read(&node->height));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;

	if (index_count == 0)
		return 0;

	position = 0;

	err = ssdfs_define_memory_folio(node, &node->index_area,
					position, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define memory page: "
			  "node_id %u, position %u, err %d\n",
			  node->node_id, position, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_find_node_content_folio(&node->content, &folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find folio: err %d\n", err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_size(folio.ptr) == fsi->pagesize) {
		page_offset = folio.desc.page_offset;
	} else {
		page_offset = SSDFS_PAGE_OFFSET_IN_FOLIO(folio_size(folio.ptr),
							 folio.desc.offset);
	}

	ssdfs_folio_lock(folio.ptr);
	kaddr = kmap_local_folio(folio.ptr, page_offset);
	ptr = (struct ssdfs_btree_index_key *)((u8 *)kaddr +
						folio.desc.offset_inside_page);
	*start_hash = le64_to_cpu(ptr->index.hash);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio.ptr);

	position = index_count - 1;

	if (position == 0) {
		*end_hash = *start_hash;
		return 0;
	}

	err = ssdfs_define_memory_folio(node, &node->index_area,
					position, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define memory page: "
			  "node_id %u, position %u, err %d\n",
			  node->node_id, position, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_find_node_content_folio(&node->content, &folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find folio: err %d\n", err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_size(folio.ptr) == fsi->pagesize) {
		page_offset = folio.desc.page_offset;
	} else {
		page_offset = SSDFS_PAGE_OFFSET_IN_FOLIO(folio_size(folio.ptr),
							 folio.desc.offset);
	}

	ssdfs_folio_lock(folio.ptr);
	kaddr = kmap_local_folio(folio.ptr, page_offset);
	ptr = (struct ssdfs_btree_index_key *)((u8 *)kaddr +
					folio.desc.offset_inside_page);
	*end_hash = le64_to_cpu(ptr->index.hash);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio.ptr);

	return 0;
}

/*
 * ssdfs_init_index_area_hash_range() - extract hash range of index area
 * @node: node object
 * @hdr: node's header
 * @start_hash: starting hash of index area [out]
 * @end_hash: ending hash of index area [out]
 *
 * This method tries to extract start and end hash from
 * the raw index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_init_index_area_hash_range(struct ssdfs_btree_node *node,
				     struct ssdfs_btree_node_header *hdr,
				     u64 *start_hash, u64 *end_hash)
{
	u16 flags;
	u16 index_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !hdr);
	BUG_ON(!start_hash || !end_hash);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, height %u\n",
		  node->node_id,
		  atomic_read(&node->height));
#endif /* CONFIG_SSDFS_DEBUG */

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;

	flags = le16_to_cpu(hdr->flags);
	if (!(flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA))
		return 0;

	index_count = le16_to_cpu(hdr->index_count);
	if (index_count == 0)
		return 0;

	return __ssdfs_init_index_area_hash_range(node, index_count,
						  start_hash, end_hash);
}

/*
 * ssdfs_btree_init_node_index_area() - init the node's index area
 * @node: node object
 * @hdr: node's header
 * @hdr_size: size of the header
 *
 * This method tries to init the node's index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - header is corrupted.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_init_node_index_area(struct ssdfs_btree_node *node,
				     struct ssdfs_btree_node_header *hdr,
				     size_t hdr_size)
{
	u16 flags;
	u32 index_area_size;
	u8 index_size;
	u16 index_count;
	u16 index_capacity;
	u32 offset;
	u64 start_hash = U64_MAX;
	u64 end_hash = U64_MAX;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !hdr);
	BUG_ON(hdr_size <= sizeof(struct ssdfs_btree_node_header));
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, height %u\n",
		  node->node_id,
		  atomic_read(&node->height));
#endif /* CONFIG_SSDFS_DEBUG */

	flags = le16_to_cpu(hdr->flags);
	index_area_size = 0;

	if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
		index_area_size = 1 << hdr->log_index_area_size;

		if (index_area_size == 0 ||
		    index_area_size > node->node_size) {
			SSDFS_ERR("invalid index area size %u\n",
				  index_area_size);
			return -EIO;
		}

		switch (hdr->type) {
		case SSDFS_BTREE_INDEX_NODE:
			if (index_area_size != node->node_size) {
				SSDFS_ERR("invalid index area's size: "
					  "index_area_size %u, node_size %u\n",
					  index_area_size,
					  node->node_size);
				return -EIO;
			}

			index_area_size -= hdr_size;
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid node type %#x\n",
				  hdr->type);
			return -EIO;
		}
	} else {
		if (index_area_size != 0) {
			SSDFS_ERR("invalid index area size %u\n",
				  index_area_size);
			return -EIO;
		}

		switch (hdr->type) {
		case SSDFS_BTREE_LEAF_NODE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid node type %#x\n",
				  hdr->type);
			return -EIO;
		}
	}

	index_size = hdr->index_size;
	index_count = le16_to_cpu(hdr->index_count);

	if (index_area_size < ((u32)index_count * index_size)) {
		SSDFS_ERR("index area is corrupted: "
			  "index_area_size %u, index_count %u, "
			  "index_size %u\n",
			  index_area_size,
			  index_count,
			  index_size);
		return -EIO;
	}

	index_capacity = index_area_size / index_size;
	if (index_capacity < index_count) {
		SSDFS_ERR("index_capacity %u < index_count %u\n",
			  index_capacity, index_count);
		return -ERANGE;
	}

	if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
		atomic_set(&node->index_area.state,
				SSDFS_BTREE_NODE_INDEX_AREA_EXIST);

		offset = le16_to_cpu(hdr->index_area_offset);

		if (offset != hdr_size) {
			SSDFS_ERR("invalid index_area_offset %u\n",
				  offset);
			return -EIO;
		}

		if ((offset + index_area_size) > node->node_size) {
			SSDFS_ERR("offset %u + area_size %u > node_size %u\n",
				  offset, index_area_size, node->node_size);
			return -ERANGE;
		}

		node->index_area.offset = offset;
		node->index_area.area_size = index_area_size;
		node->index_area.index_size = index_size;
		node->index_area.index_count = index_count;
		node->index_area.index_capacity = index_capacity;

		err = ssdfs_init_index_area_hash_range(node, hdr,
						       &start_hash,
						       &end_hash);
		if (unlikely(err)) {
			SSDFS_ERR("fail to retrieve index area hash range: "
				  "err %d\n",
				  err);
			return err;
		}

		node->index_area.start_hash = start_hash;
		node->index_area.end_hash = end_hash;

		if (start_hash > end_hash) {
			SSDFS_WARN("node_id %u, height %u, "
				   "start_hash %llx, end_hash %llx\n",
				   node->node_id,
				   atomic_read(&node->height),
				   start_hash,
				   end_hash);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#else
			return -EIO;
#endif /* CONFIG_SSDFS_DEBUG */
		}
	} else {
		atomic_set(&node->index_area.state,
				SSDFS_BTREE_NODE_AREA_ABSENT);
		node->index_area.offset = U32_MAX;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(index_area_size != 0);
#endif /* CONFIG_SSDFS_DEBUG */
		node->index_area.area_size = index_area_size;
		node->index_area.index_size = index_size;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(index_count != 0);
#endif /* CONFIG_SSDFS_DEBUG */
		node->index_area.index_count = index_count;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(index_capacity != 0);
#endif /* CONFIG_SSDFS_DEBUG */
		node->index_area.index_capacity = index_capacity;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(start_hash != U64_MAX);
		BUG_ON(end_hash != U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
		node->index_area.start_hash = start_hash;
		node->index_area.end_hash = end_hash;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "index_count %u, index_capacity %u\n",
		  start_hash, end_hash,
		  index_count, index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_init_node_items_area() - init the node's items area
 * @node: node object
 * @hdr: node's header
 * @hdr_size: size of the header
 *
 * This method tries to init the node's items area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - header is corrupted.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_init_node_items_area(struct ssdfs_btree_node *node,
				     struct ssdfs_btree_node_header *hdr,
				     size_t hdr_size)
{
	u16 flags;
	u32 index_area_size;
	u32 items_area_size;
	u8 min_item_size;
	u16 max_item_size;
	u32 offset;
	u64 start_hash;
	u64 end_hash;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !hdr);
	BUG_ON(hdr_size <= sizeof(struct ssdfs_btree_node_header));
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, height %u\n",
		  node->node_id,
		  atomic_read(&node->height));
#endif /* CONFIG_SSDFS_DEBUG */

	flags = le16_to_cpu(hdr->flags);

	if (hdr->log_index_area_size > 0) {
		index_area_size = 1 << hdr->log_index_area_size;

		switch (hdr->type) {
		case SSDFS_BTREE_INDEX_NODE:
			if (index_area_size != node->node_size) {
				SSDFS_ERR("invalid index area's size: "
					  "index_area_size %u, node_size %u\n",
					  index_area_size,
					  node->node_size);
				return -EIO;
			}

			index_area_size -= hdr_size;
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid node type %#x\n",
				  hdr->type);
			return -EIO;
		}
	} else
		index_area_size = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON((index_area_size + hdr_size) > node->node_size);
#endif /* CONFIG_SSDFS_DEBUG */

	items_area_size = node->node_size;
	items_area_size -= index_area_size;
	items_area_size -= hdr_size;

	if (flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA) {
		if (items_area_size == 0) {
			SSDFS_ERR("invalid items area size %u\n",
				  items_area_size);
			return -EIO;
		}

		switch (hdr->type) {
		case SSDFS_BTREE_HYBRID_NODE:
		case SSDFS_BTREE_LEAF_NODE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid node type %#x\n",
				  hdr->type);
			return -EIO;
		}
	} else {
		if (items_area_size != 0) {
			SSDFS_ERR("invalid items area size %u\n",
				  items_area_size);
			return -EIO;
		}

		switch (hdr->type) {
		case SSDFS_BTREE_INDEX_NODE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid node type %#x\n",
				  hdr->type);
			return -EIO;
		}
	}

	offset = hdr_size + index_area_size;

	switch (hdr->type) {
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		if (offset != le32_to_cpu(hdr->item_area_offset)) {
			SSDFS_ERR("invalid item_area_offset %u\n",
				  le32_to_cpu(hdr->item_area_offset));
			return -EIO;
		}
		break;
	}

	if ((offset + items_area_size) > node->node_size) {
		SSDFS_ERR("offset %u + items_area_size %u > node_size %u\n",
			  offset, items_area_size, node->node_size);
		return -ERANGE;
	}

	min_item_size = hdr->min_item_size;
	max_item_size = le16_to_cpu(hdr->max_item_size);

	if (max_item_size < min_item_size) {
		SSDFS_ERR("invalid item size: "
			  "min size %u, max size %u\n",
			  min_item_size, max_item_size);
		return -EIO;
	}

	start_hash = le64_to_cpu(hdr->start_hash);
	end_hash = le64_to_cpu(hdr->end_hash);

	if (start_hash > end_hash) {
		SSDFS_WARN("start_hash %llx > end_hash %llx\n",
			   start_hash, end_hash);
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		return -EIO;
#endif /* CONFIG_SSDFS_DEBUG */
	}

	if (flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA) {
		atomic_set(&node->items_area.state,
				SSDFS_BTREE_NODE_ITEMS_AREA_EXIST);
		node->items_area.offset = offset;
		node->items_area.area_size = items_area_size;
		node->items_area.min_item_size = node->tree->item_size;
		node->items_area.min_item_size = min_item_size;
		node->items_area.max_item_size = max_item_size;
		node->items_area.items_count = U16_MAX;
		node->items_area.items_capacity = U16_MAX;
		node->items_area.start_hash = start_hash;
		node->items_area.end_hash = end_hash;
	} else {
		atomic_set(&node->items_area.state,
				SSDFS_BTREE_NODE_AREA_ABSENT);
		node->items_area.offset = U32_MAX;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(items_area_size != 0);
#endif /* CONFIG_SSDFS_DEBUG */
		node->items_area.area_size = items_area_size;
		node->items_area.min_item_size = node->tree->item_size;
		node->items_area.min_item_size = min_item_size;
		node->items_area.max_item_size = max_item_size;
		node->items_area.items_count = 0;
		node->items_area.items_capacity = 0;
		node->items_area.start_hash = U64_MAX;
		node->items_area.end_hash = U64_MAX;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "items_count %u, items_capacity %u\n",
		  start_hash, end_hash,
		  node->items_area.items_count,
		  node->items_area.items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_init_node() - init node object
 * @node: node object
 * @hdr: node's header
 * @hdr_size: size of the header
 *
 * This method tries to init the node object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - header is corrupted.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_init_node(struct ssdfs_btree_node *node,
			  struct ssdfs_btree_node_header *hdr,
			  size_t hdr_size)
{
	u8 tree_height;
	u64 create_cno;
	u16 flags;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !hdr);
	BUG_ON(hdr_size <= sizeof(struct ssdfs_btree_node_header));
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("node %p, hdr %p, node_id %u\n",
		  node, hdr, node->node_id);
#else
	SSDFS_DBG("node %p, hdr %p, node_id %u\n",
		  node, hdr, node->node_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	tree_height = atomic_read(&node->tree->height);
	if (hdr->height >= tree_height) {
		SSDFS_ERR("invalid height: "
			  "tree_height %u, node_height %u\n",
			  tree_height, hdr->height);
		return -EIO;
	}
	atomic_set(&node->height, hdr->height);

	if (node->node_size != (1 << hdr->log_node_size)) {
		SSDFS_ERR("invalid node size: "
			  "node_size %u != node_size %u\n",
			  node->node_size,
			  (1 << hdr->log_node_size));
		return -EIO;
	}

	if (le32_to_cpu(hdr->node_id) != node->node_id) {
		SSDFS_WARN("node->node_id %u != hdr->node_id %u\n",
			   node->node_id,
			   le32_to_cpu(hdr->node_id));
		return -EIO;
	}

	create_cno = le64_to_cpu(hdr->create_cno);
	if (create_cno < node->tree->create_cno) {
		SSDFS_ERR("create_cno %llu < node->tree->create_cno %llu\n",
			  create_cno,
			  node->tree->create_cno);
		return -EIO;
	}
	node->create_cno = create_cno;

	flags = le16_to_cpu(hdr->flags);
	if (flags & ~SSDFS_BTREE_NODE_FLAGS_MASK) {
		SSDFS_ERR("invalid flags %#x\n",
			  flags);
		return -EIO;
	}
	atomic_set(&node->flags, flags);

	if (hdr->type <= SSDFS_BTREE_ROOT_NODE ||
	    hdr->type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_ERR("invalid type %#x\n",
			  hdr->type);
		return -EIO;
	}
	atomic_set(&node->type, hdr->type);

	switch (hdr->type) {
	case SSDFS_BTREE_INDEX_NODE:
		if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA &&
		    !(flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA)) {
			/*
			 * expected set of flags
			 */
		} else {
			SSDFS_ERR("invalid set of flags %#x for index node\n",
				  flags);
			return -EIO;
		}
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA &&
		    flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA) {
			/*
			 * expected set of flags
			 */
		} else {
			SSDFS_ERR("invalid set of flags %#x for hybrid node\n",
				  flags);
			return -EIO;
		}
		break;

	case SSDFS_BTREE_LEAF_NODE:
		if (!(flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) &&
		    flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA) {
			/*
			 * expected set of flags
			 */
		} else {
			SSDFS_ERR("invalid set of flags %#x for leaf node\n",
				  flags);
			return -EIO;
		}
		break;

	default:
		SSDFS_ERR("invalid node type %#x\n", hdr->type);
		return -ERANGE;
	};

	err = ssdfs_btree_init_node_index_area(node, hdr, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init index area: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	err = ssdfs_btree_init_node_items_area(node, hdr, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init items area: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_btree_pre_flush_root_node() - pre-flush the dirty root node
 * @node: node object
 *
 * This method tries to pre-flush the dirty root node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_pre_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_inline_root_node *root_node;
	size_t root_node_size = sizeof(struct ssdfs_btree_inline_root_node);
	int height, tree_height;
	int type;
	u32 area_size, calculated_area_size;
	u32 area_offset;
	u16 index_count;
	u16 index_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	root_node = &node->raw.root_node;

	height = atomic_read(&node->height);
	if (height >= U8_MAX || height <= 0) {
		SSDFS_ERR("invalid height %d\n", height);
		return -ERANGE;
	}

	tree_height = atomic_read(&node->tree->height);
	if (tree_height >= U8_MAX || tree_height <= 0) {
		SSDFS_ERR("invalid tree's height %d\n",
			  tree_height);
		return -ERANGE;
	}

	if ((tree_height - 1) != height) {
		SSDFS_ERR("tree_height %d, root node's height %d\n",
			  tree_height, height);
		return -ERANGE;
	}

	root_node->header.height = (u8)height;

	if (node->node_size != root_node_size) {
		SSDFS_ERR("corrupted root node size %u\n",
			  node->node_size);
		return -ERANGE;
	}

	calculated_area_size = sizeof(struct ssdfs_btree_index);
	calculated_area_size *= SSDFS_BTREE_ROOT_NODE_INDEX_COUNT;

	area_size = node->index_area.area_size;
	if (area_size != calculated_area_size) {
		SSDFS_ERR("corrupted index area size %u\n",
			  area_size);
		return -ERANGE;
	}

	type = atomic_read(&node->type);
	if (type != SSDFS_BTREE_ROOT_NODE) {
		SSDFS_ERR("invalid node type %#x\n",
			  type);
		return -ERANGE;
	}

	root_node->header.type = (u8)type;

	area_offset = node->index_area.offset;
	if (area_offset < sizeof(struct ssdfs_btree_root_node_header) ||
	    area_offset >= node->node_size) {
		SSDFS_ERR("corrupted index area offset %u\n",
			  area_offset);
		return -ERANGE;
	}

	if (node->index_area.index_count > node->index_area.index_capacity) {
		SSDFS_ERR("corrupted index area descriptor: "
			  "index_count %u, index_capacity %u\n",
			  node->index_area.index_count,
			  node->index_area.index_capacity);
		return -ERANGE;
	}

	index_count = node->index_area.index_count;

	if (index_count > SSDFS_BTREE_ROOT_NODE_INDEX_COUNT) {
		SSDFS_ERR("invalid index count %u\n",
			  index_count);
		return -ERANGE;
	}

	root_node->header.items_count = (u8)index_count;

	index_size = node->index_area.index_size;

	if (index_size != sizeof(struct ssdfs_btree_index)) {
		SSDFS_ERR("invalid index size %u\n", index_size);
		return -ERANGE;
	}

	if (((u32)index_count * index_size) > area_size) {
		SSDFS_ERR("corrupted index area: "
			  "index_count %u, index_size %u, area_size %u\n",
			  index_count,
			  index_size,
			  area_size);
		return -ERANGE;
	}

	root_node->header.upper_node_id =
		cpu_to_le32(node->tree->upper_node_id);

	return 0;
}

/*
 * ssdfs_btree_node_pre_flush_header() - pre-flush node's header
 * @node: node object
 * @hdr: node's header
 *
 * This method tries to pre-flush the node's header.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_node_pre_flush_header(struct ssdfs_btree_node *node,
					struct ssdfs_btree_node_header *hdr)
{
	int height;
	int type;
	int flags;
	u32 area_size;
	u32 area_offset;
	u8 index_size;
	u16 index_count;
	u16 index_capacity;
	u16 items_capacity;
	u16 item_size;
	u8 min_item_size;
	u16 max_item_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !hdr);
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	height = atomic_read(&node->height);
	if (height >= U8_MAX || height < 0) {
		SSDFS_ERR("invalid height %d\n", height);
		return -ERANGE;
	}

	hdr->height = (u8)height;

	if ((1 << ilog2(node->node_size)) != node->node_size) {
		SSDFS_ERR("corrupted node size %u\n",
			  node->node_size);
		return -ERANGE;
	}

	hdr->log_node_size = (u8)ilog2(node->node_size);

	type = atomic_read(&node->type);
	if (type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_ERR("invalid node type %#x\n",
			  type);
		return -ERANGE;
	}

	hdr->type = (u8)type;

	flags = atomic_read(&node->flags);
	if (flags & ~SSDFS_BTREE_NODE_FLAGS_MASK) {
		SSDFS_ERR("corrupted set of flags %#x\n",
			  flags);
		return -ERANGE;
	}

	/*
	 * Flag SSDFS_BTREE_NODE_PRE_ALLOCATED needs to be excluded.
	 * The pre-allocated node will be created during the flush
	 * operation. This flag needs only on kernel side.
	 */
	flags &= ~SSDFS_BTREE_NODE_PRE_ALLOCATED;

	hdr->flags = cpu_to_le16((u16)flags);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, type %#x, flags %#x\n",
		  node->node_id, type, flags);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		switch (atomic_read(&node->type)) {
		case SSDFS_BTREE_INDEX_NODE:
			/*
			 * Initialization code expect the node size.
			 * As a result, the index area's size is calculated
			 * by means of subtraction the header size
			 * from the node size.
			 */
			area_size = node->node_size;
			if ((1 << ilog2(area_size)) != area_size) {
				SSDFS_ERR("corrupted index area size %u\n",
					  area_size);
				return -ERANGE;
			}

			hdr->log_index_area_size = (u8)ilog2(area_size);

			/*
			 * Real area size is used for checking
			 * the rest of fields.
			 */
			area_size = node->index_area.area_size;
			break;

		default:
			area_size = node->index_area.area_size;
			if ((1 << ilog2(area_size)) != area_size) {
				SSDFS_ERR("corrupted index area size %u\n",
					  area_size);
				return -ERANGE;
			}

			hdr->log_index_area_size = (u8)ilog2(area_size);
			break;
		}

		area_offset = node->index_area.offset;
		if (area_offset <= sizeof(struct ssdfs_btree_node_header) ||
		    area_offset >= node->node_size ||
		    area_offset >= node->items_area.offset) {
			SSDFS_ERR("corrupted index area offset %u\n",
				  area_offset);
			return -ERANGE;
		}

		hdr->index_area_offset = cpu_to_le16((u16)area_offset);

		index_count = node->index_area.index_count;
		index_capacity = node->index_area.index_capacity;

		if (index_count > index_capacity) {
			SSDFS_ERR("corrupted index area descriptor: "
				  "index_count %u, index_capacity %u\n",
				  index_count, index_capacity);
			return -ERANGE;
		}

		hdr->index_count = cpu_to_le16(index_count);

		index_size = node->index_area.index_size;

		if (((u32)index_count * index_size) > area_size) {
			SSDFS_ERR("corrupted index area: "
				  "index_count %u, index_size %u, "
				  "area_size %u\n",
				  index_count, index_size, area_size);
			return -ERANGE;
		}

		hdr->index_size = index_size;
		break;

	default:
		hdr->log_index_area_size = (u8)ilog2(0);
		hdr->index_area_offset = cpu_to_le16(U16_MAX);
		hdr->index_count = cpu_to_le16(0);
		hdr->index_size = U8_MAX;
		break;
	}

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		item_size = node->items_area.item_size;
		min_item_size = node->items_area.min_item_size;
		max_item_size = node->items_area.max_item_size;
		items_capacity = node->items_area.items_capacity;
		area_size = node->items_area.area_size;
		break;

	default:
		item_size = U16_MAX;
		min_item_size = 0;
		max_item_size = 0;
		items_capacity = 0;
		area_size = 0;
		break;
	}

	switch (type) {
	case SSDFS_BTREE_LEAF_NODE:
		if (item_size == 0) {
			SSDFS_ERR("corrupted items area: "
				  "item_size %u\n",
				  item_size);
			return -ERANGE;
		} else if (min_item_size > item_size) {
			SSDFS_ERR("corrupted items area: "
				  "min_item_size %u, "
				  "item_size %u\n",
				  min_item_size, item_size);
			return -ERANGE;
		} else if (item_size > max_item_size) {
			SSDFS_ERR("corrupted items area: "
				  "item_size %u, "
				  "max_item_size %u\n",
				  item_size, max_item_size);
			return -ERANGE;
		} else if (item_size > area_size) {
			SSDFS_ERR("corrupted items area: "
				  "item_size %u, "
				  "area_size %u\n",
				  item_size, area_size);
			return -ERANGE;
		} else
			hdr->min_item_size = min_item_size;

		if (max_item_size == 0) {
			SSDFS_ERR("corrupted items area: "
				  "max_item_size %u\n",
				  max_item_size);
			return -ERANGE;
		} else if (max_item_size > area_size) {
			SSDFS_ERR("corrupted items area: "
				  "max_item_size %u, "
				  "area_size %u\n",
				  max_item_size, area_size);
			return -ERANGE;
		} else
			hdr->max_item_size = cpu_to_le16(max_item_size);

		if (items_capacity == 0) {
			SSDFS_ERR("corrupted items area's state\n");
			return -ERANGE;
		} else if (((u32)items_capacity * item_size) > area_size) {
			SSDFS_ERR("corrupted items area's state: "
				  "items_capacity %u, item_size %u, "
				  "area_size %u\n",
				  items_capacity,
				  item_size,
				  area_size);
			return -ERANGE;
		} else
			hdr->items_capacity = cpu_to_le16(items_capacity);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node_id %u, node_type %#x, "
			  "start_hash %llx, end_hash %llx\n",
			  node->node_id,
			  atomic_read(&node->type),
			  node->items_area.start_hash,
			  node->items_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

		hdr->start_hash = cpu_to_le64(node->items_area.start_hash);
		hdr->end_hash = cpu_to_le64(node->items_area.end_hash);

		area_offset = node->items_area.offset;
		area_size = node->items_area.area_size;
		if ((area_offset + area_size) > node->node_size) {
			SSDFS_ERR("corrupted items area offset %u\n",
				  area_offset);
			return -ERANGE;
		}

		hdr->item_area_offset = cpu_to_le32(area_offset);
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		if (item_size == 0) {
			SSDFS_ERR("corrupted items area: "
				  "item_size %u\n",
				  item_size);
			return -ERANGE;
		} else if (min_item_size > item_size) {
			SSDFS_ERR("corrupted items area: "
				  "min_item_size %u, "
				  "item_size %u\n",
				  min_item_size, item_size);
			return -ERANGE;
		} else if (item_size > max_item_size) {
			SSDFS_ERR("corrupted items area: "
				  "item_size %u, "
				  "max_item_size %u\n",
				  item_size, max_item_size);
			return -ERANGE;
		} else if (item_size > area_size) {
			SSDFS_ERR("corrupted items area: "
				  "item_size %u, "
				  "area_size %u\n",
				  item_size, area_size);
			return -ERANGE;
		} else
			hdr->min_item_size = min_item_size;

		if (max_item_size == 0) {
			SSDFS_ERR("corrupted items area: "
				  "max_item_size %u\n",
				  max_item_size);
			return -ERANGE;
		} else if (max_item_size > area_size) {
			SSDFS_ERR("corrupted items area: "
				  "max_item_size %u, "
				  "area_size %u\n",
				  max_item_size, area_size);
			return -ERANGE;
		} else
			hdr->max_item_size = cpu_to_le16(max_item_size);

		if (items_capacity == 0) {
			SSDFS_ERR("corrupted items area's state\n");
			return -ERANGE;
		} else if (((u32)items_capacity * min_item_size) > area_size) {
			SSDFS_ERR("corrupted items area's state: "
				  "items_capacity %u, min_item_szie %u, "
				  "area_size %u\n",
				  items_capacity,
				  min_item_size,
				  area_size);
			return -ERANGE;
		} else
			hdr->items_capacity = cpu_to_le16(items_capacity);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node_id %u, node_type %#x, "
			  "start_hash %llx, end_hash %llx\n",
			  node->node_id,
			  atomic_read(&node->type),
			  node->items_area.start_hash,
			  node->items_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

		hdr->start_hash = cpu_to_le64(node->items_area.start_hash);
		hdr->end_hash = cpu_to_le64(node->items_area.end_hash);

		area_offset = node->items_area.offset;
		area_size = node->items_area.area_size;
		if ((area_offset + area_size) > node->node_size) {
			SSDFS_ERR("corrupted items area offset %u\n",
				  area_offset);
			return -ERANGE;
		}

		hdr->item_area_offset = cpu_to_le32(area_offset);

		area_offset = node->index_area.offset;
		area_size = node->index_area.area_size;
		if ((area_offset + area_size) > node->node_size) {
			SSDFS_ERR("corrupted index area offset %u\n",
				  area_offset);
			return -ERANGE;
		} else if ((area_offset + area_size) > node->items_area.offset) {
			SSDFS_ERR("corrupted index area offset %u\n",
				  area_offset);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(area_offset >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		hdr->index_area_offset = cpu_to_le16((u16)area_offset);
		break;

	case SSDFS_BTREE_INDEX_NODE:
		if (min_item_size != 0) {
			SSDFS_ERR("corrupted items area: "
				  "min_item_size %u\n",
				  min_item_size);
			return -ERANGE;
		} else
			hdr->min_item_size = min_item_size;

		if (max_item_size != 0) {
			SSDFS_ERR("corrupted items area: "
				  "max_item_size %u\n",
				  max_item_size);
			return -ERANGE;
		} else
			hdr->max_item_size = cpu_to_le16(max_item_size);

		if (items_capacity != 0) {
			SSDFS_ERR("corrupted items area's state\n");
			return -ERANGE;
		} else
			hdr->items_capacity = cpu_to_le16(items_capacity);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node_id %u, node_type %#x, "
			  "start_hash %llx, end_hash %llx\n",
			  node->node_id,
			  atomic_read(&node->type),
			  node->index_area.start_hash,
			  node->index_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

		hdr->start_hash = cpu_to_le64(node->index_area.start_hash);
		hdr->end_hash = cpu_to_le64(node->index_area.end_hash);

		area_offset = node->index_area.offset;
		area_size = node->index_area.area_size;
		if ((area_offset + area_size) > node->node_size) {
			SSDFS_ERR("corrupted index area offset %u\n",
				  area_offset);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(area_offset >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		hdr->index_area_offset = cpu_to_le16((u16)area_offset);
		break;

	default:
		SSDFS_ERR("invalid node type %#x\n", type);
		return -ERANGE;
	}

	hdr->create_cno = cpu_to_le64(node->create_cno);
	hdr->node_id = cpu_to_le32(node->node_id);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, node_type %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "items_capacity %u\n",
		  node->node_id,
		  atomic_read(&node->type),
		  le64_to_cpu(hdr->start_hash),
		  le64_to_cpu(hdr->end_hash),
		  le16_to_cpu(hdr->items_capacity));
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_node_pre_flush() - pre-flush the dirty btree node
 * @node: node object
 *
 * This method tries to pre-flush the dirty btree node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_node_pre_flush(struct ssdfs_btree_node *node)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);

	SSDFS_DBG("node_id %u, height %u, type %#x, state %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type),
		  atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_btree_node_dirty(node))
		return 0;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
		if (!node->tree->btree_ops ||
		    !node->tree->btree_ops->pre_flush_root_node) {
			SSDFS_WARN("unable to pre-flush the root node\n");
			return -EOPNOTSUPP;
		}

		err = node->tree->btree_ops->pre_flush_root_node(node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to pre-flush root node: "
				  "node_id %u, height %u, err %d\n",
				  node->node_id,
				  atomic_read(&node->height),
				  err);
		}
		break;

	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		if (!node->tree->btree_ops ||
		    !node->tree->btree_ops->pre_flush_node) {
			SSDFS_WARN("unable to pre-flush common node\n");
			return -EOPNOTSUPP;
		}

		err = node->tree->btree_ops->pre_flush_node(node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to pre-flush common node: "
				  "node_id %u, height %u, err %d\n",
				  node->node_id,
				  atomic_read(&node->height),
				  err);
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid node type %#x\n",
			   atomic_read(&node->type));
		break;
	}

	return err;
}

/*
 * ssdfs_btree_flush_root_node() - flush root node
 * @node: node object
 * @root_node: pointer on the on-disk root node object
 */
void ssdfs_btree_flush_root_node(struct ssdfs_btree_node *node,
				struct ssdfs_btree_inline_root_node *root_node)
{

	struct ssdfs_fs_info *fsi;
	size_t node_ids_len = sizeof(__le32) *
				SSDFS_BTREE_ROOT_NODE_INDEX_COUNT;
	size_t indexes_len = sizeof(struct ssdfs_btree_index) *
				SSDFS_BTREE_ROOT_NODE_INDEX_COUNT;
	u16 items_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !root_node);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	down_write(&node->header_lock);

	items_count = node->index_area.index_count;
	root_node->header.height = (u8)atomic_read(&node->tree->height);
	root_node->header.items_count = (u8)items_count;
	root_node->header.flags = (u8)atomic_read(&node->flags);
	root_node->header.type = (u8)atomic_read(&node->type);
	ssdfs_memcpy(root_node->header.node_ids, 0, node_ids_len,
		     node->raw.root_node.header.node_ids, 0, node_ids_len,
		     node_ids_len);
	ssdfs_memcpy(root_node->indexes, 0, indexes_len,
		     node->raw.root_node.indexes, 0, indexes_len,
		     indexes_len);
	clear_ssdfs_btree_node_dirty(node);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("left index (node_id %u, hash %llx), "
		  "right index (node_id %u, hash %llx)\n",
		  le32_to_cpu(root_node->header.node_ids[0]),
		  le64_to_cpu(root_node->indexes[0].hash),
		  le32_to_cpu(root_node->header.node_ids[1]),
		  le64_to_cpu(root_node->indexes[1].hash));
#endif /* CONFIG_SSDFS_DEBUG */

	up_write(&node->header_lock);

	spin_lock(&node->tree->nodes_lock);
	root_node->header.upper_node_id =
		cpu_to_le32(node->tree->upper_node_id);
	spin_unlock(&node->tree->nodes_lock);

	ssdfs_request_init(&node->flush_req, fsi->pagesize);
	atomic_set(&node->flush_req.result.state, SSDFS_REQ_FINISHED);
}

/*
 * ssdfs_btree_node_copy_header_nolock() - copy btree node's header
 * @node: node object
 * @folio: folio to store the metadata [out]
 * @write_offset: current write offset [out]
 *
 * This method tries to save the btree node's header.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_node_copy_header_nolock(struct ssdfs_btree_node *node,
					struct folio *folio,
					u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	size_t hdr_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !folio);
	BUG_ON(!rwsem_is_locked(&node->header_lock));
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, height %u, type %#x, write_offset %u\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type), *write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;
	hdr_size = sizeof(node->raw);

	if (*write_offset >= fsi->pagesize) {
		SSDFS_ERR("invalid write_offset %u\n",
			  *write_offset);
		return -EINVAL;
	}

	/* all btrees have the same node's header size */
	err = __ssdfs_memcpy_to_folio(folio, *write_offset, folio_size(folio),
					&node->raw, 0, hdr_size,
					hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy node's header: "
			  "write_offset %u, size %zu, err %d\n",
			  *write_offset, hdr_size, err);
		return err;
	}

	*write_offset += hdr_size;

	if (*write_offset >= PAGE_SIZE) {
		SSDFS_ERR("invalid write_offset %u\n",
			  *write_offset);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_retrieve_btree_node_content() - retrieve btree node's content
 * @node: node object
 *
 * This method tries to retrive btree node's content into
 * flush request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_retrieve_btree_node_content(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_request_content_block *block;
	struct ssdfs_content_block *blk_state;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	for (i = 0; i < node->flush_req.result.content.count; i++) {
		block = &node->flush_req.result.content.blocks[i];
		blk_state = &block->new_state;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folio_batch_count(&blk_state->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(node->content.count <= i);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_memcpy_batch2batch(&blk_state->batch, 0,
					&node->content.blocks[i].batch, 0,
					fsi->pagesize);
		if (unlikely(err)) {
			SSDFS_ERR("fail to retrieve node's content: "
				  "blk_index %d, err %d\n",
				  i, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_node_prepare_flush_request() - prepare node's content for flush
 * @node: node object
 *
 * This method tries to prepare the node's content
 * for flush operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_node_prepare_flush_request(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_state_bitmap *bmap;
	struct folio *folio;
	u64 logical_offset;
	u32 data_bytes;
	u64 seg_id = U64_MAX;
	u32 logical_blk;
	u32 len;
	u32 blks_count;
	int node_flags;
	u32 write_offset = 0;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		/* expected state */
		break;

	default:
		BUG();
	};

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;
	blks_count = node->node_size >> fsi->log_pagesize;

	if (blks_count == 0 || blks_count > SSDFS_BTREE_NODE_EXTENT_LEN_MAX) {
		SSDFS_WARN("invalid memory folios count: "
			   "node_size %u, blks_count %u\n",
			   node->node_size, blks_count);
		return -ERANGE;
	}

	if (node->content.count != blks_count) {
		SSDFS_ERR("invalid blks_count: "
			  "blks_count1 %u != blks_count2 %u\n",
			  node->content.count,
			  blks_count);
		return -ERANGE;
	}

	ssdfs_request_init(&node->flush_req, fsi->pagesize);
	ssdfs_get_request(&node->flush_req);

	logical_offset = (u64)node->node_id * node->node_size;
	data_bytes = node->node_size;
	ssdfs_request_prepare_logical_extent(node->tree->owner_ino,
					     (u64)logical_offset,
					     (u32)data_bytes,
					     0, 0, &node->flush_req);

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	spin_lock(&node->descriptor_lock);
	si = node->seg;
	seg_id = le64_to_cpu(node->extent.seg_id);
	logical_blk = le32_to_cpu(node->extent.logical_blk);
	len = le32_to_cpu(node->extent.len);
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
	BUG_ON(seg_id != si->seg_id);

	SSDFS_DBG("node_id %u, height %u, type %#x, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type),
		  seg_id, logical_blk, len);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < blks_count; i++) {
		struct ssdfs_request_content_block *block;
		struct ssdfs_content_block *blk_state;

		err = ssdfs_request_add_allocated_folio_locked(i,
							&node->flush_req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add folio into request: "
				  "err %d\n",
				  err);
			goto unlock_node;
		}

		block = &node->flush_req.result.content.blocks[i];
		blk_state = &block->new_state;

		for (j = 0; j < folio_batch_count(&blk_state->batch); j++) {
			folio = blk_state->batch.folios[j];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_folio_start_writeback(fsi, seg_id,
						    logical_offset, folio);
			ssdfs_request_writeback_folios_inc(&node->flush_req);
			logical_offset += folio_size(folio);
		}
	}

	folio = node->content.blocks[0].batch.folios[0];

	ssdfs_folio_lock(folio);
	ssdfs_btree_node_copy_header_nolock(node, folio, &write_offset);
	ssdfs_folio_unlock(folio);

	ssdfs_request_define_segment(seg_id, &node->flush_req);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_blk >= U16_MAX);
	BUG_ON(len >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	ssdfs_request_define_volume_extent((u16)logical_blk, (u16)len,
					   &node->flush_req);

	err = ssdfs_retrieve_btree_node_content(node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to retrieve node's content: "
			  "node_id %u, height %u, type %#x, "
			  "seg_id %llu, logical_blk %u, "
			  "len %u, err %d\n",
			  node->node_id, atomic_read(&node->height),
			  atomic_read(&node->type),
			  seg_id, logical_blk, len, err);
		goto unlock_node;
	}

	node_flags = atomic_read(&node->flags);

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, err %d\n",
				  si->seg_id, err);
			goto unlock_node;
		}
	}

	if (node_flags & SSDFS_BTREE_NODE_PRE_ALLOCATED) {
		/* update pre-allocated extent */
		err = ssdfs_segment_update_pre_alloc_extent_async(si,
							SSDFS_REQ_ASYNC_NO_FREE,
							&node->flush_req);
	} else {
		/* update extent */
		err = ssdfs_segment_update_extent_async(si,
							SSDFS_REQ_ASYNC_NO_FREE,
							&node->flush_req);
	}

	if (!err) {
		down_read(&node->bmap_array.lock);
		bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
		spin_lock(&bmap->lock);
		bitmap_clear(bmap->ptr, 0, node->bmap_array.bits_count);
		spin_unlock(&bmap->lock);
		up_read(&node->bmap_array.lock);
		clear_ssdfs_btree_node_dirty(node);
	}

unlock_node:
	up_write(&node->header_lock);
	up_write(&node->full_lock);

	if (unlikely(err)) {
		SSDFS_ERR("update request failed: "
			  "ino %llu, logical_offset %llu, size %u, err %d\n",
			  node->flush_req.extent.ino,
			  node->flush_req.extent.logical_offset,
			  node->flush_req.extent.data_bytes,
			  err);
		goto fail_prepare_flush_request;
	}

	return 0;

fail_prepare_flush_request:
	logical_offset = (u64)node->node_id * node->node_size;

	for (i = 0; i < node->flush_req.result.content.count; i++) {
		struct ssdfs_request_content_block *block;
		struct ssdfs_content_block *blk_state;

		block = &node->flush_req.result.content.blocks[i];
		blk_state = &block->new_state;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folio_batch_count(&blk_state->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		for (j = 0; j < folio_batch_count(&blk_state->batch); j++) {
			folio = blk_state->batch.folios[j];

			if (!folio)
				continue;

			ssdfs_folio_end_writeback(fsi, seg_id,
						  logical_offset, folio);
			ssdfs_request_writeback_folios_dec(&node->flush_req);
			logical_offset += folio_size(folio);
		}
	}

	ssdfs_request_unlock_and_remove_folios(&node->flush_req);
	ssdfs_put_request(&node->flush_req);

	return err;
}

/*
 * ssdfs_btree_common_node_flush() - common method of node flushing
 * @node: node object
 *
 * This method tries to flush the node in general way.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_common_node_flush(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct folio *folio;
	size_t index_key_size = sizeof(struct ssdfs_btree_index_key);
	u32 blks_count;
	int node_flags;
	int i, j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		/* expected state */
		break;

	default:
		BUG();
	};

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	blks_count = node->node_size / fsi->pagesize;

	if (blks_count == 0 || blks_count > SSDFS_BTREE_NODE_EXTENT_LEN_MAX) {
		SSDFS_WARN("invalid folios count: "
			   "node_size %u, blks_count %u\n",
			   node->node_size, blks_count);
		return -ERANGE;
	}

	if (node->content.count != blks_count) {
		SSDFS_ERR("invalid blks_count: "
			  "blks_count1 %u != blks_count2 %u\n",
			  node->content.count, blks_count);
		return -ERANGE;
	}

	node_flags = atomic_read(&node->flags);

	if (can_diff_on_write_metadata_be_used(node)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node_id %u, height %u, type %#x\n",
			  node->node_id, atomic_read(&node->height),
			  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_btree_node_prepare_diff(node);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("node %u is not ready for diff: "
				  "ino %llu, logical_offset %llu, size %u\n",
				  node->node_id,
				  node->flush_req.extent.ino,
				  node->flush_req.extent.logical_offset,
				  node->flush_req.extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_btree_node_prepare_flush_request(node);
		}
	} else {
		err = ssdfs_btree_node_prepare_flush_request(node);
	}

	if (unlikely(err)) {
		SSDFS_ERR("update request failed: "
			  "ino %llu, logical_offset %llu, size %u, err %d\n",
			  node->flush_req.extent.ino,
			  node->flush_req.extent.logical_offset,
			  node->flush_req.extent.data_bytes,
			  err);
		goto fail_flush_node;
	} else if (node_flags & SSDFS_BTREE_NODE_PRE_ALLOCATED) {
		struct ssdfs_btree_node *parent;
		struct ssdfs_btree_index_key old_key, new_key;
		u16 flags;

		spin_lock(&node->descriptor_lock);
		ssdfs_memcpy(&old_key, 0, index_key_size,
			     &node->node_index, 0, index_key_size,
			     index_key_size);
		spin_unlock(&node->descriptor_lock);

		ssdfs_memcpy(&new_key, 0, index_key_size,
			     &old_key, 0, index_key_size,
			     index_key_size);

		flags = le16_to_cpu(old_key.flags);
		flags &= ~SSDFS_BTREE_INDEX_SHOW_PREALLOCATED_CHILD;
		new_key.flags = cpu_to_le16(flags);

		spin_lock(&node->descriptor_lock);
		parent = node->parent_node;
		spin_unlock(&node->descriptor_lock);

		err = ssdfs_btree_node_change_index(parent,
						    &old_key,
						    &new_key);
		if (!err) {
			spin_lock(&node->descriptor_lock);
			ssdfs_memcpy(&node->node_index, 0, index_key_size,
				     &new_key, 0, index_key_size,
				     index_key_size);
			spin_unlock(&node->descriptor_lock);

			atomic_and(~SSDFS_BTREE_NODE_PRE_ALLOCATED,
				   &node->flags);
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_start_bit %lu, item_start_bit %lu, "
		  "bits_count %lu\n",
		  node->bmap_array.index_start_bit,
		  node->bmap_array.item_start_bit,
		  node->bmap_array.bits_count);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

fail_flush_node:
	for (i = 0; i < node->flush_req.result.content.count; i++) {
		struct ssdfs_request_content_block *block;
		struct ssdfs_content_block *blk_state;

		block = &node->flush_req.result.content.blocks[i];
		blk_state = &block->new_state;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folio_batch_count(&blk_state->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		for (j = 0; j < folio_batch_count(&blk_state->batch); j++) {
			folio = blk_state->batch.folios[j];

			if (!folio)
				continue;

			ssdfs_folio_end_writeback(fsi, U64_MAX, 0, folio);
			ssdfs_request_writeback_folios_dec(&node->flush_req);
		}
	}

	ssdfs_request_unlock_and_remove_folios(&node->flush_req);
	ssdfs_put_request(&node->flush_req);

	return err;
}

/*
 * ssdfs_btree_node_flush() - flush the dirty btree node
 * @node: node object
 *
 * This method tries to flush the dirty btree node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_node_flush(struct ssdfs_btree_node *node)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("node_id %u, height %u, type %#x, state %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type),
		  atomic_read(&node->state));
#else
	SSDFS_DBG("node_id %u, height %u, type %#x, state %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type),
		  atomic_read(&node->state));
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!is_ssdfs_btree_node_dirty(node))
		return 0;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
		if (!node->tree->btree_ops ||
		    !node->tree->btree_ops->flush_root_node) {
			SSDFS_WARN("unable to flush the root node\n");
			return -EOPNOTSUPP;
		}

		ssdfs_btree_node_start_request_cno(node);
		err = node->tree->btree_ops->flush_root_node(node);
		ssdfs_btree_node_finish_request_cno(node);

		if (unlikely(err)) {
			SSDFS_ERR("fail to flush root node: "
				  "node_id %u, height %u, err %d\n",
				  node->node_id,
				  atomic_read(&node->height),
				  err);
		}
		break;

	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		if (!node->tree->btree_ops ||
		    !node->tree->btree_ops->flush_node) {
			SSDFS_WARN("unable to flush the common node\n");
			return -EOPNOTSUPP;
		}

		ssdfs_btree_node_start_request_cno(node);
		err = node->tree->btree_ops->flush_node(node);
		ssdfs_btree_node_finish_request_cno(node);

		if (unlikely(err)) {
			SSDFS_ERR("fail to flush common node: "
				  "node_id %u, height %u, err %d\n",
				  node->node_id,
				  atomic_read(&node->height),
				  err);
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid node type %#x\n",
			   atomic_read(&node->type));
		break;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_btree_node_object(node);

	return err;
}

/*
 * ssdfs_btree_node_commit_log() - request the log commit for the node
 * @node: node object
 *
 * This method tries to request the log commit for the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_node_commit_log(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	u64 logical_offset;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		/* expected state */
		break;

	default:
		BUG();
	};
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	ssdfs_request_init(&node->flush_req, fsi->pagesize);
	ssdfs_get_request(&node->flush_req);

	logical_offset = (u64)node->node_id * node->node_size;
	ssdfs_request_prepare_logical_extent(node->tree->owner_ino,
					     (u64)logical_offset,
					     0, 0, 0, &node->flush_req);

	spin_lock(&node->descriptor_lock);
	si = node->seg;
	seg_id = le64_to_cpu(node->extent.seg_id);
	logical_blk = le32_to_cpu(node->extent.logical_blk);
	len = le32_to_cpu(node->extent.len);
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
	BUG_ON(seg_id != si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_define_segment(seg_id, &node->flush_req);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_blk >= U16_MAX);
	BUG_ON(len >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	ssdfs_request_define_volume_extent((u16)logical_blk, (u16)len,
					   &node->flush_req);

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, err %d\n",
				  si->seg_id, err);
			goto finish_commit_log;
		}
	}

	err = ssdfs_segment_commit_log_async(si, SSDFS_REQ_ASYNC_NO_FREE,
					     &node->flush_req);
	if (unlikely(err)) {
		SSDFS_ERR("commit log request failed: "
			  "ino %llu, logical_offset %llu, err %d\n",
			  node->flush_req.extent.ino,
			  node->flush_req.extent.logical_offset,
			  err);
		goto finish_commit_log;
	}

finish_commit_log:
	if (err)
		ssdfs_put_request(&node->flush_req);

	return err;
}

/*
 * ssdfs_btree_deleted_node_commit_log() - request the log commit (deleted node)
 * @node: node object
 *
 * This method tries to request the log commit for the deleted node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_deleted_node_commit_log(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	u64 seg_id;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		/* expected state */
		break;

	default:
		BUG();
	};
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_btree_node_pre_deleted(node)) {
		SSDFS_ERR("node %u is not pre-deleted\n",
			  node->node_id);
		return -ERANGE;
	}

	fsi = node->tree->fsi;

	spin_lock(&node->descriptor_lock);
	si = node->seg;
	seg_id = le64_to_cpu(node->extent.seg_id);
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
	BUG_ON(seg_id != si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < si->pebs_count; i++) {
		struct ssdfs_segment_request *req;
		struct ssdfs_peb_container *pebc;
		struct ssdfs_requests_queue *rq;
		wait_queue_head_t *wait;

		pebc = &si->peb_array[i];

		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			return err;
		}

		ssdfs_request_init(req, fsi->pagesize);
		ssdfs_get_request(req);

		ssdfs_request_prepare_internal_data(SSDFS_PEB_UPDATE_REQ,
						    SSDFS_COMMIT_LOG_NOW,
						    SSDFS_REQ_ASYNC, req);
		ssdfs_request_define_segment(si->seg_id, req);
		ssdfs_account_commit_log_request(si);

		ssdfs_segment_create_request_cno(si);

		rq = &pebc->update_rq;
		ssdfs_requests_queue_add_tail_inc(si->fsi, rq, req);

		wait = &si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
		wake_up_all(wait);
	}

	return 0;
}

/*
 * is_ssdfs_btree_node_dirty() - check that btree node is dirty
 * @node: node object
 */
bool is_ssdfs_btree_node_dirty(struct ssdfs_btree_node *node)
{
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->state);

	switch (state) {
	case SSDFS_BTREE_NODE_DIRTY:
	case SSDFS_BTREE_NODE_PRE_DELETED:
		return true;

	case SSDFS_BTREE_NODE_INITIALIZED:
		return false;

	default:
		SSDFS_WARN("invalid node state %#x\n",
			   state);
		/* FALLTHRU */
	};

	return false;
}

/*
 * set_ssdfs_btree_node_dirty() - set btree node in dirty state
 * @node: node object
 */
void set_ssdfs_btree_node_dirty(struct ssdfs_btree_node *node)
{
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->state);

	switch (state) {
	case SSDFS_BTREE_NODE_DIRTY:
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_CREATED:
		atomic_set(&node->state, SSDFS_BTREE_NODE_DIRTY);
		spin_lock(&node->tree->nodes_lock);
		radix_tree_tag_set(&node->tree->nodes, node->node_id,
				   SSDFS_BTREE_NODE_DIRTY_TAG);
		spin_unlock(&node->tree->nodes_lock);
		break;

	default:
		SSDFS_WARN("invalid node state %#x\n",
			   state);
		/* FALLTHRU */
	};
}

/*
 * clear_ssdfs_btree_node_dirty() - clear dirty state of btree node
 * @node: node object
 */
void clear_ssdfs_btree_node_dirty(struct ssdfs_btree_node *node)
{
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->state);

	switch (state) {
	case SSDFS_BTREE_NODE_DIRTY:
		atomic_set(&node->state, SSDFS_BTREE_NODE_INITIALIZED);
		spin_lock(&node->tree->nodes_lock);
		radix_tree_tag_clear(&node->tree->nodes, node->node_id,
				     SSDFS_BTREE_NODE_DIRTY_TAG);
		spin_unlock(&node->tree->nodes_lock);
		break;

	case SSDFS_BTREE_NODE_CORRUPTED:
		spin_lock(&node->tree->nodes_lock);
		radix_tree_tag_clear(&node->tree->nodes, node->node_id,
				     SSDFS_BTREE_NODE_DIRTY_TAG);
		spin_unlock(&node->tree->nodes_lock);
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
		/* do nothing */
		break;

	default:
		SSDFS_WARN("invalid node state %#x\n",
			   state);
		/* FALLTHRU */
	};
}

/*
 * is_ssdfs_btree_node_pre_deleted() - check that btree node is pre-deleted
 * @node: node object
 */
bool is_ssdfs_btree_node_pre_deleted(struct ssdfs_btree_node *node)
{
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->state);

	switch (state) {
	case SSDFS_BTREE_NODE_PRE_DELETED:
		return true;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		return false;

	default:
		SSDFS_WARN("invalid node state %#x\n",
			   state);
		/* FALLTHRU */
	};

	return false;
}

/*
 * set_ssdfs_btree_node_pre_deleted() - set btree node in pre-deleted state
 * @node: node object
 */
void set_ssdfs_btree_node_pre_deleted(struct ssdfs_btree_node *node)
{
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->state);

	switch (state) {
	case SSDFS_BTREE_NODE_PRE_DELETED:
	case SSDFS_BTREE_NODE_DIRTY:
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_CREATED:
		atomic_set(&node->state, SSDFS_BTREE_NODE_PRE_DELETED);
		spin_lock(&node->tree->nodes_lock);
		radix_tree_tag_set(&node->tree->nodes, node->node_id,
				   SSDFS_BTREE_NODE_DIRTY_TAG);
		spin_unlock(&node->tree->nodes_lock);
		break;

	default:
		SSDFS_WARN("invalid node state %#x\n",
			   state);
		/* FALLTHRU */
	};
}

/*
 * clear_ssdfs_btree_node_pre_deleted() - clear pre-deleted state of btree node
 * @node: node object
 */
void clear_ssdfs_btree_node_pre_deleted(struct ssdfs_btree_node *node)
{
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->state);

	switch (state) {
	case SSDFS_BTREE_NODE_PRE_DELETED:
		atomic_set(&node->state, SSDFS_BTREE_NODE_INITIALIZED);
		spin_lock(&node->tree->nodes_lock);
		radix_tree_tag_clear(&node->tree->nodes, node->node_id,
				     SSDFS_BTREE_NODE_DIRTY_TAG);
		spin_unlock(&node->tree->nodes_lock);
		break;

	case SSDFS_BTREE_NODE_CORRUPTED:
		spin_lock(&node->tree->nodes_lock);
		radix_tree_tag_clear(&node->tree->nodes, node->node_id,
				     SSDFS_BTREE_NODE_DIRTY_TAG);
		spin_unlock(&node->tree->nodes_lock);
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
		/* do nothing */
		break;

	default:
		SSDFS_WARN("invalid node state %#x\n",
			   state);
		/* FALLTHRU */
	};
}

/*
 * is_ssdfs_btree_node_index_area_exist() - check that node has index area
 * @node: node object
 */
bool is_ssdfs_btree_node_index_area_exist(struct ssdfs_btree_node *node)
{
	u16 flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is not initialized\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
	case SSDFS_BTREE_NODE_PRE_DELETED:
		/* expected state */
		break;

	default:
		BUG();
	}

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
		return true;

	case SSDFS_BTREE_INDEX_NODE:
		flags = atomic_read(&node->flags);
		if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA)
			return true;
		else {
			SSDFS_WARN("index node %u hasn't index area\n",
				   node->node_id);
		}
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		flags = atomic_read(&node->flags);
		if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA)
			return true;
		break;

	case SSDFS_BTREE_LEAF_NODE:
		/* do nothing */
		break;

	default:
		BUG();
	}

	return false;
}

/*
 * is_ssdfs_btree_node_index_area_empty() - check that index area is empty
 * @node: node object
 */
bool is_ssdfs_btree_node_index_area_empty(struct ssdfs_btree_node *node)
{
	bool is_empty = false;
	int state;
	int flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is not initialized\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
	case SSDFS_BTREE_NODE_PRE_DELETED:
		/* expected state */
		break;

	default:
		BUG();
	}

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
		/* need to check the index area */
		break;

	case SSDFS_BTREE_INDEX_NODE:
		flags = atomic_read(&node->flags);
		if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
			/*
			 * need to check the index area
			 */
		} else {
			SSDFS_WARN("index node %u hasn't index area\n",
				   node->node_id);
			return false;
		}
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		flags = atomic_read(&node->flags);
		if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
			/*
			 * need to check the index area
			 */
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("node %u hasn't index area\n",
				  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return true;
		}
		break;

	case SSDFS_BTREE_LEAF_NODE:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is leaf node\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return true;

	default:
		BUG();
	}

	down_read(&node->header_lock);
	state = atomic_read(&node->index_area.state);
	if (state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST)
		err = -ERANGE;
	else if (node->index_area.index_capacity == 0)
		err = -ERANGE;
	else
		is_empty = node->index_area.index_count == 0;
	up_read(&node->header_lock);

	if (unlikely(err)) {
		SSDFS_WARN("node %u is corrupted\n", node->node_id);
		return false;
	}

	return is_empty;
}

/*
 * is_ssdfs_btree_node_items_area_exist() - check that node has items area
 * @node: node object
 */
bool is_ssdfs_btree_node_items_area_exist(struct ssdfs_btree_node *node)
{
	u16 flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
	case SSDFS_BTREE_NODE_PRE_DELETED:
		/* expected state */
		break;

	default:
		BUG();
	}

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_INDEX_NODE:
		return false;

	case SSDFS_BTREE_HYBRID_NODE:
		flags = atomic_read(&node->flags);
		if (flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA)
			return true;
		break;

	case SSDFS_BTREE_LEAF_NODE:
		flags = atomic_read(&node->flags);
		if (flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA)
			return true;
		else {
			SSDFS_WARN("corrupted leaf node %u\n",
				   node->node_id);
		}
		break;

	default:
		BUG();
	}

	return false;
}

/*
 * is_ssdfs_btree_node_items_area_empty() - check that items area is empty
 * @node: node object
 */
bool is_ssdfs_btree_node_items_area_empty(struct ssdfs_btree_node *node)
{
	bool is_empty = false;
	int state;
	int flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
	case SSDFS_BTREE_NODE_PRE_DELETED:
		/* expected state */
		break;

	default:
		BUG();
	}

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_INDEX_NODE:
		return true;

	case SSDFS_BTREE_HYBRID_NODE:
		flags = atomic_read(&node->flags);
		if (flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA) {
			/*
			 * need to check the items area
			 */
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("node %u hasn't items area\n",
				  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return true;
		}
		break;

	case SSDFS_BTREE_LEAF_NODE:
		flags = atomic_read(&node->flags);
		if (flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA) {
			/*
			 * need to check the items area
			 */
		} else {
			SSDFS_WARN("leaf node %u hasn't items area\n",
				  node->node_id);
			return false;
		}
		break;

	default:
		BUG();
	}

	down_read(&node->header_lock);
	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST)
		err = -ERANGE;
	else if (node->items_area.items_capacity == 0)
		err = -ERANGE;
	else
		is_empty = node->items_area.items_count == 0;
	up_read(&node->header_lock);

	if (unlikely(err)) {
		SSDFS_WARN("node %u is corrupted\n", node->node_id);
		return false;
	}

	return is_empty;
}

/*
 * ssdfs_btree_node_shrink_index_area() - shrink the index area
 * @node: node object
 * @new_size: the new size of index area in bytes
 *
 * This method tries to shrink the index area in size.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE       - internal error.
 * %-EOPNOTSUPP   - requsted action is not supported.
 */
static
int ssdfs_btree_node_shrink_index_area(struct ssdfs_btree_node *node,
					u32 new_size)
{
	u8 index_size;
	u16 index_count;
	u16 index_capacity;
	u32 area_size;
	u32 cur_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, new_size %u\n",
		  node->node_id, new_size);
#endif /* CONFIG_SSDFS_DEBUG */

	index_size = node->index_area.index_size;
	index_count = node->index_area.index_count;
	index_capacity = node->index_area.index_capacity;
	area_size = node->index_area.area_size;

	cur_size = (u32)index_size * index_count;

	if (area_size <= new_size) {
		SSDFS_ERR("cannot grow index area: "
			  "area_size %u, new_size %u\n",
			  area_size, new_size);
		return -EOPNOTSUPP;
	}

	if (new_size % index_size) {
		SSDFS_ERR("unaligned new_size: "
			  "index_size %u, new_size %u\n",
			  index_size, new_size);
		return -ERANGE;
	}

	if (cur_size > area_size) {
		SSDFS_WARN("invalid cur_size: "
			   "cur_size %u, area_size %u\n",
			   cur_size, area_size);
		return -ERANGE;
	}

	if (cur_size == area_size || cur_size > new_size) {
		SSDFS_ERR("unable to shrink index area: "
			  "cur_size %u, new_size %u, area_size %u\n",
			  cur_size, new_size, area_size);
		return -ERANGE;
	}

	node->index_area.area_size = new_size;
	node->index_area.index_capacity = new_size / index_size;

	return 0;
}

/*
 * ssdfs_btree_node_grow_index_area() - grow the index area
 * @node: node object
 * @new_size: the new size of index area in bytes
 *
 * This method tries to increase the size of index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE       - internal error.
 * %-EOPNOTSUPP   - requsted action is not supported.
 */
static
int ssdfs_btree_node_grow_index_area(struct ssdfs_btree_node *node,
				     u32 new_size)
{
	u8 index_size;
	u16 index_count;
	u16 index_capacity;
	u32 area_size;
	u32 cur_size;
	unsigned long offset1, offset2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, new_size %u\n",
		  node->node_id, new_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (new_size > node->node_size) {
		SSDFS_ERR("invalid new size: "
			  "new_size %u, node_size %u\n",
			  new_size, node->node_size);
		return -ERANGE;
	}

	index_size = node->index_area.index_size;
	index_count = node->index_area.index_count;
	index_capacity = node->index_area.index_capacity;
	area_size = node->index_area.area_size;

	cur_size = (u32)index_size * index_count;

	if (area_size > new_size) {
		SSDFS_ERR("cannot shrink index area: "
			  "area_size %u, new_size %u\n",
			  area_size, new_size);
		return -EOPNOTSUPP;
	}

	if (new_size % index_size) {
		SSDFS_ERR("unaligned new_size: "
			  "index_size %u, new_size %u\n",
			  index_size, new_size);
		return -ERANGE;
	}

	if (cur_size > area_size) {
		SSDFS_WARN("invalid cur_size: "
			   "cur_size %u, area_size %u\n",
			   cur_size, area_size);
		return -ERANGE;
	}

	offset1 = node->items_area.offset;
	offset2 = node->index_area.offset;

	if (new_size == node->node_size) {
		node->index_area.index_capacity =
			(new_size - node->index_area.offset) / index_size;
	} else if ((offset1 - offset2) != new_size) {
		SSDFS_ERR("unable to resize the index area: "
			  "items_area.offset %u, index_area.offset %u, "
			  "new_size %u\n",
			  node->items_area.offset,
			  node->index_area.offset,
			  new_size);
		return -ERANGE;
	} else
		node->index_area.index_capacity = new_size / index_size;

	down_read(&node->bmap_array.lock);
	offset1 = node->bmap_array.item_start_bit;
	offset2 = node->bmap_array.index_start_bit;
	if ((offset1 - offset2) < node->index_area.index_capacity)
		err = -ERANGE;
	up_read(&node->bmap_array.lock);

	if (unlikely(err)) {
		SSDFS_ERR("unable to resize the index area: "
			  "items_start_bit %lu, index_start_bit %lu, "
			  "new_index_capacity %u\n",
			  node->bmap_array.item_start_bit,
			  node->bmap_array.index_start_bit,
			  new_size / index_size);
		return -ERANGE;
	}

	if (new_size == node->node_size)
		node->index_area.area_size = new_size - node->index_area.offset;
	else
		node->index_area.area_size = new_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_area: offset %u, area_size %u, "
		  "free_space %u, capacity %u; "
		  "index_area: offset %u, area_size %u, "
		  "capacity %u\n",
		  node->items_area.offset,
		  node->items_area.area_size,
		  node->items_area.free_space,
		  node->items_area.items_capacity,
		  node->index_area.offset,
		  node->index_area.area_size,
		  node->index_area.index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_check_btree_node_after_resize() - check btree node's consistency
 * @node: node object
 *
 * This method tries to check the consistency of btree node
 * after resize.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE  - btree node is inconsistent.
 */
#ifdef CONFIG_SSDFS_DEBUG
static
int ssdfs_check_btree_node_after_resize(struct ssdfs_btree_node *node)
{
	u32 offset;
	u32 area_size;
	u8 index_size;
	u16 index_count;
	u16 index_capacity;
	u16 items_count;
	u16 items_capacity;
	u32 average_item_size;
	unsigned long bits_count;
	unsigned long index_start_bit, item_start_bit;
	int err = 0;

	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	offset = node->index_area.offset;
	area_size = node->index_area.area_size;

	if ((offset + area_size) == node->node_size) {
		/*
		 * Continue logic
		 */
	} else if ((offset + area_size) != node->items_area.offset) {
		SSDFS_ERR("invalid index area: "
			  "index_area.offset %u, "
			  "index_area.area_size %u, "
			  "items_area.offset %u\n",
			  node->index_area.offset,
			  node->index_area.area_size,
			  node->items_area.offset);
		return -ERANGE;
	}

	index_size = node->index_area.index_size;
	index_count = node->index_area.index_count;
	index_capacity = node->index_area.index_capacity;

	if (index_count > index_capacity) {
		SSDFS_ERR("index_count %u > index_capacity %u\n",
			  node->index_area.index_count,
			  node->index_area.index_capacity);
		return -ERANGE;
	}

	if (((u32)index_size * index_capacity) > area_size) {
		SSDFS_ERR("invalid index area: "
			  "index_size %u, index_capacity %u, "
			  "area_size %u\n",
			  node->index_area.index_size,
			  node->index_area.index_capacity,
			  node->index_area.area_size);
		return -ERANGE;
	}

	offset = node->items_area.offset;
	area_size = node->items_area.area_size;

	if (area_size > 0) {
		if ((offset + area_size) != node->node_size) {
			SSDFS_ERR("invalid items area: "
				  "items_area.offset %u, "
				  "items_area.area_size %u, "
				  "node_size %u\n",
				  node->items_area.offset,
				  node->items_area.area_size,
				  node->node_size);
			return -ERANGE;
		}
	}

	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;

	if (items_count > items_capacity) {
		SSDFS_ERR("invalid items area: "
			  "items_area.items_count %u, "
			  "items_area.items_capacity %u\n",
			  node->items_area.items_count,
			  node->items_area.items_capacity);
		return -ERANGE;
	}

	if (items_capacity > 0) {
		average_item_size = area_size / items_capacity;
		if (average_item_size < node->items_area.item_size ||
		    average_item_size > node->items_area.max_item_size) {
			SSDFS_ERR("invalid items area: "
				  "average_item_size %u, "
				  "item_size %u, max_item_size %u\n",
				  average_item_size,
				  node->items_area.item_size,
				  node->items_area.max_item_size);
			return -ERANGE;
		}
	}

	down_read(&node->bmap_array.lock);
	bits_count = node->bmap_array.bits_count;
	index_start_bit = node->bmap_array.index_start_bit;
	item_start_bit = node->bmap_array.item_start_bit;
	if ((index_capacity + items_capacity + 1) > bits_count)
		err = -ERANGE;
	if ((item_start_bit - index_start_bit) < index_capacity)
		err = -ERANGE;
	if ((bits_count - item_start_bit) < items_capacity)
		err = -ERANGE;
	up_read(&node->bmap_array.lock);

	if (unlikely(err)) {
		SSDFS_ERR("invalid bmap_array: "
			  "bits_count %lu, index_start_bit %lu, "
			  "item_start_bit %lu, index_capacity %u, "
			  "items_capacity %u\n",
			  bits_count, index_start_bit,
			  item_start_bit, index_capacity,
			  items_capacity);
		return err;
	}

	return 0;
}
#endif /* CONFIG_SSDFS_DEBUG */

static inline
void ssdfs_set_node_update_cno(struct ssdfs_btree_node *node)
{
	u64 current_cno = ssdfs_current_cno(node->tree->fsi->sb);

	spin_lock(&node->descriptor_lock);
	node->update_cno = current_cno;
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("current_cno %llu\n", current_cno);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_btree_node_resize_index_area() - resize the node's index area
 * @node: node object
 * @new_size: new size of node's index area
 *
 * This method tries to resize the index area of btree node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EACCES     - node is under initialization yet.
 * %-ENOENT     - index area is absent.
 * %-ENOSPC     - index area cannot be resized.
 * %-EOPNOTSUPP - resize operation is not supported.
 */
int ssdfs_btree_node_resize_index_area(struct ssdfs_btree_node *node,
					u32 new_size)
{
	struct ssdfs_fs_info *fsi;
	u16 flags;
	u8 index_size;
	u16 index_count;
	u16 index_capacity;
	u32 area_size;
	u32 cur_size;
	u32 new_items_area_size;
	int err = 0, err2;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);

	SSDFS_DBG("node_id %u, new_size %u\n",
		  node->node_id, new_size);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_INDEX_NODE:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("resize operation is unavailable: "
			   "node_id %u\n",
			   node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOSPC;

	case SSDFS_BTREE_LEAF_NODE:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index area is absent: "
			  "node_id %u\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;

	case SSDFS_BTREE_HYBRID_NODE:
		/* expected node type */
		break;

	default:
		BUG();
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index area is absent: "
			  "node_id %u\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

	flags = atomic_read(&node->tree->flags);
	if (!(flags & SSDFS_BTREE_DESC_INDEX_AREA_RESIZABLE)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to resize the index area: "
			  "node_id %u\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOSPC;
	}

	if (new_size < node->tree->index_area_min_size ||
	    new_size > node->node_size) {
		SSDFS_ERR("invalid new_size %u\n",
			  new_size);
		return -ERANGE;
	}

	if (!node->node_ops || !node->node_ops->resize_items_area) {
		SSDFS_DBG("unable to resize items area\n");
		return -EOPNOTSUPP;
	}

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	index_size = node->index_area.index_size;
	index_count = node->index_area.index_count;
	index_capacity = node->index_area.index_capacity;
	area_size = node->index_area.area_size;

	if (index_count > index_capacity) {
		err = -ERANGE;
		SSDFS_ERR("index_count %u > index_capacity %u\n",
			  index_count, index_capacity);
		goto finish_resize_operation;
	}

	if (new_size % index_size) {
		err = -ERANGE;
		SSDFS_ERR("unaligned new_size: "
			  "new_size %u, index_size %u\n",
			  new_size, index_size);
		goto finish_resize_operation;
	}

	if ((index_size * index_capacity) != area_size) {
		err = -ERANGE;
		SSDFS_ERR("invalid index area descriptor: "
			  "index_size %u, index_capacity %u, "
			  "area_size %u\n",
			  index_size, index_capacity, area_size);
		goto finish_resize_operation;
	}

	cur_size = (u32)index_size * index_count;

	if (cur_size > area_size) {
		err = -ERANGE;
		SSDFS_ERR("cur_size %u > area_size %u\n",
			  cur_size, area_size);
		goto finish_resize_operation;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_size %u, index_count %u, "
		  "index_capacity %u, index_area_size %u, "
		  "cur_size %u, new_size %u\n",
		  index_size, index_count,
		  index_capacity, area_size,
		  cur_size, new_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (new_size < node->index_area.area_size) {
		/* shrink index area */

		if (cur_size > new_size) {
			err = -ENOSPC;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to resize: "
				  "cur_size %u, new_size %u\n",
				  cur_size, new_size);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_resize_operation;
		}

		err = ssdfs_btree_node_shrink_index_area(node, new_size);
		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to shrink index area: "
				  "new_size %u\n",
				  new_size);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_resize_operation;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to shrink index area: "
				  "new_size %u, err %d\n",
				  new_size, err);
			goto finish_resize_operation;
		}

		new_items_area_size = node->items_area.area_size;
		new_items_area_size += area_size - new_size;

		err = node->node_ops->resize_items_area(node,
							new_items_area_size);
		if (err) {
			err2 = ssdfs_btree_node_grow_index_area(node,
								cur_size);
			if (err == -EOPNOTSUPP || err == -ENOSPC) {
				err = err2;
				SSDFS_ERR("fail to recover node state: "
					  "err %d\n", err);
				goto finish_resize_operation;
			}
		}

		if (err == -EOPNOTSUPP) {
			err = -ENOSPC;
			SSDFS_DBG("resize operation is unavailable\n");
			goto finish_resize_operation;
		} else if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to resize items area: "
				  "new_size %u\n",
				  new_items_area_size);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_resize_operation;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to resize items area: "
				  "new_size %u, err %d\n",
				  new_items_area_size, err);
			goto finish_resize_operation;
		}
	} else if (new_size > node->index_area.area_size) {
		/* grow index area */

		if (new_size == node->node_size) {
			/* eliminate items area */
			new_items_area_size = 0;
		} else if ((new_size - area_size) > node->items_area.area_size) {
			err = -ENOSPC;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to resize items area: "
				  "new_size %u, index_area_size %u, "
				  "items_area_size %u\n",
				  new_size,
				  node->index_area.area_size,
				  node->items_area.area_size);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_resize_operation;
		} else {
			new_items_area_size = node->items_area.area_size;
			new_items_area_size -= new_size - area_size;
		}

		err = node->node_ops->resize_items_area(node,
							new_items_area_size);
		if (err == -EOPNOTSUPP) {
			err = -ENOSPC;
			SSDFS_DBG("resize operation is unavailable\n");
			goto finish_resize_operation;
		} else if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to resize items area: "
				  "new_size %u\n",
				  new_items_area_size);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_resize_operation;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to resize items area: "
				  "new_size %u, err %d\n",
				  new_items_area_size, err);
			goto finish_resize_operation;
		}

		err = ssdfs_btree_node_grow_index_area(node, new_size);
		if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to grow index area: "
				  "new_size %u\n",
				  new_size);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_resize_operation;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to grow index area: "
				  "new_size %u, err %d\n",
				  new_size, err);
			goto finish_resize_operation;
		}
	} else {
		err = -EOPNOTSUPP;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("resize is not necessary: "
			  "old_size %u, new_size %u\n",
			  node->index_area.area_size,
			  new_size);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_resize_operation;
	}

#ifdef CONFIG_SSDFS_DEBUG
	err = ssdfs_check_btree_node_after_resize(node);
	if (unlikely(err)) {
		SSDFS_ERR("node %u is corrupted after resize\n",
			  node->node_id);
		goto finish_resize_operation;
	}
#endif /* CONFIG_SSDFS_DEBUG */

finish_resize_operation:
	up_write(&node->header_lock);
	up_write(&node->full_lock);

	if (err == -EOPNOTSUPP)
		return 0;
	else if (unlikely(err))
		return err;

	ssdfs_set_node_update_cno(node);
	set_ssdfs_btree_node_dirty(node);

	return 0;
}

/*
 * ssdfs_set_dirty_index_range() - set index range as dirty
 * @node: node object
 * @start_index: starting index
 * @count: count of indexes in the range
 *
 * This method tries to mark an index range as dirty.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EEXIST     - area is dirty already.
 */
static
int ssdfs_set_dirty_index_range(struct ssdfs_btree_node *node,
				u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long found = ULONG_MAX;
	unsigned long start_area;
	u16 capacity = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("capacity %u, start_index %u, count %u\n",
		  capacity, start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	start_area = node->bmap_array.index_start_bit;
	if (start_area == ULONG_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid items_area_start\n");
		goto finish_set_dirty_index;
	}

	if (node->bmap_array.item_start_bit == ULONG_MAX)
		capacity = node->bmap_array.bits_count;
	else
		capacity = node->bmap_array.item_start_bit - start_area;

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_set_dirty_index;
	}

	spin_lock(&bmap->lock);

	found = bitmap_find_next_zero_area(bmap->ptr, capacity,
					   start_area + start_index,
					   count, 0);
	if (found != (start_area + start_index)) {
		/* area is dirty already */
		err = -EEXIST;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("set bit: start_area %lu, start_index %u, len %u\n",
		  start_area, start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	bitmap_set(bmap->ptr, start_area + start_index, count);

	spin_unlock(&bmap->lock);

	if (unlikely(err)) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found %lu != start %lu\n",
			  found, start_area + start_index);
#endif /* CONFIG_SSDFS_DEBUG */
	}

finish_set_dirty_index:
	up_read(&node->bmap_array.lock);

	if (!err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u, tree_type %#x, "
			  "start_index %u, count %u\n",
			  node->node_id, node->tree->type,
			  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return err;
}

/*
 * ssdfs_clear_dirty_index_range_state() - clear an index range as dirty
 * @node: node object
 * @start_index: starting index
 * @count: count of indexes in the range
 *
 * This method tries to clear the state of index range as dirty.
 */
#ifdef CONFIG_SSDFS_UNDER_DEVELOPMENT_FUNC
static
void ssdfs_clear_dirty_index_range_state(struct ssdfs_btree_node *node,
					 u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long start_area;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("start_index %u, count %u\n",
		  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	start_area = node->bmap_array.index_start_bit;
	BUG_ON(start_area == ULONG_MAX);

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	BUG_ON(!bmap->ptr);

	spin_lock(&bmap->lock);
	bitmap_clear(bmap->ptr, start_area + start_index, count);
	spin_unlock(&bmap->lock);

	up_read(&node->bmap_array.lock);
}
#endif /* CONFIG_SSDFS_UNDER_DEVELOPMENT_FUNC */

/*
 * __ssdfs_lock_index_range() - lock index range
 * @node: node object
 * @start_index: starting index
 * @count: count of indexes in the range
 *
 * This method tries to lock index range without semaphore protection.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to lock the index range.
 */
static
int __ssdfs_lock_index_range(struct ssdfs_btree_node *node,
				u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long start_area;
	unsigned long upper_bound;
	int i = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->bmap_array.lock));

	SSDFS_DBG("start_index %u, count %u\n",
		  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	start_area = node->bmap_array.index_start_bit;
	if (start_area == ULONG_MAX) {
		SSDFS_ERR("invalid items_area_start\n");
		return -ERANGE;
	}

	upper_bound = start_area + start_index + count;
	if (upper_bound > node->bmap_array.item_start_bit) {
		SSDFS_ERR("invalid request: "
			  "start_area %lu, start_index %u, "
			  "count %u, item_start_bit %lu\n",
			  start_area, start_index, count,
			  node->bmap_array.item_start_bit);
		return -ERANGE;
	}

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_LOCK_BMAP];
	if (!bmap->ptr) {
		SSDFS_WARN("lock bitmap is empty\n");
		return -ERANGE;
	}

try_lock_area:
	spin_lock(&bmap->lock);

	for (; i < count; i++) {
		err = bitmap_allocate_region(bmap->ptr,
					     start_area + start_index + i, 0);
		if (err)
			break;
	}

	if (err == -EBUSY) {
		DEFINE_WAIT_FUNC(wait, woken_wake_function);

		err = 0;
		bitmap_clear(bmap->ptr, start_area + start_index, i);
		spin_unlock(&bmap->lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("waiting unlocked state of item %u\n",
			   start_index + i);
#endif /* CONFIG_SSDFS_DEBUG */

		add_wait_queue(&node->wait_queue, &wait);
		while (atomic_read(&node->bmap_array.locks_count) > 0) {
			if (signal_pending(current)) {
				break;
			} else {
				wait_woken(&wait, TASK_INTERRUPTIBLE,
					   SSDFS_DEFAULT_TIMEOUT);
			}
		}
		remove_wait_queue(&node->wait_queue, &wait);

		goto try_lock_area;
	}

	atomic_inc(&node->bmap_array.locks_count);

	spin_unlock(&bmap->lock);

	return err;
}

/*
 * ssdfs_lock_index_range() - lock index range
 * @node: node object
 * @start_index: starting index
 * @count: count of indexes in the range
 *
 * This method tries to lock index range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to lock the index range.
 */
static inline
int ssdfs_lock_index_range(struct ssdfs_btree_node *node,
			   u16 start_index, u16 count)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("start_index %u, count %u\n",
		  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);
	err = __ssdfs_lock_index_range(node, start_index, count);
	up_read(&node->bmap_array.lock);

	if (err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to lock range: "
			  "start %u, count %u, err %d\n",
			  start_index, count, err);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return err;
}

/*
 * ssdfs_lock_whole_index_area() - lock the whole index area
 * @node: node object
 * @start_index: starting index
 * @count: count of indexes in the range
 *
 * This method tries to lock the whole index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to lock the index range.
 */
int ssdfs_lock_whole_index_area(struct ssdfs_btree_node *node)
{
	unsigned long start, count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);
	start = node->bmap_array.index_start_bit;
	count = node->bmap_array.item_start_bit - start;
#ifdef CONFIG_SSDFS_DEBUG
	if (start >= U16_MAX || count >= U16_MAX) {
		SSDFS_ERR("start %lu, count %lu\n",
			  start, count);
	}

	BUG_ON(start >= U16_MAX);
	BUG_ON(count >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	err = __ssdfs_lock_index_range(node, 0, (u16)count);
	up_read(&node->bmap_array.lock);

	if (err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to lock range: "
			  "start %lu, count %lu, err %d\n",
			  start, count, err);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return err;
}

/*
 * __ssdfs_unlock_index_range() - unlock an index range
 * @node: node object
 * @start_index: starting index
 * @count: count of indexes in the range
 *
 * This method tries to unlock an index range without node's
 * semaphore protection.
 */
static
void __ssdfs_unlock_index_range(struct ssdfs_btree_node *node,
				u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long upper_bound;
	unsigned long start_area;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->bmap_array.lock));

	SSDFS_DBG("start_index %u, count %u\n",
		  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_LOCK_BMAP];
	start_area = node->bmap_array.index_start_bit;
	upper_bound = start_area + start_index + count;
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap->ptr);
	BUG_ON(start_area == ULONG_MAX);
	BUG_ON(upper_bound > node->bmap_array.item_start_bit);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&bmap->lock);
	bitmap_clear(bmap->ptr, start_area + start_index, count);
	atomic_dec(&node->bmap_array.locks_count);
	spin_unlock(&bmap->lock);
}

/*
 * ssdfs_unlock_index_range() - unlock an index range
 * @node: node object
 * @start_index: starting index
 * @count: count of indexes in the range
 *
 * This method tries to unlock an index range.
 */
static inline
void ssdfs_unlock_index_range(struct ssdfs_btree_node *node,
				u16 start_index, u16 count)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("start_index %u, count %u\n",
		  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);
	__ssdfs_unlock_index_range(node, start_index, count);
	up_read(&node->bmap_array.lock);
	wake_up_all(&node->wait_queue);
}

/*
 * ssdfs_unlock_whole_index_area() - unlock the whole index area
 * @node: node object
 * @start_index: starting index
 * @count: count of indexes in the range
 *
 * This method tries to unlock the whole index area.
 */
void ssdfs_unlock_whole_index_area(struct ssdfs_btree_node *node)
{
	unsigned long start, count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);
	start = node->bmap_array.index_start_bit;
	count = node->bmap_array.item_start_bit - start;
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(start >= U16_MAX);
	BUG_ON(count >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	__ssdfs_unlock_index_range(node, 0, (u16)count);
	up_read(&node->bmap_array.lock);
	wake_up_all(&node->wait_queue);
}

/*
 * ssdfs_btree_node_get() - increment node's reference counter
 * @node: pointer on node object
 */
void ssdfs_btree_node_get(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	WARN_ON(atomic_inc_return(&node->refs_count) <= 0);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree_type %#x, node_id %u, refs_count %d\n",
		  node->tree->type, node->node_id,
		  atomic_read(&node->refs_count));
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_btree_node_put() - decrement node's reference counter
 * @node: pointer on node object
 */
void ssdfs_btree_node_put(struct ssdfs_btree_node *node)
{
	if (!node)
		return;

	WARN_ON(atomic_dec_return(&node->refs_count) < 0);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree_type %#x, node_id %u, refs_count %d\n",
		  node->tree->type, node->node_id,
		  atomic_read(&node->refs_count));
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * is_ssdfs_node_shared() - check that node is shared between threads
 * @node: pointer on node object
 */
bool is_ssdfs_node_shared(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	return atomic_read(&node->refs_count) > 1;
}

/*
 * ssdfs_btree_root_node_find_index() - find index record in root node
 * @node: node object
 * search_hash: hash for search in the index area
 * @found_index: identification number of found index [out]
 *
 * This method tries to find the index record for the requested hash.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - unable to find the node's index.
 * %-EEXIST     - search hash has been found.
 */
static
int ssdfs_btree_root_node_find_index(struct ssdfs_btree_node *node,
				     u64 search_hash,
				     u16 *found_index)
{
	int i;
	int err = -ENODATA;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !found_index);
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, node_type %#x, search_hash %llx\n",
		  node->node_id, atomic_read(&node->type),
		  search_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	*found_index = U16_MAX;

	for (i = 0; i < SSDFS_BTREE_ROOT_NODE_INDEX_COUNT; i++) {
		struct ssdfs_btree_index *ptr = &node->raw.root_node.indexes[i];
		u64 hash = le64_to_cpu(ptr->hash);

		if (hash == U64_MAX)
			break;

		if (search_hash < hash)
			break;

		err = 0;
		*found_index = i;

		if (search_hash == hash) {
			err = -EEXIST;
			break;
		}
	}

	return err;
}

#define CUR_INDEX(kaddr, page_off, index) \
	((struct ssdfs_btree_index_key *)((u8 *)kaddr + \
	 page_off + (index * sizeof(struct ssdfs_btree_index_key))))

/*
 * ssdfs_get_index_key_hash() - get hash from a range
 * @node: node object
 * @kaddr: pointer on starting address in the page
 * @page_off: offset from page's beginning in bytes
 * @index: requested starting index in the range
 * @upper_index: last index in the available range
 * @hash_index: available (not locked) index in the range [out]
 * @hash: hash value of found index [out]
 *
 * This method tries to find any unlocked index in suggested
 * range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - unable to find the node's index.
 */
static
int ssdfs_get_index_key_hash(struct ssdfs_btree_node *node,
			     void *kaddr, u32 page_off,
			     u32 index, u32 upper_index,
			     u32 *hash_index, u64 *hash)
{
	struct ssdfs_btree_index_key *ptr;
	int err = -ENODATA;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !kaddr || !hash_index || !hash);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("kaddr %p, page_off %u, "
		  "index %u, upper_index %u\n",
		  kaddr, page_off, index, upper_index);
#endif /* CONFIG_SSDFS_DEBUG */

	*hash = U64_MAX;

	for (*hash_index = index; *hash_index <= upper_index; ++(*hash_index)) {
		err = ssdfs_lock_index_range(node, *hash_index, 1);
		if (unlikely(err)) {
			SSDFS_ERR("fail to lock index %u, err %d\n",
				  *hash_index, err);
			break;
		}

		err = -EEXIST;
		ptr = CUR_INDEX(kaddr, page_off, *hash_index);
		*hash = le64_to_cpu(ptr->index.hash);

		ssdfs_unlock_index_range(node, *hash_index, 1);

		if (err == -EEXIST) {
			err = 0;
			break;
		} else if (err == -ENODATA)
			continue;
		else if (unlikely(err))
			break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hash_index %u, hash %llx\n",
		  *hash_index, *hash);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_check_last_index() - check last index in the search
 * @node: node object
 * @kaddr: pointer on starting address in the page
 * @page_off: offset from page's beginning in bytes
 * @index: requested index for the check
 * @search_hash: hash for search
 * @range_start: first index in the index area
 * @range_end: last index in the index area
 * @prev_found: processed index on previous iteration
 * @found_index: value of found index [out]
 *
 * This method tries to check the index for the case when
 * range has only one index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOENT     - requested hash is located in previous range.
 * %-ENODATA    - unable to find the node's index.
 */
static
int ssdfs_check_last_index(struct ssdfs_btree_node *node,
			   void *kaddr, u32 page_off,
			   u32 index, u64 search_hash,
			   u32 range_start, u32 range_end,
			   u32 prev_found, u16 *found_index)
{
	u32 hash_index;
	u64 hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !kaddr || !found_index);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("kaddr %p, page_off %u, "
		  "index %u, search_hash %llx, "
		  "range_start %u, range_end %u, "
		  "prev_found %u\n",
		  kaddr, page_off, index, search_hash,
		  range_start, range_end, prev_found);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_get_index_key_hash(node, kaddr, page_off,
					index, index,
					&hash_index, &hash);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash: "
			  "index %u, err %d\n",
			  index, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hash_index %u, hash %llx\n",
		  hash_index, hash);
#endif /* CONFIG_SSDFS_DEBUG */

	if (hash_index != index) {
		SSDFS_ERR("hash_index %u != index %u\n",
			  hash_index, index);
		return -ERANGE;
	}

	if (search_hash < hash) {
		err = -ENOENT;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find index: "
			  "index %u, search_hash %llx, "
			  "hash %llx\n",
			  hash_index, search_hash,
			  hash);
#endif /* CONFIG_SSDFS_DEBUG */

		if (prev_found < U16_MAX)
			*found_index = prev_found;
		else
			*found_index = hash_index;
	} else if (search_hash == hash) {
		err = 0;
		*found_index = hash_index;
	} else {
		err = -ENODATA;
		*found_index = hash_index;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("prev_found %u, found_index %u\n",
		  prev_found, *found_index);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_check_last_index_pair() - check last pair of indexes in the search
 * @node: node object
 * @kaddr: pointer on starting address in the page
 * @page_off: offset from page's beginning in bytes
 * @lower_index: starting index in the search
 * @upper_index: ending index in the search
 * @search_hash: hash for search
 * @range_start: first index in the index area
 * @range_end: last index in the index area
 * @prev_found: processed index on previous iteration
 * @found_index: value of found index [out]
 *
 * This method tries to find an index for the case when
 * range has only two indexes.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOENT     - requested hash is located in previous range.
 * %-ENODATA    - unable to find the node's index.
 */
static
int ssdfs_check_last_index_pair(struct ssdfs_btree_node *node,
				void *kaddr, u32 page_off,
				u32 lower_index, u32 upper_index,
				u64 search_hash,
				u32 range_start, u32 range_end,
				u32 prev_found, u16 *found_index)
{
	u32 hash_index;
	u64 hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !kaddr || !found_index);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("kaddr %p, page_off %u, "
		  "lower_index %u, upper_index %u, "
		  "search_hash %llx, range_start %u, prev_found %u\n",
		  kaddr, page_off, lower_index, upper_index,
		  search_hash, range_start, prev_found);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_get_index_key_hash(node, kaddr, page_off,
					lower_index, upper_index,
					&hash_index, &hash);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash: "
			  "lower_index %u, upper_index %u, err %d\n",
			  lower_index, upper_index, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hash_index %u, hash %llx\n",
		  hash_index, hash);
#endif /* CONFIG_SSDFS_DEBUG */

	if (hash_index == lower_index) {
		if (search_hash < hash) {
			err = -ENOENT;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find index: "
				  "index %u, search_hash %llx, "
				  "hash %llx\n",
				  hash_index, search_hash,
				  hash);
#endif /* CONFIG_SSDFS_DEBUG */

			if (prev_found < U16_MAX)
				*found_index = prev_found;
			else
				*found_index = hash_index;
		} else if (search_hash == hash) {
			err = 0;
			*found_index = hash_index;
		} else {
			prev_found = hash_index;
			err = ssdfs_check_last_index(node, kaddr, page_off,
						     upper_index, search_hash,
						     range_start, range_end,
						     prev_found, found_index);
			if (err == -ENOENT) {
				err = 0;
				*found_index = prev_found;
			}
		}
	} else if (hash_index == upper_index) {
		if (search_hash > hash) {
			err = -ENODATA;
			*found_index = upper_index;
		} else if (search_hash == hash) {
			err = 0;
			*found_index = upper_index;
		} else {
			prev_found = hash_index;
			err = ssdfs_check_last_index(node, kaddr, page_off,
						     lower_index, search_hash,
						     range_start, range_end,
						     prev_found, found_index);
			if (err == -ENOENT) {
				err = 0;
				*found_index = prev_found;
			}
		}
	} else {
		SSDFS_ERR("invalid index: hash_index %u, "
			  "lower_index %u, upper_index %u\n",
			  hash_index, lower_index, upper_index);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("prev_found %u, found_index %u, err %d\n",
		  prev_found, *found_index, err);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_find_index_in_memory_page() - find index record in memory page
 * @node: node object
 * @area: description of index area
 * @start_offset: offset in the index area of the node
 * search_hash: hash for search in the index area
 * @found_index: identification number of found index [out]
 * @processed_bytes: amount of processed bytes into index area [out]
 *
 * This method tries to find the index record for the requested hash.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find the node's index.
 * %-ENOENT     - index record is outside of this memory page.
 */
static
int ssdfs_find_index_in_memory_page(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_index_area *area,
				    u32 start_offset,
				    u64 search_hash,
				    u16 *found_index,
				    u32 *processed_bytes)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	void *kaddr;
	u32 search_bytes;
	u32 index_count;
	u32 cur_index, upper_index, lower_index;
	u32 range_start, range_end;
	u32 prev_found;
	u64 hash;
	u32 page_offset;
	u32 processed_indexes = 0;
	int err = -ENODATA;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !processed_bytes || !found_index);
	BUG_ON(!node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, node_type %#x, "
		  "start_offset %u, search_hash %llx\n",
		  node->node_id, atomic_read(&node->type),
		  start_offset, search_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;
	*found_index = U16_MAX;
	*processed_bytes = 0;

	if (start_offset >= (area->offset + area->area_size)) {
		SSDFS_ERR("invalid start_offset: "
			  "offset %u, area_start %u, area_size %u\n",
			  start_offset, area->offset, area->area_size);
		return -ERANGE;
	}

	if (area->index_size != sizeof(struct ssdfs_btree_index_key)) {
		SSDFS_ERR("invalid index size %u\n",
			  area->index_size);
		return -ERANGE;
	}

	err = SSDFS_OFF2FOLIO(fsi->pagesize, start_offset, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset to folio: "
			  "start_offset %u, err %d\n",
			  start_offset, err);
		return err;
	}

	if ((folio.desc.offset_inside_page + area->index_size) > PAGE_SIZE) {
		SSDFS_ERR("invalid offset into the page: "
			  "offset %u, index_size %u\n",
			  folio.desc.offset_inside_page,
			  area->index_size);
		return -ERANGE;
	}

	if (folio.desc.offset_inside_page % area->index_size) {
		SSDFS_ERR("offset is not aligned: "
			  "offset_inside_page %u, index_size %u\n",
			  folio.desc.offset_inside_page,
			  area->index_size);
		return -ERANGE;
	}

	if (folio.desc.folio_index >= node->content.count) {
		SSDFS_ERR("invalid folio index: "
			  "folio_index %u, blocks_count %u\n",
			  folio.desc.folio_index,
			  node->content.count);
		return -ERANGE;
	}

	search_bytes = PAGE_SIZE - folio.desc.offset_inside_page;
	search_bytes = min_t(u32, search_bytes,
			(area->offset + area->area_size) - start_offset);

	index_count = search_bytes / area->index_size;
	if (index_count == 0) {
		SSDFS_ERR("invalid index_count %u\n",
			  index_count);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search_bytes %u, offset %u, area_size %u\n",
		  search_bytes, area->offset, area->area_size);
#endif /* CONFIG_SSDFS_DEBUG */

	processed_indexes = (start_offset - area->offset);
	processed_indexes /= area->index_size;

	if (processed_indexes >= area->index_capacity) {
		SSDFS_ERR("processed_indexes %u >= area->index_capacity %u\n",
			  processed_indexes,
			  area->index_capacity);
		return -ERANGE;
	} else if (processed_indexes >= area->index_count) {
		err = -ENOENT;
		*processed_bytes = search_bytes;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find an index: "
			  "processed_indexes %u, area->index_count %u\n",
			  processed_indexes,
			  area->index_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area->index_count %u, area->index_capacity %u\n",
		  area->index_count, area->index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	index_count = min_t(u32, index_count,
				area->index_count - processed_indexes);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area->index_count %u, processed_indexes %u, "
		  "index_count %u\n",
		  area->index_count, processed_indexes, index_count);
#endif /* CONFIG_SSDFS_DEBUG */

	cur_index = 0;
	range_start = lower_index = 0;
	range_end = upper_index = index_count - 1;

	err = ssdfs_find_node_content_folio(&node->content, &folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find folio: err %d\n", err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_size(folio.ptr) == fsi->pagesize) {
		page_offset = folio.desc.page_offset;
	} else {
		page_offset = SSDFS_PAGE_OFFSET_IN_FOLIO(folio_size(folio.ptr),
							 folio.desc.offset);
	}

	kaddr = kmap_local_folio(folio.ptr, page_offset);

	prev_found = *found_index;
	while (lower_index <= upper_index) {
		int diff = upper_index - lower_index;
		u32 hash_index;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("lower_index %u, upper_index %u, diff %d\n",
			  lower_index, upper_index, diff);
#endif /* CONFIG_SSDFS_DEBUG */

		if (diff < 0) {
			err = -ERANGE;
			SSDFS_ERR("invalid diff: "
				  "diff %d, lower_index %u, "
				  "upper_index %u\n",
				  diff, lower_index, upper_index);
			goto finish_search;
		}

		if (diff == 0) {
			err = ssdfs_check_last_index(node, kaddr,
						folio.desc.offset_inside_page,
						lower_index, search_hash,
						range_start, range_end,
						prev_found, found_index);
			if (err == -ENOENT) {
				if (prev_found < U16_MAX)
					*found_index = prev_found;
			} else if (err == -ENODATA) {
				/*
				 * Nothing was found
				 */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check the last index: "
					  "index %u, err %d\n",
					  lower_index, err);
			}

			*processed_bytes = search_bytes;
			goto finish_search;
		} else if (diff == 1) {
			err = ssdfs_check_last_index_pair(node, kaddr,
						folio.desc.offset_inside_page,
						lower_index, upper_index,
						search_hash,
						range_start, range_end,
						prev_found, found_index);
			if (err == -ENOENT) {
				if (prev_found < U16_MAX)
					*found_index = prev_found;
			} else if (err == -ENODATA) {
				/*
				 * Nothing was found
				 */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check the last index pair: "
					  "lower_index %u, upper_index %u, "
					  "err %d\n",
					  lower_index, upper_index, err);
			}

			*processed_bytes = search_bytes;
			goto finish_search;
		} else
			cur_index = lower_index + (diff / 2);

		err = ssdfs_get_index_key_hash(node, kaddr,
						folio.desc.offset_inside_page,
						cur_index, upper_index,
						&hash_index, &hash);
		if (unlikely(err)) {
			SSDFS_WARN("fail to get hash: "
				  "cur_index %u, upper_index %u, err %d\n",
				  cur_index, upper_index, err);
			goto finish_search;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("search_hash %llx, hash %llx, "
			  "hash_index %u, range_start %u, range_end %u\n",
			  search_hash, hash, hash_index,
			  range_start, range_end);
#endif /* CONFIG_SSDFS_DEBUG */

		if (search_hash < hash) {
			if (hash_index == range_start) {
				err = -ENOENT;
				*found_index = hash_index;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to find index: "
					  "index %u, search_hash %llx, "
					  "hash %llx\n",
					  hash_index, search_hash,
					  hash);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_search;
			} else {
				prev_found = lower_index;
				upper_index = cur_index;
			}
		} else if (search_hash == hash) {
			err = -EEXIST;
			*found_index = cur_index;
			*processed_bytes = search_bytes;
			goto finish_search;
		} else {
			if (hash_index == range_end) {
				err = -ENODATA;
				*found_index = hash_index;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to find index: "
					  "index %u, search_hash %llx, "
					  "hash %llx\n",
					  hash_index, search_hash,
					  hash);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_search;
			} else {
				prev_found = lower_index;
				lower_index = cur_index;
			}
		}
	};

finish_search:
	kunmap_local(kaddr);

	if (!err || err == -EEXIST) {
		*found_index += processed_indexes;
		if (*found_index >= area->index_capacity) {
			SSDFS_ERR("found_index %u >= capacity %u\n",
				  *found_index,
				  area->index_capacity);
			return -ERANGE;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("prev_found %u, found_index %u\n",
		  prev_found, *found_index);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_btree_common_node_find_index() - find index record
 * @node: node object
 * @area: description of index area
 * search_hash: hash for search in the index area
 * @found_index: identification number of found index [out]
 *
 * This method tries to find the index record for the requested hash.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find the node's index.
 * %-EEXIST     - search hash has been found.
 */
static
int ssdfs_btree_common_node_find_index(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_index_area *area,
				    u64 search_hash,
				    u16 *found_index)
{
	u32 start_offset, end_offset;
	u32 processed_bytes = 0;
	u16 prev_found = U16_MAX;
	int err = -ENODATA;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !found_index);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, node_type %#x, search_hash %llx\n",
		  node->node_id, atomic_read(&node->type),
		  search_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	*found_index = U16_MAX;

	if (atomic_read(&area->state) != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  atomic_read(&area->state));
		return -ERANGE;
	}

	if (area->index_count == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't any index\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	if (area->index_count > area->index_capacity) {
		SSDFS_ERR("invalid area: "
			  "index_count %u, index_capacity %u\n",
			  area->index_count,
			  area->index_capacity);
		return -ERANGE;
	}

	if ((area->offset + area->area_size) > node->node_size) {
		SSDFS_ERR("invalid area: "
			  "offset %u, area_size %u, node_size %u\n",
			  area->offset,
			  area->area_size,
			  node->node_size);
		return -ERANGE;
	}

	if (area->index_size != sizeof(struct ssdfs_btree_index_key)) {
		SSDFS_ERR("invalid index size %u\n",
			  area->index_size);
		return -ERANGE;
	}

	start_offset = area->offset;
	end_offset = area->offset + area->area_size;

	while (start_offset < end_offset) {
		prev_found = *found_index;
		err = ssdfs_find_index_in_memory_page(node, area,
						      start_offset,
						      search_hash,
						      found_index,
						      &processed_bytes);
		if (err == -ENODATA) {
			err = 0;

			if (*found_index >= U16_MAX) {
				/*
				 * continue to search
				 */
			} else if ((*found_index + 1) >= area->index_count) {
				/*
				 * index has been found
				 */
				break;
			}
		} else if (err == -ENOENT) {
			err = 0;

			if (prev_found != U16_MAX) {
				err = 0;
				*found_index = prev_found;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("node_id %u, search_hash %llx, "
					  "found_index %u\n",
					  node->node_id, search_hash,
					  *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
			}
			break;
		} else if (err == -EEXIST) {
			/*
			 * index has been found
			 */
			break;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find index: err %d\n",
				  err);
			break;
		} else
			break;

		start_offset += processed_bytes;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("prev_found %u, found_index %u, err %d\n",
		  prev_found, *found_index, err);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * __ssdfs_btree_root_node_extract_index() - extract index from root node
 * @node: node object
 * @found_index: identification number of found index
 * @search: btree search object [out]
 *
 * This method tries to extract index record from the index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int __ssdfs_btree_root_node_extract_index(struct ssdfs_btree_node *node,
					  u16 found_index,
					  struct ssdfs_btree_index_key *ptr)
{
	size_t index_size = sizeof(struct ssdfs_btree_index);
	__le32 node_id;
	int node_height;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !ptr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->tree->lock));

	SSDFS_DBG("node_id %u, node_type %#x, found_index %u\n",
		  node->node_id, atomic_read(&node->type),
		  found_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (found_index >= SSDFS_BTREE_ROOT_NODE_INDEX_COUNT) {
		SSDFS_ERR("invalid found_index %u\n",
			  found_index);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index 0: node_id %u; index 1: node_id %u\n",
		  le32_to_cpu(node->raw.root_node.header.node_ids[0]),
		  le32_to_cpu(node->raw.root_node.header.node_ids[1]));
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	node_id = node->raw.root_node.header.node_ids[found_index];
	ptr->node_id = node_id;
	ssdfs_memcpy(&ptr->index, 0, index_size,
		     &node->raw.root_node.indexes[found_index], 0, index_size,
		     index_size);
	up_read(&node->header_lock);

	node_height = atomic_read(&node->height);
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(node_height < 0);
#endif /* CONFIG_SSDFS_DEBUG */
	ptr->height = node_height - 1;

	switch (node_height) {
	case SSDFS_BTREE_LEAF_NODE_HEIGHT:
	case SSDFS_BTREE_PARENT2LEAF_HEIGHT:
		ptr->node_type = SSDFS_BTREE_LEAF_NODE;
		break;

	case SSDFS_BTREE_PARENT2HYBRID_HEIGHT:
		ptr->node_type = SSDFS_BTREE_HYBRID_NODE;
		break;

	default:
		ptr->node_type = SSDFS_BTREE_INDEX_NODE;
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_height %u, node_type %#x\n",
		  node_height, ptr->node_type);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr->flags = cpu_to_le16(SSDFS_BTREE_INDEX_HAS_VALID_EXTENT);

	return 0;
}

/*
 * ssdfs_btree_root_node_extract_index() - extract index from root node
 * @node: node object
 * @found_index: identification number of found index
 * @search: btree search object [out]
 *
 * This method tries to extract index record from the index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_btree_root_node_extract_index(struct ssdfs_btree_node *node,
					u16 found_index,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_index_key *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->tree->lock));

	SSDFS_DBG("node_id %u, node_type %#x, found_index %u\n",
		  node->node_id, atomic_read(&node->type),
		  found_index);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = &search->node.found_index;
	return __ssdfs_btree_root_node_extract_index(node, found_index, ptr);
}

/*
 * ssdfs_btree_node_get_index() - extract index from node
 * @fsi: pointer on shared file system object
 * @content: node's content
 * @area_offset: area offset from the node's beginning
 * @area_size: size of the area
 * @node_size: node size in bytes
 * @position: position of index record in the node
 * @ptr: pointer on index buffer [out]
 *
 * This method tries to extract index record from the index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_node_get_index(struct ssdfs_fs_info *fsi,
				struct ssdfs_btree_node_content *content,
				u32 area_offset, u32 area_size,
				u32 node_size, u16 position,
				struct ssdfs_btree_index_key *ptr)
{
	struct ssdfs_smart_folio folio;
	size_t index_key_size = sizeof(struct ssdfs_btree_index_key);
	u32 offset_inside_folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !content || !ptr);

	SSDFS_DBG("area_offset %u, area_size %u, "
		  "node_size %u, position %u\n",
		  area_offset, area_size,
		  node_size, position);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_define_memory_folio(fsi, area_offset, area_size,
					  node_size, index_key_size, position,
					  &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define memory folio: "
			  "position %u, err %d\n",
			  position, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_find_node_content_folio(content, &folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find folio: err %d\n", err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_size(folio.ptr) == fsi->pagesize) {
		err = ssdfs_memcpy_from_folio(ptr, 0, index_key_size,
					      &folio, index_key_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n",
				  err);
			return err;
		}
	} else {
		offset_inside_folio = folio.desc.offset % folio_size(folio.ptr);

		err = __ssdfs_memcpy_from_folio(ptr,
						0, index_key_size,
						folio.ptr,
						offset_inside_folio,
						folio_size(folio.ptr),
						index_key_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n",
				  err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, node_type %#x, hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(ptr->node_id),
		  ptr->node_type,
		  le64_to_cpu(ptr->index.hash),
		  le64_to_cpu(ptr->index.extent.seg_id),
		  le32_to_cpu(ptr->index.extent.logical_blk),
		  le32_to_cpu(ptr->index.extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * __ssdfs_btree_common_node_extract_index() - extract index from node
 * @node: node object
 * @area: description of index area
 * @found_index: identification number of found index
 * @search: btree search object [out]
 *
 * This method tries to extract index record from the index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int __ssdfs_btree_common_node_extract_index(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_index_area *area,
				    u16 found_index,
				    struct ssdfs_btree_index_key *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	size_t index_key_size = sizeof(struct ssdfs_btree_index_key);
	u32 offset_inside_folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !ptr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->tree->lock));

	SSDFS_DBG("node_id %u, node_type %#x, found_index %u\n",
		  node->node_id, atomic_read(&node->type),
		  found_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (found_index == area->index_count) {
		SSDFS_ERR("found_index %u == index_count %u\n",
			  found_index, area->index_count);
		return -ERANGE;
	}

	err = ssdfs_define_memory_folio(node, area, found_index,
					&folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define memory page: "
			  "node_id %u, found_index %u, err %d\n",
			  node->node_id, found_index, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_find_node_content_folio(&node->content, &folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find folio: err %d\n", err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_size(folio.ptr) == fsi->pagesize) {
		err = ssdfs_memcpy_from_folio(ptr, 0, index_key_size,
					      &folio, index_key_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n",
				  err);
			return err;
		}
	} else {
		offset_inside_folio = folio.desc.offset % folio_size(folio.ptr);

		err = __ssdfs_memcpy_from_folio(ptr,
						0, index_key_size,
						folio.ptr,
						offset_inside_folio,
						folio_size(folio.ptr),
						index_key_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n",
				  err);
			return err;
		}
	}

	if (ptr->node_type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    ptr->node_type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_WARN("node_id %u, node_type %#x, found_index %u\n",
			  node->node_id, atomic_read(&node->type),
			  found_index);
		SSDFS_ERR("folio_index %u, page_in_folio %u, page_off %u\n",
			  folio.desc.folio_index, folio.desc.page_in_folio,
			  folio.desc.offset_inside_page);
		SSDFS_ERR("FOUND_INDEX: node_id %u, node_type %#x, "
			  "height %u, flags %#x, hash %llx, "
			  "seg_id %llu, logical_blk %u, len %u\n",
			  le32_to_cpu(ptr->node_id),
			  ptr->node_type, ptr->height, ptr->flags,
			  le64_to_cpu(ptr->index.hash),
			  le64_to_cpu(ptr->index.extent.seg_id),
			  le32_to_cpu(ptr->index.extent.logical_blk),
			  le32_to_cpu(ptr->index.extent.len));
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("FOUND_INDEX: node_id %u, node_type %#x, "
		  "height %u, flags %#x, hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(ptr->node_id),
		  ptr->node_type, ptr->height, ptr->flags,
		  le64_to_cpu(ptr->index.hash),
		  le64_to_cpu(ptr->index.extent.seg_id),
		  le32_to_cpu(ptr->index.extent.logical_blk),
		  le32_to_cpu(ptr->index.extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_common_node_extract_index() - extract index from node
 * @node: node object
 * @area: description of index area
 * @found_index: identification number of found index
 * @search: btree search object [out]
 *
 * This method tries to extract index record from the index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_btree_common_node_extract_index(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_index_area *area,
				    u16 found_index,
				    struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_index_key *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->tree->lock));

	SSDFS_DBG("node_id %u, node_type %#x, found_index %u\n",
		  node->node_id, atomic_read(&node->type),
		  found_index);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = &search->node.found_index;
	return __ssdfs_btree_common_node_extract_index(node, area,
							found_index, ptr);
}

/*
 * ssdfs_find_index_by_hash() - find index record in the node by hash
 * @node: node object
 * @area: description of index area
 * @hash: hash value for the search
 * @found_index: found position of index record in the node [out]
 *
 * This method tries to find node's index for
 * the requested hash value.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find the node's index.
 * %-EEXIST     - search hash has been found.
 */
int ssdfs_find_index_by_hash(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_node_index_area *area,
			     u64 hash,
			     u16 *found_index)
{
	int node_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !found_index);

	SSDFS_DBG("node_id %u, hash %llx, "
		  "area->start_hash %llx, area->end_hash %llx\n",
		  node->node_id, hash,
		  area->start_hash, area->end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	*found_index = U16_MAX;

	node_type = atomic_read(&node->type);
	if (node_type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    node_type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_ERR("invalid node type %#x\n",
			  node_type);
		return -ERANGE;
	}

	if (atomic_read(&area->state) != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		SSDFS_ERR("index area hasn't been created: "
			  "node_id %u, node_type %#x\n",
			  node->node_id,
			  atomic_read(&node->type));
		return -ERANGE;
	}

	if (area->index_count == 0) {
		*found_index = 0;
		SSDFS_DBG("index area is empty\n");
		return -ENODATA;
	}

	if (area->index_count > area->index_capacity) {
		SSDFS_ERR("index_count %u > index_capacity %u\n",
			  area->index_count,
			  area->index_capacity);
		return -ERANGE;
	}

	if (area->start_hash == U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_hash is invalid: node_id %u\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (hash == U64_MAX) {
		SSDFS_ERR("invalid requested hash\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (hash < area->start_hash) {
		err = 0;
		*found_index = 0;
		goto finish_hash_search;
	}

	if (area->end_hash == U64_MAX)
		*found_index = 0;
	else if (hash >= area->end_hash) {
		*found_index = area->index_count - 1;
	} else {
		if (node_type == SSDFS_BTREE_ROOT_NODE) {
			err = ssdfs_btree_root_node_find_index(node, hash,
								found_index);
			if (err == -ENODATA) {
				SSDFS_DBG("unable to find index\n");
				goto finish_hash_search;
			} else if (err == -EEXIST) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("index exists already: "
					  "hash %llx, index %u\n",
					  hash, *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_hash_search;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to find index in root node: "
					  "err %d\n",
					  err);
				goto finish_hash_search;
			} else if (*found_index == U16_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid index was found\n");
				goto finish_hash_search;
			}
		} else {
			err = ssdfs_btree_common_node_find_index(node, area,
								 hash,
								 found_index);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to find index: "
					  "node_id %u\n",
					  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_hash_search;
			} else if (err == -EEXIST) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("index exists already: "
					  "hash %llx, index %u\n",
					  hash, *found_index);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_hash_search;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to find index in the node: "
					  "node_id %u, err %d\n",
					  node->node_id, err);
				goto finish_hash_search;
			} else if (*found_index == U16_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid index was found\n");
				goto finish_hash_search;
			}
		}
	}

finish_hash_search:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hash %llx, found_index %u, err %d\n",
		  hash, *found_index, err);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_btree_node_find_index_position() - find index's position
 * @node: node object
 * @hash: hash value
 * @found_position: pointer on returned value [out]
 *
 * This method tries to find node's index for
 * the requested hash value.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find the node's index.
 * %-ENOENT     - node hasn't the index area.
 * %-EACCES     - node is under initialization yet.
 */
int ssdfs_btree_node_find_index_position(struct ssdfs_btree_node *node,
					 u64 hash,
					 u16 *found_position)
{
	struct ssdfs_btree_node_index_area area;
	size_t desc_size = sizeof(struct ssdfs_btree_node_index_area);
	int node_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !found_position);
	BUG_ON(!node->tree);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));

	SSDFS_DBG("node_id %u, node_type %#x, hash %llx\n",
		  node->node_id,
		  atomic_read(&node->type),
		  hash);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't index area\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

	*found_position = U16_MAX;

	down_read(&node->full_lock);

	node_type = atomic_read(&node->type);
	if (node_type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    node_type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid node type %#x\n",
			  node_type);
		goto finish_index_search;
	}

	down_read(&node->header_lock);
	ssdfs_memcpy(&area, 0, desc_size,
		     &node->index_area, 0, desc_size,
		     desc_size);
	err = ssdfs_find_index_by_hash(node, &area, hash,
					found_position);
	up_read(&node->header_lock);

	if (err == -EEXIST) {
		/* hash == found hash */
		err = 0;
	} else if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find an index: "
			  "node_id %u, hash %llx\n",
			  node->node_id, hash);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_index_search;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find an index: "
			  "node_id %u, hash %llx, err %d\n",
			  node->node_id, hash, err);
		goto finish_index_search;
	}

finish_index_search:
	up_read(&node->full_lock);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(*found_position == U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_btree_node_re_init_content() - re-init node's content
 * @search: btree search object
 *
 * This method tries to re-init node's content.
 */
static inline
int ssdfs_btree_node_re_init_content(struct ssdfs_btree_node *node)
{
	struct ssdfs_segment_info *si = NULL;
	struct ssdfs_btree_index_key node_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&node->descriptor_lock);
	ssdfs_memcpy(&node_index,
		     0, sizeof(struct ssdfs_btree_index_key),
		     &node->node_index,
		     0, sizeof(struct ssdfs_btree_index_key),
		     sizeof(struct ssdfs_btree_index_key));
	spin_unlock(&node->descriptor_lock);

	err = ssdfs_btree_node_allocate_content_space(node, node->node_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate content space: "
			  "node_size %u, err %d\n",
			  node->node_size, err);
		return err;
	}

	down_write(&node->full_lock);

	err = __ssdfs_btree_node_prepare_content(node->tree->fsi,
						 &node_index,
						 node->node_size,
						 node->tree->owner_ino,
						 &si,
						 &node->content);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to prepare node's content: "
			  "node_id %u, node_type %#x, "
			  "owner_ino %llu, err %d\n",
			  le32_to_cpu(node_index.node_id),
			  node_index.node_type,
			  node->tree->owner_ino,
			  err);
	} else {
		atomic_set(&node->state, SSDFS_BTREE_NODE_INITIALIZED);

		spin_lock(&node->content.protection.cno_lock);
		node->content.protection.create_cno =
				ssdfs_current_cno(node->tree->fsi->sb);
		node->content.protection.last_request_cno =
					node->content.protection.create_cno;
		node->content.protection.protected_range =
					SSDFS_DEFAULT_PROTECTION_RANGE;
		node->content.protection.future_request_cno =
					node->content.protection.create_cno +
					SSDFS_DEFAULT_PROTECTION_RANGE;
		spin_unlock(&node->content.protection.cno_lock);
	}

	if (si)
		ssdfs_segment_put_object(si);

	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_btree_node_find_index() - find node's index
 * @search: btree search object
 *
 * This method tries to find node's index for
 * the requested hash value.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - unable to find the node's index.
 * %-ENOENT     - node hasn't the index area.
 * %-EACCES     - node is under initialization yet.
 */
int ssdfs_btree_node_find_index(struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node;
	struct ssdfs_btree_node_index_area area;
	size_t desc_size = sizeof(struct ssdfs_btree_node_index_area);
	int tree_height;
	int node_type;
	u16 found_index = U16_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->node.parent) {
		node = search->node.parent;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!node->tree);
#endif /* CONFIG_SSDFS_DEBUG */

		tree_height = atomic_read(&node->tree->height);
		if (tree_height <= (SSDFS_BTREE_LEAF_NODE_HEIGHT + 1)) {
			/* tree has only root node */
			return -ENODATA;
		}
	}

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_NONE_CONTENT:
		err = ssdfs_btree_node_re_init_content(node);
		if (err)
			return err;
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't index area\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

		node = search->node.parent;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try parent node %u\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	down_read(&node->full_lock);

	node_type = atomic_read(&node->type);
	if (node_type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    node_type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid node type %#x\n",
			  node_type);
		goto finish_index_search;
	}

	down_read(&node->header_lock);
	ssdfs_memcpy(&area, 0, desc_size,
		     &node->index_area, 0, desc_size,
		     desc_size);
	err = ssdfs_find_index_by_hash(node, &area,
					search->request.start.hash,
					&found_index);
	up_read(&node->header_lock);

	if (err == -EEXIST) {
		/* hash == found hash */
		err = 0;
	} else if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to find an index: "
			  "node_id %u, hash %llx\n",
			  node->node_id, search->request.start.hash);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_index_search;
	} else if (unlikely(err)) {
		SSDFS_WARN("fail to find an index: "
			  "node_id %u, hash %llx, err %d\n",
			  node->node_id, search->request.start.hash,
			  err);
		goto finish_index_search;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(found_index == U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (node_type == SSDFS_BTREE_ROOT_NODE) {
		ssdfs_btree_node_start_request_cno(node);
		err = ssdfs_btree_root_node_extract_index(node,
							  found_index,
							  search);
		ssdfs_btree_node_finish_request_cno(node);
	} else {
		ssdfs_btree_node_start_request_cno(node);
		err = ssdfs_btree_common_node_extract_index(node, &area,
							    found_index,
							    search);
		ssdfs_btree_node_finish_request_cno(node);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to extract index: "
			  "node_id %u, node_type %#x, "
			  "found_index %u, err %d\n",
			  node->node_id, node_type,
			  found_index, err);
		goto finish_index_search;
	}

finish_index_search:
	up_read(&node->full_lock);

	if (unlikely(err))
		ssdfs_debug_show_btree_node_indexes(node->tree, node);

	return err;
}

/*
 * can_add_new_index() - check that index area has free space
 * @node: node object
 */
bool can_add_new_index(struct ssdfs_btree_node *node)
{
	bool can_add = false;
	u16 count, capacity;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	count = node->index_area.index_count;
	capacity = node->index_area.index_capacity;
	if (count > capacity)
		err = -ERANGE;
	else
		can_add = count < capacity;
	up_read(&node->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("count %u, capacity %u, can_add %#x, err %d\n",
		  count, capacity, can_add, err);
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_WARN("count %u > capacity %u\n",
			   count, capacity);
		return false;
	}

	return can_add;
}

/*
 * ssdfs_btree_root_node_add_index() - add index record into the root node
 * @node: node object
 * @position: position in the node for storing the new index record
 * @ptr: pointer on storing index record [in]
 *
 * This method tries to add index record into the root node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - root node hasn't free space.
 * %-EEXIST     - root node contains such record already.
 */
static
int ssdfs_btree_root_node_add_index(struct ssdfs_btree_node *node,
				    u16 position,
				    struct ssdfs_btree_index_key *ptr)
{
	struct ssdfs_btree_index *found = NULL;
	size_t index_size = sizeof(struct ssdfs_btree_index);
	u64 hash1, hash2;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !ptr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, position %u\n",
		  node->node_id, position);
#endif /* CONFIG_SSDFS_DEBUG */

	if (position >= SSDFS_BTREE_ROOT_NODE_INDEX_COUNT) {
		SSDFS_ERR("invalid position %u\n",
			  position);
		return -ERANGE;
	}

	if (node->index_area.index_count > node->index_area.index_capacity) {
		SSDFS_ERR("index_count %u > index_capacity %u\n",
			  node->index_area.index_count,
			  node->index_area.index_capacity);
		return -ERANGE;
	}

	if (node->index_area.index_count == node->index_area.index_capacity) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to add the index: "
			  "index_count %u, index_capacity %u\n",
			  node->index_area.index_count,
			  node->index_area.index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOSPC;
	}

	found = &node->raw.root_node.indexes[position];

	hash1 = le64_to_cpu(found->hash);
	hash2 = le64_to_cpu(ptr->index.hash);

	if (hash1 == hash2) {
		ssdfs_memcpy(&node->raw.root_node.indexes[position],
			     0, index_size,
			     &ptr->index, 0, index_size,
			     index_size);
		ssdfs_memcpy(&node->raw.root_node.header.node_ids[position],
			     0, sizeof(__le32),
			     &ptr->node_id, 0, sizeof(__le32),
		     sizeof(__le32));
	} else if (hash1 < hash2) {
		position++;

		if (position >= SSDFS_BTREE_ROOT_NODE_INDEX_COUNT) {
			SSDFS_ERR("invalid position %u\n",
				  position);
			return -ERANGE;
		}

		ssdfs_memcpy(&node->raw.root_node.indexes[position],
			     0, index_size,
			     &ptr->index, 0, index_size,
			     index_size);
		ssdfs_memcpy(&node->raw.root_node.header.node_ids[position],
			     0, sizeof(__le32),
			     &ptr->node_id, 0, sizeof(__le32),
			     sizeof(__le32));
		node->index_area.index_count++;
	} else {
		void *indexes = node->raw.root_node.indexes;
		u32 dst_off = (u32)(position + 1) * index_size;
		u32 src_off = (u32)position * index_size;
		u32 array_size = index_size * SSDFS_BTREE_ROOT_NODE_INDEX_COUNT;
		u32 move_size = (u32)(node->index_area.index_count - position) *
					index_size;
		__le32 *node_ids;

		if ((position + 1) >= SSDFS_BTREE_ROOT_NODE_INDEX_COUNT) {
			SSDFS_ERR("invalid position %u\n",
				  position);
			return -ERANGE;
		}

		err = ssdfs_memmove(indexes, dst_off, array_size,
				    indexes, src_off, array_size,
				    move_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: err %d\n", err);
			return err;
		}

		node_ids = node->raw.root_node.header.node_ids;
		err = ssdfs_memmove(&node_ids[position + 1], 0, sizeof(__le32),
				    &node_ids[position], 0, sizeof(__le32),
				    sizeof(__le32));
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: err %d\n", err);
			return err;
		}

		ssdfs_memcpy(&node->raw.root_node.indexes[position],
			     0, index_size,
			     &ptr->index, 0, index_size,
			     index_size);
		ssdfs_memcpy(&node->raw.root_node.header.node_ids[position],
			     0, sizeof(__le32),
			     &ptr->node_id, 0, sizeof(__le32),
			     sizeof(__le32));
		node->index_area.index_count++;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, node_type %#x, hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(ptr->node_id),
		  ptr->node_type,
		  le64_to_cpu(ptr->index.hash),
		  le64_to_cpu(ptr->index.extent.seg_id),
		  le32_to_cpu(ptr->index.extent.logical_blk),
		  le32_to_cpu(ptr->index.extent.len));
	BUG_ON(node->index_area.index_count > SSDFS_BTREE_ROOT_NODE_INDEX_COUNT);
#endif /* CONFIG_SSDFS_DEBUG */

	found = &node->raw.root_node.indexes[0];
	node->index_area.start_hash = le64_to_cpu(found->hash);

	found = &node->raw.root_node.indexes[node->index_area.index_count - 1];
	node->index_area.end_hash = le64_to_cpu(found->hash);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index 0: node_id %u; index 1: node_id %u\n",
		  le32_to_cpu(node->raw.root_node.header.node_ids[0]),
		  le32_to_cpu(node->raw.root_node.header.node_ids[1]));
	SSDFS_DBG("start_hash %#llx, end_hash %#llx\n",
		  node->index_area.start_hash,
		  node->index_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * __ssdfs_btree_common_node_add_index() - add index record into the node
 * @node: node object
 * @position: position in the node for storing the new index record
 * @ptr: pointer on storing index record [in]
 *
 * This method tries to add index record into the common node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_btree_common_node_add_index(struct ssdfs_btree_node *node,
					u16 position,
					struct ssdfs_btree_index_key *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	size_t index_key_size = sizeof(struct ssdfs_btree_index_key);
	u32 offset_inside_folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !ptr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, position %u\n",
		  node->node_id, position);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (position != node->index_area.index_count) {
		SSDFS_ERR("cannot add index: "
			  "position %u, index_count %u\n",
			  position,
			  node->index_area.index_count);
		return -ERANGE;
	}

	err = ssdfs_define_memory_folio(node, &node->index_area,
					position, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define memory page: "
			  "node_id %u, position %u, err %d\n",
			  node->node_id, position, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_find_node_content_folio(&node->content, &folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find folio: err %d\n", err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_size(folio.ptr) == fsi->pagesize) {
		ssdfs_folio_lock(folio.ptr);
		err = ssdfs_memcpy_to_folio(&folio,
					    ptr, 0, index_key_size,
					    index_key_size);
		ssdfs_folio_unlock(folio.ptr);
	} else {
		offset_inside_folio = folio.desc.offset % folio_size(folio.ptr);

		ssdfs_folio_lock(folio.ptr);
		err = __ssdfs_memcpy_to_folio(folio.ptr,
					      offset_inside_folio,
					      folio_size(folio.ptr),
					      ptr,
					      0, index_key_size,
					      index_key_size);
		ssdfs_folio_unlock(folio.ptr);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio_index %u, page_in_folio %u, page_off %u\n",
		  folio.desc.folio_index, folio.desc.page_in_folio,
		  folio.desc.offset_inside_page);
	SSDFS_DBG("node_id %u, node_type %#x, hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(ptr->node_id),
		  ptr->node_type,
		  le64_to_cpu(ptr->index.hash),
		  le64_to_cpu(ptr->index.extent.seg_id),
		  le32_to_cpu(ptr->index.extent.logical_blk),
		  le32_to_cpu(ptr->index.extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_root_node_change_index() - change index record into root node
 * @node: node object
 * @found_index: position in the node of the changing index record
 * @new_index: pointer on new index record state [in]
 *
 * This method tries to change the index record into the root node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_btree_root_node_change_index(struct ssdfs_btree_node *node,
				       u16 found_index,
				       struct ssdfs_btree_index_key *new_index)
{
	size_t index_size = sizeof(struct ssdfs_btree_index);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !new_index);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, node_type %#x, found_index %u\n",
		  node->node_id, atomic_read(&node->type),
		  found_index);
	SSDFS_DBG("node_id %u, node_type %#x, hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(new_index->node_id),
		  new_index->node_type,
		  le64_to_cpu(new_index->index.hash),
		  le64_to_cpu(new_index->index.extent.seg_id),
		  le32_to_cpu(new_index->index.extent.logical_blk),
		  le32_to_cpu(new_index->index.extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	if (found_index >= SSDFS_BTREE_ROOT_NODE_INDEX_COUNT) {
		SSDFS_ERR("invalid found_index %u\n",
			  found_index);
		return -ERANGE;
	}

	ssdfs_memcpy(&node->raw.root_node.indexes[found_index],
		     0, index_size,
		     &new_index->index, 0, index_size,
		     index_size);

	switch (found_index) {
	case SSDFS_ROOT_NODE_LEFT_LEAF_NODE:
		node->index_area.start_hash =
			le64_to_cpu(new_index->index.hash);
		break;

	case SSDFS_ROOT_NODE_RIGHT_LEAF_NODE:
		node->index_area.end_hash =
			le64_to_cpu(new_index->index.hash);
		break;

	default:
		BUG();
	}

	ssdfs_memcpy(&node->raw.root_node.header.node_ids[found_index],
		     0, sizeof(__le32),
		     &new_index->node_id, 0, sizeof(__le32),
		     sizeof(__le32));

	return 0;
}

/*
 * ssdfs_btree_common_node_change_index() - change index record into common node
 * @node: node object
 * @found_index: position in the node of the changing index record
 * @new_index: pointer on new index record state [in]
 *
 * This method tries to change the index record into the common node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_common_node_change_index(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_index_area *area,
				    u16 found_index,
				    struct ssdfs_btree_index_key *new_index)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	size_t index_key_size = sizeof(struct ssdfs_btree_index_key);
	u32 offset_inside_folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, node_type %#x, found_index %u\n",
		  node->node_id, atomic_read(&node->type),
		  found_index);
	SSDFS_DBG("node_id %u, node_type %#x, hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(new_index->node_id),
		  new_index->node_type,
		  le64_to_cpu(new_index->index.hash),
		  le64_to_cpu(new_index->index.extent.seg_id),
		  le32_to_cpu(new_index->index.extent.logical_blk),
		  le32_to_cpu(new_index->index.extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (found_index == area->index_count) {
		SSDFS_ERR("found_index %u == index_count %u\n",
			  found_index, area->index_count);
		return -ERANGE;
	}

	err = ssdfs_define_memory_folio(node, area, found_index, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define memory page: "
			  "node_id %u, found_index %u, err %d\n",
			  node->node_id, found_index, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_find_node_content_folio(&node->content, &folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find folio: err %d\n", err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_size(folio.ptr) == fsi->pagesize) {
		err = ssdfs_memcpy_to_folio(&folio,
					    new_index, 0, index_key_size,
					    index_key_size);
	} else {
		offset_inside_folio = folio.desc.offset % folio_size(folio.ptr);

		err = __ssdfs_memcpy_to_folio(folio.ptr,
					      offset_inside_folio,
					      folio_size(folio.ptr),
					      new_index,
					      0, index_key_size,
					      index_key_size);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	if (found_index == 0)
		area->start_hash = le64_to_cpu(new_index->index.hash);
	else if (found_index == (area->index_count - 1))
		area->end_hash = le64_to_cpu(new_index->index.hash);

	return 0;
}

/*
 * ssdfs_btree_common_node_insert_index() - insert index record into the node
 * @node: node object
 * @position: position in the node for storing the new index record
 * @ptr: pointer on storing index record [in]
 *
 * This method tries to insert the index record into the common node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_common_node_insert_index(struct ssdfs_btree_node *node,
					 u16 position,
					 struct ssdfs_btree_index_key *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_index_key buffer[2];
	struct ssdfs_smart_folio folio;
	void *kaddr;
	u16 cur_pos = position;
	u8 index_size;
	bool is_valid_index_in_buffer = false;
	u32 page_offset;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !ptr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, position %u\n",
		  node->node_id, position);
	SSDFS_DBG("node_id %u, node_type %#x, hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(ptr->node_id),
		  ptr->node_type,
		  le64_to_cpu(ptr->index.hash),
		  le64_to_cpu(ptr->index.extent.seg_id),
		  le32_to_cpu(ptr->index.extent.logical_blk),
		  le32_to_cpu(ptr->index.extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (!(position < node->index_area.index_count)) {
		SSDFS_ERR("cannot insert index: "
			  "position %u, index_count %u\n",
			  position,
			  node->index_area.index_count);
		return -ERANGE;
	}

	index_size = node->index_area.index_size;
	if (index_size != sizeof(struct ssdfs_btree_index_key)) {
		SSDFS_ERR("invalid index_size %u\n",
			  index_size);
		return -ERANGE;
	}

	ssdfs_memcpy(&buffer[0], 0, index_size,
		     ptr, 0, index_size,
		     index_size);

	do {
		u32 rest_capacity;
		u32 moving_count;
		u32 moving_bytes;

		if (cur_pos > node->index_area.index_count) {
			SSDFS_ERR("cur_pos %u, index_area.index_count %u\n",
				  cur_pos, node->index_area.index_count);
			return -ERANGE;
		}

		err = ssdfs_define_memory_folio(node, &node->index_area,
						cur_pos, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to define memory page: "
				  "node_id %u, position %u, err %d\n",
				  node->node_id, cur_pos, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		rest_capacity = PAGE_SIZE - folio.desc.offset_inside_page;
		rest_capacity /= index_size;

		if (rest_capacity == 0) {
			SSDFS_WARN("rest_capacity == 0\n");
			return -ERANGE;
		}

		moving_count = node->index_area.index_count - cur_pos;
		moving_count = min_t(u32, moving_count, rest_capacity);

		if (moving_count == rest_capacity) {
			/*
			 * Latest item will be moved into
			 * temporary buffer (exclude from count)
			 */
			moving_bytes = (moving_count - 1) * index_size;
		} else
			moving_bytes = moving_count * index_size;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio_index %u, page_in_folio %u, "
			  "offste_inside_page %u, cur_pos %u, "
			  "moving_count %u, rest_capacity %u\n",
			  folio.desc.folio_index,
			  folio.desc.page_in_folio,
			  folio.desc.offset_inside_page, cur_pos,
			  moving_count, rest_capacity);

		if ((folio.desc.offset_inside_page + index_size) > PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "offset_inside_page %u, index_size %u\n",
				   folio.desc.offset_inside_page,
				   index_size);
			return -ERANGE;
		}

		if ((folio.desc.offset_inside_page +
					moving_bytes + index_size) >
								PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "offset_inside_page %u, moving_bytes %u, "
				   "index_size %u\n",
				   folio.desc.offset_inside_page,
				   moving_bytes,
				   index_size);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_find_node_content_folio(&node->content, &folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find folio: err %d\n", err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio_size(folio.ptr) == fsi->pagesize) {
			page_offset = folio.desc.page_offset;
		} else {
			page_offset =
			    SSDFS_PAGE_OFFSET_IN_FOLIO(folio_size(folio.ptr),
							   folio.desc.offset);
		}

		ssdfs_folio_lock(folio.ptr);
		kaddr = kmap_local_folio(folio.ptr, page_offset);

		if (moving_count == 0) {
			err = ssdfs_memcpy(kaddr,
					   folio.desc.offset_inside_page,
					   PAGE_SIZE,
					   &buffer[0],
					   0, index_size,
					   index_size);
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy: err %d\n", err);
				goto finish_copy;
			}

			is_valid_index_in_buffer = false;
			cur_pos++;
		} else {
			if (moving_count == rest_capacity) {
				err = ssdfs_memcpy(&buffer[1],
						   0, index_size,
						   kaddr,
						   PAGE_SIZE - index_size,
						   PAGE_SIZE,
						   index_size);
				if (unlikely(err)) {
					SSDFS_ERR("fail to copy: err %d\n",
						  err);
					goto finish_copy;
				}

				is_valid_index_in_buffer = true;
			} else
				is_valid_index_in_buffer = false;

			err = ssdfs_memmove(kaddr,
				folio.desc.offset_inside_page + index_size,
				PAGE_SIZE,
				kaddr,
				folio.desc.offset_inside_page,
				PAGE_SIZE,
				moving_bytes);
			if (unlikely(err)) {
				SSDFS_ERR("fail to move: err %d\n",
					  err);
				goto finish_copy;
			}

			err = ssdfs_memcpy(kaddr,
					   folio.desc.offset_inside_page,
					   PAGE_SIZE,
					   &buffer[0],
					   0, index_size,
					   index_size);
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy: err %d\n",
					  err);
				goto finish_copy;
			}

			if (is_valid_index_in_buffer) {
				ssdfs_memcpy(&buffer[0], 0, index_size,
					     &buffer[1], 0, index_size,
					     index_size);
			}

			cur_pos += moving_count;
		}

finish_copy:
		flush_dcache_folio(folio.ptr);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio.ptr);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_pos %u, index_area.index_count %u, "
			  "is_valid_index_in_buffer %#x\n",
			  cur_pos, node->index_area.index_count,
			  is_valid_index_in_buffer);
#endif /* CONFIG_SSDFS_DEBUG */

		if (unlikely(err)) {
			SSDFS_ERR("cur_pos %u, index_area.index_count %u, "
				  "is_valid_index_in_buffer %#x\n",
				  cur_pos, node->index_area.index_count,
				  is_valid_index_in_buffer);
			return err;
		}
	} while (is_valid_index_in_buffer);

	return 0;
}

/*
 * ssdfs_btree_common_node_add_index() - add index record into the node
 * @node: node object
 * @position: position in the node for storing the new index record
 * @ptr: pointer on storing index record [in]
 *
 * This method tries to add the index record into the common node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't free space.
 */
static
int ssdfs_btree_common_node_add_index(struct ssdfs_btree_node *node,
				      u16 position,
				      struct ssdfs_btree_index_key *ptr)
{
	struct ssdfs_btree_index_key tmp_key;
	u64 hash1, hash2;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !ptr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, position %u, index_count %u\n",
		  node->node_id, position,
		  node->index_area.index_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (node->index_area.index_count > node->index_area.index_capacity) {
		SSDFS_ERR("index_count %u > index_capacity %u\n",
			  node->index_area.index_count,
			  node->index_area.index_capacity);
		return -ERANGE;
	}

	if (node->index_area.index_count == node->index_area.index_capacity) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to add the index: "
			  "index_count %u, index_capacity %u\n",
			  node->index_area.index_count,
			  node->index_area.index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOSPC;
	}

	if (position > node->index_area.index_count) {
		SSDFS_ERR("invalid index place: "
			  "position %u, index_count %u\n",
			  position,
			  node->index_area.index_count);
		return -ERANGE;
	}

	if (position == node->index_area.index_count) {
		err = __ssdfs_btree_common_node_add_index(node, position, ptr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add index: "
				  "node_id %u, position %u, err %d\n",
				  node->node_id, position, err);
			return err;
		}

		node->index_area.index_count++;
	} else {
		err = __ssdfs_btree_common_node_extract_index(node,
							      &node->index_area,
							      position,
							      &tmp_key);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the index: err %d\n", err);
			return err;
		}

		hash1 = le64_to_cpu(tmp_key.index.hash);
		hash2 = le64_to_cpu(ptr->index.hash);

		if (hash1 == hash2) {
			err = ssdfs_btree_common_node_change_index(node,
							&node->index_area,
							position,
							ptr);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change index: "
					  "node_id %u, position %u, err %d\n",
					  node->node_id, position, err);
				return err;
			}
		} else {
			if (hash2 > hash1)
				position++;

			if (position == node->index_area.index_count) {
				err = __ssdfs_btree_common_node_add_index(node,
								    position,
								    ptr);
				if (unlikely(err)) {
					SSDFS_ERR("fail to add index: "
						  "node_id %u, position %u, "
						  "err %d\n",
						  node->node_id, position, err);
					return err;
				}
			} else {
				err = ssdfs_btree_common_node_insert_index(node,
								    position,
								    ptr);
				if (unlikely(err)) {
					SSDFS_ERR("fail to insert index: "
						  "node_id %u, position %u, "
						  "err %d\n",
						  node->node_id, position, err);
					return err;
				}
			}

			node->index_area.index_count++;
		}
	}

	err = __ssdfs_btree_common_node_extract_index(node,
						      &node->index_area,
						      0,
						      &tmp_key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the index: err %d\n", err);
		return err;
	}

	node->index_area.start_hash = le64_to_cpu(tmp_key.index.hash);

	err = __ssdfs_btree_common_node_extract_index(node,
					&node->index_area,
					node->index_area.index_count - 1,
					&tmp_key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the index: err %d\n", err);
		return err;
	}

	node->index_area.end_hash = le64_to_cpu(tmp_key.index.hash);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "index_count %u, index_capacity %u\n",
		  node->index_area.start_hash,
		  node->index_area.end_hash,
		  node->index_area.index_count,
		  node->index_area.index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_node_add_index() - add index into node's index area
 * @node: node object
 * @index: new index
 *
 * This method tries to insert the index into node's index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - index area hasn't free space.
 * %-ENOENT     - node hasn't the index area.
 * %-EFAULT     - corrupted index or node's index area.
 * %-EACCES     - node is under initialization yet.
 */
int ssdfs_btree_node_add_index(struct ssdfs_btree_node *node,
				struct ssdfs_btree_index_key *index)
{
	struct ssdfs_fs_info *fsi;
	u64 hash;
	int node_type;
	u16 found = U16_MAX;
	u16 count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi || !index);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	hash = le64_to_cpu(index->index.hash);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, hash %llx\n",
		  node->node_id, hash);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't index area\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (hash == U64_MAX) {
		SSDFS_ERR("invalid hash %llx\n", hash);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	node_type = atomic_read(&node->type);
	if (node_type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    node_type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_ERR("invalid node type %#x\n",
			  node_type);
		return -ERANGE;
	}

	if (!can_add_new_index(node)) {
		u32 new_size;

		down_read(&node->header_lock);
		new_size = node->index_area.area_size * 2;
		up_read(&node->header_lock);

		err = ssdfs_btree_node_resize_index_area(node, new_size);
		if (err == -EACCES) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("node %u is under initialization\n",
				  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("index area cannot be resized: "
				  "node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to resize index area: "
				  "node_id %u, new_size %u, err %d\n",
				  node->node_id, new_size, err);
			return err;
		}
	}

	if (node_type == SSDFS_BTREE_ROOT_NODE) {
		down_read(&node->full_lock);
		down_write(&node->header_lock);

		err = ssdfs_find_index_by_hash(node, &node->index_area,
						hash, &found);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(found >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		if (err == -ENODATA) {
			/* node hasn't any index */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find an index: "
				  "node_id %u, hash %llx, err %d\n",
				  node->node_id, hash, err);
			goto finish_change_root_node;
		}

		ssdfs_btree_node_start_request_cno(node);
		err = ssdfs_btree_root_node_add_index(node, found,
							index);
		ssdfs_btree_node_finish_request_cno(node);

		if (unlikely(err)) {
			SSDFS_ERR("fail to change index: "
				  "node_id %u, node_type %#x, "
				  "found_index %u, err %d\n",
				  node->node_id, node_type,
				  found, err);
		}

finish_change_root_node:
		up_write(&node->header_lock);
		up_read(&node->full_lock);

		if (unlikely(err)) {
			ssdfs_debug_show_btree_node_indexes(node->tree, node);
			return err;
		}
	} else {
		down_write(&node->full_lock);
		down_write(&node->header_lock);

		err = ssdfs_find_index_by_hash(node, &node->index_area,
						hash, &found);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(found >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		if (err == -EEXIST) {
			/* index exist already */
			err = 0;
		} else if (err == -ENODATA) {
			/* node hasn't any index */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find an index: "
				  "node_id %u, hash %llx, err %d\n",
				  node->node_id, hash, err);
			up_write(&node->header_lock);
			up_write(&node->full_lock);
			return err;
		}

		count = (node->index_area.index_count + 1) - found;
		err = ssdfs_lock_index_range(node, found, count);
		BUG_ON(err == -ENODATA);
		if (unlikely(err)) {
			SSDFS_ERR("fail to lock index range: "
				  "start %u, count %u, err %d\n",
				  found, count, err);
			up_write(&node->header_lock);
			up_write(&node->full_lock);
			return err;
		}

		downgrade_write(&node->full_lock);

		ssdfs_btree_node_start_request_cno(node);
		err = ssdfs_btree_common_node_add_index(node, found,
							index);
		ssdfs_btree_node_finish_request_cno(node);
		ssdfs_unlock_index_range(node, found, count);

		if (!err)
			err = ssdfs_set_dirty_index_range(node, found, count);

		up_write(&node->header_lock);
		up_read(&node->full_lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to add index: "
				  "node_id %u, node_type %#x, "
				  "found_index %u, err %d\n",
				  node->node_id, node_type,
				  found, err);
			ssdfs_debug_show_btree_node_indexes(node->tree, node);
		}
	}

	ssdfs_set_node_update_cno(node);
	set_ssdfs_btree_node_dirty(node);

	return 0;
}

static inline
bool is_ssdfs_btree_index_key_identical(struct ssdfs_btree_index_key *index1,
					struct ssdfs_btree_index_key *index2)
{
	u32 node_id1, node_id2;
	u8 node_type1, node_type2;
	u64 hash1, hash2;
	u64 seg_id1, seg_id2;
	u32 logical_blk1, logical_blk2;
	u32 len1, len2;

	node_id1 = le32_to_cpu(index1->node_id);
	node_type1 = index1->node_type;
	hash1 = le64_to_cpu(index1->index.hash);
	seg_id1 = le64_to_cpu(index1->index.extent.seg_id);
	logical_blk1 = le32_to_cpu(index1->index.extent.logical_blk);
	len1 = le32_to_cpu(index1->index.extent.len);

	node_id2 = le32_to_cpu(index2->node_id);
	node_type2 = index2->node_type;
	hash2 = le64_to_cpu(index2->index.hash);
	seg_id2 = le64_to_cpu(index2->index.extent.seg_id);
	logical_blk2 = le32_to_cpu(index2->index.extent.logical_blk);
	len2 = le32_to_cpu(index2->index.extent.len);

	return node_id1 == node_id2 && node_type1 == node_type2 &&
		hash1 == hash2 && seg_id1 == seg_id2 &&
		logical_blk1 == logical_blk2 && len1 == len2;
}

/*
 * __ssdfs_btree_node_change_index() - change existing index
 * @node: node object
 * @old_index: old index
 * @new_index: new index
 *
 * This method tries to change @old_index on @new_index into
 * node's index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - node's index area doesn't contain @old_index.
 * %-ENOENT     - node hasn't the index area.
 * %-EFAULT     - corrupted index or node's index area.
 * %-EACCES     - node is under initialization yet.
 */
static
int __ssdfs_btree_node_change_index(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_index_key *old_index,
				    struct ssdfs_btree_index_key *new_index)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_node_index_area area;
	size_t desc_size = sizeof(struct ssdfs_btree_node_index_area);
	int node_type;
	u64 old_hash, new_hash;
	u16 found = U16_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
	BUG_ON(!old_index || !new_index);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;
	old_hash = le64_to_cpu(old_index->index.hash);
	new_hash = le64_to_cpu(new_index->index.hash);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, old_hash %llx, new_hash %llx\n",
		  node->node_id, old_hash, new_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't index area\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (old_hash == U64_MAX || new_hash == U64_MAX) {
		SSDFS_ERR("invalid old_hash %llx or new_hash %llx\n",
			  old_hash, new_hash);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	node_type = atomic_read(&node->type);
	if (node_type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    node_type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_ERR("invalid node type %#x\n",
			  node_type);
		return -ERANGE;
	}

	if (node_type == SSDFS_BTREE_ROOT_NODE) {
		down_read(&node->full_lock);

		err = ssdfs_find_index_by_hash(node, &node->index_area,
						old_hash, &found);
		if (err == -EEXIST) {
			err = 0;
			/*
			 * Index has been found.
			 * Continue logic.
			 */
		} else if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find an index: "
				  "node_id %u, hash %llx\n",
				  node->node_id, old_hash);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_change_root_node;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find an index: "
				  "node_id %u, hash %llx, err %d\n",
				  node->node_id, old_hash, err);
			goto finish_change_root_node;
		} else {
			err = -ERANGE;
			SSDFS_ERR("no index for the hash %llx\n",
				  old_hash);
			goto finish_change_root_node;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(found == U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		down_write(&node->header_lock);

		err = ssdfs_btree_root_node_change_index(node, found,
							 new_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change index: "
				  "node_id %u, node_type %#x, "
				  "found %u, err %d\n",
				  node->node_id, node_type,
				  found, err);
		}

		up_write(&node->header_lock);
finish_change_root_node:
		up_read(&node->full_lock);

		if (unlikely(err))
			return err;
	} else {
		down_read(&node->full_lock);

		down_read(&node->header_lock);
		ssdfs_memcpy(&area, 0, desc_size,
			     &node->index_area, 0, desc_size,
			     desc_size);
		up_read(&node->header_lock);

		err = ssdfs_find_index_by_hash(node, &area,
						old_hash, &found);
		if (err == -EEXIST) {
			err = 0;
			/*
			 * Index has been found.
			 * Continue logic.
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find an index: "
				  "node_id %u, hash %llx, err %d\n",
				  node->node_id, old_hash, err);
		} else {
			err = -ERANGE;
			SSDFS_ERR("no index for the hash %llx\n",
				  old_hash);
		}

		up_read(&node->full_lock);

		if (unlikely(err))
			return err;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(found == U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		down_write(&node->full_lock);
		down_write(&node->header_lock);

		err = ssdfs_lock_index_range(node, found, 1);
		BUG_ON(err == -ENODATA);

		if (unlikely(err)) {
			SSDFS_ERR("fail to lock index %u, err %d\n",
				  found, err);
			up_write(&node->header_lock);
			up_write(&node->full_lock);
			return err;
		}

		downgrade_write(&node->full_lock);

		err = ssdfs_btree_common_node_change_index(node,
							   &node->index_area,
							   found, new_index);
		ssdfs_unlock_index_range(node, found, 1);

		if (!err)
			err = ssdfs_set_dirty_index_range(node, found, 1);

		up_write(&node->header_lock);
		up_read(&node->full_lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to change index: "
				  "node_id %u, node_type %#x, "
				  "found %u, err %d\n",
				  node->node_id, node_type,
				  found, err);
			return err;
		}
	}

	ssdfs_set_node_update_cno(node);
	set_ssdfs_btree_node_dirty(node);

	return 0;
}

/*
 * ssdfs_btree_node_change_index() - change existing index
 * @node: node object
 * @old_index: old index
 * @new_index: new index
 *
 * This method tries to change @old_index on @new_index into
 * node's index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - node's index area doesn't contain @old_index.
 * %-ENOENT     - node hasn't the index area.
 * %-EFAULT     - corrupted index or node's index area.
 * %-EACCES     - node is under initialization yet.
 */
int ssdfs_btree_node_change_index(struct ssdfs_btree_node *node,
				  struct ssdfs_btree_index_key *old_index,
				  struct ssdfs_btree_index_key *new_index)
{
	u64 old_hash, new_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
	BUG_ON(!old_index || !new_index);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	old_hash = le64_to_cpu(old_index->index.hash);
	new_hash = le64_to_cpu(new_index->index.hash);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, old_hash %llx, new_hash %llx\n",
		  node->node_id, old_hash, new_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't index area\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (old_hash == U64_MAX || new_hash == U64_MAX) {
		SSDFS_ERR("invalid old_hash %llx or new_hash %llx\n",
			  old_hash, new_hash);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_ssdfs_btree_index_key_identical(old_index, new_index)) {
		SSDFS_DBG("old and new index are identical\n");
		return 0;
	}

	if (old_hash == new_hash) {
		ssdfs_btree_node_start_request_cno(node);
		err = __ssdfs_btree_node_change_index(node, old_index,
							new_index);
		ssdfs_btree_node_finish_request_cno(node);

		if (unlikely(err)) {
			SSDFS_ERR("fail to change index: "
				  "old_hash %llx, err %d\n",
				  old_hash, err);
			goto fail_change_index;
		}
	} else {
		err = ssdfs_btree_node_delete_index(node, old_hash);
		if (unlikely(err)) {
			SSDFS_ERR("fail to delete index: "
				  "old_hash %llx, err %d\n",
				  old_hash, err);
			goto fail_change_index;
		}

		err = ssdfs_btree_node_add_index(node, new_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add index: "
				  "new_hash %llx, err %d\n",
				  new_hash, err);
			goto fail_change_index;
		}
	}

	return 0;

fail_change_index:
	SSDFS_ERR("node_id %u, node_type %#x\n",
		  node->node_id,
		  atomic_read(&node->type));
	SSDFS_ERR("node_id %u, node_type %#x, old_hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(old_index->node_id),
		  old_index->node_type,
		  le64_to_cpu(old_index->index.hash),
		  le64_to_cpu(old_index->index.extent.seg_id),
		  le32_to_cpu(old_index->index.extent.logical_blk),
		  le32_to_cpu(old_index->index.extent.len));
	SSDFS_ERR("node_id %u, node_type %#x, new_hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(new_index->node_id),
		  new_index->node_type,
		  le64_to_cpu(new_index->index.hash),
		  le64_to_cpu(new_index->index.extent.seg_id),
		  le32_to_cpu(new_index->index.extent.logical_blk),
		  le32_to_cpu(new_index->index.extent.len));

	return err;
}

/*
 * ssdfs_btree_root_node_delete_index() - delete index record from root node
 * @node: node object
 * @position: position in the node of the deleting index record
 *
 * This method tries to delete the index record from the root node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_root_node_delete_index(struct ssdfs_btree_node *node,
					u16 position)
{
	size_t index_size = sizeof(struct ssdfs_btree_index);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("index 0: node_id %u; index 1: node_id %u\n",
		  le32_to_cpu(node->raw.root_node.header.node_ids[0]),
		  le32_to_cpu(node->raw.root_node.header.node_ids[1]));
	SSDFS_DBG("node_id %u, position %u\n",
		  node->node_id, position);
#endif /* CONFIG_SSDFS_DEBUG */

	if (node->index_area.index_count > node->index_area.index_capacity) {
		SSDFS_ERR("index_count %u > index_capacity %u\n",
			  node->index_area.index_count,
			  node->index_area.index_capacity);
		return -ERANGE;
	}

	if (position >= node->index_area.index_count) {
		SSDFS_ERR("invalid position %u, index_count %u\n",
			  position,
			  node->index_area.index_count);
		return -ERANGE;
	}

	if (node->index_area.index_count == 0) {
		SSDFS_WARN("index_count == 0\n");
		return -ERANGE;
	}

	switch (position) {
	case SSDFS_ROOT_NODE_LEFT_LEAF_NODE:
		if ((position + 1) < node->index_area.index_count) {
			node->index_area.start_hash = node->index_area.end_hash;
			ssdfs_memcpy(&node->raw.root_node.indexes[position],
				0, index_size,
				&node->raw.root_node.indexes[position + 1],
				0, index_size,
				index_size);
			ssdfs_memcpy(&node->raw.root_node.header.node_ids[position],
				0, sizeof(__le32),
				&node->raw.root_node.header.node_ids[position + 1],
				0, sizeof(__le32),
				sizeof(__le32));
			memset(&node->raw.root_node.indexes[position + 1], 0xFF,
				index_size);
			node->raw.root_node.header.node_ids[position + 1] =
							cpu_to_le32(U32_MAX);
		} else {
			node->index_area.start_hash = U64_MAX;
			node->index_area.end_hash = U64_MAX;
			memset(&node->raw.root_node.indexes[position], 0xFF,
				index_size);
			node->raw.root_node.header.node_ids[position] =
							cpu_to_le32(U32_MAX);
		}
		break;

	case SSDFS_ROOT_NODE_RIGHT_LEAF_NODE:
		node->index_area.end_hash = node->index_area.start_hash;
		memset(&node->raw.root_node.indexes[position], 0xFF,
			index_size);
		node->raw.root_node.header.node_ids[position] =
						cpu_to_le32(U32_MAX);
		break;

	default:
		BUG();
	}

	node->index_area.index_count--;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node->index_area.index_count %u\n",
		  node->index_area.index_count);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_common_node_delete_tail_index() - delete the tail index record
 * @node: node object
 * @position: position in the node of the deleting index record
 * @ptr: index record before @position [out]
 *
 * This method tries to delete the tail index record from the common node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_common_node_delete_tail_index(struct ssdfs_btree_node *node,
					      u16 position,
					      struct ssdfs_btree_index_key *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	size_t index_size = sizeof(struct ssdfs_btree_index_key);
	u32 offset_inside_folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !ptr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, position %u\n",
		  node->node_id, position);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if ((position + 1) != node->index_area.index_count) {
		SSDFS_ERR("cannot delete index: "
			  "position %u, index_count %u\n",
			  position,
			  node->index_area.index_count);
		return -ERANGE;
	}

	err = ssdfs_define_memory_folio(node, &node->index_area,
					position, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define memory page: "
			  "node_id %u, position %u, err %d\n",
			  node->node_id, position, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	if ((folio.desc.offset_inside_page + index_size) > PAGE_SIZE) {
		SSDFS_ERR("invalid offset_inside_page %u\n",
			  folio.desc.offset_inside_page);
		return -ERANGE;
	}

	err = ssdfs_find_node_content_folio(&node->content, &folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find folio: err %d\n", err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_size(folio.ptr) == fsi->pagesize) {
		ssdfs_folio_lock(folio.ptr);
		ssdfs_memset_folio(&folio, 0xFF, index_size);
		ssdfs_folio_unlock(folio.ptr);
	} else {
		offset_inside_folio = folio.desc.offset % folio_size(folio.ptr);

		ssdfs_folio_lock(folio.ptr);
		__ssdfs_memset_folio(folio.ptr,
				     offset_inside_folio,
				     folio_size(folio.ptr),
				     0xFF, index_size);
		ssdfs_folio_unlock(folio.ptr);
	}

	if (position == 0)
		memset(ptr, 0xFF, index_size);
	else {
		err = ssdfs_define_memory_folio(node, &node->index_area,
						position - 1, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to define memory page: "
				  "node_id %u, position %u, err %d\n",
				  node->node_id, position - 1, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_find_node_content_folio(&node->content, &folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find folio: err %d\n", err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio_size(folio.ptr) == fsi->pagesize) {
			ssdfs_folio_lock(folio.ptr);
			err = ssdfs_memcpy_from_folio(ptr, 0, index_size,
							&folio, index_size);
			ssdfs_folio_unlock(folio.ptr);
		} else {
			offset_inside_folio =
				folio.desc.offset % folio_size(folio.ptr);

			ssdfs_folio_lock(folio.ptr);
			err = __ssdfs_memcpy_from_folio(ptr,
							0, index_size,
							folio.ptr,
							offset_inside_folio,
							folio_size(folio.ptr),
							index_size);
			ssdfs_folio_unlock(folio.ptr);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_common_node_remove_index() - remove the index record
 * @node: node object
 * @position: position in the node of the deleting index record
 * @ptr: index record on @position after deletion [out]
 *
 * This method tries to delete the index record from the common node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_common_node_remove_index(struct ssdfs_btree_node *node,
					 u16 position,
					 struct ssdfs_btree_index_key *ptr)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_index_key buffer;
	struct ssdfs_smart_folio folio;
	void *kaddr;
	u16 cur_pos = position;
	u8 index_size;
	u32 page_offset;
	u32 offset_inside_folio;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !ptr);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, position %u\n",
		  node->node_id, position);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (!((position + 1) < node->index_area.index_count)) {
		SSDFS_ERR("cannot remove index: "
			  "position %u, index_count %u\n",
			  position,
			  node->index_area.index_count);
		return -ERANGE;
	}

	index_size = node->index_area.index_size;
	if (index_size != sizeof(struct ssdfs_btree_index_key)) {
		SSDFS_ERR("invalid index_size %u\n",
			  index_size);
		return -ERANGE;
	}

	do {
		u32 rest_capacity;
		u32 moving_count;
		u32 moving_bytes;

		err = ssdfs_define_memory_folio(node, &node->index_area,
						cur_pos, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to define memory page: "
				  "node_id %u, position %u, err %d\n",
				  node->node_id, cur_pos, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_pos %u, folio_index %u, "
			  "page_in_folio %u, offset_inside_page %u\n",
			  cur_pos, folio.desc.folio_index,
			  folio.desc.page_in_folio,
			  folio.desc.offset_inside_page);

		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		rest_capacity = PAGE_SIZE -
			(folio.desc.offset_inside_page + index_size);
		rest_capacity /= index_size;

		moving_count = node->index_area.index_count - (cur_pos + 1);
		moving_count = min_t(u32, moving_count, rest_capacity);
		moving_bytes = moving_count * index_size;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("rest_capacity %u, index_count %u, "
			  "moving_count %u, moving_bytes %u\n",
			  rest_capacity,
			  node->index_area.index_count,
			  moving_count, moving_bytes);

		if ((folio.desc.offset_inside_page + index_size) >
								PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "offset_inside_page %u, index_size %u\n",
				   folio.desc.offset_inside_page, index_size);
			return -ERANGE;
		}

		if ((folio.desc.offset_inside_page + moving_bytes) >
								PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "offset_inside_page %u, moving_bytes %u\n",
				   folio.desc.offset_inside_page, moving_bytes);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_find_node_content_folio(&node->content, &folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find folio: err %d\n", err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio_size(folio.ptr) == fsi->pagesize) {
			page_offset = folio.desc.page_offset;
		} else {
			page_offset =
			    SSDFS_PAGE_OFFSET_IN_FOLIO(folio_size(folio.ptr),
							   folio.desc.offset);
		}

		ssdfs_folio_lock(folio.ptr);
		kaddr = kmap_local_folio(folio.ptr, page_offset);

		if (moving_count == 0) {
			err = ssdfs_memcpy(&buffer,
					   0, index_size,
					   kaddr,
					   folio.desc.offset_inside_page,
					   PAGE_SIZE,
					   index_size);
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy: err %d\n", err);
				goto finish_copy;
			}

			memset((u8 *)kaddr + folio.desc.offset_inside_page,
				0xFF, index_size);
		} else {
			err = ssdfs_memcpy(&buffer,
					   0, index_size,
					   kaddr,
					   folio.desc.offset_inside_page,
					   PAGE_SIZE,
					   index_size);
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy: err %d\n", err);
				goto finish_copy;
			}

			err = ssdfs_memmove(kaddr,
				    folio.desc.offset_inside_page,
				    PAGE_SIZE,
				    kaddr,
				    folio.desc.offset_inside_page + index_size,
				    PAGE_SIZE,
				    moving_bytes);
			if (unlikely(err)) {
				SSDFS_ERR("fail to move: err %d\n", err);
				goto finish_copy;
			}

			memset((u8 *)kaddr +
				    folio.desc.offset_inside_page + moving_bytes,
				0xFF, index_size);
		}

		if (cur_pos == position) {
			err = ssdfs_memcpy(ptr, 0, index_size,
					   kaddr,
					   folio.desc.offset_inside_page,
					   PAGE_SIZE,
					   index_size);
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy: err %d\n", err);
				goto finish_copy;
			}
		}

finish_copy:
		flush_dcache_folio(folio.ptr);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio.ptr);

		if (unlikely(err))
			return err;

		if (cur_pos != position) {
			err = ssdfs_define_memory_folio(node,
							&node->index_area,
							cur_pos - 1,
							&folio.desc);
			if (unlikely(err)) {
				SSDFS_ERR("fail to define memory page: "
					  "node_id %u, position %u, err %d\n",
					  node->node_id, cur_pos - 1, err);
				return err;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cur_pos %u, folio_index %u, "
				  "page_in_folio %u, offset_inside_page %u\n",
				  cur_pos, folio.desc.folio_index,
				  folio.desc.page_in_folio,
				  folio.desc.offset_inside_page);

			BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));

			if ((folio.desc.offset_inside_page + index_size) >
								PAGE_SIZE) {
				SSDFS_WARN("invalid offset: "
					   "offset_inside_page %u, "
					   "index_size %u\n",
					   folio.desc.offset_inside_page,
					   index_size);
				return -ERANGE;
			}
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_find_node_content_folio(&node->content,
							    &folio);
			if (unlikely(err)) {
				SSDFS_ERR("fail to find folio: err %d\n",
					  err);
				return err;
			}

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

			if (folio_size(folio.ptr) == fsi->pagesize) {
				ssdfs_folio_lock(folio.ptr);
				err = ssdfs_memcpy_to_folio(&folio,
							    &buffer,
							    0, index_size,
							    index_size);
				ssdfs_folio_unlock(folio.ptr);
			} else {
				offset_inside_folio =
				    folio.desc.offset % folio_size(folio.ptr);

				ssdfs_folio_lock(folio.ptr);
				err = __ssdfs_memcpy_to_folio(folio.ptr,
							offset_inside_folio,
							folio_size(folio.ptr),
							&buffer,
							0, index_size,
							index_size);
				ssdfs_folio_unlock(folio.ptr);
			}

			if (unlikely(err)) {
				SSDFS_ERR("fail to copy: err %d\n", err);
				return err;
			}
		}

		cur_pos += moving_count + 1;
	} while (cur_pos < node->index_area.index_count);

	return 0;
}

/*
 * ssdfs_btree_common_node_delete_index() - delete the index record
 * @node: node object
 * @position: position in the node of the deleting index record
 *
 * This method tries to delete the index record from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_common_node_delete_index(struct ssdfs_btree_node *node,
					 u16 position)
{
	struct ssdfs_btree_index_key buffer;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, position %u, index_count %u\n",
		  node->node_id, position,
		  node->index_area.index_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (node->index_area.index_count > node->index_area.index_capacity) {
		SSDFS_ERR("index_count %u > index_capacity %u\n",
			  node->index_area.index_count,
			  node->index_area.index_capacity);
		return -ERANGE;
	}

	if (node->index_area.index_count == 0) {
		SSDFS_WARN("index_count == 0\n");
		return -ERANGE;
	}

	if (position >= node->index_area.index_count) {
		SSDFS_ERR("invalid index place: "
			  "position %u, index_count %u\n",
			  position,
			  node->index_area.index_count);
		return -ERANGE;
	}

	if ((position + 1) == node->index_area.index_count) {
		err = ssdfs_btree_common_node_delete_tail_index(node, position,
								&buffer);
		if (unlikely(err)) {
			SSDFS_ERR("fail to delete index: "
				  "node_id %u, position %u, err %d\n",
				  node->node_id, position, err);
			return err;
		}
	} else {
		err = ssdfs_btree_common_node_remove_index(node, position,
							   &buffer);
		if (unlikely(err)) {
			SSDFS_ERR("fail to remove index: "
				  "node_id %u, position %u, err %d\n",
				  node->node_id, position, err);
			return err;
		}
	}

	node->index_area.index_count--;

	if (node->index_area.index_count == 0) {
		node->index_area.start_hash = U64_MAX;
		node->index_area.end_hash = U64_MAX;
	} else {
		if (position == 0) {
			node->index_area.start_hash =
					le64_to_cpu(buffer.index.hash);
		} else if (position == node->index_area.index_count) {
			node->index_area.end_hash =
					le64_to_cpu(buffer.index.hash);
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "index_count %u, index_capacity %u\n",
		  node->index_area.start_hash,
		  node->index_area.end_hash,
		  node->index_area.index_count,
		  node->index_area.index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * need_shrink_index_area() - check that index area should be shrinked
 * @node: node object
 * @new_size: new size of the node after shrinking [out]
 */
static
bool need_shrink_index_area(struct ssdfs_btree_node *node, u32 *new_size)
{
	u16 index_area_min_size;
	u16 count, capacity;
	u8 index_size;
	bool need_check_size = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !new_size);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	*new_size = U32_MAX;
	index_area_min_size = node->tree->index_area_min_size;

	down_read(&node->header_lock);
	count = node->index_area.index_count;
	capacity = node->index_area.index_capacity;
	index_size = node->index_area.index_size;
	if (capacity == 0)
		err = -ERANGE;
	if (count > capacity)
		err = -ERANGE;
	up_read(&node->header_lock);

	if (unlikely(err)) {
		SSDFS_WARN("count %u > capacity %u\n",
			   count, capacity);
		return false;
	}

	if (index_area_min_size == 0 || index_area_min_size % index_size) {
		SSDFS_WARN("invalid index size: "
			   "index_area_min_size %u, index_size %u\n",
			   index_area_min_size, index_size);
		return false;
	}

	if (count == 0)
		need_check_size = true;
	else
		need_check_size = ((capacity / count) >= 2);

	if (need_check_size) {
		*new_size = (capacity / 2) * index_size;
		if (*new_size >= index_area_min_size)
			return true;
		else
			*new_size = U32_MAX;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("count %u, capacity %u, index_size %u, "
		  "index_area_min_size %u, new_size %u\n",
		  count, capacity, index_size,
		  index_area_min_size, *new_size);
#endif /* CONFIG_SSDFS_DEBUG */

	return false;
}

/*
 * ssdfs_btree_node_delete_index() - delete existing index
 * @node: node object
 * @hash: hash value
 *
 * This method tries to delete index for @hash from node's
 * index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - node's index area doesn't contain index for @hash.
 * %-ENOENT     - node hasn't the index area.
 * %-EFAULT     - corrupted node's index area.
 * %-EACCES     - node is under initialization yet.
 */
int ssdfs_btree_node_delete_index(struct ssdfs_btree_node *node,
				  u64 hash)
{
	struct ssdfs_fs_info *fsi;
	int node_type;
	u16 found = U16_MAX;
	u16 count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));

	SSDFS_DBG("node_id %u, hash %llx\n",
		  node->node_id, hash);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
	case SSDFS_BTREE_NODE_PRE_DELETED:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't index area\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (hash == U64_MAX) {
		SSDFS_ERR("invalid hash %llx\n", hash);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	node_type = atomic_read(&node->type);
	if (node_type <= SSDFS_BTREE_NODE_UNKNOWN_TYPE ||
	    node_type >= SSDFS_BTREE_NODE_TYPE_MAX) {
		SSDFS_ERR("invalid node type %#x\n",
			  node_type);
		return -ERANGE;
	}

	if (node_type == SSDFS_BTREE_ROOT_NODE) {
		down_read(&node->full_lock);
		down_write(&node->header_lock);

		if (is_ssdfs_btree_node_pre_deleted(node)) {
			SSDFS_DBG("node %u is pre-deleted\n",
				  node->node_id);
			goto finish_change_root_node;
		}

		err = ssdfs_find_index_by_hash(node, &node->index_area,
						hash, &found);
		if (err == -EEXIST) {
			/* hash == found hash */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find an index: "
				  "node_id %u, hash %llx, err %d\n",
				  node->node_id, hash, err);
			goto finish_change_root_node;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(found == U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_btree_node_start_request_cno(node);
		err = ssdfs_btree_root_node_delete_index(node, found);
		ssdfs_btree_node_finish_request_cno(node);

		if (unlikely(err)) {
			SSDFS_ERR("fail to delete index: "
				  "node_id %u, node_type %#x, "
				  "found_index %u, err %d\n",
				  node->node_id, node_type,
				  found, err);
		}

finish_change_root_node:
		up_write(&node->header_lock);
		up_read(&node->full_lock);

		if (unlikely(err))
			return err;
	} else {
		down_write(&node->full_lock);
		down_write(&node->header_lock);

		if (is_ssdfs_btree_node_pre_deleted(node)) {
			SSDFS_DBG("node %u is pre-deleted\n",
				  node->node_id);
			downgrade_write(&node->full_lock);
			goto finish_change_common_node;
		}

		err = ssdfs_find_index_by_hash(node, &node->index_area,
						hash, &found);
		if (err == -EEXIST) {
			/* hash == found hash */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find an index: "
				  "node_id %u, hash %llx, err %d\n",
				  node->node_id, hash, err);
			up_write(&node->header_lock);
			up_write(&node->full_lock);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(found == U16_MAX);

		SSDFS_DBG("index_count %u, found %u\n",
			  node->index_area.index_count, found);
#endif /* CONFIG_SSDFS_DEBUG */

		count = node->index_area.index_count - found;
		err = ssdfs_lock_index_range(node, found, count);
		BUG_ON(err == -ENODATA);
		if (unlikely(err)) {
			SSDFS_ERR("fail to lock index range: "
				  "start %u, count %u, err %d\n",
				  found, count, err);
			up_write(&node->header_lock);
			up_write(&node->full_lock);
			return err;
		}

		downgrade_write(&node->full_lock);

		ssdfs_btree_node_start_request_cno(node);
		err = ssdfs_btree_common_node_delete_index(node, found);
		ssdfs_btree_node_finish_request_cno(node);
		ssdfs_unlock_index_range(node, found, count);

		if (!err)
			err = ssdfs_set_dirty_index_range(node, found, count);

finish_change_common_node:
		up_write(&node->header_lock);
		up_read(&node->full_lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to delete index: "
				  "node_id %u, node_type %#x, "
				  "found_index %u, err %d\n",
				  node->node_id, node_type,
				  found, err);
		}
	}

	if (is_ssdfs_btree_node_pre_deleted(node)) {
		SSDFS_DBG("no other activity is necessary: "
			  "node %u is pre-deleted\n",
			  node->node_id);
		return 0;
	}

	ssdfs_set_node_update_cno(node);
	set_ssdfs_btree_node_dirty(node);

	if (node_type != SSDFS_BTREE_ROOT_NODE) {
		u32 new_size;

		if (need_shrink_index_area(node, &new_size)) {
			err = ssdfs_btree_node_resize_index_area(node,
								 new_size);
			if (err == -ENOSPC) {
				err = 0;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("index area cannot be resized: "
					  "node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to resize index area: "
					  "node_id %u, new_size %u, err %d\n",
					  node->node_id, new_size, err);
				return err;
			}
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "index_count %u, index_capacity %u\n",
		  node->index_area.start_hash,
		  node->index_area.end_hash,
		  node->index_area.index_count,
		  node->index_area.index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_move_root2common_node_index_range() - move index range (root -> common)
 * @src: source node
 * @src_start: starting index in the source node
 * @dst: destination node
 * @dst_start: starting index in the destination node
 * @count: count of indexes in the range
 *
 * This method tries to move the index range from the source node
 * into destination one.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_move_root2common_node_index_range(struct ssdfs_btree_node *src,
					    u16 src_start,
					    struct ssdfs_btree_node *dst,
					    u16 dst_start, u16 count)
{
	struct ssdfs_fs_info *fsi;
	int i, j;
	int upper_bound;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!src || !dst);
	BUG_ON(!src->tree || !src->tree->fsi);
	BUG_ON(!rwsem_is_locked(&src->tree->lock));

	if (!is_ssdfs_btree_node_index_area_exist(src)) {
		SSDFS_DBG("src node %u hasn't index area\n",
			  src->node_id);
		return -EINVAL;
	}

	if (!is_ssdfs_btree_node_index_area_exist(dst)) {
		SSDFS_DBG("dst node %u hasn't index area\n",
			  dst->node_id);
		return -EINVAL;
	}

	if (atomic_read(&src->type) != SSDFS_BTREE_ROOT_NODE) {
		SSDFS_ERR("invalid src node type %#x\n",
			  atomic_read(&src->type));
		return -EINVAL;
	}

	SSDFS_DBG("src_node %u, src_start %u, "
		  "dst_node %u, dst_start %u, "
		  "count %u\n",
		  src->node_id, src_start,
		  dst->node_id, dst_start, count);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = src->tree->fsi;

	if (src_start >= SSDFS_BTREE_ROOT_NODE_INDEX_COUNT) {
		SSDFS_ERR("invalid src_start %u\n",
			  src_start);
		return -ERANGE;
	}

	if (count == 0) {
		SSDFS_ERR("count is zero\n");
		return -ERANGE;
	}

	atomic_set(&src->state, SSDFS_BTREE_NODE_CREATED);
	atomic_set(&dst->state, SSDFS_BTREE_NODE_CREATED);

	count = min_t(u16, count,
		      SSDFS_BTREE_ROOT_NODE_INDEX_COUNT - src_start);

	upper_bound = src_start + count;
	for (i = src_start, j = dst_start; i < upper_bound; i++, j++) {
		struct ssdfs_btree_index_key index;

		down_write(&src->full_lock);

		err = __ssdfs_btree_root_node_extract_index(src, i,
							    &index);
		if (unlikely(err)) {
			SSDFS_ERR("fail extract index: "
				  "index %u, err %d\n",
				  i, err);
		}

		up_write(&src->full_lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("btree index %d, "
			  "node_id %u, node_type %#x, "
			  "height %u, hash %#llx, "
			  "extent (seg_id %llu, logical_blk %u, len %u)\n",
			  i,
			  le32_to_cpu(index.node_id),
			  index.node_type,
			  index.height,
			  le64_to_cpu(index.index.hash),
			  le64_to_cpu(index.index.extent.seg_id),
			  le32_to_cpu(index.index.extent.logical_blk),
			  le32_to_cpu(index.index.extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

		if (unlikely(err)) {
			atomic_set(&src->state, SSDFS_BTREE_NODE_CORRUPTED);
			atomic_set(&dst->state, SSDFS_BTREE_NODE_CORRUPTED);
			return err;
		}

		down_write(&dst->full_lock);

		down_write(&dst->header_lock);
		err = ssdfs_btree_common_node_add_index(dst, j, &index);
		up_write(&dst->header_lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to insert index: "
				  "index %u, err %d\n",
				  j, err);
		}

		up_write(&dst->full_lock);

		if (unlikely(err)) {
			atomic_set(&src->state, SSDFS_BTREE_NODE_CORRUPTED);
			atomic_set(&dst->state, SSDFS_BTREE_NODE_CORRUPTED);
			return err;
		}
	}

	for (i = 0; i < count; i++) {
		down_write(&src->full_lock);

		down_write(&src->header_lock);
		err = ssdfs_btree_root_node_delete_index(src, src_start);
		up_write(&src->header_lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to delete index: "
				  "index %u, err %d\n",
				  i, err);
		}

		up_write(&src->full_lock);

		if (unlikely(err)) {
			atomic_set(&src->state, SSDFS_BTREE_NODE_CORRUPTED);
			atomic_set(&dst->state, SSDFS_BTREE_NODE_CORRUPTED);
			return err;
		}
	}

	ssdfs_set_node_update_cno(src);
	set_ssdfs_btree_node_dirty(src);

	ssdfs_set_node_update_cno(dst);
	set_ssdfs_btree_node_dirty(dst);

	return 0;
}

/*
 * ssdfs_copy_index_range_in_buffer() - copy index range in buffer
 * @node: node object
 * @start: starting index in the node
 * @count: requested count of indexes in the range
 * @area_offset: offset of the index area in the node
 * @index_size: size of the index in bytes
 * @buf: pointer on buffer
 * @range_len: pointer on value of count of indexes in the buffer [out]
 *
 * This method tries to copy the index range into  the buffer.
 * If a current memory page of node contains lesser amount of indexes
 * then @range_len will contain real number of indexes in the @buf.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_copy_index_range_in_buffer(struct ssdfs_btree_node *node,
				     u16 start, u16 count,
				     u32 area_offset, u16 index_size,
				     struct ssdfs_btree_index_key *buf,
				     u16 *range_len)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	u32 offset;
	u32 copy_bytes;
	u32 offset_inside_folio;
#ifdef CONFIG_SSDFS_DEBUG
	int i;
#endif /* CONFIG_SSDFS_DEBUG */
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !buf || !range_len);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
		SSDFS_DBG("node %u hasn't index area\n",
			  node->node_id);
		return -EINVAL;
	}

	SSDFS_DBG("node %u, start %u, count %u\n",
		  node->node_id, start, count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (count == 0) {
		SSDFS_ERR("count is zero\n");
		return -ERANGE;
	}

	fsi = node->tree->fsi;
	*range_len = U16_MAX;

	offset = area_offset + (start * index_size);

	err = SSDFS_OFF2FOLIO(fsi->pagesize, offset, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "offset %u, err %d\n",
			  offset, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	*range_len = PAGE_SIZE - folio.desc.offset_inside_page;
	*range_len /= index_size;
	*range_len = min_t(u32, *range_len, (u32)count);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("offset %u, folio_index %u, "
		  "page_in_folio %u, offset_inside_page %u\n",
		  offset, folio.desc.folio_index,
		  folio.desc.page_in_folio,
		  folio.desc.offset_inside_page);
	SSDFS_DBG("start %u, count %u, range_len %u\n",
		  start, count, *range_len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (*range_len == 0) {
		SSDFS_ERR("range_len == 0\n");
		return -ERANGE;
	}

	copy_bytes = *range_len * index_size;

	err = ssdfs_find_node_content_folio(&node->content, &folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find folio: err %d\n",
			  err);
		return err;
	}

	if (!folio.ptr) {
		SSDFS_ERR("folio is NULL\n");
		return -ERANGE;
	}

	if (folio_size(folio.ptr) == fsi->pagesize) {
		err = ssdfs_memcpy_from_folio(buf, 0, PAGE_SIZE,
					      &folio, copy_bytes);
	} else {
		offset_inside_folio = folio.desc.offset % folio_size(folio.ptr);

		err = __ssdfs_memcpy_from_folio(buf,
						0, PAGE_SIZE,
						folio.ptr,
						offset_inside_folio,
						folio_size(folio.ptr),
						copy_bytes);
	}

	if (unlikely(err)) {
		SSDFS_ERR("buffer is too small: "
			  "range_len %u, index_size %u, "
			  "buf_size %lu\n",
			  *range_len, index_size,
			  PAGE_SIZE);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	for (i = 0; i < *range_len; i++) {
		SSDFS_DBG("index %d, node_id %u, "
			  "node_type %#x, height %u, "
			  "flags %#x, hash %llx, seg_id %llu, "
			  "logical_blk %u, len %u\n",
			  i,
			  le32_to_cpu(buf[i].node_id),
			  buf[i].node_type,
			  buf[i].height,
			  le16_to_cpu(buf[i].flags),
			  le64_to_cpu(buf[i].index.hash),
			  le64_to_cpu(buf[i].index.extent.seg_id),
			  le32_to_cpu(buf[i].index.extent.logical_blk),
			  le32_to_cpu(buf[i].index.extent.len));
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_save_index_range_in_node() - save index range in the node
 * @node: node object
 * @start: starting index in the node
 * @count: requested count of indexes in the range
 * @area_offset: offset of the index area in the node
 * @index_size: size of the index in bytes
 * @buf: pointer on buffer
 *
 * This method tries to save the index range from @buf into @node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_save_index_range_in_node(struct ssdfs_btree_node *node,
				  u16 start, u16 count,
				  u32 area_offset, u16 index_size,
				  struct ssdfs_btree_index_key *buf)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	u32 offset;
	int i;
	u16 copied = 0;
	u32 sub_range_len = 0;
	u32 offset_inside_folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !buf);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
		SSDFS_DBG("node %u hasn't index area\n",
			  node->node_id);
		return -EINVAL;
	}

	SSDFS_DBG("node %u, start %u, count %u\n",
		  node->node_id, start, count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (count == 0) {
		SSDFS_ERR("count is zero\n");
		return -ERANGE;
	}

	fsi = node->tree->fsi;
	i = start;

	while (count > 0) {
		offset = area_offset + (i * index_size);

		err = SSDFS_OFF2FOLIO(fsi->pagesize, offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "offset %u, err %d\n",
				  offset, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		sub_range_len = PAGE_SIZE - folio.desc.offset_inside_page;
		sub_range_len /= index_size;
		sub_range_len = min_t(u32, sub_range_len, count);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("i %d, offset %u, folio_index %u, "
			  "page_in_folio %u, page_off %u, "
			  "sub_range_len %u\n",
			  i, offset,
			  folio.desc.folio_index,
			  folio.desc.page_in_folio,
			  folio.desc.offset_inside_page,
			  sub_range_len);
#endif /* CONFIG_SSDFS_DEBUG */

		if (sub_range_len == 0) {
			SSDFS_ERR("invalid sub_range_len: "
				  "i %d, count %u, folio_index %u, "
				  "page_in_folio %u, page_off %u, "
				  "sub_range_len %u\n",
				  i, count,
				  folio.desc.folio_index,
				  folio.desc.page_in_folio,
				  folio.desc.offset_inside_page,
				  sub_range_len);
			return -ERANGE;
		}

		if ((folio.desc.offset_inside_page +
					(sub_range_len * index_size)) >
								PAGE_SIZE) {
			SSDFS_ERR("out of page: "
				  "offset_inside_page %u, sub_range_len %u, "
				  "index_size %u, page_size %lu\n",
				  folio.desc.offset_inside_page,
				  sub_range_len, index_size, PAGE_SIZE);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("i %u, count %u, folio_index %u, "
			  "page_in_folio %u, page_off %u, "
			  "copied %u, sub_range_len %u\n",
			  i, count,
			  folio.desc.folio_index,
			  folio.desc.page_in_folio,
			  folio.desc.offset_inside_page,
			  copied, sub_range_len);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_find_node_content_folio(&node->content, &folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find folio: err %d\n",
				  err);
			return err;
		}

		if (!folio.ptr) {
			SSDFS_ERR("folio is NULL\n");
			return -ERANGE;
		}

		if (folio_size(folio.ptr) == fsi->pagesize) {
			err = ssdfs_memcpy_to_folio(&folio,
					buf, copied * index_size, PAGE_SIZE,
					sub_range_len * index_size);
		} else {
			offset_inside_folio =
				folio.desc.offset % folio_size(folio.ptr);

			err = __ssdfs_memcpy_to_folio(folio.ptr,
						offset_inside_folio,
						folio_size(folio.ptr),
						buf,
						copied * index_size,
						PAGE_SIZE,
						sub_range_len * index_size);
		}

		if (unlikely(err)) {
			SSDFS_ERR("out of page: "
				  "sub_range_len %u, index_size %u, "
				  "page_size %lu\n",
				  sub_range_len, index_size,
				  PAGE_SIZE);
			return err;
		}

		err = ssdfs_set_dirty_index_range(node, i,
						  (u16)sub_range_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set dirty index range: "
				  "start %u, len %u, err %d\n",
				  i, sub_range_len, err);
			return err;
		}

		i += sub_range_len;
		copied += sub_range_len;
		count -= sub_range_len;
	};

	return 0;
}

/*
 * ssdfs_clear_index_range_in_node() - clear index range in the node
 * @node: node object
 * @start: starting index in the node
 * @count: requested count of indexes in the range
 * @area_offset: offset of the index area in the node
 * @index_size: size of the index in bytes
 *
 * This method tries to clear the index range into @node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_clear_index_range_in_node(struct ssdfs_btree_node *node,
				    u16 start, u16 count,
				    u32 area_offset, u16 index_size)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	u32 offset;
	u32 sub_range_len = 0;
	u32 offset_inside_folio;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
		SSDFS_DBG("node %u hasn't index area\n",
			  node->node_id);
		return -EINVAL;
	}

	SSDFS_DBG("node %u, start %u, count %u\n",
		  node->node_id, start, count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (count == 0) {
		SSDFS_ERR("count is zero\n");
		return -ERANGE;
	}

	fsi = node->tree->fsi;
	i = start;

	while (count > 0) {
		offset = area_offset + (i * index_size);

		err = SSDFS_OFF2FOLIO(fsi->pagesize, offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "offset %u, err %d\n",
				  offset, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		sub_range_len = PAGE_SIZE - folio.desc.offset_inside_page;
		sub_range_len /= index_size;
		sub_range_len = min_t(u32, sub_range_len, count);

		if (sub_range_len == 0) {
			SSDFS_ERR("invalid sub_range_len: "
				  "i %d, count %u, "
				  "folio_index %u, page_in_folio %u, "
				  "offset_inside_page %u, "
				  "sub_range_len %u\n",
				  i, count, folio.desc.folio_index,
				  folio.desc.page_in_folio,
				  folio.desc.offset_inside_page,
				  sub_range_len);
			return -ERANGE;
		}

		if ((sub_range_len * index_size) > PAGE_SIZE) {
			SSDFS_ERR("out of page: "
				  "sub_range_len %u, index_size %u, "
				  "page_size %lu\n",
				  sub_range_len, index_size,
				  PAGE_SIZE);
			return -ERANGE;
		}

		if ((folio.desc.offset_inside_page +
					(sub_range_len * index_size)) >
								PAGE_SIZE) {
			SSDFS_ERR("out of page: "
				  "offset_inside_page %u, sub_range_len %u, "
				  "index_size %u, page_size %lu\n",
				  folio.desc.offset_inside_page,
				  sub_range_len, index_size, PAGE_SIZE);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start %u, count %u, folio_index %u, "
			  "page_in_folio %u, offset_inside_page %u, "
			  "sub_range_len %u\n",
			  start, count, folio.desc.folio_index,
			  folio.desc.page_in_folio,
			  folio.desc.offset_inside_page,
			  sub_range_len);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_find_node_content_folio(&node->content, &folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find folio: err %d\n",
				  err);
			return err;
		}

		if (!folio.ptr) {
			SSDFS_ERR("folio is NULL\n");
			return -ERANGE;
		}

		if (folio_size(folio.ptr) == fsi->pagesize) {
			ssdfs_memset_folio(&folio, 0xFF,
					   sub_range_len * index_size);
		} else {
			offset_inside_folio =
				folio.desc.offset % folio_size(folio.ptr);

			__ssdfs_memset_folio(folio.ptr,
					     offset_inside_folio,
					     folio_size(folio.ptr),
					     0xFF,
					     sub_range_len * index_size);
		}

		i += sub_range_len;
		count -= sub_range_len;
	};

	return 0;
}

/*
 * ssdfs_move_common2common_node_index_range() - move index range
 * @src: source node
 * @src_start: starting index in the source node
 * @dst: destination node
 * @dst_start: starting index in the destination node
 * @count: count of indexes in the range
 *
 * This method tries to move the index range from the common node
 * @src into the common node @dst.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_move_common2common_node_index_range(struct ssdfs_btree_node *src,
					      u16 src_start,
					      struct ssdfs_btree_node *dst,
					      u16 dst_start, u16 count)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_index_key *buf;
	u16 i, j;
	u32 src_offset, dst_offset;
	u32 src_area_size, dst_area_size;
	u16 index_size;
	u16 src_index_count, dst_index_count;
	u16 dst_index_capacity;
	u64 src_start_hash, src_end_hash;
	u64 dst_start_hash, dst_end_hash;
	u16 processed = 0;
	u16 copied = 0;
	u16 rest_unmoved = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!src || !dst);
	BUG_ON(!src->tree || !src->tree->fsi);
	BUG_ON(!rwsem_is_locked(&src->tree->lock));

	if (!is_ssdfs_btree_node_index_area_exist(src)) {
		SSDFS_DBG("src node %u hasn't index area\n",
			  src->node_id);
		return -EINVAL;
	}

	if (!is_ssdfs_btree_node_index_area_exist(dst)) {
		SSDFS_DBG("dst node %u hasn't index area\n",
			  dst->node_id);
		return -EINVAL;
	}

	SSDFS_DBG("src_node %u, src_start %u, "
		  "dst_node %u, dst_start %u, "
		  "count %u\n",
		  src->node_id, src_start,
		  dst->node_id, dst_start, count);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = src->tree->fsi;

	if (count == 0) {
		SSDFS_ERR("count is zero\n");
		return -ERANGE;
	}

	buf = ssdfs_btree_node_kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		SSDFS_ERR("fail to allocate buffer\n");
		return -ERANGE;
	}

	atomic_set(&src->state, SSDFS_BTREE_NODE_CREATED);
	atomic_set(&dst->state, SSDFS_BTREE_NODE_CREATED);

	down_read(&src->header_lock);
	src_offset = src->index_area.offset;
	src_area_size = src->index_area.area_size;
	index_size = src->index_area.index_size;
	src_index_count = src->index_area.index_count;
	src_start_hash = src->index_area.start_hash;
	src_end_hash = src->index_area.end_hash;
	up_read(&src->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("src_node %u, index_count %u, count %u\n",
		  src->node_id, src_index_count, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&dst->header_lock);
	dst_offset = dst->index_area.offset;
	dst_area_size = dst->index_area.area_size;
	dst_index_count = dst->index_area.index_count;
	dst_index_capacity = dst->index_area.index_capacity;
	dst_start_hash = dst->index_area.start_hash;
	dst_end_hash = dst->index_area.end_hash;
	up_read(&dst->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dst_node %u, index_count %u, "
		  "count %u, dst_index_capacity %u\n",
		  dst->node_id, dst_index_count,
		  count, dst_index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	if ((src_start + count) > src_index_count) {
		err = -ERANGE;
		SSDFS_ERR("invalid count: "
			  "src_start %u, count %u, "
			  "src_index_count %u\n",
			  src_start, count, src_index_count);
		goto finish_index_moving;
	}

	if ((dst_index_count + count) > dst_index_capacity) {
		err = -ERANGE;
		SSDFS_ERR("invalid count: "
			  "dst_index_count %u, count %u, "
			  "dst_index_capacity %u\n",
			  dst_index_count, count,
			  dst_index_capacity);
		goto finish_index_moving;
	}

	i = src_start;
	j = dst_start;

	down_write(&src->full_lock);
	err = ssdfs_lock_whole_index_area(src);
	downgrade_write(&src->full_lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to lock source's index area: err %d\n",
			  err);
		goto unlock_src_node;
	}

	down_write(&dst->full_lock);
	err = ssdfs_lock_whole_index_area(dst);
	downgrade_write(&dst->full_lock);

	if (unlikely(err)) {
		ssdfs_unlock_whole_index_area(src);
		SSDFS_ERR("fail to lock destination's index area: err %d\n",
			  err);
		goto unlock_dst_node;
	}

	if (dst_start == 0 && dst_start != dst_index_count) {
		down_write(&dst->header_lock);
		err = ssdfs_shift_range_right2(dst, &dst->index_area,
						index_size,
						0, dst_index_count,
						count);
		up_write(&dst->header_lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to shift index range right: "
				  "dst_node %u, index_count %u, "
				  "shift %u, err %d\n",
				  dst->node_id, dst_index_count,
				  count, err);
			goto unlock_index_area;
		}
	} else if (dst_start != dst_index_count) {
		err = -ERANGE;
		SSDFS_ERR("dst_start %u != dst_index_count %u\n",
			  dst_start, dst_index_count);
		SSDFS_ERR("source (start_hash %llx, end_hash %llx), "
			  "destination (start_hash %llx, end_hash %llx)\n",
			  src_start_hash, src_end_hash,
			  dst_start_hash, dst_end_hash);
		goto unlock_index_area;
	}

	while (processed < count) {
		u16 range_len = 0;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("i %u, j %u, processed %u, "
			  "count %u, range_len %u\n",
			  i, j, processed, count, range_len);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_copy_index_range_in_buffer(src, i,
							count - processed,
							src_offset,
							index_size,
							buf,
							&range_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy index range in buffer: "
				  "err %d\n", err);
			goto unlock_index_area;
		}

		err = ssdfs_save_index_range_in_node(dst, j, range_len,
						     dst_offset, index_size,
						     buf);
		if (unlikely(err)) {
			SSDFS_ERR("fail to save index range into node: "
				  "err %d\n", err);
			goto unlock_index_area;
		}

		i += range_len;
		j += range_len;
		processed += range_len;
	}

	err = ssdfs_clear_index_range_in_node(src, src_start, count,
					      src_offset, index_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to clear the source node's index range: "
			  "err %d\n", err);
		goto unlock_index_area;
	}

	down_write(&dst->header_lock);
	dst->index_area.index_count += processed;
	err = __ssdfs_init_index_area_hash_range(dst,
						 dst->index_area.index_count,
						 &dst->index_area.start_hash,
						 &dst->index_area.end_hash);
	up_write(&dst->header_lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to set the destination node's index range: "
			  "err %d\n", err);
		goto unlock_index_area;
	}

	if ((src_start + processed) < src_index_count) {
		i = src_start + processed;
		j = src_start;

		rest_unmoved = src_index_count - (src_start + processed);
		copied = 0;

		while (copied < rest_unmoved) {
			u16 range_len = 0;

			err = ssdfs_copy_index_range_in_buffer(src, i,
							rest_unmoved - copied,
							src_offset,
							index_size,
							buf,
							&range_len);
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy index range in buffer: "
					  "err %d\n", err);
				goto finish_source_correction;
			}

			err = ssdfs_save_index_range_in_node(src, j, range_len,
							     src_offset,
							     index_size,
							     buf);
			if (unlikely(err)) {
				SSDFS_ERR("fail to save index range into node: "
					  "err %d\n", err);
				goto finish_source_correction;
			}

finish_source_correction:
			if (unlikely(err))
				goto unlock_index_area;

			i += range_len;
			j += range_len;
			copied += range_len;
		}

		err = ssdfs_clear_index_range_in_node(src,
						      src_start + processed,
						      rest_unmoved,
						      src_offset, index_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to clear the src node's index range: "
				  "err %d\n", err);
			goto unlock_index_area;
		}

		err = ssdfs_set_dirty_index_range(src, src_start,
						  rest_unmoved);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set dirty index range: "
				  "start %u, len %u, err %d\n",
				  src_start, rest_unmoved, err);
			goto unlock_index_area;
		}
	}

	down_write(&src->header_lock);
	src->index_area.index_count -= processed;
	err = __ssdfs_init_index_area_hash_range(src,
						 src->index_area.index_count,
						 &src->index_area.start_hash,
						 &src->index_area.end_hash);
	up_write(&src->header_lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to set the source node's hash range: "
			  "err %d\n", err);
		goto unlock_index_area;
	}

unlock_index_area:
	ssdfs_unlock_whole_index_area(dst);
	ssdfs_unlock_whole_index_area(src);

unlock_dst_node:
	up_read(&dst->full_lock);

unlock_src_node:
	up_read(&src->full_lock);

finish_index_moving:
	if (unlikely(err)) {
		atomic_set(&src->state, SSDFS_BTREE_NODE_CORRUPTED);
		atomic_set(&dst->state, SSDFS_BTREE_NODE_CORRUPTED);
	} else {
		ssdfs_set_node_update_cno(src);
		set_ssdfs_btree_node_dirty(src);

		ssdfs_set_node_update_cno(dst);
		set_ssdfs_btree_node_dirty(dst);
	}

	ssdfs_btree_node_kfree(buf);
	return err;
}

/*
 * ssdfs_btree_node_move_index_range() - move index range
 * @src: source node
 * @src_start: starting index in the source node
 * @dst: destination node
 * @dst_start: starting index in the destination node
 * @count: count of indexes in the range
 *
 * This method tries to move the index range from @src into @dst.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - index area is absent.
 */
int ssdfs_btree_node_move_index_range(struct ssdfs_btree_node *src,
				      u16 src_start,
				      struct ssdfs_btree_node *dst,
				      u16 dst_start, u16 count)
{
	int src_type, dst_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!src || !dst);
	BUG_ON(!rwsem_is_locked(&src->tree->lock));

	SSDFS_DBG("src_node %u, src_start %u, "
		  "dst_node %u, dst_start %u, "
		  "count %u\n",
		  src->node_id, src_start,
		  dst->node_id, dst_start, count);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&src->state)) {
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&src->state));
		return -ERANGE;
	}

	if (!is_ssdfs_btree_node_index_area_exist(src)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("src node %u hasn't index area\n",
			  src->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

	switch (atomic_read(&dst->state)) {
	case SSDFS_BTREE_NODE_CREATED:
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&dst->state));
		return -ERANGE;
	}

	if (!is_ssdfs_btree_node_index_area_exist(dst)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("dst node %u hasn't index area\n",
			  dst->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

	src_type = atomic_read(&src->type);
	switch (src_type) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid src node type %#x\n",
			  src_type);
		return -ERANGE;
	}

	dst_type = atomic_read(&dst->type);
	switch (dst_type) {
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_INDEX_NODE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dst node type %#x\n",
			  dst_type);
		return -ERANGE;
	}

	if (src_type == SSDFS_BTREE_ROOT_NODE) {
		err = ssdfs_move_root2common_node_index_range(src, src_start,
							      dst, dst_start,
							      count);
	} else {
		err = ssdfs_move_common2common_node_index_range(src, src_start,
								dst, dst_start,
								count);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to move index range: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_btree_node_check_result_for_search() - check search result for search
 * @search: btree search object
 */
static
int ssdfs_btree_node_check_result_for_search(struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node;
	u64 update_cno;
	u64 start_hash, end_hash;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	node = search->node.child;

	down_read(&node->header_lock);
	update_cno = node->update_cno;
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	up_read(&node->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search (state %#x, search_cno %llu, "
		  "start_hash %llx, end_hash %llx), "
		  "node (update_cno %llu, "
		  "start_hash %llx, end_hash %llx)\n",
		  search->result.state,
		  search->result.search_cno,
		  search->request.start.hash,
		  search->request.end.hash,
		  update_cno, start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		if (search->result.search_cno < update_cno) {
			search->result.state =
				SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;
			return -EAGAIN;
		}

		if (search->request.start.hash < start_hash &&
		    search->request.start.hash > end_hash) {
			search->result.state =
				SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;
			return -EAGAIN;
		}

		return 0;

	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		if (search->result.search_cno < update_cno) {
			search->result.state =
				SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;
			return -EAGAIN;
		}

		return 0;

	case SSDFS_BTREE_SEARCH_UNKNOWN_RESULT:
		/* expected state */
		break;

	case SSDFS_BTREE_SEARCH_FAILURE:
	case SSDFS_BTREE_SEARCH_EMPTY_RESULT:
	case SSDFS_BTREE_SEARCH_OBSOLETE_RESULT:
		search->result.state = SSDFS_BTREE_SEARCH_UNKNOWN_RESULT;
		break;

	case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
		SSDFS_DBG("search result requests to add a node already\n");
		break;

	case SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE:
		SSDFS_WARN("unexpected search result state\n");
		search->result.state = SSDFS_BTREE_SEARCH_UNKNOWN_RESULT;
		break;

	default:
		SSDFS_WARN("invalid search result state\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search->result.state %#x\n",
		  search->result.state);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_node_check_hash_range() - check necessity to do search
 * @node: pointer on node object
 * @items_count: items count in the node
 * @items_capacity: node's capacity for items
 * @start_hash: items' area starting hash
 * @end_hash: items' area ending hash
 * @search: pointer on search request object
 *
 * This method tries to check the necessity to do
 * the real search in the node..
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - requested range is out of the node.
 * %-ENOMEM     - unable to allocate memory.
 */
int ssdfs_btree_node_check_hash_range(struct ssdfs_btree_node *node,
				      u16 items_count,
				      u16 items_capacity,
				      u64 start_hash,
				      u64 end_hash,
				      struct ssdfs_btree_search *search)
{
	u16 vacant_items;
	bool have_enough_space;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "search (start_hash %llx, end_hash %llx), "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  start_hash, end_hash,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (items_count == 0) {
		search->result.state =
			SSDFS_BTREE_SEARCH_OUT_OF_RANGE;

		search->result.err = -ENODATA;
		search->result.start_index = 0;
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

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("search->result.start_index %u, "
			  "search->result.state %#x, "
			  "search->result.err %d\n",
			  search->result.start_index,
			  search->result.state,
			  search->result.err);
#endif /* CONFIG_SSDFS_DEBUG */

		return -ENODATA;
	}

	vacant_items = items_capacity - items_count;
	have_enough_space = search->request.count <= vacant_items;

	switch (RANGE_WITHOUT_INTERSECTION(search->request.start.hash,
					   search->request.end.hash,
					   start_hash, end_hash)) {
	case 0:
		/* ranges have intersection */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("ranges have intersection\n");
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	case -1: /* range1 < range2 */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("range1 < range2\n");
#endif /* CONFIG_SSDFS_DEBUG */
		if (have_enough_space) {
			search->result.state =
				SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		} else {
			search->result.state =
				SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE;
		}

		search->result.err = -ENODATA;
		search->result.start_index = 0;
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

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("search->result.start_index %u, "
			  "search->result.state %#x, "
			  "search->result.err %d\n",
			  search->result.start_index,
			  search->result.state,
			  search->result.err);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;

	case 1: /* range1 > range2 */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("range1 > range2\n");
#endif /* CONFIG_SSDFS_DEBUG */

		if (have_enough_space) {
			search->result.state =
				SSDFS_BTREE_SEARCH_OUT_OF_RANGE;
		} else {
			search->result.state =
				SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE;
		}

		search->result.err = -ENODATA;
		search->result.start_index = items_count;
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

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("search->result.start_index %u, "
			  "search->result.state %#x, "
			  "search->result.err %d\n",
			  search->result.start_index,
			  search->result.state,
			  search->result.err);
#endif /* CONFIG_SSDFS_DEBUG */

		return -ENODATA;

	default:
		BUG();
	}

	if (!RANGE_HAS_PARTIAL_INTERSECTION(search->request.start.hash,
					    search->request.end.hash,
					    start_hash, end_hash)) {
		SSDFS_ERR("invalid request: "
			  "request (start_hash %llx, end_hash %llx), "
			  "node (start_hash %llx, end_hash %llx)\n",
			  search->request.start.hash,
			  search->request.end.hash,
			  start_hash, end_hash);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_btree_node_find_item() - find the item in the node
 * @search: btree search object
 *
 * This method tries to find an item in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - node doesn't contain item for the requested hash.
 * %-ENOENT     - node hasn't the items area.
 * %-ENOSPC     - node hasn't free space.
 * %-EACCES     - node is under initialization yet.
 * %-EAGAIN     - search object contains obsolete result.
 * %-EOPNOTSUPP - specialized searching method doesn't been implemented
 */
int ssdfs_btree_node_find_item(struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL: "
			   "type %#x, flags %#x, "
			   "start_hash %llx, end_hash %llx, "
			   "state %#x, node_id %u, height %u, "
			   "parent %p, child %p\n",
			   search->request.type, search->request.flags,
			   search->request.start.hash, search->request.end.hash,
			   search->node.state, search->node.id,
			   search->node.height, search->node.parent,
			   search->node.child);
		if (!search->node.parent) {
			SSDFS_ERR("node_id %u, type %#x\n",
				  search->node.parent->node_id,
				  atomic_read(&search->node.parent->type));
		}

		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_NONE_CONTENT:
		err = ssdfs_btree_node_re_init_content(node);
		if (err)
			return err;
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_btree_search_node_desc_consistent(search)) {
		SSDFS_WARN("node descriptor is inconsistent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_result_for_search(search);
	if (err)
		return err;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   search->node.id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return -ERANGE;
	}

	if (!node->node_ops || !node->node_ops->find_item) {
		SSDFS_WARN("unable to search in the node\n");
		return -EOPNOTSUPP;
	}

	down_read(&node->full_lock);
	ssdfs_btree_node_start_request_cno(node);
	err = node->node_ops->find_item(node, search);
	ssdfs_btree_node_finish_request_cno(node);
	up_read(&node->full_lock);

	if (err == -ENODATA) {
		u16 items_count;
		u16 items_capacity;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u "
			  "hasn't item for request "
			  "(start_hash %llx, end_hash %llx)\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_ALLOCATE_ITEM:
		case SSDFS_BTREE_SEARCH_ADD_ITEM:
			down_read(&node->header_lock);
			items_count = node->items_area.items_count;
			items_capacity = node->items_area.items_capacity;
			up_read(&node->header_lock);

			if (items_count >= items_capacity) {
				err = -ENOSPC;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("node hasn't free space: "
					  "items_count %u, "
					  "items_capacity %u\n",
					  items_count,
					  items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
				search->result.err = -ENODATA;
			}
			break;

		default:
			search->result.err = err;
			break;
		}
	} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u "
			  "hasn't all items for request "
			  "(start_hash %llx, end_hash %llx)\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u "
			  "hasn't all items for request "
			  "(start_hash %llx, end_hash %llx)\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */
		search->result.err = err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find: "
			  "node %u, "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);

		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
	}

	return err;
}

/*
 * ssdfs_btree_node_find_range() - find the range in the node
 * @search: btree search object
 *
 * This method tries to find a range of items in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - node doesn't contain items for the requested range.
 * %-ENOENT     - node hasn't the items area.
 * %-ENOSPC     - node hasn't free space.
 * %-EACCES     - node is under initialization yet.
 * %-EAGAIN     - search object contains obsolete result.
 * %-EOPNOTSUPP - specialized searching method doesn't been implemented
 */
int ssdfs_btree_node_find_range(struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_NONE_CONTENT:
		err = ssdfs_btree_node_re_init_content(node);
		if (err)
			return err;
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_btree_search_node_desc_consistent(search)) {
		SSDFS_WARN("node descriptor is inconsistent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_result_for_search(search);
	if (err)
		return err;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   search->node.id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return -ERANGE;
	}

	if (!node->node_ops || !node->node_ops->find_range) {
		SSDFS_WARN("unable to search in the node\n");
		return -EOPNOTSUPP;
	}

	down_read(&node->full_lock);
	ssdfs_btree_node_start_request_cno(node);
	err = node->node_ops->find_range(node, search);
	ssdfs_btree_node_finish_request_cno(node);
	up_read(&node->full_lock);

	if (err == -ENODATA) {
		u16 items_count;
		u16 items_capacity;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u "
			  "hasn't item for request "
			  "(start_hash %llx, end_hash %llx)\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_ALLOCATE_ITEM:
		case SSDFS_BTREE_SEARCH_ADD_ITEM:
			down_read(&node->header_lock);
			items_count = node->items_area.items_count;
			items_capacity = node->items_area.items_capacity;
			up_read(&node->header_lock);

			if (items_count >= items_capacity) {
				err = -ENOSPC;
				search->result.err = -ENODATA;
			}
			break;

		default:
			search->result.err = err;
			break;
		}
	} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u "
			  "hasn't all items for request "
			  "(start_hash %llx, end_hash %llx)\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u "
			  "hasn't all items for request "
			  "(start_hash %llx, end_hash %llx)\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */
		search->result.err = err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find: "
			  "node %u, "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);

		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
	}

	return err;
}

/*
 * ssdfs_btree_node_check_result_for_alloc() - check search result for alloc
 * @search: btree search object
 */
static inline
int ssdfs_btree_node_check_result_for_alloc(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		return -EEXIST;

	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		/* expected state */
		break;

	default:
		SSDFS_WARN("invalid search result state %#x\n",
			   search->result.state);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_btree_node_allocate_item() - allocate the item in the node
 * @search: btree search object
 *
 * This method tries to allocate an item in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - item is used already.
 * %-ENOSPC     - item is out of node.
 * %-ENOENT     - node hasn't the items area.
 * %-EACCES     - node is under initialization yet.
 * %-EAGAIN     - search object contains obsolete result.
 */
int ssdfs_btree_node_allocate_item(struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_node *node;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
	BUG_ON(search->request.start.hash > search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#else
	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_btree_search_node_desc_consistent(search)) {
		SSDFS_WARN("node descriptor is inconsistent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_result_for_alloc(search);
	if (err)
		return err;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   search->node.id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return -ERANGE;
	}

	if (node->node_ops && node->node_ops->allocate_item) {
		ssdfs_btree_node_start_request_cno(node);
		err = node->node_ops->allocate_item(node, search);
		ssdfs_btree_node_finish_request_cno(node);

		if (unlikely(err)) {
			SSDFS_ERR("fail to allocate item: err %d\n",
				  err);
			search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
			search->result.search_cno = U64_MAX;
			search->result.start_index = U16_MAX;
			search->result.count = U16_MAX;
			return err;
		}
	} else
		return -EOPNOTSUPP;

	spin_lock(&node->descriptor_lock);
	search->result.search_cno = ssdfs_current_cno(fsi->sb);
	node->update_cno = search->result.search_cno;
	flags = le16_to_cpu(node->node_index.flags);
	flags &= ~SSDFS_BTREE_INDEX_SHOW_EMPTY_NODE;
	node->node_index.flags = cpu_to_le16(flags);
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node->update_cno %llu\n",
		  search->result.search_cno);
#endif /* CONFIG_SSDFS_DEBUG */

	set_ssdfs_btree_node_dirty(node);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_btree_node_allocate_range() - allocate the range in the node
 * @search: btree search object
 *
 * This method tries to allocate a range of items in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - range of items is used already.
 * %-ENOSPC     - range is out of node.
 * %-ENOENT     - node hasn't the items area.
 * %-EACCES     - node is under initialization yet.
 * %-EAGAIN     - search object contains obsolete result.
 */
int ssdfs_btree_node_allocate_range(struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_node *node;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
	BUG_ON(search->request.start.hash > search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#else
	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_btree_search_node_desc_consistent(search)) {
		SSDFS_WARN("node descriptor is inconsistent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_result_for_alloc(search);
	if (err)
		return err;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   search->node.id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return -ERANGE;
	}

	if (node->node_ops && node->node_ops->allocate_range) {
		ssdfs_btree_node_start_request_cno(node);
		err = node->node_ops->allocate_range(node, search);
		ssdfs_btree_node_finish_request_cno(node);

		if (unlikely(err)) {
			SSDFS_ERR("fail to allocate item: err %d\n",
				  err);
			search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
			search->result.search_cno = U64_MAX;
			search->result.start_index = U16_MAX;
			search->result.count = U16_MAX;
			return err;
		}
	} else
		return -EOPNOTSUPP;

	spin_lock(&node->descriptor_lock);
	search->result.search_cno = ssdfs_current_cno(fsi->sb);
	node->update_cno = search->result.search_cno;
	flags = le16_to_cpu(node->node_index.flags);
	flags &= ~SSDFS_BTREE_INDEX_SHOW_EMPTY_NODE;
	node->node_index.flags = cpu_to_le16(flags);
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node->update_cno %llu\n",
		  search->result.search_cno);
#endif /* CONFIG_SSDFS_DEBUG */

	set_ssdfs_btree_node_dirty(node);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_btree_node_check_result_for_insert() - check search result for insert
 * @search: btree search object
 */
static inline
int ssdfs_btree_node_check_result_for_insert(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		return -EEXIST;

	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		/* expected state */
		break;

	default:
		SSDFS_WARN("invalid search result state\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_btree_node_insert_item() - insert the item in the node
 * @search: btree search object
 *
 * This method tries to insert an item in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - item exists.
 * %-ENOSPC     - node hasn't free space.
 * %-EFBIG      - some items were pushed out from the node.
 * %-ENOENT     - node hasn't the items area.
 * %-EACCES     - node is under initialization yet.
 * %-EAGAIN     - search object contains obsolete result.
 * %-EOPNOTSUPP - specialized insert method doesn't been implemented
 */
int ssdfs_btree_node_insert_item(struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_node *node;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
	BUG_ON(search->request.start.hash > search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#else
	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_space %u\n", node->items_area.free_space);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_btree_search_node_desc_consistent(search)) {
		SSDFS_WARN("node descriptor is inconsistent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_result_for_insert(search);
	if (err)
		return err;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   search->node.id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return -ERANGE;
	}

	if (!node->node_ops || !node->node_ops->insert_item) {
		SSDFS_WARN("unable to insert item\n");
		return -EOPNOTSUPP;
	}

	ssdfs_btree_node_start_request_cno(node);
	err = node->node_ops->insert_item(node, search);
	ssdfs_btree_node_finish_request_cno(node);

	if (unlikely(err)) {
		SSDFS_ERR("fail to insert: "
			  "node %u, "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);

		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
		return err;
	}

	spin_lock(&node->descriptor_lock);
	search->result.search_cno = ssdfs_current_cno(fsi->sb);
	node->update_cno = search->result.search_cno;
	flags = le16_to_cpu(node->node_index.flags);
	flags &= ~SSDFS_BTREE_INDEX_SHOW_EMPTY_NODE;
	node->node_index.flags = cpu_to_le16(flags);
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node->update_cno %llu\n",
		  search->result.search_cno);
#endif /* CONFIG_SSDFS_DEBUG */

	set_ssdfs_btree_node_dirty(node);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_btree_node_insert_range() - insert the range in the node
 * @search: btree search object
 *
 * This method tries to insert a range of items in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't free space.
 * %-EFBIG      - some items were pushed out from the node.
 * %-ENOENT     - node hasn't the items area.
 * %-EACCES     - node is under initialization yet.
 * %-EAGAIN     - search object contains obsolete result.
 */
int ssdfs_btree_node_insert_range(struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_node *node;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
	BUG_ON(search->request.start.hash > search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#else
	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_btree_search_node_desc_consistent(search)) {
		SSDFS_WARN("node descriptor is inconsistent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_result_for_insert(search);
	if (err)
		return err;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   search->node.id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return -ERANGE;
	}

	if (!node->node_ops || !node->node_ops->insert_range) {
		SSDFS_WARN("unable to insert range\n");
		return -EOPNOTSUPP;
	}

	ssdfs_btree_node_start_request_cno(node);
	err = node->node_ops->insert_range(node, search);
	ssdfs_btree_node_finish_request_cno(node);

	if (unlikely(err)) {
		SSDFS_ERR("fail to insert: "
			  "node %u, "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);

		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
		return err;
	}

	spin_lock(&node->descriptor_lock);
	search->result.search_cno = ssdfs_current_cno(fsi->sb);
	node->update_cno = search->result.search_cno;
	flags = le16_to_cpu(node->node_index.flags);
	flags &= ~SSDFS_BTREE_INDEX_SHOW_EMPTY_NODE;
	node->node_index.flags = cpu_to_le16(flags);
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node->update_cno %llu\n",
		  search->result.search_cno);
#endif /* CONFIG_SSDFS_DEBUG */

	set_ssdfs_btree_node_dirty(node);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_btree_node_check_result_for_change() - check search result for change
 * @search: btree search object
 */
static inline
int ssdfs_btree_node_check_result_for_change(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		/* expected state */
		break;

	default:
		SSDFS_WARN("invalid search result state\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_btree_node_change_item() - change the item in the node
 * @search: btree search object
 *
 * This method tries to change an item in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - node doesn't contain the item.
 * %-ENOSPC     - the new item's state cannot be stored in the node.
 * %-ENOENT     - node hasn't the items area.
 * %-EACCES     - node is under initialization yet.
 * %-EAGAIN     - search object contains obsolete result.
 */
int ssdfs_btree_node_change_item(struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_node *node;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
	BUG_ON(search->request.start.hash > search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#else
	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_btree_search_node_desc_consistent(search)) {
		SSDFS_WARN("node descriptor is inconsistent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_result_for_change(search);
	if (err)
		return err;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   search->node.id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return -ERANGE;
	}

	if (!node->node_ops || !node->node_ops->change_item) {
		SSDFS_WARN("unable to change item\n");
		return -EOPNOTSUPP;
	}

	ssdfs_btree_node_start_request_cno(node);
	err = node->node_ops->change_item(node, search);
	ssdfs_btree_node_finish_request_cno(node);

	if (unlikely(err)) {
		SSDFS_ERR("fail to change item: "
			  "node %u, "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);

		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
		return err;
	}

	spin_lock(&node->descriptor_lock);
	search->result.search_cno = ssdfs_current_cno(fsi->sb);
	node->update_cno = search->result.search_cno;
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node->update_cno %llu\n",
		  search->result.search_cno);
#endif /* CONFIG_SSDFS_DEBUG */

	set_ssdfs_btree_node_dirty(node);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_btree_node_check_result_for_delete() - check search result for delete
 * @search: btree search object
 */
static inline
int ssdfs_btree_node_check_result_for_delete(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		/* expected state */
		break;

	default:
		SSDFS_WARN("invalid search result state\n");
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_btree_node_delete_item() - delete the item from the node
 * @search: btree search object
 *
 * This method tries to delete an item from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - node doesn't contain the item.
 * %-ENOENT     - node's items area is empty.
 * %-EACCES     - node is under initialization yet.
 * %-EAGAIN     - search object contains obsolete result.
 */
int ssdfs_btree_node_delete_item(struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_node *node;
	u16 items_count, index_count;
	bool is_node_empty = false;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
	BUG_ON(search->request.start.hash > search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#else
	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_btree_search_node_desc_consistent(search)) {
		SSDFS_WARN("node descriptor is inconsistent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_result_for_delete(search);
	if (err)
		return err;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   search->node.id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return -ERANGE;
	}

	if (!node->node_ops || !node->node_ops->delete_item) {
		SSDFS_WARN("unable to delete item\n");
		return -EOPNOTSUPP;
	}

	ssdfs_btree_node_start_request_cno(node);
	err = node->node_ops->delete_item(node, search);
	ssdfs_btree_node_finish_request_cno(node);

	if (unlikely(err)) {
		SSDFS_ERR("fail to delete item: "
			  "node %u, "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);

		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
		return err;
	}

	down_read(&node->header_lock);

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		items_count = node->items_area.items_count;
		break;

	default:
		items_count = 0;
		break;
	}

	switch (atomic_read(&node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		index_count = node->index_area.index_count;
		break;

	default:
		index_count = 0;
		break;
	}

	is_node_empty = index_count == 0 && items_count == 0;

	up_read(&node->header_lock);

	spin_lock(&node->descriptor_lock);
	search->result.search_cno = ssdfs_current_cno(fsi->sb);
	node->update_cno = search->result.search_cno;
	if (is_node_empty) {
		flags = le16_to_cpu(node->node_index.flags);
		flags = SSDFS_BTREE_INDEX_SHOW_EMPTY_NODE;
		node->node_index.flags = cpu_to_le16(flags);
	}
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node->update_cno %llu\n",
		  search->result.search_cno);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
		set_ssdfs_btree_node_pre_deleted(node);
		break;

	default:
		set_ssdfs_btree_node_dirty(node);
		break;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_btree_node_delete_range() - delete the range of items from the node
 * @search: btree search object
 *
 * This method tries to delete a range of items from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - node doesn't contain the range of items.
 * %-ENOENT     - node's items area is empty.
 * %-EACCES     - node is under initialization yet.
 * %-EAGAIN     - search object contains obsolete result.
 */
int ssdfs_btree_node_delete_range(struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_node *node;
	u16 items_count, index_count;
	bool is_node_empty = false;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
	BUG_ON(search->request.start.hash > search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#else
	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	if (!is_btree_search_node_desc_consistent(search)) {
		SSDFS_WARN("node descriptor is inconsistent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_check_result_for_delete(search);
	if (err)
		return err;

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   search->node.id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return -ERANGE;
	}

	if (!node->node_ops || !node->node_ops->delete_range) {
		SSDFS_WARN("unable to delete item\n");
		return -EOPNOTSUPP;
	}

	ssdfs_btree_node_start_request_cno(node);
	err = node->node_ops->delete_range(node, search);
	ssdfs_btree_node_finish_request_cno(node);

	if (unlikely(err)) {
		SSDFS_ERR("fail to delete range: "
			  "node %u, "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  node->node_id,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);

		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
		return err;
	}

	down_read(&node->header_lock);

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		items_count = node->items_area.items_count;
		break;

	default:
		items_count = 0;
		break;
	}

	switch (atomic_read(&node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		index_count = node->index_area.index_count;
		break;

	default:
		index_count = 0;
		break;
	}

	is_node_empty = index_count == 0 && items_count == 0;

	up_read(&node->header_lock);

	spin_lock(&node->descriptor_lock);
	search->result.search_cno = ssdfs_current_cno(fsi->sb);
	node->update_cno = search->result.search_cno;
	if (is_node_empty) {
		flags = le16_to_cpu(node->node_index.flags);
		flags = SSDFS_BTREE_INDEX_SHOW_EMPTY_NODE;
		node->node_index.flags = cpu_to_le16(flags);
	}
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node->update_cno %llu\n",
		  search->result.search_cno);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
		set_ssdfs_btree_node_pre_deleted(node);
		break;

	default:
		set_ssdfs_btree_node_dirty(node);
		break;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_btree_node_clear_range() - clear range of deleted items
 * @node: pointer on node object
 * @area: items area descriptor
 * @item_size: size of item in bytes
 * @start_index: starting index of item
 * @range_len: number of deleted items
 *
 * This method tries to clear the range of deleted items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int __ssdfs_btree_node_clear_range(struct ssdfs_btree_node *node,
				   struct ssdfs_btree_node_items_area *area,
				   size_t item_size,
				   u16 start_index,
				   unsigned int range_len)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	int dst_index;
	u32 item_offset;
	u16 cleared_items = 0;
	u32 offset_inside_folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_size %zu\n",
		  node->node_id, item_size);
	SSDFS_DBG("start_index %u, range_len %u\n",
		  start_index, range_len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (range_len == 0) {
		SSDFS_WARN("range_len == 0\n");
		return -ERANGE;
	}

	if ((start_index + range_len) > area->items_capacity) {
		SSDFS_ERR("range is out of capacity: "
			  "start_index %u, range_len %u, items_capacity %u\n",
			  start_index, range_len, area->items_capacity);
		return -ERANGE;
	}

	fsi = node->tree->fsi;
	dst_index = start_index;

	do {
		u32 clearing_items;
		u32 vacant_positions;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_index %u, dst_index %d\n",
			  start_index, dst_index);
#endif /* CONFIG_SSDFS_DEBUG */

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

		err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "item_offset %u, err %d\n",
				  item_offset, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		item_offset = folio.desc.offset_inside_page;

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

		SSDFS_DBG("clearing_items %u, item_offset %u\n",
			  clearing_items, item_offset);
#endif /* CONFIG_SSDFS_DEBUG */

		if ((item_offset + (clearing_items * item_size)) > PAGE_SIZE) {
			SSDFS_ERR("invalid request: "
				  "item_offset %u, clearing_items %u, "
				  "item_size %zu\n",
				  item_offset, clearing_items, item_size);
			return -ERANGE;
		}

		err = ssdfs_find_node_content_folio(&node->content, &folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find folio: err %d\n",
				  err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio_size(folio.ptr) == fsi->pagesize) {
			ssdfs_memset_folio(&folio, 0x0,
					   clearing_items * item_size);
		} else {
			offset_inside_folio =
				folio.desc.offset % folio_size(folio.ptr);

			__ssdfs_memset_folio(folio.ptr,
					     offset_inside_folio,
					     folio_size(folio.ptr),
					     0x0,
					     clearing_items * item_size);
		}

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
 * ssdfs_btree_node_clear_range() - clear range of deleted items
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
int ssdfs_btree_node_clear_range(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *area,
				size_t item_size,
				struct ssdfs_btree_search *search)
{
	u16 start_index;
	unsigned int range_len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_size %zu\n",
		  node->node_id, item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	start_index = search->result.start_index;
	range_len = search->request.count;

	return __ssdfs_btree_node_clear_range(node, area, item_size,
						start_index, range_len);
}

/*
 * ssdfs_btree_node_extract_range() - extract the range from the node
 * @start_index: starting index in the node
 * @count: count of items in the range
 * @search: btree search object
 *
 * This method tries to extract a range of items from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - node doesn't contain items for the requested range.
 * %-ENOENT     - node hasn't the items area.
 * %-EACCES     - node is under initialization yet.
 * %-EOPNOTSUPP - specialized extract method doesn't been implemented
 */
int ssdfs_btree_node_extract_range(u16 start_index, u16 count,
				   struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p, "
		  "start_index %u, count %u\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  search->node.state, search->node.id,
		  search->node.height, search->node.parent,
		  search->node.child, start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	node = search->node.child;
	if (!node) {
		SSDFS_WARN("child node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node->tree);
	BUG_ON(!rwsem_is_locked(&node->tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is under initialization\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EACCES;

	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   search->node.id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return -ERANGE;
	}

	if (!node->node_ops || !node->node_ops->extract_range) {
		SSDFS_WARN("unable to extract the range from the node\n");
		return -EOPNOTSUPP;
	}

	ssdfs_btree_node_start_request_cno(node);
	err = node->node_ops->extract_range(node, start_index, count, search);
	ssdfs_btree_node_finish_request_cno(node);

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u "
			  "hasn't item for request "
			  "(start_index %u, count %u)\n",
			  node->node_id,
			  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

		search->result.state = SSDFS_BTREE_SEARCH_EMPTY_RESULT;
		search->result.err = err;
	} else if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u hasn't items area\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to extract the range: "
			  "node %u, "
			  "request (start_index %u, count %u), "
			  "err %d\n",
			  node->node_id,
			  start_index, count, err);

		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
	}

	return err;
}

/*
 * __ssdfs_btree_node_move_items_range() - move range between nodes
 * @src: source node
 * @dst: destination node
 * @start_item: starting index of the item
 * @count: count of items in the range
 *
 * This method tries to move a range of items from @src node into
 * @dst node.
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
int __ssdfs_btree_node_move_items_range(struct ssdfs_btree_node *src,
					struct ssdfs_btree_node *dst,
					u16 start_item, u16 count)
{
	struct ssdfs_btree_search *search;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!src || !dst);

	SSDFS_DBG("src node_id %u, dst node_id %u, "
		  "start_item %u, count %u\n",
		  src->node_id, dst->node_id,
		  start_item, count);
#endif /* CONFIG_SSDFS_DEBUG */

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);

	if (!src->node_ops) {
		if (!src->node_ops->extract_range) {
			SSDFS_WARN("unable to extract the items range\n");
			return -EOPNOTSUPP;
		}

		if (!src->node_ops->delete_range) {
			SSDFS_WARN("unable to delete the items range\n");
			return -EOPNOTSUPP;
		}
	}

	if (!dst->node_ops) {
		if (!dst->node_ops->find_range) {
			SSDFS_WARN("unable to find the items range\n");
			return -EOPNOTSUPP;
		}

		if (!dst->node_ops->insert_range) {
			SSDFS_WARN("unable to insert the items range\n");
			return -EOPNOTSUPP;
		}
	}

	err = src->node_ops->extract_range(src, start_item, count, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract range: "
			  "node_id %u, start_item %u, "
			  "count %u, err %d\n",
			  src->node_id, start_item, count, err);
		goto finish_move_items_range;
	}

	ssdfs_debug_btree_search_object(search);

	if (count != search->result.count) {
		err = -ERANGE;
		SSDFS_ERR("invalid count (request %u, result %u)\n",
			  count, search->result.count);
		goto finish_move_items_range;
	}

	switch (src->tree->type) {
	case SSDFS_EXTENTS_BTREE:
	case SSDFS_XATTR_BTREE:
		search->request.flags |= SSDFS_BTREE_SEARCH_NOT_INVALIDATE;
		break;

	default:
		/* continue logic */
		break;
	}

	search->request.type = SSDFS_BTREE_SEARCH_DELETE_RANGE;

	err = src->node_ops->delete_range(src, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete range: "
			  "node_id %u, start_item %u, "
			  "count %u, err %d\n",
			  src->node_id, start_item, count, err);
		goto finish_move_items_range;
	}

	search->request.type = SSDFS_BTREE_SEARCH_ADD_RANGE;

	err = dst->node_ops->find_range(dst, search);
	if (err == -ENODATA) {
		err = 0;
		/*
		 * Node is empty. We are ready to insert.
		 */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find range: "
			  "node_id %u, err %d\n",
			  dst->node_id, err);
		goto finish_move_items_range;
	}

	err = dst->node_ops->insert_range(dst, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert range: "
			  "node_id %u, err %d\n",
			  dst->node_id, err);
		goto finish_move_items_range;
	}

finish_move_items_range:
	ssdfs_btree_search_free(search);
	return err;
}

/*
 * ssdfs_btree_node_move_items_range() - move items range
 * @src: source node
 * @dst: destination node
 * @start_item: startig index of the item
 * @count: count of items in the range
 *
 * This method tries to move the range of items from @src into @dst.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - items area is absent.
 * %-EOPNOTSUPP - btree doesn't support the items moving operation.
 */
int ssdfs_btree_node_move_items_range(struct ssdfs_btree_node *src,
				      struct ssdfs_btree_node *dst,
				      u16 start_item, u16 count)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!src || !dst);
	BUG_ON(!src->tree);
	BUG_ON(!rwsem_is_locked(&src->tree->lock));

	SSDFS_DBG("src node_id %u, dst node_id %u, "
		  "start_item %u, count %u\n",
		  src->node_id, dst->node_id,
		  start_item, count);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = src->tree->fsi;

	switch (atomic_read(&src->state)) {
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid src node state %#x\n",
			  atomic_read(&src->state));
		return -ERANGE;
	}

	switch (atomic_read(&dst->state)) {
	case SSDFS_BTREE_NODE_CREATED:
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid dst node state %#x\n",
			  atomic_read(&dst->state));
		return -ERANGE;
	}

	switch (atomic_read(&src->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   src->node_id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   src->node_id);
		return -ERANGE;
	}

	switch (atomic_read(&dst->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		SSDFS_WARN("items area is absent: node_id %u\n",
			   dst->node_id);
		return -ENOENT;

	default:
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   dst->node_id);
		return -ERANGE;
	}

	if (!src->node_ops) {
		SSDFS_WARN("unable to move the items range\n");
		return -EOPNOTSUPP;
	} else if (!src->node_ops->move_items_range) {
		ssdfs_btree_node_start_request_cno(src);
		ssdfs_btree_node_start_request_cno(dst);
		err = __ssdfs_btree_node_move_items_range(src, dst,
							  start_item, count);
		ssdfs_btree_node_finish_request_cno(src);
		ssdfs_btree_node_finish_request_cno(dst);
	} else {
		ssdfs_btree_node_start_request_cno(src);
		ssdfs_btree_node_start_request_cno(dst);
		err = src->node_ops->move_items_range(src, dst,
							start_item, count);
		ssdfs_btree_node_finish_request_cno(src);
		ssdfs_btree_node_finish_request_cno(dst);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to move the items range: "
			  "src node_id %u, dst node_id %u, "
			  "start_item %u, count %u\n",
			  src->node_id, dst->node_id,
			  start_item, count);
		return err;
	}

	ssdfs_set_node_update_cno(src);
	ssdfs_set_node_update_cno(dst);
	set_ssdfs_btree_node_dirty(src);
	set_ssdfs_btree_node_dirty(dst);

	return 0;
}

/*
 * ssdfs_copy_item_in_buffer() - copy item from node into buffer
 * @node: pointer on node object
 * @index: item index
 * @item_size: size of item in bytes
 * @search: pointer on search request object [in|out]
 *
 * This method tries to copy item from the node into buffer.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_copy_item_in_buffer(struct ssdfs_btree_node *node,
			      u16 index,
			      size_t item_size,
			      struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_state_bitmap *bmap;
	struct ssdfs_smart_folio folio;
	u32 area_offset;
	u32 area_size;
	u32 item_offset;
	u32 buf_offset;
	u32 offset_inside_folio;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, index %u\n",
		  node->node_id, index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	down_read(&node->header_lock);
	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	up_read(&node->header_lock);

	item_offset = (u32)index * item_size;
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

	err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "item_offset %u, err %d\n",
			  item_offset, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_LOCK_BMAP];

	down_read(&node->bmap_array.lock);

try_lock_area:
	spin_lock(&bmap->lock);

	err = bitmap_allocate_region(bmap->ptr, (unsigned int)index, 0);
	if (err == -EBUSY) {
		DEFINE_WAIT_FUNC(wait, woken_wake_function);

		err = 0;

		spin_unlock(&bmap->lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("waiting unlocked state of item %u\n",
			   index);
#endif /* CONFIG_SSDFS_DEBUG */

		add_wait_queue(&node->wait_queue, &wait);
		while (atomic_read(&node->bmap_array.locks_count) > 0) {
			if (signal_pending(current)) {
				break;
			} else {
				wait_woken(&wait, TASK_INTERRUPTIBLE,
					   SSDFS_DEFAULT_TIMEOUT);
			}
		}
		remove_wait_queue(&node->wait_queue, &wait);

		goto try_lock_area;
	}

	atomic_inc(&node->bmap_array.locks_count);

	spin_unlock(&bmap->lock);

	up_read(&node->bmap_array.lock);

	if (err) {
		SSDFS_ERR("fail to lock: index %u, err %d\n",
			  index, err);
		goto finish_copy_item;
	}

	if (!search->result.buf) {
		err = -ERANGE;
		SSDFS_ERR("buffer is not created\n");
		goto finish_copy_item;
	}

	buf_offset = search->result.items_in_buffer * item_size;

	err = ssdfs_find_node_content_folio(&node->content, &folio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find folio: err %d\n",
			  err);
		goto finish_copy_item;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio_size(folio.ptr) == fsi->pagesize) {
		err = ssdfs_memcpy_from_folio(search->result.buf,
				      buf_offset, search->result.buf_size,
				      &folio, item_size);
	} else {
		offset_inside_folio =
			folio.desc.offset % folio_size(folio.ptr);

		err = __ssdfs_memcpy_from_folio(search->result.buf,
						buf_offset,
						search->result.buf_size,
						folio.ptr,
						offset_inside_folio,
						folio_size(folio.ptr),
						item_size);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		goto unlock_area;
	}

	search->result.items_in_buffer++;

unlock_area:
	down_read(&node->bmap_array.lock);
	spin_lock(&bmap->lock);
	bitmap_clear(bmap->ptr, (unsigned int)index, 1);
	atomic_dec(&node->bmap_array.locks_count);
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);

	wake_up_all(&node->wait_queue);

finish_copy_item:
	if (unlikely(err))
		return err;

	return 0;
}

/*
 * ssdfs_lock_items_range() - lock range of items in the node
 * @node: pointer on node object
 * @start_index: start index of the range
 * @count: count of items in the range
 *
 * This method tries to lock range of items in the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOENT     - unable to lock the node's header
 * %-ENODATA    - unable to lock the range of items
 */
int ssdfs_lock_items_range(struct ssdfs_btree_node *node,
			   u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long start_area;
	int i = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("start_index %u, count %u\n",
		  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	start_area = node->bmap_array.item_start_bit;
	if (start_area == ULONG_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid items_area_start\n");
		goto finish_lock;
	}

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_LOCK_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("lock bitmap is empty\n");
		goto finish_lock;
	}

try_lock_area:
	spin_lock(&bmap->lock);

	for (; i < count; i++) {
		err = bitmap_allocate_region(bmap->ptr,
					     start_area + start_index + i, 0);
		if (err)
			break;
	}

	if (err == -EBUSY) {
		DEFINE_WAIT_FUNC(wait, woken_wake_function);

		err = 0;
		bitmap_clear(bmap->ptr, start_area + start_index, i);
		spin_unlock(&bmap->lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("waiting unlocked state of item %u\n",
			   start_index + i);
#endif /* CONFIG_SSDFS_DEBUG */

		add_wait_queue(&node->wait_queue, &wait);
		while (atomic_read(&node->bmap_array.locks_count) > 0) {
			if (signal_pending(current)) {
				break;
			} else {
				wait_woken(&wait, TASK_INTERRUPTIBLE,
					   SSDFS_DEFAULT_TIMEOUT);
			}
		}
		remove_wait_queue(&node->wait_queue, &wait);

		goto try_lock_area;
	}

	atomic_inc(&node->bmap_array.locks_count);

	spin_unlock(&bmap->lock);

finish_lock:
	up_read(&node->bmap_array.lock);

	return err;
}

/*
 * ssdfs_unlock_items_range() - unlock range of items in the node
 * @node: pointer on node object
 * @start_index: start index of the range
 * @count: count of items in the range
 */
void ssdfs_unlock_items_range(struct ssdfs_btree_node *node,
				u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long start_area;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("start_index %u, count %u\n",
		  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_LOCK_BMAP];
	start_area = node->bmap_array.item_start_bit;
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap->ptr);
	BUG_ON(start_area == ULONG_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&bmap->lock);
	bitmap_clear(bmap->ptr, start_area + start_index, count);
	atomic_dec(&node->bmap_array.locks_count);
	spin_unlock(&bmap->lock);

	up_read(&node->bmap_array.lock);
	wake_up_all(&node->wait_queue);
}

/*
 * ssdfs_allocate_items_range() - allocate range of items in bitmap
 * @node: pointer on node object
 * @search: pointer on search request object
 * @items_capacity: items capacity in the node
 * @start_index: start index of the range
 * @count: count of items in the range
 *
 * This method tries to allocate range of items in bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EEXIST     - range is allocated already.
 */
int ssdfs_allocate_items_range(struct ssdfs_btree_node *node,
				struct ssdfs_btree_search *search,
				u16 items_capacity,
				u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long found = ULONG_MAX;
	unsigned long start_area;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("items_capacity %u, start_index %u, count %u\n",
		  items_capacity, start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	start_area = node->bmap_array.item_start_bit;
	if (start_area == ULONG_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid items_area_start\n");
		goto finish_allocate_items_range;
	}

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("alloc bitmap is empty\n");
		goto finish_allocate_items_range;
	}

	spin_lock(&bmap->lock);

	found = bitmap_find_next_zero_area(bmap->ptr,
					   start_area + items_capacity,
					   start_area + start_index,
					   count, 0);
	if (search->request.flags & SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE &&
	    found != (start_area + start_index)) {
		/* area is allocated already */
		err = -EEXIST;
	}

	if (!err)
		bitmap_set(bmap->ptr, found, count);

	spin_unlock(&bmap->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("found %lu, start_area %lu, start_index %u\n",
		  found, start_area, start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_ERR("found %lu != start %lu\n",
			  found, start_area + start_index);
	}

finish_allocate_items_range:
	up_read(&node->bmap_array.lock);

	return err;
}

/*
 * is_ssdfs_node_items_range_allocated() - check that range is allocated
 * @node: pointer on node object
 * @items_capacity: items capacity in the node
 * @start_index: start index of the range
 * @count: count of items in the range
 */
bool is_ssdfs_node_items_range_allocated(struct ssdfs_btree_node *node,
					 u16 items_capacity,
					 u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long found = ULONG_MAX;
	unsigned long start_area;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("start_index %u, count %u\n",
		  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	start_area = node->bmap_array.item_start_bit;
	BUG_ON(start_area == ULONG_MAX);

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP];
	if (!bmap->ptr)
		BUG();

	spin_lock(&bmap->lock);
	found = bitmap_find_next_zero_area(bmap->ptr,
					   start_area + items_capacity,
					   start_area + start_index, count, 0);
	if (found != (start_area + start_index)) {
		/* area is allocated already */
		err = -EEXIST;
	}
	spin_unlock(&bmap->lock);

	up_read(&node->bmap_array.lock);

	if (err == -EEXIST)
		return true;

	return false;
}

/*
 * ssdfs_free_items_range() - free range of items in bitmap
 * @node: pointer on node object
 * @start_index: start index of the range
 * @count: count of items in the range
 *
 * This method tries to free the range of items in bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_free_items_range(struct ssdfs_btree_node *node,
			   u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long start_area;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("start_index %u, count %u\n",
		  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	start_area = node->bmap_array.item_start_bit;
	if (start_area == ULONG_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid items_area_start\n");
		goto finish_free_items_range;
	}

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("alloc bitmap is empty\n");
		goto finish_free_items_range;
	}

	spin_lock(&bmap->lock);
	bitmap_clear(bmap->ptr, start_area + start_index, count);
	spin_unlock(&bmap->lock);

finish_free_items_range:
	up_read(&node->bmap_array.lock);

	return err;
}

/*
 * ssdfs_set_node_header_dirty() - mark the node's header as dirty
 * @node: pointer on node object
 * @items_capacity: items capacity in the node
 *
 * This method tries to mark the node's header as dirty.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_set_node_header_dirty(struct ssdfs_btree_node *node,
				u16 items_capacity)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long found = ULONG_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, items_capacity %u\n",
		  node->node_id, items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_set_header_dirty;
	}

	spin_lock(&bmap->lock);

	found = bitmap_find_next_zero_area(bmap->ptr, items_capacity,
					    SSDFS_BTREE_NODE_HEADER_INDEX,
					    1, 0);
	if (found == SSDFS_BTREE_NODE_HEADER_INDEX)
		bitmap_set(bmap->ptr, found, 1);

	spin_unlock(&bmap->lock);

finish_set_header_dirty:
	up_read(&node->bmap_array.lock);

	return err;
}

/*
 * ssdfs_clear_node_header_dirty_state() - clear node's header dirty state
 * @node: pointer on node object
 *
 * This method tries to clear the node's header dirty state.
 */
void ssdfs_clear_node_header_dirty_state(struct ssdfs_btree_node *node)
{
	struct ssdfs_state_bitmap *bmap;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	if (!bmap->ptr)
		BUG();

	spin_lock(&bmap->lock);
	bitmap_clear(bmap->ptr, SSDFS_BTREE_NODE_HEADER_INDEX, 1);
	spin_unlock(&bmap->lock);

	up_read(&node->bmap_array.lock);
}

/*
 * ssdfs_set_dirty_items_range() - mark the range of items as dirty
 * @node: pointer on node object
 * @items_capacity: items capacity in the node
 * @start_index: start index of the range
 * @count: count of items in the range
 *
 * This method tries to mark the range of items as dirty.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_set_dirty_items_range(struct ssdfs_btree_node *node,
				u16 items_capacity,
				u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long found = ULONG_MAX;
	unsigned long start_area;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("items_capacity %u, start_index %u, count %u\n",
		  items_capacity, start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	start_area = node->bmap_array.item_start_bit;
	if (start_area == ULONG_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid items_area_start\n");
		goto finish_set_dirty_items;
	}

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	if (!bmap->ptr) {
		err = -ERANGE;
		SSDFS_WARN("dirty bitmap is empty\n");
		goto finish_set_dirty_items;
	}

	spin_lock(&bmap->lock);

	found = bitmap_find_next_zero_area(bmap->ptr,
					   start_area + items_capacity,
					   start_area + start_index,
					   count, 0);
	if (found != (start_area + start_index)) {
		/* area is dirty already */
		err = -EEXIST;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("set bit: start_area %lu, start_index %u, len %u\n",
		  start_area, start_index, count);

	SSDFS_DBG("BMAP DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     bmap->ptr,
			     node->bmap_array.bmap_bytes);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	bitmap_set(bmap->ptr, start_area + start_index, count);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("BMAP DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     bmap->ptr,
			     node->bmap_array.bmap_bytes);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	spin_unlock(&bmap->lock);

	if (unlikely(err)) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found %lu != start %lu\n",
			  found, start_area + start_index);
#endif /* CONFIG_SSDFS_DEBUG */
	}

finish_set_dirty_items:
	up_read(&node->bmap_array.lock);

	if (!err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u, tree_type %#x, "
			  "start_index %u, count %u\n",
			  node->node_id, node->tree->type,
			  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return err;
}

/*
 * ssdfs_clear_dirty_items_range_state() - clear items range's dirty state
 * @node: pointer on node object
 * @start_index: start index of the range
 * @count: count of items in the range
 *
 * This method tries to clear the range of items' dirty state.
 */
void ssdfs_clear_dirty_items_range_state(struct ssdfs_btree_node *node,
					 u16 start_index, u16 count)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long start_area;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("start_index %u, count %u\n",
		  start_index, count);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->bmap_array.lock);

	start_area = node->bmap_array.item_start_bit;
	BUG_ON(start_area == ULONG_MAX);

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	BUG_ON(!bmap->ptr);

	spin_lock(&bmap->lock);
	bitmap_clear(bmap->ptr, start_area + start_index, count);
	spin_unlock(&bmap->lock);

	up_read(&node->bmap_array.lock);
}

/*
 * is_last_leaf_node_found() - check that found leaf node is the last
 * @search: pointer on search object
 */
bool is_last_leaf_node_found(struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *parent;
	u64 leaf_end_hash;
	u64 index_end_hash;
	int node_type = SSDFS_BTREE_LEAF_NODE;
	spinlock_t * lock;
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);

	SSDFS_DBG("start_hash %llx, end_hash %llx, node_id %u\n",
		  search->request.start.hash,
		  search->request.end.hash,
		  search->node.id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!search->node.child) {
		SSDFS_WARN("empty child node pointer\n");
		return false;
	}

	if (!search->node.parent) {
		SSDFS_WARN("empty parent node pointer\n");
		return false;
	}

	switch (atomic_read(&search->node.child->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_WARN("invalid area state %#x\n",
			   atomic_read(&search->node.child->items_area.state));
		return false;
	}

	down_read(&search->node.child->header_lock);
	leaf_end_hash = search->node.child->items_area.end_hash;
	up_read(&search->node.child->header_lock);

	if (leaf_end_hash >= U64_MAX) {
		SSDFS_WARN("leaf node end_hash %llx\n",
			   leaf_end_hash);
		return false;
	}

	parent = search->node.parent;

	do {
		if (!parent) {
			SSDFS_WARN("empty parent node pointer\n");
			return false;
		}

		node_type = atomic_read(&parent->type);

		switch (node_type) {
		case SSDFS_BTREE_ROOT_NODE:
		case SSDFS_BTREE_INDEX_NODE:
		case SSDFS_BTREE_HYBRID_NODE:
			state = atomic_read(&parent->index_area.state);

			switch (state) {
			case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
				/* expected state */
				break;

			default:
				SSDFS_WARN("invalid area state %#x\n",
					   state);
				return false;
			}

			down_read(&parent->header_lock);
			index_end_hash = parent->index_area.end_hash;
			up_read(&parent->header_lock);

			if (index_end_hash >= U64_MAX) {
				SSDFS_WARN("index area: end hash %llx\n",
					   index_end_hash);
				return false;
			}

			if (leaf_end_hash < index_end_hash) {
				/* internal node */
				return false;
			}
			break;

		default:
			SSDFS_WARN("invalid node type %#x\n",
				   node_type);
			return false;
		}

		lock = &parent->descriptor_lock;
		spin_lock(lock);
		parent = parent->parent_node;
		spin_unlock(lock);
		lock = NULL;
	} while (node_type != SSDFS_BTREE_ROOT_NODE);

	return true;
}

/*
 * ssdfs_btree_node_find_lookup_index_nolock() - find lookup index
 * @search: search object
 * @lookup_table: lookup table
 * @table_capacity: capacity of the lookup table
 * @lookup_index: lookup index [out]
 *
 * This method tries to find a lookup index for requested items.
 * It needs to lock the lookup table before calling this method.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - lookup index doesn't exist for requested hash.
 */
int
ssdfs_btree_node_find_lookup_index_nolock(struct ssdfs_btree_search *search,
					  __le64 *lookup_table,
					  int table_capacity,
					  u16 *lookup_index)
{
	u64 hash;
	u64 lower_bound, upper_bound;
	int index;
	int lower_index, upper_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !lookup_table || !lookup_index);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "lookup_table %p, table_capacity %d\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  lookup_table, table_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	*lookup_index = U16_MAX;
	hash = search->request.start.hash;

	if (hash >= U64_MAX) {
		SSDFS_ERR("invalid hash for search\n");
		return -ERANGE;
	}

	lower_index = 0;
	lower_bound = le64_to_cpu(lookup_table[lower_index]);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lower_index %d, lower_bound %llu\n",
		  lower_index, lower_bound);
#endif /* CONFIG_SSDFS_DEBUG */

	if (lower_bound >= U64_MAX) {
		err = -ENODATA;
		*lookup_index = lower_index;
		goto finish_index_search;
	} else if (hash < lower_bound) {
		err = -ENODATA;
		*lookup_index = lower_index;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("hash %llx < lower_bound %llx\n",
			  hash, lower_bound);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_index_search;
	} else if (hash == lower_bound) {
		err = -EEXIST;
		*lookup_index = lower_index;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("hash %llx == lower_bound %llx\n",
			  hash, lower_bound);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_index_search;
	}

	upper_index = table_capacity - 1;
	upper_bound = le64_to_cpu(lookup_table[upper_index]);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("upper_index %d, upper_bound %llu\n",
		  upper_index, upper_bound);
#endif /* CONFIG_SSDFS_DEBUG */

	if (upper_bound >= U64_MAX) {
		/*
		 * continue to search
		 */
	} else if (hash == upper_bound) {
		err = -EEXIST;
		*lookup_index = upper_index;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("hash %llx == upper_bound %llx\n",
			  hash, upper_bound);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_index_search;
	} else if (hash > upper_bound) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("hash %llx > upper_bound %llx\n",
			  hash, upper_bound);
#endif /* CONFIG_SSDFS_DEBUG */
		*lookup_index = upper_index;
		goto finish_index_search;
	}

	do {
		int diff = upper_index - lower_index;

		index = lower_index + (diff / 2);

		lower_bound = le64_to_cpu(lookup_table[index]);
		upper_bound = le64_to_cpu(lookup_table[index + 1]);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %d, lower_index %d, upper_index %d, "
			  "lower_bound %llx, upper_bound %llx\n",
			  index, lower_index, upper_index,
			  lower_bound, upper_bound);
#endif /* CONFIG_SSDFS_DEBUG */

		if (lower_bound >= U64_MAX)
			upper_index = index;
		else if (hash < lower_bound)
			upper_index = index;
		else if (hash == lower_bound) {
			err = -EEXIST;
			*lookup_index = index;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("hash %llx == lower_bound %llx\n",
				  hash, lower_bound);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_index_search;
		}

		if (lower_bound < hash && upper_bound >= U64_MAX) {
			err = 0;
			*lookup_index = index;
			goto finish_index_search;
		} else if (lower_bound < hash && hash < upper_bound) {
			err = 0;
			lower_index = index;
		} else if (hash == upper_bound) {
			err = -EEXIST;
			*lookup_index = index;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("hash %llx == upper_bound %llx\n",
				  hash, upper_bound);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_index_search;
		} else if (hash > upper_bound)
			lower_index = index;
	} while ((upper_index - lower_index) > 1);

	if ((upper_index - lower_index) > 1) {
		err = -ERANGE;
		SSDFS_ERR("lower_index %d, upper_index %d\n",
			  lower_index, upper_index);
		goto finish_index_search;
	}

	*lookup_index = lower_index;

finish_index_search:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lookup_index %u\n", *lookup_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (err == -EEXIST) {
		/* index found */
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(*lookup_index >= table_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	return err;
}

/*
 * __ssdfs_extract_range_by_lookup_index() - extract a range of items
 * @node: pointer on node object
 * @lookup_index: lookup index for requested range
 * @lookup_table_capacity: maximal number of items in lookup table
 * @item_size: size of item in bytes
 * @search: pointer on search request object
 * @check_item: specialized method of checking item
 * @prepare_buffer: specialized method of buffer preparing
 * @get_hash_range: specialized method of getting hash range
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
int __ssdfs_extract_range_by_lookup_index(struct ssdfs_btree_node *node,
				u16 lookup_index,
				int lookup_table_capacity,
				size_t item_size,
				struct ssdfs_btree_search *search,
				ssdfs_check_found_item check_item,
				ssdfs_prepare_result_buffer prepare_buffer,
				ssdfs_extract_found_item extract_item)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_state_bitmap *bmap;
	struct ssdfs_smart_folio folio;
	void *kaddr;
	u16 index, found_index;
	u16 items_count;
	u32 area_offset;
	u32 area_size;
	u32 item_offset;
	u64 start_hash = U64_MAX;
	u64 end_hash = U64_MAX;
	unsigned long start_index;
	u32 page_offset;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi || !search);
	BUG_ON(lookup_index >= lookup_table_capacity);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %d, node_id %u, height %d, "
		  "lookup_index %u\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height),
		  lookup_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	down_read(&node->header_lock);
	area_offset = node->items_area.offset;
	area_size = node->items_area.area_size;
	items_count = node->items_area.items_count;
	up_read(&node->header_lock);

	if (items_count == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node_id %u is empty\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	found_index = U16_MAX;
	index = __ssdfs_convert_lookup2item_index(lookup_index,
						  node->node_size,
						  item_size,
						  lookup_table_capacity);
	if (index >= items_count) {
		err = -ERANGE;
		SSDFS_ERR("index %u >= items_count %u\n",
			  index, items_count);
		return err;
	}

	down_read(&node->full_lock);

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_LOCK_BMAP];

	if (found_index != U16_MAX)
		goto try_extract_range;

	for (; index < items_count; index++) {
		item_offset = (u32)index * item_size;
		if (item_offset >= area_size) {
			err = -ERANGE;
			SSDFS_ERR("item_offset %u >= area_size %u\n",
				  item_offset, area_size);
			goto finish_extract_range;
		}

		item_offset += area_offset;
		if (item_offset >= node->node_size) {
			err = -ERANGE;
			SSDFS_ERR("item_offset %u >= node_size %u\n",
				  item_offset, node->node_size);
			goto finish_extract_range;
		}

		err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "item_offset %u, err %d\n",
				  item_offset, err);
			goto finish_extract_range;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		item_offset = folio.desc.offset_inside_page;

		err = ssdfs_find_node_content_folio(&node->content, &folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find folio: err %d\n", err);
			goto finish_extract_range;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		down_read(&node->bmap_array.lock);

try_lock_checking_item:
		spin_lock(&bmap->lock);

		start_index = node->bmap_array.item_start_bit + index;
		err = bitmap_allocate_region(bmap->ptr,
					     (unsigned int)start_index, 0);
		if (err == -EBUSY) {
			DEFINE_WAIT_FUNC(wait, woken_wake_function);

			err = 0;

			spin_unlock(&bmap->lock);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("waiting unlocked state of item %lu\n",
				   start_index);
#endif /* CONFIG_SSDFS_DEBUG */

			add_wait_queue(&node->wait_queue, &wait);
			while (atomic_read(&node->bmap_array.locks_count) > 0) {
				if (signal_pending(current)) {
					break;
				} else {
					wait_woken(&wait, TASK_INTERRUPTIBLE,
						   SSDFS_DEFAULT_TIMEOUT);
				}
			}
			remove_wait_queue(&node->wait_queue, &wait);

			goto try_lock_checking_item;
		}

		atomic_inc(&node->bmap_array.locks_count);

		spin_unlock(&bmap->lock);

		up_read(&node->bmap_array.lock);

		if (err) {
			SSDFS_ERR("fail to lock: index %lu, err %d\n",
				  start_index, err);
			goto finish_extract_range;
		}

		if ((item_offset + item_size) > PAGE_SIZE) {
			err = -ERANGE;
			SSDFS_ERR("invalid offset: "
				  "item_offset %u, item_size %zu\n",
				  item_offset, item_size);
			goto finish_extract_range;
		}

		if (folio_size(folio.ptr) == fsi->pagesize) {
			page_offset = folio.desc.page_offset;
		} else {
			page_offset =
			    SSDFS_PAGE_OFFSET_IN_FOLIO(folio_size(folio.ptr),
							   folio.desc.offset);
		}

		kaddr = kmap_local_folio(folio.ptr, page_offset);
		err = check_item(fsi, search,
				 (u8 *)kaddr + item_offset,
				 index,
				 &start_hash, &end_hash,
				 &found_index);
		kunmap_local(kaddr);

		down_read(&node->bmap_array.lock);
		spin_lock(&bmap->lock);
		bitmap_clear(bmap->ptr, (unsigned int)start_index, 1);
		atomic_dec(&node->bmap_array.locks_count);
		spin_unlock(&bmap->lock);
		up_read(&node->bmap_array.lock);

		wake_up_all(&node->wait_queue);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("requested (start_hash %llx, end_hash %llx), "
			  "start_hash %llx, end_hash %llx, "
			  "index %u, found_index %u, err %d\n",
			  search->request.start.hash, search->request.end.hash,
			  start_hash, end_hash, index, found_index, err);
#endif /* CONFIG_SSDFS_DEBUG */

		if (err == -EAGAIN)
			continue;
		else if (unlikely(err))
			goto finish_extract_range;
		else if (found_index != U16_MAX)
			break;
	}

	if (err == -EAGAIN) {
		if (found_index >= U16_MAX) {
			SSDFS_ERR("fail to find index\n");
			goto finish_extract_range;
		} else if (found_index == items_count) {
			err = 0;
			found_index = items_count - 1;
		} else {
			err = -ERANGE;
			SSDFS_ERR("fail to find index\n");
			goto finish_extract_range;
		}
	}

	if (found_index > items_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found_index %u, items_count %u\n",
			  found_index, items_count);
#endif /* CONFIG_SSDFS_DEBUG */

		err = -ENODATA;
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = -ENODATA;
		search->result.start_index = items_count;
		search->result.count = 1;
		goto finish_extract_range;
	} else if (is_btree_search_contains_new_item(search)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found_index %u, items_count %u\n",
			  found_index, items_count);
#endif /* CONFIG_SSDFS_DEBUG */

		err = -ENODATA;
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = -ENODATA;
		search->result.start_index = found_index;
		search->result.count = 0;
		goto finish_extract_range;
	} else {
		err = prepare_buffer(search, found_index,
				     search->request.start.hash,
				     search->request.end.hash,
				     items_count, item_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare buffers: "
				  "requested (start_hash %llx, end_hash %llx), "
				  "found_index %u, start_hash %llx, "
				  "end_hash %llx, items_count %u, "
				  "item_size %zu, err %d\n",
				  search->request.start.hash,
				  search->request.end.hash,
				  found_index, start_hash, end_hash,
				  items_count, item_size, err);
			goto finish_extract_range;
		}

		search->result.start_index = found_index;
		search->result.count = 0;
	}

try_extract_range:
	for (; found_index < items_count; found_index++) {
		item_offset = (u32)found_index * item_size;
		if (item_offset >= area_size) {
			err = -ERANGE;
			SSDFS_ERR("item_offset %u >= area_size %u\n",
				  item_offset, area_size);
			goto finish_extract_range;
		}

		item_offset += area_offset;
		if (item_offset >= node->node_size) {
			err = -ERANGE;
			SSDFS_ERR("item_offset %u >= node_size %u\n",
				  item_offset, node->node_size);
			goto finish_extract_range;
		}

		err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "item_offset %u, err %d\n",
				  item_offset, err);
			goto finish_extract_range;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		item_offset = folio.desc.offset_inside_page;

		err = ssdfs_find_node_content_folio(&node->content, &folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find folio: err %d\n", err);
			goto finish_extract_range;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		down_read(&node->bmap_array.lock);

try_lock_extracting_item:
		spin_lock(&bmap->lock);

		start_index = node->bmap_array.item_start_bit + found_index;
		err = bitmap_allocate_region(bmap->ptr,
					     (unsigned int)start_index, 0);
		if (err == -EBUSY) {
			DEFINE_WAIT_FUNC(wait, woken_wake_function);

			err = 0;

			spin_unlock(&bmap->lock);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("waiting unlocked state of item %lu\n",
				   start_index);
#endif /* CONFIG_SSDFS_DEBUG */

			add_wait_queue(&node->wait_queue, &wait);
			while (atomic_read(&node->bmap_array.locks_count) > 0) {
				if (signal_pending(current)) {
					break;
				} else {
					wait_woken(&wait, TASK_INTERRUPTIBLE,
						   SSDFS_DEFAULT_TIMEOUT);
				}
			}
			remove_wait_queue(&node->wait_queue, &wait);

			goto try_lock_extracting_item;
		}

		atomic_inc(&node->bmap_array.locks_count);

		spin_unlock(&bmap->lock);

		up_read(&node->bmap_array.lock);

		if (err) {
			SSDFS_ERR("fail to lock: index %lu, err %d\n",
				  start_index, err);
			goto finish_extract_range;
		}

		if ((item_offset + item_size) > PAGE_SIZE) {
			err = -ERANGE;
			SSDFS_ERR("invalid offset: "
				  "item_offset %u, item_size %zu\n",
				  item_offset, item_size);
			goto finish_extract_range;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("item_offset %u, item_size %zu\n",
			  item_offset, item_size);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio_size(folio.ptr) == fsi->pagesize) {
			page_offset = folio.desc.page_offset;
		} else {
			page_offset =
			    SSDFS_PAGE_OFFSET_IN_FOLIO(folio_size(folio.ptr),
							   folio.desc.offset);
		}

		kaddr = kmap_local_folio(folio.ptr, page_offset);
		err = extract_item(fsi, search, item_size,
				   (u8 *)kaddr + item_offset,
				   &start_hash, &end_hash);
		kunmap_local(kaddr);

		down_read(&node->bmap_array.lock);
		spin_lock(&bmap->lock);
		bitmap_clear(bmap->ptr, (unsigned int)start_index, 1);
		atomic_dec(&node->bmap_array.locks_count);
		spin_unlock(&bmap->lock);
		up_read(&node->bmap_array.lock);

		wake_up_all(&node->wait_queue);

		if (err == -ENODATA && search->result.count > 0) {
			err = 0;
			search->result.err = 0;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("stop search: "
				  "found_index %u, start_hash %llx, "
				  "end_hash %llx, search->request.end.hash %llx\n",
				  found_index, start_hash, end_hash,
				  search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

			goto finish_extract_range;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to extract item: "
				  "kaddr %p, item_offset %u, err %d\n",
				  kaddr, item_offset, err);
			goto finish_extract_range;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found_index %u, start_hash %llx, "
			  "end_hash %llx, search->request.end.hash %llx\n",
			  found_index, start_hash, end_hash,
			  search->request.end.hash);
#endif /* CONFIG_SSDFS_DEBUG */

		if (search->request.end.hash <= end_hash)
			break;
	}

	if (search->request.end.hash > end_hash)
		err = -EAGAIN;

finish_extract_range:
	up_read(&node->full_lock);

	if (err == -ENODATA || err == -EAGAIN) {
		/*
		 * do nothing
		 */
		search->result.err = err;
	} else if (unlikely(err)) {
		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
	}

	return err;
}

/*
 * ssdfs_calculate_item_offset() - calculate item's offset
 * @node: pointer on node object
 * @area_offset: area offset in bytes from the node's beginning
 * @area_size: area size in bytes
 * @index: item's index in the node
 * @item_size: size of item in bytes
 * @desc: offset to folio descriptor [out]
 * @item_offset: offset in bytes from a page's beginning [out]
 *
 * This method tries to calculate item's offset in a page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_calculate_item_offset(struct ssdfs_btree_node *node,
				u32 area_offset, u32 area_size,
				int index, size_t item_size,
				struct ssdfs_offset2folio *desc,
				u32 *item_offset)
{
	struct ssdfs_fs_info *fsi;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !desc || !item_offset);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, area_offset %u, area_size %u, "
		  "item_size %zu, index %d\n",
		  node->node_id, area_offset, area_size,
		  item_size, index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	*item_offset = (u32)index * item_size;
	if (*item_offset >= area_size) {
		SSDFS_ERR("item_offset %u >= area_size %u\n",
			  *item_offset, area_size);
		return -ERANGE;
	}

	*item_offset += area_offset;
	if (*item_offset >= node->node_size) {
		SSDFS_ERR("item_offset %u >= node_size %u\n",
			  *item_offset, node->node_size);
		return -ERANGE;
	}

	err = SSDFS_OFF2FOLIO(fsi->pagesize, *item_offset, desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "item_offset %u, err %d\n",
			  *item_offset, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	if (desc->folio_index >= node->content.count) {
		SSDFS_ERR("invalid folio_index: "
			  "index %d, blks_count %u\n",
			  desc->folio_index,
			  node->content.count);
		return -ERANGE;
	}

	*item_offset = desc->offset_inside_page;

	return 0;
}

/*
 * ssdfs_move_memory_range_now() - move memory range now
 * @node: pointer on node object
 * @dst_folio: destination smart folio
 * @src_folio: source smart folio
 * @moving_bytes: moving bytes number
 *
 * This method tries to move memory range right now.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_move_memory_range_now(struct ssdfs_btree_node *node,
				struct ssdfs_smart_folio *dst_folio,
				struct ssdfs_smart_folio *src_folio,
				u32 moving_bytes)
{
	u32 src_off, dst_off;
	u32 index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !src_folio || !dst_folio);
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&src_folio->desc));
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&dst_folio->desc));

	SSDFS_DBG("blks_count %u, SOURCE: (folio_index %d, "
		  "page_in_folio %u, offset_inside_page %u), "
		  "DESTINATION: (folio_index %d, page_in_folio %d, "
		  "offset_inside_page %u), moving_bytes %u\n",
		  node->content.count,
		  src_folio->desc.folio_index,
		  src_folio->desc.page_in_folio,
		  src_folio->desc.offset_inside_page,
		  dst_folio->desc.folio_index,
		  dst_folio->desc.page_in_folio,
		  dst_folio->desc.offset_inside_page,
		  moving_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	src_off = src_folio->desc.offset - src_folio->desc.folio_offset;
	dst_off = dst_folio->desc.offset - dst_folio->desc.folio_offset;

	if (src_folio->desc.folio_index == dst_folio->desc.folio_index) {
		struct ssdfs_content_block *blk;

		index = src_folio->desc.folio_index;
		blk = &node->content.blocks[index];

		err = ssdfs_memmove_inside_batch(&blk->batch,
						 dst_off, src_off,
						 moving_bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: err %d\n", err);
			return err;
		}
	} else {
		struct ssdfs_content_block *src_blk;
		struct ssdfs_content_block *dst_blk;

		index = src_folio->desc.folio_index;
		src_blk = &node->content.blocks[index];

		index = dst_folio->desc.folio_index;
		dst_blk = &node->content.blocks[index];

		err = ssdfs_memcpy_batch2batch(&dst_blk->batch, dst_off,
						&src_blk->batch, src_off,
						moving_bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_calculate_index_distance() - calculate index distance
 * @node: pointer on node object
 * @area_offset: area offset in bytes from the node's beginning
 * @area_size: area size in bytes
 * @item_size: size of item in bytes
 * @index: current index of the item
 *
 * This method tries to calculate index count from page
 * or area beginning to the current index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
u16 ssdfs_calculate_index_distance(struct ssdfs_btree_node *node,
				   u32 area_offset, u32 area_size,
				   size_t item_size, u32 index)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	u32 item_offset;
	u32 page_start_offset;
	u32 offset_diff;
	u32 index_diff;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, area_offset %u, area_size %u, "
		  "item_size %zu, index %u\n",
		  node->node_id, area_offset,
		  area_size, item_size, index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	item_offset = index * item_size;
	if (item_offset >= area_size) {
		SSDFS_ERR("item_offset %u >= area_size %u\n",
			  item_offset, area_size);
		return U16_MAX;
	}

	item_offset += area_offset;
	if (item_offset >= node->node_size) {
		SSDFS_ERR("item_offset %u >= node_size %u\n",
			  item_offset, node->node_size);
		return U16_MAX;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("item_offset %u\n", item_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset,
			      &folio.desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to convert offset into folio: "
			  "item_offset %u, err %d\n",
			  item_offset, err);
		return U16_MAX;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

	if (folio.desc.folio_index >= node->content.count) {
		SSDFS_ERR("invalid folio_index: "
			  "index %d, blks_count %u\n",
			  folio.desc.folio_index,
			  node->content.count);
		return U16_MAX;
	}

	page_start_offset = folio.desc.folio_offset + folio.desc.page_offset;
	if (page_start_offset > area_offset)
		offset_diff = item_offset - page_start_offset;
	else
		offset_diff = item_offset - area_offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(offset_diff % item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	index_diff = offset_diff / item_size;
	index_diff++;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(index_diff >= U16_MAX);

	SSDFS_DBG("offset_diff %u, index_diff %u\n",
		  offset_diff, index_diff);
#endif /* CONFIG_SSDFS_DEBUG */

	return index_diff;
}

/*
 * __ssdfs_shift_range_right() - shift the items' range to the right
 * @node: pointer on node object
 * @area_offset: area offset in bytes from the node's beginning
 * @area_size: area size in bytes
 * @item_size: size of item in bytes
 * @start_index: starting index of the range
 * @range_len: number of items in the range
 * @shift: number of position in the requested shift
 *
 * This method tries to shift the range of items to the right
 * direction.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_shift_range_right(struct ssdfs_btree_node *node,
			      u32 area_offset, u32 area_size,
			      size_t item_size,
			      u16 start_index, u16 range_len,
			      u16 shift)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio src_folio, dst_folio;
	int src_index, dst_index;
	u32 item_offset1, item_offset2;
	u32 moved_items = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, area_offset %u, area_size %u, "
		  "item_size %zu, start_index %u, "
		  "range_len %u, shift %u\n",
		  node->node_id, area_offset, area_size,
		  item_size, start_index, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	src_index = start_index + range_len - 1;
	dst_index = src_index + shift;

	if ((dst_index * item_size) > area_size) {
		SSDFS_ERR("shift is out of area: "
			  "src_index %d, shift %u, "
			  "item_size %zu, area_size %u\n",
			  src_index, shift, item_size, area_size);
		return -ERANGE;
	}

	do {
		u32 index_diff;
		u32 src_index_diff;
		u32 dst_index_diff;
		int moving_items;
		u32 moving_bytes;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("src_index %d, dst_index %d\n",
			  src_index, dst_index);
#endif /* CONFIG_SSDFS_DEBUG */

		src_index_diff = ssdfs_calculate_index_distance(node,
								area_offset,
								area_size,
								item_size,
								src_index);
		if (unlikely(src_index_diff >= U16_MAX)) {
			SSDFS_ERR("fail to calculate index diff: "
				  "src_index %d\n",
				  src_index);
			return -ERANGE;
		}

		dst_index_diff = ssdfs_calculate_index_distance(node,
								area_offset,
								area_size,
								item_size,
								dst_index);
		if (unlikely(dst_index_diff >= U16_MAX)) {
			SSDFS_ERR("fail to calculate index diff: "
				  "dst_index %d\n",
				  dst_index);
			return -ERANGE;
		}

		index_diff = min_t(u32, src_index_diff, dst_index_diff);

		if (index_diff == 0) {
			SSDFS_ERR("invalid index_diff %u\n",
				  index_diff);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index_diff %u\n", index_diff);

		BUG_ON(moved_items > range_len);
#endif /* CONFIG_SSDFS_DEBUG */

		moving_items = range_len - moved_items;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(moving_items < 0);
#endif /* CONFIG_SSDFS_DEBUG */

		moving_items = min_t(int, moving_items, (int)index_diff);

		if (moving_items == 0) {
			SSDFS_WARN("no items for moving\n");
			return -ERANGE;
		}

		moving_bytes = moving_items * item_size;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(moving_items >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		src_index -= moving_items - 1;
		dst_index = src_index + shift;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("moving_items %d, src_index %d, dst_index %d\n",
			  moving_items, src_index, dst_index);

		BUG_ON(start_index > src_index);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_calculate_item_offset(node, area_offset, area_size,
						  src_index, item_size,
						  &src_folio.desc, &item_offset1);
		if (unlikely(err)) {
			SSDFS_ERR("fail to calculate item's offset: "
				  "item_index %d, err %d\n",
				  src_index, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&src_folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_calculate_item_offset(node, area_offset, area_size,
						  dst_index, item_size,
						  &dst_folio.desc, &item_offset2);
		if (unlikely(err)) {
			SSDFS_ERR("fail to calculate item's offset: "
				  "item_index %d, err %d\n",
				  dst_index, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&dst_folio.desc));

		SSDFS_DBG("items_offset1 %u, item_offset2 %u\n",
			  item_offset1, item_offset2);

		if ((item_offset1 + moving_bytes) > PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "item_offset1 %u, moving_bytes %u\n",
				   item_offset1, moving_bytes);
			return -ERANGE;
		}

		if ((item_offset2 + moving_bytes) > PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "item_offset2 %u, moving_bytes %u\n",
				   item_offset2, moving_bytes);
			return -ERANGE;
		}

		SSDFS_DBG("blks_count %u, folio_index1 %d, "
			  "page_in_folio1 %u, item_offset1 %u, "
			  "folio_index2 %d, page_in_folio2 %d, "
			  "item_offset2 %u, moving_bytes %u\n",
			  node->content.count,
			  src_folio.desc.folio_index,
			  src_folio.desc.page_in_folio,
			  item_offset1,
			  dst_folio.desc.folio_index,
			  dst_folio.desc.page_in_folio,
			  item_offset2,
			  moving_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_move_memory_range_now(node, &dst_folio,
						  &src_folio, moving_bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: err %d\n", err);
			return err;
		}

		src_index--;
		dst_index--;
		moved_items += moving_items;
	} while (src_index >= (int)start_index);

	if (moved_items != range_len) {
		SSDFS_ERR("moved_items %u != range_len %u\n",
			  moved_items, range_len);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_shift_range_right2() - shift the items' range to the right
 * @node: pointer on node object
 * @area: area descriptor
 * @item_size: size of item in bytes
 * @start_index: starting index of the range
 * @range_len: number of items in the range
 * @shift: number of position in the requested shift
 *
 * This method tries to shift the range of items to the right
 * direction.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shift_range_right2(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_node_index_area *area,
			     size_t item_size,
			     u16 start_index, u16 range_len,
			     u16 shift)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_size %zu, "
		  "start_index %u, range_len %u, shift %u\n",
		  node->node_id, item_size,
		  start_index, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start_index > area->index_count) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, index_count %u\n",
			  start_index, area->index_count);
		return -ERANGE;
	} else if (start_index == area->index_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_index %u == index_count %u\n",
			  start_index, area->index_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	} else if ((start_index + range_len) > area->index_count) {
		SSDFS_ERR("range is out of existing items: "
			  "start_index %u, range_len %u, index_count %u\n",
			  start_index, range_len, area->index_count);
		return -ERANGE;
	} else if ((start_index + range_len + shift) > area->index_capacity) {
		SSDFS_ERR("shift is out of capacity: "
			  "start_index %u, range_len %u, "
			  "shift %u, index_capacity %u\n",
			  start_index, range_len,
			  shift, area->index_capacity);
		return -ERANGE;
	}

	return __ssdfs_shift_range_right(node, area->offset, area->area_size,
					 item_size, start_index, range_len,
					 shift);
}

/*
 * ssdfs_shift_range_right() - shift the items' range to the right
 * @node: pointer on node object
 * @area: items area descriptor
 * @item_size: size of item in bytes
 * @start_index: starting index of the range
 * @range_len: number of items in the range
 * @shift: number of position in the requested shift
 *
 * This method tries to shift the range of items to the right
 * direction.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shift_range_right(struct ssdfs_btree_node *node,
			    struct ssdfs_btree_node_items_area *area,
			    size_t item_size,
			    u16 start_index, u16 range_len,
			    u16 shift)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_size %zu, "
		  "start_index %u, range_len %u, shift %u\n",
		  node->node_id, item_size,
		  start_index, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start_index > area->items_count) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, items_count %u\n",
			  start_index, area->items_count);
		return -ERANGE;
	} else if (start_index == area->items_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_index %u == items_count %u\n",
			  start_index, area->items_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	} else if ((start_index + range_len) > area->items_count) {
		SSDFS_ERR("range is out of existing items: "
			  "start_index %u, range_len %u, items_count %u\n",
			  start_index, range_len, area->items_count);
		return -ERANGE;
	} else if ((start_index + range_len + shift) > area->items_capacity) {
		SSDFS_ERR("shift is out of capacity: "
			  "start_index %u, range_len %u, "
			  "shift %u, items_capacity %u\n",
			  start_index, range_len,
			  shift, area->items_capacity);
		return -ERANGE;
	}

	return __ssdfs_shift_range_right(node, area->offset, area->area_size,
					 item_size, start_index, range_len,
					 shift);
}

/*
 * __ssdfs_shift_range_left() - shift the items' range to the left
 * @node: pointer on node object
 * @area_offset: area offset in bytes from the node's beginning
 * @area_size: area size in bytes
 * @item_size: size of item in bytes
 * @start_index: starting index of the range
 * @range_len: number of items in the range
 * @shift: number of position in the requested shift
 *
 * This method tries to shift the range of items to the left
 * direction.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_shift_range_left(struct ssdfs_btree_node *node,
			     u32 area_offset, u32 area_size,
			     size_t item_size,
			     u16 start_index, u16 range_len,
			     u16 shift)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio src_folio, dst_folio;
	int src_index, dst_index;
	u32 item_offset1, item_offset2;
	u16 moved_items = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, area_offset %u, area_size %u, "
		  "item_size %zu, start_index %u, "
		  "range_len %u, shift %u\n",
		  node->node_id, area_offset, area_size,
		  item_size, start_index, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	src_index = start_index;
	dst_index = start_index - shift;

	do {
		u32 range_len1, range_len2;
		u32 moving_items;
		u32 moving_bytes;

		if (moved_items >= range_len) {
			SSDFS_ERR("moved_items %u >= range_len %u\n",
			      moved_items, range_len);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("src_index %d, dst_index %d\n",
			  src_index, dst_index);
#endif /* CONFIG_SSDFS_DEBUG */

		item_offset1 = (u32)src_index * item_size;
		if (item_offset1 >= area_size) {
			SSDFS_ERR("item_offset %u >= area_size %u\n",
				  item_offset1, area_size);
			return -ERANGE;
		}

		item_offset1 += area_offset;
		if (item_offset1 >= node->node_size) {
			SSDFS_ERR("item_offset %u >= node_size %u\n",
				  item_offset1, node->node_size);
			return -ERANGE;
		}

		err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset1,
				      &src_folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "item_offset %u, err %d\n",
				  item_offset1, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&src_folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (src_folio.desc.folio_index >= node->content.count) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, blks_count %u\n",
				  src_folio.desc.folio_index,
				  node->content.count);
			return -ERANGE;
		}

		item_offset1 = src_folio.desc.offset_inside_page;

		item_offset2 = (u32)dst_index * item_size;
		if (item_offset2 >= area_size) {
			SSDFS_ERR("item_offset %u >= area_size %u\n",
				  item_offset2, area_size);
			return -ERANGE;
		}

		item_offset2 += area_offset;
		if (item_offset2 >= node->node_size) {
			SSDFS_ERR("item_offset %u >= node_size %u\n",
				  item_offset2, node->node_size);
			return -ERANGE;
		}

		err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset2,
					&dst_folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "item_offset %u, err %d\n",
				  item_offset2, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&dst_folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (dst_folio.desc.folio_index >= node->content.count) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, blks_count %u\n",
				  dst_folio.desc.folio_index,
				  node->content.count);
			return -ERANGE;
		}

		item_offset2 = dst_folio.desc.offset_inside_page;

		range_len1 = (PAGE_SIZE - item_offset1) / item_size;
		range_len2 = (PAGE_SIZE - item_offset2) / item_size;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(range_len1 == 0);
		BUG_ON(range_len2 == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		moving_items = min_t(u32, range_len1, range_len2);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(moved_items > range_len);
#endif /* CONFIG_SSDFS_DEBUG */

		moving_items = min_t(u32, moving_items,
				     (u32)range_len - moved_items);

		if (moving_items == 0) {
			SSDFS_WARN("no items for moving\n");
			return -ERANGE;
		}

		moving_bytes = moving_items * item_size;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio_index1 %d, item_offset1 %u, "
			  "folio_index2 %d, item_offset2 %u\n",
			  src_folio.desc.folio_index, item_offset1,
			  dst_folio.desc.folio_index, item_offset2);

		if ((item_offset1 + moving_bytes) > PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "item_offset1 %u, moving_bytes %u\n",
				   item_offset1, moving_bytes);
			return -ERANGE;
		}

		if ((item_offset2 + moving_bytes) > PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "item_offset2 %u, moving_bytes %u\n",
				   item_offset2, moving_bytes);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_move_memory_range_now(node, &dst_folio,
						  &src_folio, moving_bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: err %d\n", err);
			return err;
		}

		src_index += moving_items;
		dst_index += moving_items;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("moving_items %u, src_index %d, dst_index %d\n",
			  moving_items, src_index, dst_index);

		BUG_ON(moving_items >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		moved_items += moving_items;
	} while (moved_items < range_len);

	return 0;
}

/*
 * ssdfs_shift_range_left2() - shift the items' range to the left
 * @node: pointer on node object
 * @area: area descriptor
 * @item_size: size of item in bytes
 * @start_index: starting index of the range
 * @range_len: number of items in the range
 * @shift: number of position in the requested shift
 *
 * This method tries to shift the range of items to the left
 * direction.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shift_range_left2(struct ssdfs_btree_node *node,
			    struct ssdfs_btree_node_index_area *area,
			    size_t item_size,
			    u16 start_index, u16 range_len,
			    u16 shift)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_size %zu, "
		  "start_index %u, range_len %u, shift %u\n",
		  node->node_id, item_size,
		  start_index, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start_index > area->index_count) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, index_count %u\n",
			  start_index, area->index_count);
		return -ERANGE;
	} else if (start_index == area->index_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_index %u == index_count %u\n",
			  start_index, area->index_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	} else if ((start_index + range_len) > area->index_count) {
		SSDFS_ERR("range is out of existing items: "
			  "start_index %u, range_len %u, index_count %u\n",
			  start_index, range_len, area->index_count);
		return -ERANGE;
	} else if (shift > start_index) {
		SSDFS_ERR("shift is out of node: "
			  "start_index %u, shift %u\n",
			  start_index, shift);
		return -ERANGE;
	}

	return __ssdfs_shift_range_left(node, area->offset, area->area_size,
					item_size, start_index, range_len,
					shift);
}

/*
 * ssdfs_shift_range_left() - shift the items' range to the left
 * @node: pointer on node object
 * @area: items area descriptor
 * @item_size: size of item in bytes
 * @start_index: starting index of the range
 * @range_len: number of items in the range
 * @shift: number of position in the requested shift
 *
 * This method tries to shift the range of items to the left
 * direction.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shift_range_left(struct ssdfs_btree_node *node,
			   struct ssdfs_btree_node_items_area *area,
			   size_t item_size,
			   u16 start_index, u16 range_len,
			   u16 shift)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_size %zu, "
		  "start_index %u, range_len %u, shift %u\n",
		  node->node_id, item_size,
		  start_index, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start_index >= area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "start_index %u, items_capacity %u\n",
			  start_index, area->items_capacity);
		return -ERANGE;
	} else if ((start_index + range_len) > area->items_capacity) {
		SSDFS_ERR("range is out of capacity: "
			  "start_index %u, range_len %u, items_capacity %u\n",
			  start_index, range_len, area->items_capacity);
		return -ERANGE;
	} else if (shift > start_index) {
		SSDFS_ERR("shift is out of node: "
			  "start_index %u, shift %u\n",
			  start_index, shift);
		return -ERANGE;
	}

	return __ssdfs_shift_range_left(node, area->offset, area->area_size,
					item_size, start_index, range_len,
					shift);
}

/*
 * __ssdfs_shift_memory_range_right() - shift the memory range to the right
 * @node: pointer on node object
 * @area_offset: area offset in bytes from the node's beginning
 * @area_size: area size in bytes
 * @offset: offset from the area's beginning to the range start
 * @range_len: length of the range in bytes
 * @shift: value of the shift in bytes
 *
 * This method tries to move the memory range (@offset; @range_len)
 * in the @node for the @shift in bytes to the right.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_shift_memory_range_right(struct ssdfs_btree_node *node,
				     u32 area_offset, u32 area_size,
				     u16 offset, u16 range_len,
				     u16 shift)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio src_folio, dst_folio;
	int src_offset, dst_offset;
	u32 range_offset1, range_offset2;
	u32 cur_range;
	u32 moved_range = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, area_offset %u, area_size %u, "
		  "offset %u, range_len %u, shift %u\n",
		  node->node_id, area_offset, area_size,
		  offset, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (((u32)offset + range_len + shift) > (area_offset + area_size)) {
		SSDFS_ERR("invalid request: "
			  "offset %u, range_len %u, shift %u, "
			  "area_offset %u, area_size %u\n",
			  offset, range_len, shift,
			  area_offset, area_size);
		return -ERANGE;
	}

	src_offset = offset + range_len;
	dst_offset = src_offset + shift;

	do {
		u32 offset_diff;
		u32 moving_range;

		range_offset1 = src_offset;
		if (range_offset1 > area_size) {
			SSDFS_ERR("range_offset1 %u > area_size %u\n",
				  range_offset1, area_size);
			return -ERANGE;
		}

		range_offset1 += area_offset;
		if (range_offset1 > node->node_size) {
			SSDFS_ERR("range_offset1 %u > node_size %u\n",
				  range_offset1, node->node_size);
			return -ERANGE;
		}

		err = SSDFS_OFF2FOLIO(fsi->pagesize, range_offset1 - 1,
					&src_folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "range_offset %u, err %d\n",
				  range_offset1, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&src_folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (src_folio.desc.folio_index >= node->content.count) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, blks_count %u\n",
				  src_folio.desc.folio_index,
				  node->content.count);
			return -ERANGE;
		}

		if (range_len <= moved_range) {
			SSDFS_ERR("range_len %u <= moved_range %u\n",
				  range_len, moved_range);
			return -ERANGE;
		}

		cur_range = range_len - moved_range;
		offset_diff = range_offset1 -
				(src_folio.desc.folio_offset +
						src_folio.desc.page_offset);

		moving_range = min_t(u32, cur_range, offset_diff);

		range_offset2 = dst_offset;
		if (range_offset2 > area_size) {
			SSDFS_ERR("range_offset2 %u > area_size %u\n",
				  range_offset2, area_size);
			return -ERANGE;
		}

		range_offset2 += area_offset;
		if (range_offset2 > node->node_size) {
			SSDFS_ERR("range_offset2 %u > node_size %u\n",
				  range_offset2, node->node_size);
			return -ERANGE;
		}

		err = SSDFS_OFF2FOLIO(fsi->pagesize, range_offset2 - 1,
					&dst_folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "range_offset %u, err %d\n",
				  range_offset2, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&dst_folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (dst_folio.desc.folio_index >= node->content.count) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, blks_count %u\n",
				  dst_folio.desc.folio_index,
				  node->content.count);
			return -ERANGE;
		}

		offset_diff = range_offset2 -
				(dst_folio.desc.folio_offset +
						dst_folio.desc.page_offset);

		moving_range = min_t(u32, moving_range, offset_diff);

		range_offset1 -= moving_range;
		range_offset2 -= moving_range;

		err = SSDFS_OFF2FOLIO(fsi->pagesize, range_offset1,
					&src_folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "range_offset %u, err %d\n",
				  range_offset1, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&src_folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		err = SSDFS_OFF2FOLIO(fsi->pagesize, range_offset2,
					&dst_folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "range_offset %u, err %d\n",
				  range_offset2, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&dst_folio.desc));

		SSDFS_DBG("range_offset1 %u, SOURCE: (folio_index %d, "
			  "page_in_folio %u, offset_inside_page %u), "
			  "range_offset2 %u, DESTINATION: (folio_index %d, "
			  "page_in_folio %d, offset_inside_page %u)\n",
			  range_offset1,
			  src_folio.desc.folio_index,
			  src_folio.desc.page_in_folio,
			  src_folio.desc.offset_inside_page,
			  range_offset2,
			  dst_folio.desc.folio_index,
			  dst_folio.desc.page_in_folio,
			  dst_folio.desc.offset_inside_page);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_move_memory_range_now(node, &dst_folio,
						  &src_folio, moving_range);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: err %d\n", err);
			return err;
		}

		src_offset -= moving_range;
		dst_offset -= moving_range;

		if (src_offset < 0 || dst_offset < 0) {
			SSDFS_ERR("src_offset %d, dst_offset %d\n",
				  src_offset, dst_offset);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(moving_range >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		moved_range += moving_range;
	} while (src_offset > offset);

	if (moved_range != range_len) {
		SSDFS_ERR("moved_range %u != range_len %u\n",
			  moved_range, range_len);
		return -ERANGE;
	}

	if (src_offset != offset) {
		SSDFS_ERR("src_offset %d != offset %u\n",
			  src_offset, offset);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_shift_memory_range_right() - shift the memory range to the right
 * @node: pointer on node object
 * @area: pointer on the area descriptor
 * @offset: offset from the area's beginning to the range start
 * @range_len: length of the range in bytes
 * @shift: value of the shift in bytes
 *
 * This method tries to move the memory range (@offset; @range_len)
 * in the @node for the @shift in bytes to the right.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shift_memory_range_right(struct ssdfs_btree_node *node,
				   struct ssdfs_btree_node_items_area *area,
				   u16 offset, u16 range_len,
				   u16 shift)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, offset %u, range_len %u, shift %u\n",
		  node->node_id, offset, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_shift_memory_range_right(node,
						area->offset, area->area_size,
						offset, range_len,
						shift);
}

/*
 * ssdfs_shift_memory_range_right2() - shift the memory range to the right
 * @node: pointer on node object
 * @area: pointer on the area descriptor
 * @offset: offset from the area's beginning to the range start
 * @range_len: length of the range in bytes
 * @shift: value of the shift in bytes
 *
 * This method tries to move the memory range (@offset; @range_len)
 * in the @node for the @shift in bytes to the right.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shift_memory_range_right2(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_index_area *area,
				    u16 offset, u16 range_len,
				    u16 shift)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, offset %u, range_len %u, shift %u\n",
		  node->node_id, offset, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_shift_memory_range_right(node,
						area->offset, area->area_size,
						offset, range_len,
						shift);
}

/*
 * __ssdfs_shift_memory_range_left() - shift the memory range to the left
 * @node: pointer on node object
 * @area_offset: offset area from the node's beginning
 * @area_size: size of area in bytes
 * @offset: offset from the area's beginning to the range start
 * @range_len: length of the range in bytes
 * @shift: value of the shift in bytes
 *
 * This method tries to move the memory range (@offset; @range_len)
 * in the @node for the @shift in bytes to the left.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_shift_memory_range_left(struct ssdfs_btree_node *node,
				    u32 area_offset, u32 area_size,
				    u16 offset, u16 range_len,
				    u16 shift)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio src_folio, dst_folio;
	int src_offset, dst_offset;
	u32 range_offset1, range_offset2;
	u32 range_len1, range_len2;
	u32 moved_range = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, area_offset %u, area_size %u, "
		  "offset %u, range_len %u, shift %u\n",
		  node->node_id, area_offset, area_size,
		  offset, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if ((offset + range_len) >= (area_offset + area_size)) {
		SSDFS_ERR("invalid request: "
			  "offset %u, range_len %u, "
			  "area_offset %u, area_size %u\n",
			  offset, range_len,
			  area_offset, area_size);
		return -ERANGE;
	} else if (shift > offset) {
		SSDFS_ERR("shift is out of area: "
			  "offset %u, shift %u\n",
			  offset, shift);
		return -ERANGE;
	}

	src_offset = offset;
	dst_offset = offset - shift;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("src_offset %u, dst_offset %u\n",
		  src_offset, dst_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		u32 moving_range;

		range_offset1 = src_offset;
		if (range_offset1 > area_size) {
			SSDFS_ERR("range_offset1 %u > area_size %u\n",
				  range_offset1, area_size);
			return -ERANGE;
		}

		range_offset1 += area_offset;
		if (range_offset1 > node->node_size) {
			SSDFS_ERR("range_offset1 %u > node_size %u\n",
				  range_offset1, node->node_size);
			return -ERANGE;
		}

		err = SSDFS_OFF2FOLIO(fsi->pagesize, range_offset1,
					&src_folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "range_offset %u, err %d\n",
				  range_offset1, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&src_folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (src_folio.desc.folio_index >= node->content.count) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, blks_count %u\n",
				  src_folio.desc.folio_index,
				  node->content.count);
			return -ERANGE;
		}

		range_offset1 = src_folio.desc.offset_inside_page;

		range_offset2 = dst_offset;
		if (range_offset2 >= area_size) {
			SSDFS_ERR("range_offset2 %u >= area_size %u\n",
				  range_offset2, area_size);
			return -ERANGE;
		}

		range_offset2 += area_offset;
		if (range_offset2 >= node->node_size) {
			SSDFS_ERR("range_offset2 %u >= node_size %u\n",
				  range_offset2, node->node_size);
			return -ERANGE;
		}

		err = SSDFS_OFF2FOLIO(fsi->pagesize, range_offset2,
					&dst_folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "range_offset %u, err %d\n",
				  range_offset2, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&dst_folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (dst_folio.desc.folio_index >= node->content.count) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, blks_count %u\n",
				  dst_folio.desc.folio_index,
				  node->content.count);
			return -ERANGE;
		}

		range_offset2 = dst_folio.desc.offset_inside_page;

		range_len1 = PAGE_SIZE - range_offset1;
		range_len2 = PAGE_SIZE - range_offset2;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(range_len1 == 0);
		BUG_ON(range_len2 == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		moving_range = min_t(u32, range_len1, range_len2);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(moved_range > range_len);
#endif /* CONFIG_SSDFS_DEBUG */

		moving_range = min_t(u32, moving_range,
				     (u32)range_len - moved_range);

		if (moving_range == 0) {
			SSDFS_WARN("no items for moving\n");
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		if ((range_offset1 + moving_range) > PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "range_offset1 %u, moving_range %u\n",
				   range_offset1, moving_range);
			return -ERANGE;
		}

		if ((range_offset2 + moving_range) > PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "range_offset2 %u, moving_range %u\n",
				   range_offset2, moving_range);
			return -ERANGE;
		}

		SSDFS_DBG("folio_index1 %d, folio_index2 %d, "
			  "range_offset1 %u, range_offset2 %u\n",
			  src_folio.desc.folio_index,
			  dst_folio.desc.folio_index,
			  range_offset1, range_offset2);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_move_memory_range_now(node, &dst_folio,
						  &src_folio, moving_range);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: err %d\n", err);
			return err;
		}

		src_offset += moving_range;
		dst_offset += moving_range;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(moving_range >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		moved_range += moving_range;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("src_offset %u, dst_offset %u, "
			  "moving_range %u, moved_range %u\n",
			  src_offset, dst_offset,
			  moving_range, moved_range);
#endif /* CONFIG_SSDFS_DEBUG */
	} while (moved_range < range_len);

	if (moved_range != range_len) {
		SSDFS_ERR("moved_range %u != range_len %u\n",
			  moved_range, range_len);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_shift_memory_range_left() - shift the memory range to the left
 * @node: pointer on node object
 * @area: pointer on the area descriptor
 * @offset: offset from the area's beginning to the range start
 * @range_len: length of the range in bytes
 * @shift: value of the shift in bytes
 *
 * This method tries to move the memory range (@offset; @range_len)
 * in the @node for the @shift in bytes to the left.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shift_memory_range_left(struct ssdfs_btree_node *node,
				   struct ssdfs_btree_node_items_area *area,
				   u16 offset, u16 range_len,
				   u16 shift)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, offset %u, range_len %u, shift %u\n",
		  node->node_id, offset, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_shift_memory_range_left(node,
						area->offset, area->area_size,
						offset, range_len, shift);
}

/*
 * ssdfs_shift_memory_range_left2() - shift the memory range to the left
 * @node: pointer on node object
 * @area: pointer on the area descriptor
 * @offset: offset from the area's beginning to the range start
 * @range_len: length of the range in bytes
 * @shift: value of the shift in bytes
 *
 * This method tries to move the memory range (@offset; @range_len)
 * in the @node for the @shift in bytes to the left.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shift_memory_range_left2(struct ssdfs_btree_node *node,
				   struct ssdfs_btree_node_index_area *area,
				   u16 offset, u16 range_len,
				   u16 shift)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, offset %u, range_len %u, shift %u\n",
		  node->node_id, offset, range_len, shift);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_shift_memory_range_left(node,
						area->offset, area->area_size,
						offset, range_len, shift);
}

/*
 * ssdfs_generic_insert_range() - insert range of items into the node
 * @node: pointer on node object
 * @area: items area descriptor
 * @item_size: size of item in bytes
 * @search: search object
 *
 * This method tries to insert the range of items into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_generic_insert_range(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *area,
				size_t item_size,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	int src_index, dst_index;
	u32 item_offset1, item_offset2;
	u16 copied_items = 0;
	u16 start_index;
	unsigned int range_len;
	u32 items;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_size %zu\n",
		  node->node_id, item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

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

	start_index = search->result.start_index;
	range_len = search->result.count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items %u, start_index %u, range_len %u\n",
		  items, start_index, range_len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (range_len == 0) {
		SSDFS_WARN("search->result.count == 0\n");
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

	src_index = start_index;
	dst_index = 0;

	do {
		struct folio_batch *batch;
		u32 copying_items;
		u32 copying_bytes;
		u32 vacant_positions;
		u32 dst_offset;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_index %u, src_index %d, dst_index %d\n",
			  start_index, src_index, dst_index);
#endif /* CONFIG_SSDFS_DEBUG */

		item_offset1 = (u32)src_index * item_size;
		if (item_offset1 >= area->area_size) {
			SSDFS_ERR("item_offset %u >= area_size %u\n",
				  item_offset1, area->area_size);
			return -ERANGE;
		}

		item_offset1 += area->offset;
		if (item_offset1 >= node->node_size) {
			SSDFS_ERR("item_offset %u >= node_size %u\n",
				  item_offset1, node->node_size);
			return -ERANGE;
		}

		err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset1, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "item_offset %u, err %d\n",
				  item_offset1, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >= node->content.count) {
			SSDFS_ERR("invalid folio_index: "
				  "index %d, blks_count %u\n",
				  folio.desc.folio_index,
				  node->content.count);
			return -ERANGE;
		}

		item_offset1 = folio.desc.offset_inside_page;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(start_index > src_index);
#endif /* CONFIG_SSDFS_DEBUG */

		copying_items = src_index - start_index;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(copying_items > range_len);
#endif /* CONFIG_SSDFS_DEBUG */

		copying_items = range_len - copying_items;

		if (copying_items == 0) {
			SSDFS_WARN("no items for moving\n");
			return -ERANGE;
		}

		vacant_positions = PAGE_SIZE - item_offset1;
		vacant_positions /= item_size;

		if (vacant_positions == 0) {
			SSDFS_WARN("invalid vacant_positions %u\n",
				   vacant_positions);
			return -ERANGE;
		}

		copying_items = min_t(u32, copying_items, vacant_positions);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(copying_items >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		copying_bytes = copying_items * item_size;

		item_offset2 = (u32)dst_index * item_size;
		if (item_offset2 >= search->result.buf_size) {
			SSDFS_ERR("item_offset %u >= buf_size %zu\n",
				  item_offset2, search->result.buf_size);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("copying_items %u, item_offset1 %u, "
			  "item_offset2 %u\n",
			  copying_items, item_offset1, item_offset2);

		if ((item_offset1 + copying_bytes) > PAGE_SIZE) {
			SSDFS_WARN("invalid offset: "
				   "item_offset1 %u, copying_bytes %u\n",
				   item_offset1, copying_bytes);
			return -ERANGE;
		}

		if ((item_offset2 + copying_bytes) > search->result.buf_size) {
			SSDFS_WARN("invalid offset: "
				   "item_offset2 %u, copying_bytes %u, "
				   "result.buf_size %zu\n",
				   item_offset2, copying_bytes,
				   search->result.buf_size);
			return -ERANGE;
		}

		SSDFS_DBG("folio_index %d, blks_count %u, "
			  "item_offset1 %u, item_offset2 %u, "
			  "copying_bytes %u, result.buf_size %zu\n",
			  folio.desc.folio_index,
			  node->content.count,
			  item_offset1, item_offset2,
			  copying_bytes,
			  search->result.buf_size);
#endif /* CONFIG_SSDFS_DEBUG */

		batch = &node->content.blocks[folio.desc.folio_index].batch;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folio_batch_count(batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		dst_offset = folio.desc.offset - folio.desc.folio_offset;

		err = ssdfs_memcpy_to_batch(batch, dst_offset,
					    search->result.buf,
					    item_offset2,
					    search->result.buf_size,
					    copying_bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move: err %d\n", err);
			return err;
		}

		src_index += copying_items;
		dst_index += copying_items;
		copied_items += copying_items;
	} while (copied_items < range_len);

	if (copied_items != range_len) {
		SSDFS_ERR("copied_items %u != range_len %u\n",
			  copied_items, range_len);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_invalidate_root_node_hierarchy() - invalidate the whole hierarchy
 * @node: pointer on node object
 *
 * This method tries to add the whole hierarchy of forks into
 * pre-invalid queue of the shared extents tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_invalidate_root_node_hierarchy(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree *tree;
	struct ssdfs_btree_index_key indexes[SSDFS_BTREE_ROOT_NODE_INDEX_COUNT];
	struct ssdfs_shared_extents_tree *shextree;
	u16 index_count;
	int index_type = SSDFS_EXTENT_INFO_UNKNOWN_TYPE;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	tree = node->tree;
	switch (tree->type) {
	case SSDFS_EXTENTS_BTREE:
		index_type = SSDFS_EXTENT_INFO_INDEX_DESCRIPTOR;
		break;

	case SSDFS_DENTRIES_BTREE:
		index_type = SSDFS_EXTENT_INFO_DENTRY_INDEX_DESCRIPTOR;
		break;

	case SSDFS_XATTR_BTREE:
		index_type = SSDFS_EXTENT_INFO_XATTR_INDEX_DESCRIPTOR;
		break;

	case SSDFS_SHARED_DICTIONARY_BTREE:
		index_type = SSDFS_EXTENT_INFO_SHDICT_INDEX_DESCRIPTOR;
		break;

	default:
		SSDFS_ERR("unsupported tree type %#x\n",
			  tree->type);
		return -ERANGE;
	}

	if (atomic_read(&node->type) != SSDFS_BTREE_ROOT_NODE) {
		SSDFS_ERR("invalid node type %#x\n",
			  atomic_read(&node->type));
		return -ERANGE;
	}

	fsi = tree->fsi;
	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	down_write(&node->full_lock);

	for (i = 0; i < SSDFS_BTREE_ROOT_NODE_INDEX_COUNT; i++) {
		err = __ssdfs_btree_root_node_extract_index(node, i,
							    &indexes[i]);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the index: "
				  "index_id %d, err %d\n",
				  i, err);
			goto finish_invalidate_root_node_hierarchy;
		}
	}

	down_write(&node->header_lock);

	index_count = node->index_area.index_count;

	if (index_count == 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid index_count %u\n",
			  index_count);
		goto finish_process_root_node;
	}

	for (i = index_count - 1; i >= 0; i--) {
		if (le64_to_cpu(indexes[i].index.hash) >= U64_MAX) {
			err = -ERANGE;
			SSDFS_ERR("index %d has invalid hash\n", i);
			goto finish_process_root_node;
		}

		err = ssdfs_btree_root_node_delete_index(node, i);
		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to delete index: "
				  "index_id %d, err %d\n",
				  i, err);
			goto finish_process_root_node;
		}

		err = ssdfs_shextree_add_pre_invalid_index(shextree,
							   tree->owner_ino,
							   index_type,
							   &indexes[i]);
		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to pre-invalid index: "
				  "index_id %d, err %d\n",
				  i, err);
			goto finish_process_root_node;
		}
	}

	set_ssdfs_btree_node_pre_deleted(node);

finish_process_root_node:
	up_write(&node->header_lock);

finish_invalidate_root_node_hierarchy:
	up_write(&node->full_lock);

	return err;
}

/*
 * __ssdfs_btree_node_extract_range() - extract range of items from node
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
int __ssdfs_btree_node_extract_range(struct ssdfs_btree_node *node,
				     u16 start_index, u16 count,
				     size_t item_size,
				     struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree *tree;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_state_bitmap *bmap;
	struct ssdfs_smart_folio folio;
	size_t desc_size = sizeof(struct ssdfs_btree_node_items_area);
	size_t buf_size;
	u32 item_offset;
	u32 calculated;
	unsigned long cur_index;
	u32 src_offset;
	unsigned long nofs_flags;
	u16 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_index %u, count %u, "
		  "state %d, node_id %u, height %d\n",
		  search->request.type, search->request.flags,
		  start_index, count,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height));
#endif /* CONFIG_SSDFS_DEBUG */

	tree = node->tree;
	fsi = tree->fsi;
	search->result.start_index = U16_MAX;
	search->result.count = 0;

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
	ssdfs_memcpy(&items_area, 0, desc_size,
		     &node->items_area, 0, desc_size,
		     desc_size);
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, items_capacity %u, items_count %u\n",
		  node->node_id,
		  items_area.items_capacity,
		  items_area.items_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (count == 0) {
		SSDFS_ERR("empty request\n");
		return -ERANGE;
	}

	if (start_index >= items_area.items_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_index %u >= items_count %u\n",
			  start_index, items_area.items_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	if ((start_index + count) > items_area.items_count)
		count = items_area.items_count - start_index;

	buf_size = count * item_size;

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE:
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		if (count == 1) {
			switch (tree->type) {
			case SSDFS_INODES_BTREE:
				search->result.buf = &search->raw.inode;
				break;

			case SSDFS_EXTENTS_BTREE:
				search->result.buf = &search->raw.fork;
				break;

			case SSDFS_DENTRIES_BTREE:
				search->result.buf = &search->raw.dentry;
				break;

			case SSDFS_XATTR_BTREE:
				search->result.buf = &search->raw.xattr;
				break;

			default:
				SSDFS_ERR("unsupported tree type %#x\n",
					  tree->type);
				return -ERANGE;
			}

			search->result.buf_state =
					SSDFS_BTREE_SEARCH_INLINE_BUFFER;
			search->result.buf_size = buf_size;
			search->result.items_in_buffer = 0;
		} else {
			err = ssdfs_btree_search_alloc_result_buf(search,
								  buf_size);
			if (unlikely(err)) {
				SSDFS_ERR("fail to allocate buffer\n");
				return err;
			}
		}
		break;

	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		if (count == 1) {
			ssdfs_btree_search_free_result_buf(search);

			switch (tree->type) {
			case SSDFS_INODES_BTREE:
				search->result.buf = &search->raw.inode;
				break;

			case SSDFS_EXTENTS_BTREE:
				search->result.buf = &search->raw.fork;
				break;

			case SSDFS_DENTRIES_BTREE:
				search->result.buf = &search->raw.dentry;
				break;

			case SSDFS_XATTR_BTREE:
				search->result.buf = &search->raw.xattr;
				break;

			default:
				SSDFS_ERR("unsupported tree type %#x\n",
					  tree->type);
				return -ERANGE;
			}

			search->result.buf_state =
					SSDFS_BTREE_SEARCH_INLINE_BUFFER;
			search->result.buf_size = buf_size;
			search->result.items_in_buffer = 0;
		} else {
			nofs_flags = memalloc_nofs_save();
			search->result.buf = krealloc(search->result.buf,
						      buf_size, GFP_KERNEL);
			memalloc_nofs_restore(nofs_flags);

			if (!search->result.buf) {
				SSDFS_ERR("fail to allocate buffer\n");
				return -ENOMEM;
			}
			search->result.buf_state =
					SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
			search->result.buf_size = buf_size;
			search->result.items_in_buffer = 0;
		}
		break;

	default:
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_LOCK_BMAP];

	for (i = start_index; i < (start_index + count); i++) {
		struct folio_batch *batch;

		item_offset = (u32)i * item_size;
		if (item_offset >= items_area.area_size) {
			err = -ERANGE;
			SSDFS_ERR("item_offset %u >= area_size %u\n",
				  item_offset, items_area.area_size);
			goto finish_extract_range;
		}

		item_offset += items_area.offset;
		if (item_offset >= node->node_size) {
			err = -ERANGE;
			SSDFS_ERR("item_offset %u >= node_size %u\n",
				  item_offset, node->node_size);
			goto finish_extract_range;
		}

		err = SSDFS_OFF2FOLIO(fsi->pagesize, item_offset, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "item_offset %u, err %d\n",
				  item_offset, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio.desc.folio_index >= node->content.count) {
			err = -ERANGE;
			SSDFS_ERR("invalid folio_index: "
				  "index %d, blks_count %u\n",
				  folio.desc.folio_index,
				  node->content.count);
			goto finish_extract_range;
		}

		calculated = search->result.items_in_buffer * item_size;
		if (calculated >= search->result.buf_size) {
			err = -ERANGE;
			SSDFS_ERR("calculated %u >= buf_size %zu\n",
				  calculated, search->result.buf_size);
			goto finish_extract_range;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */

		down_read(&node->bmap_array.lock);

try_lock_item:
		spin_lock(&bmap->lock);

		cur_index = node->bmap_array.item_start_bit + i;
		err = bitmap_allocate_region(bmap->ptr,
					     (unsigned int)cur_index, 0);
		if (err == -EBUSY) {
			DEFINE_WAIT_FUNC(wait, woken_wake_function);

			err = 0;

			spin_unlock(&bmap->lock);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("waiting unlocked state of item %lu\n",
				  cur_index);
#endif /* CONFIG_SSDFS_DEBUG */

			add_wait_queue(&node->wait_queue, &wait);
			while (atomic_read(&node->bmap_array.locks_count) > 0) {
				if (signal_pending(current)) {
					break;
				} else {
					wait_woken(&wait, TASK_INTERRUPTIBLE,
						   SSDFS_DEFAULT_TIMEOUT);
				}
			}
			remove_wait_queue(&node->wait_queue, &wait);

			goto try_lock_item;
		}

		atomic_inc(&node->bmap_array.locks_count);

		spin_unlock(&bmap->lock);

		up_read(&node->bmap_array.lock);

		if (err) {
			SSDFS_ERR("fail to lock: index %lu, err %d\n",
				  cur_index, err);
			goto finish_extract_range;
		}

		batch = &node->content.blocks[folio.desc.folio_index].batch;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folio_batch_count(batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		src_offset = folio.desc.offset - folio.desc.folio_offset;

		err = ssdfs_memcpy_from_batch(search->result.buf,
					      calculated,
					      search->result.buf_size,
					      batch, src_offset,
					      item_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n",
				  err);
		} else {
			search->result.items_in_buffer++;
			search->result.count++;
			search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;
		}

		down_read(&node->bmap_array.lock);
		spin_lock(&bmap->lock);
		bitmap_clear(bmap->ptr, (unsigned int)cur_index, 1);
		atomic_dec(&node->bmap_array.locks_count);
		spin_unlock(&bmap->lock);
		up_read(&node->bmap_array.lock);

		wake_up_all(&node->wait_queue);

		if (unlikely(err))
			goto finish_extract_range;
	}

finish_extract_range:
	if (err == -ENODATA) {
		/*
		 * do nothing
		 */
	} else if (unlikely(err)) {
		search->result.state = SSDFS_BTREE_SEARCH_FAILURE;
		search->result.err = err;
	} else
		search->result.start_index = start_index;

	return err;
}

/*
 * __ssdfs_btree_node_resize_items_area() - resize items area of the node
 * @node: node object
 * @item_size: size of the item in bytes
 * @index_size: size of the index in bytes
 * @new_size: new size of the items area
 *
 * This method tries to resize the items area of the node.
 *
 * It makes sense to allocate the bitmap with taking into
 * account that we will resize the node. So, it needs
 * to allocate the index area in bitmap is equal to
 * the whole node and items area is equal to the whole node.
 * This technique provides opportunity not to resize or
 * to shift the content of the bitmap.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
int __ssdfs_btree_node_resize_items_area(struct ssdfs_btree_node *node,
					 size_t item_size,
					 size_t index_size,
					 u32 new_size)
{
	size_t hdr_size = sizeof(struct ssdfs_extents_btree_node_header);
	bool index_area_exist = false;
	bool items_area_exist = false;
	u32 indexes_offset, items_offset;
	u32 indexes_size, items_size;
	u32 indexes_free_space, items_free_space;
	u32 space_capacity, used_space = 0;
	u16 capacity, count;
	u32 diff_size;
	u16 start_index, range_len;
	u32 shift;
	unsigned long index_start_bit;
	unsigned long item_start_bit;
	unsigned long bits_count;
	u16 index_capacity;
	u16 items_capacity;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, item_size %zu, new_size %u\n",
		  node->node_id, item_size, new_size);

	ssdfs_debug_btree_node_object(node);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_CORRUPTED:
		SSDFS_WARN("node %u is corrupted\n",
			   node->node_id);
		return -EFAULT;

	default:
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return -ERANGE;
	}

	down_write(&node->bmap_array.lock);

	switch (atomic_read(&node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		index_area_exist = true;

		indexes_offset = node->index_area.offset;
		indexes_size = node->index_area.area_size;

		if (indexes_offset != hdr_size) {
			err = -EFAULT;
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("corrupted index area: "
				  "offset %u, hdr_size %zu\n",
				  node->index_area.offset,
				  hdr_size);
			goto finish_area_resize;
		}

		if ((indexes_offset + indexes_size) > node->node_size) {
			err = -EFAULT;
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("corrupted index area: "
				  "area_offset %u, area_size %u, "
				  "node_size %u\n",
				  node->index_area.offset,
				  node->index_area.area_size,
				  node->node_size);
			goto finish_area_resize;
		}
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		index_area_exist = false;
		indexes_offset = 0;
		indexes_size = 0;
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid area state %#x\n",
			  atomic_read(&node->index_area.state));
		goto finish_area_resize;
	}

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		items_area_exist = true;

		items_offset = node->items_area.offset;
		items_size = node->items_area.area_size;

		if ((hdr_size + indexes_size) > items_offset) {
			err = -EFAULT;
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("corrupted items area: "
				  "hdr_size %zu, index area_size %u, "
				  "offset %u\n",
				  hdr_size,
				  node->index_area.area_size,
				  node->items_area.offset);
			goto finish_area_resize;
		}

		if ((items_offset + items_size) > node->node_size) {
			err = -EFAULT;
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("corrupted items area: "
				  "area_offset %u, area_size %u, "
				  "node_size %u\n",
				  node->items_area.offset,
				  node->items_area.area_size,
				  node->node_size);
			goto finish_area_resize;
		}
		break;

	case SSDFS_BTREE_NODE_AREA_ABSENT:
		items_area_exist = false;
		items_offset = 0;
		items_size = 0;
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid area state %#x\n",
			  atomic_read(&node->items_area.state));
		goto finish_area_resize;
	}

	if ((hdr_size + indexes_size + items_size) > node->node_size) {
		err = -EFAULT;
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("corrupted node: "
			  "hdr_size %zu, index area_size %u, "
			  "items area_size %u, node_size %u\n",
			  hdr_size,
			  node->index_area.area_size,
			  node->items_area.area_size,
			  node->node_size);
		goto finish_area_resize;
	}

	if (index_area_exist) {
		space_capacity = node->index_area.index_size;
		space_capacity *= node->index_area.index_capacity;

		if (space_capacity != indexes_size) {
			err = -EFAULT;
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("space_capacity %u != indexes_size %u\n",
				  space_capacity, indexes_size);
			goto finish_area_resize;
		}

		used_space = node->index_area.index_size;
		used_space *= node->index_area.index_count;

		if (used_space > space_capacity) {
			err = -EFAULT;
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("used_space %u > space_capacity %u\n",
				  used_space, space_capacity);
			goto finish_area_resize;
		}

		indexes_free_space = space_capacity - used_space;
	} else
		indexes_free_space = 0;

	if (items_area_exist) {
		space_capacity = item_size;
		space_capacity *= node->items_area.items_capacity;

		if (space_capacity != items_size) {
			err = -EFAULT;
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("space_capacity %u != items_size %u\n",
				  space_capacity, items_size);
			goto finish_area_resize;
		}

		used_space = item_size;
		used_space *= node->items_area.items_count;

		if (used_space > space_capacity) {
			err = -EFAULT;
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("used_space %u > space_capacity %u\n",
				  used_space, space_capacity);
			goto finish_area_resize;
		}

		items_free_space = space_capacity - used_space;
	} else
		items_free_space = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("indexes_offset %u, indexes_size %u, "
		  "items_offset %u, items_size %u, "
		  "indexes_free_space %u, items_free_space %u\n",
		  indexes_offset, indexes_size,
		  items_offset, items_size,
		  indexes_free_space, items_free_space);
#endif /* CONFIG_SSDFS_DEBUG */

	if (new_size > items_size) {
		/* increase items area */
		u32 unused_space;

		if ((hdr_size + indexes_size) > items_offset) {
			err = -EFAULT;
			SSDFS_ERR("corrupted node: "
				  "hdr_size %zu, indexes_size %u, "
				  "items_offset %u\n",
				  hdr_size, indexes_size, items_offset);
			goto finish_area_resize;
		}

		unused_space = items_offset - (hdr_size + indexes_size);
		diff_size = new_size - items_size;

		if ((indexes_free_space + unused_space) < diff_size) {
			err = -EFAULT;
			SSDFS_ERR("corrupted_node: "
				  "indexes_free_space %u, unused_space %u, "
				  "diff_size %u\n",
				  indexes_free_space,
				  unused_space,
				  diff_size);
			goto finish_area_resize;
		}

		shift = diff_size / item_size;

		if (shift == 0 || shift >= U16_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid shift %u\n", shift);
			goto finish_area_resize;
		}

		start_index = (u16)shift;
		range_len = node->items_area.items_count;

		if (unused_space >= diff_size) {
			/*
			 * Do nothing.
			 * It doesn't need to correct index area.
			 */
		} else if (indexes_free_space >= diff_size) {
			node->index_area.area_size -= diff_size;
			node->index_area.index_capacity =
				node->index_area.area_size /
					node->index_area.index_size;

			if (node->index_area.area_size == 0) {
				node->index_area.offset = U32_MAX;
				node->index_area.start_hash = U64_MAX;
				node->index_area.end_hash = U64_MAX;
				atomic_set(&node->index_area.state,
					   SSDFS_BTREE_NODE_AREA_ABSENT);
			}
		} else {
			err = -ERANGE;
			SSDFS_ERR("node is corrupted: "
				  "indexes_free_space %u, "
				  "unused_space %u\n",
				  indexes_free_space,
				  unused_space);
			goto finish_area_resize;
		}

		switch (atomic_read(&node->items_area.state)) {
		case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
			node->items_area.offset -= diff_size;
			node->items_area.area_size += diff_size;
			node->items_area.free_space += diff_size;
			node->items_area.items_capacity =
				node->items_area.area_size / item_size;

			if (node->items_area.items_capacity == 0) {
				err = -ERANGE;
				atomic_set(&node->state,
					   SSDFS_BTREE_NODE_CORRUPTED);
				SSDFS_ERR("invalid items_capacity %u\n",
					  node->items_area.items_capacity);
				goto finish_area_resize;
			}
			break;

		case SSDFS_BTREE_NODE_AREA_ABSENT:
			node->items_area.offset = node->index_area.offset;
			node->items_area.offset += node->index_area.area_size;
			node->items_area.area_size = new_size;
			node->items_area.free_space = new_size;
			node->items_area.item_size = item_size;
			if (item_size >= U8_MAX)
				node->items_area.min_item_size = 0;
			else
				node->items_area.min_item_size = item_size;
			node->items_area.max_item_size = item_size;
			node->items_area.items_count = 0;
			node->items_area.items_capacity =
				node->items_area.area_size / item_size;

			if (node->items_area.items_capacity == 0) {
				err = -ERANGE;
				atomic_set(&node->state,
					   SSDFS_BTREE_NODE_CORRUPTED);
				SSDFS_ERR("invalid items_capacity %u\n",
					  node->items_area.items_capacity);
				goto finish_area_resize;
			}

			node->items_area.start_hash = U64_MAX;
			node->items_area.end_hash = U64_MAX;

			atomic_set(&node->items_area.state,
				   SSDFS_BTREE_NODE_ITEMS_AREA_EXIST);
			break;

		default:
			BUG();
		}

		if (range_len > 0) {
			err = ssdfs_shift_range_left(node, &node->items_area,
						     item_size,
						     start_index, range_len,
						     (u16)shift);
			if (unlikely(err)) {
				atomic_set(&node->state,
						SSDFS_BTREE_NODE_CORRUPTED);
				SSDFS_ERR("fail to shift range to left: "
					  "start_index %u, range_len %u, "
					  "shift %u, err %d\n",
					  start_index, range_len,
					  shift, err);
				goto finish_area_resize;
			}
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("items shift is not necessary: "
				  "range_len %u\n",
				  range_len);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		/*
		 * It makes sense to allocate the bitmap with taking into
		 * account that we will resize the node. So, it needs
		 * to allocate the index area in bitmap is equal to
		 * the whole node and items area is equal to the whole node.
		 * This technique provides opportunity not to resize or
		 * to shift the content of the bitmap.
		 */
	} else if (new_size < items_size) {
		/* decrease items area */
		diff_size = items_size - new_size;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("items_size %u, used_space %u, "
			  "node->items_area.items_count %u\n",
			  items_size, used_space,
			  node->items_area.items_count);
#endif /* CONFIG_SSDFS_DEBUG */

		if (items_free_space < diff_size) {
			err = -EFAULT;
			SSDFS_ERR("items_free_space %u < diff_size %u\n",
				  items_free_space, diff_size);
			goto finish_area_resize;
		}

		shift = diff_size / item_size;

		if (shift == 0 || shift >= U16_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid shift %u\n", shift);
			goto finish_area_resize;
		}

		if (node->items_area.items_count > 0) {
			start_index = 0;
			range_len = node->items_area.items_count;

			err = ssdfs_shift_range_right(node, &node->items_area,
						      item_size,
						      start_index, range_len,
						      (u16)shift);
			if (unlikely(err)) {
				atomic_set(&node->state,
					   SSDFS_BTREE_NODE_CORRUPTED);
				SSDFS_ERR("fail to shift range to left: "
					  "start_index %u, range_len %u, "
					  "shift %u, err %d\n",
					  start_index, range_len,
					  shift, err);
				goto finish_area_resize;
			}
		}

		if (node->items_area.area_size < diff_size)
			BUG();
		else if (node->items_area.area_size == diff_size) {
			node->items_area.offset = U32_MAX;
			node->items_area.area_size = 0;
			node->items_area.free_space = 0;
			node->items_area.items_count = 0;
			node->items_area.items_capacity = 0;
			node->items_area.start_hash = U64_MAX;
			node->items_area.end_hash = U64_MAX;
			atomic_set(&node->items_area.state,
				   SSDFS_BTREE_NODE_AREA_ABSENT);
		} else {
			node->items_area.offset += diff_size;
			node->items_area.area_size -= diff_size;
			node->items_area.free_space -= diff_size;
			node->items_area.items_capacity =
				node->items_area.area_size / item_size;

			capacity = node->items_area.items_capacity;
			count = node->items_area.items_count;
			if (capacity < count) {
				err = -ERANGE;
				atomic_set(&node->state,
					   SSDFS_BTREE_NODE_CORRUPTED);
				SSDFS_ERR("capacity %u < count %u\n",
					  capacity, count);
				goto finish_area_resize;
			}
		}

		switch (atomic_read(&node->index_area.state)) {
		case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
			node->index_area.area_size += diff_size;
			node->index_area.index_capacity =
				node->index_area.area_size /
					node->index_area.index_size;

			capacity = node->index_area.index_capacity;
			count = node->index_area.index_count;
			if (capacity < count) {
				err = -ERANGE;
				atomic_set(&node->state,
					   SSDFS_BTREE_NODE_CORRUPTED);
				SSDFS_ERR("capacity %u < count %u\n",
					  capacity, count);
				goto finish_area_resize;
			}
			break;

		case SSDFS_BTREE_NODE_AREA_ABSENT:
			node->index_area.offset = hdr_size;
			node->index_area.area_size = diff_size;
			node->index_area.index_size = index_size;
			node->index_area.index_count = 0;
			node->index_area.index_capacity =
				node->index_area.area_size /
					node->index_area.index_size;

			if (node->index_area.index_capacity == 0) {
				err = -ERANGE;
				atomic_set(&node->state,
					   SSDFS_BTREE_NODE_CORRUPTED);
				SSDFS_ERR("capacity == 0\n");
				goto finish_area_resize;
			}

			node->index_area.start_hash = U64_MAX;
			node->index_area.end_hash = U64_MAX;

			atomic_set(&node->items_area.state,
				   SSDFS_BTREE_NODE_INDEX_AREA_EXIST);
			break;

		default:
			BUG();
		}

		/*
		 * It makes sense to allocate the bitmap with taking into
		 * account that we will resize the node. So, it needs
		 * to allocate the index area in bitmap is equal to
		 * the whole node and items area is equal to the whole node.
		 * This technique provides opportunity not to resize or
		 * to shift the content of the bitmap.
		 */
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no necessity to resize: "
			  "new_size %u, items_size %u\n",
			  new_size, items_size);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_area_resize;
	}

	node->bmap_array.item_start_bit =
			node->bmap_array.index_start_bit +
			node->index_area.index_capacity;

	index_capacity = node->index_area.index_capacity;
	items_capacity = node->items_area.items_capacity;
	index_start_bit = node->bmap_array.index_start_bit;
	item_start_bit = node->bmap_array.item_start_bit;

	node->bmap_array.bits_count = index_capacity + items_capacity + 1;
	bits_count = node->bmap_array.bits_count;

	if ((index_start_bit + index_capacity) > item_start_bit) {
		err = -ERANGE;
		atomic_set(&node->state,
				SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid shift: "
			  "index_start_bit %lu, index_capacity %u, "
			  "item_start_bit %lu\n",
			  index_start_bit, index_capacity, item_start_bit);
		goto finish_area_resize;
	}

	if ((index_start_bit + index_capacity) > bits_count) {
		err = -ERANGE;
		atomic_set(&node->state,
				SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid shift: "
			  "index_start_bit %lu, index_capacity %u, "
			  "bits_count %lu\n",
			  index_start_bit, index_capacity, bits_count);
		goto finish_area_resize;
	}

	if ((item_start_bit + items_capacity) > bits_count) {
		err = -ERANGE;
		atomic_set(&node->state,
				SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid shift: "
			  "item_start_bit %lu, items_capacity %u, "
			  "bits_count %lu\n",
			  item_start_bit, items_capacity, bits_count);
		goto finish_area_resize;
	}

	switch (atomic_read(&node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		index_area_exist = true;
		break;

	default:
		index_area_exist = false;
		break;
	}

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		items_area_exist = true;
		break;

	default:
		items_area_exist = false;
		break;
	}

	if (index_area_exist && items_area_exist) {
		atomic_set(&node->type, SSDFS_BTREE_HYBRID_NODE);
		atomic_or(SSDFS_BTREE_NODE_HAS_INDEX_AREA,
			  &node->flags);
		atomic_or(SSDFS_BTREE_NODE_HAS_ITEMS_AREA,
			  &node->flags);
	} else if (index_area_exist) {
		atomic_set(&node->type, SSDFS_BTREE_INDEX_NODE);
		atomic_or(SSDFS_BTREE_NODE_HAS_INDEX_AREA,
			  &node->flags);
		atomic_and(~SSDFS_BTREE_NODE_HAS_ITEMS_AREA,
			  &node->flags);
	} else if (items_area_exist) {
		atomic_set(&node->type, SSDFS_BTREE_LEAF_NODE);
		atomic_and(~SSDFS_BTREE_NODE_HAS_INDEX_AREA,
			  &node->flags);
		atomic_or(SSDFS_BTREE_NODE_HAS_ITEMS_AREA,
			  &node->flags);
	} else
		BUG();

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_area: offset %u, area_size %u, "
		  "free_space %u, capacity %u; "
		  "index_area: offset %u, area_size %u, "
		  "capacity %u\n",
		  node->items_area.offset,
		  node->items_area.area_size,
		  node->items_area.free_space,
		  node->items_area.items_capacity,
		  node->index_area.offset,
		  node->index_area.area_size,
		  node->index_area.index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	atomic_set(&node->state, SSDFS_BTREE_NODE_DIRTY);

finish_area_resize:
	up_write(&node->bmap_array.lock);

	return err;
}

/*
 * ssdfs_btree_node_get_hash_range() - extract hash range
 */
int ssdfs_btree_node_get_hash_range(struct ssdfs_btree_search *search,
				    u64 *start_hash, u64 *end_hash,
				    u16 *items_count)
{
	struct ssdfs_btree_node *node = NULL;
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !start_hash || !end_hash || !items_count);

	SSDFS_DBG("search %p, start_hash %p, "
		  "end_hash %p, items_count %p\n",
		  search, start_hash, end_hash, items_count);

	ssdfs_debug_btree_search_object(search);
#endif /* CONFIG_SSDFS_DEBUG */

	*start_hash = *end_hash = U64_MAX;
	*items_count = 0;

	switch (search->node.state) {
	case SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC:
	case SSDFS_BTREE_SEARCH_FOUND_INDEX_NODE_DESC:
		node = search->node.child;
		if (!node) {
			SSDFS_ERR("node pointer is NULL\n");
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("unexpected node state %#x\n",
			  search->node.state);
		return -ERANGE;
	}

	state = atomic_read(&node->items_area.state);
	switch (state) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected items area's state %#x\n",
			  state);
		return -ERANGE;
	}

	down_read(&node->header_lock);
	*start_hash = node->items_area.start_hash;
	*end_hash = node->items_area.end_hash;
	*items_count = node->items_area.items_count;
	up_read(&node->header_lock);

	return 0;
}

void ssdfs_show_btree_node_info(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_BTREE_CONSISTENCY_CHECK
	int i;

	BUG_ON(!node);

	SSDFS_ERR("STATIC DATA: node_id %u, height %d, "
		  "owner_ino %llu, "
		  "node_size %u, pages_per_node %u, "
		  "create_cno %llu, tree %p, "
		  "parent_node %p, node_ops %p\n",
		  node->node_id, atomic_read(&node->height),
		  node->tree->owner_ino,
		  node->node_size, node->pages_per_node,
		  node->create_cno, node->tree,
		  node->parent_node, node->node_ops);

	if (node->parent_node) {
		SSDFS_ERR("PARENT_NODE: node_id %u, height %d, "
			  "state %#x, type %#x\n",
			  node->parent_node->node_id,
			  atomic_read(&node->parent_node->height),
			  atomic_read(&node->parent_node->state),
			  atomic_read(&node->parent_node->type));
	}

	SSDFS_ERR("MUTABLE DATA: refs_count %d, state %#x, "
		  "flags %#x, type %#x\n",
		  atomic_read(&node->refs_count),
		  atomic_read(&node->state),
		  atomic_read(&node->flags),
		  atomic_read(&node->type));

	down_read(&node->header_lock);

	SSDFS_ERR("INDEX_AREA: state %#x, "
		  "offset %u, size %u, "
		  "index_size %u, index_count %u, "
		  "index_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  atomic_read(&node->index_area.state),
		  node->index_area.offset,
		  node->index_area.area_size,
		  node->index_area.index_size,
		  node->index_area.index_count,
		  node->index_area.index_capacity,
		  node->index_area.start_hash,
		  node->index_area.end_hash);

	SSDFS_ERR("ITEMS_AREA: state %#x, "
		  "offset %u, size %u, free_space %u, "
		  "item_size %u, min_item_size %u, "
		  "max_item_size %u, items_count %u, "
		  "items_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  atomic_read(&node->items_area.state),
		  node->items_area.offset,
		  node->items_area.area_size,
		  node->items_area.free_space,
		  node->items_area.item_size,
		  node->items_area.min_item_size,
		  node->items_area.max_item_size,
		  node->items_area.items_count,
		  node->items_area.items_capacity,
		  node->items_area.start_hash,
		  node->items_area.end_hash);

	SSDFS_ERR("LOOKUP_TBL_AREA: state %#x, "
		  "offset %u, size %u, "
		  "index_size %u, index_count %u, "
		  "index_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  atomic_read(&node->lookup_tbl_area.state),
		  node->lookup_tbl_area.offset,
		  node->lookup_tbl_area.area_size,
		  node->lookup_tbl_area.index_size,
		  node->lookup_tbl_area.index_count,
		  node->lookup_tbl_area.index_capacity,
		  node->lookup_tbl_area.start_hash,
		  node->lookup_tbl_area.end_hash);

	SSDFS_ERR("HASH_TBL_AREA: state %#x, "
		  "offset %u, size %u, "
		  "index_size %u, index_count %u, "
		  "index_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  atomic_read(&node->hash_tbl_area.state),
		  node->hash_tbl_area.offset,
		  node->hash_tbl_area.area_size,
		  node->hash_tbl_area.index_size,
		  node->hash_tbl_area.index_count,
		  node->hash_tbl_area.index_capacity,
		  node->hash_tbl_area.start_hash,
		  node->hash_tbl_area.end_hash);

	up_read(&node->header_lock);

	spin_lock(&node->descriptor_lock);

	SSDFS_ERR("NODE DESCRIPTOR: is_locked %d, "
		  "update_cno %llu, seg %p, "
		  "completion_done %d\n",
		  spin_is_locked(&node->descriptor_lock),
		  node->update_cno, node->seg,
		  completion_done(&node->init_end));

	SSDFS_ERR("NODE_INDEX: node_id %u, node_type %#x, "
		  "height %u, flags %#x, hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(node->node_index.node_id),
		  node->node_index.node_type,
		  node->node_index.height,
		  le16_to_cpu(node->node_index.flags),
		  le64_to_cpu(node->node_index.index.hash),
		  le64_to_cpu(node->node_index.index.extent.seg_id),
		  le32_to_cpu(node->node_index.index.extent.logical_blk),
		  le32_to_cpu(node->node_index.index.extent.len));

	SSDFS_ERR("EXTENT: seg_id %llu, logical_blk %u, len %u\n",
		  le64_to_cpu(node->extent.seg_id),
		  le32_to_cpu(node->extent.logical_blk),
		  le32_to_cpu(node->extent.len));

	if (node->seg) {
		SSDFS_ERR("SEGMENT: seg_id %llu, seg_type %#x, "
			  "seg_state %#x, refs_count %d\n",
			  node->seg->seg_id,
			  node->seg->seg_type,
			  atomic_read(&node->seg->seg_state),
			  atomic_read(&node->seg->refs_count));
	}

	spin_unlock(&node->descriptor_lock);

	down_read(&node->bmap_array.lock);

	SSDFS_ERR("BITMAP ARRAY: bits_count %lu, "
		  "bmap_bytes %zu, index_start_bit %lu, "
		  "item_start_bit %lu\n",
		  node->bmap_array.bits_count,
		  node->bmap_array.bmap_bytes,
		  node->bmap_array.index_start_bit,
		  node->bmap_array.item_start_bit);

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		struct ssdfs_state_bitmap *bmap;

		bmap = &node->bmap_array.bmap[i];

		SSDFS_ERR("BITMAP: index %d, is_locked %d, "
			  "flags %#x, ptr %p\n",
			  i, spin_is_locked(&bmap->lock),
			  bmap->flags, bmap->ptr);
	}

	SSDFS_ERR("WAIT_QUEUE: is_active %d\n",
		  waitqueue_active(&node->wait_queue));

	up_read(&node->bmap_array.lock);
#endif /* CONFIG_SSDFS_BTREE_CONSISTENCY_CHECK */
}

void ssdfs_debug_btree_node_object(struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i, j, k;

	BUG_ON(!node);

	SSDFS_DBG("STATIC DATA: node_id %u, height %d, "
		  "owner_ino %llu, "
		  "node_size %u, pages_per_node %u, "
		  "create_cno %llu, tree %p, "
		  "parent_node %p, node_ops %p\n",
		  node->node_id, atomic_read(&node->height),
		  node->tree->owner_ino,
		  node->node_size, node->pages_per_node,
		  node->create_cno, node->tree,
		  node->parent_node, node->node_ops);

	if (node->parent_node) {
		SSDFS_DBG("PARENT_NODE: node_id %u, height %d, "
			  "state %#x, type %#x\n",
			  node->parent_node->node_id,
			  atomic_read(&node->parent_node->height),
			  atomic_read(&node->parent_node->state),
			  atomic_read(&node->parent_node->type));
	}

	SSDFS_DBG("MUTABLE DATA: refs_count %d, state %#x, "
		  "flags %#x, type %#x\n",
		  atomic_read(&node->refs_count),
		  atomic_read(&node->state),
		  atomic_read(&node->flags),
		  atomic_read(&node->type));

	SSDFS_DBG("NODE HEADER: is_locked %d\n",
		  rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("RAW HEADER DUMP:\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				&node->raw,
				sizeof(node->raw));
	SSDFS_DBG("\n");

	SSDFS_DBG("INDEX_AREA: state %#x, "
		  "offset %u, size %u, "
		  "index_size %u, index_count %u, "
		  "index_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  atomic_read(&node->index_area.state),
		  node->index_area.offset,
		  node->index_area.area_size,
		  node->index_area.index_size,
		  node->index_area.index_count,
		  node->index_area.index_capacity,
		  node->index_area.start_hash,
		  node->index_area.end_hash);

	SSDFS_DBG("ITEMS_AREA: state %#x, "
		  "offset %u, size %u, free_space %u, "
		  "item_size %u, min_item_size %u, "
		  "max_item_size %u, items_count %u, "
		  "items_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  atomic_read(&node->items_area.state),
		  node->items_area.offset,
		  node->items_area.area_size,
		  node->items_area.free_space,
		  node->items_area.item_size,
		  node->items_area.min_item_size,
		  node->items_area.max_item_size,
		  node->items_area.items_count,
		  node->items_area.items_capacity,
		  node->items_area.start_hash,
		  node->items_area.end_hash);

	SSDFS_DBG("LOOKUP_TBL_AREA: state %#x, "
		  "offset %u, size %u, "
		  "index_size %u, index_count %u, "
		  "index_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  atomic_read(&node->lookup_tbl_area.state),
		  node->lookup_tbl_area.offset,
		  node->lookup_tbl_area.area_size,
		  node->lookup_tbl_area.index_size,
		  node->lookup_tbl_area.index_count,
		  node->lookup_tbl_area.index_capacity,
		  node->lookup_tbl_area.start_hash,
		  node->lookup_tbl_area.end_hash);

	SSDFS_DBG("HASH_TBL_AREA: state %#x, "
		  "offset %u, size %u, "
		  "index_size %u, index_count %u, "
		  "index_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  atomic_read(&node->hash_tbl_area.state),
		  node->hash_tbl_area.offset,
		  node->hash_tbl_area.area_size,
		  node->hash_tbl_area.index_size,
		  node->hash_tbl_area.index_count,
		  node->hash_tbl_area.index_capacity,
		  node->hash_tbl_area.start_hash,
		  node->hash_tbl_area.end_hash);

	SSDFS_DBG("NODE DESCRIPTOR: is_locked %d, "
		  "update_cno %llu, seg %p, "
		  "completion_done %d\n",
		  spin_is_locked(&node->descriptor_lock),
		  node->update_cno, node->seg,
		  completion_done(&node->init_end));

	SSDFS_DBG("NODE_INDEX: node_id %u, node_type %#x, "
		  "height %u, flags %#x, hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(node->node_index.node_id),
		  node->node_index.node_type,
		  node->node_index.height,
		  le16_to_cpu(node->node_index.flags),
		  le64_to_cpu(node->node_index.index.hash),
		  le64_to_cpu(node->node_index.index.extent.seg_id),
		  le32_to_cpu(node->node_index.index.extent.logical_blk),
		  le32_to_cpu(node->node_index.index.extent.len));

	SSDFS_DBG("EXTENT: seg_id %llu, logical_blk %u, len %u\n",
		  le64_to_cpu(node->extent.seg_id),
		  le32_to_cpu(node->extent.logical_blk),
		  le32_to_cpu(node->extent.len));

	if (node->seg) {
		SSDFS_DBG("SEGMENT: seg_id %llu, seg_type %#x, "
			  "seg_state %#x, refs_count %d\n",
			  node->seg->seg_id,
			  node->seg->seg_type,
			  atomic_read(&node->seg->seg_state),
			  atomic_read(&node->seg->refs_count));
	}

	SSDFS_DBG("BITMAP ARRAY: is_locked %d, bits_count %lu, "
		  "bmap_bytes %zu, index_start_bit %lu, "
		  "item_start_bit %lu\n",
		  rwsem_is_locked(&node->bmap_array.lock),
		  node->bmap_array.bits_count,
		  node->bmap_array.bmap_bytes,
		  node->bmap_array.index_start_bit,
		  node->bmap_array.item_start_bit);

	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		struct ssdfs_state_bitmap *bmap;

		bmap = &node->bmap_array.bmap[i];

		SSDFS_DBG("BITMAP: index %d, is_locked %d, "
			  "flags %#x, ptr %p\n",
			  i, spin_is_locked(&bmap->lock),
			  bmap->flags, bmap->ptr);

		if (bmap->ptr) {
			SSDFS_DBG("BMAP DUMP: ");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     bmap->ptr,
					     node->bmap_array.bmap_bytes);
			SSDFS_DBG("\n");
		}
	}

	SSDFS_DBG("WAIT_QUEUE: is_active %d\n",
		  waitqueue_active(&node->wait_queue));

	SSDFS_DBG("NODE CONTENT: is_locked %d, blks_count %u\n",
		  rwsem_is_locked(&node->full_lock),
		  node->content.count);

	for (i = 0; i < node->content.count; i++) {
		struct ssdfs_content_block *blk;

		blk = &node->content.blocks[i];

		for (j = 0; j < folio_batch_count(&blk->batch); j++) {
			struct folio *folio;
			void *kaddr;
			size_t capacity;

			folio = blk->batch.folios[i];

			if (!folio)
				continue;

			capacity = folio_size(folio);
			k = 0;

			while (capacity > 0) {
				kaddr = kmap_local_folio(folio, k * PAGE_SIZE);
				SSDFS_DBG("PAGE DUMP: blk_index %d, "
					  "folio_index %d, "
					  "page_in_folio %d\n",
					  i, j, k);
				print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						     kaddr,
						     PAGE_SIZE);
				SSDFS_DBG("\n");
				kunmap_local(kaddr);

				k++;
				capacity -= PAGE_SIZE;
			}
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */
}
