// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/btree_hierarchy.c - btree hierarchy functionality implementation.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "page_array.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "extents_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "btree_hierarchy.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_btree_hierarchy_page_leaks;
atomic64_t ssdfs_btree_hierarchy_folio_leaks;
atomic64_t ssdfs_btree_hierarchy_memory_leaks;
atomic64_t ssdfs_btree_hierarchy_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_btree_hierarchy_cache_leaks_increment(void *kaddr)
 * void ssdfs_btree_hierarchy_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_btree_hierarchy_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_btree_hierarchy_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_btree_hierarchy_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_btree_hierarchy_kfree(void *kaddr)
 * struct page *ssdfs_btree_hierarchy_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_btree_hierarchy_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_btree_hierarchy_free_page(struct page *page)
 * void ssdfs_btree_hierarchy_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(btree_hierarchy)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(btree_hierarchy)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_btree_hierarchy_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_btree_hierarchy_page_leaks, 0);
	atomic64_set(&ssdfs_btree_hierarchy_folio_leaks, 0);
	atomic64_set(&ssdfs_btree_hierarchy_memory_leaks, 0);
	atomic64_set(&ssdfs_btree_hierarchy_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_btree_hierarchy_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_btree_hierarchy_page_leaks) != 0) {
		SSDFS_ERR("BTREE HIERARCHY: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_btree_hierarchy_page_leaks));
	}

	if (atomic64_read(&ssdfs_btree_hierarchy_folio_leaks) != 0) {
		SSDFS_ERR("BTREE HIERARCHY: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_btree_hierarchy_folio_leaks));
	}

	if (atomic64_read(&ssdfs_btree_hierarchy_memory_leaks) != 0) {
		SSDFS_ERR("BTREE HIERARCHY: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_btree_hierarchy_memory_leaks));
	}

	if (atomic64_read(&ssdfs_btree_hierarchy_cache_leaks) != 0) {
		SSDFS_ERR("BTREE HIERARCHY: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_btree_hierarchy_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_define_hierarchy_height() - define hierarchy's height
 * @tree: btree object
 *
 * This method tries to define the hierarchy's height.
 */
static
int ssdfs_define_hierarchy_height(struct ssdfs_btree *tree)
{
	int tree_height;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);

	SSDFS_DBG("tree %p\n", tree);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_height = atomic_read(&tree->height);
	if (tree_height < 0) {
		SSDFS_WARN("invalid tree_height %d\n",
			   tree_height);
		tree_height = 0;
	}

	if (tree_height == 0) {
		/* root node + child node */
		tree_height = 2;
	} else {
		/* pre-allocate additional level */
		tree_height += 1;
	}

	return tree_height;
}

/*
 * ssdfs_btree_hierarchy_init() - init hierarchy object
 * @tree: btree object
 *
 * This method tries to init the memory for the hierarchy object.
 */
void ssdfs_btree_hierarchy_init(struct ssdfs_btree *tree,
				struct ssdfs_btree_hierarchy *ptr)
{
	int tree_height;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);

	SSDFS_DBG("hierarchy %p\n", ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_height = ssdfs_define_hierarchy_height(tree);

	ptr->desc.height = tree_height;
	ptr->desc.increment_height = false;
	ptr->desc.node_size = tree->node_size;
	ptr->desc.index_size = tree->index_size;
	ptr->desc.min_item_size = tree->min_item_size;
	ptr->desc.max_item_size = tree->max_item_size;
	ptr->desc.index_area_min_size = tree->index_area_min_size;

	for (i = 0; i < tree_height; i++) {
		ptr->array_ptr[i]->flags = 0;

		ptr->array_ptr[i]->index_area.area_size = U32_MAX;
		ptr->array_ptr[i]->index_area.free_space = U32_MAX;
		ptr->array_ptr[i]->index_area.hash.start = U64_MAX;
		ptr->array_ptr[i]->index_area.hash.end = U64_MAX;
		ptr->array_ptr[i]->index_area.add.op_state =
				SSDFS_BTREE_AREA_OP_UNKNOWN;
		ptr->array_ptr[i]->index_area.add.hash.start = U64_MAX;
		ptr->array_ptr[i]->index_area.add.hash.end = U64_MAX;
		ptr->array_ptr[i]->index_area.add.pos.state =
				SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED;
		ptr->array_ptr[i]->index_area.add.pos.start = U16_MAX;
		ptr->array_ptr[i]->index_area.add.pos.count = 0;
		ptr->array_ptr[i]->index_area.insert.op_state =
				SSDFS_BTREE_AREA_OP_UNKNOWN;
		ptr->array_ptr[i]->index_area.insert.hash.start = U64_MAX;
		ptr->array_ptr[i]->index_area.insert.hash.end = U64_MAX;
		ptr->array_ptr[i]->index_area.insert.pos.state =
				SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED;
		ptr->array_ptr[i]->index_area.insert.pos.start = U16_MAX;
		ptr->array_ptr[i]->index_area.insert.pos.count = 0;
		ptr->array_ptr[i]->index_area.move.op_state =
				SSDFS_BTREE_AREA_OP_UNKNOWN;
		ptr->array_ptr[i]->index_area.move.direction =
					SSDFS_BTREE_MOVE_NOWHERE;
		ptr->array_ptr[i]->index_area.move.pos.state =
				SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED;
		ptr->array_ptr[i]->index_area.move.pos.start = U16_MAX;
		ptr->array_ptr[i]->index_area.move.pos.count = 0;
		ptr->array_ptr[i]->index_area.delete.op_state =
				SSDFS_BTREE_AREA_OP_UNKNOWN;
		memset(&ptr->array_ptr[i]->index_area.delete.node_index,
			0xFF, sizeof(struct ssdfs_btree_index_key));

		ptr->array_ptr[i]->items_area.area_size = U32_MAX;
		ptr->array_ptr[i]->items_area.free_space = U32_MAX;
		ptr->array_ptr[i]->items_area.hash.start = U64_MAX;
		ptr->array_ptr[i]->items_area.hash.end = U64_MAX;
		ptr->array_ptr[i]->items_area.add.op_state =
				SSDFS_BTREE_AREA_OP_UNKNOWN;
		ptr->array_ptr[i]->items_area.add.hash.start = U64_MAX;
		ptr->array_ptr[i]->items_area.add.hash.end = U64_MAX;
		ptr->array_ptr[i]->items_area.add.pos.state =
				SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED;
		ptr->array_ptr[i]->items_area.add.pos.start = U16_MAX;
		ptr->array_ptr[i]->items_area.add.pos.count = 0;
		ptr->array_ptr[i]->items_area.insert.op_state =
				SSDFS_BTREE_AREA_OP_UNKNOWN;
		ptr->array_ptr[i]->items_area.insert.hash.start = U64_MAX;
		ptr->array_ptr[i]->items_area.insert.hash.end = U64_MAX;
		ptr->array_ptr[i]->items_area.insert.pos.state =
				SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED;
		ptr->array_ptr[i]->items_area.insert.pos.start = U16_MAX;
		ptr->array_ptr[i]->items_area.insert.pos.count = 0;
		ptr->array_ptr[i]->items_area.move.op_state =
				SSDFS_BTREE_AREA_OP_UNKNOWN;
		ptr->array_ptr[i]->items_area.move.direction =
					SSDFS_BTREE_MOVE_NOWHERE;
		ptr->array_ptr[i]->items_area.move.pos.state =
				SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED;
		ptr->array_ptr[i]->items_area.move.pos.start = U16_MAX;
		ptr->array_ptr[i]->items_area.move.pos.count = 0;

		ptr->array_ptr[i]->nodes.old_node.type =
				SSDFS_BTREE_NODE_UNKNOWN_TYPE;
		ptr->array_ptr[i]->nodes.old_node.index_hash.start = U64_MAX;
		ptr->array_ptr[i]->nodes.old_node.index_hash.end = U64_MAX;
		ptr->array_ptr[i]->nodes.old_node.items_hash.start = U64_MAX;
		ptr->array_ptr[i]->nodes.old_node.items_hash.end = U64_MAX;
		ptr->array_ptr[i]->nodes.old_node.ptr = NULL;
		ptr->array_ptr[i]->nodes.new_node.type =
				SSDFS_BTREE_NODE_UNKNOWN_TYPE;
		ptr->array_ptr[i]->nodes.new_node.index_hash.start = U64_MAX;
		ptr->array_ptr[i]->nodes.new_node.index_hash.end = U64_MAX;
		ptr->array_ptr[i]->nodes.new_node.items_hash.start = U64_MAX;
		ptr->array_ptr[i]->nodes.new_node.items_hash.end = U64_MAX;
		ptr->array_ptr[i]->nodes.new_node.ptr = NULL;
	}
}

/*
 * ssdfs_btree_hierarchy_allocate() - allocate hierarchy object
 * @tree: btree object
 *
 * This method tries to allocate the memory for the hierarchy object.
 *
 * RETURN:
 * [success] - pointer on the allocated hierarchy object.
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate the memory.
 */
struct ssdfs_btree_hierarchy *
ssdfs_btree_hierarchy_allocate(struct ssdfs_btree *tree)
{
	struct ssdfs_btree_hierarchy *ptr;
	size_t desc_size = sizeof(struct ssdfs_btree_hierarchy);
	size_t ptr_size = sizeof(struct ssdfs_btree_level *);
	size_t level_size = sizeof(struct ssdfs_btree_level);
	int tree_height;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);

	SSDFS_DBG("tree %p\n", tree);
#endif /* CONFIG_SSDFS_DEBUG */

	tree_height = ssdfs_define_hierarchy_height(tree);
	if (tree_height <= 0) {
		SSDFS_ERR("invalid tree_height %d\n",
			  tree_height);
		return ERR_PTR(-ERANGE);
	}

	ptr = ssdfs_btree_hierarchy_kzalloc(desc_size, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate tree levels' array\n");
		return ERR_PTR(-ENOMEM);
	}

	ptr->array_ptr = ssdfs_btree_hierarchy_kzalloc(ptr_size * tree_height,
							GFP_KERNEL);
	if (!ptr) {
		ssdfs_btree_hierarchy_kfree(ptr);
		SSDFS_ERR("fail to allocate tree levels' array\n");
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < tree_height; i++) {
		ptr->array_ptr[i] = ssdfs_btree_hierarchy_kzalloc(level_size,
								  GFP_KERNEL);
		if (!ptr) {
			for (--i; i >= 0; i--) {
				ssdfs_btree_hierarchy_kfree(ptr->array_ptr[i]);
				ptr->array_ptr[i] = NULL;
			}

			ssdfs_btree_hierarchy_kfree(ptr->array_ptr);
			ptr->array_ptr = NULL;
			ssdfs_btree_hierarchy_kfree(ptr);
			SSDFS_ERR("fail to allocate tree levels' array\n");
			return ERR_PTR(-ENOMEM);
		}
	}

	ssdfs_btree_hierarchy_init(tree, ptr);

	return ptr;
}

/*
 * ssdfs_btree_hierarchy_free() - free the hierarchy object
 * @hierarchy: pointer on the hierarchy object
 */
void ssdfs_btree_hierarchy_free(struct ssdfs_btree_hierarchy *hierarchy)
{
	int tree_height;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hierarchy %p\n", hierarchy);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!hierarchy)
		return;

	tree_height = hierarchy->desc.height;

	for (i = 0; i < tree_height; i++) {
		ssdfs_btree_hierarchy_kfree(hierarchy->array_ptr[i]);
		hierarchy->array_ptr[i] = NULL;
	}

	ssdfs_btree_hierarchy_kfree(hierarchy->array_ptr);
	hierarchy->array_ptr = NULL;

	ssdfs_btree_hierarchy_kfree(hierarchy);
}

/*
 * ssdfs_btree_prepare_add_node() - prepare the level for adding node
 * @tree: btree object
 * @node_type: type of adding node
 * @start_hash: starting hash value
 * @end_hash: ending hash value
 * @level: level object [out]
 * @node: node object [in]
 */
void ssdfs_btree_prepare_add_node(struct ssdfs_btree *tree,
				  int node_type,
				  u64 start_hash, u64 end_hash,
				  struct ssdfs_btree_level *level,
				  struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !level);

	SSDFS_DBG("tree %p, level %p, node_type %#x, "
		  "start_hash %llx, end_hash %llx\n",
		  tree, level, node_type, start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	level->flags |= SSDFS_BTREE_LEVEL_ADD_NODE;
	level->nodes.new_node.type = node_type;
	level->nodes.old_node.ptr = node;

	level->index_area.area_size = tree->index_area_min_size;
	level->index_area.free_space = tree->index_area_min_size;
	level->items_area.area_size =
			tree->node_size - tree->index_area_min_size;
	level->items_area.free_space =
			tree->node_size - tree->index_area_min_size;
	level->items_area.hash.start = start_hash;
	level->items_area.hash.end = end_hash;
}

/*
 * ssdfs_btree_prepare_add_index() - prepare the level for adding index
 * @level: level object [out]
 * @start_hash: starting hash value
 * @end_hash: ending hash value
 * @node: node object [in]
 *
 * This method tries to prepare the @level for adding the index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_prepare_add_index(struct ssdfs_btree_level *level,
				  u64 start_hash, u64 end_hash,
				  struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_node_insert *add;
	int index_area_state;
	int items_area_state;
	u32 free_space;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level || !node);

	SSDFS_DBG("level %p, node %p, "
		  "start_hash %llx, end_hash %llx\n",
		  level, node, start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	if (level->flags & SSDFS_BTREE_LEVEL_ADD_NODE) {
		level->flags |= SSDFS_BTREE_LEVEL_ADD_INDEX;

		add = &level->index_area.add;
		add->hash.start = start_hash;
		add->hash.end = end_hash;
		add->pos.start = 0;
		add->pos.state = SSDFS_HASH_RANGE_LEFT_ADJACENT;
		add->pos.count = 1;
		add->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

		return 0;
	}

	index_area_state = atomic_read(&node->index_area.state);
	items_area_state = atomic_read(&node->items_area.state);

	if (index_area_state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		SSDFS_ERR("index area is absent: "
			  "node_id %u, height %u\n",
			  node->node_id,
			  atomic_read(&node->height));
		return -ERANGE;
	}

	if (can_add_new_index(node)) {
		level->flags |= SSDFS_BTREE_LEVEL_ADD_INDEX;
		level->nodes.old_node.type = atomic_read(&node->type);
		level->nodes.old_node.ptr = node;
	} else if (atomic_read(&node->type) == SSDFS_BTREE_ROOT_NODE) {
		level->flags |= SSDFS_BTREE_LEVEL_ADD_INDEX;
		level->nodes.new_node.type = atomic_read(&node->type);
		level->nodes.new_node.ptr = node;
	} else if (level->flags & SSDFS_BTREE_TRY_RESIZE_INDEX_AREA) {
		level->flags |= SSDFS_BTREE_LEVEL_ADD_INDEX;
		level->nodes.new_node.type = atomic_read(&node->type);
		level->nodes.new_node.ptr = node;
	} else {
		SSDFS_ERR("fail to add a new index: "
			  "node_id %u, height %u\n",
			  node->node_id,
			  atomic_read(&node->height));
		return -ERANGE;
	}

	down_read(&node->header_lock);

	free_space = node->index_area.index_capacity;

	if (node->index_area.index_count > free_space) {
		err = -ERANGE;
		SSDFS_ERR("index_count %u > index_capacity %u\n",
			  node->index_area.index_count,
			  free_space);
		goto finish_prepare_level;
	}

	free_space -= node->index_area.index_count;
	free_space *= node->index_area.index_size;

	level->index_area.free_space = free_space;
	level->index_area.area_size = node->index_area.area_size;
	level->index_area.hash.start = node->index_area.start_hash;
	level->index_area.hash.end = node->index_area.end_hash;

	if (items_area_state == SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		if (node->items_area.free_space > node->node_size) {
			err = -ERANGE;
			SSDFS_ERR("free_space %u > node_size %u\n",
				  node->items_area.free_space,
				  node->node_size);
			goto finish_prepare_level;
		}

		level->items_area.free_space = node->items_area.free_space;
		level->items_area.area_size = node->items_area.area_size;
		level->items_area.hash.start = node->items_area.start_hash;
		level->items_area.hash.end = node->items_area.end_hash;
	}

finish_prepare_level:
	up_read(&node->header_lock);

	if (unlikely(err))
		return err;

	if (start_hash > end_hash) {
		SSDFS_ERR("invalid requested hash range: "
			  "start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		return -ERANGE;
	}

	add = &level->index_area.add;

	add->hash.start = start_hash;
	add->hash.end = end_hash;

	err = ssdfs_btree_node_find_index_position(node, start_hash,
						   &add->pos.start);
	if (err == -ENODATA) {
		if (add->pos.start >= U16_MAX) {
			SSDFS_ERR("fail to find the index position: "
				  "start_hash %llx, err %d\n",
				  start_hash, err);
			return err;
		} else
			err = 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the index position: "
			  "start_hash %llx, err %d\n",
			  start_hash, err);
		return err;
	} else if (level->index_area.hash.start != start_hash) {
		/*
		 * We've received the position of available
		 * index record. So, correct it for the real
		 * insert operation.
		 */
		add->pos.start++;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "level->index_area.hash.start %llx, "
		  "level->index_area.hash.end %llx\n",
		  start_hash, end_hash,
		  level->index_area.hash.start,
		  level->index_area.hash.end);
#endif /* CONFIG_SSDFS_DEBUG */

	if (end_hash < level->index_area.hash.start)
		add->pos.state = SSDFS_HASH_RANGE_LEFT_ADJACENT;
	else if (start_hash > level->index_area.hash.end)
		add->pos.state = SSDFS_HASH_RANGE_RIGHT_ADJACENT;
	else
		add->pos.state = SSDFS_HASH_RANGE_INTERSECTION;

	add->pos.count = 1;
	add->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;
	return 0;
}

static inline
void ssdfs_btree_cancel_add_index(struct ssdfs_btree_level *level)
{
	struct ssdfs_btree_node_insert *add;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level);

	SSDFS_DBG("level %p\n", level);
#endif /* CONFIG_SSDFS_DEBUG */

	level->flags &= ~SSDFS_BTREE_LEVEL_ADD_INDEX;

	add = &level->index_area.add;

	add->op_state = SSDFS_BTREE_AREA_OP_UNKNOWN;
	add->hash.start = U64_MAX;
	add->hash.end = U64_MAX;
	add->pos.state = SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED;
	add->pos.start = U16_MAX;
	add->pos.count = 0;
}

/*
 * ssdfs_btree_prepare_update_index() - prepare the level for index update
 * @level: level object [out]
 * @start_hash: starting hash value
 * @end_hash: ending hash value
 * @node: node object [in]
 *
 * This method tries to prepare the @level for adding the index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_prepare_update_index(struct ssdfs_btree_level *level,
				     u64 start_hash, u64 end_hash,
				     struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_node_insert *insert;
	int index_area_state;
	int items_area_state;
	u32 free_space;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level || !node);

	SSDFS_DBG("level %p, start_hash %llx, "
		  "end_hash %llx, node %p\n",
		  level, start_hash, end_hash, node);
#endif /* CONFIG_SSDFS_DEBUG */

	level->flags |= SSDFS_BTREE_LEVEL_UPDATE_INDEX;
	level->nodes.old_node.type = atomic_read(&node->type);
	level->nodes.old_node.ptr = node;

	index_area_state = atomic_read(&node->index_area.state);
	items_area_state = atomic_read(&node->items_area.state);

	if (index_area_state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		SSDFS_ERR("index area is absent: "
			  "node_id %u, height %u\n",
			  node->node_id,
			  atomic_read(&node->height));
		return -ERANGE;
	}

	down_read(&node->header_lock);

	free_space = node->index_area.index_capacity;

	if (node->index_area.index_count > free_space) {
		err = -ERANGE;
		SSDFS_ERR("index_count %u > index_capacity %u\n",
			  node->index_area.index_count,
			  free_space);
		goto finish_prepare_level;
	}

	free_space -= node->index_area.index_count;
	free_space *= node->index_area.index_size;

	level->index_area.free_space = free_space;
	level->index_area.area_size = node->index_area.area_size;
	level->index_area.hash.start = node->index_area.start_hash;
	level->index_area.hash.end = node->index_area.end_hash;

	if (start_hash > end_hash) {
		err = -ERANGE;
		SSDFS_ERR("invalid range: start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		goto finish_prepare_level;
	}

	if (!(level->index_area.hash.start <= start_hash &&
	      end_hash <= level->index_area.hash.end)) {
		err = -ERANGE;
		SSDFS_ERR("invalid hash range "
			  "(start_hash %llx, end_hash %llx), "
			  "node (start_hash %llx, end_hash %llx)\n",
			  start_hash, end_hash,
			  level->index_area.hash.start,
			  level->index_area.hash.end);
		goto finish_prepare_level;
	}

	if (items_area_state == SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		if (node->items_area.free_space > node->node_size) {
			err = -ERANGE;
			SSDFS_ERR("free_space %u > node_size %u\n",
				  node->items_area.free_space,
				  node->node_size);
			goto finish_prepare_level;
		}

		level->items_area.free_space = node->items_area.free_space;
		level->items_area.area_size = node->items_area.area_size;
		level->index_area.hash.start = node->items_area.start_hash;
		level->index_area.hash.end = node->items_area.end_hash;
	}

finish_prepare_level:
	up_read(&node->header_lock);

	if (unlikely(err))
		return err;

	insert = &level->index_area.insert;
	err = ssdfs_btree_node_find_index_position(node, start_hash,
						   &insert->pos.start);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the index position: "
			  "start_hash %llx, err %d\n",
			  start_hash, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "level->index_area.hash.start %llx, "
		  "level->index_area.hash.end %llx\n",
		  start_hash, end_hash,
		  level->index_area.hash.start,
		  level->index_area.hash.end);
#endif /* CONFIG_SSDFS_DEBUG */

	if (end_hash < level->index_area.hash.start)
		insert->pos.state = SSDFS_HASH_RANGE_LEFT_ADJACENT;
	else if (start_hash > level->index_area.hash.end)
		insert->pos.state = SSDFS_HASH_RANGE_RIGHT_ADJACENT;
	else
		insert->pos.state = SSDFS_HASH_RANGE_INTERSECTION;

	insert->pos.count = 1;
	insert->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;
	return 0;
}

/*
 * ssdfs_btree_prepare_do_nothing() - prepare the level for to do nothing
 * @level: level object [out]
 * @node: node object [in]
 *
 * This method tries to prepare the @level for to do nothing.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_prepare_do_nothing(struct ssdfs_btree_level *level,
				   struct ssdfs_btree_node *node)
{
	int index_area_state;
	int items_area_state;
	u32 free_space;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level || !node);

	SSDFS_DBG("level %p, node %p\n",
		  level, node);
#endif /* CONFIG_SSDFS_DEBUG */

	level->flags = 0;
	level->nodes.old_node.type = atomic_read(&node->type);
	level->nodes.old_node.ptr = node;

	index_area_state = atomic_read(&node->index_area.state);
	items_area_state = atomic_read(&node->items_area.state);

	if (index_area_state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		SSDFS_ERR("index area is absent: "
			  "node_id %u, height %u\n",
			  node->node_id,
			  atomic_read(&node->height));
		return -ERANGE;
	}

	down_read(&node->header_lock);

	free_space = node->index_area.index_capacity;

	if (node->index_area.index_count > free_space) {
		err = -ERANGE;
		SSDFS_ERR("index_count %u > index_capacity %u\n",
			  node->index_area.index_count,
			  free_space);
		goto finish_prepare_level;
	}

	free_space -= node->index_area.index_count;
	free_space *= node->index_area.index_size;

	level->index_area.free_space = free_space;
	level->index_area.area_size = node->index_area.area_size;
	level->index_area.hash.start = node->index_area.start_hash;
	level->index_area.hash.end = node->index_area.end_hash;

	if (items_area_state == SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		if (node->items_area.free_space > node->node_size) {
			err = -ERANGE;
			SSDFS_ERR("free_space %u > node_size %u\n",
				  node->items_area.free_space,
				  node->node_size);
			goto finish_prepare_level;
		}

		level->items_area.free_space = node->items_area.free_space;
		level->items_area.area_size = node->items_area.area_size;
		level->items_area.hash.start = node->items_area.start_hash;
		level->items_area.hash.end = node->items_area.end_hash;
	}

finish_prepare_level:
	up_read(&node->header_lock);

	return err;
}

/*
 * ssdfs_btree_prepare_insert_item() - prepare the level to insert item
 * @level: level object [out]
 * @search: search object
 * @node: node object [in]
 *
 * This method tries to prepare the @level to insert the item.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_prepare_insert_item(struct ssdfs_btree_level *level,
				    struct ssdfs_btree_search *search,
				    struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_node *parent;
	struct ssdfs_btree_node_insert *add;
	struct ssdfs_btree_node_move *move;
	int index_area_state;
	int items_area_state;
	u32 free_space;
	u8 index_size;
	u64 start_hash, end_hash;
	u16 items_count;
	u16 min_item_size, max_item_size;
	u32 insert_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level || !search || !node);

	SSDFS_DBG("level %p, node %p\n",
		  level, node);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
		/*
		 * Item will be added into a new node.
		 * The tree will grow.
		 * No logic is necessary for such case.
		 */
		return 0;

	case SSDFS_BTREE_INDEX_NODE:
		/*
		 * Item will be added into a new hybrid node.
		 * No logic is necessary for such case.
		 */
		return 0;

	default:
		/* continue logic */
		break;
	}

	level->flags |= SSDFS_BTREE_LEVEL_ADD_ITEM;
	level->nodes.old_node.type = atomic_read(&node->type);
	level->nodes.old_node.ptr = node;

	index_area_state = atomic_read(&node->index_area.state);
	items_area_state = atomic_read(&node->items_area.state);

	if (items_area_state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("items area is absent: "
			  "node_id %u, height %u\n",
			  node->node_id,
			  atomic_read(&node->height));
		return -ERANGE;
	}

	down_read(&node->header_lock);

	if (node->items_area.free_space > node->node_size) {
		err = -ERANGE;
		SSDFS_ERR("free_space %u > node_size %u\n",
			  node->items_area.free_space,
			  node->node_size);
		goto finish_prepare_level;
	}

	level->items_area.free_space = node->items_area.free_space;
	level->items_area.area_size = node->items_area.area_size;
	level->items_area.hash.start = node->items_area.start_hash;
	level->items_area.hash.end = node->items_area.end_hash;
	min_item_size = node->items_area.min_item_size;
	max_item_size = node->items_area.max_item_size;
	items_count = node->items_area.items_count;

	if (index_area_state == SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		free_space = node->index_area.index_capacity;

		if (node->index_area.index_count > free_space) {
			err = -ERANGE;
			SSDFS_ERR("index_count %u > index_capacity %u\n",
				  node->index_area.index_count,
				  free_space);
			goto finish_prepare_level;
		}

		free_space -= node->index_area.index_count;
		free_space *= node->index_area.index_size;

		index_size = node->index_area.index_size;

		level->index_area.free_space = free_space;
		level->index_area.area_size = node->index_area.area_size;
		level->index_area.hash.start = node->index_area.start_hash;
		level->index_area.hash.end = node->index_area.end_hash;
	}

finish_prepare_level:
	up_read(&node->header_lock);

	if (unlikely(err))
		return err;

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (start_hash > end_hash) {
		SSDFS_ERR("invalid requested hash range: "
			  "start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		return -ERANGE;
	}

	add = &level->items_area.add;

	add->hash.start = start_hash;
	add->hash.end = end_hash;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "level->items_area.hash.start %llx, "
		  "level->items_area.hash.end %llx\n",
		  start_hash, end_hash,
		  level->items_area.hash.start,
		  level->items_area.hash.end);
#endif /* CONFIG_SSDFS_DEBUG */

	if (items_count == 0) {
		add->pos.state = SSDFS_HASH_RANGE_OUT_OF_NODE;
		add->pos.start = 0;
		add->pos.count = search->request.count;
		add->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;
		return 0;
	} else if (end_hash < level->items_area.hash.start)
		add->pos.state = SSDFS_HASH_RANGE_LEFT_ADJACENT;
	else if (start_hash > level->items_area.hash.end)
		add->pos.state = SSDFS_HASH_RANGE_RIGHT_ADJACENT;
	else
		add->pos.state = SSDFS_HASH_RANGE_INTERSECTION;

	add->pos.start = search->result.start_index;
	add->pos.count = search->request.count;
	add->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

	switch (node->tree->type) {
	case SSDFS_INODES_BTREE:
		/* Inodes tree doesn't need in rebalancing */
		return 0;

	case SSDFS_EXTENTS_BTREE:
		switch (add->pos.state) {
		case SSDFS_HASH_RANGE_RIGHT_ADJACENT:
			/* skip rebalancing */
			return 0;

		default:
			/* continue rebalancing */
			break;
		}
		break;

	default:
		/* continue logic */
		break;
	}

	insert_size = max_item_size * search->request.count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("insert_size %u, free_space %u\n",
		  insert_size, level->items_area.free_space);
#endif /* CONFIG_SSDFS_DEBUG */

	if (insert_size == 0) {
		SSDFS_ERR("search->result.start_index %u, "
			  "search->request.count %u, "
			  "max_item_size %u, "
			  "insert_size %u\n",
			  search->result.start_index,
			  search->request.count,
			  max_item_size,
			  insert_size);
		return -ERANGE;
	}

	spin_lock(&node->descriptor_lock);
	parent = node->parent_node;
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!parent);
#endif /* CONFIG_SSDFS_DEBUG */

	if (level->items_area.free_space < insert_size) {
		u16 moving_items;

		if (can_add_new_index(parent))
			moving_items = items_count / 2;
		else
			moving_items = search->request.count;

		move = &level->items_area.move;

		switch (add->pos.state) {
		case SSDFS_HASH_RANGE_LEFT_ADJACENT:
			level->flags |= SSDFS_BTREE_ITEMS_AREA_NEED_MOVE;
			move->direction = SSDFS_BTREE_MOVE_TO_LEFT;
			move->pos.state = SSDFS_HASH_RANGE_INTERSECTION;
			move->pos.start = 0;
			move->pos.count = moving_items;
			move->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("MOVE_TO_LEFT: start %u, count %u\n",
				  move->pos.start, move->pos.count);
#endif /* CONFIG_SSDFS_DEBUG */
			break;

		case SSDFS_HASH_RANGE_INTERSECTION:
			level->flags |= SSDFS_BTREE_ITEMS_AREA_NEED_MOVE;
			move->direction = SSDFS_BTREE_MOVE_TO_RIGHT;
			move->pos.state = SSDFS_HASH_RANGE_INTERSECTION;
			move->pos.start = items_count - moving_items;
			move->pos.count = moving_items;
			move->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("MOVE_TO_RIGHT: start %u, count %u\n",
				  move->pos.start, move->pos.count);
#endif /* CONFIG_SSDFS_DEBUG */
			break;

		case SSDFS_HASH_RANGE_RIGHT_ADJACENT:
			/* do nothing */
			break;

		default:
			SSDFS_ERR("invalid insert position's state %#x\n",
				  add->pos.state);
			return -ERANGE;
		}
	}

	return 0;
}

static inline
void ssdfs_btree_cancel_insert_item(struct ssdfs_btree_level *level)
{
	struct ssdfs_btree_node_insert *add;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level);

	SSDFS_DBG("level %p\n", level);
#endif /* CONFIG_SSDFS_DEBUG */

	level->flags &= ~SSDFS_BTREE_LEVEL_ADD_ITEM;

	add = &level->items_area.add;

	add->op_state = SSDFS_BTREE_AREA_OP_UNKNOWN;
	add->hash.start = U64_MAX;
	add->hash.end = U64_MAX;
	add->pos.state = SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED;
	add->pos.start = U16_MAX;
	add->pos.count = 0;
}

/*
 * ssdfs_need_move_items_to_sibling() - does it need to move items?
 * @level: level object
 *
 * This method tries to check that the tree needs
 * to be rebalanced.
 */
static inline
bool ssdfs_need_move_items_to_sibling(struct ssdfs_btree_level *level)
{
	struct ssdfs_btree_node_move *move;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level);

	SSDFS_DBG("level %p\n", level);
#endif /* CONFIG_SSDFS_DEBUG */

	move = &level->items_area.move;

	if (level->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE) {
		switch (move->direction) {
		case SSDFS_BTREE_MOVE_TO_LEFT:
		case SSDFS_BTREE_MOVE_TO_RIGHT:
			return true;
		}
	}

	return false;
}

static inline
void ssdfs_btree_cancel_move_items_to_sibling(struct ssdfs_btree_level *level)
{
	struct ssdfs_btree_node_move *move;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level);

	SSDFS_DBG("level %p\n", level);
#endif /* CONFIG_SSDFS_DEBUG */

	move = &level->items_area.move;

	level->flags &= ~SSDFS_BTREE_ITEMS_AREA_NEED_MOVE;

	move->direction = SSDFS_BTREE_MOVE_NOWHERE;
	move->pos.state = SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED;
	move->pos.start = U16_MAX;
	move->pos.count = 0;
	move->op_state = SSDFS_BTREE_AREA_OP_UNKNOWN;
}

/*
 * can_index_area_being_increased() - does items area has enough free space?
 * @node: node object
 */
static inline
bool can_index_area_being_increased(struct ssdfs_btree_node *node)
{
	int flags;
	int items_area_state;
	int index_area_state;
	u32 items_area_free_space;
	u32 index_area_min_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	flags = atomic_read(&node->tree->flags);

	if (!(flags & SSDFS_BTREE_DESC_INDEX_AREA_RESIZABLE)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index area cannot be resized: "
			  "node %u\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	items_area_state = atomic_read(&node->items_area.state);
	index_area_state = atomic_read(&node->index_area.state);

	if (index_area_state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST)
		return false;

	if (items_area_state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST)
		return false;

	index_area_min_size = node->tree->index_area_min_size;

	down_read(&node->header_lock);
	items_area_free_space = node->items_area.free_space;
	up_read(&node->header_lock);

	return items_area_free_space >= index_area_min_size;
}

/*
 * ssdfs_check_capability_move_to_sibling() - check capability to rebalance tree
 * @level: level object
 *
 * This method tries to define the presence of free space in
 * sibling node with the goal to rebalance the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't free space.
 */
static
int ssdfs_check_capability_move_to_sibling(struct ssdfs_btree_level *level)
{
	struct ssdfs_btree *tree;
	struct ssdfs_btree_node *node, *parent_node;
	struct ssdfs_btree_node_move *move;
	struct ssdfs_btree_node_index_area area;
	struct ssdfs_btree_index_key index_key;
	u64 hash = U64_MAX;
	int items_area_state;
	int index_area_state;
	u16 index_count = 0;
	u16 index_capacity = 0;
	u16 vacant_indexes = 0;
	u16 index_position;
	u16 items_count;
	u16 items_capacity;
	u16 parent_items_count = 0;
	u16 parent_items_capacity = 0;
	u16 moving_items;
	int node_type;
	u32 node_id;
	bool is_resize_possible = false;
	spinlock_t *lock;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level);

	SSDFS_DBG("level %p\n", level);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(level->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE)) {
		SSDFS_DBG("no items should be moved\n");
		return 0;
	}

	move = &level->items_area.move;

	switch (move->direction) {
	case SSDFS_BTREE_MOVE_TO_LEFT:
	case SSDFS_BTREE_MOVE_TO_RIGHT:
		/* expected state */
		break;

	default:
		SSDFS_DBG("nothing should be done\n");
		return 0;
	}

	if (!level->nodes.old_node.ptr) {
		SSDFS_ERR("node pointer is empty\n");
		return -ERANGE;
	}

	node = level->nodes.old_node.ptr;
	tree = node->tree;

	spin_lock(&node->descriptor_lock);
	hash = le64_to_cpu(node->node_index.index.hash);
	spin_unlock(&node->descriptor_lock);

	items_area_state = atomic_read(&node->items_area.state);

	down_read(&node->header_lock);
	if (items_area_state == SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		items_count = node->items_area.items_count;
		items_capacity = node->items_area.items_capacity;
	} else
		err = -ERANGE;
	up_read(&node->header_lock);

	if (unlikely(err)) {
		SSDFS_ERR("items area is absent\n");
		return -ERANGE;
	}

	lock = &level->nodes.old_node.ptr->descriptor_lock;
	spin_lock(lock);
	node = level->nodes.old_node.ptr->parent_node;
	spin_unlock(lock);
	lock = NULL;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	is_resize_possible = can_index_area_being_increased(node);

	items_area_state = atomic_read(&node->items_area.state);
	index_area_state = atomic_read(&node->index_area.state);

	down_read(&node->header_lock);

	if (items_area_state == SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		parent_items_count = node->items_area.items_count;
		parent_items_capacity = node->items_area.items_capacity;
	}

	if (index_area_state == SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		index_count = node->index_area.index_count;
		index_capacity = node->index_area.index_capacity;
		vacant_indexes = index_capacity - index_count;
	} else
		err = -ERANGE;

	up_read(&node->header_lock);

	if (unlikely(err)) {
		SSDFS_ERR("index area is absent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_find_index_position(node, hash,
						   &index_position);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the index position: "
			  "hash %llx, err %d\n",
			  hash, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hash %llx, index_position %u\n",
		  hash, index_position);
#endif /* CONFIG_SSDFS_DEBUG */

	if (index_position >= index_count) {
		SSDFS_ERR("index_position %u >= index_count %u\n",
			  index_position, index_count);
		return -ERANGE;
	}

	switch (move->direction) {
	case SSDFS_BTREE_MOVE_TO_LEFT:
		if (index_position == 0) {
			SSDFS_DBG("no siblings on the left\n");

			if (vacant_indexes == 0 && !is_resize_possible) {
				/*
				 * Try to move to parent node
				 */
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("MOVE_TO_PARENT: start %u, count %u\n",
					  move->pos.start, move->pos.count);
#endif /* CONFIG_SSDFS_DEBUG */
				move->direction = SSDFS_BTREE_MOVE_TO_PARENT;
				moving_items = items_capacity / 4;
				move->pos.start = 0;
				move->pos.count = moving_items;
			}

			return -ENOSPC;
		}

		index_position--;
		break;

	case SSDFS_BTREE_MOVE_TO_RIGHT:
		if ((index_position + 1) == index_count) {
			SSDFS_DBG("no siblings on the right\n");

			if (vacant_indexes == 0 && !is_resize_possible) {
				/*
				 * Try to move to parent node
				 */
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("MOVE_TO_PARENT: start %u, count %u\n",
					  move->pos.start, move->pos.count);
#endif /* CONFIG_SSDFS_DEBUG */
				move->direction = SSDFS_BTREE_MOVE_TO_PARENT;
				moving_items = items_capacity / 4;
				move->pos.start = items_capacity - moving_items;
				move->pos.count = moving_items;
			}

			return -ENOSPC;
		}

		index_position++;
		break;

	default:
		BUG();
	}

	node_type = atomic_read(&node->type);

	down_read(&node->full_lock);

	if (node_type == SSDFS_BTREE_ROOT_NODE) {
		err = __ssdfs_btree_root_node_extract_index(node,
							    index_position,
							    &index_key);
	} else {
		down_read(&node->header_lock);
		ssdfs_memcpy(&area,
			     0, sizeof(struct ssdfs_btree_node_index_area),
			     &node->index_area,
			     0, sizeof(struct ssdfs_btree_node_index_area),
			     sizeof(struct ssdfs_btree_node_index_area));
		up_read(&node->header_lock);

		err = __ssdfs_btree_common_node_extract_index(node, &area,
							      index_position,
							      &index_key);
	}

	up_read(&node->full_lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to extract index key: "
			  "index_position %u, err %d\n",
			  index_position, err);
		ssdfs_debug_show_btree_node_indexes(node->tree, node);
		return err;
	}

	parent_node = node;
	node_id = le32_to_cpu(index_key.node_id);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_position %u, node_id %u\n",
		  index_position, node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_radix_tree_find(tree, node_id, &node);
	if (err == -ENOENT) {
		err = 0;
		node = __ssdfs_btree_read_node(tree, parent_node,
						&index_key,
						index_key.node_type,
						node_id);
		if (unlikely(IS_ERR_OR_NULL(node))) {
			err = !node ? -ENOMEM : PTR_ERR(node);
			SSDFS_ERR("fail to read: "
				  "node %llu, err %d\n",
				  (u64)node_id, err);
			return err;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find node in radix tree: "
			  "node_id %llu, err %d\n",
			  (u64)node_id, err);
		return err;
	} else if (!node) {
		SSDFS_WARN("empty node pointer\n");
		return -ERANGE;
	}

	items_area_state = atomic_read(&node->items_area.state);

	down_read(&node->header_lock);
	if (items_area_state == SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		items_count = node->items_area.items_count;
		items_capacity = node->items_area.items_capacity;
	} else
		err = -ERANGE;
	up_read(&node->header_lock);

	if (unlikely(err)) {
		SSDFS_ERR("items area is absent\n");
		return -ERANGE;
	} else if (items_count >= items_capacity) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("items area hasn't free space: "
			  "items_count %u, items_capacity %u\n",
			  items_count, items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

		if (vacant_indexes == 0 && !is_resize_possible) {
			/*
			 * Try to move to parent node
			 */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("MOVE_TO_PARENT: start %u, count %u\n",
				  move->pos.start, move->pos.count);
#endif /* CONFIG_SSDFS_DEBUG */

			move->direction = SSDFS_BTREE_MOVE_TO_PARENT;
			moving_items = items_capacity / 4;
			move->pos.start = items_capacity - moving_items;
			move->pos.count = moving_items;
		}

		return -ENOSPC;
	}

	moving_items = items_capacity - items_count;
	moving_items /= 2;
	if (moving_items == 0)
		moving_items = 1;

	switch (move->direction) {
	case SSDFS_BTREE_MOVE_TO_LEFT:
		move->pos.count = moving_items;
		break;

	case SSDFS_BTREE_MOVE_TO_RIGHT:
		items_count = move->pos.start + move->pos.count;
		moving_items = min_t(u16, moving_items, move->pos.count);
		move->pos.start = items_count - moving_items;
		move->pos.count = moving_items;
		break;

	default:
		BUG();
	}

	level->nodes.new_node.type = atomic_read(&node->type);
	level->nodes.new_node.ptr = node;

	return 0;
}

/*
 * ssdfs_need_move_items_to_parent() - does it need to move items?
 * @level: level object
 *
 * This method tries to check that items need to move
 * to the parent node.
 */
static inline
bool ssdfs_need_move_items_to_parent(struct ssdfs_btree_level *level)
{
	struct ssdfs_btree_node_move *move;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level);

	SSDFS_DBG("level %p\n", level);
#endif /* CONFIG_SSDFS_DEBUG */

	move = &level->items_area.move;

	if (level->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE) {
		switch (move->direction) {
		case SSDFS_BTREE_MOVE_TO_PARENT:
			return true;
		}
	}

	return false;
}

static inline
void ssdfs_btree_cancel_move_items_to_parent(struct ssdfs_btree_level *level)
{
	struct ssdfs_btree_node_move *move;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level);

	SSDFS_DBG("level %p\n", level);
#endif /* CONFIG_SSDFS_DEBUG */

	move = &level->items_area.move;

	level->flags &= ~SSDFS_BTREE_ITEMS_AREA_NEED_MOVE;

	move->direction = SSDFS_BTREE_MOVE_NOWHERE;
	move->pos.state = SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED;
	move->pos.start = U16_MAX;
	move->pos.count = 0;
	move->op_state = SSDFS_BTREE_AREA_OP_UNKNOWN;
}

/*
 * ssdfs_prepare_move_items_to_parent() - prepare tree rebalance
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to prepare the moving items from child
 * to parent with the goal to rebalance the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_prepare_move_items_to_parent(struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *node;
	struct ssdfs_btree_node_insert *insert;
	struct ssdfs_btree_node_move *move;
	int items_area_state;
	u64 start_hash, end_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !parent || !child);

	SSDFS_DBG("search %p, parent %p, child %p\n",
		  search, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(child->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE)) {
		SSDFS_DBG("no items should be moved\n");
		return 0;
	}

	move = &child->items_area.move;

	switch (move->direction) {
	case SSDFS_BTREE_MOVE_TO_PARENT:
		/* expected state */
		break;

	default:
		SSDFS_DBG("nothing should be done\n");
		return 0;
	}

	if (!(parent->flags & SSDFS_BTREE_LEVEL_ADD_NODE)) {
		SSDFS_DBG("items can be copied only into a new node\n");
		ssdfs_btree_cancel_move_items_to_parent(child);
		return 0;
	}

	node = child->nodes.old_node.ptr;

	if (!node) {
		SSDFS_WARN("node pointer is empty\n");
		return -ERANGE;
	}

	items_area_state = atomic_read(&node->items_area.state);

	down_read(&node->header_lock);
	if (items_area_state == SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		start_hash = node->items_area.start_hash;
		end_hash = node->items_area.end_hash;
	} else
		err = -ERANGE;
	up_read(&node->header_lock);

	if (unlikely(err)) {
		SSDFS_ERR("items area is absent\n");
		return -ERANGE;
	}

	if (search->request.start.hash > end_hash ||
	    search->request.end.hash < start_hash) {
		ssdfs_btree_cancel_move_items_to_parent(child);
		return 0;
	}

	insert = &parent->items_area.insert;

	insert->hash.start = search->request.start.hash;
	insert->hash.end = child->items_area.hash.end;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "child->items_area.hash.start %llx, "
		  "child->items_area.hash.end %llx\n",
		  insert->hash.start,
		  insert->hash.end,
		  child->items_area.hash.start,
		  child->items_area.hash.end);
#endif /* CONFIG_SSDFS_DEBUG */

	insert->pos.state = SSDFS_HASH_RANGE_LEFT_ADJACENT;
	insert->pos.start = 0;
	insert->pos.count = move->pos.count;
	insert->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

	return 0;
}

/*
 * ssdfs_btree_define_moving_indexes() - define moving index range
 * @parent: parent level object [in|out]
 * @child: child level object [in|out]
 *
 * This method tries to define what index range should be moved
 * between @parent and @child levels.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_define_moving_indexes(struct ssdfs_btree_level *parent,
				      struct ssdfs_btree_level *child)
{
#ifdef CONFIG_SSDFS_DEBUG
	int state;
#endif /* CONFIG_SSDFS_DEBUG */
	struct ssdfs_btree_node *child_node;
	u8 index_size;
	u16 index_count;
	u16 index_capacity;
	u64 start_hash;
	u64 end_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!parent || !child);

	SSDFS_DBG("parent: node_type %#x, node %p, "
		  "child: node_type %#x, node %p\n",
		  parent->nodes.old_node.type,
		  parent->nodes.old_node.ptr,
		  child->nodes.old_node.type,
		  child->nodes.old_node.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (parent->nodes.old_node.type) {
	case SSDFS_BTREE_ROOT_NODE:
		switch (child->nodes.old_node.type) {
		case SSDFS_BTREE_INDEX_NODE:
		case SSDFS_BTREE_HYBRID_NODE:
			/*
			 * Nothing should be done for the case of
			 * adding the node.
			 */
			break;

		case SSDFS_BTREE_LEAF_NODE:
			/*
			 * Nothing should be done for the case of
			 * adding the node.
			 */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child->nodes.old_node.type);
			break;
		}
		break;

	case SSDFS_BTREE_INDEX_NODE:
		switch (child->nodes.old_node.type) {
		case SSDFS_BTREE_INDEX_NODE:
			/*
			 * Nothing should be done for the case of
			 * adding the node.
			 */
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			/*
			 * Nothing should be done for the case of
			 * adding the node.
			 */
			break;

		case SSDFS_BTREE_LEAF_NODE:
			/*
			 * Nothing should be done for the case of
			 * adding the node.
			 */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child->nodes.old_node.type);
			break;
		}
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		switch (child->nodes.old_node.type) {
		case SSDFS_BTREE_INDEX_NODE:
			/*
			 * Nothing should be done for the case of
			 * adding the node.
			 */
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			/*
			 * Nothing should be done for the case of
			 * adding the node.
			 */
			break;

		case SSDFS_BTREE_LEAF_NODE:
			/*
			 * Nothing should be done for the case of
			 * adding the node.
			 */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child->nodes.old_node.type);
			break;
		}
		break;

	default:
		switch (child->nodes.old_node.type) {
		case SSDFS_BTREE_ROOT_NODE:
			child_node = child->nodes.old_node.ptr;
#ifdef CONFIG_SSDFS_DEBUG
			if (!child_node) {
				SSDFS_ERR("child node is NULL\n");
				return -ERANGE;
			}

			state = atomic_read(&child_node->index_area.state);
			if (state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
				SSDFS_ERR("index area is absent\n");
				return -ERANGE;
			}
#endif /* CONFIG_SSDFS_DEBUG */

			down_read(&child_node->header_lock);
			index_size = child_node->index_area.index_size;
			index_count = child_node->index_area.index_count;
			index_capacity = child_node->index_area.index_capacity;
			start_hash = child_node->index_area.start_hash;
			end_hash = child_node->index_area.end_hash;
			up_read(&child_node->header_lock);

			if (index_count != index_capacity) {
				SSDFS_ERR("count %u != capacity %u\n",
					  index_count, index_capacity);
				return -ERANGE;
			}

			parent->nodes.new_node.type = SSDFS_BTREE_ROOT_NODE;
			parent->nodes.new_node.ptr = child_node;

			parent->flags |= SSDFS_BTREE_INDEX_AREA_NEED_MOVE;
			parent->index_area.move.direction =
						SSDFS_BTREE_MOVE_TO_CHILD;
			parent->index_area.move.pos.state =
					SSDFS_HASH_RANGE_INTERSECTION;
			parent->index_area.move.pos.start = 0;
			parent->index_area.move.pos.count = index_count;
			parent->index_area.move.op_state =
					SSDFS_BTREE_AREA_OP_REQUESTED;

			child->index_area.insert.pos.state =
					SSDFS_HASH_RANGE_LEFT_ADJACENT;
			child->index_area.insert.hash.start = start_hash;
			child->index_area.insert.hash.end = end_hash;
			child->index_area.insert.pos.start = 0;
			child->index_area.insert.pos.count = index_count;
			child->index_area.insert.op_state =
					SSDFS_BTREE_AREA_OP_REQUESTED;
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child->nodes.old_node.type);
			break;
		}
		break;
	}

	return err;
}

/*
 * ssdfs_prepare_move_indexes_right() - prepare to move indexes (right)
 * @parent: parent level object [in|out]
 * @parent_node: parent node
 *
 * This method tries to define what index range should be moved
 * from @parent_node to a new node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_prepare_move_indexes_right(struct ssdfs_btree_level *parent,
				     struct ssdfs_btree_node *parent_node)
{
#ifdef CONFIG_SSDFS_DEBUG
	int state;
#endif /* CONFIG_SSDFS_DEBUG */
	struct ssdfs_btree_node_move *move;
	u16 index_count;
	u16 index_capacity;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!parent || !parent_node);

	SSDFS_DBG("parent: node_type %#x, node %p, node_id %u\n",
		  parent->nodes.old_node.type,
		  parent->nodes.old_node.ptr,
		  parent_node->node_id);

	state = atomic_read(&parent_node->index_area.state);
	if (state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		SSDFS_ERR("index area is absent\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&parent_node->header_lock);
	index_count = parent_node->index_area.index_count;
	index_capacity = parent_node->index_area.index_capacity;
	up_read(&parent_node->header_lock);

	if (index_count != index_capacity) {
		SSDFS_ERR("count %u != capacity %u\n",
			  index_count, index_capacity);
		return -ERANGE;
	}

	if (index_count == 0) {
		SSDFS_ERR("invalid count %u\n",
			  index_count);
		return -ERANGE;
	}

	move = &parent->index_area.move;

	parent->flags |= SSDFS_BTREE_INDEX_AREA_NEED_MOVE;
	move->direction = SSDFS_BTREE_MOVE_TO_RIGHT;
	move->pos.state = SSDFS_HASH_RANGE_INTERSECTION;
	move->pos.start = index_count / 2;
	move->pos.count = index_count - move->pos.start;
	move->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("MOVE_TO_RIGHT: start %u, count %u\n",
		  move->pos.start, move->pos.count);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_check_capability_move_indexes_to_sibling() - check ability to rebalance
 * @level: level object
 *
 * This method tries to define the presence of free space in
 * sibling index node with the goal to rebalance the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - node hasn't free space.
 */
static int
ssdfs_check_capability_move_indexes_to_sibling(struct ssdfs_btree_level *level)
{
	struct ssdfs_btree *tree;
	struct ssdfs_btree_node *node, *parent_node;
	struct ssdfs_btree_node_move *move;
	struct ssdfs_btree_node_index_area area;
	struct ssdfs_btree_index_key index_key;
	u64 hash = U64_MAX;
	int index_area_state;
	u16 index_count = 0;
	u16 index_capacity = 0;
	u16 vacant_indexes = 0;
	u16 src_index_count = 0;
	u16 index_position;
	int node_type;
	u32 node_id;
	spinlock_t *lock;
	u16 moving_indexes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level);

	SSDFS_DBG("level %p\n", level);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!level->nodes.old_node.ptr) {
		SSDFS_ERR("node pointer is empty\n");
		return -ERANGE;
	}

	node = level->nodes.old_node.ptr;
	tree = node->tree;

	spin_lock(&node->descriptor_lock);
	hash = le64_to_cpu(node->node_index.index.hash);
	spin_unlock(&node->descriptor_lock);

	index_area_state = atomic_read(&node->index_area.state);

	down_read(&node->header_lock);

	if (index_area_state == SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		src_index_count = node->index_area.index_count;
		index_capacity = node->index_area.index_capacity;
		vacant_indexes = index_capacity - src_index_count;
	} else
		err = -ERANGE;

	up_read(&node->header_lock);

	if (unlikely(err)) {
		SSDFS_ERR("index area is absent\n");
		return -ERANGE;
	} else if (vacant_indexes != 0) {
		SSDFS_ERR("node %u is not exhausted: "
			  "index_count %u, index_capacity %u\n",
			  node->node_id, src_index_count,
			  index_capacity);
		return -ERANGE;
	}

	lock = &level->nodes.old_node.ptr->descriptor_lock;
	spin_lock(lock);
	node = level->nodes.old_node.ptr->parent_node;
	spin_unlock(lock);
	lock = NULL;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	index_area_state = atomic_read(&node->index_area.state);

	down_read(&node->header_lock);

	if (index_area_state == SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		index_count = node->index_area.index_count;
		index_capacity = node->index_area.index_capacity;
		vacant_indexes = index_capacity - index_count;
	} else
		err = -ERANGE;

	up_read(&node->header_lock);

	if (unlikely(err)) {
		SSDFS_ERR("index area is absent\n");
		return -ERANGE;
	}

	err = ssdfs_btree_node_find_index_position(node, hash,
						   &index_position);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the index position: "
			  "hash %llx, err %d\n",
			  hash, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hash %llx, index_position %u\n",
		  hash, index_position);
#endif /* CONFIG_SSDFS_DEBUG */

	if (index_position >= index_count) {
		SSDFS_ERR("index_position %u >= index_count %u\n",
			  index_position, index_count);
		return -ERANGE;
	}

	if ((index_position + 1) == index_count) {
		SSDFS_DBG("no siblings on the right\n");

		if (vacant_indexes == 0) {
			SSDFS_DBG("cannot add index\n");
			return -ENOSPC;
		} else {
			SSDFS_DBG("need add empty index node\n");
			return -ENOENT;
		}
	}

	index_position++;

	node_type = atomic_read(&node->type);

	down_read(&node->full_lock);

	if (node_type == SSDFS_BTREE_ROOT_NODE) {
		err = __ssdfs_btree_root_node_extract_index(node,
							    index_position,
							    &index_key);
	} else {
		down_read(&node->header_lock);
		ssdfs_memcpy(&area,
			     0, sizeof(struct ssdfs_btree_node_index_area),
			     &node->index_area,
			     0, sizeof(struct ssdfs_btree_node_index_area),
			     sizeof(struct ssdfs_btree_node_index_area));
		up_read(&node->header_lock);

		err = __ssdfs_btree_common_node_extract_index(node, &area,
							      index_position,
							      &index_key);
	}

	up_read(&node->full_lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to extract index key: "
			  "index_position %u, err %d\n",
			  index_position, err);
		ssdfs_debug_show_btree_node_indexes(node->tree, node);
		return err;
	}

	parent_node = node;
	node_id = le32_to_cpu(index_key.node_id);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_position %u, node_id %u\n",
		  index_position, node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_radix_tree_find(tree, node_id, &node);
	if (err == -ENOENT) {
		err = 0;
		node = __ssdfs_btree_read_node(tree, parent_node,
						&index_key,
						index_key.node_type,
						node_id);
		if (unlikely(IS_ERR_OR_NULL(node))) {
			err = !node ? -ENOMEM : PTR_ERR(node);
			SSDFS_ERR("fail to read: "
				  "node %llu, err %d\n",
				  (u64)node_id, err);
			return err;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find node in radix tree: "
			  "node_id %llu, err %d\n",
			  (u64)node_id, err);
		return err;
	} else if (!node) {
		SSDFS_WARN("empty node pointer\n");
		return -ERANGE;
	}

	index_area_state = atomic_read(&node->index_area.state);

	down_read(&node->header_lock);

	if (index_area_state == SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		index_count = node->index_area.index_count;
		index_capacity = node->index_area.index_capacity;
		vacant_indexes = index_capacity - index_count;
	} else
		err = -ERANGE;

	up_read(&node->header_lock);

	if (unlikely(err)) {
		SSDFS_ERR("index area is absent\n");
		return -ERANGE;
	} else if (index_count >= index_capacity) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index area hasn't free space: "
			  "index_count %u, index_capacity %u\n",
			  index_count, index_capacity);
		SSDFS_DBG("cannot move indexes\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOENT;
	}

	moving_indexes = vacant_indexes / 2;
	if (moving_indexes == 0)
		moving_indexes = 1;

	move = &level->index_area.move;

	level->flags |= SSDFS_BTREE_INDEX_AREA_NEED_MOVE;
	move->direction = SSDFS_BTREE_MOVE_TO_RIGHT;
	move->pos.state = SSDFS_HASH_RANGE_INTERSECTION;
	move->pos.start = src_index_count - moving_indexes;
	move->pos.count = src_index_count - move->pos.start;
	move->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("MOVE_TO_RIGHT: start %u, count %u\n",
		  move->pos.start, move->pos.count);
#endif /* CONFIG_SSDFS_DEBUG */

	level->nodes.new_node.type = atomic_read(&node->type);
	level->nodes.new_node.ptr = node;

	return 0;
}

/*
 * ssdfs_define_hybrid_node_moving_items() - define moving items range
 * @tree: btree object
 * @start_hash: starting hash
 * @end_hash: ending hash
 * @parent_node: pointer on parent node
 * @child_node: pointer on child node
 * @parent: parent level object [in|out]
 * @child: child level object [in|out]
 *
 * This method tries to define what items range should be moved
 * between @parent and @child levels.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_define_hybrid_node_moving_items(struct ssdfs_btree *tree,
					u64 start_hash, u64 end_hash,
					struct ssdfs_btree_node *parent_node,
					struct ssdfs_btree_node *child_node,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node_move *move;
	struct ssdfs_btree_node_insert *insert;
	int state;
	u32 free_space = 0;
	u16 item_size;
	u16 items_count;
	u16 items_capacity;
	u64 parent_start_hash;
	u64 parent_end_hash;
	u32 index_area_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!parent || !child || !parent_node);

	SSDFS_DBG("parent: node_type %#x, node %p\n",
		  parent->nodes.old_node.type,
		  parent->nodes.old_node.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&parent_node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("items area is absent\n");
		return -ERANGE;
	}

	down_read(&parent_node->header_lock);
	item_size = parent_node->items_area.item_size;
	items_count = parent_node->items_area.items_count;
	items_capacity = parent_node->items_area.items_capacity;
	parent_start_hash = parent_node->items_area.start_hash;
	parent_end_hash = parent_node->items_area.end_hash;
	index_area_size = parent_node->index_area.area_size;
	up_read(&parent_node->header_lock);

	if (child_node) {
		down_read(&child_node->header_lock);
		free_space = child_node->items_area.free_space;
		up_read(&child_node->header_lock);
	} else {
		/* it needs to add a child node */
		free_space = (u32)items_capacity * item_size;
	}

	if (items_count == 0) {
		SSDFS_DBG("no items to move\n");
		return 0;
	}

	if (free_space < ((u32)item_size * items_count)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to move items: "
			  "free_space %u, item_size %u, items_count %u\n",
			  free_space, item_size, items_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	move = &parent->items_area.move;
	insert = &child->items_area.insert;

	switch (tree->type) {
	case SSDFS_INODES_BTREE:
	case SSDFS_EXTENTS_BTREE:
	case SSDFS_SHARED_EXTENTS_BTREE:
		/* no additional check is necessary */
		break;

	case SSDFS_DENTRIES_BTREE:
	case SSDFS_XATTR_BTREE:
	case SSDFS_SHARED_DICTIONARY_BTREE:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_hash %llx, "
			  "end_hash %llx, "
			  "parent: (start_hash %llx, "
			  "end_hash %llx)\n",
			  start_hash, end_hash,
			  parent_start_hash,
			  parent_end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

		if ((index_area_size * 2) < parent_node->node_size) {
			/* parent node will be still hybrid one */
			items_count /= 2;
		}
		break;

	default:
		BUG();
	}

	parent->flags |= SSDFS_BTREE_ITEMS_AREA_NEED_MOVE;
	move->direction = SSDFS_BTREE_MOVE_TO_CHILD;
	move->pos.state = SSDFS_HASH_RANGE_INTERSECTION;
	move->pos.start = 0;
	move->pos.count = items_count;
	move->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

	insert->pos.state = SSDFS_HASH_RANGE_LEFT_ADJACENT;
	insert->hash.start = start_hash;
	insert->hash.end = end_hash;
	insert->pos.start = 0;
	insert->pos.count = items_count;
	insert->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

	child->flags |= SSDFS_BTREE_LEVEL_ADD_NODE;

	return 0;
}

/*
 * ssdfs_btree_define_moving_items() - define moving items range
 * @tree: btree object
 * @search: search object
 * @parent: parent level object [in|out]
 * @child: child level object [in|out]
 *
 * This method tries to define what items range should be moved
 * between @parent and @child levels.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_define_moving_items(struct ssdfs_btree *tree,
				    struct ssdfs_btree_search *search,
				    struct ssdfs_btree_level *parent,
				    struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node, *child_node = NULL;
	struct ssdfs_btree_node_move *move;
	struct ssdfs_btree_node_insert *insert;
	int state;
	u32 free_space = 0;
	u16 item_size;
	u16 items_count;
	u16 items_capacity;
	int child_node_type;
	u64 start_hash1, end_hash1;
	u64 start_hash2, end_hash2;
	bool has_intersection = false;
	bool can_add_index = true;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !parent || !child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE)
		child_node_type = child->nodes.new_node.type;
	else {
		child_node_type = child->nodes.old_node.type;
		child_node = child->nodes.old_node.ptr;

		if (!child_node) {
			SSDFS_ERR("child node is empty\n");
			return -EINVAL;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("parent: node_type %#x, node %p, "
		  "child: node_type %#x, node %p\n",
		  parent->nodes.old_node.type,
		  parent->nodes.old_node.ptr,
		  child_node_type,
		  child_node);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (parent->nodes.old_node.type) {
	case SSDFS_BTREE_ROOT_NODE:
		switch (child_node_type) {
		case SSDFS_BTREE_INDEX_NODE:
		case SSDFS_BTREE_HYBRID_NODE:
		case SSDFS_BTREE_LEAF_NODE:
			/*
			 * Nothing should be done.
			 * The root node is pure index node.
			 */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child->nodes.old_node.type);
			break;
		}
		break;

	case SSDFS_BTREE_INDEX_NODE:
		switch (child_node_type) {
		case SSDFS_BTREE_INDEX_NODE:
		case SSDFS_BTREE_HYBRID_NODE:
		case SSDFS_BTREE_LEAF_NODE:
			/*
			 * Nothing should be done.
			 * The index node hasn't items at all.
			 */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child->nodes.old_node.type);
			break;
		}
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		switch (child_node_type) {
		case SSDFS_BTREE_INDEX_NODE:
			/*
			 * Nothing should be done.
			 * The index node hasn't items at all.
			 */
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			parent_node = parent->nodes.old_node.ptr;
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!parent_node);
#endif /* CONFIG_SSDFS_DEBUG */

			state = atomic_read(&parent_node->items_area.state);
			if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
				SSDFS_ERR("items area is absent\n");
				return -ERANGE;
			}

			if (!(child->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE))
				return 0;

			down_read(&parent_node->header_lock);
			free_space = parent_node->items_area.area_size;
			item_size = parent_node->items_area.item_size;
			items_count = parent_node->items_area.items_count;
			items_capacity = parent_node->items_area.items_capacity;
			start_hash1 = parent_node->items_area.start_hash;
			end_hash1 = parent_node->items_area.end_hash;
			up_read(&parent_node->header_lock);

			if (child_node) {
				down_read(&child_node->header_lock);
				free_space = child_node->items_area.free_space;
				up_read(&child_node->header_lock);
			} else {
				/* it needs to add a child node */
				free_space = (u32)items_capacity * item_size;
			}

			if (items_count == 0) {
				SSDFS_DBG("no items to move\n");
				return 0;
			}

			if (free_space < ((u32)item_size * items_count)) {
				SSDFS_WARN("unable to move items: "
					  "items_area.free_space %u, "
					  "items_area.item_size %u, "
					  "items_count %u\n",
					  free_space, item_size,
					  items_count);
				return 0;
			}

			start_hash2 = search->request.start.hash;
			end_hash2 = search->request.end.hash;

			has_intersection =
				RANGE_HAS_PARTIAL_INTERSECTION(start_hash1,
								end_hash1,
								start_hash2,
								end_hash2);
			can_add_index = can_add_new_index(parent_node);

			move = &parent->items_area.move;
			insert = &child->items_area.insert;

			switch (tree->type) {
			case SSDFS_INODES_BTREE:
			case SSDFS_EXTENTS_BTREE:
			case SSDFS_SHARED_EXTENTS_BTREE:
				/* no additional check is necessary */
				break;

			case SSDFS_DENTRIES_BTREE:
			case SSDFS_XATTR_BTREE:
			case SSDFS_SHARED_DICTIONARY_BTREE:
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("search: (start_hash %llx, "
					  "end_hash %llx), "
					  "items_area: (start_hash %llx, "
					  "end_hash %llx)\n",
					  start_hash2, end_hash2,
					  start_hash1, end_hash1);
#endif /* CONFIG_SSDFS_DEBUG */

				if (has_intersection)
					items_count /= 2;
				else if (can_add_index) {
					SSDFS_DBG("no need to move items\n");

					move->op_state =
						SSDFS_BTREE_AREA_OP_UNKNOWN;
					move->direction =
						SSDFS_BTREE_MOVE_NOWHERE;
					move->pos.start = U16_MAX;
					move->pos.count = 0;
					return 0;
				} else {
					SSDFS_DBG("need two phase adding\n");
					return -EAGAIN;
				}
				break;

			default:
				BUG();
			}

			parent->flags |= SSDFS_BTREE_ITEMS_AREA_NEED_MOVE;
			move->direction = SSDFS_BTREE_MOVE_TO_CHILD;
			move->pos.state = SSDFS_HASH_RANGE_INTERSECTION;
			move->pos.start = 0;
			move->pos.count = items_count;
			move->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

			insert->pos.state = SSDFS_HASH_RANGE_LEFT_ADJACENT;
			insert->hash.start = start_hash1;
			insert->hash.end = end_hash1;
			insert->pos.start = 0;
			insert->pos.count = items_count;
			insert->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

			child->flags |= SSDFS_BTREE_LEVEL_ADD_NODE;
			break;

		case SSDFS_BTREE_LEAF_NODE:
			parent_node = parent->nodes.old_node.ptr;
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!parent_node);
#endif /* CONFIG_SSDFS_DEBUG */

			state = atomic_read(&parent_node->items_area.state);
			if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
				SSDFS_ERR("items area is absent\n");
				return -ERANGE;
			}

			down_read(&parent_node->header_lock);
			free_space = parent_node->items_area.area_size;
			item_size = parent_node->items_area.item_size;
			items_count = parent_node->items_area.items_count;
			items_capacity = parent_node->items_area.items_capacity;
			start_hash1 = parent_node->items_area.start_hash;
			end_hash1 = parent_node->items_area.end_hash;
			up_read(&parent_node->header_lock);

			if (child_node) {
				down_read(&child_node->header_lock);
				free_space = child_node->items_area.free_space;
				up_read(&child_node->header_lock);
			} else {
				/* it needs to add a child node */
				free_space = (u32)items_capacity * item_size;
			}

			if (items_count == 0) {
				SSDFS_DBG("no items to move\n");
				return 0;
			}

			if (free_space < ((u32)item_size * items_count)) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to move items: "
					  "items_area.free_space %u, "
					  "items_area.item_size %u, "
					  "items_count %u\n",
					  free_space, item_size,
					  items_count);
#endif /* CONFIG_SSDFS_DEBUG */
				return 0;
			}

			start_hash2 = search->request.start.hash;
			end_hash2 = search->request.end.hash;

			has_intersection =
				RANGE_HAS_PARTIAL_INTERSECTION(start_hash1,
								end_hash1,
								start_hash2,
								end_hash2);
			can_add_index = can_add_new_index(parent_node);

			move = &parent->items_area.move;
			insert = &child->items_area.insert;

			switch (tree->type) {
			case SSDFS_INODES_BTREE:
			case SSDFS_EXTENTS_BTREE:
			case SSDFS_SHARED_EXTENTS_BTREE:
				/* no additional check is necessary */
				break;

			case SSDFS_DENTRIES_BTREE:
			case SSDFS_XATTR_BTREE:
			case SSDFS_SHARED_DICTIONARY_BTREE:
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("search: (start_hash %llx, "
					  "end_hash %llx), "
					  "items_area: (start_hash %llx, "
					  "end_hash %llx)\n",
					  start_hash2, end_hash2,
					  start_hash1, end_hash1);
#endif /* CONFIG_SSDFS_DEBUG */

				if (has_intersection)
					items_count /= 2;
				else if (can_add_index) {
					SSDFS_DBG("no need to move items\n");

					move->op_state =
						SSDFS_BTREE_AREA_OP_UNKNOWN;
					move->direction =
						SSDFS_BTREE_MOVE_NOWHERE;
					move->pos.start = U16_MAX;
					move->pos.count = 0;
					return 0;
				} else {
					SSDFS_DBG("need two phase adding\n");
					return -EAGAIN;
				}
				break;

			default:
				BUG();
			}

			parent->flags |= SSDFS_BTREE_ITEMS_AREA_NEED_MOVE;
			move->direction = SSDFS_BTREE_MOVE_TO_CHILD;
			move->pos.state = SSDFS_HASH_RANGE_INTERSECTION;
			move->pos.start = 0;
			move->pos.count = items_count;
			move->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

			insert->pos.state = SSDFS_HASH_RANGE_LEFT_ADJACENT;
			insert->hash.start = start_hash1;
			insert->hash.end = end_hash1;
			insert->pos.start = 0;
			insert->pos.count = items_count;
			insert->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

			child->flags |= SSDFS_BTREE_LEVEL_ADD_NODE;
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child->nodes.old_node.type);
			break;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid parent node's type %#x\n",
			  parent->nodes.old_node.type);
		break;
	}

	return err;
}

/*
 * need_update_parent_index_area() - does it need to update parent's index area
 * @start_hash: starting hash value
 * @child: btree node object
 */
bool need_update_parent_index_area(u64 start_hash,
				   struct ssdfs_btree_node *child)
{
	int state;
	u64 child_start_hash = U64_MAX;
	bool need_update = false;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!child);

	SSDFS_DBG("start_hash %llx, node_id %u, "
		  "node type %#x, tree type %#x\n",
		  start_hash, child->node_id,
		  atomic_read(&child->type),
		  child->tree->type);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&child->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_INDEX_NODE:
		state = atomic_read(&child->index_area.state);
		if (state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
			SSDFS_ERR("invalid index area's state %#x\n",
				  state);
			return false;
		}

		down_read(&child->header_lock);
		child_start_hash = child->index_area.start_hash;
		up_read(&child->header_lock);
		break;

	case SSDFS_BTREE_LEAF_NODE:
		state = atomic_read(&child->items_area.state);
		if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
			SSDFS_ERR("invalid items area's state %#x\n",
				  state);
			return false;
		}

		down_read(&child->header_lock);
		child_start_hash = child->items_area.start_hash;
		up_read(&child->header_lock);
		break;

	default:
		SSDFS_ERR("unexpected node's type %#x\n",
			  atomic_read(&child->type));
		return false;
	}

	if (child_start_hash >= U64_MAX) {
		SSDFS_WARN("invalid start_hash %llx\n",
			  child_start_hash);
		return false;
	}

	switch (atomic_read(&child->state)) {
	case SSDFS_BTREE_NODE_PRE_DELETED:
	case SSDFS_BTREE_NODE_INVALID:
	case SSDFS_BTREE_NODE_CORRUPTED:
		need_update = false;
		break;

	default:
		if (start_hash <= child_start_hash)
			need_update = true;
		else
			need_update = false;
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, child_start_hash %llx, "
		  "need_update %#x\n",
		  start_hash, child_start_hash,
		  need_update);
#endif /* CONFIG_SSDFS_DEBUG */

	return need_update;
}

/*
 * is_index_area_resizable() - is it possible to resize the index area?
 * @node: btree node object
 */
static inline
bool is_index_area_resizable(struct ssdfs_btree_node *node)
{
	int flags;
	int state;
	u32 node_size;
	u32 index_area_size, items_area_size;
	size_t hdr_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	flags = atomic_read(&node->tree->flags);

	if (!(flags & SSDFS_BTREE_DESC_INDEX_AREA_RESIZABLE)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index area cannot be resized: "
			  "node %u\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	node_size = node->node_size;
	hdr_size = sizeof(node->raw);

	down_read(&node->header_lock);
	index_area_size = node->index_area.area_size;
	items_area_size = node->items_area.area_size;
	up_read(&node->header_lock);

	state = atomic_read(&node->index_area.state);
	if (state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST)
		index_area_size = 0;

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST)
		items_area_size = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, node_size %u, hdr_size %zu, "
		  "index_area_size %u, items_area_size %u\n",
		  node->node_id, node_size, hdr_size,
		  index_area_size, items_area_size);

	BUG_ON(node_size < (hdr_size + index_area_size + items_area_size));
#else
	if (node_size < (hdr_size + index_area_size + items_area_size)) {
		SSDFS_WARN("node_size %u < "
			   "(hdr_size %zu +index_area %u + items_area %u)\n",
			   node_size, hdr_size,
			   index_area_size, items_area_size);
		return false;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return items_area_size == 0 ? false : true;
}

/*
 * ssdfs_btree_prepare_index_area_resize() - prepare index area resize
 * @level: level object
 * @node: node object
 *
 * This method tries to prepare index area for resize operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_prepare_index_area_resize(struct ssdfs_btree_level *level,
					  struct ssdfs_btree_node *node)
{
	int state;
	u16 items_count;
	u16 items_capacity;
	u32 index_area_size, items_area_size;
	u32 index_area_min_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level);
	BUG_ON(!node || !node->tree);

	SSDFS_DBG("node_id %u\n", node->node_id);

	BUG_ON(!is_index_area_resizable(node));
#endif /* CONFIG_SSDFS_DEBUG */

	level->flags |= SSDFS_BTREE_TRY_RESIZE_INDEX_AREA;

	down_read(&node->header_lock);
	index_area_size = node->index_area.area_size;
	items_area_size = node->items_area.area_size;
	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;
	up_read(&node->header_lock);

	index_area_min_size = node->tree->index_area_min_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_area_size %u, index_area_min_size %u, "
		  "items_area_size %u, items_count %u, "
		  "items_capacity %u\n",
		  index_area_size, index_area_min_size,
		  items_area_size, items_count, items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("items area doesn't exist: "
			  "node_id %u\n",
			  node->node_id);
		return -ERANGE;
	}

	if (items_count == 0 || items_count > items_capacity) {
		SSDFS_ERR("corrupted items area: "
			  "items_count %u, items_capacity %u\n",
			  items_count, items_capacity);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_btree_check_nothing_root_pair() - check pair of nothing and root nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the nothing and root nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_nothing_root_pair(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	int child_type;
	struct ssdfs_btree_node *child_node;
	u64 start_hash, end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("child is NULL\n");
		return -ERANGE;
	}

	child_type = atomic_read(&child_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "child id %u, child_type %#x\n",
		  tree, search, parent, child,
		  child_node->node_id, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (child_type != SSDFS_BTREE_ROOT_NODE) {
		SSDFS_WARN("invalid child node's type %#x\n",
			   child_type);
		return -ERANGE;
	}

	if (!(child->flags & SSDFS_BTREE_LEVEL_ADD_NODE))
		return 0;

	down_read(&child_node->header_lock);
	start_hash = child_node->index_area.start_hash;
	end_hash = U64_MAX;
	up_read(&child_node->header_lock);

	err = ssdfs_btree_prepare_add_index(parent,
					    start_hash,
					    end_hash,
					    child_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare level: "
			  "node_id %u, height %u\n",
			  child_node->node_id,
			  atomic_read(&child_node->height));
		return err;
	}

	err = ssdfs_btree_define_moving_indexes(parent, child);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define moving indexes: "
			  "err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_btree_check_root_nothing_pair() - check pair of root and nothing nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the root and nothing nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_root_nothing_pair(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	int tree_height;
	int parent_type;
	struct ssdfs_btree_node *parent_node;
	u64 start_hash, end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id,
		  parent_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_ROOT_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	tree_height = atomic_read(&tree->height);
	if (tree_height <= 0 || tree_height > 1) {
		SSDFS_WARN("unexpected tree_height %u\n",
			  tree_height);
		return -EINVAL;
	}

	if (!can_add_new_index(parent_node)) {
		SSDFS_ERR("unable add index into the root\n");
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	ssdfs_btree_prepare_add_node(tree, SSDFS_BTREE_LEAF_NODE,
				     start_hash, end_hash,
				     child, NULL);

	err = ssdfs_btree_prepare_add_index(parent, start_hash,
					    end_hash, parent_node);
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
 * ssdfs_btree_check_root_index_pair() - check pair of root and index nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the root and index nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - needs to increase the tree's height.
 */
static
int ssdfs_btree_check_root_index_pair(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	int parent_type, child_type;
	int parent_height, child_height;
	struct ssdfs_btree_node *parent_node, *child_node;
	u64 start_hash, end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("child is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);
	child_type = atomic_read(&child_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, parent_type %#x, "
		  "child id %u, child_type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id, parent_type,
		  child_node->node_id, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_ROOT_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	if (child_type != SSDFS_BTREE_INDEX_NODE) {
		SSDFS_WARN("invalid child node's type %#x\n",
			   child_type);
		return -ERANGE;
	}

	parent_height = atomic_read(&parent_node->height);
	child_height = atomic_read(&child_node->height);

	if ((child_height + 1) != parent_height) {
		SSDFS_ERR("invalid pair: "
			  "parent_height %u, child_height %u\n",
			  parent_height, child_height);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE) {
		if (can_add_new_index(parent_node)) {
			err = ssdfs_btree_prepare_add_index(parent,
							    start_hash,
							    end_hash,
							    parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare level: "
					  "node_id %u\n",
					  parent_node->node_id);
				return err;
			}
		} else {
			ssdfs_btree_prepare_add_node(tree,
						     SSDFS_BTREE_INDEX_NODE,
						     start_hash, end_hash,
						     parent, parent_node);

			err = ssdfs_btree_prepare_add_index(parent,
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

			/*
			 * it needs to prepare increasing
			 * the tree's height
			 */
			return -ENOSPC;
		}
	} else if (need_update_parent_index_area(start_hash, child_node)) {
		err = ssdfs_btree_prepare_update_index(parent,
							start_hash,
							end_hash,
							parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare update index: "
				  "err %d\n", err);
			return err;
		}
	}

	if (!parent->flags) {
		err = ssdfs_btree_prepare_do_nothing(parent,
						     parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare root node: "
				  "err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_check_root_hybrid_pair() - check pair of root and hybrid nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the root and hybrid nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - needs to increase the tree's height.
 */
static
int ssdfs_btree_check_root_hybrid_pair(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	int tree_height;
	int parent_type, child_type;
	struct ssdfs_btree_node *parent_node, *child_node;
	u64 start_hash, end_hash;
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("child is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);
	child_type = atomic_read(&child_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, parent_type %#x, "
		  "child id %u, child_type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id, parent_type,
		  child_node->node_id, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_ROOT_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	if (child_type != SSDFS_BTREE_HYBRID_NODE) {
		SSDFS_WARN("invalid child node's type %#x\n",
			   child_type);
		return -ERANGE;
	}

	tree_height = atomic_read(&tree->height);
	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (tree_height < 2) {
		SSDFS_ERR("invalid tree height %d\n",
			  tree_height);
		return -ERANGE;
	}

	down_read(&child_node->header_lock);
	items_count = child_node->items_area.items_count;
	up_read(&child_node->header_lock);

	if (tree_height >= 3 && items_count == 0) {
		err = ssdfs_btree_prepare_insert_item(child, search,
						      child_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare the insert: "
				  "node_id %u, height %u\n",
				  child_node->node_id,
				  atomic_read(&child_node->height));
			return err;
		}

		if (need_update_parent_index_area(start_hash, child_node)) {
			err = ssdfs_btree_prepare_update_index(parent,
								start_hash,
								end_hash,
								parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare update index: "
					  "err %d\n", err);
				return err;
			}
		}
	} else if (tree_height == 2) {
		err = ssdfs_btree_prepare_insert_item(child, search, child_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare the insert: "
				  "node_id %u, height %u\n",
				  child_node->node_id,
				  atomic_read(&child_node->height));
			return err;
		}

		ssdfs_btree_prepare_add_node(tree, SSDFS_BTREE_LEAF_NODE,
					     start_hash, end_hash,
					     child, child_node);

		err = ssdfs_btree_prepare_add_index(child,
						    start_hash,
						    end_hash,
						    child_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare level: "
				  "node_id %u, height %u\n",
				  child_node->node_id,
				  atomic_read(&child_node->height));
			return err;
		}

		err = ssdfs_btree_define_moving_items(tree, search,
							child, child);
		if (unlikely(err)) {
			SSDFS_ERR("fail to define moving items: "
				  "err %d\n", err);
			return err;
		}

		/*
		 * it needs to prepare increasing
		 * the tree's height
		 */
		return -ENOSPC;
	} else if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE) {
		if (can_add_new_index(parent_node)) {
			err = ssdfs_btree_prepare_add_index(parent,
							start_hash,
							end_hash,
							parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare level: "
					  "node_id %u\n",
					  parent_node->node_id);
				return err;
			}
		} else {
			ssdfs_btree_prepare_add_node(tree,
						SSDFS_BTREE_INDEX_NODE,
						start_hash, end_hash,
						parent, parent_node);

			err = ssdfs_btree_prepare_add_index(parent,
							start_hash,
							end_hash,
							parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare level: "
					  "node_id %u\n",
					  parent_node->node_id);
				return err;
			}

			/*
			 * it needs to prepare increasing
			 * the tree's height
			 */
			return -ENOSPC;
		}
	} else if (need_update_parent_index_area(start_hash,
						 child_node)) {
		err = ssdfs_btree_prepare_update_index(parent,
							start_hash,
							end_hash,
							parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare update index: "
				  "err %d\n", err);
			return err;
		}
	}

	if (!parent->flags) {
		err = ssdfs_btree_prepare_do_nothing(parent,
						     parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare root node: "
				  "err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_check_root_leaf_pair() - check pair of root and leaf nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the root and leaf nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - needs to increase the tree's height.
 */
static
int ssdfs_btree_check_root_leaf_pair(struct ssdfs_btree *tree,
				     struct ssdfs_btree_search *search,
				     struct ssdfs_btree_level *parent,
				     struct ssdfs_btree_level *child)
{
	int tree_height;
	int parent_type, child_type;
	struct ssdfs_btree_node *parent_node, *child_node;
	u64 start_hash, end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("child is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);
	child_type = atomic_read(&child_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, parent_type %#x, "
		  "child id %u, child_type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id, parent_type,
		  child_node->node_id, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_ROOT_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	if (child_type != SSDFS_BTREE_LEAF_NODE) {
		SSDFS_WARN("invalid child node's type %#x\n",
			   child_type);
		return -ERANGE;
	}

	tree_height = atomic_read(&tree->height);
	if (tree_height > 2) {
		SSDFS_WARN("unexpected tree_height %u\n",
			  tree_height);
		return -EINVAL;
	}

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (can_add_new_index(parent_node)) {
		/* tree has only one leaf node */
		err = ssdfs_btree_prepare_insert_item(child,
						      search,
						      child_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare the insert: "
				  "node_id %u, height %u\n",
				  child_node->node_id,
				  atomic_read(&child_node->height));
			return err;
		}

		if (ssdfs_need_move_items_to_sibling(child)) {
			err = ssdfs_check_capability_move_to_sibling(child);
			if (err == -ENOSPC) {
				/*
				 * It needs to add a node.
				 */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check moving to sibling: "
					  "err %d\n", err);
				return err;
			}
		} else
			err = -ENOSPC;

		if (err == -ENOSPC) {
			ssdfs_btree_prepare_add_node(tree,
						     SSDFS_BTREE_LEAF_NODE,
						     start_hash, end_hash,
						     child, child_node);

			err = ssdfs_btree_prepare_add_index(parent,
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
		} else {
			err = ssdfs_btree_prepare_update_index(parent,
								start_hash,
								end_hash,
								parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare update index: "
					  "err %d\n", err);
				return err;
			}
		}
	} else {
		err = ssdfs_btree_prepare_insert_item(child,
						      search,
						      child_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare the insert: "
				  "node_id %u, height %u\n",
				  child_node->node_id,
				  atomic_read(&child_node->height));
			return err;
		}

		if (ssdfs_need_move_items_to_sibling(child)) {
			err = ssdfs_check_capability_move_to_sibling(child);
			if (err == -ENOSPC) {
				/*
				 * It needs to add a node.
				 */
				ssdfs_btree_cancel_insert_item(child);
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check moving to sibling: "
					  "err %d\n", err);
				return err;
			} else {
				err = ssdfs_btree_prepare_update_index(parent,
								start_hash,
								end_hash,
								parent_node);
				if (unlikely(err)) {
					SSDFS_ERR("fail to prepare update: "
						  "err %d\n", err);
					return err;
				}

				return 0;
			}
		} else
			ssdfs_btree_cancel_insert_item(child);

		ssdfs_btree_prepare_add_node(tree,
					     SSDFS_BTREE_HYBRID_NODE,
					     start_hash, end_hash,
					     parent, parent_node);

		err = ssdfs_btree_prepare_insert_item(parent,
						      search,
						      parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare the insert: "
				  "node_id %u, height %u\n",
				  parent_node->node_id,
				  atomic_read(&parent_node->height));
			return err;
		}

		if (ssdfs_need_move_items_to_parent(child)) {
			err = ssdfs_prepare_move_items_to_parent(search,
								 parent,
								 child);
			if (unlikely(err)) {
				SSDFS_ERR("fail to check moving to sibling: "
					  "err %d\n", err);
				return err;
			}
		}

		/* it needs to prepare increasing the tree's height */
		return -ENOSPC;
	}

	return 0;
}

/*
 * ssdfs_btree_check_index_index_pair() - check pair of index and index nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the index and index nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_index_index_pair(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	int parent_type, child_type;
	int parent_height, child_height;
	struct ssdfs_btree_node *parent_node, *child_node;
	u64 start_hash, end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("child is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);
	child_type = atomic_read(&child_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, parent_type %#x, "
		  "child id %u, child_type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id, parent_type,
		  child_node->node_id, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_INDEX_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	if (child_type != SSDFS_BTREE_INDEX_NODE) {
		SSDFS_WARN("invalid child node's type %#x\n",
			   child_type);
		return -ERANGE;
	}

	parent_height = atomic_read(&parent_node->height);
	child_height = atomic_read(&child_node->height);

	if ((child_height + 1) != parent_height) {
		SSDFS_ERR("invalid pair: "
			  "parent_height %u, child_height %u\n",
			  parent_height, child_height);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE) {
		if (can_add_new_index(parent_node)) {
			err = ssdfs_btree_prepare_add_index(parent,
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
		} else {
			ssdfs_btree_prepare_add_node(tree,
						     SSDFS_BTREE_INDEX_NODE,
						     start_hash, end_hash,
						     parent, parent_node);

			err = ssdfs_btree_prepare_add_index(parent,
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
		}
	} else if (need_update_parent_index_area(start_hash, child_node)) {
		err = ssdfs_btree_prepare_update_index(parent,
							start_hash,
							end_hash,
							parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare update index: "
				  "err %d\n", err);
			return err;
		}
	}

	if (!parent->flags) {
		err = ssdfs_btree_prepare_do_nothing(parent,
						     parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare index node: "
				  "err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_check_index_hybrid_pair() - check pair of index and hybrid nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the index and hybrid nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_index_hybrid_pair(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	int parent_type, child_type;
	int parent_height, child_height;
	struct ssdfs_btree_node *parent_node, *child_node;
	u64 start_hash, end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("child is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);
	child_type = atomic_read(&child_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, parent_type %#x, "
		  "child id %u, child_type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id, parent_type,
		  child_node->node_id, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_INDEX_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	if (child_type != SSDFS_BTREE_HYBRID_NODE) {
		SSDFS_WARN("invalid child node's type %#x\n",
			   child_type);
		return -ERANGE;
	}

	parent_height = atomic_read(&parent_node->height);
	child_height = atomic_read(&child_node->height);

	if ((child_height + 1) != parent_height) {
		SSDFS_ERR("invalid pair: "
			  "parent_height %u, child_height %u\n",
			  parent_height, child_height);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (child->flags & SSDFS_BTREE_TRY_RESIZE_INDEX_AREA) {
		err = ssdfs_btree_define_moving_indexes(parent, child);
		if (unlikely(err)) {
			SSDFS_ERR("fail to define moving indexes: "
				  "err %d\n", err);
			return err;
		}

		if (need_update_parent_index_area(start_hash, child_node)) {
			err = ssdfs_btree_prepare_update_index(parent,
								start_hash,
								end_hash,
								parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare update index: "
					  "err %d\n", err);
				return err;
			}
		}
	} else if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE) {
		if (can_add_new_index(parent_node)) {
			err = ssdfs_btree_prepare_add_index(parent,
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
		} else {
			ssdfs_btree_prepare_add_node(tree,
						     SSDFS_BTREE_INDEX_NODE,
						     start_hash, end_hash,
						     parent, parent_node);

			err = ssdfs_btree_prepare_add_index(parent,
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
		}
	} else if (need_update_parent_index_area(start_hash, child_node)) {
		err = ssdfs_btree_prepare_update_index(parent,
							start_hash,
							end_hash,
							parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare update index: "
				  "err %d\n", err);
			return err;
		}
	}

	if (!parent->flags) {
		err = ssdfs_btree_prepare_do_nothing(parent,
						     parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare index node: "
				  "err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_check_index_leaf_pair() - check pair of index and leaf nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the index and leaf nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_index_leaf_pair(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	int parent_type, child_type;
	int parent_height, child_height;
	struct ssdfs_btree_node *parent_node, *child_node;
	u64 start_hash, end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("child is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);
	child_type = atomic_read(&child_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, parent_type %#x, "
		  "child id %u, child_type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id, parent_type,
		  child_node->node_id, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_INDEX_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	if (child_type != SSDFS_BTREE_LEAF_NODE) {
		SSDFS_WARN("invalid child node's type %#x\n",
			   child_type);
		return -ERANGE;
	}

	parent_height = atomic_read(&parent_node->height);
	child_height = atomic_read(&child_node->height);

	if ((child_height + 1) != parent_height) {
		SSDFS_ERR("invalid pair: "
			  "parent_height %u, child_height %u\n",
			  parent_height, child_height);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (can_add_new_index(parent_node)) {
		err = ssdfs_btree_prepare_insert_item(child,
						      search,
						      child_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare the insert: "
				  "node_id %u, height %u\n",
				  child_node->node_id,
				  atomic_read(&child_node->height));
			return err;
		}

		if (ssdfs_need_move_items_to_sibling(child)) {
			err = ssdfs_check_capability_move_to_sibling(child);
			if (err == -ENOSPC) {
				/*
				 * It needs to add a node.
				 */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check moving to sibling: "
					  "err %d\n", err);
				return err;
			}
		} else
			err = -ENOSPC;

		if (err == -ENOSPC) {
			ssdfs_btree_prepare_add_node(tree,
						     SSDFS_BTREE_LEAF_NODE,
						     start_hash, end_hash,
						     child, child_node);

			err = ssdfs_btree_prepare_add_index(parent,
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
		} else {
			err = ssdfs_btree_prepare_update_index(parent,
								start_hash,
								end_hash,
								parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare update index: "
					  "err %d\n", err);
				return err;
			}
		}
	} else {
		err = ssdfs_check_capability_move_indexes_to_sibling(parent);
		if (err == -ENOENT) {
			ssdfs_btree_prepare_add_node(tree,
						     SSDFS_BTREE_INDEX_NODE,
						     U64_MAX, U64_MAX,
						     parent, parent_node);

			err = ssdfs_prepare_move_indexes_right(parent,
								parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare to move indexes: "
					  "node_id %u, height %u\n",
					  parent_node->node_id,
					  atomic_read(&parent_node->height));
				return err;
			}
		} else if (err == -ENOSPC) {
			ssdfs_btree_prepare_add_node(tree,
						     SSDFS_BTREE_INDEX_NODE,
						     U64_MAX, U64_MAX,
						     parent, parent_node);

			err = ssdfs_prepare_move_indexes_right(parent,
								parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare to move indexes: "
					  "node_id %u, height %u\n",
					  parent_node->node_id,
					  atomic_read(&parent_node->height));
				return err;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to prepare to move indexes: "
				  "node_id %u, height %u\n",
				  parent_node->node_id,
				  atomic_read(&parent_node->height));
			return err;
		} else {
			/*
			 * Do nothing.
			 * The index moving has been prepared already.
			 */
		}

		/* make first phase of transformation */
		return -EAGAIN;
	}

	return 0;
}

/*
 * ssdfs_btree_check_hybrid_nothing_pair() - check pair of hybrid and nothing
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the hybrid and nothing nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_hybrid_nothing_pair(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	int parent_type;
	struct ssdfs_btree_node *parent_node;
	u64 start_hash, end_hash;
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id,
		  parent_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_HYBRID_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	down_read(&parent_node->header_lock);
	items_count = parent_node->items_area.items_count;
	start_hash = parent_node->items_area.start_hash;
	end_hash = parent_node->items_area.end_hash;
	up_read(&parent_node->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, start_hash %llx, end_hash %llx\n",
		  items_count, start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	if (items_count == 0) {
		/*
		 * Do nothing.
		*/
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("parent id %u, type %#x, items_count == 0\n",
			  parent_node->node_id,
			  parent_type);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (can_add_new_index(parent_node)) {
		ssdfs_btree_prepare_add_node(tree, SSDFS_BTREE_LEAF_NODE,
					     start_hash, end_hash,
					     child, NULL);

		err = ssdfs_btree_prepare_add_index(parent,
						    start_hash,
						    start_hash,
						    parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare update index: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_btree_define_moving_items(tree, search,
							parent, child);
		if (unlikely(err)) {
			SSDFS_ERR("fail to define moving items: "
				  "err %d\n", err);
			return err;
		}
	} else if (is_index_area_resizable(parent_node)) {
		err = ssdfs_btree_prepare_index_area_resize(parent,
							parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare resize of index area: "
				  "err %d\n", err);
			return err;
		}

		ssdfs_btree_prepare_add_node(tree, SSDFS_BTREE_LEAF_NODE,
					     start_hash, end_hash,
					     child, NULL);

		err = ssdfs_btree_prepare_add_index(parent,
						    start_hash,
						    start_hash,
						    parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare update index: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_btree_define_moving_items(tree, search,
							parent, child);
		if (unlikely(err)) {
			SSDFS_ERR("fail to define moving items: "
				  "err %d\n", err);
			return err;
		}
	} else {
		start_hash = search->request.start.hash;
		end_hash = search->request.end.hash;

		ssdfs_btree_prepare_add_node(tree, SSDFS_BTREE_HYBRID_NODE,
					     start_hash, end_hash,
					     parent, parent_node);

		err = ssdfs_btree_prepare_add_index(parent, start_hash,
						    end_hash, parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare level: "
				  "node_id %u, height %u\n",
				  parent_node->node_id,
				  atomic_read(&parent_node->height));
			return err;
		}
	}

	if (!parent->flags) {
		err = ssdfs_btree_prepare_do_nothing(parent,
						     parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare root node: "
				  "err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_check_hybrid_index_pair() - check pair of hybrid and index nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the hybrid and index nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_hybrid_index_pair(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	int parent_type, child_type;
	int parent_height, child_height;
	struct ssdfs_btree_node *parent_node, *child_node;
	u64 start_hash, end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("child is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);
	child_type = atomic_read(&child_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, parent_type %#x, "
		  "child id %u, child_type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id, parent_type,
		  child_node->node_id, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_HYBRID_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	if (child_type != SSDFS_BTREE_INDEX_NODE) {
		SSDFS_WARN("invalid child node's type %#x\n",
			   child_type);
		return -ERANGE;
	}

	parent_height = atomic_read(&parent_node->height);
	child_height = atomic_read(&child_node->height);

	if ((child_height + 1) != parent_height) {
		SSDFS_ERR("invalid pair: "
			  "parent_height %u, child_height %u\n",
			  parent_height, child_height);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE) {
		if (can_add_new_index(parent_node)) {
			err = ssdfs_btree_prepare_add_index(parent,
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
		} else if (is_index_area_resizable(parent_node)) {
			err = ssdfs_btree_prepare_index_area_resize(parent,
								parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare resize of index area: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_btree_prepare_add_index(parent,
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
		} else {
			ssdfs_btree_prepare_add_node(tree,
						     SSDFS_BTREE_HYBRID_NODE,
						     start_hash, end_hash,
						     parent, parent_node);

			err = ssdfs_btree_prepare_add_index(parent,
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
		}
	} else if (need_update_parent_index_area(start_hash, child_node)) {
		err = ssdfs_btree_prepare_update_index(parent,
							start_hash,
							end_hash,
							parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare update index: "
				  "err %d\n", err);
			return err;
		}
	}

	if (!parent->flags) {
		err = ssdfs_btree_prepare_do_nothing(parent,
						     parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare hybrid node: "
				  "err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_check_hybrid_hybrid_pair() - check pair of hybrid + hybrid nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the hybrid and hybrid nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_hybrid_hybrid_pair(struct ssdfs_btree *tree,
					 struct ssdfs_btree_search *search,
					 struct ssdfs_btree_level *parent,
					 struct ssdfs_btree_level *child)
{
	int parent_type, child_type;
	int parent_height, child_height;
	struct ssdfs_btree_node *parent_node, *child_node;
	u64 start_hash, end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("child is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);
	child_type = atomic_read(&child_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, parent_type %#x, "
		  "child id %u, child_type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id, parent_type,
		  child_node->node_id, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_HYBRID_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	if (child_type != SSDFS_BTREE_HYBRID_NODE) {
		SSDFS_WARN("invalid child node's type %#x\n",
			   child_type);
		return -ERANGE;
	}

	parent_height = atomic_read(&parent_node->height);
	child_height = atomic_read(&child_node->height);

	if ((child_height + 1) != parent_height) {
		SSDFS_ERR("invalid pair: "
			  "parent_height %u, child_height %u\n",
			  parent_height, child_height);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	err = ssdfs_btree_define_moving_items(tree, search,
						parent, child);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define moving items: "
			  "err %d\n", err);
		return err;
	}

	if (child->flags & SSDFS_BTREE_TRY_RESIZE_INDEX_AREA) {
		err = ssdfs_btree_define_moving_indexes(parent, child);
		if (unlikely(err)) {
			SSDFS_ERR("fail to define moving indexes: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_btree_prepare_update_index(parent,
							start_hash,
							end_hash,
							parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare update index: "
				  "err %d\n", err);
			return err;
		}
	} else if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE) {
		if (can_add_new_index(parent_node)) {
			err = ssdfs_btree_prepare_add_index(parent,
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
		} else if (is_index_area_resizable(parent_node)) {
			err = ssdfs_btree_prepare_index_area_resize(parent,
								parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare resize of index area: "
					  "err %d\n", err);
				return err;
			}

			err = ssdfs_btree_prepare_add_index(parent,
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
		} else {
			ssdfs_btree_prepare_add_node(tree,
						     SSDFS_BTREE_HYBRID_NODE,
						     start_hash, end_hash,
						     parent, parent_node);

			err = ssdfs_btree_prepare_add_index(parent,
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
		}
	} else if (need_update_parent_index_area(start_hash, child_node)) {
		err = ssdfs_btree_prepare_update_index(parent,
							start_hash,
							end_hash,
							parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare update index: "
				  "err %d\n", err);
			return err;
		}
	}

	if (!parent->flags) {
		err = ssdfs_btree_prepare_do_nothing(parent,
						     parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare index node: "
				  "err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_check_hybrid_leaf_pair() - check pair of hybrid and leaf nodes
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the hybrid and leaf nodes pair.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_hybrid_leaf_pair(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	int parent_type, child_type;
	int parent_height, child_height;
	struct ssdfs_btree_node *parent_node, *child_node;
	u64 start_hash, end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("parent is NULL\n");
		return -ERANGE;
	}

	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("child is NULL\n");
		return -ERANGE;
	}

	parent_type = atomic_read(&parent_node->type);
	child_type = atomic_read(&child_node->type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree %p, search %p, "
		  "parent %p, child %p, "
		  "parent id %u, parent_type %#x, "
		  "child id %u, child_type %#x\n",
		  tree, search, parent, child,
		  parent_node->node_id, parent_type,
		  child_node->node_id, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent_type != SSDFS_BTREE_HYBRID_NODE) {
		SSDFS_WARN("invalid parent node's type %#x\n",
			   parent_type);
		return -ERANGE;
	}

	if (child_type != SSDFS_BTREE_LEAF_NODE) {
		SSDFS_WARN("invalid child node's type %#x\n",
			   child_type);
		return -ERANGE;
	}

	parent_height = atomic_read(&parent_node->height);
	child_height = atomic_read(&child_node->height);

	if ((child_height + 1) != parent_height) {
		SSDFS_ERR("invalid pair: "
			  "parent_height %u, child_height %u\n",
			  parent_height, child_height);
		return -ERANGE;
	}

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	err = ssdfs_btree_prepare_insert_item(child, search, child_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare the insert: "
			  "node_id %u, height %u\n",
			  child_node->node_id,
			  atomic_read(&child_node->height));
		return err;
	}

	if (ssdfs_need_move_items_to_sibling(child)) {
		err = ssdfs_check_capability_move_to_sibling(child);
		if (err == -ENOSPC) {
			/*
			 * It needs to add a node.
			 */
			goto try_add_node;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to check moving to sibling: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_btree_prepare_update_index(parent,
						start_hash,
						end_hash,
						parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare update: "
				  "err %d\n", err);
			return err;
		}

		return 0;
	}

try_add_node:
	ssdfs_btree_prepare_add_node(tree,
				     SSDFS_BTREE_LEAF_NODE,
				     start_hash, end_hash,
				     child, child_node);

	if (can_add_new_index(parent_node)) {
		err = ssdfs_btree_prepare_add_index(parent,
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
	} else if (is_index_area_resizable(parent_node)) {
		err = ssdfs_btree_prepare_index_area_resize(parent,
							parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare resize: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_btree_prepare_add_index(parent,
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

		err = ssdfs_btree_define_moving_items(tree, search,
							parent, child);
		if (err == -EAGAIN) {
			ssdfs_btree_cancel_insert_item(child);
			ssdfs_btree_cancel_move_items_to_sibling(child);
			ssdfs_btree_cancel_add_index(parent);

			down_read(&parent_node->header_lock);
			start_hash = parent_node->items_area.start_hash;
			up_read(&parent_node->header_lock);

			end_hash = start_hash;

			ssdfs_btree_prepare_add_node(tree,
						     SSDFS_BTREE_LEAF_NODE,
						     start_hash, end_hash,
						     child, child_node);

			err = ssdfs_btree_prepare_add_index(parent,
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

			err = ssdfs_define_hybrid_node_moving_items(tree,
								start_hash,
								end_hash,
								parent_node,
								NULL,
								parent,
								child);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare level: "
					  "node_id %u, height %u\n",
					  parent_node->node_id,
					  atomic_read(&parent_node->height));
				return err;
			}

			/* make first phase of transformation */
			return -EAGAIN;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to define moving items: "
				  "err %d\n", err);
			return err;
		}
	} else {
		ssdfs_btree_prepare_add_node(tree,
					     SSDFS_BTREE_HYBRID_NODE,
					     start_hash, end_hash,
					     parent, parent_node);

		if (ssdfs_need_move_items_to_parent(child)) {
			err = ssdfs_prepare_move_items_to_parent(search,
								 parent,
								 child);
			if (unlikely(err)) {
				SSDFS_ERR("fail to check moving to parent: "
					  "err %d\n", err);
				return err;
			}
		}

		err = ssdfs_btree_prepare_add_index(parent,
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
	}

	return 0;
}

/*
 * ssdfs_btree_check_level_for_add() - check btree's level for adding a node
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the level of btree for adding a node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - needs to increase the tree's height.
 */
int ssdfs_btree_check_level_for_add(struct ssdfs_btree_state_descriptor *desc,
				    struct ssdfs_btree *tree,
				    struct ssdfs_btree_search *search,
				    struct ssdfs_btree_level *parent,
				    struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *node = NULL;
	int parent_type, child_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !tree || !search);
	BUG_ON(!parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));

	SSDFS_DBG("tree %p, search %p, parent %p, child %p\n",
		  tree, search, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	parent_type = parent->nodes.old_node.type;
	if (parent_type != SSDFS_BTREE_NODE_UNKNOWN_TYPE) {
		BUG_ON(!parent->nodes.old_node.ptr);
		parent_type = atomic_read(&parent->nodes.old_node.ptr->type);
	}

	child_type = child->nodes.old_node.type;
	if (child_type != SSDFS_BTREE_NODE_UNKNOWN_TYPE) {
		BUG_ON(!child->nodes.old_node.ptr);
		child_type = atomic_read(&child->nodes.old_node.ptr->type);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("parent_type %#x, child_type %#x\n",
		  parent_type, child_type);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (parent_type) {
	case SSDFS_BTREE_NODE_UNKNOWN_TYPE:
		switch (child_type) {
		case SSDFS_BTREE_ROOT_NODE:
			err = ssdfs_btree_check_nothing_root_pair(tree,
								  search,
								  parent,
								  child);
			if (unlikely(err)) {
				SSDFS_ERR("fail to check nothing-root pair: "
					  "err %d\n", err);
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child_type);
		};
		break;

	case SSDFS_BTREE_ROOT_NODE:
		switch (child_type) {
		case SSDFS_BTREE_NODE_UNKNOWN_TYPE:
			err = ssdfs_btree_check_root_nothing_pair(tree,
								  search,
								  parent,
								  child);
			if (unlikely(err)) {
				SSDFS_ERR("fail to check root-nothing pair: "
					  "err %d\n", err);
			}

			node = parent->nodes.old_node.ptr;
			if (is_ssdfs_btree_node_index_area_empty(node)) {
				/* root node should be moved on upper level */
				desc->increment_height = true;
				SSDFS_DBG("need to grow the tree height\n");
			}
			break;

		case SSDFS_BTREE_INDEX_NODE:
			err = ssdfs_btree_check_root_index_pair(tree,
								search,
								parent,
								child);
			if (err == -ENOSPC) {
				/* root node should be moved on upper level */
				desc->increment_height = true;
				SSDFS_DBG("need to grow the tree height\n");
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check root-index pair: "
					  "err %d\n", err);
			}
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			err = ssdfs_btree_check_root_hybrid_pair(tree,
								 search,
								 parent,
								 child);
			if (err == -ENOSPC) {
				/* root node should be moved on upper level */
				desc->increment_height = true;
				SSDFS_DBG("need to grow the tree height\n");
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check root-hybrid pair: "
					  "err %d\n", err);
			}
			break;

		case SSDFS_BTREE_LEAF_NODE:
			err = ssdfs_btree_check_root_leaf_pair(tree,
								search,
								parent,
								child);
			if (err == -ENOSPC) {
				/* root node should be moved on upper level */
				desc->increment_height = true;
				SSDFS_DBG("need to grow the tree height\n");
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check root-leaf pair: "
					  "err %d\n", err);
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child_type);
		};
		break;

	case SSDFS_BTREE_INDEX_NODE:
		switch (child_type) {
		case SSDFS_BTREE_INDEX_NODE:
			err = ssdfs_btree_check_index_index_pair(tree,
								 search,
								 parent,
								 child);
			if (unlikely(err)) {
				SSDFS_ERR("fail to check index-index pair: "
					  "err %d\n", err);
			}
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			err = ssdfs_btree_check_index_hybrid_pair(tree,
								  search,
								  parent,
								  child);
			if (unlikely(err)) {
				SSDFS_ERR("fail to check index-hybrid pair: "
					  "err %d\n", err);
			}
			break;

		case SSDFS_BTREE_LEAF_NODE:
			err = ssdfs_btree_check_index_leaf_pair(tree,
								search,
								parent,
								child);
			if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("need to prepare hierarchy: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check index-leaf pair: "
					  "err %d\n", err);
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child_type);
		};
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		switch (child_type) {
		case SSDFS_BTREE_NODE_UNKNOWN_TYPE:
			err = ssdfs_btree_check_hybrid_nothing_pair(tree,
								  search,
								  parent,
								  child);
			if (unlikely(err)) {
				SSDFS_ERR("fail to check hybrid-nothing pair: "
					  "err %d\n", err);
			}
			break;

		case SSDFS_BTREE_INDEX_NODE:
			err = ssdfs_btree_check_hybrid_index_pair(tree,
								  search,
								  parent,
								  child);
			if (unlikely(err)) {
				SSDFS_ERR("fail to check hybrid-index pair: "
					  "err %d\n", err);
			}
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			err = ssdfs_btree_check_hybrid_hybrid_pair(tree,
								   search,
								   parent,
								   child);
			if (unlikely(err)) {
				SSDFS_ERR("fail to check hybrid-hybrid pair: "
					  "err %d\n", err);
			}
			break;

		case SSDFS_BTREE_LEAF_NODE:
			err = ssdfs_btree_check_hybrid_leaf_pair(tree,
								 search,
								 parent,
								 child);
			if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("need to prepare hierarchy: "
					  "err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to check hybrid-leaf pair: "
					  "err %d\n", err);
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid child node's type %#x\n",
				  child_type);
		};
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid parent node's type %#x\n",
			  parent_type);
	}

	return err;
}

/*
 * ssdfs_btree_descend_to_leaf_node() - descend to a leaf node
 * @tree: btree object
 * @search: search object
 *
 * This method tries to descend from the current level till a leaf node.
 *
 * RETURN:
 * [success] - pointer on a leaf node.
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
struct ssdfs_btree_node *
ssdfs_btree_descend_to_leaf_node(struct ssdfs_btree *tree,
				 struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node *node = NULL;
	int type;
	u64 upper_hash;
	u64 start_item_hash;
	u16 items_count;
	u32 prev_node_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);
	BUG_ON(!rwsem_is_locked(&tree->lock));

	SSDFS_DBG("tree %p, search %p\n",
		  tree, search);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->node.height == SSDFS_BTREE_LEAF_NODE_HEIGHT) {
		SSDFS_DBG("search object contains leaf node\n");
		return 0;
	}

	if (!search->node.child) {
		err = -ERANGE;
		SSDFS_ERR("child node object is NULL\n");
		return ERR_PTR(err);
	}

	type = atomic_read(&search->node.child->type);
	if (type != SSDFS_BTREE_HYBRID_NODE) {
		err = -ERANGE;
		SSDFS_ERR("invalid search object: "
			  "height %u, node_type %#x\n",
			  atomic_read(&search->node.child->height),
			  type);
		return ERR_PTR(err);
	}

	if (!is_ssdfs_btree_node_index_area_exist(search->node.child)) {
		err = -ERANGE;
		SSDFS_ERR("index area is absent: "
			  "node_id %u\n",
			  search->node.child->node_id);
		return ERR_PTR(err);
	}

	down_read(&search->node.child->header_lock);
	items_count = search->node.child->items_area.items_count;
	start_item_hash = search->node.child->items_area.start_hash;
	upper_hash = search->node.child->index_area.end_hash;
	up_read(&search->node.child->header_lock);

	if (upper_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid upper hash\n");
		return ERR_PTR(err);
	}

	node = search->node.child;
	prev_node_id = node->node_id;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, items_count %u, "
		  "start_item_hash %llx, end_index_hash %llx\n",
		  node->node_id, items_count,
		  start_item_hash, upper_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	if (type == SSDFS_BTREE_HYBRID_NODE) {
		if (items_count == 0)
			return node;
		else if (start_item_hash >= U64_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid start_item_hash %llx\n",
				  start_item_hash);
			return ERR_PTR(err);
		}

		if (start_item_hash == upper_hash)
			return node;
	}

	do {
		node = ssdfs_btree_get_child_node_for_hash(tree, node,
							   upper_hash);
		if (IS_ERR_OR_NULL(node)) {
			err = !node ? -ERANGE : PTR_ERR(node);
			SSDFS_ERR("fail to get the child node: err %d\n",
				  err);
			return node;
		}

		type = atomic_read(&node->type);

		if (prev_node_id == node->node_id) {
			switch (type) {
			case SSDFS_BTREE_HYBRID_NODE:
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("node_id %u, type %#x\n",
				  node->node_id, type);
#endif /* CONFIG_SSDFS_DEBUG */
				return node;

			default:
				SSDFS_ERR("infinite cycle detected: "
					  "node_id %u, type %#x\n",
					  node->node_id,
					  type);
				return ERR_PTR(-ERANGE);
			}
		} else
			prev_node_id = node->node_id;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node_id %u, type %#x, "
			  "end_index_hash %llx\n",
			  node->node_id, atomic_read(&node->type),
			  upper_hash);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (type) {
		case SSDFS_BTREE_LEAF_NODE:
			/* do nothing */
			break;

		case SSDFS_BTREE_HYBRID_NODE:
		case SSDFS_BTREE_INDEX_NODE:
			if (!is_ssdfs_btree_node_index_area_exist(node)) {
				err = -ERANGE;
				SSDFS_ERR("index area is absent: "
					  "node_id %u\n",
					  node->node_id);
				return ERR_PTR(err);
			}

			down_read(&node->header_lock);
			upper_hash = node->index_area.end_hash;
			up_read(&node->header_lock);

			if (upper_hash == U64_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid upper hash\n");
				return ERR_PTR(err);
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid node type: "
				  "node_id %u, height %u, type %#x\n",
				  node->node_id,
				  atomic_read(&node->height),
				  type);
			return ERR_PTR(err);
		}
	} while (type != SSDFS_BTREE_LEAF_NODE);

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("invalid node state %#x\n",
			  atomic_read(&node->state));
		return ERR_PTR(err);
	}

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		/* expected state */
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid items area state: node_id %u\n",
			   search->node.id);
		return ERR_PTR(err);
	}

	return node;
}

static
void ssdfs_btree_hierarchy_init_hash_range(struct ssdfs_btree_level *level,
					   struct ssdfs_btree_node *node)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!level);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!node)
		return;

	down_read(&node->header_lock);
	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_INDEX_NODE:
		level->nodes.old_node.index_hash.start =
					node->index_area.start_hash;
		level->nodes.old_node.index_hash.end =
					node->index_area.end_hash;
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		level->nodes.old_node.index_hash.start =
					node->index_area.start_hash;
		level->nodes.old_node.index_hash.end =
					node->index_area.end_hash;
		level->nodes.old_node.items_hash.start =
					node->items_area.start_hash;
		level->nodes.old_node.items_hash.end =
					node->items_area.end_hash;
		break;

	case SSDFS_BTREE_LEAF_NODE:
		level->nodes.old_node.items_hash.start =
					node->items_area.start_hash;
		level->nodes.old_node.items_hash.end =
					node->items_area.end_hash;
		break;

	default:
		SSDFS_WARN("unexpected node type %#x\n",
			   atomic_read(&node->type));
		break;
	}
	up_read(&node->header_lock);
}

/*
 * ssdfs_btree_check_hierarchy_for_add() - check the btree for add node
 * @tree: btree object
 * @search: search object
 * @hierarchy: btree's hierarchy object
 *
 * This method tries to check the btree's hierarchy for operation of
 * node addition.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_check_hierarchy_for_add(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_hierarchy *hierarchy)
{
	struct ssdfs_btree_level *level;
	struct ssdfs_btree_node *parent_node, *child_node;
	int child_node_height, cur_height, tree_height;
	int parent_node_type, child_node_type;
	spinlock_t *lock = NULL;
	int err;
	int res = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !hierarchy);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);
#else
	SSDFS_DBG("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	tree_height = atomic_read(&tree->height);
	if (tree_height <= 0) {
		SSDFS_ERR("invalid tree_height %d\n",
			  tree_height);
		return -ERANGE;
	}

	if (search->node.id == SSDFS_BTREE_ROOT_NODE_ID) {
		if (tree_height <= 0 || tree_height > 1) {
			SSDFS_ERR("invalid search object state: "
				  "tree_height %u, node_id %u\n",
				  tree_height,
				  search->node.id);
			return -ERANGE;
		}

		child_node = search->node.child;
		parent_node = search->node.parent;

		if (child_node || !parent_node) {
			SSDFS_ERR("invalid search object state: "
				  "child_node %p, parent_node %p\n",
				  child_node, parent_node);
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		child_node_type = SSDFS_BTREE_NODE_UNKNOWN_TYPE;

		if (parent_node_type != SSDFS_BTREE_ROOT_NODE) {
			SSDFS_ERR("invalid parent node's type %#x\n",
				  parent_node_type);
			return -ERANGE;
		}

		child_node_height = search->node.height;
	} else {
		child_node = search->node.child;
		parent_node = search->node.parent;

		if (!child_node || !parent_node) {
			SSDFS_ERR("invalid search object state: "
				  "child_node %p, parent_node %p\n",
				  child_node, parent_node);
			return -ERANGE;
		}

		switch (atomic_read(&child_node->type)) {
		case SSDFS_BTREE_LEAF_NODE:
			/* do nothing */
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			child_node = ssdfs_btree_descend_to_leaf_node(tree,
								      search);
			if (unlikely(IS_ERR_OR_NULL(child_node))) {
				err = !child_node ?
					-ERANGE : PTR_ERR(child_node);
				SSDFS_ERR("fail to descend to leaf node: "
					  "err %d\n", err);
				return err;
			}

			lock = &child_node->descriptor_lock;
			spin_lock(lock);
			parent_node = child_node->parent_node;
			spin_unlock(lock);
			lock = NULL;

			if (!child_node || !parent_node) {
				SSDFS_ERR("invalid search object state: "
					  "child_node %p, parent_node %p\n",
					  child_node, parent_node);
				return -ERANGE;
			}
			break;

		default:
			SSDFS_ERR("invalid child node's type %#x\n",
				  atomic_read(&child_node->type));
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		child_node_type = atomic_read(&child_node->type);

		switch (child_node_type) {
		case SSDFS_BTREE_LEAF_NODE:
		case SSDFS_BTREE_HYBRID_NODE:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid child node's type %#x\n",
				  child_node_type);
			return -ERANGE;
		}

		child_node_height = atomic_read(&child_node->height);
	}

	cur_height = child_node_height;
	if (cur_height > tree_height) {
		SSDFS_ERR("cur_height %u > tree_height %u\n",
			  cur_height, tree_height);
		return -ERANGE;
	}

	if ((cur_height + 1) >= hierarchy->desc.height) {
		SSDFS_ERR("invalid hierarchy: "
			  "tree_height %u, cur_height %u, "
			  "hierarchy->desc.height %u\n",
			  tree_height, cur_height,
			  hierarchy->desc.height);
		return -ERANGE;
	}

	level = hierarchy->array_ptr[cur_height];
	level->nodes.old_node.type = child_node_type;
	level->nodes.old_node.ptr = child_node;
	ssdfs_btree_hierarchy_init_hash_range(level, child_node);

	cur_height++;
	level = hierarchy->array_ptr[cur_height];
	level->nodes.old_node.type = parent_node_type;
	level->nodes.old_node.ptr = parent_node;
	ssdfs_btree_hierarchy_init_hash_range(level, parent_node);

	cur_height++;
	lock = &parent_node->descriptor_lock;
	spin_lock(lock);
	parent_node = parent_node->parent_node;
	spin_unlock(lock);
	lock = NULL;
	for (; cur_height < tree_height; cur_height++) {
		if (!parent_node) {
			SSDFS_ERR("parent node is NULL\n");
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		level = hierarchy->array_ptr[cur_height];
		level->nodes.old_node.type = parent_node_type;
		level->nodes.old_node.ptr = parent_node;
		ssdfs_btree_hierarchy_init_hash_range(level, parent_node);

		lock = &parent_node->descriptor_lock;
		spin_lock(lock);
		parent_node = parent_node->parent_node;
		spin_unlock(lock);
		lock = NULL;
	}

	cur_height = child_node_height;

	if (child_node_type == SSDFS_BTREE_HYBRID_NODE) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(cur_height < 1);
#endif /* CONFIG_SSDFS_DEBUG */

		cur_height--;
	}

	for (; cur_height <= tree_height; cur_height++) {
		struct ssdfs_btree_level *parent;
		struct ssdfs_btree_level *child;

		parent = hierarchy->array_ptr[cur_height + 1];
		child = hierarchy->array_ptr[cur_height];

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_height %d, tree_height %d\n",
			  cur_height, tree_height);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_btree_check_level_for_add(&hierarchy->desc,
						      tree, search,
						      parent, child);
		if (err == -EAGAIN) {
			res = -EAGAIN;
			err = 0;
			ssdfs_debug_btree_hierarchy_object(hierarchy);
			SSDFS_DBG("need to prepare btree hierarchy for add\n");
			/* continue logic for upper layers */
			continue;
		} else if (err == -ENOSPC) {
			if ((cur_height + 1) != (tree_height - 1)) {
				ssdfs_debug_btree_hierarchy_object(hierarchy);
				SSDFS_ERR("invalid current height: "
					  "cur_height %u, tree_height %u\n",
					  cur_height, tree_height);
				return -ERANGE;
			} else {
				err = 0;
				continue;
			}
		} else if (unlikely(err)) {
			ssdfs_debug_btree_hierarchy_object(hierarchy);
			SSDFS_ERR("fail to check btree's level: "
				  "cur_height %u, tree_height %u, "
				  "err %d\n",
				  cur_height, tree_height, err);
			return err;
		} else if ((cur_height + 1) >= tree_height)
			break;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_btree_hierarchy_object(hierarchy);

	return res;
}

/*
 * ssdfs_btree_check_level_for_delete() - check btree's level for node deletion
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the level of btree for node deletion.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_level_for_delete(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node, *child_node;
	u16 index_count, items_count;
	u64 hash;
	u64 parent_start_hash, parent_end_hash;
	u64 child_start_hash, child_end_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));

	SSDFS_DBG("tree %p, search %p, parent %p, child %p\n",
		  tree, search, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;
	child_node = child->nodes.old_node.ptr;

	if (!child_node) {
		SSDFS_ERR("node is NULL\n");
		return -ERANGE;
	}

	switch (atomic_read(&child_node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
		/* do nothing */
		return 0;

	default:
		if (!parent_node) {
			SSDFS_ERR("node is NULL\n");
			return -ERANGE;
		}
	}

	if (child->flags & SSDFS_BTREE_LEVEL_DELETE_NODE) {
		parent->flags |= SSDFS_BTREE_LEVEL_DELETE_INDEX;

		switch (atomic_read(&parent_node->type)) {
		case SSDFS_BTREE_ROOT_NODE:
		case SSDFS_BTREE_HYBRID_NODE:
		case SSDFS_BTREE_INDEX_NODE:
			/* expected type */
			break;

		default:
			SSDFS_ERR("invalid parent node type %#x\n",
				  atomic_read(&parent_node->type));
			return -ERANGE;
		}

		parent->index_area.delete.op_state =
				SSDFS_BTREE_AREA_OP_REQUESTED;

		spin_lock(&child_node->descriptor_lock);
		ssdfs_memcpy(&parent->index_area.delete.node_index,
			     0, sizeof(struct ssdfs_btree_index_key),
			     &child_node->node_index,
			     0, sizeof(struct ssdfs_btree_index_key),
			     sizeof(struct ssdfs_btree_index_key));
		spin_unlock(&child_node->descriptor_lock);

		down_read(&parent_node->header_lock);

		index_count = parent_node->index_area.index_count;
		items_count = parent_node->items_area.items_count;

		switch (atomic_read(&parent_node->type)) {
		case SSDFS_BTREE_HYBRID_NODE:
			/*
			 * Hybrid node has self-index.
			 * It needs to be deleted if there is:
			 * (1) no items in node
			 * (2) self-index + index of leaf node
			 */
			if (index_count <= 2 && items_count == 0)
				parent->flags |= SSDFS_BTREE_LEVEL_DELETE_NODE;
			break;

		default:
			if (index_count <= 1 && items_count == 0)
				parent->flags |= SSDFS_BTREE_LEVEL_DELETE_NODE;
			break;
		}

		up_read(&parent_node->header_lock);
	} else if (child->flags & SSDFS_BTREE_LEVEL_DELETE_INDEX) {
		struct ssdfs_btree_node_delete *delete;

		delete = &child->index_area.delete;

		if (delete->op_state != SSDFS_BTREE_AREA_OP_REQUESTED) {
			SSDFS_ERR("invalid operation state %#x\n",
				  delete->op_state);
			return -ERANGE;
		}

		hash = le64_to_cpu(delete->node_index.index.hash);

		down_read(&child_node->header_lock);
		child_start_hash = child_node->index_area.start_hash;
		child_end_hash = child_node->index_area.end_hash;
		up_read(&child_node->header_lock);

		if (hash == child_start_hash || hash == child_end_hash) {
			parent->flags |= SSDFS_BTREE_LEVEL_UPDATE_INDEX;

			/*
			 * Simply add flag.
			 * Maybe it will need to add additional code.
			 */
		}
	} else if (child->flags & SSDFS_BTREE_LEVEL_UPDATE_INDEX) {
		down_read(&parent_node->header_lock);
		parent_start_hash = parent_node->index_area.start_hash;
		parent_end_hash = parent_node->index_area.end_hash;
		up_read(&parent_node->header_lock);

		down_read(&child_node->header_lock);
		child_start_hash = child_node->index_area.start_hash;
		child_end_hash = child_node->index_area.end_hash;
		up_read(&child_node->header_lock);

		if (child_start_hash == parent_start_hash ||
		    child_start_hash == parent_end_hash) {
			/* set update index flag */
			parent->flags |= SSDFS_BTREE_LEVEL_UPDATE_INDEX;
		} else if (child_end_hash == parent_start_hash ||
			   child_end_hash == parent_end_hash) {
			/* set update index flag */
			parent->flags |= SSDFS_BTREE_LEVEL_UPDATE_INDEX;
		} else {
			err = ssdfs_btree_prepare_do_nothing(parent,
							     parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare index node: "
					  "err %d\n", err);
				return err;
			}
		}
	} else {
		err = ssdfs_btree_prepare_do_nothing(parent,
						     parent_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare index node: "
				  "err %d\n", err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_check_hierarchy_for_delete() - check the btree for node deletion
 * @tree: btree object
 * @search: search object
 * @hierarchy: btree's hierarchy object
 *
 * This method tries to check the btree's hierarchy for operation of
 * node deletion.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_check_hierarchy_for_delete(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_hierarchy *hierarchy)
{
	struct ssdfs_btree_level *level;
	struct ssdfs_btree_node *parent_node, *child_node;
	int child_node_height, cur_height, tree_height;
	int parent_node_type, child_node_type;
	spinlock_t *lock = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !hierarchy);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);
#else
	SSDFS_DBG("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	tree_height = atomic_read(&tree->height);
	if (tree_height == 0) {
		SSDFS_ERR("invalid tree_height %u\n",
			  tree_height);
		return -ERANGE;
	}

	if (search->node.id == SSDFS_BTREE_ROOT_NODE_ID) {
		SSDFS_ERR("root node cannot be deleted\n");
		return -ERANGE;
	} else {
		child_node = search->node.child;

		lock = &child_node->descriptor_lock;
		spin_lock(lock);
		parent_node = child_node->parent_node;
		spin_unlock(lock);
		lock = NULL;

		if (!child_node || !parent_node) {
			SSDFS_ERR("invalid search object state: "
				  "child_node %p, parent_node %p\n",
				  child_node, parent_node);
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		child_node_type = atomic_read(&child_node->type);
		child_node_height = atomic_read(&child_node->height);
	}

	cur_height = child_node_height;
	if (cur_height >= tree_height) {
		SSDFS_ERR("cur_height %u >= tree_height %u\n",
			  cur_height, tree_height);
		return -ERANGE;
	}

	if ((cur_height + 1) >= hierarchy->desc.height ||
	    (cur_height + 1) >= tree_height) {
		SSDFS_ERR("invalid hierarchy: "
			  "tree_height %u, cur_height %u, "
			  "hierarchy->desc.height %u\n",
			  tree_height, cur_height,
			  hierarchy->desc.height);
		return -ERANGE;
	}

	level = hierarchy->array_ptr[cur_height];
	level->nodes.old_node.type = child_node_type;
	level->nodes.old_node.ptr = child_node;
	ssdfs_btree_hierarchy_init_hash_range(level, child_node);
	level->flags |= SSDFS_BTREE_LEVEL_DELETE_NODE;

	cur_height++;
	level = hierarchy->array_ptr[cur_height];
	level->nodes.old_node.type = parent_node_type;
	level->nodes.old_node.ptr = parent_node;
	ssdfs_btree_hierarchy_init_hash_range(level, parent_node);

	cur_height++;
	lock = &parent_node->descriptor_lock;
	spin_lock(lock);
	parent_node = parent_node->parent_node;
	spin_unlock(lock);
	lock = NULL;
	for (; cur_height < tree_height; cur_height++) {
		if (!parent_node) {
			SSDFS_ERR("parent node is NULL\n");
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		level = hierarchy->array_ptr[cur_height];
		level->nodes.old_node.type = parent_node_type;
		level->nodes.old_node.ptr = parent_node;
		ssdfs_btree_hierarchy_init_hash_range(level, parent_node);

		lock = &parent_node->descriptor_lock;
		spin_lock(lock);
		parent_node = parent_node->parent_node;
		spin_unlock(lock);
		lock = NULL;
	}

	cur_height = child_node_height;
	for (; cur_height < tree_height; cur_height++) {
		struct ssdfs_btree_level *parent;
		struct ssdfs_btree_level *child;

		parent = hierarchy->array_ptr[cur_height + 1];
		child = hierarchy->array_ptr[cur_height];

		err = ssdfs_btree_check_level_for_delete(tree, search,
							 parent, child);
		if (unlikely(err)) {
			SSDFS_ERR("fail to check btree's level: "
				  "cur_height %u, tree_height %u, "
				  "err %d\n",
				  cur_height, tree_height, err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * ssdfs_btree_check_level_for_update() - check btree's level for index update
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the level of btree for index update.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_level_for_update(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node, *child_node;
	int state;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));

	SSDFS_DBG("tree %p, search %p, parent %p, child %p\n",
		  tree, search, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	child_node = child->nodes.old_node.ptr;
	if (!child_node) {
		SSDFS_ERR("child node is NULL\n");
		return -ERANGE;
	}

	if (child_node->node_id == SSDFS_BTREE_ROOT_NODE_ID) {
		SSDFS_DBG("nothing should be done for the root node\n");
		return 0;
	}

	parent_node = parent->nodes.old_node.ptr;
	if (!parent_node) {
		SSDFS_ERR("parent node is NULL\n");
		return -ERANGE;
	}

	state = atomic_read(&parent_node->index_area.state);
	if (state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
		SSDFS_ERR("parent node %u hasn't index area\n",
			  parent_node->node_id);
		return -ERANGE;
	}

	switch (atomic_read(&child_node->type)) {
	case SSDFS_BTREE_LEAF_NODE:
		state = atomic_read(&child_node->items_area.state);
		if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
			SSDFS_ERR("child node %u hasn't items area\n",
				  child_node->node_id);
			return -ERANGE;
		}

		/* set necessity to update the parent's index */
		parent->flags |= SSDFS_BTREE_LEVEL_UPDATE_INDEX;
		break;

	default:
		state = atomic_read(&child_node->index_area.state);
		if (state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
			SSDFS_ERR("child node %u hasn't index area\n",
				  child_node->node_id);
			return -ERANGE;
		}

		/* set necessity to update the parent's index */
		parent->flags |= SSDFS_BTREE_LEVEL_UPDATE_INDEX;
		break;
	}

	return 0;
}

/*
 * ssdfs_btree_check_hierarchy_for_update() - check the btree for index update
 * @tree: btree object
 * @search: search object
 * @hierarchy: btree's hierarchy object
 *
 * This method tries to check the btree's hierarchy for operation of
 * index update.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_check_hierarchy_for_update(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_hierarchy *hierarchy)
{
	struct ssdfs_btree_level *level;
	struct ssdfs_btree_node *parent_node, *child_node;
	int child_node_height, cur_height, tree_height;
	int parent_node_type, child_node_type;
	spinlock_t *lock;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !hierarchy);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);
#else
	SSDFS_DBG("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	tree_height = atomic_read(&tree->height);
	if (tree_height == 0) {
		SSDFS_ERR("invalid tree_height %u\n",
			  tree_height);
		return -ERANGE;
	}

	if (search->node.id == SSDFS_BTREE_ROOT_NODE_ID) {
		SSDFS_ERR("parent node is absent\n");
		return -ERANGE;
	} else {
		child_node = search->node.child;

		lock = &child_node->descriptor_lock;
		spin_lock(lock);
		parent_node = child_node->parent_node;
		spin_unlock(lock);
		lock = NULL;

		if (!child_node || !parent_node) {
			SSDFS_ERR("invalid search object state: "
				  "child_node %p, parent_node %p\n",
				  child_node, parent_node);
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		child_node_type = atomic_read(&child_node->type);
		child_node_height = atomic_read(&child_node->height);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("child_node %px, child_node_id %u, child_node_type %#x\n",
		  child_node, child_node->node_id, child_node_type);
	SSDFS_DBG("parent_node %px, parent_node_id %u, parent_node_type %#x\n",
		  parent_node, parent_node->node_id, parent_node_type);
#endif /* CONFIG_SSDFS_DEBUG */

	cur_height = child_node_height;
	if (cur_height >= tree_height) {
		SSDFS_ERR("cur_height %u >= tree_height %u\n",
			  cur_height, tree_height);
		return -ERANGE;
	}

	if ((cur_height + 1) >= hierarchy->desc.height ||
	    (cur_height + 1) >= tree_height) {
		SSDFS_ERR("invalid hierarchy: "
			  "tree_height %u, cur_height %u, "
			  "hierarchy->desc.height %u\n",
			  tree_height, cur_height,
			  hierarchy->desc.height);
		return -ERANGE;
	}

	level = hierarchy->array_ptr[cur_height];
	level->nodes.old_node.type = child_node_type;
	level->nodes.old_node.ptr = child_node;
	ssdfs_btree_hierarchy_init_hash_range(level, child_node);

	cur_height++;
	level = hierarchy->array_ptr[cur_height];
	level->nodes.old_node.type = parent_node_type;
	level->nodes.old_node.ptr = parent_node;
	ssdfs_btree_hierarchy_init_hash_range(level, parent_node);
	level->flags |= SSDFS_BTREE_LEVEL_UPDATE_INDEX;

	cur_height++;
	lock = &parent_node->descriptor_lock;
	spin_lock(lock);
	parent_node = parent_node->parent_node;
	spin_unlock(lock);
	lock = NULL;
	for (; cur_height < tree_height; cur_height++) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_height %d, tree_height %d, parent_node %px\n",
			  cur_height, tree_height, parent_node);
#endif /* CONFIG_SSDFS_DEBUG */

		if (!parent_node) {
			SSDFS_ERR("parent node is NULL\n");
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		level = hierarchy->array_ptr[cur_height];
		level->nodes.old_node.type = parent_node_type;
		level->nodes.old_node.ptr = parent_node;
		ssdfs_btree_hierarchy_init_hash_range(level, parent_node);

		lock = &parent_node->descriptor_lock;
		spin_lock(lock);
		parent_node = parent_node->parent_node;
		spin_unlock(lock);
		lock = NULL;
	}

	cur_height = child_node_height;
	for (; cur_height < tree_height; cur_height++) {
		struct ssdfs_btree_level *parent;
		struct ssdfs_btree_level *child;

		parent = hierarchy->array_ptr[cur_height + 1];
		child = hierarchy->array_ptr[cur_height];

		err = ssdfs_btree_check_level_for_update(tree, search,
							 parent, child);
		if (unlikely(err)) {
			SSDFS_ERR("fail to check btree's level: "
				  "cur_height %u, tree_height %u, "
				  "err %d\n",
				  cur_height, tree_height, err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

/*
 * __need_migrate_items_to_parent_node() - check necessity to migrate items in parent node
 * @parent: parent node
 * @child: child node
 */
bool __need_migrate_items_to_parent_node(struct ssdfs_btree_node *parent,
					 struct ssdfs_btree_node *child)
{
	struct ssdfs_btree_node_index_area area;
	struct ssdfs_btree_index_key index_key;
	u16 index_count;
	u16 child_items_count;
	u16 parent_items_count;
	u16 parent_items_capacity;
	u16 vacant_items;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!child);
	BUG_ON(!parent);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (parent->tree->type) {
	case SSDFS_INODES_BTREE:
		/* inodes b-tree cannot do merging */
		return false;

	default:
		/* continue logic */
		break;
	}

	switch (atomic_read(&child->type)) {
	case SSDFS_BTREE_LEAF_NODE:
		/* continue logic */
		break;

	default:
		return false;
	}

	switch (atomic_read(&parent->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		/* continue logic */
		break;

	default:
		return false;
	}

	down_read(&child->header_lock);
	child_items_count = child->items_area.items_count;
	up_read(&child->header_lock);

	down_read(&parent->header_lock);
	index_count = parent->index_area.index_count;
	parent_items_count = parent->items_area.items_count;
	parent_items_capacity = parent->items_area.items_capacity;
	up_read(&parent->header_lock);

	if (index_count > 2) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("it is not time to migrate: "
			  "child (node_id %u, items_count %u), "
			  "parent (node_id %u, index_count %u, "
			  "items_count %u, items_capacity %u)\n",
			  child->node_id, child_items_count,
			  parent->node_id, index_count,
			  parent_items_count,
			  parent_items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	} else if (index_count == 2) {
		u16 last_index = index_count - 1;
		u32 node_id;

		down_read(&parent->full_lock);
		down_read(&parent->header_lock);
		ssdfs_memcpy(&area,
			     0, sizeof(struct ssdfs_btree_node_index_area),
			     &parent->index_area,
			     0, sizeof(struct ssdfs_btree_node_index_area),
			     sizeof(struct ssdfs_btree_node_index_area));
		up_read(&parent->header_lock);
		err = __ssdfs_btree_common_node_extract_index(parent, &area,
							      last_index,
							      &index_key);
		up_read(&parent->full_lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to extract index key: "
				  "index_position %u, err %d\n",
				  last_index, err);
			ssdfs_debug_show_btree_node_indexes(parent->tree,
							    parent);
			return false;
		}

		node_id = le32_to_cpu(index_key.node_id);

		if (node_id != parent->node_id) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("it is not time to migrate: "
				  "parent node %u has index_count %u\n",
				  parent->node_id, index_count);
#endif /* CONFIG_SSDFS_DEBUG */
			return false;
		}
	}

	vacant_items = parent_items_capacity - parent_items_count;

	if (vacant_items < child_items_count) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("it is not time to migrate: "
			  "child (node_id %u, items_count %u), "
			  "parent (node_id %u, index_count %u, "
			  "items_count %u, items_capacity %u)\n",
			  child->node_id, child_items_count,
			  parent->node_id, index_count,
			  parent_items_count,
			  parent_items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("time to migrate: "
		  "child (node_id %u, items_count %u), "
		  "parent (node_id %u, index_count %u, "
		  "items_count %u, items_capacity %u)\n",
		  child->node_id, child_items_count,
		  parent->node_id, index_count,
		  parent_items_count,
		  parent_items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return true;
}

/*
 * ssdfs_btree_check_level_for_parent_child_merge() - check btree's level for merge
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the level of btree for parent
 * and child nodes merge.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_level_for_parent_child_merge(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node, *child_node;
	struct ssdfs_btree_node_move *move;
	u16 items_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));

	SSDFS_DBG("tree %p, search %p, parent %p, child %p\n",
		  tree, search, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	child_node = child->nodes.old_node.ptr;
	if (!child_node) {
		SSDFS_ERR("child node is NULL\n");
		return -ERANGE;
	}

	if (child_node->node_id == SSDFS_BTREE_ROOT_NODE_ID) {
		SSDFS_DBG("nothing should be done for the root node\n");
		return 0;
	}

	parent_node = parent->nodes.old_node.ptr;
	if (!parent_node) {
		SSDFS_ERR("parent node is NULL\n");
		return -ERANGE;
	}

	switch (atomic_read(&child_node->type)) {
	case SSDFS_BTREE_LEAF_NODE:
		if (__need_migrate_items_to_parent_node(parent_node,
							child_node)) {
			move = &child->items_area.move;

			switch (atomic_read(&parent_node->type)) {
			case SSDFS_BTREE_HYBRID_NODE:
				/* expected type */
				break;

			default:
				SSDFS_ERR("invalid parent node type %#x\n",
					  atomic_read(&parent_node->type));
				return -ERANGE;
			}

			down_read(&child_node->header_lock);
			items_count = child_node->items_area.items_count;
			up_read(&child_node->header_lock);

			child->flags |= SSDFS_BTREE_ITEMS_AREA_NEED_MOVE;
			move->direction = SSDFS_BTREE_MOVE_TO_PARENT;
			move->pos.state = SSDFS_HASH_RANGE_INTERSECTION;
			move->pos.start = 0;
			move->pos.count = items_count;
			move->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

			child->flags |= SSDFS_BTREE_LEVEL_DELETE_NODE;
		} else {
			err = ssdfs_btree_prepare_do_nothing(parent,
							     parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare parent node: "
					  "err %d\n", err);
				return err;
			}
		}
		break;

	default:
		if (child->flags & SSDFS_BTREE_LEVEL_DELETE_NODE) {
			parent->flags |= SSDFS_BTREE_LEVEL_UPDATE_INDEX;

			/*
			 * Simply add flag.
			 * Maybe it will need to add additional code.
			 */
		}
		break;
	}

	return 0;
}

/*
 * ssdfs_btree_check_hierarchy_for_parent_child_merge() - check the btree for merge
 * @tree: btree object
 * @search: search object
 * @hierarchy: btree's hierarchy object
 *
 * This method tries to check the btree's hierarchy for operation of
 * merging parent hybrid node and child leaf node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_check_hierarchy_for_parent_child_merge(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_hierarchy *hierarchy)
{
	struct ssdfs_btree_level *level;
	struct ssdfs_btree_node *parent_node, *child_node;
	int child_node_height, cur_height, tree_height;
	int parent_node_type, child_node_type;
	spinlock_t *lock;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !hierarchy);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);
#else
	SSDFS_DBG("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	tree_height = atomic_read(&tree->height);
	if (tree_height == 0) {
		SSDFS_ERR("invalid tree_height %u\n",
			  tree_height);
		return -ERANGE;
	}

	if (search->node.id == SSDFS_BTREE_ROOT_NODE_ID) {
		SSDFS_ERR("parent node is absent\n");
		return -ERANGE;
	} else {
		child_node = search->node.child;

		lock = &child_node->descriptor_lock;
		spin_lock(lock);
		parent_node = child_node->parent_node;
		spin_unlock(lock);
		lock = NULL;

		if (!child_node || !parent_node) {
			SSDFS_ERR("invalid search object state: "
				  "child_node %p, parent_node %p\n",
				  child_node, parent_node);
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		child_node_type = atomic_read(&child_node->type);
		child_node_height = atomic_read(&child_node->height);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("child_node %px, child_node_id %u, child_node_type %#x\n",
		  child_node, child_node->node_id, child_node_type);
	SSDFS_DBG("parent_node %px, parent_node_id %u, parent_node_type %#x\n",
		  parent_node, parent_node->node_id, parent_node_type);
#endif /* CONFIG_SSDFS_DEBUG */

	cur_height = child_node_height;
	if (cur_height >= tree_height) {
		SSDFS_ERR("cur_height %u >= tree_height %u\n",
			  cur_height, tree_height);
		return -ERANGE;
	}

	if ((cur_height + 1) >= hierarchy->desc.height ||
	    (cur_height + 1) >= tree_height) {
		SSDFS_ERR("invalid hierarchy: "
			  "tree_height %u, cur_height %u, "
			  "hierarchy->desc.height %u\n",
			  tree_height, cur_height,
			  hierarchy->desc.height);
		return -ERANGE;
	}

	level = hierarchy->array_ptr[cur_height];
	level->nodes.old_node.type = child_node_type;
	level->nodes.old_node.ptr = child_node;
	ssdfs_btree_hierarchy_init_hash_range(level, child_node);

	cur_height++;
	level = hierarchy->array_ptr[cur_height];
	level->nodes.old_node.type = parent_node_type;
	level->nodes.old_node.ptr = parent_node;
	ssdfs_btree_hierarchy_init_hash_range(level, parent_node);

	cur_height++;
	lock = &parent_node->descriptor_lock;
	spin_lock(lock);
	parent_node = parent_node->parent_node;
	spin_unlock(lock);
	lock = NULL;
	for (; cur_height < tree_height; cur_height++) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_height %d, tree_height %d, parent_node %px\n",
			  cur_height, tree_height, parent_node);
#endif /* CONFIG_SSDFS_DEBUG */

		if (!parent_node) {
			SSDFS_ERR("parent node is NULL\n");
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		level = hierarchy->array_ptr[cur_height];
		level->nodes.old_node.type = parent_node_type;
		level->nodes.old_node.ptr = parent_node;
		ssdfs_btree_hierarchy_init_hash_range(level, parent_node);

		lock = &parent_node->descriptor_lock;
		spin_lock(lock);
		parent_node = parent_node->parent_node;
		spin_unlock(lock);
		lock = NULL;
	}

	cur_height = child_node_height;
	for (; cur_height < tree_height; cur_height++) {
		struct ssdfs_btree_level *parent;
		struct ssdfs_btree_level *child;

		parent = hierarchy->array_ptr[cur_height + 1];
		child = hierarchy->array_ptr[cur_height];

		err = ssdfs_btree_check_level_for_parent_child_merge(tree,
								     search,
								     parent,
								     child);
		if (unlikely(err)) {
			SSDFS_ERR("fail to check btree's level: "
				  "cur_height %u, tree_height %u, "
				  "err %d\n",
				  cur_height, tree_height, err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

#define SSDFS_ITEMS_COUNT_MERGE_PERCENTAGE	(15)

/*
 * __need_merge_sibling_nodes() - check necessity to merge sibling nodes
 * @parent: parent node
 * @child: child node
 */
bool __need_merge_sibling_nodes(struct ssdfs_btree_node *parent,
				struct ssdfs_btree_node *child)
{
	struct ssdfs_btree *tree;
	struct ssdfs_btree_node *left_sibling;
	struct ssdfs_btree_node_index_area area;
	struct ssdfs_btree_index_key index_key;
	u16 index_count;
	u16 index_capacity;
	u16 index_position;
	u16 child_items_count;
	u16 child_items_capacity;
	u64 hash;
	u32 percentage;
	u32 node_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!child);
	BUG_ON(!parent);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (parent->tree->type) {
	case SSDFS_INODES_BTREE:
		/* inodes b-tree cannot do merging */
		return false;

	default:
		/* continue logic */
		break;
	}

	switch (atomic_read(&child->type)) {
	case SSDFS_BTREE_LEAF_NODE:
		/* continue logic */
		break;

	default:
		return false;
	}

	switch (atomic_read(&parent->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		/* continue logic */
		break;

	default:
		return false;
	}

	down_read(&child->header_lock);
	child_items_count = child->items_area.items_count;
	child_items_capacity = child->items_area.items_capacity;
	up_read(&child->header_lock);

	percentage = (child_items_count * 100) / child_items_capacity;

	if (percentage >= SSDFS_ITEMS_COUNT_MERGE_PERCENTAGE) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("child node %u doesn't achieve threshold: "
			  "child_items_count %u, child_items_capacity %u\n",
			  child->node_id, child_items_count,
			  child_items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	down_read(&parent->header_lock);
	index_count = parent->index_area.index_count;
	index_capacity = parent->index_area.index_capacity;
	up_read(&parent->header_lock);

	spin_lock(&child->descriptor_lock);
	hash = le64_to_cpu(child->node_index.index.hash);
	spin_unlock(&child->descriptor_lock);

	err = ssdfs_btree_node_find_index_position(parent, hash,
						   &index_position);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the index position: "
			  "hash %llx, err %d\n",
			  hash, err);
		return false;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("hash %llx, index_position %u\n",
		  hash, index_position);
#endif /* CONFIG_SSDFS_DEBUG */

	if (index_position >= index_count) {
		SSDFS_ERR("index_position %u >= index_count %u\n",
			  index_position, index_count);
		return false;
	} else if (index_position == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("child node %u has no left sibling: "
			  "index_position %u, index_count %u\n",
			  child->node_id, index_position,
			  index_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	} else if ((index_count - index_position) > 2) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("child node %u has right sibling: "
			  "index_position %u, index_count %u\n",
			  child->node_id, index_position,
			  index_count);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	} else if ((index_count - index_position) == 2) {
		u16 last_index = index_count - 1;

		down_read(&parent->full_lock);
		down_read(&parent->header_lock);
		ssdfs_memcpy(&area,
			     0, sizeof(struct ssdfs_btree_node_index_area),
			     &parent->index_area,
			     0, sizeof(struct ssdfs_btree_node_index_area),
			     sizeof(struct ssdfs_btree_node_index_area));
		up_read(&parent->header_lock);
		err = __ssdfs_btree_common_node_extract_index(parent, &area,
							      last_index,
							      &index_key);
		up_read(&parent->full_lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to extract index key: "
				  "index_position %u, err %d\n",
				  last_index, err);
			ssdfs_debug_show_btree_node_indexes(parent->tree,
							    parent);
			return false;
		}

		node_id = le32_to_cpu(index_key.node_id);

		if (node_id != parent->node_id) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("child node %u has right sibling: "
			  "index_position %u, index_count %u\n",
			  child->node_id, index_position,
			  index_count);
#endif /* CONFIG_SSDFS_DEBUG */
			return false;
		}
	}

	index_position--;

	down_read(&parent->full_lock);
	down_read(&parent->header_lock);
	ssdfs_memcpy(&area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     &parent->index_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     sizeof(struct ssdfs_btree_node_index_area));
	up_read(&parent->header_lock);
	err = __ssdfs_btree_common_node_extract_index(parent, &area,
						      index_position,
						      &index_key);
	up_read(&parent->full_lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to extract index key: "
			  "index_position %u, err %d\n",
			  index_position, err);
		ssdfs_debug_show_btree_node_indexes(parent->tree, parent);
		return false;
	}

	tree = parent->tree;
	node_id = le32_to_cpu(index_key.node_id);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_position %u, node_id %u\n",
		  index_position, node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_radix_tree_find(tree, node_id, &left_sibling);
	if (err == -ENOENT) {
		err = 0;
		left_sibling = __ssdfs_btree_read_node(tree, parent,
							&index_key,
							index_key.node_type,
							node_id);
		if (unlikely(IS_ERR_OR_NULL(left_sibling))) {
			err = !left_sibling ? -ENOMEM : PTR_ERR(left_sibling);
			SSDFS_ERR("fail to read: "
				  "node %llu, err %d\n",
				  (u64)node_id, err);
			return false;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find node in radix tree: "
			  "node_id %llu, err %d\n",
			  (u64)node_id, err);
		return false;
	} else if (!left_sibling) {
		SSDFS_WARN("empty node pointer\n");
		return false;
	}

	down_read(&left_sibling->header_lock);
	child_items_count = left_sibling->items_area.items_count;
	child_items_capacity = left_sibling->items_area.items_capacity;
	up_read(&left_sibling->header_lock);

	percentage = (child_items_count * 100) / child_items_capacity;

	if (percentage >= SSDFS_ITEMS_COUNT_MERGE_PERCENTAGE) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("child node %u doesn't achieve threshold: "
			  "child_items_count %u, child_items_capacity %u\n",
			  left_sibling->node_id, child_items_count,
			  child_items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	return true;
}

/*
 * ssdfs_btree_check_level_for_siblings_merge() - check btree's level for nodes merge
 * @tree: btree object
 * @search: search object
 * @parent: parent level object
 * @child: child level object
 *
 * This method tries to check the level of btree for sibling nodes merge.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_check_level_for_siblings_merge(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_level *parent,
					struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node, *child_node;
	struct ssdfs_btree_node *left_sibling;
	struct ssdfs_btree_node_move *move;
	struct ssdfs_btree_node_delete *delete;
	struct ssdfs_btree_node_index_area area;
	struct ssdfs_btree_index_key index_key;
	u16 items_count;
	u16 index_count;
	u64 hash;
	u64 child_start_hash;
	u64 child_end_hash;
	u16 index_position;
	u32 node_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !parent || !child);
	BUG_ON(!rwsem_is_locked(&tree->lock));

	SSDFS_DBG("tree %p, search %p, parent %p, child %p\n",
		  tree, search, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	child_node = child->nodes.old_node.ptr;
	if (!child_node) {
		SSDFS_ERR("child node is NULL\n");
		return -ERANGE;
	}

	if (child_node->node_id == SSDFS_BTREE_ROOT_NODE_ID) {
		SSDFS_DBG("nothing should be done for the root node\n");
		return 0;
	}

	parent_node = parent->nodes.old_node.ptr;
	if (!parent_node) {
		SSDFS_ERR("parent node is NULL\n");
		return -ERANGE;
	}

	switch (atomic_read(&child_node->type)) {
	case SSDFS_BTREE_LEAF_NODE:
		if (__need_merge_sibling_nodes(parent_node, child_node)) {
			move = &child->items_area.move;

			down_read(&child_node->header_lock);
			items_count = child_node->items_area.items_count;
			up_read(&child_node->header_lock);

			child->flags |= SSDFS_BTREE_ITEMS_AREA_NEED_MOVE;
			move->direction = SSDFS_BTREE_MOVE_TO_LEFT;
			move->pos.state = SSDFS_HASH_RANGE_INTERSECTION;
			move->pos.start = 0;
			move->pos.count = items_count;
			move->op_state = SSDFS_BTREE_AREA_OP_REQUESTED;

			down_read(&parent_node->header_lock);
			index_count = parent_node->index_area.index_count;
			up_read(&parent_node->header_lock);

			spin_lock(&child_node->descriptor_lock);
			hash = le64_to_cpu(child_node->node_index.index.hash);
			spin_unlock(&child_node->descriptor_lock);

			err = ssdfs_btree_node_find_index_position(parent_node,
								hash,
								&index_position);
			if (unlikely(err)) {
				SSDFS_ERR("fail to find the index position: "
					  "hash %llx, err %d\n",
					  hash, err);
				return err;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("hash %llx, index_position %u\n",
				  hash, index_position);
#endif /* CONFIG_SSDFS_DEBUG */

			if (index_position == 0 ||
			    index_position >= index_count) {
				SSDFS_ERR("invalid index_position: "
					  "index_position %u, index_count %u\n",
					  index_position, index_count);
				return -ERANGE;
			}

			index_position--;

			down_read(&parent_node->full_lock);
			down_read(&parent_node->header_lock);
			ssdfs_memcpy(&area,
				0, sizeof(struct ssdfs_btree_node_index_area),
				&parent_node->index_area,
				0, sizeof(struct ssdfs_btree_node_index_area),
				sizeof(struct ssdfs_btree_node_index_area));
			up_read(&parent_node->header_lock);
			err = __ssdfs_btree_common_node_extract_index(parent_node,
								&area,
								index_position,
								&index_key);
			up_read(&parent_node->full_lock);

			if (unlikely(err)) {
				SSDFS_ERR("fail to extract index key: "
					  "index_position %u, err %d\n",
					  index_position, err);
				ssdfs_debug_show_btree_node_indexes(tree,
								    parent_node);
				return err;
			}

			node_id = le32_to_cpu(index_key.node_id);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("index_position %u, node_id %u\n",
				  index_position, node_id);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_btree_radix_tree_find(tree, node_id,
							  &left_sibling);
			if (err == -ENOENT) {
				err = 0;
				left_sibling = __ssdfs_btree_read_node(tree,
							parent_node,
							&index_key,
							index_key.node_type,
							node_id);
				if (IS_ERR_OR_NULL(left_sibling)) {
					err = !left_sibling ?
						-ENOMEM : PTR_ERR(left_sibling);
					SSDFS_ERR("fail to read: "
						  "node %llu, err %d\n",
						  (u64)node_id, err);
					return err;
				}
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to find node in radix tree: "
					  "node_id %llu, err %d\n",
					  (u64)node_id, err);
				return err;
			} else if (!left_sibling) {
				SSDFS_WARN("empty node pointer\n");
				return -ERANGE;
			}

			child->nodes.new_node.type =
					atomic_read(&left_sibling->type);
			child->nodes.new_node.ptr = left_sibling;

			parent->flags |= SSDFS_BTREE_LEVEL_DELETE_INDEX;

			switch (atomic_read(&parent_node->type)) {
			case SSDFS_BTREE_HYBRID_NODE:
				/* expected type */
				break;

			default:
				SSDFS_ERR("invalid parent node type %#x\n",
					  atomic_read(&parent_node->type));
				return -ERANGE;
			}

			parent->index_area.delete.op_state =
					SSDFS_BTREE_AREA_OP_REQUESTED;

			spin_lock(&child_node->descriptor_lock);
			ssdfs_memcpy(&parent->index_area.delete.node_index,
				     0, sizeof(struct ssdfs_btree_index_key),
				     &child_node->node_index,
				     0, sizeof(struct ssdfs_btree_index_key),
				     sizeof(struct ssdfs_btree_index_key));
			spin_unlock(&child_node->descriptor_lock);

			child->flags |= SSDFS_BTREE_LEVEL_DELETE_NODE;
		} else {
			err = ssdfs_btree_prepare_do_nothing(parent,
							     parent_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare parent node: "
					  "err %d\n", err);
				return err;
			}
		}
		break;

	default:
		if (child->flags & SSDFS_BTREE_LEVEL_DELETE_INDEX) {
			delete = &child->index_area.delete;

			if (delete->op_state != SSDFS_BTREE_AREA_OP_REQUESTED) {
				SSDFS_ERR("invalid operation state %#x\n",
					  delete->op_state);
				return -ERANGE;
			}

			hash = le64_to_cpu(delete->node_index.index.hash);

			down_read(&child_node->header_lock);
			child_start_hash = child_node->index_area.start_hash;
			child_end_hash = child_node->index_area.end_hash;
			up_read(&child_node->header_lock);

			if (hash == child_start_hash || hash == child_end_hash) {
				parent->flags |= SSDFS_BTREE_LEVEL_UPDATE_INDEX;

				/*
				 * Simply add flag.
				 * Maybe it will need to add additional code.
				 */
			}
		}
		break;
	}

	return 0;
}

/*
 * ssdfs_btree_check_hierarchy_for_siblings_merge() - check the btree for nodes merge
 * @tree: btree object
 * @search: search object
 * @hierarchy: btree's hierarchy object
 *
 * This method tries to check the btree's hierarchy for operation of
 * merging sibling child leaf nodes.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_check_hierarchy_for_siblings_merge(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_hierarchy *hierarchy)
{
	struct ssdfs_btree_level *level;
	struct ssdfs_btree_node *parent_node, *child_node;
	int child_node_height, cur_height, tree_height;
	int parent_node_type, child_node_type;
	spinlock_t *lock;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !hierarchy);
	BUG_ON(!rwsem_is_locked(&tree->lock));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);
#else
	SSDFS_DBG("tree %p, search %p, hierarchy %p\n",
		  tree, search, hierarchy);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	tree_height = atomic_read(&tree->height);
	if (tree_height == 0) {
		SSDFS_ERR("invalid tree_height %u\n",
			  tree_height);
		return -ERANGE;
	}

	if (search->node.id == SSDFS_BTREE_ROOT_NODE_ID) {
		SSDFS_ERR("parent node is absent\n");
		return -ERANGE;
	} else {
		child_node = search->node.child;

		lock = &child_node->descriptor_lock;
		spin_lock(lock);
		parent_node = child_node->parent_node;
		spin_unlock(lock);
		lock = NULL;

		if (!child_node || !parent_node) {
			SSDFS_ERR("invalid search object state: "
				  "child_node %p, parent_node %p\n",
				  child_node, parent_node);
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		child_node_type = atomic_read(&child_node->type);
		child_node_height = atomic_read(&child_node->height);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("child_node %px, child_node_id %u, child_node_type %#x\n",
		  child_node, child_node->node_id, child_node_type);
	SSDFS_DBG("parent_node %px, parent_node_id %u, parent_node_type %#x\n",
		  parent_node, parent_node->node_id, parent_node_type);
#endif /* CONFIG_SSDFS_DEBUG */

	cur_height = child_node_height;
	if (cur_height >= tree_height) {
		SSDFS_ERR("cur_height %u >= tree_height %u\n",
			  cur_height, tree_height);
		return -ERANGE;
	}

	if ((cur_height + 1) >= hierarchy->desc.height ||
	    (cur_height + 1) >= tree_height) {
		SSDFS_ERR("invalid hierarchy: "
			  "tree_height %u, cur_height %u, "
			  "hierarchy->desc.height %u\n",
			  tree_height, cur_height,
			  hierarchy->desc.height);
		return -ERANGE;
	}

	level = hierarchy->array_ptr[cur_height];
	level->nodes.old_node.type = child_node_type;
	level->nodes.old_node.ptr = child_node;
	ssdfs_btree_hierarchy_init_hash_range(level, child_node);

	cur_height++;
	level = hierarchy->array_ptr[cur_height];
	level->nodes.old_node.type = parent_node_type;
	level->nodes.old_node.ptr = parent_node;
	ssdfs_btree_hierarchy_init_hash_range(level, parent_node);

	cur_height++;
	lock = &parent_node->descriptor_lock;
	spin_lock(lock);
	parent_node = parent_node->parent_node;
	spin_unlock(lock);
	lock = NULL;
	for (; cur_height < tree_height; cur_height++) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_height %d, tree_height %d, parent_node %px\n",
			  cur_height, tree_height, parent_node);
#endif /* CONFIG_SSDFS_DEBUG */

		if (!parent_node) {
			SSDFS_ERR("parent node is NULL\n");
			return -ERANGE;
		}

		parent_node_type = atomic_read(&parent_node->type);
		level = hierarchy->array_ptr[cur_height];
		level->nodes.old_node.type = parent_node_type;
		level->nodes.old_node.ptr = parent_node;
		ssdfs_btree_hierarchy_init_hash_range(level, parent_node);

		lock = &parent_node->descriptor_lock;
		spin_lock(lock);
		parent_node = parent_node->parent_node;
		spin_unlock(lock);
		lock = NULL;
	}

	cur_height = child_node_height;
	for (; cur_height < tree_height; cur_height++) {
		struct ssdfs_btree_level *parent;
		struct ssdfs_btree_level *child;

		parent = hierarchy->array_ptr[cur_height + 1];
		child = hierarchy->array_ptr[cur_height];

		err = ssdfs_btree_check_level_for_siblings_merge(tree, search,
								 parent, child);
		if (unlikely(err)) {
			SSDFS_ERR("fail to check btree's level: "
				  "cur_height %u, tree_height %u, "
				  "err %d\n",
				  cur_height, tree_height, err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;
}

static
int ssdfs_btree_update_index_after_move(struct ssdfs_btree_level *child,
					struct ssdfs_btree_node *parent_node);

/*
 * ssdfs_btree_move_items_left() - move head items from old to new node
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to move the head items from the old node into
 * new one.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_move_items_left(struct ssdfs_btree_state_descriptor *desc,
				struct ssdfs_btree_level *parent,
				struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node;
	struct ssdfs_btree_node *old_node;
	struct ssdfs_btree_node *new_node;
	int type;
	u32 calculated;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	if (!(child->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE &&
	      child->items_area.move.direction == SSDFS_BTREE_MOVE_TO_LEFT)) {
		SSDFS_WARN("invalid move request: "
			   "flags %#x, direction %#x\n",
			   child->flags,
			   child->items_area.move.direction);
		return -ERANGE;
	}

	SSDFS_DBG("desc %p, child %p\n",
		  desc, child);
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("fail to move items: "
			  "parent_node %p\n",
			  parent_node);
		return -ERANGE;
	}

	type = atomic_read(&parent_node->type);

	switch (type) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected type */
		break;

	default:
		SSDFS_ERR("parent node has improper type: "
			  "node_id %u, type %#x\n",
			  parent_node->node_id, type);
		return -ERANGE;
	}

	if (child->items_area.move.op_state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  child->items_area.move.op_state);
		return -ERANGE;
	} else
		child->items_area.move.op_state = SSDFS_BTREE_AREA_OP_FAILED;

	old_node = child->nodes.old_node.ptr;
	new_node = child->nodes.new_node.ptr;

	if (!old_node || !new_node) {
		SSDFS_ERR("fail to move items: "
			  "old_node %p, new_node %p\n",
			  old_node, new_node);
		return -ERANGE;
	}

	type = atomic_read(&old_node->type);
	switch (type) {
	case SSDFS_BTREE_LEAF_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected type */
		break;

	default:
		SSDFS_ERR("old node is not leaf node: "
			  "node_id %u, type %#x\n",
			  old_node->node_id, type);
		return -ERANGE;
	}

	type = atomic_read(&new_node->type);

	switch (type) {
	case SSDFS_BTREE_LEAF_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected type */
		break;

	default:
		SSDFS_ERR("new node is not leaf node: "
			  "node_id %u, type %#x\n",
			  new_node->node_id, type);
		return -ERANGE;
	}

	switch (child->items_area.move.pos.state) {
	case SSDFS_HASH_RANGE_INTERSECTION:
	case SSDFS_HASH_RANGE_OUT_OF_NODE:
		if (child->items_area.move.pos.start != 0) {
			SSDFS_ERR("invalid position's start %u\n",
				  child->items_area.move.pos.start);
			return -ERANGE;
		}

		if (child->items_area.move.pos.count == 0) {
			SSDFS_ERR("invalid position's count %u\n",
				  child->items_area.move.pos.count);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid position's state %#x\n",
			  child->items_area.move.pos.state);
		return -ERANGE;
	}

	calculated = child->items_area.move.pos.count * desc->min_item_size;
	if (calculated >= desc->node_size) {
		SSDFS_ERR("invalid position: "
			  "count %u, min_item_size %u, node_size %u\n",
			  child->items_area.move.pos.count,
			  desc->min_item_size,
			  desc->node_size);
		return -ERANGE;
	}

	err = ssdfs_btree_node_move_items_range(old_node, new_node,
					child->items_area.move.pos.start,
					child->items_area.move.pos.count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move items range: "
			  "src_node %u, dst_node %u, "
			  "start_item %u, count %u, "
			  "err %d\n",
			  old_node->node_id,
			  new_node->node_id,
			  child->items_area.move.pos.start,
			  child->items_area.move.pos.count,
			  err);
		return err;
	}

	down_read(&old_node->header_lock);
	child->index_area.hash.start = old_node->index_area.start_hash;
	child->index_area.hash.end = old_node->index_area.end_hash;
	child->items_area.hash.start = old_node->items_area.start_hash;
	child->items_area.hash.end = old_node->items_area.end_hash;
	up_read(&old_node->header_lock);

	err = ssdfs_btree_update_index_after_move(child, parent_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update indexes in parent: err %d\n",
			  err);
		return err;
	}

	child->items_area.move.op_state = SSDFS_BTREE_AREA_OP_DONE;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("src_node %u, dst_node %u, "
		  "start_item %u, count %u\n",
		  old_node->node_id,
		  new_node->node_id,
		  child->items_area.move.pos.start,
		  child->items_area.move.pos.count);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_move_items_right() - move tail items from old to new node
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to move the tail items from the old node into
 * new one.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_move_items_right(struct ssdfs_btree_state_descriptor *desc,
				 struct ssdfs_btree_level *parent,
				 struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node;
	struct ssdfs_btree_node *old_node;
	struct ssdfs_btree_node *new_node;
	int type;
	u32 calculated;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	if (!(child->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE &&
	      child->items_area.move.direction == SSDFS_BTREE_MOVE_TO_RIGHT)) {
		SSDFS_WARN("invalid move request: "
			   "flags %#x, direction %#x\n",
			   child->flags,
			   child->items_area.move.direction);
		return -ERANGE;
	}

	SSDFS_DBG("desc %p, child %p\n",
		  desc, child);
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;

	if (!parent_node) {
		SSDFS_ERR("fail to move items: "
			  "parent_node %p\n",
			  parent_node);
		return -ERANGE;
	}

	type = atomic_read(&parent_node->type);
	switch (type) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected type */
		break;

	default:
		SSDFS_ERR("parent node has improper type: "
			  "node_id %u, type %#x\n",
			  parent_node->node_id, type);
		return -ERANGE;
	}

	if (child->items_area.move.op_state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  child->items_area.move.op_state);
		return -ERANGE;
	} else
		child->items_area.move.op_state = SSDFS_BTREE_AREA_OP_FAILED;

	old_node = child->nodes.old_node.ptr;
	new_node = child->nodes.new_node.ptr;

	if (!old_node || !new_node) {
		SSDFS_ERR("fail to move items: "
			  "old_node %p, new_node %p\n",
			  old_node, new_node);
		return -ERANGE;
	}

	type = atomic_read(&old_node->type);
	switch (type) {
	case SSDFS_BTREE_LEAF_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected type */
		break;

	default:
		SSDFS_ERR("old node is not leaf node: "
			  "node_id %u, type %#x\n",
			  old_node->node_id, type);
		return -ERANGE;
	}

	type = atomic_read(&new_node->type);
	switch (type) {
	case SSDFS_BTREE_LEAF_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected type */
		break;

	default:
		SSDFS_ERR("new node is not leaf node: "
			  "node_id %u, type %#x\n",
			  new_node->node_id, type);
		return -ERANGE;
	}

	switch (child->items_area.move.pos.state) {
	case SSDFS_HASH_RANGE_INTERSECTION:
	case SSDFS_HASH_RANGE_OUT_OF_NODE:
		if (child->items_area.move.pos.count == 0) {
			SSDFS_ERR("invalid position's count %u\n",
				  child->items_area.move.pos.count);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid position's state %#x\n",
			  child->items_area.move.pos.state);
		return -ERANGE;
	}

	calculated = child->items_area.move.pos.count * desc->min_item_size;
	if (calculated >= desc->node_size) {
		SSDFS_ERR("invalid position: "
			  "count %u, min_item_size %u, node_size %u\n",
			  child->items_area.move.pos.count,
			  desc->min_item_size,
			  desc->node_size);
		return -ERANGE;
	}

	err = ssdfs_btree_node_move_items_range(old_node, new_node,
					child->items_area.move.pos.start,
					child->items_area.move.pos.count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move items range: "
			  "src_node %u, dst_node %u, "
			  "start_item %u, count %u, "
			  "err %d\n",
			  old_node->node_id,
			  new_node->node_id,
			  child->items_area.move.pos.start,
			  child->items_area.move.pos.count,
			  err);
		return err;
	}

	down_read(&old_node->header_lock);
	child->index_area.hash.start = old_node->index_area.start_hash;
	child->index_area.hash.end = old_node->index_area.end_hash;
	child->items_area.hash.start = old_node->items_area.start_hash;
	child->items_area.hash.end = old_node->items_area.end_hash;
	up_read(&old_node->header_lock);

	err = ssdfs_btree_update_index_after_move(child, parent_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update indexes in parent: err %d\n",
			  err);
		return err;
	}

	child->items_area.move.op_state = SSDFS_BTREE_AREA_OP_DONE;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("src_node %u, dst_node %u, "
		  "start_item %u, count %u\n",
		  old_node->node_id,
		  new_node->node_id,
		  child->items_area.move.pos.start,
		  child->items_area.move.pos.count);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_move_items_parent2child() - move items from parent to child node
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to move items from the parent node into
 * child one.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static int
ssdfs_btree_move_items_parent2child(struct ssdfs_btree_state_descriptor *desc,
				    struct ssdfs_btree_level *parent,
				    struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node;
	struct ssdfs_btree_node *child_node;
	int type;
	u32 calculated;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	if (!(parent->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE &&
	      parent->items_area.move.direction == SSDFS_BTREE_MOVE_TO_CHILD)) {
		SSDFS_WARN("invalid move request: "
			   "flags %#x, direction %#x\n",
			   parent->flags,
			   parent->items_area.move.direction);
		return -ERANGE;
	}

	SSDFS_DBG("desc %p, parent %p, child %p\n",
		  desc, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent->items_area.move.op_state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  parent->items_area.move.op_state);
		return -ERANGE;
	} else
		parent->items_area.move.op_state = SSDFS_BTREE_AREA_OP_FAILED;

	parent_node = parent->nodes.old_node.ptr;

	if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE)
		child_node = child->nodes.new_node.ptr;
	else
		child_node = child->nodes.old_node.ptr;

	if (!parent_node || !child_node) {
		SSDFS_ERR("fail to move items: "
			  "parent_node %p, child_node %p\n",
			  parent_node, child_node);
		return -ERANGE;
	}

	type = atomic_read(&parent_node->type);
	if (type != SSDFS_BTREE_HYBRID_NODE) {
		SSDFS_ERR("parent node has improper type: "
			  "node_id %u, type %#x\n",
			  parent_node->node_id, type);
		return -ERANGE;
	}

	type = atomic_read(&child_node->type);
	switch (type) {
	case SSDFS_BTREE_LEAF_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("child node has improper type: "
			  "node_id %u, type %#x\n",
			  child_node->node_id, type);
		return -ERANGE;
	}

	switch (parent->items_area.move.pos.state) {
	case SSDFS_HASH_RANGE_INTERSECTION:
		if (parent->items_area.move.pos.count == 0) {
			SSDFS_ERR("invalid position's count %u\n",
				  parent->items_area.move.pos.count);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid position's state %#x\n",
			  parent->items_area.move.pos.state);
		return -ERANGE;
	}

	calculated = parent->items_area.move.pos.count * desc->min_item_size;

	if (calculated >= desc->node_size) {
		SSDFS_ERR("invalid position: "
			  "count %u, min_item_size %u, node_size %u\n",
			  parent->items_area.move.pos.count,
			  desc->min_item_size,
			  desc->node_size);
		return -ERANGE;
	}

	if (!(child->flags & SSDFS_BTREE_LEVEL_ADD_NODE) &&
	    calculated > child->items_area.free_space) {
		SSDFS_ERR("child has not enough free space: "
			  "calculated %u, free_space %u\n",
			  calculated,
			  child->items_area.free_space);
		return -ERANGE;
	}

	err = ssdfs_btree_node_move_items_range(parent_node, child_node,
					parent->items_area.move.pos.start,
					parent->items_area.move.pos.count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move items range: "
			  "src_node %u, dst_node %u, "
			  "start_item %u, count %u, "
			  "err %d\n",
			  parent_node->node_id,
			  child_node->node_id,
			  parent->items_area.move.pos.start,
			  parent->items_area.move.pos.count,
			  err);
		return err;
	}

	down_read(&child_node->header_lock);

	switch (atomic_read(&child_node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		child->index_area.area_size = child_node->index_area.area_size;
		calculated = child_node->index_area.index_capacity;
		calculated -= child_node->index_area.index_count;
		calculated *= child_node->index_area.index_size;
		child->index_area.free_space = calculated;
		child->index_area.hash.start =
				child_node->index_area.start_hash;
		child->index_area.hash.end =
				child_node->index_area.end_hash;
		break;

	default:
		/* do nothing */
		break;
	}

	switch (atomic_read(&child_node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		child->items_area.area_size = child_node->items_area.area_size;
		child->items_area.free_space =
					child_node->items_area.free_space;
		child->items_area.hash.start =
				child_node->items_area.start_hash;
		child->items_area.hash.end =
				child_node->items_area.end_hash;
		break;

	default:
		/* do nothing */
		break;
	}

	up_read(&child_node->header_lock);

	down_read(&parent_node->header_lock);

	switch (atomic_read(&parent_node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		parent->index_area.area_size =
			parent_node->index_area.area_size;
		calculated = parent_node->index_area.index_capacity;
		calculated -= parent_node->index_area.index_count;
		calculated *= parent_node->index_area.index_size;
		parent->index_area.free_space = calculated;
		parent->index_area.hash.start =
				parent_node->index_area.start_hash;
		parent->index_area.hash.end =
				parent_node->index_area.end_hash;
		break;

	default:
		/* do nothing */
		break;
	}

	switch (atomic_read(&parent_node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		parent->items_area.area_size =
					parent_node->items_area.area_size;
		parent->items_area.free_space =
					parent_node->items_area.free_space;
		parent->items_area.hash.start =
				parent_node->items_area.start_hash;
		parent->items_area.hash.end =
				parent_node->items_area.end_hash;
		break;

	default:
		/* do nothing */
		break;
	}

	up_read(&parent_node->header_lock);

	parent->items_area.move.op_state = SSDFS_BTREE_AREA_OP_DONE;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("src_node %u, dst_node %u, "
		  "start_item %u, count %u\n",
		  parent_node->node_id,
		  child_node->node_id,
		  parent->items_area.move.pos.start,
		  parent->items_area.move.pos.count);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_move_items_child2parent() - move items from child to parent node
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to move items from the child node into
 * parent one.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static int
ssdfs_btree_move_items_child2parent(struct ssdfs_btree_state_descriptor *desc,
				    struct ssdfs_btree_level *parent,
				    struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node;
	struct ssdfs_btree_node *child_node;
	int type;
	u32 calculated;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	if (!(child->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE &&
	      child->items_area.move.direction == SSDFS_BTREE_MOVE_TO_PARENT)) {
		SSDFS_WARN("invalid move request: "
			   "flags %#x, direction %#x\n",
			   parent->flags,
			   parent->items_area.move.direction);
		return -ERANGE;
	}

	SSDFS_DBG("desc %p, parent %p, child %p\n",
		  desc, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (child->items_area.move.op_state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  parent->items_area.move.op_state);
		return -ERANGE;
	} else
		child->items_area.move.op_state = SSDFS_BTREE_AREA_OP_FAILED;

	if (parent->flags & SSDFS_BTREE_LEVEL_ADD_NODE)
		parent_node = parent->nodes.new_node.ptr;
	else
		parent_node = parent->nodes.old_node.ptr;

	child_node = child->nodes.old_node.ptr;

	if (!parent_node || !child_node) {
		SSDFS_ERR("fail to move items: "
			  "parent_node %p, child_node %p\n",
			  parent_node, child_node);
		return -ERANGE;
	}

	type = atomic_read(&parent_node->type);
	if (type != SSDFS_BTREE_HYBRID_NODE) {
		SSDFS_ERR("parent node has improper type: "
			  "node_id %u, type %#x\n",
			  parent_node->node_id, type);
		return -ERANGE;
	}

	type = atomic_read(&child_node->type);
	switch (type) {
	case SSDFS_BTREE_LEAF_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("child node has improper type: "
			  "node_id %u, type %#x\n",
			  child_node->node_id, type);
		return -ERANGE;
	}

	switch (child->items_area.move.pos.state) {
	case SSDFS_HASH_RANGE_INTERSECTION:
		if (child->items_area.move.pos.count == 0) {
			SSDFS_ERR("invalid position's count %u\n",
				  child->items_area.move.pos.count);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid position's state %#x\n",
			  child->items_area.move.pos.state);
		return -ERANGE;
	}

	calculated = child->items_area.move.pos.count * desc->min_item_size;

	if (calculated >= desc->node_size) {
		SSDFS_ERR("invalid position: "
			  "count %u, min_item_size %u, node_size %u\n",
			  child->items_area.move.pos.count,
			  desc->min_item_size,
			  desc->node_size);
		return -ERANGE;
	}

	if (!(parent->flags & SSDFS_BTREE_LEVEL_ADD_NODE) &&
	    calculated > parent->items_area.free_space) {
		SSDFS_ERR("child has not enough free space: "
			  "calculated %u, free_space %u\n",
			  calculated,
			  parent->items_area.free_space);
		return -ERANGE;
	}

	err = ssdfs_btree_node_move_items_range(child_node, parent_node,
					child->items_area.move.pos.start,
					child->items_area.move.pos.count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move items range: "
			  "src_node %u, dst_node %u, "
			  "start_item %u, count %u, "
			  "err %d\n",
			  child_node->node_id,
			  parent_node->node_id,
			  child->items_area.move.pos.start,
			  child->items_area.move.pos.count,
			  err);
		return err;
	}

	down_read(&child_node->header_lock);

	switch (atomic_read(&child_node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		child->index_area.area_size = child_node->index_area.area_size;
		calculated = child_node->index_area.index_capacity;
		calculated -= child_node->index_area.index_count;
		calculated *= child_node->index_area.index_size;
		child->index_area.free_space = calculated;
		child->index_area.hash.start =
				child_node->index_area.start_hash;
		child->index_area.hash.end =
				child_node->index_area.end_hash;
		break;

	default:
		/* do nothing */
		break;
	}

	switch (atomic_read(&child_node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		child->items_area.area_size = child_node->items_area.area_size;
		child->items_area.free_space =
					child_node->items_area.free_space;
		child->items_area.hash.start =
				child_node->items_area.start_hash;
		child->items_area.hash.end =
				child_node->items_area.end_hash;
		break;

	default:
		/* do nothing */
		break;
	}

	up_read(&child_node->header_lock);

	down_read(&parent_node->header_lock);

	switch (atomic_read(&parent_node->index_area.state)) {
	case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
		parent->index_area.area_size =
			parent_node->index_area.area_size;
		calculated = parent_node->index_area.index_capacity;
		calculated -= parent_node->index_area.index_count;
		calculated *= parent_node->index_area.index_size;
		parent->index_area.free_space = calculated;
		parent->index_area.hash.start =
				parent_node->index_area.start_hash;
		parent->index_area.hash.end =
				parent_node->index_area.end_hash;
		break;

	default:
		/* do nothing */
		break;
	}

	switch (atomic_read(&parent_node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		parent->items_area.area_size =
					parent_node->items_area.area_size;
		parent->items_area.free_space =
					parent_node->items_area.free_space;
		parent->items_area.hash.start =
				parent_node->items_area.start_hash;
		parent->items_area.hash.end =
				parent_node->items_area.end_hash;
		break;

	default:
		/* do nothing */
		break;
	}

	up_read(&parent_node->header_lock);

	child->items_area.move.op_state = SSDFS_BTREE_AREA_OP_DONE;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("src_node %u, dst_node %u, "
		  "start_item %u, count %u\n",
		  child_node->node_id,
		  parent_node->node_id,
		  child->items_area.move.pos.start,
		  child->items_area.move.pos.count);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_move_items() - move items between nodes
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to move items between nodes.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_move_items(struct ssdfs_btree_state_descriptor *desc,
			   struct ssdfs_btree_level *parent,
			   struct ssdfs_btree_level *child)
{
	int op_state;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	SSDFS_DBG("desc %p, parent %p, child %p\n",
		  desc, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (child->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE) {
		switch (child->items_area.move.direction) {
		case SSDFS_BTREE_MOVE_TO_CHILD:
			op_state = child->items_area.move.op_state;
			if (op_state != SSDFS_BTREE_AREA_OP_DONE) {
				SSDFS_ERR("invalid op_state %#x\n",
					  op_state);
				return -ERANGE;
			}
			break;

		case SSDFS_BTREE_MOVE_TO_PARENT:
			err = ssdfs_btree_move_items_child2parent(desc,
								  parent,
								  child);
			if (unlikely(err)) {
				SSDFS_ERR("failed to move items: err %d\n",
					  err);
				return err;
			}
			break;

		case SSDFS_BTREE_MOVE_TO_LEFT:
			err = ssdfs_btree_move_items_left(desc, parent, child);
			if (unlikely(err)) {
				SSDFS_ERR("failed to move items: err %d\n",
					  err);
				return err;
			}
			break;

		case SSDFS_BTREE_MOVE_TO_RIGHT:
			err = ssdfs_btree_move_items_right(desc, parent, child);
			if (unlikely(err)) {
				SSDFS_ERR("failed to move items: err %d\n",
					  err);
				return err;
			}
			break;

		default:
			SSDFS_ERR("invalid move direction %#x\n",
				  child->items_area.move.direction);
			return -ERANGE;
		}
	}

	if (parent->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE) {
		switch (parent->items_area.move.direction) {
		case SSDFS_BTREE_MOVE_TO_CHILD:
			err = ssdfs_btree_move_items_parent2child(desc,
								  parent,
								  child);
			if (unlikely(err)) {
				SSDFS_ERR("failed to move items: err %d\n",
					  err);
				return err;
			}
			break;

		default:
			SSDFS_ERR("invalid move direction %#x\n",
				  parent->items_area.move.direction);
			return -ERANGE;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_move_indexes_to_parent() - move indexes from child to parent node
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to move indexes from the child to the parent node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static int
ssdfs_btree_move_indexes_to_parent(struct ssdfs_btree_state_descriptor *desc,
				   struct ssdfs_btree_level *parent,
				   struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node;
	struct ssdfs_btree_node *child_node;
	int type;
	u16 start, count;
	u32 calculated;
	int state;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	if (!(child->flags & SSDFS_BTREE_INDEX_AREA_NEED_MOVE &&
	      child->index_area.move.direction == SSDFS_BTREE_MOVE_TO_PARENT)) {
		SSDFS_WARN("invalid move request: "
			   "flags %#x, direction %#x\n",
			   child->flags,
			   child->index_area.move.direction);
		return -ERANGE;
	}

	SSDFS_DBG("desc %p, parent %p, child %p\n",
		  desc, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	state = child->index_area.move.op_state;
	if (state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  state);
		return -ERANGE;
	} else
		child->index_area.move.op_state = SSDFS_BTREE_AREA_OP_FAILED;

	parent_node = parent->nodes.old_node.ptr;
	child_node = child->nodes.old_node.ptr;

	if (!parent_node || !child_node) {
		SSDFS_ERR("fail to move items: "
			  "parent_node %p, child_node %p\n",
			  parent_node, child_node);
		return -ERANGE;
	}

	type = atomic_read(&parent_node->type);
	switch (type) {
	case SSDFS_BTREE_INDEX_NODE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("parent node has improper type: "
			  "node_id %u, type %#x\n",
			  parent_node->node_id, type);
		return -ERANGE;
	}

	type = atomic_read(&child_node->type);
	switch (type) {
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("child node has improper type: "
			  "node_id %u, type %#x\n",
			  child_node->node_id, type);
		return -ERANGE;
	}

	start = child->index_area.move.pos.start;
	count = child->index_area.move.pos.count;

	switch (child->index_area.move.pos.state) {
	case SSDFS_HASH_RANGE_INTERSECTION:
		if (count == 0) {
			SSDFS_ERR("invalid position's count %u\n",
				  count);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid position's state %#x\n",
			  parent->index_area.move.pos.state);
		return -ERANGE;
	}

	calculated = (start + count) * desc->index_size;
	if (calculated >= desc->node_size) {
		SSDFS_ERR("invalid position: "
			  "start %u, count %u, "
			  "index_size %u, node_size %u\n",
			  child->index_area.move.pos.start,
			  child->index_area.move.pos.count,
			  desc->index_size,
			  desc->node_size);
		return -ERANGE;
	}

	calculated = count * desc->index_size;
	if (calculated > parent->index_area.free_space) {
		SSDFS_ERR("child has not enough free space: "
			  "calculated %u, free_space %u\n",
			  calculated,
			  parent->index_area.free_space);
		return -ERANGE;
	}

	state = parent->index_area.insert.op_state;
	if (state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  state);
		return -ERANGE;
	} else
		parent->index_area.insert.op_state = SSDFS_BTREE_AREA_OP_FAILED;

	switch (parent->index_area.insert.pos.state) {
	case SSDFS_HASH_RANGE_RIGHT_ADJACENT:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid position's state %#x\n",
			  parent->index_area.insert.pos.state);
		return -ERANGE;
	}

	if (count != parent->index_area.insert.pos.count) {
		SSDFS_ERR("inconsistent state: "
			  "child->index_area.move.pos.count %u, "
			  "parent->index_area.insert.pos.count %u\n",
			  child->index_area.move.pos.count,
			  parent->index_area.insert.pos.count);
		return -ERANGE;
	}

	err = ssdfs_btree_node_move_index_range(child_node,
					child->index_area.move.pos.start,
					parent_node,
					parent->index_area.insert.pos.start,
					parent->index_area.insert.pos.count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move index range: "
			  "src_node %u, dst_node %u, "
			  "src_start %u, dst_start %u, count %u, "
			  "err %d\n",
			  child_node->node_id,
			  parent_node->node_id,
			  child->index_area.move.pos.start,
			  parent->index_area.insert.pos.start,
			  parent->index_area.insert.pos.count,
			  err);
		return err;
	}

	down_read(&parent_node->header_lock);
	parent->index_area.hash.start = parent_node->index_area.start_hash;
	parent->index_area.hash.end = parent_node->index_area.end_hash;
	parent->items_area.hash.start = parent_node->items_area.start_hash;
	parent->items_area.hash.end = parent_node->items_area.end_hash;
	up_read(&parent_node->header_lock);

	down_read(&child_node->header_lock);
	child->index_area.hash.start = child_node->index_area.start_hash;
	child->index_area.hash.end = child_node->index_area.end_hash;
	child->items_area.hash.start = child_node->items_area.start_hash;
	child->items_area.hash.end = child_node->items_area.end_hash;
	up_read(&child_node->header_lock);

	parent->index_area.insert.op_state = SSDFS_BTREE_AREA_OP_DONE;
	child->index_area.move.op_state = SSDFS_BTREE_AREA_OP_DONE;

	return 0;
}

/*
 * ssdfs_btree_move_indexes_to_child() - move indexes from parent to child node
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to move indexes from the parent to the child node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_move_indexes_to_child(struct ssdfs_btree_state_descriptor *desc,
				      struct ssdfs_btree_level *parent,
				      struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node;
	struct ssdfs_btree_node *child_node;
	int type;
	u16 start, count;
	u32 calculated;
	int state;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	if (!(parent->flags & SSDFS_BTREE_INDEX_AREA_NEED_MOVE &&
	      parent->index_area.move.direction == SSDFS_BTREE_MOVE_TO_CHILD)) {
		SSDFS_WARN("invalid move request: "
			   "flags %#x, direction %#x\n",
			   parent->flags,
			   parent->index_area.move.direction);
		return -ERANGE;
	}

	SSDFS_DBG("desc %p, parent %p, child %p\n",
		  desc, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	state = parent->index_area.move.op_state;
	if (state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  state);
		return -ERANGE;
	} else
		parent->index_area.move.op_state = SSDFS_BTREE_AREA_OP_FAILED;

	if (parent->nodes.new_node.type == SSDFS_BTREE_ROOT_NODE)
		parent_node = parent->nodes.new_node.ptr;
	else
		parent_node = parent->nodes.old_node.ptr;

	if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE)
		child_node = child->nodes.new_node.ptr;
	else
		child_node = child->nodes.old_node.ptr;

	if (!parent_node || !child_node) {
		SSDFS_ERR("fail to move items: "
			  "parent_node %p, child_node %p\n",
			  parent_node, child_node);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("parent node %u, child node %u\n",
		  parent_node->node_id,
		  child_node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	type = atomic_read(&parent_node->type);
	switch (type) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("parent node has improper type: "
			  "node_id %u, type %#x\n",
			  parent_node->node_id, type);
		return -ERANGE;
	}

	type = atomic_read(&child_node->type);
	switch (type) {
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_INDEX_NODE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("child node has improper type: "
			  "node_id %u, type %#x\n",
			  child_node->node_id, type);
		return -ERANGE;
	}

	start = parent->index_area.move.pos.start;
	count = parent->index_area.move.pos.count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start %u, count %u, state %#x\n",
		  parent->index_area.move.pos.start,
		  parent->index_area.move.pos.count,
		  parent->index_area.move.pos.state);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (parent->index_area.move.pos.state) {
	case SSDFS_HASH_RANGE_INTERSECTION:
		if (count == 0) {
			SSDFS_ERR("invalid position's count %u\n",
				  count);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid position's state %#x\n",
			  parent->index_area.move.pos.state);
		return -ERANGE;
	}

	calculated = (start + count) * desc->index_size;
	if (calculated >= desc->node_size) {
		SSDFS_ERR("invalid position: "
			  "start %u, count %u, "
			  "index_size %u, node_size %u\n",
			  parent->index_area.move.pos.start,
			  parent->index_area.move.pos.count,
			  desc->index_size,
			  desc->node_size);
		return -ERANGE;
	}

	calculated = count * desc->index_size;
	if (calculated > child->index_area.free_space) {
		SSDFS_ERR("child has not enough free space: "
			  "calculated %u, free_space %u\n",
			  calculated,
			  child->index_area.free_space);
		return -ERANGE;
	}

	state = child->index_area.insert.op_state;
	if (state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  state);
		return -ERANGE;
	} else
		child->index_area.insert.op_state = SSDFS_BTREE_AREA_OP_FAILED;

	switch (child->index_area.insert.pos.state) {
	case SSDFS_HASH_RANGE_LEFT_ADJACENT:
	case SSDFS_HASH_RANGE_INTERSECTION:
	case SSDFS_HASH_RANGE_RIGHT_ADJACENT:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid position's state %#x\n",
			  child->index_area.insert.pos.state);
		return -ERANGE;
	}

	if (count != child->index_area.insert.pos.count) {
		SSDFS_ERR("inconsistent state: "
			  "parent->index_area.move.pos.count %u, "
			  "child->index_area.insert.pos.count %u\n",
			  parent->index_area.move.pos.count,
			  child->index_area.insert.pos.count);
		return -ERANGE;
	}

	err = ssdfs_btree_node_move_index_range(parent_node,
					parent->index_area.move.pos.start,
					child_node,
					child->index_area.insert.pos.start,
					child->index_area.insert.pos.count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move index range: "
			  "src_node %u, dst_node %u, "
			  "src_start %u, dst_start %u, count %u, "
			  "err %d\n",
			  parent_node->node_id,
			  child_node->node_id,
			  parent->index_area.move.pos.start,
			  child->index_area.insert.pos.start,
			  child->index_area.insert.pos.count,
			  err);
		SSDFS_ERR("child_node %u\n", child_node->node_id);
		ssdfs_debug_show_btree_node_indexes(child_node->tree,
						    child_node);
		SSDFS_ERR("parent_node %u\n", parent_node->node_id);
		ssdfs_debug_show_btree_node_indexes(parent_node->tree,
						    parent_node);
		return err;
	}

	down_read(&parent_node->header_lock);
	parent->index_area.hash.start = parent_node->index_area.start_hash;
	parent->index_area.hash.end = parent_node->index_area.end_hash;
	parent->items_area.hash.start = parent_node->items_area.start_hash;
	parent->items_area.hash.end = parent_node->items_area.end_hash;
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("parent node: "
		  "index_area (start_hash %#llx, end_hash %#llx), "
		  "items_area (start_hash %#llx, end_hash %#llx)\n",
		  parent_node->index_area.start_hash,
		  parent_node->index_area.end_hash,
		  parent_node->items_area.start_hash,
		  parent_node->items_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */
	up_read(&parent_node->header_lock);

	down_read(&child_node->header_lock);
	child->index_area.hash.start = child_node->index_area.start_hash;
	child->index_area.hash.end = child_node->index_area.end_hash;
	child->items_area.hash.start = child_node->items_area.start_hash;
	child->items_area.hash.end = child_node->items_area.end_hash;
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("child node: "
		  "index_area (start_hash %#llx, end_hash %#llx), "
		  "items_area (start_hash %#llx, end_hash %#llx)\n",
		  child_node->index_area.start_hash,
		  child_node->index_area.end_hash,
		  child_node->items_area.start_hash,
		  child_node->items_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */
	up_read(&child_node->header_lock);

	parent->index_area.move.op_state = SSDFS_BTREE_AREA_OP_DONE;
	child->index_area.insert.op_state = SSDFS_BTREE_AREA_OP_DONE;

	return 0;
}

/*
 * ssdfs_btree_move_indexes_right() - move indexes from old to new node
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to move indexes from the old to new node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_move_indexes_right(struct ssdfs_btree_state_descriptor *desc,
				   struct ssdfs_btree_level *parent,
				   struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node;
	struct ssdfs_btree_node *old_node;
	struct ssdfs_btree_node *new_node;
	int type;
	u16 start, count;
	u32 calculated;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	if (!(child->flags & SSDFS_BTREE_INDEX_AREA_NEED_MOVE &&
	      child->index_area.move.direction == SSDFS_BTREE_MOVE_TO_RIGHT)) {
		SSDFS_WARN("invalid move request: "
			   "flags %#x, direction %#x\n",
			   child->flags,
			   child->index_area.move.direction);
		return -ERANGE;
	}

	SSDFS_DBG("desc %p, parent %p, child %p\n",
		  desc, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	parent_node = parent->nodes.old_node.ptr;
	if (!parent_node) {
		SSDFS_ERR("fail to move indexes: "
			  "parent_node %p\n",
			  parent_node);
		return -ERANGE;
	}

	type = atomic_read(&parent_node->type);

	switch (type) {
	case SSDFS_BTREE_ROOT_NODE:
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected type */
		break;

	default:
		SSDFS_ERR("parent node has improper type: "
			  "node_id %u, type %#x\n",
			  parent_node->node_id, type);
		return -ERANGE;
	}

	if (child->index_area.move.op_state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  child->index_area.move.op_state);
		return -ERANGE;
	} else
		child->index_area.move.op_state = SSDFS_BTREE_AREA_OP_FAILED;

	old_node = child->nodes.old_node.ptr;
	new_node = child->nodes.new_node.ptr;

	if (!old_node || !new_node) {
		SSDFS_ERR("fail to move indexes: "
			  "old_node %p, new_node %p\n",
			  old_node, new_node);
		return -ERANGE;
	}

	type = atomic_read(&old_node->type);
	switch (type) {
	case SSDFS_BTREE_INDEX_NODE:
		/* expected type */
		break;

	default:
		SSDFS_ERR("old node is not index node: "
			  "node_id %u, type %#x\n",
			  old_node->node_id, type);
		return -ERANGE;
	}

	type = atomic_read(&new_node->type);
	switch (type) {
	case SSDFS_BTREE_INDEX_NODE:
		/* expected type */
		break;

	default:
		SSDFS_ERR("new node is not index node: "
			  "node_id %u, type %#x\n",
			  new_node->node_id, type);
		return -ERANGE;
	}

	switch (child->index_area.move.pos.state) {
	case SSDFS_HASH_RANGE_INTERSECTION:
	case SSDFS_HASH_RANGE_OUT_OF_NODE:
		if (child->index_area.move.pos.count == 0) {
			SSDFS_ERR("invalid position's count %u\n",
				  child->index_area.move.pos.count);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("invalid position's state %#x\n",
			  child->index_area.move.pos.state);
		return -ERANGE;
	}

	start = child->index_area.move.pos.start;
	count = child->index_area.move.pos.count;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start %u, count %u, state %#x\n",
		  child->index_area.move.pos.start,
		  child->index_area.move.pos.count,
		  child->index_area.move.pos.state);
#endif /* CONFIG_SSDFS_DEBUG */

	calculated = (start + count) * desc->index_size;
	if (calculated >= desc->node_size) {
		SSDFS_ERR("invalid position: "
			  "start %u, count %u, "
			  "index_size %u, node_size %u\n",
			  child->index_area.move.pos.start,
			  child->index_area.move.pos.count,
			  desc->index_size,
			  desc->node_size);
		return -ERANGE;
	}

	err = ssdfs_btree_node_move_index_range(old_node,
					child->index_area.move.pos.start,
					new_node,
					0,
					child->index_area.move.pos.count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move index range: "
			  "src_node %u, dst_node %u, "
			  "src_start %u, dst_start %u, count %u, "
			  "err %d\n",
			  old_node->node_id,
			  new_node->node_id,
			  child->index_area.move.pos.start,
			  0,
			  child->index_area.move.pos.count,
			  err);
		goto fail_move_indexes_right;
	}

	err = ssdfs_btree_update_index_after_move(child, parent_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update indexes in parent: err %d\n",
			  err);
		goto fail_move_indexes_right;
	}

	err = ssdfs_btree_update_parent_node_pointer(old_node->tree, old_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update parent pointer: "
			  "node_id %u, err %d\n",
			  old_node->node_id, err);
		goto fail_move_indexes_right;
	}

	err = ssdfs_btree_update_parent_node_pointer(new_node->tree, new_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update parent pointer: "
			  "node_id %u, err %d\n",
			  new_node->node_id, err);
		goto fail_move_indexes_right;
	}

	child->index_area.move.op_state = SSDFS_BTREE_AREA_OP_DONE;
	return 0;

fail_move_indexes_right:
	SSDFS_ERR("old_node %u\n", old_node->node_id);
	ssdfs_debug_show_btree_node_indexes(old_node->tree, old_node);

	SSDFS_ERR("new_node %u\n", new_node->node_id);
	ssdfs_debug_show_btree_node_indexes(new_node->tree, new_node);

	SSDFS_ERR("parent_node %u\n", parent_node->node_id);
	ssdfs_debug_show_btree_node_indexes(parent_node->tree, parent_node);

	return err;
}

/*
 * ssdfs_btree_move_indexes() - move indexes between parent and child nodes
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to move indexes between parent and child nodes.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_move_indexes(struct ssdfs_btree_state_descriptor *desc,
			     struct ssdfs_btree_level *parent,
			     struct ssdfs_btree_level *child)
{
	int op_state;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	SSDFS_DBG("desc %p, parent %p, child %p\n",
		  desc, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (parent->flags & SSDFS_BTREE_INDEX_AREA_NEED_MOVE) {
		switch (parent->index_area.move.direction) {
		case SSDFS_BTREE_MOVE_TO_PARENT:
			/* do nothing */
			break;

		case SSDFS_BTREE_MOVE_TO_CHILD:
			err = ssdfs_btree_move_indexes_to_child(desc,
								parent,
								child);
			if (unlikely(err)) {
				SSDFS_ERR("failed to move indexes: err %d\n",
					  err);
				return err;
			}
			break;

		case SSDFS_BTREE_MOVE_TO_RIGHT:
			/* do nothing */
			break;

		default:
			SSDFS_ERR("invalid move direction %#x\n",
				  parent->index_area.move.direction);
			return -ERANGE;
		}
	}

	if (child->flags & SSDFS_BTREE_INDEX_AREA_NEED_MOVE) {
		switch (child->index_area.move.direction) {
		case SSDFS_BTREE_MOVE_TO_PARENT:
			err = ssdfs_btree_move_indexes_to_parent(desc,
								 parent,
								 child);
			if (unlikely(err)) {
				SSDFS_ERR("failed to move indexes: err %d\n",
					  err);
				return err;
			}
			break;

		case SSDFS_BTREE_MOVE_TO_CHILD:
			op_state = child->index_area.move.op_state;
			if (op_state != SSDFS_BTREE_AREA_OP_DONE) {
				SSDFS_ERR("invalid op_state %#x\n",
					  op_state);
				return -ERANGE;
			}
			break;

		case SSDFS_BTREE_MOVE_TO_RIGHT:
			err = ssdfs_btree_move_indexes_right(desc,
							     parent,
							     child);
			if (unlikely(err)) {
				SSDFS_ERR("failed to move indexes: err %d\n",
					  err);
				return err;
			}
			break;

		default:
			SSDFS_ERR("invalid move direction %#x\n",
				  child->index_area.move.direction);
			return -ERANGE;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_resize_index_area() - resize index area of the node
 * @desc: btree state descriptor
 * @child: child level descriptor
 *
 * This method tries to resize the index area of the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - unable to resize the index area.
 */
static
int ssdfs_btree_resize_index_area(struct ssdfs_btree_state_descriptor *desc,
				  struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *node;
	u32 index_area_size, index_free_area;
	u32 items_area_size, items_free_area;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !child);

	SSDFS_DBG("desc %p, child %p\n",
		  desc, child);
#endif /* CONFIG_SSDFS_DEBUG */

	node = child->nodes.old_node.ptr;

	if (!node) {
		SSDFS_ERR("node is NULL\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(child->flags & SSDFS_BTREE_TRY_RESIZE_INDEX_AREA)) {
		SSDFS_WARN("resize hasn't been requested\n");
		return 0;
	}

	if (child->index_area.free_space >= desc->node_size) {
		SSDFS_ERR("invalid index area's free space: "
			  "free_space %u, node_size %u\n",
			  child->index_area.free_space,
			  desc->node_size);
		return -ERANGE;
	}

	if (child->items_area.free_space >= desc->node_size) {
		SSDFS_ERR("invalid items area's free space: "
			  "free_space %u, node_size %u\n",
			  child->items_area.free_space,
			  desc->node_size);
		return -ERANGE;
	}

	if (child->index_area.free_space % desc->index_size) {
		SSDFS_ERR("invalid index area's free space: "
			  "free_space %u, index_size %u\n",
			  child->index_area.free_space,
			  desc->index_size);
		return -ERANGE;
	}

	if (desc->index_size >= desc->index_area_min_size) {
		SSDFS_ERR("corrupted descriptor: "
			  "index_size %u, index_area_min_size %u\n",
			  desc->index_size,
			  desc->index_area_min_size);
		return -ERANGE;
	}

	if (desc->index_area_min_size % desc->index_size) {
		SSDFS_ERR("corrupted descriptor: "
			  "index_size %u, index_area_min_size %u\n",
			  desc->index_size,
			  desc->index_area_min_size);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("INITIAL_STATE: "
		  "items_area: area_size %u, free_space %u; "
		  "index_area: area_size %u, free_space %u\n",
		  child->items_area.area_size,
		  child->items_area.free_space,
		  child->index_area.area_size,
		  child->index_area.free_space);
#endif /* CONFIG_SSDFS_DEBUG */

	index_area_size = child->index_area.area_size << 1;
	index_free_area = index_area_size - child->index_area.area_size;

	if (index_area_size > desc->node_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to resize the index area: "
			  "requested_size %u, node_size %u\n",
			  index_free_area, desc->node_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOSPC;
	} else if (index_area_size == desc->node_size) {
		index_area_size = desc->node_size;
		index_free_area = child->index_area.free_space;
		index_free_area += child->items_area.free_space;

		items_area_size = 0;
		items_free_area = 0;
	} else if (child->items_area.free_space < index_free_area) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to resize the index area: "
			  "free_space %u, requested_size %u\n",
			  child->items_area.free_space,
			  index_free_area);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOSPC;
	} else {
		items_area_size = child->items_area.area_size;
		items_area_size -= index_free_area;
		items_free_area = child->items_area.free_space;
		items_free_area -= index_free_area;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("NEW_STATE: "
		  "items_area: area_size %u, free_space %u; "
		  "index_area: area_size %u, free_space %u\n",
		  items_area_size, items_free_area,
		  index_area_size, index_free_area);

	BUG_ON(index_area_size == 0);
	BUG_ON(index_area_size > desc->node_size);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_node_resize_index_area(node, index_area_size);
	if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to resize the index area: "
			  "node_id %u, new_size %u\n",
			  node->node_id, index_area_size);
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to resize the index area: "
			  "node_id %u, new_size %u\n",
			  node->node_id, index_area_size);
	} else {
		child->index_area.area_size = index_area_size;
		child->index_area.free_space = index_free_area;
		child->items_area.area_size = items_area_size;
		child->items_area.free_space = items_free_area;
	}

	return err;
}

/*
 * ssdfs_btree_prepare_add_item() - prepare to add an item into the node
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to prepare the node for adding an item.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_prepare_add_item(struct ssdfs_btree_level *parent,
				 struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node_insert *add;
	struct ssdfs_btree_node *node = NULL;
	struct ssdfs_btree_node *left_node = NULL, *right_node = NULL;
	u64 start_hash, end_hash;
	u16 count;
	u8 min_item_size;
	u32 free_space;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!parent || !child);

	SSDFS_DBG("parent %p, child %p\n",
		  parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(child->flags & SSDFS_BTREE_LEVEL_ADD_ITEM)) {
		SSDFS_WARN("add item hasn't been requested\n");
		return 0;
	}

	add = &child->items_area.add;

	if (add->op_state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  add->op_state);
		return -ERANGE;
	} else
		add->op_state = SSDFS_BTREE_AREA_OP_FAILED;

	switch (add->pos.state) {
	case SSDFS_HASH_RANGE_OUT_OF_NODE:
		node = child->nodes.old_node.ptr;

		if (!node) {
			SSDFS_ERR("node %p\n", node);
			return -ERANGE;
		}

		start_hash = child->items_area.add.hash.start;
		end_hash = child->items_area.add.hash.end;
		count = child->items_area.add.pos.count;

		down_write(&node->header_lock);

		if (node->items_area.items_count == 0) {
			node->items_area.start_hash = start_hash;
			node->items_area.end_hash = end_hash;
		}

		free_space = node->items_area.free_space;
		min_item_size = node->items_area.min_item_size;

		if (((u32)count * min_item_size) > free_space) {
			err = -ERANGE;
			SSDFS_ERR("free_space %u is too small\n",
				  free_space);
		}

		up_write(&node->header_lock);
		break;

	case SSDFS_HASH_RANGE_LEFT_ADJACENT:
		left_node = child->nodes.new_node.ptr;
		right_node = child->nodes.old_node.ptr;

		if (!left_node || !right_node) {
			SSDFS_ERR("left_node %p, right_node %p\n",
				  left_node, right_node);
			return -ERANGE;
		}

		start_hash = child->items_area.add.hash.start;
		end_hash = child->items_area.add.hash.end;
		count = child->items_area.add.pos.count;

		down_write(&left_node->header_lock);

		if (left_node->items_area.items_count == 0) {
			left_node->items_area.start_hash = start_hash;
			left_node->items_area.end_hash = end_hash;
		}

		free_space = left_node->items_area.free_space;
		min_item_size = left_node->items_area.min_item_size;

		if (((u32)count * min_item_size) > free_space) {
			err = -ERANGE;
			SSDFS_ERR("free_space %u is too small\n",
				  free_space);
			goto finish_left_adjacent_check;
		}

finish_left_adjacent_check:
		up_write(&left_node->header_lock);
		break;

	case SSDFS_HASH_RANGE_INTERSECTION:
		left_node = child->nodes.old_node.ptr;
		right_node = child->nodes.new_node.ptr;

		if (!left_node) {
			SSDFS_ERR("left_node %p, right_node %p\n",
				  left_node, right_node);
			return -ERANGE;
		}

		count = child->items_area.add.pos.count;

		down_write(&left_node->header_lock);

		free_space = left_node->items_area.free_space;
		min_item_size = left_node->items_area.min_item_size;

		if (((u32)count * min_item_size) > free_space) {
			err = -ERANGE;
			SSDFS_ERR("free_space %u is too small\n",
				  free_space);
			goto finish_intersection_check;
		}

finish_intersection_check:
		up_write(&left_node->header_lock);
		break;

	case SSDFS_HASH_RANGE_RIGHT_ADJACENT:
		left_node = child->nodes.old_node.ptr;
		right_node = child->nodes.new_node.ptr;

		if (!left_node || !right_node) {
			SSDFS_ERR("left_node %p, right_node %p\n",
				  left_node, right_node);
			return -ERANGE;
		}

		start_hash = child->items_area.add.hash.start;
		end_hash = child->items_area.add.hash.end;
		count = child->items_area.add.pos.count;

		down_write(&right_node->header_lock);

		if (right_node->items_area.items_count == 0) {
			right_node->items_area.start_hash = start_hash;
			right_node->items_area.end_hash = end_hash;
		}

		free_space = right_node->items_area.free_space;
		min_item_size = right_node->items_area.min_item_size;

		if (((u32)count * min_item_size) > free_space) {
			err = -ERANGE;
			SSDFS_ERR("free_space %u is too small\n",
				  free_space);
			goto finish_right_adjacent_check;
		}

finish_right_adjacent_check:
		up_write(&right_node->header_lock);
		break;

	default:
		SSDFS_ERR("invalid position's state %#x\n",
			  add->pos.state);
		return -ERANGE;
	}

	if (!err)
		add->op_state = SSDFS_BTREE_AREA_OP_DONE;

	return err;
}

/*
 * __ssdfs_btree_update_index() - update index in the parent node
 * @parent_node: parent node
 * @child_node: child node
 *
 * This method tries to update an index into the parent node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENODATA    - child node is empty.
 */
static
int __ssdfs_btree_update_index(struct ssdfs_btree_node *parent_node,
				struct ssdfs_btree_node *child_node)
{
	struct ssdfs_btree_index_key old_key, new_key;
	int parent_type, child_type;
	u64 start_hash = U64_MAX;
	u64 old_hash = U64_MAX;
	u16 items_count = 0;
	u16 index_count = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!parent_node || !child_node);

	SSDFS_DBG("parent_node %p, child_node %p\n",
		  parent_node, child_node);
#endif /* CONFIG_SSDFS_DEBUG */

	parent_type = atomic_read(&parent_node->type);
	child_type = atomic_read(&child_node->type);

	switch (parent_type) {
	case SSDFS_BTREE_ROOT_NODE:
		switch (child_type) {
		case SSDFS_BTREE_LEAF_NODE:
			down_read(&child_node->header_lock);
			start_hash = child_node->items_area.start_hash;
			items_count = child_node->items_area.items_count;
			up_read(&child_node->header_lock);
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			down_read(&child_node->header_lock);
			start_hash = child_node->index_area.start_hash;
			items_count = child_node->items_area.items_count;
			index_count = child_node->index_area.index_count;
			up_read(&child_node->header_lock);
			break;

		case SSDFS_BTREE_INDEX_NODE:
			down_read(&child_node->header_lock);
			start_hash = child_node->index_area.start_hash;
			index_count = child_node->index_area.index_count;
			up_read(&child_node->header_lock);
			break;

		default:
			SSDFS_ERR("unexpected child type %#x\n",
				  child_type);
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		switch (child_type) {
		case SSDFS_BTREE_LEAF_NODE:
			down_read(&child_node->header_lock);
			start_hash = child_node->items_area.start_hash;
			items_count = child_node->items_area.items_count;
			up_read(&child_node->header_lock);
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			if (parent_node == child_node) {
				down_read(&child_node->header_lock);
				start_hash = child_node->items_area.start_hash;
				items_count = child_node->items_area.items_count;
				index_count = child_node->index_area.index_count;
				up_read(&child_node->header_lock);
			} else {
				down_read(&child_node->header_lock);
				start_hash = child_node->index_area.start_hash;
				items_count = child_node->items_area.items_count;
				index_count = child_node->index_area.index_count;
				up_read(&child_node->header_lock);
			}
			break;

		case SSDFS_BTREE_INDEX_NODE:
			down_read(&child_node->header_lock);
			start_hash = child_node->index_area.start_hash;
			index_count = child_node->index_area.index_count;
			up_read(&child_node->header_lock);
			break;

		default:
			SSDFS_ERR("unexpected child type %#x\n",
				  child_type);
			return -ERANGE;
		}

		break;

	case SSDFS_BTREE_INDEX_NODE:
		switch (child_type) {
		case SSDFS_BTREE_LEAF_NODE:
			down_read(&child_node->header_lock);
			start_hash = child_node->items_area.start_hash;
			items_count = child_node->items_area.items_count;
			up_read(&child_node->header_lock);
			break;

		case SSDFS_BTREE_HYBRID_NODE:
			down_read(&child_node->header_lock);
			start_hash = child_node->index_area.start_hash;
			items_count = child_node->items_area.items_count;
			index_count = child_node->index_area.index_count;
			up_read(&child_node->header_lock);
			break;

		case SSDFS_BTREE_INDEX_NODE:
			down_read(&child_node->header_lock);
			start_hash = child_node->index_area.start_hash;
			index_count = child_node->index_area.index_count;
			up_read(&child_node->header_lock);
			break;

		default:
			SSDFS_ERR("unexpected child type %#x\n",
				  child_type);
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("unexpected parent type %#x\n",
			  parent_type);
		return -ERANGE;
	}

	if (items_count == 0 && index_count == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("child node %u is empty\n",
			  child_node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	if (parent_type == SSDFS_BTREE_HYBRID_NODE &&
	    child_type == SSDFS_BTREE_HYBRID_NODE &&
	    parent_node == child_node) {
		down_read(&parent_node->header_lock);
		old_hash = parent_node->items_area.start_hash;
		up_read(&parent_node->header_lock);
	}

	spin_lock(&child_node->descriptor_lock);

	ssdfs_memcpy(&old_key,
		     0, sizeof(struct ssdfs_btree_index_key),
		     &child_node->node_index,
		     0, sizeof(struct ssdfs_btree_index_key),
		     sizeof(struct ssdfs_btree_index_key));

	if (parent_type == SSDFS_BTREE_HYBRID_NODE &&
	    child_type == SSDFS_BTREE_HYBRID_NODE &&
	    parent_node == child_node) {
		if (old_hash == U64_MAX) {
			err = -ERANGE;
			SSDFS_WARN("invalid old hash\n");
			goto finish_update_index;
		}

		old_key.index.hash = cpu_to_le64(old_hash);
	}

	ssdfs_memcpy(&child_node->node_index.index.extent,
		     0, sizeof(struct ssdfs_raw_extent),
		     &child_node->extent,
		     0, sizeof(struct ssdfs_raw_extent),
		     sizeof(struct ssdfs_raw_extent));
	ssdfs_memcpy(&new_key,
		     0, sizeof(struct ssdfs_btree_index_key),
		     &child_node->node_index,
		     0, sizeof(struct ssdfs_btree_index_key),
		     sizeof(struct ssdfs_btree_index_key));
	new_key.index.hash = cpu_to_le64(start_hash);
	ssdfs_memcpy(&child_node->node_index,
		     0, sizeof(struct ssdfs_btree_index_key),
		     &new_key,
		     0, sizeof(struct ssdfs_btree_index_key),
		     sizeof(struct ssdfs_btree_index_key));

finish_update_index:
	spin_unlock(&child_node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, node_type %#x, "
		  "node_height %u, hash %llx\n",
		  le32_to_cpu(new_key.node_id),
		  new_key.node_type,
		  new_key.height,
		  le64_to_cpu(new_key.index.hash));
	SSDFS_DBG("seg_id %llu, logical_blk %u, len %u\n",
		  le64_to_cpu(new_key.index.extent.seg_id),
		  le32_to_cpu(new_key.index.extent.logical_blk),
		  le32_to_cpu(new_key.index.extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err))
		return err;

	err = ssdfs_btree_node_change_index(parent_node,
					    &old_key, &new_key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update index: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_btree_update_index() - update the index in the parent node
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to update the index into the parent node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_update_index(struct ssdfs_btree_state_descriptor *desc,
			     struct ssdfs_btree_level *parent,
			     struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node = NULL, *child_node = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	SSDFS_DBG("desc %p, parent %p, child %p\n",
		  desc, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(parent->flags & SSDFS_BTREE_LEVEL_UPDATE_INDEX)) {
		SSDFS_WARN("update index hasn't been requested\n");
		return 0;
	}

	if (parent->flags & SSDFS_BTREE_LEVEL_ADD_NODE)
		parent_node = parent->nodes.new_node.ptr;
	else if (parent->nodes.old_node.ptr)
		parent_node = parent->nodes.old_node.ptr;
	else
		parent_node = parent->nodes.new_node.ptr;

	if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE)
		child_node = child->nodes.new_node.ptr;
	else
		child_node = child->nodes.old_node.ptr;

	if (!parent_node || !child_node) {
		SSDFS_ERR("invalid pointer: "
			  "parent_node %p, child_node %p\n",
			  parent_node, child_node);
		return -ERANGE;
	}

	err = __ssdfs_btree_update_index(parent_node, child_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update index: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * __ssdfs_btree_add_index() - add index in the parent node
 * @parent_node: parent node
 * @child_node: child node
 *
 * This method tries to add an index into the parent node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_btree_add_index(struct ssdfs_btree_node *parent_node,
			    struct ssdfs_btree_node *child_node)
{
	struct ssdfs_btree_index_key key;
	int type;
	u64 start_hash = U64_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!parent_node || !child_node);

	SSDFS_DBG("parent_node %p, child_node %p\n",
		  parent_node, child_node);
#endif /* CONFIG_SSDFS_DEBUG */

	type = atomic_read(&child_node->type);

	switch (type) {
	case SSDFS_BTREE_LEAF_NODE:
		down_read(&child_node->header_lock);
		start_hash = child_node->items_area.start_hash;
		up_read(&child_node->header_lock);
		break;

	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_INDEX_NODE:
		down_read(&child_node->header_lock);
		start_hash = child_node->index_area.start_hash;
		up_read(&child_node->header_lock);
		break;
	}

	spin_lock(&child_node->descriptor_lock);
	if (start_hash != U64_MAX) {
		child_node->node_index.index.hash =
				    cpu_to_le64(start_hash);
	}
	ssdfs_memcpy(&child_node->node_index.index.extent,
		     0, sizeof(struct ssdfs_raw_extent),
		     &child_node->extent,
		     0, sizeof(struct ssdfs_raw_extent),
		     sizeof(struct ssdfs_raw_extent));
	ssdfs_memcpy(&key,
		     0, sizeof(struct ssdfs_btree_index_key),
		     &child_node->node_index,
		     0, sizeof(struct ssdfs_btree_index_key),
		     sizeof(struct ssdfs_btree_index_key));
	spin_unlock(&child_node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, node_type %#x, "
		  "node_height %u, hash %llx\n",
		  le32_to_cpu(key.node_id),
		  key.node_type,
		  key.height,
		  le64_to_cpu(key.index.hash));
	SSDFS_DBG("seg_id %llu, logical_blk %u, len %u\n",
		  le64_to_cpu(key.index.extent.seg_id),
		  le32_to_cpu(key.index.extent.logical_blk),
		  le32_to_cpu(key.index.extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_node_add_index(parent_node, &key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add index: err %d\n", err);
		return err;
	}


	return 0;
}

/*
 * ssdfs_btree_add_index() - add an index into parent node
 * @desc: btree state descriptor
 * @parent: parent level descriptor
 * @child: child level descriptor
 *
 * This method tries to add an index into parent node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_add_index(struct ssdfs_btree_state_descriptor *desc,
			  struct ssdfs_btree_level *parent,
			  struct ssdfs_btree_level *child)
{
	struct ssdfs_btree_node *parent_node = NULL, *child_node = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !parent || !child);

	SSDFS_DBG("desc %p, parent %p, child %p\n",
		  desc, parent, child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(parent->flags & SSDFS_BTREE_LEVEL_ADD_INDEX)) {
		SSDFS_WARN("add index hasn't been requested\n");
		return -ERANGE;
	}

	if (parent->flags & SSDFS_BTREE_LEVEL_ADD_NODE)
		parent_node = parent->nodes.new_node.ptr;
	else if (parent->nodes.old_node.ptr)
		parent_node = parent->nodes.old_node.ptr;
	else
		parent_node = parent->nodes.new_node.ptr;

	child_node = child->nodes.new_node.ptr;

	if (!parent_node || !child_node) {
		SSDFS_ERR("invalid pointer: "
			  "parent_node %p, child_node %p\n",
			  parent_node, child_node);
		return -ERANGE;
	}

	err = __ssdfs_btree_add_index(parent_node, child_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add index: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_btree_update_index_after_move() - update sibling nodes' indexes
 * @child: child level descriptor
 * @parent_node: parent node
 *
 * This method tries to update the sibling nodes' indexes
 * after operation of moving items/indexes.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_update_index_after_move(struct ssdfs_btree_level *child,
					struct ssdfs_btree_node *parent_node)
{
	struct ssdfs_btree_node *child_node = NULL;
	int parent_type, child_type;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!child || !parent_node);

	SSDFS_DBG("child %p, parent_node %p\n",
		  child, parent_node);
#endif /* CONFIG_SSDFS_DEBUG */

	if (child->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE ||
	    child->flags & SSDFS_BTREE_INDEX_AREA_NEED_MOVE) {
		struct ssdfs_btree_node_move *move;

		if (child->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE)
			move = &child->items_area.move;
		else if (child->flags & SSDFS_BTREE_INDEX_AREA_NEED_MOVE)
			move = &child->index_area.move;
		else
			BUG();

		switch (move->direction) {
		case SSDFS_BTREE_MOVE_TO_LEFT:
		case SSDFS_BTREE_MOVE_TO_RIGHT:
			/* expected state */
			break;

		default:
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("nothing should be done: "
				  "direction %#x\n",
				  move->direction);
#endif /* CONFIG_SSDFS_DEBUG */
			return 0;
		}

		child_node = child->nodes.old_node.ptr;
		if (!child_node) {
			SSDFS_ERR("invalid child pointer\n");
			return -ERANGE;
		}

		parent_type = atomic_read(&parent_node->type);
		child_type = atomic_read(&child_node->type);

		if (parent_type == SSDFS_BTREE_HYBRID_NODE &&
		    child_type == SSDFS_BTREE_HYBRID_NODE &&
		    parent_node == child_node) {
			/*
			 * The hybrid node has been updated already.
			 */
		} else {
			err = __ssdfs_btree_update_index(parent_node,
							 child_node);
			if (err == -ENODATA) {
				/* ignore error */
				err = 0;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("child node %u is empty\n",
					  child_node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to update index: err %d\n",
					  err);
				return err;
			}
		}

		child_node = child->nodes.new_node.ptr;
		if (!child_node) {
			SSDFS_ERR("invalid child pointer\n");
			return -ERANGE;
		}

		parent_type = atomic_read(&parent_node->type);
		child_type = atomic_read(&child_node->type);

		if (parent_type == SSDFS_BTREE_HYBRID_NODE &&
		    child_type == SSDFS_BTREE_HYBRID_NODE &&
		    parent_node == child_node) {
			/*
			 * The hybrid node has been updated already.
			 */
		} else {
			if (child->flags & SSDFS_BTREE_LEVEL_ADD_NODE) {
				/*
				 * Do nothing. Index will be added later.
				 */
				SSDFS_DBG("nothing should be done: "
					  "index will be added later\n");
			} else {
				err = __ssdfs_btree_update_index(parent_node,
								 child_node);
				if (unlikely(err)) {
					SSDFS_ERR("fail to update index: "
						  "err %d\n",
						  err);
					return err;
				}
			}
		}
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing should be done: "
			  "flags %#x\n", child->flags);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return 0;
}

/*
 * ssdfs_btree_process_level_for_add() - process a level of btree's hierarchy
 * @hierarchy: btree's hierarchy
 * @cur_height: current height
 * @search: search object
 *
 * This method tries to process the level of btree's hierarchy.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOSPC     - unable to resize the index area.
 */
int ssdfs_btree_process_level_for_add(struct ssdfs_btree_hierarchy *hierarchy,
					int cur_height,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_state_descriptor *desc;
	struct ssdfs_btree_level *cur_level;
	struct ssdfs_btree_level *parent;
	struct ssdfs_btree_node *node;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!hierarchy || !search);

	SSDFS_DBG("hierarchy %p, cur_height %d\n",
		  hierarchy, cur_height);
#endif /* CONFIG_SSDFS_DEBUG */

	if (cur_height >= hierarchy->desc.height) {
		SSDFS_ERR("invalid hierarchy: "
			  "cur_height %d, tree_height %d\n",
			  cur_height, hierarchy->desc.height);
		return -ERANGE;
	}

	desc = &hierarchy->desc;
	cur_level = hierarchy->array_ptr[cur_height];

	if (!cur_level->flags) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing to do: cur_height %d\n",
			  cur_height);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	if (cur_height == (hierarchy->desc.height - 1))
		goto check_necessity_increase_tree_height;

	parent = hierarchy->array_ptr[cur_height + 1];

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_height %d, tree_height %d, "
		  "cur_level->flags %#x, parent->flags %#x\n",
		  cur_height, hierarchy->desc.height,
		  cur_level->flags, parent->flags);
#endif /* CONFIG_SSDFS_DEBUG */

	if (cur_level->flags & ~SSDFS_BTREE_ADD_NODE_MASK ||
	    parent->flags & ~SSDFS_BTREE_ADD_NODE_MASK) {
		SSDFS_ERR("invalid flags: cur_level %#x, parent %#x\n",
			  cur_level->flags,
			  parent->flags);
		return -ERANGE;
	}

	if (cur_level->flags & SSDFS_BTREE_LEVEL_ADD_NODE) {
		if (!cur_level->nodes.new_node.ptr) {
			SSDFS_ERR("new node hasn't been created\n");
			return -ERANGE;
		}
	}

	if (parent->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE) {
		err = ssdfs_btree_move_items(desc, parent, cur_level);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move items: err %d\n",
				  err);
			return err;
		}
	}

	if (cur_level->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE) {
		err = ssdfs_btree_move_items(desc, parent, cur_level);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move items: err %d\n",
				  err);
			return err;
		}
	}

	if (parent->flags & SSDFS_BTREE_TRY_RESIZE_INDEX_AREA) {
		err = ssdfs_btree_resize_index_area(desc, parent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to resize index area: err %d\n",
				  err);
			return err;
		}
	}

	if (parent->flags & SSDFS_BTREE_INDEX_AREA_NEED_MOVE) {
		err = ssdfs_btree_move_indexes(desc, parent, cur_level);
		if (err == -ENOSPC) {
			err = ssdfs_btree_resize_index_area(desc, cur_level);
			if (unlikely(err)) {
				SSDFS_ERR("fail to resize index area: err %d\n",
					  err);
				return err;
			}

			err = ssdfs_btree_move_indexes(desc, parent, cur_level);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to move indexes: err %d\n",
				  err);
			return err;
		}
	}

	if (cur_level->flags & SSDFS_BTREE_INDEX_AREA_NEED_MOVE) {
		err = ssdfs_btree_move_indexes(desc, parent, cur_level);
		if (err == -ENOSPC) {
			err = ssdfs_btree_resize_index_area(desc, cur_level);
			if (unlikely(err)) {
				SSDFS_ERR("fail to resize index area: err %d\n",
					  err);
				return err;
			}

			err = ssdfs_btree_move_indexes(desc, parent, cur_level);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to move indexes: err %d\n",
				  err);
			return err;
		}
	}

	if (cur_level->flags & SSDFS_BTREE_LEVEL_ADD_ITEM) {
		err = ssdfs_btree_prepare_add_item(parent, cur_level);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare node for add: err %d\n",
				  err);
			return err;
		}
	}

	if (parent->flags & SSDFS_BTREE_LEVEL_UPDATE_INDEX) {
		err = ssdfs_btree_update_index(desc, parent, cur_level);
		if (unlikely(err)) {
			SSDFS_ERR("fail to update the index: err %d\n",
				  err);
			return err;
		}
	}

	if (parent->flags & SSDFS_BTREE_LEVEL_ADD_INDEX) {
		err = ssdfs_btree_add_index(desc, parent, cur_level);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add the index: err %d\n",
				  err);
			return err;
		}
	}

	if (cur_height == (hierarchy->desc.height - 1)) {
check_necessity_increase_tree_height:
		if (cur_level->nodes.old_node.ptr)
			node = cur_level->nodes.old_node.ptr;
		else if (cur_level->nodes.new_node.ptr)
			node = cur_level->nodes.new_node.ptr;
		else
			goto finish_process_level_for_add;

		switch (atomic_read(&node->type)) {
		case SSDFS_BTREE_ROOT_NODE:
			if (hierarchy->desc.increment_height)
				atomic_inc(&node->height);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("node_id %u, node height %u, "
				  "cur_height %u, increment_height %#x\n",
				  node->node_id, atomic_read(&node->height),
				  cur_height, hierarchy->desc.increment_height);
#endif /* CONFIG_SSDFS_DEBUG */
			break;

		default:
			/* do nothing */
			break;
		}
	}

finish_process_level_for_add:
	return 0;
}

/*
 * ssdfs_btree_delete_index() - delete index from the node
 * @desc: btree state descriptor
 * @level: level descriptor
 *
 * This method tries to delete an index from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_delete_index(struct ssdfs_btree_state_descriptor *desc,
			     struct ssdfs_btree_level *level)
{
	struct ssdfs_btree_node *node;
	struct ssdfs_btree_node_delete *delete;
	u64 hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc || !level);

	SSDFS_DBG("desc %p, level %p\n",
		  desc, level);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!(level->flags & SSDFS_BTREE_LEVEL_DELETE_INDEX)) {
		SSDFS_WARN("delete index hasn't been requested\n");
		return 0;
	}

	node = level->nodes.old_node.ptr;
	if (!node) {
		SSDFS_ERR("invalid pointer: node %p\n",
			  node);
		return -ERANGE;
	}

	delete = &level->index_area.delete;

	if (delete->op_state != SSDFS_BTREE_AREA_OP_REQUESTED) {
		SSDFS_ERR("invalid operation state %#x\n",
			  delete->op_state);
		return -ERANGE;
	} else
		delete->op_state = SSDFS_BTREE_AREA_OP_FAILED;

	hash = cpu_to_le64(delete->node_index.index.hash);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("tree type %#x, node_id %u, hash %llx\n",
		  node->tree->type, node->node_id, hash);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_node_delete_index(node, hash);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete index: "
			  "hash %llx, err %d\n",
			  hash, err);
		return err;
	}

	delete->op_state = SSDFS_BTREE_AREA_OP_DONE;

	return 0;
}

/*
 * ssdfs_btree_process_level_for_delete() - process a level of btree's hierarchy
 * @hierarchy: btree's hierarchy
 * @cur_height: current height
 * @search: search object
 *
 * This method tries to process the level of btree's hierarchy.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_process_level_for_delete(struct ssdfs_btree_hierarchy *ptr,
					 int cur_height,
					 struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_state_descriptor *desc;
	struct ssdfs_btree_level *cur_level;
	struct ssdfs_btree_level *parent;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !search);

	SSDFS_DBG("hierarchy %p, cur_height %d\n",
		  ptr, cur_height);
#endif /* CONFIG_SSDFS_DEBUG */

	if (cur_height >= ptr->desc.height) {
		SSDFS_ERR("invalid hierarchy: "
			  "cur_height %d, tree_height %d\n",
			  cur_height, ptr->desc.height);
		return -ERANGE;
	}

	desc = &ptr->desc;
	cur_level = ptr->array_ptr[cur_height];
	parent = ptr->array_ptr[cur_height + 1];

	if (!cur_level->flags) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing to do: cur_height %d\n",
			  cur_height);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	if (cur_level->flags & ~SSDFS_BTREE_DELETE_NODE_MASK) {
		SSDFS_ERR("invalid flags %#x\n",
			  cur_level->flags);
		return -ERANGE;
	}

	if (cur_level->flags & SSDFS_BTREE_LEVEL_DELETE_INDEX) {
		err = ssdfs_btree_delete_index(desc, cur_level);
		if (unlikely(err)) {
			SSDFS_ERR("fail to delete the index: err %d\n",
				  err);
			return err;
		}
	}

	if (parent->flags & SSDFS_BTREE_LEVEL_UPDATE_INDEX) {
		err = ssdfs_btree_update_index(desc, parent, cur_level);
		if (unlikely(err)) {
			SSDFS_ERR("fail to update the index: err %d\n",
				  err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_process_level_for_update() - process a level of btree's hierarchy
 * @hierarchy: btree's hierarchy
 * @cur_height: current height
 * @search: search object
 *
 * This method tries to process the level of btree's hierarchy.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_process_level_for_update(struct ssdfs_btree_hierarchy *ptr,
					 int cur_height,
					 struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_state_descriptor *desc;
	struct ssdfs_btree_level *cur_level;
	struct ssdfs_btree_level *parent;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !search);

	SSDFS_DBG("hierarchy %p, cur_height %d\n",
		  ptr, cur_height);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_debug_btree_hierarchy_object(ptr);

	if (cur_height >= ptr->desc.height) {
		SSDFS_ERR("invalid hierarchy: "
			  "cur_height %d, tree_height %d\n",
			  cur_height, ptr->desc.height);
		return -ERANGE;
	}

	desc = &ptr->desc;
	cur_level = ptr->array_ptr[cur_height];
	parent = ptr->array_ptr[cur_height + 1];

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("parent->flags %#x\n", parent->flags);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!parent->flags) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing to do: cur_height %d\n",
			  cur_height);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	if (parent->flags & ~SSDFS_BTREE_LEVEL_FLAGS_MASK) {
		SSDFS_ERR("invalid flags %#x\n",
			  cur_level->flags);
		return -ERANGE;
	}

	if (parent->flags & SSDFS_BTREE_LEVEL_UPDATE_INDEX) {
		err = ssdfs_btree_update_index(desc, parent, cur_level);
		if (unlikely(err)) {
			SSDFS_ERR("fail to update the index: err %d\n",
				  err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_btree_process_level_for_node_merge() - process a level of btree's hierarchy
 * @hierarchy: btree's hierarchy
 * @cur_height: current height
 * @search: search object
 *
 * This method tries to process the level of btree's hierarchy.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_process_level_for_node_merge(struct ssdfs_btree_hierarchy *ptr,
					     int cur_height,
					     struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_state_descriptor *desc;
	struct ssdfs_btree_level *cur_level;
	struct ssdfs_btree_level *parent;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !search);

	SSDFS_DBG("hierarchy %p, cur_height %d\n",
		  ptr, cur_height);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_debug_btree_hierarchy_object(ptr);

	if (cur_height >= ptr->desc.height) {
		SSDFS_ERR("invalid hierarchy: "
			  "cur_height %d, tree_height %d\n",
			  cur_height, ptr->desc.height);
		return -ERANGE;
	}

	desc = &ptr->desc;
	cur_level = ptr->array_ptr[cur_height];

	if (!cur_level->flags) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("nothing to do: cur_height %d\n",
			  cur_height);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	parent = ptr->array_ptr[cur_height + 1];

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_height %d, tree_height %d, "
		  "cur_level->flags %#x, parent->flags %#x\n",
		  cur_height, ptr->desc.height,
		  cur_level->flags, parent->flags);
#endif /* CONFIG_SSDFS_DEBUG */

	if (cur_level->flags & SSDFS_BTREE_ITEMS_AREA_NEED_MOVE) {
		err = ssdfs_btree_move_items(desc, parent, cur_level);
		if (unlikely(err)) {
			SSDFS_ERR("fail to move items: err %d\n",
				  err);
			return err;
		}
	}

	err = ssdfs_btree_process_level_for_delete(ptr, cur_height, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to process the tree's level: "
			  "cur_height %u, err %d\n",
			  cur_height, err);
		return err;
	}

	return 0;
}

void ssdfs_show_btree_hierarchy_object(struct ssdfs_btree_hierarchy *ptr)
{
	struct ssdfs_btree_index_key *index_key;
	int i;

	BUG_ON(!ptr);

	SSDFS_ERR("DESCRIPTOR: "
		  "height %d, increment_height %d, "
		  "node_size %u, index_size %u, "
		  "min_item_size %u, max_item_size %u, "
		  "index_area_min_size %u\n",
		  ptr->desc.height, ptr->desc.increment_height,
		  ptr->desc.node_size, ptr->desc.index_size,
		  ptr->desc.min_item_size,
		  ptr->desc.max_item_size,
		  ptr->desc.index_area_min_size);

	for (i = 0; i < ptr->desc.height; i++) {
		struct ssdfs_btree_level *level = ptr->array_ptr[i];

		SSDFS_ERR("LEVEL: height %d, flags %#x, "
			  "OLD_NODE: type %#x, ptr %p, "
			  "index_area (start %llx, end %llx), "
			  "items_area (start %llx, end %llx), "
			  "NEW_NODE: type %#x, ptr %p, "
			  "index_area (start %llx, end %llx), "
			  "items_area (start %llx, end %llx)\n",
			  i, level->flags,
			  level->nodes.old_node.type,
			  level->nodes.old_node.ptr,
			  level->nodes.old_node.index_hash.start,
			  level->nodes.old_node.index_hash.end,
			  level->nodes.old_node.items_hash.start,
			  level->nodes.old_node.items_hash.end,
			  level->nodes.new_node.type,
			  level->nodes.new_node.ptr,
			  level->nodes.new_node.index_hash.start,
			  level->nodes.new_node.index_hash.end,
			  level->nodes.new_node.items_hash.start,
			  level->nodes.new_node.items_hash.end);

		SSDFS_ERR("INDEX_AREA: area_size %u, free_space %u, "
			  "start_hash %llx, end_hash %llx\n",
			  level->index_area.area_size,
			  level->index_area.free_space,
			  level->index_area.hash.start,
			  level->index_area.hash.end);

		SSDFS_ERR("ADD: op_state %#x, start_hash %llx, "
			  "end_hash %llx, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->index_area.add.op_state,
			  level->index_area.add.hash.start,
			  level->index_area.add.hash.end,
			  level->index_area.add.pos.state,
			  level->index_area.add.pos.start,
			  level->index_area.add.pos.count);

		SSDFS_ERR("INSERT: op_state %#x, start_hash %llx, "
			  "end_hash %llx, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->index_area.insert.op_state,
			  level->index_area.insert.hash.start,
			  level->index_area.insert.hash.end,
			  level->index_area.insert.pos.state,
			  level->index_area.insert.pos.start,
			  level->index_area.insert.pos.count);

		SSDFS_ERR("MOVE: op_state %#x, direction %#x, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->index_area.move.op_state,
			  level->index_area.move.direction,
			  level->index_area.move.pos.state,
			  level->index_area.move.pos.start,
			  level->index_area.move.pos.count);

		index_key = &level->index_area.delete.node_index;
		SSDFS_ERR("DELETE: op_state %#x, "
			  "INDEX_KEY: node_id %u, node_type %#x, "
			  "height %u, flags %#x, hash %llx, "
			  "seg_id %llu, logical_blk %u, len %u\n",
			  level->index_area.delete.op_state,
			  le32_to_cpu(index_key->node_id),
			  index_key->node_type,
			  index_key->height,
			  le16_to_cpu(index_key->flags),
			  le64_to_cpu(index_key->index.hash),
			  le64_to_cpu(index_key->index.extent.seg_id),
			  le32_to_cpu(index_key->index.extent.logical_blk),
			  le32_to_cpu(index_key->index.extent.len));

		SSDFS_ERR("ITEMS_AREA: area_size %u, free_space %u, "
			  "start_hash %llx, end_hash %llx\n",
			  level->items_area.area_size,
			  level->items_area.free_space,
			  level->items_area.hash.start,
			  level->items_area.hash.end);

		SSDFS_ERR("ADD: op_state %#x, start_hash %llx, "
			  "end_hash %llx, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->items_area.add.op_state,
			  level->items_area.add.hash.start,
			  level->items_area.add.hash.end,
			  level->items_area.add.pos.state,
			  level->items_area.add.pos.start,
			  level->items_area.add.pos.count);

		SSDFS_ERR("INSERT: op_state %#x, start_hash %llx, "
			  "end_hash %llx, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->items_area.insert.op_state,
			  level->items_area.insert.hash.start,
			  level->items_area.insert.hash.end,
			  level->items_area.insert.pos.state,
			  level->items_area.insert.pos.start,
			  level->items_area.insert.pos.count);

		SSDFS_ERR("MOVE: op_state %#x, direction %#x, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->items_area.move.op_state,
			  level->items_area.move.direction,
			  level->items_area.move.pos.state,
			  level->items_area.move.pos.start,
			  level->items_area.move.pos.count);
	}
}

void ssdfs_debug_btree_hierarchy_object(struct ssdfs_btree_hierarchy *ptr)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct ssdfs_btree_index_key *index_key;
	int i;

	BUG_ON(!ptr);

	SSDFS_DBG("DESCRIPTOR: "
		  "height %d, increment_height %d, "
		  "node_size %u, index_size %u, "
		  "min_item_size %u, max_item_size %u, "
		  "index_area_min_size %u\n",
		  ptr->desc.height, ptr->desc.increment_height,
		  ptr->desc.node_size, ptr->desc.index_size,
		  ptr->desc.min_item_size,
		  ptr->desc.max_item_size,
		  ptr->desc.index_area_min_size);

	for (i = 0; i < ptr->desc.height; i++) {
		struct ssdfs_btree_level *level = ptr->array_ptr[i];

		SSDFS_DBG("LEVEL: height %d, flags %#x, "
			  "OLD_NODE: type %#x, ptr %p, "
			  "index_area (start %llx, end %llx), "
			  "items_area (start %llx, end %llx), "
			  "NEW_NODE: type %#x, ptr %p, "
			  "index_area (start %llx, end %llx), "
			  "items_area (start %llx, end %llx)\n",
			  i, level->flags,
			  level->nodes.old_node.type,
			  level->nodes.old_node.ptr,
			  level->nodes.old_node.index_hash.start,
			  level->nodes.old_node.index_hash.end,
			  level->nodes.old_node.items_hash.start,
			  level->nodes.old_node.items_hash.end,
			  level->nodes.new_node.type,
			  level->nodes.new_node.ptr,
			  level->nodes.new_node.index_hash.start,
			  level->nodes.new_node.index_hash.end,
			  level->nodes.new_node.items_hash.start,
			  level->nodes.new_node.items_hash.end);

		SSDFS_DBG("INDEX_AREA: area_size %u, free_space %u, "
			  "start_hash %llx, end_hash %llx\n",
			  level->index_area.area_size,
			  level->index_area.free_space,
			  level->index_area.hash.start,
			  level->index_area.hash.end);

		SSDFS_DBG("ADD: op_state %#x, start_hash %llx, "
			  "end_hash %llx, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->index_area.add.op_state,
			  level->index_area.add.hash.start,
			  level->index_area.add.hash.end,
			  level->index_area.add.pos.state,
			  level->index_area.add.pos.start,
			  level->index_area.add.pos.count);

		SSDFS_DBG("INSERT: op_state %#x, start_hash %llx, "
			  "end_hash %llx, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->index_area.insert.op_state,
			  level->index_area.insert.hash.start,
			  level->index_area.insert.hash.end,
			  level->index_area.insert.pos.state,
			  level->index_area.insert.pos.start,
			  level->index_area.insert.pos.count);

		SSDFS_DBG("MOVE: op_state %#x, direction %#x, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->index_area.move.op_state,
			  level->index_area.move.direction,
			  level->index_area.move.pos.state,
			  level->index_area.move.pos.start,
			  level->index_area.move.pos.count);

		index_key = &level->index_area.delete.node_index;
		SSDFS_DBG("DELETE: op_state %#x, "
			  "INDEX_KEY: node_id %u, node_type %#x, "
			  "height %u, flags %#x, hash %llx, "
			  "seg_id %llu, logical_blk %u, len %u\n",
			  level->index_area.delete.op_state,
			  le32_to_cpu(index_key->node_id),
			  index_key->node_type,
			  index_key->height,
			  le16_to_cpu(index_key->flags),
			  le64_to_cpu(index_key->index.hash),
			  le64_to_cpu(index_key->index.extent.seg_id),
			  le32_to_cpu(index_key->index.extent.logical_blk),
			  le32_to_cpu(index_key->index.extent.len));

		SSDFS_DBG("ITEMS_AREA: area_size %u, free_space %u, "
			  "start_hash %llx, end_hash %llx\n",
			  level->items_area.area_size,
			  level->items_area.free_space,
			  level->items_area.hash.start,
			  level->items_area.hash.end);

		SSDFS_DBG("ADD: op_state %#x, start_hash %llx, "
			  "end_hash %llx, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->items_area.add.op_state,
			  level->items_area.add.hash.start,
			  level->items_area.add.hash.end,
			  level->items_area.add.pos.state,
			  level->items_area.add.pos.start,
			  level->items_area.add.pos.count);

		SSDFS_DBG("INSERT: op_state %#x, start_hash %llx, "
			  "end_hash %llx, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->items_area.insert.op_state,
			  level->items_area.insert.hash.start,
			  level->items_area.insert.hash.end,
			  level->items_area.insert.pos.state,
			  level->items_area.insert.pos.start,
			  level->items_area.insert.pos.count);

		SSDFS_DBG("MOVE: op_state %#x, direction %#x, "
			  "POSITION(state %#x, start %u, count %u)\n",
			  level->items_area.move.op_state,
			  level->items_area.move.direction,
			  level->items_area.move.pos.state,
			  level->items_area.move.pos.start,
			  level->items_area.move.pos.count);
	}
#endif /* CONFIG_SSDFS_DEBUG */
}
