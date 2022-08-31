//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/invalidated_extents_tree.c - invalidated extents btree implementation.
 *
 * Copyright (c) 2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagevec.h>
#include <linux/time.h>
#include <linux/time64.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "shared_dictionary.h"
#include "dentries_tree.h"
#include "invalidated_extents_tree.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_invext_tree_page_leaks;
atomic64_t ssdfs_invext_tree_memory_leaks;
atomic64_t ssdfs_invext_tree_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_invext_tree_cache_leaks_increment(void *kaddr)
 * void ssdfs_invext_tree_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_invext_tree_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_invext_tree_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_invext_tree_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_invext_tree_kfree(void *kaddr)
 * struct page *ssdfs_invext_tree_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_invext_tree_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_invext_tree_free_page(struct page *page)
 * void ssdfs_invext_tree_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(invext_tree)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(invext_tree)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_invext_tree_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_invext_tree_page_leaks, 0);
	atomic64_set(&ssdfs_invext_tree_memory_leaks, 0);
	atomic64_set(&ssdfs_invext_tree_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_invext_tree_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_invext_tree_page_leaks) != 0) {
		SSDFS_ERR("INVALIDATED EXTENTS TREE: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_invext_tree_page_leaks));
	}

	if (atomic64_read(&ssdfs_invext_tree_memory_leaks) != 0) {
		SSDFS_ERR("INVALIDATED EXTENTS TREE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_invext_tree_memory_leaks));
	}

	if (atomic64_read(&ssdfs_invext_tree_cache_leaks) != 0) {
		SSDFS_ERR("INVALIDATED EXTENTS TREE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_invext_tree_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/******************************************************************************
 *                  INVALIDATED EXTENTS TREE OBJECT FUNCTIONALITY             *
 ******************************************************************************/

/*
 * ssdfs_invextree_create() - create invalidated extents btree
 * @fsi: pointer on shared file system object
 *
 * This method tries to create invalidated extents btree object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
int ssdfs_invextree_create(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_invextree_info *ptr;
	size_t desc_size = sizeof(struct ssdfs_invextree_info);
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p\n", fsi);
#else
	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi->invextree = NULL;

	ptr = ssdfs_invext_tree_kzalloc(desc_size, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate invalidated extents tree\n");
		return -ENOMEM;
	}

	atomic_set(&ptr->state, SSDFS_INVEXTREE_UNKNOWN_STATE);

	fsi->invextree = ptr;
	ptr->fsi = fsi;

	err = ssdfs_btree_create(fsi,
				 SSDFS_INVALID_EXTENTS_BTREE_INO,
				 &ssdfs_invextree_desc_ops,
				 &ssdfs_invextree_ops,
				 &ptr->generic_tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create invalidated extents tree: err %d\n",
			  err);
		goto fail_create_invextree;
	}

	init_rwsem(&ptr->lock);

	atomic64_set(&ptr->extents_count, 0);

	atomic_set(&ptr->state, SSDFS_INVEXTREE_CREATED);

	ssdfs_debug_invextree_object(ptr);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("DONE: create invalidated extents tree\n");
#else
	SSDFS_DBG("DONE: create invalidated extents tree\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

fail_create_invextree:
	ssdfs_invext_tree_kfree(ptr);
	fsi->invextree = NULL;
	return err;
}

/*
 * ssdfs_invextree_destroy - destroy invalidated extents btree
 * @fsi: pointer on shared file system object
 */
void ssdfs_invextree_destroy(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_invextree_info *tree;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p\n", fsi->invextree);
#else
	SSDFS_DBG("tree %p\n", fsi->invextree);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!fsi->invextree)
		return;

	tree = fsi->invextree;

	ssdfs_debug_invextree_object(tree);

	ssdfs_btree_destroy(&tree->generic_tree);

	ssdfs_invext_tree_kfree(tree);
	fsi->invextree = NULL;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
}

/*
 * ssdfs_invextree_flush() - flush dirty invalidated extents btree
 * @fsi: pointer on shared file system object
 *
 * This method tries to flush the dirty invalidated extents btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_invextree_flush(struct ssdfs_fs_info *fsi)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->invextree);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p\n", fsi->invextree);
#else
	SSDFS_DBG("tree %p\n", fsi->invextree);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_btree_flush(&fsi->invextree->generic_tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush invalidated extents btree: err %d\n",
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_invextree_object(fsi->invextree);

	return 0;
}

/******************************************************************************
 *                INVALIDATED EXTENTS TREE OBJECT FUNCTIONALITY               *
 ******************************************************************************/

/*
 * ssdfs_invextree_calculate_hash() - calculate hash value
 * @fsi: pointer on shared file system object
 * @seg_id: segment or zone ID
 * @logical_blk: logical block index in the segment or zone
 */
static inline
u64 ssdfs_invextree_calculate_hash(struct ssdfs_fs_info *fsi,
				   u64 seg_id, u32 logical_blk)
{
	u64 hash = U64_MAX;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("seg_id %llu, logical_block %u\n",
		  seg_id, logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	hash = seg_id;
	hash *= fsi->pebs_per_seg;
	hash *= fsi->pages_per_peb;
	hash += logical_blk;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, logical_block %u, "
		  "pebs_per_seg %u, pages_per_peb %u, "
		  "hash %llx\n",
		  seg_id, logical_blk,
		  fsi->pebs_per_seg,
		  fsi->pages_per_peb,
		  hash);
#endif /* CONFIG_SSDFS_DEBUG */

	return hash;
}

/*
 * need_initialize_invextree_search() - check necessity to init the search
 * @fsi: pointer on shared file system object
 * @seg_id: segment or zone ID
 * @logical_blk: logical block index in the segment or zone
 * @search: search object
 */
static inline
bool need_initialize_invextree_search(struct ssdfs_fs_info *fsi,
					u64 seg_id, u32 logical_blk,
					struct ssdfs_btree_search *search)
{
	u64 hash = ssdfs_invextree_calculate_hash(fsi, seg_id, logical_blk);

	return need_initialize_btree_search(search) ||
				search->request.start.hash != hash;
}

/*
 * ssdfs_invextree_find() - find invalidated extent
 * @tree: pointer on invalidated extents btree object
 * @extent: searching range of invalidated logical blocks
 * @search: pointer on search request object
 *
 * This method tries to find an invalidated extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_invextree_find(struct ssdfs_invextree_info *tree,
			 struct ssdfs_raw_extent *extent,
			 struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u64 start_hash;
	u64 end_hash;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !extent || !search);

	SSDFS_DBG("tree %p, search %p, "
		  "extent (seg_id %llu, logical_blk %u, len %u)\n",
		  tree, search,
		  le64_to_cpu(extent->seg_id),
		  le32_to_cpu(extent->logical_blk),
		  le32_to_cpu(extent->len));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tree->fsi;

	seg_id = le64_to_cpu(extent->seg_id);
	logical_blk = le32_to_cpu(extent->logical_blk);
	len = le32_to_cpu(extent->len);

	start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id, logical_blk);
	end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						  logical_blk + len - 1);

	search->request.type = SSDFS_BTREE_SEARCH_FIND_RANGE;

	if (need_initialize_invextree_search(fsi, seg_id, logical_blk, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_RANGE;
		search->request.flags = SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.start.hash = start_hash;
		search->request.end.hash = end_hash;
		search->request.count = len;
	}

	return ssdfs_btree_find_range(&tree->generic_tree, search);
}

/*
 * ssdfs_invextree_find_leaf_node() - find a leaf node in the tree
 * @tree: invalidated extents tree
 * @seg_id: segment or zone ID
 * @search: search object
 *
 * This method tries to find a leaf node for the requested @seg_id.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_invextree_find_leaf_node(struct ssdfs_invextree_info *tree,
				   u64 seg_id,
				   struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	u64 hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);

	SSDFS_DBG("tree %p, seg_id %llu, search %p\n",
		  tree, seg_id, search);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tree->fsi;
	hash = ssdfs_invextree_calculate_hash(fsi, seg_id, 0);

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_invextree_search(fsi, seg_id, 0, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags = SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.start.hash = hash;
		search->request.end.hash = hash;
		search->request.count = 1;
	}

	err = ssdfs_btree_find_item(&tree->generic_tree, search);
	if (err == -ENODATA) {
		switch (search->result.state) {
		case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
			/* expected state */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("unexpected result's state %#x\n",
				  search->result.state);
			goto finish_find_leaf_node;
		}

		switch (search->node.state) {
		case SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC:
		case SSDFS_BTREE_SEARCH_FOUND_INDEX_NODE_DESC:
			/* expected state */
			err = 0;
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("unexpected node state %#x\n",
				  search->node.state);
			break;
		}
	}

finish_find_leaf_node:
	return err;
}

/*
 * ssdfs_invextree_get_start_hash() - get starting hash of the tree
 * @tree: invalidated extents tree
 * @start_hash: extracted start hash [out]
 *
 * This method tries to extract a start hash of the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_invextree_get_start_hash(struct ssdfs_invextree_info *tree,
				   u64 *start_hash)
{
	struct ssdfs_btree_node *node;
	u64 extents_count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !start_hash);

	SSDFS_DBG("tree %p, start_hash %p\n",
		  tree, start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	*start_hash = U64_MAX;

	switch (atomic_read(&tree->state)) {
	case SSDFS_INVEXTREE_CREATED:
	case SSDFS_INVEXTREE_INITIALIZED:
	case SSDFS_INVEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid invalidated extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	extents_count = atomic64_read(&tree->extents_count);

	if (extents_count < 0) {
		SSDFS_WARN("invalid invalidated extents count: "
			   "extents_count %llu\n",
			   extents_count);
		return -ERANGE;
	} else if (extents_count == 0)
		return -ENOENT;

	down_read(&tree->lock);

	err = ssdfs_btree_radix_tree_find(&tree->generic_tree,
					  SSDFS_BTREE_ROOT_NODE_ID,
					  &node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find root node in radix tree: "
			  "err %d\n", err);
		goto finish_get_start_hash;
	} else if (!node) {
		err = -ENOENT;
		SSDFS_WARN("empty node pointer\n");
		goto finish_get_start_hash;
	}

	down_read(&node->header_lock);
	*start_hash = node->index_area.start_hash;
	up_read(&node->header_lock);

finish_get_start_hash:
	up_read(&tree->lock);

	if (*start_hash >= U64_MAX) {
		/* warn about invalid hash code */
		SSDFS_WARN("hash_code is invalid\n");
	}

	return err;
}

/*
 * ssdfs_invextree_node_hash_range() - get node's hash range
 * @tree: invalidated extents tree
 * @search: search object
 * @start_hash: extracted start hash [out]
 * @end_hash: extracted end hash [out]
 * @items_count: extracted number of items in node [out]
 *
 * This method tries to extract start hash, end hash,
 * and items count in a node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_invextree_node_hash_range(struct ssdfs_invextree_info *tree,
				    struct ssdfs_btree_search *search,
				    u64 *start_hash, u64 *end_hash,
				    u16 *items_count)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !start_hash || !end_hash || !items_count);

	SSDFS_DBG("search %p, start_hash %p, "
		  "end_hash %p, items_count %p\n",
		  search, start_hash, end_hash, items_count);
#endif /* CONFIG_SSDFS_DEBUG */

	*start_hash = *end_hash = U64_MAX;
	*items_count = 0;

	switch (atomic_read(&tree->state)) {
	case SSDFS_INVEXTREE_CREATED:
	case SSDFS_INVEXTREE_INITIALIZED:
	case SSDFS_INVEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid invalidated extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	err = ssdfs_btree_node_get_hash_range(search,
					      start_hash,
					      end_hash,
					      items_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get hash range: err %d\n",
			  err);
		goto finish_extract_hash_range;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, items_count %u\n",
		  *start_hash, *end_hash, *items_count);
#endif /* CONFIG_SSDFS_DEBUG */

finish_extract_hash_range:
	return err;
}

/*
 * ssdfs_invextree_extract_range() - extract range of items
 * @tree: invalidated extents tree
 * @start_index: start item index in the node
 * @count: requested count of items
 * @search: search object
 *
 * This method tries to extract a range of items from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENOENT     - unable to extract any items.
 */
int ssdfs_invextree_extract_range(struct ssdfs_invextree_info *tree,
				  u16 start_index, u16 count,
				  struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search);

	SSDFS_DBG("tree %p, start_index %u, count %u, search %p\n",
		  tree, start_index, count, search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&tree->state)) {
	case SSDFS_INVEXTREE_CREATED:
	case SSDFS_INVEXTREE_INITIALIZED:
	case SSDFS_INVEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid invalidated extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	down_read(&tree->lock);
	err = ssdfs_btree_extract_range(&tree->generic_tree,
					start_index, count,
					search);
	up_read(&tree->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the range: "
			  "start_index %u, count %u, err %d\n",
			  start_index, count, err);
	}

	return err;
}

/*
 * ssdfs_invextree_check_search_result() - check result of search
 * @search: search object
 */
int ssdfs_invextree_check_search_result(struct ssdfs_btree_search *search)
{
	size_t desc_size = sizeof(struct ssdfs_raw_extent);
	u16 items_count;
	size_t buf_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected result's state %#x\n",
			  search->result.state);
		return  -ERANGE;
	}

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		if (!search->result.buf) {
			SSDFS_ERR("buffer pointer is NULL\n");
			return -ERANGE;
		}
		break;

	default:
		SSDFS_ERR("unexpected buffer's state\n");
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.items_in_buffer >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	items_count = (u16)search->result.items_in_buffer;

	if (items_count == 0) {
		SSDFS_ERR("items_in_buffer %u\n",
			  items_count);
		return -ENOENT;
	} else if (items_count != search->result.count) {
		SSDFS_ERR("items_count %u != search->result.count %u\n",
			  items_count, search->result.count);
		return -ERANGE;
	}

	buf_size = desc_size * items_count;

	if (buf_size != search->result.buf_size) {
		SSDFS_ERR("buf_size %zu != search->result.buf_size %zu\n",
			  buf_size,
			  search->result.buf_size);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_invextree_get_next_hash() - get next node's starting hash
 * @tree: invalidated extents tree
 * @search: search object
 * @next_hash: next node's starting hash [out]
 */
int ssdfs_invextree_get_next_hash(struct ssdfs_invextree_info *tree,
				  struct ssdfs_btree_search *search,
				  u64 *next_hash)
{
	u64 old_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !search || !next_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	old_hash = le64_to_cpu(search->node.found_index.index.hash);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search %p, next_hash %p, old (node %u, hash %llx)\n",
		  search, next_hash, search->node.id, old_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&tree->lock);
	err = ssdfs_btree_get_next_hash(&tree->generic_tree, search, next_hash);
	up_read(&tree->lock);

	return err;
}

/*
 * ssdfs_prepare_invalidated_extent() - prepare invalidated extent
 * @extent: invalidated extent
 * @search: pointer on search request object
 *
 * This method tries to prepare an invalidated extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_prepare_invalidated_extent(struct ssdfs_raw_extent *extent,
				     struct ssdfs_btree_search *search)
{
	struct ssdfs_raw_extent *desc = NULL;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE:
		search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
		search->result.buf = &search->raw.invalidated_extent;
		search->result.buf_size = sizeof(struct ssdfs_raw_extent);
		search->result.items_in_buffer = 1;
		break;

	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.buf);
		BUG_ON(search->result.buf_size !=
			sizeof(struct ssdfs_raw_extent));
		BUG_ON(search->result.items_in_buffer != 1);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	default:
		SSDFS_ERR("unexpected buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	desc = &search->raw.invalidated_extent;

	ssdfs_memcpy(desc, 0, sizeof(struct ssdfs_raw_extent),
		     extent, 0, sizeof(struct ssdfs_raw_extent),
		     sizeof(struct ssdfs_raw_extent));

	return 0;
}

/*
 * ssdfs_invextree_add() - add invalidated extent into the tree
 * @tree: pointer on invalidated extents btree object
 * @extent: invalidated extent
 * @search: search object
 *
 * This method tries to add invalidated extent info into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - invalidated extent exists in the tree.
 */
int ssdfs_invextree_add(struct ssdfs_invextree_info *tree,
			struct ssdfs_raw_extent *extent,
			struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	u64 hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !extent || !search);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, extent %p, search %p\n",
		  tree, extent, search);
#else
	SSDFS_DBG("tree %p, extent %p, search %p\n",
		  tree, extent, search);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = tree->fsi;
	hash = ssdfs_invextree_calculate_hash(fsi,
				le64_to_cpu(extent->seg_id),
				le32_to_cpu(extent->logical_blk));

	ssdfs_btree_search_init(search);
	search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;
	search->request.flags = SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
	search->request.start.hash = hash;
	search->request.end.hash = hash;
	search->request.count = 1;

	switch (atomic_read(&tree->state)) {
	case SSDFS_INVEXTREE_CREATED:
	case SSDFS_INVEXTREE_INITIALIZED:
	case SSDFS_INVEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid invalidated extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	down_read(&tree->lock);

	err = ssdfs_btree_find_item(&tree->generic_tree, search);
	if (err == -ENODATA) {
		/*
		 * Invalidated extent doesn't exist.
		 */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the invalidated extent: "
			  "seg_id %llu, logical_blk %u, err %d\n",
			  le64_to_cpu(extent->seg_id),
			  le32_to_cpu(extent->logical_blk),
			  err);
		goto finish_add_invalidated_extent;
	}

	if (err == -ENODATA) {
		err = ssdfs_prepare_invalidated_extent(extent, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare invalidated extent: "
				  "err %d\n", err);
			goto finish_add_invalidated_extent;
		}

		search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;

		switch (search->result.state) {
		case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		case SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE:
			/* expected state */
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid search result's state %#x\n",
				  search->result.state);
			goto finish_add_invalidated_extent;
		}

		if (search->result.buf_state !=
					SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
			err = -ERANGE;
			SSDFS_ERR("invalid buf_state %#x\n",
				  search->result.buf_state);
			goto finish_add_invalidated_extent;
		}

		err = ssdfs_btree_add_item(&tree->generic_tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add invalidated extent the tree: "
				  "err %d\n", err);
			goto finish_add_invalidated_extent;
		}

		atomic_set(&tree->state, SSDFS_INVEXTREE_DIRTY);

		ssdfs_btree_search_forget_parent_node(search);
		ssdfs_btree_search_forget_child_node(search);

		if (unlikely(err)) {
			SSDFS_ERR("fail to add invalidated extent: "
				  "err %d\n", err);
			goto finish_add_invalidated_extent;
		}
	} else {
		err = -EEXIST;
		SSDFS_DBG("invalidated extent exists in the tree\n");
		goto finish_add_invalidated_extent;
	}

finish_add_invalidated_extent:
	up_read(&tree->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_invextree_object(tree);

	return err;
}

/*
 * ssdfs_invextree_delete() - delete invalidated extent from the tree
 * @tree: invalidated extents tree
 * @extent: invalidated extent
 * @search: search object
 *
 * This method tries to delete invalidated extent from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - invalidated extent doesn't exist in the tree.
 */
int ssdfs_invextree_delete(struct ssdfs_invextree_info *tree,
			   struct ssdfs_raw_extent *extent,
			   struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_raw_extent *desc;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u64 start_hash;
	u64 end_hash;
	s64 extents_count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !extent || !search);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, extent %p, search %p\n",
		  tree, extent, search);
#else
	SSDFS_DBG("tree %p, extent %p, search %p\n",
		  tree, extent, search);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	switch (atomic_read(&tree->state)) {
	case SSDFS_INVEXTREE_CREATED:
	case SSDFS_INVEXTREE_INITIALIZED:
	case SSDFS_INVEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid invalidated extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	seg_id = le64_to_cpu(extent->seg_id);
	logical_blk = le32_to_cpu(extent->logical_blk);
	len = le32_to_cpu(extent->len);

	fsi = tree->fsi;
	start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id, logical_blk);
	end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						  logical_blk + len - 1);

	search->request.type = SSDFS_BTREE_SEARCH_DELETE_RANGE;

	if (need_initialize_invextree_search(fsi, seg_id,
					     logical_blk, search)) {
		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_DELETE_RANGE;
		search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.start.hash = start_hash;
		search->request.end.hash = end_hash;
		search->request.count = len;
	}

	down_read(&tree->lock);

	err = ssdfs_btree_find_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the invalidated extent: "
			  "seg_id %llu, err %d\n",
			  seg_id, err);
		goto finish_delete_invalidated_extent;
	}

	search->request.type = SSDFS_BTREE_SEARCH_DELETE_ITEM;

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		err = -ERANGE;
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		goto finish_delete_invalidated_extent;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		err = -ERANGE;
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		goto finish_delete_invalidated_extent;
	}

	desc = &search->raw.invalidated_extent;

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		if (seg_id != cpu_to_le64(desc->seg_id)) {
			SSDFS_ERR("invalid result state: "
				  "seg_id1 %llu != seg_id2 %llu\n",
				  seg_id, cpu_to_le64(desc->seg_id));
			goto finish_delete_invalidated_extent;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("unexpected result state %#x\n",
			   search->result.state);
		goto finish_delete_invalidated_extent;
	}

	extents_count = atomic64_read(&tree->extents_count);
	if (extents_count == 0) {
		err = -ENOENT;
		SSDFS_DBG("empty tree\n");
		goto finish_delete_invalidated_extent;
	}

	if (search->result.start_index >= extents_count) {
		err = -ENODATA;
		SSDFS_ERR("invalid search result: "
			  "start_index %u, extents_count %lld\n",
			  search->result.start_index,
			  extents_count);
		goto finish_delete_invalidated_extent;
	}

	err = ssdfs_btree_delete_item(&tree->generic_tree,
				      search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete invalidated extent from the tree: "
			  "err %d\n", err);
		goto finish_delete_invalidated_extent;
	}

	atomic_set(&tree->state, SSDFS_INVEXTREE_DIRTY);

	ssdfs_btree_search_forget_parent_node(search);
	ssdfs_btree_search_forget_child_node(search);

	extents_count = atomic64_read(&tree->extents_count);

	if (extents_count == 0) {
		err = -ENOENT;
		SSDFS_DBG("tree is empty now\n");
		goto finish_delete_invalidated_extent;
	} else if (extents_count < 0) {
		err = -ERANGE;
		SSDFS_WARN("invalid extents_count %lld\n",
			   extents_count);
		atomic_set(&tree->state, SSDFS_INVEXTREE_CORRUPTED);
		goto finish_delete_invalidated_extent;
	}

finish_delete_invalidated_extent:
	up_read(&tree->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_invextree_object(tree);

	return err;
}

/******************************************************************************
 *         SPECIALIZED INVALIDATED EXTENTS BTREE DESCRIPTOR OPERATIONS        *
 ******************************************************************************/

/*
 * ssdfs_invextree_desc_init() - specialized btree descriptor init
 * @fsi: pointer on shared file system object
 * @tree: pointer on invalidated extents btree object
 */
static
int ssdfs_invextree_desc_init(struct ssdfs_fs_info *fsi,
			      struct ssdfs_btree *tree)
{
	struct ssdfs_btree_descriptor *desc;
	u32 erasesize;
	u32 node_size;
	size_t desc_size = sizeof(struct ssdfs_raw_extent);
	u16 item_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !tree);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));

	SSDFS_DBG("fsi %p, tree %p\n",
		  fsi, tree);
#endif /* CONFIG_SSDFS_DEBUG */

	erasesize = fsi->erasesize;

	desc = &fsi->vh->invextree.desc;

	if (le32_to_cpu(desc->magic) != SSDFS_INVEXT_BTREE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic %#x\n",
			  le32_to_cpu(desc->magic));
		goto finish_btree_desc_init;
	}

	/* TODO: check flags */

	if (desc->type != SSDFS_INVALIDATED_EXTENTS_BTREE) {
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

	if (item_size != desc_size) {
		err = -EIO;
		SSDFS_ERR("invalid item size %u\n",
			  item_size);
		goto finish_btree_desc_init;
	}

	if (le16_to_cpu(desc->index_area_min_size) != (16 * desc_size)) {
		err = -EIO;
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc->index_area_min_size));
		goto finish_btree_desc_init;
	}

	err = ssdfs_btree_desc_init(fsi, tree, desc, (u8)item_size, item_size);

finish_btree_desc_init:
	if (unlikely(err)) {
		SSDFS_ERR("fail to init btree descriptor: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_invextree_desc_flush() - specialized btree's descriptor flush
 * @tree: pointer on invalidated extents btree object
 */
static
int ssdfs_invextree_desc_flush(struct ssdfs_btree *tree)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_descriptor desc;
	size_t desc_size = sizeof(struct ssdfs_raw_extent);
	u32 erasesize;
	u32 node_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi);
	BUG_ON(!rwsem_is_locked(&tree->fsi->volume_sem));

	SSDFS_DBG("owner_ino %llu, type %#x, state %#x\n",
		  tree->owner_ino, tree->type,
		  atomic_read(&tree->state));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = tree->fsi;

	memset(&desc, 0xFF, sizeof(struct ssdfs_btree_descriptor));

	desc.magic = cpu_to_le32(SSDFS_INVEXT_BTREE_MAGIC);
	desc.item_size = cpu_to_le16(desc_size);

	err = ssdfs_btree_desc_flush(tree, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("invalid btree descriptor: err %d\n",
			  err);
		return err;
	}

	if (desc.type != SSDFS_INVALIDATED_EXTENTS_BTREE) {
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

	if (le16_to_cpu(desc.index_area_min_size) != (16 * desc_size)) {
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc.index_area_min_size));
		return -ERANGE;
	}

	ssdfs_memcpy(&fsi->vh->invextree.desc,
		     0, sizeof(struct ssdfs_btree_descriptor),
		     &desc,
		     0, sizeof(struct ssdfs_btree_descriptor),
		     sizeof(struct ssdfs_btree_descriptor));

	return 0;
}

/******************************************************************************
 *              SPECIALIZED INVALIDATED EXTENTS BTREE OPERATIONS              *
 ******************************************************************************/

/*
 * ssdfs_invextree_create_root_node() - specialized root node creation
 * @fsi: pointer on shared file system object
 * @node: pointer on node object [out]
 */
static
int ssdfs_invextree_create_root_node(struct ssdfs_fs_info *fsi,
				     struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_inline_root_node *root_node;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !fsi->vs || !node);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));

	SSDFS_DBG("fsi %p, node %p\n",
		  fsi, node);
#endif /* CONFIG_SSDFS_DEBUG */

	root_node = &fsi->vh->invextree.root_node;
	err = ssdfs_btree_create_root_node(node, root_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create root node: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_invextree_pre_flush_root_node() - specialized root node pre-flush
 * @node: pointer on node object
 */
static
int ssdfs_invextree_pre_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_state_bitmap *bmap;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

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

	if (tree->type != SSDFS_INVALIDATED_EXTENTS_BTREE) {
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
 * ssdfs_invextree_flush_root_node() - specialized root node flush
 * @node: pointer on node object
 */
static
int ssdfs_invextree_flush_root_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_inline_root_node *root_node;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->tree->fsi->volume_sem));

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_btree_node_dirty(node)) {
		SSDFS_WARN("node %u is not dirty\n",
			   node->node_id);
		return 0;
	}

	root_node = &node->tree->fsi->vh->invextree.root_node;
	ssdfs_btree_flush_root_node(node, root_node);

	return 0;
}

/*
 * ssdfs_invextree_create_node() - specialized node creation
 * @node: pointer on node object
 */
static
int ssdfs_invextree_create_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	size_t hdr_size = sizeof(struct ssdfs_invextree_node_header);
	u32 node_size;
	u32 items_area_size = 0;
	u16 item_size = 0;
	u16 index_size = 0;
	u16 index_area_min_size;
	u16 items_capacity = 0;
	u16 index_capacity = 0;
	u32 index_area_size = 0;
	size_t bmap_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);
	WARN_ON(atomic_read(&node->state) != SSDFS_BTREE_NODE_CREATED);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	tree = node->tree;
	node_size = tree->node_size;
	index_area_min_size = tree->index_area_min_size;

	node->node_ops = &ssdfs_invextree_node_ops;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
		switch (atomic_read(&node->index_area.state)) {
		case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid index area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}

		switch (atomic_read(&node->items_area.state)) {
		case SSDFS_BTREE_NODE_AREA_ABSENT:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid items area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		switch (atomic_read(&node->index_area.state)) {
		case SSDFS_BTREE_NODE_INDEX_AREA_EXIST:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid index area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}

		switch (atomic_read(&node->items_area.state)) {
		case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid items area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_LEAF_NODE:
		switch (atomic_read(&node->index_area.state)) {
		case SSDFS_BTREE_NODE_AREA_ABSENT:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid index area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}

		switch (atomic_read(&node->items_area.state)) {
		case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
			/* expected state */
			break;

		default:
			SSDFS_ERR("invalid items area's state %#x\n",
				  atomic_read(&node->items_area.state));
			return -ERANGE;
		}
		break;

	default:
		SSDFS_WARN("invalid node type %#x\n",
			   atomic_read(&node->type));
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
		node->bmap_array.item_start_bit =
			node->bmap_array.index_start_bit + index_capacity;
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

		SSDFS_DBG("node_size %u, hdr_size %zu, free_space %u\n",
			  node_size, hdr_size,
			  node->items_area.free_space);

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

		SSDFS_DBG("node_size %u, hdr_size %zu, free_space %u\n",
			  node_size, hdr_size,
			  node->items_area.free_space);

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

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_INVEXTREE_BMAP_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bmap_bytes %zu\n",
			  bmap_bytes);
		goto finish_create_node;
	}

	node->raw.invextree_header.extents_count = cpu_to_le32(0);

	SSDFS_DBG("node_id %u, extents_count %u\n",
		  node->node_id,
		  le32_to_cpu(node->raw.invextree_header.extents_count));
	SSDFS_DBG("items_count %u, items_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  node->items_area.items_count,
		  node->items_area.items_capacity,
		  node->items_area.start_hash,
		  node->items_area.end_hash);
	SSDFS_DBG("index_count %u, index_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  node->index_area.index_count,
		  node->index_area.index_capacity,
		  node->index_area.start_hash,
		  node->index_area.end_hash);

finish_create_node:
	up_write(&node->bmap_array.lock);
	up_write(&node->header_lock);

	if (unlikely(err))
		return err;

	err = ssdfs_btree_node_allocate_bmaps(addr, bmap_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate node's bitmaps: "
			  "bmap_bytes %zu, err %d\n",
			  bmap_bytes, err);
		return err;
	}

	down_write(&node->bmap_array.lock);
	for (i = 0; i < SSDFS_BTREE_NODE_BMAP_COUNT; i++) {
		spin_lock(&node->bmap_array.bmap[i].lock);
		node->bmap_array.bmap[i].ptr = addr[i];
		addr[i] = NULL;
		spin_unlock(&node->bmap_array.bmap[i].lock);
	}
	up_write(&node->bmap_array.lock);

	err = ssdfs_btree_node_allocate_content_space(node, node_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate content space: "
			  "node_size %u, err %d\n",
			  node_size, err);
		return err;
	}

	ssdfs_debug_btree_node_object(node);

	return err;
}

/*
 * ssdfs_invextree_init_node() - init invalidated extents tree's node
 * @node: pointer on node object
 *
 * This method tries to init the node of invalidated extents btree.
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
int ssdfs_invextree_init_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_invextree_info *tree_info = NULL;
	struct ssdfs_invextree_node_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_invextree_node_header);
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	struct page *page;
	void *kaddr;
	u64 start_hash, end_hash;
	u32 node_size;
	u16 item_size;
	u32 extents_count;
	u16 items_capacity;
	u32 items_count;
	u16 free_space = 0;
	u32 calculated_used_space;
	u16 flags;
	u8 index_size;
	u32 index_area_size = 0;
	u16 index_capacity = 0;
	size_t bmap_bytes;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (node->tree->type == SSDFS_INVALIDATED_EXTENTS_BTREE)
		tree_info = (struct ssdfs_invextree_info *)node->tree;
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

	kaddr = kmap_local_page(page);

	hdr = (struct ssdfs_invextree_node_header *)kaddr;

	if (!is_csum_valid(&hdr->node.check, hdr, hdr_size)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum: node_id %u\n",
			  node->node_id);
		goto finish_init_operation;
	}

	if (le32_to_cpu(hdr->node.magic.common) != SSDFS_SUPER_MAGIC ||
	    le16_to_cpu(hdr->node.magic.key) != SSDFS_INVEXT_BNODE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic: common %#x, key %#x\n",
			  le32_to_cpu(hdr->node.magic.common),
			  le16_to_cpu(hdr->node.magic.key));
		goto finish_init_operation;
	}

	down_write(&node->header_lock);

	ssdfs_memcpy(&node->raw.invextree_header, 0, hdr_size,
		     hdr, 0, hdr_size,
		     hdr_size);

	err = ssdfs_btree_init_node(node, &hdr->node,
				    hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init node: id %u, err %d\n",
			  node->node_id, err);
		goto finish_header_init;
	}

	flags = atomic_read(&node->flags);

	start_hash = le64_to_cpu(hdr->node.start_hash);
	end_hash = le64_to_cpu(hdr->node.end_hash);
	node_size = 1 << hdr->node.log_node_size;
	index_size = hdr->node.index_size;
	item_size = hdr->node.min_item_size;
	items_capacity = le16_to_cpu(hdr->node.items_capacity);
	extents_count = le32_to_cpu(hdr->extents_count);

	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "items_capacity %u, extents_count %u\n",
		  start_hash, end_hash,
		  items_capacity, extents_count);

	if (item_size == 0 || node_size % item_size) {
		err = -EIO;
		SSDFS_ERR("invalid size: item_size %u, node_size %u\n",
			  item_size, node_size);
		goto finish_header_init;
	}

	if (item_size != sizeof(struct ssdfs_raw_extent)) {
		err = -EIO;
		SSDFS_ERR("invalid item_size: "
			  "size %u, expected size %zu\n",
			  item_size,
			  sizeof(struct ssdfs_raw_extent));
		goto finish_header_init;
	}

	calculated_used_space = hdr_size;
	calculated_used_space += extents_count * item_size;

	if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
		index_area_size = 1 << hdr->node.log_index_area_size;
		calculated_used_space += index_area_size;
	}

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_ROOT_NODE:
		/* do nothing */
		break;

	case SSDFS_BTREE_INDEX_NODE:
		if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
			if (index_area_size != node->node_size) {
				err = -EIO;
				SSDFS_ERR("invalid index area's size: "
					  "node_id %u, index_area_size %u, "
					  "node_size %u\n",
					  node->node_id,
					  index_area_size,
					  node->node_size);
				goto finish_header_init;
			}

			calculated_used_space -= hdr_size;
		} else {
			err = -EIO;
			SSDFS_ERR("invalid set of flags: "
				  "node_id %u, flags %#x\n",
				  node->node_id, flags);
			goto finish_header_init;
		}

		free_space = 0;
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		if (flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA) {
			/*
			 * expected state
			 */
		} else {
			err = -EIO;
			SSDFS_ERR("invalid set of flags: "
				  "node_id %u, flags %#x\n",
				  node->node_id, flags);
			goto finish_header_init;
		}
		/* FALLTHRU */
		fallthrough;
	case SSDFS_BTREE_LEAF_NODE:
		if (extents_count > 0 &&
		    (start_hash >= U64_MAX || end_hash >= U64_MAX)) {
			err = -EIO;
			SSDFS_ERR("invalid hash range: "
				  "start_hash %llx, end_hash %llx\n",
				  start_hash, end_hash);
			goto finish_header_init;
		}

		if (item_size == 0 || node_size % item_size) {
			err = -EIO;
			SSDFS_ERR("invalid size: item_size %u, node_size %u\n",
				  item_size, node_size);
			goto finish_header_init;
		}

		if (item_size != sizeof(struct ssdfs_raw_extent)) {
			err = -EIO;
			SSDFS_ERR("invalid item_size: "
				  "size %u, expected size %zu\n",
				  item_size,
				  sizeof(struct ssdfs_raw_extent));
			goto finish_header_init;
		}

		if (items_capacity == 0 ||
		    items_capacity > (node_size / item_size)) {
			err = -EIO;
			SSDFS_ERR("invalid items_capacity %u\n",
				  items_capacity);
			goto finish_header_init;
		}

		if (extents_count > items_capacity) {
			err = -EIO;
			SSDFS_ERR("items_capacity %u != extents_count %u\n",
				  items_capacity,
				  extents_count);
			goto finish_header_init;
		}

		free_space =
			(u32)(items_capacity - extents_count) * item_size;
		if (free_space > node->items_area.area_size) {
			err = -EIO;
			SSDFS_ERR("free_space %u > area_size %u\n",
				  free_space,
				  node->items_area.area_size);
			goto finish_header_init;
		}
		break;

	default:
		BUG();
	}

	SSDFS_DBG("free_space %u, index_area_size %u, "
		  "hdr_size %zu, extents_count %u, "
		  "item_size %u\n",
		  free_space, index_area_size, hdr_size,
		  extents_count, item_size);

	if (free_space != (node_size - calculated_used_space)) {
		err = -EIO;
		SSDFS_ERR("free_space %u, node_size %u, "
			  "calculated_used_space %u\n",
			  free_space, node_size,
			  calculated_used_space);
		goto finish_header_init;
	}

	node->items_area.free_space = free_space;
	node->items_area.items_count = (u16)extents_count;
	node->items_area.items_capacity = items_capacity;

	SSDFS_DBG("items_count %u, items_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  node->items_area.items_count,
		  node->items_area.items_capacity,
		  node->items_area.start_hash,
		  node->items_area.end_hash);
	SSDFS_DBG("index_count %u, index_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  node->index_area.index_count,
		  node->index_area.index_capacity,
		  node->index_area.start_hash,
		  node->index_area.end_hash);

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

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_INVEXTREE_BMAP_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bmap_bytes %zu\n",
			  bmap_bytes);
		goto finish_init_operation;
	}

	err = ssdfs_btree_node_allocate_bmaps(addr, bmap_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate node's bitmaps: "
			  "bmap_bytes %zu, err %d\n",
			  bmap_bytes, err);
		goto finish_init_operation;
	}

	down_write(&node->bmap_array.lock);

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

	ssdfs_btree_node_init_bmaps(node, addr);

	spin_lock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);
	bitmap_set(node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].ptr,
		   0, extents_count);
	spin_unlock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);

	up_write(&node->bmap_array.lock);
finish_init_operation:
	kunmap_local(kaddr);

	if (unlikely(err))
		goto finish_init_node;

	atomic64_add((u64)extents_count, &tree_info->extents_count);

finish_init_node:
	up_read(&node->full_lock);

	ssdfs_debug_btree_node_object(node);

	return err;
}

static
void ssdfs_invextree_destroy_node(struct ssdfs_btree_node *node)
{
	SSDFS_DBG("operation is unavailable\n");
}

/*
 * ssdfs_invextree_add_node() - add node into invalidated extents btree
 * @node: pointer on node object
 *
 * This method tries to finish addition of node
 * into invalidated extents btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_invextree_add_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	int type;
	u16 items_capacity = 0;
	u64 start_hash = U64_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_CREATED:
	case SSDFS_BTREE_NODE_INITIALIZED:
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
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

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	down_read(&node->header_lock);

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		items_capacity = node->items_area.items_capacity;
		start_hash = node->items_area.start_hash;
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
	}

	SSDFS_DBG("node_id %u, extents_count %u\n",
		  node->node_id,
		  le32_to_cpu(node->raw.invextree_header.extents_count));
	SSDFS_DBG("items_count %u, items_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  node->items_area.items_count,
		  node->items_area.items_capacity,
		  node->items_area.start_hash,
		  node->items_area.end_hash);
	SSDFS_DBG("index_count %u, index_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  node->index_area.index_count,
		  node->index_area.index_capacity,
		  node->index_area.start_hash,
		  node->index_area.end_hash);

finish_add_node:
	up_read(&node->header_lock);

	ssdfs_debug_btree_node_object(node);

	if (err)
		return err;

	err = ssdfs_btree_update_parent_node_pointer(tree, node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update parent pointer: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	return 0;
}

static
int ssdfs_invextree_delete_node(struct ssdfs_btree_node *node)
{
	/* TODO: implement */
	SSDFS_DBG("TODO: implement\n");
	return 0;

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
}

/*
 * ssdfs_invextree_pre_flush_node() - pre-flush node's header
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
int ssdfs_invextree_pre_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_invextree_node_header invextree_header;
	size_t hdr_size = sizeof(struct ssdfs_invextree_node_header);
	struct ssdfs_btree *tree;
	struct ssdfs_invextree_info *tree_info = NULL;
	struct ssdfs_state_bitmap *bmap;
	struct page *page;
	u16 items_count;
	u32 items_area_size;
	u16 extents_count;
	u32 used_space;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

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

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_INVALIDATED_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_invextree_info,
					 generic_tree);
	}

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	ssdfs_memcpy(&invextree_header, 0, hdr_size,
		     &node->raw.invextree_header, 0, hdr_size,
		     hdr_size);

	invextree_header.node.magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	invextree_header.node.magic.key =
				cpu_to_le16(SSDFS_INVEXT_BNODE_MAGIC);
	invextree_header.node.magic.version.major = SSDFS_MAJOR_REVISION;
	invextree_header.node.magic.version.minor = SSDFS_MINOR_REVISION;

	err = ssdfs_btree_node_pre_flush_header(node, &invextree_header.node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush generic header: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_invextree_header_preparation;
	}

	items_count = node->items_area.items_count;
	items_area_size = node->items_area.area_size;
	extents_count = le16_to_cpu(invextree_header.extents_count);

	if (extents_count != items_count) {
		err = -ERANGE;
		SSDFS_ERR("extents_count %u != items_count %u\n",
			  extents_count, items_count);
		goto finish_invextree_header_preparation;
	}

	used_space = (u32)items_count * sizeof(struct ssdfs_raw_extent);

	if (used_space > items_area_size) {
		err = -ERANGE;
		SSDFS_ERR("used_space %u > items_area_size %u\n",
			  used_space, items_area_size);
		goto finish_invextree_header_preparation;
	}

	SSDFS_DBG("extents_count %u, "
		  "items_area_size %u, item_size %zu\n",
		  extents_count, items_area_size,
		  sizeof(struct ssdfs_raw_extent));

	invextree_header.node.check.bytes = cpu_to_le16((u16)hdr_size);
	invextree_header.node.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&invextree_header.node.check,
				   &invextree_header, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto finish_invextree_header_preparation;
	}

	ssdfs_memcpy(&node->raw.invextree_header, 0, hdr_size,
		     &invextree_header, 0, hdr_size,
		     hdr_size);

finish_invextree_header_preparation:
	up_write(&node->header_lock);

	if (unlikely(err))
		goto finish_node_pre_flush;

	if (pagevec_count(&node->content.pvec) < 1) {
		err = -ERANGE;
		SSDFS_ERR("pagevec is empty\n");
		goto finish_node_pre_flush;
	}

	page = node->content.pvec.pages[0];
	ssdfs_memcpy_to_page(page, 0, PAGE_SIZE,
			     &invextree_header, 0, hdr_size,
			     hdr_size);

finish_node_pre_flush:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_invextree_btree_flush_node() - flush node
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
int ssdfs_invextree_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree *tree;
	u64 fs_feature_compat;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node %p, node_id %u\n",
		  node, node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_INVALIDATED_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	}

	fsi = node->tree->fsi;

	spin_lock(&fsi->volume_state_lock);
	fs_feature_compat = fsi->fs_feature_compat;
	spin_unlock(&fsi->volume_state_lock);

	if (fs_feature_compat & SSDFS_HAS_INVALID_EXTENTS_TREE_COMPAT_FLAG) {
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
		SSDFS_CRIT("invalidated extents tree is absent\n");
	}

	ssdfs_debug_btree_node_object(node);

	return err;
}

/******************************************************************************
 *           SPECIALIZED INVALIDATED EXTENTS BTREE NODE OPERATIONS            *
 ******************************************************************************/

/*
 * ssdfs_convert_lookup2item_index() - convert lookup into item index
 * @node_size: size of the node in bytes
 * @lookup_index: lookup index
 */
static inline
u16 ssdfs_convert_lookup2item_index(u32 node_size, u16 lookup_index)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_size %u, lookup_index %u\n",
		  node_size, lookup_index);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_convert_lookup2item_index(lookup_index, node_size,
					sizeof(struct ssdfs_raw_extent),
					SSDFS_INVEXTREE_LOOKUP_TABLE_SIZE);
}

/*
 * ssdfs_convert_item2lookup_index() - convert item into lookup index
 * @node_size: size of the node in bytes
 * @item_index: item index
 */
static inline
u16 ssdfs_convert_item2lookup_index(u32 node_size, u16 item_index)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_size %u, item_index %u\n",
		  node_size, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_convert_item2lookup_index(item_index, node_size,
					sizeof(struct ssdfs_raw_extent),
					SSDFS_INVEXTREE_LOOKUP_TABLE_SIZE);
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_size %u, item_index %u\n",
		  node_size, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	lookup_index = ssdfs_convert_item2lookup_index(node_size, item_index);
	calculated = ssdfs_convert_lookup2item_index(node_size, lookup_index);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("lookup_index %u, calculated %u\n",
		  lookup_index, calculated);
#endif /* CONFIG_SSDFS_DEBUG */

	return calculated == item_index;
}

/*
 * ssdfs_invextree_node_find_lookup_index() - find lookup index
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
int ssdfs_invextree_node_find_lookup_index(struct ssdfs_btree_node *node,
					   struct ssdfs_btree_search *search,
					   u16 *lookup_index)
{
	__le64 *lookup_table;
	int array_size = SSDFS_INVEXTREE_LOOKUP_TABLE_SIZE;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search || !lookup_index);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	lookup_table = node->raw.invextree_header.lookup_table;
	err = ssdfs_btree_node_find_lookup_index_nolock(search,
							lookup_table,
							array_size,
							lookup_index);
	up_read(&node->header_lock);

	return err;
}

/*
 * __ssdfs_check_extent_for_request() - check invalidated extent
 * @fsi:  pointer on shared file system object
 * @extent: pointer on invalidated extent object
 * @search: search object
 *
 * This method tries to check @extent for the @search request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EAGAIN     - continue the search.
 * %-ENODATA    - possible place was found.
 */
static
int __ssdfs_check_extent_for_request(struct ssdfs_fs_info *fsi,
				     struct ssdfs_raw_extent *extent,
				     struct ssdfs_btree_search *search)
{
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u64 start_hash;
	u64 end_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !extent || !search);

	SSDFS_DBG("fsi %p, extent %p, search %p\n",
		  fsi, extent, search);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_id = le64_to_cpu(extent->seg_id);
	logical_blk = le32_to_cpu(extent->logical_blk);
	len = le32_to_cpu(extent->len);

	start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						    logical_blk);
	end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						  logical_blk + len - 1);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("request (start_hash %llx, end_hash %llx), "
		  "extent (start_hash %llx, end_hash %llx)\n",
		  search->request.start.hash,
		  search->request.end.hash,
		  start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start_hash > search->request.end.hash) {
		/* no data for request */
		err = -ENODATA;
	} else if (search->request.start.hash > end_hash) {
		/* continue the search */
		err = -EAGAIN;
	} else {
		/*
		 * extent is inside request [start_hash, end_hash]
		 */
	}

	return err;
}

/*
 * ssdfs_check_extent_for_request() - check invalidated extent
 * @fsi:  pointer on shared file system object
 * @extent: pointer on invalidated extent object
 * @search: search object
 *
 * This method tries to check @extent for the @search request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EAGAIN     - continue the search.
 * %-ENODATA    - possible place was found.
 */
static
int ssdfs_check_extent_for_request(struct ssdfs_fs_info *fsi,
				   struct ssdfs_raw_extent *extent,
				   struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !extent || !search);

	SSDFS_DBG("fsi %p, extent %p, search %p\n",
		  fsi, extent, search);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_check_extent_for_request(fsi, extent, search);
	if (err == -EAGAIN) {
		/* continue the search */
		return err;
	} else if (err == -ENODATA) {
		search->result.err = -ENODATA;
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check invalidated extent: err %d\n",
			  err);
		return err;
	} else {
		/* valid item found */
		search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;
	}

	return 0;
}

/*
 * ssdfs_get_extent_hash_range() - get extent's hash range
 * @fsi:  pointer on shared file system object
 * @kaddr: pointer on extent object
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 */
static
void ssdfs_get_extent_hash_range(struct ssdfs_fs_info *fsi,
				 void *kaddr,
				 u64 *start_hash,
				 u64 *end_hash)
{
	struct ssdfs_raw_extent *extent;
	u64 seg_id;
	u32 logical_blk;
	u32 len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !kaddr || !start_hash || !end_hash);

	SSDFS_DBG("kaddr %p\n", kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	extent = (struct ssdfs_raw_extent *)kaddr;

	seg_id = le64_to_cpu(extent->seg_id);
	logical_blk = le32_to_cpu(extent->logical_blk);
	len = le32_to_cpu(extent->len);

	*start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						     logical_blk);
	*end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						   logical_blk + len - 1);
}

/*
 * ssdfs_check_found_extent() - check found invalidated extent
 * @fsi: pointer on shared file system object
 * @search: search object
 * @kaddr: pointer on invalidated extent object
 * @item_index: index of the extent
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 * @found_index: pointer on found index [out]
 *
 * This method tries to check the found invalidated extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - corrupted invalidated extent.
 * %-EAGAIN     - continue the search.
 * %-ENODATA    - possible place was found.
 */
static
int ssdfs_check_found_extent(struct ssdfs_fs_info *fsi,
			     struct ssdfs_btree_search *search,
			     void *kaddr,
			     u16 item_index,
			     u64 *start_hash,
			     u64 *end_hash,
			     u16 *found_index)
{
	struct ssdfs_raw_extent *extent;
	u32 req_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !kaddr || !found_index);
	BUG_ON(!start_hash || !end_hash);

	SSDFS_DBG("item_index %u\n", item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;
	*found_index = U16_MAX;

	extent = (struct ssdfs_raw_extent *)kaddr;
	req_flags = search->request.flags;

	if (!(req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE)) {
		SSDFS_ERR("invalid request: hash is absent\n");
		return -ERANGE;
	}

	ssdfs_get_extent_hash_range(fsi, kaddr, start_hash, end_hash);

	err = ssdfs_check_extent_for_request(fsi, extent, search);
	if (err == -ENODATA) {
		search->result.state =
			SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
		search->result.err = err;
		search->result.start_index = item_index;
		search->result.count = 1;

		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_ADD_ITEM:
		case SSDFS_BTREE_SEARCH_ADD_RANGE:
		case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
			/* do nothing */
			break;

		default:
			ssdfs_btree_search_free_result_buf(search);

			search->result.buf_state =
				SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
			search->result.buf = NULL;
			search->result.buf_size = 0;
			search->result.items_in_buffer = 0;
			break;
		}
	} else if (err == -EAGAIN) {
		/* continue to search */
		err = 0;
		*found_index = U16_MAX;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check extent: err %d\n",
			  err);
	} else {
		*found_index = item_index;
		search->result.state =
			SSDFS_BTREE_SEARCH_VALID_ITEM;
	}

	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "found_index %u\n",
		  *start_hash, *end_hash,
		  *found_index);

	return err;
}

/*
 * ssdfs_prepare_extents_buffer() - prepare buffer for extents
 * @search: search object
 * @found_index: found index of invalidated extent
 * @start_hash: starting hash
 * @end_hash: ending hash
 * @items_count: count of items in the sequence
 * @item_size: size of the item
 */
static
int ssdfs_prepare_extents_buffer(struct ssdfs_btree_search *search,
				 u16 found_index,
				 u64 start_hash,
				 u64 end_hash,
				 u16 items_count,
				 size_t item_size)
{
	u16 found_extents = 0;
	size_t buf_size = sizeof(struct ssdfs_raw_extent);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);

	SSDFS_DBG("found_index %u, start_hash %llx, end_hash %llx, "
		  "items_count %u, item_size %zu\n",
		   found_index, start_hash, end_hash,
		   items_count, item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_btree_search_free_result_buf(search);

	if (start_hash == end_hash) {
		/* use inline buffer */
		found_extents = 1;
	} else {
		/* use external buffer */
		if (found_index >= items_count) {
			SSDFS_ERR("found_index %u >= items_count %u\n",
				  found_index, items_count);
			return -ERANGE;
		}
		found_extents = items_count - found_index;
	}

	if (found_extents == 1) {
		search->result.buf_state =
			SSDFS_BTREE_SEARCH_INLINE_BUFFER;
		search->result.buf = &search->raw.invalidated_extent;
		search->result.buf_size = buf_size;
		search->result.items_in_buffer = 0;
	} else {
		if (search->result.buf) {
			SSDFS_WARN("search->result.buf %p, "
				   "search->result.buf_state %#x\n",
				   search->result.buf,
				   search->result.buf_state);
		}

		err = ssdfs_btree_search_alloc_result_buf(search,
						buf_size * found_extents);
		if (unlikely(err)) {
			SSDFS_ERR("fail to allocate memory for buffer\n");
			return err;
		}
	}

	SSDFS_DBG("found_extents %u, "
		  "search->result.items_in_buffer %u\n",
		  found_extents,
		  search->result.items_in_buffer);

	return 0;
}

/*
 * ssdfs_extract_found_extent() - extract found extent
 * @fsi: pointer on shared file system object
 * @search: search object
 * @item_size: size of the item
 * @kaddr: pointer on invalidated extent
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 *
 * This method tries to extract the found extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extract_found_extent(struct ssdfs_fs_info *fsi,
				 struct ssdfs_btree_search *search,
				 size_t item_size,
				 void *kaddr,
				 u64 *start_hash,
				 u64 *end_hash)
{
	struct ssdfs_raw_extent *extent;
	size_t buf_size = sizeof(struct ssdfs_raw_extent);
	u32 calculated;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !search || !kaddr);
	BUG_ON(!start_hash || !end_hash);

	SSDFS_DBG("kaddr %p\n", kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;

	calculated = search->result.items_in_buffer * buf_size;
	if (calculated > search->result.buf_size) {
		SSDFS_ERR("calculated %u > buf_size %zu\n",
			  calculated, search->result.buf_size);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search->result.items_in_buffer %u, "
		  "calculated %u\n",
		  search->result.items_in_buffer,
		  calculated);

	BUG_ON(!search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */

	extent = (struct ssdfs_raw_extent *)kaddr;
	ssdfs_get_extent_hash_range(fsi, extent, start_hash, end_hash);

	err = __ssdfs_check_extent_for_request(fsi, extent, search);
	if (err == -ENODATA) {
		SSDFS_DBG("current extent is out of requested range\n");
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check extent: err %d\n",
			  err);
		return err;
	}

	err = ssdfs_memcpy(search->result.buf,
			   calculated, search->result.buf_size,
			   extent, 0, item_size,
			   item_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: calculated %u, "
			  "search->result.buf_size %zu, err %d\n",
			  calculated, search->result.buf_size, err);
		return err;
	}

	search->result.items_in_buffer++;
	search->result.count++;
	search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;

	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "search->result.count %u\n",
		  *start_hash, *end_hash,
		  search->result.count);

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
	int capacity = SSDFS_INVEXTREE_LOOKUP_TABLE_SIZE;
	size_t item_size = sizeof(struct ssdfs_raw_extent);

	return __ssdfs_extract_range_by_lookup_index(node, lookup_index,
						capacity, item_size,
						search,
						ssdfs_check_found_extent,
						ssdfs_prepare_extents_buffer,
						ssdfs_extract_found_extent);
}

/*
 * ssdfs_invextree_node_find_range() - find a range of items into the node
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
int ssdfs_invextree_node_find_range(struct ssdfs_btree_node *node,
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

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	state = atomic_read(&node->items_area.state);
	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	up_read(&node->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("request (start_hash %llx, end_hash %llx), "
		  "node (start_hash %llx, end_hash %llx)\n",
		  search->request.start.hash,
		  search->request.end.hash,
		  start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

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

	err = ssdfs_invextree_node_find_lookup_index(node, search,
						     &lookup_index);
	if (err == -ENODATA) {
		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
		case SSDFS_BTREE_SEARCH_DELETE_ITEM:
			/* do nothing */
			goto try_extract_range_by_lookup_index;

		default:
			/* continue logic */
			break;
		}

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

try_extract_range_by_lookup_index:

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(lookup_index >= SSDFS_INVEXTREE_LOOKUP_TABLE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_extract_range_by_lookup_index(node, lookup_index,
						  search);
	search->result.search_cno = ssdfs_current_cno(node->tree->fsi->sb);

	if (err == -EAGAIN) {
		SSDFS_DBG("node contains not all requested extents: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx)\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash);
		return err;
	} else if (err == -ENODATA) {
		SSDFS_DBG("unable to extract range: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
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
 * ssdfs_invextree_node_find_item() - find item into node
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
int ssdfs_invextree_node_find_item(struct ssdfs_btree_node *node,
				   struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->request.count != 1) {
		SSDFS_ERR("invalid request state: "
			  "count %d, start_hash %llx, end_hash %llx\n",
			  search->request.count,
			  search->request.start.hash,
			  search->request.end.hash);
		return -ERANGE;
	}

	return ssdfs_invextree_node_find_range(node, search);
}

static
int ssdfs_invextree_node_allocate_item(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

static
int ssdfs_invextree_node_allocate_range(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

/*
 * __ssdfs_invextree_node_get_extent() - extract the invalidated extent
 * @pvec: pointer on pagevec
 * @area_offset: area offset from the node's beginning
 * @area_size: area size
 * @node_size: size of the node
 * @item_index: index of the extent in the node
 * @extent: pointer on extent's buffer [out]
 *
 * This method tries to extract the invalidated extent from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_invextree_node_get_extent(struct pagevec *pvec,
					u32 area_offset,
					u32 area_size,
					u32 node_size,
					u16 item_index,
					struct ssdfs_raw_extent *extent)
{
	size_t item_size = sizeof(struct ssdfs_raw_extent);
	u32 item_offset;
	int page_index;
	struct page *page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec || !extent);

	SSDFS_DBG("area_offset %u, area_size %u, item_index %u\n",
		  area_offset, area_size, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

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

	err = ssdfs_memcpy_from_page(extent, 0, item_size,
				     page, item_offset, PAGE_SIZE,
				     item_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_invextree_node_get_extent() - extract extent from the node
 * @node: pointer on node object
 * @area: items area descriptor
 * @item_index: index of the extent
 * @extent: pointer on extracted extent [out]
 *
 * This method tries to extract the extent from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_invextree_node_get_extent(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *area,
				u16 item_index,
				struct ssdfs_raw_extent *extent)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !extent);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, item_index);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_invextree_node_get_extent(&node->content.pvec,
						 area->offset,
						 area->area_size,
						 node->node_size,
						 item_index,
						 extent);
}

/*
 * is_requested_position_correct() - check that requested position is correct
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to check that requested position of an extent
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
	struct ssdfs_fs_info *fsi;
	struct ssdfs_raw_extent extent;
	u16 item_index;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u64 start_hash;
	u64 end_hash;
	int direction = SSDFS_CHECK_POSITION_FAILURE;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	item_index = search->result.start_index;
	if ((item_index + search->request.count) > area->items_capacity) {
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

	err = ssdfs_invextree_node_get_extent(node, area, item_index, &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the extent: "
			  "item_index %u, err %d\n",
			  item_index, err);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	seg_id = le64_to_cpu(extent.seg_id);
	logical_blk = le32_to_cpu(extent.logical_blk);
	len = le32_to_cpu(extent.len);

	start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						    logical_blk);
	end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						  logical_blk + len - 1);

	if (search->request.end.hash < start_hash)
		direction = SSDFS_SEARCH_LEFT_DIRECTION;
	else if (end_hash < search->request.start.hash)
		direction = SSDFS_SEARCH_RIGHT_DIRECTION;
	else
		direction = SSDFS_CORRECT_POSITION;

	SSDFS_DBG("extent (start_hash %llx, end_hash %llx), "
		  "search (start_hash %llx, end_hash %llx), "
		  "direction %#x\n",
		  start_hash, end_hash,
		  search->request.start.hash,
		  search->request.end.hash,
		  direction);

	return direction;
}

/*
 * ssdfs_find_correct_position_from_left() - find position from the left
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to find a correct position of the extent
 * from the left side of extents' sequence in the node.
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
	struct ssdfs_fs_info *fsi;
	struct ssdfs_raw_extent extent;
	int item_index;
	u64 seg_id;
	u32 logical_blk;
	u64 start_hash;
	u32 req_flags;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	if (item_index >= area->items_count) {
		if (area->items_count == 0)
			item_index = area->items_count;
		else
			item_index = area->items_count - 1;

		search->result.start_index = (u16)item_index;
		return 0;
	}

	req_flags = search->request.flags;

	for (; item_index >= 0; item_index--) {
		err = ssdfs_invextree_node_get_extent(node, area,
							(u16)item_index,
							&extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the extent: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		seg_id = le64_to_cpu(extent.seg_id);
		logical_blk = le32_to_cpu(extent.logical_blk);

		start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
							    logical_blk);

		if (search->request.start.hash == start_hash) {
			search->result.start_index = (u16)item_index;
			return 0;
		} else if (start_hash < search->request.start.hash) {
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
 * This method tries to find a correct position of the extent
 * from the right side of extents' sequence in the node.
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
	struct ssdfs_fs_info *fsi;
	struct ssdfs_raw_extent extent;
	int item_index;
	u64 seg_id;
	u32 logical_blk;
	u64 start_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	item_index = search->result.start_index;
	if ((item_index + search->request.count) >= area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	if (item_index >= area->items_count) {
		if (area->items_count == 0)
			item_index = area->items_count;
		else
			item_index = area->items_count - 1;

		search->result.start_index = (u16)item_index;

		return 0;
	}

	for (; item_index < area->items_count; item_index++) {
		err = ssdfs_invextree_node_get_extent(node, area,
							(u16)item_index,
							&extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the extent: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		seg_id = le64_to_cpu(extent.seg_id);
		logical_blk = le32_to_cpu(extent.logical_blk);

		start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
							    logical_blk);

		if (search->request.start.hash == start_hash) {
			search->result.start_index = (u16)item_index;
			return 0;
		} else if (search->request.end.hash < start_hash) {
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

	search->result.start_index = area->items_count;
	return 0;
}

/*
 * ssdfs_clean_lookup_table() - clean unused space of lookup table
 * @node: pointer on node object
 * @area: items area descriptor
 * @start_index: starting index
 *
 * This method tries to clean the unused space of lookup table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_clean_lookup_table(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_node_items_area *area,
			     u16 start_index)
{
	__le64 *lookup_table;
	u16 lookup_index;
	u16 item_index;
	u16 items_count;
	u16 items_capacity;
	u16 cleaning_indexes;
	u32 cleaning_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, start_index %u\n",
		  node->node_id, start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	items_capacity = node->items_area.items_capacity;
	if (start_index >= items_capacity) {
		SSDFS_DBG("start_index %u >= items_capacity %u\n",
			  start_index, items_capacity);
		return 0;
	}

	lookup_table = node->raw.invextree_header.lookup_table;

	lookup_index = ssdfs_convert_item2lookup_index(node->node_size,
						       start_index);
	if (unlikely(lookup_index >= SSDFS_INVEXTREE_LOOKUP_TABLE_SIZE)) {
		SSDFS_ERR("invalid lookup_index %u\n",
			  lookup_index);
		return -ERANGE;
	}

	items_count = node->items_area.items_count;
	item_index = ssdfs_convert_lookup2item_index(node->node_size,
						     lookup_index);
	if (unlikely(item_index >= items_capacity)) {
		SSDFS_ERR("item_index %u >= items_capacity %u\n",
			  item_index, items_capacity);
		return -ERANGE;
	}

	if (item_index != start_index)
		lookup_index++;

	cleaning_indexes = SSDFS_INVEXTREE_LOOKUP_TABLE_SIZE - lookup_index;
	cleaning_bytes = cleaning_indexes * sizeof(__le64);

	SSDFS_DBG("lookup_index %u, cleaning_indexes %u, cleaning_bytes %u\n",
		  lookup_index, cleaning_indexes, cleaning_bytes);

	memset(&lookup_table[lookup_index], 0xFF, cleaning_bytes);

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
	struct ssdfs_fs_info *fsi;
	__le64 *lookup_table;
	struct ssdfs_raw_extent extent;
	u64 seg_id;
	u32 logical_blk;
	u64 hash;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (range_len == 0) {
		SSDFS_DBG("range_len == 0\n");
		return 0;
	}

	lookup_table = node->raw.invextree_header.lookup_table;

	for (i = 0; i < range_len; i++) {
		int item_index = start_index + i;
		u16 lookup_index;

		if (is_hash_for_lookup_table(node->node_size, item_index)) {
			lookup_index =
				ssdfs_convert_item2lookup_index(node->node_size,
								item_index);

			err = ssdfs_invextree_node_get_extent(node,
								area,
								item_index,
								&extent);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract extent: "
					  "item_index %d, err %d\n",
					  item_index, err);
				return err;
			}

			seg_id = le64_to_cpu(extent.seg_id);
			logical_blk = le32_to_cpu(extent.logical_blk);

			hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
							      logical_blk);

			lookup_table[lookup_index] = hash;
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

	SSDFS_DBG("node_id %u\n", node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

	lookup_table = node->raw.invextree_header.lookup_table;
	memset(lookup_table, 0xFF,
		sizeof(__le64) * SSDFS_INVEXTREE_LOOKUP_TABLE_SIZE);
}

/*
 * ssdfs_show_extent_items() - show invalidated extent items
 * @node: pointer on node object
 * @items_area: items area descriptor
 */
static inline
void ssdfs_show_extent_items(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_node_items_area *items_area)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_raw_extent extent;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u64 start_hash;
	u64 end_hash;
	int i;
	int err;

	fsi = node->tree->fsi;

	for (i = 0; i < items_area->items_count; i++) {
		err = ssdfs_invextree_node_get_extent(node,
						      items_area,
						      i,
						      &extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get invalidated extent item: "
				  "err %d\n", err);
			return;
		}

		seg_id = le64_to_cpu(extent.seg_id);
		logical_blk = le32_to_cpu(extent.logical_blk);
		len = le32_to_cpu(extent.len);

		start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
							    logical_blk);
		end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						    logical_blk + len - 1);

		SSDFS_ERR("index %d, seg_id %llu, logical_blk %u, len %u, "
			  "start_hash %llxm end_hash %llx\n",
			  i, seg_id, logical_blk, len,
			  start_hash, end_hash);
	}
}

/*
 * ssdfs_invextree_node_do_insert_range() - insert range into node
 * @tree: invalidated extents tree
 * @node: pointer on node object
 * @items_area: items area state
 * @search: search object [in|out]
 *
 * This method tries to insert the range of extents into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_invextree_node_do_insert_range(struct ssdfs_invextree_info *tree,
				struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *items_area,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_invextree_node_header *hdr;
	struct ssdfs_raw_extent extent;
	size_t item_size = sizeof(struct ssdfs_raw_extent);
	u16 item_index;
	u16 range_len;
	u32 used_space;
	u64 seg_id;
	u32 logical_blk;
	u16 extents_count = 0;
	u64 start_hash, end_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !node || !items_area || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	item_index = search->result.start_index;
	if ((item_index + search->request.count) > items_area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	range_len = items_area->items_count - search->result.start_index;
	extents_count = range_len + search->request.count;

	err = ssdfs_shift_range_right(node, items_area, item_size,
				      item_index, range_len,
				      search->request.count);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to shift dentries range: "
			  "start %u, count %u, err %d\n",
			  item_index, search->request.count,
			  err);
		return err;
	}

	ssdfs_debug_btree_node_object(node);

	err = ssdfs_generic_insert_range(node, items_area,
					 item_size, search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to insert item: err %d\n",
			  err);
		return err;
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

	SSDFS_DBG("items_capacity %u, items_count %u\n",
		  items_area->items_capacity,
		  items_area->items_count);

	used_space = (u32)search->request.count * item_size;
	if (used_space > node->items_area.free_space) {
		err = -ERANGE;
		SSDFS_ERR("used_space %u > free_space %u\n",
			  used_space,
			  node->items_area.free_space);
		goto finish_items_area_correction;
	}
	node->items_area.free_space -= used_space;

	err = ssdfs_invextree_node_get_extent(node,
					      &node->items_area,
					      0, &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		goto finish_items_area_correction;
	}

	seg_id = le64_to_cpu(extent.seg_id);
	logical_blk = le32_to_cpu(extent.logical_blk);

	start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						    logical_blk);

	err = ssdfs_invextree_node_get_extent(node,
					      &node->items_area,
					      node->items_area.items_count - 1,
					      &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		goto finish_items_area_correction;
	}

	seg_id = le64_to_cpu(extent.seg_id);
	logical_blk = le32_to_cpu(extent.logical_blk);

	end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						  logical_blk);

	if (start_hash >= U64_MAX || end_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		goto finish_items_area_correction;
	}

	SSDFS_DBG("BEFORE: node_id %u, start_hash %llx, end_hash %llx\n",
		  node->node_id,
		  node->items_area.start_hash,
		  node->items_area.end_hash);

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	SSDFS_DBG("AFTER: node_id %u, start_hash %llx, end_hash %llx\n",
		  node->node_id, start_hash, end_hash);

	err = ssdfs_correct_lookup_table(node, &node->items_area,
					 item_index, extents_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

	hdr = &node->raw.invextree_header;

	le32_add_cpu(&hdr->extents_count, search->request.count);
	atomic64_add(search->request.count, &tree->extents_count);

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

	return err;
}

/*
 * ssdfs_invextree_node_merge_range_left() - merge range with left extent
 * @tree: invalidated extents tree
 * @node: pointer on node object
 * @items_area: items area state
 * @search: search object [in|out]
 *
 * This method tries to merge a left extent with inserting range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_invextree_node_merge_range_left(struct ssdfs_invextree_info *tree,
				struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *items_area,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_invextree_node_header *hdr;
	struct ssdfs_raw_extent *prepared = NULL;
	struct ssdfs_raw_extent extent;
	size_t item_size = sizeof(struct ssdfs_raw_extent);
	u16 item_index;
	u16 range_len;
	u32 used_space;
	u64 seg_id;
	u32 logical_blk;
	u32 added_extents = 0;
	u16 extents_count = 0;
	u32 len;
	u64 start_hash, end_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !node || !items_area || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	item_index = search->result.start_index;
	if (item_index == 0) {
		SSDFS_ERR("there is no item from the left\n");
		return -ERANGE;
	}

	search->result.start_index--;

	item_index = search->result.start_index;
	if ((item_index + search->request.count) > items_area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	range_len = items_area->items_count - search->result.start_index;
	extents_count = range_len + search->request.count;

	prepared = (struct ssdfs_raw_extent *)search->result.buf;
	len = le32_to_cpu(prepared->len);

	err = ssdfs_invextree_node_get_extent(node,
					      items_area,
					      item_index - 1,
					      &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		return err;
	}

	le32_add_cpu(&extent.len, len);

	ssdfs_memcpy(search->result.buf, 0, search->result.buf_size,
		     &extent, 0, item_size,
		     item_size);

	added_extents = search->request.count - 1;

	if (search->request.count > 1) {
		err = ssdfs_shift_range_right(node, items_area, item_size,
					      item_index + 1, range_len - 1,
					      added_extents);
		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to shift dentries range: "
				  "start %u, count %u, err %d\n",
				  item_index, added_extents, err);
			return err;
		}
	}

	ssdfs_debug_btree_node_object(node);

	err = ssdfs_generic_insert_range(node, items_area,
					 item_size, search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to insert item: err %d\n",
			  err);
		return err;
	}

	down_write(&node->header_lock);

	if (search->request.count > 1) {
		node->items_area.items_count += added_extents;
		if (node->items_area.items_count >
					node->items_area.items_capacity) {
			err = -ERANGE;
			SSDFS_ERR("items_count %u > items_capacity %u\n",
				  node->items_area.items_count,
				  node->items_area.items_capacity);
			goto finish_items_area_correction;
		}

		SSDFS_DBG("items_capacity %u, items_count %u\n",
			  items_area->items_capacity,
			  items_area->items_count);

		used_space = added_extents * item_size;
		if (used_space > node->items_area.free_space) {
			err = -ERANGE;
			SSDFS_ERR("used_space %u > free_space %u\n",
				  used_space,
				  node->items_area.free_space);
			goto finish_items_area_correction;
		}
		node->items_area.free_space -= used_space;
	}

	err = ssdfs_invextree_node_get_extent(node,
					      &node->items_area,
					      0, &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		goto finish_items_area_correction;
	}

	seg_id = le64_to_cpu(extent.seg_id);
	logical_blk = le32_to_cpu(extent.logical_blk);

	start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						    logical_blk);

	err = ssdfs_invextree_node_get_extent(node,
					      &node->items_area,
					      node->items_area.items_count - 1,
					      &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		goto finish_items_area_correction;
	}

	seg_id = le64_to_cpu(extent.seg_id);
	logical_blk = le32_to_cpu(extent.logical_blk);

	end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						  logical_blk);

	if (start_hash >= U64_MAX || end_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		goto finish_items_area_correction;
	}

	SSDFS_DBG("BEFORE: node_id %u, start_hash %llx, end_hash %llx\n",
		  node->node_id,
		  node->items_area.start_hash,
		  node->items_area.end_hash);

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	SSDFS_DBG("AFTER: node_id %u, start_hash %llx, end_hash %llx\n",
		  node->node_id, start_hash, end_hash);

	err = ssdfs_correct_lookup_table(node, &node->items_area,
					 item_index, extents_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

	if (search->request.count > 1) {
		hdr = &node->raw.invextree_header;

		le32_add_cpu(&hdr->extents_count, added_extents);
		atomic64_add(added_extents, &tree->extents_count);
	}

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

	return err;
}

/*
 * ssdfs_invextree_node_merge_range_right() - merge range with right extent
 * @tree: invalidated extents tree
 * @node: pointer on node object
 * @items_area: items area state
 * @search: search object [in|out]
 *
 * This method tries to merge a right extent with inserting range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int ssdfs_invextree_node_merge_range_right(struct ssdfs_invextree_info *tree,
				struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *items_area,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_invextree_node_header *hdr;
	struct ssdfs_raw_extent extent;
	struct ssdfs_raw_extent *prepared = NULL;
	size_t item_size = sizeof(struct ssdfs_raw_extent);
	u16 item_index;
	u16 range_len;
	u32 used_space;
	u64 seg_id;
	u32 logical_blk;
	u32 offset;
	u32 len;
	u32 added_extents = 0;
	u16 extents_count = 0;
	u64 start_hash, end_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !node || !items_area || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	item_index = search->result.start_index + search->request.count - 1;
	if (item_index >= items_area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, items_capacity %u\n",
			  item_index, items_area->items_capacity);
		return -ERANGE;
	}

	range_len = items_area->items_count - search->result.start_index;
	extents_count = range_len + search->request.count;

	offset = (search->result.items_in_buffer - 1) *
			sizeof(struct ssdfs_raw_extent);

	prepared =
		(struct ssdfs_raw_extent *)((u8 *)search->result.buf + offset);
	len = le32_to_cpu(prepared->len);

	err = ssdfs_invextree_node_get_extent(node,
						items_area,
						item_index,
						&extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		return err;
	}

	extent.logical_blk = prepared->logical_blk;
	le32_add_cpu(&extent.len, len);

	ssdfs_memcpy(search->result.buf, offset, search->result.buf_size,
		     &extent, 0, item_size,
		     item_size);

	item_index = search->result.start_index + 1;
	added_extents = search->request.count - 1;

	if (search->request.count > 1) {
		err = ssdfs_shift_range_right(node, items_area, item_size,
					      item_index, range_len - 1,
					      added_extents);
		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to shift dentries range: "
				  "start %u, count %u, err %d\n",
				  item_index, added_extents, err);
			return err;
		}
	}

	ssdfs_debug_btree_node_object(node);

	err = ssdfs_generic_insert_range(node, items_area,
					 item_size, search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to insert item: err %d\n",
			  err);
		return err;
	}

	down_write(&node->header_lock);

	if (search->request.count > 1) {
		node->items_area.items_count += added_extents;
		if (node->items_area.items_count >
					node->items_area.items_capacity) {
			err = -ERANGE;
			SSDFS_ERR("items_count %u > items_capacity %u\n",
				  node->items_area.items_count,
				  node->items_area.items_capacity);
			goto finish_items_area_correction;
		}

		SSDFS_DBG("items_capacity %u, items_count %u\n",
			  items_area->items_capacity,
			  items_area->items_count);

		used_space = added_extents * item_size;
		if (used_space > node->items_area.free_space) {
			err = -ERANGE;
			SSDFS_ERR("used_space %u > free_space %u\n",
				  used_space,
				  node->items_area.free_space);
			goto finish_items_area_correction;
		}
		node->items_area.free_space -= used_space;
	}

	err = ssdfs_invextree_node_get_extent(node,
					      &node->items_area,
					      0, &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		goto finish_items_area_correction;
	}

	seg_id = le64_to_cpu(extent.seg_id);
	logical_blk = le32_to_cpu(extent.logical_blk);

	start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						    logical_blk);

	err = ssdfs_invextree_node_get_extent(node,
					      &node->items_area,
					      node->items_area.items_count - 1,
					      &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		goto finish_items_area_correction;
	}

	seg_id = le64_to_cpu(extent.seg_id);
	logical_blk = le32_to_cpu(extent.logical_blk);

	end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						  logical_blk);

	if (start_hash >= U64_MAX || end_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		goto finish_items_area_correction;
	}

	SSDFS_DBG("BEFORE: node_id %u, start_hash %llx, end_hash %llx\n",
		  node->node_id,
		  node->items_area.start_hash,
		  node->items_area.end_hash);

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	SSDFS_DBG("AFTER: node_id %u, start_hash %llx, end_hash %llx\n",
		  node->node_id, start_hash, end_hash);

	err = ssdfs_correct_lookup_table(node, &node->items_area,
					 item_index, extents_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

	if (search->request.count > 1) {
		hdr = &node->raw.invextree_header;

		le32_add_cpu(&hdr->extents_count, added_extents);
		atomic64_add(added_extents, &tree->extents_count);
	}

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

	return err;
}

/*
 * ssdfs_invextree_node_merge_left_and_right() - merge range with neighbours
 * @tree: invalidated extents tree
 * @node: pointer on node object
 * @items_area: items area state
 * @search: search object [in|out]
 *
 * This method tries to merge inserting range with left and right extents.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static int
ssdfs_invextree_node_merge_left_and_right(struct ssdfs_invextree_info *tree,
				struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *items_area,
				struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_invextree_node_header *hdr;
	struct ssdfs_raw_extent extent;
	struct ssdfs_raw_extent *prepared = NULL;
	size_t item_size = sizeof(struct ssdfs_raw_extent);
	u16 item_index;
	u16 range_len;
	u32 used_space;
	u64 seg_id;
	u32 logical_blk;
	u32 offset;
	u32 len;
	int added_extents = 0;
	u16 extents_count = 0;
	u64 start_hash, end_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !node || !items_area || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	item_index = search->result.start_index;
	if ((item_index + search->request.count) > items_area->items_capacity) {
		SSDFS_ERR("invalid request: "
			  "item_index %u, count %u\n",
			  item_index, search->request.count);
		return -ERANGE;
	}

	prepared = (struct ssdfs_raw_extent *)search->result.buf;
	len = le32_to_cpu(prepared->len);

	if (item_index == 0) {
		SSDFS_ERR("there is no item from the left\n");
		return -ERANGE;
	}

	err = ssdfs_invextree_node_get_extent(node,
					      items_area,
					      item_index - 1,
					      &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		return err;
	}

	le32_add_cpu(&extent.len, len);

	ssdfs_memcpy(search->result.buf, 0, search->result.buf_size,
		     &extent, 0, item_size,
		     item_size);

	item_index = search->result.start_index + search->request.count - 1;

	offset = (search->result.items_in_buffer - 1) *
			sizeof(struct ssdfs_raw_extent);

	prepared =
		(struct ssdfs_raw_extent *)((u8 *)search->result.buf + offset);
	len = le32_to_cpu(prepared->len);

	err = ssdfs_invextree_node_get_extent(node,
						items_area,
						item_index,
						&extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		return err;
	}

	if (search->request.count > 1)
		extent.logical_blk = prepared->logical_blk;

	le32_add_cpu(&extent.len, len);

	ssdfs_memcpy(search->result.buf, offset, search->result.buf_size,
		     &extent, 0, item_size,
		     item_size);

	range_len = items_area->items_count - search->result.start_index;
	extents_count = range_len + search->request.count;
	added_extents = search->request.count - 2;

	if (search->request.count <= 0) {
		SSDFS_ERR("invalid request count %d\n",
			  search->request.count);
		return -ERANGE;
	} else if (search->request.count == 1) {
		err = ssdfs_shift_range_left(node, items_area, item_size,
					     item_index, range_len,
					     search->request.count);
		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to shift dentries range: "
				  "start %u, count %u, err %d\n",
				  item_index, search->request.count, err);
			return err;
		}

		item_index = search->result.start_index - 1;
	} else if (search->request.count == 2) {
		/* no shift */
		item_index = search->result.start_index - 1;
	} else {
		item_index = search->result.start_index + 1;

		err = ssdfs_shift_range_right(node, items_area, item_size,
					      item_index, range_len - 1,
					      added_extents);
		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to shift dentries range: "
				  "start %u, count %u, err %d\n",
				  item_index, added_extents, err);
			return err;
		}

		item_index = search->result.start_index - 1;
	}

	ssdfs_debug_btree_node_object(node);

	err = ssdfs_generic_insert_range(node, items_area,
					 item_size, search);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to insert item: err %d\n",
			  err);
		return err;
	}

	down_write(&node->header_lock);

	if (search->request.count <= 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid request count %d\n",
			  search->request.count);
		goto finish_items_area_correction;
	} else if (search->request.count == 1) {
		if (node->items_area.items_count == 0) {
			err = -ERANGE;
			SSDFS_ERR("node's items area is empty\n");
			goto finish_items_area_correction;
		}

		/* two items are exchanged on one */
		node->items_area.items_count--;

		SSDFS_DBG("items_capacity %u, items_count %u\n",
			  items_area->items_capacity,
			  items_area->items_count);

		node->items_area.free_space += item_size;
	} else if (search->request.count == 2) {
		/*
		 * Nothing has been added.
		 */
	} else {
		node->items_area.items_count += added_extents;
		if (node->items_area.items_count >
					node->items_area.items_capacity) {
			err = -ERANGE;
			SSDFS_ERR("items_count %u > items_capacity %u\n",
				  node->items_area.items_count,
				  node->items_area.items_capacity);
			goto finish_items_area_correction;
		}

		SSDFS_DBG("items_capacity %u, items_count %u\n",
			  items_area->items_capacity,
			  items_area->items_count);

		used_space = added_extents * item_size;
		if (used_space > node->items_area.free_space) {
			err = -ERANGE;
			SSDFS_ERR("used_space %u > free_space %u\n",
				  used_space,
				  node->items_area.free_space);
			goto finish_items_area_correction;
		}
		node->items_area.free_space -= used_space;
	}

	err = ssdfs_invextree_node_get_extent(node,
					      &node->items_area,
					      0, &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		goto finish_items_area_correction;
	}

	seg_id = le64_to_cpu(extent.seg_id);
	logical_blk = le32_to_cpu(extent.logical_blk);

	start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						    logical_blk);

	err = ssdfs_invextree_node_get_extent(node,
					      &node->items_area,
					      node->items_area.items_count - 1,
					      &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		goto finish_items_area_correction;
	}

	seg_id = le64_to_cpu(extent.seg_id);
	logical_blk = le32_to_cpu(extent.logical_blk);

	end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						  logical_blk);

	if (start_hash >= U64_MAX || end_hash >= U64_MAX) {
		err = -ERANGE;
		SSDFS_ERR("start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		goto finish_items_area_correction;
	}

	SSDFS_DBG("BEFORE: node_id %u, start_hash %llx, end_hash %llx\n",
		  node->node_id,
		  node->items_area.start_hash,
		  node->items_area.end_hash);

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	SSDFS_DBG("AFTER: node_id %u, start_hash %llx, end_hash %llx\n",
		  node->node_id, start_hash, end_hash);

	err = ssdfs_correct_lookup_table(node, &node->items_area,
					 item_index, extents_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

	if (search->request.count == 1) {
		hdr = &node->raw.invextree_header;

		le32_add_cpu(&hdr->extents_count, added_extents);
		atomic64_add(added_extents, &tree->extents_count);
	} else if (search->request.count == 2) {
		/*
		 * Nothing has been added.
		 */
	} else {
		hdr = &node->raw.invextree_header;

		le32_add_cpu(&hdr->extents_count, added_extents);
		atomic64_add(added_extents, &tree->extents_count);
	}

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

	return err;
}

/*
 * __ssdfs_invextree_node_insert_range() - insert range into node
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to insert the range of extents into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int __ssdfs_invextree_node_insert_range(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree *tree;
	struct ssdfs_invextree_info *tree_info;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_raw_extent found;
	struct ssdfs_raw_extent *prepared = NULL;
	size_t item_size = sizeof(struct ssdfs_raw_extent);
	u64 old_hash;
	u64 start_hash = U64_MAX, end_hash = U64_MAX;
	u64 cur_hash;
	u16 item_index;
	int free_items;
	u16 range_len;
	u16 extents_count = 0;
	u64 seg_id1, seg_id2;
	u32 logical_blk1, logical_blk2;
	u32 len;
	int direction;
	bool need_merge_with_left = false;
	bool need_merge_with_right = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
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

	tree = node->tree;
	fsi = tree->fsi;

	switch (tree->type) {
	case SSDFS_INVALIDATED_EXTENTS_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	tree_info = container_of(tree,
				 struct ssdfs_invextree_info,
				 generic_tree);

	down_read(&node->header_lock);
	ssdfs_memcpy(&items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     &node->items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     sizeof(struct ssdfs_btree_node_items_area));
	old_hash = node->items_area.start_hash;
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

	SSDFS_DBG("items_capacity %u, items_count %u\n",
		  items_area.items_capacity,
		  items_area.items_count);
	SSDFS_DBG("items_area: start_hash %llx, end_hash %llx\n",
		  items_area.start_hash, items_area.end_hash);
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

	if (((u64)free_items * item_size) > items_area.free_space) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("invalid free_items: "
			  "free_items %d, item_size %zu, free_space %u\n",
			  free_items, item_size, items_area.free_space);
		return -EFAULT;
	}

	item_index = search->result.start_index;
	if ((item_index + search->request.count) > items_area.items_capacity) {
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
	extents_count = range_len + search->request.count;

	item_index = search->result.start_index;
	if ((item_index + extents_count) > items_area.items_capacity) {
		err = -ERANGE;
		SSDFS_ERR("invalid snapshots_count: "
			  "item_index %u, extents_count %u, "
			  "items_capacity %u\n",
			  item_index, extents_count,
			  items_area.items_capacity);
		goto finish_detect_affected_items;
	}

	if (items_area.items_count == 0)
		goto lock_items_range;

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (item_index > 0) {
		err = ssdfs_invextree_node_get_extent(node,
						      &items_area,
						      item_index - 1,
						      &found);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_detect_affected_items;
		}

		seg_id1 = le64_to_cpu(found.seg_id);
		logical_blk1 = le32_to_cpu(found.logical_blk);
		len = le32_to_cpu(found.len);

		cur_hash = ssdfs_invextree_calculate_hash(fsi, seg_id1,
						    logical_blk1 + len - 1);

		if (cur_hash < start_hash) {
			prepared =
				(struct ssdfs_raw_extent *)search->result.buf;

			seg_id2 = le64_to_cpu(prepared->seg_id);
			logical_blk2 = le32_to_cpu(prepared->logical_blk);

			if (seg_id1 == seg_id2 &&
			    (logical_blk1 + len) == logical_blk2) {
				/*
				 * Left and prepared extents need to be merged
				 */
				need_merge_with_left = true;
			}
		} else {
			SSDFS_ERR("invalid range: item_index %u, "
				  "cur_hash %llx, "
				  "start_hash %llx, end_hash %llx\n",
				  item_index, cur_hash,
				  start_hash, end_hash);

			ssdfs_show_extent_items(node, &items_area);

			err = -ERANGE;
			goto finish_detect_affected_items;
		}
	}

	if (item_index < items_area.items_count) {
		err = ssdfs_invextree_node_get_extent(node,
						      &items_area,
						      item_index,
						      &found);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_detect_affected_items;
		}

		seg_id1 = le64_to_cpu(found.seg_id);
		logical_blk1 = le32_to_cpu(found.logical_blk);

		cur_hash = ssdfs_invextree_calculate_hash(fsi, seg_id1,
							  logical_blk1);

		if (end_hash < cur_hash) {
			prepared =
				(struct ssdfs_raw_extent *)search->result.buf;
			prepared += search->result.items_in_buffer - 1;

			seg_id2 = le64_to_cpu(prepared->seg_id);
			logical_blk2 = le32_to_cpu(prepared->logical_blk);
			len = le32_to_cpu(prepared->len);

			if (seg_id1 == seg_id2 &&
			    (logical_blk2 + len) == logical_blk1) {
				/*
				 * Right and prepared extents need to be merged
				 */
				need_merge_with_right = true;
			}
		} else {
			SSDFS_ERR("invalid range: item_index %u, "
				  "cur_hash %llx, "
				  "start_hash %llx, end_hash %llx\n",
				  item_index, cur_hash,
				  start_hash, end_hash);

			ssdfs_show_extent_items(node, &items_area);

			err = -ERANGE;
			goto finish_detect_affected_items;
		}
	}

	if (need_merge_with_left) {
		item_index -= 1;
		search->result.start_index = item_index;

		range_len = items_area.items_count - search->result.start_index;
		extents_count = range_len + search->request.count;
	}

lock_items_range:
	err = ssdfs_lock_items_range(node, item_index, extents_count);
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

	if (need_merge_with_left && need_merge_with_right) {
		err = ssdfs_invextree_node_merge_left_and_right(tree_info,
								node,
								&items_area,
								search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert range: err %d\n", err);
			goto unlock_items_range;
		}
	} else if (need_merge_with_left) {
		err = ssdfs_invextree_node_merge_range_left(tree_info,
							    node,
							    &items_area,
							    search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert range: err %d\n", err);
			goto unlock_items_range;
		}
	} else if (need_merge_with_right) {
		err = ssdfs_invextree_node_merge_range_right(tree_info,
							     node,
							     &items_area,
							     search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert range: err %d\n", err);
			goto unlock_items_range;
		}
	} else {
		err = ssdfs_invextree_node_do_insert_range(tree_info, node,
							   &items_area,
							   search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to insert range: err %d\n", err);
			goto unlock_items_range;
		}
	}

	err = ssdfs_set_node_header_dirty(node, items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto unlock_items_range;
	}

	err = ssdfs_set_dirty_items_range(node, items_area.items_capacity,
					  item_index, extents_count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  item_index, extents_count, err);
		goto unlock_items_range;
	}

unlock_items_range:
	ssdfs_unlock_items_range(node, item_index, extents_count);

finish_insert_item:
	up_read(&node->full_lock);

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		if (items_area.items_count == 0) {
			struct ssdfs_btree_index_key key;

			spin_lock(&node->descriptor_lock);
			ssdfs_memcpy(&key,
				     0, sizeof(struct ssdfs_btree_index_key),
				     &node->node_index,
				     0, sizeof(struct ssdfs_btree_index_key),
				     sizeof(struct ssdfs_btree_index_key));
			spin_unlock(&node->descriptor_lock);

			key.index.hash = cpu_to_le64(start_hash);

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
		} else if (old_hash != start_hash) {
			struct ssdfs_btree_index_key old_key, new_key;

			spin_lock(&node->descriptor_lock);
			ssdfs_memcpy(&old_key,
				     0, sizeof(struct ssdfs_btree_index_key),
				     &node->node_index,
				     0, sizeof(struct ssdfs_btree_index_key),
				     sizeof(struct ssdfs_btree_index_key));
			ssdfs_memcpy(&new_key,
				     0, sizeof(struct ssdfs_btree_index_key),
				     &node->node_index,
				     0, sizeof(struct ssdfs_btree_index_key),
				     sizeof(struct ssdfs_btree_index_key));
			spin_unlock(&node->descriptor_lock);

			old_key.index.hash = cpu_to_le64(old_hash);
			new_key.index.hash = cpu_to_le64(start_hash);

			err = ssdfs_btree_node_change_index(node,
							&old_key, &new_key);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change index: err %d\n",
					  err);
				return err;
			}
		}
		break;

	default:
		/* do nothing */
		break;
	}

	ssdfs_debug_btree_node_object(node);

	return err;
}

/*
 * ssdfs_invextree_node_insert_item() - insert item in the node
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
int ssdfs_invextree_node_insert_item(struct ssdfs_btree_node *node,
				     struct ssdfs_btree_search *search)
{
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

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
#endif /* CONFIG_SSDFS_DEBUG */

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
		search->result.err = 0;
		/*
		 * Node doesn't contain requested item.
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

	err = __ssdfs_invextree_node_insert_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert item: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	SSDFS_DBG("free_space %u\n", node->items_area.free_space);

	return 0;
}

/*
 * ssdfs_invextree_node_insert_range() - insert range of items
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
int ssdfs_invextree_node_insert_range(struct ssdfs_btree_node *node,
				      struct ssdfs_btree_search *search)
{
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

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
#endif /* CONFIG_SSDFS_DEBUG */

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
	BUG_ON(search->result.count < 1);
	BUG_ON(!search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = __ssdfs_invextree_node_insert_range(node, search);
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
 * ssdfs_change_item_only() - change snapshot in the node
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
	struct ssdfs_fs_info *fsi;
	struct ssdfs_raw_extent extent;
	size_t item_size = sizeof(struct ssdfs_raw_extent);
	u16 range_len;
	u16 item_index;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u64 start_hash, end_hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

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

	err = ssdfs_invextree_node_get_extent(node, area, item_index, &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
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
		err = ssdfs_invextree_node_get_extent(node,
						      &node->items_area,
						      item_index,
						      &extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_items_area_correction;
		}

		seg_id = le64_to_cpu(extent.seg_id);
		logical_blk = le32_to_cpu(extent.logical_blk);

		start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
							    logical_blk);
	}

	if ((item_index + range_len) == node->items_area.items_count) {
		err = ssdfs_invextree_node_get_extent(node,
						    &node->items_area,
						    item_index + range_len - 1,
						    &extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_items_area_correction;
		}

		seg_id = le64_to_cpu(extent.seg_id);
		logical_blk = le32_to_cpu(extent.logical_blk);
		len = le32_to_cpu(extent.len);

		end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						    logical_blk + len - 1);
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

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

	return err;
}

/*
 * ssdfs_invextree_node_change_item() - change item in the node
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
int ssdfs_invextree_node_change_item(struct ssdfs_btree_node *node,
				     struct ssdfs_btree_search *search)
{
	struct ssdfs_btree_node_items_area items_area;
	size_t item_size = sizeof(struct ssdfs_raw_extent);
	u16 item_index;
	int direction;
	u16 range_len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

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
	ssdfs_memcpy(&items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     &node->items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
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
		/* expected type */
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

	err = ssdfs_change_item_only(node, &items_area, search);
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

	ssdfs_debug_btree_node_object(node);

	return err;
}

/*
 * __ssdfs_invalidate_items_area() - invalidate the items area
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @start_index: starting index of the item
 * @range_len: number of items in the range
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
	struct ssdfs_btree_node *parent = NULL;
	bool is_hybrid = false;
	bool has_index_area = false;
	bool index_area_empty = false;
	bool items_area_empty = false;
	int parent_type = SSDFS_BTREE_LEAF_NODE;
	spinlock_t  *lock;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);
#endif /* CONFIG_SSDFS_DEBUG */

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

	down_write(&node->header_lock);

	switch (atomic_read(&node->items_area.state)) {
	case SSDFS_BTREE_NODE_ITEMS_AREA_EXIST:
		if (node->items_area.items_count == range_len)
			items_area_empty = true;
		else
			items_area_empty = false;
		break;

	default:
		items_area_empty = false;
		break;
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
		} else if (items_area_empty) {
			search->result.state =
				SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE;
		} else {
			search->result.state =
				SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_ALL:
		search->result.state =
			SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;

		parent = node;

		do {
			lock = &parent->descriptor_lock;
			spin_lock(lock);
			parent = parent->parent_node;
			spin_unlock(lock);
			lock = NULL;

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

	SSDFS_DBG("node_id %u, area %p, search %p\n",
		  node->node_id, area, search);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_invalidate_items_area(node, area,
					     0, area->items_count,
					     search);
}

/*
 * ssdfs_invalidate_items_area_partially() - invalidate the items area
 * @node: pointer on node object
 * @area: pointer on items area's descriptor
 * @start_index: starting index
 * @range_len: number of items in the range
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

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_invalidate_items_area(node, area,
					     start_index, range_len,
					     search);
}

/*
 * __ssdfs_invextree_node_delete_range() - delete range of items
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
int __ssdfs_invextree_node_delete_range(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree *tree;
	struct ssdfs_invextree_info *tree_info;
	struct ssdfs_invextree_node_header *hdr;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_raw_extent extent;
	size_t item_size = sizeof(struct ssdfs_raw_extent);
	u16 index_count = 0;
	int free_items;
	u16 item_index;
	int direction;
	u16 range_len;
	u16 shift_range_len = 0;
	u16 locked_len = 0;
	u32 deleted_space, free_space;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u64 start_hash = U64_MAX;
	u64 end_hash = U64_MAX;
	u64 old_hash;
	u32 old_extents_count = 0, extents_count = 0;
	u32 extents_diff;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

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
	case SSDFS_INVALIDATED_EXTENTS_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	tree_info = container_of(tree,
				 struct ssdfs_invextree_info,
				 generic_tree);

	down_read(&node->header_lock);
	ssdfs_memcpy(&items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     &node->items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     sizeof(struct ssdfs_btree_node_items_area));
	old_hash = node->items_area.start_hash;
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

	extents_count = items_area.items_count;
	item_index = search->result.start_index;

	range_len = search->request.count;
	if (range_len == 0) {
		SSDFS_ERR("range_len == 0\n");
		return -ERANGE;
	}

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		if ((item_index + range_len) > items_area.items_count) {
			SSDFS_ERR("invalid request: "
				  "item_index %u, range_len %u, "
				  "items_count %u\n",
				  item_index, range_len,
				  items_area.items_count);
			return -ERANGE;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
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
			SSDFS_ERR("invalid dentries_count: "
				  "item_index %u, dentries_count %u, "
				  "items_count %u\n",
				  item_index, range_len,
				  items_area.items_count);
			goto finish_detect_affected_items;
		}
		break;

	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
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

	err = ssdfs_btree_node_clear_range(node, &node->items_area,
					   item_size, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to clear items range: err %d\n",
			  err);
		goto finish_delete_range;
	}

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

	shift_range_len = locked_len - range_len;
	if (shift_range_len != 0) {
		err = ssdfs_shift_range_left(node, &items_area, item_size,
					     item_index + range_len,
					     shift_range_len, range_len);
		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to shift the range: "
				  "start %u, count %u, err %d\n",
				  item_index + range_len,
				  shift_range_len,
				  err);
			goto finish_delete_range;
		}

		err = __ssdfs_btree_node_clear_range(node,
						&items_area, item_size,
						item_index + shift_range_len,
						range_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to clear range: "
				  "start %u, count %u, err %d\n",
				  item_index + range_len,
				  shift_range_len,
				  err);
			goto finish_delete_range;
		}
	}

	down_write(&node->header_lock);

	SSDFS_DBG("INITIAL STATE: node_id %u, "
		  "items_count %u, free_space %u\n",
		  node->node_id,
		  node->items_area.items_count,
		  node->items_area.free_space);

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

	SSDFS_DBG("NEW STATE: node_id %u, "
		  "items_count %u, free_space %u\n",
		  node->node_id,
		  node->items_area.items_count,
		  node->items_area.free_space);

	if (node->items_area.items_count == 0) {
		start_hash = U64_MAX;
		end_hash = U64_MAX;
	} else {
		err = ssdfs_invextree_node_get_extent(node,
						      &node->items_area,
						      0, &extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_items_area_correction;
		}

		seg_id = le64_to_cpu(extent.seg_id);
		logical_blk = le32_to_cpu(extent.logical_blk);

		start_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
							    logical_blk);

		err = ssdfs_invextree_node_get_extent(node,
					&node->items_area,
					node->items_area.items_count - 1,
					&extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_items_area_correction;
		}

		seg_id = le64_to_cpu(extent.seg_id);
		logical_blk = le32_to_cpu(extent.logical_blk);
		len = le32_to_cpu(extent.len);

		end_hash = ssdfs_invextree_calculate_hash(fsi, seg_id,
						    logical_blk + len - 1);
	}

	SSDFS_DBG("BEFORE: node_id %u, items_area.start_hash %llx, "
		  "items_area.end_hash %llx\n",
		  node->node_id,
		  node->items_area.start_hash,
		  node->items_area.end_hash);

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

	SSDFS_DBG("AFTER: node_id %u, items_area.start_hash %llx, "
		  "items_area.end_hash %llx\n",
		  node->node_id,
		  node->items_area.start_hash,
		  node->items_area.end_hash);

	if (node->items_area.items_count == 0)
		ssdfs_initialize_lookup_table(node);
	else {
		err = ssdfs_clean_lookup_table(node,
						&node->items_area,
						node->items_area.items_count);
		if (unlikely(err)) {
			SSDFS_ERR("fail to clean the rest of lookup table: "
				  "start_index %u, err %d\n",
				  node->items_area.items_count, err);
			goto finish_items_area_correction;
		}

		if (shift_range_len != 0) {
			int start_index =
				node->items_area.items_count - shift_range_len;

			if (start_index < 0) {
				err = -ERANGE;
				SSDFS_ERR("invalid start_index %d\n",
					  start_index);
				goto finish_items_area_correction;
			}

			err = ssdfs_correct_lookup_table(node,
						&node->items_area,
						start_index,
						shift_range_len);
			if (unlikely(err)) {
				SSDFS_ERR("fail to correct lookup table: "
					  "err %d\n", err);
				goto finish_items_area_correction;
			}
		}
	}

	hdr = &node->raw.invextree_header;

	old_extents_count = le32_to_cpu(hdr->extents_count);

	if (node->items_area.items_count == 0) {
		hdr->extents_count = cpu_to_le32(0);
	} else {
		if (old_extents_count < search->request.count) {
			hdr->extents_count = cpu_to_le32(0);
		} else {
			extents_count = le32_to_cpu(hdr->extents_count);
			extents_count -= search->request.count;
			hdr->extents_count = cpu_to_le32(extents_count);
		}
	}

	extents_count = le32_to_cpu(hdr->extents_count);
	extents_diff = old_extents_count - extents_count;
	atomic64_sub(extents_diff, &tree_info->extents_count);

	ssdfs_memcpy(&items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     &node->items_area,
		     0, sizeof(struct ssdfs_btree_node_items_area),
		     sizeof(struct ssdfs_btree_node_items_area));

	err = ssdfs_set_node_header_dirty(node, items_area.items_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set header dirty: err %d\n",
			  err);
		goto finish_items_area_correction;
	}

	if (extents_count != 0) {
		err = ssdfs_set_dirty_items_range(node,
					items_area.items_capacity,
					item_index,
					old_extents_count - item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set items range as dirty: "
				  "start %u, count %u, err %d\n",
				  item_index,
				  old_extents_count - item_index,
				  err);
			goto finish_items_area_correction;
		}
	}

finish_items_area_correction:
	up_write(&node->header_lock);

	if (unlikely(err))
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);

finish_delete_range:
	ssdfs_unlock_items_range(node, item_index, locked_len);
	up_read(&node->full_lock);

	if (unlikely(err))
		return err;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		if (extents_count == 0) {
			int state;

			down_read(&node->header_lock);
			state = atomic_read(&node->index_area.state);
			index_count = node->index_area.index_count;
			end_hash = node->index_area.end_hash;
			up_read(&node->header_lock);

			if (state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
				SSDFS_ERR("invalid area state %#x\n",
					  state);
				return -ERANGE;
			}

			SSDFS_DBG("index_count %u, end_hash %llx, "
				  "old_hash %llx\n",
				  index_count, end_hash, old_hash);

			if (index_count <= 1 || end_hash == old_hash) {
				err = ssdfs_btree_node_delete_index(node,
								    old_hash);
				if (unlikely(err)) {
					SSDFS_ERR("fail to delete index: "
						  "old_hash %llx, err %d\n",
						  old_hash, err);
					return err;
				}

				if (index_count > 0)
					index_count--;
			}
		} else if (old_hash != start_hash) {
			struct ssdfs_btree_index_key old_key, new_key;

			spin_lock(&node->descriptor_lock);
			ssdfs_memcpy(&old_key,
				     0, sizeof(struct ssdfs_btree_index_key),
				     &node->node_index,
				     0, sizeof(struct ssdfs_btree_index_key),
				     sizeof(struct ssdfs_btree_index_key));
			ssdfs_memcpy(&new_key,
				     0, sizeof(struct ssdfs_btree_index_key),
				     &node->node_index,
				     0, sizeof(struct ssdfs_btree_index_key),
				     sizeof(struct ssdfs_btree_index_key));
			spin_unlock(&node->descriptor_lock);

			old_key.index.hash = cpu_to_le64(old_hash);
			new_key.index.hash = cpu_to_le64(start_hash);

			err = ssdfs_btree_node_change_index(node,
							&old_key, &new_key);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change index: err %d\n",
					  err);
				return err;
			}
		}
		break;

	default:
		/* do nothing */
		break;
	}

	SSDFS_DBG("node_type %#x, extents_count %u, index_count %u\n",
		  atomic_read(&node->type),
		  extents_count, index_count);

	if (extents_count == 0 && index_count == 0)
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

	ssdfs_debug_btree_node_object(node);

	return 0;
}

/*
 * ssdfs_invextree_node_delete_item() - delete an item from node
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
int ssdfs_invextree_node_delete_item(struct ssdfs_btree_node *node,
				     struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p, "
		  "search->result.count %d\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child,
		  search->result.count);

	BUG_ON(search->result.count != 1);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_invextree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete extent: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_invextree_node_delete_range() - delete range of items from node
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
int ssdfs_invextree_node_delete_range(struct ssdfs_btree_node *node,
				      struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_invextree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete extents range: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_invextree_node_extract_range() - extract range of items from node
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
int ssdfs_invextree_node_extract_range(struct ssdfs_btree_node *node,
				       u16 start_index, u16 count,
				       struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_raw_extent *extent;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_index %u, count %u, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  start_index, count,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	down_read(&node->full_lock);
	err = __ssdfs_btree_node_extract_range(node, start_index, count,
						sizeof(struct ssdfs_raw_extent),
						search);
	up_read(&node->full_lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to extract a range: "
			  "start %u, count %u, err %d\n",
			  start_index, count, err);
		return err;
	}

	search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;

	extent = (struct ssdfs_raw_extent *)search->result.buf;

	seg_id = le64_to_cpu(extent->seg_id);
	logical_blk = le32_to_cpu(extent->logical_blk);
	search->request.start.hash =
		ssdfs_invextree_calculate_hash(fsi, seg_id,
						logical_blk);

	extent += search->result.count - 1;

	seg_id = le64_to_cpu(extent->seg_id);
	logical_blk = le32_to_cpu(extent->logical_blk);
	len = le32_to_cpu(extent->len);
	search->request.end.hash =
		ssdfs_invextree_calculate_hash(fsi, seg_id,
						logical_blk + len - 1);

	search->request.count = count;

	return 0;
}

/*
 * ssdfs_invextree_resize_items_area() - resize items area of the node
 * @node: node object
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
static
int ssdfs_invextree_resize_items_area(struct ssdfs_btree_node *node,
				      u32 new_size)
{
	struct ssdfs_fs_info *fsi;
	size_t item_size = sizeof(struct ssdfs_raw_extent);
	size_t index_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));

	SSDFS_DBG("node_id %u, new_size %u\n",
		  node->node_id, new_size);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;
	index_size = le16_to_cpu(fsi->vh->invextree.desc.index_size);

	err = __ssdfs_btree_node_resize_items_area(node,
						   item_size,
						   index_size,
						   new_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to resize items area: "
			  "node_id %u, new_size %u, err %d\n",
			  node->node_id, new_size, err);
		return err;
	}

	return 0;
}

void ssdfs_debug_invextree_object(struct ssdfs_invextree_info *tree)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);

	SSDFS_DBG("INVALIDATED EXTENTS TREE: state %#x, "
		  "extents_count %llu, is_locked %d, fsi %p\n",
		  atomic_read(&tree->state),
		  (u64)atomic64_read(&tree->extents_count),
		  rwsem_is_locked(&tree->lock),
		  tree->fsi);

	ssdfs_debug_btree_object(&tree->generic_tree);
#endif /* CONFIG_SSDFS_DEBUG */
}

const struct ssdfs_btree_descriptor_operations ssdfs_invextree_desc_ops = {
	.init		= ssdfs_invextree_desc_init,
	.flush		= ssdfs_invextree_desc_flush,
};

const struct ssdfs_btree_operations ssdfs_invextree_ops = {
	.create_root_node	= ssdfs_invextree_create_root_node,
	.create_node		= ssdfs_invextree_create_node,
	.init_node		= ssdfs_invextree_init_node,
	.destroy_node		= ssdfs_invextree_destroy_node,
	.add_node		= ssdfs_invextree_add_node,
	.delete_node		= ssdfs_invextree_delete_node,
	.pre_flush_root_node	= ssdfs_invextree_pre_flush_root_node,
	.flush_root_node	= ssdfs_invextree_flush_root_node,
	.pre_flush_node		= ssdfs_invextree_pre_flush_node,
	.flush_node		= ssdfs_invextree_flush_node,
};

const struct ssdfs_btree_node_operations ssdfs_invextree_node_ops = {
	.find_item		= ssdfs_invextree_node_find_item,
	.find_range		= ssdfs_invextree_node_find_range,
	.extract_range		= ssdfs_invextree_node_extract_range,
	.allocate_item		= ssdfs_invextree_node_allocate_item,
	.allocate_range		= ssdfs_invextree_node_allocate_range,
	.insert_item		= ssdfs_invextree_node_insert_item,
	.insert_range		= ssdfs_invextree_node_insert_range,
	.change_item		= ssdfs_invextree_node_change_item,
	.delete_item		= ssdfs_invextree_node_delete_item,
	.delete_range		= ssdfs_invextree_node_delete_range,
	.resize_items_area	= ssdfs_invextree_resize_items_area,
};
