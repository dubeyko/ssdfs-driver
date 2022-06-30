//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/shared_extents_tree.c - Shared extents tree implementation.
 *
 * Copyright (c) 2014-2022 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2022, HGST, Inc., All rights reserved.
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
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "segment_tree.h"
#include "shared_extents_tree.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_shextree_page_leaks;
atomic64_t ssdfs_shextree_memory_leaks;
atomic64_t ssdfs_shextree_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_shextree_cache_leaks_increment(void *kaddr)
 * void ssdfs_shextree_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_shextree_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_shextree_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_shextree_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_shextree_kfree(void *kaddr)
 * struct page *ssdfs_shextree_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_shextree_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_shextree_free_page(struct page *page)
 * void ssdfs_shextree_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(shextree)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(shextree)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_shextree_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_shextree_page_leaks, 0);
	atomic64_set(&ssdfs_shextree_memory_leaks, 0);
	atomic64_set(&ssdfs_shextree_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_shextree_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_shextree_page_leaks) != 0) {
		SSDFS_ERR("SHARED EXTENTS TREE: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_shextree_page_leaks));
	}

	if (atomic64_read(&ssdfs_shextree_memory_leaks) != 0) {
		SSDFS_ERR("SHARED EXTENTS TREE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_shextree_memory_leaks));
	}

	if (atomic64_read(&ssdfs_shextree_cache_leaks) != 0) {
		SSDFS_ERR("SHARED EXTENTS TREE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_shextree_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/******************************************************************************
 *                   SHARED EXTENTS TREE OBJECT FUNCTIONALITY                 *
 ******************************************************************************/

/*
 * ssdfs_fingerprint2hash() - convert fingerprint into hash
 * @fingerprint: fingerprint buffer
 * @len: fingeprint's length in bytes
 */
static inline
u64 ssdfs_fingerprint2hash(u8 *fingerprint, u8 len)
{
	u8 *input, *output;
	int step;
	u64 hash = 0;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fingerprint);
	BUG_ON(len > SSDFS_FINGERPRINT_LENGTH_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	step = len / sizeof(u64);

	for (i = 0; i < sizeof(u64); i += step) {
		input = fingerprint + (i * step);
		output = (u8 *)&hash + i;
		*output = *input;
	}

	return hash;
}

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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p\n", fsi);
#else
	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi->shextree = NULL;

	kaddr = ssdfs_shextree_kzalloc(shextree_obj_size, GFP_KERNEL);
	if (!kaddr) {
		SSDFS_ERR("fail to allocate shared extents tree's object\n");
		return -ENOMEM;
	}

	ptr = (struct ssdfs_shared_extents_tree *)kaddr;
	ptr->fsi = fsi;

	atomic_set(&ptr->state, SSDFS_SHEXTREE_UNKNOWN_STATE);

	err = ssdfs_btree_create(fsi,
				 SSDFS_SHARED_EXTENTS_BTREE_INO,
				 &ssdfs_shextree_desc_ops,
				 &ssdfs_shextree_ops,
				 &ptr->generic_tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create shared extents tree: err %d\n",
			  err);
		goto fail_create_shextree;
	}

	init_rwsem(&ptr->lock);
	init_waitqueue_head(&ptr->wait_queue);

	atomic64_set(&ptr->shared_extents, 0);

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

	atomic_set(&ptr->state, SSDFS_SHEXTREE_CREATED);

	ssdfs_debug_shextree_object(ptr);

	fsi->shextree = ptr;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("DONE: create shared extents tree\n");
#else
	SSDFS_DBG("DONE: create shared extents tree\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

destroy_shextree_object:
	for (; i >= 0; i--)
		ssdfs_shextree_stop_thread(ptr, i);

	ssdfs_btree_destroy(&ptr->generic_tree);

fail_create_shextree:
	ssdfs_shextree_kfree(ptr);

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
	struct ssdfs_shared_extents_tree *tree;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("shextree %p\n", fsi->shextree);
#else
	SSDFS_DBG("shextree %p\n", fsi->shextree);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!fsi->shextree)
		return;

	tree = fsi->shextree;

	ssdfs_debug_shextree_object(tree);

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

	ssdfs_btree_destroy(&tree->generic_tree);

	ssdfs_shextree_kfree(fsi->shextree);
	fsi->shextree = NULL;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
}

/*
 * ssdfs_shextree_flush() - flush dirty shared extents btree
 * @fsi: pointer on shared file system object
 *
 * This method tries to flush the dirty shared extents btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_shextree_flush(struct ssdfs_fs_info *fsi)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p\n", fsi->shextree);
#else
	SSDFS_DBG("tree %p\n", fsi->shextree);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!fsi->shextree) {
		SSDFS_WARN("shared extents btree is absent\n");
		return -EINVAL;
	}

	err = ssdfs_btree_flush(&fsi->shextree->generic_tree);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush shared extents btree: err %d\n",
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_shextree_object(fsi->shextree);

	return 0;
}

/******************************************************************************
 *                   SHARED EXTENTS TREE OBJECT FUNCTIONALITY                 *
 ******************************************************************************/

/*
 * need_initialize_shextree_search() - check necessity to init the search
 * @fingerprint: fingerprint object
 * @search: search object
 */
static inline
bool need_initialize_shextree_search(struct ssdfs_fingerprint *fingerprint,
				     struct ssdfs_btree_search *search)
{
	bool need_init = false;
	void *buf1, *buf2;

	if (search->request.start.fingerprint) {
		buf1 = search->request.start.fingerprint->buf;
		buf2 = fingerprint->buf;

		if (memcmp(buf1, buf2, SSDFS_FINGERPRINT_LENGTH_MAX) != 0)
			need_init = true;
	} else
		need_init = true;

	return need_initialize_btree_search(search) || need_init;
}

/*
 * ssdfs_shextree_find() - find shared extent
 * @tree: pointer on shared extents btree object
 * @fingerprint: fingerprint object
 * @search: pointer on search request object
 *
 * This method tries to find a shared extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_shextree_find(struct ssdfs_shared_extents_tree *tree,
			struct ssdfs_fingerprint *fingerprint,
			struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !fingerprint || !search);

	SSDFS_DBG("tree %p, fingerprint %pUb, search %p\n",
		  tree, fingerprint->buf, search);
#endif /* CONFIG_SSDFS_DEBUG */

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_shextree_search(fingerprint, search)) {
		u64 hash;

		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
				SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT |
				SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.start.fingerprint = fingerprint;
		search->request.end.fingerprint = fingerprint;
		hash = ssdfs_fingerprint2hash(fingerprint->buf,
					      fingerprint->len);
		search->request.start.hash = hash;
		search->request.end.hash = hash;
		search->request.count = 1;
	}

	return ssdfs_btree_find_item(&tree->generic_tree, search);
}

/*
 * ssdfs_shextree_find_range() - find range of shared extents
 * @tree: pointer on shared extents btree object
 * @range: fingerprints range
 * @search: pointer on search request object
 *
 * This method tries to find the range of shared extents.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_shextree_find_range(struct ssdfs_shared_extents_tree *tree,
			      struct ssdfs_fingeprint_range *range,
			      struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !range || !search);

	SSDFS_DBG("tree %p, range (start %pUb, end %pUb), search %p\n",
		  tree, range->start.buf, range->end.buf, search);
#endif /* CONFIG_SSDFS_DEBUG */

	search->request.type = SSDFS_BTREE_SEARCH_FIND_RANGE;

	if (need_initialize_shextree_search(&range->start, search)) {
		u64 hash;

		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_RANGE;
		search->request.flags =
				SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT |
				SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.start.fingerprint = &range->start;
		hash = ssdfs_fingerprint2hash(range->start.buf,
					      range->start.len);
		search->request.start.hash = hash;
		search->request.end.fingerprint = &range->end;
		hash = ssdfs_fingerprint2hash(range->end.buf,
					      range->end.len);
		search->request.end.hash = hash;
	}

	return ssdfs_btree_find_range(&tree->generic_tree, search);
}

/*
 * ssdfs_shextree_find_leaf_node() - find a leaf node in the tree
 * @tree: shared extents tree
 * @fingerprint: fingerprint object
 * @search: search object
 *
 * This method tries to find a leaf node for the requested @fingerprint.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_shextree_find_leaf_node(struct ssdfs_shared_extents_tree *tree,
				  struct ssdfs_fingerprint *fingerprint,
				  struct ssdfs_btree_search *search)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !fingerprint || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, fingerprint %pUb, search %p\n",
		  tree, fingerprint->buf, search);

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_shextree_search(fingerprint, search)) {
		u64 hash;

		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_RANGE;
		search->request.flags =
				SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT |
				SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.start.fingerprint = fingerprint;
		search->request.end.fingerprint = fingerprint;
		hash = ssdfs_fingerprint2hash(fingerprint->buf,
					      fingerprint->len);
		search->request.start.hash = hash;
		search->request.end.hash = hash;
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
 * ssdfs_prepare_shared_extent() - prepare shared extent object
 * @extent: shared extent
 * @search: search object
 *
 * This method tries to prepare a shared extent for adding into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_prepare_shared_extent(struct ssdfs_shared_extent *extent,
				struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!extent || !search);

	SSDFS_DBG("extent %p, search %p\n",
		  extent, search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.buf_state) {
	case SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE:
		search->result.buf_state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
		search->result.buf = &search->raw.shared_extent;
		search->result.buf_size = sizeof(struct ssdfs_shared_extent);
		search->result.items_in_buffer = 1;
		break;

	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.buf);
		BUG_ON(search->result.buf_size !=
			sizeof(struct ssdfs_shared_extent));
		BUG_ON(search->result.items_in_buffer != 1);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	default:
		SSDFS_ERR("unexpected buffer state %#x\n",
			  search->result.buf_state);
		return -ERANGE;
	}

	ssdfs_memcpy(search->result.buf, 0, sizeof(struct ssdfs_shared_extent),
		     extent, 0, sizeof(struct ssdfs_shared_extent),
		     sizeof(struct ssdfs_shared_extent));

	search->request.flags |= SSDFS_BTREE_SEARCH_INLINE_BUF_HAS_NEW_ITEM;

	return 0;
}

/*
 * ssdfs_shextree_add() - add shared extent info into the tree
 * @tree: pointer on shared extents btree object
 * @fingerprint: fingerprint object
 * @extent: shared extent
 * @search: search object
 *
 * This method tries to add shared extent info into the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EEXIST     - shared extent exists in the tree.
 */
int ssdfs_shextree_add(struct ssdfs_shared_extents_tree *tree,
			struct ssdfs_fingerprint *fingerprint,
			struct ssdfs_shared_extent *extent,
			struct ssdfs_btree_search *search)
{
	u64 hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !extent || !search);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, extent %p, search %p\n",
		  tree, extent, search);
#else
	SSDFS_DBG("tree %p, extent %p, search %p\n",
		  tree, extent, search);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_btree_search_init(search);
	search->request.type = SSDFS_BTREE_SEARCH_ADD_ITEM;
	search->request.flags = SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT |
				SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
	search->request.start.fingerprint = fingerprint;
	search->request.end.fingerprint = fingerprint;
	hash = ssdfs_fingerprint2hash(fingerprint->buf,
				      fingerprint->len);
	search->request.start.hash = hash;
	search->request.end.hash = hash;
	search->request.count = 1;

	switch (atomic_read(&tree->state)) {
	case SSDFS_SHEXTREE_CREATED:
	case SSDFS_SHEXTREE_INITIALIZED:
	case SSDFS_SHEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid shared extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	down_read(&tree->lock);

	err = ssdfs_btree_find_item(&tree->generic_tree, search);
	if (err == -ENODATA) {
		/*
		 * Shared extent doesn't exist.
		 */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find the shared extent: "
			  "fingerprint %pUb, err %d\n",
			  extent->fingerprint, err);
		goto finish_add_shared_extent;
	}

	if (err == -ENODATA) {
		err = ssdfs_prepare_shared_extent(extent, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare the shared extent: "
				  "err %d\n", err);
			goto finish_add_shared_extent;
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
			goto finish_add_shared_extent;
		}

		if (search->result.buf_state !=
					SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
			err = -ERANGE;
			SSDFS_ERR("invalid buf_state %#x\n",
				  search->result.buf_state);
			goto finish_add_shared_extent;
		}

		err = ssdfs_btree_add_item(&tree->generic_tree, search);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add shared extent into the tree: "
				  "err %d\n", err);
			goto finish_add_shared_extent;
		}

		atomic_set(&tree->state, SSDFS_SHEXTREE_DIRTY);

		ssdfs_btree_search_forget_parent_node(search);
		ssdfs_btree_search_forget_child_node(search);

		if (unlikely(err)) {
			SSDFS_ERR("fail to add shared extent: "
				  "err %d\n", err);
			goto finish_add_shared_extent;
		}
	} else {
		err = -EEXIST;
		SSDFS_DBG("shared extent exists in the tree\n");
		goto finish_add_shared_extent;
	}

finish_add_shared_extent:
	up_read(&tree->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_shextree_object(tree);

	return err;
}

/*
 * ssdfs_shextree_change() - change shared extent in the tree
 * @tree: shared extents tree
 * @fingerprint: old fingerprint
 * @extent: new state of shared extent
 * @search: search object
 *
 * This method tries to change shared extent in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - shared extent doesn't exist in the tree.
 */
int ssdfs_shextree_change(struct ssdfs_shared_extents_tree *tree,
			  struct ssdfs_fingerprint *fingerprint,
			  struct ssdfs_shared_extent *extent,
			  struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
	BUG_ON(!fingerprint || !extent);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, fingerprint %pUb, "
		  "extent %p, search %p\n",
		  tree, fingerprint->buf, extent, search);
#else
	SSDFS_DBG("tree %p, fingerprint %pUb, "
		  "extent %p, search %p\n",
		  tree, fingerprint->buf, extent, search);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	switch (atomic_read(&tree->state)) {
	case SSDFS_SHEXTREE_CREATED:
	case SSDFS_SHEXTREE_INITIALIZED:
	case SSDFS_SHEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid shared extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	fsi = tree->fsi;

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_shextree_search(fingerprint, search)) {
		u64 hash;

		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
				SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT |
				SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.start.fingerprint = fingerprint;
		search->request.end.fingerprint = fingerprint;
		hash = ssdfs_fingerprint2hash(fingerprint->buf,
					      fingerprint->len);
		search->request.start.hash = hash;
		search->request.end.hash = hash;
		search->request.count = 1;
	}

	down_read(&tree->lock);

	err = ssdfs_btree_find_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the shared extent: "
			  "fingerprint %pUb, err %d\n",
			  fingerprint->buf, err);
		goto finish_change_shared_extent;
	}

	search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		err = -ERANGE;
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		goto finish_change_shared_extent;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		err = -ERANGE;
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		goto finish_change_shared_extent;
	}

	err = ssdfs_memcpy(search->result.buf, 0, search->result.buf_size,
			  extent, 0, sizeof(struct ssdfs_shared_extent),
			  sizeof(struct ssdfs_shared_extent));
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare new state of shared extent: "
			  "err %d\n", err);
		goto finish_change_shared_extent;
	}

	err = ssdfs_btree_change_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change shared extent in the tree: "
			  "err %d\n", err);
		goto finish_change_shared_extent;
	}

	atomic_set(&tree->state, SSDFS_SHEXTREE_DIRTY);

	ssdfs_btree_search_forget_parent_node(search);
	ssdfs_btree_search_forget_child_node(search);

finish_change_shared_extent:
	up_read(&tree->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_shextree_object(tree);

	return err;
}

/*
 * ssdfs_shextree_ref_count_inc() - increment shared extent's ref count
 * @tree: shared extents tree
 * @fingerprint: old fingerprint
 * @search: search object
 *
 * This method tries to increment the reference counter of
 * shared extent in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - shared extent doesn't exist in the tree.
 */
int ssdfs_shextree_ref_count_inc(struct ssdfs_shared_extents_tree *tree,
				 struct ssdfs_fingerprint *fingerprint,
				 struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
	BUG_ON(!fingerprint);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, fingerprint %pUb, "
		  "search %p\n",
		  tree, fingerprint->buf, search);
#else
	SSDFS_DBG("tree %p, fingerprint %pUb, "
		  "search %p\n",
		  tree, fingerprint->buf, search);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	switch (atomic_read(&tree->state)) {
	case SSDFS_SHEXTREE_CREATED:
	case SSDFS_SHEXTREE_INITIALIZED:
	case SSDFS_SHEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid shared extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	fsi = tree->fsi;

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_shextree_search(fingerprint, search)) {
		u64 hash;

		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
				SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT |
				SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.start.fingerprint = fingerprint;
		search->request.end.fingerprint = fingerprint;
		hash = ssdfs_fingerprint2hash(fingerprint->buf,
					      fingerprint->len);
		search->request.start.hash = hash;
		search->request.end.hash = hash;
		search->request.count = 1;
	}

	down_read(&tree->lock);

	err = ssdfs_btree_find_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the shared extent: "
			  "fingerprint %pUb, err %d\n",
			  fingerprint->buf, err);
		goto finish_change_shared_extent;
	}

	search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;
	search->request.flags |= SSDFS_BTREE_SEARCH_INCREMENT_REF_COUNT;

	err = ssdfs_btree_change_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change shared exetnt in the tree: "
			  "err %d\n", err);
		goto finish_change_shared_extent;
	}

	atomic_set(&tree->state, SSDFS_SHEXTREE_DIRTY);

	ssdfs_btree_search_forget_parent_node(search);
	ssdfs_btree_search_forget_child_node(search);

finish_change_shared_extent:
	up_read(&tree->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_shextree_object(tree);

	return err;
}

/*
 * ssdfs_shextree_ref_count_dec() - decrement shared extent's ref count
 * @tree: shared extents tree
 * @fingerprint: old fingerprint
 * @search: search object
 *
 * This method tries to decrement the reference counter of
 * shared extent in the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - shared extent doesn't exist in the tree.
 */
int ssdfs_shextree_ref_count_dec(struct ssdfs_shared_extents_tree *tree,
				 struct ssdfs_fingerprint *fingerprint,
				 struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !search);
	BUG_ON(!fingerprint);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, fingerprint %pUb, "
		  "search %p\n",
		  tree, fingerprint->buf, search);
#else
	SSDFS_DBG("tree %p, fingerprint %pUb, "
		  "search %p\n",
		  tree, fingerprint->buf, search);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	switch (atomic_read(&tree->state)) {
	case SSDFS_SHEXTREE_CREATED:
	case SSDFS_SHEXTREE_INITIALIZED:
	case SSDFS_SHEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid shared extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	fsi = tree->fsi;

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_shextree_search(fingerprint, search)) {
		u64 hash;

		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
				SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT |
				SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.start.fingerprint = fingerprint;
		search->request.end.fingerprint = fingerprint;
		hash = ssdfs_fingerprint2hash(fingerprint->buf,
					      fingerprint->len);
		search->request.start.hash = hash;
		search->request.end.hash = hash;
		search->request.count = 1;
	}

	down_read(&tree->lock);

	err = ssdfs_btree_find_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the shared extent: "
			  "fingerprint %pUb, err %d\n",
			  fingerprint->buf, err);
		goto finish_change_shared_extent;
	}

	search->request.type = SSDFS_BTREE_SEARCH_CHANGE_ITEM;
	search->request.flags |= SSDFS_BTREE_SEARCH_DECREMENT_REF_COUNT;

	err = ssdfs_btree_change_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to change shared exetnt in the tree: "
			  "err %d\n", err);
		goto finish_change_shared_extent;
	}

	atomic_set(&tree->state, SSDFS_SHEXTREE_DIRTY);

	ssdfs_btree_search_forget_parent_node(search);
	ssdfs_btree_search_forget_child_node(search);

finish_change_shared_extent:
	up_read(&tree->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_shextree_object(tree);

	return err;
}

/*
 * ssdfs_shextree_delete() - delete shared extent from the tree
 * @tree: shared extents tree
 * @fingerprint: fingerprint value
 * @search: search object
 *
 * This method tries to delete shared extent from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENODATA    - shared extent doesn't exist in the tree.
 */
int ssdfs_shextree_delete(struct ssdfs_shared_extents_tree *tree,
			  struct ssdfs_fingerprint *fingerprint,
			  struct ssdfs_btree_search *search)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_shared_extent *shared_extent;
	s64 shared_extents_count;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !tree->fsi || !fingerprint || !search);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, fingerprint %pUb, search %p\n",
		  tree, fingerprint->buf, search);
#else
	SSDFS_DBG("tree %p, fingerprint %pUb, search %p\n",
		  tree, fingerprint->buf, search);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	switch (atomic_read(&tree->state)) {
	case SSDFS_SHEXTREE_CREATED:
	case SSDFS_SHEXTREE_INITIALIZED:
	case SSDFS_SHEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid shared extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	fsi = tree->fsi;

	search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;

	if (need_initialize_shextree_search(fingerprint, search)) {
		u64 hash;

		ssdfs_btree_search_init(search);
		search->request.type = SSDFS_BTREE_SEARCH_FIND_ITEM;
		search->request.flags =
				SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT |
				SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE;
		search->request.start.fingerprint = fingerprint;
		search->request.end.fingerprint = fingerprint;
		hash = ssdfs_fingerprint2hash(fingerprint->buf,
					      fingerprint->len);
		search->request.start.hash = hash;
		search->request.end.hash = hash;
		search->request.count = 1;
	}

	down_read(&tree->lock);

	err = ssdfs_btree_find_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find the shared extent: "
			  "fingerprint %pUb, err %d\n",
			  fingerprint->buf, err);
		goto finish_delete_shared_extent;
	}

	search->request.type = SSDFS_BTREE_SEARCH_DELETE_ITEM;

	if (search->result.state != SSDFS_BTREE_SEARCH_VALID_ITEM) {
		err = -ERANGE;
		SSDFS_ERR("invalid search result's state %#x\n",
			  search->result.state);
		goto finish_delete_shared_extent;
	}

	if (search->result.buf_state != SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
		err = -ERANGE;
		SSDFS_ERR("invalid buf_state %#x\n",
			  search->result.buf_state);
		goto finish_delete_shared_extent;
	}

	shared_extent = &search->raw.shared_extent;

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		if (le32_to_cpu(shared_extent->ref_count) != 0) {
			err = -ERANGE;
			SSDFS_ERR("shared extent has references yet: "
				  "ref_count %u\n",
				  le32_to_cpu(shared_extent->ref_count));
			goto finish_delete_shared_extent;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("unexpected result state %#x\n",
			   search->result.state);
		goto finish_delete_shared_extent;
	}

	shared_extents_count = atomic64_read(&tree->shared_extents);
	if (shared_extents_count == 0) {
		err = -ENOENT;
		SSDFS_DBG("empty tree\n");
		goto finish_delete_shared_extent;
	}

	if (search->result.start_index >= shared_extents_count) {
		err = -ENODATA;
		SSDFS_ERR("invalid search result: "
			  "start_index %u, shared_extents_count %lld\n",
			  search->result.start_index,
			  shared_extents_count);
		goto finish_delete_shared_extent;
	}

	err = ssdfs_btree_delete_item(&tree->generic_tree,
				      search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete the shared extent from the tree: "
			  "err %d\n", err);
		goto finish_delete_shared_extent;
	}

	atomic_set(&tree->state, SSDFS_SHEXTREE_DIRTY);

	ssdfs_btree_search_forget_parent_node(search);
	ssdfs_btree_search_forget_child_node(search);

	shared_extents_count = atomic64_read(&tree->shared_extents);

	if (shared_extents_count == 0) {
		err = -ENOENT;
		SSDFS_DBG("tree is empty now\n");
		goto finish_delete_shared_extent;
	} else if (shared_extents_count < 0) {
		err = -ERANGE;
		SSDFS_WARN("invalid shared_extents_count %lld\n",
			   shared_extents_count);
		atomic_set(&tree->state, SSDFS_SHEXTREE_CORRUPTED);
		goto finish_delete_shared_extent;
	}

finish_delete_shared_extent:
	up_read(&tree->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_debug_shextree_object(tree);

	return err;
}

/*
 * ssdfs_shextree_delete_all() - delete all shared extents in the tree
 * @tree: shared extents tree
 *
 * This method tries to delete all shared extents from the tree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_shextree_delete_all(struct ssdfs_shared_extents_tree *tree)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p\n", tree);
#else
	SSDFS_DBG("tree %p\n", tree);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	switch (atomic_read(&tree->state)) {
	case SSDFS_SHEXTREE_CREATED:
	case SSDFS_SHEXTREE_INITIALIZED:
	case SSDFS_SHEXTREE_DIRTY:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid shared extents tree's state %#x\n",
			  atomic_read(&tree->state));
		return -ERANGE;
	};

	down_write(&tree->lock);
	err = ssdfs_btree_delete_all(&tree->generic_tree);
	if (!err)
		atomic64_set(&tree->shared_extents, 0);
	up_write(&tree->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to delete the all shared extents: "
			  "err %d\n",
			  err);
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
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

#ifdef CONFIG_SSDFS_TESTING
	if (!tree->fsi->do_fork_invalidation &&
	    owner_ino == SSDFS_TESTING_INO) {
		SSDFS_DBG("ignore extent: "
			  "owner_ino %llu, seg_id %llu, "
			  "logical_blk %u, len %u\n",
			  owner_ino, seg_id, logical_blk, len);
		return 0;
	}
#endif /* CONFIG_SSDFS_TESTING */

	if (seg_id == U64_MAX || logical_blk == U32_MAX || len == U32_MAX) {
		SSDFS_ERR("invalid extent: "
			  "seg_id %llu, logical_blk %u, len %u\n",
			  seg_id, logical_blk, len);
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

#ifdef CONFIG_SSDFS_TESTING
	if (!tree->fsi->do_fork_invalidation &&
	    owner_ino == SSDFS_TESTING_INO) {
		SSDFS_DBG("ignore fork: "
			  "owner_ino %llu, start_offset %llu, "
			  "blks_count %llu\n",
			  owner_ino, start_offset, blks_count);
		return 0;
	}
#endif /* CONFIG_SSDFS_TESTING */

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

	SSDFS_DBG("INVALIDATING FORK: "
		  "start_offset %llu, blks_count %llu\n",
		  le64_to_cpu(fork->start_offset),
		  le64_to_cpu(fork->blks_count));

	for (i = 0; i < SSDFS_INLINE_EXTENTS_COUNT; i++) {
		struct ssdfs_raw_extent *ptr = &fork->extents[i];
		u32 len = le32_to_cpu(ptr->len);
		u64 seg_id = le64_to_cpu(ptr->seg_id);
		u32 start_blk = le32_to_cpu(ptr->logical_blk);

		SSDFS_DBG("INVALIDATING FORK: extent[%d]: "
			  "seg_id %llu, start_blk %u, len %u\n",
			  i, seg_id, start_blk, len);

		err = ssdfs_shextree_add_pre_invalid_extent(tree, owner_ino,
							    ptr);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add pre-invalid extent: "
				  "err %d\n",
				  err);
			return err;
		}

		processed_blks += len;

		if (processed_blks >= blks_count)
			break;
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

#ifdef CONFIG_SSDFS_TESTING
	if (!tree->fsi->do_fork_invalidation &&
	    owner_ino == SSDFS_TESTING_INO) {
		SSDFS_DBG("ignore index: "
			  "owner_ino %llu, index_type %#x, "
			  "node_id %u, node_type %#x, "
			  "height %u, flags %#x, "
			  "hash %llx, seg_id %llu, "
			  "logical_blk %u, len %u\n",
			  owner_ino, index_type,
			  node_id, node_type, height, flags,
			  hash, seg_id, logical_blk, len);
		return 0;
	}
#endif /* CONFIG_SSDFS_TESTING */

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

/******************************************************************************
 *             SPECIALIZED SHARED EXTENTS BTREE DESCRIPTOR OPERATIONS         *
 ******************************************************************************/

/*
 * ssdfs_shextree_desc_init() - specialized btree descriptor init
 * @fsi: pointer on shared file system object
 * @tree: pointer on shared extents btree object
 */
static
int ssdfs_shextree_desc_init(struct ssdfs_fs_info *fsi,
			     struct ssdfs_btree *tree)
{
	struct ssdfs_btree_descriptor *desc;
	u32 erasesize;
	u32 node_size;
	size_t shared_extent_desc_size = sizeof(struct ssdfs_shared_extent);
	u16 item_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !tree);
	BUG_ON(!rwsem_is_locked(&fsi->volume_sem));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, tree %p\n",
		  fsi, tree);

	erasesize = fsi->erasesize;

	desc = &fsi->vs->shared_extents_btree.desc;

	if (le32_to_cpu(desc->magic) != SSDFS_SHARED_EXTENTS_BTREE_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid magic %#x\n",
			  le32_to_cpu(desc->magic));
		goto finish_btree_desc_init;
	}

	/* TODO: check flags */

	if (desc->type != SSDFS_SHARED_EXTENTS_BTREE) {
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

	if (item_size != shared_extent_desc_size) {
		err = -EIO;
		SSDFS_ERR("invalid item size %u\n",
			  item_size);
		goto finish_btree_desc_init;
	}

	if (le16_to_cpu(desc->index_area_min_size) !=
					(4 * shared_extent_desc_size)) {
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
 * ssdfs_shextree_desc_flush() - specialized btree's descriptor flush
 * @tree: pointer on inodes btree object
 */
static
int ssdfs_shextree_desc_flush(struct ssdfs_btree *tree)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_descriptor desc;
	size_t shared_extent_desc_size = sizeof(struct ssdfs_shared_extent);
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

	desc.magic = cpu_to_le32(SSDFS_SHARED_EXTENTS_BTREE_MAGIC);
	desc.item_size = cpu_to_le16(shared_extent_desc_size);

	err = ssdfs_btree_desc_flush(tree, &desc);
	if (unlikely(err)) {
		SSDFS_ERR("invalid btree descriptor: err %d\n",
			  err);
		return err;
	}

	if (desc.type != SSDFS_SHARED_EXTENTS_BTREE) {
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

	if (le16_to_cpu(desc.index_area_min_size) !=
					(4 * shared_extent_desc_size)) {
		SSDFS_ERR("invalid index_area_min_size %u\n",
			  le16_to_cpu(desc.index_area_min_size));
		return -ERANGE;
	}

	ssdfs_memcpy(&fsi->vs->shared_extents_btree.desc,
		     0, sizeof(struct ssdfs_btree_descriptor),
		     &desc,
		     0, sizeof(struct ssdfs_btree_descriptor),
		     sizeof(struct ssdfs_btree_descriptor));

	return 0;
}

/******************************************************************************
 *                 SPECIALIZED SHARED EXTENTS BTREE OPERATIONS                *
 ******************************************************************************/

/*
 * ssdfs_shextree_create_root_node() - specialized root node creation
 * @fsi: pointer on shared file system object
 * @node: pointer on node object [out]
 */
static
int ssdfs_shextree_create_root_node(struct ssdfs_fs_info *fsi,
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

	root_node = &fsi->vs->shared_extents_btree.root_node;
	err = ssdfs_btree_create_root_node(node, root_node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create root node: err %d\n",
			  err);
	}

	return err;
}

/*
 * ssdfs_shextree_pre_flush_root_node() - specialized root node pre-flush
 * @node: pointer on node object
 */
static
int ssdfs_shextree_pre_flush_root_node(struct ssdfs_btree_node *node)
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

	if (tree->type != SSDFS_SHARED_EXTENTS_BTREE) {
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
 * ssdfs_shextree_flush_root_node() - specialized root node flush
 * @node: pointer on node object
 */
static
int ssdfs_shextree_flush_root_node(struct ssdfs_btree_node *node)
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

	root_node = &node->tree->fsi->vs->shared_extents_btree.root_node;
	ssdfs_btree_flush_root_node(node, root_node);

	return 0;
}

/*
 * ssdfs_shextree_create_node() - specialized node creation
 * @node: pointer on node object
 */
static
int ssdfs_shextree_create_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	size_t hdr_size = sizeof(struct ssdfs_shextree_node_header);
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	tree = node->tree;
	node_size = tree->node_size;
	index_area_min_size = tree->index_area_min_size;

	node->node_ops = &ssdfs_shextree_node_ops;

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

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_SHEXTREE_BMAP_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bmap_bytes %zu\n",
			  bmap_bytes);
		goto finish_create_node;
	}

	node->raw.shextree_header.shared_extents = cpu_to_le32(0);

	SSDFS_DBG("node_id %u, shared_extents %u\n",
		  node->node_id,
		  le32_to_cpu(node->raw.shextree_header.shared_extents));
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
 * ssdfs_shextree_init_node() - init shared extents tree's node
 * @node: pointer on node object
 *
 * This method tries to init the node of shared extents btree.
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
int ssdfs_shextree_init_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	struct ssdfs_shared_extents_tree *tree_info = NULL;
	struct ssdfs_shextree_node_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_shextree_node_header);
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	struct page *page;
	void *kaddr;
	u64 start_hash, end_hash;
	u32 node_size;
	u16 item_size;
	u32 shared_extents;
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (node->tree->type == SSDFS_SHARED_EXTENTS_BTREE)
		tree_info = (struct ssdfs_shared_extents_tree *)node->tree;
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

	hdr = (struct ssdfs_shextree_node_header *)kaddr;

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

	ssdfs_memcpy(&node->raw.shextree_header, 0, hdr_size,
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
	shared_extents = le32_to_cpu(hdr->shared_extents);

	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "items_capacity %u, shared_extents %u\n",
		  start_hash, end_hash,
		  items_capacity, shared_extents);

	if (item_size == 0 || node_size % item_size) {
		err = -EIO;
		SSDFS_ERR("invalid size: item_size %u, node_size %u\n",
			  item_size, node_size);
		goto finish_header_init;
	}

	if (item_size != sizeof(struct ssdfs_shared_extent)) {
		err = -EIO;
		SSDFS_ERR("invalid item_size: "
			  "size %u, expected size %zu\n",
			  item_size,
			  sizeof(struct ssdfs_shared_extent));
		goto finish_header_init;
	}

	calculated_used_space = hdr_size;
	calculated_used_space += shared_extents * item_size;

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
		/* pass through */

	case SSDFS_BTREE_LEAF_NODE:
		if (shared_extents > 0 &&
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

		if (item_size != sizeof(struct ssdfs_shared_extent)) {
			err = -EIO;
			SSDFS_ERR("invalid item_size: "
				  "size %u, expected size %zu\n",
				  item_size,
				  sizeof(struct ssdfs_shared_extent));
			goto finish_header_init;
		}

		if (items_capacity == 0 ||
		    items_capacity > (node_size / item_size)) {
			err = -EIO;
			SSDFS_ERR("invalid items_capacity %u\n",
				  items_capacity);
			goto finish_header_init;
		}

		if (shared_extents > items_capacity) {
			err = -EIO;
			SSDFS_ERR("items_capacity %u != shared_extents %u\n",
				  items_capacity,
				  shared_extents);
			goto finish_header_init;
		}

		free_space =
			(u32)(items_capacity - shared_extents) * item_size;
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
		  "hdr_size %zu, shared_extents %u, "
		  "item_size %u\n",
		  free_space, index_area_size, hdr_size,
		  shared_extents, item_size);

	if (free_space != (node_size - calculated_used_space)) {
		err = -EIO;
		SSDFS_ERR("free_space %u, node_size %u, "
			  "calculated_used_space %u\n",
			  free_space, node_size,
			  calculated_used_space);
		goto finish_header_init;
	}

	node->items_area.free_space = free_space;
	node->items_area.items_count = (u16)shared_extents;
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

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_SHEXTREE_BMAP_SIZE) {
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
		   0, shared_extents);
	spin_unlock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);

	up_write(&node->bmap_array.lock);
finish_init_operation:
	kunmap(page);

	if (unlikely(err))
		goto finish_init_node;

	atomic64_add((u64)shared_extents, &tree_info->shared_extents);

finish_init_node:
	up_read(&node->full_lock);

	ssdfs_debug_btree_node_object(node);

	return err;
}

static
void ssdfs_shextree_destroy_node(struct ssdfs_btree_node *node)
{
	SSDFS_DBG("operation is unavailable\n");
}

/*
 * ssdfs_shextree_add_node() - add node into shared extents btree
 * @node: pointer on node object
 *
 * This method tries to finish addition of node into shared extents btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shextree_add_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	int type;
	u16 items_capacity = 0;
	u64 start_hash = U64_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

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

	SSDFS_DBG("node_id %u, shared_extents %u\n",
		  node->node_id,
		  le16_to_cpu(node->raw.shextree_header.shared_extents));
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
int ssdfs_shextree_delete_node(struct ssdfs_btree_node *node)
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
 * ssdfs_shextree_pre_flush_node() - pre-flush node's header
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
int ssdfs_shextree_pre_flush_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_shextree_node_header header;
	size_t hdr_size = sizeof(struct ssdfs_shextree_node_header);
	struct ssdfs_btree *tree;
	struct ssdfs_shared_extents_tree *tree_info = NULL;
	struct ssdfs_state_bitmap *bmap;
	struct page *page;
	void *kaddr;
	u16 items_count;
	u32 items_area_size;
	u16 shared_extents;
	u32 used_space;
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

	tree = node->tree;
	if (!tree) {
		SSDFS_ERR("node hasn't pointer on tree\n");
		return -ERANGE;
	}

	if (tree->type != SSDFS_SHARED_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	} else {
		tree_info = container_of(tree,
					 struct ssdfs_shared_extents_tree,
					 generic_tree);
	}

	down_write(&node->full_lock);
	down_write(&node->header_lock);

	ssdfs_memcpy(&header, 0, hdr_size,
		     &node->raw.shextree_header, 0, hdr_size,
		     hdr_size);

	header.node.magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	header.node.magic.key = cpu_to_le16(SSDFS_EXTENTS_BNODE_MAGIC);
	header.node.magic.version.major = SSDFS_MAJOR_REVISION;
	header.node.magic.version.minor = SSDFS_MINOR_REVISION;

	err = ssdfs_btree_node_pre_flush_header(node, &header.node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to flush generic header: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		goto finish_shextree_header_preparation;
	}

	items_count = node->items_area.items_count;
	items_area_size = node->items_area.area_size;
	shared_extents = le16_to_cpu(header.shared_extents);

	if (shared_extents != items_count) {
		err = -ERANGE;
		SSDFS_ERR("shared_extents %u != items_count %u\n",
			  shared_extents, items_count);
		goto finish_shextree_header_preparation;
	}

	used_space = (u32)items_count * sizeof(struct ssdfs_shared_extent);

	if (used_space > items_area_size) {
		err = -ERANGE;
		SSDFS_ERR("used_space %u > items_area_size %u\n",
			  used_space, items_area_size);
		goto finish_shextree_header_preparation;
	}

	SSDFS_DBG("shared_extents %u, "
		  "items_area_size %u, item_size %zu\n",
		  shared_extents, items_area_size,
		  sizeof(struct ssdfs_shared_extent));

	header.node.check.bytes = cpu_to_le16((u16)hdr_size);
	header.node.check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&header.node.check,
				   &header, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto finish_shextree_header_preparation;
	}

	ssdfs_memcpy(&node->raw.shextree_header, 0, hdr_size,
		     &header, 0, hdr_size,
		     hdr_size);

finish_shextree_header_preparation:
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
	ssdfs_memcpy(kaddr, 0, hdr_size,
		     &header, 0, hdr_size,
		     hdr_size);
	kunmap_atomic(kaddr);

finish_node_pre_flush:
	up_write(&node->full_lock);

	return err;
}

/*
 * ssdfs_shextree_flush_node() - flush node
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
int ssdfs_shextree_flush_node(struct ssdfs_btree_node *node)
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

	if (tree->type != SSDFS_SHARED_EXTENTS_BTREE) {
		SSDFS_WARN("invalid tree type %#x\n",
			   tree->type);
		return -ERANGE;
	}

	fsi = node->tree->fsi;

	spin_lock(&fsi->volume_state_lock);
	fs_feature_compat = fsi->fs_feature_compat;
	spin_unlock(&fsi->volume_state_lock);

	if (fs_feature_compat & SSDFS_HAS_SHARED_EXTENTS_COMPAT_FLAG) {
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
		SSDFS_CRIT("shared extents tree is absent\n");
	}

	ssdfs_debug_btree_node_object(node);

	return err;
}

/******************************************************************************
 *             SPECIALIZED SHARED EXTENTS BTREE NODE OPERATIONS               *
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
					sizeof(struct ssdfs_shared_extent),
					SSDFS_SHEXTREE_LOOKUP_TABLE_SIZE);
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
					sizeof(struct ssdfs_shared_extent),
					SSDFS_SHEXTREE_LOOKUP_TABLE_SIZE);
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

	SSDFS_DBG("node_size %u, item_index %u\n",
		  node_size, item_index);

	lookup_index = ssdfs_convert_item2lookup_index(node_size, item_index);
	calculated = ssdfs_convert_lookup2item_index(node_size, lookup_index);

	SSDFS_DBG("lookup_index %u, calculated %u\n",
		  lookup_index, calculated);

	return calculated == item_index;
}

/*
 * ssdfs_shextree_node_find_lookup_index() - find lookup index
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
int ssdfs_shextree_node_find_lookup_index(struct ssdfs_btree_node *node,
					  struct ssdfs_btree_search *search,
					  u16 *lookup_index)
{
	__le64 *lookup_table;
	int array_size = SSDFS_SHEXTREE_LOOKUP_TABLE_SIZE;
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
	lookup_table = node->raw.shextree_header.lookup_table;
	err = ssdfs_btree_node_find_lookup_index_nolock(search,
							lookup_table,
							array_size,
							lookup_index);
	up_read(&node->header_lock);

	return err;
}

/*
 * ssdfs_check_shared_extent_for_request() - check shared extent
 * @fsi:  pointer on shared file system object
 * @extent: pointer on shared extent object
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
int ssdfs_check_shared_extent_for_request(struct ssdfs_fs_info *fsi,
					  struct ssdfs_shared_extent *extent,
					  struct ssdfs_btree_search *search)
{
	u32 req_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !extent || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p, extent %p, search %p\n",
		  fsi, extent, search);

	req_flags = search->request.flags;

	SSDFS_DBG("start: (hash %llx, fingerprint %pUb), "
		  "end (hash %llx, fingerprint %pUb), "
		  "req_flags %#x\n",
		  search->request.start.hash,
		  search->request.start.fingerprint->buf,
		  search->request.end.hash,
		  search->request.end.fingerprint->buf,
		  req_flags);

	if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT) {
		u8 type1, type2;
		u8 len1, len2;
		int res;

		type1 = search->request.start.fingerprint->type;
		type2 = extent->fingerprint_type;

		if (type1 != type2) {
			err = -ERANGE;
			SSDFS_ERR("fingerprint: type1 %#x != type2 %#x\n",
				  type1, type2);
			goto finish_check_shared_extent;
		}

		len1 = search->request.start.fingerprint->len;
		len2 = extent->fingerprint_len;

		if (len1 != len2) {
			err = -ERANGE;
			SSDFS_ERR("fingerprint: len1 %u != len2 %u\n",
				  len1, len2);
			goto finish_check_shared_extent;
		}

		res = memcmp(search->request.start.fingerprint->buf,
			     extent->fingerprint,
			     len1);

		if (res == 0) {
			search->result.state = SSDFS_BTREE_SEARCH_VALID_ITEM;
			goto finish_check_shared_extent;
		} else if (res > 0) {
			/* continue the search */
			err = -EAGAIN;
			goto finish_check_shared_extent;
		}

		res = memcmp(search->request.end.fingerprint->buf,
			     extent->fingerprint,
			     len1);

		if (res >= 0) {
			err = -ERANGE;
			SSDFS_ERR("invalid request: "
				  "start: (hash %llx, fingerprint %pUb), "
				  "end (hash %llx, fingerprint %pUb)\n",
				  search->request.start.hash,
				  search->request.start.fingerprint->buf,
				  search->request.end.hash,
				  search->request.end.fingerprint->buf);
			goto finish_check_shared_extent;
		} else {
			err = -ENODATA;
			search->result.err = -ENODATA;
			search->result.state =
				SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
			goto finish_check_shared_extent;
		}
	} else {
		err = -ERANGE;
		SSDFS_ERR("invalid set of flags: %#x\n", req_flags);
		goto finish_check_shared_extent;
	}

finish_check_shared_extent:
	return err;
}

/*
 * ssdfs_get_shared_extents_hash_range() - get shared extents' hash range
 * @kaddr: pointer on shared extent object
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 */
static
void ssdfs_get_shared_extents_hash_range(void *kaddr,
					 u64 *start_hash,
					 u64 *end_hash)
{
	struct ssdfs_shared_extent *extent;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!kaddr || !start_hash || !end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p\n", kaddr);

	extent = (struct ssdfs_shared_extent *)kaddr;
	*start_hash = ssdfs_fingerprint2hash(extent->fingerprint,
					     extent->fingerprint_len);
	*end_hash = *start_hash;
}

/*
 * ssdfs_check_found_shared_extent() - check found shared extent
 * @fsi: pointer on shared file system object
 * @search: search object
 * @kaddr: pointer on shared extent object
 * @item_index: index of the shared extent
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 * @found_index: pointer on found index [out]
 *
 * This method tries to check the found shared extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - corrupted shared extent.
 * %-EAGAIN     - continue the search.
 * %-ENODATA    - possible place was found.
 */
static
int ssdfs_check_found_shared_extent(struct ssdfs_fs_info *fsi,
				    struct ssdfs_btree_search *search,
				    void *kaddr,
				    u16 item_index,
				    u64 *start_hash,
				    u64 *end_hash,
				    u16 *found_index)
{
	struct ssdfs_shared_extent *extent;
	u32 req_flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search || !kaddr || !found_index);
	BUG_ON(!start_hash || !end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("item_index %u\n", item_index);

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;
	*found_index = U16_MAX;

	extent = (struct ssdfs_shared_extent *)kaddr;
	req_flags = search->request.flags;

	if (!(req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT)) {
		SSDFS_ERR("invalid request: fingerprint is absent\n");
		return -ERANGE;
	}

	ssdfs_get_shared_extents_hash_range(kaddr, start_hash, end_hash);

	err = ssdfs_check_shared_extent_for_request(fsi, extent, search);
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

		*found_index = item_index;
	} else if (err == -EAGAIN) {
		/* continue to search */
		err = 0;
		*found_index = U16_MAX;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check shared extent: err %d\n",
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
 * ssdfs_prepare_shared_extents_buffer() - prepare buffer for shared extents
 * @search: search object
 * @found_index: found index of shared extent
 * @start_hash: starting hash
 * @end_hash: ending hash
 * @items_count: count of items in the sequence
 * @item_size: size of the item
 */
static
int ssdfs_prepare_shared_extents_buffer(struct ssdfs_btree_search *search,
					u16 found_index,
					u64 start_hash,
					u64 end_hash,
					u16 items_count,
					size_t item_size)
{
	u16 found_extents = 0;
	size_t buf_size = sizeof(struct ssdfs_shared_extent);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("found_index %u, start_hash %llx, end_hash %llx, "
		  "items_count %u, item_size %zu\n",
		   found_index, start_hash, end_hash,
		   items_count, item_size);

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
		search->result.buf = &search->raw.shared_extent;
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

	return 0;
}

/*
 * ssdfs_extract_found_shared_extent() - extract found shared extent
 * @fsi: pointer on shared file system object
 * @search: search object
 * @item_size: size of the item
 * @kaddr: pointer on shared extent
 * @start_hash: pointer on start_hash value [out]
 * @end_hash: pointer on end_hash value [out]
 *
 * This method tries to extract the found shared extent.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_extract_found_shared_extent(struct ssdfs_fs_info *fsi,
				      struct ssdfs_btree_search *search,
				      size_t item_size,
				      void *kaddr,
				      u64 *start_hash,
				      u64 *end_hash)
{
	struct ssdfs_shared_extent *extent;
	size_t buf_size = sizeof(struct ssdfs_shared_extent);
	u32 calculated;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !search || !kaddr);
	BUG_ON(!start_hash || !end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("kaddr %p\n", kaddr);

	*start_hash = U64_MAX;
	*end_hash = U64_MAX;

	calculated = search->result.items_in_buffer * buf_size;
	if (calculated > search->result.buf_size) {
		SSDFS_ERR("calculated %u > buf_size %zu\n",
			  calculated, search->result.buf_size);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */

	extent = (struct ssdfs_shared_extent *)kaddr;
	ssdfs_get_shared_extents_hash_range(extent, start_hash, end_hash);

	err = ssdfs_memcpy(search->result.buf,
			   calculated, search->result.buf_size,
			   extent, 0, item_size,
			   item_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
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
	int capacity = SSDFS_SHEXTREE_LOOKUP_TABLE_SIZE;
	size_t item_size = sizeof(struct ssdfs_shared_extent);

	return __ssdfs_extract_range_by_lookup_index(node, lookup_index,
					capacity, item_size, search,
					ssdfs_check_found_shared_extent,
					ssdfs_prepare_shared_extents_buffer,
					ssdfs_extract_found_shared_extent);
}

/*
 * ssdfs_btree_search_result_no_data() - prepare result state for no data case
 * @node: pointer on node object
 * @lookup_index: lookup index
 * @search: pointer on search request object [in|out]
 *
 * This method prepares result state for no data case.
 */
static inline
void ssdfs_btree_search_result_no_data(struct ssdfs_btree_node *node,
					u16 lookup_index,
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

	search->result.state = SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND;
	search->result.err = -ENODATA;
	search->result.start_index =
			ssdfs_convert_lookup2item_index(node->node_size,
							lookup_index);
	search->result.count = search->request.count;
	search->result.search_cno = ssdfs_current_cno(node->tree->fsi->sb);

	if (!is_btree_search_contains_new_item(search)) {
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
}

/*
 * ssdfs_shextree_node_find_range() - find a range of items into the node
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
int ssdfs_shextree_node_find_range(struct ssdfs_btree_node *node,
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

	err = ssdfs_shextree_node_find_lookup_index(node, search,
						    &lookup_index);
	if (err == -ENODATA) {
		ssdfs_btree_search_result_no_data(node, lookup_index, search);
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
	BUG_ON(lookup_index >= SSDFS_SHEXTREE_LOOKUP_TABLE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_extract_range_by_lookup_index(node, lookup_index,
						  search);
	search->result.search_cno = ssdfs_current_cno(node->tree->fsi->sb);

	if (err == -EAGAIN) {
		SSDFS_DBG("node contains not all requested shared extents: "
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
		ssdfs_btree_search_result_no_data(node, lookup_index, search);
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

	search->request.flags &= ~SSDFS_BTREE_SEARCH_INLINE_BUF_HAS_NEW_ITEM;

	return 0;
}

/*
 * ssdfs_shextree_node_find_item() - find item into node
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
int ssdfs_shextree_node_find_item(struct ssdfs_btree_node *node,
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

	if (search->request.count != 1) {
		SSDFS_ERR("invalid request state: "
			  "count %d, start_hash %llx, end_hash %llx\n",
			  search->request.count,
			  search->request.start.hash,
			  search->request.end.hash);
		return -ERANGE;
	}

	return ssdfs_shextree_node_find_range(node, search);
}

static
int ssdfs_shextree_node_allocate_item(struct ssdfs_btree_node *node,
				      struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

static
int ssdfs_shextree_node_allocate_range(struct ssdfs_btree_node *node,
				       struct ssdfs_btree_search *search)
{
	SSDFS_DBG("operation is unavailable\n");
	return -EOPNOTSUPP;
}

/*
 * __ssdfs_shextree_node_get_shared_extent() - extract the shared extent
 * @pvec: pointer on pagevec
 * @area_offset: area offset from the node's beginning
 * @area_size: area size
 * @node_size: size of the node
 * @item_index: index of the shared extent in the node
 * @extent: pointer on shared extent's buffer [out]
 *
 * This method tries to extract the shared extent from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_shextree_node_get_shared_extent(struct pagevec *pvec,
					    u32 area_offset,
					    u32 area_size,
					    u32 node_size,
					    u16 item_index,
					    struct ssdfs_shared_extent *extent)
{
	size_t item_size = sizeof(struct ssdfs_shared_extent);
	u32 item_offset;
	int page_index;
	struct page *page;
	void *kaddr;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec || !extent);
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
	err = ssdfs_memcpy(extent, 0, item_size,
			   kaddr, item_offset, PAGE_SIZE,
			   item_size);
	kunmap_atomic(kaddr);

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_shextree_node_get_shared_extent() - extract shared extent from the node
 * @node: pointer on node object
 * @area: items area descriptor
 * @item_index: index of the shared extent
 * @extent: pointer on extracted shared extent [out]
 *
 * This method tries to extract the shared extent from the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_shextree_node_get_shared_extent(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *area,
				u16 item_index,
				struct ssdfs_shared_extent *extent)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !extent);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, item_index);

	return __ssdfs_shextree_node_get_shared_extent(&node->content.pvec,
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
 * This method tries to check that requested position of a shared extent
 * in the node is correct.
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
	struct ssdfs_shared_extent extent;
	u16 item_index;
	u32 req_flags;
	int direction = SSDFS_CHECK_POSITION_FAILURE;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, item_index %u\n",
		  node->node_id, search->result.start_index);

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

	if (area->items_count == 0) {
		direction = SSDFS_CORRECT_POSITION;
		goto finish_check_position;
	}

	err = ssdfs_shextree_node_get_shared_extent(node, area,
						    item_index, &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to extract the shared extent: "
			  "item_index %u, err %d\n",
			  item_index, err);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

	req_flags = search->request.flags;

	if (req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT) {
		u8 type1, type2;
		u8 len1, len2;
		int res;

		type1 = search->request.start.fingerprint->type;
		type2 = extent.fingerprint_type;

		if (type1 != type2) {
			SSDFS_ERR("fingerprint: type1 %#x != type2 %#x\n",
				  type1, type2);
			return SSDFS_CHECK_POSITION_FAILURE;
		}

		len1 = search->request.start.fingerprint->len;
		len2 = extent.fingerprint_len;

		if (len1 != len2) {
			SSDFS_ERR("fingerprint: len1 %u != len2 %u\n",
				  len1, len2);
			return SSDFS_CHECK_POSITION_FAILURE;
		}

		res = memcmp(search->request.start.fingerprint->buf,
			     extent.fingerprint,
			     len1);

		if (res == 0) {
			direction = SSDFS_CORRECT_POSITION;
			goto finish_check_position;
		} else if (res > 0) {
			direction = SSDFS_SEARCH_RIGHT_DIRECTION;
			goto finish_check_position;
		}

		res = memcmp(search->request.end.fingerprint->buf,
			     extent.fingerprint,
			     len1);

		if (res >= 0) {
			SSDFS_ERR("invalid request: "
				  "start: (hash %llx, fingerprint %pUb), "
				  "end (hash %llx, fingerprint %pUb)\n",
				  search->request.start.hash,
				  search->request.start.fingerprint->buf,
				  search->request.end.hash,
				  search->request.end.fingerprint->buf);
			return SSDFS_CHECK_POSITION_FAILURE;
		} else {
			direction = SSDFS_SEARCH_LEFT_DIRECTION;
			goto finish_check_position;
		}
	} else {
		SSDFS_ERR("invalid set of flags: %#x\n", req_flags);
		return SSDFS_CHECK_POSITION_FAILURE;
	}

finish_check_position:
	SSDFS_DBG("start: (hash %llx, fingerprint %pUb), "
		  "end (hash %llx, fingerprint %pUb), "
		  "direction %#x\n",
		  search->request.start.hash,
		  search->request.start.fingerprint->buf,
		  search->request.end.hash,
		  search->request.end.fingerprint->buf,
		  direction);

	return direction;
}

/*
 * ssdfs_find_correct_position_from_left() - find position from the left
 * @node: pointer on node object
 * @area: items area descriptor
 * @search: search object
 *
 * This method tries to find a correct position of the shared extent
 * from the left side of shared extents' sequence in the node.
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
	struct ssdfs_shared_extent extent;
	int item_index;
	u32 req_flags;
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

	if (!(req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT)) {
		SSDFS_ERR("invalid request: req_flags %#x\n",
			  req_flags);
		return -ERANGE;
	}

	for (; item_index >= 0; item_index--) {
		u8 type1, type2;
		u8 len1, len2;
		int res;

		err = ssdfs_shextree_node_get_shared_extent(node, area,
							    (u16)item_index,
							    &extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the shared extent: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		type1 = search->request.start.fingerprint->type;
		type2 = extent.fingerprint_type;

		if (type1 != type2) {
			SSDFS_ERR("fingerprint: type1 %#x != type2 %#x\n",
				  type1, type2);
			return -ERANGE;;
		}

		len1 = search->request.start.fingerprint->len;
		len2 = extent.fingerprint_len;

		if (len1 != len2) {
			SSDFS_ERR("fingerprint: len1 %u != len2 %u\n",
				  len1, len2);
			return -ERANGE;
		}

		res = memcmp(search->request.start.fingerprint->buf,
			     extent.fingerprint,
			     len1);

		if (res == 0) {
			search->result.start_index = (u16)item_index;
			return 0;
		} else if (res > 0) {
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
 * This method tries to find a correct position of the shared extent
 * from the right side of shared extents' sequence in the node.
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
	struct ssdfs_shared_extent extent;
	int item_index;
	u32 req_flags;
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

	if (!(req_flags & SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT)) {
		SSDFS_ERR("invalid request: req_flags %#x\n",
			  req_flags);
		return -ERANGE;
	}

	for (; item_index < area->items_count; item_index++) {
		u8 type1, type2;
		u8 len1, len2;
		int res;

		err = ssdfs_shextree_node_get_shared_extent(node, area,
							    (u16)item_index,
							    &extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract the shared extent: "
				  "item_index %d, err %d\n",
				  item_index, err);
			return err;
		}

		type1 = search->request.end.fingerprint->type;
		type2 = extent.fingerprint_type;

		if (type1 != type2) {
			SSDFS_ERR("fingerprint: type1 %#x != type2 %#x\n",
				  type1, type2);
			return -ERANGE;;
		}

		len1 = search->request.end.fingerprint->len;
		len2 = extent.fingerprint_len;

		if (len1 != len2) {
			SSDFS_ERR("fingerprint: len1 %u != len2 %u\n",
				  len1, len2);
			return -ERANGE;
		}

		res = memcmp(search->request.end.fingerprint->buf,
			     extent.fingerprint,
			     len1);

		if (res <= 0) {
			search->result.start_index = (u16)item_index;
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u\n",
		  node->node_id, start_index);

	items_capacity = node->items_area.items_capacity;
	if (start_index >= items_capacity) {
		SSDFS_DBG("start_index %u >= items_capacity %u\n",
			  start_index, items_capacity);
		return 0;
	}

	lookup_table = node->raw.shextree_header.lookup_table;

	lookup_index = ssdfs_convert_item2lookup_index(node->node_size,
						       start_index);
	if (unlikely(lookup_index >= SSDFS_SHEXTREE_LOOKUP_TABLE_SIZE)) {
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

	cleaning_indexes = SSDFS_SHEXTREE_LOOKUP_TABLE_SIZE - lookup_index;
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
	__le64 *lookup_table;
	struct ssdfs_shared_extent extent;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !area);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);

	if (range_len == 0) {
		SSDFS_DBG("range_len == 0\n");
		return 0;
	}

	lookup_table = node->raw.shextree_header.lookup_table;

	for (i = 0; i < range_len; i++) {
		int item_index = start_index + i;
		u16 lookup_index;

		if (is_hash_for_lookup_table(node->node_size, item_index)) {
			lookup_index =
				ssdfs_convert_item2lookup_index(node->node_size,
								item_index);

			err = ssdfs_shextree_node_get_shared_extent(node,
								    area,
								    item_index,
								    &extent);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract the shared extent: "
					  "item_index %d, err %d\n",
					  item_index, err);
				return err;
			}

			lookup_table[lookup_index] =
				ssdfs_fingerprint2hash(extent.fingerprint,
							extent.fingerprint_len);
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

	lookup_table = node->raw.shextree_header.lookup_table;
	memset(lookup_table, 0xFF,
		sizeof(__le64) * SSDFS_SHEXTREE_LOOKUP_TABLE_SIZE);
}

/*
 * __ssdfs_shextree_node_insert_range() - insert range into node
 * @node: pointer on node object
 * @search: search object
 *
 * This method tries to insert the range of shared extents into the node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EFAULT     - node is corrupted.
 */
static
int __ssdfs_shextree_node_insert_range(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_btree *tree;
	struct ssdfs_shared_extents_tree *tree_info;
	struct ssdfs_shextree_node_header *hdr;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_shared_extent extent;
	size_t item_size = sizeof(struct ssdfs_shared_extent);
	u16 item_index;
	int free_items;
	u16 range_len;
	u16 shared_extents = 0;
	int direction;
	u32 used_space;
	u64 start_hash = U64_MAX;
	u64 end_hash = U64_MAX;
	u64 cur_hash;
	u64 old_hash;
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
	case SSDFS_SHARED_EXTENTS_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	tree_info = container_of(tree,
				 struct ssdfs_shared_extents_tree,
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
	shared_extents = range_len + search->request.count;

	item_index = search->result.start_index;
	if ((item_index + shared_extents) > items_area.items_capacity) {
		err = -ERANGE;
		SSDFS_ERR("invalid shared_extents: "
			  "item_index %u, shared_extents %u, "
			  "items_capacity %u\n",
			  item_index, shared_extents,
			  items_area.items_capacity);
		goto finish_detect_affected_items;
	}

	if (items_area.items_count == 0)
		goto lock_items_range;

	start_hash = search->request.start.hash;
	end_hash = search->request.end.hash;

	if (item_index > 0) {
		err = ssdfs_shextree_node_get_shared_extent(node,
							    &items_area,
							    item_index - 1,
							    &extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_detect_affected_items;
		}

		cur_hash = ssdfs_fingerprint2hash(extent.fingerprint,
						  extent.fingerprint_len);

		if (cur_hash < start_hash) {
			/*
			 * expected state
			 */
		} else {
			SSDFS_ERR("invalid range: item_index %u, "
				  "cur_hash %llx, "
				  "start_hash %llx, end_hash %llx\n",
				  item_index, cur_hash,
				  start_hash, end_hash);

			for (i = 0; i < items_area.items_count; i++) {
				err =
				   ssdfs_shextree_node_get_shared_extent(node,
								  &items_area,
								  i, &extent);
				if (unlikely(err)) {
					SSDFS_ERR("fail to get snapshot: "
						  "err %d\n", err);
					goto finish_detect_affected_items;
				}

				SSDFS_ERR("index %d, hash %llx\n",
				    i,
				    ssdfs_fingerprint2hash(extent.fingerprint,
						  extent.fingerprint_len));
			}

			err = -ERANGE;
			goto finish_detect_affected_items;
		}
	}

	if (item_index < items_area.items_count) {
		err = ssdfs_shextree_node_get_shared_extent(node,
							    &items_area,
							    item_index,
							    &extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_detect_affected_items;
		}

		cur_hash = ssdfs_fingerprint2hash(extent.fingerprint,
						  extent.fingerprint_len);

		if (end_hash < cur_hash) {
			/*
			 * expected state
			 */
		} else {
			SSDFS_ERR("invalid range: item_index %u, "
				  "cur_hash %llx, "
				  "start_hash %llx, end_hash %llx\n",
				  item_index, cur_hash,
				  start_hash, end_hash);

			for (i = 0; i < items_area.items_count; i++) {
				err =
				   ssdfs_shextree_node_get_shared_extent(node,
								  &items_area,
								  i, &extent);
				if (unlikely(err)) {
					SSDFS_ERR("fail to get snapshot: "
						  "err %d\n", err);
					goto finish_detect_affected_items;
				}

				SSDFS_ERR("index %d, hash %llx\n",
				    i,
				    ssdfs_fingerprint2hash(extent.fingerprint,
						  extent.fingerprint_len));
			}

			err = -ERANGE;
			goto finish_detect_affected_items;
		}
	}

lock_items_range:
	err = ssdfs_lock_items_range(node, item_index, shared_extents);
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

	err = ssdfs_shift_range_right(node, &items_area, item_size,
				      item_index, range_len,
				      search->request.count);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to shift dentries range: "
			  "start %u, count %u, err %d\n",
			  item_index, search->request.count,
			  err);
		goto unlock_items_range;
	}

	ssdfs_debug_btree_node_object(node);

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

	SSDFS_DBG("items_capacity %u, items_count %u\n",
		  items_area.items_capacity,
		  items_area.items_count);

	used_space = (u32)search->request.count * item_size;
	if (used_space > node->items_area.free_space) {
		err = -ERANGE;
		SSDFS_ERR("used_space %u > free_space %u\n",
			  used_space,
			  node->items_area.free_space);
		goto finish_items_area_correction;
	}
	node->items_area.free_space -= used_space;

	err = ssdfs_shextree_node_get_shared_extent(node, &node->items_area,
						    0, &extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		goto finish_items_area_correction;
	}
	start_hash = ssdfs_fingerprint2hash(extent.fingerprint,
					    extent.fingerprint_len);

	err = ssdfs_shextree_node_get_shared_extent(node,
					&node->items_area,
					node->items_area.items_count - 1,
					&extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		goto finish_items_area_correction;
	}
	end_hash = ssdfs_fingerprint2hash(extent.fingerprint,
					  extent.fingerprint_len);

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
					 item_index, shared_extents);
	if (unlikely(err)) {
		SSDFS_ERR("fail to correct lookup table: "
			  "err %d\n", err);
		goto finish_items_area_correction;
	}

	hdr = &node->raw.shextree_header;

	le32_add_cpu(&hdr->shared_extents, search->request.count);
	atomic64_add(search->request.count, &tree_info->shared_extents);

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
					  item_index, shared_extents);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  item_index, shared_extents, err);
		goto unlock_items_range;
	}

unlock_items_range:
	ssdfs_unlock_items_range(node, item_index, shared_extents);

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
 * ssdfs_shextree_node_insert_item() - insert item in the node
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
int ssdfs_shextree_node_insert_item(struct ssdfs_btree_node *node,
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
		search->result.err = 0;
		/*
		 * Node doesn't contain requested item.
		 */
	} else if (search->result.err) {
		SSDFS_WARN("invalid search result: err %d\n",
			   search->result.err);
		return search->result.err;
	}

	if (is_btree_search_contains_new_item(search)) {
		switch (search->result.buf_state) {
		case SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE:
			search->result.buf_state =
					SSDFS_BTREE_SEARCH_INLINE_BUFFER;
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
			search->result.buf = &search->raw.shared_extent;
			search->result.buf_size =
					sizeof(struct ssdfs_shared_extent);
			search->result.items_in_buffer = 1;
			break;

		case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!search->result.buf);
			BUG_ON(search->result.buf_size !=
					sizeof(struct ssdfs_shared_extent));
			BUG_ON(search->result.items_in_buffer != 1);
#endif /* CONFIG_SSDFS_DEBUG */
			break;

		default:
			SSDFS_ERR("unexpected buffer state %#x\n",
				  search->result.buf_state);
			return -ERANGE;
		}
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(search->result.count != 1);
		BUG_ON(!search->result.buf);
		BUG_ON(search->result.buf_state !=
				SSDFS_BTREE_SEARCH_INLINE_BUFFER);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = __ssdfs_shextree_node_insert_range(node, search);
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
 * ssdfs_shextree_node_insert_range() - insert range of items
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
int ssdfs_shextree_node_insert_range(struct ssdfs_btree_node *node,
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
	BUG_ON(search->result.count < 1);
	BUG_ON(!search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&node->items_area.state);
	if (state != SSDFS_BTREE_NODE_ITEMS_AREA_EXIST) {
		SSDFS_ERR("invalid area state %#x\n",
			  state);
		return -ERANGE;
	}

	err = __ssdfs_shextree_node_insert_range(node, search);
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
 * ssdfs_change_item_only() - change shared extent in the node
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
	struct ssdfs_shared_extent shared_extent;
	struct ssdfs_shared_extent *ptr;
	size_t item_size = sizeof(struct ssdfs_shared_extent);
	u16 range_len;
	u16 item_index;
	u64 start_hash, end_hash;
	u32 req_flags;
	u32 extent_len;
	u64 ref_count;
	int res;
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

	err = ssdfs_shextree_node_get_shared_extent(node, area, item_index,
						    &shared_extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get extent: err %d\n", err);
		return err;
	}

	req_flags = search->request.flags;

	if (req_flags & SSDFS_BTREE_SEARCH_INCREMENT_REF_COUNT) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(req_flags & SSDFS_BTREE_SEARCH_DECREMENT_REF_COUNT);
#endif /* CONFIG_SSDFS_DEBUG */

		if (range_len > 1) {
			SSDFS_ERR("fail to increment several extents\n");
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.buf);

		if (search->result.buf_state !=
				SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
			SSDFS_ERR("invalid state of result buffer %#x\n",
				  search->result.buf_state);
			return -ERANGE;
		}

		if (search->result.buf_size != item_size) {
			SSDFS_ERR("invalid buffer size: "
				  "current %zu, expected %zu\n",
				  search->result.buf_size, item_size);
			return -ERANGE;
		}

		if (search->result.items_in_buffer != 1) {
			SSDFS_ERR("unexpected number of items in buffer %u\n",
				  search->result.items_in_buffer);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		ptr = (struct ssdfs_shared_extent *)search->result.buf;

		res = memcmp(shared_extent.fingerprint, ptr->fingerprint,
			     shared_extent.fingerprint_len);
		if (res != 0) {
			SSDFS_ERR("fingerprints do not match: "
				  "fingerprint1 %pUb, fingerprint2 %pUb\n",
				  shared_extent.fingerprint,
				  ptr->fingerprint);
			return -ERANGE;
		}

		ref_count = le64_to_cpu(shared_extent.ref_count);
		extent_len = le32_to_cpu(shared_extent.extent.len);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(ref_count >= (U64_MAX - extent_len));
#endif /* CONFIG_SSDFS_DEBUG */

		ref_count += extent_len;
		ptr->ref_count = cpu_to_le64(ref_count);
	} else if (req_flags & SSDFS_BTREE_SEARCH_DECREMENT_REF_COUNT) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(req_flags & SSDFS_BTREE_SEARCH_INCREMENT_REF_COUNT);
#endif /* CONFIG_SSDFS_DEBUG */

		if (range_len > 1) {
			SSDFS_ERR("fail to decrement several extents\n");
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.buf);

		if (search->result.buf_state !=
				SSDFS_BTREE_SEARCH_INLINE_BUFFER) {
			SSDFS_ERR("invalid state of result buffer %#x\n",
				  search->result.buf_state);
			return -ERANGE;
		}

		if (search->result.buf_size != item_size) {
			SSDFS_ERR("invalid buffer size: "
				  "current %zu, expected %zu\n",
				  search->result.buf_size, item_size);
			return -ERANGE;
		}

		if (search->result.items_in_buffer != 1) {
			SSDFS_ERR("unexpected number of items in buffer %u\n",
				  search->result.items_in_buffer);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		ptr = (struct ssdfs_shared_extent *)search->result.buf;

		res = memcmp(shared_extent.fingerprint, ptr->fingerprint,
			     shared_extent.fingerprint_len);
		if (res != 0) {
			SSDFS_ERR("fingerprints do not match: "
				  "fingerprint1 %pUb, fingerprint2 %pUb\n",
				  shared_extent.fingerprint,
				  ptr->fingerprint);
			return -ERANGE;
		}

		ref_count = le64_to_cpu(shared_extent.ref_count);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(ref_count == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		ref_count--;
		ptr->ref_count = cpu_to_le64(ref_count);
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
		err = ssdfs_shextree_node_get_shared_extent(node,
							   &node->items_area,
							   item_index,
							   &shared_extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_items_area_correction;
		}
		start_hash = ssdfs_fingerprint2hash(shared_extent.fingerprint,
						shared_extent.fingerprint_len);
	}

	if ((item_index + range_len) == node->items_area.items_count) {
		err = ssdfs_shextree_node_get_shared_extent(node,
						    &node->items_area,
						    item_index + range_len - 1,
						    &shared_extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_items_area_correction;
		}
		end_hash = ssdfs_fingerprint2hash(shared_extent.fingerprint,
						shared_extent.fingerprint_len);
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
 * ssdfs_shextree_node_change_item() - change item in the node
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
int ssdfs_shextree_node_change_item(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_search *search)
{
	size_t item_size = sizeof(struct ssdfs_shared_extent);
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

	if (is_btree_search_contains_new_item(search)) {
		switch (search->result.buf_state) {
		case SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE:
			search->result.buf_state =
					SSDFS_BTREE_SEARCH_INLINE_BUFFER;
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(search->result.buf);
#endif /* CONFIG_SSDFS_DEBUG */
			search->result.buf = &search->raw.shared_extent;
			search->result.buf_size =
					sizeof(struct ssdfs_shared_extent);
			search->result.items_in_buffer = 1;
			break;

		case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!search->result.buf);
			BUG_ON(search->result.buf_size !=
					sizeof(struct ssdfs_shared_extent));
			BUG_ON(search->result.items_in_buffer != 1);
#endif /* CONFIG_SSDFS_DEBUG */
			break;

		default:
			SSDFS_ERR("unexpected buffer state %#x\n",
				  search->result.buf_state);
			return -ERANGE;
		}
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(search->result.count != 1);
		BUG_ON(!search->result.buf);
		BUG_ON(search->result.buf_state !=
				SSDFS_BTREE_SEARCH_INLINE_BUFFER);
		BUG_ON(search->result.items_in_buffer != 1);
#endif /* CONFIG_SSDFS_DEBUG */
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, start_index %u, range_len %u\n",
		  node->node_id, start_index, range_len);

	return __ssdfs_invalidate_items_area(node, area,
					     start_index, range_len,
					     search);
}

/*
 * __ssdfs_shextree_node_delete_range() - delete range of items
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
int __ssdfs_shextree_node_delete_range(struct ssdfs_btree_node *node,
					struct ssdfs_btree_search *search)
{
	struct ssdfs_btree *tree;
	struct ssdfs_shared_extents_tree *tree_info;
	struct ssdfs_shextree_node_header *hdr;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_shared_extent extent;
	size_t item_size = sizeof(struct ssdfs_shared_extent);
	u16 index_count = 0;
	int free_items;
	u16 item_index;
	int direction;
	u16 range_len;
	u16 shift_range_len = 0;
	u16 locked_len = 0;
	u32 deleted_space, free_space;
	u64 start_hash = U64_MAX;
	u64 end_hash = U64_MAX;
	u64 old_hash;
	u32 old_shared_extents = 0, shared_extents = 0;
	u32 extents_diff;
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
	case SSDFS_SHARED_EXTENTS_BTREE:
		/* expected btree type */
		break;

	default:
		SSDFS_ERR("invalid btree type %#x\n", tree->type);
		return -ERANGE;
	}

	tree_info = container_of(tree,
				 struct ssdfs_shared_extents_tree,
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

	shared_extents = items_area.items_count;
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
		err = ssdfs_shextree_node_get_shared_extent(node,
						    &node->items_area,
						    0, &extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_items_area_correction;
		}
		start_hash = ssdfs_fingerprint2hash(extent.fingerprint,
						    extent.fingerprint_len);

		err = ssdfs_shextree_node_get_shared_extent(node,
					&node->items_area,
					node->items_area.items_count - 1,
					&extent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get extent: err %d\n", err);
			goto finish_items_area_correction;
		}
		end_hash = ssdfs_fingerprint2hash(extent.fingerprint,
						  extent.fingerprint_len);
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

	hdr = &node->raw.shextree_header;

	old_shared_extents = le16_to_cpu(hdr->shared_extents);

	if (node->items_area.items_count == 0) {
		hdr->shared_extents = cpu_to_le16(0);
	} else {
		if (old_shared_extents < search->request.count) {
			hdr->shared_extents = cpu_to_le16(0);
		} else {
			shared_extents = le16_to_cpu(hdr->shared_extents);
			shared_extents -= search->request.count;
			hdr->shared_extents = cpu_to_le16(shared_extents);
		}
	}

	shared_extents = le16_to_cpu(hdr->shared_extents);
	extents_diff = old_shared_extents - shared_extents;
	atomic64_sub(extents_diff, &tree_info->shared_extents);

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

	if (shared_extents != 0) {
		err = ssdfs_set_dirty_items_range(node,
					items_area.items_capacity,
					item_index,
					old_shared_extents - item_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set items range as dirty: "
				  "start %u, count %u, err %d\n",
				  item_index,
				  old_shared_extents - item_index,
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
		if (shared_extents == 0) {
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

	SSDFS_DBG("node_type %#x, shared_extents %u, index_count %u\n",
		  atomic_read(&node->type),
		  shared_extents, index_count);

	if (shared_extents == 0 && index_count == 0)
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
 * ssdfs_shextree_node_delete_item() - delete an item from node
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
int ssdfs_shextree_node_delete_item(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_search *search)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

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

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(search->result.count != 1);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_shextree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete shared extent: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_shextree_node_delete_range() - delete range of items from node
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
int ssdfs_shextree_node_delete_range(struct ssdfs_btree_node *node,
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

	err = __ssdfs_shextree_node_delete_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to delete snapshots range: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_shextree_node_extract_range() - extract range of items from node
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
int ssdfs_shextree_node_extract_range(struct ssdfs_btree_node *node,
				      u16 start_index, u16 count,
				      struct ssdfs_btree_search *search)
{
	struct ssdfs_shared_extent *extent;
	int err;

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

	down_read(&node->full_lock);
	err = __ssdfs_btree_node_extract_range(node, start_index, count,
					sizeof(struct ssdfs_shared_extent),
					search);
	up_read(&node->full_lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to extract a range: "
			  "start %u, count %u, err %d\n",
			  start_index, count, err);
		return err;
	}

	search->request.flags =
			SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT |
			SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE |
			SSDFS_BTREE_SEARCH_HAS_VALID_COUNT;
	extent = (struct ssdfs_shared_extent *)search->result.buf;
	search->request.start.hash = ssdfs_fingerprint2hash(extent->fingerprint,
							extent->fingerprint_len);
	extent += search->result.count - 1;
	search->request.end.hash = ssdfs_fingerprint2hash(extent->fingerprint,
							extent->fingerprint_len);
	search->request.count = count;

	return 0;
}

/*
 * ssdfs_shextree_resize_items_area() - resize items area of the node
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
int ssdfs_shextree_resize_items_area(struct ssdfs_btree_node *node,
				     u32 new_size)
{
	struct ssdfs_fs_info *fsi;
	size_t item_size = sizeof(struct ssdfs_shared_extent);
	size_t index_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	BUG_ON(!rwsem_is_locked(&node->header_lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("node_id %u, new_size %u\n",
		  node->node_id, new_size);

	fsi = node->tree->fsi;
	index_size = le16_to_cpu(fsi->vs->shared_extents_btree.desc.index_size);

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

void ssdfs_debug_shextree_object(struct ssdfs_shared_extents_tree *tree)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);

	SSDFS_DBG("SHARED EXTENTS TREE: state %#x, "
		  "shared_extents %llu, is_locked %d, fsi %p\n",
		  atomic_read(&tree->state),
		  (u64)atomic64_read(&tree->shared_extents),
		  rwsem_is_locked(&tree->lock),
		  tree->fsi);

	ssdfs_debug_btree_object(&tree->generic_tree);
#endif /* CONFIG_SSDFS_DEBUG */
}

const struct ssdfs_btree_descriptor_operations ssdfs_shextree_desc_ops = {
	.init		= ssdfs_shextree_desc_init,
	.flush		= ssdfs_shextree_desc_flush,
};

const struct ssdfs_btree_operations ssdfs_shextree_ops = {
	.create_root_node	= ssdfs_shextree_create_root_node,
	.create_node		= ssdfs_shextree_create_node,
	.init_node		= ssdfs_shextree_init_node,
	.destroy_node		= ssdfs_shextree_destroy_node,
	.add_node		= ssdfs_shextree_add_node,
	.delete_node		= ssdfs_shextree_delete_node,
	.pre_flush_root_node	= ssdfs_shextree_pre_flush_root_node,
	.flush_root_node	= ssdfs_shextree_flush_root_node,
	.pre_flush_node		= ssdfs_shextree_pre_flush_node,
	.flush_node		= ssdfs_shextree_flush_node,
};

const struct ssdfs_btree_node_operations ssdfs_shextree_node_ops = {
	.find_item		= ssdfs_shextree_node_find_item,
	.find_range		= ssdfs_shextree_node_find_range,
	.extract_range		= ssdfs_shextree_node_extract_range,
	.allocate_item		= ssdfs_shextree_node_allocate_item,
	.allocate_range		= ssdfs_shextree_node_allocate_range,
	.insert_item		= ssdfs_shextree_node_insert_item,
	.insert_range		= ssdfs_shextree_node_insert_range,
	.change_item		= ssdfs_shextree_node_change_item,
	.delete_item		= ssdfs_shextree_node_delete_item,
	.delete_range		= ssdfs_shextree_node_delete_range,
	.resize_items_area	= ssdfs_shextree_resize_items_area,
};
