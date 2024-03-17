/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/inodes_tree.c - inodes btree implementation.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2024 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "inodes_tree.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_ino_tree_folio_leaks;
atomic64_t ssdfs_ino_tree_memory_leaks;
atomic64_t ssdfs_ino_tree_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_ino_tree_cache_leaks_increment(void *kaddr)
 * void ssdfs_ino_tree_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_ino_tree_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_ino_tree_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_ino_tree_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_ino_tree_kfree(void *kaddr)
 * struct folio *ssdfs_ino_tree_alloc_folio(gfp_t gfp_mask,
 *                                          unsigned int order)
 * struct folio *ssdfs_ino_tree_add_batch_folio(struct folio_batch *batch,
 *                                              unsigned int order)
 * void ssdfs_ino_tree_free_folio(struct folio *folio)
 * void ssdfs_ino_tree_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(ino_tree)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(ino_tree)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_ino_tree_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_ino_tree_folio_leaks, 0);
	atomic64_set(&ssdfs_ino_tree_memory_leaks, 0);
	atomic64_set(&ssdfs_ino_tree_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_ino_tree_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_ino_tree_folio_leaks) != 0) {
		SSDFS_ERR("INODES TREE: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_ino_tree_folio_leaks));
	}

	if (atomic64_read(&ssdfs_ino_tree_memory_leaks) != 0) {
		SSDFS_ERR("INODES TREE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_ino_tree_memory_leaks));
	}

	if (atomic64_read(&ssdfs_ino_tree_cache_leaks) != 0) {
		SSDFS_ERR("INODES TREE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_ino_tree_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static struct kmem_cache *ssdfs_free_ino_desc_cachep;

void ssdfs_zero_free_ino_desc_cache_ptr(void)
{
	ssdfs_free_ino_desc_cachep = NULL;
}

static
void ssdfs_init_free_ino_desc_once(void *obj)
{
	struct ssdfs_inodes_btree_range *range_desc = obj;

	memset(range_desc, 0, sizeof(struct ssdfs_inodes_btree_range));
}

void ssdfs_shrink_free_ino_desc_cache(void)
{
	if (ssdfs_free_ino_desc_cachep)
		kmem_cache_shrink(ssdfs_free_ino_desc_cachep);
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
				SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
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
	unsigned int nofs_flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_free_ino_desc_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	nofs_flags = memalloc_nofs_save();
	ptr = kmem_cache_alloc(ssdfs_free_ino_desc_cachep, GFP_KERNEL);
	memalloc_nofs_restore(nofs_flags);

	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for free inodes range\n");
		return ERR_PTR(-ENOMEM);
	}

	ssdfs_ino_tree_cache_leaks_increment(ptr);

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

	ssdfs_ino_tree_cache_leaks_decrement(range);
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
				list_del(&first->list);
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

	if (first && first->area.count == 0) {
		ssdfs_free_inodes_range_free(first);
		first = NULL;
	}

	if (unlikely(err)) {
		ssdfs_free_inodes_range_free(tmp);
		return err;
	} else if (is_empty) {
		ssdfs_free_inodes_range_free(tmp);
		SSDFS_DBG("free inodes queue is empty\n");
		return -ENODATA;
	}

	*range = tmp;

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
static inline
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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("fsi %p\n", fsi);
#else
	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ptr = ssdfs_ino_tree_kzalloc(sizeof(struct ssdfs_inodes_btree_info),
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
	ptr->last_free_ino = 0;
	ptr->allocated_inodes = le64_to_cpu(raw_btree->allocated_inodes);
	ptr->free_inodes = le64_to_cpu(raw_btree->free_inodes);
	ptr->inodes_capacity = le64_to_cpu(raw_btree->inodes_capacity);
	ptr->leaf_nodes = le32_to_cpu(raw_btree->leaf_nodes);
	ptr->nodes_count = le32_to_cpu(raw_btree->nodes_count);
	ptr->raw_inode_size = le16_to_cpu(raw_btree->desc.item_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("upper_allocated_ino %llu, allocated_inodes %llu, "
		  "free_inodes %llu, inodes_capacity %llu\n",
		  ptr->upper_allocated_ino,
		  ptr->allocated_inodes,
		  ptr->free_inodes,
		  ptr->inodes_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_memcpy(&ptr->root_folder, 0, raw_inode_size,
		     &fsi->vs->root_folder, 0, raw_inode_size,
		     raw_inode_size);

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

		ptr->allocated_inodes = 0;
		ptr->free_inodes = 0;
		ptr->inodes_capacity = 0;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("upper_allocated_ino %llu, allocated_inodes %llu, "
			  "free_inodes %llu, inodes_capacity %llu\n",
			  ptr->upper_allocated_ino,
			  ptr->allocated_inodes,
			  ptr->free_inodes,
			  ptr->inodes_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

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

		ssdfs_memcpy(search->result.buf, 0, search->result.buf_size,
			     &ptr->root_folder, 0, raw_inode_size,
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

		spin_lock(&ptr->lock);
		if (ptr->last_free_ino > 0 &&
		    ptr->last_free_ino < ptr->upper_allocated_ino) {
			ptr->upper_allocated_ino = ptr->last_free_ino - 1;
		}
		spin_unlock(&ptr->lock);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("last_free_ino %llu, upper_allocated_ino %llu\n",
			  ptr->last_free_ino,
			  ptr->upper_allocated_ino);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("DONE: create inodes btree\n");
#else
	SSDFS_DBG("DONE: create inodes btree\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

fail_create_inodes_tree:
	fsi->inodes_tree = NULL;
	ssdfs_ino_tree_kfree(ptr);
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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p\n", fsi->inodes_tree);
#else
	SSDFS_DBG("tree %p\n", fsi->inodes_tree);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!fsi->inodes_tree)
		return;

	ssdfs_debug_inodes_btree_object(fsi->inodes_tree);

	tree = fsi->inodes_tree;
	ssdfs_btree_destroy(&tree->generic_tree);
	ssdfs_free_inodes_queue_remove_all(&tree->free_inodes_queue);

	ssdfs_ino_tree_kfree(fsi->inodes_tree);
	fsi->inodes_tree = NULL;

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */
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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p\n", tree);
#else
	SSDFS_DBG("tree %p\n", tree);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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
	ssdfs_memcpy(&fsi->vs->root_folder,
		     0, sizeof(struct ssdfs_inode),
		     &tree->root_folder,
		     0, sizeof(struct ssdfs_inode),
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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	SSDFS_DBG("tree %p, ino %lu, search %p\n",
		  tree, ino, search);
#endif /* CONFIG_SSDFS_DEBUG */

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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, ino %p, search %p\n",
		  tree, ino, search);
#else
	SSDFS_DBG("tree %p, ino %p, search %p\n",
		  tree, ino, search);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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
		else if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to add the node: err %d\n",
				  err);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %llu, start_index %u\n",
		  (u64)*ino, (u32)search->result.start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_allocate_item(&tree->generic_tree, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate item: ino %llu, err %d\n",
			  search->request.start.hash, err);
		goto finish_inode_allocation;
	}

finish_inode_allocation:
	ssdfs_free_inodes_range_free(range);

	ssdfs_btree_search_forget_parent_node(search);
	ssdfs_btree_search_forget_child_node(search);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, ino %lu, search %p\n",
		  tree, ino, search);
#else
	SSDFS_DBG("tree %p, ino %lu, search %p\n",
		  tree, ino, search);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	ssdfs_btree_search_forget_parent_node(search);
	ssdfs_btree_search_forget_child_node(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to change inode: ino %lu, err %d\n",
			  ino, err);
		return err;
	}

	if (ino == SSDFS_ROOT_INO) {
		spin_lock(&tree->lock);
		ssdfs_memcpy(&tree->root_folder,
			     0, sizeof(struct ssdfs_inode),
			     search->result.buf,
			     0, search->result.buf_size,
			     sizeof(struct ssdfs_inode));
		spin_unlock(&tree->lock);
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("tree %p, ino %lu, count %u\n",
		  tree, ino, count);
#else
	SSDFS_DBG("tree %p, ino %lu, count %u\n",
		  tree, ino, count);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("add free range: node_id %u, "
		  "start_hash %llx, start_index %u, "
		  "count %u\n",
		  range->node_id,
		  range->area.start_hash,
		  range->area.start_index,
		  range->area.count);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_free_inodes_queue_add_head(&tree->free_inodes_queue, range);

	spin_lock(&tree->lock);
	if (range->area.start_hash > tree->last_free_ino) {
		tree->last_free_ino =
			range->area.start_hash + range->area.count;
	}
	spin_unlock(&tree->lock);

finish_delete_inodes_range:
	ssdfs_btree_search_free(search);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	SSDFS_DBG("tree %p, ino %lu\n",
		  tree, ino);
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("fsi %p, tree %p\n",
		  fsi, tree);
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("owner_ino %llu, type %#x, state %#x\n",
		  tree->owner_ino, tree->type,
		  atomic_read(&tree->state));
#endif /* CONFIG_SSDFS_DEBUG */

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

	ssdfs_memcpy(&fsi->vs->inodes_btree.desc,
		     0, sizeof(struct ssdfs_btree_descriptor),
		     &desc,
		     0, sizeof(struct ssdfs_btree_descriptor),
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

	SSDFS_DBG("fsi %p, node %p\n",
		  fsi, node);
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is clean\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

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
 * ssdfs_inodes_btree_node_index_capacity() - calculate index capacity
 * @node: pointer on node object
 */
static inline
u16 ssdfs_inodes_btree_node_index_capacity(struct ssdfs_btree_node *node)
{
	size_t hdr_size = sizeof(struct ssdfs_inodes_btree_node_header);
	u32 node_size;
	u16 index_area_min_size;
	u16 index_size;
	u32 area_size;
	u16 max_index_capacity;
	u16 index_capacity = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	node_size = node->tree->node_size;
	index_area_min_size = node->tree->index_area_min_size;
	index_size = node->index_area.index_size;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
		area_size = node_size - hdr_size;
		index_capacity = area_size / index_size;

		max_index_capacity = SSDFS_INODE_BMAP_SIZE * BITS_PER_BYTE;
		index_capacity = min_t(u16, index_capacity, max_index_capacity);
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		index_capacity = index_area_min_size / index_size;
		break;

	default:
		/* do nothing */
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_type %#x, index_capacity %u\n",
		  atomic_read(&node->type), index_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return index_capacity;
}

/*
 * ssdfs_inodes_btree_create_node() - specialized node creation
 * @node: pointer on node object
 */
static
int ssdfs_inodes_btree_create_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree *tree;
	void *addr[SSDFS_BTREE_NODE_BMAP_COUNT];
	struct ssdfs_inodes_btree_node_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_inodes_btree_node_header);
	u32 node_size;
	u32 items_area_size = 0;
	u16 item_size = 0;
	u16 index_size = 0;
	u16 index_area_min_size;
	u16 items_capacity = 0;
	u16 index_capacity = 0;
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

	node->node_ops = &ssdfs_inodes_btree_node_ops;

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
		index_size = node->index_area.index_size;

		index_capacity = ssdfs_inodes_btree_node_index_capacity(node);
		node->index_area.index_capacity = index_capacity;

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
		index_size = node->index_area.index_size;

		index_capacity = ssdfs_inodes_btree_node_index_capacity(node);
		node->index_area.index_capacity = index_capacity;

		atomic_set(&node->index_area.flags,
			   SSDFS_PLEASE_ADD_HYBRID_NODE_SELF_INDEX);

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

		atomic_set(&node->items_area.flags,
			   SSDFS_PLEASE_ADD_FREE_ITEMS_RANGE);

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

		atomic_set(&node->items_area.flags,
			   SSDFS_PLEASE_ADD_FREE_ITEMS_RANGE);

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
		index_capacity = ssdfs_inodes_btree_node_index_capacity(node);
	else
		index_capacity = 0;

	bmap_bytes = index_capacity + items_capacity + 1;
	bmap_bytes += BITS_PER_LONG + (BITS_PER_LONG - 1);
	bmap_bytes /= BITS_PER_BYTE;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_capacity %u, items_capacity %u, "
		  "bmap_bytes %zu, max_bmap_bytes %u\n",
		  index_capacity, items_capacity,
		  bmap_bytes, SSDFS_INODE_BMAP_SIZE);

	if (index_capacity == 0 && items_capacity == 0) {
		SSDFS_WARN("node_id %u, state %#x, "
			   "type %#x, index_capacity %u, "
			   "items_capacity %u, bits_count %lu, "
			   "bmap_bytes %zu\n",
			   node->node_id,
			   atomic_read(&node->state),
			   atomic_read(&node->type),
			   index_capacity, items_capacity,
			   node->bmap_array.bits_count,
			   bmap_bytes);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	node->bmap_array.bmap_bytes = bmap_bytes;

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_INODE_BMAP_SIZE) {
		err = -EIO;
		SSDFS_ERR("invalid bmap_bytes %zu\n",
			  bmap_bytes);
		goto finish_create_node;
	}

	hdr = &node->raw.inodes_header;
	hdr->inodes_count = cpu_to_le16(0);
	hdr->valid_inodes = cpu_to_le16(0);

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
 * ssdfs_process_deleted_nodes() - process deleted nodes
 * @node: pointer on node object
 * @q: pointer on temporary ranges queue
 * @start_hash: starting hash of the range
 * @end_hash: ending hash of the range
 * @inodes_per_node: number of inodes per leaf node
 *
 * This method tries to process the deleted nodes.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_process_deleted_nodes(struct ssdfs_btree_node *node,
				struct ssdfs_free_inode_range_queue *q,
				u64 start_hash, u64 end_hash,
				u32 inodes_per_node)
{
	struct ssdfs_inodes_btree_info *tree;
	struct ssdfs_inodes_btree_range *range;
	u64 inodes_range;
	u64 deleted_nodes;
	u32 remainder;
	s64 i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !q);

	SSDFS_DBG("node_id %u, state %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "inodes_per_node %u\n",
		  node->node_id, atomic_read(&node->state),
		  start_hash, end_hash, inodes_per_node);
#endif /* CONFIG_SSDFS_DEBUG */

	if (node->tree->type == SSDFS_INODES_BTREE)
		tree = (struct ssdfs_inodes_btree_info *)node->tree;
	else {
		SSDFS_ERR("invalid tree type %#x\n",
			  node->tree->type);
		return -ERANGE;
	}

	if (start_hash == U64_MAX || end_hash == U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("invalid range: "
			  "start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	} else if (start_hash > end_hash) {
		SSDFS_ERR("invalid range: "
			  "start_hash %llx, end_hash %llx\n",
			  start_hash, end_hash);
		return -ERANGE;
	}

	inodes_range = end_hash - start_hash;
	deleted_nodes = div_u64_rem(inodes_range, inodes_per_node, &remainder);

	if (remainder != 0) {
		SSDFS_ERR("invalid range: "
			  "inodes_range %llu, inodes_per_node %u, "
			  "remainder %u\n",
			  inodes_range, inodes_per_node, remainder);
		return -ERANGE;
	}

	for (i = 0; i < deleted_nodes; i++) {
		range = ssdfs_free_inodes_range_alloc();
		if (unlikely(!range)) {
			SSDFS_ERR("fail to allocate inodes range\n");
			return -ENOMEM;
		}

		ssdfs_free_inodes_range_init(range);
		range->node_id = node->node_id;
		range->area.start_hash = start_hash + (i * inodes_per_node);
		range->area.start_index = 0;
		range->area.count = (u16)inodes_per_node;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("add free range: node_id %u, "
			  "start_hash %llx, start_index %u, "
			  "count %u\n",
			  range->node_id,
			  range->area.start_hash,
			  range->area.start_index,
			  range->area.count);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_free_inodes_queue_add_tail(q, range);

		spin_lock(&tree->lock);
		if (range->area.start_hash > tree->last_free_ino) {
			tree->last_free_ino =
				range->area.start_hash + range->area.count;
		}
		spin_unlock(&tree->lock);
	}

	return 0;
}

/*
 * ssdfs_inodes_btree_detect_deleted_nodes() - detect deleted nodes
 * @node: pointer on node object
 * @q: pointer on temporary ranges queue
 *
 * This method tries to detect deleted nodes.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_inodes_btree_detect_deleted_nodes(struct ssdfs_btree_node *node,
					struct ssdfs_free_inode_range_queue *q)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_node_index_area index_area;
	struct ssdfs_btree_index_key index;
	size_t hdr_size = sizeof(struct ssdfs_inodes_btree_node_header);
	u16 item_size;
	u32 inodes_per_node;
	u64 prev_hash, start_hash;
	s64 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !q);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	down_read(&node->header_lock);
	ssdfs_memcpy(&index_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     &node->index_area,
		     0, sizeof(struct ssdfs_btree_node_index_area),
		     sizeof(struct ssdfs_btree_node_index_area));
	up_read(&node->header_lock);

	item_size = node->tree->item_size;
	inodes_per_node = node->node_size;
	inodes_per_node -= hdr_size;
	inodes_per_node /= item_size;

	if (inodes_per_node == 0) {
		SSDFS_ERR("invalid inodes_per_node %u\n",
			  inodes_per_node);
		return -ERANGE;
	}

	if (index_area.start_hash == U64_MAX ||
	    index_area.end_hash == U64_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to detect deleted nodes: "
			  "start_hash %llx, end_hash %llx\n",
			  index_area.start_hash,
			  index_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_process_index_area;
	} else if (index_area.start_hash > index_area.end_hash) {
		err = -ERANGE;
		SSDFS_ERR("invalid range: "
			  "start_hash %llx, end_hash %llx\n",
			  index_area.start_hash,
			  index_area.end_hash);
		goto finish_process_index_area;
	} else if (index_area.start_hash == index_area.end_hash) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("empty range: "
			  "start_hash %llx, end_hash %llx\n",
			  index_area.start_hash,
			  index_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_process_index_area;
	}

	prev_hash = index_area.start_hash;

	for (i = 0; i < index_area.index_count; i++) {
		err = ssdfs_btree_node_get_index(fsi,
						 &node->content,
						 index_area.offset,
						 index_area.area_size,
						 node->node_size,
						 (u16)i, &index);
		if (unlikely(err)) {
			atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
			SSDFS_ERR("fail to extract index: "
				  "node_id %u, index %d, err %d\n",
				  node->node_id, 0, err);
			goto finish_process_index_area;
		}

		start_hash = le64_to_cpu(index.index.hash);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("prev_hash %llx, start_hash %llx, "
			  "index_area.start_hash %llx\n",
			  prev_hash, start_hash,
			  index_area.start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

		if (prev_hash != start_hash) {
			err = ssdfs_process_deleted_nodes(node, q,
							  prev_hash,
							  start_hash,
							  inodes_per_node);
			if (unlikely(err)) {
				SSDFS_ERR("fail to process deleted nodes: "
					  "start_hash %llx, end_hash %llx, "
					  "err %d\n",
					  prev_hash, start_hash, err);
				goto finish_process_index_area;
			}
		}

		prev_hash = start_hash + inodes_per_node;
	}

	if (prev_hash < index_area.end_hash) {
		start_hash = index_area.end_hash + inodes_per_node;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("prev_hash %llx, start_hash %llx, "
			  "index_area.end_hash %llx\n",
			  prev_hash, start_hash,
			  index_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_process_deleted_nodes(node, q,
						  prev_hash,
						  start_hash,
						  inodes_per_node);
		if (unlikely(err)) {
			SSDFS_ERR("fail to process deleted nodes: "
				  "start_hash %llx, end_hash %llx, "
				  "err %d\n",
				  prev_hash, start_hash, err);
			goto finish_process_index_area;
		}
	}

finish_process_index_area:
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
	struct folio *folio;
	void *kaddr;
	u32 node_size;
	u16 flags;
	u16 item_size;
	u32 items_count = 0;
	u8 index_size;
	u16 items_capacity;
	u32 index_area_size = 0;
	u16 index_capacity = 0;
	u16 inodes_count;
	u16 valid_inodes;
	size_t bmap_bytes;
	u64 start_hash, end_hash;
	unsigned long start, end;
	unsigned long size, upper_bound;
	signed long count;
	unsigned long free_inodes;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

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

	if (node->content.count == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty node's content: id %u\n",
			  node->node_id);
		goto finish_init_node;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(folio_batch_count(&node->content.blocks[0].batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	folio = node->content.blocks[0].batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = kmap_local_folio(folio, 0);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("PAGE DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     kaddr,
			     PAGE_SIZE);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

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

	ssdfs_memcpy(&node->raw.inodes_header, 0, hdr_size,
		     hdr, 0, hdr_size,
		     hdr_size);

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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("start_hash %llx, end_hash %llx, "
		  "items_capacity %u, valid_inodes %u, "
		  "inodes_count %u\n",
		  start_hash, end_hash, items_capacity,
		  valid_inodes, inodes_count);
#endif /* CONFIG_SSDFS_DEBUG */

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

	switch (hdr->node.type) {
	case SSDFS_BTREE_LEAF_NODE:
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
		free_inodes = inodes_count - valid_inodes;

		node->items_area.free_space = (u32)free_inodes * item_size;
		if (node->items_area.free_space > node->items_area.area_size) {
			err = -EIO;
			SSDFS_ERR("free_space %u > area_size %u\n",
				  node->items_area.free_space,
				  node->items_area.area_size);
			goto finish_header_init;
		}

		items_count = node_size / item_size;
		items_capacity = node_size / item_size;

		index_capacity = 0;
		break;

	case SSDFS_BTREE_HYBRID_NODE:
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
		free_inodes = inodes_count - valid_inodes;

		node->items_area.free_space = (u32)free_inodes * item_size;
		if (node->items_area.free_space > node->items_area.area_size) {
			err = -EIO;
			SSDFS_ERR("free_space %u > area_size %u\n",
				  node->items_area.free_space,
				  node->items_area.area_size);
			goto finish_header_init;
		}

		node->index_area.start_hash =
				le64_to_cpu(hdr->index_area.start_hash);
		node->index_area.end_hash =
				le64_to_cpu(hdr->index_area.end_hash);

		if (node->index_area.start_hash >= U64_MAX ||
		    node->index_area.end_hash >= U64_MAX) {
			err = -EIO;
			SSDFS_ERR("corrupted node: "
				  "index_area (start_hash %llx, end_hash %llx)\n",
				  node->index_area.start_hash,
				  node->index_area.end_hash);
			goto finish_header_init;
		}

		items_count = node_size / item_size;
		items_capacity = node_size / item_size;

		index_capacity = ssdfs_inodes_btree_node_index_capacity(node);
		break;

	case SSDFS_BTREE_INDEX_NODE:
		node->items_area.items_count = 0;
		node->items_area.items_capacity = 0;
		node->items_area.free_space = 0;

		items_count = 0;
		items_capacity = 0;

		if (start_hash != le64_to_cpu(hdr->index_area.start_hash) ||
		    end_hash != le64_to_cpu(hdr->index_area.end_hash)) {
			err = -EIO;
			SSDFS_ERR("corrupted node: "
				  "node index_area "
				  "(start_hash %llx, end_hash %llx), "
				  "header index_area "
				  "(start_hash %llx, end_hash %llx)\n",
				  node->index_area.start_hash,
				  node->index_area.end_hash,
				  le64_to_cpu(hdr->index_area.start_hash),
				  le64_to_cpu(hdr->index_area.end_hash));
			goto finish_header_init;
		}

		index_capacity = ssdfs_inodes_btree_node_index_capacity(node);
		break;

	default:
		SSDFS_ERR("unexpected node type %#x\n",
			  hdr->node.type);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, area_size %u, free_space %u\n",
		  node->items_area.items_count,
		  node->items_area.area_size,
		  node->items_area.free_space);
#endif /* CONFIG_SSDFS_DEBUG */

finish_header_init:
	up_write(&node->header_lock);

	if (unlikely(err))
		goto finish_init_operation;

	bmap_bytes = index_capacity + items_capacity + 1;
	bmap_bytes += BITS_PER_LONG + (BITS_PER_LONG - 1);
	bmap_bytes /= BITS_PER_BYTE;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_capacity %u, items_capacity %u, bmap_bytes %zu\n",
		  index_capacity, items_capacity, bmap_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	if (bmap_bytes == 0 || bmap_bytes > SSDFS_INODE_BMAP_SIZE) {
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_capacity %u, index_area_size %u, "
		  "index_size %u\n",
		  index_capacity, index_area_size, index_size);
	SSDFS_DBG("index_start_bit %lu, item_start_bit %lu, "
		  "bits_count %lu\n",
		  node->bmap_array.index_start_bit,
		  node->bmap_array.item_start_bit,
		  node->bmap_array.bits_count);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_btree_node_init_bmaps(node, addr);

	spin_lock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);
	ssdfs_memcpy(node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].ptr,
		     0, bmap_bytes,
		     hdr->bmap,
		     0, bmap_bytes,
		     bmap_bytes);
	spin_unlock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);

	start = node->bmap_array.item_start_bit;

	up_write(&node->bmap_array.lock);
finish_init_operation:
	kunmap_local(kaddr);

	if (unlikely(err))
		goto finish_init_node;

	if (hdr->node.type == SSDFS_BTREE_INDEX_NODE)
		goto finish_init_node;

	ssdfs_free_inodes_queue_init(&q);

	switch (hdr->node.type) {
	case SSDFS_BTREE_HYBRID_NODE:
		err = ssdfs_inodes_btree_detect_deleted_nodes(node, &q);
		if (unlikely(err)) {
			SSDFS_ERR("fail to detect deleted nodes: "
				  "err %d\n", err);
			ssdfs_free_inodes_queue_remove_all(&q);
			goto finish_init_node;
		}
		break;

	default:
		/* do nothing */
		break;
	}

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

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start_hash %llx, end_hash %llx, "
			  "range->area.start_hash %llx\n",
			  start_hash, end_hash,
			  range->area.start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

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

		spin_lock(&tree->lock);
		if (range->area.start_hash > tree->last_free_ino) {
			tree->last_free_ino =
				range->area.start_hash + range->area.count;
		}
		spin_unlock(&tree->lock);

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

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("add free range: node_id %u, "
			  "start_hash %llx, start_index %u, "
			  "count %u\n",
			  range->node_id,
			  range->area.start_hash,
			  range->area.start_index,
			  range->area.count);
#endif /* CONFIG_SSDFS_DEBUG */

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
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("operation is unavailable\n");
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_add_free_items_range() - add free items range
 * @itree: pointer on inodes tree
 * @node_id: node identification number
 * @start_hash: start hash of the range
 * @items_count: items count in items area
 * @items_capacity: capacity of items area
 *
 * This method tries to add free items range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_add_free_items_range(struct ssdfs_inodes_btree_info *itree,
				u32 node_id, u64 start_hash,
				u16 items_count, u16 items_capacity)
{
	struct ssdfs_inodes_btree_range *range = NULL;
	u16 free_items;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!itree);
	BUG_ON(start_hash >= U64_MAX);
	BUG_ON(items_capacity == 0);
	BUG_ON(items_count > items_capacity);

	SSDFS_DBG("node_id %u, start_hash %#llx, "
		  "items_count %u, items_capacity %u\n",
		  node_id, start_hash,
		  items_count, items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	free_items = items_capacity - items_count;

	range = ssdfs_free_inodes_range_alloc();
	if (unlikely(!range)) {
		SSDFS_ERR("fail to allocate inodes range\n");
		return -ENOMEM;
	}

	ssdfs_free_inodes_range_init(range);
	range->node_id = node_id;
	range->area.start_hash = start_hash + items_count;
	range->area.start_index = items_count;
	range->area.count = free_items;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("add free range: node_id %u, "
		  "start_hash %llx, start_index %u, "
		  "count %u\n",
		  range->node_id,
		  range->area.start_hash,
		  range->area.start_index,
		  range->area.count);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_free_inodes_queue_add_tail(&itree->free_inodes_queue, range);

	spin_lock(&itree->lock);
	if (range->area.start_hash > itree->last_free_ino) {
		itree->last_free_ino =
			range->area.start_hash + range->area.count;
	}
	spin_unlock(&itree->lock);

	return 0;
}

/*
 * ssdfs_inodes_btree_correct_leaf_node_hash_range() - correct node's hash range
 * @node: pointer on node object
 * @start_hash: start hash of the range
 *
 * This method tries to correct leaf node's hash range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static int
ssdfs_inodes_btree_correct_leaf_node_hash_range(struct ssdfs_btree_node *node,
						u64 start_hash)
{
	struct ssdfs_inodes_btree_info *itree;
	u16 items_count;
	u16 items_capacity;
	int type;
	int items_area_flags = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(start_hash >= U64_MAX);

	SSDFS_DBG("node_id %u, state %#x, "
		  "node_type %#x, start_hash %llx\n",
		  node->node_id, atomic_read(&node->state),
		  atomic_read(&node->type), start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	itree = (struct ssdfs_inodes_btree_info *)node->tree;
	type = atomic_read(&node->type);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(type != SSDFS_BTREE_LEAF_NODE);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&node->header_lock);

	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = start_hash + items_capacity - 1;

	items_area_flags = atomic_read(&node->items_area.flags);
	atomic_set(&node->items_area.flags,
		    items_area_flags & ~SSDFS_PLEASE_ADD_FREE_ITEMS_RANGE);

	up_write(&node->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(items_count > items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	if (items_capacity == 0) {
		SSDFS_ERR("invalid node state: "
			  "type %#x, items_capacity %u\n",
			  type, items_capacity);
		return -ERANGE;
	} else {
		err = ssdfs_add_free_items_range(itree, node->node_id,
						 start_hash, items_count,
						 items_capacity);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add free range: "
				  "node_id %u, start_hash %#llx, "
				  "items_count %u, items_capacity %u\n",
				  node->node_id, start_hash,
				  items_count, items_capacity);
			return err;
		}
	}

	ssdfs_debug_btree_node_object(node);

	return 0;
}

/*
 * ssdfs_add_hybrid_node_self_index() - add hybrid node's self index
 * @node: pointer on node object
 * @start_hash: start hash of the range
 *
 * This method tries to add hybrid node's self index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_add_hybrid_node_self_index(struct ssdfs_btree_node *node,
				     u64 start_hash)
{
	struct ssdfs_btree_index_key new_key;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(start_hash >= U64_MAX);

	SSDFS_DBG("node_id %u, state %#x, "
		  "node_type %#x, start_hash %llx\n",
		  node->node_id, atomic_read(&node->state),
		  atomic_read(&node->type), start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&node->descriptor_lock);
	ssdfs_memcpy(&new_key,
		     0, sizeof(struct ssdfs_btree_index_key),
		     &node->node_index,
		     0, sizeof(struct ssdfs_btree_index_key),
		     sizeof(struct ssdfs_btree_index_key));
	spin_unlock(&node->descriptor_lock);

	new_key.index.hash = cpu_to_le64(start_hash);

	err = ssdfs_btree_node_add_index(node, &new_key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add index: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_inodes_btree_correct_hybrid_node_hash_range() - correct node's hash range
 * @node: pointer on node object
 * @start_hash: start hash of the range
 *
 * This method tries to correct hybrid node's hash range.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static int
ssdfs_inodes_btree_correct_hybrid_node_hash_range(struct ssdfs_btree_node *node,
						  u64 start_hash)
{
	struct ssdfs_inodes_btree_info *itree;
	u64 end_hash;
	u64 old_start_hash, old_end_hash;
	u16 items_count;
	u16 items_capacity;
	int type;
	int index_area_flags = 0;
	int items_area_flags = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(start_hash >= U64_MAX);

	SSDFS_DBG("node_id %u, state %#x, "
		  "node_type %#x, start_hash %llx\n",
		  node->node_id, atomic_read(&node->state),
		  atomic_read(&node->type), start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	itree = (struct ssdfs_inodes_btree_info *)node->tree;
	type = atomic_read(&node->type);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(type != SSDFS_BTREE_HYBRID_NODE);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&node->header_lock);

	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;
	old_start_hash = node->items_area.start_hash;
	old_end_hash = node->items_area.end_hash;
	end_hash = start_hash + items_capacity - 1;

	index_area_flags = atomic_read(&node->index_area.flags);
	atomic_set(&node->index_area.flags,
		    index_area_flags & ~SSDFS_PLEASE_ADD_HYBRID_NODE_SELF_INDEX);

	items_area_flags = atomic_read(&node->items_area.flags);
	atomic_set(&node->items_area.flags,
		    items_area_flags & ~SSDFS_PLEASE_ADD_FREE_ITEMS_RANGE);

	if (old_start_hash == end_hash) {
		err = -ERANGE;
		SSDFS_ERR("corrupted node: "
			  "request (start_hash %#llx, end_hash %#llx), "
			  "node (start_hash %#llx, end_hash %#llx)\n",
			  start_hash, end_hash,
			  old_start_hash, old_end_hash);
	} else if (old_start_hash > end_hash) {
		/*
		 * Hybrid node has free indexes.
		 * Do nothing.
		 */
	} else {
		node->items_area.start_hash = start_hash;
		node->items_area.end_hash = end_hash;
	}

	up_write(&node->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(items_count > items_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	if (items_capacity == 0) {
		SSDFS_ERR("invalid node state: "
			  "type %#x, items_capacity %u\n",
			  type, items_capacity);
		return -ERANGE;
	}

	if (old_start_hash > end_hash) {
		err = ssdfs_add_free_items_range(itree, U32_MAX,
						 start_hash, items_count,
						 items_capacity);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add free range: "
				  "node_id %u, start_hash %#llx, "
				  "items_count %u, items_capacity %u\n",
				  node->node_id, start_hash,
				  items_count, items_capacity);
			return err;
		}
	} else if (old_start_hash == start_hash) {
		if (index_area_flags & SSDFS_PLEASE_ADD_HYBRID_NODE_SELF_INDEX) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("add self index: "
				  "node_id %u, state %#x, "
				  "node_type %#x, start_hash %llx\n",
				  node->node_id, atomic_read(&node->state),
				  atomic_read(&node->type), start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_add_hybrid_node_self_index(node,
								start_hash);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add index: err %d\n",
					  err);
				return err;
			}
		}

		if (items_area_flags & SSDFS_PLEASE_ADD_FREE_ITEMS_RANGE) {
			err = ssdfs_add_free_items_range(itree,
							 node->node_id,
							 start_hash,
							 items_count,
							 items_capacity);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add free range: "
					  "node_id %u, start_hash %#llx, "
					  "items_count %u, items_capacity %u\n",
					  node->node_id, start_hash,
					  items_count, items_capacity);
				return err;
			}
		}
	} else {
		err = ssdfs_add_hybrid_node_self_index(node, start_hash);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add index: err %d\n",
				  err);
			return err;
		}

		err = ssdfs_add_free_items_range(itree, node->node_id,
						 start_hash, items_count,
						 items_capacity);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add free range: "
				  "node_id %u, start_hash %#llx, "
				  "items_count %u, items_capacity %u\n",
				  node->node_id, start_hash,
				  items_count, items_capacity);
			return err;
		}
	}

	ssdfs_debug_btree_node_object(node);

	return 0;
}

/*
 * ssdfs_inodes_btree_node_correct_hash_range() - correct node's hash range
 * @node: pointer on node object
 * @start_hash: start hash of the range
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
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(start_hash >= U64_MAX);

	SSDFS_DBG("node_id %u, state %#x, "
		  "node_type %#x, start_hash %llx\n",
		  node->node_id, atomic_read(&node->state),
		  atomic_read(&node->type), start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_LEAF_NODE:
		return ssdfs_inodes_btree_correct_leaf_node_hash_range(node,
								start_hash);

	case SSDFS_BTREE_HYBRID_NODE:
		return ssdfs_inodes_btree_correct_hybrid_node_hash_range(node,
								    start_hash);

	default:
		/* do nothing */
		break;
	}

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
	struct ssdfs_btree_node *parent_node = NULL;
	int type;
	u64 start_hash = U64_MAX;
	u16 items_capacity;
	spinlock_t *lock;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

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

		lock = &node->descriptor_lock;
		spin_lock(lock);
		parent_node = node->parent_node;
		spin_unlock(lock);
		lock = NULL;

		start_hash += items_capacity;

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

	err = ssdfs_btree_update_parent_node_pointer(node->tree, node);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update parent pointer: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

	ssdfs_debug_btree_node_object(node);

	return 0;
}

static
int ssdfs_correct_hybrid_node_hashes(struct ssdfs_btree_node *node);

/*
 * ssdfs_inodes_btree_delete_node() - prepare node for deletion
 * @node: pointer on node object
 *
 * This method tries to finish deletion of node from inodes btree.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_inodes_btree_delete_node(struct ssdfs_btree_node *node)
{
	struct ssdfs_btree_node *parent;
	u16 items_count;
	u16 index_count;
	u64 old_hash;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));

	ssdfs_debug_btree_node_object(node);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_LEAF_NODE:
		spin_lock(&node->descriptor_lock);
		parent = node->parent_node;
		spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!parent);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (atomic_read(&parent->type)) {
		case SSDFS_BTREE_HYBRID_NODE:
			if (is_ssdfs_btree_node_pre_deleted(parent)) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("do nothing: "
					  "node %u is pre-deleted\n",
					  parent->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_delete_node;
			}

			down_read(&parent->header_lock);
			items_count = parent->items_area.items_count;
			index_count = parent->index_area.index_count;
			old_hash = parent->items_area.start_hash;
			up_read(&parent->header_lock);

			if (items_count == 0) {
				if (index_count == 0) {
					SSDFS_ERR("hybrid node hasn't self index: "
						  "node_id %u\n",
						  parent->node_id);
					return -ERANGE;
				} else if (index_count == 1) {
#ifdef CONFIG_SSDFS_DEBUG
					SSDFS_DBG("hybrid node has self index only: "
						  "node_id %u\n",
						  parent->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
					goto finish_delete_node;
				}

				err = ssdfs_btree_node_delete_index(parent,
								    old_hash);
				if (unlikely(err)) {
					SSDFS_ERR("fail to delete index: "
						  "old_hash %llx, err %d\n",
						  old_hash, err);
					return err;
				}

				err = ssdfs_correct_hybrid_node_hashes(parent);
				if (unlikely(err)) {
					SSDFS_ERR("fail to correct hybrid nodes: "
						  "err %d\n", err);
					return err;
				}
			}
			break;

		default:
			/* do nothing */
			break;
		}
		break;

	default:
		/* do nothing */
		break;
	}

finish_delete_node:
	return 0;
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
	struct ssdfs_fs_info *fsi;
	struct ssdfs_inodes_btree_node_header inodes_header;
	struct ssdfs_state_bitmap *bmap;
	struct folio *folio;
	size_t hdr_size = sizeof(struct ssdfs_inodes_btree_node_header);
	u32 bmap_bytes;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, state %#x\n",
		  node->node_id, atomic_read(&node->state));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	ssdfs_debug_btree_node_object(node);

	switch (atomic_read(&node->state)) {
	case SSDFS_BTREE_NODE_DIRTY:
		/* expected state */
		break;

	case SSDFS_BTREE_NODE_INITIALIZED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is clean\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;

	case SSDFS_BTREE_NODE_PRE_DELETED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is pre-deleted\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
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

	ssdfs_memcpy(&inodes_header, 0, hdr_size,
		     &node->raw.inodes_header, 0, hdr_size,
		     hdr_size);

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

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
		inodes_header.index_area.start_hash =
				cpu_to_le64(node->index_area.start_hash);
		inodes_header.index_area.end_hash =
				cpu_to_le64(node->index_area.end_hash);
		break;

	case SSDFS_BTREE_LEAF_NODE:
		/* do nothing */
		break;

	default:
		SSDFS_WARN("invalid node type %#x\n",
			   atomic_read(&node->type));
		break;
	};

	down_read(&node->bmap_array.lock);
	bmap_bytes = node->bmap_array.bmap_bytes;
	spin_lock(&node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].lock);
	ssdfs_memcpy(inodes_header.bmap,
		     0, bmap_bytes,
		     node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP].ptr,
		     0, bmap_bytes,
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

	ssdfs_memcpy(&node->raw.inodes_header, 0, hdr_size,
		     &inodes_header, 0, hdr_size,
		     hdr_size);

finish_inodes_header_preparation:
	up_write(&node->header_lock);

	if (unlikely(err))
		goto finish_node_pre_flush;

	if (node->content.count < 1) {
		err = -ERANGE;
		SSDFS_ERR("folio batch is empty\n");
		goto finish_node_pre_flush;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(folio_batch_count(&node->content.blocks[0].batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	folio = node->content.blocks[0].batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	__ssdfs_memcpy_to_folio(folio, 0, folio_size(folio),
				&inodes_header, 0, hdr_size,
				hdr_size);

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

	SSDFS_DBG("node %p, node_id %u\n",
		  node, node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */

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
	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to extract range: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (err)
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, items_capacity %u, "
		  "item_start_bit %lu, found_index %llu, "
		  "start_index %llu, found_bit %llu\n",
		  items_count, items_capacity,
		  item_start_bit, found_index,
		  start_index, found_bit);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_allocated) {
		if (search->request.count == 1) {
			search->result.buf_state =
				SSDFS_BTREE_SEARCH_INLINE_BUFFER;
			search->result.buf = &search->raw.inode;
			search->result.buf_size = item_size;
			search->result.items_in_buffer = 0;
		} else {
			err = ssdfs_btree_search_alloc_result_buf(search,
					item_size * search->request.count);
			if (unlikely(err)) {
				SSDFS_ERR("fail to allocate buffer\n");
				return err;
			}
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

#ifdef CONFIG_SSDFS_DEBUG
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
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("node (id %u, start_hash %llx, "
		  "end_hash %llx), "
		  "request (start_hash %llx, "
		  "end_hash %llx, flags %#x)\n",
		  search->node.id, start_hash, end_hash,
		  search->request.start.hash,
		  search->request.end.hash,
		  search->request.flags);
#endif /* CONFIG_SSDFS_DEBUG */

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
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	struct folio_batch *batch;
	size_t item_size = sizeof(struct ssdfs_inode);
	u32 area_offset;
	u32 area_size;
	u32 item_offset;
	u32 dst_offset;
	u32 buf_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, item_index %u, buf_index %u\n",
		  node->node_id, item_index, buf_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

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
		SSDFS_ERR("invalid page_index: "
			  "index %d, blks_count %u\n",
			  folio.desc.folio_index,
			  node->content.count);
		return -ERANGE;
	}

	batch = &node->content.blocks[folio.desc.folio_index].batch;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(folio_batch_count(batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

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
	dst_offset = folio.desc.offset - folio.desc.folio_offset;

	err = ssdfs_memcpy_to_batch(batch, dst_offset,
				    search->result.buf,
				    buf_offset, search->result.buf_size,
				    item_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy item: "
			  "buf_offset %u, item_offset %u, "
			  "item_size %zu, buf_size %zu\n",
			  buf_offset, item_offset,
			  item_size, search->result.buf_size);
		return err;
	}

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
	u64 free_inodes;
	u64 allocated_inodes;
	u64 upper_allocated_ino;
	u64 inodes_capacity;
	u32 used_space;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&node->header_lock);
	item_size = node->items_area.item_size;
	max_item_size = node->items_area.max_item_size;
	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	up_read(&node->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, start %u, count %u, "
		  "items_count %u, items_capacity %u, "
		  "start_hash %llx, end_hash %llx\n",
		  node->node_id, start, count,
		  items_count, items_capacity,
		  start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

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

	if (search->request.start.hash < start_hash) {
		SSDFS_ERR("invalid request: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx)\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash);
		return -ERANGE;
	}

	if (search->request.end.hash > end_hash) {
		SSDFS_ERR("invalid request: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx)\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash);
		return -ERANGE;
	}

	item_index = search->result.start_index;

	if (start != item_index) {
		search->result.start_index = start;
		item_index = search->result.start_index;
	}

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
	search->result.buf_size = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("search->result.start_index %u\n",
		  (u32)search->result.start_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (count > 1) {
		size_t allocated_bytes = item_size * count;

		err = ssdfs_btree_search_alloc_result_buf(search,
							  allocated_bytes);
		if (unlikely(err)) {
			SSDFS_ERR("fail to allocate memory for buffer\n");
			goto finish_allocate_item;
		}
		search->result.items_in_buffer = count;
		search->result.buf_size = allocated_bytes;
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
	ssdfs_memcpy(hdr->bmap, 0, bmap_bytes,
		     bmap->ptr, 0, bmap_bytes,
		     bmap_bytes);
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);
	node->items_area.items_count += count;
	used_space = (u32)node->items_area.item_size * count;
	if (used_space > node->items_area.free_space) {
		err = -ERANGE;
		SSDFS_ERR("used_space %u > free_space %u\n",
			  used_space,
			  node->items_area.free_space);
		goto finish_change_node_header;
	} else
		node->items_area.free_space -= used_space;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, area_size %u, "
		  "free_space %u, valid_inodes %u\n",
		  node->items_area.items_count,
		  node->items_area.area_size,
		  node->items_area.free_space,
		  le16_to_cpu(hdr->valid_inodes));
#endif /* CONFIG_SSDFS_DEBUG */

	up_write(&node->header_lock);

finish_change_node_header:
	if (unlikely(err))
		goto finish_allocate_item;

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
	free_inodes = itree->free_inodes;
	if (free_inodes < count)
		err = -ERANGE;
	else {
		u64 upper_bound = start_hash + start + count - 1;

		itree->allocated_inodes += count;
		itree->free_inodes -= count;
		if (itree->upper_allocated_ino < upper_bound)
			itree->upper_allocated_ino = upper_bound;
	}

	upper_allocated_ino = itree->upper_allocated_ino;
	allocated_inodes = itree->allocated_inodes;
	free_inodes = itree->free_inodes;
	inodes_capacity = itree->inodes_capacity;
	spin_unlock(&itree->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("upper_allocated_ino %llu, allocated_inodes %llu, "
		  "free_inodes %llu, inodes_capacity %llu\n",
		  itree->upper_allocated_ino,
		  itree->allocated_inodes,
		  itree->free_inodes,
		  itree->inodes_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_ERR("fail to correct free_inodes count: "
			  "free_inodes %llu, count %u, err %d\n",
			  free_inodes, count, err);
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
#endif /* CONFIG_SSDFS_DEBUG */

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
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("operation is unavailable\n");
#endif /* CONFIG_SSDFS_DEBUG */
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
	struct ssdfs_inodes_btree_node_header *hdr;
	struct ssdfs_btree_node_items_area items_area;
	size_t item_size = sizeof(struct ssdfs_inode);
	struct ssdfs_btree_index_key key;
	u16 item_index;
	int free_items;
	u16 inodes_count = 0;
	u32 used_space;
	u16 items_count = 0;
	u16 valid_inodes = 0;
	u64 free_inodes;
	u64 allocated_inodes;
	u64 inodes_capacity;
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_capacity %u, items_count %u\n",
		  items_area.items_capacity,
		  items_area.items_count);
	SSDFS_DBG("area_size %u, free_space %u\n",
		  items_area.area_size,
		  items_area.free_space);
#endif /* CONFIG_SSDFS_DEBUG */

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
	items_count = node->items_area.items_count;

	hdr = &node->raw.inodes_header;
	le16_add_cpu(&hdr->valid_inodes, (u16)search->request.count);
	valid_inodes = le16_to_cpu(hdr->valid_inodes);

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

	if (unlikely(err))
		return err;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		spin_lock(&node->descriptor_lock);
		ssdfs_memcpy(&key,
			     0, sizeof(struct ssdfs_btree_index_key),
			     &node->node_index,
			     0, sizeof(struct ssdfs_btree_index_key),
			     sizeof(struct ssdfs_btree_index_key));
		spin_unlock(&node->descriptor_lock);

		key.index.hash = cpu_to_le64(search->request.start.hash);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node_id %u, node_type %#x, "
			  "node_height %u, hash %llx\n",
			  le32_to_cpu(key.node_id),
			  key.node_type,
			  key.height,
			  le64_to_cpu(key.index.hash));
#endif /* CONFIG_SSDFS_DEBUG */

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

	spin_lock(&itree->lock);
	free_inodes = itree->free_inodes;
	if (free_inodes < search->request.count)
		err = -ERANGE;
	else {
		itree->allocated_inodes += search->request.count;
		itree->free_inodes -= search->request.count;
	}
	allocated_inodes = itree->allocated_inodes;
	free_inodes = itree->free_inodes;
	inodes_capacity = itree->inodes_capacity;
	spin_unlock(&itree->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("valid_inodes %u, items_count %u, "
		  "allocated_inodes %llu, "
		  "free_inodes %llu, inodes_capacity %llu, "
		  "search->request.count %u\n",
		  valid_inodes, items_count,
		  allocated_inodes,
		  free_inodes, inodes_capacity,
		  search->request.count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_ERR("fail to correct allocated_inodes count: "
			  "err %d\n",
			  err);
		return err;
	}

	ssdfs_debug_btree_node_object(node);

	return 0;
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

	err = __ssdfs_inodes_btree_node_insert_range(node, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to insert range: "
			  "node_id %u, err %d\n",
			  node->node_id, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_space %u\n", node->items_area.free_space);
#endif /* CONFIG_SSDFS_DEBUG */

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
	u64 found_index;
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

	ssdfs_debug_btree_search_object(search);
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

	err = ssdfs_btree_node_check_hash_range(node,
						items_count,
						items_capacity,
						start_hash,
						end_hash,
						search);
	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to extract range: "
			  "node (start_hash %llx, end_hash %llx), "
			  "request (start_hash %llx, end_hash %llx), "
			  "err %d\n",
			  start_hash, end_hash,
			  search->request.start.hash,
			  search->request.end.hash,
			  err);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (err)
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

	item_index = (u16)found_index;

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
 * ssdfs_correct_hybrid_node_hashes() - correct items area hashes
 * @node: pointer on node object
 */
static
int ssdfs_correct_hybrid_node_hashes(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_index_key key;
	size_t hdr_size = sizeof(struct ssdfs_inodes_btree_node_header);
	u64 start_hash;
	u64 end_hash;
	u16 items_count;
	u16 index_count;
	u32 items_area_size;
	u32 items_capacity;
	u16 index_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		/* expected node type */
		break;

	default:
		return -ERANGE;
	}

	down_write(&node->header_lock);

	items_count = node->items_area.items_count;

	if (items_count != 0) {
		err = -ERANGE;
		SSDFS_ERR("invalid request: items_count %u\n",
			  items_count);
		goto unlock_header;
	}

	index_count = node->index_area.index_count;

	if (index_count == 0) {
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("do nothing: node %u is empty\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto unlock_header;
	}

	index_id = index_count - 1;
	err = ssdfs_btree_node_get_index(fsi,
					 &node->content,
					 node->index_area.offset,
					 node->index_area.area_size,
					 node->node_size,
					 index_id, &key);
	if (unlikely(err)) {
		atomic_set(&node->state, SSDFS_BTREE_NODE_CORRUPTED);
		SSDFS_ERR("fail to extract index: "
			  "node_id %u, index %d, err %d\n",
			  node->node_id, index_id, err);
		goto unlock_header;
	}

	items_area_size = node->node_size - hdr_size;
	items_capacity = items_area_size / node->tree->item_size;

	start_hash = le64_to_cpu(key.index.hash);
	start_hash += items_capacity;
	end_hash = start_hash + node->items_area.items_capacity - 1;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, index_count %u, index_id %u, "
		  "start_hash %llx, end_hash %llx\n",
		  node->node_id, index_count, index_id,
		  start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	node->items_area.start_hash = start_hash;
	node->items_area.end_hash = end_hash;

unlock_header:
	up_write(&node->header_lock);

	if (err == -ENODATA) {
		err = 0;
		/* do nothing */
		goto finish_correct_hybrid_node_hashes;
	} else if (unlikely(err)) {
		/* finish logic */
		goto finish_correct_hybrid_node_hashes;
	}

	spin_lock(&node->descriptor_lock);
	ssdfs_memcpy(&key,
		     0, sizeof(struct ssdfs_btree_index_key),
		     &node->node_index,
		     0, sizeof(struct ssdfs_btree_index_key),
		     sizeof(struct ssdfs_btree_index_key));
	spin_unlock(&node->descriptor_lock);

	key.index.hash = cpu_to_le64(start_hash);

	err = ssdfs_btree_node_add_index(node, &key);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add index: err %d\n",
			  err);
		return err;
	}

finish_correct_hybrid_node_hashes:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, "
		  "items_area (start_hash %llx, end_hash %llx), "
		  "index_area (start_hash %llx, end_hash %llx)\n",
		  node->node_id,
		  node->items_area.start_hash,
		  node->items_area.end_hash,
		  node->index_area.start_hash,
		  node->index_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
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
	u16 index_count = 0;
	int free_items;
	u64 start_hash;
	u64 end_hash;
	u64 old_hash;
	u64 index_start_hash;
	u64 index_end_hash;
	u32 bmap_bytes;
	u16 valid_inodes;
	u64 allocated_inodes;
	u64 free_inodes;
	u64 inodes_capacity;
	u32 area_size;
	u32 freed_space;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !search);

	SSDFS_DBG("node_id %u, type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  node->node_id,
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

	down_read(&node->header_lock);
	state = atomic_read(&node->items_area.state);
	item_size = node->items_area.item_size;
	items_count = node->items_area.items_count;
	items_capacity = node->items_area.items_capacity;
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	old_hash = start_hash;
	up_read(&node->header_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, items_capacity %u, "
		  "node (start_hash %llx, end_hash %llx)\n",
		  items_count, items_capacity,
		  start_hash, end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

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

	err = ssdfs_btree_node_clear_range(node, &node->items_area,
					   item_size, search);
	if (unlikely(err)) {
		SSDFS_ERR("fail to clear items range: err %d\n",
			  err);
		goto finish_delete_range;
	}

	err = ssdfs_set_dirty_items_range(node, items_capacity,
					  item_index,
					  search->result.count);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set items range as dirty: "
			  "start %u, count %u, err %d\n",
			  item_index, search->result.count, err);
		goto finish_delete_range;
	}

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
	valid_inodes = le16_to_cpu(hdr->valid_inodes);
	down_read(&node->bmap_array.lock);
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP];
	bmap_bytes = node->bmap_array.bmap_bytes;
	spin_lock(&bmap->lock);
	ssdfs_memcpy(hdr->bmap, 0, bmap_bytes,
		     bmap->ptr, 0, bmap_bytes,
		     bmap_bytes);
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);
	node->items_area.items_count -= search->result.count;
	area_size = node->items_area.area_size;
	freed_space = (u32)node->items_area.item_size * search->result.count;
	if ((node->items_area.free_space + freed_space) > area_size) {
		err = -ERANGE;
		SSDFS_ERR("freed_space %u, free_space %u, area_size %u\n",
			  freed_space,
			  node->items_area.free_space,
			  area_size);
		goto finish_change_node_header;
	} else
		node->items_area.free_space += freed_space;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_count %u, valid_inodes %u, "
		  "area_size %u, free_space %u, "
		  "node (start_hash %llx, end_hash %llx)\n",
		  node->items_area.items_count,
		  valid_inodes,
		  node->items_area.area_size,
		  node->items_area.free_space,
		  node->items_area.start_hash,
		  node->items_area.end_hash);
#endif /* CONFIG_SSDFS_DEBUG */

	up_write(&node->header_lock);

finish_change_node_header:
	if (unlikely(err))
		goto finish_delete_range;

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

	down_read(&node->header_lock);
	items_count = node->items_area.items_count;
	start_hash = node->items_area.start_hash;
	end_hash = node->items_area.end_hash;
	index_count = node->index_area.index_count;
	index_start_hash = node->index_area.start_hash;
	index_end_hash = node->index_area.end_hash;
	up_read(&node->header_lock);

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_HYBRID_NODE:
		state = atomic_read(&node->index_area.state);

		if (state != SSDFS_BTREE_NODE_INDEX_AREA_EXIST) {
			SSDFS_ERR("invalid area state %#x\n",
				  state);
			return -ERANGE;
		}

		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_DELETE_RANGE:
		case SSDFS_BTREE_SEARCH_DELETE_ALL:
			/*
			 * Moving all items into a leaf node
			 */
			if (items_count == 0) {
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
			} else {
				SSDFS_WARN("unexpected items_count %u\n",
					   items_count);
				return -ERANGE;
			}
			break;

		case SSDFS_BTREE_SEARCH_DELETE_ITEM:
			if (items_count == 0) {
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

				err = ssdfs_correct_hybrid_node_hashes(node);
				if (unlikely(err)) {
					SSDFS_ERR("fail to correct hybrid nodes: "
						  "err %d\n", err);
					return err;
				}

				down_read(&node->header_lock);
				start_hash = node->items_area.start_hash;
				end_hash = node->items_area.end_hash;
				up_read(&node->header_lock);
			}
			break;

		default:
			BUG();
		}
		break;

	default:
		/* do nothing */
		break;
	}

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
	free_inodes = itree->free_inodes;
	allocated_inodes = itree->allocated_inodes;
	spin_unlock(&itree->lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("valid_inodes %u, allocated_inodes %llu, "
		  "free_inodes %llu, inodes_capacity %llu, "
		  "search->request.count %u\n",
		  valid_inodes, allocated_inodes,
		  free_inodes, inodes_capacity,
		  search->request.count);
	SSDFS_DBG("items_area (start_hash %llx, end_hash %llx), "
		  "index_area (start_hash %llx, end_hash %llx), "
		  "valid_inodes %u, index_count %u\n",
		  start_hash, end_hash,
		  index_start_hash, index_end_hash,
		  valid_inodes, index_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_ERR("fail to correct allocated_inodes count: "
			  "err %d\n",
			  err);
		return err;
	}

	if (valid_inodes == 0 && index_count == 0) {
		search->result.state = SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("PLEASE, DELETE node_id %u\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
	} else
		search->result.state = SSDFS_BTREE_SEARCH_OBSOLETE_RESULT;

	ssdfs_debug_btree_node_object(node);

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

	SSDFS_DBG("type %#x, flags %#x, "
		  "start_hash %llx, end_hash %llx, "
		  "state %#x, node_id %u, height %u, "
		  "parent %p, child %p\n",
		  search->request.type, search->request.flags,
		  search->request.start.hash, search->request.end.hash,
		  atomic_read(&node->state), node->node_id,
		  atomic_read(&node->height), search->node.parent,
		  search->node.child);

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
	struct ssdfs_inode *inode;
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

	down_read(&node->full_lock);
	err = __ssdfs_btree_node_extract_range(node, start_index, count,
						sizeof(struct ssdfs_inode),
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
	inode = (struct ssdfs_inode *)search->result.buf;
	search->request.start.hash = le64_to_cpu(inode->ino);
	inode += search->result.count - 1;
	search->request.end.hash = le64_to_cpu(inode->ino);
	search->request.count = count;

	return 0;
}

static
int ssdfs_inodes_btree_resize_items_area(struct ssdfs_btree_node *node,
					 u32 new_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("operation is unavailable\n");
#endif /* CONFIG_SSDFS_DEBUG */
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
