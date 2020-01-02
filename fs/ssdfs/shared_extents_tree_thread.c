//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/shared_extents_tree_thread.c - shared extents tree's thread impl.
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
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "extents_queue.h"
#include "request_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"
#include "shared_extents_tree.h"

#include <trace/events/ssdfs.h>

/*
 * has_shextree_pre_invalid_extents() - is invalidation queue empty?
 * @tree: shared extents tree's object
 * @index: queue's index
 */
static inline
bool has_shextree_pre_invalid_extents(struct ssdfs_shared_extents_tree *tree,
					int index)
{
	struct ssdfs_extents_queue *queue;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(index >= SSDFS_INVALIDATION_QUEUE_NUMBER);
#endif /* CONFIG_SSDFS_DEBUG */

	queue = &tree->array[index].queue;
	return !is_ssdfs_extents_queue_empty(queue);
}

/*
 * ssdfs_shextree_invalidate_extent() - invalidate extent
 * @tree: shared extents tree's object
 * @ei: extent info
 */
static
int ssdfs_shextree_invalidate_extent(struct ssdfs_shared_extents_tree *tree,
				     struct ssdfs_extent_info *ei)
{
	u64 seg_id;
	u32 logical_blk;
	u32 len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !ei);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_id = le64_to_cpu(ei->raw.extent.seg_id);
	logical_blk = le32_to_cpu(ei->raw.extent.logical_blk);
	len = le32_to_cpu(ei->raw.extent.len);

	SSDFS_DBG("tree %p, ei %p, seg_id %llu, "
		  "logical_blk %u, len %u\n",
		  tree, ei, seg_id, logical_blk, len);

	if (ei->type != SSDFS_EXTENT_INFO_RAW_EXTENT) {
		SSDFS_ERR("invalid type %#x\n",
			  ei->type);
		return -ERANGE;
	}

	return ssdfs_invalidate_extent(tree->fsi, &ei->raw.extent);
}

/*
 * ssdfs_shextree_invalidate_index() - invalidate index
 * @tree: shared extents tree's object
 * @ei: index info
 */
static
int ssdfs_shextree_invalidate_index(struct ssdfs_shared_extents_tree *tree,
				    struct ssdfs_extent_info *ei)
{
	u32 node_id;
	u8 node_type;
	u8 height;
	u16 flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !ei);
#endif /* CONFIG_SSDFS_DEBUG */

	node_id = le32_to_cpu(ei->raw.index.node_id);
	node_type = ei->raw.index.node_type;
	height = ei->raw.index.height;
	flags = ei->raw.index.flags;

	SSDFS_DBG("node_id %u, node_type %u, height %u, flags %#x\n",
		  node_id, node_type, height, flags);

	switch (ei->type) {
	case SSDFS_EXTENT_INFO_INDEX_DESCRIPTOR:
		return ssdfs_invalidate_extents_btree_index(tree->fsi,
							    ei->owner_ino,
							    &ei->raw.index);

	case SSDFS_EXTENT_INFO_DENTRY_INDEX_DESCRIPTOR:
		return ssdfs_invalidate_dentries_btree_index(tree->fsi,
							     ei->owner_ino,
							     &ei->raw.index);

	case SSDFS_EXTENT_INFO_SHDICT_INDEX_DESCRIPTOR:
		return ssdfs_invalidate_shared_dict_btree_index(tree->fsi,
								ei->owner_ino,
								&ei->raw.index);

	case SSDFS_EXTENT_INFO_XATTR_INDEX_DESCRIPTOR:
		return ssdfs_invalidate_xattrs_btree_index(tree->fsi,
							   ei->owner_ino,
							   &ei->raw.index);
	};

	SSDFS_ERR("invalid type %#x\n", ei->type);
	return -ERANGE;
}

#define SHEXTREE_PTR(tree) \
	((struct ssdfs_shared_extents_tree *)(tree))
#define SHEXTREE_THREAD_WAKE_CONDITION(tree, index) \
	(kthread_should_stop() || \
	 has_shextree_pre_invalid_extents(SHEXTREE_PTR(tree), index))

/*
 * ssdfs_shextree_extent_thread_func() - shextree object's thread's function
 */
static
int ssdfs_shextree_extent_thread_func(void *data)
{
	struct ssdfs_shared_extents_tree *tree = data;
	wait_queue_head_t *wait_queue;
	struct ssdfs_invalidation_queue *ptr;
	int id = SSDFS_EXTENT_INVALIDATION_QUEUE;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!tree) {
		SSDFS_ERR("pointer on shared extents tree's object is NULL\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("shared extents tree's thread: "
		  "extents invalidation queue\n");

	wait_queue = &tree->wait_queue;
	ptr = &tree->array[id];

repeat:
	if (unlikely(err)) {
		SSDFS_WARN("shared extents tree's thread failed: "
			   "err %d\n",
			   err);
		complete_all(&ptr->thread.full_stop);
		return err;
	}

	if (kthread_should_stop()) {
		if (has_shextree_pre_invalid_extents(tree, id))
			goto try_invalidate_queue;

		complete_all(&ptr->thread.full_stop);
		return err;
	}

	if (!has_shextree_pre_invalid_extents(tree, id))
		goto sleep_shextree_thread;

try_invalidate_queue:
	do {
		struct ssdfs_extent_info *ei = NULL;

		err = ssdfs_extents_queue_remove_first(&ptr->queue,
							&ei);
		if (err == -ENODATA) {
			err = 0;
			goto sleep_shextree_thread;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get extent for invalidation: "
				  "err %d\n",
				  err);
			goto repeat;
		} else if (ei == NULL) {
			err = -ERANGE;
			SSDFS_ERR("invalid extent info\n");
			goto repeat;
		}

		err = ssdfs_shextree_invalidate_extent(tree, ei);
		if (err) {
			ssdfs_fs_error(tree->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to invalidate extent: "
				"(seg_id %llu, logical_blk %u, len %u), "
				"err %d\n",
				le64_to_cpu(ei->raw.extent.seg_id),
				le32_to_cpu(ei->raw.extent.logical_blk),
				le32_to_cpu(ei->raw.extent.len),
				err);
			ssdfs_extent_info_free(ei);
			goto repeat;
		} else
			ssdfs_extent_info_free(ei);
	} while (has_shextree_pre_invalid_extents(tree, id));

	if (kthread_should_stop())
		goto repeat;

sleep_shextree_thread:
	wait_event_interruptible(*wait_queue,
				 SHEXTREE_THREAD_WAKE_CONDITION(tree, id));
	goto repeat;
}

/*
 * ssdfs_shextree_extent_thread_func() - shextree object's thread's function
 */
static
int ssdfs_shextree_index_thread_func(void *data)
{
	struct ssdfs_shared_extents_tree *tree = data;
	wait_queue_head_t *wait_queue;
	struct ssdfs_invalidation_queue *ptr;
	int id = SSDFS_INDEX_INVALIDATION_QUEUE;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!tree) {
		SSDFS_ERR("pointer on shared extents tree's object is NULL\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("shared extents tree's thread: "
		  "index invalidation queue\n");

	wait_queue = &tree->wait_queue;
	ptr = &tree->array[id];

repeat:
	if (unlikely(err)) {
		SSDFS_WARN("shared extents tree's thread failed: "
			   "err %d\n",
			   err);
		complete_all(&ptr->thread.full_stop);
		return err;
	}

	if (kthread_should_stop()) {
		if (has_shextree_pre_invalid_extents(tree, id))
			goto try_invalidate_queue;

		complete_all(&ptr->thread.full_stop);
		return err;
	}

	if (!has_shextree_pre_invalid_extents(tree, id))
		goto sleep_shextree_thread;

try_invalidate_queue:
	do {
		struct ssdfs_extent_info *ei = NULL;

		err = ssdfs_extents_queue_remove_first(&ptr->queue,
							&ei);
		if (err == -ENODATA) {
			err = 0;
			goto sleep_shextree_thread;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get index for invalidation: "
				  "err %d\n",
				  err);
			goto repeat;
		} else if (ei == NULL) {
			err = -ERANGE;
			SSDFS_ERR("invalid index info\n");
			goto repeat;
		}

		err = ssdfs_shextree_invalidate_index(tree, ei);
		if (err) {
			ssdfs_fs_error(tree->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to invalidate index: "
				"(node_id %u, node_type %u, height %u), "
				"err %d\n",
				le32_to_cpu(ei->raw.index.node_id),
				ei->raw.index.node_type,
				ei->raw.index.height,
				err);
			ssdfs_extent_info_free(ei);
			goto repeat;
		} else
			ssdfs_extent_info_free(ei);
	} while (has_shextree_pre_invalid_extents(tree, id));

	if (kthread_should_stop())
		goto repeat;

sleep_shextree_thread:
	wait_event_interruptible(*wait_queue,
				 SHEXTREE_THREAD_WAKE_CONDITION(tree, id));
	goto repeat;
}

static
struct ssdfs_thread_descriptor thread_desc[SSDFS_INVALIDATION_QUEUE_NUMBER] = {
	{.threadfn = ssdfs_shextree_extent_thread_func,
	 .fmt = "ssdfs-shextree-extent",},
	{.threadfn = ssdfs_shextree_index_thread_func,
	 .fmt = "ssdfs-shextree-index",},
};

/*
 * ssdfs_shextree_start_thread() - start shared extents tree's thread
 * @tree: shared extents tree's object
 * @index: queue's ID
 */
int ssdfs_shextree_start_thread(struct ssdfs_shared_extents_tree *tree,
				int index)
{
	struct ssdfs_invalidation_queue *ptr;
	ssdfs_threadfn threadfn;
	const char *fmt;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(index >= SSDFS_INVALIDATION_QUEUE_NUMBER);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, index %d\n", tree, index);

	threadfn = thread_desc[index].threadfn;
	fmt = thread_desc[index].fmt;

	ptr = &tree->array[index];
	ptr->thread.task = kthread_create(threadfn, tree, fmt);
	if (IS_ERR_OR_NULL(ptr->thread.task)) {
		err = PTR_ERR(ptr->thread.task);
		SSDFS_ERR("fail to start shared extents tree's thread: "
			  "err %d\n", err);
		return err;
	}

	init_waitqueue_entry(&ptr->thread.wait, ptr->thread.task);
	add_wait_queue(&tree->wait_queue, &ptr->thread.wait);
	init_completion(&ptr->thread.full_stop);

	wake_up_process(ptr->thread.task);

	return 0;
}

/*
 * ssdfs_shextree_stop_thread() - stop shared extents tree's thread
 * @tree: shared extents tree's object
 * @index: queue's ID
 */
int ssdfs_shextree_stop_thread(struct ssdfs_shared_extents_tree *tree,
				int index)
{
	struct ssdfs_invalidation_queue *ptr;
	unsigned long res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
	BUG_ON(index >= SSDFS_INVALIDATION_QUEUE_NUMBER);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = &tree->array[index];
	if (!ptr->thread.task)
		return 0;

	err = kthread_stop(ptr->thread.task);
	if (err == -EINTR) {
		/*
		 * Ignore this error.
		 * The wake_up_process() was never called.
		 */
		return 0;
	} else if (unlikely(err)) {
		SSDFS_WARN("thread function had some issue: err %d\n",
			    err);
		return err;
	}

	finish_wait(&tree->wait_queue, &ptr->thread.wait);
	ptr->thread.task = NULL;

	res = wait_for_completion_timeout(&ptr->thread.full_stop,
					  SSDFS_DEFAULT_TIMEOUT);
	if (res == 0) {
		err = -ERANGE;
		SSDFS_ERR("stop thread fails: err %d\n", err);
		return err;
	}

	return 0;
}
