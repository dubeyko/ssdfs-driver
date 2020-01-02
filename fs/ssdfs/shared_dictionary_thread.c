//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/shared_dictionary_thread.c - shared dictionary tree's thread impl.
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
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "shared_dictionary.h"

#include <trace/events/ssdfs.h>

/*
 * has_queue_unprocessed_names() - is requests queue empty?
 * @tree: shared dictionary tree's object
 */
bool has_queue_unprocessed_names(struct ssdfs_shared_dict_btree_info *tree)
{
	struct ssdfs_names_queue *queue;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	queue = &tree->requests.queue;
	return !is_ssdfs_names_queue_empty(queue);
}

/*
 * ssdfs_shared_dict_pre_fetch_nodes() - pre-fetch root node's child nodes
 * @tree: shared dictionary tree's object
 * @ptr: requests queue
 */
static
int ssdfs_shared_dict_pre_fetch_nodes(struct ssdfs_shared_dict_btree_info *tree,
				      struct ssdfs_name_requests_queue *ptr)
{
	struct ssdfs_name_info *ni = NULL;
	int req_type = SSDFS_INIT_SHDICT_NODE;
	struct ssdfs_btree_node *parent, *child;
	int initialized_nodes = 0;
	u64 hash;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p, queue %p\n",
		  tree, ptr);

	do {
		err = ssdfs_names_queue_remove_first(&ptr->queue, &ni);
		if (err == -ENODATA) {
			if (initialized_nodes == 0) {
				SSDFS_WARN("empty queue\n");
				return err;
			} else {
				/* finish initialization */
				err = 0;
				goto finish_init;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get name: err %d\n",
				  err);
			goto finish_init;
		} else if (ni == NULL) {
			err = -ERANGE;
			SSDFS_ERR("invalid name info\n");
			goto finish_init;
		}

		req_type = ni->type;

		if (req_type != SSDFS_INIT_SHDICT_NODE) {
			ssdfs_names_queue_add_head(&ptr->queue, ni);

			if (initialized_nodes == 0) {
				err = -ERANGE;
				SSDFS_WARN("queue hasn't init requests\n");
			}

			goto finish_init;
		}

		hash = le64_to_cpu(ni->desc.index.hash);

		down_write(&tree->lock);

		err = ssdfs_btree_radix_tree_find(&tree->generic_tree,
						  SSDFS_BTREE_ROOT_NODE_ID,
						  &parent);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get the root node: err %d\n",
				  err);
			goto finish_read_child_node;
		} else if (unlikely(!parent)) {
			err = -ERANGE;
			SSDFS_WARN("empty node pointer\n");
			goto finish_read_child_node;
		}

		child = ssdfs_btree_get_child_node_for_hash(&tree->generic_tree,
							    parent, hash);
		if (IS_ERR_OR_NULL(child)) {
			err = !child ? -ERANGE : PTR_ERR(child);
			SSDFS_ERR("fail to get the child node: err %d\n",
				  err);
			goto finish_read_child_node;
		}

finish_read_child_node:
		up_write(&tree->lock);

		if (unlikely(err))
			goto finish_init;

		initialized_nodes++;
	} while (req_type == SSDFS_INIT_SHDICT_NODE);

finish_init:
	return err;
}

#define SHDICT_PTR(tree) \
	((struct ssdfs_shared_dict_btree_info *)(tree))
#define SHDICT_THREAD_WAKE_CONDITION(tree) \
	(kthread_should_stop() || \
	 has_queue_unprocessed_names(SHDICT_PTR(tree)))

/*
 * ssdfs_shared_dict_thread_func() - shared dictionary object's thread's func
 */
static
int ssdfs_shared_dict_thread_func(void *data)
{
	struct ssdfs_shared_dict_btree_info *tree = data;
	wait_queue_head_t *wait_queue;
	struct ssdfs_name_requests_queue *ptr;
	struct ssdfs_btree_search *search;
	int read_reqs;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!tree) {
		SSDFS_ERR("pointer on shared dictionary tree is NULL\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("shared dictionary tree's thread\n");

	wait_queue = &tree->wait_queue;
	ptr = &tree->requests;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

repeat:
	if (unlikely(err)) {
		SSDFS_WARN("shared dictionary tree's thread failed: "
			   "err %d\n",
			   err);
		complete_all(&ptr->thread.full_stop);
		goto finish_shared_dict_thread;
	}

	if (kthread_should_stop()) {
		if (has_queue_unprocessed_names(tree))
			goto try_process_queue;

		complete_all(&ptr->thread.full_stop);
		goto finish_shared_dict_thread;
	}

	if (!has_queue_unprocessed_names(tree))
		goto sleep_shared_dict_thread;

try_process_queue:
	do {
		struct ssdfs_name_info *ni = NULL;

		switch (atomic_read(&tree->state)) {
		case SSDFS_SHDICT_BTREE_UNDER_INIT:
			err = ssdfs_shared_dict_pre_fetch_nodes(tree, ptr);
			if (unlikely(err)) {
				atomic_set(&tree->state,
					   SSDFS_SHDICT_BTREE_CORRUPTED);
				ssdfs_fs_error(tree->generic_tree.fsi->sb,
						__FILE__, __func__, __LINE__,
						"fail to initialize nodes\n");
				wake_up_all(&tree->wait_queue);
				goto repeat;
			} else {
				atomic_set(&tree->state,
					   SSDFS_SHDICT_BTREE_INITIALIZED);
				wake_up_all(&tree->wait_queue);
			}
			break;

		case SSDFS_SHDICT_BTREE_CORRUPTED:
			err = -EFAULT;
			ssdfs_fs_error(tree->generic_tree.fsi->sb,
					__FILE__, __func__, __LINE__,
					"shared dictionary is corrupted\n");
			goto repeat;

		case SSDFS_SHDICT_BTREE_CREATED:
		case SSDFS_SHDICT_BTREE_INITIALIZED:
			/* continue to work */
			break;

		default:
			err = -EFAULT;
			ssdfs_fs_error(tree->generic_tree.fsi->sb,
					__FILE__, __func__, __LINE__,
					"invalid shared dictionary state %#x\n",
					atomic_read(&tree->state));
			goto repeat;
		}

		read_reqs = atomic_read(&tree->read_reqs);
		if (read_reqs > 0)
			goto sleep_shared_dict_thread;

		err = ssdfs_names_queue_remove_first(&ptr->queue, &ni);
		if (err == -ENODATA) {
			err = 0;
			goto sleep_shared_dict_thread;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get name: err %d\n", err);
			goto repeat;
		} else if (ni == NULL) {
			err = -ERANGE;
			SSDFS_ERR("invalid name info\n");
			goto repeat;
		}

		switch (ni->type) {
		case SSDFS_NAME_ADD:
			ssdfs_btree_search_init(search);

			down_write(&tree->lock);
			err = ssdfs_shared_dict_tree_add(tree,
							 ni->desc.name.hash,
							 ni->desc.name.str_buf,
							 ni->desc.name.len,
							 search);
			up_write(&tree->lock);

			if (err == -EEXIST) {
				/* name exist -> do nothing */
				err = 0;
				ssdfs_name_info_free(ni);
				continue;
			} else if (unlikely(err)) {
				ssdfs_fs_error(tree->generic_tree.fsi->sb,
						__FILE__, __func__, __LINE__,
						"fail to add name: "
						"hash %llx, name %s, len %zu, "
						"err %d\n",
						ni->desc.name.hash,
						ni->desc.name.str_buf,
						ni->desc.name.len,
						err);
				ssdfs_name_info_free(ni);
				goto repeat;
			} else
				ssdfs_name_info_free(ni);
			break;

		case SSDFS_NAME_CHANGE:
		case SSDFS_NAME_DELETE:
			SSDFS_ERR("unsupported operation: "
				  "type %#x, hash %llx, len %zu\n",
				  ni->type,
				  ni->desc.name.hash,
				  ni->desc.name.len);
			ssdfs_name_info_free(ni);
			break;

		default:
			SSDFS_ERR("invalid operation type: "
				  "type %#x, hash %llx, len %zu\n",
				  ni->type,
				  ni->desc.name.hash,
				  ni->desc.name.len);
			ssdfs_name_info_free(ni);
			break;
		};
	} while (has_queue_unprocessed_names(tree));

	if (kthread_should_stop())
		goto repeat;

sleep_shared_dict_thread:
	wait_event_interruptible(*wait_queue,
				 SHDICT_THREAD_WAKE_CONDITION(tree));
	goto repeat;

finish_shared_dict_thread:
	ssdfs_btree_search_free(search);
	return err;
}

static
struct ssdfs_thread_descriptor thread_desc[1] = {
	{.threadfn = ssdfs_shared_dict_thread_func,
	 .fmt = "ssdfs-shared-dict",},
};

/*
 * ssdfs_shared_dict_start_thread() - start shared dictionary tree's thread
 * @tree: shared dictionary tree's object
 */
int ssdfs_shared_dict_start_thread(struct ssdfs_shared_dict_btree_info *tree)
{
	struct ssdfs_name_requests_queue *ptr;
	ssdfs_threadfn threadfn;
	const char *fmt;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("tree %p\n", tree);

	threadfn = thread_desc[0].threadfn;
	fmt = thread_desc[0].fmt;

	ptr = &tree->requests;
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
 * ssdfs_shared_dict_stop_thread() - stop shared dictionary tree's thread
 * @tree: shared dictionary tree's object
 */
int ssdfs_shared_dict_stop_thread(struct ssdfs_shared_dict_btree_info *tree)
{
	struct ssdfs_name_requests_queue *ptr;
	unsigned long res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = &tree->requests;
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
