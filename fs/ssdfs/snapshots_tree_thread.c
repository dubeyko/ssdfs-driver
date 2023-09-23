// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshots_tree_thread.c - snapshots btree's thread implementation.
 *
 * Copyright (c) 2021-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "shared_dictionary.h"
#include "dentries_tree.h"
#include "snapshot.h"
#include "page_array.h"
#include "folio_array.h"
#include "peb_mapping_table.h"
#include "snapshots_tree.h"

#include <trace/events/ssdfs.h>

#define SNAPTREE_THREAD_WAKE_CONDITION(tree) \
	(kthread_should_stop() || \
	 !is_ssdfs_snapshot_reqs_queue_empty(&tree->requests.queue))
#define SNAPTREE_FAILED_THREAD_WAKE_CONDITION() \
	(kthread_should_stop())

static inline
bool has_any_snapshot_been_deleted(struct ssdfs_snapshots_btree_info *tree)
{
	return atomic64_read(&tree->deleted_snapshots) > 0;
}

static inline
bool is_time_process_requests(struct ssdfs_snapshots_btree_info *tree)
{
	return !is_ssdfs_snapshot_reqs_queue_empty(&tree->requests.queue);
}

/*
 * ssdfs_check_necessity_delete_peb2time() - check/delete obsolete PEB2time pairs
 * @fsi: pointer on shared file system object
 * @tree: snapshot btree
 * @item: snapshot or PEB2time set item
 *
 * This function tries to check the necessity to delete PEB2time pair.
 * If PEB doesn't contain any snapshots already then
 * PEB is marked as ready to be erased and PEB2time pair
 * is deleted from snapshots tree.
 *
 * RETURN:
 * [success] - snapshots_btree thread has been stopped.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static int
ssdfs_check_necessity_delete_peb2time(struct ssdfs_fs_info *fsi,
				      struct ssdfs_snapshots_btree_info *tree,
				      union ssdfs_snapshot_item *item)
{
	struct ssdfs_peb2time_set *peb2time;
	struct ssdfs_btree_search *search = NULL;
	struct ssdfs_timestamp_range range;
	u8 pairs_count;
	u64 create_time;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!tree || !item);

	SSDFS_DBG("tree %p, item %p\n",
		  tree, item);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_item_snapshot(item)) {
		SSDFS_DBG("item is snapshot\n");
		return 0;
	} else if (is_item_peb2time_record(item)) {
		/*
		 * Expected state. Continue logic.
		 */
	} else {
		SSDFS_ERR("corrupted record: magic %#x\n",
			  le16_to_cpu(item->magic));
		return -ERANGE;
	}

	peb2time = (struct ssdfs_peb2time_set *)item;
	pairs_count = peb2time->pairs_count;
	create_time = le64_to_cpu(peb2time->create_time);

	if (pairs_count == 0 || pairs_count > SSDFS_PEB2TIME_ARRAY_CAPACITY) {
		SSDFS_ERR("corrupted PEB2time set: "
			  "pairs_count %u\n", pairs_count);
		return -ERANGE;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	for (i = 0; i < pairs_count; i++) {
		struct completion *init_end;
		struct ssdfs_peb2time_pair *pair;
		struct ssdfs_peb_timestamps peb_timestamps;
		u64 peb_id;
		u64 last_log_time;

		pair = &peb2time->array[i];
		peb_id = le64_to_cpu(pair->peb_id);
		last_log_time = le64_to_cpu(pair->last_log_time);

		range.start = create_time;
		range.end = last_log_time;

		ssdfs_btree_search_init(search);
		err = ssdfs_snapshots_btree_check_range(tree, &range, search);
		if (err == -ENODATA) {
			int res;

			err = ssdfs_maptbl_set_pre_erased_snapshot_peb(fsi,
								peb_id,
								&init_end);
			if (err == -EAGAIN) {
				res = wait_for_completion_timeout(init_end,
							SSDFS_DEFAULT_TIMEOUT);
				if (res == 0) {
					err = -ERANGE;
					SSDFS_ERR("maptbl init failed: "
						  "err %d\n", err);
					goto finish_check_peb2time_set;
				}

				err =
				   ssdfs_maptbl_set_pre_erased_snapshot_peb(fsi,
								    peb_id,
								    &init_end);
			}

			if (unlikely(err)) {
				SSDFS_ERR("fail to set pre-erase state: "
					  "peb_id %llu, err %d\n",
					  peb_id, err);
				goto finish_check_peb2time_set;
			}

			ssdfs_btree_search_init(search);

			peb_timestamps.peb_id = peb_id;
			peb_timestamps.create_time = create_time;
			peb_timestamps.last_log_time = last_log_time;

			err = ssdfs_snapshots_btree_delete_peb2time(tree,
								&peb_timestamps,
								search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to delete PEB2time pair: "
					  "peb_id %llu, create_time %llu, "
					  "last_log_time %llu, err %d\n",
					  peb_id, create_time,
					  last_log_time, err);
				goto finish_check_peb2time_set;
			}
		} else if (err == -EAGAIN) {
			err = 0;
			/* continue logic */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find snapshot: "
				  "start_timestamp %llu, end_timestamp %llu, "
				  "err %d\n",
				  create_time, last_log_time, err);
			goto finish_check_peb2time_set;
		}
	}

finish_check_peb2time_set:
	ssdfs_btree_search_free(search);

	return err;
}

/*
 * ssdfs_snapshots_btree_thread_func() - snapshots btree thread's function
 */
static
int ssdfs_snapshots_btree_thread_func(void *data)
{
	struct ssdfs_fs_info *fsi = data;
	struct ssdfs_snapshots_btree_info *tree;
	struct ssdfs_snapshot_reqs_queue *rq;
	wait_queue_head_t *wait_queue = NULL;
	struct ssdfs_btree_search *search = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!fsi) {
		SSDFS_ERR("fsi is NULL\n");
		BUG();
	}

	SSDFS_DBG("snapshots btree thread\n");
#endif /* CONFIG_SSDFS_DEBUG */

	tree = fsi->snapshots.tree;
	wait_queue = &tree->wait_queue;
	rq = &tree->requests.queue;

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto sleep_failed_snapshots_btree_thread;
	}

repeat:
	if (unlikely(err)) {
		wake_up_all(&tree->wait_queue);

		if (kthread_should_stop())
			goto finish_thread;
		else
			goto sleep_failed_snapshots_btree_thread;
	}

	if (kthread_should_stop()) {
		if (is_time_process_requests(tree))
			goto try_process_queue;

finish_thread:
		complete_all(&tree->requests.thread.full_stop);
		if (search)
			ssdfs_btree_search_free(search);
		return err;
	}

	if (!is_time_process_requests(tree) &&
	    !has_any_snapshot_been_deleted(tree)) {
		/* sleep time */
		goto sleep_snapshots_btree_thread;
	}

try_process_queue:
	while (is_time_process_requests(tree)) {
		struct ssdfs_snapshot_request *snr = NULL;

		switch (atomic_read(&tree->state)) {
		case SSDFS_SNAPSHOTS_BTREE_CORRUPTED:
			err = -EFAULT;
			ssdfs_fs_error(tree->generic_tree.fsi->sb,
					__FILE__, __func__, __LINE__,
					"snapshots btree is corrupted\n");
			goto repeat;

		case SSDFS_SNAPSHOTS_BTREE_CREATED:
		case SSDFS_SNAPSHOTS_BTREE_INITIALIZED:
			/* continue to work */
			break;

		default:
			err = -EFAULT;
			ssdfs_fs_error(tree->generic_tree.fsi->sb,
					__FILE__, __func__, __LINE__,
					"invalid snapshots btree state %#x\n",
					atomic_read(&tree->state));
			goto repeat;
		}

		err = ssdfs_snapshot_reqs_queue_remove_first(rq, &snr);
		if (err == -ENODATA) {
			err = 0;
			goto sleep_snapshots_btree_thread;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get request: err %d\n", err);
			goto repeat;
		} else if (snr == NULL) {
			err = -ERANGE;
			SSDFS_ERR("invalid request\n");
			goto repeat;
		}

		switch (snr->operation) {
		case SSDFS_CREATE_SNAPSHOT:
			ssdfs_btree_search_init(search);
			err = ssdfs_snapshots_btree_add(tree, snr, search);
			if (err == -EEXIST) {
				/* snapshot exist -> do nothing */
				err = 0;
				SSDFS_ERR("snapshot exists already\n");
				SHOW_SNAPSHOT_INFO(snr);
				ssdfs_snapshot_request_free(snr);
				continue;
			} else if (unlikely(err)) {
				ssdfs_fs_error(tree->generic_tree.fsi->sb,
						__FILE__, __func__, __LINE__,
						"fail to create snapshot: "
						"err %d\n", err);
				SHOW_SNAPSHOT_INFO(snr);
				ssdfs_snapshot_request_free(snr);
				goto repeat;
			} else
				ssdfs_snapshot_request_free(snr);
			break;

		case SSDFS_MODIFY_SNAPSHOT:
			ssdfs_btree_search_init(search);
			err = ssdfs_snapshots_btree_change(tree, snr, search);
			if (unlikely(err)) {
				ssdfs_fs_error(tree->generic_tree.fsi->sb,
						__FILE__, __func__, __LINE__,
						"fail to modify snapshot: "
						"err %d\n", err);
				SHOW_SNAPSHOT_INFO(snr);
				ssdfs_snapshot_request_free(snr);
				goto repeat;
			} else
				ssdfs_snapshot_request_free(snr);
			break;

		case SSDFS_REMOVE_SNAPSHOT:
		case SSDFS_REMOVE_RANGE:
			ssdfs_btree_search_init(search);
			err = ssdfs_snapshots_btree_delete(tree, snr, search);
			if (unlikely(err)) {
				ssdfs_fs_error(tree->generic_tree.fsi->sb,
						__FILE__, __func__, __LINE__,
						"fail to delete snapshot: "
						"err %d\n", err);
				SHOW_SNAPSHOT_INFO(snr);
				ssdfs_snapshot_request_free(snr);
				goto repeat;
			} else
				ssdfs_snapshot_request_free(snr);
			break;

		default:
			SSDFS_ERR("unsupported operation type: "
				  "operation %#x\n",
				  snr->operation);
			ssdfs_snapshot_request_free(snr);
			snr = NULL;
			break;
		};
	};

	if (has_any_snapshot_been_deleted(tree)) {
		u64 start_hash = U64_MAX;
		u64 end_hash = U64_MAX;

		err = ssdfs_snapshots_tree_get_start_hash(tree,
							  &start_hash);
		if (err == -ENOENT) {
			err = 0;
			SSDFS_DBG("snapshots tree is empty\n");
			goto finish_snapshots_tree_processing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get start root hash: err %d\n",
				  err);
			goto repeat;
		} else if (start_hash >= U64_MAX) {
			err = -ERANGE;
			SSDFS_ERR("invalid start hash value\n");
			goto repeat;
		}

		do {
			struct ssdfs_timestamp_range range;
			size_t item_size = sizeof(union ssdfs_snapshot_item);
			u16 items_count;
			u64 i;

			range.start = range.end = start_hash;

			ssdfs_btree_search_init(search);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("start_hash %llx\n",
				  start_hash);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_snapshots_tree_find_leaf_node(tree,
								  &range,
								  search);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to find a leaf node: "
					  "hash %llx, err %d\n",
					  start_hash, err);
#endif /* CONFIG_SSDFS_DEBUG */
				goto finish_snapshots_tree_processing;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to find a leaf node: "
					  "hash %llx, err %d\n",
					  start_hash, err);
				goto repeat;
			}

			err = ssdfs_snapshots_tree_node_hash_range(tree,
								search,
								&start_hash,
								&end_hash,
								&items_count);
			if (unlikely(err)) {
				SSDFS_ERR("fail to get node's hash range: "
					  "err %d\n", err);
				goto repeat;
			}

			if (items_count == 0) {
				err = -ENOENT;
				SSDFS_DBG("empty leaf node\n");
				goto finish_snapshots_tree_processing;
			}

			if (start_hash > end_hash) {
				err = -ENOENT;
				SSDFS_ERR("start_hash %#llx > end_hash %#llx\n",
					  start_hash, end_hash);
				goto repeat;
			}

			err = ssdfs_snapshots_tree_extract_range(tree,
								 0, items_count,
								 search);
			if (unlikely(err)) {
				SSDFS_ERR("fail to extract the range: "
					  "items_count %u, err %d\n",
					  items_count, err);
				goto repeat;
			}

			err = ssdfs_snapshots_tree_check_search_result(search);
			if (unlikely(err)) {
				SSDFS_ERR("corrupted search result: "
					  "err %d\n", err);
				goto repeat;
			}

			items_count = search->result.count;

			ssdfs_btree_search_forget_child_node(search);

			for (i = 0; i < items_count; i++) {
				union ssdfs_snapshot_item *item;
				u8 *start_ptr = (u8 *)search->result.buf;

				item = (union ssdfs_snapshot_item *)(start_ptr +
								(i * item_size));

				err = ssdfs_check_necessity_delete_peb2time(fsi,
									  tree,
									  item);
				if (unlikely(err)) {
					SSDFS_ERR("fail to check item: "
						  "index %llu, err %d\n",
						  i, err);
					goto repeat;
				}

				if (kthread_should_stop())
					goto repeat;

				if (is_time_process_requests(tree))
					goto try_process_queue;
			}

			start_hash = end_hash + 1;

			err = ssdfs_snapshots_tree_get_next_hash(tree,
								 search,
								 &start_hash);

			ssdfs_btree_search_forget_parent_node(search);
			ssdfs_btree_search_forget_child_node(search);

			if (err == -ENOENT || err == -ENODATA) {
				err = 0;
				SSDFS_DBG("no more items in the tree\n");
				goto finish_snapshots_tree_processing;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to get next hash: err %d\n",
					  err);
				goto repeat;
			}

			if (kthread_should_stop())
				goto repeat;

			if (is_time_process_requests(tree))
				goto try_process_queue;
		} while (start_hash < U64_MAX);

finish_snapshots_tree_processing:
		atomic64_dec(&tree->deleted_snapshots);
	}

	if (kthread_should_stop())
		goto repeat;

	if (is_time_process_requests(tree) ||
	    has_any_snapshot_been_deleted(tree)) {
		/* continue to work */
		goto try_process_queue;
	}

sleep_snapshots_btree_thread:
	wait_event_interruptible(*wait_queue,
				 SNAPTREE_THREAD_WAKE_CONDITION(tree));
	goto repeat;

sleep_failed_snapshots_btree_thread:
	wait_event_interruptible(*wait_queue,
				SNAPTREE_FAILED_THREAD_WAKE_CONDITION());
	goto repeat;
}

static
struct ssdfs_thread_descriptor thread_desc[1] = {
	{.threadfn = ssdfs_snapshots_btree_thread_func,
	 .fmt = "ssdfs-snapshots-btree",},
};

/*
 * ssdfs_start_snapshots_btree_thread() - start snapshots btree thread
 * @fsi: pointer on shared file system object
 *
 * This function tries to start snapshots btree thread.
 *
 * RETURN:
 * [success] - snapshots btree thread has been started.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_start_snapshots_btree_thread(struct ssdfs_fs_info *fsi)
{
	ssdfs_threadfn threadfn;
	const char *fmt;
	struct ssdfs_thread_info *thread;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	threadfn = thread_desc[0].threadfn;
	fmt = thread_desc[0].fmt;
	thread = &fsi->snapshots.tree->requests.thread;

	thread->task = kthread_create(threadfn, fsi, fmt);
	if (IS_ERR_OR_NULL(thread->task)) {
		err = PTR_ERR(thread->task);
		if (err == -EINTR) {
			/*
			 * Ignore this error.
			 */
		} else {
			if (err == 0)
				err = -ERANGE;
			SSDFS_ERR("fail to start snapshots btree's thread: "
				  "err %d\n", err);
		}

		return err;
	}

	init_waitqueue_entry(&thread->wait, thread->task);
	add_wait_queue(&fsi->snapshots.tree->wait_queue,
			&thread->wait);
	init_completion(&thread->full_stop);

	wake_up_process(thread->task);

	return 0;
}

/*
 * ssdfs_stop_snapshots_btree_thread() - stop snapshots_btree thread
 * @fsi: pointer on shared file system object
 *
 * This function tries to stop snapshots_btree thread.
 *
 * RETURN:
 * [success] - snapshots_btree thread has been stopped.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_stop_snapshots_btree_thread(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_thread_info *thread;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	thread = &fsi->snapshots.tree->requests.thread;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("task %p\n", thread->task);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!thread->task)
		return 0;

	err = kthread_stop(thread->task);
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

	finish_wait(&fsi->snapshots.tree->wait_queue,
		    &thread->wait);

	fsi->snapshots.tree->requests.thread.task = NULL;

	err = SSDFS_WAIT_COMPLETION(&thread->full_stop);
	if (unlikely(err)) {
		SSDFS_ERR("stop thread fails: err %d\n", err);
		return err;
	}

	return 0;
}
