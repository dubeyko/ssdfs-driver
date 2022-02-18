//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshots_tree_thread.c - snapshots btree's thread implementation.
 *
 * Copyright (c) 2021-2022 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "shared_dictionary.h"
#include "dentries_tree.h"
#include "snapshot.h"
#include "snapshots_tree.h"

#include <trace/events/ssdfs.h>

#define SNAPTREE_THREAD_WAKE_CONDITION(tree) \
	(kthread_should_stop() || \
	 !is_ssdfs_snapshot_reqs_queue_empty(&tree->requests.queue))
#define SNAPTREE_FAILED_THREAD_WAKE_CONDITION() \
	(kthread_should_stop())

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("snapshots btree thread\n");

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
		if (!is_ssdfs_snapshot_reqs_queue_empty(&tree->requests.queue))
			goto try_process_queue;

finish_thread:
		complete_all(&tree->requests.thread.full_stop);
		if (search)
			ssdfs_btree_search_free(search);
		return err;
	}

	if (is_ssdfs_snapshot_reqs_queue_empty(&tree->requests.queue))
		goto sleep_snapshots_btree_thread;

try_process_queue:
	do {
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
	} while (!is_ssdfs_snapshot_reqs_queue_empty(&tree->requests.queue));

	if (kthread_should_stop())
		goto repeat;

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("fsi %p\n", fsi);

	threadfn = thread_desc[0].threadfn;
	fmt = thread_desc[0].fmt;
	thread = &fsi->snapshots.tree->requests.thread;

	thread->task = kthread_create(threadfn, fsi, fmt);
	if (IS_ERR_OR_NULL(thread->task)) {
		err = PTR_ERR(thread->task);
		SSDFS_ERR("fail to start snapshots btree thread\n");
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
	unsigned long res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	thread = &fsi->snapshots.tree->requests.thread;

	SSDFS_DBG("task %p\n", thread->task);

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

	res = wait_for_completion_timeout(&thread->full_stop,
					  SSDFS_DEFAULT_TIMEOUT);
	if (res == 0) {
		err = -ERANGE;
		SSDFS_ERR("stop thread fails: err %d\n", err);
		return err;
	}

	return 0;
}
