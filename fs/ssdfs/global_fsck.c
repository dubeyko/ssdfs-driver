/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/global_fsck.c - global fsck thread functionality.
 *
 * Copyright (c) 2025 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "compression.h"
#include "block_bitmap.h"
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "peb_mapping_table.h"
#include "request_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "extents_queue.h"
#include "btree.h"
#include "diff_on_write.h"
#include "shared_extents_tree.h"
#include "invalidated_extents_tree.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_global_fsck_folio_leaks;
atomic64_t ssdfs_global_fsck_memory_leaks;
atomic64_t ssdfs_global_fsck_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_global_fsck_cache_leaks_increment(void *kaddr)
 * void ssdfs_global_fsck_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_global_fsck_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_global_fsck_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_global_fsck_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_global_fsck_kfree(void *kaddr)
 * struct folio *ssdfs_global_fsck_alloc_folio(gfp_t gfp_mask,
 *                                       unsigned int order)
 * struct folio *ssdfs_global_fsck_add_batch_folio(struct folio_batch *batch,
 *                                           unsigned int order)
 * void ssdfs_global_fsck_free_folio(struct folio *folio)
 * void ssdfs_global_fsck_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(global_fsck)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(global_fsck)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_global_fsck_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_global_fsck_folio_leaks, 0);
	atomic64_set(&ssdfs_global_fsck_memory_leaks, 0);
	atomic64_set(&ssdfs_global_fsck_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_global_fsck_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_global_fsck_folio_leaks) != 0) {
		SSDFS_ERR("GLOBAL FSCK THREAD: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_global_fsck_folio_leaks));
	}

	if (atomic64_read(&ssdfs_global_fsck_memory_leaks) != 0) {
		SSDFS_ERR("GLOBAL FSCK THREAD: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_global_fsck_memory_leaks));
	}

	if (atomic64_read(&ssdfs_global_fsck_cache_leaks) != 0) {
		SSDFS_ERR("GLOBAL FSCK THREAD: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_global_fsck_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * is_global_fsck_requests_queue_empty() - check that FSCK queue has requests
 * @fsi: pointer on shared file system object
 */
static inline
bool is_global_fsck_requests_queue_empty(struct ssdfs_fs_info *fsi)
{
	return is_ssdfs_requests_queue_empty(&fsi->global_fsck.rq);
}

static
int ssdfs_erase_and_re_write_sb_snapshot_segment(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi;
	struct folio_batch fbatch;
	struct folio *folio;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!sb);

	SSDFS_DBG("sb %p", sb);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = SSDFS_FS_I(sb);

	folio_batch_init(&fbatch);

	for (i = 0; i < SSDFS_SB_SNAPSHOT_LOG_PAGES; i++) {
		folio = ssdfs_global_fsck_alloc_folio(GFP_KERNEL | __GFP_ZERO,
							get_order(PAGE_SIZE));
		if (IS_ERR_OR_NULL(folio)) {
			err = (folio == NULL ? -ENOMEM : PTR_ERR(folio));
			SSDFS_ERR("unable to allocate memory folio\n");
			goto finish_re_write_sb_snapshot_segment;
		}

		ssdfs_folio_get(folio);
		folio_batch_add(&fbatch, folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	for (i = 0; i < SSDFS_SB_SNAPSHOT_LOG_PAGES; i++) {
		/* ->read_blocks() expect locked folios and do unlock */
		ssdfs_folio_lock(fbatch.folios[i]);
	}

	err = fsi->devops->read_blocks(sb, &fbatch, 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read batch: err %d\n", err);
		goto finish_re_write_sb_snapshot_segment;
	}

	err = fsi->devops->trim(sb, 0, fsi->erasesize);
	if (unlikely(err)) {
		SSDFS_ERR("fail to erase: err %d\n",
			  err);
		goto finish_re_write_sb_snapshot_segment;
	}

	for (i = 0; i < SSDFS_SB_SNAPSHOT_LOG_PAGES; i++) {
		folio = fbatch.folios[i];

		/* ->writepage() calls put_folio() */
		ssdfs_folio_get(folio);

		ssdfs_folio_lock(folio);
		folio_mark_uptodate(folio);
		folio_set_dirty(folio);
		ssdfs_folio_unlock(folio);
	}

	err = fsi->devops->write_blocks(sb, 0, &fbatch);
	if (unlikely(err)) {
		SSDFS_ERR("fail to write batch: err %d\n", err);
		goto finish_re_write_sb_snapshot_segment;
	}

	for (i = 0; i < SSDFS_SB_SNAPSHOT_LOG_PAGES; i++) {
		folio = fbatch.folios[i];

		ssdfs_folio_lock(folio);
		folio_clear_uptodate(folio);
		ssdfs_folio_unlock(folio);
	}

finish_re_write_sb_snapshot_segment:
	for (i = 0; i < folio_batch_count(&fbatch); i++) {
		folio = fbatch.folios[i];

		ssdfs_folio_put(folio);
		ssdfs_global_fsck_free_folio(folio);
		fbatch.folios[i] = NULL;
	}

	return err;
}

/*
 * ssdfs_process_fsck_request() - process global FSCK request
 * @req: FSCK request
 *
 * This function detects command of FSCK request and
 * to call a proper function for request processing.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_process_fsck_request(struct ssdfs_fs_info *fsi,
				struct ssdfs_segment_request *req)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req);

	SSDFS_DBG("class %#x, cmd %#x, type %#x\n",
		  req->private.class, req->private.cmd,
		  req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (req->private.cmd < SSDFS_FSCK_ERASE_RE_WRITE_SB_SNAP_SEG ||
	    req->private.cmd >= SSDFS_GLOBAL_FSCK_CMD_MAX) {
		SSDFS_ERR("unknown FSCK command %d\n",
			  req->private.cmd);
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		req->result.err = -EINVAL;
		return -EINVAL;
	}

	atomic_set(&req->result.state, SSDFS_REQ_STARTED);

	switch (req->private.cmd) {
	case SSDFS_FSCK_ERASE_RE_WRITE_SB_SNAP_SEG:
		err = ssdfs_erase_and_re_write_sb_snapshot_segment(fsi->sb);
		if (unlikely(err)) {
			SSDFS_ERR("fail to erase superblock snapshots segment: "
				  "err %d\n", err);
		}
		break;

	default:
		BUG();
	}

	if (unlikely(err))
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);

	return err;
}

/*
 * ssdfs_finish_fsck_request() - finish global FSCK request
 * @req: segment request
 * @wait: wait queue head
 * @err: error code (read request failure code)
 *
 * This function makes final activity with FSCK request.
 */
static
void ssdfs_finish_fsck_request(struct ssdfs_segment_request *req,
				wait_queue_head_t *wait, int err)
{
	int res;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);

	SSDFS_DBG("class %#x, cmd %#x, type %#x, err %d\n",
		  req->private.class, req->private.cmd,
		  req->private.type, err);
#endif /* CONFIG_SSDFS_DEBUG */

	req->result.err = err;

	switch (req->private.type) {
	case SSDFS_REQ_SYNC:
		if (err) {
			SSDFS_DBG("failure: req %p, err %d\n", req, err);
			atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		} else
			atomic_set(&req->result.state, SSDFS_REQ_FINISHED);

		complete(&req->result.wait);
		wake_up_all(&req->private.wait_queue);
		wake_up_all(wait);
		break;

	case SSDFS_REQ_ASYNC:
		if (err) {
			SSDFS_DBG("failure: req %p, err %d\n", req, err);
			atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		} else
			atomic_set(&req->result.state, SSDFS_REQ_FINISHED);

		complete(&req->result.wait);
		wake_up_all(&req->private.wait_queue);
		wake_up_all(wait);

		ssdfs_put_request(req);
		if (atomic_read(&req->private.refs_count) != 0) {
			struct ssdfs_request_internal_data *ptr;

			ptr = &req->private;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("start waiting: refs_count %d\n",
				   atomic_read(&ptr->refs_count));
#endif /* CONFIG_SSDFS_DEBUG */

			res = wait_event_killable_timeout(*wait,
					atomic_read(&ptr->refs_count) == 0,
					SSDFS_DEFAULT_TIMEOUT);
			if (res < 0) {
				WARN_ON(1);
			} else if (res > 1) {
				/*
				 * Condition changed before timeout
				 */
			} else {
				/* timeout is elapsed */
				SSDFS_ERR("class %#x, cmd %#x, type %#x, "
					  "result.state %#x, "
					  "refs_count %#x\n",
					  req->private.class,
					  req->private.cmd,
					  req->private.type,
					  atomic_read(&req->result.state),
					  atomic_read(&ptr->refs_count));
				WARN_ON(1);
			}
		}

		ssdfs_request_free(req, NULL);
		break;

	case SSDFS_REQ_ASYNC_NO_FREE:
		if (err) {
			SSDFS_DBG("failure: req %p, err %d\n", req, err);
			atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		} else
			atomic_set(&req->result.state, SSDFS_REQ_FINISHED);

		complete(&req->result.wait);
		wake_up_all(&req->private.wait_queue);
		ssdfs_put_request(req);
		wake_up_all(wait);
		break;

	default:
		BUG();
	};
}

#define GLOBAL_FSCK_THREAD_WAKE_CONDITION(fsi) \
	(kthread_should_stop() || \
	 !is_global_fsck_requests_queue_empty(fsi))
#define GLOBAL_FSCK_FAILED_THREAD_WAKE_CONDITION() \
	(kthread_should_stop())

/*
 * ssdfs_global_fsck_thread_func() - main fuction of global FSCK thread
 * @data: pointer on data object
 *
 * This function is main fuction of global FSCK thread.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_global_fsck_thread_func(void *data)
{
	struct ssdfs_fs_info *fsi = data;
	wait_queue_head_t *wait_queue;
	struct ssdfs_segment_request *req;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!fsi) {
		SSDFS_ERR("pointer on file system shared object is NULL\n");
		BUG();
	}

	SSDFS_DBG("global fsck thread\n");
#endif /* CONFIG_SSDFS_DEBUG */

	wait_queue = &fsi->global_fsck.wait_queue;

repeat:
	if (kthread_should_stop()) {
		if (!is_global_fsck_requests_queue_empty(fsi)) {
			ssdfs_requests_queue_remove_all(fsi,
							&fsi->global_fsck.rq,
							0);
		}

		complete_all(&fsi->global_fsck.thread.full_stop);
		return err;
	}

	switch (atomic_read(&fsi->global_fs_state)) {
	case SSDFS_UNKNOWN_GLOBAL_FS_STATE:
		err = SSDFS_WAIT_COMPLETION(&fsi->mount_end);
		if (unlikely(err)) {
			SSDFS_ERR("mount failed\n");
			goto sleep_failed_fsck_thread;
		}
		break;

	default:
		/* continue logic */
		break;
	}

	if (fsi->sb->s_flags & SB_RDONLY)
		goto sleep_fsck_thread;

	if (is_global_fsck_requests_queue_empty(fsi))
		goto sleep_fsck_thread;

	do {
		err = ssdfs_requests_queue_remove_first(&fsi->global_fsck.rq,
							&req);
		if (err == -ENODATA) {
			/* empty queue */
			err = 0;
			break;
		} else if (err == -ENOENT) {
			SSDFS_WARN("request queue contains NULL request\n");
			err = 0;
			continue;
		} else if (unlikely(err < 0)) {
			SSDFS_CRIT("fail to get request from the queue: "
				   "err %d\n",
				   err);
			goto sleep_failed_fsck_thread;
		}

		err = ssdfs_process_fsck_request(fsi, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to process fsck request: "
				  "err %d\n", err);
		}

		ssdfs_finish_fsck_request(req, wait_queue, err);
	} while (!is_global_fsck_requests_queue_empty(fsi));

sleep_fsck_thread:
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	add_wait_queue(wait_queue, &wait);
	if (!GLOBAL_FSCK_THREAD_WAKE_CONDITION(fsi)) {
		if (signal_pending(current)) {
			err = -ERESTARTSYS;
		} else {
			wait_woken(&wait, TASK_INTERRUPTIBLE,
				   SSDFS_DEFAULT_TIMEOUT);
		}
	}
	remove_wait_queue(wait_queue, &wait);
	goto repeat;

sleep_failed_fsck_thread:
	wait_event_interruptible(*wait_queue,
				 GLOBAL_FSCK_FAILED_THREAD_WAKE_CONDITION());
	goto repeat;
}

static
struct ssdfs_thread_descriptor thread_desc[1] = {
	{.threadfn = ssdfs_global_fsck_thread_func,
	 .fmt = "ssdfs-global-fsck",},
};

/*
 * ssdfs_start_global_fsck_thread() - start global fsck thread
 * @fsi: pointer on shared file system object
 *
 * This function tries to start global fsck thread.
 *
 * RETURN:
 * [success] - global fsck thread has been started.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_start_global_fsck_thread(struct ssdfs_fs_info *fsi)
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
	thread = &fsi->global_fsck.thread;

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
			SSDFS_ERR("fail to start global fsck's thread: "
				  "err %d\n", err);
		}

		return err;
	}

	init_waitqueue_entry(&thread->wait, thread->task);
	add_wait_queue(&fsi->global_fsck.wait_queue,
			&thread->wait);
	init_completion(&thread->full_stop);

	wake_up_process(thread->task);

	return 0;
}

/*
 * ssdfs_stop_global_fsck_thread() - stop global fsck thread
 * @fsi: pointer on shared file system object
 *
 * This function tries to stop global fsck thread.
 *
 * RETURN:
 * [success] - global fsck thread has been stopped.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_stop_global_fsck_thread(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_thread_info *thread;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	thread = &fsi->global_fsck.thread;

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

	finish_wait(&fsi->global_fsck.wait_queue,
		    &thread->wait);

	fsi->global_fsck.thread.task = NULL;

	err = SSDFS_WAIT_COMPLETION(&thread->full_stop);
	if (unlikely(err)) {
		SSDFS_ERR("stop thread fails: err %d\n", err);
		return err;
	}

	return 0;
}
