// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_fsck_thread.c - fsck thread functionality.
 *
 * Copyright (c) 2023 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "page_vector.h"
#include "ssdfs.h"
#include "compression.h"
#include "block_bitmap.h"
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "page_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "peb_mapping_table.h"
#include "extents_queue.h"
#include "request_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "diff_on_write.h"
#include "shared_extents_tree.h"
#include "invalidated_extents_tree.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_fsck_page_leaks;
atomic64_t ssdfs_fsck_memory_leaks;
atomic64_t ssdfs_fsck_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_fsck_cache_leaks_increment(void *kaddr)
 * void ssdfs_fsck_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_fsck_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_fsck_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_fsck_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_fsck_kfree(void *kaddr)
 * struct page *ssdfs_fsck_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_fsck_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_fsck_free_page(struct page *page)
 * void ssdfs_fsck_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(fsck)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(fsck)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_fsck_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_fsck_page_leaks, 0);
	atomic64_set(&ssdfs_fsck_memory_leaks, 0);
	atomic64_set(&ssdfs_fsck_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_fsck_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_fsck_page_leaks) != 0) {
		SSDFS_ERR("FSCK THREAD: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_fsck_page_leaks));
	}

	if (atomic64_read(&ssdfs_fsck_memory_leaks) != 0) {
		SSDFS_ERR("FSCK THREAD: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_fsck_memory_leaks));
	}

	if (atomic64_read(&ssdfs_fsck_cache_leaks) != 0) {
		SSDFS_ERR("FSCK THREAD: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_fsck_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

#define FSCK_THREAD_WAKE_CONDITION(pebc) \
	(kthread_should_stop() || \
	 !is_fsck_requests_queue_empty(pebc))
#define FSCK_FAILED_THREAD_WAKE_CONDITION() \
	(kthread_should_stop())
#define FSCK_THREAD_LONG_WAIT_TIMEOUT	(msecs_to_jiffies(3000))

/*
 * is_time_do_fsck_check() - check that it's good time for FSCK activity
 * @fsi: pointer on shared file system object
 * @io_stats: I/O load estimation [in|out]
 *
 * This method tries to estimate the I/O load with
 * the goal to define the good time for FSCK activity.
 */
int is_time_do_fsck_check(struct ssdfs_fs_info *fsi,
			  struct ssdfs_io_load_stats *io_stats)
{
	return is_time_collect_garbage(fsi, io_stats);
}

/*
 * ssdfs_peb_fsck_thread_func() - main fuction of FSCK thread
 * @data: pointer on data object
 *
 * This function is main fuction of FSCK thread.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_peb_fsck_thread_func(void *data)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_container *pebc = data;
	wait_queue_head_t *wait_queue;
	struct ssdfs_io_load_stats io_stats;
	size_t io_stats_size = sizeof(struct ssdfs_io_load_stats);
	int fsck_strategy;
	u64 timeout = FSCK_THREAD_LONG_WAIT_TIMEOUT;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		BUG();
	}

	SSDFS_DBG("fsck thread: seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;
	wait_queue = &pebc->parent_si->wait_queue[SSDFS_PEB_FSCK_THREAD];

repeat:
	if (kthread_should_stop()) {
		if (!is_ssdfs_requests_queue_empty(&pebc->fsck_rq))
			ssdfs_requests_queue_remove_all(&pebc->fsck_rq, 0);

		complete_all(&pebc->thread[SSDFS_PEB_FSCK_THREAD].full_stop);
		return err;
	}

	if (is_fsck_requests_queue_empty(pebc))
		goto sleep_fsck_thread;

	if (atomic_read(&fsi->fsck_priority) > 0)
		goto do_fsck_check_now;

	memset(&io_stats, 0, io_stats_size);
	fsck_strategy = SSDFS_UNDEFINED_FSCK_STATE;

	do {
		fsck_strategy = is_time_do_fsck_check(fsi, &io_stats);

		switch (fsck_strategy) {
		case SSDFS_DO_FSCK_CHECK_NOW:
			goto do_fsck_check_now;

		case SSDFS_STOP_FSCK_ACTIVITY_NOW:
			wait_event_interruptible_timeout(*wait_queue,
						kthread_should_stop(),
						timeout);

			if (kthread_should_stop())
				goto repeat;

			timeout = min_t(u64, timeout * 2,
					(u64)SSDFS_DEFAULT_TIMEOUT);
			break;

		case SSDFS_WAIT_IDLE_STATE:
			wait_event_interruptible_timeout(*wait_queue,
						kthread_should_stop(),
						HZ);

			if (kthread_should_stop())
				goto repeat;
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("unexpected strategy %#x\n",
				  fsck_strategy);
			goto sleep_failed_fsck_thread;
		}
	} while (fsck_strategy == SSDFS_FSCK_WAIT_IDLE_STATE);

do_fsck_check_now:
	if (kthread_should_stop())
		goto repeat;


/* TODO: add main logic */

sleep_fsck_thread:
	wait_event_interruptible(*wait_queue,
				 FSCK_THREAD_WAKE_CONDITION(pebc));
	goto repeat;

sleep_failed_fsck_thread:
	wait_event_interruptible(*wait_queue,
				 FSCK_FAILED_THREAD_WAKE_CONDITION());
	goto repeat;
}
