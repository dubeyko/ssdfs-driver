//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_gc_thread.c - GC thread functionality.
 *
 * Copyright (c) 2014-2018 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2009-2018, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "compression.h"
#include "block_bitmap.h"
#include "page_array.h"
#include "peb.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"

#include <trace/events/ssdfs.h>

/******************************************************************************
 *                           GC THREAD FUNCTIONALITY                          *
 ******************************************************************************/

/* TODO: add condition of presence of items for processing  */
#define GC_THREAD_WAKE_CONDITION(pebi) \
	(kthread_should_stop())
	/*(kthread_should_stop() || kthread_should_park())*/

/*
 * ssdfs_peb_gc_thread_func() - main fuction of GC thread
 * @data: pointer on data object
 *
 * This function is main fuction of GC thread.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_peb_gc_thread_func(void *data)
{
	struct ssdfs_peb_container *pebc = data;
	wait_queue_head_t *wait_queue;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("GC thread: seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	wait_queue = &pebc->parent_si->wait_queue[SSDFS_PEB_GC_THREAD];

repeat:
	if (kthread_should_stop()) {
		complete_all(&pebc->thread[SSDFS_PEB_GC_THREAD].full_stop);
		return 0;
	}

	/*
	 * TODO: It is possible to use the concept of "parking" in the future.
	 *       Currently, there is compilation issue with
	 *       kthread_should_park(), kthread_parkme() on linking stage
	 *       when SSDFS file system driver is compiled as Linux
	 *       kernel module:
	 *
	 *       ERROR: "kthread_should_park" [fs/ssdfs/ssdfs.ko] undefined!
	 *       ERROR: "kthread_parkme" [fs/ssdfs/ssdfs.ko] undefined!
	 */

	/*if (kthread_should_park())
		kthread_parkme();*/

	/* TODO: collect garbage */
	SSDFS_DBG("TODO: implement %s\n", __func__);
	goto sleep_gc_thread;
	/*return -ENOSYS;*/

sleep_gc_thread:
	wait_event_interruptible(*wait_queue, GC_THREAD_WAKE_CONDITION(pebi));
	goto repeat;
}
