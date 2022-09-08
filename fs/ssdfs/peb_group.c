//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_group.c - PEBs group implementation.
 *
 * Copyright (c) 2021-2022 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "ssdfs.h"
#include "page_array.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "peb_group.h"


static
struct ssdfs_thread_descriptor thread_desc[SSDFS_PEB_THREAD_TYPE_MAX] = {
	{.threadfn = ssdfs_peb_read_thread_func,
	 .fmt = "ssdfs-r%llu",},
	{.threadfn = ssdfs_peb_flush_thread_func,
	 .fmt = "ssdfs-f%llu",},
};

/*
 * ssdfs_peb_group_start_thread() - start PEB group's thread
 * @group: pointer on PEB group
 * @type: thread type
 *
 * This function tries to start PEB group's thread of @type.
 *
 * RETURN:
 * [success] - PEB group's thread has been started.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_peb_group_start_thread(struct ssdfs_peb_group *group,
				 u64 group_id, int type)
{
	ssdfs_threadfn threadfn;
	const char *fmt;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!group);

	if (type >= SSDFS_PEB_THREAD_TYPE_MAX) {
		SSDFS_ERR("invalid thread type %d\n", type);
		return -EINVAL;
	}

SSDFS_ERR("start_leb %llu, lebs_count %u, "
		  "group_id %llu, thread_type %#x\n",
		  group->start_leb, group->lebs_count,
		  group_id, type);
#endif /* CONFIG_SSDFS_DEBUG */

	threadfn = thread_desc[type].threadfn;
	fmt = thread_desc[type].fmt;

	group->thread[type].task = kthread_create(threadfn, group, fmt,
						  group_id);
	if (IS_ERR_OR_NULL(group->thread[type].task)) {
		err = PTR_ERR(group->thread[type].task);
		SSDFS_ERR("fail to start thread: "
			  "group_id %llu, thread_type %d\n",
			  group_id, type);
		return err;
	}

	init_waitqueue_entry(&group->thread[type].wait,
			     group->thread[type].task);
	add_wait_queue(&group->wait_queue[type],
			&group->thread[type].wait);
	init_completion(&group->thread[type].full_stop);

	wake_up_process(group->thread[type].task);

	return 0;
}

/*
 * ssdfs_peb_group_stop_thread() - stop PEB group's thread
 * @group: pointer on PEB group
 * @type: thread type
 *
 * This function tries to stop PEB group's thread of @type.
 *
 * RETURN:
 * [success] - PEB group's thread has been stopped.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_peb_group_stop_thread(struct ssdfs_peb_group *group, int type)
{
	unsigned long res;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!group);

	if (type >= SSDFS_PEB_THREAD_TYPE_MAX) {
		SSDFS_ERR("invalid thread type %d\n", type);
		return -EINVAL;
	}

SSDFS_ERR("start_leb %llu, lebs_count %u, "
		  "thread_type %#x, task %p\n",
		  group->start_leb, group->lebs_count,
		  type, group->thread[type].task);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!group->thread[type].task)
		return 0;

	err = kthread_stop(group->thread[type].task);
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

	finish_wait(&group->wait_queue[type],
			&group->thread[type].wait);

	group->thread[type].task = NULL;

	res = wait_for_completion_timeout(&group->thread[type].full_stop,
					  SSDFS_DEFAULT_TIMEOUT);
	if (res == 0) {
		err = -ERANGE;
		SSDFS_ERR("stop thread fails: err %d\n", err);
		return err;
	}

	return 0;
}

u64 SSDFS_SEG2LEB(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_fs_info *fsi = pebc->parent_si->fsi;
	u64 seg_id = pebc->parent_si->seg_id;
	u16 peb_index = pebc->peb_index;

	return (seg_id * fsi->pebs_per_seg) + peb_index;
}

u16 SSDFS_LEB2INDEX(struct ssdfs_peb_group *group,
		    struct ssdfs_peb_container *pebc)
{
	u64 leb_id = SSDFS_SEG2LEB(pebc);
	u64 index;

	if (leb_id < group->start_leb ||
	    leb_id >= (group->start_leb + group->lebs_count)) {
		SSDFS_ERR("invalid leb_id %llu, "
			  "group (start_leb %llu, lebs_count %u)\n",
			  leb_id, group->start_leb, group->lebs_count);
		return U16_MAX;
	}

	index = leb_id - group->start_leb;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u16)index;
}

/*
 * ssdfs_peb_group_create() - create PEB group object
 * @fsi: pointer on shared file system object
 * @group: ponter on allocated PEB group object
 * @group_id: PEB group ID
 *
 * This function tries to initialize a PEB group object.
 *
 * RETURN:
 * [success] - PEB group object has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_group_create(struct ssdfs_fs_info *fsi,
			   struct ssdfs_peb_group *group,
			   u64 group_id)
{
	size_t ptr_size = sizeof(struct ssdfs_peb_container *);
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !group);

	SSDFS_DBG("fsi %p, group %p, group_id %llu\n",
		  fsi, group, group_id);
#endif /* CONFIG_SSDFS_DEBUG */

	group->start_leb = SSDFS_GROUP2LEB_ID(fsi, group_id);
	group->lebs_count = fsi->pebs_per_group;

	group->fsi = fsi;

	for (i = 0; i < SSDFS_PEB_THREAD_TYPE_MAX; i++) {
		init_waitqueue_head(&group->wait_queue[i]);
		atomic64_set(&group->reqs_counter[i], 0);
	}

	SSDFS_SET_CREATE_RQ_EMPTY(group);

	spin_lock_init(&group->group_lock);
	group->active_pebs = 0;
	memset(group->pebs, 0, ptr_size * SSDFS_DEFAULT_PEBS_PER_GROUP);

	err = ssdfs_peb_group_start_thread(group, group_id,
					   SSDFS_PEB_READ_THREAD);
	if (unlikely(err)) {
		SSDFS_ERR("fail to start read thread: "
			  "group_id %llu, err %d\n",
			  group_id, err);
		goto fail_create_peb_group;
	}

	err = ssdfs_peb_group_start_thread(group, group_id,
					   SSDFS_PEB_FLUSH_THREAD);
	if (unlikely(err)) {
		SSDFS_ERR("fail to start flush thread: "
			  "group_id %llu, err %d\n",
			  group_id, err);
		goto stop_read_thread;
	}

	return 0;

stop_read_thread:
	ssdfs_peb_group_stop_thread(group, SSDFS_PEB_READ_THREAD);

fail_create_peb_group:
	return err;
}

/*
 * ssdfs_peb_group_destroy() - destroy PEB group object
 * @group: ponter on PEB group object
 *
 * This function tries to destroy a PEB group object.
 */
void ssdfs_peb_group_destroy(struct ssdfs_peb_group *group)
{
	int i;
	int err;

	if (!group)
		return;

#ifdef CONFIG_SSDFS_DEBUG
SSDFS_ERR("group %p, start_leb %llu, lebs_count %u\n",
		  group, group->start_leb, group->lebs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_PEB_THREAD_TYPE_MAX; i++) {
		err = ssdfs_peb_group_stop_thread(group, i);
		if (err == -EIO) {
			SSDFS_WARN("thread I/O issue: "
				   "start_leb %llu, lebs_count %u, "
				   "thread type %#x\n",
				   group->start_leb, group->lebs_count, i);
		} else if (unlikely(err)) {
			SSDFS_WARN("thread stopping issue: "
				   "start_leb %llu, lebs_count %u, "
				   "thread type %#x, err %d\n",
				   group->start_leb, group->lebs_count,
				   i, err);
		}
	}

	for (i = 0; i < SSDFS_DEFAULT_PEBS_PER_GROUP; i++) {
		struct ssdfs_peb_container *pebc;

		spin_lock(&group->group_lock);
		pebc = group->pebs[i];
		spin_unlock(&group->group_lock);

		if (pebc != NULL) {
			SSDFS_ERR("PEB container is not NULL: "
				  "start_leb %llu, lebs_count %u, "
				  "index %d\n",
				  group->start_leb, group->lebs_count, i);
		}
	}
}

/*
 * ssdfs_peb_group_add_peb() - add PEB container into the group
 * @group: ponter on PEB group object
 * @pebc: pointer on PEB container
 *
 * This function tries to add PEB container into the group.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EEXIST     - PEB container has been added already.
 */
int ssdfs_peb_group_add_peb(struct ssdfs_peb_group *group,
			    struct ssdfs_peb_container *pebc)
{
	struct ssdfs_peb_container *ptr;
	u16 index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!group || !pebc);

	SSDFS_DBG("start_leb %llu, seg %llu, peb_index %u\n",
		   group->start_leb,
		   pebc->parent_si->seg_id,
		   pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	index = SSDFS_LEB2INDEX(group, pebc);
	if (index >= SSDFS_DEFAULT_PEBS_PER_GROUP) {
		SSDFS_ERR("invalid index %u\n",
			  index);
		return -ERANGE;
	}

	spin_lock(&group->group_lock);
	ptr = group->pebs[index];
	if (ptr != NULL) {
		/* exist already */
		err = -EEXIST;
	} else {
		group->active_pebs++;
		group->pebs[index] = pebc;
	}
	spin_unlock(&group->group_lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to add PEB container: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
	}

	return err;
}

/*
 * ssdfs_peb_group_remove_peb() - remove PEB container from the group
 * @group: ponter on PEB group object
 * @pebc: pointer on PEB container
 *
 * This function tries to remove PEB container from the group.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOENT     - PEB container doesn't exist.
 */
int ssdfs_peb_group_remove_peb(struct ssdfs_peb_group *group,
				struct ssdfs_peb_container *pebc)
{
	struct ssdfs_peb_container *ptr;
	u16 index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!group || !pebc);

	SSDFS_DBG("start_leb %llu, seg %llu, peb_index %u\n",
		   group->start_leb,
		   pebc->parent_si->seg_id,
		   pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	index = SSDFS_LEB2INDEX(group, pebc);
	if (index >= SSDFS_DEFAULT_PEBS_PER_GROUP) {
		SSDFS_ERR("invalid index %u\n",
			  index);
		return -ERANGE;
	}

	spin_lock(&group->group_lock);
	ptr = group->pebs[index];
	if (ptr == NULL) {
		/* not exist */
		err = -ENOENT;
	} else {
		group->pebs[index] = NULL;
		group->active_pebs--;
	}
	spin_unlock(&group->group_lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to remove PEB container: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
	}

	return err;
}
