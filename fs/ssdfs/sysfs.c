/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/sysfs.c - sysfs support.
 *
 * Copyright (c) 2019-2025 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mtd/mtd.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "current_segment.h"
#include "peb_mapping_table.h"
#include "sysfs.h"

/*
 * /sys/fs/ssdfs/
 */
static struct kset *ssdfs_kset;

#define SSDFS_SHOW_TIME(ns, buf) ({ \
	struct timespec64 timespec_val; \
	struct tm res; \
	int count = 0; \
	timespec_val = ns_to_timespec64(ns); \
	time64_to_tm(timespec_val.tv_sec, 0, &res); \
	res.tm_year += 1900; \
	res.tm_mon += 1; \
	count = scnprintf(buf, PAGE_SIZE, \
			    "%ld-%.2d-%.2d %.2d:%.2d:%.2d\n", \
			    res.tm_year, res.tm_mon, res.tm_mday, \
			    res.tm_hour, res.tm_min, res.tm_sec);\
	count; \
})

/************************************************************************
 *                          SSDFS peb attrs                             *
 ************************************************************************/

static ssize_t ssdfs_peb_id_show(struct ssdfs_peb_attr *attr,
				 struct ssdfs_peb_container *pebc,
				 char *buf)
{
	int count = 0;

	if (pebc->src_peb) {
		count += snprintf(buf + count, PAGE_SIZE - count,
				  "SOURCE PEB: %llu\n",
				  pebc->src_peb->peb_id);
	}

	if (pebc->dst_peb) {
		count += snprintf(buf + count, PAGE_SIZE - count,
				  "DESTINATION PEB: %llu\n",
				  pebc->dst_peb->peb_id);
	}

	return count;
}

static ssize_t ssdfs_peb_peb_index_show(struct ssdfs_peb_attr *attr,
					struct ssdfs_peb_container *pebc,
					char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", pebc->peb_index);
}

static ssize_t ssdfs_peb_log_pages_show(struct ssdfs_peb_attr *attr,
					struct ssdfs_peb_container *pebc,
					char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", pebc->log_blocks);
}

static ssize_t ssdfs_peb_valid_pages_show(struct ssdfs_peb_attr *attr,
					 struct ssdfs_peb_container *pebc,
					 char *buf)
{
	int valid_pages;

	valid_pages = ssdfs_peb_get_used_data_pages(pebc);
	if (valid_pages < 0)
		return valid_pages;

	return snprintf(buf, PAGE_SIZE, "%d\n", valid_pages);
}

static ssize_t ssdfs_peb_invalid_pages_show(struct ssdfs_peb_attr *attr,
					    struct ssdfs_peb_container *pebc,
					    char *buf)
{
	int invalid_pages;

	invalid_pages = ssdfs_peb_get_invalid_pages(pebc);
	if (invalid_pages < 0)
		return invalid_pages;

	return snprintf(buf, PAGE_SIZE, "%d\n", invalid_pages);
}

static ssize_t ssdfs_peb_free_pages_show(struct ssdfs_peb_attr *attr,
					 struct ssdfs_peb_container *pebc,
					 char *buf)
{
	int free_pages;

	free_pages = ssdfs_peb_get_free_pages(pebc);
	if (free_pages < 0)
		return free_pages;

	return snprintf(buf, PAGE_SIZE, "%d\n", free_pages);
}

/******************************************************************************
 * BEGIN                     adopted from procfs code                   BEGIN *
 ******************************************************************************/

/*
 * The task state array is a strange "bitmap" of
 * reasons to sleep. Thus "running" is zero, and
 * you can test for combinations of others with
 * simple bit tests.
 */
static const char * const task_state_array[] = {
	"R (running)",		/*   0 */
	"S (sleeping)",		/*   1 */
	"D (disk sleep)",	/*   2 */
	"T (stopped)",		/*   4 */
	"t (tracing stop)",	/*   8 */
	"X (dead)",		/*  16 */
	"Z (zombie)",		/*  32 */
	"P (parked)",		/*  64 */
};

static inline const char *get_task_state(struct task_struct *tsk)
{
	unsigned int state = (tsk->__state | tsk->exit_state) & TASK_REPORT;

	BUILD_BUG_ON(1 + ilog2(TASK_REPORT) != ARRAY_SIZE(task_state_array)-1);

	return task_state_array[fls(state)];
}

/******************************************************************************
 * END                      adopted from procfs code                      END *
 ******************************************************************************/

static const char * const thread_type_array[] = {
	"READ thread",		/* SSDFS_PEB_READ_THREAD */
	"FLUSH thread",		/* SSDFS_PEB_FLUSH_THREAD */
	"GC thread",		/* SSDFS_PEB_GC_THREAD */
};

static ssize_t ssdfs_peb_threads_info_show(struct ssdfs_peb_attr *attr,
					   struct ssdfs_peb_container *pebc,
					   char *buf)
{
	int count = 0;
	pid_t pid;
	const char *state = NULL;
	const char *type = NULL;
	int thread_state;
	int unfinished_reqs;
	int thread_err;
	int i;
#ifdef CONFIG_SSDFS_DEBUG
	struct ssdfs_thread_call_stack *stack;
	struct ssdfs_thread_execution_point *point;
	u32 stack_size;
	const char *file = NULL;
	const char *function = NULL;
	u32 code_line = U32_MAX;
	int j;
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_PEB_THREAD_TYPE_MAX; i++) {
		if (!pebc->thread[i].task)
			continue;
		pid = task_pid_nr(pebc->thread[i].task);
		state = get_task_state(pebc->thread[i].task);
		type = thread_type_array[i];
		thread_state = pebc->thread_state[i].state;
#ifdef CONFIG_SSDFS_DEBUG
		unfinished_reqs = pebc->thread_state[i].unfinished_reqs;
#else
		unfinished_reqs = 0;
#endif /* CONFIG_SSDFS_DEBUG */
		thread_err = pebc->thread_state[i].err;
		count += snprintf(buf + count, PAGE_SIZE - count,
				  "%s: pid %d, state %s, "
				  "thread_state %#x, unfinished_reqs %d, "
				  "thread_err %d\n",
				  type, pid, state,
				  thread_state, unfinished_reqs,
				  thread_err);
#ifdef CONFIG_SSDFS_DEBUG
		stack = &pebc->thread_state[i].call_stack;
		stack_size = min_t(u32,
				   (u32)SSDFS_CALL_STACK_CAPACITY,
				   stack->count);
		for (j = 0; j < stack_size; j++) {
			point = &stack->points[j];

			if (point->file)
				file = point->file;
			else
				file = "UNKNOWN";

			if (point->function)
				function = point->function;
			else
				function = "UNKNOWN";

			code_line = point->code_line;

			count += snprintf(buf + count, PAGE_SIZE - count,
					  "[%d] file %s, function %s, "
					  "code_line %u\n",
					  j, file, function, code_line);
		}
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return count;
}

SSDFS_PEB_RO_ATTR(id);
SSDFS_PEB_RO_ATTR(peb_index);
SSDFS_PEB_RO_ATTR(log_pages);
SSDFS_PEB_RO_ATTR(valid_pages);
SSDFS_PEB_RO_ATTR(invalid_pages);
SSDFS_PEB_RO_ATTR(free_pages);
SSDFS_PEB_RO_ATTR(threads_info);

static struct attribute *ssdfs_peb_attrs[] = {
	SSDFS_PEB_ATTR_LIST(id),
	SSDFS_PEB_ATTR_LIST(peb_index),
	SSDFS_PEB_ATTR_LIST(log_pages),
	SSDFS_PEB_ATTR_LIST(valid_pages),
	SSDFS_PEB_ATTR_LIST(invalid_pages),
	SSDFS_PEB_ATTR_LIST(free_pages),
	SSDFS_PEB_ATTR_LIST(threads_info),
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_peb);

static ssize_t ssdfs_peb_attr_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct ssdfs_peb_container *pebc = container_of(kobj,
						   struct ssdfs_peb_container,
						   peb_kobj);
	struct ssdfs_peb_attr *a = container_of(attr, struct ssdfs_peb_attr,
						attr);

	return a->show ? a->show(a, pebc, buf) : 0;
}

static ssize_t ssdfs_peb_attr_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf, size_t len)
{
	struct ssdfs_peb_container *pebc = container_of(kobj,
						   struct ssdfs_peb_container,
						   peb_kobj);
	struct ssdfs_peb_attr *a = container_of(attr, struct ssdfs_peb_attr,
						attr);

	return a->store ? a->store(a, pebc, buf, len) : 0;
}

static void ssdfs_peb_attr_release(struct kobject *kobj)
{
	struct ssdfs_peb_container *pebc = container_of(kobj,
						   struct ssdfs_peb_container,
						   peb_kobj);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release peb %u group\n", pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&pebc->peb_kobj_unregister);
}

static const struct sysfs_ops ssdfs_peb_attr_ops = {
	.show	= ssdfs_peb_attr_show,
	.store	= ssdfs_peb_attr_store,
};

static struct kobj_type ssdfs_peb_ktype = {
	.default_groups = ssdfs_peb_groups,
	.sysfs_ops	= &ssdfs_peb_attr_ops,
	.release	= ssdfs_peb_attr_release,
};

int ssdfs_sysfs_create_peb_group(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si = pebc->parent_si;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create peb %u group\n", pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	pebc->peb_kobj.kset = ssdfs_kset;
	init_completion(&pebc->peb_kobj_unregister);
	err = kobject_init_and_add(&pebc->peb_kobj,
				   &ssdfs_peb_ktype,
				   &si->pebs_kobj,
				   "peb%u",
				   pebc->peb_index);
	if (err)
		return err;

	return 0;
}

void ssdfs_sysfs_delete_peb_group(struct ssdfs_peb_container *pebc)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete peb %u group\n", pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	kobject_del(&pebc->peb_kobj);
	kobject_put(&pebc->peb_kobj);
	wait_for_completion(&pebc->peb_kobj_unregister);
}

/************************************************************************
 *                          SSDFS pebs group                            *
 ************************************************************************/

static struct attribute *ssdfs_pebs_attrs[] = {
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_pebs);

static ssize_t ssdfs_pebs_attr_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct ssdfs_segment_info *si = container_of(kobj->parent,
						struct ssdfs_segment_info,
						pebs_kobj);
	struct ssdfs_pebs_attr *a = container_of(attr,
						struct ssdfs_pebs_attr,
						attr);
	return a->show ? a->show(a, si, buf) : 0;
}

static ssize_t ssdfs_pebs_attr_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buf, size_t len)
{
	struct ssdfs_segment_info *si = container_of(kobj,
						struct ssdfs_segment_info,
						pebs_kobj);
	struct ssdfs_pebs_attr *a = container_of(attr,
						struct ssdfs_pebs_attr,
						attr);
	return a->store ? a->store(a, si, buf, len) : 0;
}

static void ssdfs_pebs_attr_release(struct kobject *kobj)
{
	struct ssdfs_segment_info *si = container_of(kobj,
						     struct ssdfs_segment_info,
						     pebs_kobj);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release pebs group: seg_id %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&si->pebs_kobj_unregister);
}

static const struct sysfs_ops ssdfs_pebs_attr_ops = {
	.show	= ssdfs_pebs_attr_show,
	.store	= ssdfs_pebs_attr_store,
};

static struct kobj_type ssdfs_pebs_ktype = {
	.default_groups = ssdfs_pebs_groups,
	.sysfs_ops	= &ssdfs_pebs_attr_ops,
	.release	= ssdfs_pebs_attr_release,
};

static int ssdfs_sysfs_create_pebs_group(struct ssdfs_segment_info *si)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create pebs group: seg_id %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	si->pebs_kobj.kset = ssdfs_kset;
	init_completion(&si->pebs_kobj_unregister);
	err = kobject_init_and_add(&si->pebs_kobj, &ssdfs_pebs_ktype,
				   si->seg_kobj, "pebs");
	if (err)
		return err;

	return 0;
}

static void ssdfs_sysfs_delete_pebs_group(struct ssdfs_segment_info *si)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete pebs group: seg_id %llu\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	kobject_del(&si->pebs_kobj);
	kobject_put(&si->pebs_kobj);
	wait_for_completion(&si->pebs_kobj_unregister);
}

/************************************************************************
 *                        SSDFS segment attrs                           *
 ************************************************************************/

static ssize_t ssdfs_seg_id_show(struct ssdfs_seg_attr *attr,
				 struct ssdfs_segment_info *si,
				 char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", si->seg_id);
}

static ssize_t ssdfs_seg_log_pages_show(struct ssdfs_seg_attr *attr,
					struct ssdfs_segment_info *si,
					char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", si->log_pages);
}

static ssize_t ssdfs_seg_create_threads_show(struct ssdfs_seg_attr *attr,
					     struct ssdfs_segment_info *si,
					     char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", si->create_threads);
}

static ssize_t ssdfs_seg_seg_type_show(struct ssdfs_seg_attr *attr,
					struct ssdfs_segment_info *si,
					char *buf)
{
	switch(si->seg_type) {
	case SSDFS_SB_SEG_TYPE:
		return snprintf(buf, PAGE_SIZE, "SSDFS_SB_SEG_TYPE\n");

	case SSDFS_INITIAL_SNAPSHOT_SEG_TYPE:
		return snprintf(buf, PAGE_SIZE,
				"SSDFS_INITIAL_SNAPSHOT_SEG_TYPE\n");

	case SSDFS_SEGBMAP_SEG_TYPE:
		return snprintf(buf, PAGE_SIZE,
				"SSDFS_SEGBMAP_SEG_TYPE\n");

	case SSDFS_MAPTBL_SEG_TYPE:
		return snprintf(buf, PAGE_SIZE,
				"SSDFS_MAPTBL_SEG_TYPE\n");

	case SSDFS_LEAF_NODE_SEG_TYPE:
		return snprintf(buf, PAGE_SIZE,
				"SSDFS_LEAF_NODE_SEG_TYPE\n");

	case SSDFS_HYBRID_NODE_SEG_TYPE:
		return snprintf(buf, PAGE_SIZE,
				"SSDFS_HYBRID_NODE_SEG_TYPE\n");

	case SSDFS_INDEX_NODE_SEG_TYPE:
		return snprintf(buf, PAGE_SIZE,
				"SSDFS_INDEX_NODE_SEG_TYPE\n");

	case SSDFS_USER_DATA_SEG_TYPE:
		return snprintf(buf, PAGE_SIZE,
				"SSDFS_USER_DATA_SEG_TYPE\n");
	}

	SSDFS_WARN("unknown segment type\n");
	return -EINVAL;
}

static ssize_t ssdfs_seg_pebs_count_show(struct ssdfs_seg_attr *attr,
					 struct ssdfs_segment_info *si,
					 char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", si->pebs_count);
}

static ssize_t ssdfs_seg_refs_count_show(struct ssdfs_seg_attr *attr,
					 struct ssdfs_segment_info *si,
					 char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", atomic_read(&si->refs_count));
}

static ssize_t ssdfs_seg_valid_pages_show(struct ssdfs_seg_attr *attr,
					  struct ssdfs_segment_info *si,
					  char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n",
			atomic_read(&si->blk_bmap.seg_valid_blks));
}

static ssize_t ssdfs_seg_invalid_pages_show(struct ssdfs_seg_attr *attr,
					    struct ssdfs_segment_info *si,
					    char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n",
			atomic_read(&si->blk_bmap.seg_invalid_blks));
}

static ssize_t ssdfs_seg_free_pages_show(struct ssdfs_seg_attr *attr,
					 struct ssdfs_segment_info *si,
					 char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n",
			atomic_read(&si->blk_bmap.seg_free_blks));
}

static ssize_t ssdfs_seg_seg_state_show(struct ssdfs_seg_attr *attr,
					struct ssdfs_segment_info *si,
					char *buf)
{
	int seg_state;

	down_read(&si->modification_lock);
	seg_state = atomic_read(&si->seg_state);
	up_read(&si->modification_lock);

	switch(seg_state) {
	case SSDFS_SEG_CLEAN:
		return snprintf(buf, PAGE_SIZE, "SSDFS_SEG_CLEAN\n");

	case SSDFS_SEG_DATA_USING:
		return snprintf(buf, PAGE_SIZE, "SSDFS_SEG_DATA_USING\n");

	case SSDFS_SEG_LEAF_NODE_USING:
		return snprintf(buf, PAGE_SIZE, "SSDFS_SEG_LEAF_NODE_USING\n");

	case SSDFS_SEG_HYBRID_NODE_USING:
		return snprintf(buf, PAGE_SIZE,
				"SSDFS_SEG_HYBRID_NODE_USING\n");

	case SSDFS_SEG_INDEX_NODE_USING:
		return snprintf(buf, PAGE_SIZE,
				"SSDFS_SEG_INDEX_NODE_USING\n");

	case SSDFS_SEG_USED:
		return snprintf(buf, PAGE_SIZE, "SSDFS_SEG_USED\n");

	case SSDFS_SEG_PRE_DIRTY:
		return snprintf(buf, PAGE_SIZE, "SSDFS_SEG_PRE_DIRTY\n");

	case SSDFS_SEG_DIRTY:
		return snprintf(buf, PAGE_SIZE, "SSDFS_SEG_DIRTY\n");
	}

	SSDFS_WARN("unknown segment state\n");
	return -EINVAL;
}

SSDFS_SEG_RO_ATTR(id);
SSDFS_SEG_RO_ATTR(log_pages);
SSDFS_SEG_RO_ATTR(create_threads);
SSDFS_SEG_RO_ATTR(seg_type);
SSDFS_SEG_RO_ATTR(pebs_count);
SSDFS_SEG_RO_ATTR(refs_count);
SSDFS_SEG_RO_ATTR(valid_pages);
SSDFS_SEG_RO_ATTR(invalid_pages);
SSDFS_SEG_RO_ATTR(free_pages);
SSDFS_SEG_RO_ATTR(seg_state);

static struct attribute *ssdfs_seg_attrs[] = {
	SSDFS_SEG_ATTR_LIST(id),
	SSDFS_SEG_ATTR_LIST(log_pages),
	SSDFS_SEG_ATTR_LIST(create_threads),
	SSDFS_SEG_ATTR_LIST(seg_type),
	SSDFS_SEG_ATTR_LIST(pebs_count),
	SSDFS_SEG_ATTR_LIST(refs_count),
	SSDFS_SEG_ATTR_LIST(valid_pages),
	SSDFS_SEG_ATTR_LIST(invalid_pages),
	SSDFS_SEG_ATTR_LIST(free_pages),
	SSDFS_SEG_ATTR_LIST(seg_state),
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_seg);

static ssize_t ssdfs_seg_attr_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct ssdfs_segment_info *si = container_of(kobj,
						     struct ssdfs_segment_info,
						     seg_kobj_buf);
	struct ssdfs_seg_attr *a = container_of(attr, struct ssdfs_seg_attr,
						attr);

	return a->show ? a->show(a, si, buf) : 0;
}

static ssize_t ssdfs_seg_attr_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf, size_t len)
{
	struct ssdfs_segment_info *si = container_of(kobj,
						     struct ssdfs_segment_info,
						     seg_kobj_buf);
	struct ssdfs_seg_attr *a = container_of(attr, struct ssdfs_seg_attr,
						attr);

	return a->store ? a->store(a, si, buf, len) : 0;
}

static void ssdfs_seg_attr_release(struct kobject *kobj)
{
	struct ssdfs_segment_info *si = container_of(kobj,
						     struct ssdfs_segment_info,
						     seg_kobj_buf);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release seg %llu group\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&si->seg_kobj_unregister);
}

static const struct sysfs_ops ssdfs_seg_attr_ops = {
	.show	= ssdfs_seg_attr_show,
	.store	= ssdfs_seg_attr_store,
};

static struct kobj_type ssdfs_seg_ktype = {
	.default_groups = ssdfs_seg_groups,
	.sysfs_ops	= &ssdfs_seg_attr_ops,
	.release	= ssdfs_seg_attr_release,
};

int ssdfs_sysfs_create_seg_group(struct ssdfs_segment_info *si)
{
	struct ssdfs_fs_info *fsi = si->fsi;
	struct ssdfs_peb_container *pebc;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create seg %llu group\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	si->seg_kobj = &si->seg_kobj_buf;

	si->seg_kobj->kset = ssdfs_kset;
	init_completion(&si->seg_kobj_unregister);
	err = kobject_init_and_add(&si->seg_kobj_buf,
				   &ssdfs_seg_ktype,
				   &fsi->segments_kobj,
				   "seg%llu",
				   si->seg_id);
	if (err)
		goto free_seg_subgroups;

	err = ssdfs_sysfs_create_pebs_group(si);
	if (err)
		goto cleanup_seg_kobject;

	for (i = 0; i < si->pebs_count; i++) {
		pebc = &si->peb_array[i];
		err = ssdfs_sysfs_create_peb_group(pebc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create peb's sysfs group: "
				  "seg %llu, peb_index %d\n",
				  si->seg_id, i);
			goto cleanup_peb_kobjects;
		}
	}

	return 0;

cleanup_peb_kobjects:
	for (i--; i >= 0; i--) {
		pebc = &si->peb_array[i];
		ssdfs_sysfs_delete_peb_group(pebc);
	}

cleanup_seg_kobject:
	kobject_del(&si->seg_kobj_buf);
	kobject_put(&si->seg_kobj_buf);
	wait_for_completion(&si->seg_kobj_unregister);
	si->seg_kobj = NULL;

free_seg_subgroups:
	return err;
}

void ssdfs_sysfs_delete_seg_group(struct ssdfs_segment_info *si)
{
	struct ssdfs_peb_container *pebc;
	int i;

	if (!si || !si->seg_kobj)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete seg %llu group\n", si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < si->pebs_count; i++) {
		pebc = &si->peb_array[i];
		ssdfs_sysfs_delete_peb_group(pebc);
	}

	ssdfs_sysfs_delete_pebs_group(si);
	kobject_del(&si->seg_kobj_buf);
	kobject_put(&si->seg_kobj_buf);
	wait_for_completion(&si->seg_kobj_unregister);
	si->seg_kobj = NULL;
}

/************************************************************************
 *                        SSDFS segments group                          *
 ************************************************************************/

static
ssize_t ssdfs_segments_current_segments_show(struct ssdfs_segments_attr *attr,
					     struct ssdfs_fs_info *fsi,
					     char *buf)
{
	struct ssdfs_current_segs_array *array = fsi->cur_segs;
	u64 seg_id;
	int count = 0;
	int i, j;

	if (!array) {
		SSDFS_WARN("current_segments array is empty\n");
		return 0;
	}

	down_read(&array->lock);
	for (i = 0; i < SSDFS_CUR_SEGS_COUNT; i++) {
		struct ssdfs_current_segment *cur_seg;
		struct ssdfs_segment_info *real_seg;
		const char *type = NULL;

		switch (i) {
		case SSDFS_CUR_DATA_SEG:
			type = "CURRENT_DATA_SEGMENT";
			break;
		case SSDFS_CUR_LNODE_SEG:
			type = "CURRENT_LEAF_NODE_SEGMENT";
			break;
		case SSDFS_CUR_HNODE_SEG:
			type = "CURRENT_HYBRID_NODE_SEGMENT";
			break;
		case SSDFS_CUR_IDXNODE_SEG:
			type = "CURRENT_INDEX_NODE_SEGMENT";
			break;
		case SSDFS_CUR_DATA_UPDATE_SEG:
			type = "CURRENT_DATA_UPDATE_SEGMENT";
			break;
		default:
			BUG();
		}

		cur_seg = array->objects[i];

		if (cur_seg == NULL) {
			count += snprintf(buf + count,
					  PAGE_SIZE - count,
					  "%s: <empty>\n",
					  type);
			continue;
		}

		ssdfs_current_segment_lock(cur_seg);

		real_seg = cur_seg->real_seg;

		if (real_seg == NULL) {
			count += snprintf(buf + count,
					  PAGE_SIZE - count,
					  "%s: <empty>\n",
					  type);
			ssdfs_current_segment_unlock(cur_seg);
			continue;
		}

		seg_id = real_seg->seg_id;

		count += snprintf(buf + count,
				  PAGE_SIZE - count,
				  "%s: seg_id %llu: <",
				  type, seg_id);

		for (j = 0; j < real_seg->pebs_count; j++) {
			struct ssdfs_peb_container *pebc =
					&real_seg->peb_array[j];

			if (is_peb_joined_into_create_requests_queue(pebc)) {
				count += snprintf(buf + count,
						  PAGE_SIZE - count,
						  "peb_index %u",
						  pebc->peb_index);
			}
		}

		count += snprintf(buf + count,
				  PAGE_SIZE - count,
				  ">, create_threads %u\n",
				  real_seg->create_threads);

		ssdfs_current_segment_unlock(cur_seg);
	}
	up_read(&array->lock);

	return count;
}


SSDFS_SEGMENTS_RO_ATTR(current_segments);

static struct attribute *ssdfs_segments_attrs[] = {
	SSDFS_SEGMENTS_ATTR_LIST(current_segments),
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_segments);

static ssize_t ssdfs_segments_attr_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 segments_kobj);
	struct ssdfs_segments_attr *a = container_of(attr,
						struct ssdfs_segments_attr,
						attr);
	return a->show ? a->show(a, fsi, buf) : 0;
}

static ssize_t ssdfs_segments_attr_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buf, size_t len)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 segments_kobj);
	struct ssdfs_segments_attr *a = container_of(attr,
						struct ssdfs_segments_attr,
						attr);
	return a->store ? a->store(a, fsi, buf, len) : 0;
}

static void ssdfs_segments_attr_release(struct kobject *kobj)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 segments_kobj);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release segments group\n");
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&fsi->segments_kobj_unregister);
}

static const struct sysfs_ops ssdfs_segments_attr_ops = {
	.show	= ssdfs_segments_attr_show,
	.store	= ssdfs_segments_attr_store,
};

static struct kobj_type ssdfs_segments_ktype = {
	.default_groups = ssdfs_segments_groups,
	.sysfs_ops	= &ssdfs_segments_attr_ops,
	.release	= ssdfs_segments_attr_release,
};

static int ssdfs_sysfs_create_segments_group(struct ssdfs_fs_info *fsi)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create segments group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->segments_kobj.kset = ssdfs_kset;
	init_completion(&fsi->segments_kobj_unregister);
	err = kobject_init_and_add(&fsi->segments_kobj, &ssdfs_segments_ktype,
				   &fsi->dev_kobj, "segments");
	if (err)
		return err;

	return 0;
}

static void ssdfs_sysfs_delete_segments_group(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete segments group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	kobject_del(&fsi->segments_kobj);
	kobject_put(&fsi->segments_kobj);
	wait_for_completion(&fsi->segments_kobj_unregister);
}

/************************************************************************
 *                      SSDFS segbmap fragment attrs                   *
 ************************************************************************/

static ssize_t
ssdfs_segbmap_frag_id_show(struct ssdfs_segbmap_frag_attr *attr,
			   struct ssdfs_segbmap_fragment_desc *fdesc,
			   char *buf)
{
	struct ssdfs_segment_bmap *segbmap;
	u16 fragment_id;

	segbmap = fdesc->segbmap;

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);
	fragment_id = fdesc->fragment_id;
	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragment_id);
}

static ssize_t
ssdfs_segbmap_frag_state_show(struct ssdfs_segbmap_frag_attr *attr,
			      struct ssdfs_segbmap_fragment_desc *fdesc,
			      char *buf)
{
	struct ssdfs_segment_bmap *segbmap;
	int state;
	const char *state_name;

	segbmap = fdesc->segbmap;

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);
	state = fdesc->state;
	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

	switch (state) {
	case SSDFS_SEGBMAP_FRAG_CREATED:
		state_name = "CREATED";
		break;
	case SSDFS_SEGBMAP_FRAG_INIT_FAILED:
		state_name = "INIT_FAILED";
		break;
	case SSDFS_SEGBMAP_FRAG_INITIALIZED:
		state_name = "INITIALIZED";
		break;
	case SSDFS_SEGBMAP_FRAG_DIRTY:
		state_name = "DIRTY";
		break;
	case SSDFS_SEGBMAP_FRAG_TOWRITE:
		state_name = "TOWRITE";
		break;
	default:
		state_name = "UNKNOWN";
		break;
	}

	return snprintf(buf, PAGE_SIZE, "%s\n", state_name);
}

static ssize_t
ssdfs_segbmap_frag_total_segs_show(struct ssdfs_segbmap_frag_attr *attr,
				   struct ssdfs_segbmap_fragment_desc *fdesc,
				   char *buf)
{
	struct ssdfs_segment_bmap *segbmap;
	u16 total_segs;

	segbmap = fdesc->segbmap;

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);
	total_segs = fdesc->total_segs;
	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", total_segs);
}

static ssize_t
ssdfs_segbmap_frag_clean_or_using_segs_show(struct ssdfs_segbmap_frag_attr *attr,
					struct ssdfs_segbmap_fragment_desc *fdesc,
					char *buf)
{
	struct ssdfs_segment_bmap *segbmap;
	u16 clean_or_using_segs;

	segbmap = fdesc->segbmap;

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);
	clean_or_using_segs = fdesc->clean_or_using_segs;
	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", clean_or_using_segs);
}

static ssize_t
ssdfs_segbmap_frag_used_or_dirty_segs_show(struct ssdfs_segbmap_frag_attr *attr,
					   struct ssdfs_segbmap_fragment_desc *fdesc,
					   char *buf)
{
	struct ssdfs_segment_bmap *segbmap;
	u16 used_or_dirty_segs;

	segbmap = fdesc->segbmap;

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);
	used_or_dirty_segs = fdesc->used_or_dirty_segs;
	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", used_or_dirty_segs);
}

static ssize_t
ssdfs_segbmap_frag_bad_segs_show(struct ssdfs_segbmap_frag_attr *attr,
				 struct ssdfs_segbmap_fragment_desc *fdesc,
				 char *buf)
{
	struct ssdfs_segment_bmap *segbmap;
	u16 bad_segs;

	segbmap = fdesc->segbmap;

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);
	bad_segs = fdesc->bad_segs;
	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", bad_segs);
}

#define SSDFS_SEGBMAP_OUTPUT_THRESHOLD1		(PAGE_SIZE - 300)
#define SSDFS_SEGBMAP_OUTPUT_THRESHOLD2		(PAGE_SIZE - 200)
#define SSDFS_SEGBMAP_OUTPUT_THRESHOLD3		(PAGE_SIZE - 100)
#define SSDFS_SEGBMAP_OUTPUT_THRESHOLD4		(PAGE_SIZE - 150)
#define SSDFS_SEGBMAP_OUTPUT_CHARS_PER_LINE	(35)

static ssize_t
ssdfs_segbmap_frag_sections_count_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_bmap *segbmap;
	u32 sections_count = 0;
	u32 entries_per_section;
	u32 total_entries;

	segbmap = fdesc->segbmap;
	if (!segbmap) {
		SSDFS_ERR("segment bitmap is NULL\n");
		return snprintf(buf, PAGE_SIZE, "0\n");
	}

	fsi = segbmap->fsi;

	if (fdesc->state < SSDFS_SEGBMAP_FRAG_INITIALIZED) {
		return snprintf(buf, PAGE_SIZE, "0\n");
	}

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);

	if (fdesc->fragment_id >= segbmap->fragments_count) {
		up_read(&segbmap->search_lock);
		up_read(&segbmap->resize_lock);
		return snprintf(buf, PAGE_SIZE, "0\n");
	}

	total_entries = fdesc->total_segs;
	/* Each segment line takes ~35 chars, so ~115 segments per section */
	entries_per_section =
		SSDFS_SEGBMAP_OUTPUT_THRESHOLD2 /
			SSDFS_SEGBMAP_OUTPUT_CHARS_PER_LINE;
	sections_count =
		(total_entries + entries_per_section - 1) / entries_per_section;

	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", sections_count);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_show(struct ssdfs_segbmap_fragment_desc *fdesc,
					int section_index,
					char *buf)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_bmap *segbmap;
	struct ssdfs_segbmap_fragment_header *hdr;
	struct folio *folio;
	void *kaddr;
	u8 *bitmap;
	const char *state_name;
	u32 items_per_fragment;
	u32 hdr_size = sizeof(struct ssdfs_segbmap_fragment_header);
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_SEG_STATE_BITS);
	u16 fragment_id = fdesc->fragment_id;
	u32 entries_per_section = SSDFS_SEGBMAP_OUTPUT_THRESHOLD2 /
					SSDFS_SEGBMAP_OUTPUT_CHARS_PER_LINE;
	u32 section_start = section_index * entries_per_section;
	u32 section_end;
	int count = 0;
	u8 byte_value;
	u8 seg_state;
	u32 seg_index;
	u32 i, j;
	int err = 0;

	segbmap = fdesc->segbmap;
	if (!segbmap) {
		SSDFS_ERR("segment bitmap is NULL\n");
		return snprintf(buf, PAGE_SIZE, "Fragment bitmap not available\n");
	}

	fsi = segbmap->fsi;

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);

	if (fdesc->fragment_id >= segbmap->fragments_count) {
		err = -ERANGE;
		SSDFS_ERR("fragment_id %u >= fragments_count %u\n",
			  fdesc->fragment_id, segbmap->fragments_count);
		goto finish_show_bitmap;
	}

	folio = ssdfs_folio_array_get_folio_locked(&segbmap->folios,
						   fragment_id);
	if (IS_ERR_OR_NULL(folio)) {
		err = folio == NULL ? -ERANGE : PTR_ERR(folio);
		SSDFS_ERR("fail to find folio: fragment_id %u, err %d\n",
			  fragment_id, err);
		goto finish_show_bitmap;
	}

	kaddr = kmap_local_folio(folio, 0);

	hdr = (struct ssdfs_segbmap_fragment_header *)kaddr;

	if (le16_to_cpu(hdr->magic) != SSDFS_SEGBMAP_HDR_MAGIC) {
		count += snprintf(buf + count, PAGE_SIZE - count,
				  "INVALID MAGIC (0x%x != 0x%x)\n",
				  le16_to_cpu(hdr->magic),
				  SSDFS_SEGBMAP_HDR_MAGIC);
		goto finish_folio;
	}

	items_per_fragment =
		ssdfs_segbmap_items_per_fragment(segbmap->fragment_size);
	items_per_fragment =
		min_t(u32, items_per_fragment, le16_to_cpu(hdr->total_segs));

	section_end =
		min_t(u32, section_start + entries_per_section,
							items_per_fragment);

	if (section_start >= items_per_fragment) {
		count = snprintf(buf + count, PAGE_SIZE - count,
				 "Section %d out of range\n", section_index);
		goto finish_folio;
	}

	count += snprintf(buf + count, PAGE_SIZE - count,
			  "SEGMENT BITMAP FRAGMENT %u SECTION %d (segments %u-%u):\n",
			  fragment_id, section_index,
			  section_start, section_end - 1);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  Header: magic=0x%x, seg_index=%u, peb_index=%u\n",
			  le16_to_cpu(hdr->magic),
			  le16_to_cpu(hdr->seg_index),
			  le16_to_cpu(hdr->peb_index));
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  Total segments: %u, Clean/Using: %u, Used/Dirty: %u, Bad: %u\n",
			  le16_to_cpu(hdr->total_segs),
			  le16_to_cpu(hdr->clean_or_using_segs),
			  le16_to_cpu(hdr->used_or_dirty_segs),
			  le16_to_cpu(hdr->bad_segs));

	bitmap = (u8 *)kaddr + hdr_size;

	for (i = section_start;
	     i < section_end && count < SSDFS_SEGBMAP_OUTPUT_THRESHOLD3; i++) {
		if (i >= items_per_fragment)
			break;

		seg_index = i;
		j = i % items_per_byte;
		byte_value = bitmap[i / items_per_byte];
		seg_state = byte_value >> (j * SSDFS_SEG_STATE_BITS);
		seg_state &= SSDFS_SEG_STATE_MASK;

		switch (seg_state) {
		case SSDFS_SEG_CLEAN:
			state_name = "CLEAN";
			break;
		case SSDFS_SEG_DATA_USING:
			state_name = "DATA_USING";
			break;
		case SSDFS_SEG_LEAF_NODE_USING:
			state_name = "LEAF_NODE_USING";
			break;
		case SSDFS_SEG_HYBRID_NODE_USING:
			state_name = "HYBRID_NODE_USING";
			break;
		case SSDFS_SEG_INDEX_NODE_USING:
			state_name = "INDEX_NODE_USING";
			break;
		case SSDFS_SEG_USED:
			state_name = "USED";
			break;
		case SSDFS_SEG_PRE_DIRTY:
			state_name = "PRE_DIRTY";
			break;
		case SSDFS_SEG_DIRTY:
			state_name = "DIRTY";
			break;
		case SSDFS_SEG_BAD:
			state_name = "BAD";
			break;
		case SSDFS_SEG_RESERVED:
			state_name = "RESERVED";
			break;
		default:
			state_name = "UNKNOWN";
			break;
		}

		count += snprintf(buf + count, PAGE_SIZE - count,
				  "  Segment %u: %s (%u)\n",
				  seg_index, state_name, seg_state);
	}

	if (i < section_end) {
		count += snprintf(buf + count, PAGE_SIZE - count,
				  "  ... (section truncated at segment %u)\n", i);
	}

finish_folio:
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

finish_show_bitmap:
	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

	if (err)
		return err;

	return count;
}

static ssize_t
ssdfs_segbmap_frag_bitmap_show(struct ssdfs_segbmap_frag_attr *attr,
				struct ssdfs_segbmap_fragment_desc *fdesc,
				char *buf)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_bmap *segbmap;
	u32 total_entries;
	u32 entries_per_section = SSDFS_SEGBMAP_OUTPUT_THRESHOLD2 /
					SSDFS_SEGBMAP_OUTPUT_CHARS_PER_LINE;
	u32 sections_count;
	u16 fragment_id;

	segbmap = fdesc->segbmap;
	if (!segbmap) {
		SSDFS_ERR("segment bitmap is NULL\n");
		return snprintf(buf, PAGE_SIZE, "Fragment bitmap not available\n");
	}

	fsi = segbmap->fsi;

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);
	fragment_id = fdesc->fragment_id;
	total_entries = fdesc->total_segs;
	sections_count = (total_entries + entries_per_section - 1) / entries_per_section;
	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

	return snprintf(buf, PAGE_SIZE,
			"SEGMENT BITMAP FRAGMENT %u SUMMARY:\n"
			"  Total segments: %u\n"
			"  Sections available: %u (~%u segments per section)\n"
			"  Use 'sections_count' to get exact count\n"
			"  Use 'bitmap_section_0', 'bitmap_section_1', etc. to view content\n",
			fragment_id, total_entries,
			sections_count, entries_per_section);
}

/* Individual bitmap section show functions */
static ssize_t
ssdfs_segbmap_frag_bitmap_section_0_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 0, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_1_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 1, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_2_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 2, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_3_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 3, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_4_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 4, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_5_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 5, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_6_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 6, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_7_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 7, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_8_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 8, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_9_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 9, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_10_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 10, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_11_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 11, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_12_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 12, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_13_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 13, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_14_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 14, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_15_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 15, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_16_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 16, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_17_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 17, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_18_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 18, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_19_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 19, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_20_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 20, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_21_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 21, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_22_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 22, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_23_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 23, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_24_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 24, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_25_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 25, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_26_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 26, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_27_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 27, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_28_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 28, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_29_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 29, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_30_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 30, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_31_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 31, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_32_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 32, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_33_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 33, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_34_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 34, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_35_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 35, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_36_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 36, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_37_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 37, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_38_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 38, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_39_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 39, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_40_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 40, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_41_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 41, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_42_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 42, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_43_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 43, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_44_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 44, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_45_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 45, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_46_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 46, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_47_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 47, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_48_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 48, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_49_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 49, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_50_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 50, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_51_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 51, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_52_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 52, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_53_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 53, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_54_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 54, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_55_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 55, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_56_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 56, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_57_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 57, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_58_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 58, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_59_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 59, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_60_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 60, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_61_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 61, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_62_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 62, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_63_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 63, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_64_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 64, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_65_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 65, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_66_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 66, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_67_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 67, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_68_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 68, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_69_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 69, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_70_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 70, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_71_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 71, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_72_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 72, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_73_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 73, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_74_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 74, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_75_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 75, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_76_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 76, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_77_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 77, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_78_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 78, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_79_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 79, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_80_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 80, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_81_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 81, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_82_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 82, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_83_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 83, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_84_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 84, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_85_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 85, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_86_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 86, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_87_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 87, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_88_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 88, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_89_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 89, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_90_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 90, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_91_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 91, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_92_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 92, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_93_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 93, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_94_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 94, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_95_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 95, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_96_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 96, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_97_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 97, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_98_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 98, buf);
}

static ssize_t
ssdfs_segbmap_frag_bitmap_section_99_show(struct ssdfs_segbmap_frag_attr *attr,
				    struct ssdfs_segbmap_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_segbmap_frag_bitmap_section_show(fdesc, 99, buf);
}

SSDFS_SEGBMAP_FRAG_RO_ATTR(id);
SSDFS_SEGBMAP_FRAG_RO_ATTR(state);
SSDFS_SEGBMAP_FRAG_RO_ATTR(total_segs);
SSDFS_SEGBMAP_FRAG_RO_ATTR(clean_or_using_segs);
SSDFS_SEGBMAP_FRAG_RO_ATTR(used_or_dirty_segs);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bad_segs);
SSDFS_SEGBMAP_FRAG_RO_ATTR(sections_count);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_0);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_1);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_2);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_3);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_4);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_5);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_6);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_7);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_8);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_9);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_10);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_11);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_12);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_13);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_14);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_15);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_16);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_17);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_18);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_19);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_20);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_21);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_22);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_23);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_24);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_25);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_26);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_27);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_28);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_29);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_30);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_31);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_32);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_33);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_34);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_35);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_36);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_37);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_38);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_39);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_40);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_41);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_42);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_43);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_44);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_45);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_46);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_47);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_48);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_49);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_50);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_51);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_52);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_53);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_54);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_55);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_56);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_57);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_58);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_59);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_60);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_61);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_62);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_63);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_64);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_65);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_66);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_67);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_68);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_69);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_70);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_71);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_72);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_73);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_74);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_75);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_76);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_77);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_78);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_79);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_80);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_81);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_82);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_83);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_84);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_85);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_86);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_87);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_88);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_89);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_90);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_91);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_92);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_93);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_94);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_95);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_96);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_97);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_98);
SSDFS_SEGBMAP_FRAG_RO_ATTR(bitmap_section_99);

static struct attribute *ssdfs_segbmap_frag_attrs[] = {
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(id),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(state),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(total_segs),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(clean_or_using_segs),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(used_or_dirty_segs),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bad_segs),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(sections_count),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_0),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_1),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_2),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_3),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_4),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_5),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_6),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_7),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_8),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_9),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_10),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_11),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_12),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_13),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_14),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_15),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_16),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_17),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_18),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_19),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_20),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_21),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_22),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_23),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_24),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_25),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_26),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_27),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_28),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_29),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_30),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_31),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_32),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_33),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_34),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_35),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_36),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_37),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_38),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_39),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_40),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_41),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_42),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_43),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_44),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_45),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_46),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_47),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_48),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_49),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_50),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_51),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_52),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_53),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_54),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_55),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_56),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_57),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_58),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_59),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_60),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_61),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_62),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_63),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_64),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_65),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_66),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_67),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_68),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_69),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_70),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_71),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_72),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_73),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_74),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_75),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_76),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_77),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_78),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_79),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_80),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_81),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_82),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_83),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_84),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_85),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_86),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_87),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_88),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_89),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_90),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_91),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_92),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_93),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_94),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_95),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_96),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_97),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_98),
	SSDFS_SEGBMAP_FRAG_ATTR_LIST(bitmap_section_99),
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_segbmap_frag);

static ssize_t ssdfs_segbmap_frag_attr_show(struct kobject *kobj,
					     struct attribute *attr, char *buf)
{
	struct ssdfs_segbmap_fragment_desc *fdesc = container_of(kobj,
					struct ssdfs_segbmap_fragment_desc,
					frag_kobj);
	struct ssdfs_segbmap_frag_attr *a = container_of(attr,
					struct ssdfs_segbmap_frag_attr,
					attr);

	return a->show ? a->show(a, fdesc, buf) : 0;
}

static ssize_t ssdfs_segbmap_frag_attr_store(struct kobject *kobj,
					      struct attribute *attr,
					      const char *buf, size_t len)
{
	struct ssdfs_segbmap_fragment_desc *fdesc = container_of(kobj,
					struct ssdfs_segbmap_fragment_desc,
					frag_kobj);
	struct ssdfs_segbmap_frag_attr *a = container_of(attr,
					struct ssdfs_segbmap_frag_attr,
					attr);

	return a->store ? a->store(a, fdesc, buf, len) : 0;
}

static void ssdfs_segbmap_frag_attr_release(struct kobject *kobj)
{
	struct ssdfs_segbmap_fragment_desc *fdesc = container_of(kobj,
					struct ssdfs_segbmap_fragment_desc,
					frag_kobj);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release segbmap fragment %u group\n",
		  fdesc->fragment_id);
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&fdesc->frag_kobj_unregister);
}

static const struct sysfs_ops ssdfs_segbmap_frag_attr_ops = {
	.show	= ssdfs_segbmap_frag_attr_show,
	.store	= ssdfs_segbmap_frag_attr_store,
};

static const struct kobj_type ssdfs_segbmap_frag_ktype = {
	.default_groups	= ssdfs_segbmap_frag_groups,
	.sysfs_ops	= &ssdfs_segbmap_frag_attr_ops,
	.release	= ssdfs_segbmap_frag_attr_release,
};

static inline int
ssdfs_sysfs_create_segbmap_frag_group(struct ssdfs_segbmap_fragment_desc *fdesc,
				      struct kobject *parent_kobj)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create segbmap fragment %u group\n", fdesc->fragment_id);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc->frag_kobj.kset = ssdfs_kset;
	init_completion(&fdesc->frag_kobj_unregister);
	err = kobject_init_and_add(&fdesc->frag_kobj,
				   &ssdfs_segbmap_frag_ktype,
				   parent_kobj,
				   "fragment%u",
				   fdesc->fragment_id);

	return err;
}

static inline void
ssdfs_sysfs_delete_segbmap_frag_group(struct ssdfs_segbmap_fragment_desc *fdesc)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete segbmap fragment %u group\n", fdesc->fragment_id);
#endif /* CONFIG_SSDFS_DEBUG */

	kobject_del(&fdesc->frag_kobj);
	kobject_put(&fdesc->frag_kobj);
	wait_for_completion(&fdesc->frag_kobj_unregister);
}

static int ssdfs_sysfs_create_segbmap_fragments(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_segment_bmap *segbmap = fsi->segbmap;
	struct ssdfs_segbmap_fragment_desc *fdesc;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create segbmap fragment sysfs entries\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (!segbmap) {
		SSDFS_ERR("segment bitmap is NULL\n");
		return -ERANGE;
	}

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);

	for (i = 0; i < segbmap->fragments_count; i++) {
		fdesc = &segbmap->desc_array[i];
		err = ssdfs_sysfs_create_segbmap_frag_group(fdesc,
						    &fsi->segbmap_frags_kobj);
		if (err) {
			SSDFS_ERR("fail to create segbmap fragment %d group: "
				  "err %d\n", i, err);
			goto cleanup_created_groups;
		}
	}

	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segbmap fragment sysfs entries have been created\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

cleanup_created_groups:
	for (--i; i >= 0; i--) {
		fdesc = &segbmap->desc_array[i];
		ssdfs_sysfs_delete_segbmap_frag_group(fdesc);
	}

	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);
	return err;
}

static void ssdfs_sysfs_delete_segbmap_fragments(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_segment_bmap *segbmap = fsi->segbmap;
	struct ssdfs_segbmap_fragment_desc *fdesc;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete segbmap fragment sysfs entries\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (!segbmap) {
		SSDFS_ERR("segment bitmap is NULL\n");
		return;
	}

	down_read(&segbmap->resize_lock);
	down_read(&segbmap->search_lock);

	for (i = 0; i < segbmap->fragments_count; i++) {;
		fdesc = &segbmap->desc_array[i];
		ssdfs_sysfs_delete_segbmap_frag_group(fdesc);
	}

	up_read(&segbmap->search_lock);
	up_read(&segbmap->resize_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segbmap fragment sysfs entries have been deleted\n");
#endif /* CONFIG_SSDFS_DEBUG */
}

/************************************************************************
 *                      SSDFS segbmap fragments attrs                  *
 ************************************************************************/

static struct attribute *ssdfs_segbmap_frags_attrs[] = {
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_segbmap_frags);

static ssize_t ssdfs_segbmap_frags_attr_show(struct kobject *kobj,
					      struct attribute *attr, char *buf)
{
	struct ssdfs_fs_info *fsi = container_of(kobj->parent,
						 struct ssdfs_fs_info,
						 segbmap_frags_kobj);
	struct ssdfs_segbmap_frags_attr *a = container_of(attr,
						struct ssdfs_segbmap_frags_attr,
						attr);

	return a->show ? a->show(a, fsi, buf) : 0;
}

static ssize_t ssdfs_segbmap_frags_attr_store(struct kobject *kobj,
					       struct attribute *attr,
					       const char *buf, size_t len)
{
	struct ssdfs_fs_info *fsi = container_of(kobj->parent,
						 struct ssdfs_fs_info,
						 segbmap_frags_kobj);
	struct ssdfs_segbmap_frags_attr *a = container_of(attr,
						struct ssdfs_segbmap_frags_attr,
						attr);

	return a->store ? a->store(a, fsi, buf, len) : 0;
}

static void ssdfs_segbmap_frags_attr_release(struct kobject *kobj)
{
	struct ssdfs_fs_info *fsi = container_of(kobj,
						 struct ssdfs_fs_info,
						 segbmap_frags_kobj);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release segbmap fragments group\n");
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&fsi->segbmap_frags_kobj_unregister);
}

static const struct sysfs_ops ssdfs_segbmap_frags_attr_ops = {
	.show	= ssdfs_segbmap_frags_attr_show,
	.store	= ssdfs_segbmap_frags_attr_store,
};

static struct kobj_type ssdfs_segbmap_frags_ktype = {
	.default_groups = ssdfs_segbmap_frags_groups,
	.sysfs_ops	= &ssdfs_segbmap_frags_attr_ops,
	.release	= ssdfs_segbmap_frags_attr_release,
};

static int ssdfs_sysfs_create_segbmap_frags_group(struct ssdfs_fs_info *fsi)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create segbmap fragments group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->segbmap_frags_kobj.kset = ssdfs_kset;
	init_completion(&fsi->segbmap_frags_kobj_unregister);
	err = kobject_init_and_add(&fsi->segbmap_frags_kobj,
				   &ssdfs_segbmap_frags_ktype,
				   &fsi->segbmap_kobj, "fragments");
	if (err)
		return err;

	return 0;
}

static void ssdfs_sysfs_delete_segbmap_frags_group(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete segbmap fragments group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	kobject_del(&fsi->segbmap_frags_kobj);
	kobject_put(&fsi->segbmap_frags_kobj);
	wait_for_completion(&fsi->segbmap_frags_kobj_unregister);
}

/************************************************************************
 *                        SSDFS segbmap attrs                           *
 ************************************************************************/

static ssize_t ssdfs_segbmap_flags_show(struct ssdfs_segbmap_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	struct ssdfs_segment_bmap *bmap = fsi->segbmap;
	u16 flags;

	if (!bmap) {
		SSDFS_WARN("segbmap is absent\n");
		return 0;
	}

	down_read(&bmap->resize_lock);
	flags = bmap->flags;
	up_read(&bmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%#x\n", flags);
}

static ssize_t ssdfs_segbmap_bytes_count_show(struct ssdfs_segbmap_attr *attr,
						struct ssdfs_fs_info *fsi,
						char *buf)
{
	struct ssdfs_segment_bmap *bmap = fsi->segbmap;
	u32 bytes_count;

	if (!bmap) {
		SSDFS_WARN("segbmap is absent\n");
		return 0;
	}

	down_read(&bmap->resize_lock);
	bytes_count = bmap->bytes_count;
	up_read(&bmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", bytes_count);
}

static ssize_t ssdfs_segbmap_items_count_show(struct ssdfs_segbmap_attr *attr,
						struct ssdfs_fs_info *fsi,
						char *buf)
{
	struct ssdfs_segment_bmap *bmap = fsi->segbmap;
	u64 items_count;

	if (!bmap) {
		SSDFS_WARN("segbmap is absent\n");
		return 0;
	}

	down_read(&bmap->resize_lock);
	items_count = bmap->items_count;
	up_read(&bmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", items_count);
}

static
ssize_t ssdfs_segbmap_fragments_count_show(struct ssdfs_segbmap_attr *attr,
					    struct ssdfs_fs_info *fsi,
					    char *buf)
{
	struct ssdfs_segment_bmap *bmap = fsi->segbmap;
	u16 fragments_count;

	if (!bmap) {
		SSDFS_WARN("segbmap is absent\n");
		return 0;
	}

	down_read(&bmap->resize_lock);
	fragments_count = bmap->fragments_count;
	up_read(&bmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragments_count);
}

static
ssize_t ssdfs_segbmap_fragments_per_seg_show(struct ssdfs_segbmap_attr *attr,
					     struct ssdfs_fs_info *fsi,
					     char *buf)
{
	struct ssdfs_segment_bmap *bmap = fsi->segbmap;
	u16 fragments_per_seg;

	if (!bmap) {
		SSDFS_WARN("segbmap is absent\n");
		return 0;
	}

	down_read(&bmap->resize_lock);
	fragments_per_seg = bmap->fragments_per_seg;
	up_read(&bmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragments_per_seg);
}

static
ssize_t ssdfs_segbmap_fragments_per_peb_show(struct ssdfs_segbmap_attr *attr,
					     struct ssdfs_fs_info *fsi,
					     char *buf)
{
	struct ssdfs_segment_bmap *bmap = fsi->segbmap;
	u16 fragments_per_peb;

	if (!bmap) {
		SSDFS_WARN("segbmap is absent\n");
		return 0;
	}

	down_read(&bmap->resize_lock);
	fragments_per_peb = bmap->fragments_per_peb;
	up_read(&bmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragments_per_peb);
}

static
ssize_t ssdfs_segbmap_fragment_size_show(struct ssdfs_segbmap_attr *attr,
					 struct ssdfs_fs_info *fsi,
					 char *buf)
{
	struct ssdfs_segment_bmap *bmap = fsi->segbmap;
	u16 fragment_size;

	if (!bmap) {
		SSDFS_WARN("segbmap is absent\n");
		return 0;
	}

	down_read(&bmap->resize_lock);
	fragment_size = bmap->fragment_size;
	up_read(&bmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragment_size);
}

static
ssize_t ssdfs_segbmap_segs_count_show(struct ssdfs_segbmap_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	struct ssdfs_segment_bmap *bmap = fsi->segbmap;
	u16 segs_count;

	if (!bmap) {
		SSDFS_WARN("segbmap is absent\n");
		return 0;
	}

	down_read(&bmap->resize_lock);
	segs_count = bmap->segs_count;
	up_read(&bmap->resize_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", segs_count);
}

static
ssize_t ssdfs_segbmap_seg_numbers_show(struct ssdfs_segbmap_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	struct ssdfs_segment_bmap *bmap = fsi->segbmap;
	u64 seg_numbers[SSDFS_SEGBMAP_SEGS][SSDFS_SEGBMAP_SEG_COPY_MAX];
	size_t array_size;
	int count = 0;
	int i, j;

	if (!bmap) {
		SSDFS_WARN("segbmap is absent\n");
		return 0;
	}

	array_size = sizeof(u64);
	array_size *= SSDFS_SEGBMAP_SEGS;
	array_size *= SSDFS_SEGBMAP_SEG_COPY_MAX;

	down_read(&bmap->resize_lock);
	memcpy(seg_numbers, bmap->seg_numbers, array_size);
	up_read(&bmap->resize_lock);

	for (i = 0; i < SSDFS_SEGBMAP_SEGS; i++) {
		for (j = 0; j < SSDFS_SEGBMAP_SEG_COPY_MAX; j++) {
			if (seg_numbers[i][j] == U64_MAX) {
				count += snprintf(buf + count,
						  PAGE_SIZE - count,
						  "seg[%d][%d] = U64_MAX\n",
						  i, j);
			} else {
				count += snprintf(buf + count,
						  PAGE_SIZE - count,
						  "seg[%d][%d] = %llu\n",
						  i, j,
						  seg_numbers[i][j]);
			}
		}
	}

	return count;
}

SSDFS_SEGBMAP_RO_ATTR(flags);
SSDFS_SEGBMAP_RO_ATTR(bytes_count);
SSDFS_SEGBMAP_RO_ATTR(items_count);
SSDFS_SEGBMAP_RO_ATTR(fragments_count);
SSDFS_SEGBMAP_RO_ATTR(fragments_per_seg);
SSDFS_SEGBMAP_RO_ATTR(fragments_per_peb);
SSDFS_SEGBMAP_RO_ATTR(fragment_size);
SSDFS_SEGBMAP_RO_ATTR(segs_count);
SSDFS_SEGBMAP_RO_ATTR(seg_numbers);

static struct attribute *ssdfs_segbmap_attrs[] = {
	SSDFS_SEGBMAP_ATTR_LIST(flags),
	SSDFS_SEGBMAP_ATTR_LIST(bytes_count),
	SSDFS_SEGBMAP_ATTR_LIST(items_count),
	SSDFS_SEGBMAP_ATTR_LIST(fragments_count),
	SSDFS_SEGBMAP_ATTR_LIST(fragments_per_seg),
	SSDFS_SEGBMAP_ATTR_LIST(fragments_per_peb),
	SSDFS_SEGBMAP_ATTR_LIST(fragment_size),
	SSDFS_SEGBMAP_ATTR_LIST(segs_count),
	SSDFS_SEGBMAP_ATTR_LIST(seg_numbers),
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_segbmap);

static ssize_t ssdfs_segbmap_attr_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 segbmap_kobj);
	struct ssdfs_segbmap_attr *a = container_of(attr,
						struct ssdfs_segbmap_attr,
						attr);
	return a->show ? a->show(a, fsi, buf) : 0;
}

static ssize_t ssdfs_segbmap_attr_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buf, size_t len)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 segbmap_kobj);
	struct ssdfs_segbmap_attr *a = container_of(attr,
						struct ssdfs_segbmap_attr,
						attr);
	return a->store ? a->store(a, fsi, buf, len) : 0;
}

static void ssdfs_segbmap_attr_release(struct kobject *kobj)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 segbmap_kobj);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release segbmap group\n");
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&fsi->segbmap_kobj_unregister);
}

static const struct sysfs_ops ssdfs_segbmap_attr_ops = {
	.show	= ssdfs_segbmap_attr_show,
	.store	= ssdfs_segbmap_attr_store,
};

static struct kobj_type ssdfs_segbmap_ktype = {
	.default_groups = ssdfs_segbmap_groups,
	.sysfs_ops	= &ssdfs_segbmap_attr_ops,
	.release	= ssdfs_segbmap_attr_release,
};

int ssdfs_sysfs_create_segbmap_group(struct ssdfs_fs_info *fsi)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create segbmap group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->segbmap_kobj.kset = ssdfs_kset;
	init_completion(&fsi->segbmap_kobj_unregister);
	err = kobject_init_and_add(&fsi->segbmap_kobj, &ssdfs_segbmap_ktype,
				   &fsi->dev_kobj, "segbmap");
	if (err)
		return err;

	err = ssdfs_sysfs_create_segbmap_frags_group(fsi);
	if (err)
		goto cleanup_segbmap_kobject;

	err = ssdfs_sysfs_create_segbmap_fragments(fsi);
	if (err)
		goto cleanup_segbmap_frags_group;

	return 0;

cleanup_segbmap_frags_group:
	ssdfs_sysfs_delete_segbmap_frags_group(fsi);

cleanup_segbmap_kobject:
	kobject_del(&fsi->segbmap_kobj);
	kobject_put(&fsi->segbmap_kobj);
	wait_for_completion(&fsi->segbmap_kobj_unregister);
	return err;
}

void ssdfs_sysfs_delete_segbmap_group(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete segbmap group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_sysfs_delete_segbmap_fragments(fsi);
	ssdfs_sysfs_delete_segbmap_frags_group(fsi);
	kobject_del(&fsi->segbmap_kobj);
	kobject_put(&fsi->segbmap_kobj);
	wait_for_completion(&fsi->segbmap_kobj_unregister);
}

/************************************************************************
 *                       SSDFS maptbl fragment attrs                   *
 ************************************************************************/

static ssize_t ssdfs_maptbl_frag_id_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	u32 fragment_id;

	down_read(&fdesc->lock);
	fragment_id = fdesc->fragment_id;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragment_id);
}

static ssize_t ssdfs_maptbl_frag_state_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	int state = atomic_read(&fdesc->state);

	switch (state) {
	case SSDFS_MAPTBL_FRAG_CREATED:
		return snprintf(buf, PAGE_SIZE, "CREATED\n");
	case SSDFS_MAPTBL_FRAG_INIT_FAILED:
		return snprintf(buf, PAGE_SIZE, "INIT_FAILED\n");
	case SSDFS_MAPTBL_FRAG_INITIALIZED:
		return snprintf(buf, PAGE_SIZE, "INITIALIZED\n");
	case SSDFS_MAPTBL_FRAG_DIRTY:
		return snprintf(buf, PAGE_SIZE, "DIRTY\n");
	case SSDFS_MAPTBL_FRAG_TOWRITE:
		return snprintf(buf, PAGE_SIZE, "TOWRITE\n");
	default:
		return snprintf(buf, PAGE_SIZE, "UNKNOWN(%d)\n", state);
	}
}

static ssize_t
ssdfs_maptbl_frag_start_leb_show(struct ssdfs_maptbl_frag_attr *attr,
				 struct ssdfs_maptbl_fragment_desc *fdesc,
				 char *buf)
{
	u64 start_leb;

	down_read(&fdesc->lock);
	start_leb = fdesc->start_leb;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", start_leb);
}

static ssize_t
ssdfs_maptbl_frag_lebs_count_show(struct ssdfs_maptbl_frag_attr *attr,
				  struct ssdfs_maptbl_fragment_desc *fdesc,
				  char *buf)
{
	u32 lebs_count;

	down_read(&fdesc->lock);
	lebs_count = fdesc->lebs_count;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", lebs_count);
}

static ssize_t
ssdfs_maptbl_frag_mapped_lebs_show(struct ssdfs_maptbl_frag_attr *attr,
				   struct ssdfs_maptbl_fragment_desc *fdesc,
				   char *buf)
{
	u32 mapped_lebs;

	down_read(&fdesc->lock);
	mapped_lebs = fdesc->mapped_lebs;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", mapped_lebs);
}

static ssize_t
ssdfs_maptbl_frag_migrating_lebs_show(struct ssdfs_maptbl_frag_attr *attr,
				      struct ssdfs_maptbl_fragment_desc *fdesc,
				      char *buf)
{
	u32 migrating_lebs;

	down_read(&fdesc->lock);
	migrating_lebs = fdesc->migrating_lebs;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", migrating_lebs);
}

static ssize_t
ssdfs_maptbl_frag_reserved_pebs_show(struct ssdfs_maptbl_frag_attr *attr,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     char *buf)
{
	u32 reserved_pebs;

	down_read(&fdesc->lock);
	reserved_pebs = fdesc->reserved_pebs;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", reserved_pebs);
}

static ssize_t
ssdfs_maptbl_frag_pre_erase_pebs_show(struct ssdfs_maptbl_frag_attr *attr,
				      struct ssdfs_maptbl_fragment_desc *fdesc,
				      char *buf)
{
	u32 pre_erase_pebs;

	down_read(&fdesc->lock);
	pre_erase_pebs = fdesc->pre_erase_pebs;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", pre_erase_pebs);
}

static ssize_t
ssdfs_maptbl_frag_recovering_pebs_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	u32 recovering_pebs;

	down_read(&fdesc->lock);
	recovering_pebs = fdesc->recovering_pebs;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", recovering_pebs);
}

static ssize_t
ssdfs_maptbl_frag_fragment_folios_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	u32 fragment_folios;

	down_read(&fdesc->lock);
	fragment_folios = fdesc->fragment_folios;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragment_folios);
}

static ssize_t
ssdfs_maptbl_frag_lebs_per_page_show(struct ssdfs_maptbl_frag_attr *attr,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     char *buf)
{
	u16 lebs_per_page;

	down_read(&fdesc->lock);
	lebs_per_page = fdesc->lebs_per_page;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", lebs_per_page);
}

static ssize_t
ssdfs_maptbl_frag_lebtbl_pages_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	u16 lebtbl_pages;

	down_read(&fdesc->lock);
	lebtbl_pages = fdesc->lebtbl_pages;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", lebtbl_pages);
}

static ssize_t
ssdfs_maptbl_frag_pebs_per_page_show(struct ssdfs_maptbl_frag_attr *attr,
				     struct ssdfs_maptbl_fragment_desc *fdesc,
				     char *buf)
{
	u16 pebs_per_page;

	down_read(&fdesc->lock);
	pebs_per_page = fdesc->pebs_per_page;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", pebs_per_page);
}

static ssize_t
ssdfs_maptbl_frag_stripe_pages_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	u16 stripe_pages;

	down_read(&fdesc->lock);
	stripe_pages = fdesc->stripe_pages;
	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", stripe_pages);
}

#define SSDFS_MAPTBL_OUTPUT_THRESHOLD1		(PAGE_SIZE - 300)
#define SSDFS_MAPTBL_OUTPUT_THRESHOLD2		(PAGE_SIZE - 200)
#define SSDFS_MAPTBL_OUTPUT_THRESHOLD3		(PAGE_SIZE - 100)
#define SSDFS_MAPTBL_OUTPUT_THRESHOLD4		(PAGE_SIZE - 150)

static ssize_t
ssdfs_maptbl_frag_leb_table_show(struct ssdfs_maptbl_frag_attr *attr,
				 struct ssdfs_maptbl_fragment_desc *fdesc,
				 char *buf)
{
	struct folio *folio;
	void *kaddr;
	struct ssdfs_leb_table_fragment_header *hdr;
	struct ssdfs_leb_descriptor *leb_desc;
	u64 start_leb, lebs_count;
	pgoff_t folio_index;
	int count = 0;
#define SSDFS_LEBTBL_PAGES_MAX		(3)
	u32 lebtbl_pages_max = SSDFS_LEBTBL_PAGES_MAX;
#define SSDFS_LEBS_COUNT_MAX		(8)
	u32 lebs_count_max = SSDFS_LEBS_COUNT_MAX;
	int i, j;
	int err = 0;

	down_read(&fdesc->lock);

	if (atomic_read(&fdesc->state) < SSDFS_MAPTBL_FRAG_INITIALIZED) {
		count = snprintf(buf + count, PAGE_SIZE - count,
				"Fragment not initialized (state: %d)\n",
				atomic_read(&fdesc->state));
		goto finish_show_leb_table;
	}

	start_leb = fdesc->start_leb;
	lebs_count = fdesc->lebs_count;

	if (lebs_count >= U32_MAX) {
		count = snprintf(buf + count, PAGE_SIZE - count,
				 "LEB table not available\n");
		goto finish_show_leb_table;
	}

	count += snprintf(buf + count, PAGE_SIZE - count,
			  "LEB Table (start_leb: %llu, count: %u):\n",
			  start_leb, fdesc->lebs_count);

	/* Show LEB table entries from the first few folios */
	lebtbl_pages_max = min_t(u32, fdesc->lebtbl_pages,
				 SSDFS_LEBTBL_PAGES_MAX);
	for (i = 0; i < lebtbl_pages_max; i++) {
		if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD2) {
			count += snprintf(buf + count, PAGE_SIZE - count,
					  "  ... (output truncated)\n");
			break;
		}

		folio_index = i;
		folio = ssdfs_folio_array_get_folio_locked(&fdesc->array,
							   folio_index);
		if (IS_ERR_OR_NULL(folio)) {
			err = (folio == NULL ? -ENOENT : PTR_ERR(folio));
			if (err == -ENOENT) {
				count += snprintf(buf + count, PAGE_SIZE - count,
						  "  folio %d: <not allocated>\n", i);
				continue;
			} else {
				count += snprintf(buf + count, PAGE_SIZE - count,
						  "  folio %d: <error %d>\n", i, err);
				continue;
			}
		}

		kaddr = kmap_local_folio(folio, 0);
		hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;

		/* Show header info for first folio */
		if (i == 0) {
			/* Verify header magic */
			if (le32_to_cpu(hdr->magic) != SSDFS_LEB_TABLE_MAGIC) {
				count += snprintf(buf + count, PAGE_SIZE - count,
						  "  Header: INVALID MAGIC (0x%x != 0x%x)\n",
						  le32_to_cpu(hdr->magic),
						  SSDFS_LEB_TABLE_MAGIC);
				goto finish_folio_processing;
			}
			count += snprintf(buf + count, PAGE_SIZE - count,
					  "  Header: magic=0x%x, start_leb=%llu, lebs_count=%u\n",
					  le32_to_cpu(hdr->magic),
					  le64_to_cpu(hdr->start_leb),
					  le16_to_cpu(hdr->lebs_count));
		}

		/* Show first few LEB descriptors from this folio */
		leb_desc = (struct ssdfs_leb_descriptor *)((u8 *)kaddr +
			    sizeof(struct ssdfs_leb_table_fragment_header));
		lebs_count_max = min_t(u32, le16_to_cpu(hdr->lebs_count),
					SSDFS_LEBS_COUNT_MAX);
		for (j = 0; j < lebs_count_max; j++) {
			if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD3) {
				count += snprintf(buf + count, PAGE_SIZE - count,
						  "  ... (truncated)\n");
				goto finish_folio_processing;
			}
			
			count += snprintf(buf + count, PAGE_SIZE - count,
					  "  LEB %llu -> PEB_IDX[%u,%u]\n",
					  start_leb + (i * fdesc->lebs_per_page) + j,
					  le16_to_cpu(leb_desc[j].physical_index),
					  le16_to_cpu(leb_desc[j].relation_index));
		}

finish_folio_processing:
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

		if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD3)
			break;
	}

	if (fdesc->lebtbl_pages > SSDFS_LEBTBL_PAGES_MAX) {
		count += snprintf(buf + count, PAGE_SIZE - count,
				  "  ... (%u more folios)\n",
				  fdesc->lebtbl_pages - SSDFS_LEBTBL_PAGES_MAX);
	}

finish_show_leb_table:
	up_read(&fdesc->lock);
	return count;
}

static ssize_t
ssdfs_maptbl_frag_peb_table_show(struct ssdfs_maptbl_frag_attr *attr,
				 struct ssdfs_maptbl_fragment_desc *fdesc,
				 char *buf)
{
	struct folio *folio;
	void *kaddr;
	struct ssdfs_peb_table_fragment_header *hdr;
	struct ssdfs_peb_descriptor *peb_desc;
	pgoff_t folio_index;
	int count = 0;
#define SSDFS_PEBTBL_PAGES_MAX		(2)
	u32 frag_pages_max = SSDFS_PEBTBL_PAGES_MAX;
#define SSDFS_PEBS_COUNT_MAX		(4)
	u32 pebs_count_max = SSDFS_PEBS_COUNT_MAX;
	u64 start_peb = U64_MAX;
	int i, j;
	int err = 0;

	down_read(&fdesc->lock);

	if (atomic_read(&fdesc->state) < SSDFS_MAPTBL_FRAG_INITIALIZED) {
		count = snprintf(buf + count, PAGE_SIZE - count,
				"Fragment not initialized (state: %d)\n",
				atomic_read(&fdesc->state));
		goto finish_show_peb_table;
	}

	count += snprintf(buf + count, PAGE_SIZE - count,
			  "PEB Table:\n");

	/* Show PEB table entries from first few folios after LEB table */
	frag_pages_max = min_t(u32,
				fdesc->lebtbl_pages + SSDFS_PEBTBL_PAGES_MAX,
				fdesc->fragment_folios);
	for (i = fdesc->lebtbl_pages; i < frag_pages_max; i++) {
		if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD1) {
			count += snprintf(buf + count, PAGE_SIZE - count,
					  "  ... (output truncated)\n");
			break;
		}

		folio_index = i;
		folio = ssdfs_folio_array_get_folio_locked(&fdesc->array,
							   folio_index);
		if (IS_ERR_OR_NULL(folio)) {
			err = (folio == NULL ? -ENOENT : PTR_ERR(folio));
			if (err == -ENOENT) {
				count += snprintf(buf + count, PAGE_SIZE - count,
						  "  folio %d: <not allocated>\n", i);
				continue;
			} else {
				count += snprintf(buf + count, PAGE_SIZE - count,
						  "  folio %d: <error %d>\n", i, err);
				continue;
			}
		}

		kaddr = kmap_local_folio(folio, 0);
		hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

		/* Show header info */
		if (i == fdesc->lebtbl_pages) {
			/* Verify header magic */
			if (le32_to_cpu(hdr->magic) != SSDFS_PEB_TABLE_MAGIC) {
				count += snprintf(buf + count, PAGE_SIZE - count,
						  "  Header: INVALID MAGIC (0x%x != 0x%x)\n",
						  le32_to_cpu(hdr->magic),
						  SSDFS_PEB_TABLE_MAGIC);
				goto finish_peb_folio_processing;
			}
			count += snprintf(buf + count, PAGE_SIZE - count,
					  "  Header: magic=0x%x, start_peb=%llu, pebs_count=%u\n",
					  le32_to_cpu(hdr->magic),
					  le64_to_cpu(hdr->start_peb),
					  le16_to_cpu(hdr->pebs_count));
		}

		start_peb = le64_to_cpu(hdr->start_peb);

		/* Show first few PEB descriptors from this folio */
		peb_desc = (struct ssdfs_peb_descriptor *)((u8 *)kaddr +
			    sizeof(struct ssdfs_peb_table_fragment_header));
		pebs_count_max = min_t(u32, le16_to_cpu(hdr->pebs_count),
					SSDFS_PEBS_COUNT_MAX);
		for (j = 0; j < pebs_count_max; j++) {
			if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD2) {
				count += snprintf(buf + count, PAGE_SIZE - count,
						  "  ... (truncated)\n");
				goto finish_peb_folio_processing;
			}

			count += snprintf(buf + count, PAGE_SIZE - count,
					  "  PEB[%d]: id=%llu, cycles=%u, type=%u, state=%u, flags=0x%x\n",
					  j,
					  start_peb + j,
					  le32_to_cpu(peb_desc[j].erase_cycles),
					  peb_desc[j].type,
					  peb_desc[j].state,
					  peb_desc[j].flags);
		}

finish_peb_folio_processing:
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

		if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD3)
			break;
	}

finish_show_peb_table:
	up_read(&fdesc->lock);
	return count;
}

static ssize_t
ssdfs_maptbl_frag_summary_show(struct ssdfs_maptbl_frag_attr *attr,
				struct ssdfs_maptbl_fragment_desc *fdesc,
				char *buf)
{
	int count = 0;

	down_read(&fdesc->lock);

	count += snprintf(buf + count, PAGE_SIZE - count,
			  "Fragment Summary:\n");
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  ID: %u\n", fdesc->fragment_id);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  State: %d\n", atomic_read(&fdesc->state));
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  LEB range: %llu - %llu (%u LEBs)\n",
			  fdesc->start_leb,
			  fdesc->start_leb + fdesc->lebs_count - 1,
			  fdesc->lebs_count);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  Mapped LEBs: %u\n", fdesc->mapped_lebs);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  Migrating LEBs: %u\n", fdesc->migrating_lebs);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  Reserved PEBs: %u\n", fdesc->reserved_pebs);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  Pre-erase PEBs: %u\n", fdesc->pre_erase_pebs);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  Recovering PEBs: %u\n", fdesc->recovering_pebs);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "  Memory layout:\n");
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "    Total folios: %u\n", fdesc->fragment_folios);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "    LEB table folios: %u\n", fdesc->lebtbl_pages);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "    LEBs per folio: %u\n", fdesc->lebs_per_page);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "    PEBs per folio: %u\n", fdesc->pebs_per_page);
	count += snprintf(buf + count, PAGE_SIZE - count,
			  "    Stripe folios: %u\n", fdesc->stripe_pages);

	up_read(&fdesc->lock);
	return count;
}

static ssize_t
ssdfs_maptbl_frag_leb_sections_count_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	u32 sections_count = 0;
	u32 entries_per_section;
	u32 total_entries;

	down_read(&fdesc->lock);

	if (atomic_read(&fdesc->state) < SSDFS_MAPTBL_FRAG_INITIALIZED) {
		up_read(&fdesc->lock);
		return snprintf(buf, PAGE_SIZE, "0\n");
	}

	if (fdesc->lebs_count == U32_MAX) {
		up_read(&fdesc->lock);
		return snprintf(buf, PAGE_SIZE, "0\n");
	}

	total_entries = fdesc->lebs_count;
	entries_per_section = SSDFS_MAPTBL_OUTPUT_THRESHOLD2 / 50;
	sections_count =
		(total_entries + entries_per_section - 1) / entries_per_section;

	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", sections_count);
}

static ssize_t
ssdfs_maptbl_frag_peb_sections_count_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	u32 sections_count = 0;
	u32 entries_per_section;
	u32 total_entries;

	down_read(&fdesc->lock);

	if (atomic_read(&fdesc->state) < SSDFS_MAPTBL_FRAG_INITIALIZED) {
		up_read(&fdesc->lock);
		return snprintf(buf, PAGE_SIZE, "0\n");
	}

	total_entries = fdesc->reserved_pebs +
				fdesc->pre_erase_pebs +
					fdesc->recovering_pebs;
	entries_per_section = SSDFS_MAPTBL_OUTPUT_THRESHOLD2 / 100;
	sections_count =
		(total_entries + entries_per_section - 1) / entries_per_section;

	up_read(&fdesc->lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", sections_count);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_show(struct ssdfs_maptbl_fragment_desc *fdesc,
					 int section_index, char *buf)
{
	struct folio *folio;
	void *kaddr;
	struct ssdfs_leb_table_fragment_header *hdr;
	struct ssdfs_leb_descriptor *leb_desc;
	u64 start_leb;
	u32 entries_per_section = SSDFS_MAPTBL_OUTPUT_THRESHOLD2 / 50;
	u32 section_start = section_index * entries_per_section;
	u32 section_end;
	pgoff_t folio_index;
	u32 folio_entry_start, folio_entry_count;
	int count = 0;
	int i, j;
	int err = 0;

	down_read(&fdesc->lock);

	if (atomic_read(&fdesc->state) < SSDFS_MAPTBL_FRAG_INITIALIZED) {
		count = snprintf(buf + count, PAGE_SIZE - count,
				"Fragment not initialized (state: %d)\n",
				atomic_read(&fdesc->state));
		goto finish_show_section;
	}

	if (fdesc->lebs_count >= U32_MAX) {
		count = snprintf(buf, PAGE_SIZE, "LEB table not available\n");
		goto finish_show_section;
	}

	start_leb = fdesc->start_leb;
	section_end = min_t(u32,
			    section_start + entries_per_section,
			    fdesc->lebs_count);

	if (section_start >= fdesc->lebs_count) {
		count = snprintf(buf + count, PAGE_SIZE - count,
				 "Section %d out of range\n", section_index);
		goto finish_show_section;
	}

	count += snprintf(buf + count, PAGE_SIZE - count,
			  "LEB Table Section %d (entries %u-%u):\n",
			  section_index, section_start, section_end - 1);

	for (i = 0; i < fdesc->lebtbl_pages; i++) {
		folio_entry_start = i * fdesc->lebs_per_page;
		folio_entry_count = min_t(u32, fdesc->lebs_per_page, 
					  fdesc->lebs_count - folio_entry_start);

		if (folio_entry_start >= section_end)
			break;

		if (folio_entry_start + folio_entry_count <= section_start)
			continue;

		folio_index = i;
		folio = ssdfs_folio_array_get_folio_locked(&fdesc->array,
							   folio_index);
		if (IS_ERR_OR_NULL(folio)) {
			err = (folio == NULL ? -ENOENT : PTR_ERR(folio));
			if (err == -ENOENT) {
				count += snprintf(buf + count,
						  PAGE_SIZE - count,
						  "  folio %d: <not allocated>\n",
						  i);
				continue;
			} else {
				count += snprintf(buf + count,
						  PAGE_SIZE - count,
						  "  folio %d: <error %d>\n",
						  i, err);
				continue;
			}
		}

		kaddr = kmap_local_folio(folio, 0);
		hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;

		if (le32_to_cpu(hdr->magic) != SSDFS_LEB_TABLE_MAGIC) {
			count += snprintf(buf + count, PAGE_SIZE - count,
					  "  Header: INVALID MAGIC (0x%x != 0x%x)\n",
					  le32_to_cpu(hdr->magic),
					  SSDFS_LEB_TABLE_MAGIC);
			goto finish_folio;
		}

		leb_desc = (struct ssdfs_leb_descriptor *)((u8 *)kaddr +
			    sizeof(struct ssdfs_leb_table_fragment_header));

		for (j = 0; j < folio_entry_count; j++) {
			u32 global_entry_index = folio_entry_start + j;
			
			if (global_entry_index < section_start)
				continue;
			if (global_entry_index >= section_end)
				break;

			if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD3) {
				count += snprintf(buf + count,
						  PAGE_SIZE - count,
						  "  ... (page full)\n");
				goto finish_folio;
			}
			
			count += snprintf(buf + count, PAGE_SIZE - count,
					  "  LEB %llu -> PEB_IDX[%u,%u]\n",
					  start_leb + global_entry_index,
					  le16_to_cpu(leb_desc[j].physical_index),
					  le16_to_cpu(leb_desc[j].relation_index));
		}

finish_folio:
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

		if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD3)
			break;
	}

finish_show_section:
	up_read(&fdesc->lock);
	return count;
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_show(struct ssdfs_maptbl_fragment_desc *fdesc,
					 int section_index, char *buf)
{
	struct folio *folio;
	void *kaddr;
	struct ssdfs_peb_table_fragment_header *hdr;
	struct ssdfs_peb_descriptor *peb_desc;
	u32 entries_per_section = (PAGE_SIZE - 200) / 100;
	u32 section_start = section_index * entries_per_section;
	u32 section_end;
	u32 total_pebs = 0;
	pgoff_t folio_index;
	u32 folio_entry_count;
	u32 current_entry = 0;
	int count = 0;
	u64 start_peb = U64_MAX;
	int i, j;
	int err = 0;

	down_read(&fdesc->lock);

	if (atomic_read(&fdesc->state) < SSDFS_MAPTBL_FRAG_INITIALIZED) {
		count = snprintf(buf + count, PAGE_SIZE - count,
				"Fragment not initialized (state: %d)\n",
				atomic_read(&fdesc->state));
		goto finish_show_peb_section;
	}

	total_pebs = fdesc->reserved_pebs +
				fdesc->pre_erase_pebs +
						fdesc->recovering_pebs;
	section_end = min_t(u32,
			    section_start + entries_per_section,
			    total_pebs);

	if (section_start >= total_pebs) {
		count = snprintf(buf + count, PAGE_SIZE - count,
				 "Section %d out of range\n", section_index);
		goto finish_show_peb_section;
	}

	count += snprintf(buf + count, PAGE_SIZE - count,
			  "PEB Table Section %d (entries %u-%u):\n",
			  section_index, section_start, section_end - 1);

	for (i = fdesc->lebtbl_pages; i < fdesc->fragment_folios; i++) {
		if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD1)
			break;

		folio_index = i;
		folio = ssdfs_folio_array_get_folio_locked(&fdesc->array,
							   folio_index);
		if (IS_ERR_OR_NULL(folio)) {
			err = (folio == NULL ? -ENOENT : PTR_ERR(folio));
			if (err == -ENOENT) {
				count += snprintf(buf + count,
						  PAGE_SIZE - count,
						  "  folio %d: <not allocated>\n",
						  i);
				continue;
			} else {
				count += snprintf(buf + count,
						  PAGE_SIZE - count,
						  "  folio %d: <error %d>\n",
						  i, err);
				continue;
			}
		}

		kaddr = kmap_local_folio(folio, 0);
		hdr = (struct ssdfs_peb_table_fragment_header *)kaddr;

		if (le32_to_cpu(hdr->magic) != SSDFS_PEB_TABLE_MAGIC) {
			count += snprintf(buf + count, PAGE_SIZE - count,
					  "  Header: INVALID MAGIC (0x%x != 0x%x)\n",
					  le32_to_cpu(hdr->magic),
					  SSDFS_PEB_TABLE_MAGIC);
			goto finish_peb_folio;
		}

		start_peb = le64_to_cpu(hdr->start_peb);

		peb_desc = (struct ssdfs_peb_descriptor *)((u8 *)kaddr +
			    sizeof(struct ssdfs_peb_table_fragment_header));

		folio_entry_count = min_t(u32, fdesc->pebs_per_page,
					  le16_to_cpu(hdr->pebs_count));

		for (j = 0; j < folio_entry_count; j++) {
			if (current_entry < section_start) {
				current_entry++;
				continue;
			}
			if (current_entry >= section_end)
				goto finish_peb_folio;

			if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD4) {
				count += snprintf(buf + count, PAGE_SIZE - count,
						  "  ... (page full)\n");
				goto finish_peb_folio;
			}

			count += snprintf(buf + count, PAGE_SIZE - count,
					  "  PEB %u: ID=%llu, erase_cycles=%u, type=%u, state=%u, flags=0x%x\n",
					  current_entry,
					  start_peb + j,
					  le32_to_cpu(peb_desc[j].erase_cycles),
					  peb_desc[j].type,
					  peb_desc[j].state,
					  le16_to_cpu(peb_desc[j].flags));
			current_entry++;
		}

finish_peb_folio:
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

		if (count >= SSDFS_MAPTBL_OUTPUT_THRESHOLD3 ||
		    current_entry >= section_end)
			break;
	}

finish_show_peb_section:
	up_read(&fdesc->lock);
	return count;
}

SSDFS_MAPTBL_FRAG_RO_ATTR(id);
SSDFS_MAPTBL_FRAG_RO_ATTR(state);
SSDFS_MAPTBL_FRAG_RO_ATTR(start_leb);
SSDFS_MAPTBL_FRAG_RO_ATTR(lebs_count);
SSDFS_MAPTBL_FRAG_RO_ATTR(mapped_lebs);
SSDFS_MAPTBL_FRAG_RO_ATTR(migrating_lebs);
SSDFS_MAPTBL_FRAG_RO_ATTR(reserved_pebs);
SSDFS_MAPTBL_FRAG_RO_ATTR(pre_erase_pebs);
SSDFS_MAPTBL_FRAG_RO_ATTR(recovering_pebs);
SSDFS_MAPTBL_FRAG_RO_ATTR(fragment_folios);
SSDFS_MAPTBL_FRAG_RO_ATTR(lebs_per_page);
SSDFS_MAPTBL_FRAG_RO_ATTR(lebtbl_pages);
SSDFS_MAPTBL_FRAG_RO_ATTR(pebs_per_page);
SSDFS_MAPTBL_FRAG_RO_ATTR(stripe_pages);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table);
SSDFS_MAPTBL_FRAG_RO_ATTR(summary);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_sections_count);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_sections_count);

static ssize_t
ssdfs_maptbl_frag_leb_table_section_0_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 0, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_1_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 1, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_2_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 2, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_3_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 3, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_4_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 4, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_5_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 5, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_6_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 6, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_7_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 7, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_8_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 8, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_9_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 9, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_10_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 10, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_11_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 11, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_12_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 12, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_13_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 13, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_14_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 14, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_15_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 15, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_16_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 16, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_17_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 17, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_18_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 18, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_19_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 19, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_20_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 20, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_21_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 21, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_22_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 22, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_23_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 23, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_24_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 24, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_25_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 25, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_26_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 26, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_27_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 27, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_28_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 28, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_29_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 29, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_30_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 30, buf);
}

static ssize_t
ssdfs_maptbl_frag_leb_table_section_31_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_leb_table_section_show(fdesc, 31, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_0_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 0, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_1_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 1, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_2_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 2, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_3_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 3, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_4_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 4, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_5_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 5, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_6_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 6, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_7_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 7, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_8_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 8, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_9_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 9, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_10_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 10, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_11_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 11, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_12_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 12, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_13_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 13, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_14_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 14, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_15_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 15, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_16_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 16, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_17_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 17, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_18_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 18, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_19_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 19, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_20_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 20, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_21_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 21, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_22_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 22, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_23_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 23, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_24_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 24, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_25_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 25, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_26_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 26, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_27_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 27, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_28_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 28, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_29_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 29, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_30_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 30, buf);
}

static ssize_t
ssdfs_maptbl_frag_peb_table_section_31_show(struct ssdfs_maptbl_frag_attr *attr,
				    struct ssdfs_maptbl_fragment_desc *fdesc,
				    char *buf)
{
	return ssdfs_maptbl_frag_peb_table_section_show(fdesc, 31, buf);
}

SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_0);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_1);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_2);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_3);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_4);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_5);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_6);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_7);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_8);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_9);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_10);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_11);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_12);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_13);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_14);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_15);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_16);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_17);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_18);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_19);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_20);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_21);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_22);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_23);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_24);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_25);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_26);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_27);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_28);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_29);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_30);
SSDFS_MAPTBL_FRAG_RO_ATTR(leb_table_section_31);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_0);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_1);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_2);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_3);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_4);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_5);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_6);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_7);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_8);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_9);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_10);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_11);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_12);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_13);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_14);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_15);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_16);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_17);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_18);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_19);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_20);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_21);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_22);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_23);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_24);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_25);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_26);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_27);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_28);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_29);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_30);
SSDFS_MAPTBL_FRAG_RO_ATTR(peb_table_section_31);

static struct attribute *ssdfs_maptbl_frag_attrs[] = {
	SSDFS_MAPTBL_FRAG_ATTR_LIST(id),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(state),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(start_leb),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(lebs_count),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(mapped_lebs),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(migrating_lebs),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(reserved_pebs),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(pre_erase_pebs),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(recovering_pebs),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(fragment_folios),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(lebs_per_page),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(lebtbl_pages),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(pebs_per_page),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(stripe_pages),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(summary),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_sections_count),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_sections_count),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_0),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_1),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_2),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_3),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_4),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_5),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_6),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_7),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_8),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_9),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_10),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_11),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_12),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_13),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_14),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_15),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_16),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_17),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_18),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_19),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_20),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_21),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_22),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_23),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_24),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_25),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_26),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_27),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_28),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_29),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_30),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(leb_table_section_31),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_0),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_1),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_2),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_3),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_4),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_5),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_6),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_7),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_8),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_9),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_10),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_11),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_12),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_13),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_14),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_15),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_16),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_17),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_18),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_19),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_20),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_21),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_22),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_23),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_24),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_25),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_26),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_27),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_28),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_29),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_30),
	SSDFS_MAPTBL_FRAG_ATTR_LIST(peb_table_section_31),
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_maptbl_frag);

static ssize_t ssdfs_maptbl_frag_attr_show(struct kobject *kobj,
					    struct attribute *attr, char *buf)
{
	struct ssdfs_maptbl_fragment_desc *fdesc = container_of(kobj,
						struct ssdfs_maptbl_fragment_desc,
						frag_kobj);
	struct ssdfs_maptbl_frag_attr *a = container_of(attr,
						struct ssdfs_maptbl_frag_attr,
						attr);
	const char *attr_name = attr->name;
	int section_index;

	if (sscanf(attr_name, "leb_table_section_%d", &section_index) == 1) {
		return ssdfs_maptbl_frag_leb_table_section_show(fdesc,
								section_index,
								buf);
	}

	if (sscanf(attr_name, "peb_table_section_%d", &section_index) == 1) {
		return ssdfs_maptbl_frag_peb_table_section_show(fdesc,
								section_index,
								buf);
	}

	return a->show ? a->show(a, fdesc, buf) : 0;
}

static ssize_t ssdfs_maptbl_frag_attr_store(struct kobject *kobj,
					     struct attribute *attr,
					     const char *buf, size_t len)
{
	struct ssdfs_maptbl_fragment_desc *fdesc = container_of(kobj,
						struct ssdfs_maptbl_fragment_desc,
						frag_kobj);
	struct ssdfs_maptbl_frag_attr *a = container_of(attr,
						struct ssdfs_maptbl_frag_attr,
						attr);

	return a->store ? a->store(a, fdesc, buf, len) : 0;
}

static void ssdfs_maptbl_frag_attr_release(struct kobject *kobj)
{
	struct ssdfs_maptbl_fragment_desc *fdesc = container_of(kobj,
						struct ssdfs_maptbl_fragment_desc,
						frag_kobj);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release maptbl fragment %u group\n", fdesc->fragment_id);
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&fdesc->frag_kobj_unregister);
}

static const struct sysfs_ops ssdfs_maptbl_frag_attr_ops = {
	.show	= ssdfs_maptbl_frag_attr_show,
	.store	= ssdfs_maptbl_frag_attr_store,
};

static struct kobj_type ssdfs_maptbl_frag_ktype = {
	.default_groups = ssdfs_maptbl_frag_groups,
	.sysfs_ops	= &ssdfs_maptbl_frag_attr_ops,
	.release	= ssdfs_maptbl_frag_attr_release,
};

static inline
int ssdfs_sysfs_create_maptbl_frag_group(struct ssdfs_maptbl_fragment_desc *fdesc,
					 struct kobject *parent_kobj)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create maptbl fragment %u group\n", fdesc->fragment_id);
#endif /* CONFIG_SSDFS_DEBUG */

	fdesc->frag_kobj.kset = ssdfs_kset;
	init_completion(&fdesc->frag_kobj_unregister);
	err = kobject_init_and_add(&fdesc->frag_kobj,
				   &ssdfs_maptbl_frag_ktype,
				   parent_kobj,
				   "fragment%u",
				   fdesc->fragment_id);
	if (err)
		return err;

	return 0;
}

static inline
void ssdfs_sysfs_delete_maptbl_frag_group(struct ssdfs_maptbl_fragment_desc *fdesc)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete maptbl fragment %u group\n", fdesc->fragment_id);
#endif /* CONFIG_SSDFS_DEBUG */

	kobject_del(&fdesc->frag_kobj);
	kobject_put(&fdesc->frag_kobj);
	wait_for_completion(&fdesc->frag_kobj_unregister);
}

static int ssdfs_sysfs_create_maptbl_fragments(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create maptbl fragment sysfs entries\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return -EINVAL;
	}

	for (i = 0; i < tbl->fragments_count; i++) {
		fdesc = &tbl->desc_array[i];
		err = ssdfs_sysfs_create_maptbl_frag_group(fdesc,
							   &fsi->maptbl_frags_kobj);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create fragment %d sysfs group: "
				  "err %d\n", i, err);
			goto cleanup_fragments;
		}
	}

	return 0;

cleanup_fragments:
	for (i--; i >= 0; i--) {
		fdesc = &tbl->desc_array[i];
		ssdfs_sysfs_delete_maptbl_frag_group(fdesc);
	}
	return err;
}

static void ssdfs_sysfs_delete_maptbl_fragments(struct ssdfs_fs_info *fsi)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	struct ssdfs_maptbl_fragment_desc *fdesc;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete maptbl fragment sysfs entries\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return;
	}

	down_read(&tbl->tbl_lock);
	for (i = 0; i < tbl->fragments_count; i++) {
		fdesc = &tbl->desc_array[i];

		down_read(&fdesc->lock);
		ssdfs_sysfs_delete_maptbl_frag_group(fdesc);
		up_read(&fdesc->lock);
	}
	up_read(&tbl->tbl_lock);
}

/************************************************************************
 *                      SSDFS maptbl fragments group                   *
 ************************************************************************/

static struct attribute *ssdfs_maptbl_frags_attrs[] = {
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_maptbl_frags);

static ssize_t ssdfs_maptbl_frags_attr_show(struct kobject *kobj,
					     struct attribute *attr, char *buf)
{
	struct ssdfs_fs_info *fsi = container_of(kobj->parent,
						 struct ssdfs_fs_info,
						 maptbl_frags_kobj);
	struct ssdfs_maptbl_frags_attr *a = container_of(attr,
						struct ssdfs_maptbl_frags_attr,
						attr);
	return a->show ? a->show(a, fsi, buf) : 0;
}

static ssize_t ssdfs_maptbl_frags_attr_store(struct kobject *kobj,
					      struct attribute *attr,
					      const char *buf, size_t len)
{
	struct ssdfs_fs_info *fsi = container_of(kobj->parent,
						 struct ssdfs_fs_info,
						 maptbl_frags_kobj);
	struct ssdfs_maptbl_frags_attr *a = container_of(attr,
						struct ssdfs_maptbl_frags_attr,
						attr);
	return a->store ? a->store(a, fsi, buf, len) : 0;
}

static void ssdfs_maptbl_frags_attr_release(struct kobject *kobj)
{
	struct ssdfs_fs_info *fsi = container_of(kobj,
						 struct ssdfs_fs_info,
						 maptbl_frags_kobj);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release maptbl fragments group\n");
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&fsi->maptbl_frags_kobj_unregister);
}

static const struct sysfs_ops ssdfs_maptbl_frags_attr_ops = {
	.show	= ssdfs_maptbl_frags_attr_show,
	.store	= ssdfs_maptbl_frags_attr_store,
};

static struct kobj_type ssdfs_maptbl_frags_ktype = {
	.default_groups = ssdfs_maptbl_frags_groups,
	.sysfs_ops	= &ssdfs_maptbl_frags_attr_ops,
	.release	= ssdfs_maptbl_frags_attr_release,
};

static int ssdfs_sysfs_create_maptbl_frags_group(struct ssdfs_fs_info *fsi)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create maptbl fragments group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->maptbl_frags_kobj.kset = ssdfs_kset;
	init_completion(&fsi->maptbl_frags_kobj_unregister);
	err = kobject_init_and_add(&fsi->maptbl_frags_kobj,
				   &ssdfs_maptbl_frags_ktype,
				   &fsi->maptbl_kobj, "fragments");
	if (err)
		return err;

	return 0;
}

static void ssdfs_sysfs_delete_maptbl_frags_group(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete maptbl fragments group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	kobject_del(&fsi->maptbl_frags_kobj);
	kobject_put(&fsi->maptbl_frags_kobj);
	wait_for_completion(&fsi->maptbl_frags_kobj_unregister);
}

/************************************************************************
 *                        SSDFS maptbl attrs                            *
 ************************************************************************/

static
ssize_t ssdfs_maptbl_fragments_count_show(struct ssdfs_maptbl_attr *attr,
					  struct ssdfs_fs_info *fsi,
					  char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	u32 fragments_count;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);
	fragments_count = tbl->fragments_count;
	up_read(&tbl->tbl_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragments_count);
}

static
ssize_t ssdfs_maptbl_fragments_per_seg_show(struct ssdfs_maptbl_attr *attr,
					    struct ssdfs_fs_info *fsi,
					    char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	u16 fragments_per_seg;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);
	fragments_per_seg = tbl->fragments_per_seg;
	up_read(&tbl->tbl_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragments_per_seg);
}

static
ssize_t ssdfs_maptbl_fragments_per_peb_show(struct ssdfs_maptbl_attr *attr,
					    struct ssdfs_fs_info *fsi,
					    char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	u16 fragments_per_peb;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);
	fragments_per_peb = tbl->fragments_per_peb;
	up_read(&tbl->tbl_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragments_per_peb);
}

static
ssize_t ssdfs_maptbl_fragment_bytes_show(struct ssdfs_maptbl_attr *attr,
					 struct ssdfs_fs_info *fsi,
					 char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	u32 fragment_bytes;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);
	fragment_bytes = tbl->fragment_bytes;
	up_read(&tbl->tbl_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", fragment_bytes);
}

static
ssize_t ssdfs_maptbl_flags_show(struct ssdfs_maptbl_attr *attr,
				struct ssdfs_fs_info *fsi,
				char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	return snprintf(buf, PAGE_SIZE, "%#x\n",
			atomic_read(&tbl->flags));
}

static
ssize_t ssdfs_maptbl_lebs_count_show(struct ssdfs_maptbl_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	u64 lebs_count;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);
	lebs_count = tbl->lebs_count;
	up_read(&tbl->tbl_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", lebs_count);
}

static
ssize_t ssdfs_maptbl_pebs_count_show(struct ssdfs_maptbl_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	u64 pebs_count;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);
	pebs_count = tbl->pebs_count;
	up_read(&tbl->tbl_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", pebs_count);
}

static
ssize_t ssdfs_maptbl_lebs_per_fragment_show(struct ssdfs_maptbl_attr *attr,
					    struct ssdfs_fs_info *fsi,
					    char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	u16 lebs_per_fragment;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);
	lebs_per_fragment = tbl->lebs_per_fragment;
	up_read(&tbl->tbl_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", lebs_per_fragment);
}

static
ssize_t ssdfs_maptbl_pebs_per_fragment_show(struct ssdfs_maptbl_attr *attr,
					    struct ssdfs_fs_info *fsi,
					    char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	u16 pebs_per_fragment;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);
	pebs_per_fragment = tbl->pebs_per_fragment;
	up_read(&tbl->tbl_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", pebs_per_fragment);
}

static
ssize_t ssdfs_maptbl_pebs_per_stripe_show(struct ssdfs_maptbl_attr *attr,
					    struct ssdfs_fs_info *fsi,
					    char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	u16 pebs_per_stripe;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);
	pebs_per_stripe = tbl->pebs_per_stripe;
	up_read(&tbl->tbl_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", pebs_per_stripe);
}

static
ssize_t ssdfs_maptbl_stripes_per_fragment_show(struct ssdfs_maptbl_attr *attr,
						struct ssdfs_fs_info *fsi,
						char *buf)
{
	struct ssdfs_peb_mapping_table *tbl = fsi->maptbl;
	u16 stripes_per_fragment;

	if (!tbl) {
		SSDFS_WARN("maptbl is absent\n");
		return 0;
	}

	down_read(&tbl->tbl_lock);
	stripes_per_fragment = tbl->stripes_per_fragment;
	up_read(&tbl->tbl_lock);

	return snprintf(buf, PAGE_SIZE, "%u\n", stripes_per_fragment);
}

SSDFS_MAPTBL_RO_ATTR(fragments_count);
SSDFS_MAPTBL_RO_ATTR(fragments_per_seg);
SSDFS_MAPTBL_RO_ATTR(fragments_per_peb);
SSDFS_MAPTBL_RO_ATTR(fragment_bytes);
SSDFS_MAPTBL_RO_ATTR(flags);
SSDFS_MAPTBL_RO_ATTR(lebs_count);
SSDFS_MAPTBL_RO_ATTR(pebs_count);
SSDFS_MAPTBL_RO_ATTR(lebs_per_fragment);
SSDFS_MAPTBL_RO_ATTR(pebs_per_fragment);
SSDFS_MAPTBL_RO_ATTR(pebs_per_stripe);
SSDFS_MAPTBL_RO_ATTR(stripes_per_fragment);

static struct attribute *ssdfs_maptbl_attrs[] = {
	SSDFS_MAPTBL_ATTR_LIST(fragments_count),
	SSDFS_MAPTBL_ATTR_LIST(fragments_per_seg),
	SSDFS_MAPTBL_ATTR_LIST(fragments_per_peb),
	SSDFS_MAPTBL_ATTR_LIST(fragment_bytes),
	SSDFS_MAPTBL_ATTR_LIST(flags),
	SSDFS_MAPTBL_ATTR_LIST(lebs_count),
	SSDFS_MAPTBL_ATTR_LIST(pebs_count),
	SSDFS_MAPTBL_ATTR_LIST(lebs_per_fragment),
	SSDFS_MAPTBL_ATTR_LIST(pebs_per_fragment),
	SSDFS_MAPTBL_ATTR_LIST(pebs_per_stripe),
	SSDFS_MAPTBL_ATTR_LIST(stripes_per_fragment),
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_maptbl);

static ssize_t ssdfs_maptbl_attr_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 maptbl_kobj);
	struct ssdfs_maptbl_attr *a = container_of(attr,
						struct ssdfs_maptbl_attr,
						attr);
	return a->show ? a->show(a, fsi, buf) : 0;
}

static ssize_t ssdfs_maptbl_attr_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buf, size_t len)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 maptbl_kobj);
	struct ssdfs_maptbl_attr *a = container_of(attr,
						struct ssdfs_maptbl_attr,
						attr);
	return a->store ? a->store(a, fsi, buf, len) : 0;
}

static void ssdfs_maptbl_attr_release(struct kobject *kobj)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 maptbl_kobj);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release maptbl group\n");
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&fsi->maptbl_kobj_unregister);
}

static const struct sysfs_ops ssdfs_maptbl_attr_ops = {
	.show	= ssdfs_maptbl_attr_show,
	.store	= ssdfs_maptbl_attr_store,
};

static struct kobj_type ssdfs_maptbl_ktype = {
	.default_groups = ssdfs_maptbl_groups,
	.sysfs_ops	= &ssdfs_maptbl_attr_ops,
	.release	= ssdfs_maptbl_attr_release,
};

int ssdfs_sysfs_create_maptbl_group(struct ssdfs_fs_info *fsi)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create maptbl group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->maptbl_kobj.kset = ssdfs_kset;
	init_completion(&fsi->maptbl_kobj_unregister);
	err = kobject_init_and_add(&fsi->maptbl_kobj, &ssdfs_maptbl_ktype,
				   &fsi->dev_kobj, "maptbl");
	if (err)
		return err;

	err = ssdfs_sysfs_create_maptbl_frags_group(fsi);
	if (err)
		goto cleanup_maptbl_kobject;

	err = ssdfs_sysfs_create_maptbl_fragments(fsi);
	if (err)
		goto cleanup_maptbl_frags_group;

	return 0;

cleanup_maptbl_frags_group:
	ssdfs_sysfs_delete_maptbl_frags_group(fsi);

cleanup_maptbl_kobject:
	kobject_del(&fsi->maptbl_kobj);
	kobject_put(&fsi->maptbl_kobj);
	wait_for_completion(&fsi->maptbl_kobj_unregister);
	return err;
}

void ssdfs_sysfs_delete_maptbl_group(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete maptbl group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_sysfs_delete_maptbl_fragments(fsi);
	ssdfs_sysfs_delete_maptbl_frags_group(fsi);
	kobject_del(&fsi->maptbl_kobj);
	kobject_put(&fsi->maptbl_kobj);
	wait_for_completion(&fsi->maptbl_kobj_unregister);
}

/************************************************************************
 *                        SSDFS device attrs                            *
 ************************************************************************/

static ssize_t ssdfs_dev_revision_show(struct ssdfs_dev_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	u8 major, minor;

	down_read(&fsi->volume_sem);
	major = fsi->vh->magic.version.major;
	minor = fsi->vh->magic.version.minor;
	up_read(&fsi->volume_sem);

	return snprintf(buf, PAGE_SIZE, "%d.%d\n", major, minor);
}

static ssize_t ssdfs_dev_pagesize_show(struct ssdfs_dev_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", fsi->pagesize);
}

static ssize_t ssdfs_dev_erasesize_show(struct ssdfs_dev_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", fsi->erasesize);
}

static ssize_t ssdfs_dev_segsize_show(struct ssdfs_dev_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", fsi->segsize);
}

static ssize_t ssdfs_dev_pebs_per_seg_show(struct ssdfs_dev_attr *attr,
					    struct ssdfs_fs_info *fsi,
					    char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", fsi->pebs_per_seg);
}

static ssize_t ssdfs_dev_pages_per_peb_show(struct ssdfs_dev_attr *attr,
					    struct ssdfs_fs_info *fsi,
					    char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", fsi->pages_per_peb);
}

static ssize_t ssdfs_dev_pages_per_seg_show(struct ssdfs_dev_attr *attr,
					    struct ssdfs_fs_info *fsi,
					    char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", fsi->pages_per_seg);
}

static ssize_t ssdfs_dev_create_time_show(struct ssdfs_dev_attr *attr,
					  struct ssdfs_fs_info *fsi,
					  char *buf)
{
	return SSDFS_SHOW_TIME(fsi->fs_ctime, buf);
}

static ssize_t ssdfs_dev_create_time_ns_show(struct ssdfs_dev_attr *attr,
					     struct ssdfs_fs_info *fsi,
					     char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", fsi->fs_ctime);
}

static ssize_t ssdfs_dev_create_cno_show(struct ssdfs_dev_attr *attr,
					 struct ssdfs_fs_info *fsi,
					 char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n", fsi->fs_cno);
}

static ssize_t ssdfs_dev_mount_time_show(struct ssdfs_dev_attr *attr,
					  struct ssdfs_fs_info *fsi,
					  char *buf)
{
	u64 mount_time_ns;

	spin_lock(&fsi->volume_state_lock);
	mount_time_ns = fsi->fs_mount_time;
	spin_unlock(&fsi->volume_state_lock);

	return SSDFS_SHOW_TIME(mount_time_ns, buf);
}

static ssize_t ssdfs_dev_mount_time_ns_show(struct ssdfs_dev_attr *attr,
					     struct ssdfs_fs_info *fsi,
					     char *buf)
{
	u64 mount_time_ns;

	spin_lock(&fsi->volume_state_lock);
	mount_time_ns = fsi->fs_mount_time;
	spin_unlock(&fsi->volume_state_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", mount_time_ns);
}

static ssize_t ssdfs_dev_write_time_show(struct ssdfs_dev_attr *attr,
					  struct ssdfs_fs_info *fsi,
					  char *buf)
{
	u64 write_time_ns;

	spin_lock(&fsi->volume_state_lock);
	write_time_ns = fsi->fs_mod_time;
	spin_unlock(&fsi->volume_state_lock);

	return SSDFS_SHOW_TIME(write_time_ns, buf);
}

static ssize_t ssdfs_dev_write_time_ns_show(struct ssdfs_dev_attr *attr,
					     struct ssdfs_fs_info *fsi,
					     char *buf)
{
	u64 write_time_ns;

	spin_lock(&fsi->volume_state_lock);
	write_time_ns = fsi->fs_mod_time;
	spin_unlock(&fsi->volume_state_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", write_time_ns);
}

static ssize_t ssdfs_dev_mount_cno_show(struct ssdfs_dev_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	u64 mount_cno;

	spin_lock(&fsi->volume_state_lock);
	mount_cno = fsi->fs_mount_cno;
	spin_unlock(&fsi->volume_state_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", mount_cno);
}

static ssize_t ssdfs_dev_superblock_segments_show(struct ssdfs_dev_attr *attr,
						  struct ssdfs_fs_info *fsi,
						  char *buf)
{
	u64 sb_lebs[SSDFS_SB_CHAIN_MAX][SSDFS_SB_SEG_COPY_MAX];
	u64 sb_pebs[SSDFS_SB_CHAIN_MAX][SSDFS_SB_SEG_COPY_MAX];
	size_t size = sizeof(u64) * SSDFS_SB_CHAIN_MAX * SSDFS_SB_SEG_COPY_MAX;
	int i, j;
	ssize_t bytes_out = 0;

	down_read(&fsi->sb_segs_sem);
	memcpy(sb_lebs, fsi->sb_lebs, size);
	memcpy(sb_pebs, fsi->sb_pebs, size);
	up_read(&fsi->sb_segs_sem);

	for (i = 0; i < SSDFS_SB_CHAIN_MAX; i++) {
		for (j = 0; j < SSDFS_SB_SEG_COPY_MAX; j++) {
			if (bytes_out == PAGE_SIZE) {
				SSDFS_WARN("fail to output full details\n");
				return bytes_out;
			}
			bytes_out += snprintf(buf + bytes_out,
					     PAGE_SIZE - bytes_out,
					     "sb_lebs[%d][%d] = %llu, "
					     "sb_pebs[%d][%d] = %llu\n",
					     i, j, sb_lebs[i][j],
					     i, j, sb_pebs[i][j]);
			if (unlikely(bytes_out < 0))
				return bytes_out;
			BUG_ON(bytes_out > PAGE_SIZE);
		}
	}

	return bytes_out;
}

static ssize_t ssdfs_dev_last_superblock_log_show(struct ssdfs_dev_attr *attr,
					struct ssdfs_fs_info *fsi,
					char *buf)
{
	struct ssdfs_peb_extent last_log;

	down_read(&fsi->volume_sem);
	memcpy(&last_log, &fsi->sbi.last_log, sizeof(struct ssdfs_peb_extent));
	up_read(&fsi->volume_sem);

	return snprintf(buf, PAGE_SIZE,
			"LEB: %llu, PEB: %llu, OFF: %u, SIZE: %u\n",
			last_log.leb_id, last_log.peb_id,
			last_log.page_offset, last_log.pages_count);
}

static ssize_t ssdfs_dev_segments_count_show(struct ssdfs_dev_attr *attr,
					     struct ssdfs_fs_info *fsi,
					     char *buf)
{
	u64 nsegs;

	mutex_lock(&fsi->resize_mutex);
	nsegs = le64_to_cpu(fsi->vs->nsegs);
	mutex_unlock(&fsi->resize_mutex);

	return snprintf(buf, PAGE_SIZE, "%llu\n", nsegs);
}

static ssize_t ssdfs_dev_free_pages_show(struct ssdfs_dev_attr *attr,
					 struct ssdfs_fs_info *fsi,
					 char *buf)
{
	u64 free_pages;

	spin_lock(&fsi->volume_state_lock);
	free_pages = fsi->free_pages;
	spin_unlock(&fsi->volume_state_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", free_pages);
}

static ssize_t ssdfs_dev_uuid_show(struct ssdfs_dev_attr *attr,
				    struct ssdfs_fs_info *fsi,
				    char *buf)
{
	__le8 uuid[SSDFS_UUID_SIZE];

	down_read(&fsi->volume_sem);
	memcpy(uuid, fsi->vs->uuid, SSDFS_UUID_SIZE);
	up_read(&fsi->volume_sem);

	return snprintf(buf, PAGE_SIZE, "%pUb\n", uuid);
}

static ssize_t ssdfs_dev_volume_label_show(struct ssdfs_dev_attr *attr,
					    struct ssdfs_fs_info *fsi,
					    char *buf)
{
	char label[SSDFS_VOLUME_LABEL_MAX];

	down_read(&fsi->volume_sem);
	memcpy(label, fsi->vs->label, SSDFS_VOLUME_LABEL_MAX);
	up_read(&fsi->volume_sem);

	return scnprintf(buf, sizeof(label), "%s\n", label);
}

static ssize_t ssdfs_dev_error_behavior_show(struct ssdfs_dev_attr *attr,
						struct ssdfs_fs_info *fsi,
						char *buf)
{
	u16 fs_errors;

	spin_lock(&fsi->volume_state_lock);
	fs_errors = fsi->fs_errors;
	spin_unlock(&fsi->volume_state_lock);

	switch(fs_errors) {
	case SSDFS_ERRORS_CONTINUE:
		return snprintf(buf, PAGE_SIZE, "ERRORS_CONTINUE\n");

	case SSDFS_ERRORS_RO:
		return snprintf(buf, PAGE_SIZE, "ERRORS_RO\n");

	case SSDFS_ERRORS_PANIC:
		return snprintf(buf, PAGE_SIZE, "ERRORS_PANIC\n");
	}

	SSDFS_WARN("unknown fs behavior\n");
	return -EINVAL;
}

static ssize_t ssdfs_dev_error_behavior_store(struct ssdfs_dev_attr *attr,
						struct ssdfs_fs_info *fsi,
						const char *buf, size_t count)
{
	unsigned int val;
	int err;

	err = kstrtouint(skip_spaces(buf), 0, &val);
	if (err) {
		SSDFS_ERR("unable to convert string: err %d\n", err);
		return err;
	}

	if (val == 0 || val > SSDFS_LAST_KNOWN_FS_ERROR) {
		SSDFS_ERR("unknown fs behavior: %u\n", val);
		return -EINVAL;
	}

	spin_lock(&fsi->volume_state_lock);
	fsi->fs_errors = val;
	spin_unlock(&fsi->volume_state_lock);

	return sizeof(val);
}

SSDFS_DEV_RO_ATTR(revision);
SSDFS_DEV_RO_ATTR(pagesize);
SSDFS_DEV_RO_ATTR(erasesize);
SSDFS_DEV_RO_ATTR(segsize);
SSDFS_DEV_RO_ATTR(pebs_per_seg);
SSDFS_DEV_RO_ATTR(pages_per_peb);
SSDFS_DEV_RO_ATTR(pages_per_seg);
SSDFS_DEV_RO_ATTR(create_time);
SSDFS_DEV_RO_ATTR(create_time_ns);
SSDFS_DEV_RO_ATTR(create_cno);
SSDFS_DEV_RO_ATTR(mount_time);
SSDFS_DEV_RO_ATTR(mount_time_ns);
SSDFS_DEV_RO_ATTR(write_time);
SSDFS_DEV_RO_ATTR(write_time_ns);
SSDFS_DEV_RO_ATTR(mount_cno);
SSDFS_DEV_RO_ATTR(superblock_segments);
SSDFS_DEV_RO_ATTR(last_superblock_log);
SSDFS_DEV_RO_ATTR(segments_count);
SSDFS_DEV_RO_ATTR(free_pages);
SSDFS_DEV_RO_ATTR(uuid);
SSDFS_DEV_RO_ATTR(volume_label);
SSDFS_DEV_RW_ATTR(error_behavior);

static struct attribute *ssdfs_dev_attrs[] = {
	SSDFS_DEV_ATTR_LIST(revision),
	SSDFS_DEV_ATTR_LIST(pagesize),
	SSDFS_DEV_ATTR_LIST(erasesize),
	SSDFS_DEV_ATTR_LIST(segsize),
	SSDFS_DEV_ATTR_LIST(pebs_per_seg),
	SSDFS_DEV_ATTR_LIST(pages_per_peb),
	SSDFS_DEV_ATTR_LIST(pages_per_seg),
	SSDFS_DEV_ATTR_LIST(create_time),
	SSDFS_DEV_ATTR_LIST(create_time_ns),
	SSDFS_DEV_ATTR_LIST(create_cno),
	SSDFS_DEV_ATTR_LIST(mount_time),
	SSDFS_DEV_ATTR_LIST(mount_time_ns),
	SSDFS_DEV_ATTR_LIST(write_time),
	SSDFS_DEV_ATTR_LIST(write_time_ns),
	SSDFS_DEV_ATTR_LIST(mount_cno),
	SSDFS_DEV_ATTR_LIST(superblock_segments),
	SSDFS_DEV_ATTR_LIST(last_superblock_log),
	SSDFS_DEV_ATTR_LIST(segments_count),
	SSDFS_DEV_ATTR_LIST(free_pages),
	SSDFS_DEV_ATTR_LIST(uuid),
	SSDFS_DEV_ATTR_LIST(volume_label),
	SSDFS_DEV_ATTR_LIST(error_behavior),
	NULL,
};
ATTRIBUTE_GROUPS(ssdfs_dev);

static ssize_t ssdfs_dev_attr_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 dev_kobj);
	struct ssdfs_dev_attr *a = container_of(attr, struct ssdfs_dev_attr,
						attr);

	return a->show ? a->show(a, fsi, buf) : 0;
}

static ssize_t ssdfs_dev_attr_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf, size_t len)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 dev_kobj);
	struct ssdfs_dev_attr *a = container_of(attr, struct ssdfs_dev_attr,
						attr);

	return a->store ? a->store(a, fsi, buf, len) : 0;
}

static void ssdfs_dev_attr_release(struct kobject *kobj)
{
	struct ssdfs_fs_info *fsi = container_of(kobj, struct ssdfs_fs_info,
						 dev_kobj);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("release device group\n");
#endif /* CONFIG_SSDFS_DEBUG */
	complete_all(&fsi->dev_kobj_unregister);
}

static const struct sysfs_ops ssdfs_dev_attr_ops = {
	.show	= ssdfs_dev_attr_show,
	.store	= ssdfs_dev_attr_store,
};

static struct kobj_type ssdfs_dev_ktype = {
	.default_groups = ssdfs_dev_groups,
	.sysfs_ops	= &ssdfs_dev_attr_ops,
	.release	= ssdfs_dev_attr_release,
};

int ssdfs_sysfs_create_device_group(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("create device group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	fsi->dev_kobj.kset = ssdfs_kset;
	init_completion(&fsi->dev_kobj_unregister);
	err = kobject_init_and_add(&fsi->dev_kobj, &ssdfs_dev_ktype, NULL,
				   "%s", fsi->devops->device_name(sb));
	if (err)
		goto free_dev_subgroups;

	err = ssdfs_sysfs_create_segments_group(fsi);
	if (err)
		goto cleanup_dev_kobject;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DONE: create device group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

cleanup_dev_kobject:
	kobject_del(&fsi->dev_kobj);
	kobject_put(&fsi->dev_kobj);
	wait_for_completion(&fsi->dev_kobj_unregister);

free_dev_subgroups:
	return err;
}

void ssdfs_sysfs_delete_device_group(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("delete device group\n");
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_sysfs_delete_segments_group(fsi);

	kobject_del(&fsi->dev_kobj);
	kobject_put(&fsi->dev_kobj);
	wait_for_completion(&fsi->dev_kobj_unregister);
}

/************************************************************************
 *                        SSDFS feature attrs                           *
 ************************************************************************/

static ssize_t ssdfs_feature_test_ro_attr_show(struct kobject *kobj,
						struct attribute *attr,
						char *buf)
{
	SSDFS_WARN("TODO: implement %s\n", __func__);
	return snprintf(buf, PAGE_SIZE, "%s\n", __func__);
}

SSDFS_FEATURE_INFO_ATTR(xattr_supported);
SSDFS_FEATURE_INFO_ATTR(xattr_user_supported);
SSDFS_FEATURE_INFO_ATTR(xattr_trusted_supported);
#ifdef CONFIG_SSDFS_SECURITY
SSDFS_FEATURE_INFO_ATTR(xattr_security_supported);
#endif
#ifdef CONFIG_SSDFS_POSIX_ACL
SSDFS_FEATURE_INFO_ATTR(acl_supported);
#endif
SSDFS_FEATURE_RO_ATTR(test_ro_attr);

static struct attribute *ssdfs_feature_attrs[] = {
	SSDFS_FEATURE_ATTR_LIST(xattr_supported),
	SSDFS_FEATURE_ATTR_LIST(xattr_user_supported),
	SSDFS_FEATURE_ATTR_LIST(xattr_trusted_supported),
#ifdef CONFIG_SSDFS_SECURITY
	SSDFS_FEATURE_ATTR_LIST(xattr_security_supported),
#endif
#ifdef CONFIG_SSDFS_POSIX_ACL
	SSDFS_FEATURE_ATTR_LIST(acl_supported),
#endif
	SSDFS_FEATURE_ATTR_LIST(test_ro_attr),
	NULL,
};

static const struct attribute_group ssdfs_feature_attr_group = {
	.name = "features",
	.attrs = ssdfs_feature_attrs,
};

int ssdfs_sysfs_init(void)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("try to initialize sysfs entry\n");
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_kset = kset_create_and_add("ssdfs", NULL, fs_kobj);
	if (!ssdfs_kset) {
		err = -ENOMEM;
		SSDFS_ERR("unable to create sysfs entry: err %d\n", err);
		goto failed_sysfs_init;
	}

	err = sysfs_create_group(&ssdfs_kset->kobj, &ssdfs_feature_attr_group);
	if (unlikely(err)) {
		SSDFS_ERR("unable to create feature group: err %d\n", err);
		goto cleanup_sysfs_init;
	}

	return 0;

cleanup_sysfs_init:
	kset_unregister(ssdfs_kset);

failed_sysfs_init:
	return err;
}

void ssdfs_sysfs_exit(void)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("deinitialize sysfs entry\n");
#endif /* CONFIG_SSDFS_DEBUG */

	sysfs_remove_group(&ssdfs_kset->kobj, &ssdfs_feature_attr_group);
	kset_unregister(ssdfs_kset);
}
