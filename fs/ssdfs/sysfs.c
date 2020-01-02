//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/sysfs.c - sysfs support.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "ssdfs.h"
#include "page_array.h"
#include "peb.h"
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
	struct timespec timespec_val; \
	struct tm res; \
	int count = 0; \
	timespec_val = ns_to_timespec(ns); \
	time64_to_tm(timespec_val.tv_sec, 0, &res); \
	res.tm_year += 1900; \
	res.tm_mon += 1; \
	count = scnprintf(buf, PAGE_SIZE, \
			    "%ld-%.2d-%.2d %.2d:%.2d:%.2d\n", \
			    res.tm_year, res.tm_mon, res.tm_mday, \
			    res.tm_hour, res.tm_min, res.tm_sec);\
	count; \
})

#define SSDFS_SEG_INT_GROUP_OPS(name) \
static ssize_t ssdfs_##name##_attr_show(struct kobject *kobj, \
					struct attribute *attr, char *buf) \
{ \
	struct ssdfs_segment_info *si = container_of(kobj->parent, \
						struct ssdfs_segment_info, \
						seg_kobj); \
	struct ssdfs_##name##_attr *a = container_of(attr, \
						struct ssdfs_##name##_attr, \
						attr); \
	return a->show ? a->show(a, si, buf) : 0; \
} \
static ssize_t ssdfs_##name##_attr_store(struct kobject *kobj, \
					 struct attribute *attr, \
					 const char *buf, size_t len) \
{ \
	struct ssdfs_segment_info *si = container_of(kobj->parent, \
						struct ssdfs_segment_info, \
						seg_kobj); \
	struct ssdfs_##name##_attr *a = container_of(attr, \
						struct ssdfs_##name##_attr, \
						attr); \
	return a->store ? a->store(a, si, buf, len) : 0; \
} \
static const struct sysfs_ops ssdfs_##name##_attr_ops = { \
	.show	= ssdfs_##name##_attr_show, \
	.store	= ssdfs_##name##_attr_store, \
};

#define SSDFS_SEG_INT_GROUP_TYPE(name) \
static void ssdfs_##name##_attr_release(struct kobject *kobj) \
{ \
	struct ssdfs_sysfs_seg_subgroups *subgroups; \
	struct ssdfs_segment_info *si = container_of(kobj->parent, \
						struct ssdfs_segment_info, \
						seg_kobj); \
	subgroups = si->seg_subgroups; \
	complete(&subgroups->sg_##name##_kobj_unregister); \
} \
static struct kobj_type ssdfs_##name##_ktype = { \
	.default_attrs	= ssdfs_##name##_attrs, \
	.sysfs_ops	= &ssdfs_##name##_attr_ops, \
	.release	= ssdfs_##name##_attr_release, \
};

#define SSDFS_SEG_INT_GROUP_FNS(name) \
static int ssdfs_sysfs_create_##name##_group(struct ssdfs_segment_info *si) \
{ \
	struct kobject *parent; \
	struct kobject *kobj; \
	struct completion *kobj_unregister; \
	struct ssdfs_sysfs_seg_subgroups *subgroups; \
	int err; \
	subgroups = si->seg_subgroups; \
	kobj = &subgroups->sg_##name##_kobj; \
	kobj_unregister = &subgroups->sg_##name##_kobj_unregister; \
	parent = &si->seg_kobj; \
	kobj->kset = ssdfs_kset; \
	init_completion(kobj_unregister); \
	err = kobject_init_and_add(kobj, &ssdfs_##name##_ktype, parent, \
				    #name); \
	if (err) \
		return err; \
	return 0; \
} \
static void ssdfs_sysfs_delete_##name##_group(struct ssdfs_segment_info *si) \
{ \
	kobject_del(&si->seg_subgroups->sg_##name##_kobj); \
}

#define SSDFS_DEV_INT_GROUP_OPS(name) \
static ssize_t ssdfs_##name##_attr_show(struct kobject *kobj, \
					struct attribute *attr, char *buf) \
{ \
	struct ssdfs_fs_info *fsi = container_of(kobj->parent, \
						 struct ssdfs_fs_info, \
						 dev_kobj); \
	struct ssdfs_##name##_attr *a = container_of(attr, \
						struct ssdfs_##name##_attr, \
						attr); \
	return a->show ? a->show(a, fsi, buf) : 0; \
} \
static ssize_t ssdfs_##name##_attr_store(struct kobject *kobj, \
					 struct attribute *attr, \
					 const char *buf, size_t len) \
{ \
	struct ssdfs_fs_info *fsi = container_of(kobj->parent, \
						 struct ssdfs_fs_info, \
						 dev_kobj); \
	struct ssdfs_##name##_attr *a = container_of(attr, \
						struct ssdfs_##name##_attr, \
						attr); \
	return a->store ? a->store(a, fsi, buf, len) : 0; \
} \
static const struct sysfs_ops ssdfs_##name##_attr_ops = { \
	.show	= ssdfs_##name##_attr_show, \
	.store	= ssdfs_##name##_attr_store, \
};

#define SSDFS_DEV_INT_GROUP_TYPE(name) \
static void ssdfs_##name##_attr_release(struct kobject *kobj) \
{ \
	struct ssdfs_sysfs_dev_subgroups *subgroups; \
	struct ssdfs_fs_info *fsi = container_of(kobj->parent, \
						 struct ssdfs_fs_info, \
						 dev_kobj); \
	subgroups = fsi->dev_subgroups; \
	complete(&subgroups->sg_##name##_kobj_unregister); \
} \
static struct kobj_type ssdfs_##name##_ktype = { \
	.default_attrs	= ssdfs_##name##_attrs, \
	.sysfs_ops	= &ssdfs_##name##_attr_ops, \
	.release	= ssdfs_##name##_attr_release, \
};

#define SSDFS_DEV_INT_GROUP_FNS(name) \
static int ssdfs_sysfs_create_##name##_group(struct ssdfs_fs_info *fsi) \
{ \
	struct kobject *parent; \
	struct kobject *kobj; \
	struct completion *kobj_unregister; \
	struct ssdfs_sysfs_dev_subgroups *subgroups; \
	int err; \
	subgroups = fsi->dev_subgroups; \
	kobj = &subgroups->sg_##name##_kobj; \
	kobj_unregister = &subgroups->sg_##name##_kobj_unregister; \
	parent = &fsi->dev_kobj; \
	kobj->kset = ssdfs_kset; \
	init_completion(kobj_unregister); \
	err = kobject_init_and_add(kobj, &ssdfs_##name##_ktype, parent, \
				    #name); \
	if (err) \
		return err; \
	return 0; \
} \
static void ssdfs_sysfs_delete_##name##_group(struct ssdfs_fs_info *fsi) \
{ \
	kobject_del(&fsi->dev_subgroups->sg_##name##_kobj); \
}

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
	return snprintf(buf, PAGE_SIZE, "%u\n", pebc->log_pages);
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
	unsigned int state = (tsk->state | tsk->exit_state) & TASK_REPORT;

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
	int i;

	for (i = 0; i < SSDFS_PEB_THREAD_TYPE_MAX; i++) {
		pid = task_pid_nr(pebc->thread[i].task);
		state = get_task_state(pebc->thread[i].task);
		type = thread_type_array[i];
		count += snprintf(buf + count, PAGE_SIZE - count,
				  "%s: pid %d, state %s\n",
				  type, pid, state);
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
	complete(&pebc->peb_kobj_unregister);
}

static const struct sysfs_ops ssdfs_peb_attr_ops = {
	.show	= ssdfs_peb_attr_show,
	.store	= ssdfs_peb_attr_store,
};

static struct kobj_type ssdfs_peb_ktype = {
	.default_attrs	= ssdfs_peb_attrs,
	.sysfs_ops	= &ssdfs_peb_attr_ops,
	.release	= ssdfs_peb_attr_release,
};

int ssdfs_sysfs_create_peb_group(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct kobject *parent;
	int err;

	parent = &si->seg_subgroups->sg_pebs_kobj;

	pebc->peb_kobj.kset = ssdfs_kset;
	init_completion(&pebc->peb_kobj_unregister);
	err = kobject_init_and_add(&pebc->peb_kobj,
				   &ssdfs_peb_ktype,
				   parent,
				   "peb%u",
				   pebc->peb_index);
	if (err)
		return err;

	return 0;
}

void ssdfs_sysfs_delete_peb_group(struct ssdfs_peb_container *pebc)
{
	kobject_del(&pebc->peb_kobj);
}

/************************************************************************
 *                          SSDFS pebs group                            *
 ************************************************************************/

static struct attribute *ssdfs_pebs_attrs[] = {
	NULL,
};

SSDFS_SEG_INT_GROUP_OPS(pebs);
SSDFS_SEG_INT_GROUP_TYPE(pebs);
SSDFS_SEG_INT_GROUP_FNS(pebs);

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
			atomic_read(&si->blk_bmap.valid_logical_blks));
}

static ssize_t ssdfs_seg_invalid_pages_show(struct ssdfs_seg_attr *attr,
					    struct ssdfs_segment_info *si,
					    char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n",
			atomic_read(&si->blk_bmap.invalid_logical_blks));
}

static ssize_t ssdfs_seg_free_pages_show(struct ssdfs_seg_attr *attr,
					 struct ssdfs_segment_info *si,
					 char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n",
			atomic_read(&si->blk_bmap.free_logical_blks));
}

static ssize_t ssdfs_seg_seg_state_show(struct ssdfs_seg_attr *attr,
					struct ssdfs_segment_info *si,
					char *buf)
{
	switch(atomic_read(&si->seg_state)) {
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

static ssize_t ssdfs_seg_attr_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct ssdfs_segment_info *si = container_of(kobj,
						     struct ssdfs_segment_info,
						     seg_kobj);
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
						     seg_kobj);
	struct ssdfs_seg_attr *a = container_of(attr, struct ssdfs_seg_attr,
						attr);

	return a->store ? a->store(a, si, buf, len) : 0;
}

static void ssdfs_seg_attr_release(struct kobject *kobj)
{
	struct ssdfs_segment_info *si = container_of(kobj,
						     struct ssdfs_segment_info,
						     seg_kobj);
	complete(&si->seg_kobj_unregister);
}

static const struct sysfs_ops ssdfs_seg_attr_ops = {
	.show	= ssdfs_seg_attr_show,
	.store	= ssdfs_seg_attr_store,
};

static struct kobj_type ssdfs_seg_ktype = {
	.default_attrs	= ssdfs_seg_attrs,
	.sysfs_ops	= &ssdfs_seg_attr_ops,
	.release	= ssdfs_seg_attr_release,
};

int ssdfs_sysfs_create_seg_group(struct ssdfs_segment_info *si)
{
	struct ssdfs_fs_info *fsi = si->fsi;
	size_t seggrp_size = sizeof(struct ssdfs_sysfs_seg_subgroups);
	struct kobject *parent;
	int err;

	si->seg_subgroups = kzalloc(seggrp_size, GFP_KERNEL);
	if (unlikely(!si->seg_subgroups))
		return -ENOMEM;

	parent = &fsi->dev_subgroups->sg_segments_kobj;

	si->seg_kobj.kset = ssdfs_kset;
	init_completion(&si->seg_kobj_unregister);
	err = kobject_init_and_add(&si->seg_kobj,
				   &ssdfs_seg_ktype,
				   parent,
				   "seg%llu",
				   si->seg_id);
	if (err)
		goto free_seg_subgroups;

	err = ssdfs_sysfs_create_pebs_group(si);
	if (err)
		goto cleanup_seg_kobject;

	return 0;

cleanup_seg_kobject:
	kobject_del(&si->seg_kobj);

free_seg_subgroups:
	kfree(si->seg_subgroups);

	return err;
}

void ssdfs_sysfs_delete_seg_group(struct ssdfs_segment_info *si)
{
	ssdfs_sysfs_delete_pebs_group(si);
	kobject_del(&si->seg_kobj);
	kfree(si->seg_subgroups);
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
			continue;
		}

		seg_id = real_seg->seg_id;

		count += snprintf(buf + count,
				  PAGE_SIZE - count,
				  "%s: seg_id %llu: < ",
				  type, seg_id);

		for (j = 0; j < real_seg->pebs_count; j++) {
			struct ssdfs_peb_container *pebc =
					&real_seg->peb_array[j];

			if (is_peb_joined_into_create_requests_queue(pebc)) {
				count += snprintf(buf + count,
						  PAGE_SIZE - count,
						  "peb_index %u ",
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

SSDFS_DEV_INT_GROUP_OPS(segments);
SSDFS_DEV_INT_GROUP_TYPE(segments);
SSDFS_DEV_INT_GROUP_FNS(segments);

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

static ssize_t ssdfs_segbmap_attr_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct ssdfs_fs_info *fsi = container_of(kobj->parent,
						 struct ssdfs_fs_info,
						 dev_kobj);
	struct ssdfs_segbmap_attr *a = container_of(attr,
						struct ssdfs_segbmap_attr,
						attr);
	return a->show ? a->show(a, fsi, buf) : 0;
}

static ssize_t ssdfs_segbmap_attr_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buf, size_t len)
{
	struct ssdfs_fs_info *fsi = container_of(kobj->parent,
						 struct ssdfs_fs_info,
						 dev_kobj);
	struct ssdfs_segbmap_attr *a = container_of(attr,
						struct ssdfs_segbmap_attr,
						attr);
	return a->store ? a->store(a, fsi, buf, len) : 0;
}

static void ssdfs_segbmap_attr_release(struct kobject *kobj)
{
	struct ssdfs_sysfs_dev_subgroups *subgroups;
	struct ssdfs_fs_info *fsi = container_of(kobj->parent,
						 struct ssdfs_fs_info,
						 dev_kobj);
	subgroups = fsi->dev_subgroups;
	complete(&subgroups->sg_segbmap_kobj_unregister);
}

static const struct sysfs_ops ssdfs_segbmap_attr_ops = {
	.show	= ssdfs_segbmap_attr_show,
	.store	= ssdfs_segbmap_attr_store,
};

static struct kobj_type ssdfs_segbmap_ktype = {
	.default_attrs	= ssdfs_segbmap_attrs,
	.sysfs_ops	= &ssdfs_segbmap_attr_ops,
	.release	= ssdfs_segbmap_attr_release,
};

int ssdfs_sysfs_create_segbmap_group(struct ssdfs_fs_info *fsi)
{
	struct kobject *parent;
	struct kobject *kobj;
	struct completion *kobj_unregister;
	struct ssdfs_sysfs_dev_subgroups *subgroups;
	int err;

	subgroups = fsi->dev_subgroups;
	kobj = &subgroups->sg_segbmap_kobj;
	kobj_unregister = &subgroups->sg_segbmap_kobj_unregister;
	parent = &fsi->dev_kobj;
	kobj->kset = ssdfs_kset;
	init_completion(kobj_unregister);

	err = kobject_init_and_add(kobj, &ssdfs_segbmap_ktype, parent,
				   "segbmap");
	if (err)
		return err;

	return 0;
}

void ssdfs_sysfs_delete_segbmap_group(struct ssdfs_fs_info *fsi)
{
	kobject_del(&fsi->dev_subgroups->sg_segbmap_kobj);
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

static ssize_t ssdfs_maptbl_attr_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct ssdfs_fs_info *fsi = container_of(kobj->parent,
						 struct ssdfs_fs_info,
						 dev_kobj);
	struct ssdfs_maptbl_attr *a = container_of(attr,
						struct ssdfs_maptbl_attr,
						attr);
	return a->show ? a->show(a, fsi, buf) : 0;
}

static ssize_t ssdfs_maptbl_attr_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buf, size_t len)
{
	struct ssdfs_fs_info *fsi = container_of(kobj->parent,
						 struct ssdfs_fs_info,
						 dev_kobj);
	struct ssdfs_maptbl_attr *a = container_of(attr,
						struct ssdfs_maptbl_attr,
						attr);
	return a->store ? a->store(a, fsi, buf, len) : 0;
}

static void ssdfs_maptbl_attr_release(struct kobject *kobj)
{
	struct ssdfs_sysfs_dev_subgroups *subgroups;
	struct ssdfs_fs_info *fsi = container_of(kobj->parent,
						 struct ssdfs_fs_info,
						 dev_kobj);
	subgroups = fsi->dev_subgroups;
	complete(&subgroups->sg_maptbl_kobj_unregister);
}

static const struct sysfs_ops ssdfs_maptbl_attr_ops = {
	.show	= ssdfs_maptbl_attr_show,
	.store	= ssdfs_maptbl_attr_store,
};

static struct kobj_type ssdfs_maptbl_ktype = {
	.default_attrs	= ssdfs_maptbl_attrs,
	.sysfs_ops	= &ssdfs_maptbl_attr_ops,
	.release	= ssdfs_maptbl_attr_release,
};

int ssdfs_sysfs_create_maptbl_group(struct ssdfs_fs_info *fsi)
{
	struct kobject *parent;
	struct kobject *kobj;
	struct completion *kobj_unregister;
	struct ssdfs_sysfs_dev_subgroups *subgroups;
	int err;

	subgroups = fsi->dev_subgroups;
	kobj = &subgroups->sg_maptbl_kobj;
	kobj_unregister = &subgroups->sg_maptbl_kobj_unregister;
	parent = &fsi->dev_kobj;
	kobj->kset = ssdfs_kset;
	init_completion(kobj_unregister);

	err = kobject_init_and_add(kobj, &ssdfs_maptbl_ktype, parent,
				   "maptbl");
	if (err)
		return err;

	return 0;
}

void ssdfs_sysfs_delete_maptbl_group(struct ssdfs_fs_info *fsi)
{
	kobject_del(&fsi->dev_subgroups->sg_maptbl_kobj);
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
	nsegs = fsi->vs->nsegs;
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
	complete(&fsi->dev_kobj_unregister);
}

static const struct sysfs_ops ssdfs_dev_attr_ops = {
	.show	= ssdfs_dev_attr_show,
	.store	= ssdfs_dev_attr_store,
};

static struct kobj_type ssdfs_dev_ktype = {
	.default_attrs	= ssdfs_dev_attrs,
	.sysfs_ops	= &ssdfs_dev_attr_ops,
	.release	= ssdfs_dev_attr_release,
};

int ssdfs_sysfs_create_device_group(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	size_t devgrp_size = sizeof(struct ssdfs_sysfs_dev_subgroups);
	int err;

	fsi->dev_subgroups = kzalloc(devgrp_size, GFP_KERNEL);
	if (unlikely(!fsi->dev_subgroups))
		return -ENOMEM;

	fsi->dev_kobj.kset = ssdfs_kset;
	init_completion(&fsi->dev_kobj_unregister);
	err = kobject_init_and_add(&fsi->dev_kobj, &ssdfs_dev_ktype, NULL,
				   "%s", fsi->devops->device_name(sb));
	if (err)
		goto free_dev_subgroups;

	err = ssdfs_sysfs_create_segments_group(fsi);
	if (err)
		goto cleanup_dev_kobject;

	err = ssdfs_sysfs_create_segbmap_group(fsi);
	if (err)
		goto delete_segments_group;

	err = ssdfs_sysfs_create_maptbl_group(fsi);
	if (err)
		goto delete_segbmap_group;

	SSDFS_DBG("DONE: create device group\n");

	return 0;

delete_segbmap_group:
	ssdfs_sysfs_delete_segbmap_group(fsi);

delete_segments_group:
	ssdfs_sysfs_delete_segments_group(fsi);

cleanup_dev_kobject:
	kobject_del(&fsi->dev_kobj);

free_dev_subgroups:
	kfree(fsi->dev_subgroups);

	return err;
}

void ssdfs_sysfs_delete_device_group(struct ssdfs_fs_info *fsi)
{
	ssdfs_sysfs_delete_maptbl_group(fsi);
	ssdfs_sysfs_delete_segbmap_group(fsi);
	ssdfs_sysfs_delete_segments_group(fsi);
	kobject_del(&fsi->dev_kobj);
	kfree(fsi->dev_subgroups);
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

	SSDFS_DBG("try to initialize sysfs entry\n");

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
	SSDFS_DBG("deinitialize sysfs entry\n");

	sysfs_remove_group(&ssdfs_kset->kobj, &ssdfs_feature_attr_group);
	kset_unregister(ssdfs_kset);
}
