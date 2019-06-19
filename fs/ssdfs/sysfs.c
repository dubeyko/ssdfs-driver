//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 *  SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/sysfs.c - sysfs support.
 *
 * Copyright (c) 2019 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/mtd/mtd.h>

#include "ssdfs.h"
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
	time_to_tm(timespec_val.tv_sec, 0, &res); \
	res.tm_year += 1900; \
	res.tm_mon += 1; \
	count = scnprintf(buf, PAGE_SIZE, \
			    "%ld-%.2d-%.2d %.2d:%.2d:%.2d\n", \
			    res.tm_year, res.tm_mon, res.tm_mday, \
			    res.tm_hour, res.tm_min, res.tm_sec);\
	count; \
})

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
	u64 sb_segs[SSDFS_SB_CHAIN_MAX][SSDFS_SB_SEG_COPY_MAX];
	size_t size = sizeof(u64) * SSDFS_SB_CHAIN_MAX * SSDFS_SB_SEG_COPY_MAX;
	int i, j;
	ssize_t bytes_out = 0;

	down_read(&fsi->sb_segs_sem);
	memcpy(sb_segs, fsi->sb_segs, size);
	up_read(&fsi->sb_segs_sem);

	for (i = 0; i < SSDFS_SB_CHAIN_MAX; i++) {
		for (j = 0; j < SSDFS_SB_SEG_COPY_MAX; j++) {
			if (bytes_out == PAGE_SIZE) {
				SSDFS_WARN("fail to output full details\n");
				return bytes_out;
			}
			bytes_out += snprintf(buf + bytes_out,
					     PAGE_SIZE - bytes_out,
					     "sb_seg[%d][%d] = %llu\n",
					     i, j, sb_segs[i][j]);
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
	struct ssdfs_extent last_log;

	down_read(&fsi->volume_sem);
	memcpy(&last_log, &fsi->sbi.last_log, sizeof(struct ssdfs_extent));
	up_read(&fsi->volume_sem);

	return snprintf(buf, PAGE_SIZE, "SEG: %llu, OFF: %u, SIZE: %u\n",
			last_log.seg, last_log.offset, last_log.size);
}

static ssize_t ssdfs_dev_segments_count_show(struct ssdfs_dev_attr *attr,
					     struct ssdfs_fs_info *fsi,
					     char *buf)
{
	int is_locked;
	u64 nsegs;

	is_locked = mutex_trylock(&fsi->resize_mutex);

	if (!is_locked) {
		SSDFS_WARN("volume is under resize!!!\n");
		return -ENOLCK;
	}

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
	int err;

	fsi->dev_kobj.kset = ssdfs_kset;
	init_completion(&fsi->dev_kobj_unregister);
	err = kobject_init_and_add(&fsi->dev_kobj, &ssdfs_dev_ktype, NULL,
				   "%s", fsi->devops->device_name(sb));
	if (err)
		return err;

	return 0;
}

void ssdfs_sysfs_delete_device_group(struct ssdfs_fs_info *fsi)
{
	kobject_del(&fsi->dev_kobj);
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

int __init ssdfs_sysfs_init(void)
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

void __exit ssdfs_sysfs_exit(void)
{
	SSDFS_DBG("deinitialize sysfs entry\n");

	sysfs_remove_group(&ssdfs_kset->kobj, &ssdfs_feature_attr_group);
	kset_unregister(ssdfs_kset);
}
