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

/************************************************************************
 *                        SSDFS device attrs                            *
 ************************************************************************/

static ssize_t ssdfs_dev_test_ro_attr_show(struct ssdfs_dev_attr *attr,
						struct ssdfs_fs_info *fsi,
						char *buf)
{
	SSDFS_WARN("TODO: implement %s\n", __func__);
	return snprintf(buf, PAGE_SIZE, "%s\n", __func__);
}

static ssize_t ssdfs_dev_test_rw_attr_show(struct ssdfs_dev_attr *attr,
						struct ssdfs_fs_info *fsi,
						char *buf)
{
	SSDFS_WARN("TODO: implement %s\n", __func__);
	return snprintf(buf, PAGE_SIZE, "%s\n", __func__);
}

static ssize_t ssdfs_dev_test_rw_attr_store(struct ssdfs_dev_attr *attr,
						struct ssdfs_fs_info *fsi,
						const char *buf, size_t count)
{
	unsigned long long val;
	int err;

	err = kstrtoull(skip_spaces(buf), 0, &val);
	if (err) {
		SSDFS_ERR("unable to convert string: err %d\n", err);
		return err;
	}

	SSDFS_INFO("value %llu\n", val);
	SSDFS_WARN("TODO: implement %s\n", __func__);

	return count;
}

SSDFS_DEV_RO_ATTR(test_ro_attr);
SSDFS_DEV_RW_ATTR(test_rw_attr);

static struct attribute *ssdfs_dev_attrs[] = {
	SSDFS_DEV_ATTR_LIST(test_ro_attr),
	SSDFS_DEV_ATTR_LIST(test_rw_attr),
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
				   "%d (\"%s\")", sb->s_mtd->index,
				    sb->s_mtd->name);
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

void ssdfs_sysfs_exit(void)
{
	SSDFS_DBG("deinitialize sysfs entry\n");

	sysfs_remove_group(&ssdfs_kset->kobj, &ssdfs_feature_attr_group);
	kset_unregister(ssdfs_kset);
}
