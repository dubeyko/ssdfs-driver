/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/quota.h - disk quota declarations.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_QUOTA_H
#define _SSDFS_QUOTA_H

#include <linux/quota.h>

extern const struct dquot_operations ssdfs_dquot_operations;
extern const struct quotactl_ops ssdfs_qctl_operations;

ssize_t ssdfs_quota_read(struct super_block *sb, int type, char *data,
			 size_t len, loff_t off);
ssize_t ssdfs_quota_write(struct super_block *sb, int type, const char *data,
			  size_t len, loff_t off);
struct dquot __rcu **ssdfs_get_dquots(struct inode *inode);

#endif /* _SSDFS_QUOTA_H */
