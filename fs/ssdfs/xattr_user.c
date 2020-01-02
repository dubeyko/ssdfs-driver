//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/xattr_user.c - handler for extended user attributes.
 *
 * Copyright (c) 2014-2020 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2020, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "xattr.h"

static
int ssdfs_user_getxattr(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	size_t len;

	if (name == NULL || strcmp(name, "") == 0) {
		SSDFS_ERR("invalid name\n");
		return -EINVAL;
	}

	SSDFS_DBG("ino %lu, name %s, buffer %p, size %zu\n",
		  (unsigned long)inode->i_ino,
		  name, buffer, size);

	len = strlen(name);

	if ((len + XATTR_USER_PREFIX_LEN) > XATTR_NAME_MAX)
		return -EOPNOTSUPP;

	return ssdfs_getxattr(inode, SSDFS_USER_XATTR_ID, name,
				buffer, size);
}

static
int ssdfs_user_setxattr(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, const void *value,
			size_t size, int flags)
{
	size_t len;

	if (name == NULL || strcmp(name, "") == 0) {
		SSDFS_ERR("invalid name\n");
		return -EINVAL;
	}

	SSDFS_DBG("ino %lu, name %s, value %p, size %zu, flags %#x\n",
		  (unsigned long)inode->i_ino,
		  name, value, size, flags);

	len = strlen(name);

	if ((len + XATTR_USER_PREFIX_LEN) > XATTR_NAME_MAX)
		return -EOPNOTSUPP;

	return ssdfs_setxattr(inode, SSDFS_USER_XATTR_ID, name,
				value, size, flags);
}

const struct xattr_handler ssdfs_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.get	= ssdfs_user_getxattr,
	.set	= ssdfs_user_setxattr,
};
