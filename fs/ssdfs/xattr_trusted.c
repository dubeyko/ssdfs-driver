/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/xattr_trusted.c - handler for trusted extended attributes.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2025 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 *
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot
 *                  Zvonimir Bandic
 */

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "xattr.h"

static
int ssdfs_trusted_getxattr(const struct xattr_handler *handler,
			   struct dentry *unused, struct inode *inode,
			   const char *name, void *buffer, size_t size)
{
	size_t len;

	if (name == NULL || strcmp(name, "") == 0) {
		SSDFS_ERR("invalid name\n");
		return -EINVAL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, name %s, buffer %p, size %zu\n",
		  (unsigned long)inode->i_ino,
		  name, buffer, size);
#endif /* CONFIG_SSDFS_DEBUG */

	len = strlen(name);

	if ((len + XATTR_TRUSTED_PREFIX_LEN) > XATTR_NAME_MAX)
		return -EOPNOTSUPP;

	return ssdfs_getxattr(inode, SSDFS_TRUSTED_XATTR_ID, name,
				buffer, size);
}

static
int ssdfs_trusted_setxattr(const struct xattr_handler *handler,
			   struct mnt_idmap *idmap,
			   struct dentry *unused, struct inode *inode,
			   const char *name, const void *value,
			   size_t size, int flags)
{
	size_t len;

	if (name == NULL || strcmp(name, "") == 0) {
		SSDFS_ERR("invalid name\n");
		return -EINVAL;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, name %s, value %p, size %zu, flags %#x\n",
		  (unsigned long)inode->i_ino,
		  name, value, size, flags);
#endif /* CONFIG_SSDFS_DEBUG */

	len = strlen(name);

	if ((len + XATTR_TRUSTED_PREFIX_LEN) > XATTR_NAME_MAX)
		return -EOPNOTSUPP;

	return ssdfs_setxattr(inode, SSDFS_TRUSTED_XATTR_ID, name,
				value, size, flags);
}

const struct xattr_handler ssdfs_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.get	= ssdfs_trusted_getxattr,
	.set	= ssdfs_trusted_setxattr,
};
