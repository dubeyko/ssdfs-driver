/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/xattr_security.c - handler for storing security labels as xattrs.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2026 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include <linux/security.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "xattr.h"
#include "acl.h"

static
int ssdfs_security_getxattr(const struct xattr_handler *handler,
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

	if ((len + XATTR_SECURITY_PREFIX_LEN) > XATTR_NAME_MAX)
		return -EOPNOTSUPP;

	return ssdfs_getxattr(inode, SSDFS_SECURITY_XATTR_ID, name,
				buffer, size);
}

static
int ssdfs_security_setxattr(const struct xattr_handler *handler,
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

	if ((len + XATTR_SECURITY_PREFIX_LEN) > XATTR_NAME_MAX)
		return -EOPNOTSUPP;

	return ssdfs_setxattr(inode, SSDFS_SECURITY_XATTR_ID, name,
				value, size, flags);
}

static
int ssdfs_initxattrs(struct inode *inode, const struct xattr *xattr_array,
			void *fs_info)
{
	const struct xattr *xattr;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, xattr_array %p, fs_info %p\n",
		  (unsigned long)inode->i_ino,
		  xattr_array, fs_info);
#endif /* CONFIG_SSDFS_DEBUG */

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		size_t name_len;

		name_len = strlen(xattr->name);

		if (name_len == 0)
			continue;

		if (name_len + XATTR_SECURITY_PREFIX_LEN > XATTR_NAME_MAX)
			return -EOPNOTSUPP;

		err = __ssdfs_setxattr(inode, SSDFS_SECURITY_XATTR_ID,
					xattr->name, xattr->value,
					xattr->value_len, 0);
		if (err)
			return err;
	}

	return 0;
}

int ssdfs_init_security(struct inode *inode, struct inode *dir,
			const struct qstr *qstr)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir_ino %lu, ino %lu\n",
		  (unsigned long)dir->i_ino,
		  (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	return security_inode_init_security(inode, dir, qstr,
					    &ssdfs_initxattrs, NULL);
}

int ssdfs_init_inode_security(struct inode *inode, struct inode *dir,
				const struct qstr *qstr)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir_ino %lu, ino %lu\n",
		  (unsigned long)dir->i_ino,
		  (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_init_acl(inode, dir);
	if (!err)
		err = ssdfs_init_security(inode, dir, qstr);
	return err;
}

const struct xattr_handler ssdfs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= ssdfs_security_getxattr,
	.set	= ssdfs_security_setxattr,
};
