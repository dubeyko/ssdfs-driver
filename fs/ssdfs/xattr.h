//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/xattr.h - extended attributes support declarations.
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

#ifndef _SSDFS_XATTR_H
#define _SSDFS_XATTR_H

#include <linux/xattr.h>

/* Name indexes */
#define SSDFS_USER_XATTR_ID			1
#define SSDFS_POSIX_ACL_ACCESS_XATTR_ID		2
#define SSDFS_POSIX_ACL_DEFAULT_XATTR_ID	3
#define SSDFS_TRUSTED_XATTR_ID			4
#define SSDFS_SECURITY_XATTR_ID			5
#define SSDFS_SYSTEM_XATTR_ID			6
#define SSDFS_RICHACL_XATTR_ID			7
#define SSDFS_XATTR_MAX_ID			255

extern const struct xattr_handler ssdfs_xattr_user_handler;
extern const struct xattr_handler ssdfs_xattr_trusted_handler;
extern const struct xattr_handler ssdfs_xattr_security_handler;

extern const struct xattr_handler *ssdfs_xattr_handlers[];

ssize_t __ssdfs_getxattr(struct inode *, int, const char *, void *, size_t);

static inline
ssize_t ssdfs_getxattr(struct inode *inode,
			int name_index, const char *name,
			void *value, size_t size)
{
	return __ssdfs_getxattr(inode, name_index, name, value, size);
}

int __ssdfs_setxattr(struct inode *, int, const char *,
			const void *, size_t, int);

static inline
int ssdfs_setxattr(struct inode *inode,
		    int name_index, const char *name,
		    const void *value, size_t size, int flags)
{
	return __ssdfs_setxattr(inode, name_index, name,
				value, size, flags);
}

ssize_t ssdfs_listxattr(struct dentry *, char *, size_t);

#ifdef CONFIG_SSDFS_SECURITY
int ssdfs_init_security(struct inode *, struct inode *, const struct qstr *);
int ssdfs_init_inode_security(struct inode *, struct inode *,
				const struct qstr *);
#else
static inline
int ssdfs_init_security(struct inode *inode, struct inode *dir,
			const struct qstr *qstr)
{
	return 0;
}

static inline
int ssdfs_init_inode_security(struct inode *inode, struct inode *dir,
				const struct qstr *qstr)
{
	return 0;
}
#endif /* CONFIG_SSDFS_SECURITY */

#endif /* _SSDFS_XATTR_H */
