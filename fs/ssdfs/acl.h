// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/acl.h - ACLs support declarations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
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

#ifndef _SSDFS_ACL_H
#define _SSDFS_ACL_H

#include <linux/posix_acl_xattr.h>

#ifdef CONFIG_SSDFS_POSIX_ACL

#define set_posix_acl_flag(sb) \
	((sb)->s_flags |= SB_POSIXACL)

/* acl.c */
struct posix_acl *ssdfs_get_acl(struct inode *, int, bool);
int ssdfs_set_acl(struct mnt_idmap *idmap, struct dentry *,
		  struct posix_acl *, int);
int ssdfs_init_acl(struct inode *, struct inode *);

#else  /* CONFIG_SSDFS_POSIX_ACL */

#define set_posix_acl_flag(sb) \
	((sb)->s_flags &= ~SB_POSIXACL)

#define ssdfs_get_acl NULL
#define ssdfs_set_acl NULL

static inline int ssdfs_init_acl(struct inode *inode, struct inode *dir)
{
	return 0;
}

#endif  /* CONFIG_SSDFS_POSIX_ACL */

#endif /* _SSDFS_ACL_H */
