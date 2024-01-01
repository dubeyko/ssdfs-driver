/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/acl.c - ACLs support implementation.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2024 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "acl.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_acl_folio_leaks;
atomic64_t ssdfs_acl_memory_leaks;
atomic64_t ssdfs_acl_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_acl_cache_leaks_increment(void *kaddr)
 * void ssdfs_acl_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_acl_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_acl_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_acl_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_acl_kfree(void *kaddr)
 * struct folio *ssdfs_acl_alloc_foliogfp_t gfp_mask, unsigned int order)
 * struct folio *ssdfs_acl_add_batch_folio(struct folio_batch *batch,
 *                                         unsigned int order)
 * void ssdfs_acl_free_folio(struct folio *folio)
 * void ssdfs_acl_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(acl)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(acl)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_acl_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_acl_folio_leaks, 0);
	atomic64_set(&ssdfs_acl_memory_leaks, 0);
	atomic64_set(&ssdfs_acl_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_acl_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_acl_folio_leaks) != 0) {
		SSDFS_ERR("ACL: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_acl_folio_leaks));
	}

	if (atomic64_read(&ssdfs_acl_memory_leaks) != 0) {
		SSDFS_ERR("ACL: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_acl_memory_leaks));
	}

	if (atomic64_read(&ssdfs_acl_cache_leaks) != 0) {
		SSDFS_ERR("ACL: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_acl_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

struct posix_acl *ssdfs_get_acl(struct inode *inode, int type, bool rcu)
{
	struct posix_acl *acl;
	char *xattr_name;
	int name_index;
	char *value = NULL;
	ssize_t size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, type %#x\n",
		  (unsigned long)inode->i_ino, type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (rcu)
		return ERR_PTR(-ECHILD);

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = SSDFS_POSIX_ACL_ACCESS_XATTR_ID;
		xattr_name = XATTR_NAME_POSIX_ACL_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name_index = SSDFS_POSIX_ACL_DEFAULT_XATTR_ID;
		xattr_name = XATTR_NAME_POSIX_ACL_DEFAULT;
		break;
	default:
		SSDFS_ERR("unknown type %#x\n", type);
		return ERR_PTR(-EINVAL);
	}

	size = __ssdfs_getxattr(inode, name_index, xattr_name, NULL, 0);

	if (size > 0) {
		value = ssdfs_acl_kzalloc(size, GFP_KERNEL);
		if (unlikely(!value)) {
			SSDFS_ERR("unable to allocate memory\n");
			return ERR_PTR(-ENOMEM);
		}
		size = __ssdfs_getxattr(inode, name_index, xattr_name,
					value, size);
	}

	if (size > 0)
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
	else if (size == -ENODATA)
		acl = NULL;
	else
		acl = ERR_PTR(size);

	ssdfs_acl_kfree(value);
	return acl;
}

static
int __ssdfs_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int name_index;
	char *xattr_name;
	size_t size = 0;
	char *value = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, type %#x, acl %p\n",
		  (unsigned long)inode->i_ino, type, acl);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = SSDFS_POSIX_ACL_ACCESS_XATTR_ID;
		xattr_name = XATTR_NAME_POSIX_ACL_ACCESS;
		break;

	case ACL_TYPE_DEFAULT:
		name_index = SSDFS_POSIX_ACL_DEFAULT_XATTR_ID;
		xattr_name = XATTR_NAME_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;

	default:
		SSDFS_ERR("unknown type %#x\n", type);
		return -EINVAL;
	}

	if (acl) {
		size = posix_acl_xattr_size(acl->a_count);
		value = ssdfs_acl_kzalloc(size, GFP_KERNEL);
		if (!value) {
			SSDFS_ERR("unable to allocate memory\n");
			return -ENOMEM;
		}
		err = posix_acl_to_xattr(&init_user_ns, acl, value, size);
		if (err < 0) {
			SSDFS_ERR("unable to convert acl to xattr\n");
			goto end_set_acl;
		}
	}

	err = __ssdfs_setxattr(inode, name_index, xattr_name, value, size, 0);

end_set_acl:
	ssdfs_acl_kfree(value);

	if (!err)
		set_cached_acl(inode, type, acl);

	return err;
}

int ssdfs_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		  struct posix_acl *acl, int type)
{
	int update_mode = 0;
	struct inode *inode = d_inode(dentry);
	umode_t mode = inode->i_mode;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, type %#x, acl %p\n",
		  (unsigned long)inode->i_ino, type, acl);
#endif /* CONFIG_SSDFS_DEBUG */

	if (type == ACL_TYPE_ACCESS && acl) {
		err = posix_acl_update_mode(idmap, inode, &mode, &acl);
		if (err)
			goto end_set_acl;

		if (mode != inode->i_mode)
			update_mode = 1;
	}

	err = __ssdfs_set_acl(inode, acl, type);
	if (!err && update_mode) {
		inode->i_mode = mode;

		inode_set_ctime_to_ts(inode, current_time(inode));
		mark_inode_dirty(inode);
	}

end_set_acl:
	return err;
}

int ssdfs_init_acl(struct inode *inode, struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("dir_ino %lu, ino %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	err = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (err)
		return err;

	if (default_acl) {
		err = __ssdfs_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		posix_acl_release(default_acl);
	}

	if (acl) {
		if (!err)
			err = __ssdfs_set_acl(inode, acl, ACL_TYPE_ACCESS);
		posix_acl_release(acl);
	}
	return err;
}
