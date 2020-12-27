//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/acl.c - ACLs support implementation.
 *
 * Copyright (c) 2014-2021 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2021, HGST, Inc., All rights reserved.
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
#include "acl.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_acl_page_leaks;
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
 * struct page *ssdfs_acl_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_acl_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_acl_free_page(struct page *page)
 * void ssdfs_acl_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(acl)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(acl)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_acl_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_acl_page_leaks, 0);
	atomic64_set(&ssdfs_acl_memory_leaks, 0);
	atomic64_set(&ssdfs_acl_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_acl_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_acl_page_leaks) != 0) {
		SSDFS_ERR("ACL: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_acl_page_leaks));
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

struct posix_acl *ssdfs_get_acl(struct inode *inode, int type)
{
	struct posix_acl *acl;
	char *xattr_name;
	int name_index;
	char *value = NULL;
	ssize_t size;

	SSDFS_DBG("ino %lu, type %#x\n",
		  (unsigned long)inode->i_ino, type);

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

int ssdfs_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int name_index;
	char *xattr_name;
	size_t size = 0;
	char *value = NULL;
	int err;

	SSDFS_DBG("ino %lu, type %#x, acl %p\n",
		  (unsigned long)inode->i_ino, type, acl);

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = SSDFS_POSIX_ACL_ACCESS_XATTR_ID;
		xattr_name = XATTR_NAME_POSIX_ACL_ACCESS;
		if (acl) {
			err = posix_acl_equiv_mode(acl, &inode->i_mode);
			if (err < 0)
				return err;
		}
		err = 0;
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

int ssdfs_init_acl(struct inode *inode, struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int err = 0;

	SSDFS_DBG("dir_ino %lu, ino %lu\n",
		  (unsigned long)dir->i_ino, (unsigned long)inode->i_ino);

	err = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (err)
		return err;

	if (default_acl) {
		err = ssdfs_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		posix_acl_release(default_acl);
	}

	if (acl) {
		if (!err)
			err = ssdfs_set_acl(inode, acl, ACL_TYPE_ACCESS);
		posix_acl_release(acl);
	}
	return err;
}
