/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/fscrypt.c - fscrypt (FS-level encryption) support.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pagevec.h>
#include <linux/fscrypt.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "ssdfs_inode_info.h"
#include "xattr.h"
#include "fscrypt.h"

/*
 * ssdfs_get_context() - read fscrypt context from inode's xattrs
 */
static int ssdfs_get_context(struct inode *inode, void *ctx, size_t len)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, len %zu\n", (unsigned long)inode->i_ino, len);
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_getxattr(inode, SSDFS_ENCRYPTION_XATTR_ID,
			      SSDFS_XATTR_NAME_ENCRYPTION_CONTEXT, ctx, len);
}

/*
 * ssdfs_set_fscrypt_context() - write fscrypt context to inode's xattrs
 *
 * This is the set_context callback for struct fscrypt_operations.
 * Named with prefix to avoid collision with the fscrypt core
 * fscrypt_set_context() helper.
 */
static int ssdfs_set_fscrypt_context(struct inode *inode, const void *ctx,
				     size_t len, void *fs_data)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %lu, len %zu\n", (unsigned long)inode->i_ino, len);
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_setxattr(inode, SSDFS_ENCRYPTION_XATTR_ID,
			      SSDFS_XATTR_NAME_ENCRYPTION_CONTEXT,
			      ctx, len, XATTR_CREATE);
}

/*
 * ssdfs_has_stable_inodes() - report that SSDFS has stable inode numbers
 *
 * SSDFS inode numbers do not change after creation, so we can safely use
 * IV_INO_LBLK-style encryption policies.
 */
static bool ssdfs_has_stable_inodes(struct super_block *sb)
{
	return true;
}

const struct fscrypt_operations ssdfs_cryptops = {
	/*
	 * Offset of the fscrypt_inode_info pointer within ssdfs_inode_info,
	 * measured from the embedded struct inode.
	 */
	.inode_info_offs	= (int)offsetof(struct ssdfs_inode_info,
						i_crypt_info) -
				  (int)offsetof(struct ssdfs_inode_info,
						vfs_inode),
	.needs_bounce_pages	= 1,
	.has_32bit_inodes	= 1,
	.legacy_key_prefix	= "ssdfs:",
	.get_context		= ssdfs_get_context,
	.set_context		= ssdfs_set_fscrypt_context,
	.empty_dir		= ssdfs_empty_dir,
	.has_stable_inodes	= ssdfs_has_stable_inodes,
};
