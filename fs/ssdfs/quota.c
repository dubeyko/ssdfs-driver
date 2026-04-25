// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/quota.c - disk quota support.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/fs.h>
#include <linux/quota.h>
#include <linux/quotaops.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "quota.h"

/*
 * ssdfs_quota_read - read from quota file
 * @sb:   superblock
 * @type: quota type (USRQUOTA / GRPQUOTA / PRJQUOTA)
 * @data: buffer to read into
 * @len:  number of bytes to read
 * @off:  byte offset in the quota file
 *
 * Read @len bytes from the quota file of type @type starting at @off
 * into @data. Uses the page cache of the quota inode so SSDFS's normal
 * readpage path handles the actual I/O.
 *
 * Returns number of bytes read, or negative errno.
 */
ssize_t ssdfs_quota_read(struct super_block *sb, int type, char *data,
			 size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	struct address_space *mapping = inode->i_mapping;
	loff_t i_size = i_size_read(inode);
	size_t toread;

	if (off > i_size)
		return 0;

	if (off + len > i_size)
		len = i_size - off;

	toread = len;
	while (toread > 0) {
		struct folio *folio;
		size_t offset, tocopy;

retry:
		folio = mapping_read_folio_gfp(mapping,
					       off >> PAGE_SHIFT,
					       GFP_NOFS);
		if (IS_ERR(folio)) {
			if (PTR_ERR(folio) == -ENOMEM) {
				memalloc_retry_wait(GFP_NOFS);
				goto retry;
			}
			return PTR_ERR(folio);
		}

		offset = offset_in_folio(folio, off);
		tocopy = min(folio_size(folio) - offset, toread);

		folio_lock(folio);
		if (unlikely(folio->mapping != mapping)) {
			folio_unlock(folio);
			folio_put(folio);
			goto retry;
		}
		memcpy_from_folio(data, folio, offset, tocopy);
		folio_unlock(folio);
		folio_put(folio);

		toread -= tocopy;
		data += tocopy;
		off += tocopy;
	}
	return len;
}

/*
 * ssdfs_quota_write - write to quota file
 * @sb:   superblock
 * @type: quota type (USRQUOTA / GRPQUOTA / PRJQUOTA)
 * @data: buffer to write from
 * @len:  number of bytes to write
 * @off:  byte offset in the quota file
 *
 * Write @len bytes from @data into the quota file of type @type starting
 * at @off.  Uses write_begin / write_end from the quota inode's
 * address_space_operations so that SSDFS's normal write path (block
 * allocation, writeback) handles the actual I/O. The iocb pointer
 * passed to write_begin is NULL; ssdfs_write_begin() handles that by
 * deriving the inode from the mapping instead.
 *
 * Returns number of bytes written, or negative errno.
 */
ssize_t ssdfs_quota_write(struct super_block *sb, int type, const char *data,
			  size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	struct address_space *mapping = inode->i_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	int offset = off & (sb->s_blocksize - 1);
	size_t towrite = len;
	struct folio *folio;
	void *fsdata = NULL;
	int tocopy;
	int err = 0;

	while (towrite > 0) {
		tocopy = min_t(int, sb->s_blocksize - offset, (int)towrite);
retry:
		/*
		 * Pass NULL as iocb: ssdfs_write_begin() handles this by
		 * deriving file context from mapping->host rather than
		 * iocb->ki_filp.
		 */
		err = a_ops->write_begin(NULL, mapping, off, tocopy,
					 &folio, &fsdata);
		if (unlikely(err)) {
			if (err == -ENOMEM) {
				memalloc_retry_wait(GFP_NOFS);
				goto retry;
			}
			break;
		}

		memcpy_to_folio(folio, offset_in_folio(folio, off),
				data, tocopy);

		a_ops->write_end(NULL, mapping, off, tocopy, tocopy,
				 folio, fsdata);
		offset = 0;
		towrite -= tocopy;
		off += tocopy;
		data += tocopy;
		cond_resched();
	}

	if (len == towrite)
		return err;

	inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
	mark_inode_dirty(inode);
	return len - towrite;
}

/*
 * ssdfs_get_dquots - return per-inode dquot array
 * @inode: inode whose dquots to return
 *
 * Called by the generic quota code to find the dquot pointers attached
 * to @inode. These are stored in ssdfs_inode_info.i_dquot[].
 */
struct dquot __rcu **ssdfs_get_dquots(struct inode *inode)
{
	return SSDFS_I(inode)->i_dquot;
}

/*
 * ssdfs_dquot_operations - quota operations registered on the superblock
 *
 * We use the generic helpers from fs/quota/dquot.c throughout.
 */
const struct dquot_operations ssdfs_dquot_operations = {
	.write_dquot	= dquot_commit,
	.acquire_dquot	= dquot_acquire,
	.release_dquot	= dquot_release,
	.mark_dirty	= dquot_mark_dquot_dirty,
	.write_info	= dquot_commit_info,
	.alloc_dquot	= dquot_alloc,
	.destroy_dquot	= dquot_destroy,
	.get_next_id	= dquot_get_next_id,
};

/*
 * ssdfs_qctl_operations - quotactl operations registered on the superblock
 *
 * All operations delegate to the generic VFS helpers which take care of
 * quota-file management and the in-memory dquot cache.
 */
const struct quotactl_ops ssdfs_qctl_operations = {
	.quota_on	= dquot_quota_on,
	.quota_off	= dquot_quota_off,
	.quota_sync	= dquot_quota_sync,
	.get_state	= dquot_get_state,
	.set_info	= dquot_set_dqinfo,
	.get_dqblk	= dquot_get_dqblk,
	.set_dqblk	= dquot_set_dqblk,
	.get_nextdqblk	= dquot_get_next_dqblk,
};
