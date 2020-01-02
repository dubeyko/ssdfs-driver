//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/ssdfs_inode_info.h - SSDFS in-core inode.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_INODE_INFO_H
#define _SSDFS_INODE_INFO_H

/*
 * Inode flags (GETFLAGS/SETFLAGS)
 */
#define	SSDFS_SECRM_FL			FS_SECRM_FL	/* Secure deletion */
#define	SSDFS_UNRM_FL			FS_UNRM_FL	/* Undelete */
#define	SSDFS_COMPR_FL			FS_COMPR_FL	/* Compress file */
#define SSDFS_SYNC_FL			FS_SYNC_FL	/* Synchronous updates */
#define SSDFS_IMMUTABLE_FL		FS_IMMUTABLE_FL	/* Immutable file */
#define SSDFS_APPEND_FL			FS_APPEND_FL	/* writes to file may only append */
#define SSDFS_NODUMP_FL			FS_NODUMP_FL	/* do not dump file */
#define SSDFS_NOATIME_FL		FS_NOATIME_FL	/* do not update atime */
/* Reserved for compression usage... */
#define SSDFS_DIRTY_FL			FS_DIRTY_FL
#define SSDFS_COMPRBLK_FL		FS_COMPRBLK_FL	/* One or more compressed clusters */
#define SSDFS_NOCOMP_FL			FS_NOCOMP_FL	/* Don't compress */
#define SSDFS_ECOMPR_FL			FS_ECOMPR_FL	/* Compression error */
/* End compression flags --- maybe not all used */	
#define SSDFS_BTREE_FL			FS_BTREE_FL	/* btree format dir */
#define SSDFS_INDEX_FL			FS_INDEX_FL	/* hash-indexed directory */
#define SSDFS_IMAGIC_FL			FS_IMAGIC_FL	/* AFS directory */
#define SSDFS_JOURNAL_DATA_FL		FS_JOURNAL_DATA_FL /* Reserved for ext3 */
#define SSDFS_NOTAIL_FL			FS_NOTAIL_FL	/* file tail should not be merged */
#define SSDFS_DIRSYNC_FL		FS_DIRSYNC_FL	/* dirsync behaviour (directories only) */
#define SSDFS_TOPDIR_FL			FS_TOPDIR_FL	/* Top of directory hierarchies*/
#define SSDFS_RESERVED_FL		FS_RESERVED_FL	/* reserved for ext2 lib */

#define SSDFS_FL_USER_VISIBLE		FS_FL_USER_VISIBLE	/* User visible flags */
#define SSDFS_FL_USER_MODIFIABLE	FS_FL_USER_MODIFIABLE	/* User modifiable flags */

/* Flags that should be inherited by new inodes from their parent. */
#define SSDFS_FL_INHERITED (SSDFS_SECRM_FL | SSDFS_UNRM_FL | SSDFS_COMPR_FL |\
			   SSDFS_SYNC_FL | SSDFS_NODUMP_FL |\
			   SSDFS_NOATIME_FL | SSDFS_COMPRBLK_FL |\
			   SSDFS_NOCOMP_FL | SSDFS_JOURNAL_DATA_FL |\
			   SSDFS_NOTAIL_FL | SSDFS_DIRSYNC_FL)

/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define SSDFS_REG_FLMASK (~(SSDFS_DIRSYNC_FL | SSDFS_TOPDIR_FL))

/* Flags that are appropriate for non-directories/regular files. */
#define SSDFS_OTHER_FLMASK (SSDFS_NODUMP_FL | SSDFS_NOATIME_FL)

/* Mask out flags that are inappropriate for the given type of inode. */
static inline __u32 ssdfs_mask_flags(umode_t mode, __u32 flags)
{
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & SSDFS_REG_FLMASK;
	else
		return flags & SSDFS_OTHER_FLMASK;
}

/*
 * struct ssdfs_inode_info - in-core inode
 * @vfs_inode: VFS inode object
 * @birthtime: creation time
 * @private_flags: inode's private flags
 * @lock: inode lock
 * @parent_ino: parent inode ID
 * @flags: inode flags
 * @name_hash: name's hash code
 * @name_len: name length
 * @extents_tree: extents btree
 * @dentries_tree: dentries btree
 * @xattrs_tree: extended attributes tree
 * @raw_inode: raw inode
 */
struct ssdfs_inode_info {
	struct inode vfs_inode;
	struct timespec64 birthtime;

	atomic_t private_flags;

	struct rw_semaphore lock;
	u64 parent_ino;
	u32 flags;
	u64 name_hash;
	u16 name_len;
	struct ssdfs_extents_btree_info *extents_tree;
	struct ssdfs_dentries_btree_info *dentries_tree;
	struct ssdfs_xattrs_btree_info *xattrs_tree;
	struct ssdfs_inode raw_inode;
};

static inline struct ssdfs_inode_info *SSDFS_I(struct inode *inode)
{
	return container_of(inode, struct ssdfs_inode_info, vfs_inode);
}

static inline
struct ssdfs_extents_btree_info *SSDFS_EXTREE(struct ssdfs_inode_info *ii)
{
	if (S_ISDIR(ii->vfs_inode.i_mode))
		return NULL;
	else
		return ii->extents_tree;
}

static inline
struct ssdfs_dentries_btree_info *SSDFS_DTREE(struct ssdfs_inode_info *ii)
{
	if (S_ISDIR(ii->vfs_inode.i_mode))
		return ii->dentries_tree;
	else
		return NULL;
}

static inline
struct ssdfs_xattrs_btree_info *SSDFS_XATTREE(struct ssdfs_inode_info *ii)
{
	return ii->xattrs_tree;
}

extern const struct file_operations ssdfs_dir_operations;
extern const struct inode_operations ssdfs_dir_inode_operations;
extern const struct file_operations ssdfs_file_operations;
extern const struct inode_operations ssdfs_file_inode_operations;
extern const struct address_space_operations ssdfs_aops;
extern const struct inode_operations ssdfs_special_inode_operations;
extern const struct inode_operations ssdfs_symlink_inode_operations;

#endif /* _SSDFS_INODE_INFO_H */
