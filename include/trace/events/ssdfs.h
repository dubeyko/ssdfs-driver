//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * include/trace/events/ssdfs.h - definition of tracepoints.
 *
 * Copyright (c) 2019-2020 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM ssdfs

#if !defined(_TRACE_SSDFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SSDFS_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(ssdfs__inode,

	TP_PROTO(struct inode *inode),

	TP_ARGS(inode),

	TP_STRUCT__entry(
		__field(dev_t,	dev)
		__field(ino_t,	ino)
		__field(umode_t, mode)
		__field(loff_t,	size)
		__field(unsigned int, nlink)
		__field(blkcnt_t, blocks)
	),

	TP_fast_assign(
		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->mode	= inode->i_mode;
		__entry->nlink	= inode->i_nlink;
		__entry->size	= inode->i_size;
		__entry->blocks	= inode->i_blocks;
	),

	TP_printk("dev = (%d,%d), ino = %lu, i_mode = 0x%hx, "
		"i_size = %lld, i_nlink = %u, i_blocks = %llu",
		MAJOR(__entry->dev),
		MINOR(__entry->dev),
		(unsigned long)__entry->ino,
		__entry->mode,
		__entry->size,
		(unsigned int)__entry->nlink,
		(unsigned long long)__entry->blocks)
);

DECLARE_EVENT_CLASS(ssdfs__inode_exit,

	TP_PROTO(struct inode *inode, int ret),

	TP_ARGS(inode, ret),

	TP_STRUCT__entry(
		__field(dev_t,	dev)
		__field(ino_t,	ino)
		__field(int,	ret)
	),

	TP_fast_assign(
		__entry->dev	= inode->i_sb->s_dev;
		__entry->ino	= inode->i_ino;
		__entry->ret	= ret;
	),

	TP_printk("dev = (%d,%d), ino = %lu, ret = %d",
		MAJOR(__entry->dev),
		MINOR(__entry->dev),
		(unsigned long)__entry->ino,
		__entry->ret)
);

DEFINE_EVENT(ssdfs__inode, ssdfs_inode_new,

	TP_PROTO(struct inode *inode),

	TP_ARGS(inode)
);

DEFINE_EVENT(ssdfs__inode_exit, ssdfs_inode_new_exit,

	TP_PROTO(struct inode *inode, int ret),

	TP_ARGS(inode, ret)
);

DEFINE_EVENT(ssdfs__inode, ssdfs_inode_request,

	TP_PROTO(struct inode *inode),

	TP_ARGS(inode)
);

DEFINE_EVENT(ssdfs__inode, ssdfs_inode_evict,

	TP_PROTO(struct inode *inode),

	TP_ARGS(inode)
);

DEFINE_EVENT(ssdfs__inode, ssdfs_iget,

	TP_PROTO(struct inode *inode),

	TP_ARGS(inode)
);

DEFINE_EVENT(ssdfs__inode_exit, ssdfs_iget_exit,

	TP_PROTO(struct inode *inode, int ret),

	TP_ARGS(inode, ret)
);

TRACE_EVENT(ssdfs_sync_fs,

	TP_PROTO(struct super_block *sb, int wait),

	TP_ARGS(sb, wait),

	TP_STRUCT__entry(
		__field(dev_t,	dev)
		__field(int,	wait)
	),

	TP_fast_assign(
		__entry->dev	= sb->s_dev;
		__entry->wait	= wait;
	),

	TP_printk("dev = (%d,%d), wait = %d",
		MAJOR(__entry->dev),
		MINOR(__entry->dev),
		__entry->wait)
);

TRACE_EVENT(ssdfs_sync_fs_exit,

	TP_PROTO(struct super_block *sb, int wait, int ret),

	TP_ARGS(sb, wait, ret),

	TP_STRUCT__entry(
		__field(dev_t,	dev)
		__field(int,	wait)
		__field(int,	ret)
	),

	TP_fast_assign(
		__entry->dev	= sb->s_dev;
		__entry->wait	= wait;
		__entry->ret	= ret;
	),

	TP_printk("dev = (%d,%d), wait = %d, ret = %d",
		MAJOR(__entry->dev),
		MINOR(__entry->dev),
		__entry->wait,
		__entry->ret)
);

DEFINE_EVENT(ssdfs__inode, ssdfs_sync_file_enter,

	TP_PROTO(struct inode *inode),

	TP_ARGS(inode)
);

TRACE_EVENT(ssdfs_sync_file_exit,

	TP_PROTO(struct file *file, int datasync, int ret),

	TP_ARGS(file, datasync, ret),

	TP_STRUCT__entry(
		__field(dev_t,	dev)
		__field(ino_t,	ino)
		__field(ino_t,	parent)
		__field(int,	datasync)
		__field(int,	ret)
	),

	TP_fast_assign(
		struct dentry *dentry = file->f_path.dentry;
		struct inode *inode = dentry->d_inode;

		__entry->dev		= inode->i_sb->s_dev;
		__entry->ino		= inode->i_ino;
		__entry->parent		= dentry->d_parent->d_inode->i_ino;
		__entry->datasync	= datasync;
		__entry->ret		= ret;
	),

	TP_printk("dev = (%d,%d), ino = %lu, parent = %ld, "
		"datasync = %d, ret = %d",
		MAJOR(__entry->dev),
		MINOR(__entry->dev),
		(unsigned long)__entry->ino,
		(unsigned long)__entry->parent,
		__entry->datasync,
		__entry->ret)
);

TRACE_EVENT(ssdfs_unlink_enter,

	TP_PROTO(struct inode *dir, struct dentry *dentry),

	TP_ARGS(dir, dentry),

	TP_STRUCT__entry(
		__field(dev_t,	dev)
		__field(ino_t,	ino)
		__field(loff_t,	size)
		__field(blkcnt_t, blocks)
		__field(const char *,	name)
	),

	TP_fast_assign(
		__entry->dev	= dir->i_sb->s_dev;
		__entry->ino	= dir->i_ino;
		__entry->size	= dir->i_size;
		__entry->blocks	= dir->i_blocks;
		__entry->name	= dentry->d_name.name;
	),

	TP_printk("dev = (%d,%d), dir ino = %lu, i_size = %lld, "
		"i_blocks = %llu, name = %s",
		MAJOR(__entry->dev),
		MINOR(__entry->dev),
		(unsigned long)__entry->ino,
		__entry->size,
		(unsigned long long)__entry->blocks,
		__entry->name)
);

DEFINE_EVENT(ssdfs__inode_exit, ssdfs_unlink_exit,

	TP_PROTO(struct inode *inode, int ret),

	TP_ARGS(inode, ret)
);

#endif /* _TRACE_SSDFS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
