//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/extents_queue.h - extents queue declarations.
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

#ifndef _SSDFS_EXTENTS_QUEUE_H
#define _SSDFS_EXTENTS_QUEUE_H

/*
 * struct ssdfs_extents_queue - extents queue descriptor
 * @lock: extents queue's lock
 * @list: extents queue's list
 */
struct ssdfs_extents_queue {
	spinlock_t lock;
	struct list_head list;
};

/*
 * struct ssdfs_extent_info - extent info
 * @list: extents queue list
 * @type: extent info type
 * @owner_ino: btree's owner inode id
 * @raw.extent: raw extent
 * @raw.index: raw index
 */
struct ssdfs_extent_info {
	struct list_head list;
	int type;
	u64 owner_ino;
	union {
		struct ssdfs_raw_extent extent;
		struct ssdfs_btree_index_key index;
	} raw;
};

/* Extent info existing types */
enum {
	SSDFS_EXTENT_INFO_UNKNOWN_TYPE,
	SSDFS_EXTENT_INFO_RAW_EXTENT,
	SSDFS_EXTENT_INFO_INDEX_DESCRIPTOR,
	SSDFS_EXTENT_INFO_DENTRY_INDEX_DESCRIPTOR,
	SSDFS_EXTENT_INFO_SHDICT_INDEX_DESCRIPTOR,
	SSDFS_EXTENT_INFO_XATTR_INDEX_DESCRIPTOR,
	SSDFS_EXTENT_INFO_TYPE_MAX
};

/*
 * Extents queue API
 */
void ssdfs_extents_queue_init(struct ssdfs_extents_queue *eq);
bool is_ssdfs_extents_queue_empty(struct ssdfs_extents_queue *eq);
void ssdfs_extents_queue_add_tail(struct ssdfs_extents_queue *eq,
				   struct ssdfs_extent_info *ei);
void ssdfs_extents_queue_add_head(struct ssdfs_extents_queue *eq,
				   struct ssdfs_extent_info *ei);
int ssdfs_extents_queue_remove_first(struct ssdfs_extents_queue *eq,
				      struct ssdfs_extent_info **ei);
void ssdfs_extents_queue_remove_all(struct ssdfs_extents_queue *eq);

/*
 * Extent info's API
 */
int ssdfs_init_extent_info_cache(void);
void ssdfs_destroy_extent_info_cache(void);

struct ssdfs_extent_info *ssdfs_extent_info_alloc(void);
void ssdfs_extent_info_free(struct ssdfs_extent_info *ei);
void ssdfs_extent_info_init(int type, void *ptr, u64 owner_ino,
			    struct ssdfs_extent_info *ei);

int ssdfs_invalidate_extent(struct ssdfs_fs_info *fsi,
			    struct ssdfs_raw_extent *extent);
int ssdfs_invalidate_extents_btree_index(struct ssdfs_fs_info *fsi,
					 u64 owner_ino,
					 struct ssdfs_btree_index_key *index);
int ssdfs_invalidate_dentries_btree_index(struct ssdfs_fs_info *fsi,
					  u64 owner_ino,
					  struct ssdfs_btree_index_key *index);
int ssdfs_invalidate_shared_dict_btree_index(struct ssdfs_fs_info *fsi,
					  u64 owner_ino,
					  struct ssdfs_btree_index_key *index);
int ssdfs_invalidate_xattrs_btree_index(struct ssdfs_fs_info *fsi,
					u64 owner_ino,
					struct ssdfs_btree_index_key *index);

#endif /* _SSDFS_EXTENTS_QUEUE_H */
