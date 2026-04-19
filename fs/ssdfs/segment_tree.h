/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_tree.h - segment tree declarations.
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

#ifndef _SSDFS_SEGMENT_TREE_H
#define _SSDFS_SEGMENT_TREE_H

/*
 * struct ssdfs_seg_object_info - segment object info
 * @list: segment objects queue list
 * @si: pointer on segment object
 */
struct ssdfs_seg_object_info {
	struct list_head list;
	struct ssdfs_segment_info *si;
};

/*
 * struct ssdfs_seg_objects_queue - segment objects queue descriptor
 * @lock: segment objects queue's lock
 * @list: segment objects queue's list
 */
struct ssdfs_seg_objects_queue {
	spinlock_t lock;
	struct list_head list;
};

/*
 * struct ssdfs_segment_tree - tree of segment objects
 * @lnodes_seg_log_pages: full log size in leaf nodes segment (pages count)
 * @hnodes_seg_log_pages: full log size in hybrid nodes segment (pages count)
 * @inodes_seg_log_pages: full log size in index nodes segment (pages count)
 * @user_data_log_pages: full log size in user data segment (pages count)
 * @default_log_pages: default full log size (pages count)
 * @dentries_btree: dentries b-tree descriptor
 * @extents_btree: extents b-tree descriptor
 * @xattr_btree: xattrs b-tree descriptor
 * @lock: xarray's lock for compound operations
 * @objects: xarray of segment object pointers indexed by seg_id
 * @segs_list_lock: spinlock protecting the global segments list
 * @segs_list: list of all created segment objects
 * @segs_count: count of segment objects currently in the list
 */
struct ssdfs_segment_tree {
	u16 lnodes_seg_log_pages;
	u16 hnodes_seg_log_pages;
	u16 inodes_seg_log_pages;
	u16 user_data_log_pages;
	u16 default_log_pages;

	struct ssdfs_dentries_btree_descriptor dentries_btree;
	struct ssdfs_extents_btree_descriptor extents_btree;
	struct ssdfs_xattr_btree_descriptor xattr_btree;

	struct rw_semaphore lock;
	struct xarray objects;

	spinlock_t segs_list_lock;
	struct list_head segs_list;
	u64 segs_count;
};

/*
 * Segment objects queue API
 */
void ssdfs_seg_objects_queue_init(struct ssdfs_seg_objects_queue *soq);
bool is_ssdfs_seg_objects_queue_empty(struct ssdfs_seg_objects_queue *soq);
void ssdfs_seg_objects_queue_add_tail(struct ssdfs_seg_objects_queue *soq,
				      struct ssdfs_seg_object_info *soi);
void ssdfs_seg_objects_queue_add_head(struct ssdfs_seg_objects_queue *soq,
				      struct ssdfs_seg_object_info *soi);
int ssdfs_seg_objects_queue_remove_first(struct ssdfs_seg_objects_queue *soq,
					 struct ssdfs_seg_object_info **soi);
void ssdfs_seg_objects_queue_remove_all(struct ssdfs_seg_objects_queue *soq);

/*
 * Segment object info's API
 */
void ssdfs_zero_seg_object_info_cache_ptr(void);
int ssdfs_init_seg_object_info_cache(void);
void ssdfs_shrink_seg_object_info_cache(void);
void ssdfs_destroy_seg_object_info_cache(void);

struct ssdfs_seg_object_info *ssdfs_seg_object_info_alloc(void);
void ssdfs_seg_object_info_free(struct ssdfs_seg_object_info *soi);
void ssdfs_seg_object_info_init(struct ssdfs_seg_object_info *soi,
				struct ssdfs_segment_info *si);

/*
 * Segments' tree API
 */
int ssdfs_segment_tree_create(struct ssdfs_fs_info *fsi);
void ssdfs_segment_tree_destroy(struct ssdfs_fs_info *fsi);
int ssdfs_segment_tree_add(struct ssdfs_fs_info *fsi,
			   struct ssdfs_segment_info *si);
int ssdfs_segment_tree_remove(struct ssdfs_fs_info *fsi,
			      struct ssdfs_segment_info *si);
struct ssdfs_segment_info *
ssdfs_segment_tree_find(struct ssdfs_fs_info *fsi, u64 seg_id);
u64 ssdfs_segment_tree_get_segs_count(struct ssdfs_fs_info *fsi);

#endif /* _SSDFS_SEGMENT_TREE_H */
