//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_tree.h - segment tree declarations.
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

#ifndef _SSDFS_SEGMENT_TREE_H
#define _SSDFS_SEGMENT_TREE_H

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
 * @pages: pages of segment tree
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

	struct address_space pages;
};

#define SSDFS_SEG_OBJ_PTR_PER_PAGE \
	(PAGE_SIZE / sizeof(struct ssdfs_segment_info *))

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

#endif /* _SSDFS_SEGMENT_TREE_H */
