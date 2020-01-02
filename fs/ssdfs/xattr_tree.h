//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/xattr_tree.h - extended attributes btree declarations.
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

#ifndef _SSDFS_XATTR_TREE_H
#define _SSDFS_XATTR_TREE_H

/*
 * struct ssdfs_xattrs_btree_info - xattrs btree info
 * @type: xattrs btree type
 * @state: xattrs btree state
 * @lock: xattrs btree lock
 * @generic_tree: pointer on generic btree object
 * @inline_xattrs: pointer on inline xattrs array
 * @inline_count: number of valid inline xattrs
 * @inline_capacity: capacity of xattrs in the inline array
 * @buffer.tree: piece of memory for generic btree object
 * @buffer.xattr: piece of memory for the inline xattr
 * @root: pointer on root node
 * @root_buffer: buffer for root node
 * @desc: b-tree descriptor
 * @owner: pointer on owner inode object
 * @fsi: pointer on shared file system object
 */
struct ssdfs_xattrs_btree_info {
	atomic_t type;
	atomic_t state;

	struct rw_semaphore lock;
	struct ssdfs_btree *generic_tree;
	struct ssdfs_xattr_entry *inline_xattrs;
	u16 inline_count;
	u16 inline_capacity;

	union {
		struct ssdfs_btree tree;
		struct ssdfs_xattr_entry xattr;
	} buffer;
	struct ssdfs_btree_inline_root_node *root;
	struct ssdfs_btree_inline_root_node root_buffer;

	struct ssdfs_xattr_btree_descriptor desc;
	struct ssdfs_inode_info *owner;
	struct ssdfs_fs_info *fsi;
};

/* Xattr tree types */
enum {
	SSDFS_XATTR_BTREE_UNKNOWN_TYPE,
	SSDFS_INLINE_XATTR,
	SSDFS_INLINE_XATTR_ARRAY,
	SSDFS_PRIVATE_XATTR_BTREE,
	SSDFS_XATTR_BTREE_TYPE_MAX
};

/* Xattr tree states */
enum {
	SSDFS_XATTR_BTREE_UNKNOWN_STATE,
	SSDFS_XATTR_BTREE_CREATED,
	SSDFS_XATTR_BTREE_INITIALIZED,
	SSDFS_XATTR_BTREE_DIRTY,
	SSDFS_XATTR_BTREE_CORRUPTED,
	SSDFS_XATTR_BTREE_STATE_MAX
};

/*
 * Xattr tree API
 */
int ssdfs_xattrs_tree_create(struct ssdfs_fs_info *fsi,
			    struct ssdfs_inode_info *ii);
int ssdfs_xattrs_tree_init(struct ssdfs_fs_info *fsi,
			  struct ssdfs_inode_info *ii);
void ssdfs_xattrs_tree_destroy(struct ssdfs_inode_info *ii);
int ssdfs_xattrs_tree_flush(struct ssdfs_fs_info *fsi,
			   struct ssdfs_inode_info *ii);

int ssdfs_xattrs_tree_find(struct ssdfs_xattrs_btree_info *tree,
			  const char *name, size_t len,
			  struct ssdfs_btree_search *search);
int ssdfs_xattrs_tree_add(struct ssdfs_xattrs_btree_info *tree,
			 const char *name, size_t name_len,
			 const void *value, size_t size,
			 struct ssdfs_inode_info *ii,
			 struct ssdfs_btree_search *search);
int ssdfs_xattrs_tree_change(struct ssdfs_xattrs_btree_info *tree,
			    u64 name_hash,
			    const char *name, size_t name_len,
			    const void *value, size_t size,
			    struct ssdfs_btree_search *search);
int ssdfs_xattrs_tree_delete(struct ssdfs_xattrs_btree_info *tree,
			    u64 name_hash,
			    struct ssdfs_btree_search *search);
int ssdfs_xattrs_tree_delete_all(struct ssdfs_xattrs_btree_info *tree);

/*
 * Xattr tree internal API
 */
int __ssdfs_xattrs_btree_node_get_xattr(struct pagevec *pvec,
					u32 area_offset,
					u32 area_size,
					u32 node_size,
					u16 item_index,
					struct ssdfs_xattr_entry *xattr);
int ssdfs_xattrs_tree_find_leaf_node(struct ssdfs_xattrs_btree_info *tree,
					u64 name_hash,
					struct ssdfs_btree_search *search);
int ssdfs_xattrs_tree_extract_range(struct ssdfs_xattrs_btree_info *tree,
				    u16 start_index, u16 count,
				    struct ssdfs_btree_search *search);

void ssdfs_debug_xattrs_btree_object(struct ssdfs_xattrs_btree_info *tree);

/*
 * Xattr btree specialized operations
 */
extern const struct ssdfs_btree_descriptor_operations
						ssdfs_xattrs_btree_desc_ops;
extern const struct ssdfs_btree_operations ssdfs_xattrs_btree_ops;
extern const struct ssdfs_btree_node_operations ssdfs_xattrs_btree_node_ops;

#endif /* _SSDFS_XATTR_TREE_H */
