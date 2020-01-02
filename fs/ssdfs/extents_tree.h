//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/extents_tree.h - extents tree declarations.
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

#ifndef _SSDFS_EXTENTS_TREE_H
#define _SSDFS_EXTENTS_TREE_H

/*
 * struct ssdfs_extents_btree_info - extents btree info
 * @type: extents btree type
 * @state: extents btree state
 * @forks_count: count of the forks in the whole extents tree
 * @lock: extents btree lock
 * @generic_tree: pointer on generic btree object
 * @inline_forks: pointer on inline forks array
 * @buffer.tree: piece of memory for generic btree object
 * @buffer.forks: piece of memory for the inline forks
 * @root: pointer on root node
 * @root_buffer: buffer for root node
 * @desc: b-tree descriptor
 * @owner: pointer on owner inode object
 * @fsi: pointer on shared file system object
 *
 * A newly created inode tries to store extents into inline
 * forks. Every fork contains three extents. The raw on-disk
 * inode has internal private area that is able to contain the
 * two inline forks or root node of extents btree and extended
 * attributes btree. If inode hasn't extended attributes and
 * the amount of extents are lesser than six then everithing
 * can be stored inside of inline forks. Otherwise, the real
 * extents btree should be created.
 */
struct ssdfs_extents_btree_info {
	atomic_t type;
	atomic_t state;
	atomic64_t forks_count;

	struct rw_semaphore lock;
	struct ssdfs_btree *generic_tree;
	struct ssdfs_raw_fork *inline_forks;
	union {
		struct ssdfs_btree tree;
		struct ssdfs_raw_fork forks[SSDFS_INLINE_FORKS_COUNT];
	} buffer;
	struct ssdfs_btree_inline_root_node *root;
	struct ssdfs_btree_inline_root_node root_buffer;

	struct ssdfs_extents_btree_descriptor desc;
	struct ssdfs_inode_info *owner;
	struct ssdfs_fs_info *fsi;
};

/* Extents tree types */
enum {
	SSDFS_EXTENTS_BTREE_UNKNOWN_TYPE,
	SSDFS_INLINE_FORKS_ARRAY,
	SSDFS_PRIVATE_EXTENTS_BTREE,
	SSDFS_EXTENTS_BTREE_TYPE_MAX
};

/* Extents tree states */
enum {
	SSDFS_EXTENTS_BTREE_UNKNOWN_STATE,
	SSDFS_EXTENTS_BTREE_CREATED,
	SSDFS_EXTENTS_BTREE_INITIALIZED,
	SSDFS_EXTENTS_BTREE_DIRTY,
	SSDFS_EXTENTS_BTREE_CORRUPTED,
	SSDFS_EXTENTS_BTREE_STATE_MAX
};

/*
 * Extents tree API
 */
int ssdfs_extents_tree_create(struct ssdfs_fs_info *fsi,
				struct ssdfs_inode_info *ii);
int ssdfs_extents_tree_init(struct ssdfs_fs_info *fsi,
			    struct ssdfs_inode_info *ii);
void ssdfs_extents_tree_destroy(struct ssdfs_inode_info *ii);
int ssdfs_extents_tree_flush(struct ssdfs_fs_info *fsi,
			     struct ssdfs_inode_info *ii);

int ssdfs_prepare_volume_extent(struct ssdfs_fs_info *fsi,
				struct ssdfs_segment_request *req);
bool ssdfs_extents_tree_has_logical_block(u64 blk_offset, struct inode *inode);
int ssdfs_extents_tree_add_block(struct inode *inode,
				 struct ssdfs_segment_request *req);
int ssdfs_extents_tree_truncate(struct inode *inode);

/*
 * Extents tree internal API
 */
int ssdfs_extents_tree_find_fork(struct ssdfs_extents_btree_info *tree,
				 u64 blk,
				 struct ssdfs_btree_search *search);
int ssdfs_extents_tree_add_extent(struct ssdfs_extents_btree_info *tree,
				  u64 blk,
				  struct ssdfs_raw_extent *extent,
				  struct ssdfs_btree_search *search);
int ssdfs_extents_tree_change_extent(struct ssdfs_extents_btree_info *tree,
				     u64 blk,
				     struct ssdfs_raw_extent *extent,
				     struct ssdfs_btree_search *search);
int ssdfs_extents_tree_truncate_extent(struct ssdfs_extents_btree_info *tree,
					u64 blk, u32 new_len,
					struct ssdfs_btree_search *search);
int ssdfs_extents_tree_delete_extent(struct ssdfs_extents_btree_info *tree,
				     u64 blk,
				     struct ssdfs_btree_search *search);
int ssdfs_extents_tree_delete_all(struct ssdfs_extents_btree_info *tree);
int __ssdfs_extents_btree_node_get_fork(struct pagevec *pvec,
					u32 area_offset,
					u32 area_size,
					u32 node_size,
					u16 item_index,
					struct ssdfs_raw_fork *fork);

void ssdfs_debug_extents_btree_object(struct ssdfs_extents_btree_info *tree);

/*
 * Extents btree specialized operations
 */
extern const struct ssdfs_btree_descriptor_operations
						ssdfs_extents_btree_desc_ops;
extern const struct ssdfs_btree_operations ssdfs_extents_btree_ops;
extern const struct ssdfs_btree_node_operations ssdfs_extents_btree_node_ops;

#endif /* _SSDFS_EXTENTS_TREE_H */
