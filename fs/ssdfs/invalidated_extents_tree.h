//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/invalidated_extents_tree.h - invalidated extents btree declarations.
 *
 * Copyright (c) 2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_INVALIDATED_EXTENTS_TREE_H
#define _SSDFS_INVALIDATED_EXTENTS_TREE_H

/*
 * struct ssdfs_invextree_info - invalidated extents tree object
 * @state: invalidated extents btree state
 * @lock: invalidated extents btree lock
 * @generic_tree: generic btree description
 * @extents_count: count of extents in the whole tree
 * @fsi: pointer on shared file system object
 */
struct ssdfs_invextree_info {
	atomic_t state;
	struct rw_semaphore lock;
	struct ssdfs_btree generic_tree;

	atomic64_t extents_count;

	struct ssdfs_fs_info *fsi;
};

/* Invalidated extents tree states */
enum {
	SSDFS_INVEXTREE_UNKNOWN_STATE,
	SSDFS_INVEXTREE_CREATED,
	SSDFS_INVEXTREE_INITIALIZED,
	SSDFS_INVEXTREE_DIRTY,
	SSDFS_INVEXTREE_CORRUPTED,
	SSDFS_INVEXTREE_STATE_MAX
};

/*
 * Invalidated extents tree API
 */
int ssdfs_invextree_create(struct ssdfs_fs_info *fsi);
void ssdfs_invextree_destroy(struct ssdfs_fs_info *fsi);
int ssdfs_invextree_flush(struct ssdfs_fs_info *fsi);

int ssdfs_invextree_find(struct ssdfs_invextree_info *tree,
			 struct ssdfs_raw_extent *extent,
			 struct ssdfs_btree_search *search);
int ssdfs_invextree_add(struct ssdfs_invextree_info *tree,
			struct ssdfs_raw_extent *extent,
			struct ssdfs_btree_search *search);
int ssdfs_invextree_delete(struct ssdfs_invextree_info *tree,
			   struct ssdfs_raw_extent *extent,
			   struct ssdfs_btree_search *search);

/*
 * Invalidated extents tree's internal API
 */
int ssdfs_invextree_find_leaf_node(struct ssdfs_invextree_info *tree,
				   u64 seg_id,
				   struct ssdfs_btree_search *search);
int ssdfs_invextree_get_start_hash(struct ssdfs_invextree_info *tree,
				   u64 *start_hash);
int ssdfs_invextree_node_hash_range(struct ssdfs_invextree_info *tree,
				    struct ssdfs_btree_search *search,
				    u64 *start_hash, u64 *end_hash,
				    u16 *items_count);
int ssdfs_invextree_extract_range(struct ssdfs_invextree_info *tree,
				  u16 start_index, u16 count,
				  struct ssdfs_btree_search *search);
int ssdfs_invextree_check_search_result(struct ssdfs_btree_search *search);
int ssdfs_invextree_get_next_hash(struct ssdfs_invextree_info *tree,
				  struct ssdfs_btree_search *search,
				  u64 *next_hash);

void ssdfs_debug_invextree_object(struct ssdfs_invextree_info *tree);

/*
 * Invalidated extents btree specialized operations
 */
extern const struct ssdfs_btree_descriptor_operations ssdfs_invextree_desc_ops;
extern const struct ssdfs_btree_operations ssdfs_invextree_ops;
extern const struct ssdfs_btree_node_operations ssdfs_invextree_node_ops;

#endif /* _SSDFS_INVALIDATED_EXTENTS_TREE_H */
