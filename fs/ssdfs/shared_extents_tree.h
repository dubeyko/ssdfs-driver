/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/shared_extents_tree.h - shared extents tree declarations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2025 Viacheslav Dubeyko <slava@dubeyko.com>
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

#ifndef _SSDFS_SHARED_EXTENTS_TREE_H
#define _SSDFS_SHARED_EXTENTS_TREE_H

#include "fingerprint.h"

/*
 * struct ssdfs_invalidation_queue - invalidation queue object
 * @queue: extents/index queue object
 * @content: btree node's content buffer
 * @thread: descriptor of queue's thread
 */
struct ssdfs_invalidation_queue {
	struct ssdfs_extents_queue queue;
	struct ssdfs_btree_node_content content;
	struct ssdfs_thread_info thread;
};

/* Invalidation queue ID */
enum {
	SSDFS_EXTENT_INVALIDATION_QUEUE,
	SSDFS_INDEX_INVALIDATION_QUEUE,
	SSDFS_INVALIDATION_QUEUE_NUMBER
};

/*
 * struct ssdfs_shared_extents_tree - shared extents tree object
 * @state: shared extents btree state
 * @lock: shared extents btree lock
 * @generic_tree: generic btree description
 * @shared_extents: count of the shared extents in the whole tree
 * @array: invalidation queues array
 * @wait_queue: wait queue of shared extents tree's thread
 * @fsi: pointer on shared file system object
 */
struct ssdfs_shared_extents_tree {
	atomic_t state;
	struct rw_semaphore lock;
	struct ssdfs_btree generic_tree;

	atomic64_t shared_extents;

	struct ssdfs_invalidation_queue array[SSDFS_INVALIDATION_QUEUE_NUMBER];
	wait_queue_head_t wait_queue;

	struct ssdfs_fs_info *fsi;
};

/* Shared extents tree states */
enum {
	SSDFS_SHEXTREE_UNKNOWN_STATE,
	SSDFS_SHEXTREE_CREATED,
	SSDFS_SHEXTREE_INITIALIZED,
	SSDFS_SHEXTREE_DIRTY,
	SSDFS_SHEXTREE_CORRUPTED,
	SSDFS_SHEXTREE_STATE_MAX
};

#define SSDFS_SHARED_EXT(ptr) \
	((struct ssdfs_shared_extent *)(ptr))

/*
 * Shared extents tree API
 */
int ssdfs_shextree_create(struct ssdfs_fs_info *fsi);
void ssdfs_shextree_destroy(struct ssdfs_fs_info *fsi);
int ssdfs_shextree_flush(struct ssdfs_fs_info *fsi);

int ssdfs_shextree_find(struct ssdfs_shared_extents_tree *tree,
			struct ssdfs_fingerprint *fingerprint,
			struct ssdfs_btree_search *search);
int ssdfs_shextree_find_range(struct ssdfs_shared_extents_tree *tree,
			      struct ssdfs_fingerprint_range *range,
			      struct ssdfs_btree_search *search);
int ssdfs_shextree_find_leaf_node(struct ssdfs_shared_extents_tree *tree,
				  struct ssdfs_fingerprint *fingerprint,
				  struct ssdfs_btree_search *search);
int ssdfs_shextree_add(struct ssdfs_shared_extents_tree *tree,
			struct ssdfs_fingerprint *fingerprint,
			struct ssdfs_shared_extent *extent,
			struct ssdfs_btree_search *search);
int ssdfs_shextree_change(struct ssdfs_shared_extents_tree *tree,
			  struct ssdfs_fingerprint *fingerprint,
			  struct ssdfs_shared_extent *extent,
			  struct ssdfs_btree_search *search);
int ssdfs_shextree_ref_count_inc(struct ssdfs_shared_extents_tree *tree,
				 struct ssdfs_fingerprint *fingerprint,
				 struct ssdfs_btree_search *search);
int ssdfs_shextree_ref_count_dec(struct ssdfs_shared_extents_tree *tree,
				 struct ssdfs_fingerprint *fingerprint,
				 struct ssdfs_btree_search *search);
int ssdfs_shextree_delete(struct ssdfs_shared_extents_tree *tree,
			  struct ssdfs_fingerprint *fingerprint,
			  struct ssdfs_btree_search *search);
int ssdfs_shextree_delete_all(struct ssdfs_shared_extents_tree *tree);

int ssdfs_shextree_add_pre_invalid_extent(struct ssdfs_shared_extents_tree *tree,
					  u64 owner_ino,
					  struct ssdfs_raw_extent *extent);
int ssdfs_shextree_add_pre_invalid_fork(struct ssdfs_shared_extents_tree *tree,
					u64 owner_ino,
					struct ssdfs_raw_fork *fork);
int ssdfs_shextree_add_pre_invalid_index(struct ssdfs_shared_extents_tree *tree,
					 u64 owner_ino,
					 int index_type,
					 struct ssdfs_btree_index_key *index);

/*
 * Shared extents tree's internal API
 */
int ssdfs_shextree_start_thread(struct ssdfs_shared_extents_tree *tree,
				int index);
int ssdfs_shextree_stop_thread(struct ssdfs_shared_extents_tree *tree,
				int index);

void ssdfs_debug_shextree_object(struct ssdfs_shared_extents_tree *tree);

/*
 * Shared extents btree specialized operations
 */
extern const struct ssdfs_btree_descriptor_operations ssdfs_shextree_desc_ops;
extern const struct ssdfs_btree_operations ssdfs_shextree_ops;
extern const struct ssdfs_btree_node_operations ssdfs_shextree_node_ops;

#endif /* _SSDFS_SHARED_EXTENTS_TREE_H */
