//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/shared_extents_tree.h - shared extents tree declarations.
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

#ifndef _SSDFS_SHARED_EXTENTS_TREE_H
#define _SSDFS_SHARED_EXTENTS_TREE_H

/*
 * struct ssdfs_invalidation_queue - invalidation queue object
 * @queue: extents/index queue object
 * @thread: descriptor of queue's thread
 */
struct ssdfs_invalidation_queue {
	struct ssdfs_extents_queue queue;
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
 * @array: invalidation queues array
 * @wait_queue: wait queue of shared extents tree's thread
 * @fsi: pointer on shared file system object
 */
struct ssdfs_shared_extents_tree {
	struct ssdfs_invalidation_queue array[SSDFS_INVALIDATION_QUEUE_NUMBER];
	wait_queue_head_t wait_queue;

	struct ssdfs_fs_info *fsi;
};

/*
 * Shared extents tree API
 */
int ssdfs_shextree_create(struct ssdfs_fs_info *fsi);
void ssdfs_shextree_destroy(struct ssdfs_fs_info *fsi);

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

#endif /* _SSDFS_SHARED_EXTENTS_TREE_H */
