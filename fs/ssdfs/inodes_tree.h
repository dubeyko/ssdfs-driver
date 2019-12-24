//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/inodes_tree.h - inodes btree declarations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#ifndef _SSDFS_INODES_TREE_H
#define _SSDFS_INODES_TREE_H

/*
 * struct ssdfs_inodes_range - items range
 * @start_hash: starting hash
 * @start_index: staring index in the node
 * @count: count of items in the range
 */
struct ssdfs_inodes_range {
#define SSDFS_INODES_RANGE_INVALID_START	(U64_MAX)
	u64 start_hash;
#define SSDFS_INODES_RANGE_INVALID_INDEX	(U16_MAX)
	u16 start_index;
	u16 count;
};

/*
 * struct ssdfs_inodes_btree_range - node's items range descriptor
 * @list: free inode ranges queue
 * @node_id: node identification number
 * @area: items range
 */
struct ssdfs_inodes_btree_range {
	struct list_head list;
	u32 node_id;
	struct ssdfs_inodes_range area;
};

/*
 * struct ssdfs_free_inode_range_queue - free inode ranges queue
 * @lock: queue's lock
 * @list: queue's list
 */
struct ssdfs_free_inode_range_queue {
	spinlock_t lock;
	struct list_head list;
};

/*
 * struct ssdfs_inodes_btree_info - inodes btree info
 * @generic_tree: generic btree description
 * @lock: inodes btree lock
 * @root_folder: copy of root folder's inode
 * @upper_allocated_ino: maximal allocated inode ID number
 * @allocated_inodes: allocated inodes count in the whole tree
 * @free_inodes: free inodes count in the whole tree
 * @inodes_capacity: inodes capacity in the whole tree
 * @leaf_nodes: count of leaf nodes in the whole tree
 * @nodes_count: count of all nodes in the whole tree
 * @raw_inode_size: size in bytes of raw inode
 * @free_inodes_queue: queue of free inode descriptors
 */
struct ssdfs_inodes_btree_info {
	struct ssdfs_btree generic_tree;

	spinlock_t lock;
	struct ssdfs_inode root_folder;
	u64 upper_allocated_ino;
	u64 allocated_inodes;
	u64 free_inodes;
	u64 inodes_capacity;
	u32 leaf_nodes;
	u32 nodes_count;
	u16 raw_inode_size;

/*
 * Inodes btree should have special allocation queue.
 * If a btree nodes has free (not allocated) inodes
 * items then the information about such btree node
 * should be added into queue. Moreover, queue should
 * contain as so many node's descriptors as free items
 * in the node.
 *
 * If some btree node has deleted inodes (free items)
 * then all node's descriptors should be added into
 * the head of allocation queue. Descriptors of the last
 * btree's node should be added into tail of the queue.
 * Information about node's descriptors should be added
 * into the allocation queue during btree node creation
 * or reading from the volume. Otherwise, allocation of
 * new items should be done from last leaf btree's node.
 */
	struct ssdfs_free_inode_range_queue free_inodes_queue;
};

/*
 * Inline methods
 */
static inline
bool is_free_inodes_range_invalid(struct ssdfs_inodes_btree_range *range)
{
	bool is_invalid;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!range);
#endif /* CONFIG_SSDFS_DEBUG */

	is_invalid = range->node_id == SSDFS_BTREE_NODE_INVALID_ID ||
		range->area.start_hash == SSDFS_INODES_RANGE_INVALID_START ||
		range->area.start_index == SSDFS_INODES_RANGE_INVALID_INDEX ||
		range->area.count == 0;

	if (is_invalid) {
		SSDFS_ERR("node_id %u, start_hash %llx, "
			  "start_index %u, count %u\n",
			  range->node_id,
			  range->area.start_hash,
			  range->area.start_index,
			  range->area.count);
	}

	return is_invalid;
}

/*
 * Free inodes range API
 */
struct ssdfs_inodes_btree_range *ssdfs_free_inodes_range_alloc(void);
void ssdfs_free_inodes_range_free(struct ssdfs_inodes_btree_range *range);
void ssdfs_free_inodes_range_init(struct ssdfs_inodes_btree_range *range);

/*
 * Inodes btree API
 */
int ssdfs_inodes_btree_create(struct ssdfs_fs_info *fsi);
void ssdfs_inodes_btree_destroy(struct ssdfs_fs_info *fsi);
int ssdfs_inodes_btree_flush(struct ssdfs_inodes_btree_info *tree);

int ssdfs_inodes_btree_allocate(struct ssdfs_inodes_btree_info *tree,
				ino_t *ino,
				struct ssdfs_btree_search *search);
int ssdfs_inodes_btree_find(struct ssdfs_inodes_btree_info *tree,
			    ino_t ino,
			    struct ssdfs_btree_search *search);
int ssdfs_inodes_btree_change(struct ssdfs_inodes_btree_info *tree,
				ino_t ino,
				struct ssdfs_btree_search *search);
int ssdfs_inodes_btree_delete(struct ssdfs_inodes_btree_info *tree,
				ino_t ino);
int ssdfs_inodes_btree_delete_range(struct ssdfs_inodes_btree_info *tree,
				    ino_t ino, u16 count);

void ssdfs_debug_inodes_btree_object(struct ssdfs_inodes_btree_info *tree);

/*
 * Inodes btree specialized operations
 */
extern const struct ssdfs_btree_descriptor_operations
						ssdfs_inodes_btree_desc_ops;
extern const struct ssdfs_btree_operations ssdfs_inodes_btree_ops;
extern const struct ssdfs_btree_node_operations ssdfs_inodes_btree_node_ops;

#endif /* _SSDFS_INODES_TREE_H */
