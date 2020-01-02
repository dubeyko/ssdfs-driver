//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/btree.h - btree declarations.
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

#ifndef _SSDFS_BTREE_H
#define _SSDFS_BTREE_H

struct ssdfs_btree;

/*
 * struct ssdfs_btree_descriptor_operations - btree descriptor operations
 * @init: initialize btree object by descriptor
 * @flush: save btree descriptor into superblock
 */
struct ssdfs_btree_descriptor_operations {
	int (*init)(struct ssdfs_fs_info *fsi,
		    struct ssdfs_btree *tree);
	int (*flush)(struct ssdfs_btree *tree);
};

/*
 * struct ssdfs_btree_operations - btree operations specialization
 * @create_root_node: specialization of root node creation
 * @create_node: specialization of node's construction operation
 * @init_node: specialization of node's init operation
 * @destroy_node: specialization of node's destroy operation
 * @add_node: specialization of adding into the tree a new empty node
 * @delete_node: specialization of deletion a node from the tree
 * @pre_flush_root_node: specialized flush preparation of root node
 * @flush_root_node: specialized method of root node flushing
 * @pre_flush_node: specialized flush preparation of common node
 * @flush_node: specialized method of common node flushing
 */
struct ssdfs_btree_operations {
	int (*create_root_node)(struct ssdfs_fs_info *fsi,
				struct ssdfs_btree_node *node);
	int (*create_node)(struct ssdfs_btree_node *node);
	int (*init_node)(struct ssdfs_btree_node *node);
	void (*destroy_node)(struct ssdfs_btree_node *node);
	int (*add_node)(struct ssdfs_btree_node *node);
	int (*delete_node)(struct ssdfs_btree_node *node);
	int (*pre_flush_root_node)(struct ssdfs_btree_node *node);
	int (*flush_root_node)(struct ssdfs_btree_node *node);
	int (*pre_flush_node)(struct ssdfs_btree_node *node);
	int (*flush_node)(struct ssdfs_btree_node *node);
};

/*
 * struct ssdfs_btree - generic btree
 * @type: btree type
 * @owner_ino: inode identification number of btree owner
 * @node_size: size of the node in bytes
 * @pages_per_node: physical pages per node
 * @node_ptr_size: size in bytes of pointer on btree node
 * @index_size: size in bytes of btree's index
 * @item_size: default size of item in bytes
 * @min_item_size: min size of item in bytes
 * @max_item_size: max possible size of item in bytes
 * @index_area_min_size: minimal size in bytes of index area in btree node
 * @create_cno: btree's create checkpoint
 * @state: btree state
 * @flags: btree flags
 * @height: current height of the tree
 * @lock: btree's lock
 * @nodes_lock: radix tree lock
 * @upper_node_id: last allocated node id
 * @nodes: nodes' radix tree
 * @fsi: pointer on shared file system object
 *
 * Btree nodes are organized by radix tree.
 * Another good point about radix tree is
 * supporting of knowledge about dirty items.
 */
struct ssdfs_btree {
	/* static data */
	u8 type;
	u64 owner_ino;
	u32 node_size;
	u8 pages_per_node;
	u8 node_ptr_size;
	u16 index_size;
	u16 item_size;
	u8 min_item_size;
	u16 max_item_size;
	u16 index_area_min_size;
	u64 create_cno;

	/* operation specializations */
	const struct ssdfs_btree_descriptor_operations *desc_ops;
	const struct ssdfs_btree_operations *btree_ops;

	/* mutable data */
	atomic_t state;
	atomic_t flags;
	atomic_t height;

	struct rw_semaphore lock;

	spinlock_t nodes_lock;
	u32 upper_node_id;
	struct radix_tree_root nodes;

	struct ssdfs_fs_info *fsi;
};

/* Btree object states */
enum {
	SSDFS_BTREE_UNKNOWN_STATE,
	SSDFS_BTREE_CREATED,
	SSDFS_BTREE_DIRTY,
	SSDFS_BTREE_STATE_MAX
};

/* Radix tree tags */
#define SSDFS_BTREE_NODE_DIRTY_TAG	PAGECACHE_TAG_DIRTY
#define SSDFS_BTREE_NODE_TOWRITE_TAG	PAGECACHE_TAG_TOWRITE

/*
 * Btree API
 */
int ssdfs_btree_create(struct ssdfs_fs_info *fsi,
		    u64 owner_ino,
		    const struct ssdfs_btree_descriptor_operations *desc_ops,
		    const struct ssdfs_btree_operations *btree_ops,
		    struct ssdfs_btree *tree);
void ssdfs_btree_destroy(struct ssdfs_btree *tree);
int ssdfs_btree_flush(struct ssdfs_btree *tree);

int ssdfs_btree_find_item(struct ssdfs_btree *tree,
			  struct ssdfs_btree_search *search);
int ssdfs_btree_find_range(struct ssdfs_btree *tree,
			   struct ssdfs_btree_search *search);
bool is_ssdfs_btree_empty(struct ssdfs_btree *tree);
int ssdfs_btree_allocate_item(struct ssdfs_btree *tree,
			      struct ssdfs_btree_search *search);
int ssdfs_btree_allocate_range(struct ssdfs_btree *tree,
				struct ssdfs_btree_search *search);
int ssdfs_btree_add_item(struct ssdfs_btree *tree,
			 struct ssdfs_btree_search *search);
int ssdfs_btree_add_range(struct ssdfs_btree *tree,
			  struct ssdfs_btree_search *search);
int ssdfs_btree_change_item(struct ssdfs_btree *tree,
			    struct ssdfs_btree_search *search);
int ssdfs_btree_delete_item(struct ssdfs_btree *tree,
			    struct ssdfs_btree_search *search);
int ssdfs_btree_delete_range(struct ssdfs_btree *tree,
			     struct ssdfs_btree_search *search);
int ssdfs_btree_delete_all(struct ssdfs_btree *tree);

/*
 * Internal Btree API
 */
int ssdfs_btree_desc_init(struct ssdfs_fs_info *fsi,
			  struct ssdfs_btree *tree,
			  struct ssdfs_btree_descriptor *desc,
			  u8 min_item_size,
			  u16 max_item_size);
int ssdfs_btree_desc_flush(struct ssdfs_btree *tree,
			   struct ssdfs_btree_descriptor *desc);
struct ssdfs_btree_node *
ssdfs_btree_get_child_node_for_hash(struct ssdfs_btree *tree,
				    struct ssdfs_btree_node *parent,
				    u64 hash);
int ssdfs_btree_add_node(struct ssdfs_btree *tree,
			 struct ssdfs_btree_search *search);
int ssdfs_btree_insert_node(struct ssdfs_btree *tree,
			    struct ssdfs_btree_search *search);
int ssdfs_btree_delete_node(struct ssdfs_btree *tree,
			    struct ssdfs_btree_search *search);
int ssdfs_btree_get_head_range(struct ssdfs_btree *tree,
				u32 expected_len,
				struct ssdfs_btree_search *search);
int ssdfs_btree_extract_range(struct ssdfs_btree *tree,
				u16 start_index, u16 count,
				struct ssdfs_btree_search *search);
int ssdfs_btree_destroy_node_range(struct ssdfs_btree *tree,
				   u64 start_hash);
int ssdfs_btree_radix_tree_find(struct ssdfs_btree *tree,
				unsigned long node_id,
				struct ssdfs_btree_node **node);
int ssdfs_btree_synchronize_root_node(struct ssdfs_btree *tree,
				struct ssdfs_btree_inline_root_node *root);

void ssdfs_debug_btree_object(struct ssdfs_btree *tree);

#endif /* _SSDFS_BTREE_H */
