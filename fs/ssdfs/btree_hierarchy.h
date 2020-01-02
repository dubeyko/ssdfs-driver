//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/btree_hierarchy.h - btree hierarchy declarations.
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

#ifndef _SSDFS_BTREE_HIERARCHY_H
#define _SSDFS_BTREE_HIERARCHY_H

/*
 * struct ssdfs_hash_range - hash range
 * @start: start hash
 * @end: end hash
 */
struct ssdfs_hash_range {
	u64 start;
	u64 end;
};

/*
 * struct ssdfs_btree_node_position - node's position range
 * @state: intersection state
 * @start: starting node's position
 * @count: number of positions in the range
 */
struct ssdfs_btree_node_position {
	int state;
	u16 start;
	u16 count;
};

/* Intersection states */
enum {
	SSDFS_HASH_RANGE_INTERSECTION_UNDEFINED,
	SSDFS_HASH_RANGE_LEFT_ADJACENT,
	SSDFS_HASH_RANGE_INTERSECTION,
	SSDFS_HASH_RANGE_RIGHT_ADJACENT,
	SSDFS_HASH_RANGE_OUT_OF_NODE,
	SSDFS_HASH_RANGE_INTERSECTION_STATE_MAX
};

/*
 * struct ssdfs_btree_node_insert - insert position
 * @op_state: operation state
 * @hash: hash range of insertion
 * @pos: position descriptor
 */
struct ssdfs_btree_node_insert {
	int op_state;
	struct ssdfs_hash_range hash;
	struct ssdfs_btree_node_position pos;
};

/*
 * struct ssdfs_btree_node_move - moving range descriptor
 * @op_state: operation state
 * @direction: moving direction
 * @pos: position descriptor
 */
struct ssdfs_btree_node_move {
	int op_state;
	int direction;
	struct ssdfs_btree_node_position pos;
};

/*
 * struct ssdfs_btree_node_delete - deleting node's index descriptor
 * @op_state: operation state
 * @node_index: node index for deletion
 */
struct ssdfs_btree_node_delete {
	int op_state;
	struct ssdfs_btree_index_key node_index;
};

/* Possible operation states */
enum {
	SSDFS_BTREE_AREA_OP_UNKNOWN,
	SSDFS_BTREE_AREA_OP_REQUESTED,
	SSDFS_BTREE_AREA_OP_DONE,
	SSDFS_BTREE_AREA_OP_FAILED,
	SSDFS_BTREE_AREA_OP_STATE_MAX
};

/* Possible moving directions */
enum {
	SSDFS_BTREE_MOVE_NOWHERE,
	SSDFS_BTREE_MOVE_TO_PARENT,
	SSDFS_BTREE_MOVE_TO_CHILD,
	SSDFS_BTREE_MOVE_TO_LEFT,
	SSDFS_BTREE_MOVE_TO_RIGHT,
	SSDFS_BTREE_MOVE_DIRECTION_MAX
};

/* Btree level's flags */
#define SSDFS_BTREE_LEVEL_ADD_NODE		(1 << 0)
#define SSDFS_BTREE_LEVEL_ADD_INDEX		(1 << 1)
#define SSDFS_BTREE_LEVEL_UPDATE_INDEX		(1 << 2)
#define SSDFS_BTREE_LEVEL_ADD_ITEM		(1 << 3)
#define SSDFS_BTREE_INDEX_AREA_NEED_MOVE	(1 << 4)
#define SSDFS_BTREE_ITEMS_AREA_NEED_MOVE	(1 << 5)
#define SSDFS_BTREE_TRY_RESIZE_INDEX_AREA	(1 << 6)
#define SSDFS_BTREE_LEVEL_DELETE_NODE		(1 << 7)
#define SSDFS_BTREE_LEVEL_DELETE_INDEX		(1 << 8)
#define SSDFS_BTREE_LEVEL_FLAGS_MASK		0x1FF

#define SSDFS_BTREE_ADD_NODE_MASK \
	(SSDFS_BTREE_LEVEL_ADD_NODE | SSDFS_BTREE_LEVEL_ADD_INDEX | \
	 SSDFS_BTREE_LEVEL_UPDATE_INDEX | SSDFS_BTREE_LEVEL_ADD_ITEM | \
	 SSDFS_BTREE_INDEX_AREA_NEED_MOVE | \
	 SSDFS_BTREE_ITEMS_AREA_NEED_MOVE | \
	 SSDFS_BTREE_TRY_RESIZE_INDEX_AREA)

#define SSDFS_BTREE_DELETE_NODE_MASK \
	(SSDFS_BTREE_LEVEL_UPDATE_INDEX | SSDFS_BTREE_LEVEL_DELETE_NODE | \
	 SSDFS_BTREE_LEVEL_DELETE_INDEX)

/*
 * struct ssdfs_btree_level_node - node descriptor
 * @type: node's type
 * @ptr: pointer on node's object
 */
struct ssdfs_btree_level_node {
	int type;
	struct ssdfs_btree_node *ptr;
};

/*
 * struct ssdfs_btree_level_node_desc - descriptor of level's nodes
 * @old_node: old node of the level
 * @new_node: created empty node
 */
struct ssdfs_btree_level_node_desc {
	struct ssdfs_btree_level_node old_node;
	struct ssdfs_btree_level_node new_node;
};

/*
 * struct ssdfs_btree_level - btree level descriptor
 * @flags: level's flags
 * @index_area.area_size: size of the index area
 * @index_area.free_space: free space in index area
 * @index_area.hash: hash range of index area
 * @index_area.insert: insert position descriptor
 * @index_area.move: move range descriptor
 * @index_area.delete: delete index descriptor
 * @items_area.area_size: size of the items area
 * @items_area.free_space: free space in items area
 * @items_area.hash: hash range of items area
 * @items_area.insert: insert position descriptor
 * @items_area.move: move range descriptor
 * @nodes: descriptor of level's nodes
 */
struct ssdfs_btree_level {
	u32 flags;

	struct {
		u32 area_size;
		u32 free_space;
		struct ssdfs_hash_range hash;
		struct ssdfs_btree_node_insert insert;
		struct ssdfs_btree_node_move move;
		struct ssdfs_btree_node_delete delete;
	} index_area;

	struct {
		u32 area_size;
		u32 free_space;
		struct ssdfs_hash_range hash;
		struct ssdfs_btree_node_insert insert;
		struct ssdfs_btree_node_move move;
	} items_area;

	struct ssdfs_btree_level_node_desc nodes;
};

/*
 * struct ssdfs_btree_state_descriptor - btree's state descriptor
 * @height: btree height
 * @increment_height: request to increment tree's height
 * @node_size: size of the node in bytes
 * @index_size: size of the index record in bytes
 * @min_item_size: minimum item size in bytes
 * @max_item_size: maximum item size in bytes
 * @index_area_min_size: minimum size of index area in bytes
 */
struct ssdfs_btree_state_descriptor {
	int height;
	bool increment_height;
	u32 node_size;
	u16 index_size;
	u16 min_item_size;
	u16 max_item_size;
	u16 index_area_min_size;
};

/*
 * struct ssdfs_btree_hierarchy - btree's hierarchy descriptor
 * @desc: btree state's descriptor
 * @array: btree level's array
 */
struct ssdfs_btree_hierarchy {
	struct ssdfs_btree_state_descriptor desc;
	struct ssdfs_btree_level array[0];
};

/* Btree hierarchy inline methods */
static inline
bool need_add_node(struct ssdfs_btree_level *level)
{
	return level->flags & SSDFS_BTREE_LEVEL_ADD_NODE;
}

static inline
bool need_delete_node(struct ssdfs_btree_level *level)
{
	return level->flags & SSDFS_BTREE_LEVEL_DELETE_NODE;
}

/* Btree hierarchy API */
struct ssdfs_btree_hierarchy *
ssdfs_btree_hierarchy_allocate(struct ssdfs_btree *tree);
void ssdfs_btree_hierarchy_free(struct ssdfs_btree_hierarchy *hierarchy);

bool need_update_parent_index_area(u64 start_hash,
				   struct ssdfs_btree_node *parent);
int ssdfs_btree_check_hierarchy_for_add(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_hierarchy *ptr);
int ssdfs_btree_check_hierarchy_for_delete(struct ssdfs_btree *tree,
					struct ssdfs_btree_search *search,
					struct ssdfs_btree_hierarchy *ptr);
int ssdfs_btree_process_level_for_add(struct ssdfs_btree_hierarchy *ptr,
					int cur_height,
					struct ssdfs_btree_search *search);
int ssdfs_btree_process_level_for_delete(struct ssdfs_btree_hierarchy *ptr,
					 int cur_height,
					 struct ssdfs_btree_search *search);
int ssdfs_btree_check_hierarchy_for_update(struct ssdfs_btree *tree,
					   struct ssdfs_btree_search *search,
					   struct ssdfs_btree_hierarchy *ptr);
int ssdfs_btree_process_level_for_update(struct ssdfs_btree_hierarchy *ptr,
					 int cur_height,
					 struct ssdfs_btree_search *search);

/* Btree hierarchy internal API*/
void ssdfs_btree_prepare_add_node(struct ssdfs_btree *tree,
				  int node_type,
				  u64 start_hash, u64 end_hash,
				  struct ssdfs_btree_level *level,
				  struct ssdfs_btree_node *node);
int ssdfs_btree_prepare_add_index(struct ssdfs_btree_level *level,
				  u64 start_hash, u64 end_hash,
				  struct ssdfs_btree_node *node);

void ssdfs_debug_btree_hierarchy_object(struct ssdfs_btree_hierarchy *ptr);

#endif /* _SSDFS_BTREE_HIERARCHY_H */
