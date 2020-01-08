//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/btree_node.h - btree node declarations.
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

#ifndef _SSDFS_BTREE_NODE_H
#define _SSDFS_BTREE_NODE_H

#include "request_queue.h"

/*
 * struct ssdfs_btree_node_operations - node operations specialization
 * @find_item: specialized item searching algorithm
 * @find_range: specialized range searching algorithm
 * @extract_range: specialized extract range operation
 * @allocate_item: specialized item allocation operation
 * @allocate_range: specialized range allocation operation
 * @insert_item: specialized insert item operation
 * @insert_range: specialized insert range operation
 * @change_item: specialized change item operation
 * @delete_item: specialized delete item operation
 * @delete_range: specialized delete range operation
 * @move_items_range: specialized move items operation
 * @resize_items_area: specialized resize items area operation
 */
struct ssdfs_btree_node_operations {
	int (*find_item)(struct ssdfs_btree_node *node,
			 struct ssdfs_btree_search *search);
	int (*find_range)(struct ssdfs_btree_node *node,
			  struct ssdfs_btree_search *search);
	int (*extract_range)(struct ssdfs_btree_node *node,
			     u16 start_index, u16 count,
			     struct ssdfs_btree_search *search);
	int (*allocate_item)(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_search *search);
	int (*allocate_range)(struct ssdfs_btree_node *node,
			      struct ssdfs_btree_search *search);
	int (*insert_item)(struct ssdfs_btree_node *node,
			   struct ssdfs_btree_search *search);
	int (*insert_range)(struct ssdfs_btree_node *node,
			    struct ssdfs_btree_search *search);
	int (*change_item)(struct ssdfs_btree_node *node,
			   struct ssdfs_btree_search *search);
	int (*delete_item)(struct ssdfs_btree_node *node,
			   struct ssdfs_btree_search *search);
	int (*delete_range)(struct ssdfs_btree_node *node,
			    struct ssdfs_btree_search *search);
	int (*move_items_range)(struct ssdfs_btree_node *src,
				struct ssdfs_btree_node *dst,
				u16 start_item, u16 count);
	int (*resize_items_area)(struct ssdfs_btree_node *node,
				 u32 new_size);
};

/* Btree node area's states */
enum {
	SSDFS_BTREE_NODE_AREA_UNKNOWN_STATE,
	SSDFS_BTREE_NODE_AREA_ABSENT,
	SSDFS_BTREE_NODE_INDEX_AREA_EXIST,
	SSDFS_BTREE_NODE_ITEMS_AREA_EXIST,
	SSDFS_BTREE_NODE_LOOKUP_TBL_EXIST,
	SSDFS_BTREE_NODE_HASH_TBL_EXIST,
	SSDFS_BTREE_NODE_AREA_STATE_MAX
};

/*
 * struct ssdfs_btree_node_index_area - btree node's index area
 * @state: area state
 * @offset: area offset from node's beginning
 * @area_size: area size in bytes
 * @index_size: index size in bytes
 * @index_count: count of indexes in area
 * @index_capacity: index area capacity
 * @start_hash: starting hash in index area
 * @end_hash: ending hash in index area
 */
struct ssdfs_btree_node_index_area {
	atomic_t state;

	u32 offset;
	u32 area_size;

	u8 index_size;
	u16 index_count;
	u16 index_capacity;

	u64 start_hash;
	u64 end_hash;
};

/*
 * struct ssdfs_btree_node_items_area - btree node's data area
 * @state: area state
 * @offset: area offset from node's beginning
 * @area_size: area size in bytes
 * @free_space: free space in bytes
 * @item_size: item size in bytes
 * @min_item_size: minimal possible item size in bytes
 * @max_item_size: maximal possible item size in bytes
 * @items_count: count of allocated items in area
 * @items_capacity: items area capacity
 * @start_hash: starting hash in items area
 * @end_hash: ending hash in items area
 */
struct ssdfs_btree_node_items_area {
	atomic_t state;

	u32 offset;
	u32 area_size;
	u32 free_space;

	u16 item_size;
	u8 min_item_size;
	u16 max_item_size;

	u16 items_count;
	u16 items_capacity;

	u64 start_hash;
	u64 end_hash;
};

struct ssdfs_btree;

/*
 * struct ssdfs_state_bitmap - bitmap of states
 * @lock: bitmap lock
 * @flags: bitmap's flags
 * @ptr: bitmap
 */
struct ssdfs_state_bitmap {
	spinlock_t lock;

#define SSDFS_LOOKUP_TBL2_IS_USING	(1 << 0)
#define SSDFS_HASH_TBL_IS_USING		(1 << 1)
#define SSDFS_BMAP_ARRAY_FLAGS_MASK	0x3
	u32 flags;

	unsigned long *ptr;
};

/*
 * struct ssdfs_state_bitmap_array - array of bitmaps
 * @lock: bitmap array lock
 * @bits_count: whole bits count in the bitmap
 * @bmap_bytes: size in bytes of every bitmap
 * @index_start_bit: starting bit of index area in the bitmap
 * @item_start_bit: starting bit of items area in the bitmap
 * @bmap: partial locks, alloc and dirty bitmaps
 */
struct ssdfs_state_bitmap_array {
	struct rw_semaphore lock;
	unsigned long bits_count;
	size_t bmap_bytes;
	unsigned long index_start_bit;
	unsigned long item_start_bit;

#define SSDFS_BTREE_NODE_LOCK_BMAP	(0)
#define SSDFS_BTREE_NODE_ALLOC_BMAP	(1)
#define SSDFS_BTREE_NODE_DIRTY_BMAP	(2)
#define SSDFS_BTREE_NODE_BMAP_COUNT	(3)
	struct ssdfs_state_bitmap bmap[SSDFS_BTREE_NODE_BMAP_COUNT];
};

/*
 * union ssdfs_btree_node_content - btree node's content
 * @pvec: page vector
 */
struct ssdfs_btree_node_content {
	struct pagevec pvec;
};

/*
 * struct ssdfs_btree_node - btree node
 * @height: node's height
 * @node_size: node size in bytes
 * @pages_per_node: count of memory pages per node
 * @create_cno: create checkpoint
 * @node_id: node identification number
 * @parent_node: pointer on parent node
 * @tree: pointer on node's parent tree
 * @node_ops: btree's node operation specialization
 * @refs_count: reference counter
 * @state: node state
 * @flags: node's flags
 * @type: node type
 * @header_lock: header lock
 * @raw.root_node: root node copy
 * @raw.generic_header: generic node's header
 * @raw.inodes_header: inodes node's header
 * @raw.dentries_header: dentries node's header
 * @raw.extents_header: extents node's header
 * @raw.dict_header: shared dictionary node's header
 * @raw.xattrs_header: xattrs node's header
 * @index_area: index area descriptor
 * @items_area: items area descriptor
 * @lookup_tbl_area: lookup table's area descriptor
 * @hash_tbl_area: hash table's area descriptor
 * @descriptor_lock: node's descriptor lock
 * @update_cno: last update checkpoint
 * @node_index: node's index (for using in search operations)
 * @extent: node's location
 * @seg: pointer on segment object
 * @init_end: wait of init ending
 * @flush_req: flush request
 * @bmap_array: partial locks, alloc and dirty bitmaps
 * @wait_queue: queue of threads are waiting partial lock
 * @full_lock: the whole node lock
 * @content: node's content
 */
struct ssdfs_btree_node {
	/* static data */
	atomic_t height;
	u32 node_size;
	u8 pages_per_node;
	u64 create_cno;
	u32 node_id;

	struct ssdfs_btree_node *parent_node;
	struct ssdfs_btree *tree;

	/* btree's node operation specialization */
	const struct ssdfs_btree_node_operations *node_ops;

	/*
	 * Reference counter
	 * The goal of reference counter is to account how
	 * many btree search objects are referencing the
	 * node's object. If some thread deletes all records
	 * in a node then the node will be left undeleted
	 * from the tree in the case of @refs_count is greater
	 * than one.
	 */
	atomic_t refs_count;

	/* mutable data */
	atomic_t state;
	atomic_t flags;
	atomic_t type;

	/* node's header */
	struct rw_semaphore header_lock;
	union {
		struct ssdfs_btree_inline_root_node root_node;
		struct ssdfs_btree_node_header generic_header;
		struct ssdfs_inodes_btree_node_header inodes_header;
		struct ssdfs_dentries_btree_node_header dentries_header;
		struct ssdfs_extents_btree_node_header extents_header;
		struct ssdfs_shared_dictionary_node_header dict_header;
		struct ssdfs_xattrs_btree_node_header xattrs_header;
	} raw;
	struct ssdfs_btree_node_index_area index_area;
	struct ssdfs_btree_node_items_area items_area;
	struct ssdfs_btree_node_index_area lookup_tbl_area;
	struct ssdfs_btree_node_index_area hash_tbl_area;

	/* node's descriptor */
	spinlock_t descriptor_lock;
	u64 update_cno;
	struct ssdfs_btree_index_key node_index;
	struct ssdfs_raw_extent extent;
	struct ssdfs_segment_info *seg;
	struct completion init_end;
	struct ssdfs_segment_request flush_req;

	/* partial locks, alloc and dirty bitmaps */
	struct ssdfs_state_bitmap_array bmap_array;
	wait_queue_head_t wait_queue;

	/* node raw content */
	struct rw_semaphore full_lock;
	struct ssdfs_btree_node_content content;
};

/* Btree node states */
enum {
	SSDFS_BTREE_NODE_UNKNOWN_STATE,
	SSDFS_BTREE_NODE_CREATED,
	SSDFS_BTREE_NODE_CONTENT_PREPARED,
	SSDFS_BTREE_NODE_INITIALIZED,
	SSDFS_BTREE_NODE_DIRTY,
	SSDFS_BTREE_NODE_INVALID,
	SSDFS_BTREE_NODE_CORRUPTED,
	SSDFS_BTREE_NODE_STATE_MAX
};

/*
 * TODO: it is possible to use knowledge about partial
 *       updates and to send only changed pieces of
 *       data for the case of Diff-On-Write approach.
 *       Metadata is good case for determination of
 *       partial updates and to send changed part(s)
 *       only. For example, bitmap could show dirty
 *       items in the node.
 */

/*
 * Inline functions
 */

/*
 * NODE2SEG_TYPE() - convert node type into segment type
 * @node_type: node type
 */
static inline
u8 NODE2SEG_TYPE(u8 node_type)
{
	switch (node_type) {
	case SSDFS_BTREE_INDEX_NODE:
		return SSDFS_INDEX_NODE_SEG_TYPE;

	case SSDFS_BTREE_HYBRID_NODE:
		return SSDFS_HYBRID_NODE_SEG_TYPE;

	case SSDFS_BTREE_LEAF_NODE:
		return SSDFS_LEAF_NODE_SEG_TYPE;
	}

	SSDFS_WARN("invalid node type %#x\n", node_type);

	return SSDFS_UNKNOWN_SEG_TYPE;
}

/*
 * RANGE_WITHOUT_INTERSECTION() - check that ranges have intersection
 * @start1: starting hash of the first range
 * @end1: ending hash of the first range
 * @start2: starting hash of the second range
 * @end2: ending hash of the second range
 *
 * This method checks that ranges have intersection.
 *
 * RETURN:
 *  0  - ranges have intersection
 *  1  - range1 > range2
 * -1  - range1 < range2
 */
static inline
int RANGE_WITHOUT_INTERSECTION(u64 start1, u64 end1, u64 start2, u64 end2)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(start1 >= U64_MAX || end1 >= U64_MAX ||
		start2 >= U64_MAX || end2 >= U64_MAX);
	BUG_ON(start1 > end1);
	BUG_ON(start2 > end2);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start1 > end2)
		return 1;

	if (end1 < start2)
		return -1;

	return 0;
}

/*
 * RANGE_HAS_PARTIAL_INTERSECTION() - check that ranges intersect partially
 * @start1: starting hash of the first range
 * @end1: ending hash of the first range
 * @start2: starting hash of the second range
 * @end2: ending hash of the second range
 */
static inline
bool RANGE_HAS_PARTIAL_INTERSECTION(u64 start1, u64 end1,
				    u64 start2, u64 end2)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(start1 >= U64_MAX || end1 >= U64_MAX ||
		start2 >= U64_MAX || end2 >= U64_MAX);
	BUG_ON(start1 > end1);
	BUG_ON(start2 > end2);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start1 > end2)
		return false;

	if (end1 < start2)
		return false;

	return true;
}

/*
 * __ssdfs_items_per_lookup_index() - calculate items per lookup index
 * @items_per_node: number of items per node
 * @lookup_table_capacity: maximal number of items in lookup table
 */
static inline
u16 __ssdfs_items_per_lookup_index(u32 items_per_node,
				   int lookup_table_capacity)
{
	u32 items_per_lookup_index;

	items_per_lookup_index = items_per_node / lookup_table_capacity;

	if (items_per_node % lookup_table_capacity)
		items_per_lookup_index++;

	SSDFS_DBG("items_per_lookup_index %u\n", items_per_lookup_index);

	return items_per_lookup_index;
}

/*
 * __ssdfs_convert_lookup2item_index() - convert lookup into item index
 * @lookup_index: lookup index
 * @node_size: size of the node in bytes
 * @item_size: size of the item in bytes
 * @lookup_table_capacity: maximal number of items in lookup table
 */
static inline
u16 __ssdfs_convert_lookup2item_index(u16 lookup_index,
					u32 node_size,
					size_t item_size,
					int lookup_table_capacity)
{
	u32 items_per_node;
	u32 items_per_lookup_index;
	u32 item_index;

	SSDFS_DBG("lookup_index %u, node_size %u, "
		  "item_size %zu, table_capacity %d\n",
		  lookup_index, node_size,
		  item_size, lookup_table_capacity);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(lookup_index >= lookup_table_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	items_per_node = node_size / item_size;
	items_per_lookup_index = __ssdfs_items_per_lookup_index(items_per_node,
							lookup_table_capacity);

	item_index = (u32)lookup_index * items_per_lookup_index;

	SSDFS_DBG("lookup_index %u, item_inxdex %u\n",
		  lookup_index, item_index);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(item_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u16)item_index;
}

/*
 * __ssdfs_convert_item2lookup_index() - convert item into lookup index
 * @item_index: item index
 * @node_size: size of the node in bytes
 * @item_size: size of the item in bytes
 * @lookup_table_capacity: maximal number of items in lookup table
 */
static inline
u16 __ssdfs_convert_item2lookup_index(u16 item_index,
					u32 node_size,
					size_t item_size,
					int lookup_table_capacity)
{
	u32 items_per_node;
	u32 items_per_lookup_index;
	u16 lookup_index;

	SSDFS_DBG("item_index %u, node_size %u, "
		  "item_size %zu, table_capacity %d\n",
		  item_index, node_size,
		  item_size, lookup_table_capacity);

	items_per_node = node_size / item_size;
	items_per_lookup_index = __ssdfs_items_per_lookup_index(items_per_node,
							lookup_table_capacity);
	lookup_index = item_index / items_per_lookup_index;

	SSDFS_DBG("item_index %u, lookup_index %u, table_capacity %d\n",
		  item_index, lookup_index, lookup_table_capacity);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(lookup_index >= lookup_table_capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return lookup_index;
}

/*
 * Btree node API
 */
struct ssdfs_btree_node *
ssdfs_btree_node_create(struct ssdfs_btree *tree,
			u32 node_id,
			struct ssdfs_btree_node *parent,
			u8 height, int type, u64 start_hash);
void ssdfs_btree_node_destroy(struct ssdfs_btree_node *node);
int ssdfs_btree_node_prepare_content(struct ssdfs_btree_node *node,
				     struct ssdfs_btree_index_key *index);
int ssdfs_btree_init_node(struct ssdfs_btree_node *node,
			  struct ssdfs_btree_node_header *hdr,
			  size_t hdr_size);
int ssdfs_btree_pre_flush_root_node(struct ssdfs_btree_node *node);
void ssdfs_btree_flush_root_node(struct ssdfs_btree_node *node,
				struct ssdfs_btree_inline_root_node *root_node);
int ssdfs_btree_node_pre_flush(struct ssdfs_btree_node *node);
int ssdfs_btree_node_flush(struct ssdfs_btree_node *node);

void ssdfs_btree_node_get(struct ssdfs_btree_node *node);
void ssdfs_btree_node_put(struct ssdfs_btree_node *node);
bool is_ssdfs_node_shared(struct ssdfs_btree_node *node);

bool is_ssdfs_btree_node_dirty(struct ssdfs_btree_node *node);
void set_ssdfs_btree_node_dirty(struct ssdfs_btree_node *node);
void clear_ssdfs_btree_node_dirty(struct ssdfs_btree_node *node);

bool is_ssdfs_btree_node_index_area_exist(struct ssdfs_btree_node *node);
bool is_ssdfs_btree_node_index_area_empty(struct ssdfs_btree_node *node);
int ssdfs_btree_node_resize_index_area(struct ssdfs_btree_node *node,
					u32 new_size);
int ssdfs_btree_node_find_index(struct ssdfs_btree_search *search);
bool can_add_new_index(struct ssdfs_btree_node *node);
int ssdfs_btree_node_add_index(struct ssdfs_btree_node *node,
				struct ssdfs_btree_index_key *key);
int ssdfs_btree_node_change_index(struct ssdfs_btree_node *node,
				  struct ssdfs_btree_index_key *old_key,
				  struct ssdfs_btree_index_key *new_key);
int ssdfs_btree_node_delete_index(struct ssdfs_btree_node *node,
				  u64 hash);

bool is_ssdfs_btree_node_items_area_exist(struct ssdfs_btree_node *node);
bool is_ssdfs_btree_node_items_area_empty(struct ssdfs_btree_node *node);
int ssdfs_btree_node_find_item(struct ssdfs_btree_search *search);
int ssdfs_btree_node_find_range(struct ssdfs_btree_search *search);
int ssdfs_btree_node_allocate_item(struct ssdfs_btree_search *search);
int ssdfs_btree_node_allocate_range(struct ssdfs_btree_search *search);
int ssdfs_btree_node_insert_item(struct ssdfs_btree_search *search);
int ssdfs_btree_node_insert_range(struct ssdfs_btree_search *search);
int ssdfs_btree_node_change_item(struct ssdfs_btree_search *search);
int ssdfs_btree_node_delete_item(struct ssdfs_btree_search *search);
int ssdfs_btree_node_delete_range(struct ssdfs_btree_search *search);

/*
 * Internal Btree node API
 */
int ssdfs_lock_items_range(struct ssdfs_btree_node *node,
			   u16 start_index, u16 count);
void ssdfs_unlock_items_range(struct ssdfs_btree_node *node,
				u16 start_index, u16 count);
int ssdfs_lock_whole_index_area(struct ssdfs_btree_node *node);
void ssdfs_unlock_whole_index_area(struct ssdfs_btree_node *node);
int ssdfs_allocate_items_range(struct ssdfs_btree_node *node,
				struct ssdfs_btree_search *search,
				u16 items_capacity,
				u16 start_index, u16 count);
bool is_ssdfs_node_items_range_allocated(struct ssdfs_btree_node *node,
					 u16 items_capacity,
					 u16 start_index, u16 count);
int ssdfs_free_items_range(struct ssdfs_btree_node *node,
			   u16 start_index, u16 count);
int ssdfs_set_node_header_dirty(struct ssdfs_btree_node *node,
				u16 items_capacity);
void ssdfs_clear_node_header_dirty_state(struct ssdfs_btree_node *node);
int ssdfs_set_dirty_items_range(struct ssdfs_btree_node *node,
				u16 items_capacity,
				u16 start_index, u16 count);
void ssdfs_clear_dirty_items_range_state(struct ssdfs_btree_node *node,
					 u16 start_index, u16 count);

int __ssdfs_btree_node_prepare_content(struct ssdfs_fs_info *fsi,
					struct ssdfs_btree_index_key *ptr,
					u32 node_size,
					u64 owner_id,
					struct ssdfs_segment_info **si,
					struct pagevec *pvec);
int ssdfs_btree_create_root_node(struct ssdfs_btree_node *node,
				struct ssdfs_btree_inline_root_node *root_node);
int ssdfs_btree_node_pre_flush_header(struct ssdfs_btree_node *node,
					struct ssdfs_btree_node_header *hdr);
int ssdfs_btree_common_node_flush(struct ssdfs_btree_node *node);
int ssdfs_btree_node_commit_log(struct ssdfs_btree_node *node);
int __ssdfs_btree_root_node_extract_index(struct ssdfs_btree_node *node,
					  u16 found_index,
					  struct ssdfs_btree_index_key *ptr);
int ssdfs_btree_root_node_delete_index(struct ssdfs_btree_node *node,
					u16 position);
int ssdfs_btree_common_node_delete_index(struct ssdfs_btree_node *node,
					 u16 position);
int ssdfs_find_index_by_hash(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_node_index_area *area,
			     u64 hash,
			     u16 *found_index);
int ssdfs_btree_node_find_index_position(struct ssdfs_btree_node *node,
					 u64 hash,
					 u16 *found_position);
int ssdfs_btree_node_extract_range(u16 start_index, u16 count,
				   struct ssdfs_btree_search *search);
int ssdfs_btree_node_get_index(struct pagevec *pvec,
				u32 area_offset, u32 area_size,
				u32 node_size, u16 position,
				struct ssdfs_btree_index_key *ptr);
int ssdfs_btree_node_move_index_range(struct ssdfs_btree_node *src,
				      u16 src_start,
				      struct ssdfs_btree_node *dst,
				      u16 dst_start, u16 count);
int ssdfs_btree_node_move_items_range(struct ssdfs_btree_node *src,
				      struct ssdfs_btree_node *dst,
				      u16 start_item, u16 count);
int ssdfs_copy_item_in_buffer(struct ssdfs_btree_node *node,
			      u16 index,
			      size_t item_size,
			      struct ssdfs_btree_search *search);
bool is_last_leaf_node_found(struct ssdfs_btree_search *search);
int ssdfs_btree_node_find_lookup_index_nolock(struct ssdfs_btree_search *search,
						__le64 *lookup_table,
						int table_capacity,
						u16 *lookup_index);
typedef int (*ssdfs_check_found_item)(struct ssdfs_fs_info *fsi,
					struct ssdfs_btree_search *search,
					void *kaddr,
					u16 item_index,
					u64 *start_hash,
					u64 *end_hash,
					u16 *found_index);
typedef int (*ssdfs_prepare_result_buffer)(struct ssdfs_btree_search *search,
					   u16 found_index,
					   u64 start_hash,
					   u64 end_hash,
					   u16 items_count,
					   size_t item_size);
typedef int (*ssdfs_extract_found_item)(struct ssdfs_fs_info *fsi,
					struct ssdfs_btree_search *search,
					size_t item_size,
					void *kaddr,
					u64 *start_hash,
					u64 *end_hash);
int __ssdfs_extract_range_by_lookup_index(struct ssdfs_btree_node *node,
				u16 lookup_index,
				int lookup_table_capacity,
				size_t item_size,
				struct ssdfs_btree_search *search,
				ssdfs_check_found_item check_item,
				ssdfs_prepare_result_buffer prepare_buffer,
				ssdfs_extract_found_item extract_item);
int ssdfs_shift_range_right(struct ssdfs_btree_node *node,
			    struct ssdfs_btree_node_items_area *area,
			    size_t item_size,
			    u16 start_index, u16 range_len,
			    u16 shift);
int ssdfs_shift_range_right2(struct ssdfs_btree_node *node,
			     struct ssdfs_btree_node_index_area *area,
			     size_t item_size,
			     u16 start_index, u16 range_len,
			     u16 shift);
int ssdfs_shift_range_left(struct ssdfs_btree_node *node,
			   struct ssdfs_btree_node_items_area *area,
			   size_t item_size,
			   u16 start_index, u16 range_len,
			   u16 shift);
int ssdfs_shift_range_left2(struct ssdfs_btree_node *node,
			    struct ssdfs_btree_node_index_area *area,
			    size_t item_size,
			    u16 start_index, u16 range_len,
			    u16 shift);
int ssdfs_shift_memory_range_right(struct ssdfs_btree_node *node,
				   struct ssdfs_btree_node_items_area *area,
				   u16 offset, u16 range_len,
				   u16 shift);
int ssdfs_shift_memory_range_left(struct ssdfs_btree_node *node,
				   struct ssdfs_btree_node_items_area *area,
				   u16 offset, u16 range_len,
				   u16 shift);
int ssdfs_generic_insert_range(struct ssdfs_btree_node *node,
				struct ssdfs_btree_node_items_area *area,
				size_t item_size,
				struct ssdfs_btree_search *search);
int ssdfs_invalidate_root_node_hierarchy(struct ssdfs_btree_node *node);
int __ssdfs_btree_node_extract_range(struct ssdfs_btree_node *node,
				     u16 start_index, u16 count,
				     size_t item_size,
				     struct ssdfs_btree_search *search);
int __ssdfs_btree_node_resize_items_area(struct ssdfs_btree_node *node,
					 size_t item_size,
					 size_t index_size,
					 u32 new_size);
int __ssdfs_define_memory_page(u32 area_offset, u32 area_size,
				u32 node_size, size_t item_size,
				u16 position,
				u32 *page_index, u32 *page_off);
int ssdfs_btree_node_get_hash_range(struct ssdfs_btree_search *search,
				    u64 *start_hash, u64 *end_hash,
				    u16 *items_count);
int __ssdfs_btree_common_node_extract_index(struct ssdfs_btree_node *node,
				    struct ssdfs_btree_node_index_area *area,
				    u16 found_index,
				    struct ssdfs_btree_index_key *ptr);
int ssdfs_btree_node_check_hash_range(struct ssdfs_btree_node *node,
				      u16 items_count,
				      u16 items_capacity,
				      u64 start_hash,
				      u64 end_hash,
				      struct ssdfs_btree_search *search);

void ssdfs_debug_btree_node_object(struct ssdfs_btree_node *node);

#endif /* _SSDFS_BTREE_NODE_H */
