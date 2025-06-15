/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/btree_search.h - btree search object declarations.
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

#ifndef _SSDFS_BTREE_SEARCH_H
#define _SSDFS_BTREE_SEARCH_H

/* Search request types */
enum {
	SSDFS_BTREE_SEARCH_UNKNOWN_TYPE,
	SSDFS_BTREE_SEARCH_FIND_ITEM,
	SSDFS_BTREE_SEARCH_FIND_RANGE,
	SSDFS_BTREE_SEARCH_ALLOCATE_ITEM,
	SSDFS_BTREE_SEARCH_ALLOCATE_RANGE,
	SSDFS_BTREE_SEARCH_ADD_ITEM,
	SSDFS_BTREE_SEARCH_ADD_RANGE,
	SSDFS_BTREE_SEARCH_CHANGE_ITEM,
	SSDFS_BTREE_SEARCH_MOVE_ITEM,
	SSDFS_BTREE_SEARCH_DELETE_ITEM,
	SSDFS_BTREE_SEARCH_DELETE_RANGE,
	SSDFS_BTREE_SEARCH_DELETE_ALL,
	SSDFS_BTREE_SEARCH_INVALIDATE_TAIL,
	SSDFS_BTREE_SEARCH_TYPE_MAX
};

/*
 * struct ssdfs_peb_timestamps - PEB timestamps
 * @peb_id: PEB ID
 * @create_time: PEB's create timestamp
 * @last_log_time: PEB's last log create timestamp
 */
struct ssdfs_peb_timestamps {
	u64 peb_id;
	u64 create_time;
	u64 last_log_time;
};

/*
 * struct ssdfs_btree_search_hash - btree search hash
 * @name: name of the searching object
 * @name_len: length of the name in bytes
 * @uuid: UUID of the searching object
 * @hash: hash value
 * @ino: inode ID
 * @fingerprint: fingerprint value
 * @peb2time: PEB timestamps
 */
struct ssdfs_btree_search_hash {
	const char *name;
	size_t name_len;
	u8 *uuid;
	u64 hash;
	u64 ino;
	struct ssdfs_fingerprint *fingerprint;
	struct ssdfs_peb_timestamps *peb2time;
};

/*
 * struct ssdfs_btree_search_request - btree search request
 * @type: request type
 * @flags: request flags
 * @start: starting hash value
 * @end: ending hash value
 * @count: range of hashes length in the request
 */
struct ssdfs_btree_search_request {
	int type;
#define SSDFS_BTREE_SEARCH_HAS_VALID_HASH_RANGE		(1 << 0)
#define SSDFS_BTREE_SEARCH_HAS_VALID_COUNT		(1 << 1)
#define SSDFS_BTREE_SEARCH_HAS_VALID_NAME		(1 << 2)
#define SSDFS_BTREE_SEARCH_HAS_VALID_INO		(1 << 3)
#define SSDFS_BTREE_SEARCH_NOT_INVALIDATE		(1 << 4)
#define SSDFS_BTREE_SEARCH_HAS_VALID_UUID		(1 << 5)
#define SSDFS_BTREE_SEARCH_HAS_VALID_FINGERPRINT	(1 << 6)
#define SSDFS_BTREE_SEARCH_INCREMENT_REF_COUNT		(1 << 7)
#define SSDFS_BTREE_SEARCH_DECREMENT_REF_COUNT		(1 << 8)
#define SSDFS_BTREE_SEARCH_INLINE_BUF_HAS_NEW_ITEM	(1 << 9)
#define SSDFS_BTREE_SEARCH_DONT_EXTRACT_RECORD		(1 << 10)
#define SSDFS_BTREE_SEARCH_HAS_PEB2TIME_PAIR		(1 << 11)
#define SSDFS_BTREE_SEARCH_REQUEST_FLAGS_MASK		0xFFF
	u32 flags;

	struct ssdfs_btree_search_hash start;
	struct ssdfs_btree_search_hash end;
	unsigned int count;
};

/* Node descriptor possible states */
enum {
	SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY,
	SSDFS_BTREE_SEARCH_ROOT_NODE_DESC,
	SSDFS_BTREE_SEARCH_FOUND_INDEX_NODE_DESC,
	SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC,
	SSDFS_BTREE_SEARCH_NODE_DESC_STATE_MAX
};

/*
 * struct ssdfs_btree_search_node_desc - btree node descriptor
 * @state: descriptor state
 * @id: node ID number
 * @height: node height
 * @found_index: index of child node
 * @parent: last parent node
 * @child: last child node
 */
struct ssdfs_btree_search_node_desc {
	int state;

	u32 id;
	u8 height;

	struct ssdfs_btree_index_key found_index;
	struct ssdfs_btree_node *parent;
	struct ssdfs_btree_node *child;
};

/* Search result possible states */
enum {
	SSDFS_BTREE_SEARCH_UNKNOWN_RESULT,
	SSDFS_BTREE_SEARCH_FAILURE,
	SSDFS_BTREE_SEARCH_EMPTY_RESULT,
	SSDFS_BTREE_SEARCH_VALID_ITEM,
	SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND,
	SSDFS_BTREE_SEARCH_OUT_OF_RANGE,
	SSDFS_BTREE_SEARCH_OBSOLETE_RESULT,
	SSDFS_BTREE_SEARCH_PLEASE_ADD_NODE,
	SSDFS_BTREE_SEARCH_PLEASE_DELETE_NODE,
	SSDFS_BTREE_SEARCH_PLEASE_MOVE_BUF_CONTENT,
	SSDFS_BTREE_SEARCH_RESULT_STATE_MAX
};

/* Search result buffer possible states */
enum {
	SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE,
	SSDFS_BTREE_SEARCH_INLINE_BUFFER,
	SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER,
	SSDFS_BTREE_SEARCH_BUFFER_STATE_MAX
};

/*
 * struct ssdfs_lookup_descriptor - lookup descriptor
 * @index: index of item in the lookup1 table
 * @desc: descriptor of lookup1 table's item
 */
struct ssdfs_lookup_descriptor {
	u16 index;
	struct ssdfs_shdict_ltbl1_item desc;
};

/*
 * struct ssdfs_strings_range_descriptor - strings range descriptor
 * @index: index of item in the lookup2 table
 * @desc: descriptor of lookup2 table's item
 */
struct ssdfs_strings_range_descriptor {
	u16 index;
	struct ssdfs_shdict_ltbl2_item desc;
};

/*
 * struct ssdfs_string_descriptor - string descriptor
 * @index: index of item in the hash table
 * @desc: descriptor of hash table's item
 */
struct ssdfs_string_descriptor {
	u16 index;
	struct ssdfs_shdict_htbl_item desc;
};

/*
 * struct ssdfs_string_table_index - string table indexes
 * @lookup1_index: index in lookup1 table
 * @lookup2_index: index in lookup2 table
 * @hash_index: index in hash table
 *
 * Search operation defines lookup, strings_range, prefix,
 * left_name, and right_name. This information contains
 * potential position to store the string. However,
 * the final position to insert string and indexes can
 * be defined during the insert operation. This field
 * keeps the knowledge of finally used indexes to store
 * the string and lookup1, lookup2, hash indexes.
 */
struct ssdfs_string_table_index {
	u16 lookup1_index;
	u16 lookup2_index;
	u16 hash_index;
};

/*
 * struct ssdfs_name_string - name string
 * @hash: name hash
 * @lookup: lookup item descriptor
 * @strings_range: range of strings descriptor
 * @prefix: prefix descriptor
 * @left_name: left name descriptor
 * @right_name: right name descriptor
 * @placement: stored indexes descriptor
 * @len: name length
 * @str: name buffer
 */
struct ssdfs_name_string {
	u64 hash;
	struct ssdfs_lookup_descriptor lookup;
	struct ssdfs_strings_range_descriptor strings_range;
	struct ssdfs_string_descriptor prefix;
	struct ssdfs_string_descriptor left_name;
	struct ssdfs_string_descriptor right_name;

	struct ssdfs_string_table_index placement;

	size_t len;
	unsigned char str[SSDFS_MAX_NAME_LEN];
};

/*
 * struct ssdfs_btree_search_buffer - buffer descriptor
 * @state: state of the buffer
 * @size: size of the buffer in bytes
 * @item_size: size of one item in bytes
 * @items_count: items count in buffer
 * @place.ptr: pointer on buffer
 * @place.ltbl2_items: pointer on buffer with lookup2 table's items
 * @place.htbl_items: pointer on buffer with hash table's items
 * @place.name: pointer on buffer with name descriptor(s)
 * @place.name_range: pointer on buffer with names range
 */
struct ssdfs_btree_search_buffer {
	int state;
	size_t size;

	size_t item_size;
	u32 items_count;

	union {
		void *ptr;
		struct ssdfs_shdict_ltbl2_item *ltbl2_items;
		struct ssdfs_shdict_htbl_item *htbl_items;
		struct ssdfs_name_string *name;
		struct ssdfs_name_string_range *name_range;
	} place;
};

/*
 * struct ssdfs_name_string_range - name string range
 * @lookup1: lookup1 item descriptor
 * @lookup2_table.index: index of first item in the lookup2 table
 * @lookup2_table.buf: lookup2 table's buffer
 * @hash_table.index: index of first item in the hash table
 * @hash_table.buf: hash table's buffer
 * @strings.buf: buffer with strings
 * @placement: final destination of storing range
 */
struct ssdfs_name_string_range {
	struct ssdfs_lookup_descriptor lookup1;

	struct {
		u16 index;
		struct ssdfs_btree_search_buffer buf;
	} lookup2_table;

	struct {
		u16 index;
		struct ssdfs_btree_search_buffer buf;
	} hash_table;

	struct {
		struct ssdfs_btree_search_buffer buf;
	} strings;

	struct ssdfs_string_table_index placement;
};

/*
 * struct ssdfs_btree_search_result - btree search result
 * @state: result state
 * @err: result error code
 * @flags: result's flags
 * @start_index: starting found item index
 * @count: count of found items
 * @search_cno: checkpoint of search activity
 * @name_buf: name(s) buffer
 * @range_buf: buffer with names range
 * @raw_buf: raw buffer with item(s)
 */
struct ssdfs_btree_search_result {
	int state;
	int err;

#define SSDFS_BTREE_SEARCH_RESULT_HAS_NAME		(1 << 0)
#define SSDFS_BTREE_SEARCH_RESULT_HAS_RANGE		(1 << 1)
#define SSDFS_BTREE_SEARCH_RESULT_HAS_RAW_DATA		(1 << 2)
#define SSDFS_BTREE_SEARCH_RESULT_FLAGS_MASK		0x7
	u32 flags;

	u16 start_index;
	u16 count;

	u64 search_cno;

	struct ssdfs_btree_search_buffer name_buf;
	struct ssdfs_btree_search_buffer range_buf;
	struct ssdfs_btree_search_buffer raw_buf;
};

/* Position check results */
enum {
	SSDFS_CORRECT_POSITION,
	SSDFS_SEARCH_LEFT_DIRECTION,
	SSDFS_SEARCH_RIGHT_DIRECTION,
	SSDFS_CHECK_POSITION_FAILURE
};

/*
 * struct ssdfs_btree_search - btree search
 * @request: search request
 * @node: btree node descriptor
 * @result: search result
 * @raw.fork: raw fork buffer
 * @raw.inode: raw inode buffer
 * @raw.dentry.header: raw directory entry header
 * @raw.xattr.header: raw xattr entry header
 * @raw.shared_extent: shared extent buffer
 * @raw.snapshot: raw snapshot info buffer
 * @raw.peb2time: raw PEB2time set
 * @raw.invalidated_extent: invalidated extent buffer
 * @name.string: name string
 * @name.range: range of names
 */
struct ssdfs_btree_search {
	struct ssdfs_btree_search_request request;
	struct ssdfs_btree_search_node_desc node;
	struct ssdfs_btree_search_result result;
	union ssdfs_btree_search_raw_data {
		struct ssdfs_raw_fork fork;
		struct ssdfs_inode inode;
		struct ssdfs_raw_dentry {
			struct ssdfs_dir_entry header;
		} dentry;
		struct ssdfs_raw_xattr {
			struct ssdfs_xattr_entry header;
		} xattr;
		struct ssdfs_shared_extent shared_extent;
		struct ssdfs_snapshot snapshot;
		struct ssdfs_peb2time_set peb2time;
		struct ssdfs_raw_extent invalidated_extent;
	} raw;
	struct {
		struct ssdfs_name_string string;
		struct ssdfs_name_string_range range;
	} name;
};

/* Btree height's classification */
enum {
	SSDFS_BTREE_PARENT2LEAF_HEIGHT		= 1,
	SSDFS_BTREE_PARENT2HYBRID_HEIGHT	= 2,
	SSDFS_BTREE_PARENT2INDEX_HEIGHT		= 3,
};

/*
 * Inline functions
 */

static inline
bool is_btree_search_contains_new_item(struct ssdfs_btree_search *search)
{
	return search->request.flags &
			SSDFS_BTREE_SEARCH_INLINE_BUF_HAS_NEW_ITEM;
}

/*
 * Btree search object API
 */
struct ssdfs_btree_search *ssdfs_btree_search_alloc(void);
void ssdfs_btree_search_free(struct ssdfs_btree_search *search);
void ssdfs_btree_search_init(struct ssdfs_btree_search *search);
bool need_initialize_btree_search(struct ssdfs_btree_search *search);
bool is_btree_search_request_valid(struct ssdfs_btree_search *search);
bool is_btree_index_search_request_valid(struct ssdfs_btree_search *search,
					 u32 prev_node_id,
					 u8 prev_node_height);
bool is_btree_leaf_node_found(struct ssdfs_btree_search *search);
bool is_btree_search_node_desc_consistent(struct ssdfs_btree_search *search);
void ssdfs_btree_search_define_parent_node(struct ssdfs_btree_search *search,
					   struct ssdfs_btree_node *parent);
void ssdfs_btree_search_define_child_node(struct ssdfs_btree_search *search,
					  struct ssdfs_btree_node *child);
void ssdfs_btree_search_forget_parent_node(struct ssdfs_btree_search *search);
void ssdfs_btree_search_forget_child_node(struct ssdfs_btree_search *search);
int ssdfs_btree_search_alloc_result_buf(struct ssdfs_btree_search *search,
					size_t buf_size);
void ssdfs_btree_search_free_result_buf(struct ssdfs_btree_search *search);
int ssdfs_btree_search_alloc_result_name(struct ssdfs_btree_search *search,
					 size_t string_size);
void ssdfs_btree_search_free_result_name(struct ssdfs_btree_search *search);
int ssdfs_btree_search_alloc_result_name_range(struct ssdfs_btree_search *search,
						size_t ltbl2_size,
						size_t htbl_size,
						size_t str_buf_size);
void ssdfs_btree_search_free_result_name_range(struct ssdfs_btree_search *search);

void ssdfs_debug_btree_search_object(struct ssdfs_btree_search *search);

#endif /* _SSDFS_BTREE_SEARCH_H */
