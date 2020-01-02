//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/btree_search.h - btree search object declarations.
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
	SSDFS_BTREE_SEARCH_DELETE_ITEM,
	SSDFS_BTREE_SEARCH_DELETE_RANGE,
	SSDFS_BTREE_SEARCH_DELETE_ALL,
	SSDFS_BTREE_SEARCH_INVALIDATE_TAIL,
	SSDFS_BTREE_SEARCH_TYPE_MAX
};

/*
 * struct ssdfs_btree_search_hash - btree search hash
 * @name: name of the searching object
 * @name_len: length of the name in bytes
 * @hash: hash value
 * @ino: inode ID
 */
struct ssdfs_btree_search_hash {
	const char *name;
	size_t name_len;
	u64 hash;
	u64 ino;
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
#define SSDFS_BTREE_SEARCH_REQUEST_FLAGS_MASK		0xF
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
 * struct ssdfs_name_string - name string
 * @hash: name hash
 * @lookup: lookup item descriptor
 * @strings_range: range of strings descriptor
 * @prefix: prefix descriptor
 * @left_name: left name descriptor
 * @right_name: right name descriptor
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

	size_t len;
	unsigned char str[SSDFS_MAX_NAME_LEN];
};

/*
 * struct ssdfs_btree_search_result - btree search result
 * @state: result state
 * @err: result error code
 * @start_index: starting found item index
 * @count: count of found items
 * @search_cno: checkpoint of search activity
 * @name_state: state of the name buffer
 * @name: pointer on buffer with name(s)
 * @name_string_size: size of the buffer in bytes
 * @names_in_buffer: count of names in buffer
 * @buf_state: state of the buffer
 * @buf: pointer on buffer with item(s)
 * @buf_size: size of the buffer in bytes
 * @items_in_buffer: count of items in buffer
 */
struct ssdfs_btree_search_result {
	int state;
	int err;

	u16 start_index;
	u16 count;

	u64 search_cno;

	int name_state;
	struct ssdfs_name_string *name;
	size_t name_string_size;
	u32 names_in_buffer;

	int buf_state;
	void *buf;
	size_t buf_size;
	u32 items_in_buffer;
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
 * @name: name string
 */
struct ssdfs_btree_search {
	struct ssdfs_btree_search_request request;
	struct ssdfs_btree_search_node_desc node;
	struct ssdfs_btree_search_result result;
	union {
		struct ssdfs_raw_fork fork;
		struct ssdfs_inode inode;
		struct ssdfs_raw_dentry {
			struct ssdfs_dir_entry header;
		} dentry;
		struct ssdfs_raw_xattr {
			struct ssdfs_xattr_entry header;
		} xattr;
	} raw;
	struct ssdfs_name_string name;
};

/* Btree height's classification */
enum {
	SSDFS_BTREE_PARENT2LEAF_HEIGHT		= 1,
	SSDFS_BTREE_PARENT2HYBRID_HEIGHT	= 2,
	SSDFS_BTREE_PARENT2INDEX_HEIGHT		= 3,
};

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

void ssdfs_debug_btree_search_object(struct ssdfs_btree_search *search);

#endif /* _SSDFS_BTREE_SEARCH_H */
