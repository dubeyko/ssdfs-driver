//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/btree_search.c - btree search object functionality.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"

static struct kmem_cache *ssdfs_btree_search_obj_cachep;

/******************************************************************************
 *                       BTREE SEARCH OBJECT CACHE                            *
 ******************************************************************************/

static void ssdfs_init_btree_search_object_once(void *obj)
{
	struct ssdfs_btree_search *search_obj = obj;

	memset(search_obj, 0, sizeof(struct ssdfs_btree_search));
}

void ssdfs_destroy_btree_search_obj_cache(void)
{
	if (ssdfs_btree_search_obj_cachep)
		kmem_cache_destroy(ssdfs_btree_search_obj_cachep);
}

int ssdfs_init_btree_search_obj_cache(void)
{
	ssdfs_btree_search_obj_cachep =
			kmem_cache_create("ssdfs_btree_search_obj_cache",
					sizeof(struct ssdfs_btree_search), 0,
					SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD |
					SLAB_ACCOUNT,
					ssdfs_init_btree_search_object_once);
	if (!ssdfs_btree_search_obj_cachep) {
		SSDFS_ERR("unable to create btree search objects cache\n");
		return -ENOMEM;
	}

	return 0;
}

/******************************************************************************
 *                      BTREE SEARCH OBJECT FUNCTIONALITY                     *
 ******************************************************************************/

/*
 * ssdfs_btree_search_alloc() - allocate memory for btree search object
 */
struct ssdfs_btree_search *ssdfs_btree_search_alloc(void)
{
	struct ssdfs_btree_search *ptr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_btree_search_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	ptr = kmem_cache_alloc(ssdfs_btree_search_obj_cachep, GFP_KERNEL);
	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for btree search object\n");
		return ERR_PTR(-ENOMEM);
	}

	return ptr;
}

/*
 * ssdfs_btree_search_free() - free memory for btree search object
 */
void ssdfs_btree_search_free(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_btree_search_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!search)
		return;

	if (search->node.parent) {
		ssdfs_btree_node_put(search->node.parent);
		search->node.parent = NULL;
	}

	if (search->node.child) {
		ssdfs_btree_node_put(search->node.child);
		search->node.child = NULL;
	}

	search->node.state = SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY;

	if (search->result.buf_state == SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER &&
	    search->result.buf) {
		/* free allocated memory */
		kfree(search->result.buf);
		search->result.buf = NULL;
	}

	search->result.buf_state = SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;

	if (search->result.name_state == SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER &&
	    search->result.name) {
		/* free allocated memory */
		kfree(search->result.name);
		search->result.name = NULL;
	}

	search->result.name = SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;

	kmem_cache_free(ssdfs_btree_search_obj_cachep, search);
}

/*
 * ssdfs_btree_search_init() - init btree search object
 * @search: btree search object [out]
 */
void ssdfs_btree_search_init(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->result.buf_state == SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER) {
		if (search->result.buf)
			kfree(search->result.buf);
	}

	memset(search, 0, sizeof(struct ssdfs_btree_search));
	search->request.type = SSDFS_BTREE_SEARCH_UNKNOWN_TYPE;
	search->node.state = SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY;
	search->node.parent = NULL;
	search->node.child = NULL;
	search->result.state = SSDFS_BTREE_SEARCH_UNKNOWN_RESULT;
	search->result.err = 0;
	search->result.buf = NULL;
	search->result.buf_state = SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
	search->result.name = NULL;
	search->result.name_state = SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
}

/*
 * need_initialize_btree_search() - check necessity to init the search object
 * @search: btree search object
 */
bool need_initialize_btree_search(struct ssdfs_btree_search *search)
{
	bool need_initialize = false;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.state) {
	case SSDFS_BTREE_SEARCH_UNKNOWN_RESULT:
	case SSDFS_BTREE_SEARCH_FAILURE:
	case SSDFS_BTREE_SEARCH_EMPTY_RESULT:
	case SSDFS_BTREE_SEARCH_OBSOLETE_RESULT:
		need_initialize = true;
		break;

	case SSDFS_BTREE_SEARCH_VALID_ITEM:
		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_FIND_ITEM:
		case SSDFS_BTREE_SEARCH_FIND_RANGE:
		case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
		case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		case SSDFS_BTREE_SEARCH_DELETE_RANGE:
		case SSDFS_BTREE_SEARCH_DELETE_ALL:
		case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
			need_initialize = false;
			break;

		case SSDFS_BTREE_SEARCH_ALLOCATE_ITEM:
		case SSDFS_BTREE_SEARCH_ALLOCATE_RANGE:
		case SSDFS_BTREE_SEARCH_ADD_ITEM:
		case SSDFS_BTREE_SEARCH_ADD_RANGE:
			need_initialize = true;
			break;

		default:
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
			break;
		};
		break;

	case SSDFS_BTREE_SEARCH_POSSIBLE_PLACE_FOUND:
		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_ALLOCATE_ITEM:
		case SSDFS_BTREE_SEARCH_ALLOCATE_RANGE:
		case SSDFS_BTREE_SEARCH_ADD_ITEM:
		case SSDFS_BTREE_SEARCH_ADD_RANGE:
			need_initialize = false;
			break;

		case SSDFS_BTREE_SEARCH_FIND_ITEM:
		case SSDFS_BTREE_SEARCH_FIND_RANGE:
		case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
		case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		case SSDFS_BTREE_SEARCH_DELETE_RANGE:
		case SSDFS_BTREE_SEARCH_DELETE_ALL:
		case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
			need_initialize = true;
			break;

		default:
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
			break;
		};
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		break;
	};

	return need_initialize;
}

/*
 * is_btree_search_request_valid() - check validity of search request
 * @search: btree search object
 */
bool is_btree_search_request_valid(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->request.type) {
	case SSDFS_BTREE_SEARCH_FIND_ITEM:
	case SSDFS_BTREE_SEARCH_FIND_RANGE:
	case SSDFS_BTREE_SEARCH_ALLOCATE_ITEM:
	case SSDFS_BTREE_SEARCH_ALLOCATE_RANGE:
	case SSDFS_BTREE_SEARCH_ADD_ITEM:
	case SSDFS_BTREE_SEARCH_ADD_RANGE:
	case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
	case SSDFS_BTREE_SEARCH_DELETE_ITEM:
	case SSDFS_BTREE_SEARCH_DELETE_RANGE:
	case SSDFS_BTREE_SEARCH_DELETE_ALL:
	case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
		/* valid type */
		break;

	default:
		SSDFS_WARN("invalid search request type %#x\n",
			   search->request.type);
		return false;
	};

	if (search->request.flags & ~SSDFS_BTREE_SEARCH_REQUEST_FLAGS_MASK) {
		SSDFS_WARN("invalid flags set: %#x\n",
			   search->request.flags);
		return false;
	}

	if (search->request.start.hash == U64_MAX) {
		SSDFS_WARN("invalid start_hash\n");
		return false;
	} else if (search->request.start.hash > search->request.end.hash) {
		SSDFS_WARN("invalid range: "
			   "start_hash %llx, end_hash %llx\n",
			   search->request.start.hash,
			   search->request.end.hash);
		return false;
	}

	return true;
}

/*
 * is_btree_index_search_request_valid() - check index node search request
 * @search: btree search object
 * @prev_node_id: node ID from previous search
 * @prev_node_height: node height from previous search
 */
bool is_btree_index_search_request_valid(struct ssdfs_btree_search *search,
					 u32 prev_node_id,
					 u8 prev_node_height)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
	BUG_ON(prev_node_id == SSDFS_BTREE_NODE_INVALID_ID);
	BUG_ON(prev_node_height == U8_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_btree_search_request_valid(search))
		return false;

	if (prev_node_id == search->node.id)
		return false;

	if (search->node.height != (prev_node_height - 1))
		return false;

	if (search->node.state != SSDFS_BTREE_SEARCH_FOUND_INDEX_NODE_DESC)
		return false;

	return true;
}

/*
 * is_btree_leaf_node_found() - check that leaf btree node has been found
 * @search: btree search object
 */
bool is_btree_leaf_node_found(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->node.state != SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC)
		return false;

	if (search->node.height >= SSDFS_BTREE_PARENT2HYBRID_HEIGHT)
		return false;

	if (search->node.id == SSDFS_BTREE_NODE_INVALID_ID)
		return false;

	if (search->node.child == NULL)
		return false;

	return true;
}

/*
 * is_btree_search_node_desc_consistent() - check node descriptor consistency
 * @search: btree search object
 */
bool is_btree_search_node_desc_consistent(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->node.state != SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC)
		return false;

	if (!search->node.parent || !search->node.child)
		return false;

	if (search->node.id != search->node.child->node_id)
		return false;

	if (search->node.height != atomic_read(&search->node.child->height))
		return false;

	return true;
}

/*
 * ssdfs_btree_search_define_child_node() - define child node for the search
 * @search: search object
 * @child: child node object
 */
void ssdfs_btree_search_define_child_node(struct ssdfs_btree_search *search,
					  struct ssdfs_btree_node *child)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->node.child)
		ssdfs_btree_node_put(search->node.child);

	search->node.child = child;

	if (search->node.child)
		ssdfs_btree_node_get(search->node.child);
}

/*
 * ssdfs_btree_search_define_parent_node() - define parent node for the search
 * @search: search object
 * @child: child node object
 */
void ssdfs_btree_search_define_parent_node(struct ssdfs_btree_search *search,
					   struct ssdfs_btree_node *parent)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->node.parent)
		ssdfs_btree_node_put(search->node.parent);

	search->node.parent = parent;

	if (search->node.parent)
		ssdfs_btree_node_get(search->node.parent);
}

void ssdfs_debug_btree_search_object(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct ssdfs_btree_index_key *node_index;
	struct ssdfs_shdict_ltbl2_item *ltbl2_item;
	size_t item_size;
	size_t count;
	int i;

	BUG_ON(!search);

	SSDFS_DBG("REQUEST: type %#x, flags %#x, count %u, "
		  "START: name %p, name_len %zu, hash %llx, ino %llu, "
		  "END: name %p, name_len %zu, hash %llx, ino %llu\n",
		  search->request.type,
		  search->request.flags,
		  search->request.count,
		  search->request.start.name,
		  search->request.start.name_len,
		  search->request.start.hash,
		  search->request.start.ino,
		  search->request.end.name,
		  search->request.end.name_len,
		  search->request.end.hash,
		  search->request.end.ino);

	SSDFS_DBG("NODE: state %#x, id %u, height %u, "
		  "parent %p, child %p\n",
		  search->node.state,
		  search->node.id,
		  search->node.height,
		  search->node.parent,
		  search->node.child);

	node_index = &search->node.found_index;
	SSDFS_DBG("NODE_INDEX: node_id %u, node_type %#x, "
		  "height %u, flags %#x, hash %llx, "
		  "seg_id %llu, logical_blk %u, len %u\n",
		  le32_to_cpu(node_index->node_id),
		  node_index->node_type,
		  node_index->height,
		  le16_to_cpu(node_index->flags),
		  le64_to_cpu(node_index->index.hash),
		  le64_to_cpu(node_index->index.extent.seg_id),
		  le32_to_cpu(node_index->index.extent.logical_blk),
		  le32_to_cpu(node_index->index.extent.len));

	if (search->node.parent) {
		SSDFS_DBG("PARENT NODE: node_id %u, state %#x, "
			  "type %#x, height %d, refs_count %d\n",
			  search->node.parent->node_id,
			  atomic_read(&search->node.parent->state),
			  atomic_read(&search->node.parent->type),
			  atomic_read(&search->node.parent->height),
			  atomic_read(&search->node.parent->refs_count));
	}

	if (search->node.child) {
		SSDFS_DBG("CHILD NODE: node_id %u, state %#x, "
			  "type %#x, height %d, refs_count %d\n",
			  search->node.child->node_id,
			  atomic_read(&search->node.child->state),
			  atomic_read(&search->node.child->type),
			  atomic_read(&search->node.child->height),
			  atomic_read(&search->node.child->refs_count));
	}

	SSDFS_DBG("RESULT: state %#x, err %d, start_index %u, count %u, "
		  "search_cno %llu\n",
		  search->result.state,
		  search->result.err,
		  search->result.start_index,
		  search->result.count,
		  search->result.search_cno);

	SSDFS_DBG("NAME: name_state %#x, name %p, "
		  "name_string_size %zu, names_in_buffer %u\n",
		  search->result.name_state,
		  search->result.name,
		  search->result.name_string_size,
		  search->result.names_in_buffer);

	if (search->result.name) {
		count = search->result.names_in_buffer;

		if (count > 0)
			item_size = search->result.name_string_size / count;
		else
			item_size = 0;

		for (i = 0; i < search->result.names_in_buffer; i++) {
			struct ssdfs_name_string *name;
			u8 *addr;

			addr = (u8 *)search->result.name + (i * item_size);
			name = (struct ssdfs_name_string *)addr;

			SSDFS_DBG("NAME: index %d, hash %llx, str_len %zu\n",
				  i, name->hash, name->len);

			SSDFS_DBG("LOOKUP: index %u, hash_lo %u, "
				  "start_index %u, range_len %u\n",
				  name->lookup.index,
				  le32_to_cpu(name->lookup.desc.hash_lo),
				  le16_to_cpu(name->lookup.desc.start_index),
				  le16_to_cpu(name->lookup.desc.range_len));

			ltbl2_item = &name->strings_range.desc;
			SSDFS_DBG("STRINGS_RANGE: index %u, hash_lo %u, "
				  "prefix_len %u, str_count %u, "
				  "hash_index %u\n",
				  name->strings_range.index,
				  le32_to_cpu(ltbl2_item->hash_lo),
				  ltbl2_item->prefix_len,
				  ltbl2_item->str_count,
				  le16_to_cpu(ltbl2_item->hash_index));

			SSDFS_DBG("PREFIX: index %u, hash_hi %u, "
				  "str_offset %u, str_len %u, type %#x\n",
				  name->prefix.index,
				  le32_to_cpu(name->prefix.desc.hash_hi),
				  le16_to_cpu(name->prefix.desc.str_offset),
				  name->prefix.desc.str_len,
				  name->prefix.desc.type);

			SSDFS_DBG("LEFT_NAME: index %u, hash_hi %u, "
				  "str_offset %u, str_len %u, type %#x\n",
				  name->left_name.index,
				  le32_to_cpu(name->left_name.desc.hash_hi),
				  le16_to_cpu(name->left_name.desc.str_offset),
				  name->left_name.desc.str_len,
				  name->left_name.desc.type);

			SSDFS_DBG("RIGHT_NAME: index %u, hash_hi %u, "
				  "str_offset %u, str_len %u, type %#x\n",
				  name->right_name.index,
				  le32_to_cpu(name->right_name.desc.hash_hi),
				  le16_to_cpu(name->right_name.desc.str_offset),
				  name->right_name.desc.str_len,
				  name->right_name.desc.type);

			SSDFS_DBG("RAW STRING DUMP: index %d\n",
				  i);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						name->str,
						name->len);
			SSDFS_DBG("\n");
		}
	}

	SSDFS_DBG("BUFFER: buf_state %#x, buf %p, "
		  "buf_size %zu, items_in_buffer %u\n",
		  search->result.buf_state,
		  search->result.buf,
		  search->result.buf_size,
		  search->result.items_in_buffer);

	if (search->result.buf) {
		count = search->result.items_in_buffer;

		if (count > 0)
			item_size = search->result.buf_size / count;
		else
			item_size = 0;

		for (i = 0; i < search->result.items_in_buffer; i++) {
			void *item;

			item = (u8 *)search->result.buf + (i * item_size);

			SSDFS_DBG("RAW BUF DUMP: index %d\n",
				  i);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						item,
						item_size);
			SSDFS_DBG("\n");
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */
}
