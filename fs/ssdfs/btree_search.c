/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/btree_search.c - btree search object functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2026 Viacheslav Dubeyko <slava@dubeyko.com>
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_btree_search_folio_leaks;
atomic64_t ssdfs_btree_search_memory_leaks;
atomic64_t ssdfs_btree_search_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_btree_search_cache_leaks_increment(void *kaddr)
 * void ssdfs_btree_search_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_btree_search_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_btree_search_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_btree_search_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_btree_search_kfree(void *kaddr)
 * struct folio *ssdfs_btree_search_alloc_folio(gfp_t gfp_mask,
 *                                              unsigned int order)
 * struct folio *ssdfs_btree_search_add_batch_folio(struct folio_batch *batch,
 *                                                  unsigned int order)
 * void ssdfs_btree_search_free_folio(struct folio *folio)
 * void ssdfs_btree_search_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(btree_search)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(btree_search)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_btree_search_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_btree_search_folio_leaks, 0);
	atomic64_set(&ssdfs_btree_search_memory_leaks, 0);
	atomic64_set(&ssdfs_btree_search_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_btree_search_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_btree_search_folio_leaks) != 0) {
		SSDFS_ERR("BTREE SEARCH: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_btree_search_folio_leaks));
	}

	if (atomic64_read(&ssdfs_btree_search_memory_leaks) != 0) {
		SSDFS_ERR("BTREE SEARCH: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_btree_search_memory_leaks));
	}

	if (atomic64_read(&ssdfs_btree_search_cache_leaks) != 0) {
		SSDFS_ERR("BTREE SEARCH: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_btree_search_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/******************************************************************************
 *                       BTREE SEARCH OBJECT CACHE                            *
 ******************************************************************************/

static struct kmem_cache *ssdfs_btree_search_obj_cachep;

void ssdfs_zero_btree_search_obj_cache_ptr(void)
{
	ssdfs_btree_search_obj_cachep = NULL;
}

static void ssdfs_init_btree_search_object_once(void *obj)
{
	struct ssdfs_btree_search *search_obj = obj;

	memset(search_obj, 0, sizeof(struct ssdfs_btree_search));
}

void ssdfs_shrink_btree_search_obj_cache(void)
{
	if (ssdfs_btree_search_obj_cachep)
		kmem_cache_shrink(ssdfs_btree_search_obj_cachep);
}

void ssdfs_destroy_btree_search_obj_cache(void)
{
	if (ssdfs_btree_search_obj_cachep)
		kmem_cache_destroy(ssdfs_btree_search_obj_cachep);
}

int ssdfs_init_btree_search_obj_cache(void)
{
	ssdfs_btree_search_obj_cachep =
		kmem_cache_create_usercopy("ssdfs_btree_search_obj_cache",
				sizeof(struct ssdfs_btree_search), 0,
				SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
				offsetof(struct ssdfs_btree_search, raw),
				sizeof(union ssdfs_btree_search_raw_data) +
				sizeof(struct ssdfs_name_string),
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
	unsigned int nofs_flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_btree_search_obj_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	nofs_flags = memalloc_nofs_save();
	ptr = kmem_cache_alloc(ssdfs_btree_search_obj_cachep, GFP_KERNEL);
	memalloc_nofs_restore(nofs_flags);

	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for btree search object\n");
		return ERR_PTR(-ENOMEM);
	}

	ssdfs_btree_search_cache_leaks_increment(ptr);

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

	ssdfs_btree_search_free_result_buf(search);
	ssdfs_btree_search_free_result_name(search);
	ssdfs_btree_search_free_result_name_range(search);

	ssdfs_btree_search_cache_leaks_decrement(search);
	kmem_cache_free(ssdfs_btree_search_obj_cachep, search);
}

/*
 * ssdfs_btree_search_buffer_init() - init btree search buffer
 */
static inline
void ssdfs_btree_search_buffer_init(struct ssdfs_btree_search_buffer *buf)
{
	buf->state = SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
	buf->size = 0;
	buf->place.ptr = NULL;
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

	ssdfs_btree_search_free_result_buf(search);
	ssdfs_btree_search_free_result_name(search);
	ssdfs_btree_search_free_result_name_range(search);

	if (search->node.parent) {
		ssdfs_btree_node_put(search->node.parent);
		search->node.parent = NULL;
	}

	if (search->node.child) {
		ssdfs_btree_node_put(search->node.child);
		search->node.child = NULL;
	}

	memset(search, 0, sizeof(struct ssdfs_btree_search));
	search->request.type = SSDFS_BTREE_SEARCH_UNKNOWN_TYPE;
	search->node.state = SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY;
	search->result.state = SSDFS_BTREE_SEARCH_UNKNOWN_RESULT;
	search->result.err = 0;
	search->result.flags = 0;
	ssdfs_btree_search_buffer_init(&search->result.name_buf);
	ssdfs_btree_search_buffer_init(&search->result.raw_buf);
	ssdfs_btree_search_buffer_init(&search->result.range_buf);
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
		case SSDFS_BTREE_SEARCH_MOVE_ITEM:
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
			SSDFS_ERR("search->request.type %#x\n",
				  search->request.type);
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
		case SSDFS_BTREE_SEARCH_MOVE_ITEM:
		case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		case SSDFS_BTREE_SEARCH_DELETE_RANGE:
		case SSDFS_BTREE_SEARCH_DELETE_ALL:
		case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
			need_initialize = true;
			break;

		default:
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_ERR("search->request.type %#x\n",
				  search->request.type);
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
			break;
		};
		break;

	case SSDFS_BTREE_SEARCH_OUT_OF_RANGE:
		switch (search->request.type) {
		case SSDFS_BTREE_SEARCH_ADD_ITEM:
			need_initialize = false;
			break;

		case SSDFS_BTREE_SEARCH_FIND_ITEM:
		case SSDFS_BTREE_SEARCH_FIND_RANGE:
		case SSDFS_BTREE_SEARCH_CHANGE_ITEM:
		case SSDFS_BTREE_SEARCH_MOVE_ITEM:
		case SSDFS_BTREE_SEARCH_DELETE_ITEM:
		case SSDFS_BTREE_SEARCH_DELETE_RANGE:
		case SSDFS_BTREE_SEARCH_DELETE_ALL:
		case SSDFS_BTREE_SEARCH_INVALIDATE_TAIL:
			need_initialize = true;
			break;

		default:
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_ERR("search->request.type %#x\n",
				  search->request.type);
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
			break;
		};
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_ERR("search->result.state %#x\n",
			  search->result.state);
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
	case SSDFS_BTREE_SEARCH_MOVE_ITEM:
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

	if (search->node.state != SSDFS_BTREE_SEARCH_FOUND_LEAF_NODE_DESC) {
		SSDFS_ERR("unexpected search->node.state %#x\n",
			  search->node.state);
		return false;
	}

	if (!search->node.parent) {
		SSDFS_ERR("search->node.parent is NULL\n");
		return false;
	}

	if (!search->node.child) {
		SSDFS_ERR("search->node.child is NULL\n");
		return false;
	}

	if (search->node.id != search->node.child->node_id) {
		SSDFS_ERR("search->node.id %u != search->node.child->node_id %u\n",
			  search->node.id, search->node.child->node_id);
		return false;
	}

	if (search->node.height != atomic_read(&search->node.child->height)) {
		SSDFS_ERR("invalid height: "
			  "search->node.height %u, "
			  "search->node.child->height %d\n",
			  search->node.height,
			  atomic_read(&search->node.child->height));
		return false;
	}

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
 * ssdfs_btree_search_forget_child_node() - forget child node for the search
 * @search: search object
 */
void ssdfs_btree_search_forget_child_node(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->node.child) {
		ssdfs_btree_node_put(search->node.child);
		search->node.child = NULL;
		search->node.state = SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY;
	}
}

/*
 * ssdfs_btree_search_define_parent_node() - define parent node for the search
 * @search: search object
 * @parent: parent node object
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

/*
 * ssdfs_btree_search_forget_parent_node() - forget parent node for the search
 * @search: search object
 */
void ssdfs_btree_search_forget_parent_node(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	if (search->node.parent) {
		ssdfs_btree_node_put(search->node.parent);
		search->node.parent = NULL;
		search->node.state = SSDFS_BTREE_SEARCH_NODE_DESC_EMPTY;
	}
}

/*
 * ssdfs_btree_search_result_alloc_buffer() - allocate result buffer
 * @search: search object
 * @buf_size: buffer size
 */
static inline int
ssdfs_btree_search_result_alloc_buffer(struct ssdfs_btree_search_buffer *buf,
					size_t buf_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!buf);
#endif /* CONFIG_SSDFS_DEBUG */

	buf->place.ptr = ssdfs_btree_search_kzalloc(buf_size, GFP_KERNEL);
	if (!buf->place.ptr) {
		SSDFS_ERR("fail to allocate buffer: size %zu\n",
			  buf_size);
		return -ENOMEM;
	}

	buf->state = SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER;
	buf->size = buf_size;

	buf->item_size = 0;
	buf->items_count = 0;
	return 0;
}

/*
 * ssdfs_btree_search_result_free_buffer() - free result buffer
 * @search: search object
 */
static inline void
ssdfs_btree_search_result_free_buffer(struct ssdfs_btree_search_buffer *buf)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (buf->state == SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER) {
		if (buf->place.ptr) {
			ssdfs_btree_search_kfree(buf->place.ptr);
		}
	}

	buf->state = SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE;
	buf->size = 0;
	buf->item_size = 0;
	buf->items_count = 0;
	buf->place.ptr = NULL;
}

/*
 * ssdfs_btree_search_alloc_result_buf() - allocate result buffer
 * @search: search object
 * @buf_size: buffer size
 */
int ssdfs_btree_search_alloc_result_buf(struct ssdfs_btree_search *search,
					size_t buf_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_btree_search_result_alloc_buffer(&search->result.raw_buf,
							buf_size);
}

/*
 * ssdfs_btree_search_free_result_buf() - free result buffer
 * @search: search object
 */
void ssdfs_btree_search_free_result_buf(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_btree_search_result_free_buffer(&search->result.raw_buf);
}

/*
 * ssdfs_btree_search_alloc_result_name() - allocate result name
 * @search: search object
 * @string_size: name string size
 */
int ssdfs_btree_search_alloc_result_name(struct ssdfs_btree_search *search,
					 size_t string_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_btree_search_result_alloc_buffer(&search->result.name_buf,
							string_size);
}

/*
 * ssdfs_btree_search_free_result_name() - free result name
 * @search: search object
 */
void ssdfs_btree_search_free_result_name(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_btree_search_result_free_buffer(&search->result.name_buf);
}

/*
 * ssdfs_btree_search_alloc_result_name_range() - allocate result name range
 * @search: search object
 * @ltbl2_size: lookup2 table size in bytes
 * @htbl_size: hash table size in bytes
 * @str_buf_size: strings buffer size in bytes
 */
int ssdfs_btree_search_alloc_result_name_range(struct ssdfs_btree_search *search,
						size_t ltbl2_size,
						size_t htbl_size,
						size_t str_buf_size)
{
	struct ssdfs_name_string_range *name_range;
	struct ssdfs_btree_search_buffer *buf;
	size_t ltbl2_item_size = sizeof(struct ssdfs_shdict_ltbl2_item);
	size_t htbl_item_size = sizeof(struct ssdfs_shdict_htbl_item);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
	BUG_ON(search->result.range_buf.state !=
			SSDFS_BTREE_SEARCH_UNKNOWN_BUFFER_STATE);
	BUG_ON(ltbl2_size == 0);
	BUG_ON(htbl_size == 0);
	BUG_ON(str_buf_size == 0);
	BUG_ON(ltbl2_size % ltbl2_item_size);
	BUG_ON(htbl_size % htbl_item_size);
	BUG_ON(search->name.range.lookup2_table.buf.place.ltbl2_items);
	BUG_ON(search->name.range.hash_table.buf.place.htbl_items);
	BUG_ON(search->name.range.strings.buf.place.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	name_range = &search->name.range;

	buf = &name_range->lookup2_table.buf;
	ssdfs_btree_search_buffer_init(buf);
	buf = &name_range->hash_table.buf;
	ssdfs_btree_search_buffer_init(buf);
	buf = &name_range->strings.buf;
	ssdfs_btree_search_buffer_init(buf);
	buf = &search->result.range_buf;
	ssdfs_btree_search_buffer_init(buf);

	buf = &name_range->lookup2_table.buf;
	err = ssdfs_btree_search_result_alloc_buffer(buf, ltbl2_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate lookup2 table buffer: "
			  "buf_size %zu, err %d\n",
			  ltbl2_size, err);
		goto free_memory;
	}
	buf->item_size = ltbl2_item_size;

	buf = &name_range->hash_table.buf;
	err = ssdfs_btree_search_result_alloc_buffer(buf, htbl_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate hash table buffer: "
			  "buf_size %zu, err %d\n",
			  htbl_size, err);
		goto free_memory;
	}
	buf->item_size = htbl_item_size;

	buf = &name_range->strings.buf;
	err = ssdfs_btree_search_result_alloc_buffer(buf, str_buf_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to allocate strings buffer: "
			  "buf_size %zu, err %d\n",
			  str_buf_size, err);
		goto free_memory;
	}

	buf = &search->result.range_buf;
	buf->place.name_range = name_range;
	buf->state = SSDFS_BTREE_SEARCH_INLINE_BUFFER;
	buf->size = sizeof(struct ssdfs_name_string_range);
	buf->item_size = sizeof(struct ssdfs_name_string_range);
	buf->items_count = 1;

	return 0;

free_memory:
	buf = &name_range->lookup2_table.buf;
	ssdfs_btree_search_result_free_buffer(buf);
	buf = &name_range->hash_table.buf;
	ssdfs_btree_search_result_free_buffer(buf);
	buf = &name_range->strings.buf;
	ssdfs_btree_search_result_free_buffer(buf);

	return -ENOMEM;
}

/*
 * ssdfs_btree_search_free_result_name_range() - free result name range
 * @search: search object
 */
void ssdfs_btree_search_free_result_name_range(struct ssdfs_btree_search *search)
{
	struct ssdfs_name_string_range *name_range;
	struct ssdfs_btree_search_buffer *buf;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!search);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (search->result.range_buf.state) {
	case SSDFS_BTREE_SEARCH_EXTERNAL_BUFFER:
		BUG();
		break;

	case SSDFS_BTREE_SEARCH_INLINE_BUFFER:
		name_range = &search->name.range;
		buf = &name_range->lookup2_table.buf;
		ssdfs_btree_search_result_free_buffer(buf);
		buf = &name_range->hash_table.buf;
		ssdfs_btree_search_result_free_buffer(buf);
		buf = &name_range->strings.buf;
		ssdfs_btree_search_result_free_buffer(buf);
		break;

	default:
		/* do nothing */
		break;
	}

	buf = &search->result.range_buf;
	ssdfs_btree_search_result_free_buffer(buf);
}

void ssdfs_debug_btree_search_object(struct ssdfs_btree_search *search)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct ssdfs_btree_index_key *node_index;
	struct ssdfs_shdict_ltbl2_item *ltbl2_item;
	struct ssdfs_btree_search_buffer *buf;
	void *kaddr;
	size_t bytes_count;
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

	SSDFS_DBG("RESULT: state %#x, err %d, flags %#x, "
		  "start_index %u, count %u, search_cno %llu\n",
		  search->result.state,
		  search->result.err,
		  search->result.flags,
		  search->result.start_index,
		  search->result.count,
		  search->result.search_cno);

	buf = &search->result.name_buf;
	SSDFS_DBG("NAME: state %#x, size %zu, "
		  "item_size %zu, items_count %u, ptr %p\n",
		  buf->state, buf->size, buf->item_size,
		  buf->items_count, buf->place.ptr);

	SSDFS_DBG("LOOKUP: index %u, hash_lo %u, "
		  "start_index %u, range_len %u\n",
		  search->name.string.lookup.index,
		  le32_to_cpu(search->name.string.lookup.desc.hash_lo),
		  le16_to_cpu(search->name.string.lookup.desc.start_index),
		  le16_to_cpu(search->name.string.lookup.desc.range_len));

	ltbl2_item = &search->name.string.strings_range.desc;
	SSDFS_DBG("STRINGS_RANGE: index %u, hash %#llx, "
		  "prefix_len %u, str_count %u, "
		  "hash_index %u\n",
		  search->name.string.strings_range.index,
		  le64_to_cpu(ltbl2_item->hash),
		  ltbl2_item->prefix_len,
		  ltbl2_item->str_count,
		  le16_to_cpu(ltbl2_item->hash_index));

	SSDFS_DBG("PREFIX: index %u, hash %#llx, "
		  "str_offset %u, str_len %u, type %#x\n",
		  search->name.string.prefix.index,
		  le64_to_cpu(search->name.string.prefix.desc.hash),
		  le16_to_cpu(search->name.string.prefix.desc.str_offset),
		  search->name.string.prefix.desc.str_len,
		  search->name.string.prefix.desc.type);

	SSDFS_DBG("LEFT_NAME: index %u, hash %#llx, "
		  "str_offset %u, str_len %u, type %#x\n",
		  search->name.string.left_name.index,
		  le64_to_cpu(search->name.string.left_name.desc.hash),
		  le16_to_cpu(search->name.string.left_name.desc.str_offset),
		  search->name.string.left_name.desc.str_len,
		  search->name.string.left_name.desc.type);

	SSDFS_DBG("RIGHT_NAME: index %u, hash %#llx, "
		  "str_offset %u, str_len %u, type %#x\n",
		  search->name.string.right_name.index,
		  le64_to_cpu(search->name.string.right_name.desc.hash),
		  le16_to_cpu(search->name.string.right_name.desc.str_offset),
		  search->name.string.right_name.desc.str_len,
		  search->name.string.right_name.desc.type);

	if (buf->place.ptr) {
		count = buf->items_count;

		if (count > 0)
			item_size = buf->size / count;
		else
			item_size = 0;

		for (i = 0; i < count; i++) {
			struct ssdfs_name_string *name;

			kaddr = (u8 *)buf->place.ptr + (i * item_size);
			name = (struct ssdfs_name_string *)kaddr;

			SSDFS_DBG("NAME: index %d, hash %llx, str_len %zu\n",
				  i, name->hash, name->len);

			SSDFS_DBG("LOOKUP: index %u, hash_lo %u, "
				  "start_index %u, range_len %u\n",
				  name->lookup.index,
				  le32_to_cpu(name->lookup.desc.hash_lo),
				  le16_to_cpu(name->lookup.desc.start_index),
				  le16_to_cpu(name->lookup.desc.range_len));

			ltbl2_item = &name->strings_range.desc;
			SSDFS_DBG("STRINGS_RANGE: index %u, hash %#llx, "
				  "prefix_len %u, str_count %u, "
				  "hash_index %u\n",
				  name->strings_range.index,
				  le64_to_cpu(ltbl2_item->hash),
				  ltbl2_item->prefix_len,
				  ltbl2_item->str_count,
				  le16_to_cpu(ltbl2_item->hash_index));

			SSDFS_DBG("PREFIX: index %u, hash %#llx, "
				  "str_offset %u, str_len %u, type %#x\n",
				  name->prefix.index,
				  le64_to_cpu(name->prefix.desc.hash),
				  le16_to_cpu(name->prefix.desc.str_offset),
				  name->prefix.desc.str_len,
				  name->prefix.desc.type);

			SSDFS_DBG("LEFT_NAME: index %u, hash %#llx, "
				  "str_offset %u, str_len %u, type %#x\n",
				  name->left_name.index,
				  le64_to_cpu(name->left_name.desc.hash),
				  le16_to_cpu(name->left_name.desc.str_offset),
				  name->left_name.desc.str_len,
				  name->left_name.desc.type);

			SSDFS_DBG("RIGHT_NAME: index %u, hash %#llx, "
				  "str_offset %u, str_len %u, type %#x\n",
				  name->right_name.index,
				  le64_to_cpu(name->right_name.desc.hash),
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

	SSDFS_DBG("NAME STRING RANGE: "
		  "lookup1 table (index %u), "
		  "lookup2_table (state %#x, items %p, "
		  "size %zu, item_size %zu, items_count %u), "
		  "hash_table (state %#x, items %p, "
		  "size %zu, item_size %zu, items_count %u), "
		  "strings (state %#x, buf %p, "
		  "size %zu)\n",
		  search->name.range.lookup1.index,
		  search->name.range.lookup2_table.buf.state,
		  search->name.range.lookup2_table.buf.place.ltbl2_items,
		  search->name.range.lookup2_table.buf.size,
		  search->name.range.lookup2_table.buf.item_size,
		  search->name.range.lookup2_table.buf.items_count,
		  search->name.range.hash_table.buf.state,
		  search->name.range.hash_table.buf.place.htbl_items,
		  search->name.range.hash_table.buf.size,
		  search->name.range.hash_table.buf.item_size,
		  search->name.range.hash_table.buf.items_count,
		  search->name.range.strings.buf.state,
		  search->name.range.strings.buf.place.ptr,
		  search->name.range.strings.buf.size);

	buf = &search->result.range_buf;
	if (buf->place.ptr) {
		struct ssdfs_btree_search_buffer *buf1;

		buf1 = &buf->place.name_range->lookup2_table.buf;
		if (buf1->place.ltbl2_items) {
			kaddr = buf1->place.ltbl2_items;
			bytes_count = buf1->size;

			SSDFS_DBG("LOOKUP2 TABLE DUMP:\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr, bytes_count);
			SSDFS_DBG("\n");
		}

		buf1 = &buf->place.name_range->hash_table.buf;
		if (buf1->place.htbl_items) {
			kaddr = buf1->place.htbl_items;
			bytes_count = buf1->size;

			SSDFS_DBG("HASH TABLE DUMP:\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr, bytes_count);
			SSDFS_DBG("\n");
		}

		buf1 = &buf->place.name_range->strings.buf;
		if (buf1->place.ptr) {
			kaddr = buf1->place.ptr;
			bytes_count = buf1->size;

			SSDFS_DBG("STRINGS DUMP:\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr, bytes_count);
			SSDFS_DBG("\n");
		}
	}

	buf = &search->result.raw_buf;
	SSDFS_DBG("RESULT BUFFER: state %#x, size %zu, "
		  "item_size %zu, items_count %u, ptr %p\n",
		  buf->state, buf->size, buf->item_size,
		  buf->items_count, buf->place.ptr);

	if (buf->place.ptr) {
		count = buf->items_count;

		if (count > 0)
			item_size = buf->size / count;
		else
			item_size = 0;

		for (i = 0; i < count; i++) {
			void *item;

			item = (u8 *)buf->place.ptr + (i * item_size);

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
