/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/extents_queue.c - extents queue implementation.
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

#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "segment_bitmap.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_queue.h"
#include "shared_extents_tree.h"
#include "extents_tree.h"
#include "xattr_tree.h"

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_ext_queue_folio_leaks;
atomic64_t ssdfs_ext_queue_memory_leaks;
atomic64_t ssdfs_ext_queue_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_ext_queue_cache_leaks_increment(void *kaddr)
 * void ssdfs_ext_queue_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_ext_queue_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_ext_queue_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_ext_queue_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_ext_queue_kfree(void *kaddr)
 * struct folio *ssdfs_ext_queue_alloc_folio(gfp_t gfp_mask,
 *                                           unsigned int order)
 * struct folio *ssdfs_ext_queue_add_batch_folio(struct folio_batch *batch,
 *                                               unsigned int order)
 * void ssdfs_ext_queue_free_folio(struct folio *folio)
 * void ssdfs_ext_queue_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(ext_queue)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(ext_queue)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_ext_queue_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_ext_queue_folio_leaks, 0);
	atomic64_set(&ssdfs_ext_queue_memory_leaks, 0);
	atomic64_set(&ssdfs_ext_queue_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_ext_queue_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_ext_queue_folio_leaks) != 0) {
		SSDFS_ERR("EXTENTS QUEUE: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_ext_queue_folio_leaks));
	}

	if (atomic64_read(&ssdfs_ext_queue_memory_leaks) != 0) {
		SSDFS_ERR("EXTENTS QUEUE: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_ext_queue_memory_leaks));
	}

	if (atomic64_read(&ssdfs_ext_queue_cache_leaks) != 0) {
		SSDFS_ERR("EXTENTS QUEUE: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_ext_queue_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static inline
void ssdfs_ext_queue_account_folio_batch(struct folio_batch *batch)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	int i;

	for (i = 0; i < folio_batch_count(batch); i++) {
		ssdfs_ext_queue_account_folio(batch->folios[i]);
	}

#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static struct kmem_cache *ssdfs_extent_info_cachep;

void ssdfs_zero_extent_info_cache_ptr(void)
{
	ssdfs_extent_info_cachep = NULL;
}

static
void ssdfs_init_extent_info_once(void *obj)
{
	struct ssdfs_extent_info *ei_obj = obj;

	memset(ei_obj, 0, sizeof(struct ssdfs_extent_info));
}

void ssdfs_shrink_extent_info_cache(void)
{
	if (ssdfs_extent_info_cachep)
		kmem_cache_shrink(ssdfs_extent_info_cachep);
}

void ssdfs_destroy_extent_info_cache(void)
{
	if (ssdfs_extent_info_cachep)
		kmem_cache_destroy(ssdfs_extent_info_cachep);
}

int ssdfs_init_extent_info_cache(void)
{
	ssdfs_extent_info_cachep = kmem_cache_create("ssdfs_extent_info_cache",
					sizeof(struct ssdfs_extent_info), 0,
					SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
					ssdfs_init_extent_info_once);
	if (!ssdfs_extent_info_cachep) {
		SSDFS_ERR("unable to create extent info objects cache\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * ssdfs_extents_queue_init() - initialize extents queue
 * @eq: initialized extents queue
 */
void ssdfs_extents_queue_init(struct ssdfs_extents_queue *eq)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!eq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock_init(&eq->lock);
	INIT_LIST_HEAD(&eq->list);
}

/*
 * is_ssdfs_extents_queue_empty() - check that extents queue is empty
 * @eq: extents queue
 */
bool is_ssdfs_extents_queue_empty(struct ssdfs_extents_queue *eq)
{
	bool is_empty;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!eq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&eq->lock);
	is_empty = list_empty_careful(&eq->list);
	spin_unlock(&eq->lock);

	return is_empty;
}

/*
 * ssdfs_extents_queue_add_head() - add extent at the head of queue
 * @eq: extents queue
 * @ei: extent info
 */
void ssdfs_extents_queue_add_head(struct ssdfs_extents_queue *eq,
				   struct ssdfs_extent_info *ei)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!eq || !ei);

	SSDFS_DBG("type %#x, owner_ino %llu\n",
		  ei->type, ei->owner_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&eq->lock);
	list_add(&ei->list, &eq->list);
	spin_unlock(&eq->lock);
}

/*
 * ssdfs_extents_queue_add_tail() - add extent at the tail of queue
 * @eq: extents queue
 * @ei: extent info
 */
void ssdfs_extents_queue_add_tail(struct ssdfs_extents_queue *eq,
				   struct ssdfs_extent_info *ei)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!eq || !ei);

	SSDFS_DBG("type %#x, owner_ino %llu\n",
		  ei->type, ei->owner_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&eq->lock);
	list_add_tail(&ei->list, &eq->list);
	spin_unlock(&eq->lock);
}

/*
 * ssdfs_extents_queue_remove_first() - get extent and remove from queue
 * @eq: extents queue
 * @ei: first extent [out]
 *
 * This function get first extent in @eq, remove it from queue
 * and return as @ei.
 *
 * RETURN:
 * [success] - @ei contains pointer on extent.
 * [failure] - error code:
 *
 * %-ENODATA     - queue is empty.
 * %-ENOENT      - first entry is NULL.
 */
int ssdfs_extents_queue_remove_first(struct ssdfs_extents_queue *eq,
				      struct ssdfs_extent_info **ei)
{
	bool is_empty;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!eq || !ei);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&eq->lock);
	is_empty = list_empty_careful(&eq->list);
	if (!is_empty) {
		*ei = list_first_entry_or_null(&eq->list,
						struct ssdfs_extent_info,
						list);
		if (!*ei) {
			SSDFS_WARN("first entry is NULL\n");
			err = -ENOENT;
		} else
			list_del(&(*ei)->list);
	}
	spin_unlock(&eq->lock);

	if (is_empty) {
		SSDFS_WARN("extents queue is empty\n");
		err = -ENODATA;
	}

	return err;
}

/*
 * ssdfs_extents_queue_remove_all() - remove all extents from queue
 * @eq: extents queue
 *
 * This function removes all extents from the queue.
 */
void ssdfs_extents_queue_remove_all(struct ssdfs_extents_queue *eq)
{
	bool is_empty;
	LIST_HEAD(tmp_list);
	struct list_head *this, *next;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!eq);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&eq->lock);
	is_empty = list_empty_careful(&eq->list);
	if (!is_empty)
		list_replace_init(&eq->list, &tmp_list);
	spin_unlock(&eq->lock);

	if (is_empty)
		return;

	list_for_each_safe(this, next, &tmp_list) {
		struct ssdfs_extent_info *ei;

		ei = list_entry(this, struct ssdfs_extent_info, list);
		list_del(&ei->list);

		switch (ei->type) {
		case SSDFS_EXTENT_INFO_RAW_EXTENT:
			SSDFS_WARN("delete extent: "
				   "seg_id %llu, logical_blk %u, len %u\n",
				   le64_to_cpu(ei->raw.extent.seg_id),
				   le32_to_cpu(ei->raw.extent.logical_blk),
				   le32_to_cpu(ei->raw.extent.len));
			break;

		case SSDFS_EXTENT_INFO_INDEX_DESCRIPTOR:
		case SSDFS_EXTENT_INFO_DENTRY_INDEX_DESCRIPTOR:
		case SSDFS_EXTENT_INFO_SHDICT_INDEX_DESCRIPTOR:
		case SSDFS_EXTENT_INFO_XATTR_INDEX_DESCRIPTOR:
			SSDFS_WARN("delete index: "
				   "node_id %u, node_type %#x, height %u, "
				   "seg_id %llu, logical_blk %u, len %u\n",
			    le32_to_cpu(ei->raw.index.node_id),
			    ei->raw.index.node_type,
			    ei->raw.index.height,
			    le64_to_cpu(ei->raw.index.index.extent.seg_id),
			    le32_to_cpu(ei->raw.index.index.extent.logical_blk),
			    le32_to_cpu(ei->raw.index.index.extent.len));
			break;

		default:
			SSDFS_WARN("invalid extent info type %#x\n",
				   ei->type);
			break;
		}

		ssdfs_extent_info_free(ei);
	}
}

/*
 * ssdfs_extent_info_alloc() - allocate memory for extent info object
 */
struct ssdfs_extent_info *ssdfs_extent_info_alloc(void)
{
	struct ssdfs_extent_info *ptr;
	unsigned int nofs_flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_extent_info_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	nofs_flags = memalloc_nofs_save();
	ptr = kmem_cache_alloc(ssdfs_extent_info_cachep, GFP_KERNEL);
	memalloc_nofs_restore(nofs_flags);

	if (!ptr) {
		SSDFS_ERR("fail to allocate memory for extent\n");
		return ERR_PTR(-ENOMEM);
	}

	ssdfs_ext_queue_cache_leaks_increment(ptr);

	return ptr;
}

/*
 * ssdfs_extent_info_free() - free memory for extent info object
 */
void ssdfs_extent_info_free(struct ssdfs_extent_info *ei)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ssdfs_extent_info_cachep);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!ei)
		return;

	ssdfs_ext_queue_cache_leaks_decrement(ei);
	kmem_cache_free(ssdfs_extent_info_cachep, ei);
}

/*
 * ssdfs_extent_info_init() - extent info initialization
 * @type: extent info type
 * @ptr: pointer on extent info item
 * @owner_ino: btree's owner inode id
 * @ei: extent info [out]
 */
void ssdfs_extent_info_init(int type, void *ptr, u64 owner_ino,
			    struct ssdfs_extent_info *ei)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr || !ei);
#endif /* CONFIG_SSDFS_DEBUG */

	memset(ei, 0, sizeof(struct ssdfs_extent_info));

	INIT_LIST_HEAD(&ei->list);
	ei->type = SSDFS_EXTENT_INFO_UNKNOWN_TYPE;

	switch (type) {
	case SSDFS_EXTENT_INFO_RAW_EXTENT:
		ei->type = type;
		ei->owner_ino = owner_ino;
		ssdfs_memcpy(&ei->raw.extent,
			     0, sizeof(struct ssdfs_raw_extent),
			     ptr,
			     0, sizeof(struct ssdfs_raw_extent),
			     sizeof(struct ssdfs_raw_extent));
		break;

	case SSDFS_EXTENT_INFO_INDEX_DESCRIPTOR:
	case SSDFS_EXTENT_INFO_DENTRY_INDEX_DESCRIPTOR:
	case SSDFS_EXTENT_INFO_SHDICT_INDEX_DESCRIPTOR:
	case SSDFS_EXTENT_INFO_XATTR_INDEX_DESCRIPTOR:
		ei->type = type;
		ei->owner_ino = owner_ino;
		ssdfs_memcpy(&ei->raw.index,
			     0, sizeof(struct ssdfs_btree_index_key),
			     ptr,
			     0, sizeof(struct ssdfs_btree_index_key),
			     sizeof(struct ssdfs_btree_index_key));
		break;

	default:
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#else
		SSDFS_WARN("invalid type %#x\n", type);
#endif /* CONFIG_SSDFS_DEBUG */
		break;
	}
}

static inline
int ssdfs_mark_segment_under_invalidation(struct ssdfs_segment_info *si)
{
	int activity_type;

	activity_type = atomic_cmpxchg(&si->activity_type,
				SSDFS_SEG_OBJECT_REGULAR_ACTIVITY,
				SSDFS_SEG_UNDER_INVALIDATION);
	if (activity_type != SSDFS_SEG_OBJECT_REGULAR_ACTIVITY) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu is busy under activity %#x\n",
			   si->seg_id, activity_type);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EBUSY;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segment %llu is under invalidation\n",
		  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

static inline
int ssdfs_revert_invalidation_to_regular_activity(struct ssdfs_segment_info *si)
{
	int activity_type;

	activity_type = atomic_cmpxchg(&si->activity_type,
				SSDFS_SEG_UNDER_INVALIDATION,
				SSDFS_SEG_OBJECT_REGULAR_ACTIVITY);
	if (activity_type != SSDFS_SEG_UNDER_INVALIDATION) {
		SSDFS_WARN("segment %llu is under activity %#x\n",
			   si->seg_id, activity_type);
		return -EFAULT;
	}

	wake_up_all(&si->wait_queue[SSDFS_PEB_FLUSH_THREAD]);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("segment %llu has been reverted from invalidation\n",
		  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_init_node_content() - init btree node's content
 * @fsi: pointer on shared file system object
 * @content: buffer for btree node's content
 * @node_size: node size in bytes
 */
static inline
int ssdfs_init_node_content(struct ssdfs_fs_info *fsi,
			    struct ssdfs_btree_node_content *content,
			    u32 node_size)
{
	u32 len;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !content);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_btree_node_content_init(content);

	len = node_size / fsi->pagesize;

	if (len == 0 || len > SSDFS_BTREE_NODE_EXTENT_LEN_MAX) {
		SSDFS_ERR("invalid blocks_count %u\n", len);
		return -ERANGE;
	}

	for (i = 0; i < len; i++) {
		struct folio_batch *batch = &content->blocks[i].batch;
		folio_batch_init(batch);
		content->count++;
	}

	return 0;
}

/*
 * ssdfs_destroy_btree_node_content() - destroy btree node's content
 * @content: buffer for btree node's content
 */
static inline
void ssdfs_destroy_btree_node_content(struct ssdfs_btree_node_content *content)
{
	struct ssdfs_content_block *blk;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!content);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < content->count; i++) {
		blk = &content->blocks[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(folio_batch_count(&blk->batch) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_ext_queue_folio_batch_release(&blk->batch);
	}
}

/*
 * ssdfs_invalidate_index_area() - invalidate index area
 * @fsi: pointer on shared file system object
 * @shextree: shared dictionary tree
 * @owner_ino: inode ID of btree's owner
 * @node_size: node size in bytes
 * @content: btree node's content
 *
 * This method tries to invalidate the index area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - node is corrupted.
 */
static
int ssdfs_invalidate_index_area(struct ssdfs_fs_info *fsi,
				struct ssdfs_shared_extents_tree *shextree,
				u64 owner_ino,
				struct ssdfs_btree_node_header *hdr,
				u32 node_size,
				struct ssdfs_btree_node_content *content)
{
	struct ssdfs_btree_index_key cur_index;
	u8 index_size;
	u16 index_count;
	u32 area_offset, area_size;
	u16 flags;
	int index_type = SSDFS_EXTENT_INFO_UNKNOWN_TYPE;
	u32 node_id1, node_id2;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!shextree || !hdr || !content);

	SSDFS_DBG("owner_id %llu, node_size %u\n",
		  owner_ino, node_size);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (le16_to_cpu(hdr->magic.key)) {
	case SSDFS_EXTENTS_BNODE_MAGIC:
		index_type = SSDFS_EXTENT_INFO_INDEX_DESCRIPTOR;
		break;

	case SSDFS_DENTRIES_BNODE_MAGIC:
		index_type = SSDFS_EXTENT_INFO_DENTRY_INDEX_DESCRIPTOR;
		break;

	case SSDFS_DICTIONARY_BNODE_MAGIC:
		index_type = SSDFS_EXTENT_INFO_SHDICT_INDEX_DESCRIPTOR;
		break;

	case SSDFS_XATTR_BNODE_MAGIC:
		index_type = SSDFS_EXTENT_INFO_XATTR_INDEX_DESCRIPTOR;
		break;

	default:
		SSDFS_ERR("unsupported btree: magic %#x\n",
			  le16_to_cpu(hdr->magic.key));
		return -ERANGE;
	}

	index_size = hdr->index_size;
	index_count = le16_to_cpu(hdr->index_count);

	area_offset = le16_to_cpu(hdr->index_area_offset);
	area_size = 1 << hdr->log_index_area_size;

	if (area_size < ((u32)index_count * index_size)) {
		SSDFS_ERR("corrupted node header: "
			  "index_size %u, index_count %u, "
			  "area_size %u\n",
			  index_size, index_count, area_size);
		return -EIO;
	}

	for (i = 0; i < index_count; i++) {
		err = ssdfs_btree_node_get_index(fsi,
						 content,
						 area_offset,
						 area_size,
						 node_size,
						 i,
						 &cur_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to get index: "
				  "position %u, err %d\n",
				  i, err);
			return err;
		}

		node_id1 = le32_to_cpu(cur_index.node_id);
		node_id2 = le32_to_cpu(hdr->node_id);

		if (node_id1 >= U32_MAX) {
			SSDFS_ERR("corrupted index: "
				  "node_id %u\n",
				  node_id1);
			return -EIO;
		}

		if (node_id2 >= U32_MAX) {
			SSDFS_ERR("corrupted node header: "
				  "node_id %u\n",
				  node_id2);
			return -EIO;
		}

		switch (cur_index.node_type) {
		case SSDFS_BTREE_HYBRID_NODE:
			if (node_id1 == node_id2) {
				SSDFS_DBG("items area has been invalidated: "
					  "node_id %u\n",
					  node_id2);
				continue;
			}
			break;

		case SSDFS_BTREE_INDEX_NODE:
		case SSDFS_BTREE_LEAF_NODE:
			if (node_id1 == node_id2) {
				SSDFS_DBG("corrupted index area: "
					  "node_id %u\n",
					  node_id2);
				return -EFAULT;
			}
			break;

		default:
			SSDFS_ERR("corrupted index: "
				  "invalid node type %#x\n",
				  cur_index.node_type);
			return -EIO;
		}

		if (cur_index.height >= U8_MAX) {
			SSDFS_ERR("corrupted index: "
				  "invalid height %u\n",
				  cur_index.height);
			return -EIO;
		}

		flags = le16_to_cpu(cur_index.flags);
		if (flags & ~SSDFS_BTREE_INDEX_FLAGS_MASK) {
			SSDFS_ERR("corrupted index: "
				  "invalid flags set %#x\n",
				  flags);
			return -EIO;
		}

		if (le64_to_cpu(cur_index.index.hash) >= U64_MAX) {
			SSDFS_ERR("corrupted index: "
				  "invalid hash %llx\n",
				  le64_to_cpu(cur_index.index.hash));
			return -EIO;
		}

		err = ssdfs_shextree_add_pre_invalid_index(shextree,
							   owner_ino,
							   index_type,
							   &cur_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add pre-invalid index: "
				  "position %u, err %d\n",
				  i, err);
			return err;
		}
	}

	return 0;
}

/*
 * __ssdfs_invalidate_btree_index() - invalidate btree's index
 * @fsi: pointer on shared file system object
 * @content: buffer for btree node's content
 * @owner_ino: inode ID of btree's owner
 * @node_size: node size in bytes
 * @hdr: pointer on header's buffer
 * @hdr_size: size of the header in bytes
 * @extent: extent for invalidation
 *
 * This method tries to invalidate the index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - node is corrupted.
 */
static
int __ssdfs_invalidate_btree_index(struct ssdfs_fs_info *fsi,
				   struct ssdfs_btree_node_content *content,
				   u64 owner_ino,
				   u32 node_size,
				   void *hdr,
				   size_t hdr_size,
				   struct ssdfs_btree_index_key *index)
{
	struct ssdfs_shared_extents_tree *shextree = NULL;
	struct ssdfs_segment_info *si = NULL;
	struct ssdfs_btree_node_header *hdr_ptr;
	struct ssdfs_content_block *blk;
	struct folio *folio;
	u32 node_id1, node_id2;
	int node_type1, node_type2;
	u8 height1, height2;
	u16 flags;
	bool has_index_area, has_items_area;
	u32 start_blk;
	u32 len;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !content || !hdr || !index);

	SSDFS_DBG("node_id %u, node_type %#x, "
		  "height %u, owner_ino %llu, "
		  "node_size %u, hdr_size %zu\n",
		  le32_to_cpu(index->node_id),
		  index->node_type,
		  index->height,
		  owner_ino,
		  node_size,
		  hdr_size);
#endif /* CONFIG_SSDFS_DEBUG */

	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	hdr_ptr = (struct ssdfs_btree_node_header *)hdr;

	err = ssdfs_init_node_content(fsi, content, node_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init node's content: "
			  "node_id %u, node_type %#x, "
			  "owner_ino %llu, err %d\n",
			  le32_to_cpu(index->node_id),
			  index->node_type,
			  owner_ino, err);
		goto fail_invalidate_index;
	}

	err = __ssdfs_btree_node_prepare_content(fsi, index, node_size,
						 owner_ino, &si, content);
	if (err == -ENODATA) {
		SSDFS_DBG("unable to prepare node's content: "
			  "node_id %u, node_type %#x, "
			  "owner_ino %llu, err %d\n",
			  le32_to_cpu(index->node_id),
			  index->node_type,
			  owner_ino, err);
		goto fail_invalidate_index;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to prepare node's content: "
			  "node_id %u, node_type %#x, "
			  "owner_ino %llu, err %d\n",
			  le32_to_cpu(index->node_id),
			  index->node_type,
			  owner_ino, err);
		goto fail_invalidate_index;
	}

	if (content->count == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty node's content: id %u\n",
			  le32_to_cpu(index->node_id));
		goto finish_invalidate_index;
	}

	blk = &content->blocks[0];
	folio = blk->batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	__ssdfs_memcpy_from_folio(hdr, 0, hdr_size,
				  folio, 0, PAGE_SIZE,
				  hdr_size);

	if (!is_csum_valid(&hdr_ptr->check, hdr_ptr, hdr_size)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum: node_id %u\n",
			  le32_to_cpu(index->node_id));
	}

	if (unlikely(err))
		goto finish_invalidate_index;

	if (node_size != (1 << hdr_ptr->log_node_size)) {
		err = -EIO;
		SSDFS_ERR("node_size1 %u != node_size2 %u\n",
			  node_size,
			  1 << hdr_ptr->log_node_size);
		goto finish_invalidate_index;
	}

	node_id1 = le32_to_cpu(index->node_id);
	node_id2 = le32_to_cpu(hdr_ptr->node_id);

	if (node_id1 != node_id2) {
		err = -ERANGE;
		SSDFS_ERR("node_id1 %u != node_id2 %u\n",
			  node_id1, node_id2);
		goto finish_invalidate_index;
	}

	node_type1 = index->node_type;
	node_type2 = hdr_ptr->type;

	if (node_type1 != node_type2) {
		err = -ERANGE;
		SSDFS_ERR("node_type1 %#x != node_type2 %#x\n",
			  node_type1, node_type2);
		goto finish_invalidate_index;
	}

	height1 = index->height;
	height2 = hdr_ptr->height;

	if (height1 != height2) {
		err = -ERANGE;
		SSDFS_ERR("height1 %u != height2 %u\n",
			  height1, height2);
		goto finish_invalidate_index;
	}

	flags = le16_to_cpu(hdr_ptr->flags);

	if (flags & ~SSDFS_BTREE_NODE_FLAGS_MASK) {
		err = -EIO;
		SSDFS_ERR("corrupted node header: flags %#x\n",
			  flags);
		goto finish_invalidate_index;
	}

	has_index_area = flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA;
	has_items_area = flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA;

	if (!has_index_area && !has_items_area) {
		err = -EIO;
		SSDFS_ERR("corrupted node header: no areas\n");
		goto finish_invalidate_index;
	}

	if (has_index_area) {
		err = ssdfs_invalidate_index_area(fsi, shextree, owner_ino,
						  hdr_ptr,
						  node_size, content);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate index area: "
				  "err %d\n", err);
			goto finish_invalidate_index;
		}
	}

	start_blk = le32_to_cpu(index->index.extent.logical_blk);
	len = le32_to_cpu(index->index.extent.len);

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, err %d\n",
				  si->seg_id, err);
			goto finish_invalidate_index;
		}
	}

	err = ssdfs_mark_segment_under_invalidation(si);
	if (err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu is busy\n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_invalidate_index;
	}

	err = ssdfs_segment_invalidate_logical_extent(si, start_blk, len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate node: "
			  "node_id %u, seg_id %llu, "
			  "start_blk %u, len %u\n",
			  node_id1, si->seg_id,
			  start_blk, len);
		goto revert_invalidation_state;
	}

	for (i = 0; i < si->pebs_count; i++) {
		struct ssdfs_segment_request *req;

		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			goto revert_invalidation_state;
		}

		ssdfs_request_init(req, fsi->pagesize);
		ssdfs_get_request(req);

		err = ssdfs_segment_commit_log_async2(si, SSDFS_REQ_ASYNC,
						      i, req);
		if (unlikely(err)) {
			SSDFS_ERR("commit log request failed: "
				  "peb_index %d, err %d\n",
				  i, err);
			ssdfs_put_request(req);
			ssdfs_request_free(req, si);
			goto revert_invalidation_state;
		}
	}

revert_invalidation_state:
	err = ssdfs_revert_invalidation_to_regular_activity(si);
	if (unlikely(err)) {
		SSDFS_ERR("unexpected segment %llu activity\n",
			  si->seg_id);
	}

finish_invalidate_index:
	ssdfs_segment_put_object(si);

fail_invalidate_index:
	ssdfs_destroy_btree_node_content(content);

	return err;
}

/*
 * ssdfs_invalidate_dentries_btree_index() - invalidate dentries btree index
 * @fsi: pointer on shared file system object
 * @content: buffer for btree node's content
 * @owner_ino: inode ID of btree's owner
 * @extent: extent for invalidation
 *
 * This method tries to invalidate the index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - node is corrupted.
 */
int ssdfs_invalidate_dentries_btree_index(struct ssdfs_fs_info *fsi,
				    struct ssdfs_btree_node_content *content,
				    u64 owner_ino,
				    struct ssdfs_btree_index_key *index)
{
	struct ssdfs_dentries_btree_descriptor *dentries_btree;
	u32 node_size;
	struct ssdfs_dentries_btree_node_header hdr;
	size_t hdr_size = sizeof(struct ssdfs_dentries_btree_node_header);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !index);

	SSDFS_DBG("node_id %u, node_type %#x, "
		  "height %u, owner_ino %llu\n",
		  le32_to_cpu(index->node_id),
		  index->node_type,
		  index->height,
		  owner_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	dentries_btree = &fsi->vh->dentries_btree;
	node_size = 1 << dentries_btree->desc.log_node_size;

	return __ssdfs_invalidate_btree_index(fsi, content, owner_ino, node_size,
					      &hdr, hdr_size, index);
}

/*
 * ssdfs_invalidate_shared_dict_btree_index() - invalidate shared dict index
 * @fsi: pointer on shared file system object
 * @content: buffer for btree node's content
 * @owner_ino: inode ID of btree's owner
 * @extent: extent for invalidation
 *
 * This method tries to invalidate the index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - node is corrupted.
 */
int ssdfs_invalidate_shared_dict_btree_index(struct ssdfs_fs_info *fsi,
				    struct ssdfs_btree_node_content *content,
				    u64 owner_ino,
				    struct ssdfs_btree_index_key *index)
{
	struct ssdfs_shared_dictionary_btree *shared_dict;
	struct ssdfs_shared_dictionary_node_header hdr;
	size_t hdr_size = sizeof(struct ssdfs_shared_dictionary_node_header);
	u32 node_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !content || !index);

	SSDFS_DBG("node_id %u, node_type %#x, "
		  "height %u, owner_ino %llu\n",
		  le32_to_cpu(index->node_id),
		  index->node_type,
		  index->height,
		  owner_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	shared_dict = &fsi->vs->shared_dict_btree;
	node_size = 1 << shared_dict->desc.log_node_size;

	return __ssdfs_invalidate_btree_index(fsi, content, owner_ino, node_size,
					      &hdr, hdr_size, index);
}

/*
 * ssdfs_invalidate_extents_btree_index() - invalidate extents btree index
 * @fsi: pointer on shared file system object
 * @content: buffer for btree node's content
 * @owner_ino: inode ID of btree's owner
 * @extent: extent for invalidation
 *
 * This method tries to invalidate the index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - node is corrupted.
 */
int ssdfs_invalidate_extents_btree_index(struct ssdfs_fs_info *fsi,
				    struct ssdfs_btree_node_content *content,
				    u64 owner_ino,
				    struct ssdfs_btree_index_key *index)
{
	struct ssdfs_shared_extents_tree *shextree = NULL;
	struct ssdfs_segment_info *si = NULL;
	struct ssdfs_extents_btree_descriptor *extents_btree;
	struct ssdfs_content_block *blk;
	struct ssdfs_btree_node_header hdr;
	struct ssdfs_extents_btree_node_header *hdr_ptr;
	struct folio *folio;
	void *kaddr;
	size_t hdr_size = sizeof(struct ssdfs_extents_btree_node_header);
	u32 node_size;
	u64 parent_ino;
	u64 blks_count, calculated_blks = 0;
	u32 forks_count;
	u32 allocated_extents;
	u32 valid_extents;
	u32 max_extent_blks;
	u32 node_id1, node_id2;
	int node_type1, node_type2;
	u8 height1, height2;
	u16 flags;
	u32 area_offset, area_size;
	bool has_index_area, has_items_area;
	u32 i;
	u32 start_blk;
	u32 len;
	int err = 0, err1;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !content || !index);

	SSDFS_DBG("node_id %u, node_type %#x, "
		  "height %u, owner_ino %llu\n",
		  le32_to_cpu(index->node_id),
		  index->node_type,
		  index->height,
		  owner_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	extents_btree = &fsi->vh->extents_btree;
	node_size = 1 << extents_btree->desc.log_node_size;

	err = ssdfs_init_node_content(fsi, content, node_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init node's content: "
			  "node_id %u, node_type %#x, "
			  "owner_ino %llu, err %d\n",
			  le32_to_cpu(index->node_id),
			  index->node_type,
			  owner_ino, err);
		goto fail_invalidate_extents_btree_index;
	}

	err = __ssdfs_btree_node_prepare_content(fsi, index, node_size,
						 owner_ino, &si, content);
	if (err == -ENODATA) {
		SSDFS_DBG("unable to prepare node's content: "
			  "node_id %u, node_type %#x, "
			  "owner_ino %llu, err %d\n",
			  le32_to_cpu(index->node_id),
			  index->node_type,
			  owner_ino, err);
		goto fail_invalidate_extents_btree_index;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to prepare node's content: "
			  "node_id %u, node_type %#x, "
			  "owner_ino %llu, err %d\n",
			  le32_to_cpu(index->node_id),
			  index->node_type,
			  owner_ino, err);
		goto fail_invalidate_extents_btree_index;
	}

	if (content->count == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty node's content: id %u\n",
			  le32_to_cpu(index->node_id));
		goto finish_invalidate_index;
	}

	blk = &content->blocks[0];
	folio = blk->batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = kmap_local_folio(folio, 0);

	ssdfs_memcpy(&hdr, 0, sizeof(struct ssdfs_btree_node_header),
		     kaddr, 0, PAGE_SIZE,
		     sizeof(struct ssdfs_btree_node_header));

	hdr_ptr = (struct ssdfs_extents_btree_node_header *)kaddr;
	parent_ino = le64_to_cpu(hdr_ptr->parent_ino);
	blks_count = le64_to_cpu(hdr_ptr->blks_count);
	forks_count = le32_to_cpu(hdr_ptr->forks_count);
	allocated_extents = le32_to_cpu(hdr_ptr->allocated_extents);
	valid_extents = le32_to_cpu(hdr_ptr->valid_extents);
	max_extent_blks = le32_to_cpu(hdr_ptr->max_extent_blks);

	if (!is_csum_valid(&hdr_ptr->node.check, hdr_ptr, hdr_size)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum: node_id %u\n",
			  le32_to_cpu(index->node_id));
	}

	hdr_ptr = NULL;
	kunmap_local(kaddr);

	if (unlikely(err))
		goto finish_invalidate_index;

	if (node_size != (1 << hdr.log_node_size)) {
		err = -EIO;
		SSDFS_ERR("node_size1 %u != node_size2 %u\n",
			  node_size,
			  1 << hdr.log_node_size);
		goto finish_invalidate_index;
	}

	node_id1 = le32_to_cpu(index->node_id);
	node_id2 = le32_to_cpu(hdr.node_id);

	if (node_id1 != node_id2) {
		err = -ERANGE;
		SSDFS_ERR("node_id1 %u != node_id2 %u\n",
			  node_id1, node_id2);
		goto finish_invalidate_index;
	}

	node_type1 = index->node_type;
	node_type2 = hdr.type;

	if (node_type1 != node_type2) {
		err = -ERANGE;
		SSDFS_ERR("node_type1 %#x != node_type2 %#x\n",
			  node_type1, node_type2);
		goto finish_invalidate_index;
	}

	height1 = index->height;
	height2 = hdr.height;

	if (height1 != height2) {
		err = -ERANGE;
		SSDFS_ERR("height1 %u != height2 %u\n",
			  height1, height2);
		goto finish_invalidate_index;
	}

	flags = le16_to_cpu(hdr.flags);

	if (flags & ~SSDFS_BTREE_NODE_FLAGS_MASK) {
		err = -EIO;
		SSDFS_ERR("corrupted node header: flags %#x\n",
			  flags);
		goto finish_invalidate_index;
	}

	has_index_area = flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA;
	has_items_area = flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA;

	if (!has_index_area && !has_items_area) {
		err = -EIO;
		SSDFS_ERR("corrupted node header: no areas\n");
		goto finish_invalidate_index;
	}

	if (has_index_area) {
		err = ssdfs_invalidate_index_area(fsi, shextree,
						  owner_ino, &hdr,
						  node_size, content);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate index area: "
				  "err %d\n", err);
			goto finish_invalidate_index;
		}
	}

	if (has_items_area) {
		struct ssdfs_raw_fork fork;
		u64 forks_size;
		u64 start_hash, end_hash;

		forks_size = (u64)forks_count * sizeof(struct ssdfs_raw_fork);
		area_offset = le32_to_cpu(hdr.item_area_offset);
		start_hash = le64_to_cpu(hdr.start_hash);
		end_hash = le64_to_cpu(hdr.end_hash);

		if (area_offset >= node_size) {
			err = -EIO;
			SSDFS_ERR("area_offset %u >= node_size %u\n",
				  area_offset, node_size);
			goto finish_invalidate_index;
		}

		area_size = node_size - area_offset;

		if (area_size < forks_size) {
			err = -EIO;
			SSDFS_ERR("corrupted node header: "
				  "fork_size %lu, forks_count %u, "
				  "area_size %u\n",
				  sizeof(struct ssdfs_raw_fork),
				  forks_count, area_size);
			goto finish_invalidate_index;
		}

		for (i = 0; i < forks_count; i++) {
			u64 start_offset, fork_blks;

			err = __ssdfs_extents_btree_node_get_fork(fsi,
								  content,
								  area_offset,
								  area_size,
								  node_size,
								  i,
								  &fork);
			if (unlikely(err)) {
				SSDFS_ERR("fail to get fork: "
					  "fork_index %u\n",
					  i);
				goto finish_invalidate_index;
			}

			start_offset = le64_to_cpu(fork.start_offset);
			fork_blks = le64_to_cpu(fork.blks_count);

			if (start_offset >= U64_MAX || fork_blks >= U64_MAX) {
				err = -EIO;
				SSDFS_ERR("corrupted fork: "
					  "start_offset %llu, "
					  "blks_count %llu\n",
					  start_offset, fork_blks);
				goto finish_invalidate_index;
			}

			if (fork_blks == 0) {
				err = -EIO;
				SSDFS_ERR("corrupted fork: "
					  "start_offset %llu, "
					  "blks_count %llu\n",
					  start_offset, fork_blks);
				goto finish_invalidate_index;
			}

			if (start_offset < start_hash ||
			    start_offset > end_hash) {
				err = -EIO;
				SSDFS_ERR("corrupted fork: "
					  "start_hash %llx, end_hash %llx, "
					  "start_offset %llu\n",
					  start_hash, end_hash,
					  start_offset);
				goto finish_invalidate_index;
			}

			calculated_blks += fork_blks;

			if (calculated_blks > blks_count) {
				err = -EIO;
				SSDFS_ERR("corrupted fork: "
					  "calculated_blks %llu, "
					  "blks_count %llu\n",
					  calculated_blks,
					  blks_count);
				goto finish_invalidate_index;
			}

			err = ssdfs_shextree_add_pre_invalid_fork(shextree,
								  owner_ino,
								  &fork);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add the fork into queue: "
					  "fork_index %u, err %d\n",
					  i, err);
				goto finish_invalidate_index;
			}
		}
	}

	start_blk = le32_to_cpu(index->index.extent.logical_blk);
	len = le32_to_cpu(index->index.extent.len);

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, err %d\n",
				  si->seg_id, err);
			goto finish_invalidate_index;
		}
	}

	err = ssdfs_mark_segment_under_invalidation(si);
	if (err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu is busy\n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_invalidate_index;
	}

	err = ssdfs_segment_invalidate_logical_extent(si, start_blk, len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate node: "
			  "node_id %u, seg_id %llu, "
			  "start_blk %u, len %u\n",
			  node_id1, si->seg_id,
			  start_blk, len);
		goto revert_invalidation_state;
	}

	for (i = 0; i < si->pebs_count; i++) {
		struct ssdfs_segment_request *req;

		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			goto revert_invalidation_state;
		}

		ssdfs_request_init(req, fsi->pagesize);
		ssdfs_get_request(req);

		err = ssdfs_segment_commit_log_async2(si, SSDFS_REQ_ASYNC,
						      i, req);
		if (unlikely(err)) {
			SSDFS_ERR("commit log request failed: "
				  "peb_index %d, err %d\n",
				  i, err);
			ssdfs_put_request(req);
			ssdfs_request_free(req, si);
			goto revert_invalidation_state;
		}
	}

revert_invalidation_state:
	err1 = ssdfs_revert_invalidation_to_regular_activity(si);
	if (unlikely(err1)) {
		SSDFS_ERR("unexpected segment %llu activity\n",
			  si->seg_id);
	}

finish_invalidate_index:
	ssdfs_segment_put_object(si);

fail_invalidate_extents_btree_index:
	ssdfs_destroy_btree_node_content(content);

	return err;
}

/*
 * ssdfs_invalidate_xattrs_btree_index() - invalidate xattrs btree index
 * @fsi: pointer on shared file system object
 * @content: buffer for btree node's content
 * @owner_ino: inode ID of btree's owner
 * @extent: extent for invalidation
 *
 * This method tries to invalidate the index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - node is corrupted.
 */
int ssdfs_invalidate_xattrs_btree_index(struct ssdfs_fs_info *fsi,
				    struct ssdfs_btree_node_content *content,
				    u64 owner_ino,
				    struct ssdfs_btree_index_key *index)
{
	struct ssdfs_shared_extents_tree *shextree = NULL;
	struct ssdfs_segment_info *si = NULL;
	struct ssdfs_xattr_btree_descriptor *xattrs_btree;
	struct ssdfs_content_block *blk;
	struct ssdfs_btree_node_header hdr;
	struct ssdfs_xattrs_btree_node_header *hdr_ptr;
	struct folio *folio;
	void *kaddr;
	size_t hdr_size = sizeof(struct ssdfs_xattrs_btree_node_header);
	u32 node_size;
	u64 parent_ino;
	u32 xattrs_count;
	u32 node_id1, node_id2;
	int node_type1, node_type2;
	u8 height1, height2;
	u16 flags;
	u32 area_offset, area_size;
	bool has_index_area, has_items_area;
	u32 i;
	u32 start_blk;
	u32 len;
	int err = 0, err1;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !content || !index);

	SSDFS_DBG("node_id %u, node_type %#x, "
		  "height %u, owner_ino %llu\n",
		  le32_to_cpu(index->node_id),
		  index->node_type,
		  index->height,
		  owner_ino);
#endif /* CONFIG_SSDFS_DEBUG */

	shextree = fsi->shextree;

	if (!shextree) {
		SSDFS_ERR("shared extents tree is absent\n");
		return -ERANGE;
	}

	xattrs_btree = &fsi->vh->xattr_btree;
	node_size = 1 << xattrs_btree->desc.log_node_size;

	err = ssdfs_init_node_content(fsi, content, node_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init node's content: "
			  "node_id %u, node_type %#x, "
			  "owner_ino %llu, err %d\n",
			  le32_to_cpu(index->node_id),
			  index->node_type,
			  owner_ino, err);
		goto fail_invalidate_index;
	}

	err = __ssdfs_btree_node_prepare_content(fsi, index, node_size,
						 owner_ino, &si, content);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare node's content: "
			  "node_id %u, node_type %#x, "
			  "owner_ino %llu, err %d\n",
			  le32_to_cpu(index->node_id),
			  index->node_type,
			  owner_ino, err);
		goto fail_invalidate_index;
	}

	if (content->count == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty node's content: id %u\n",
			  le32_to_cpu(index->node_id));
		goto finish_invalidate_index;
	}

	blk = &content->blocks[0];
	folio = blk->batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = kmap_local_folio(folio, 0);

	ssdfs_memcpy(&hdr, 0, sizeof(struct ssdfs_btree_node_header),
		     kaddr, 0, PAGE_SIZE,
		     sizeof(struct ssdfs_btree_node_header));

	hdr_ptr = (struct ssdfs_xattrs_btree_node_header *)kaddr;
	parent_ino = le64_to_cpu(hdr_ptr->parent_ino);
	xattrs_count = le16_to_cpu(hdr_ptr->xattrs_count);

	if (!is_csum_valid(&hdr_ptr->node.check, hdr_ptr, hdr_size)) {
		err = -EIO;
		SSDFS_ERR("invalid checksum: node_id %u\n",
			  le32_to_cpu(index->node_id));
	}

	hdr_ptr = NULL;
	kunmap_local(kaddr);

	if (unlikely(err))
		goto finish_invalidate_index;

	if (node_size != (1 << hdr.log_node_size)) {
		err = -EIO;
		SSDFS_ERR("node_size1 %u != node_size2 %u\n",
			  node_size,
			  1 << hdr.log_node_size);
		goto finish_invalidate_index;
	}

	node_id1 = le32_to_cpu(index->node_id);
	node_id2 = le32_to_cpu(hdr.node_id);

	if (node_id1 != node_id2) {
		err = -ERANGE;
		SSDFS_ERR("node_id1 %u != node_id2 %u\n",
			  node_id1, node_id2);
		goto finish_invalidate_index;
	}

	node_type1 = index->node_type;
	node_type2 = hdr.type;

	if (node_type1 != node_type2) {
		err = -ERANGE;
		SSDFS_ERR("node_type1 %#x != node_type2 %#x\n",
			  node_type1, node_type2);
		goto finish_invalidate_index;
	}

	height1 = index->height;
	height2 = hdr.height;

	if (height1 != height2) {
		err = -ERANGE;
		SSDFS_ERR("height1 %u != height2 %u\n",
			  height1, height2);
		goto finish_invalidate_index;
	}

	flags = le16_to_cpu(hdr.flags);

	if (flags & ~SSDFS_BTREE_NODE_FLAGS_MASK) {
		err = -EIO;
		SSDFS_ERR("corrupted node header: flags %#x\n",
			  flags);
		goto finish_invalidate_index;
	}

	has_index_area = flags & SSDFS_BTREE_NODE_HAS_INDEX_AREA;
	has_items_area = flags & SSDFS_BTREE_NODE_HAS_ITEMS_AREA;

	if (!has_index_area && !has_items_area) {
		err = -EIO;
		SSDFS_ERR("corrupted node header: no areas\n");
		goto finish_invalidate_index;
	}

	if (has_index_area) {
		err = ssdfs_invalidate_index_area(fsi, shextree,
						  owner_ino, &hdr,
						  node_size, content);
		if (unlikely(err)) {
			SSDFS_ERR("fail to invalidate index area: "
				  "err %d\n", err);
			goto finish_invalidate_index;
		}
	}

	if (has_items_area) {
		struct ssdfs_xattr_entry xattr;
		u64 xattrs_size;
		u64 start_hash, end_hash;

		xattrs_size = (u64)xattrs_count *
				sizeof(struct ssdfs_xattr_entry);
		area_offset = le32_to_cpu(hdr.item_area_offset);
		start_hash = le64_to_cpu(hdr.start_hash);
		end_hash = le64_to_cpu(hdr.end_hash);

		if (area_offset >= node_size) {
			err = -EIO;
			SSDFS_ERR("area_offset %u >= node_size %u\n",
				  area_offset, node_size);
			goto finish_invalidate_index;
		}

		area_size = node_size - area_offset;

		if (area_size < xattrs_size) {
			err = -EIO;
			SSDFS_ERR("corrupted node header: "
				  "xattr_size %lu, xattrs_count %u, "
				  "area_size %u\n",
				  sizeof(struct ssdfs_xattr_entry),
				  xattrs_count, area_size);
			goto finish_invalidate_index;
		}

		for (i = 0; i < xattrs_count; i++) {
			struct ssdfs_blob_extent *desc;
			struct ssdfs_raw_extent *extent;
			bool is_flag_invalid;

			err = __ssdfs_xattrs_btree_node_get_xattr(fsi,
								  content,
								  area_offset,
								  area_size,
								  node_size,
								  i,
								  &xattr);
			if (unlikely(err)) {
				SSDFS_ERR("fail to get xattr: "
					  "xattr_index %u\n",
					  i);
				goto finish_invalidate_index;
			}

			switch (xattr.blob_type) {
			case SSDFS_XATTR_INLINE_BLOB:
				is_flag_invalid = xattr.blob_flags &
						SSDFS_XATTR_HAS_EXTERNAL_BLOB;

				if (is_flag_invalid) {
					err = -ERANGE;
					SSDFS_ERR("invalid xattr: "
						  "blob_type %#x, "
						  "blob_flags %#x\n",
						  xattr.blob_type,
						  xattr.blob_flags);
					goto finish_invalidate_index;
				} else {
					/* skip invalidation -> inline blob */
					continue;
				}
				break;

			case SSDFS_XATTR_REGULAR_BLOB:
				is_flag_invalid = xattr.blob_flags &
						~SSDFS_XATTR_HAS_EXTERNAL_BLOB;

				if (is_flag_invalid) {
					err = -ERANGE;
					SSDFS_ERR("invalid xattr: "
						  "blob_type %#x, "
						  "blob_flags %#x\n",
						  xattr.blob_type,
						  xattr.blob_flags);
					goto finish_invalidate_index;
				}

				desc = &xattr.blob.descriptor;
				extent = &xattr.blob.descriptor.extent;
				err =
				 ssdfs_shextree_add_pre_invalid_extent(shextree,
								    owner_ino,
								    extent);
				if (unlikely(err)) {
					SSDFS_ERR("fail to pre-invalid: "
						  "cur_index %u, err %d\n",
						  i, err);
					goto finish_invalidate_index;
				}
				break;

			default:
				err = -ERANGE;
				SSDFS_ERR("invalid blob_type %#x\n",
					  xattr.blob_type);
				goto finish_invalidate_index;
			}
		}
	}

	start_blk = le32_to_cpu(index->index.extent.logical_blk);
	len = le32_to_cpu(index->index.extent.len);

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, err %d\n",
				  si->seg_id, err);
			goto finish_invalidate_index;
		}
	}

	err = ssdfs_mark_segment_under_invalidation(si);
	if (err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu is busy\n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_invalidate_index;
	}

	err = ssdfs_segment_invalidate_logical_extent(si, start_blk, len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate node: "
			  "node_id %u, seg_id %llu, "
			  "start_blk %u, len %u\n",
			  node_id1, si->seg_id,
			  start_blk, len);
		goto revert_invalidation_state;
	}

	for (i = 0; i < si->pebs_count; i++) {
		struct ssdfs_segment_request *req;

		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			goto revert_invalidation_state;
		}

		ssdfs_request_init(req, fsi->pagesize);
		ssdfs_get_request(req);

		err = ssdfs_segment_commit_log_async2(si, SSDFS_REQ_ASYNC,
						      i, req);
		if (unlikely(err)) {
			SSDFS_ERR("commit log request failed: "
				  "peb_index %d, err %d\n",
				  i, err);
			ssdfs_put_request(req);
			ssdfs_request_free(req, si);
			goto revert_invalidation_state;
		}
	}

revert_invalidation_state:
	err1 = ssdfs_revert_invalidation_to_regular_activity(si);
	if (unlikely(err1)) {
		SSDFS_ERR("unexpected segment %llu activity\n",
			  si->seg_id);
	}

finish_invalidate_index:
	ssdfs_segment_put_object(si);

fail_invalidate_index:
	ssdfs_destroy_btree_node_content(content);

	return err;
}

/*
 * ssdfs_invalidate_extent() - invalidate extent
 * @fsi: pointer on shared file system object
 * @extent: extent for invalidation
 *
 * This method tries to invalidate extent in the segment.
 * The extent should be deleted from the extents tree
 * beforehand. This method has goal to do real invalidation
 * the extents from the extents queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_invalidate_extent(struct ssdfs_fs_info *fsi,
			    struct ssdfs_raw_extent *extent)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_search_state seg_search;
	u64 seg_id;
	u32 start_blk;
	u32 len;
	int i;
	int err = 0, err1;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !extent);
	BUG_ON(le64_to_cpu(extent->seg_id) == U64_MAX ||
		le32_to_cpu(extent->logical_blk) == U32_MAX ||
		le32_to_cpu(extent->len) == U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_id = le64_to_cpu(extent->seg_id);
	start_blk = le32_to_cpu(extent->logical_blk);
	len = le32_to_cpu(extent->len);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, start_blk %u, len %u\n",
		  seg_id, start_blk, len);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_segment_search_state_init(&seg_search,
					SSDFS_USER_DATA_SEG_TYPE,
					seg_id, U64_MAX);

	si = ssdfs_grab_segment(fsi, &seg_search);
	if (unlikely(IS_ERR_OR_NULL(si))) {
		SSDFS_ERR("fail to grab segment object: "
			  "seg %llu, err %d\n",
			  seg_id, err);
		return PTR_ERR(si);
	}

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, err %d\n",
				  si->seg_id, err);
			goto finish_invalidate_extent;
		}
	}

	err = ssdfs_mark_segment_under_invalidation(si);
	if (err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("segment %llu is busy\n",
			  si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_invalidate_extent;
	}

	err = ssdfs_segment_invalidate_logical_extent(si, start_blk, len);
	if (err == -ENODATA) {
		SSDFS_DBG("unable to invalidate logical extent: "
			  "seg %llu, extent (start_blk %u, len %u), err %d\n",
			  seg_id, start_blk, len, err);
		goto revert_invalidation_state;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to invalidate logical extent: "
			  "seg %llu, extent (start_blk %u, len %u), err %d\n",
			  seg_id, start_blk, len, err);
		goto revert_invalidation_state;
	}

	for (i = 0; i < si->pebs_count; i++) {
		struct ssdfs_segment_request *req;

		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			goto revert_invalidation_state;
		}

		ssdfs_request_init(req, fsi->pagesize);
		ssdfs_get_request(req);

		err = ssdfs_segment_commit_log_async2(si, SSDFS_REQ_ASYNC,
						      i, req);
		if (unlikely(err)) {
			SSDFS_ERR("commit log request failed: "
				  "peb_index %d, err %d\n",
				  i, err);
			ssdfs_put_request(req);
			ssdfs_request_free(req, si);
			goto revert_invalidation_state;
		}
	}

revert_invalidation_state:
	err1 = ssdfs_revert_invalidation_to_regular_activity(si);
	if (unlikely(err1)) {
		SSDFS_ERR("unexpected segment %llu activity\n",
			  si->seg_id);
	}

finish_invalidate_extent:
	ssdfs_segment_put_object(si);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}
