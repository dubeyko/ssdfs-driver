// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/diff_on_write_metadata.c - Diff-On-Write metadata implementation.
 *
 * Copyright (c) 2021-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "common_bitmap.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "request_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "diff_on_write.h"

#define GET_CHECKSUM(kaddr) \
	((__le32 *)((u8 *)kaddr + \
		sizeof(struct ssdfs_metadata_diff_blob_header)))
#define GET_BMAP(kaddr) \
	((unsigned long *)((u8 *)kaddr + \
		sizeof(struct ssdfs_metadata_diff_blob_header) + \
			sizeof(__le32)))

/*
 * ssdfs_calculate_block_checksum() - calculate block's checksum
 * @fsi: file system info object
 * @blk_index: logical block index
 * @batch: folio batch with node's content
 * @checksum: calculated checksum [out]
 */
static inline
int ssdfs_calculate_block_checksum(struct ssdfs_fs_info *fsi,
				   u32 blk_index,
				   struct folio_batch *batch,
				   __le32 *checksum)
{
	u32 mem_pages_per_block;
	u32 batch_size;
	u32 csum = ~0;
	u32 i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !checksum);

	SSDFS_DBG("blk_index %u, batch %p, checksum %p\n",
		  blk_index, batch, checksum);
#endif /* CONFIG_SSDFS_DEBUG */

	*checksum = U32_MAX;

	mem_pages_per_block = fsi->pagesize / PAGE_SIZE;
	batch_size = folio_batch_count(batch);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("mem_pages_per_block %u, blk_index %u, "
		  "batch_size %u\n",
		  mem_pages_per_block,
		  blk_index,
		  batch_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (blk_index >= batch_size) {
		SSDFS_ERR("blk_index %u >= batch_size %u\n",
			  blk_index, batch_size);
		return -ERANGE;
	}

	for (i = 0; i < mem_pages_per_block; i++) {
		struct page *page;
		void *kaddr;

		page = folio_page(batch->folios[blk_index], i);

		if (!page)
			BUG();

		kaddr = kmap_local_page(page);
		csum = crc32(csum, kaddr, PAGE_SIZE);
		kunmap_local(kaddr);
	}

	*checksum = cpu_to_le32(csum);

	return 0;
}

/*
 * ssdfs_btree_node_reserve_diff_blob_header() - reserve space for blob header
 * @node: node object
 * @blk_index: logical block index
 * @hdr: diff blob's header [out]
 * @write_offset: current write offset [out]
 *
 * This method reserves space for diff blob header.
 */
static inline
void ssdfs_btree_node_reserve_diff_blob_header(struct ssdfs_btree_node *node,
				    u32 blk_index,
				    struct ssdfs_metadata_diff_blob_header *hdr,
				    u32 *write_offset)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */

	hdr->diff.magic = cpu_to_le16(SSDFS_DIFF_BLOB_MAGIC);
	hdr->diff.type = SSDFS_BTREE_NODE_DIFF_BLOB;

	if (blk_index == 0) {
		hdr->diff.flags =
			cpu_to_le16(SSDFS_DIFF_BLOB_HAS_BTREE_NODE_HEADER);
	} else
		hdr->diff.flags = cpu_to_le16(0);

	*write_offset = sizeof(struct ssdfs_metadata_diff_blob_header);
}

/*
 * ssdfs_calculate_diff_bits_range() - calculate range of bits for block
 * @blk_index: logical block index
 * @pagesize: logical block size in bytes
 * @area_offset: offset of area from node's beginning in bytes
 * @area_size: size of area in bytes
 * @item_size: size of item in bytes
 * @start: staring bit of range [out]
 * @max_bit: ending bit of range [out]
 *
 * This method calculates range of bits for logical block.
 */
static inline
void ssdfs_calculate_diff_bits_range(u32 blk_index, u32 pagesize,
				     u32 area_offset, u32 area_size,
				     u32 item_size,
				     unsigned long *start_bit,
				     unsigned long *max_bit)
{
	u32 blk_offset;
	u32 bytes_diff;
	u32 rest_bytes;
	u32 items_capacity;
	u32 bits_count;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!start_bit || !max_bit);

	SSDFS_DBG("blk_index %u, pagesize %u, "
		  "area_offset %u, area_size %u, "
		  "item_size %u\n",
		  blk_index, pagesize, area_offset,
		  area_size, item_size);
#endif /* CONFIG_SSDFS_DEBUG */

	*start_bit = 0;
	*max_bit = 0;

	if (area_size == 0) {
		SSDFS_WARN("area_size == 0\n");
		return;
	}

	blk_offset = blk_index * pagesize;

	if (blk_offset >= (area_offset + area_size)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("logical block hasn't items: "
			  "blk_index %u, area_offset %u, "
			  "area_size %u\n",
			  blk_index, area_offset, area_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return;
	}

	bits_count = area_size / item_size;

	if (blk_offset <= area_offset) {
		*start_bit = 0;
		bytes_diff = area_offset - blk_offset;
		rest_bytes = pagesize - bytes_diff;
		*max_bit = min_t(u32, bits_count, rest_bytes / item_size);
	} else {
		*start_bit = 0;
		*start_bit += (blk_offset - area_offset) / item_size;
		items_capacity = pagesize / item_size;
		*max_bit = min_t(u32, bits_count, *start_bit + items_capacity);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("blk_offset %u, area_offset %u, item_size %u, "
		  "start_bit %lu, max_bit %lu\n",
		  blk_offset, area_offset, item_size,
		  *start_bit, *max_bit);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_calculate_index_diff_bits_range() - calculate range of bits for block
 * @blk_index: logical block index
 * @pagesize: logical block size in bytes
 * @area_offset: offset of area from node's beginning in bytes
 * @area_size: size of area in bytes
 * index_start_bit: starting bit of index area
 * item_start_bit: starting bit of items area
 * @index_size: size of index in bytes
 * @start: staring bit of range [out]
 * @max_bit: ending bit of range [out]
 *
 * This method calculates range of bits for logical block.
 */
static inline
void ssdfs_calculate_index_diff_bits_range(u32 blk_index, u32 pagesize,
					   u32 area_offset, u32 area_size,
					   unsigned long index_start_bit,
					   unsigned long item_start_bit,
					   u32 index_size,
					   unsigned long *start_bit,
					   unsigned long *max_bit)
{
	ssdfs_calculate_diff_bits_range(blk_index, pagesize,
					area_offset, area_size,
					index_size,
					start_bit, max_bit);

	if (*start_bit == 0 && *max_bit == 0) {
		/*
		 * do nothing
		 */
	} else {
		*start_bit += index_start_bit;
		*max_bit += index_start_bit;
		*max_bit = min_t(unsigned long, *max_bit, item_start_bit);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("blk_index %u, area_offset %u, index_size %u, "
		  "index_start_bit %lu, "
		  "start_bit %lu, max_bit %lu\n",
		  blk_index, area_offset, index_size,
		  index_start_bit,
		  *start_bit, *max_bit);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_calculate_items_diff_bits_range() - calculate range of bits for block
 * @blk_index: logical block index
 * @pagesize: logical block size in bytes
 * @area_offset: offset of area from node's beginning in bytes
 * @area_size: size of area in bytes
 * item_start_bit: starting bit of items area
 * @bits_count: number of bits in the whole bitmap
 * @item_size: size of item in bytes
 * @start: staring bit of range [out]
 * @max_bit: ending bit of range [out]
 *
 * This method calculates range of bits for logical block.
 */
static inline
void ssdfs_calculate_items_diff_bits_range(u32 blk_index, u32 pagesize,
					   u32 area_offset, u32 area_size,
					   unsigned long item_start_bit,
					   unsigned long bits_count,
					   u32 item_size,
					   unsigned long *start_bit,
					   unsigned long *max_bit)
{
	ssdfs_calculate_diff_bits_range(blk_index, pagesize,
					area_offset, area_size,
					item_size,
					start_bit, max_bit);

	if (*start_bit == 0 && *max_bit == 0) {
		/*
		 * do nothing
		 */
	} else {
		*start_bit += item_start_bit;
		*max_bit += item_start_bit;
		*max_bit = min_t(unsigned long, *max_bit, bits_count);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("blk_index %u, area_offset %u, item_size %u, "
		  "item_start_bit %lu, "
		  "start_bit %lu, max_bit %lu\n",
		  blk_index, area_offset, item_size,
		  item_start_bit,
		  *start_bit, *max_bit);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_calculate_block_start_bit() - calculate starting bit for block
 * @blk_index: logical block index
 * @pagesize: logical block size in bytes
 * @index_area_offset: offset of index area from node's beginning in bytes
 * @index_area_size: size of index area in bytes
 * @index_size: size of index in bytes
 * @index_start_bit: indexes' starting bit in bitmap
 * @items_area_offset: offset of items area from node's beginning in bytes
 * @items_area_size: size of items area in bytes
 * @item_size: size of item in bytes
 * @item_start_bit: items' starting bit in bitmap
 * @blk_start_bit: staring bit of logical block [out]
 *
 * This method calculates starting bit for logical block.
 */
static
void ssdfs_calculate_block_start_bit(u32 blk_index, u32 pagesize,
				     u32 index_area_offset,
				     u32 index_area_size,
				     u32 index_size,
				     unsigned long index_start_bit,
				     u32 items_area_offset,
				     u32 items_area_size,
				     u32 item_size,
				     unsigned long item_start_bit,
				     unsigned long *blk_start_bit)
{
	u32 index_capacity = 0;
	u32 items_capacity = 0;
	u32 blk_offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!blk_start_bit);

	SSDFS_DBG("blk_index %u, pagesize %u, "
		  "index_area_offset %u, index_area_size %u, "
		  "index_size %u, index_start_bit %lu, "
		  "items_area_offset %u, items_area_size %u, "
		  "item_size %u, item_start_bit %lu\n",
		  blk_index, pagesize,
		  index_area_offset, index_area_size,
		  index_size, index_start_bit,
		  items_area_offset, items_area_size,
		  item_size, item_start_bit);
#endif /* CONFIG_SSDFS_DEBUG */

	*blk_start_bit = 0;

	if (index_size == 0)
		index_capacity = 0;
	else
		index_capacity = index_area_size / index_size;

	if (item_size == 0)
		items_capacity = 0;
	else
		items_capacity = items_area_size / item_size;

	blk_offset = blk_index * pagesize;

	if (index_capacity == 0 && items_capacity == 0) {
		SSDFS_WARN("index_capacity == 0 && items_capacity == 0\n");
		*blk_start_bit = ULONG_MAX;
	} else if (index_capacity == 0) {
		/* node has only items area */

		if (blk_offset < items_area_offset) {
			/* first block */
			*blk_start_bit = SSDFS_BTREE_NODE_HEADER_INDEX + 1;
		} else if (blk_offset < (items_area_offset + items_area_size)) {
			/* start bit inside items area */
			*blk_start_bit = blk_offset - items_area_offset;
			*blk_start_bit /= item_size;
			*blk_start_bit += SSDFS_BTREE_NODE_HEADER_INDEX + 1;
		} else {
			*blk_start_bit = SSDFS_BTREE_NODE_HEADER_INDEX + 1;
			*blk_start_bit += items_capacity;
		}
	} else if (items_capacity == 0) {
		/* node has only index area */

		if (blk_offset < index_area_offset) {
			/* first block */
			*blk_start_bit = index_start_bit;
		} else if (blk_offset < (index_area_offset + index_area_size)) {
			/* start bit inside index area */
			*blk_start_bit = blk_offset - index_area_offset;
			*blk_start_bit /= index_size;
			*blk_start_bit += index_start_bit;
		} else {
			*blk_start_bit = index_start_bit;
			*blk_start_bit += index_capacity;
		}
	} else {
		if (blk_offset < index_area_offset) {
			/* first block */
			*blk_start_bit = index_start_bit;
		} else if (blk_offset < (index_area_offset + index_area_size)) {
			/* start bit inside index area */

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(blk_offset < index_area_offset);
#endif /* CONFIG_SSDFS_DEBUG */

			*blk_start_bit = blk_offset - index_area_offset;
			*blk_start_bit /= index_size;
			*blk_start_bit += index_start_bit;
		} else if (blk_offset < (items_area_offset + items_area_size)) {
			/* start bit inside items area */

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(blk_offset < items_area_offset);
#endif /* CONFIG_SSDFS_DEBUG */

			*blk_start_bit = blk_offset - items_area_offset;
			*blk_start_bit /= item_size;
			*blk_start_bit += item_start_bit;
		} else {
			*blk_start_bit = item_start_bit;
			*blk_start_bit += items_capacity;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("blk_index %u, blk_start_bit %lu\n",
		  blk_index, *blk_start_bit);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_btree_node_save_diff_blob_metadata() - save diff blob's metadata
 * @node: node object
 * @blk_index: logical block index
 * @folio: memory folio to store the metadata [out]
 * @hdr: diff blob's header [out]
 * @write_offset: current write offset [out]
 *
 * This method tries to save the diff blob's metadata.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-E2BIG      - metadata is too huge.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_node_save_diff_blob_metadata(struct ssdfs_btree_node *node,
				u32 blk_index, struct folio *folio,
				struct ssdfs_metadata_diff_blob_header *hdr,
				u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_state_bitmap *bmap;
	void *kaddr;
	u8 index_size;
	u32 index_area_offset;
	u32 index_area_size;
	u16 item_size;
	u32 items_area_offset;
	u32 items_area_size;
	unsigned long index_start_bit;
	unsigned long item_start_bit;
	unsigned long bits_count;
	size_t bmap_bytes = 0;
	unsigned long start_bit;
	unsigned long max_bit;
	__le32 csum = ~0;
	__le32 *csum_ptr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !folio || !write_offset);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	WARN_ON(!folio_test_locked(folio));

	SSDFS_DBG("node_id %u, height %u, type %#x, "
		  "blk_index %u, write_offset %u\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type),
		  blk_index, *write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (*write_offset >= PAGE_SIZE) {
		SSDFS_ERR("invalid write_offset %u\n",
			  *write_offset);
		return -EINVAL;
	}

	down_read(&node->header_lock);
	index_size = node->index_area.index_size;
	index_area_offset = node->index_area.offset;
	index_area_size = node->index_area.area_size;
	item_size = cpu_to_le16(node->items_area.item_size);
	items_area_offset = node->items_area.offset;
	items_area_size = node->items_area.area_size;
	up_read(&node->header_lock);

	down_read(&node->bmap_array.lock);
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];

	spin_lock(&bmap->lock);

	if (node->bmap_array.bits_count >= U16_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid bits_count %lu\n",
			  node->bmap_array.bits_count);
		goto unlock_bmap;
	}

	hdr->bits_count = cpu_to_le16((u16)node->bmap_array.bits_count);

	index_start_bit = node->bmap_array.index_start_bit;
	item_start_bit = node->bmap_array.item_start_bit;
	bits_count = node->bmap_array.bits_count;

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
		if (index_start_bit > bits_count) {
			err = -ERANGE;
			SSDFS_ERR("corrupted bitmap: index_start_bit %lu, "
				  "item_start_bit %lu, bits_count %lu\n",
				  index_start_bit,
				  item_start_bit,
				  bits_count);
			goto unlock_bmap;
		}

		ssdfs_calculate_index_diff_bits_range(blk_index,
						      fsi->pagesize,
						      index_area_offset,
						      index_area_size,
						      index_start_bit,
						      item_start_bit,
						      index_size,
						      &start_bit,
						      &max_bit);

		if (start_bit == max_bit || start_bit > max_bit) {
			err = -ERANGE;
			SSDFS_ERR("invalid bits range: "
				  "start_bit %lu, max_bit %lu\n",
				  start_bit, max_bit);
			goto unlock_bmap;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(start_bit >= U16_MAX);
		BUG_ON(max_bit >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		hdr->index_start_bit = cpu_to_le16(0);
		hdr->item_start_bit = cpu_to_le16((u16)max_bit - start_bit);
		hdr->item_size = cpu_to_le16(U16_MAX);
		break;

	case SSDFS_BTREE_HYBRID_NODE:
		if (index_start_bit > bits_count ||
		    item_start_bit > bits_count) {
			err = -ERANGE;
			SSDFS_ERR("corrupted bitmap: index_start_bit %lu, "
				  "item_start_bit %lu, bits_count %lu\n",
				  index_start_bit,
				  item_start_bit,
				  bits_count);
			goto unlock_bmap;
		}

		hdr->item_size = cpu_to_le16(item_size);

		ssdfs_calculate_index_diff_bits_range(blk_index,
						      fsi->pagesize,
						      index_area_offset,
						      index_area_size,
						      index_start_bit,
						      item_start_bit,
						      index_size,
						      &start_bit,
						      &max_bit);

		if (start_bit > max_bit) {
			err = -ERANGE;
			SSDFS_ERR("invalid bits range: "
				  "start_bit %lu, max_bit %lu\n",
				  start_bit, max_bit);
			goto unlock_bmap;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(start_bit >= U16_MAX);
		BUG_ON(max_bit >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		hdr->index_start_bit = cpu_to_le16(0);
		hdr->item_start_bit = cpu_to_le16((u16)max_bit - start_bit);

		ssdfs_calculate_items_diff_bits_range(blk_index,
						      fsi->pagesize,
						      items_area_offset,
						      items_area_size,
						      item_start_bit,
						      bits_count,
						      item_size,
						      &start_bit,
						      &max_bit);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(start_bit >= U16_MAX);
		BUG_ON(max_bit >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		if (start_bit == max_bit) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("no items in the logical block: "
				  "blk_index %u\n",
				  blk_index);
#endif /* CONFIG_SSDFS_DEBUG */
			goto unlock_bmap;
		} else if (start_bit > max_bit) {
			err = -ERANGE;
			SSDFS_ERR("invalid bits range: "
				  "start_bit %lu, max_bit %lu\n",
				  start_bit, max_bit);
			goto unlock_bmap;
		}
		break;

	case SSDFS_BTREE_LEAF_NODE:
		if (item_start_bit > bits_count) {
			err = -ERANGE;
			SSDFS_ERR("corrupted bitmap: index_start_bit %lu, "
				  "item_start_bit %lu, bits_count %lu\n",
				  index_start_bit,
				  item_start_bit,
				  bits_count);
			goto unlock_bmap;
		}

		ssdfs_calculate_items_diff_bits_range(blk_index,
						      fsi->pagesize,
						      items_area_offset,
						      items_area_size,
						      item_start_bit,
						      bits_count,
						      item_size,
						      &start_bit,
						      &max_bit);

		if (start_bit == max_bit || start_bit > max_bit) {
			err = -ERANGE;
			SSDFS_ERR("invalid bits range: "
				  "start_bit %lu, max_bit %lu\n",
				  start_bit, max_bit);
			goto unlock_bmap;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(start_bit >= U16_MAX);
		BUG_ON(max_bit >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		hdr->item_start_bit = cpu_to_le16(0);
		hdr->index_start_bit = hdr->item_start_bit;
		hdr->item_size = cpu_to_le16(item_size);
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid node type %#x\n",
			   atomic_read(&node->type));
		goto unlock_bmap;
	}

	err = ssdfs_calculate_block_checksum(fsi, blk_index,
					     &node->content.batch,
					     &csum);
	if (err) {
		SSDFS_ERR("fail to calculate block's checksum: "
			  "blk_index %u, err %d\n",
			  blk_index, err);
		goto unlock_bmap;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, height %u, type %#x, "
		  "blk_index %u, checksum %#x\n",
		  node->node_id,
		  atomic_read(&node->height),
		  atomic_read(&node->type),
		  blk_index,
		  le32_to_cpu(csum));
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = kmap_local_folio(folio, 0);
	csum_ptr = GET_CHECKSUM(kaddr);
	*csum_ptr = csum;
	*write_offset += sizeof(__le32);
	bmap_bytes = node->bmap_array.bmap_bytes;
	memset(GET_BMAP(kaddr), 0, bmap_bytes);
	*write_offset += bmap_bytes;
	flush_dcache_folio(folio);
	kunmap_local(kaddr);

unlock_bmap:
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to save the diff blob metadata: "
			  "write_offset %u, bmap_bytes %zu, err %d\n",
			  *write_offset, bmap_bytes, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_start_bit %u, item_start_bit %u, "
		  "bits_count %u\n",
		  le16_to_cpu(hdr->index_start_bit),
		  le16_to_cpu(hdr->item_start_bit),
		  le16_to_cpu(hdr->bits_count));
#endif /* CONFIG_SSDFS_DEBUG */

	if (bmap_bytes >= U8_MAX) {
		SSDFS_ERR("bmap_bytes %zu is too huge\n",
			  bmap_bytes);
		return -E2BIG;
	}

	hdr->diff.desc_size = (u8)bmap_bytes + sizeof(__le32);

	if (*write_offset >= PAGE_SIZE) {
		SSDFS_ERR("invalid write_offset %u\n",
			  *write_offset);
		return -ERANGE;
	}

	return 0;
}

/*
 * BYTE_CONTAINS_STATE() - check that provided byte contains state
 * @value: pointer on analysed byte
 * @state: requested state
 *
 * RETURN:
 * [true]  - @value contains @state.
 * [false] - @value hasn't @state.
 */
static inline
bool BYTE_CONTAINS_STATE(u8 *value, int state)
{
	switch (state) {
	case SSDFS_DIRTY_ITEM:
		return *value != 0;
	};

	return false;
}

/*
 * ssdfs_metadata_find_first_dirty_item() - find first dirty item
 * @bmap: dirty bitmap
 * @bmap_bytes: number of bytes in bitmap
 * @start: starting item for search
 * @max: upper bound for search
 * @found_item: pointer on found dirty item [out]
 *
 * This function tries to find a first dirty item
 * in range [@start, @max_blk).
 *
 * RETURN:
 * [success] - @found_item contains found dirty item number.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENODATA    - requested range [@start, @max_blk) doesn't contain
 *                any dirty item.
 */
static
int ssdfs_metadata_find_first_dirty_item(unsigned long *bmap,
					 size_t bmap_bytes,
					 unsigned long start,
					 unsigned long max,
					 unsigned long *found_item)
{
	const int state = SSDFS_DIRTY_ITEM;
	const u8 state_bits = 1;
	const int state_mask = SSDFS_DIRTY_ITEM_MASK;
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(state_bits);
	unsigned long byte_index;
	u32 items_diff;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!bmap || !found_item);

	if (start > max) {
		SSDFS_ERR("start %lu > max %lu\n", start, max);
		return -EINVAL;
	}

	SSDFS_DBG("start %lu, max %lu, found_item %p\n",
		  start, max, found_item);

	SSDFS_DBG("BMAP DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     bmap,
			     bmap_bytes);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	*found_item = U32_MAX;
	byte_index = start / items_per_byte;
	items_diff = start % items_per_byte;

	for (; byte_index < bmap_bytes; byte_index++) {
		u8 *value;
		u8 found_off;

		value = (u8 *)bmap + byte_index;
		err = FIND_FIRST_ITEM_IN_BYTE(value, state,
					      state_bits, state_mask,
					      items_diff,
					      BYTE_CONTAINS_STATE,
					      FIRST_STATE_IN_BYTE,
					      &found_off);
		if (err == -ENODATA) {
			items_diff = 0;
			continue;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find item in byte: err %d\n",
				  err);
			return err;
		}

		*found_item = byte_index * items_per_byte;
		*found_item += found_off;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("value %#x, byte_index %lu, "
			  "found_off %u, found_item %lu\n",
			  *value, byte_index,
			  found_off, *found_item);

		SSDFS_DBG("BMAP DUMP\n");
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     bmap,
				     bmap_bytes);
		SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

		if (*found_item >= max) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("item is out of range: "
				  "found_item %lu, max %lu\n",
				  *found_item, max);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_search;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("item %lu has been found\n",
				  *found_item);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		return 0;
	}

finish_search:
	return -ENODATA;
}

/*
 * ssdfs_btree_node_find_first_dirty_item() - find first dirty item
 * @node: node object
 * @start: starting item for search
 * @max_blk: upper bound for search
 * @found_item: pointer on found dirty item [out]
 *
 * This function tries to find a first dirty item
 * in range [@start, @max_blk).
 *
 * RETURN:
 * [success] - @found_item contains found dirty item number.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ENODATA    - requested range [@start, @max_blk) doesn't contain
 *                any dirty item.
 */
static
int ssdfs_btree_node_find_first_dirty_item(struct ssdfs_btree_node *node,
					   unsigned long start,
					   unsigned long max,
					   unsigned long *found_item)
{
	struct ssdfs_state_bitmap *bmap = NULL;
	size_t bmap_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!found_item);
	BUG_ON(!rwsem_is_locked(&node->bmap_array.lock));

	if (start >= node->bmap_array.bits_count) {
		SSDFS_ERR("start %lu >= bits_count %lu\n",
			  start,
			  node->bmap_array.bits_count);
		return -EINVAL;
	}

	if (start > max) {
		SSDFS_ERR("start %lu > max %lu\n", start, max);
		return -EINVAL;
	}

	SSDFS_DBG("node_id %u, height %u, type %#x, "
		  "start %lu, max %lu,  found_item %p\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type),
		  start, max, found_item);
#endif /* CONFIG_SSDFS_DEBUG */

	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	bmap_bytes = node->bmap_array.bmap_bytes;

	spin_lock(&bmap->lock);
	err = ssdfs_metadata_find_first_dirty_item(bmap->ptr, bmap_bytes,
						   start, max, found_item);
	spin_unlock(&bmap->lock);

	return err;
}

/*
 * ssdfs_btree_node_copy_dirty_indexes() - copy dirty indexes
 * @node: node object
 * @area_offset: index area offset
 * @area_size: index area size
 * @blk_index: logical block index
 * @blk_start_bit: starting bit of logical block
 * @folio: destination folio for copying operation [in|out]
 * @write_offset: pointer on current write offset [in|out]
 *
 * This function tries to copy the dirty indexes from
 * the node's content into the @folio starting from @write_offset.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_node_copy_dirty_indexes(struct ssdfs_btree_node *node,
					u32 area_offset,
					u32 area_size,
					u32 blk_index,
					unsigned long blk_start_bit,
					struct folio *folio,
					u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_index_key index;
	size_t index_size = sizeof(struct ssdfs_btree_index_key);
	u32 blk_offset;
	void *kaddr;
	unsigned long index_start_bit;
	unsigned long item_start_bit;
	unsigned long bits_count;
	unsigned long start = 0;
	unsigned long max = 0;
	unsigned long found_item = 0;
	bool is_deleted_index = false;
#ifdef CONFIG_SSDFS_DEBUG
	size_t bmap_bytes = 0;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !folio);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	WARN_ON(!folio_test_locked(folio));

	SSDFS_DBG("node_id %u, height %u, type %#x, write_offset %u\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type), *write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (*write_offset >= PAGE_SIZE) {
		SSDFS_ERR("invalid write_offset %u\n",
			  *write_offset);
		return -EINVAL;
	}

	if (!is_ssdfs_btree_node_index_area_exist(node)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node hasn't indexes: "
			  "node_id %u, height %u, type %#x\n",
			  node->node_id,
			  atomic_read(&node->height),
			  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	blk_offset = blk_index * fsi->pagesize;

	if (blk_offset >= (area_offset + area_size)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("logical block hasn't indexes: "
			  "node_id %u, height %u, "
			  "type %#x, blk_index %u\n",
			  node->node_id,
			  atomic_read(&node->height),
			  atomic_read(&node->type),
			  blk_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	down_read(&node->bmap_array.lock);

	index_start_bit = node->bmap_array.index_start_bit;
	item_start_bit = node->bmap_array.item_start_bit;
	bits_count = node->bmap_array.bits_count;
#ifdef CONFIG_SSDFS_DEBUG
	bmap_bytes = node->bmap_array.bmap_bytes;
#endif /* CONFIG_SSDFS_DEBUG */

	if (index_start_bit > bits_count || item_start_bit > bits_count) {
		err = -ERANGE;
		SSDFS_ERR("corrupted bitmap: index_start_bit %lu, "
			  "item_start_bit %lu, bits_count %lu\n",
			  index_start_bit,
			  item_start_bit,
			  bits_count);
		goto finish_copy_indexes;
	}

	ssdfs_calculate_index_diff_bits_range(blk_index,
					      fsi->pagesize,
					      area_offset,
					      area_size,
					      index_start_bit,
					      item_start_bit,
					      index_size,
					      &start,
					      &max);

	if (start > max) {
		err = -ERANGE;
		SSDFS_ERR("invalid bits range: "
			  "start_bit %lu, max_bit %lu\n",
			  start, max);
		goto finish_copy_indexes;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(start >= U16_MAX);
	BUG_ON(max >= U16_MAX);

	kaddr = kmap_local_folio(folio, 0);
	SSDFS_DBG("BMAP DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     GET_BMAP(kaddr),
			     bmap_bytes);
	SSDFS_DBG("\n");
	kunmap_local(kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start == max) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("block hasn't indexes: "
			  "blk_index %u\n",
			  blk_index);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_copy_indexes;
	}

	while (start < max) {
		err = ssdfs_btree_node_find_first_dirty_item(node,
							     start, max,
							     &found_item);
		if (err == -ENODATA) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("no more dirty indexes: "
				  "start %lu, max %lu\n",
				  start, max);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_copy_indexes;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find dirty index: "
				  "start %lu, max %lu, err %d\n",
				  start, max, err);
			goto finish_copy_indexes;
		}

		err = ssdfs_btree_node_get_index(fsi,
					 &node->content.batch,
					 area_offset, area_size,
					 node->node_size,
					 (u16)found_item - index_start_bit,
					  &index);
		if (err == -ENODATA) {
			err = 0;
			is_deleted_index = true;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("deleted index: "
				  "found_item %lu\n",
				  found_item);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to extract index: "
				  "node_id %u, index %d, err %d\n",
				  node->node_id, 0, err);
			goto finish_copy_indexes;
		}

		kaddr = kmap_local_folio(folio, 0);

		if (!is_deleted_index) {
			err = ssdfs_memcpy(kaddr, *write_offset, PAGE_SIZE,
					   &index, 0, index_size,
					   index_size);
		} else
			is_deleted_index = false;

		if (!err) {
			bitmap_set(GET_BMAP(kaddr),
				   found_item - blk_start_bit, 1);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("set bit %lu: "
				  "found_item %lu, blk_start_bit %lu\n",
				  found_item - blk_start_bit,
				  found_item, blk_start_bit);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		flush_dcache_folio(folio);
		kunmap_local(kaddr);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy index: "
				  "write_offset %u, size %zu, err %d\n",
				  *write_offset, index_size, err);
			goto finish_copy_indexes;
		}

		*write_offset += index_size;

		if (*write_offset >= PAGE_SIZE) {
			err = -ERANGE;
			SSDFS_ERR("invalid write_offset %u\n",
				  *write_offset);
			goto finish_copy_indexes;
		}

		start = found_item + 1;
	}

finish_copy_indexes:
	up_read(&node->bmap_array.lock);

	return err;
}

/*
 * ssdfs_btree_node_copy_dirty_items() - copy dirty items
 * @node: node object
 * @area_offset: items area offset
 * @area_size: items area size
 * @item_size: item size in bytes
 * @blk_index: logical block index
 * @blk_start_bit: starting bit of logical block
 * @folio: destination folio for copying operation [in|out]
 * @write_offset: pointer on current write offset [in|out]
 *
 * This function tries to copy the dirty items from
 * the node's content into the @folio starting from @write_offset.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input value.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_node_copy_dirty_items(struct ssdfs_btree_node *node,
				      u32 area_offset,
				      u32 area_size,
				      u16 item_size,
				      u32 index_capacity,
				      u32 blk_index,
				      unsigned long blk_start_bit,
				      struct folio *folio,
				      u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_btree_search *search;
	void *kaddr;
	u32 blk_offset;
	unsigned long item_start_bit;
	unsigned long bits_count;
	unsigned long start;
	unsigned long max;
	unsigned long found_item = 0;
	bool is_deleted_item = false;
#ifdef CONFIG_SSDFS_DEBUG
	size_t bmap_bytes = 0;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !folio);
	BUG_ON(!rwsem_is_locked(&node->full_lock));
	WARN_ON(!folio_test_locked(folio));

	SSDFS_DBG("node_id %u, height %u, type %#x, write_offset %u\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type), *write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (*write_offset >= PAGE_SIZE) {
		SSDFS_ERR("invalid write_offset %u\n",
			  *write_offset);
		return -EINVAL;
	}

	if (!is_ssdfs_btree_node_items_area_exist(node)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node hasn't items: "
			  "node_id %u, height %u, type %#x\n",
			  node->node_id,
			  atomic_read(&node->height),
			  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	blk_offset = blk_index * fsi->pagesize;

	if (blk_offset >= (area_offset + area_size)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("logical block hasn't items: "
			  "node_id %u, height %u, "
			  "type %#x, blk_index %u\n",
			  node->node_id,
			  atomic_read(&node->height),
			  atomic_read(&node->type),
			  blk_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	down_read(&node->bmap_array.lock);
	item_start_bit = node->bmap_array.item_start_bit;
	bits_count = node->bmap_array.bits_count;
#ifdef CONFIG_SSDFS_DEBUG
	bmap_bytes = node->bmap_array.bmap_bytes;
#endif /* CONFIG_SSDFS_DEBUG */
	up_read(&node->bmap_array.lock);

	if (item_start_bit > bits_count) {
		SSDFS_ERR("corrupted bitmap: "
			  "item_start_bit %lu, bits_count %lu\n",
			  item_start_bit,
			  bits_count);
		return -ERANGE;
	}

	ssdfs_calculate_items_diff_bits_range(blk_index,
					      fsi->pagesize,
					      area_offset,
					      area_size,
					      item_start_bit,
					      bits_count,
					      item_size,
					      &start,
					      &max);

	if (start > max) {
		SSDFS_ERR("invalid bits range: "
			  "start_bit %lu, max_bit %lu\n",
			  start, max);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(start >= U16_MAX);
	BUG_ON(max >= U16_MAX);

	kaddr = kmap_local_folio(folio, 0);
	SSDFS_DBG("BMAP DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     GET_BMAP(kaddr),
			     bmap_bytes);
	SSDFS_DBG("\n");
	kunmap_local(kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

	if (start == max) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("block hasn't items: "
			  "blk_index %u\n",
			  blk_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	while (start < max) {
		down_read(&node->bmap_array.lock);
		err = ssdfs_btree_node_find_first_dirty_item(node, start, max,
							     &found_item);
		up_read(&node->bmap_array.lock);

		if (err == -ENODATA) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("no more dirty items: "
				  "start %lu, max %lu\n",
				  start, max);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_copy_items;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find dirty item: "
				  "start %lu, max %lu, err %d\n",
				  start, max, err);
			goto finish_copy_items;
		}

		ssdfs_btree_search_init(search);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found_item %lu\n",
			  found_item - item_start_bit);
#endif /* CONFIG_SSDFS_DEBUG */

		err = __ssdfs_btree_node_extract_range(node,
						found_item - item_start_bit,
						1, item_size,
						search);
		if (err == -ENODATA) {
			err = 0;
			is_deleted_item = true;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("deleted item: "
				  "found_item %lu\n",
				  found_item);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to extract an item: "
				  "found_item %lu, err %d\n",
				  found_item, err);
			goto finish_copy_items;
		}

		kaddr = kmap_local_folio(folio, 0);

		if (!is_deleted_item) {
			err = ssdfs_memcpy(kaddr, *write_offset, PAGE_SIZE,
					   search->result.buf, 0, item_size,
					   item_size);
		} else
			is_deleted_item = false;

		if (!err) {
			unsigned long set_bit = found_item;

			if (blk_index == 0) {
				set_bit -= item_start_bit;
				set_bit += index_capacity;
			} else
				set_bit -= blk_start_bit;

			bitmap_set(GET_BMAP(kaddr), set_bit, 1);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("set bit %lu: "
				  "found_item %lu, blk_index %u, "
				  "blk_start_bit %lu, item_start_bit %lu\n",
				  set_bit, found_item,
				  blk_index, blk_start_bit,
				  item_start_bit);

			SSDFS_DBG("BMAP DUMP\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     GET_BMAP(kaddr),
					     bmap_bytes);
			SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */
		}

		flush_dcache_folio(folio);
		kunmap_local(kaddr);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy item: "
				  "write_offset %u, size %u, err %d\n",
				  *write_offset, item_size, err);
			goto finish_copy_items;
		}

		*write_offset += item_size;

		if (*write_offset >= PAGE_SIZE) {
			err = -ERANGE;
			SSDFS_ERR("invalid write_offset %u\n",
				  *write_offset);
			goto finish_copy_items;
		}

		start = found_item + 1;
	}

finish_copy_items:
	ssdfs_btree_search_free(search);

	return err;
}

/*
 * ssdfs_btree_node_ready_for_diff() - check that node is ready for diff
 * @node: node object
 *
 * This method tries to check that node is ready for diff.
 */
static
int ssdfs_btree_node_ready_for_diff(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *pebc;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *blk_desc_off;
	u16 peb_index;
	int migration_state = SSDFS_LBLOCK_UNKNOWN_STATE;
	struct ssdfs_offset_position pos = {0};
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u32 i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		/* expected state */
		break;

	default:
		BUG();
	};

	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	spin_lock(&node->descriptor_lock);
	si = node->seg;
	seg_id = le64_to_cpu(node->extent.seg_id);
	logical_blk = le32_to_cpu(node->extent.logical_blk);
	len = le32_to_cpu(node->extent.len);
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);
	BUG_ON(seg_id != si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	table = si->blk2off_table;

	for (i = 0; i < len; i++) {
		u32 cur_blk = logical_blk + i;

		blk_desc_off = ssdfs_blk2off_table_convert(table,
							   cur_blk,
							   &peb_index,
							   &migration_state,
							   &pos);
		if (IS_ERR(blk_desc_off) && PTR_ERR(blk_desc_off) == -EAGAIN) {
			struct completion *end = &table->full_init_end;

			err = SSDFS_WAIT_COMPLETION(end);
			if (unlikely(err)) {
				SSDFS_ERR("blk2off init failed: "
					  "err %d\n", err);
				return err;
			}

			blk_desc_off = ssdfs_blk2off_table_convert(table,
							    cur_blk,
							    &peb_index,
							    &migration_state,
							    &pos);
		}

		if (IS_ERR_OR_NULL(blk_desc_off)) {
			err = (blk_desc_off ==
				    NULL ? -ERANGE : PTR_ERR(blk_desc_off));
			SSDFS_ERR("fail to convert: "
				  "logical_blk %u, err %d\n",
				  cur_blk, err);
			return err;
		}

		switch (pos.blk_desc.status) {
		case SSDFS_BLK_DESC_BUF_INITIALIZED:
			/* expecting state */
			break;

		case SSDFS_BLK_DESC_BUF_UNKNOWN_STATE:
		case SSDFS_BLK_DESC_BUF_ALLOCATED:
			SSDFS_ERR("unexpected status: "
				  "pos->blk_desc.status %#x\n",
				  pos.blk_desc.status);
			return -ERANGE;

		default:
			SSDFS_ERR("unexpected status: "
				  "pos->blk_desc.status %#x\n",
				  pos.blk_desc.status);
			BUG();
		}

		if (!IS_SSDFS_BLK_DESC_READY_FOR_DIFF(&pos.blk_desc.buf)) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("logical block %u is not ready for diff\n",
				  cur_blk);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EAGAIN;
		} else if (IS_SSDFS_BLK_DESC_EXHAUSTED(&pos.blk_desc.buf)) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("block descripor is exhausted: "
				  "seg %llu, peb_index %u\n",
				  seg_id, peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EAGAIN;
		} else {
			struct ssdfs_peb_info *pebi = NULL;
			u8 migration_id1;
			int migration_id2;
			u64 peb_id;
			bool is_peb_exhausted = false;
			bool is_peb_ready_to_exhaust = false;

			migration_id1 =
			    SSDFS_GET_BLK_DESC_MIGRATION_ID(&pos.blk_desc.buf);
			if (migration_id1 >= U8_MAX) {
				SSDFS_WARN("invalid migration_id %#x\n",
					   migration_id1);
				return -ERANGE;
			}

			pebc = &si->peb_array[peb_index];

			pebi = ssdfs_get_current_peb_locked(pebc);
			if (IS_ERR_OR_NULL(pebi)) {
				err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
				SSDFS_ERR("fail to get PEB object: "
					  "seg %llu, peb_index %u, err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				return err;
			}

			ssdfs_peb_current_log_lock(pebi);
			migration_id2 =
				ssdfs_get_peb_migration_id_checked(pebi);
			peb_id = pebi->peb_id;
			is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
			is_peb_ready_to_exhaust =
				is_ssdfs_peb_ready_to_exhaust(fsi, pebi);
			ssdfs_peb_current_log_unlock(pebi);
			ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("peb_id %llu, is_peb_exhausted %#x, "
				  "is_peb_ready_to_exhaust %#x, "
				  "migration_id1 %u, migration_id2 %d\n",
				  peb_id, is_peb_exhausted,
				  is_peb_ready_to_exhaust,
				  migration_id1, migration_id2);
#endif /* CONFIG_SSDFS_DEBUG */

			if (is_peb_exhausted || is_peb_ready_to_exhaust) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("PEB is exhausted: "
					  "seg %llu, peb_id %llu\n",
					  pebc->parent_si->seg_id, peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
				return -EAGAIN;
			} else if (migration_id1 != migration_id2) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("migration has been started: "
					  "migration_id1 %u, "
					  "migration_id2 %d\n",
					  migration_id1, migration_id2);
#endif /* CONFIG_SSDFS_DEBUG */
				return -EAGAIN;
			} else {
#ifdef CONFIG_SSDFS_DEBUG
				DEBUG_BLOCK_DESCRIPTOR(pebc->parent_si->seg_id,
							peb_id,
							&pos.blk_desc.buf);
#endif /* CONFIG_SSDFS_DEBUG */
			}
		}
	}

	return 0;
}

/*
 * is_ssdfs_btree_node_logical_block_modified() - is logicasl block modified?
 * @node: node object
 * @blk_index: block index in the node
 *
 * This method tries to check that logical block has been modified.
 */
static
bool is_ssdfs_btree_node_logical_block_modified(struct ssdfs_btree_node *node,
						u32 blk_index)
{
	struct ssdfs_fs_info *fsi;
	u8 index_size;
	u16 item_size;
	u32 index_area_offset;
	u32 index_area_size;
	u32 items_area_offset;
	u32 items_area_size;
	unsigned long index_start_bit;
	unsigned long item_start_bit;
	unsigned long bits_count;
	unsigned long start;
	unsigned long max;
	unsigned long found_item = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node);
	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, height %u, type %#x, blk_index %u\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type), blk_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;

	if (blk_index == 0) {
		/*
		 * Any dirty node has modified header.
		 */
		return true;
	}

	down_read(&node->header_lock);
	index_size = node->index_area.index_size;
	item_size = cpu_to_le16(node->items_area.item_size);
	index_area_offset = node->index_area.offset;
	index_area_size = node->index_area.area_size;
	items_area_offset = node->items_area.offset;
	items_area_size = node->items_area.area_size;
	up_read(&node->header_lock);

	down_read(&node->bmap_array.lock);
	index_start_bit = node->bmap_array.index_start_bit;
	item_start_bit = node->bmap_array.item_start_bit;
	bits_count = node->bmap_array.bits_count;
	up_read(&node->bmap_array.lock);

	if (is_ssdfs_btree_node_index_area_exist(node)) {
		ssdfs_calculate_index_diff_bits_range(blk_index,
						      fsi->pagesize,
						      index_area_offset,
						      index_area_size,
						      index_start_bit,
						      item_start_bit,
						      index_size,
						      &start,
						      &max);
		if (start >= max) {
			/* do nothing */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("index area: blk_index %u, "
				  "start %lu, max %lu\n",
				  blk_index, start, max);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			down_read(&node->bmap_array.lock);
			err = ssdfs_btree_node_find_first_dirty_item(node,
								start, max,
								&found_item);
			up_read(&node->bmap_array.lock);

			if (err) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("no dirty indexes: "
					  "start %lu, max %lu\n",
					  start, max);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("found dirty index: "
					  "found_item %lu\n",
					  found_item);
#endif /* CONFIG_SSDFS_DEBUG */
				return true;
			}
		}
	}

	if (is_ssdfs_btree_node_items_area_exist(node)) {
		ssdfs_calculate_items_diff_bits_range(blk_index,
						      fsi->pagesize,
						      items_area_offset,
						      items_area_size,
						      item_start_bit,
						      bits_count,
						      item_size,
						      &start,
						      &max);
		if (start >= max) {
			/* do nothing */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("items area: blk_index %u, "
				  "start %lu, max %lu\n",
				  blk_index, start, max);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			down_read(&node->bmap_array.lock);
			err = ssdfs_btree_node_find_first_dirty_item(node,
								start, max,
								&found_item);
			up_read(&node->bmap_array.lock);

			if (err) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("no dirty items: "
					  "start %lu, max %lu\n",
					  start, max);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("found dirty item: "
					  "found_item %lu\n",
					  found_item);
#endif /* CONFIG_SSDFS_DEBUG */
				return true;
			}
		}
	}

	return false;
}

/*
 * ssdfs_btree_node_prepare_logical_block_diff() - prepare block's diff
 * @node: node object
 * @logical_blk: logical block ID
 * @blk_index: block index in the node
 *
 * This method tries to prepare the logical block's diff for flush operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_node_prepare_logical_block_diff(struct ssdfs_btree_node *node,
						u32 logical_blk,
						u32 blk_index)
{
	struct ssdfs_metadata_diff_blob_header hdr;
	struct folio *folio;
	size_t hdr_size = sizeof(struct ssdfs_metadata_diff_blob_header);
	u8 index_size;
	u16 item_size;
	u32 index_area_offset;
	u32 index_area_size;
	u32 index_capacity;
	u32 items_area_offset;
	u32 items_area_size;
	u32 write_offset = 0;
	u32 blob_offset = 0;
	u32 blob_size;
	unsigned long index_start_bit;
	unsigned long item_start_bit;
	unsigned long blk_start_bit = ULONG_MAX;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		/* expected state */
		break;

	default:
		BUG();
	};

	BUG_ON(!rwsem_is_locked(&node->full_lock));

	SSDFS_DBG("node_id %u, height %u, type %#x, "
		  "logical_blk %u, blk_index %u\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type),
		  logical_blk, blk_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_btree_node_logical_block_modified(node, blk_index)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("logical block has not been modified: "
			  "logical_blk %u\n",
			  logical_blk);

		BUG_ON(node->flush_req.result.batch.folios[blk_index] != NULL);
#endif /* CONFIG_SSDFS_DEBUG */

		node->flush_req.result.batch.folios[blk_index] = NULL;

		if ((blk_index + 1) > node->flush_req.result.batch.nr)
			node->flush_req.result.batch.nr = blk_index + 1;

		return 0;
	}

	down_read(&node->header_lock);
	index_size = node->index_area.index_size;
	item_size = cpu_to_le16(node->items_area.item_size);
	index_area_offset = node->index_area.offset;
	index_area_size = node->index_area.area_size;
	items_area_offset = node->items_area.offset;
	items_area_size = node->items_area.area_size;
	up_read(&node->header_lock);

	down_read(&node->bmap_array.lock);
	index_start_bit = node->bmap_array.index_start_bit;
	item_start_bit = node->bmap_array.item_start_bit;
	up_read(&node->bmap_array.lock);

	index_capacity = index_area_size / index_size;

	ssdfs_calculate_block_start_bit(blk_index,
					node->tree->fsi->pagesize,
					index_area_offset,
					index_area_size,
					index_size,
					index_start_bit,
					items_area_offset,
					items_area_size,
					item_size,
					item_start_bit,
					&blk_start_bit);

	memset(&hdr, 0, hdr_size);
	ssdfs_btree_node_reserve_diff_blob_header(node, blk_index,
						  &hdr, &write_offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("RESERVE DIFF BLOB HEADER: write_offset %u\n",
		  write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	folio = ssdfs_request_allocate_locked_diff_folio(&node->flush_req,
							 blk_index);
	if (unlikely(IS_ERR_OR_NULL(folio))) {
		err = folio == NULL ? -ERANGE : PTR_ERR(folio);
		ssdfs_request_unlock_and_remove_folios(&node->flush_req);
		SSDFS_ERR("fail to add folio into request: "
			  "blk_index %u, err %d\n",
			  blk_index, err);
		return err;
	}

	folio_start_writeback(folio);

	err = ssdfs_btree_node_save_diff_blob_metadata(node,
							blk_index,
							folio,
							&hdr,
							&write_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to save diff blob's metadata: "
			  "write_offset %u, err %d\n",
			  write_offset, err);
		goto finish_prepare_diff_blob;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("SAVE DIFF BLOB METADATA: write_offset %u\n",
		  write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	blob_offset = write_offset;

	if (blk_index == 0) {
		down_read(&node->header_lock);
		err = ssdfs_btree_node_copy_header_nolock(node, folio,
							  &write_offset);
		up_read(&node->header_lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to save btree node's header: "
				  "write_offset %u, err %d\n",
				  write_offset, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("SAVE BTREE NODE HEADER: write_offset %u\n",
			  write_offset);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	err = ssdfs_btree_node_copy_dirty_indexes(node,
						  index_area_offset,
						  index_area_size,
						  blk_index,
						  blk_start_bit,
						  folio,
						  &write_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy dirty indexes: "
			  "write_offset %u, err %d\n",
			  write_offset, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("SAVE DIRTY INDEXES: write_offset %u\n",
		  write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_node_copy_dirty_items(node,
						items_area_offset,
						items_area_size,
						item_size,
						index_capacity,
						blk_index,
						blk_start_bit,
						folio,
						&write_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy dirty items: "
			  "write_offset %u, err %d\n",
			  write_offset, err);
		goto finish_prepare_diff_blob;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("SAVE DIRTY ITEMS: write_offset %u\n",
		  write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	blob_size = write_offset - blob_offset;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(blob_size >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr.diff.blob_size = cpu_to_le16((u16)blob_size);

	err = __ssdfs_memcpy_to_folio(folio, 0, PAGE_SIZE,
				      &hdr, 0, hdr_size,
				      hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy diff blob's header: "
			  "err %d\n", err);
		goto finish_prepare_diff_blob;
	}

finish_prepare_diff_blob:
	return err;
}

/*
 * ssdfs_btree_node_prepare_diff() - prepare node's diff for flush operation
 * @node: node object
 *
 * This method tries to prepare the node's diff for flush operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - block descriptor is not ready for diff.
 */
int ssdfs_btree_node_prepare_diff(struct ssdfs_btree_node *node)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_state_bitmap *bmap;
	u32 mem_pages_per_block;
	u64 logical_offset;
	u32 data_bytes;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u32 i;
#ifdef CONFIG_SSDFS_DEBUG
	struct folio *folio;
	void *kaddr;
	int j;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!node || !node->tree || !node->tree->fsi);

	switch (atomic_read(&node->type)) {
	case SSDFS_BTREE_INDEX_NODE:
	case SSDFS_BTREE_HYBRID_NODE:
	case SSDFS_BTREE_LEAF_NODE:
		/* expected state */
		break;

	default:
		BUG();
	};
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = node->tree->fsi;
	mem_pages_per_block = fsi->pagesize / PAGE_SIZE;

	err = ssdfs_btree_node_ready_for_diff(node);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("node %u is not ready for diff\n",
			  node->node_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check readiness for diff: "
			  "node_id %u, height %u, type %#x, err %d\n",
			  node->node_id,
			  atomic_read(&node->height),
			  atomic_read(&node->type),
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("node_id %u, height %u, type %#x\n",
		  node->node_id, atomic_read(&node->height),
		  atomic_read(&node->type));

	SSDFS_DBG("NODE CONTENT: is_locked %d, batch_size %u\n",
		  rwsem_is_locked(&node->full_lock),
		  folio_batch_count(&node->content.batch));

	for (i = 0; i < folio_batch_count(&node->content.batch); i++) {
		folio = node->content.batch.folios[i];

		if (!folio)
			continue;

		for (j = 0; j < mem_pages_per_block; j++) {
			kaddr = kmap_local_folio(folio, j * PAGE_SIZE);
			SSDFS_DBG("PAGE DUMP: folio_index %d, "
				  "page_index %d\n",
				  i, j);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&node->descriptor_lock);
	si = node->seg;
	seg_id = le64_to_cpu(node->extent.seg_id);
	logical_blk = le32_to_cpu(node->extent.logical_blk);
	len = le32_to_cpu(node->extent.len);
	spin_unlock(&node->descriptor_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, logical_blk %u, len %u\n",
		  seg_id, logical_blk, len);

	BUG_ON(!si);
	BUG_ON(seg_id != si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_init(&node->flush_req, fsi->pagesize);
	ssdfs_get_request(&node->flush_req);

	down_read(&node->full_lock);

	for (i = 0; i < len; i++) {
		u32 cur_blk = logical_blk + i;

		err = ssdfs_btree_node_prepare_logical_block_diff(node,
								  cur_blk,
								  i);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare logical block's diff: "
				  "node_id %u, height %u, type %#x, "
				  "logical_blk %u, err %d\n",
				  node->node_id,
				  atomic_read(&node->height),
				  atomic_read(&node->type),
				  cur_blk, err);
			goto finish_prepare_diff_blob;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("DIFF CONTENT: batch_size %u\n",
		  folio_batch_count(&node->flush_req.result.batch));

	for (i = 0; i < folio_batch_count(&node->flush_req.result.batch); i++) {
		folio = node->flush_req.result.batch.folios[i];

		if (!folio)
			continue;

		for (j = 0; j < mem_pages_per_block; j++) {
			kaddr = kmap_local_folio(folio, j * PAGE_SIZE);
			SSDFS_DBG("DIFF DUMP: folio_index %d, "
				  "page_index %d\n",
				  i, j);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	logical_offset = (u64)node->node_id * node->node_size;
	data_bytes = len * fsi->pagesize;
	ssdfs_request_prepare_logical_extent(node->tree->owner_ino,
					     (u64)logical_offset,
					     (u32)data_bytes,
					     0, 0, &node->flush_req);

	ssdfs_request_define_segment(seg_id, &node->flush_req);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_blk >= U16_MAX);
	BUG_ON(len >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_define_volume_extent((u16)logical_blk, (u16)len,
					   &node->flush_req);

	err = ssdfs_segment_node_diff_on_write_async(si,
						     SSDFS_REQ_ASYNC_NO_FREE,
						     &node->flush_req);
	if (!err) {
		down_read(&node->bmap_array.lock);
		bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
		spin_lock(&bmap->lock);
		bitmap_clear(bmap->ptr, 0, node->bmap_array.bits_count);
		spin_unlock(&bmap->lock);
		up_read(&node->bmap_array.lock);
		clear_ssdfs_btree_node_dirty(node);
	}

finish_prepare_diff_blob:
	up_read(&node->full_lock);

	if (unlikely(err)) {
		ssdfs_request_unlock_and_remove_folios(&node->flush_req);
		SSDFS_ERR("diff-on-write request failed: "
			  "ino %llu, logical_offset %llu, size %u, err %d\n",
			  node->flush_req.extent.ino,
			  node->flush_req.extent.logical_offset,
			  node->flush_req.extent.data_bytes,
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_node_apply_header() - apply actual state of btree node
 * @fsi: file system info object
 * @req: read request
 * @kaddr: diff blob
 * @offset: pointer on offset in diff blob [in|out]
 *
 * This method tries to apply the actual state of
 * btree node's header.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_node_apply_header(struct ssdfs_fs_info *fsi,
				  struct ssdfs_segment_request *req,
				  void *kaddr, u32 *offset)
{
	size_t hdr_size = sizeof(union ssdfs_aggregated_btree_node_header);
	u32 hdr_offset = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !kaddr || !offset);

	SSDFS_DBG("req %p, kaddr %p, offset %u\n",
		  req, kaddr, *offset);
#endif /* CONFIG_SSDFS_DEBUG */

	if ((*offset + hdr_size) > PAGE_SIZE) {
		SSDFS_ERR("invalid request: offset %u, hdr_size %zu\n",
			  *offset, hdr_size);
		return -ERANGE;
	}

	hdr_offset = req->result.processed_blks * fsi->pagesize;

	err = ssdfs_unaligned_write_folio_batch(fsi,
						&req->result.batch,
						hdr_offset, hdr_size,
						(u8 *)kaddr + *offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to apply btree node's header: "
			  "err %d\n", err);
		return err;
	}

	*offset += hdr_size;
	return 0;
}

/*
 * ssdfs_btree_node_apply_indexes() - apply actual state of modified indexes
 * @fsi: file system info object
 * @req: read request
 * @index_size: size of index in bytes
 * @bmap: pointer on dirty bitmap
 * @bmap_bytes: size of bitmap in bytes
 * @start_bit: starting item for search
 * @max_bit: upper bound for search
 * @kaddr: diff blob
 * @offset: pointer on offset in diff blob [in|out]
 *
 * This method tries to apply the actual state of
 * btree node's indexes.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_node_apply_indexes(struct ssdfs_fs_info *fsi,
				   struct ssdfs_segment_request *req,
				   u8 index_size,
				   unsigned long *bmap, size_t bmap_bytes,
				   u16 start_bit, u16 max_bit,
				   void *kaddr, u32 *offset)
{
	struct ssdfs_metadata_diff_blob_header *hdr;
	size_t hdr_size = sizeof(union ssdfs_aggregated_btree_node_header);
	u16 diff_flags;
	u32 index_offset;
	unsigned long search_start = start_bit;
	unsigned long found_item = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !bmap || !kaddr || !offset);

	SSDFS_DBG("req %p, index_size %u, "
		  "bmap %p, bmap_bytes %zu, "
		  "start_bit %u, max_bit %u, "
		  "kaddr %p, offset %u\n",
		  req, index_size,
		  bmap, bmap_bytes,
		  start_bit, max_bit,
		  kaddr, *offset);
#endif /* CONFIG_SSDFS_DEBUG */

	if (*offset >= PAGE_SIZE) {
		SSDFS_ERR("invalid offset %u\n",
			  *offset);
		return -EINVAL;
	}

	hdr = (struct ssdfs_metadata_diff_blob_header *)kaddr;
	diff_flags = le16_to_cpu(hdr->diff.flags);

	while (search_start < max_bit) {
		err = ssdfs_metadata_find_first_dirty_item(bmap,
							   bmap_bytes,
							   search_start,
							   max_bit,
							   &found_item);
		if (err == -ENODATA) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("no more dirty indexes: "
				  "start %lu, max %u\n",
				  search_start, max_bit);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_apply_indexes;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find dirty index: "
				  "start %lu, max %u, err %d\n",
				  search_start, max_bit, err);
			goto finish_apply_indexes;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found bit %lu: "
			  "start_bit %lu, max_bit %u\n",
			  found_item,
			  search_start, max_bit);
#endif /* CONFIG_SSDFS_DEBUG */

		index_offset = req->result.processed_blks * fsi->pagesize;

		if (diff_flags & SSDFS_DIFF_BLOB_HAS_BTREE_NODE_HEADER)
			index_offset += hdr_size;

		index_offset += ((found_item - start_bit) * index_size);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found bit %lu, index_offset %u\n",
			  found_item, index_offset);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_unaligned_write_folio_batch(fsi,
							&req->result.batch,
							index_offset, index_size,
							(u8 *)kaddr + *offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to apply btree node's index: "
				  "index_offset %u, index_size %u, "
				  "offset %u, err %d\n",
				  index_offset, index_size,
				  *offset, err);
			goto finish_apply_indexes;
		}

		*offset += index_size;

		if (*offset >= PAGE_SIZE) {
			err = -ERANGE;
			SSDFS_ERR("invalid offset %u\n",
				  *offset);
			goto finish_apply_indexes;
		}

		search_start = found_item + 1;
	}

finish_apply_indexes:
	return err;
}

/*
 * ssdfs_btree_node_apply_items() - apply actual state of modified items
 * @fsi: file system info object
 * @req: read request
 * @index_size: size of index in bytes
 * @indexes_capacity: capacity of indexes in btree node
 * @bmap: pointer on dirty bitmap
 * @bmap_bytes: size of bitmap in bytes
 * @item_size: size of item in bytes
 * @start_bit: starting item for search
 * @max_bit: upper bound for search
 * @kaddr: diff blob
 * @offset: pointer on offset in diff blob [in|out]
 *
 * This method tries to apply the actual state of
 * btree node's items.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_node_apply_items(struct ssdfs_fs_info *fsi,
				 struct ssdfs_segment_request *req,
				 u8 index_size, u32 indexes_capacity,
				 unsigned long *bmap, size_t bmap_bytes,
				 u16 item_size,
				 u16 start_bit, u16 max_bit,
				 void *kaddr, u32 *offset)
{
	struct ssdfs_metadata_diff_blob_header *hdr;
	size_t hdr_size = sizeof(union ssdfs_aggregated_btree_node_header);
	u16 diff_flags;
	u32 item_offset;
	unsigned long search_start = start_bit;
	unsigned long found_item = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !bmap || !kaddr || !offset);

	SSDFS_DBG("req %p, item_size %u, "
		  "bmap %p, bmap_bytes %zu, "
		  "indexes_capacity %u, "
		  "start_bit %u, max_bit %u, "
		  "kaddr %p, offset %u\n",
		  req, item_size,
		  bmap, bmap_bytes,
		  indexes_capacity,
		  start_bit, max_bit,
		  kaddr, *offset);
#endif /* CONFIG_SSDFS_DEBUG */

	if (*offset >= PAGE_SIZE) {
		SSDFS_ERR("invalid offset %u\n",
			  *offset);
		return -EINVAL;
	}

	hdr = (struct ssdfs_metadata_diff_blob_header *)kaddr;
	diff_flags = le16_to_cpu(hdr->diff.flags);

	while (search_start < max_bit) {
		err = ssdfs_metadata_find_first_dirty_item(bmap,
							   bmap_bytes,
							   search_start,
							   max_bit,
							   &found_item);
		if (err == -ENODATA) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("no more dirty items: "
				  "start %lu, max %u\n",
				  search_start, max_bit);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_apply_items;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find dirty item: "
				  "start %lu, max %u, err %d\n",
				  search_start, max_bit, err);
			goto finish_apply_items;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found bit %lu: "
			  "start_bit %lu, max_bit %u\n",
			  found_item,
			  search_start, max_bit);
#endif /* CONFIG_SSDFS_DEBUG */

		item_offset = req->result.processed_blks * fsi->pagesize;

		if (diff_flags & SSDFS_DIFF_BLOB_HAS_BTREE_NODE_HEADER)
			item_offset += hdr_size;

		item_offset += indexes_capacity * index_size;
		item_offset += (found_item - start_bit) * item_size;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("found_item %lu, item_offset %u\n",
			  found_item - start_bit, item_offset);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_unaligned_write_folio_batch(fsi,
							&req->result.batch,
							item_offset, item_size,
							(u8 *)kaddr + *offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to apply btree node's item: "
				  "item_offset %u, item_size %u, "
				  "offset %u, err %d\n",
				  item_offset, item_size,
				  *offset, err);
			goto finish_apply_items;
		}

		*offset += item_size;

		if (*offset >= PAGE_SIZE) {
			err = -ERANGE;
			SSDFS_ERR("invalid offset %u\n",
				  *offset);
			goto finish_apply_items;
		}

		search_start = found_item + 1;
	}

finish_apply_items:
	return err;
}

/*
 * ssdfs_btree_node_apply_diff_page() - apply diff blob on btree node
 * @fsi: file system info object
 * @req: read request
 * @folio: current folio with diff blob
 *
 * This method tries to apply a diff blob on btree node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_btree_node_apply_diff_page(struct ssdfs_fs_info *fsi,
				     struct ssdfs_segment_request *req,
				     struct folio *folio)
{
	struct ssdfs_metadata_diff_blob_header *hdr;
	size_t hdr_size = sizeof(struct ssdfs_metadata_diff_blob_header);
	size_t index_size = sizeof(struct ssdfs_btree_index_key);
	void *kaddr;
	unsigned long *bmap;
	size_t bmap_bytes;
	u16 bits_count;
	u16 item_start_bit;
	u16 index_start_bit;
	u16 indexes_capacity;
	u16 item_size;
	u16 diff_flags;
	u32 offset;
	__le32 calculated_csum = ~0;
	__le32 csum;
#ifdef CONFIG_SSDFS_DEBUG
	u32 mem_pages_per_block;
	int i, j;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !folio);
	WARN_ON(!folio_test_locked(folio));

	SSDFS_DBG("req %p, folio %p\n", req, folio);
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = kmap_local_folio(folio, 0);

	hdr = (struct ssdfs_metadata_diff_blob_header *)kaddr;

	if (le16_to_cpu(hdr->diff.magic) != SSDFS_DIFF_BLOB_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid header magic %#x\n",
			  le16_to_cpu(hdr->diff.magic));
		goto finish_apply_diff_folio;
	}

	if (hdr->diff.type != SSDFS_BTREE_NODE_DIFF_BLOB) {
		err = -EIO;
		SSDFS_ERR("invalid blob type %#x\n",
			  hdr->diff.type);
		goto finish_apply_diff_folio;
	}

	bits_count = le16_to_cpu(hdr->bits_count);
	index_start_bit = le16_to_cpu(hdr->index_start_bit);
	item_start_bit = le16_to_cpu(hdr->item_start_bit);
	indexes_capacity = item_start_bit - index_start_bit;
	item_size = le16_to_cpu(hdr->item_size);
	diff_flags = le16_to_cpu(hdr->diff.flags);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("index_start_bit %u, item_start_bit %u, "
		  "indexes_capacity %u, item_size %u, "
		  "diff_flags %#x\n",
		  index_start_bit, item_start_bit,
		  indexes_capacity, item_size, diff_flags);
#endif /* CONFIG_SSDFS_DEBUG */

	if (index_start_bit >= bits_count) {
		err = -EIO;
		SSDFS_ERR("corrupted diff blob: "
			  "index_start_bit %u >= bits_count %u\n",
			  index_start_bit, bits_count);
		goto finish_apply_diff_folio;
	}

	if (item_start_bit >= bits_count) {
		err = -EIO;
		SSDFS_ERR("corrupted diff blob: "
			  "item_start_bit %u >= bits_count %u\n",
			  item_start_bit, bits_count);
		goto finish_apply_diff_folio;
	}

	if (index_start_bit > item_start_bit) {
		err = -EIO;
		SSDFS_ERR("corrupted diff blob: "
			  "index_start_bit %u > item_start_bit %u\n",
			  index_start_bit, item_start_bit);
		goto finish_apply_diff_folio;
	}

	if (diff_flags & ~SSDFS_DIFF_BLOB_FLAGS_MASK) {
		err = -EIO;
		SSDFS_ERR("invalid set of flags: "
			  "diff_flags %#x\n",
			  diff_flags);
		goto finish_apply_diff_folio;
	}

	/* copy checksum at first */
	csum = *GET_CHECKSUM(kaddr);

	/* bitmap is located after header and checksum */
	bmap = GET_BMAP(kaddr);
	bmap_bytes = hdr->diff.desc_size - sizeof(__le32);

	offset = hdr_size + sizeof(__le32) + bmap_bytes;

	if (offset >= PAGE_SIZE) {
		err = -EIO;
		SSDFS_ERR("corrupted diff blob: "
			  "hdr_size %zu, desc_size %u\n",
			  hdr_size, hdr->diff.desc_size);
		goto finish_apply_diff_folio;
	}

	if (diff_flags & SSDFS_DIFF_BLOB_HAS_BTREE_NODE_HEADER) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("APPLY HEADER: offset %u\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_btree_node_apply_header(fsi, req, kaddr, &offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to apply btree node's header: "
				  "offset %u, err %d\n",
				  offset, err);
			goto finish_apply_diff_folio;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("APPLY INDEXES: offset %u\n",
		  offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_node_apply_indexes(fsi, req, index_size,
					     bmap, bmap_bytes,
					     index_start_bit,
					     item_start_bit,
					     kaddr, &offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to apply btree node's indexes: "
			  "offset %u, err %d\n",
			  offset, err);
		goto finish_apply_diff_folio;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("APPLY ITEMS: offset %u\n",
		  offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_btree_node_apply_items(fsi, req,
					   index_size, indexes_capacity,
					   bmap, bmap_bytes, item_size,
					   item_start_bit, bits_count,
					   kaddr, &offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to apply btree node's items: "
			  "offset %u, err %d\n",
			  offset, err);
		goto finish_apply_diff_folio;
	}

finish_apply_diff_folio:
	flush_dcache_folio(folio);
	kunmap_local(kaddr);

	if (unlikely(err)) {
		SSDFS_ERR("fail to apply diff folio: err %d\n",
			  err);
		return err;
	}

	err = ssdfs_calculate_block_checksum(fsi,
					     req->result.processed_blks,
					     &req->result.batch,
					     &calculated_csum);
	if (err) {
		SSDFS_ERR("fail to calculate block's checksum: "
			  "blk_index %u, err %d\n",
			  req->result.processed_blks, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("blk_index %u, checksum %#x\n",
		  req->result.processed_blks,
		  le32_to_cpu(calculated_csum));
#endif /* CONFIG_SSDFS_DEBUG */

	if (calculated_csum != csum) {
		SSDFS_WARN("invalid checksum: "
			   "calculated_csum %#x != csum %#x\n",
			   le32_to_cpu(calculated_csum),
			   le32_to_cpu(csum));

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("NODE CONTENT: batch_size %u\n",
			  folio_batch_count(&req->result.batch));

		mem_pages_per_block = fsi->pagesize / PAGE_SIZE;

		for (i = 0; i < folio_batch_count(&req->result.batch); i++) {
			struct folio *content_folio =
						req->result.batch.folios[i];

			if (!content_folio)
				continue;

			for (j = 0; j < mem_pages_per_block; j++) {
				kaddr = kmap_local_folio(folio, j * PAGE_SIZE);
				SSDFS_DBG("PAGE DUMP: folio_index %d, "
					  "page_index %d\n",
					  i, j);
				print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						     kaddr,
						     PAGE_SIZE);
				SSDFS_DBG("\n");
				kunmap_local(kaddr);
			}
		}

		BUG();
#else
		return -EIO;
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("FINISHED: offset %u\n",
		  offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_btree_node_apply_diffs() - synthesize the actual state of btree node
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This method tries to synthesize the actual state of btree node.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_btree_node_apply_diffs(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct folio *folio;
	u32 mem_pages_per_block;
	int i;
#ifdef CONFIG_SSDFS_DEBUG
	void *kaddr;
	int j;
#endif /* CONFIG_SSDFS_DEBUG */
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "class %#x, cmd %#x, type %#x, "
		  "ino %llu, logical_offset %llu, data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  req->private.class, req->private.cmd, req->private.type,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	mem_pages_per_block = fsi->pagesize / PAGE_SIZE;

	if (folio_batch_count(&req->result.diffs) == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("diff batch is empty: "
			  "seg %llu, peb %llu, "
			  "class %#x, cmd %#x, type %#x, "
			  "ino %llu, logical_offset %llu, data_bytes %u\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  req->private.class, req->private.cmd,
			  req->private.type, req->extent.ino,
			  req->extent.logical_offset,
			  req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("NODE CONTENT: batch_size %u\n",
		  folio_batch_count(&req->result.batch));

	for (i = 0; i < folio_batch_count(&req->result.batch); i++) {
		folio = req->result.batch.folios[i];

		if (!folio)
			continue;

		for (j = 0; j < mem_pages_per_block; j++) {
			kaddr = kmap_local_folio(folio, j * PAGE_SIZE);
			SSDFS_DBG("PAGE DUMP: folio_index %d, page_index %d\n",
				  i, j);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < folio_batch_count(&req->result.diffs); i++) {
		folio = req->result.diffs.folios[i];

		if (!folio) {
			SSDFS_WARN("folio %d is NULL\n", i);
			continue;
		}

#ifdef CONFIG_SSDFS_DEBUG
		WARN_ON(!folio_test_locked(folio));

		for (j = 0; j < mem_pages_per_block; j++) {
			kaddr = kmap_local_folio(folio, j * PAGE_SIZE);
			SSDFS_DBG("DIFF DUMP: folio_index %d, page_index %d\n",
				  i, j);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);
		}
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_btree_node_apply_diff_page(fsi, req, folio);
		if (unlikely(err)) {
			SSDFS_ERR("fail to apply diff page: "
				  "seg %llu, peb %llu, folio_index %d, "
				  "class %#x, cmd %#x, type %#x, "
				  "ino %llu, logical_offset %llu, "
				  "data_bytes %u\n",
				  pebi->pebc->parent_si->seg_id, pebi->peb_id,
				  i, req->private.class, req->private.cmd,
				  req->private.type, req->extent.ino,
				  req->extent.logical_offset,
				  req->extent.data_bytes);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("NODE CONTENT: batch_size %u\n",
		  folio_batch_count(&req->result.batch));

	for (i = 0; i < folio_batch_count(&req->result.batch); i++) {
		folio = req->result.batch.folios[i];

		if (!folio)
			continue;

		for (j = 0; j < mem_pages_per_block; j++) {
			kaddr = kmap_local_folio(folio, j * PAGE_SIZE);
			SSDFS_DBG("PAGE DUMP: folio_index %d, page_index %d\n",
				  i, j);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}
