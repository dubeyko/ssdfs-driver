// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/diff_on_write.c - Diff-On-Write approach implementation.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
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

/*
 * can_diff_on_write_metadata_be_used() - check Diff-On-Write way applicability
 * @node: node object
 *
 * This method tries to check that Diff-On-Write way
 * can be used for metadata case.
 */
bool can_diff_on_write_metadata_be_used(struct ssdfs_btree_node *node)
{
	struct ssdfs_state_bitmap *bmap;
	unsigned long dirty_bits = 0;
	unsigned long dirty_indexes = 0;
	unsigned long dirty_items = 0;
	unsigned long allocated_bits = 0;
	unsigned long bits_count = 0;
	unsigned long items_count = 0;
	unsigned long items_capacity = 0;
	unsigned long item_size = 0;
	unsigned long index_count = 0;
	unsigned long index_capacity = 0;
	unsigned long index_size = 0;
	unsigned long percentage = 0;
	unsigned long bmap_bytes = 0;
	u64 total_bytes = 0;
	u64 dirty_bytes = 0;
	bool can_be_used = false;

	down_read(&node->header_lock);

	down_read(&node->bmap_array.lock);
	bmap_bytes = node->bmap_array.bmap_bytes;
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_DIRTY_BMAP];
	spin_lock(&bmap->lock);
	bits_count = node->bmap_array.bits_count;
	dirty_bits = bitmap_weight(bmap->ptr, bits_count);
	dirty_indexes = bitmap_weight(bmap->ptr,
				node->bmap_array.item_start_bit);
	dirty_items = dirty_bits - dirty_indexes;
	spin_unlock(&bmap->lock);
	bmap = &node->bmap_array.bmap[SSDFS_BTREE_NODE_ALLOC_BMAP];
	spin_lock(&bmap->lock);
	allocated_bits = bitmap_weight(bmap->ptr,
					node->bmap_array.bits_count);
	spin_unlock(&bmap->lock);
	up_read(&node->bmap_array.lock);

	if (is_ssdfs_btree_node_index_area_exist(node)) {
		index_count = node->index_area.index_count;
		index_capacity = node->index_area.index_capacity;
		index_size = node->index_area.index_size;
	}

	if (is_ssdfs_btree_node_items_area_exist(node)) {
		items_count = node->items_area.items_count;
		items_capacity = node->items_area.items_capacity;
		item_size = node->items_area.item_size;
	}

	if (index_count == 0 && items_count == 0) {
		SSDFS_WARN("index_count %ld, items_count %ld\n",
			   index_count, items_count);
		can_be_used = false;
		goto finish_check;
	}

	percentage = (dirty_bits * 100) / (index_capacity + items_capacity);

	total_bytes = ((u64)index_capacity * index_size) +
			((u64)items_capacity * item_size);

#ifdef CONFIG_SSDFS_DIFF_ON_WRITE_METADATA
	if (percentage <= CONFIG_SSDFS_DIFF_ON_WRITE_METADATA_THRESHOLD) {
#else
	if (percentage <= SSDFS_DIFF_ON_WRITE_PCT_THRESHOLD) {
#endif /* CONFIG_SSDFS_DIFF_ON_WRITE_METADATA */
		dirty_bytes = sizeof(struct ssdfs_diff_blob_header);
		dirty_bytes += bmap_bytes;
		dirty_bytes += sizeof(node->raw);
		dirty_bytes += dirty_indexes * index_size;
		dirty_bytes += dirty_items * item_size;

		if (dirty_bytes <= PAGE_SIZE)
			can_be_used = true;
	} else
		can_be_used = false;

finish_check:
	up_read(&node->header_lock);

	if (can_be_used) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("Diff-On-Write: node_id %u, height %u, type %#x, "
			  "dirty_bits %ld, dirty_indexes %ld, dirty_items %ld, "
			  "allocated_bits %ld, bits_count %ld, "
			  "items_count %ld, items_capacity %ld, item_size %ld, "
			  "index_count %ld, index_capacity %ld, index_size %ld, "
			  "percentage %ld, total_bytes %llu, dirty_bytes %llu\n",
			  node->node_id, atomic_read(&node->height),
			  atomic_read(&node->type),
			  dirty_bits, dirty_indexes, dirty_items,
			  allocated_bits, bits_count,
			  items_count, items_capacity, item_size,
			  index_count, index_capacity, index_size,
			  percentage, total_bytes, dirty_bytes);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_DIFF_ON_WRITE_METADATA
	return can_be_used;
#else
	return false;
#endif /* CONFIG_SSDFS_DIFF_ON_WRITE_METADATA */
}
