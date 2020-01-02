//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_block_bitmap.h - segment's block bitmap declarations.
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

#ifndef _SSDFS_SEGMENT_BLOCK_BITMAP_H
#define _SSDFS_SEGMENT_BLOCK_BITMAP_H

#include "peb_block_bitmap.h"

/*
 * struct ssdfs_segment_blk_bmap - segment block bitmap object
 * @state: segment block bitmap's state
 * @pages_per_peb: pages per physical erase block
 * @pages_per_seg: pages per segment
 * @valid_logical_blks: segment's valid logical blocks count
 * @invalid_logical_blks: segment's invalid logical blocks count
 * @free_logical_blks: segment's free logical blocks count
 * @peb: array of PEB block bitmap objects
 * @pebs_count: PEBs count in segment
 * @parent_si: pointer on parent segment object
 */
struct ssdfs_segment_blk_bmap {
	atomic_t state;

	u32 pages_per_peb;
	u32 pages_per_seg;

	atomic_t valid_logical_blks;
	atomic_t invalid_logical_blks;
	atomic_t free_logical_blks;

	struct ssdfs_peb_blk_bmap *peb;
	u16 pebs_count;

	struct ssdfs_segment_info *parent_si;
};

/* Segment block bitmap's possible states */
enum {
	SSDFS_SEG_BLK_BMAP_STATE_UNKNOWN,
	SSDFS_SEG_BLK_BMAP_CREATED,
	SSDFS_SEG_BLK_BMAP_STATE_MAX,
};

/*
 * Segment block bitmap API
 */
int ssdfs_segment_blk_bmap_create(struct ssdfs_segment_info *si,
				  u32 pages_per_peb,
				  int init_flag, int init_state);
void ssdfs_segment_blk_bmap_destroy(struct ssdfs_segment_blk_bmap *ptr);
int ssdfs_segment_blk_bmap_partial_init(struct ssdfs_segment_blk_bmap *bmap,
				    u16 peb_index,
				    struct pagevec *source,
				    struct ssdfs_block_bitmap_fragment *hdr,
				    u64 cno);
void ssdfs_segment_blk_bmap_init_failed(struct ssdfs_segment_blk_bmap *bmap,
					u16 peb_index);

int ssdfs_segment_blk_bmap_reserve_metapages(struct ssdfs_segment_blk_bmap *ptr,
					     struct ssdfs_peb_container *pebc,
					     u16 count);
int ssdfs_segment_blk_bmap_free_metapages(struct ssdfs_segment_blk_bmap *ptr,
					  struct ssdfs_peb_container *pebc,
					  u16 count);
int ssdfs_segment_blk_bmap_pre_allocate(struct ssdfs_segment_blk_bmap *ptr,
					struct ssdfs_peb_container *pebc,
					u32 *len,
					struct ssdfs_block_bmap_range *range);
int ssdfs_segment_blk_bmap_allocate(struct ssdfs_segment_blk_bmap *ptr,
				    struct ssdfs_peb_container *pebc,
				    u32 *len,
				    struct ssdfs_block_bmap_range *range);
int ssdfs_segment_blk_bmap_update_range(struct ssdfs_segment_blk_bmap *ptr,
				    struct ssdfs_peb_container *pebc,
				    u8 peb_migration_id,
				    int range_state,
				    struct ssdfs_block_bmap_range *range);

static inline
int ssdfs_segment_blk_bmap_get_free_pages(struct ssdfs_segment_blk_bmap *ptr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->free_logical_blks),
		  atomic_read(&ptr->valid_logical_blks),
		  atomic_read(&ptr->invalid_logical_blks),
		  ptr->pages_per_seg);
	WARN_ON((atomic_read(&ptr->free_logical_blks) +
		atomic_read(&ptr->valid_logical_blks) +
		atomic_read(&ptr->invalid_logical_blks)) >= ptr->pages_per_seg);
#endif /* CONFIG_SSDFS_DEBUG */
	return atomic_read(&ptr->free_logical_blks);
}

static inline
int ssdfs_segment_blk_bmap_get_used_pages(struct ssdfs_segment_blk_bmap *ptr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->free_logical_blks),
		  atomic_read(&ptr->valid_logical_blks),
		  atomic_read(&ptr->invalid_logical_blks),
		  ptr->pages_per_seg);
	WARN_ON((atomic_read(&ptr->free_logical_blks) +
		atomic_read(&ptr->valid_logical_blks) +
		atomic_read(&ptr->invalid_logical_blks)) >= ptr->pages_per_seg);
#endif /* CONFIG_SSDFS_DEBUG */
	return atomic_read(&ptr->valid_logical_blks);
}

static inline
int ssdfs_segment_blk_bmap_get_invalid_pages(struct ssdfs_segment_blk_bmap *ptr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  atomic_read(&ptr->free_logical_blks),
		  atomic_read(&ptr->valid_logical_blks),
		  atomic_read(&ptr->invalid_logical_blks),
		  ptr->pages_per_seg);
	WARN_ON((atomic_read(&ptr->free_logical_blks) +
		atomic_read(&ptr->valid_logical_blks) +
		atomic_read(&ptr->invalid_logical_blks)) >= ptr->pages_per_seg);
#endif /* CONFIG_SSDFS_DEBUG */
	return atomic_read(&ptr->invalid_logical_blks);
}

#endif /* _SSDFS_SEGMENT_BLOCK_BITMAP_H */
