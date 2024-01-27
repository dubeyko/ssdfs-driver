/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_block_bitmap.h - segment's block bitmap declarations.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2024 Viacheslav Dubeyko <slava@dubeyko.com>
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

#ifndef _SSDFS_SEGMENT_BLOCK_BITMAP_H
#define _SSDFS_SEGMENT_BLOCK_BITMAP_H

#include "peb_block_bitmap.h"

/*
 * struct ssdfs_segment_blk_bmap - segment block bitmap object
 * @state: segment block bitmap's state
 * @pages_per_peb: pages per physical erase block
 * @pages_per_seg: pages per segment
 * @modification_lock: lock for modification operations
 * @seg_valid_blks: segment's valid logical blocks count
 * @seg_invalid_blks: segment's invalid logical blocks count
 * @seg_free_blks: segment's free logical blocks count
 * @seg_reserved_metapages: number of reserved metapages
 * @peb: array of PEB block bitmap objects
 * @pebs_count: PEBs count in segment
 * @parent_si: pointer on parent segment object
 */
struct ssdfs_segment_blk_bmap {
	atomic_t state;

	u32 pages_per_peb;
	u32 pages_per_seg;

	struct rw_semaphore modification_lock;
	atomic_t seg_valid_blks;
	atomic_t seg_invalid_blks;
	atomic_t seg_free_blks;
	atomic_t seg_reserved_metapages;

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
				  int init_flag, int init_state);
void ssdfs_segment_blk_bmap_destroy(struct ssdfs_segment_blk_bmap *ptr);
int ssdfs_segment_blk_bmap_partial_init(struct ssdfs_segment_blk_bmap *bmap,
				    u16 peb_index,
				    struct ssdfs_folio_vector *source,
				    struct ssdfs_block_bitmap_fragment *hdr,
				    u64 cno);
int
ssdfs_segment_blk_bmap_partial_clean_init(struct ssdfs_segment_blk_bmap *bmap,
					  u16 peb_index);
void ssdfs_segment_blk_bmap_init_failed(struct ssdfs_segment_blk_bmap *bmap,
					u16 peb_index);

bool is_ssdfs_segment_blk_bmap_dirty(struct ssdfs_segment_blk_bmap *bmap,
					u16 peb_index);

bool has_ssdfs_segment_blk_bmap_initialized(struct ssdfs_segment_blk_bmap *ptr,
					    struct ssdfs_peb_container *pebc);
int ssdfs_segment_blk_bmap_wait_init_end(struct ssdfs_segment_blk_bmap *ptr,
					 struct ssdfs_peb_container *pebc);

int ssdfs_segment_blk_bmap_get_block_state(struct ssdfs_segment_blk_bmap *ptr,
					   struct ssdfs_peb_container *pebc,
					   u32 blk);
int ssdfs_segment_blk_bmap_reserve_metapages(struct ssdfs_segment_blk_bmap *ptr,
					     struct ssdfs_peb_container *pebc,
					     u32 count);
int ssdfs_segment_blk_bmap_free_metapages(struct ssdfs_segment_blk_bmap *ptr,
					  struct ssdfs_peb_container *pebc,
					  u32 count);
int ssdfs_segment_blk_bmap_reserve_block(struct ssdfs_segment_blk_bmap *ptr);
int ssdfs_segment_blk_bmap_reserve_extent(struct ssdfs_segment_blk_bmap *ptr,
					  u32 count, u32 *reserved_blks);
int ssdfs_segment_blk_bmap_pre_allocate(struct ssdfs_segment_blk_bmap *ptr,
					struct ssdfs_peb_container *pebc,
					struct ssdfs_block_bmap_range *range);
int ssdfs_segment_blk_bmap_allocate(struct ssdfs_segment_blk_bmap *ptr,
				    struct ssdfs_peb_container *pebc,
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
	int free_blks;
	int valid_blks;
	int invalid_blks;
	int calculated;

	BUG_ON(!ptr);

	free_blks = atomic_read(&ptr->seg_free_blks);
	valid_blks = atomic_read(&ptr->seg_valid_blks);
	invalid_blks = atomic_read(&ptr->seg_invalid_blks);
	calculated = free_blks + valid_blks + invalid_blks;

	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  free_blks, valid_blks, invalid_blks,
		  ptr->pages_per_seg);

	if (calculated > ptr->pages_per_seg) {
		SSDFS_WARN("free_logical_blks %d, valid_logical_blks %d, "
			   "invalid_logical_blks %d, calculated %d, "
			   "pages_per_seg %u\n",
			   free_blks, valid_blks, invalid_blks,
			   calculated, ptr->pages_per_seg);
	}
#endif /* CONFIG_SSDFS_DEBUG */
	return atomic_read(&ptr->seg_free_blks);
}

static inline
int ssdfs_segment_blk_bmap_get_used_pages(struct ssdfs_segment_blk_bmap *ptr)
{
	int valid_blks;

#ifdef CONFIG_SSDFS_DEBUG
	int free_blks;
	int invalid_blks;
	int calculated;

	BUG_ON(!ptr);

	down_read(&ptr->modification_lock);
	free_blks = atomic_read(&ptr->seg_free_blks);
	valid_blks = atomic_read(&ptr->seg_valid_blks);
	invalid_blks = atomic_read(&ptr->seg_invalid_blks);
	calculated = free_blks + valid_blks + invalid_blks;
	up_read(&ptr->modification_lock);

	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  free_blks, valid_blks, invalid_blks,
		  ptr->pages_per_seg);

	if (calculated > ptr->pages_per_seg) {
		SSDFS_WARN("free_logical_blks %d, valid_logical_blks %d, "
			   "invalid_logical_blks %d, calculated %d, "
			   "pages_per_seg %u\n",
			   free_blks, valid_blks, invalid_blks,
			   calculated, ptr->pages_per_seg);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&ptr->modification_lock);
	valid_blks = atomic_read(&ptr->seg_valid_blks);
	up_read(&ptr->modification_lock);

	return valid_blks;
}

static inline
int ssdfs_segment_blk_bmap_get_invalid_pages(struct ssdfs_segment_blk_bmap *ptr)
{
	int invalid_blks;

#ifdef CONFIG_SSDFS_DEBUG
	int free_blks;
	int valid_blks;
	int calculated;

	BUG_ON(!ptr);

	down_read(&ptr->modification_lock);
	free_blks = atomic_read(&ptr->seg_free_blks);
	valid_blks = atomic_read(&ptr->seg_valid_blks);
	invalid_blks = atomic_read(&ptr->seg_invalid_blks);
	calculated = free_blks + valid_blks + invalid_blks;
	up_read(&ptr->modification_lock);

	SSDFS_DBG("free_logical_blks %d, valid_logical_blks %d, "
		  "invalid_logical_blks %d, pages_per_seg %u\n",
		  free_blks, valid_blks, invalid_blks,
		  ptr->pages_per_seg);

	if (calculated > ptr->pages_per_seg) {
		SSDFS_WARN("free_logical_blks %d, valid_logical_blks %d, "
			   "invalid_logical_blks %d, calculated %d, "
			   "pages_per_seg %u\n",
			   free_blks, valid_blks, invalid_blks,
			   calculated, ptr->pages_per_seg);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&ptr->modification_lock);
	invalid_blks = atomic_read(&ptr->seg_invalid_blks);
	up_read(&ptr->modification_lock);

	return invalid_blks;
}

#endif /* _SSDFS_SEGMENT_BLOCK_BITMAP_H */
