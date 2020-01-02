//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_block_bitmap.h - PEB's block bitmap declarations.
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

#ifndef _SSDFS_PEB_BLOCK_BITMAP_H
#define _SSDFS_PEB_BLOCK_BITMAP_H

#include "block_bitmap.h"

/* PEB's block bitmap indexes */
enum {
	SSDFS_PEB_BLK_BMAP1,
	SSDFS_PEB_BLK_BMAP2,
	SSDFS_PEB_BLK_BMAP_ITEMS_MAX
};

/*
 * struct ssdfs_peb_blk_bmap - PEB container's block bitmap object
 * @state: PEB container's block bitmap's state
 * @peb_index: PEB index in array
 * @pages_per_peb: pages per physical erase block
 * @valid_logical_blks: PEB container's valid logical blocks count
 * @invalid_logical_blks: PEB container's invalid logical blocks count
 * @free_logical_blks: PEB container's free logical blocks count
 * @buffers_state: buffers state
 * @lock: buffers lock
 * @init_cno: initialization checkpoint
 * @src: source PEB's block bitmap object's pointer
 * @dst: destination PEB's block bitmap object's pointer
 * @buffers: block bitmap buffers
 * @init_end: wait of init ending
 * @parent: pointer on parent segment block bitmap
 */
struct ssdfs_peb_blk_bmap {
	atomic_t state;

	u16 peb_index;
	u32 pages_per_peb;

	atomic_t valid_logical_blks;
	atomic_t invalid_logical_blks;
	atomic_t free_logical_blks;

	atomic_t buffers_state;
	struct rw_semaphore lock;
	u64 init_cno;
	struct ssdfs_block_bmap *src;
	struct ssdfs_block_bmap *dst;
	struct ssdfs_block_bmap buffer[SSDFS_PEB_BLK_BMAP_ITEMS_MAX];
	struct completion init_end;

	struct ssdfs_segment_blk_bmap *parent;
};

/* PEB container's block bitmap's possible states */
enum {
	SSDFS_PEB_BLK_BMAP_STATE_UNKNOWN,
	SSDFS_PEB_BLK_BMAP_CREATED,
	SSDFS_PEB_BLK_BMAP_HAS_CLEAN_DST,
	SSDFS_PEB_BLK_BMAP_INITIALIZED,
	SSDFS_PEB_BLK_BMAP_STATE_MAX,
};

/* PEB's buffer array possible states */
enum {
	SSDFS_PEB_BMAP_BUFFERS_EMPTY,
	SSDFS_PEB_BMAP1_SRC,
	SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST,
	SSDFS_PEB_BMAP2_SRC,
	SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST,
	SSDFS_PEB_BMAP_BUFFERS_STATE_MAX
};

/* PEB's block bitmap operation destination */
enum {
	SSDFS_PEB_BLK_BMAP_SOURCE,
	SSDFS_PEB_BLK_BMAP_DESTINATION,
	SSDFS_PEB_BLK_BMAP_INDEX_MAX
};

/*
 * PEB block bitmap API
 */
int ssdfs_peb_blk_bmap_create(struct ssdfs_segment_blk_bmap *parent,
			      u16 peb_index, u32 items_count,
			      int init_flag, int init_state);
void ssdfs_peb_blk_bmap_destroy(struct ssdfs_peb_blk_bmap *ptr);
int ssdfs_peb_blk_bmap_init(struct ssdfs_peb_blk_bmap *bmap,
			    struct pagevec *source,
			    struct ssdfs_block_bitmap_fragment *hdr,
			    u64 cno);
void ssdfs_peb_blk_bmap_init_failed(struct ssdfs_peb_blk_bmap *bmap);

bool ssdfs_peb_blk_bmap_initialized(struct ssdfs_peb_blk_bmap *ptr);

int ssdfs_peb_blk_bmap_get_free_pages(struct ssdfs_peb_blk_bmap *ptr);
int ssdfs_peb_blk_bmap_get_used_pages(struct ssdfs_peb_blk_bmap *ptr);
int ssdfs_peb_blk_bmap_get_invalid_pages(struct ssdfs_peb_blk_bmap *ptr);

int ssdfs_peb_define_reserved_pages_per_log(struct ssdfs_peb_blk_bmap *bmap);
int ssdfs_peb_blk_bmap_reserve_metapages(struct ssdfs_peb_blk_bmap *bmap,
					 int bmap_index,
					 u16 count);
int ssdfs_peb_blk_bmap_free_metapages(struct ssdfs_peb_blk_bmap *bmap,
				      int bmap_index,
				      u16 count);
int ssdfs_peb_blk_bmap_pre_allocate(struct ssdfs_peb_blk_bmap *bmap,
				    int bmap_index,
				    u32 *len,
				    struct ssdfs_block_bmap_range *range);
int ssdfs_peb_blk_bmap_allocate(struct ssdfs_peb_blk_bmap *bmap,
				int bmap_index,
				u32 *len,
				struct ssdfs_block_bmap_range *range);
int ssdfs_peb_blk_bmap_invalidate(struct ssdfs_peb_blk_bmap *bmap,
				  int bmap_index,
				  struct ssdfs_block_bmap_range *range);
int ssdfs_peb_blk_bmap_update_range(struct ssdfs_peb_blk_bmap *bmap,
				    int bmap_index,
				    int new_range_state,
				    struct ssdfs_block_bmap_range *range);
int ssdfs_peb_blk_bmap_collect_garbage(struct ssdfs_peb_blk_bmap *bmap,
					u32 start, u32 max_len,
					int blk_state,
					struct ssdfs_block_bmap_range *range);
int ssdfs_peb_blk_bmap_start_migration(struct ssdfs_peb_blk_bmap *bmap);
int ssdfs_peb_blk_bmap_migrate(struct ssdfs_peb_blk_bmap *bmap,
				int new_range_state,
				struct ssdfs_block_bmap_range *range);
int ssdfs_peb_blk_bmap_finish_migration(struct ssdfs_peb_blk_bmap *bmap);

/*
 * PEB block bitmap internal API
 */
int ssdfs_src_blk_bmap_get_free_pages(struct ssdfs_peb_blk_bmap *ptr);
int ssdfs_src_blk_bmap_get_used_pages(struct ssdfs_peb_blk_bmap *ptr);
int ssdfs_src_blk_bmap_get_invalid_pages(struct ssdfs_peb_blk_bmap *ptr);
int ssdfs_dst_blk_bmap_get_free_pages(struct ssdfs_peb_blk_bmap *ptr);
int ssdfs_dst_blk_bmap_get_used_pages(struct ssdfs_peb_blk_bmap *ptr);
int ssdfs_dst_blk_bmap_get_invalid_pages(struct ssdfs_peb_blk_bmap *ptr);

#endif /* _SSDFS_PEB_BLOCK_BITMAP_H */
