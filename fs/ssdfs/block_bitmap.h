// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/block_bitmap.h - PEB's block bitmap declarations.
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

#ifndef _SSDFS_BLOCK_BITMAP_H
#define _SSDFS_BLOCK_BITMAP_H

#include "common_bitmap.h"

#define SSDFS_BLK_STATE_BITS	2
#define SSDFS_BLK_STATE_MASK	0x3

enum {
	SSDFS_BLK_FREE		= 0x0,
	SSDFS_BLK_PRE_ALLOCATED	= 0x1,
	SSDFS_BLK_VALID		= 0x3,
	SSDFS_BLK_INVALID	= 0x2,
	SSDFS_BLK_STATE_MAX	= SSDFS_BLK_VALID + 1,
};

#define SSDFS_FREE_STATES_BYTE		0x00
#define SSDFS_PRE_ALLOC_STATES_BYTE	0x55
#define SSDFS_VALID_STATES_BYTE		0xFF
#define SSDFS_INVALID_STATES_BYTE	0xAA

#define SSDFS_BLK_BMAP_BYTE(blk_state)({ \
	u8 value; \
	switch (blk_state) { \
	case SSDFS_BLK_FREE: \
		value = SSDFS_FREE_STATES_BYTE; \
		break; \
	case SSDFS_BLK_PRE_ALLOCATED: \
		value = SSDFS_PRE_ALLOC_STATES_BYTE; \
		break; \
	case SSDFS_BLK_VALID: \
		value = SSDFS_VALID_STATES_BYTE; \
		break; \
	case SSDFS_BLK_INVALID: \
		value = SSDFS_INVALID_STATES_BYTE; \
		break; \
	default: \
		BUG(); \
	}; \
	value; \
})

#define BLK_BMAP_BYTES(items_count) \
	((items_count + SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS) - 1)  / \
	 SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS))

static inline
int SSDFS_BLK2FOLIO(u32 blk, u8 item_bits, u16 *offset)
{
	u32 blks_per_byte = SSDFS_ITEMS_PER_BYTE(item_bits);
	u32 blks_per_long = SSDFS_ITEMS_PER_LONG(item_bits);
	u32 blks_per_folio = PAGE_SIZE * blks_per_byte;
	u32 off;

	if (offset) {
		off = (blk % blks_per_folio) / blks_per_long;
		off *= sizeof(unsigned long);
		BUG_ON(off >= U16_MAX);
		*offset = off;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("blk %u, item_bits %u, blks_per_byte %u, "
		  "blks_per_long %u, blks_per_folio %u, "
		  "folio_index %u\n",
		  blk, item_bits, blks_per_byte,
		  blks_per_long, blks_per_folio,
		  blk / blks_per_folio);
#endif /* CONFIG_SSDFS_DEBUG */

	return blk / blks_per_folio;
}

/*
 * struct ssdfs_last_bmap_search - last search in bitmap
 * @folio_index: index of folio in folio vector
 * @offset: offset of cache from page's begining
 * @cache: cached bmap's part
 */
struct ssdfs_last_bmap_search {
	int folio_index;
	u16 offset;
	unsigned long cache;
};

static inline
u32 SSDFS_FIRST_CACHED_BLOCK(struct ssdfs_last_bmap_search *search)
{
	u32 blks_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_BLK_STATE_BITS);
	u32 blks_per_folio = PAGE_SIZE * blks_per_byte;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio_index %d, offset %u, "
		  "blks_per_byte %u, blks_per_folio %u\n",
		  search->folio_index,
		  search->offset,
		  blks_per_byte, blks_per_folio);
#endif /* CONFIG_SSDFS_DEBUG */

	return (search->folio_index * blks_per_folio) +
		(search->offset * blks_per_byte);
}

enum {
	SSDFS_FREE_BLK_SEARCH,
	SSDFS_VALID_BLK_SEARCH,
	SSDFS_OTHER_BLK_SEARCH,
	SSDFS_SEARCH_TYPE_MAX,
};

static inline
int SSDFS_GET_CACHE_TYPE(int blk_state)
{
	switch (blk_state) {
	case SSDFS_BLK_FREE:
		return SSDFS_FREE_BLK_SEARCH;

	case SSDFS_BLK_VALID:
		return SSDFS_VALID_BLK_SEARCH;

	case SSDFS_BLK_PRE_ALLOCATED:
	case SSDFS_BLK_INVALID:
		return SSDFS_OTHER_BLK_SEARCH;
	};

	return SSDFS_SEARCH_TYPE_MAX;
}

#define SSDFS_BLK_BMAP_INITIALIZED	(1 << 0)
#define SSDFS_BLK_BMAP_DIRTY		(1 << 1)

/*
 * struct ssdfs_block_bmap_storage - block bitmap's storage
 * @state: storage state
 * @array: vector of folios
 * @buf: pointer on memory buffer
 */
struct ssdfs_block_bmap_storage {
	int state;
	struct ssdfs_folio_vector array;
	void *buf;
};

/* Block bitmap's storage's states */
enum {
	SSDFS_BLOCK_BMAP_STORAGE_ABSENT,
	SSDFS_BLOCK_BMAP_STORAGE_FOLIO_VEC,
	SSDFS_BLOCK_BMAP_STORAGE_BUFFER,
	SSDFS_BLOCK_BMAP_STORAGE_STATE_MAX
};

/*
 * struct ssdfs_block_bmap - in-core segment's block bitmap
 * @lock: block bitmap lock
 * @flags: block bitmap state flags
 * @storage: block bitmap's storage
 * @bytes_count: block bitmap size in bytes
 * @items_count: items count in bitmap
 * @metadata_items: count of metadata items
 * @used_blks: count of valid blocks
 * @invalid_blks: count of invalid blocks
 * @last_search: last search/access cache array
 */
struct ssdfs_block_bmap {
	struct mutex lock;
	atomic_t flags;
	struct ssdfs_block_bmap_storage storage;
	size_t bytes_count;
	size_t items_count;
	u32 metadata_items;
	u32 used_blks;
	u32 invalid_blks;
	struct ssdfs_last_bmap_search last_search[SSDFS_SEARCH_TYPE_MAX];
};

/*
 * compare_block_bmap_ranges() - compare two ranges
 * @range1: left range
 * @range2: right range
 *
 * RETURN:
 *  0: range1 == range2
 * -1: range1 < range2
 *  1: range1 > range2
 */
static inline
int compare_block_bmap_ranges(struct ssdfs_block_bmap_range *range1,
				struct ssdfs_block_bmap_range *range2)
{
	u32 range1_end, range2_end;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!range1 || !range2);

	SSDFS_DBG("range1 (start %u, len %u), range2 (start %u, len %u)\n",
		  range1->start, range1->len, range2->start, range2->len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (range1->start == range2->start) {
		if (range1->len == range2->len)
			return 0;
		else if (range1->len < range2->len)
			return -1;
		else
			return 1;
	} else if (range1->start < range2->start) {
		range1_end = range1->start + range1->len;
		range2_end = range2->start + range2->len;

		if (range2_end <= range1_end)
			return 1;
		else
			return -1;
	}

	/* range1->start > range2->start */
	return -1;
}

/*
 * ranges_have_intersection() - have ranges intersection?
 * @range1: left range
 * @range2: right range
 *
 * RETURN:
 * [true]  - ranges have intersection
 * [false] - ranges doesn't intersect
 */
static inline
bool ranges_have_intersection(struct ssdfs_block_bmap_range *range1,
				struct ssdfs_block_bmap_range *range2)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!range1 || !range2);

	SSDFS_DBG("range1 (start %u, len %u), range2 (start %u, len %u)\n",
		  range1->start, range1->len, range2->start, range2->len);
#endif /* CONFIG_SSDFS_DEBUG */

	if ((range2->start + range2->len) <= range1->start)
		return false;
	else if ((range1->start + range1->len) <= range2->start)
		return false;

	return true;
}

enum {
	SSDFS_BLK_BMAP_CREATE,
	SSDFS_BLK_BMAP_INIT,
};

/* Function prototypes */
int ssdfs_block_bmap_create(struct ssdfs_fs_info *fsi,
			    struct ssdfs_block_bmap *bmap,
			    u32 items_count,
			    int flag, int init_state);
void ssdfs_block_bmap_destroy(struct ssdfs_block_bmap *blk_bmap);
int ssdfs_block_bmap_init(struct ssdfs_block_bmap *blk_bmap,
			  struct ssdfs_page_vector *source,
			  u32 last_free_blk,
			  u32 metadata_blks,
			  u32 invalid_blks);
int ssdfs_block_bmap_snapshot(struct ssdfs_block_bmap *blk_bmap,
				struct ssdfs_page_vector *snapshot,
				u32 *last_free_page,
				u32 *metadata_blks,
				u32 *invalid_blks,
				size_t *bytes_count);
void ssdfs_block_bmap_forget_snapshot(struct ssdfs_page_vector *snapshot);

int ssdfs_block_bmap_lock(struct ssdfs_block_bmap *blk_bmap);
bool ssdfs_block_bmap_is_locked(struct ssdfs_block_bmap *blk_bmap);
void ssdfs_block_bmap_unlock(struct ssdfs_block_bmap *blk_bmap);

bool ssdfs_block_bmap_dirtied(struct ssdfs_block_bmap *blk_bmap);
void ssdfs_block_bmap_clear_dirty_state(struct ssdfs_block_bmap *blk_bmap);
bool ssdfs_block_bmap_initialized(struct ssdfs_block_bmap *blk_bmap);
void ssdfs_set_block_bmap_initialized(struct ssdfs_block_bmap *blk_bmap);

bool ssdfs_block_bmap_test_block(struct ssdfs_block_bmap *blk_bmap,
				 u32 blk, int blk_state);
bool ssdfs_block_bmap_test_range(struct ssdfs_block_bmap *blk_bmap,
				 struct ssdfs_block_bmap_range *range,
				 int blk_state);
int ssdfs_get_block_state(struct ssdfs_block_bmap *blk_bmap, u32 blk);
int ssdfs_get_range_state(struct ssdfs_block_bmap *blk_bmap,
			  struct ssdfs_block_bmap_range *range);
int ssdfs_block_bmap_reserve_metadata_pages(struct ssdfs_block_bmap *blk_bmap,
					    u32 count);
int ssdfs_block_bmap_free_metadata_pages(struct ssdfs_block_bmap *blk_bmap,
					 u32 count, u32 *freed_items);
int ssdfs_block_bmap_get_free_pages(struct ssdfs_block_bmap *blk_bmap);
int ssdfs_block_bmap_get_used_pages(struct ssdfs_block_bmap *blk_bmap);
int ssdfs_block_bmap_get_invalid_pages(struct ssdfs_block_bmap *blk_bmap);
int ssdfs_block_bmap_pre_allocate(struct ssdfs_block_bmap *blk_bmap,
				  u32 start, u32 *len,
				  struct ssdfs_block_bmap_range *range);
int ssdfs_block_bmap_allocate(struct ssdfs_block_bmap *blk_bmap,
				u32 start, u32 *len,
				struct ssdfs_block_bmap_range *range);
int ssdfs_block_bmap_invalidate(struct ssdfs_block_bmap *blk_bmap,
				struct ssdfs_block_bmap_range *range);
int ssdfs_block_bmap_collect_garbage(struct ssdfs_block_bmap *blk_bmap,
				     u32 start, u32 max_len,
				     int blk_state,
				     struct ssdfs_block_bmap_range *range);
int ssdfs_block_bmap_clean(struct ssdfs_block_bmap *blk_bmap);

#define SSDFS_BLK_BMAP_FNS(state, name)					\
static inline								\
bool is_block_##name(struct ssdfs_block_bmap *blk_bmap, u32 blk)	\
{									\
	return ssdfs_block_bmap_test_block(blk_bmap, blk,		\
					    SSDFS_BLK_##state);		\
}									\
static inline								\
bool is_range_##name(struct ssdfs_block_bmap *blk_bmap,			\
			struct ssdfs_block_bmap_range *range)		\
{									\
	return ssdfs_block_bmap_test_range(blk_bmap, range,		\
					    SSDFS_BLK_##state);		\
}									\

/*
 * is_block_free()
 * is_range_free()
 */
SSDFS_BLK_BMAP_FNS(FREE, free)

/*
 * is_block_pre_allocated()
 * is_range_pre_allocated()
 */
SSDFS_BLK_BMAP_FNS(PRE_ALLOCATED, pre_allocated)

/*
 * is_block_valid()
 * is_range_valid()
 */
SSDFS_BLK_BMAP_FNS(VALID, valid)

/*
 * is_block_invalid()
 * is_range_invalid()
 */
SSDFS_BLK_BMAP_FNS(INVALID, invalid)

#endif /* _SSDFS_BLOCK_BITMAP_H */
