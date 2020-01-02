//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/segment_bitmap.h - bitmap of segments declarations.
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

#ifndef _SSDFS_SEGMENT_BITMAP_H
#define _SSDFS_SEGMENT_BITMAP_H

#include "common_bitmap.h"
#include "request_queue.h"

/* Segment states */
enum {
	SSDFS_SEG_CLEAN			= 0x0,
	SSDFS_SEG_DATA_USING		= 0x1,
	SSDFS_SEG_LEAF_NODE_USING	= 0x2,
	SSDFS_SEG_HYBRID_NODE_USING	= 0x5,
	SSDFS_SEG_INDEX_NODE_USING	= 0x3,
	SSDFS_SEG_USED			= 0x7,
	SSDFS_SEG_PRE_DIRTY		= 0x6,
	SSDFS_SEG_DIRTY			= 0x4,
	SSDFS_SEG_BAD			= 0x8,
	SSDFS_SEG_RESERVED		= 0x9,
	SSDFS_SEG_STATE_MAX		= SSDFS_SEG_RESERVED + 1,
};

/* Segment state flags */
#define SSDFS_SEG_CLEAN_STATE_FLAG		(1 << 0)
#define SSDFS_SEG_DATA_USING_STATE_FLAG		(1 << 1)
#define SSDFS_SEG_LEAF_NODE_USING_STATE_FLAG	(1 << 2)
#define SSDFS_SEG_HYBRID_NODE_USING_STATE_FLAG	(1 << 3)
#define SSDFS_SEG_INDEX_NODE_USING_STATE_FLAG	(1 << 4)
#define SSDFS_SEG_USED_STATE_FLAG		(1 << 5)
#define SSDFS_SEG_PRE_DIRTY_STATE_FLAG		(1 << 6)
#define SSDFS_SEG_DIRTY_STATE_FLAG		(1 << 7)
#define SSDFS_SEG_BAD_STATE_FLAG		(1 << 8)
#define SSDFS_SEG_RESERVED_STATE_FLAG		(1 << 9)

/* Segment state masks */
#define SSDFS_SEG_CLEAN_USING_MASK \
	(SSDFS_SEG_CLEAN_STATE_FLAG | \
	 SSDFS_SEG_DATA_USING_STATE_FLAG | \
	 SSDFS_SEG_LEAF_NODE_USING_STATE_FLAG | \
	 SSDFS_SEG_HYBRID_NODE_USING_STATE_FLAG | \
	 SSDFS_SEG_INDEX_NODE_USING_STATE_FLAG)
#define SSDFS_SEG_USED_DIRTY_MASK \
	(SSDFS_SEG_USED_STATE_FLAG | \
	 SSDFS_SEG_PRE_DIRTY_STATE_FLAG | \
	 SSDFS_SEG_DIRTY_STATE_FLAG)
#define SSDFS_SEG_BAD_STATE_MASK \
	(SSDFS_SEG_BAD_STATE_FLAG)

#define SSDFS_SEG_STATE_BITS	4
#define SSDFS_SEG_STATE_MASK	0xF

/*
 * struct ssdfs_segbmap_fragment_desc - fragment descriptor
 * @state: fragment's state
 * @total_segs: total count of segments in fragment
 * @clean_or_using_segs: count of clean or using segments in fragment
 * @used_or_dirty_segs: count of used, pre-dirty, dirty or reserved segments
 * @bad_segs: count of bad segments in fragment
 * @init_end: wait of init ending
 * @flush_req1: main flush request
 * @flush_req2: backup flush request
 */
struct ssdfs_segbmap_fragment_desc {
	int state;
	u16 total_segs;
	u16 clean_or_using_segs;
	u16 used_or_dirty_segs;
	u16 bad_segs;
	struct completion init_end;
	struct ssdfs_segment_request flush_req1;
	struct ssdfs_segment_request flush_req2;
};

/* Fragment's state */
enum {
	SSDFS_SEGBMAP_FRAG_CREATED	= 0,
	SSDFS_SEGBMAP_FRAG_INIT_FAILED	= 1,
	SSDFS_SEGBMAP_FRAG_INITIALIZED	= 2,
	SSDFS_SEGBMAP_FRAG_DIRTY	= 3,
	SSDFS_SEGBMAP_FRAG_TOWRITE	= 4,
	SSDFS_SEGBMAP_FRAG_STATE_MAX	= 5,
};

/* Fragments bitmap types */
enum {
	SSDFS_SEGBMAP_CLEAN_USING_FBMAP,
	SSDFS_SEGBMAP_USED_DIRTY_FBMAP,
	SSDFS_SEGBMAP_BAD_FBMAP,
	SSDFS_SEGBMAP_MODIFICATION_FBMAP,
	SSDFS_SEGBMAP_FBMAP_TYPE_MAX,
};

/*
 * struct ssdfs_segment_bmap - segments bitmap
 * @resize_lock: lock for possible resize operation
 * @flags: bitmap flags
 * @bytes_count: count of bytes in the whole segment bitmap
 * @items_count: count of volume's segments
 * @fragments_count: count of fragments in the whole segment bitmap
 * @fragments_per_seg: segbmap's fragments per segment
 * @fragments_per_peb: segbmap's fragments per PEB
 * @fragment_size: size of fragment in bytes
 * @seg_numbers: array of segment bitmap's segment numbers
 * @segs_count: count of segment objects are used for segment bitmap
 * @segs: array of pointers on segment objects
 * @search_lock: lock for search and change state operations
 * @fbmap: array of fragment bitmaps
 * @desc_array: array of fragments' descriptors
 * @pages: memory pages of the whole segment bitmap
 * @fsi: pointer on shared file system object
 */
struct ssdfs_segment_bmap {
	struct rw_semaphore resize_lock;
	u16 flags;
	u32 bytes_count;
	u64 items_count;
	u16 fragments_count;
	u16 fragments_per_seg;
	u16 fragments_per_peb;
	u16 fragment_size;
#define SEGS_LIMIT1	SSDFS_SEGBMAP_SEGS
#define SEGS_LIMIT2	SSDFS_SEGBMAP_SEG_COPY_MAX
	u64 seg_numbers[SEGS_LIMIT1][SEGS_LIMIT2];
	u16 segs_count;
	struct ssdfs_segment_info *segs[SEGS_LIMIT1][SEGS_LIMIT2];

	struct rw_semaphore search_lock;
	unsigned long *fbmap[SSDFS_SEGBMAP_FBMAP_TYPE_MAX];
	struct ssdfs_segbmap_fragment_desc *desc_array;
	struct address_space pages;

	struct ssdfs_fs_info *fsi;
};

/*
 * Inline functions
 */
static inline
u32 SEG_BMAP_BYTES(u64 items_count)
{
	u64 bytes;

	bytes = items_count + SSDFS_ITEMS_PER_BYTE(SSDFS_SEG_STATE_BITS) - 1;
	bytes /= SSDFS_ITEMS_PER_BYTE(SSDFS_SEG_STATE_BITS);

	BUG_ON(bytes >= U32_MAX);

	return (u32)bytes;
}

static inline
u16 SEG_BMAP_FRAGMENTS(u64 items_count)
{
	u32 hdr_size = sizeof(struct ssdfs_segbmap_fragment_header);
	u32 bytes = SEG_BMAP_BYTES(items_count);
	u32 pages, fragments;

	pages = (bytes + PAGE_SIZE - 1) >> PAGE_SHIFT;
	bytes += pages * hdr_size;

	fragments = (bytes + PAGE_SIZE - 1) >> PAGE_SHIFT;
	BUG_ON(fragments >= U16_MAX);

	return (u16)fragments;
}

static inline
u16 ssdfs_segbmap_seg_2_fragment_index(u64 seg)
{
	u16 fragments_count = SEG_BMAP_FRAGMENTS(seg);

	BUG_ON(fragments_count == 0);
	return fragments_count - 1;
}

static inline
u32 ssdfs_segbmap_items_per_fragment(size_t fragment_size)
{
	u32 hdr_size = sizeof(struct ssdfs_segbmap_fragment_header);
	u32 payload_bytes;
	u64 items;

	BUG_ON(hdr_size >= fragment_size);

	payload_bytes = fragment_size - hdr_size;
	items = payload_bytes * SSDFS_ITEMS_PER_BYTE(SSDFS_SEG_STATE_BITS);

	BUG_ON(items >= U32_MAX);

	return (u32)items;
}

static inline
u64 ssdfs_segbmap_define_first_fragment_item(pgoff_t fragment_index,
					     size_t fragment_size)
{
	return fragment_index * ssdfs_segbmap_items_per_fragment(fragment_size);
}

static inline
u32 ssdfs_segbmap_get_item_byte_offset(u32 fragment_item)
{
	u32 hdr_size = sizeof(struct ssdfs_segbmap_fragment_header);
	u32 items_per_byte = SSDFS_ITEMS_PER_BYTE(SSDFS_SEG_STATE_BITS);
	return hdr_size + (fragment_item / items_per_byte);
}

static inline
int ssdfs_segbmap_seg_id_2_seg_index(struct ssdfs_segment_bmap *segbmap,
				     u64 seg_id)
{
	int i;

	if (seg_id == U64_MAX)
		return -ENODATA;

	for (i = 0; i < segbmap->segs_count; i++) {
		if (seg_id == segbmap->seg_numbers[i][SSDFS_MAIN_SEGBMAP_SEG])
			return i;
		if (seg_id == segbmap->seg_numbers[i][SSDFS_COPY_SEGBMAP_SEG])
			return i;
	}

	return -ENODATA;
}

static inline
bool ssdfs_segbmap_fragment_has_content(struct page *page)
{
	bool has_content = false;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("page %p\n", page);

	kaddr = kmap_atomic(page);
	if (memchr_inv(kaddr, 0xff, PAGE_SIZE) != NULL)
		has_content = true;
	kunmap_atomic(kaddr);

	return has_content;
}

static inline
void ssdfs_debug_segbmap_object(struct ssdfs_segment_bmap *bmap)
{
#ifdef CONFIG_SSDFS_DEBUG
	int i, j;
	size_t bytes;

	BUG_ON(!bmap);

	SSDFS_DBG("flags %#x, bytes_count %u, items_count %llu, "
		  "fragments_count %u, fragments_per_seg %u, "
		  "fragments_per_peb %u, fragment_size %u\n",
		  bmap->flags, bmap->bytes_count, bmap->items_count,
		  bmap->fragments_count, bmap->fragments_per_seg,
		  bmap->fragments_per_peb, bmap->fragment_size);

	for (i = 0; i < SSDFS_SEGBMAP_SEGS; i++) {
		for (j = 0; j < SSDFS_SEGBMAP_SEG_COPY_MAX; j++) {
			SSDFS_DBG("seg_numbers[%d][%d] = %llu\n",
				  i, j, bmap->seg_numbers[i][j]);
		}
	}

	SSDFS_DBG("segs_count %u\n", bmap->segs_count);

	for (i = 0; i < SSDFS_SEGBMAP_SEGS; i++) {
		for (j = 0; j < SSDFS_SEGBMAP_SEG_COPY_MAX; j++) {
			SSDFS_DBG("segs[%d][%d] = %p\n",
				  i, j, bmap->segs[i][j]);
		}
	}

	bytes = bmap->fragments_count + BITS_PER_LONG - 1;
	bytes /= BITS_PER_BYTE;

	for (i = 0; i < SSDFS_SEGBMAP_FBMAP_TYPE_MAX; i++) {
		SSDFS_DBG("fbmap[%d]\n", i);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					bmap->fbmap[i], bytes);
	}

	for (i = 0; i < bmap->fragments_count; i++) {
		struct ssdfs_segbmap_fragment_desc *desc;

		desc = &bmap->desc_array[i];

		SSDFS_DBG("state %#x, total_segs %u, "
			  "clean_or_using_segs %u, used_or_dirty_segs %u, "
			  "bad_segs %u\n",
			  desc->state, desc->total_segs,
			  desc->clean_or_using_segs,
			  desc->used_or_dirty_segs,
			  desc->bad_segs);
	}

	for (i = 0; i < bmap->fragments_count; i++) {
		struct page *page;
		void *kaddr;

		page = find_lock_page(&bmap->pages, i);

		SSDFS_DBG("page[%d] %p\n", i, page);
		if (!page)
			continue;

		SSDFS_DBG("page_index %llu, flags %#lx\n",
			  (u64)page_index(page), page->flags);

		kaddr = kmap_atomic(page);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					kaddr, PAGE_SIZE);
		kunmap_atomic(kaddr);

		unlock_page(page);
		put_page(page);
	}
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * Segment bitmap's API
 */
int ssdfs_segbmap_create(struct ssdfs_fs_info *fsi);
void ssdfs_segbmap_destroy(struct ssdfs_fs_info *fsi);
int ssdfs_segbmap_check_fragment_header(struct ssdfs_peb_container *pebc,
					u16 seg_index,
					u16 sequence_id,
					struct page *page);
int ssdfs_segbmap_fragment_init(struct ssdfs_peb_container *pebc,
				u16 sequence_id,
				struct page *page,
				int state);
int ssdfs_segbmap_flush(struct ssdfs_segment_bmap *segbmap);
int ssdfs_segbmap_resize(struct ssdfs_segment_bmap *segbmap,
			 u64 new_items_count);

int ssdfs_segbmap_check_state(struct ssdfs_segment_bmap *segbmap,
				u64 seg, int state,
				struct completion **end);
int ssdfs_segbmap_get_state(struct ssdfs_segment_bmap *segbmap,
			    u64 seg, struct completion **end);
int ssdfs_segbmap_change_state(struct ssdfs_segment_bmap *segbmap,
				u64 seg, int new_state,
				struct completion **end);
int ssdfs_segbmap_find(struct ssdfs_segment_bmap *segbmap,
			u64 start, u64 max,
			int state, int mask,
			u64 *seg, struct completion **end);
int ssdfs_segbmap_find_and_set(struct ssdfs_segment_bmap *segbmap,
				u64 start, u64 max,
				int state, int mask,
				int new_state,
				u64 *seg, struct completion **end);
int ssdfs_segbmap_reserve_clean_segment(struct ssdfs_segment_bmap *segbmap,
					u64 start, u64 max,
					u64 *seg, struct completion **end);

#endif /* _SSDFS_SEGMENT_BITMAP_H */
