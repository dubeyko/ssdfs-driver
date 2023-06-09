// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_flush_thread.c - flush thread functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * Copyright (c) 2022-2023 Bytedance Ltd. and/or its affiliates.
 *              https://www.bytedance.com/
 *
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot
 *                  Zvonimir Bandic
 *                  Cong Wang
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>
#include <linux/delay.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "ssdfs.h"
#include "compression.h"
#include "block_bitmap.h"
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "page_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "current_segment.h"
#include "peb_mapping_table.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "extents_tree.h"
#include "diff_on_write.h"
#include "invalidated_extents_tree.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_flush_page_leaks;
atomic64_t ssdfs_flush_memory_leaks;
atomic64_t ssdfs_flush_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_flush_cache_leaks_increment(void *kaddr)
 * void ssdfs_flush_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_flush_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_flush_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_flush_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_flush_kfree(void *kaddr)
 * struct page *ssdfs_flush_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_flush_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_flush_free_page(struct page *page)
 * void ssdfs_flush_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(flush)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(flush)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_flush_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_flush_page_leaks, 0);
	atomic64_set(&ssdfs_flush_memory_leaks, 0);
	atomic64_set(&ssdfs_flush_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_flush_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_flush_page_leaks) != 0) {
		SSDFS_ERR("FLUSH THREAD: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_flush_page_leaks));
	}

	if (atomic64_read(&ssdfs_flush_memory_leaks) != 0) {
		SSDFS_ERR("FLUSH THREAD: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_flush_memory_leaks));
	}

	if (atomic64_read(&ssdfs_flush_cache_leaks) != 0) {
		SSDFS_ERR("FLUSH THREAD: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_flush_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * struct ssdfs_fragment_source - fragment source descriptor
 * @page: memory page that contains uncompressed fragment
 * @start_offset: offset into page to fragment's begin
 * @data_bytes: size of fragment in bytes
 * @sequence_id: fragment's sequence number
 * @fragment_type: fragment type
 * @fragment_flags: fragment's flags
 */
struct ssdfs_fragment_source {
	struct page *page;
	u32 start_offset;
	size_t data_bytes;
	u8 sequence_id;
	u8 fragment_type;
	u8 fragment_flags;
};

/*
 * struct ssdfs_fragment_destination - fragment destination descriptor
 * @area_offset: offset of area from log's beginning
 * @write_offset: offset of @store pointer from area's begin
 * @store: pointer for storing fragment
 * @free_space: available space in bytes for fragment storing [in|out]
 * @compr_size: size of fragment in bytes after compression [out]
 * @desc: fragment descriptor [out]
 */
struct ssdfs_fragment_destination {
	u32 area_offset;
	u32 write_offset;
	unsigned char *store;
	size_t free_space;
	size_t compr_size;
	struct ssdfs_fragment_desc *desc;
};

/*
 * struct ssdfs_byte_stream_descriptor - byte stream descriptor
 * @pvec: pagevec that contains byte stream
 * @start_offset: offset in bytes of byte stream in pagevec
 * @data_bytes: size of uncompressed byte stream
 * @write_offset: write offset of byte stream in area [out]
 * @compr_bytes: size of byte stream after compression [out]
 */
struct ssdfs_byte_stream_descriptor {
	struct pagevec *pvec;
	u32 start_offset;
	u32 data_bytes;
	u32 write_offset;
	u32 compr_bytes;
};

/*
 * struct ssdfs_bmap_descriptor - block bitmap flush descriptor
 * @pebi: pointer on PEB object
 * @snapshot: block bitmap snapshot
 * @peb_index: PEB index of bitmap owner
 * @flags: fragment flags
 * @type: fragment type
 * @compression_type: type of compression
 * @last_free_blk: last logical free block
 * @metadata_blks: count of physical pages are used by metadata
 * @invalid_blks: count of invalid blocks
 * @frag_id: pointer on fragment counter
 * @log_offset: pointer on current log offset
 */
struct ssdfs_bmap_descriptor {
	struct ssdfs_peb_info *pebi;
	struct ssdfs_page_vector *snapshot;
	u16 peb_index;
	u8 flags;
	u8 type;
	u8 compression_type;
	u32 last_free_blk;
	u32 metadata_blks;
	u32 invalid_blks;
	size_t bytes_count;
	u8 *frag_id;
	struct ssdfs_peb_log_offset *log_offset;
};

/*
 * struct ssdfs_pagevec_descriptor - pagevec descriptor
 * @pebi: pointer on PEB object
 * @page_vec: pagevec with saving data
 * @start_sequence_id: start sequence id
 * @area_offset: offset of area
 * @bytes_count: size in bytes of valid data in pagevec
 * @desc_array: array of fragment descriptors
 * @array_capacity: capacity of fragment descriptors' array
 * @compression_type: type of compression
 * @compr_size: whole size of all compressed fragments [out]
 * @uncompr_size: whole size of all fragments in uncompressed state [out]
 * @fragments_count: count of saved fragments
 * @log_offset: pointer on current log offset
 */
struct ssdfs_pagevec_descriptor {
	struct ssdfs_peb_info *pebi;
	struct ssdfs_page_vector *page_vec;
	u16 start_sequence_id;
	u32 area_offset;
	size_t bytes_count;
	struct ssdfs_fragment_desc *desc_array;
	size_t array_capacity;
	u8 compression_type;
	u32 compr_size;
	u32 uncompr_size;
	u16 fragments_count;
	struct ssdfs_peb_log_offset *log_offset;
};

/******************************************************************************
 *                         FLUSH THREAD FUNCTIONALITY                         *
 ******************************************************************************/

/*
 * __ssdfs_peb_estimate_blk_bmap_bytes() - estimate block bitmap's bytes
 * @bits_count: bits count in bitmap
 * @is_migrating: is PEB migrating?
 */
static inline
int __ssdfs_peb_estimate_blk_bmap_bytes(u32 bits_count, bool is_migrating)
{
	size_t blk_bmap_hdr_size = sizeof(struct ssdfs_block_bitmap_header);
	size_t blk_bmap_frag_hdr_size = sizeof(struct ssdfs_block_bitmap_fragment);
	size_t frag_desc_size = sizeof(struct ssdfs_fragment_desc);
	size_t blk_bmap_bytes;
	int reserved_bytes = 0;

	blk_bmap_bytes = BLK_BMAP_BYTES(bits_count);

	reserved_bytes += blk_bmap_hdr_size;

	if (is_migrating) {
		reserved_bytes += 2 * blk_bmap_frag_hdr_size;
		reserved_bytes += 2 * frag_desc_size;
		reserved_bytes += 2 * blk_bmap_bytes;
	} else {
		reserved_bytes += blk_bmap_frag_hdr_size;
		reserved_bytes += frag_desc_size;
		reserved_bytes += blk_bmap_bytes;
	}

	return reserved_bytes;
}

/*
 * ssdfs_peb_estimate_blk_bmap_bytes() - estimate block bitmap's bytes
 * @pages_per_peb: number of pages in one PEB
 * @is_migrating: is PEB migrating?
 * @prev_log_bmap_bytes: bytes count in block bitmap of previous log
 */
static inline
int ssdfs_peb_estimate_blk_bmap_bytes(u32 pages_per_peb, bool is_migrating,
				      u32 prev_log_bmap_bytes)
{
	int reserved_bytes = 0;

	reserved_bytes = __ssdfs_peb_estimate_blk_bmap_bytes(pages_per_peb,
							     is_migrating);

	if (prev_log_bmap_bytes < S32_MAX) {
		reserved_bytes = min_t(int, reserved_bytes,
					(int)(prev_log_bmap_bytes * 2));
	}

	return reserved_bytes;
}

/*
 * __ssdfs_peb_estimate_blk2off_bytes() - estimate blk2off table's bytes
 * @items_number: number of allocated logical blocks
 * @pebs_per_seg: number of PEBs in one segment
 */
static inline
int __ssdfs_peb_estimate_blk2off_bytes(u32 items_number, u32 pebs_per_seg)
{
	size_t blk2off_tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	size_t pot_tbl_hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	size_t phys_off_desc_size = sizeof(struct ssdfs_phys_offset_descriptor);
	int reserved_bytes = 0;

	reserved_bytes += blk2off_tbl_hdr_size;
	reserved_bytes += pot_tbl_hdr_size;
	reserved_bytes += (phys_off_desc_size * items_number) * pebs_per_seg;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_number %u, pebs_per_seg %u, "
		  "reserved_bytes %d\n",
		  items_number, pebs_per_seg, reserved_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return reserved_bytes;
}

/*
 * ssdfs_peb_estimate_blk2off_bytes() - estimate blk2off table's bytes
 * @log_pages: number of pages in the full log
 * @pebs_per_seg: number of PEBs in one segment
 * @log_start_page: start page of the log
 * @pages_per_peb: number of pages per PEB
 */
static inline
int ssdfs_peb_estimate_blk2off_bytes(u16 log_pages, u32 pebs_per_seg,
				     u16 log_start_page, u32 pages_per_peb)
{
	u32 items_number;

	items_number = min_t(u32, log_pages - (log_start_page % log_pages),
				pages_per_peb - log_start_page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_number %u, log_pages %u, "
		  "pages_per_peb %u, log_start_page %u\n",
		  items_number, log_pages,
		  pages_per_peb, log_start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	return __ssdfs_peb_estimate_blk2off_bytes(items_number, pebs_per_seg);
}

/*
 * __ssdfs_peb_estimate_blk_desc_tbl_bytes() - estimate block desc table's bytes
 * @items_number: number of allocated logical blocks
 */
static inline
int __ssdfs_peb_estimate_blk_desc_tbl_bytes(u32 items_number)
{
	size_t blk_desc_tbl_hdr_size = sizeof(struct ssdfs_area_block_table);
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	int reserved_bytes = 0;

	reserved_bytes += blk_desc_tbl_hdr_size;
	reserved_bytes += blk_desc_size * items_number;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("items_number %u, reserved_bytes %d\n",
		  items_number, reserved_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return reserved_bytes;
}

/*
 * ssdfs_peb_estimate_blk_desc_tbl_bytes() - estimate block desc table's bytes
 * @log_pages: number of pages in the full log
 * @log_start_page: start page of the log
 * @pages_per_peb: number of pages per PEB
 */
static inline
int ssdfs_peb_estimate_blk_desc_tbl_bytes(u16 log_pages,
					  u16 log_start_page,
					  u32 pages_per_peb)
{
	u32 items_number;
	int reserved_bytes = 0;

	items_number = min_t(u32,
				log_pages - (log_start_page % log_pages),
				pages_per_peb - log_start_page);

	reserved_bytes = __ssdfs_peb_estimate_blk_desc_tbl_bytes(items_number);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("log_pages %u, log_start_page %u, "
		  "pages_per_peb %u, items_number %u, "
		  "reserved_bytes %d\n",
		  log_pages, log_start_page,
		  pages_per_peb, items_number,
		  reserved_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return reserved_bytes;
}

/*
 * ssdfs_peb_estimate_reserved_metapages() - estimate reserved metapages in log
 * @page_size: size of page in bytes
 * @pages_per_peb: number of pages in one PEB
 * @log_pages: number of pages in the full log
 * @pebs_per_seg: number of PEBs in one segment
 * @is_migrating: is PEB migrating?
 */
u16 ssdfs_peb_estimate_reserved_metapages(u32 page_size, u32 pages_per_peb,
					  u16 log_pages, u32 pebs_per_seg,
					  bool is_migrating)
{
	size_t seg_hdr_size = sizeof(struct ssdfs_segment_header);
	size_t lf_hdr_size = sizeof(struct ssdfs_log_footer);
	u32 reserved_bytes = 0;
	u32 reserved_pages = 0;

	/* segment header */
	reserved_bytes += seg_hdr_size;

	/* block bitmap */
	reserved_bytes += ssdfs_peb_estimate_blk_bmap_bytes(pages_per_peb,
							    is_migrating,
							    U32_MAX);

	/* blk2off table */
	reserved_bytes += ssdfs_peb_estimate_blk2off_bytes(log_pages,
							   pebs_per_seg,
							   0, pages_per_peb);

	/* block descriptor table */
	reserved_bytes += ssdfs_peb_estimate_blk_desc_tbl_bytes(log_pages, 0,
								pages_per_peb);

	reserved_bytes += page_size - 1;
	reserved_bytes /= page_size;
	reserved_bytes *= page_size;

	/* log footer header */
	reserved_bytes += lf_hdr_size;

	/* block bitmap */
	reserved_bytes += ssdfs_peb_estimate_blk_bmap_bytes(pages_per_peb,
							    is_migrating,
							    U32_MAX);

	/* blk2off table */
	reserved_bytes += ssdfs_peb_estimate_blk2off_bytes(log_pages,
							   pebs_per_seg,
							   0, pages_per_peb);

	reserved_bytes += page_size - 1;
	reserved_bytes /= page_size;
	reserved_bytes *= page_size;

	reserved_pages = reserved_bytes / page_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_bytes %u, reserved_pages %u\n",
		  reserved_bytes, reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	BUG_ON(reserved_pages >= U16_MAX);

	return reserved_pages;
}

/*
 * ssdfs_peb_blk_bmap_reserved_bytes() - calculate block bitmap's reserved bytes
 * @pebi: pointer on PEB object
 */
static inline
int ssdfs_peb_blk_bmap_reserved_bytes(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_peb_container *pebc = pebi->pebc;
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	u32 pages_per_peb = fsi->pages_per_peb;
	bool is_migrating = false;
	u32 prev_log_bmap_bytes;

	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
	case SSDFS_PEB_UNDER_MIGRATION:
		is_migrating = true;
		break;

	default:
		is_migrating = false;
		break;
	}

	prev_log_bmap_bytes = pebi->current_log.prev_log_bmap_bytes;

	return ssdfs_peb_estimate_blk_bmap_bytes(pages_per_peb, is_migrating,
						 prev_log_bmap_bytes);
}

/*
 * ssdfs_peb_blk2off_reserved_bytes() - calculate blk2off table's reserved bytes
 * @pebi: pointer on PEB object
 */
static inline
int ssdfs_peb_blk2off_reserved_bytes(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_peb_container *pebc = pebi->pebc;
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	u32 pebs_per_seg = fsi->pebs_per_seg;
	u16 log_pages = pebi->log_pages;
	u32 pages_per_peb = fsi->pages_per_peb;
	u16 log_start_page = pebi->current_log.start_page;

	return ssdfs_peb_estimate_blk2off_bytes(log_pages, pebs_per_seg,
						log_start_page, pages_per_peb);
}

/*
 * ssdfs_peb_blk_desc_tbl_reserved_bytes() - calculate block desc reserved bytes
 * @pebi: pointer on PEB object
 */
static inline
int ssdfs_peb_blk_desc_tbl_reserved_bytes(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_peb_container *pebc = pebi->pebc;
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	u16 log_pages = pebi->log_pages;
	u32 pages_per_peb = fsi->pages_per_peb;
	u16 log_start_page = pebi->current_log.start_page;

	return ssdfs_peb_estimate_blk_desc_tbl_bytes(log_pages,
						     log_start_page,
						     pages_per_peb);
}

/*
 * ssdfs_peb_log_footer_reserved_bytes() - calculate log footer's reserved bytes
 * @pebi: pointer on PEB object
 */
static inline
u32 ssdfs_peb_log_footer_reserved_bytes(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_peb_container *pebc = pebi->pebc;
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	size_t lf_hdr_size = sizeof(struct ssdfs_log_footer);
	u32 page_size = fsi->pagesize;
	u32 reserved_bytes = 0;

	/* log footer header */
	reserved_bytes = lf_hdr_size;

	/* block bitmap */
	reserved_bytes += atomic_read(&pebi->reserved_bytes.blk_bmap);

	/* blk2off table */
	reserved_bytes += atomic_read(&pebi->reserved_bytes.blk2off_tbl);

	reserved_bytes += page_size - 1;
	reserved_bytes /= page_size;
	reserved_bytes *= page_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("block_bitmap %d, blk2off_table %d, "
		  "reserved_bytes %u\n",
		  atomic_read(&pebi->reserved_bytes.blk_bmap),
		  atomic_read(&pebi->reserved_bytes.blk2off_tbl),
		  reserved_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return reserved_bytes;
}

/*
 * ssdfs_peb_log_footer_metapages() - calculate log footer's metadata pages
 * @pebi: pointer on PEB object
 */
static inline
u32 ssdfs_peb_log_footer_metapages(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_peb_container *pebc = pebi->pebc;
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	u32 page_size = fsi->pagesize;
	u32 reserved_pages = 0;

	reserved_pages = ssdfs_peb_log_footer_reserved_bytes(pebi) / page_size;

	BUG_ON(reserved_pages >= U16_MAX);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_pages %u\n", reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	return reserved_pages;
}

/*
 * ssdfs_peb_define_reserved_metapages() - calculate reserved metadata pages
 * @pebi: pointer on PEB object
 */
static
u16 ssdfs_peb_define_reserved_metapages(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_peb_container *pebc = pebi->pebc;
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	u32 reserved_bytes = 0;
	u32 reserved_pages = 0;
	size_t seg_hdr_size = sizeof(struct ssdfs_segment_header);
	u32 page_size = fsi->pagesize;
	u32 offset;
	u32 blk_desc_reserved;

	/* segment header */
	reserved_bytes += seg_hdr_size;

	/* block bitmap */
	atomic_set(&pebi->reserved_bytes.blk_bmap,
		   ssdfs_peb_blk_bmap_reserved_bytes(pebi));
	reserved_bytes += atomic_read(&pebi->reserved_bytes.blk_bmap);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebi->reserved_bytes.blk_bmap %d\n",
		  atomic_read(&pebi->reserved_bytes.blk_bmap));
#endif /* CONFIG_SSDFS_DEBUG */

	/* blk2off table */
	atomic_set(&pebi->reserved_bytes.blk2off_tbl,
		   ssdfs_peb_blk2off_reserved_bytes(pebi));
	reserved_bytes += atomic_read(&pebi->reserved_bytes.blk2off_tbl);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebi->reserved_bytes.blk2off_tbl %d\n",
		  atomic_read(&pebi->reserved_bytes.blk2off_tbl));
#endif /* CONFIG_SSDFS_DEBUG */

	/* block descriptor table */
	offset = reserved_bytes;
	blk_desc_reserved = ssdfs_peb_blk_desc_tbl_reserved_bytes(pebi);
	atomic_set(&pebi->reserved_bytes.blk_desc_tbl, blk_desc_reserved);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebi->reserved_bytes.blk_desc_tbl %d\n",
		  atomic_read(&pebi->reserved_bytes.blk_desc_tbl));
#endif /* CONFIG_SSDFS_DEBUG */

	reserved_bytes += atomic_read(&pebi->reserved_bytes.blk_desc_tbl);

	reserved_bytes += page_size - 1;
	reserved_bytes /= page_size;
	reserved_bytes *= page_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_bytes %u, offset %u\n",
		  reserved_bytes, offset);
#endif /* CONFIG_SSDFS_DEBUG */

	reserved_bytes += ssdfs_peb_log_footer_reserved_bytes(pebi);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_bytes %u\n", reserved_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	reserved_pages = reserved_bytes / page_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_pages %u\n", reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	BUG_ON(reserved_pages >= U16_MAX);

	return reserved_pages;
}

/*
 * ssdfs_peb_reserve_blk_desc_space() - reserve space for block descriptors
 * @pebi: pointer on PEB object
 * @metadata: pointer on area's metadata
 *
 * This function tries to reserve space for block descriptors.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate the memory.
 */
static
int ssdfs_peb_reserve_blk_desc_space(struct ssdfs_peb_info *pebi,
				     struct ssdfs_peb_area_metadata *metadata)
{
	struct ssdfs_page_array *area_pages;
	size_t blk_desc_tbl_hdr_size = sizeof(struct ssdfs_area_block_table);
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	size_t count;
	int buf_size;
	struct page *page;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb %llu, current_log.start_page %u\n",
		  pebi->peb_id, pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	buf_size = atomic_read(&pebi->reserved_bytes.blk_desc_tbl);

	if (buf_size <= blk_desc_tbl_hdr_size) {
		SSDFS_ERR("invalid reserved_size %d\n",
			  atomic_read(&pebi->reserved_bytes.blk_desc_tbl));
		return -ERANGE;
	}

	buf_size -= blk_desc_tbl_hdr_size;

	if (buf_size < blk_desc_size) {
		SSDFS_ERR("invalid reserved_size %d\n",
			  buf_size);
		return -ERANGE;
	}

	count = buf_size / blk_desc_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("buf_size %d, blk_desc_size %zu, count %zu\n",
		  buf_size, blk_desc_size, count);
#endif /* CONFIG_SSDFS_DEBUG */

	area_pages = &pebi->current_log.area[SSDFS_LOG_BLK_DESC_AREA].array;

	page = ssdfs_page_array_grab_page(area_pages, 0);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to add page into area space\n");
		return -ENOMEM;
	}

	ssdfs_memzero_page(page, 0, PAGE_SIZE, PAGE_SIZE);

	ssdfs_set_page_private(page, 0);
	ssdfs_put_page(page);
	ssdfs_unlock_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	metadata->area.blk_desc.items_count = 0;
	metadata->area.blk_desc.capacity = count;

	return 0;
}

/*
 * ssdfs_peb_estimate_min_partial_log_pages() - estimate min partial log size
 * @pebi: pointer on PEB object
 */
u16 ssdfs_peb_estimate_min_partial_log_pages(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_peb_container *pebc = pebi->pebc;
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	u32 reserved_bytes = 0;
	u32 reserved_pages = 0;
	size_t pl_hdr_size = sizeof(struct ssdfs_partial_log_header);
	u32 page_size = fsi->pagesize;
	size_t lf_hdr_size = sizeof(struct ssdfs_log_footer);

	/* partial log header */
	reserved_bytes += pl_hdr_size;

	/* block bitmap */
	reserved_bytes += ssdfs_peb_blk_bmap_reserved_bytes(pebi);

	/* blk2off table */
	reserved_bytes += ssdfs_peb_blk2off_reserved_bytes(pebi);

	/* block descriptor table */
	reserved_bytes += ssdfs_peb_blk_desc_tbl_reserved_bytes(pebi);

	reserved_bytes += page_size - 1;
	reserved_bytes /= page_size;
	reserved_bytes *= page_size;

	/* log footer header */
	reserved_bytes += lf_hdr_size;

	/* block bitmap */
	reserved_bytes += ssdfs_peb_blk_bmap_reserved_bytes(pebi);

	/* blk2off table */
	reserved_bytes += ssdfs_peb_blk2off_reserved_bytes(pebi);

	reserved_bytes += page_size - 1;
	reserved_bytes /= page_size;
	reserved_bytes *= page_size;

	reserved_pages = reserved_bytes / page_size;

	BUG_ON(reserved_pages >= U16_MAX);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_pages %u, reserved_bytes %u, "
		  "blk_bmap_reserved_bytes %d, "
		  "blk2off_reserved_bytes %d, "
		  "blk_desc_tbl_reserved_bytes %d\n",
		  reserved_pages, reserved_bytes,
		  ssdfs_peb_blk_bmap_reserved_bytes(pebi),
		  ssdfs_peb_blk2off_reserved_bytes(pebi),
		  ssdfs_peb_blk_desc_tbl_reserved_bytes(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	return reserved_pages;
}

enum {
	SSDFS_START_FULL_LOG,
	SSDFS_START_PARTIAL_LOG,
	SSDFS_CONTINUE_PARTIAL_LOG,
	SSDFS_FINISH_PARTIAL_LOG,
	SSDFS_FINISH_FULL_LOG
};

/*
 * is_log_partial() - should the next log be partial?
 * @pebi: pointer on PEB object
 */
static inline
int is_log_partial(struct ssdfs_peb_info *pebi)
{
	u16 log_pages;
	u16 free_data_pages;
	u16 reserved_pages;
	u16 min_partial_log_pages;
	int sequence_id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	log_pages = pebi->log_pages;
	free_data_pages = pebi->current_log.free_data_pages;
	reserved_pages = pebi->current_log.reserved_pages;
	sequence_id = atomic_read(&pebi->current_log.sequence_id);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("log_pages %u, free_data_pages %u, "
		  "reserved_pages %u, sequence_id %d\n",
		  log_pages, free_data_pages,
		  reserved_pages, sequence_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (free_data_pages == 0) {
		if (sequence_id > 0)
			return SSDFS_FINISH_PARTIAL_LOG;
		else
			return SSDFS_FINISH_FULL_LOG;
	}

	if (free_data_pages >= log_pages)
		return SSDFS_START_FULL_LOG;

	min_partial_log_pages = ssdfs_peb_estimate_min_partial_log_pages(pebi);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("min_partial_log_pages %u, reserved_pages %u\n",
		  min_partial_log_pages, reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	if (reserved_pages == 0) {
		if (free_data_pages <= min_partial_log_pages) {
			if (sequence_id > 0)
				return SSDFS_FINISH_PARTIAL_LOG;
			else
				return SSDFS_FINISH_FULL_LOG;
		}
	} else {
		u32 available_pages = free_data_pages + reserved_pages;

		if (available_pages <= min_partial_log_pages) {
			if (sequence_id > 0)
				return SSDFS_FINISH_PARTIAL_LOG;
			else
				return SSDFS_FINISH_FULL_LOG;
		} else if (free_data_pages < min_partial_log_pages) {
			/*
			 * Next partial log cannot be created
			 */
			if (sequence_id > 0)
				return SSDFS_FINISH_PARTIAL_LOG;
			else
				return SSDFS_FINISH_FULL_LOG;
		}
	}

	if (sequence_id == 0)
		return SSDFS_START_PARTIAL_LOG;

	return SSDFS_CONTINUE_PARTIAL_LOG;
}

/*
 * ssdfs_peb_create_log() - create new log
 * @pebi: pointer on PEB object
 *
 * This function tries to create new log in page cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - PEB is full.
 * %-EIO        - area contain dirty (not committed) pages.
 * %-EAGAIN     - current log is not initialized.
 */
static
int ssdfs_peb_create_log(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_log *log;
	struct ssdfs_metadata_options *options;
	int log_state;
	int log_strategy;
	u32 pages_per_peb;
	u32 log_footer_pages;
	int compr_type;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebi->pebc->parent_si;
	log_state = atomic_read(&pebi->current_log.state);

	switch (log_state) {
	case SSDFS_LOG_UNKNOWN:
	case SSDFS_LOG_PREPARED:
		SSDFS_ERR("peb %llu current log is not initialized\n",
			  pebi->peb_id);
		return -ERANGE;

	case SSDFS_LOG_INITIALIZED:
	case SSDFS_LOG_COMMITTED:
		/* do function's work */
		break;

	case SSDFS_LOG_CREATED:
		SSDFS_WARN("peb %llu current log is not initialized\n",
			   pebi->peb_id);
		return -ERANGE;

	default:
		BUG();
	};

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, peb %llu, current_log.start_page %u\n",
		  si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);
#else
	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	ssdfs_peb_current_log_lock(pebi);

	log = &pebi->current_log;
	pages_per_peb = min_t(u32, si->fsi->leb_pages_capacity,
				   si->fsi->peb_pages_capacity);

	/*
	 * Start page of the next log should be defined during commit.
	 * It needs to check this value here only.
	 */

	if (log->start_page >= pages_per_peb) {
		SSDFS_ERR("current_log.start_page %u >= pages_per_peb %u\n",
			  log->start_page, pages_per_peb);
		err = -ENOSPC;
		goto finish_log_create;
	}

	log_strategy = is_log_partial(pebi);

	switch (log_strategy) {
	case SSDFS_START_FULL_LOG:
		if ((log->start_page + log->free_data_pages) % pebi->log_pages) {
			SSDFS_WARN("unexpected state: "
				   "log->start_page %u, "
				   "log->free_data_pages %u, "
				   "pebi->log_pages %u\n",
				   log->start_page,
				   log->free_data_pages,
				   pebi->log_pages);
		}

		log->reserved_pages = ssdfs_peb_define_reserved_metapages(pebi);
		break;

	case SSDFS_START_PARTIAL_LOG:
		log->reserved_pages = ssdfs_peb_define_reserved_metapages(pebi);
		break;

	case SSDFS_CONTINUE_PARTIAL_LOG:
		log->reserved_pages = ssdfs_peb_define_reserved_metapages(pebi);
		log_footer_pages = ssdfs_peb_log_footer_metapages(pebi);
		log->reserved_pages -= log_footer_pages;
		break;

	case SSDFS_FINISH_PARTIAL_LOG:
	case SSDFS_FINISH_FULL_LOG:
		if (log->free_data_pages == 0) {
			err = -ENOSPC;
			SSDFS_ERR("seg %llu, peb %llu, "
				  "start_page %u, free_data_pages %u\n",
				  si->seg_id, pebi->peb_id,
				  log->start_page, log->free_data_pages);
			goto finish_log_create;
		} else {
			log->reserved_pages =
				ssdfs_peb_define_reserved_metapages(pebi);
			log_footer_pages =
				ssdfs_peb_log_footer_metapages(pebi);
			/*
			 * The reserved pages imply presence of header
			 * and footer. However, it needs to add the page
			 * for data itself. If header's page is able
			 * to keep the data too then footer will be in
			 * the log. Otherwise, footer will be absent.
			 */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log_footer_pages %u, log->reserved_pages %u\n",
				  log_footer_pages, log->reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

			log->free_data_pages += log_footer_pages;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_CRIT("unexpected log strategy %#x\n",
			   log_strategy);
		goto finish_log_create;
	}

	if (log->free_data_pages < log->reserved_pages) {
		err = -ENOSPC;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("log->free_data_pages %u < log->reserved_pages %u\n",
			  log->free_data_pages, log->reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_log_create;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("log_strategy %#x, free_data_pages %u, reserved_pages %u\n",
		  log_strategy, log->free_data_pages, log->reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_segment_blk_bmap_reserve_metapages(&si->blk_bmap,
							pebi->pebc,
							log->reserved_pages);
	if (err == -ENOSPC) {
		/*
		 * The goal of reservation is to decrease the number of
		 * free logical blocks because some PEB's space is used
		 * for the metadata. Such decreasing prevents from
		 * allocation of logical blocks out of physically
		 * available space in the PEB. However, if no space
		 * for reservation but there are some physical pages
		 * for logs creation then the operation of reservation
		 * can be simply ignored. Because, current log's
		 * metadata structure manages the real available
		 * space in the PEB.
		 */
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to reserve metadata pages: "
			  "count %u, err %d\n",
			  log->reserved_pages, err);
		goto finish_log_create;
	}

	log->free_data_pages -= log->reserved_pages;
	pebi->current_log.seg_flags = 0;

	memset(&log->blk2off_tbl.hdr, 0xFF,
		sizeof(struct ssdfs_blk2off_table_header));
	log->blk2off_tbl.reserved_offset = U32_MAX;
	log->blk2off_tbl.compressed_offset = 0;

	for (i = 0; i < SSDFS_LOG_AREA_MAX; i++) {
		struct ssdfs_peb_area *area;
		struct ssdfs_page_array *area_pages;
		struct ssdfs_peb_area_metadata *metadata;
		struct ssdfs_fragments_chain_header *chain_hdr;
		size_t metadata_size = sizeof(struct ssdfs_peb_area_metadata);
		size_t blk_table_size = sizeof(struct ssdfs_area_block_table);
		size_t desc_size = sizeof(struct ssdfs_fragment_desc);

		area = &pebi->current_log.area[i];
		area_pages = &area->array;

		if (atomic_read(&area_pages->state) == SSDFS_PAGE_ARRAY_DIRTY) {
			/*
			 * It needs to repeat the commit.
			 */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("PEB %llu is dirty on log creation\n",
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			err = ssdfs_page_array_release_all_pages(area_pages);
			if (unlikely(err)) {
				ssdfs_fs_error(si->fsi->sb,
						__FILE__, __func__, __LINE__,
						"fail to release pages: "
						"PEB %llu\n",
						pebi->peb_id);
				err = -EIO;
				goto finish_log_create;
			}
		}

		metadata = &area->metadata;

		switch (i) {
		case SSDFS_LOG_BLK_DESC_AREA:
			memset(&metadata->area.blk_desc.table,
			       0, sizeof(struct ssdfs_area_block_table));
			chain_hdr = &metadata->area.blk_desc.table.chain_hdr;
			chain_hdr->desc_size = cpu_to_le16(desc_size);
			chain_hdr->magic = SSDFS_CHAIN_HDR_MAGIC;

			options = &si->fsi->metadata_options;
			compr_type = options->blk2off_tbl.compression;

			switch (compr_type) {
			case SSDFS_BLK2OFF_TBL_NOCOMPR_TYPE:
				chain_hdr->type = SSDFS_BLK_DESC_CHAIN_HDR;
				break;
			case SSDFS_BLK2OFF_TBL_ZLIB_COMPR_TYPE:
				chain_hdr->type = SSDFS_BLK_DESC_ZLIB_CHAIN_HDR;
				break;
			case SSDFS_BLK2OFF_TBL_LZO_COMPR_TYPE:
				chain_hdr->type = SSDFS_BLK_DESC_LZO_CHAIN_HDR;
				break;
			default:
				BUG();
			}

			area->has_metadata = true;
			area->write_offset = blk_table_size;
			area->compressed_offset = blk_table_size;
			metadata->area.blk_desc.capacity = 0;
			metadata->area.blk_desc.items_count = 0;
			metadata->reserved_offset = 0;
			metadata->sequence_id = 0;

			err = ssdfs_peb_reserve_blk_desc_space(pebi, metadata);
			if (unlikely(err)) {
				SSDFS_ERR("fail to reserve blk desc space: "
					  "err %d\n", err);
				goto finish_log_create;
			}
			break;

		case SSDFS_LOG_DIFFS_AREA:
			memset(metadata, 0, metadata_size);
			chain_hdr = &metadata->area.diffs.table.hdr.chain_hdr;
			chain_hdr->desc_size = cpu_to_le16(desc_size);
			chain_hdr->magic = SSDFS_CHAIN_HDR_MAGIC;
			chain_hdr->type = SSDFS_BLK_STATE_CHAIN_HDR;
			area->has_metadata = false;
			area->write_offset = 0;
			area->metadata.reserved_offset = 0;
			break;

		case SSDFS_LOG_JOURNAL_AREA:
			memset(metadata, 0, metadata_size);
			chain_hdr = &metadata->area.journal.table.hdr.chain_hdr;
			chain_hdr->desc_size = cpu_to_le16(desc_size);
			chain_hdr->magic = SSDFS_CHAIN_HDR_MAGIC;
			chain_hdr->type = SSDFS_BLK_STATE_CHAIN_HDR;
			area->has_metadata = false;
			area->write_offset = 0;
			area->metadata.reserved_offset = 0;
			break;

		case SSDFS_LOG_MAIN_AREA:
			memset(metadata, 0, metadata_size);
			area->has_metadata = false;
			area->write_offset = 0;
			area->metadata.reserved_offset = 0;
			break;

		default:
			BUG();
		};
	}

	ssdfs_peb_set_current_log_state(pebi, SSDFS_LOG_CREATED);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("log created: "
		  "seg %llu, peb %llu, "
		  "current_log.start_page %u, free_data_pages %u\n",
		  si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  log->free_data_pages);
#else
	SSDFS_DBG("log created: "
		  "seg %llu, peb %llu, "
		  "current_log.start_page %u, free_data_pages %u\n",
		  si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  log->free_data_pages);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

finish_log_create:
	ssdfs_peb_current_log_unlock(pebi);
	return err;
}

/*
 * ssdfs_peb_grow_log_area() - grow log's area
 * @pebi: pointer on PEB object
 * @area_type: area type
 * @fragment_size: size of fragment
 *
 * This function tries to add memory page into log's area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - log is full.
 * %-ENOMEM     - fail to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_grow_log_area(struct ssdfs_peb_info *pebi, int area_type,
			    u32 fragment_size)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_page_array *area_pages;
	u32 write_offset;
	pgoff_t index_start, index_end;
	struct page *page;
	u16 metadata_pages = 0;
	u16 free_data_pages;
	u16 reserved_pages;
	int phys_pages = 0;
	int log_strategy;
	u32 min_log_pages;
	u32 footer_pages;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("peb %llu, current_log.free_data_pages %u, "
		  "area_type %#x, area.write_offset %u, "
		  "fragment_size %u\n",
		  pebi->peb_id,
		  pebi->current_log.free_data_pages,
		  area_type,
		  pebi->current_log.area[area_type].write_offset,
		  fragment_size);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	si = pebi->pebc->parent_si;
	area_pages = &pebi->current_log.area[area_type].array;

	write_offset = pebi->current_log.area[area_type].write_offset;

	BUG_ON(fragment_size > (2 * PAGE_SIZE));

	index_start = (((write_offset >> fsi->log_pagesize) <<
			fsi->log_pagesize) >> PAGE_SHIFT);

	if (fsi->pagesize > PAGE_SIZE) {
		index_end = write_offset + fragment_size + fsi->pagesize - 1;
		index_end >>= fsi->log_pagesize;
		index_end <<= fsi->log_pagesize;
		index_end >>= PAGE_SHIFT;
	} else {
		index_end = write_offset + fragment_size + PAGE_SIZE - 1;
		index_end >>= PAGE_SHIFT;
	}

	do {
		page = ssdfs_page_array_get_page(area_pages, index_start);
		if (IS_ERR_OR_NULL(page))
			break;
		else {
			index_start++;
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
		}
	} while (index_start < index_end);

	if (index_start >= index_end) {
		SSDFS_DBG("log doesn't need to grow\n");
		return 0;
	}

	phys_pages = index_end - index_start;

	if (fsi->pagesize > PAGE_SIZE) {
		phys_pages >>= fsi->log_pagesize - PAGE_SHIFT;
		if (phys_pages == 0)
			phys_pages = 1;
	} else if (fsi->pagesize < PAGE_SIZE)
		phys_pages <<= PAGE_SHIFT - fsi->log_pagesize;

	log_strategy = is_log_partial(pebi);
	free_data_pages = pebi->current_log.free_data_pages;
	reserved_pages = pebi->current_log.reserved_pages;
	min_log_pages = ssdfs_peb_estimate_min_partial_log_pages(pebi);
	footer_pages = ssdfs_peb_log_footer_metapages(pebi);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("min_log_pages %u, footer_pages %u, "
		  "log_strategy %#x, free_data_pages %u, "
		  "reserved_pages %u\n",
		  min_log_pages, footer_pages,
		  log_strategy, free_data_pages,
		  reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	if (phys_pages <= free_data_pages) {
		/*
		 * Continue logic.
		 */
	} else if (phys_pages <= (free_data_pages + footer_pages) &&
		   reserved_pages >= min_log_pages) {
		switch (log_strategy) {
		case SSDFS_START_FULL_LOG:
		case SSDFS_FINISH_FULL_LOG:
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("new_page_count %u > free_data_pages %u\n",
				  phys_pages,
				  pebi->current_log.free_data_pages);
#endif /* CONFIG_SSDFS_DEBUG */
			return -ENOSPC;

		case SSDFS_START_PARTIAL_LOG:
			pebi->current_log.free_data_pages += footer_pages;
			pebi->current_log.reserved_pages -= footer_pages;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("use footer page for data: "
				  "free_data_pages %u, reserved_pages %u\n",
				  pebi->current_log.free_data_pages,
				  pebi->current_log.reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */
			break;

		case SSDFS_CONTINUE_PARTIAL_LOG:
		case SSDFS_FINISH_PARTIAL_LOG:
			/* no free space available */

		default:
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("new_page_count %u > free_data_pages %u\n",
				  phys_pages,
				  pebi->current_log.free_data_pages);
#endif /* CONFIG_SSDFS_DEBUG */
			return -ENOSPC;
		}
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("new_page_count %u > free_data_pages %u\n",
			  phys_pages,
			  pebi->current_log.free_data_pages);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENOSPC;
	}

	for (; index_start < index_end; index_start++) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page_index %lu, current_log.free_data_pages %u\n",
			  index_start, pebi->current_log.free_data_pages);
#endif /* CONFIG_SSDFS_DEBUG */

		page = ssdfs_page_array_grab_page(area_pages, index_start);
		if (IS_ERR_OR_NULL(page)) {
			SSDFS_ERR("fail to add page %lu into area %#x space\n",
				  index_start, area_type);
			return -ENOMEM;
		}

		ssdfs_memzero_page(page, 0, PAGE_SIZE, PAGE_SIZE);

		ssdfs_set_page_private(page, 0);
		ssdfs_put_page(page);
		ssdfs_unlock_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	pebi->current_log.free_data_pages -= phys_pages;

	if (area_type == SSDFS_LOG_BLK_DESC_AREA)
		metadata_pages = phys_pages;

	if (metadata_pages > 0) {
		err = ssdfs_segment_blk_bmap_reserve_metapages(&si->blk_bmap,
								pebi->pebc,
								metadata_pages);
		if (err == -ENOSPC) {
			/*
			 * The goal of reservation is to decrease the number of
			 * free logical blocks because some PEB's space is used
			 * for the metadata. Such decreasing prevents from
			 * allocation of logical blocks out of physically
			 * available space in the PEB. However, if no space
			 * for reservation but there are some physical pages
			 * for logs creation then the operation of reservation
			 * can be simply ignored. Because, current log's
			 * metadata structure manages the real available
			 * space in the PEB.
			 */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to reserve metadata pages: "
				  "count %u, err %d\n",
				  metadata_pages, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_peb_store_fragment() - store fragment into page cache
 * @from: fragment source descriptor
 * @to: fragment destination descriptor [in|out]
 *
 * This function tries to store fragment into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - fail to store fragment into available space.
 */
static
int ssdfs_peb_store_fragment(struct ssdfs_fragment_source *from,
			     struct ssdfs_fragment_destination *to)
{
	int compr_type;
	unsigned char *src;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!from || !to);
	BUG_ON(!from->page || !to->store || !to->desc);
	BUG_ON((from->start_offset + from->data_bytes) > PAGE_SIZE);
	BUG_ON(from->fragment_type <= SSDFS_UNKNOWN_FRAGMENT_TYPE ||
		from->fragment_type >= SSDFS_FRAGMENT_DESC_MAX_TYPE);
	BUG_ON(from->fragment_flags & ~SSDFS_FRAGMENT_DESC_FLAGS_MASK);
	BUG_ON(to->free_space > PAGE_SIZE);

	SSDFS_DBG("page %p, start_offset %u, data_bytes %zu, "
		  "sequence_id %u, fragment_type %#x, fragment_flags %#x, "
		  "write_offset %u, store %p, free_space %zu\n",
		  from->page, from->start_offset, from->data_bytes,
		  from->sequence_id, from->fragment_type,
		  from->fragment_flags,
		  to->write_offset, to->store, to->free_space);
#endif /* CONFIG_SSDFS_DEBUG */

	if (from->data_bytes == 0) {
		SSDFS_WARN("from->data_bytes == 0\n");
		return 0;
	}

	if (to->free_space == 0) {
		SSDFS_WARN("to->free_space is not enough\n");
		return -EAGAIN;
	}

	switch (from->fragment_type) {
	case SSDFS_FRAGMENT_UNCOMPR_BLOB:
		compr_type = SSDFS_COMPR_NONE;
		break;
	case SSDFS_FRAGMENT_ZLIB_BLOB:
		compr_type = SSDFS_COMPR_ZLIB;
		break;
	case SSDFS_FRAGMENT_LZO_BLOB:
		compr_type = SSDFS_COMPR_LZO;
		break;
	default:
		BUG();
	};

	if (!ssdfs_can_compress_data(from->page, from->data_bytes)) {
		compr_type = SSDFS_COMPR_NONE;
		from->fragment_type = SSDFS_FRAGMENT_UNCOMPR_BLOB;
	}

	to->compr_size = to->free_space;

	src = kmap_local_page(from->page);
	src += from->start_offset;
	to->desc->checksum = ssdfs_crc32_le(src, from->data_bytes);
	err = ssdfs_compress(compr_type, src, to->store,
			     &from->data_bytes, &to->compr_size);
	kunmap_local(src);

	if (err == -E2BIG || err == -EOPNOTSUPP) {
		BUG_ON(from->data_bytes > PAGE_SIZE);
		BUG_ON(from->data_bytes > to->free_space);

		from->fragment_type = SSDFS_FRAGMENT_UNCOMPR_BLOB;

		src = kmap_local_page(from->page);
		err = ssdfs_memcpy(to->store, 0, to->free_space,
				   src, from->start_offset, PAGE_SIZE,
				   from->data_bytes);
		kunmap_local(src);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: err %d\n", err);
			return err;
		}

		to->compr_size = from->data_bytes;
	} else if (err) {
		SSDFS_ERR("fail to compress fragment: "
			  "data_bytes %zu, free_space %zu, err %d\n",
			  from->data_bytes, to->free_space, err);
		return err;
	}

	BUG_ON(to->area_offset > to->write_offset);
	to->desc->offset = cpu_to_le32(to->write_offset - to->area_offset);

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(to->compr_size > U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	to->desc->compr_size = cpu_to_le16((u16)to->compr_size);

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(from->data_bytes > U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	to->desc->uncompr_size = cpu_to_le16((u16)from->data_bytes);

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(from->sequence_id >= U8_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	to->desc->sequence_id = from->sequence_id;
	to->desc->magic = SSDFS_FRAGMENT_DESC_MAGIC;
	to->desc->type = from->fragment_type;
	to->desc->flags = from->fragment_flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("offset %u, compr_size %u, "
		  "uncompr_size %u, checksum %#x\n",
		  to->desc->offset,
		  to->desc->compr_size,
		  to->desc->uncompr_size,
		  le32_to_cpu(to->desc->checksum));
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_define_stream_fragments_count() - calculate fragments count
 * @start_offset: offset byte stream in bytes
 * @data_bytes: size of stream in bytes
 *
 * This function calculates count of fragments of byte stream.
 * The byte stream is part of memory page or it can be distributed
 * between several memory pages. One fragment can't be greater
 * than memory page (PAGE_SIZE) in bytes. Logic of this
 * function calculates count of parts are divided between
 * memory pages.
 */
static inline
u16 ssdfs_define_stream_fragments_count(u32 start_offset,
					u32 data_bytes)
{
	u16 count = 0;
	u32 partial_offset;
	u32 front_part;

	if (data_bytes == 0)
		return 0;

	partial_offset = start_offset % PAGE_SIZE;
	front_part = PAGE_SIZE - partial_offset;
	front_part = min_t(u32, front_part, data_bytes);

	if (front_part < data_bytes) {
		count++;
		data_bytes -= front_part;
	}

	count += (data_bytes + PAGE_SIZE - 1) >> PAGE_SHIFT;

	return count;
}

/*
 * ssdfs_peb_store_data_block_fragment() - store data block's fragment
 * @pebi: pointer on PEB object
 * @from: fragment source descriptor
 * @write_offset: write offset
 * @type: area type
 * @desc: pointer on fragment descriptor
 *
 * This function tries to store data block's fragment into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - fail to get memory page.
 * %-EAGAIN     - unable to store data fragment.
 */
static
int ssdfs_peb_store_data_block_fragment(struct ssdfs_peb_info *pebi,
					struct ssdfs_fragment_source *from,
					u32 write_offset,
					int type,
					struct ssdfs_fragment_desc *desc)
{
	struct ssdfs_fragment_destination to;
	struct page *page;
	pgoff_t page_index;
	u32 offset;
	u32 written_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !from);
	BUG_ON(type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("from->page %p, from->start_offset %u, "
		  "from->data_bytes %zu, from->sequence_id %u, "
		  "write_offset %u, type %#x\n",
		  from->page, from->start_offset, from->data_bytes,
		  from->sequence_id, write_offset, type);
#endif /* CONFIG_SSDFS_DEBUG */

	to.area_offset = 0;
	to.write_offset = write_offset;

	to.store = ssdfs_flush_kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!to.store) {
		SSDFS_ERR("fail to allocate buffer for fragment\n");
		return -ENOMEM;
	}

	to.free_space = PAGE_SIZE;
	to.compr_size = 0;
	to.desc = desc;

	err = ssdfs_peb_store_fragment(from, &to);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to store data fragment: "
			  "write_offset %u, dst_free_space %zu\n",
			  write_offset, to.free_space);
#endif /* CONFIG_SSDFS_DEBUG */
		goto free_compr_buffer;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to store fragment: "
			  "sequence_id %u, write_offset %u, err %d\n",
			  from->sequence_id, write_offset, err);
		goto free_compr_buffer;
	}

	BUG_ON(to.compr_size == 0);

	do {
		struct ssdfs_page_array *area_pages;
		u32 size;

		page_index = to.write_offset + written_bytes;
		page_index >>= PAGE_SHIFT;

		area_pages = &pebi->current_log.area[type].array;
		page = ssdfs_page_array_get_page_locked(area_pages,
							page_index);
		if (IS_ERR_OR_NULL(page)) {
			err = page == NULL ? -ERANGE : PTR_ERR(page);

			if (err == -ENOENT) {
				err = ssdfs_peb_grow_log_area(pebi, type,
							from->data_bytes);
				if (err == -ENOSPC) {
					err = -EAGAIN;
					SSDFS_DBG("log is full\n");
					goto free_compr_buffer;
				} else if (unlikely(err)) {
					SSDFS_ERR("fail to grow log area: "
						  "type %#x, err %d\n",
						  type, err);
					goto free_compr_buffer;
				}
			} else {
				SSDFS_ERR("fail to get page: "
					  "index %lu for area %#x\n",
					  page_index, type);
				goto free_compr_buffer;
			}

			/* try to get page again */
			page = ssdfs_page_array_get_page_locked(area_pages,
								page_index);
			if (IS_ERR_OR_NULL(page)) {
				err = page == NULL ? -ERANGE : PTR_ERR(page);
				SSDFS_ERR("fail to get page: "
					  "index %lu for area %#x\n",
					  page_index, type);
				goto free_compr_buffer;
			}
		}

		offset = to.write_offset + written_bytes;
		offset %= PAGE_SIZE;
		size = PAGE_SIZE - offset;
		size = min_t(u32, size, to.compr_size - written_bytes);

		err = ssdfs_memcpy_to_page(page,
					   offset, PAGE_SIZE,
					   to.store,
					   written_bytes, to.free_space,
					   size);
		if (unlikely(err)) {
			SSDFS_ERR("failt to copy: err %d\n", err);
			goto finish_copy;
		}

		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(area_pages,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: "
				  "err %d\n",
				  page_index, err);
		}

finish_copy:
		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		if (err)
			goto free_compr_buffer;

		written_bytes += size;
	} while (written_bytes < to.compr_size);

free_compr_buffer:
	ssdfs_flush_kfree(to.store);

	return err;
}

/*
 * ssdfs_peb_store_block_state_desc() - store block state descriptor
 * @pebi: pointer on PEB object
 * @write_offset: write offset
 * @type: area type
 * @desc: pointer on block state descriptor
 * @array: fragment descriptors array
 * @array_size: number of items in array
 *
 * This function tries to store block state descriptor into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - fail to get memory page.
 */
static
int ssdfs_peb_store_block_state_desc(struct ssdfs_peb_info *pebi,
				    u32 write_offset,
				    int type,
				    struct ssdfs_block_state_descriptor *desc,
				    struct ssdfs_fragment_desc *array,
				    u32 array_size)
{
	struct ssdfs_page_array *area_pages;
	struct page *page;
	pgoff_t page_index;
	unsigned char *kaddr;
	u32 page_off;
	size_t desc_size = sizeof(struct ssdfs_block_state_descriptor);
	size_t table_size = sizeof(struct ssdfs_fragment_desc) * array_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!desc || !array);
	BUG_ON(array_size == 0);
	BUG_ON(type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("write_offset %u, type %#x, desc %p, "
		  "array %p, array_size %u\n",
		  write_offset, type, desc, array, array_size);
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = write_offset / PAGE_SIZE;
	area_pages = &pebi->current_log.area[type].array;

	page = ssdfs_page_array_get_page_locked(area_pages, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = page == NULL ? -ERANGE : PTR_ERR(page);
		SSDFS_ERR("fail to get page %lu for area %#x\n",
			  page_index, type);
		return err;
	}

	page_off = write_offset % PAGE_SIZE;

	kaddr = kmap_local_page(page);

	err = ssdfs_memcpy(kaddr, page_off, PAGE_SIZE,
			   desc, 0, desc_size,
			   desc_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		goto fail_copy;
	}

	err = ssdfs_memcpy(kaddr, page_off + desc_size, PAGE_SIZE,
			   array, 0, table_size,
			   table_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		goto fail_copy;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("write_offset %u, page_off %u, "
		  "desc_size %zu, table_size %zu\n",
		  write_offset, page_off, desc_size, table_size);
	SSDFS_DBG("BLOCK STATE DESC AREA DUMP:\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     kaddr, PAGE_SIZE);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

fail_copy:
	flush_dcache_page(page);
	kunmap_local(kaddr);

	if (unlikely(err))
		goto finish_copy;

	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(area_pages,
					      page_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: "
			  "err %d\n",
			  page_index, err);
	}

finish_copy:
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_peb_store_byte_stream_in_main_area() - store byte stream into main area
 * @pebi: pointer on PEB object
 * @stream: byte stream descriptor
 * @cno: checkpoint
 * @parent_snapshot: parent snapshot number
 *
 * This function tries to store store data block of some size
 * from pagevec into main area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_byte_stream_in_main_area(struct ssdfs_peb_info *pebi,
				struct ssdfs_byte_stream_descriptor *stream,
				u64 cno,
				u64 parent_snapshot)
{
	struct ssdfs_peb_area *area;
	int area_type = SSDFS_LOG_MAIN_AREA;
	struct ssdfs_fragment_desc cur_desc = {0};
	int start_page, page_index;
	u16 fragments;
	u32 written_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !stream);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!stream->pvec);
	BUG_ON(pagevec_count(stream->pvec) == 0);
	BUG_ON((pagevec_count(stream->pvec) * PAGE_SIZE) <
		(stream->start_offset + stream->data_bytes));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, "
		  "write_offset %u, "
		  "stream->start_offset %u, stream->data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.area[area_type].write_offset,
		  stream->start_offset, stream->data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	area = &pebi->current_log.area[area_type];

	fragments = ssdfs_define_stream_fragments_count(stream->start_offset,
							stream->data_bytes);
	if (fragments == 0) {
		SSDFS_ERR("invalid fragments count %u\n", fragments);
		return -ERANGE;
	}

	start_page = stream->start_offset >> PAGE_SHIFT;

	if ((start_page + fragments) > pagevec_count(stream->pvec)) {
		SSDFS_ERR("start_page %d + fragments %u > pagevec_count %u\n",
			  start_page, fragments, pagevec_count(stream->pvec));
		err = -ERANGE;
		goto finish_store_byte_stream;
	}

	stream->write_offset = area->write_offset;

	for (page_index = 0; page_index < fragments; page_index++) {
		int i = start_page + page_index;
		struct ssdfs_fragment_source from;
		u32 write_offset;

		if (written_bytes >= stream->data_bytes) {
			SSDFS_ERR("written_bytes %u >= data_bytes %u\n",
				  written_bytes, stream->data_bytes);
			err = -ERANGE;
			goto finish_store_byte_stream;
		}

		from.page = stream->pvec->pages[i];
		from.start_offset = (stream->start_offset + written_bytes) %
					PAGE_SIZE;
		from.data_bytes = min_t(u32, PAGE_SIZE,
					stream->data_bytes - written_bytes);
		from.sequence_id = page_index;

		from.fragment_type = SSDFS_FRAGMENT_UNCOMPR_BLOB;
		from.fragment_flags = 0;

try_get_next_page:
		write_offset = area->write_offset;
		err = ssdfs_peb_store_data_block_fragment(pebi, &from,
							  write_offset,
							  area_type,
							  &cur_desc);

		if (err == -EAGAIN) {
			u32 page_off = write_offset % PAGE_SIZE;
			u32 rest = PAGE_SIZE - page_off;

			if (page_off == 0)
				goto finish_store_byte_stream;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("try to get next page: "
				  "write_offset %u, free_space %u\n",
				  write_offset, rest);
#endif /* CONFIG_SSDFS_DEBUG */

			pebi->current_log.area[area_type].write_offset += rest;
			goto try_get_next_page;
		}

		if (err) {
			SSDFS_ERR("fail to store fragment: "
				  "sequence_id %u, write_offset %u, err %d\n",
				  from.sequence_id,
				  area->write_offset,
				  err);
			goto finish_store_byte_stream;
		}

		written_bytes += from.data_bytes;
		area->write_offset += le16_to_cpu(cur_desc.compr_size);
	}

	stream->compr_bytes = area->write_offset;

finish_store_byte_stream:
	if (err)
		area->write_offset = 0;

	return err;
}

static
int ssdfs_peb_define_metadata_space(struct ssdfs_peb_info *pebi,
				    int area_type,
				    u32 start_offset,
				    u32 data_bytes,
				    u32 *metadata_offset,
				    u32 *metadata_space)
{
	struct ssdfs_peb_area *area;
	u16 fragments;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!metadata_offset || !metadata_space);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "area_type %#x, write_offset %u, "
		  "start_offset %u, data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_type,
		  pebi->current_log.area[area_type].write_offset,
		  start_offset, data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	area = &pebi->current_log.area[area_type];

	*metadata_offset = area->write_offset;
	*metadata_space = sizeof(struct ssdfs_block_state_descriptor);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("metadata_offset %u, metadata_space %u\n",
		  *metadata_offset, *metadata_space);
#endif /* CONFIG_SSDFS_DEBUG */

	fragments = ssdfs_define_stream_fragments_count(start_offset,
							data_bytes);
	if (fragments == 0) {
		SSDFS_ERR("invalid fragments count %u\n", fragments);
		return -ERANGE;
	}

	*metadata_space += fragments * sizeof(struct ssdfs_fragment_desc);
	*metadata_offset = ssdfs_peb_correct_area_write_offset(*metadata_offset,
							       *metadata_space);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fragments %u, metadata_offset %u, metadata_space %u\n",
		  fragments, *metadata_offset, *metadata_space);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_peb_store_byte_stream() - store byte stream into log
 * @pebi: pointer on PEB object
 * @stream: byte stream descriptor
 * @area_type: area type
 * @fragment_type: fragment type
 * @cno: checkpoint
 * @parent_snapshot: parent snapshot number
 *
 * This function tries to store store data block of some size
 * from pagevec into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_peb_store_byte_stream(struct ssdfs_peb_info *pebi,
				struct ssdfs_byte_stream_descriptor *stream,
				int area_type,
				int fragment_type,
				u64 cno,
				u64 parent_snapshot)
{
	struct ssdfs_block_state_descriptor state_desc;
	struct ssdfs_fragment_desc cur_desc = {0};
	struct ssdfs_peb_area *area;
	struct ssdfs_fragment_desc *array = NULL;
	u16 fragments;
	int start_page, page_index;
	u32 metadata_offset;
	u32 metadata_space;
	u32 written_bytes = 0;
#ifdef CONFIG_SSDFS_DEBUG
	void *kaddr;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !stream);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!stream->pvec);
	BUG_ON(pagevec_count(stream->pvec) == 0);
	BUG_ON((pagevec_count(stream->pvec) * PAGE_SIZE) <
		(stream->start_offset + stream->data_bytes));
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(fragment_type <= SSDFS_UNKNOWN_FRAGMENT_TYPE ||
		fragment_type >= SSDFS_FRAGMENT_DESC_MAX_TYPE);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, "
		  "area_type %#x, fragment_type %#x, write_offset %u, "
		  "stream->start_offset %u, stream->data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_type, fragment_type,
		  pebi->current_log.area[area_type].write_offset,
		  stream->start_offset, stream->data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	area = &pebi->current_log.area[area_type];

	fragments = ssdfs_define_stream_fragments_count(stream->start_offset,
							stream->data_bytes);
	if (fragments == 0) {
		SSDFS_ERR("invalid fragments count %u\n", fragments);
		return -ERANGE;
	} else if (fragments > 1) {
		array = ssdfs_flush_kcalloc(fragments,
				      sizeof(struct ssdfs_fragment_desc),
				      GFP_KERNEL);
		if (!array) {
			SSDFS_ERR("fail to allocate fragment desc array: "
				  "fragments %u\n",
				  fragments);
			return -ENOMEM;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fragments %u, start_offset %u, data_bytes %u\n",
		  fragments, stream->start_offset, stream->data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	start_page = stream->start_offset >> PAGE_SHIFT;

	if ((start_page + fragments) > pagevec_count(stream->pvec)) {
		SSDFS_ERR("start_page %d + fragments %u > pagevec_count %u\n",
			  start_page, fragments, pagevec_count(stream->pvec));
		err = -ERANGE;
		goto free_array;
	}

	err = ssdfs_peb_define_metadata_space(pebi, area_type,
						stream->start_offset,
						stream->data_bytes,
						&metadata_offset,
						&metadata_space);
	if (err) {
		SSDFS_ERR("fail to define metadata space: err %d\n",
			  err);
		goto free_array;
	}

	stream->write_offset = area->write_offset = metadata_offset;
	area->write_offset += metadata_space;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("write_offset %u\n", area->write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	for (page_index = 0; page_index < fragments; page_index++) {
		int i = start_page + page_index;
		struct ssdfs_fragment_source from;
		u32 write_offset;

		if (written_bytes >= stream->data_bytes) {
			SSDFS_ERR("written_bytes %u >= data_bytes %u\n",
				  written_bytes, stream->data_bytes);
			err = -ERANGE;
			goto free_array;
		}

#ifdef CONFIG_SSDFS_DEBUG
		kaddr = kmap_local_page(stream->pvec->pages[i]);
		SSDFS_DBG("PAGE DUMP: index %d\n",
			  i);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr,
				     PAGE_SIZE);
		SSDFS_DBG("\n");
		kunmap_local(kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

		from.page = stream->pvec->pages[i];
		from.start_offset = (stream->start_offset + written_bytes) %
					PAGE_SIZE;
		from.data_bytes = min_t(u32, PAGE_SIZE,
					stream->data_bytes - written_bytes);
		from.sequence_id = page_index;
		from.fragment_type = fragment_type;
		from.fragment_flags = SSDFS_FRAGMENT_HAS_CSUM;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("from.start_offset %u, from.data_bytes %zu, "
			  "page_index %d\n",
			  from.start_offset, from.data_bytes,
			  page_index);
#endif /* CONFIG_SSDFS_DEBUG */

try_get_next_page:
		write_offset = area->write_offset;
		err = ssdfs_peb_store_data_block_fragment(pebi, &from,
							  write_offset,
							  area_type,
							  &cur_desc);

		if (err == -EAGAIN) {
			u32 page_off = write_offset % PAGE_SIZE;
			u32 rest = PAGE_SIZE - page_off;

			if (page_off == 0)
				goto free_array;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("try to get next page: "
				  "write_offset %u, free_space %u\n",
				  write_offset, rest);
#endif /* CONFIG_SSDFS_DEBUG */

			pebi->current_log.area[area_type].write_offset += rest;
			goto try_get_next_page;
		}

		if (err) {
			SSDFS_ERR("fail to store fragment: "
				  "sequence_id %u, write_offset %u, err %d\n",
				  from.sequence_id,
				  area->write_offset,
				  err);
			goto free_array;
		}

		if (array) {
			ssdfs_memcpy(&array[page_index],
				     0, sizeof(struct ssdfs_fragment_desc),
				     &cur_desc,
				     0, sizeof(struct ssdfs_fragment_desc),
				     sizeof(struct ssdfs_fragment_desc));
		} else if (page_index > 0)
			BUG();

		written_bytes += from.data_bytes;
		area->write_offset += le16_to_cpu(cur_desc.compr_size);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("written_bytes %u, write_offset %u\n",
			  written_bytes, area->write_offset);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	stream->compr_bytes =
		area->write_offset - (metadata_offset + metadata_space);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("write_offset %u, metadata_offset %u, metadata_space %u\n",
		  area->write_offset, metadata_offset, metadata_space);
#endif /* CONFIG_SSDFS_DEBUG */

	state_desc.cno = cpu_to_le64(cno);
	state_desc.parent_snapshot = cpu_to_le64(parent_snapshot);

	state_desc.chain_hdr.compr_bytes = cpu_to_le32(stream->compr_bytes);
	state_desc.chain_hdr.uncompr_bytes = cpu_to_le32(written_bytes);
	state_desc.chain_hdr.fragments_count = cpu_to_le16(fragments);
	state_desc.chain_hdr.desc_size =
			cpu_to_le16(sizeof(struct ssdfs_fragment_desc));
	state_desc.chain_hdr.magic = SSDFS_CHAIN_HDR_MAGIC;
	state_desc.chain_hdr.type = SSDFS_BLK_STATE_CHAIN_HDR;
	state_desc.chain_hdr.flags = 0;

	if (array) {
		err = ssdfs_peb_store_block_state_desc(pebi, metadata_offset,
							area_type, &state_desc,
							array, fragments);
	} else {
		err = ssdfs_peb_store_block_state_desc(pebi, metadata_offset,
							area_type, &state_desc,
							&cur_desc, 1);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to store block state descriptor: "
			  "write_offset %u, area_type %#x, err %d\n",
			  metadata_offset, area_type, err);
		goto free_array;
	}

free_array:
	if (array)
		ssdfs_flush_kfree(array);

	if (err)
		area->write_offset = metadata_offset;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, "
		  "area_type %#x, fragment_type %#x, write_offset %u, "
		  "stream->start_offset %u, stream->data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_type, fragment_type,
		  pebi->current_log.area[area_type].write_offset,
		  stream->start_offset, stream->data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_area_free_space() - calculate area's free space
 * @pebi: pointer on PEB object
 * @area_type: area type
 */
static
u32 ssdfs_area_free_space(struct ssdfs_peb_info *pebi, int area_type)
{
	struct ssdfs_fs_info *fsi;
	u32 write_offset;
	u32 page_index;
	unsigned long pages_count;
	u32 free_space = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("area_type %#x\n", area_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	write_offset = pebi->current_log.area[area_type].write_offset;
	page_index = write_offset / PAGE_SIZE;

	down_read(&pebi->current_log.area[area_type].array.lock);
	pages_count = pebi->current_log.area[area_type].array.pages_count;
	up_read(&pebi->current_log.area[area_type].array.lock);

	if (page_index < pages_count)
		free_space += PAGE_SIZE - (write_offset % PAGE_SIZE);

	free_space += pebi->current_log.free_data_pages * fsi->pagesize;

	/*
	 * Reserved pages could be used for segment header
	 * and log footer. However, partial log header is
	 * the special combination of segment header and
	 * log footer. Usually, latest log has to be ended
	 * by the log footer. However, it could be used
	 * only partial log header if it needs to use
	 * the reserved space for log footer by user data.
	 */
	free_space += (pebi->current_log.reserved_pages - 1) * fsi->pagesize;

	return free_space;
}

/*
 * can_area_add_fragment() - do we can store fragment into area?
 * @pebi: pointer on PEB object
 * @area_type: area type
 * @fragment_size: size of fragment
 *
 * This function checks that we can add fragment into
 * free space of requested area.
 */
static
bool can_area_add_fragment(struct ssdfs_peb_info *pebi, int area_type,
			   u32 fragment_size)
{
	u32 write_offset;
	u32 free_space;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(fragment_size == 0);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("area_type %#x, fragment_size %u\n",
		  area_type, fragment_size);
#endif /* CONFIG_SSDFS_DEBUG */

	write_offset = pebi->current_log.area[area_type].write_offset;
	free_space = ssdfs_area_free_space(pebi, area_type);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("write_offset %u, free_space %u\n",
		  write_offset, free_space);
#endif /* CONFIG_SSDFS_DEBUG */

	return fragment_size <= free_space;
}

/*
 * has_current_page_free_space() - check current area's memory page
 * @pebi: pointer on PEB object
 * @area_type: area type
 * @fragment_size: size of fragment
 *
 * This function checks that we can add fragment into
 * free space of current memory page.
 */
static
bool has_current_page_free_space(struct ssdfs_peb_info *pebi,
				 int area_type,
				 u32 fragment_size)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_page_array *area_pages;
	bool is_space_enough, is_page_available;
	u32 write_offset;
	pgoff_t page_index;
	unsigned long pages_count;
	struct page *page;
	u32 free_space = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(fragment_size == 0);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("area_type %#x, fragment_size %u\n",
		  area_type, fragment_size);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	write_offset = pebi->current_log.area[area_type].write_offset;
	page_index = write_offset / PAGE_SIZE;

	down_read(&pebi->current_log.area[area_type].array.lock);
	pages_count = pebi->current_log.area[area_type].array.pages_count;
	up_read(&pebi->current_log.area[area_type].array.lock);

	if (page_index < pages_count)
		free_space += PAGE_SIZE - (write_offset % PAGE_SIZE);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("write_offset %u, free_space %u\n",
		  write_offset, free_space);
#endif /* CONFIG_SSDFS_DEBUG */

	is_space_enough = fragment_size <= free_space;

	page_index = write_offset >> PAGE_SHIFT;
	area_pages = &pebi->current_log.area[area_type].array;
	page = ssdfs_page_array_get_page(area_pages, page_index);
	if (IS_ERR_OR_NULL(page))
		is_page_available = false;
	else {
		is_page_available = true;
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return is_space_enough && is_page_available;
}

/*
 * ssdfs_peb_get_area_free_frag_desc() - get free fragment descriptor
 * @pebi: pointer on PEB object
 * @area_type: area type
 *
 * This function tries to get next vacant fragment descriptor
 * from block table.
 *
 * RETURN:
 * [success] - pointer on vacant fragment descriptor.
 * [failure] - NULL (block table is full).
 */
static
struct ssdfs_fragment_desc *
ssdfs_peb_get_area_free_frag_desc(struct ssdfs_peb_info *pebi, int area_type)
{
	struct ssdfs_area_block_table *table;
	u16 vacant_item;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (area_type) {
	case SSDFS_LOG_MAIN_AREA:
	case SSDFS_LOG_DIFFS_AREA:
	case SSDFS_LOG_JOURNAL_AREA:
		/* these areas haven't area block table */
		SSDFS_DBG("area block table doesn't be created\n");
		return ERR_PTR(-ERANGE);

	case SSDFS_LOG_BLK_DESC_AREA:
		/* store area block table */
		break;

	default:
		BUG();
	};

	table = &pebi->current_log.area[area_type].metadata.area.blk_desc.table;
	vacant_item = le16_to_cpu(table->chain_hdr.fragments_count);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_type %#x, vacant_item %u\n",
		  area_type, vacant_item);
#endif /* CONFIG_SSDFS_DEBUG */

	BUG_ON(vacant_item > SSDFS_BLK_TABLE_MAX);
	if (vacant_item == SSDFS_BLK_TABLE_MAX) {
		SSDFS_DBG("block table is full\n");
		return NULL;
	}

	le16_add_cpu(&table->chain_hdr.fragments_count, 1);
	return &table->blk[vacant_item];
}

/*
 * ssdfs_peb_get_area_cur_frag_desc() - get current fragment descriptor
 * @pebi: pointer on PEB object
 * @area_type: area type
 *
 * This function tries to get current fragment descriptor
 * from block table.
 *
 * RETURN:
 * [success] - pointer on current fragment descriptor.
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
struct ssdfs_fragment_desc *
ssdfs_peb_get_area_cur_frag_desc(struct ssdfs_peb_info *pebi, int area_type)
{
	struct ssdfs_area_block_table *table;
	u16 fragments_count;
	u16 cur_item = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (area_type) {
	case SSDFS_LOG_MAIN_AREA:
	case SSDFS_LOG_DIFFS_AREA:
	case SSDFS_LOG_JOURNAL_AREA:
		/* these areas haven't area block table */
		SSDFS_DBG("area block table doesn't be created\n");
		return ERR_PTR(-ERANGE);

	case SSDFS_LOG_BLK_DESC_AREA:
		/* store area block table */
		break;

	default:
		BUG();
	};

	table = &pebi->current_log.area[area_type].metadata.area.blk_desc.table;
	fragments_count = le16_to_cpu(table->chain_hdr.fragments_count);

	if (fragments_count > 0)
		cur_item = fragments_count - 1;
	else
		cur_item = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_type %#x, cur_item %u\n",
		  area_type, cur_item);
#endif /* CONFIG_SSDFS_DEBUG */

	BUG_ON(cur_item >= SSDFS_BLK_TABLE_MAX);

	return &table->blk[cur_item];
}

/*
 * ssdfs_peb_store_area_block_table() - store block table
 * @pebi: pointer on PEB object
 * @area_type: area type
 * @flags: area block table header's flags
 *
 * This function tries to store block table into area's address
 * space by reserved offset.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_area_block_table(struct ssdfs_peb_info *pebi,
				     int area_type, u16 flags)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_area *area;
	struct ssdfs_area_block_table *table;
	struct ssdfs_fragment_desc *last_desc;
	u16 fragments;
	u32 reserved_offset, new_offset;
	size_t blk_table_size = sizeof(struct ssdfs_area_block_table);
	u16 hdr_flags;
	struct page *page;
	pgoff_t page_index;
	u32 page_off;
	bool is_compressed = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (area_type) {
	case SSDFS_LOG_MAIN_AREA:
	case SSDFS_LOG_DIFFS_AREA:
	case SSDFS_LOG_JOURNAL_AREA:
		/* these areas haven't area block table */
		SSDFS_DBG("area block table doesn't be created\n");
		return 0;

	case SSDFS_LOG_BLK_DESC_AREA:
		/* store area block table */
		break;

	default:
		BUG();
	};

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_offset %u, area_type %#x\n",
		  pebi->current_log.area[area_type].metadata.reserved_offset,
		  area_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	is_compressed = fsi->metadata_options.blk2off_tbl.flags &
				SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION;

	area = &pebi->current_log.area[area_type];
	table = &area->metadata.area.blk_desc.table;

	fragments = le16_to_cpu(table->chain_hdr.fragments_count);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("table->chain_hdr.fragments_count %u\n",
		  fragments);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fragments < SSDFS_BLK_TABLE_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(flags & SSDFS_MULTIPLE_HDR_CHAIN);
#endif /* CONFIG_SSDFS_DEBUG */

		if (fragments > 0)
			last_desc = &table->blk[fragments - 1];
		else
			last_desc = &table->blk[0];

		last_desc->magic = SSDFS_FRAGMENT_DESC_MAGIC;

		switch (fsi->metadata_options.blk2off_tbl.compression) {
		case SSDFS_BLK2OFF_TBL_NOCOMPR_TYPE:
			last_desc->type = SSDFS_DATA_BLK_DESC;
			break;
		case SSDFS_BLK2OFF_TBL_ZLIB_COMPR_TYPE:
			last_desc->type = SSDFS_DATA_BLK_DESC_ZLIB;
			break;
		case SSDFS_BLK2OFF_TBL_LZO_COMPR_TYPE:
			last_desc->type = SSDFS_DATA_BLK_DESC_LZO;
			break;
		default:
			BUG();
		}

		last_desc->flags = 0;
	} else if (flags & SSDFS_MULTIPLE_HDR_CHAIN) {
		u32 write_offset = 0;

		BUG_ON(fragments > SSDFS_BLK_TABLE_MAX);

		last_desc = &table->blk[SSDFS_NEXT_BLK_TABLE_INDEX];

		if (is_compressed) {
			write_offset = area->compressed_offset;
			new_offset =
			    ssdfs_peb_correct_area_write_offset(write_offset,
								blk_table_size);
			area->compressed_offset = new_offset;
		} else {
			write_offset = area->write_offset;
			new_offset =
			    ssdfs_peb_correct_area_write_offset(write_offset,
								blk_table_size);
			area->write_offset = new_offset;
		}

		last_desc->offset = cpu_to_le32(new_offset);

		last_desc->compr_size = cpu_to_le16(blk_table_size);
		last_desc->uncompr_size = cpu_to_le16(blk_table_size);
		last_desc->checksum = 0;

		if (area->metadata.sequence_id == U8_MAX)
			area->metadata.sequence_id = 0;

		last_desc->sequence_id = area->metadata.sequence_id++;

		last_desc->magic = SSDFS_FRAGMENT_DESC_MAGIC;
		last_desc->type = SSDFS_NEXT_TABLE_DESC;
		last_desc->flags = 0;
	}

	hdr_flags = le16_to_cpu(table->chain_hdr.flags);
	hdr_flags |= flags;
	table->chain_hdr.flags = cpu_to_le16(hdr_flags);

	reserved_offset = area->metadata.reserved_offset;
	page_index = reserved_offset / PAGE_SIZE;
	page = ssdfs_page_array_get_page_locked(&area->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get page %lu for area %#x\n",
			  page_index, area_type);
		return -ERANGE;
	}

	page_off = reserved_offset % PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_offset %u, page_index %lu, "
		  "page_off %u\n",
		  reserved_offset, page_index,
		  page_off);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_memcpy_to_page(page, page_off, PAGE_SIZE,
				   table, 0, blk_table_size,
				   blk_table_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		goto finish_copy;
	}

	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&area->array, page_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: "
			  "err %d\n",
			  page_index, err);
	}

finish_copy:
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_peb_allocate_area_block_table() - reserve block table
 * @pebi: pointer on PEB object
 * @area_type: area type
 *
 * This function tries to prepare new in-core block table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - log is full.
 */
static
int ssdfs_peb_allocate_area_block_table(struct ssdfs_peb_info *pebi,
					int area_type)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_area *area;
	u16 fragments;
	struct ssdfs_area_block_table *table;
	struct ssdfs_fragment_desc *last_desc;
	size_t blk_table_size = sizeof(struct ssdfs_area_block_table);
	u32 write_offset = 0;
	bool is_compressed = false;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	switch (area_type) {
	case SSDFS_LOG_MAIN_AREA:
	case SSDFS_LOG_DIFFS_AREA:
	case SSDFS_LOG_JOURNAL_AREA:
		/* these areas haven't area block table */
		SSDFS_DBG("area block table doesn't be created\n");
		return 0;

	case SSDFS_LOG_BLK_DESC_AREA:
		/* store area block table */
		break;

	default:
		BUG();
	};

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("write_offset %u, area_type %#x\n",
		  pebi->current_log.area[area_type].write_offset,
		  area_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	is_compressed = fsi->metadata_options.blk2off_tbl.flags &
				SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION;

	area = &pebi->current_log.area[area_type];
	table = &area->metadata.area.blk_desc.table;
	fragments = le16_to_cpu(table->chain_hdr.fragments_count);

	BUG_ON(fragments > SSDFS_BLK_TABLE_MAX);

	if (fragments < SSDFS_BLK_TABLE_MAX) {
		SSDFS_ERR("invalid fragments count %u\n", fragments);
		return -ERANGE;
	}

	last_desc = &table->blk[SSDFS_NEXT_BLK_TABLE_INDEX];

	if (is_compressed)
		write_offset = area->compressed_offset;
	else
		write_offset = area->write_offset;

	if (le32_to_cpu(last_desc->offset) != write_offset) {
		SSDFS_ERR("last_desc->offset %u != write_offset %u\n",
			  le32_to_cpu(last_desc->offset), write_offset);
		return -ERANGE;
	}

	if (!has_current_page_free_space(pebi, area_type, blk_table_size)) {
		err = ssdfs_peb_grow_log_area(pebi, area_type, blk_table_size);
		if (err == -ENOSPC) {
			SSDFS_DBG("log is full\n");
			return -EAGAIN;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to grow log area: "
				  "type %#x, err %d\n",
				  area_type, err);
			return err;
		}
	}

	table->chain_hdr.compr_bytes = 0;
	table->chain_hdr.uncompr_bytes = 0;
	table->chain_hdr.fragments_count = 0;
	table->chain_hdr.desc_size =
			cpu_to_le16(sizeof(struct ssdfs_fragment_desc));
	table->chain_hdr.magic = SSDFS_CHAIN_HDR_MAGIC;
	table->chain_hdr.flags = 0;

	memset(table->blk, 0,
		sizeof(struct ssdfs_fragment_desc) * SSDFS_BLK_TABLE_MAX);

	area->metadata.reserved_offset = write_offset;

	if (is_compressed)
		area->compressed_offset += blk_table_size;
	else
		area->write_offset += blk_table_size;

	return 0;
}

/* try to estimate fragment size in the log */
static inline
u32 ssdfs_peb_estimate_data_fragment_size(u32 uncompr_bytes)
{
	u32 estimated_compr_size;

	/*
	 * There are several alternatives:
	 * (1) overestimate size;
	 * (2) underestimate size;
	 * (3) try to predict possible size by means of some formula.
	 *
	 * Currently, try to estimate size as 65% from uncompressed state
	 * for compression case.
	 */

	estimated_compr_size = (uncompr_bytes * 65) / 100;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("uncompr_bytes %u, estimated_compr_size %u\n",
		  uncompr_bytes, estimated_compr_size);
#endif /* CONFIG_SSDFS_DEBUG */

	return estimated_compr_size;
}

/*
 * ssdfs_request_rest_bytes() - define rest bytes in request
 * @pebi: pointer on PEB object
 * @req: I/O request
 */
static inline
u32 ssdfs_request_rest_bytes(struct ssdfs_peb_info *pebi,
			     struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi = pebi->pebc->parent_si->fsi;
	u32 processed_bytes = req->result.processed_blks * fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("processed_bytes %u, req->extent.data_bytes %u\n",
		  processed_bytes, req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	if (processed_bytes > req->extent.data_bytes)
		return 0;
	else
		return req->extent.data_bytes - processed_bytes;
}

/*
 * ssdfs_peb_increase_area_payload_size() - increase area size
 * @pebi: pointer on PEB object
 * @area_type: area type
 * @p: byte stream object ponter
 */
static void
ssdfs_peb_increase_area_payload_size(struct ssdfs_peb_info *pebi,
				     int area_type,
				     struct ssdfs_byte_stream_descriptor *p)
{
	struct ssdfs_peb_area *area;
	struct ssdfs_fragments_chain_header *chain_hdr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !p);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	area = &pebi->current_log.area[area_type];

	switch (area_type) {
	case SSDFS_LOG_BLK_DESC_AREA:
		chain_hdr = &area->metadata.area.blk_desc.table.chain_hdr;
		break;

	case SSDFS_LOG_DIFFS_AREA:
		chain_hdr = &area->metadata.area.diffs.table.hdr.chain_hdr;
		break;

	case SSDFS_LOG_JOURNAL_AREA:
		chain_hdr = &area->metadata.area.journal.table.hdr.chain_hdr;
		break;

	case SSDFS_LOG_MAIN_AREA:
		chain_hdr = &area->metadata.area.main.desc.chain_hdr;
		break;

	default:
		BUG();
	};

	le32_add_cpu(&chain_hdr->compr_bytes, p->compr_bytes);
	le32_add_cpu(&chain_hdr->uncompr_bytes, (u32)p->data_bytes);
}

/*
 * ssdfs_peb_define_area_offset() - define fragment's offset
 * @pebi: pointer on PEB object
 * @area_type: area type
 * @p: byte stream object ponter
 * @off: PEB's physical offset to data [out]
 */
static
int ssdfs_peb_define_area_offset(struct ssdfs_peb_info *pebi,
				  int area_type,
				  struct ssdfs_byte_stream_descriptor *p,
				  struct ssdfs_peb_phys_offset *off)
{
	int id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !p);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	id = ssdfs_get_peb_migration_id_checked(pebi);
	if (unlikely(id < 0)) {
		SSDFS_ERR("invalid peb_migration_id: "
			  "seg %llu, peb_id %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, id);
		return id;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(id > U8_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	off->peb_index = pebi->peb_index;
	off->peb_migration_id = (u8)id;
	off->log_area = area_type;
	off->byte_offset = p->write_offset;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("off->peb_index %u, off->peb_migration_id %u, "
		  "off->log_area %#x, off->byte_offset %u\n",
		  pebi->peb_index, id, area_type, p->write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

static inline
void ssdfs_prepare_user_data_options(struct ssdfs_fs_info *fsi,
				     u8 *compression)
{
	u16 flags;
	u8 type;

	flags = fsi->metadata_options.user_data.flags;
	type = fsi->metadata_options.user_data.compression;

	*compression = SSDFS_FRAGMENT_UNCOMPR_BLOB;

	if (flags & SSDFS_USER_DATA_MAKE_COMPRESSION) {
		switch (type) {
		case SSDFS_USER_DATA_NOCOMPR_TYPE:
			*compression = SSDFS_FRAGMENT_UNCOMPR_BLOB;
			break;

		case SSDFS_USER_DATA_ZLIB_COMPR_TYPE:
			*compression = SSDFS_FRAGMENT_ZLIB_BLOB;
			break;

		case SSDFS_USER_DATA_LZO_COMPR_TYPE:
			*compression = SSDFS_FRAGMENT_LZO_BLOB;
			break;
		}
	}
}

/*
 * ssdfs_peb_store_fragment_in_area() - try to store fragment into area
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @area_type: area type
 * @start_offset: start offset of fragment in bytes
 * @data_bytes: size of fragment in bytes
 * @off: PEB's physical offset to data [out]
 *
 * This function tries to store fragment into data area (diff updates
 * or journal) of the log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to store data block in current log.
 */
static
int ssdfs_peb_store_fragment_in_area(struct ssdfs_peb_info *pebi,
				     struct ssdfs_segment_request *req,
				     int area_type,
				     u32 start_offset,
				     u32 data_bytes,
				     struct ssdfs_peb_phys_offset *off)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_byte_stream_descriptor byte_stream = {0};
	u8 compression_type = SSDFS_FRAGMENT_UNCOMPR_BLOB;
	u32 metadata_offset;
	u32 metadata_space;
	u32 estimated_compr_size = data_bytes;
	u32 check_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !off);
	BUG_ON(req->extent.data_bytes <
		(req->result.processed_blks *
			pebi->pebc->parent_si->fsi->pagesize));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, area_type %#x, "
		  "start_offset %u, data_bytes %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks, area_type,
		  start_offset, data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	err = ssdfs_peb_define_metadata_space(pebi, area_type,
						start_offset,
						data_bytes,
						&metadata_offset,
						&metadata_space);
	if (err) {
		SSDFS_ERR("fail to define metadata space: err %d\n",
			  err);
		return err;
	}

	ssdfs_prepare_user_data_options(fsi, &compression_type);

	switch (compression_type) {
	case SSDFS_FRAGMENT_UNCOMPR_BLOB:
		estimated_compr_size = data_bytes;
		break;

	case SSDFS_FRAGMENT_ZLIB_BLOB:
#if defined(CONFIG_SSDFS_ZLIB)
		estimated_compr_size =
			ssdfs_peb_estimate_data_fragment_size(data_bytes);
#else
		compression_type = SSDFS_FRAGMENT_UNCOMPR_BLOB;
		estimated_compr_size = data_bytes;
		SSDFS_WARN("ZLIB compression is not supported\n");
#endif
		break;

	case SSDFS_FRAGMENT_LZO_BLOB:
#if defined(CONFIG_SSDFS_LZO)
		estimated_compr_size =
			ssdfs_peb_estimate_data_fragment_size(data_bytes);
#else
		compression_type = SSDFS_FRAGMENT_UNCOMPR_BLOB;
		estimated_compr_size = data_bytes;
		SSDFS_WARN("LZO compression is not supported\n");
#endif
		break;

	default:
		BUG();
	}

	check_bytes = metadata_space + estimated_compr_size;

	if (!can_area_add_fragment(pebi, area_type, check_bytes)) {
		pebi->current_log.free_data_pages = 0;
		SSDFS_DBG("log is full\n");
		return -EAGAIN;
	}

	if (!has_current_page_free_space(pebi, area_type, check_bytes)) {
		err = ssdfs_peb_grow_log_area(pebi, area_type, check_bytes);
		if (err == -ENOSPC) {
			SSDFS_DBG("log is full\n");
			return -EAGAIN;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to grow log area: "
				  "type %#x, err %d\n",
				  area_type, err);
			return err;
		}
	}

	byte_stream.pvec = &req->result.pvec;
	byte_stream.start_offset = start_offset;
	byte_stream.data_bytes = data_bytes;

	err = ssdfs_peb_store_byte_stream(pebi, &byte_stream, area_type,
					  compression_type,
					  req->extent.cno,
					  req->extent.parent_snapshot);

	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to add byte stream: "
			  "start_offset %u, data_bytes %u, area_type %#x, "
			  "cno %llu, parent_snapshot %llu\n",
			  byte_stream.start_offset, data_bytes, area_type,
			  req->extent.cno, req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to add byte stream: "
			  "start_offset %u, data_bytes %u, area_type %#x, "
			  "cno %llu, parent_snapshot %llu\n",
			  byte_stream.start_offset, data_bytes, area_type,
			  req->extent.cno, req->extent.parent_snapshot);
		return err;
	}

	ssdfs_peb_increase_area_payload_size(pebi, area_type, &byte_stream);

	err = ssdfs_peb_define_area_offset(pebi, area_type, &byte_stream, off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define area offset: "
			  "seg %llu, peb_id %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_store_in_journal_area() - try to store fragment into Journal area
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @start_offset: start offset of fragment in bytes
 * @data_bytes: size of fragment in bytes
 * @off: PEB's physical offset to data [out]
 *
 * This function tries to store fragment into Journal area of the log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to store data block in current log.
 */
static inline
int ssdfs_peb_store_in_journal_area(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req,
				    u32 start_offset,
				    u32 data_bytes,
				    struct ssdfs_peb_phys_offset *off)
{
	int area_type = SSDFS_LOG_JOURNAL_AREA;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !off);
	BUG_ON(req->extent.data_bytes <
		(req->result.processed_blks *
			pebi->pebc->parent_si->fsi->pagesize));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, start_offset %u, data_bytes %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks, start_offset, data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_peb_store_fragment_in_area(pebi, req, area_type,
						start_offset, data_bytes,
						off);
}

/*
 * ssdfs_peb_store_in_diff_area() - try to store fragment into Diff area
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @start_offset: start offset of fragment in bytes
 * @data_bytes: size of fragment in bytes
 * @off: PEB's physical offset to data [out]
 *
 * This function tries to store fragment into Diff Updates area of the log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to store data block in current log.
 */
static inline
int ssdfs_peb_store_in_diff_area(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req,
				 u32 start_offset,
				 u32 data_bytes,
				 struct ssdfs_peb_phys_offset *off)
{
	int area_type = SSDFS_LOG_DIFFS_AREA;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !off);
	BUG_ON(req->extent.data_bytes <
		(req->result.processed_blks *
			pebi->pebc->parent_si->fsi->pagesize));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, start_offset %u, data_bytes %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks, start_offset, data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_peb_store_fragment_in_area(pebi, req, area_type,
						start_offset, data_bytes,
						off);
}

/*
 * ssdfs_peb_store_in_main_area() - try to store fragment into Main area
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @start_offset: start offset of fragment in bytes
 * @data_bytes: size of fragment in bytes
 * @off: PEB's physical offset to data [out]
 *
 * This function tries to store fragment into Main area of the log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to store data block in current log.
 */
static
int ssdfs_peb_store_in_main_area(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req,
				 u32 start_offset,
				 u32 data_bytes,
				 struct ssdfs_peb_phys_offset *off)
{
	int area_type = SSDFS_LOG_MAIN_AREA;
	struct ssdfs_byte_stream_descriptor byte_stream = {0};
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !off);
	BUG_ON(req->extent.data_bytes <
		(req->result.processed_blks *
			pebi->pebc->parent_si->fsi->pagesize));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, rest_bytes %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks,
		  data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!can_area_add_fragment(pebi, area_type, data_bytes)) {
		pebi->current_log.free_data_pages = 0;
		SSDFS_DBG("log is full\n");
		return -EAGAIN;
	}

	if (!has_current_page_free_space(pebi, area_type, data_bytes)) {
		err = ssdfs_peb_grow_log_area(pebi, area_type, data_bytes);
		if (err == -ENOSPC) {
			SSDFS_DBG("log is full\n");
			return -EAGAIN;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to grow log area: "
				  "type %#x, err %d\n",
				  area_type, err);
			return err;
		}
	}

	byte_stream.pvec = &req->result.pvec;
	byte_stream.start_offset = start_offset;
	byte_stream.data_bytes = data_bytes;

	err = ssdfs_peb_store_byte_stream_in_main_area(pebi, &byte_stream,
						req->extent.cno,
						req->extent.parent_snapshot);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to add byte stream: "
			  "start_offset %u, data_bytes %u, area_type %#x, "
			  "cno %llu, parent_snapshot %llu\n",
			  start_offset, data_bytes, area_type,
			  req->extent.cno, req->extent.parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to add byte stream: "
			  "start_offset %u, data_bytes %u, area_type %#x, "
			  "cno %llu, parent_snapshot %llu\n",
			  start_offset, data_bytes, area_type,
			  req->extent.cno, req->extent.parent_snapshot);
		return err;
	}

	ssdfs_peb_increase_area_payload_size(pebi, area_type, &byte_stream);

	err = ssdfs_peb_define_area_offset(pebi, area_type, &byte_stream, off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define area offset: "
			  "seg %llu, peb_id %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		return err;
	}

	return 0;
}

/*
 * is_ssdfs_block_full() - check that data size is equal to page size
 * @pagesize: page size in bytes
 * @data_size: data size in bytes
 */
static inline
bool is_ssdfs_block_full(u32 pagesize, u32 data_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pagesize %u, data_size %u\n",
		  pagesize, data_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagesize > PAGE_SIZE)
		return data_size >= pagesize;

	return data_size >= PAGE_SIZE;
}

/*
 * can_ssdfs_pagevec_be_compressed() - check that pagevec can be compressed
 * @start_page: starting page in pagevec
 * @page_count: count of pages in the portion
 * @bytes_count: bytes number in the portion
 * @req: segment request
 */
static
bool can_ssdfs_pagevec_be_compressed(u32 start_page, u32 page_count,
				     u32 bytes_count,
				     struct ssdfs_segment_request *req)
{
	struct page *page;
	int page_index;
	u32 start_offset;
	u32 portion_size;
	u32 tested_bytes = 0;
	u32 can_compress[2] = {0, 0};
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);

	SSDFS_DBG("start_page %u, page_count %u, "
		  "bytes_count %u\n",
		  start_page, page_count, bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < page_count; i++) {
		int state;

		page_index = i + start_page;
		start_offset = page_index >> PAGE_SHIFT;
		portion_size = PAGE_SIZE;

		if (page_index >= pagevec_count(&req->result.pvec)) {
			SSDFS_ERR("fail to check page: "
				  "index %d, pvec_size %u\n",
				  page_index,
				  pagevec_count(&req->result.pvec));
			return false;
		}

		page = req->result.pvec.pages[page_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(tested_bytes >= bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

		portion_size = min_t(u32, portion_size,
				     bytes_count - tested_bytes);

		if (ssdfs_can_compress_data(page, portion_size))
			state = 1;
		else
			state = 0;

		can_compress[state]++;
		tested_bytes += portion_size;
	}

	return can_compress[true] >= can_compress[false];
}

/*
 * ssdfs_peb_define_area_type() - define area type
 * @pebi: pointer on PEB object
 * @bytes_count: bytes number in the portion
 * @start_page: starting page in pagevec
 * @page_count: count of pages in the portion
 * @req: I/O request
 * @desc_off: block descriptor offset
 * @pos: offset position
 * @area_type: type of area [out]
 */
static
int ssdfs_peb_define_area_type(struct ssdfs_peb_info *pebi,
				u32 bytes_count,
				u32 start_page, u32 page_count,
				struct ssdfs_segment_request *req,
				struct ssdfs_phys_offset_descriptor *desc_off,
				struct ssdfs_offset_position *pos,
				int *area_type)
{
	struct ssdfs_fs_info *fsi;
	bool can_be_compressed = false;
#ifdef CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA
	int err;
#endif /* CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA */

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !area_type);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, bytes_count %u, "
		  "start_page %u, page_count %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks,
		  bytes_count, start_page, page_count);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	*area_type = SSDFS_LOG_AREA_MAX;

	if (req->private.class == SSDFS_PEB_DIFF_ON_WRITE_REQ) {
		*area_type = SSDFS_LOG_DIFFS_AREA;
	} else if (!is_ssdfs_block_full(fsi->pagesize, bytes_count))
		*area_type = SSDFS_LOG_JOURNAL_AREA;
	else {
#ifdef CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA
		if (req->private.class == SSDFS_PEB_UPDATE_REQ) {
			err = ssdfs_user_data_prepare_diff(pebi->pebc,
							   desc_off,
							   pos, req);
		} else
			err = -ENOENT;

		if (err == -ENOENT) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to prepare user data diff: "
				  "seg %llu, peb %llu, ino %llu, "
				  "processed_blks %d, bytes_count %u, "
				  "start_page %u, page_count %u\n",
				  req->place.start.seg_id,
				  pebi->peb_id,
				  req->extent.ino,
				  req->result.processed_blks,
				  bytes_count, start_page,
				  page_count);
#endif /* CONFIG_SSDFS_DEBUG */

			can_be_compressed =
				can_ssdfs_pagevec_be_compressed(start_page,
								page_count,
								bytes_count,
								req);
			if (can_be_compressed)
				*area_type = SSDFS_LOG_DIFFS_AREA;
			else
				*area_type = SSDFS_LOG_MAIN_AREA;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to prepare user data diff: "
				  "seg %llu, peb %llu, ino %llu, "
				  "processed_blks %d, bytes_count %u, "
				  "start_page %u, page_count %u, err %d\n",
				  req->place.start.seg_id,
				  pebi->peb_id,
				  req->extent.ino,
				  req->result.processed_blks,
				  bytes_count, start_page,
				  page_count, err);
			return err;
		} else
			*area_type = SSDFS_LOG_DIFFS_AREA;
#else
		can_be_compressed = can_ssdfs_pagevec_be_compressed(start_page,
								    page_count,
								    bytes_count,
								    req);
		if (can_be_compressed)
			*area_type = SSDFS_LOG_DIFFS_AREA;
		else
			*area_type = SSDFS_LOG_MAIN_AREA;
#endif /* CONFIG_SSDFS_DIFF_ON_WRITE_USER_DATA */
	}

	return 0;
}

/*
 * ssdfs_peb_add_block_into_data_area() - try to add data block into log
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @desc_off: block descriptor offset
 * @pos: offset position
 * @off: PEB's physical offset to data [out]
 * @written_bytes: amount of written bytes [out]
 *
 * This function tries to add data block into data area (main, diff updates
 * or journal) of the log. If attempt to add data or block descriptor
 * has failed with %-EAGAIN error then it needs to return request into
 * head of the queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to store data block in current log.
 */
static
int ssdfs_peb_add_block_into_data_area(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_phys_offset_descriptor *desc_off,
				struct ssdfs_offset_position *pos,
				struct ssdfs_peb_phys_offset *off,
				u32 *written_bytes)
{
	struct ssdfs_fs_info *fsi;
	int area_type = SSDFS_LOG_AREA_MAX;
	u32 rest_bytes;
	u32 start_page = 0;
	u32 page_count = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !off);
	BUG_ON(req->extent.data_bytes <
		(req->result.processed_blks *
			pebi->pebc->parent_si->fsi->pagesize));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	*written_bytes = 0;
	rest_bytes = ssdfs_request_rest_bytes(pebi, req);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, rest_bytes %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks,
		  rest_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	if (req->private.class == SSDFS_PEB_DIFF_ON_WRITE_REQ) {
		start_page = req->result.processed_blks;
		rest_bytes = PAGE_SIZE;
		page_count = 1;
	} else if (fsi->pagesize < PAGE_SIZE) {
		start_page = req->result.processed_blks << fsi->log_pagesize;
		start_page >>= PAGE_SHIFT;
		rest_bytes = min_t(u32, rest_bytes, PAGE_SIZE);
		page_count = rest_bytes + PAGE_SIZE - 1;
		page_count >>= PAGE_SHIFT;
	} else {
		start_page = req->result.processed_blks << fsi->log_pagesize;
		start_page >>= PAGE_SHIFT;
		rest_bytes = min_t(u32, rest_bytes, fsi->pagesize);
		page_count = rest_bytes + PAGE_SIZE - 1;
		page_count >>= PAGE_SHIFT;
	}

	err = ssdfs_peb_define_area_type(pebi, rest_bytes,
					 start_page, page_count,
					 req, desc_off, pos, &area_type);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define area type: "
			  "rest_bytes %u, start_page %u, "
			  "page_count %u, err %d\n",
			  rest_bytes, start_page,
			  page_count, err);
		return err;
	}

	for (i = 0; i < page_count; i++) {
		int page_index = i + start_page;
		u32 start_offset = page_index << PAGE_SHIFT;
		u32 portion_size = PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(*written_bytes >= rest_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		portion_size = min_t(u32, portion_size,
					  rest_bytes - *written_bytes);

		switch (area_type) {
		case SSDFS_LOG_JOURNAL_AREA:
			err = ssdfs_peb_store_in_journal_area(pebi, req,
							      start_offset,
							      portion_size,
							      off);
			break;

		case SSDFS_LOG_DIFFS_AREA:
			err = ssdfs_peb_store_in_diff_area(pebi, req,
							   start_offset,
							   portion_size,
							   off);
			break;

		case SSDFS_LOG_MAIN_AREA:
			err = ssdfs_peb_store_in_main_area(pebi, req,
							   start_offset,
							   portion_size,
							   off);
			break;

		default:
			BUG();
		}

		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to add page into current log: "
				  "index %d, portion_size %u\n",
				  page_index, portion_size);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to add page into current log: "
				  "index %d, portion_size %u\n",
				  page_index, portion_size);
#endif /* CONFIG_SSDFS_DEBUG */
			return -EAGAIN;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add page: "
				  "index %d, portion_size %u, err %d\n",
				  page_index, portion_size, err);
			return err;
		}

		*written_bytes += portion_size;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("written_bytes %u\n", *written_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * need_reserve_free_space() - check necessuty to reserve free space
 * @pebi: pointer on PEB object
 * @area_type: area type
 * @fragment_size: size of fragment
 *
 * This function checks that it needs to reserve free space.
 */
static
bool need_reserve_free_space(struct ssdfs_peb_info *pebi,
			     int area_type,
			     u32 fragment_size)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_page_array *area_pages;
	bool is_space_enough, is_page_available;
	u32 write_offset;
	pgoff_t page_index;
	unsigned long pages_count;
	struct page *page;
	struct ssdfs_peb_area_metadata *metadata;
	u32 free_space = 0;
	u16 flags;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(fragment_size == 0);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("area_type %#x, fragment_size %u\n",
		  area_type, fragment_size);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	switch (area_type) {
	case SSDFS_LOG_BLK_DESC_AREA:
		flags = fsi->metadata_options.blk2off_tbl.flags;
		if (flags & SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION) {
			/*
			 * continue logic
			 */
		} else
			return has_current_page_free_space(pebi, area_type,
							   fragment_size);
		break;

	default:
		return has_current_page_free_space(pebi, area_type,
						   fragment_size);
	}

	write_offset = pebi->current_log.area[area_type].write_offset;
	page_index = write_offset / PAGE_SIZE;

	down_read(&pebi->current_log.area[area_type].array.lock);
	pages_count = pebi->current_log.area[area_type].array.pages_count;
	up_read(&pebi->current_log.area[area_type].array.lock);

	if (page_index < pages_count)
		free_space += PAGE_SIZE - (write_offset % PAGE_SIZE);

	metadata = &pebi->current_log.area[area_type].metadata;
	write_offset = metadata->area.blk_desc.flush_buf.write_offset;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("write_offset %u, free_space %u\n",
		  write_offset, free_space);
#endif /* CONFIG_SSDFS_DEBUG */

	is_space_enough = (write_offset / 2) < free_space;

	write_offset = pebi->current_log.area[area_type].write_offset;

	page_index = write_offset >> PAGE_SHIFT;
	area_pages = &pebi->current_log.area[area_type].array;
	page = ssdfs_page_array_get_page(area_pages, page_index);
	if (IS_ERR_OR_NULL(page))
		is_page_available = false;
	else {
		is_page_available = true;
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return is_space_enough && is_page_available;
}

/*
 * ssdfs_peb_reserve_block_descriptor() - reserve block descriptor space
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to reserve space for block descriptor in
 * block descriptor area. If attempt to add data or block descriptor
 * has failed with %-EAGAIN error then it needs to return request into
 * head of the queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to reserve block descriptor in current log.
 */
static
int ssdfs_peb_reserve_block_descriptor(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area_metadata *metadata;
	struct ssdfs_area_block_table *table;
	int items_count, capacity;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	u16 flags;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!req);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("ino %llu, logical_offset %llu, processed_blks %d\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	flags = fsi->metadata_options.blk2off_tbl.flags;

	metadata = &pebi->current_log.area[area_type].metadata;
	table = &metadata->area.blk_desc.table;

	items_count = metadata->area.blk_desc.items_count;
	capacity = metadata->area.blk_desc.capacity;

	if (items_count > capacity) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("items_count %d > capacity %d\n",
			  items_count, capacity);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("items_count %d, capacity %d\n",
			  items_count, capacity);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	if (flags & SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION) {
		if (need_reserve_free_space(pebi, area_type,
					    blk_desc_size)) {
			err = ssdfs_peb_grow_log_area(pebi, area_type,
						      blk_desc_size);
			if (err == -ENOSPC) {
				SSDFS_DBG("log is full\n");
				return -EAGAIN;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to grow log area: "
					  "type %#x, err %d\n",
					  area_type, err);
				return err;
			}
		}
	} else {
		if (!has_current_page_free_space(pebi, area_type,
						 blk_desc_size)) {
			err = ssdfs_peb_grow_log_area(pebi, area_type,
						      blk_desc_size);
			if (err == -ENOSPC) {
				SSDFS_DBG("log is full\n");
				return -EAGAIN;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to grow log area: "
					  "type %#x, err %d\n",
					  area_type, err);
				return err;
			}
		}
	}

	metadata->area.blk_desc.items_count++;

	return 0;
}

/*
 * ssdfs_peb_init_block_descriptor_state() - init block descriptor's state
 * @pebi: pointer on PEB object
 * @data: data offset inside PEB
 * @state: block descriptor's state [out]
 *
 * This function initializes a state of block descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - corrupted block descriptor.
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_peb_init_block_descriptor_state(struct ssdfs_peb_info *pebi,
					  struct ssdfs_peb_phys_offset *data,
					  struct ssdfs_blk_state_offset *state)
{
	int id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !data || !state);
#endif /* CONFIG_SSDFS_DEBUG */

	state->log_start_page = cpu_to_le16(pebi->current_log.start_page);
	state->log_area = data->log_area;
	state->byte_offset = cpu_to_le32(data->byte_offset);

	id = ssdfs_get_peb_migration_id_checked(pebi);
	if (unlikely(id < 0)) {
		SSDFS_ERR("invalid peb_migration_id: "
			  "seg %llu, peb_id %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, id);
		return id;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(id > U8_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	state->peb_migration_id = (u8)id;

	return 0;
}

/*
 * ssdfs_peb_prepare_block_descriptor() - prepare new state of block descriptor
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @data: data offset inside PEB
 * @desc: block descriptor [out]
 *
 * This function prepares new state of block descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - corrupted block descriptor.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_prepare_block_descriptor(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_peb_phys_offset *data,
				struct ssdfs_block_descriptor *desc)
{
	u64 logical_offset;
	u32 pagesize;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !desc || !data);
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);

	SSDFS_DBG("ino %llu, logical_offset %llu, processed_blks %d\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	pagesize = pebi->pebc->parent_si->fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(req->result.processed_blks > req->place.len);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_offset = req->extent.logical_offset +
			 (req->result.processed_blks * pagesize);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_offset >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_offset /= pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	DEBUG_BLOCK_DESCRIPTOR(pebi->pebc->parent_si->seg_id,
				pebi->peb_id, desc);
#endif /* CONFIG_SSDFS_DEBUG */

	i = 0;

	do {
		if (IS_SSDFS_BLK_STATE_OFFSET_INVALID(&desc->state[i]))
			break;
		else
			i++;
	} while (i < SSDFS_BLK_STATE_OFF_MAX);

	if (i == 0) {
		/* empty block descriptor */
		desc->ino = cpu_to_le64(req->extent.ino);
		desc->logical_offset = cpu_to_le32((u32)logical_offset);
		desc->peb_index = cpu_to_le16(data->peb_index);
		desc->peb_page = cpu_to_le16(data->peb_page);

		err = ssdfs_peb_init_block_descriptor_state(pebi, data,
							    &desc->state[0]);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init block descriptor state: "
				  "err %d\n", err);
			return err;
		}
	} else if (i >= SSDFS_BLK_STATE_OFF_MAX) {
		SSDFS_WARN("block descriptor is exhausted: "
			   "seg_id %llu, peb_id %llu, "
			   "ino %llu, logical_offset %llu\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   req->extent.ino,
			   req->extent.logical_offset);
		return -ERANGE;
	} else {
		if (le64_to_cpu(desc->ino) != req->extent.ino) {
			SSDFS_ERR("corrupted block state: "
				  "ino1 %llu != ino2 %llu\n",
				  le64_to_cpu(desc->ino),
				  req->extent.ino);
			return -EIO;
		}

		if (le32_to_cpu(desc->logical_offset) != logical_offset) {
			SSDFS_ERR("corrupted block state: "
				  "logical_offset1 %u != logical_offset2 %llu\n",
				  le32_to_cpu(desc->logical_offset),
				  logical_offset);
			return -EIO;
		}

		if (le16_to_cpu(desc->peb_index) != data->peb_index) {
			SSDFS_ERR("corrupted block state: "
				  "peb_index1 %u != peb_index2 %u\n",
				  le16_to_cpu(desc->peb_index),
				  data->peb_index);
			return -EIO;
		}

		if (le16_to_cpu(desc->peb_page) != data->peb_page) {
			SSDFS_ERR("corrupted block state: "
				  "peb_page1 %u != peb_page2 %u\n",
				  le16_to_cpu(desc->peb_page),
				  data->peb_page);
			return -EIO;
		}

		err = ssdfs_peb_init_block_descriptor_state(pebi, data,
							    &desc->state[i]);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init block descriptor state: "
				  "err %d\n", err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	DEBUG_BLOCK_DESCRIPTOR(pebi->pebc->parent_si->seg_id,
				pebi->peb_id, desc);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_peb_write_block_descriptor() - write block descriptor into area
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @desc: block descriptor
 * @data_off: offset to data in PEB [in]
 * @off: block descriptor offset in PEB [out]
 * @write_offset: write offset for written block descriptor [out]
 *
 * This function tries to write block descriptor into dedicated area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-E2BIG      - buffer is full.
 */
static
int ssdfs_peb_write_block_descriptor(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_block_descriptor *desc,
					struct ssdfs_peb_phys_offset *data_off,
					struct ssdfs_peb_phys_offset *off,
					u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area *area;
	struct ssdfs_peb_area_metadata *metadata;
	struct ssdfs_peb_temp_buffer *buf;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	struct page *page;
	pgoff_t page_index;
	u32 page_off;
	int id;
	int items_count, capacity;
	u16 flags;
	bool is_buffer_full = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req || !desc || !off || !write_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("ino %llu, logical_offset %llu, processed_blks %d\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	flags = fsi->metadata_options.blk2off_tbl.flags;

	area = &pebi->current_log.area[area_type];
	metadata = &area->metadata;
	items_count = metadata->area.blk_desc.items_count;
	capacity = metadata->area.blk_desc.capacity;

	if (items_count < 1) {
		SSDFS_ERR("block descriptor is not reserved\n");
		return -ERANGE;
	}

	*write_offset = ssdfs_peb_correct_area_write_offset(area->write_offset,
							    blk_desc_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area->write_offset %u, write_offset %u\n",
		  area->write_offset, *write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	if (flags & SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION) {
		buf = &metadata->area.blk_desc.flush_buf;

#ifdef CONFIG_SSDFS_DEBUG
		if (buf->write_offset % blk_desc_size) {
			SSDFS_ERR("invalid write_offset %u\n",
				  buf->write_offset);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		if ((buf->write_offset + buf->granularity) > buf->size) {
			SSDFS_ERR("buffer is full: "
				  "write_offset %u, granularity %zu, "
				  "size %zu\n",
				  buf->write_offset,
				  buf->granularity,
				  buf->size);

			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!buf->ptr);

		if (buf->granularity != blk_desc_size) {
			SSDFS_ERR("invalid granularity: "
				  "granularity %zu, item_size %zu\n",
				  buf->granularity, blk_desc_size);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_memcpy(buf->ptr, buf->write_offset, buf->size,
				   desc, 0, blk_desc_size,
				   blk_desc_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "write_offset %u, blk_desc_size %zu, "
				  "err %d\n",
				  buf->write_offset, blk_desc_size, err);
			return err;
		}

		buf->write_offset += blk_desc_size;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("buf->write_offset %u, buf->size %zu\n",
			  buf->write_offset, buf->size);
#endif /* CONFIG_SSDFS_DEBUG */

		if (buf->write_offset == buf->size) {
			err = ssdfs_peb_realloc_write_buffer(buf);
			if (err == -E2BIG) {
				err = 0;

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("buffer is full: "
					  "write_offset %u, size %zu\n",
					  buf->write_offset,
					  buf->size);
#endif /* CONFIG_SSDFS_DEBUG */

				is_buffer_full = true;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to reallocate buffer: "
					  "err %d\n", err);
				return err;
			}
		}
	} else {
		page_index = *write_offset / PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("area->write_offset %u, blk_desc_size %zu, "
			  "write_offset %u, page_index %lu\n",
			  area->write_offset, blk_desc_size,
			  *write_offset, page_index);
#endif /* CONFIG_SSDFS_DEBUG */

		page = ssdfs_page_array_grab_page(&area->array, page_index);
		if (IS_ERR_OR_NULL(page)) {
			SSDFS_ERR("fail to get page %lu for area %#x\n",
				  page_index, area_type);
			return -ERANGE;
		}

		page_off = *write_offset % PAGE_SIZE;

		err = ssdfs_memcpy_to_page(page, page_off, PAGE_SIZE,
					   desc, 0, blk_desc_size,
					   blk_desc_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "page_off %u, blk_desc_size %zu, err %d\n",
				  page_off, blk_desc_size, err);
			goto finish_copy;
		}

		SetPageUptodate(page);

		err = ssdfs_page_array_set_page_dirty(&area->array,
							page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: "
				  "err %d\n",
				  page_index, err);
		}

finish_copy:
		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		if (unlikely(err))
			return err;
	}

	id = ssdfs_get_peb_migration_id_checked(pebi);
	if (unlikely(id < 0)) {
		SSDFS_ERR("invalid peb_migration_id: "
			  "seg %llu, peb_id %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, id);
		return id;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(id > U8_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	/* Prepare block descriptor's offset in PEB */
	off->peb_index = pebi->peb_index;
	off->peb_migration_id = (u8)id;
	off->peb_page = data_off->peb_page;
	off->log_area = area_type;
	off->byte_offset = *write_offset;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, peb_id %llu, "
		  "peb_index %u, peb_page %u, "
		  "log_area %#x, byte_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  le16_to_cpu(off->peb_index),
		  le16_to_cpu(off->peb_page),
		  off->log_area,
		  le32_to_cpu(off->byte_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	area->write_offset = *write_offset + blk_desc_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area->write_offset %u, write_offset %u\n",
		  area->write_offset, *write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_buffer_full)
		return -E2BIG;

	return 0;
}

/*
 * ssdfs_peb_compress_blk_desc_fragment_in_place() - compress fragment in place
 * @pebi: pointer on PEB object
 * @uncompr_size: uncompressed size
 * @compr_size: compressed size of data [out]
 *
 * This method tries to compressed data directly into destination
 * page. If available space is not enough, then method returns error.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOENT     - memory page is not available.
 * %-E2BIG      - available space is not enough for compression.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_compress_blk_desc_fragment_in_place(struct ssdfs_peb_info *pebi,
						  size_t uncompr_size,
						  size_t *compr_size)
{
	struct ssdfs_fs_info *fsi;
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area *area;
	struct ssdfs_peb_temp_buffer *buf;
	struct page *page;
	pgoff_t page_index;
	unsigned char *kaddr;
	u32 page_off;
	u8 compr_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !compr_size);

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "uncompr_size %zu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  pebi->current_log.start_page,
		  uncompr_size);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];
	buf = &area->metadata.area.blk_desc.flush_buf;

	if (uncompr_size > buf->size) {
		SSDFS_ERR("uncompr_size %zu > buf->size %zu\n",
			  uncompr_size, buf->size);
		return -ERANGE;
	}

	switch (fsi->metadata_options.blk2off_tbl.compression) {
	case SSDFS_BLK2OFF_TBL_NOCOMPR_TYPE:
		compr_type = SSDFS_COMPR_NONE;
		break;
	case SSDFS_BLK2OFF_TBL_ZLIB_COMPR_TYPE:
		compr_type = SSDFS_COMPR_ZLIB;
		break;
	case SSDFS_BLK2OFF_TBL_LZO_COMPR_TYPE:
		compr_type = SSDFS_COMPR_LZO;
		break;
	default:
		BUG();
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!buf->ptr);

	SSDFS_DBG("BUF DUMP: size %zu\n",
		  buf->size);
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     buf->ptr,
			     buf->size);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	page_index = area->compressed_offset / PAGE_SIZE;

	page = ssdfs_page_array_grab_page(&area->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get page %lu for area %#x\n",
			  page_index, area_type);
		return -ERANGE;
	}

	page_off = area->compressed_offset % PAGE_SIZE;
	*compr_size = PAGE_SIZE - page_off;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area->compressed_offset %u, page_index %lu, "
		  "page_off %u, compr_size %zu\n",
		  area->compressed_offset, page_index,
		  page_off, *compr_size);
#endif /* CONFIG_SSDFS_DEBUG */

	kaddr = kmap_local_page(page);
	err = ssdfs_compress(compr_type,
			     buf->ptr, (u8 *)kaddr + page_off,
			     &uncompr_size, compr_size);
	flush_dcache_page(page);
	kunmap_local(kaddr);

	if (err == -E2BIG) {
		*compr_size = uncompr_size;
		SSDFS_DBG("unable to compress fragment in place: "
			  "uncompr_size %zu\n",
			  uncompr_size);
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to compress fragment in place: "
			  "uncompr_size %zu, err %d\n",
			  uncompr_size, err);
	} else {
		ssdfs_set_page_private(page, 0);
		SetPageUptodate(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("area->compressed_offset %u, page_index %lu, "
			  "page_off %u, compr_size %zu\n",
			  area->compressed_offset, page_index,
			  page_off, *compr_size);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_page_array_set_page_dirty(&area->array,
							page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: "
				  "err %d\n",
				  page_index, err);
		}
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * __ssdfs_peb_copy_blob_into_page_cache() - copy blob into page cache
 * @pebi: pointer on PEB object
 * @blob: pointer on blob buffer
 * @blob_size: blob size in bytes
 * @copied_len: really copied length [out]
 *
 * This method tries to store blob into page cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_peb_copy_blob_into_page_cache(struct ssdfs_peb_info *pebi,
					  void *blob, size_t blob_size,
					  size_t *copied_len)
{
	struct ssdfs_fs_info *fsi;
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area *area;
	struct page *page;
	u32 offset;
	pgoff_t page_index;
	u32 page_off;
	size_t copy_len;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !blob || !copied_len);

	SSDFS_DBG("peb %llu, current_log.start_page %u, "
		  "blob_size %zu, copied_len %zu\n",
		  pebi->peb_id,
		  pebi->current_log.start_page,
		  blob_size, *copied_len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (*copied_len >= blob_size) {
		SSDFS_ERR("copied_len %zu >= blob_size %zu\n",
			  *copied_len, blob_size);
		return -ERANGE;
	}

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];

	offset = area->compressed_offset + *copied_len;
	page_index = offset / PAGE_SIZE;

	page = ssdfs_page_array_grab_page(&area->array, page_index);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get page %lu for area %#x\n",
			  page_index, area_type);
		return -ERANGE;
	}

	page_off = offset % PAGE_SIZE;

	copy_len = PAGE_SIZE - page_off;
	copy_len = min_t(size_t, copy_len, blob_size - *copied_len);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area->compressed_offset %u, offset %u, "
		  "page_index %lu, page_off %u, copy_len %zu\n",
		  area->compressed_offset, offset, page_index,
		  page_off, copy_len);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_memcpy_to_page(page, page_off, PAGE_SIZE,
				   blob, *copied_len, PAGE_SIZE,
				   copy_len);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: err %d\n", err);
		goto unlock_grabbed_page;
	}

	ssdfs_set_page_private(page, 0);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&area->array,
						page_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: "
			  "err %d\n",
			  page_index, err);
		goto unlock_grabbed_page;
	}

	*copied_len += copy_len;

	if (*copied_len != blob_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("not full blob has been copied: "
			  "*copied_len %zu, blob_size %zu\n",
			  *copied_len, blob_size);
#endif /* CONFIG_SSDFS_DEBUG */
		err = -EAGAIN;
	}

unlock_grabbed_page:
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_peb_copy_blob_into_page_cache() - copy blob into page cache
 * @pebi: pointer on PEB object
 * @blob: pointer on blob buffer
 * @blob_size: blob size in bytes
 *
 * This method tries to store blob into page cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_copy_blob_into_page_cache(struct ssdfs_peb_info *pebi,
					void *blob, size_t blob_size)
{
	size_t copied_len = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !blob);

	SSDFS_DBG("peb %llu, current_log.start_page %u, "
		  "blob_size %zu\n",
		  pebi->peb_id,
		  pebi->current_log.start_page,
		  blob_size);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_peb_copy_blob_into_page_cache(pebi,
						    blob,
						    blob_size,
						    &copied_len);
	if (err == -EAGAIN) {
		if (copied_len >= blob_size) {
			SSDFS_ERR("invalid result: "
				  "copied_len %zu >= blob_size %zu\n",
				  copied_len, blob_size);
			return -ERANGE;
		}

		err = __ssdfs_peb_copy_blob_into_page_cache(pebi,
							    blob,
							    blob_size,
							    &copied_len);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy blob into page cache: "
				  "err %d\n", err);
			return err;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to copy blob into page cache: "
			  "err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_compress_blk_desc_fragment_in_buffer() - compress fragment in buffer
 * @pebi: pointer on PEB object
 * @uncompr_size: uncompressed size
 * @compr_size: compressed size of data [out]
 *
 * This method allocates temporary buffer, compress data into
 * the buffer, and store the compressed data memory pages.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - unable to allocate memory.
 * %-ERANGE     - internal error.
 * %-E2BIG      - fragment is stored uncompressed.
 */
static
int ssdfs_peb_compress_blk_desc_fragment_in_buffer(struct ssdfs_peb_info *pebi,
						   size_t uncompr_size,
						   size_t *compr_size)
{
	struct ssdfs_fs_info *fsi;
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area *area;
	struct ssdfs_peb_temp_buffer *buf;
	u8 compr_type;
	void *compr_buf = NULL;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!uncompr_size || !compr_size);

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "uncompr_size %zu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  pebi->current_log.start_page,
		  uncompr_size);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];
	buf = &area->metadata.area.blk_desc.flush_buf;

	if (uncompr_size <= SSDFS_UNCOMPR_BLOB_UPPER_THRESHOLD) {
		err = ssdfs_peb_copy_blob_into_page_cache(pebi,
							  buf->ptr,
							  uncompr_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy blob into page cache: "
				  "err %d\n", err);
			return err;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("blob has been stored uncompressed: "
				  "size %zu\n", uncompr_size);
#endif /* CONFIG_SSDFS_DEBUG */
			*compr_size = uncompr_size;
			return -E2BIG;
		}
	}

	switch (fsi->metadata_options.blk2off_tbl.compression) {
	case SSDFS_BLK2OFF_TBL_NOCOMPR_TYPE:
		compr_type = SSDFS_COMPR_NONE;
		break;
	case SSDFS_BLK2OFF_TBL_ZLIB_COMPR_TYPE:
		compr_type = SSDFS_COMPR_ZLIB;
		break;
	case SSDFS_BLK2OFF_TBL_LZO_COMPR_TYPE:
		compr_type = SSDFS_COMPR_LZO;
		break;
	default:
		BUG();
	}

	compr_buf = ssdfs_flush_kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!compr_buf) {
		SSDFS_ERR("fail to allocate buffer\n");
		return -ENOMEM;
	}

	*compr_size = PAGE_SIZE;
	err = ssdfs_compress(compr_type,
			     buf->ptr, compr_buf,
			     &uncompr_size, compr_size);
	if (err == -E2BIG || err == -EOPNOTSUPP) {
		*compr_size = uncompr_size;
		err = ssdfs_peb_copy_blob_into_page_cache(pebi,
							  buf->ptr,
							  uncompr_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy blob into page cache: "
				  "err %d\n", err);
			goto free_compr_buf;
		} else {
			err = -E2BIG;
			*compr_size = uncompr_size;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("blob has been stored uncompressed: "
				  "size %zu\n", uncompr_size);
#endif /* CONFIG_SSDFS_DEBUG */
			goto free_compr_buf;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to compress fragment in buffer: "
			  "uncompr_size %zu, err %d\n",
			  uncompr_size, err);
		goto free_compr_buf;
	} else {
		err = ssdfs_peb_copy_blob_into_page_cache(pebi,
							  compr_buf,
							  *compr_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to copy blob into page cache: "
				  "err %d\n", err);
			goto free_compr_buf;
		}
	}

free_compr_buf:
	ssdfs_flush_kfree(compr_buf);

	return err;
}

/*
 * ssdfs_peb_compress_blk_descs_fragment() - compress block descriptor fragment
 * @pebi: pointer on PEB object
 * @uncompr_size: size of uncompressed fragment
 * @compr_size: size of compressed fragment [out]
 *
 * This function tries to compress block descriptor fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to get fragment descriptor.
 * %-E2BIG      - fragment is stored uncompressed.
 */
static
int ssdfs_peb_compress_blk_descs_fragment(struct ssdfs_peb_info *pebi,
					  size_t uncompr_size,
					  size_t *compr_size)
{
	struct ssdfs_fs_info *fsi;
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area *area;
	struct ssdfs_peb_temp_buffer *buf;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !compr_size);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];
	buf = &area->metadata.area.blk_desc.flush_buf;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, "
		  "compressed_offset %u, write_offset %u, "
		  "uncompr_size %zu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  area->compressed_offset,
		  area->write_offset,
		  uncompr_size);
#endif /* CONFIG_SSDFS_DEBUG */

	if (uncompr_size > buf->size) {
		SSDFS_ERR("uncompr_size %zu > buf->size %zu\n",
			  uncompr_size, buf->size);
		return -ERANGE;
	}

	err = ssdfs_peb_compress_blk_desc_fragment_in_place(pebi,
							    uncompr_size,
							    compr_size);
	if (err == -E2BIG) {
		err = ssdfs_peb_compress_blk_desc_fragment_in_buffer(pebi,
							    uncompr_size,
							    compr_size);
		if (err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment has been stored uncompressed: "
				  "size %zu\n", uncompr_size);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_fragment_compress;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to compress fragment: "
				  "uncompr_size %zu, "
				  "err %d\n",
				  uncompr_size,
				  err);
			goto finish_fragment_compress;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to compress fragment: "
			  "uncompr_size %zu, compr_size %zu, err %d\n",
			  uncompr_size, *compr_size, err);
		goto finish_fragment_compress;
	}

finish_fragment_compress:
	memset(buf->ptr, 0, buf->size);
	buf->write_offset = 0;

	return err;
}

/*
 * ssdfs_peb_store_compressed_block_descriptor() - store block descriptor
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @blk_desc: block descriptor
 * @data_off: offset to data in PEB [in]
 * @desc_off: offset to block descriptor in PEB [out]
 *
 * This function tries to compress and to store block descriptor
 * into dedicated area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to get fragment descriptor.
 */
static
int ssdfs_peb_store_compressed_block_descriptor(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_block_descriptor *blk_desc,
					struct ssdfs_peb_phys_offset *data_off,
					struct ssdfs_peb_phys_offset *desc_off)
{
	struct ssdfs_fs_info *fsi;
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area *area;
	struct ssdfs_peb_temp_buffer *buf;
	struct ssdfs_fragments_chain_header *chain_hdr;
	struct ssdfs_fragment_desc *meta_desc;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	u32 write_offset = 0;
	u32 old_offset;
	u16 bytes_count;
	u16 fragments_count;
	size_t compr_size = 0;
	u8 fragment_type = SSDFS_DATA_BLK_DESC;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req || !blk_desc || !data_off || !desc_off);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "logical_offset %llu, processed_blks %d\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];
	buf = &area->metadata.area.blk_desc.flush_buf;
	chain_hdr = &area->metadata.area.blk_desc.table.chain_hdr;
	fragments_count = le16_to_cpu(chain_hdr->fragments_count);

	switch (fsi->metadata_options.blk2off_tbl.compression) {
	case SSDFS_BLK2OFF_TBL_NOCOMPR_TYPE:
		fragment_type = SSDFS_DATA_BLK_DESC;
		break;
	case SSDFS_BLK2OFF_TBL_ZLIB_COMPR_TYPE:
		fragment_type = SSDFS_DATA_BLK_DESC_ZLIB;
		break;
	case SSDFS_BLK2OFF_TBL_LZO_COMPR_TYPE:
		fragment_type = SSDFS_DATA_BLK_DESC_LZO;
		break;
	default:
		BUG();
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fragments_count %u, fragment_type %#x\n",
		  fragments_count, fragment_type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fragments_count == 0) {
		meta_desc = ssdfs_peb_get_area_free_frag_desc(pebi, area_type);
		if (IS_ERR(meta_desc)) {
			SSDFS_ERR("fail to get current fragment descriptor: "
				  "err %d\n",
				  (int)PTR_ERR(meta_desc));
			return PTR_ERR(meta_desc);
		} else if (!meta_desc) {
			err = -ERANGE;
			SSDFS_ERR("fail to get current fragment descriptor: "
				  "err %d\n",
				  err);
			return err;
		}

		meta_desc->magic = SSDFS_FRAGMENT_DESC_MAGIC;
		meta_desc->type = fragment_type;
		meta_desc->flags = SSDFS_FRAGMENT_HAS_CSUM;
		meta_desc->offset = cpu_to_le32(area->compressed_offset);
		meta_desc->checksum = 0;
	} else if (fragments_count == SSDFS_BLK_TABLE_MAX) {
		err = ssdfs_peb_store_area_block_table(pebi, area_type,
						SSDFS_MULTIPLE_HDR_CHAIN);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store area's block table: "
				  "area %#x, err %d\n",
				  area_type, err);
			return err;
		}

		err = ssdfs_peb_allocate_area_block_table(pebi, area_type);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log is full, "
				  "unable to add next fragments chain: "
				  "area %#x\n",
				  area_type);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add next fragments chain: "
				  "area %#x\n",
				  area_type);
			return err;
		}

		meta_desc = ssdfs_peb_get_area_free_frag_desc(pebi, area_type);
		if (IS_ERR(meta_desc)) {
			SSDFS_ERR("fail to get current fragment descriptor: "
				  "err %d\n",
				  (int)PTR_ERR(meta_desc));
			return PTR_ERR(meta_desc);
		} else if (!meta_desc) {
			err = -ERANGE;
			SSDFS_ERR("fail to get current fragment descriptor: "
				  "err %d\n",
				  err);
			return err;
		}

		meta_desc->offset = cpu_to_le32(area->compressed_offset);
		meta_desc->compr_size = cpu_to_le16(0);
		meta_desc->uncompr_size = cpu_to_le16(0);
		meta_desc->checksum = 0;

		if (area->metadata.sequence_id == U8_MAX)
			area->metadata.sequence_id = 0;

		meta_desc->sequence_id = area->metadata.sequence_id++;

		meta_desc->magic = SSDFS_FRAGMENT_DESC_MAGIC;
		meta_desc->type = fragment_type;
		meta_desc->flags = SSDFS_FRAGMENT_HAS_CSUM;
	} else {
		meta_desc = ssdfs_peb_get_area_cur_frag_desc(pebi,
							     area_type);
		if (IS_ERR(meta_desc)) {
			SSDFS_ERR("fail to get current fragment descriptor: "
				  "err %d\n",
				  (int)PTR_ERR(meta_desc));
			return PTR_ERR(meta_desc);
		} else if (!meta_desc) {
			err = -ERANGE;
			SSDFS_ERR("fail to get current fragment descriptor: "
				  "err %d\n",
				  err);
			return err;
		}
	}

	old_offset = le32_to_cpu(meta_desc->offset);
	bytes_count = le16_to_cpu(meta_desc->uncompr_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("old_offset %u, bytes_count %u\n",
		  old_offset, bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_prepare_block_descriptor(pebi, req, data_off,
						 blk_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare block descriptor: "
			  "ino %llu, logical_offset %llu, "
			  "processed_blks %d, err %d\n",
			  req->extent.ino, req->extent.logical_offset,
			  req->result.processed_blks, err);
		return err;
	}

	err = ssdfs_peb_write_block_descriptor(pebi, req, blk_desc,
						data_off, desc_off,
						&write_offset);
	if (err == -E2BIG) {
		/*
		 * continue logic
		 */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to write block descriptor: "
			  "ino %llu, logical_offset %llu, "
			  "processed_blks %d, err %d\n",
			  req->extent.ino, req->extent.logical_offset,
			  req->result.processed_blks, err);
		return err;
	}

	bytes_count += blk_desc_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("bytes_count %u\n",
		  bytes_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (err == -E2BIG) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!buf->ptr);

		if (buf->write_offset != buf->size) {
			SSDFS_ERR("invalid request: "
				  "buf->write_offset %u, buf->size %zu\n",
				  buf->write_offset, buf->size);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		if (bytes_count > buf->size) {
			SSDFS_ERR("invalid size: "
				  "bytes_count %u > buf->size %zu\n",
				  bytes_count, buf->size);
			return -ERANGE;
		}

		meta_desc->checksum = ssdfs_crc32_le(buf->ptr, bytes_count);

		if (le32_to_cpu(meta_desc->checksum) == 0) {
			SSDFS_WARN("checksum is invalid: "
				   "seg %llu, peb %llu, ino %llu, "
				   "logical_offset %llu, processed_blks %d, "
				   "bytes_count %u\n",
				   pebi->pebc->parent_si->seg_id,
				   pebi->peb_id,
				   req->extent.ino,
				   req->extent.logical_offset,
				   req->result.processed_blks,
				   bytes_count);
			return -ERANGE;
		}

		err = ssdfs_peb_compress_blk_descs_fragment(pebi,
							    bytes_count,
							    &compr_size);
		if (err == -E2BIG) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment has been stored uncompressed: "
				  "size %zu\n", compr_size);
#endif /* CONFIG_SSDFS_DEBUG */
			compr_size = bytes_count;
			meta_desc->type = SSDFS_DATA_BLK_DESC;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to compress blk desc fragment: "
				  "err %d\n", err);
			return err;
		}

		meta_desc->offset = cpu_to_le32(area->compressed_offset);

#ifdef CONFIG_SSDFS_DEBUG
		WARN_ON(compr_size > U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
		meta_desc->compr_size = cpu_to_le16((u16)compr_size);

#ifdef CONFIG_SSDFS_DEBUG
		WARN_ON(bytes_count > U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
		meta_desc->uncompr_size = cpu_to_le16((u16)bytes_count);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("offset %u, compr_size %u, "
			  "uncompr_size %u, checksum %#x\n",
			  le32_to_cpu(meta_desc->offset),
			  le16_to_cpu(meta_desc->compr_size),
			  le16_to_cpu(meta_desc->uncompr_size),
			  le32_to_cpu(meta_desc->checksum));
#endif /* CONFIG_SSDFS_DEBUG */

		area->compressed_offset += compr_size;
		le32_add_cpu(&chain_hdr->compr_bytes, compr_size);

		meta_desc = ssdfs_peb_get_area_free_frag_desc(pebi, area_type);
		if (IS_ERR(meta_desc)) {
			SSDFS_ERR("fail to get vacant fragment descriptor: "
				  "err %d\n",
				  (int)PTR_ERR(meta_desc));
			return PTR_ERR(meta_desc);
		} else if (!meta_desc) {
			SSDFS_ERR("fail to get fragment descriptor: "
				  "area_type %#x\n",
				  area_type);
			return -ERANGE;
		}

		meta_desc->offset = cpu_to_le32(area->compressed_offset);
		meta_desc->compr_size = cpu_to_le16(0);
		meta_desc->uncompr_size = cpu_to_le16(0);
		meta_desc->checksum = 0;

		if (area->metadata.sequence_id == U8_MAX)
			area->metadata.sequence_id = 0;

		meta_desc->sequence_id = area->metadata.sequence_id++;

		meta_desc->magic = SSDFS_FRAGMENT_DESC_MAGIC;
		meta_desc->type = fragment_type;
		meta_desc->flags = SSDFS_FRAGMENT_HAS_CSUM;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("old_offset %u, write_offset %u, bytes_count %u\n",
			  old_offset, area->compressed_offset, bytes_count);
		SSDFS_DBG("fragments_count %u, fragment (offset %u, "
			  "compr_size %u, sequence_id %u, type %#x)\n",
			  le16_to_cpu(chain_hdr->fragments_count),
			  le32_to_cpu(meta_desc->offset),
			  le16_to_cpu(meta_desc->compr_size),
			  meta_desc->sequence_id,
			  meta_desc->type);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
		BUG_ON(bytes_count >= U16_MAX);

		meta_desc->uncompr_size = cpu_to_le16((u16)bytes_count);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("old_offset %u, write_offset %u, bytes_count %u\n",
			  old_offset, write_offset, bytes_count);
		SSDFS_DBG("fragments_count %u, fragment (offset %u, "
			  "uncompr_size %u, sequence_id %u, type %#x)\n",
			  le16_to_cpu(chain_hdr->fragments_count),
			  le32_to_cpu(meta_desc->offset),
			  le16_to_cpu(meta_desc->uncompr_size),
			  meta_desc->sequence_id,
			  meta_desc->type);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	le32_add_cpu(&chain_hdr->uncompr_bytes, (u32)blk_desc_size);

	return 0;
}

/*
 * __ssdfs_peb_store_block_descriptor() - store block descriptor into area
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @blk_desc: block descriptor
 * @data_off: offset to data in PEB [in]
 * @desc_off: offset to block descriptor in PEB [out]
 *
 * This function tries to store block descriptor into dedicated area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to get fragment descriptor.
 */
static
int __ssdfs_peb_store_block_descriptor(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_block_descriptor *blk_desc,
				struct ssdfs_peb_phys_offset *data_off,
				struct ssdfs_peb_phys_offset *desc_off)
{
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area *area;
	struct ssdfs_fragments_chain_header *chain_hdr;
	struct ssdfs_fragment_desc *meta_desc;
	u32 write_offset, old_offset;
	u32 old_page_index, new_page_index;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	u16 bytes_count;
	u16 fragments_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req || !blk_desc || !data_off || !desc_off);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "logical_offset %llu, processed_blks %d\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	area = &pebi->current_log.area[area_type];
	chain_hdr = &area->metadata.area.blk_desc.table.chain_hdr;
	fragments_count = le16_to_cpu(chain_hdr->fragments_count);

	if (fragments_count == 0) {
		meta_desc = ssdfs_peb_get_area_free_frag_desc(pebi, area_type);
		if (IS_ERR(meta_desc)) {
			SSDFS_ERR("fail to get current fragment descriptor: "
				  "err %d\n",
				  (int)PTR_ERR(meta_desc));
			return PTR_ERR(meta_desc);
		} else if (!meta_desc) {
			err = -ERANGE;
			SSDFS_ERR("fail to get current fragment descriptor: "
				  "err %d\n",
				  err);
			return err;
		}

		meta_desc->magic = SSDFS_FRAGMENT_DESC_MAGIC;
		meta_desc->type = SSDFS_DATA_BLK_DESC;
		meta_desc->flags = 0;
		meta_desc->offset = cpu_to_le32(area->write_offset);
		meta_desc->checksum = 0;
	} else {
		meta_desc = ssdfs_peb_get_area_cur_frag_desc(pebi, area_type);
		if (IS_ERR(meta_desc)) {
			SSDFS_ERR("fail to get current fragment descriptor: "
				  "err %d\n",
				  (int)PTR_ERR(meta_desc));
			return PTR_ERR(meta_desc);
		} else if (!meta_desc) {
			err = -ERANGE;
			SSDFS_ERR("fail to get current fragment descriptor: "
				  "err %d\n",
				  err);
			return err;
		}
	}

	old_offset = le32_to_cpu(meta_desc->offset);
	old_page_index = old_offset / PAGE_SIZE;
	new_page_index = area->write_offset / PAGE_SIZE;
	bytes_count = le16_to_cpu(meta_desc->compr_size);

	if (old_page_index != new_page_index &&
	    fragments_count == SSDFS_NEXT_BLK_TABLE_INDEX) {
		err = ssdfs_peb_store_area_block_table(pebi, area_type,
						SSDFS_MULTIPLE_HDR_CHAIN);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store area's block table: "
				  "area %#x, err %d\n",
				  area_type, err);
			return err;
		}

		err = ssdfs_peb_allocate_area_block_table(pebi,
							  area_type);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log is full, "
				  "unable to add next fragments chain: "
				  "area %#x\n",
				  area_type);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add next fragments chain: "
				  "area %#x\n",
				  area_type);
			return err;
		}
	}

	err = ssdfs_peb_prepare_block_descriptor(pebi, req, data_off,
						 blk_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare block descriptor: "
			  "ino %llu, logical_offset %llu, "
			  "processed_blks %d, err %d\n",
			  req->extent.ino, req->extent.logical_offset,
			  req->result.processed_blks, err);
		return err;
	}

	err = ssdfs_peb_write_block_descriptor(pebi, req, blk_desc,
						data_off, desc_off,
						&write_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to write block descriptor: "
			  "ino %llu, logical_offset %llu, "
			  "processed_blks %d, err %d\n",
			  req->extent.ino, req->extent.logical_offset,
			  req->result.processed_blks, err);
		return err;
	}

	new_page_index = write_offset / PAGE_SIZE;

	if (old_page_index == new_page_index) {
		bytes_count += blk_desc_size;

		BUG_ON(bytes_count >= U16_MAX);

		meta_desc->compr_size = cpu_to_le16((u16)bytes_count);
		meta_desc->uncompr_size = cpu_to_le16((u16)bytes_count);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("old_offset %u, write_offset %u, bytes_count %u\n",
			  old_offset, write_offset, bytes_count);
		SSDFS_DBG("fragments_count %u, fragment (offset %u, "
			  "compr_size %u, sequence_id %u, type %#x)\n",
			  le16_to_cpu(chain_hdr->fragments_count),
			  le32_to_cpu(meta_desc->offset),
			  le16_to_cpu(meta_desc->compr_size),
			  meta_desc->sequence_id,
			  meta_desc->type);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
		meta_desc = ssdfs_peb_get_area_free_frag_desc(pebi, area_type);
		if (IS_ERR(meta_desc)) {
			SSDFS_ERR("fail to get vacant fragment descriptor: "
				  "err %d\n",
				  (int)PTR_ERR(meta_desc));
			return PTR_ERR(meta_desc);
		} else if (!meta_desc) {
			SSDFS_ERR("fail to get fragment descriptor: "
				  "area_type %#x\n",
				  area_type);
			return -ERANGE;
		}

		meta_desc->offset = cpu_to_le32(write_offset);
		meta_desc->compr_size = cpu_to_le16(blk_desc_size);
		meta_desc->uncompr_size = cpu_to_le16(blk_desc_size);
		meta_desc->checksum = 0;

		if (area->metadata.sequence_id == U8_MAX)
			area->metadata.sequence_id = 0;

		meta_desc->sequence_id = area->metadata.sequence_id++;

		meta_desc->magic = SSDFS_FRAGMENT_DESC_MAGIC;
		meta_desc->type = SSDFS_DATA_BLK_DESC;
		meta_desc->flags = 0;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("old_offset %u, write_offset %u, bytes_count %u\n",
			  old_offset, write_offset, bytes_count);
		SSDFS_DBG("fragments_count %u, fragment (offset %u, "
			  "compr_size %u, sequence_id %u, type %#x)\n",
			  le16_to_cpu(chain_hdr->fragments_count),
			  le32_to_cpu(meta_desc->offset),
			  le16_to_cpu(meta_desc->compr_size),
			  meta_desc->sequence_id,
			  meta_desc->type);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	le32_add_cpu(&chain_hdr->compr_bytes, (u32)blk_desc_size);
	le32_add_cpu(&chain_hdr->uncompr_bytes, (u32)blk_desc_size);

	return 0;
}

/*
 * ssdfs_peb_store_block_descriptor() - store block descriptor into area
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @blk_desc: block descriptor
 * @data_off: offset to data in PEB [in]
 * @desc_off: offset to block descriptor in PEB [out]
 *
 * This function tries to store block descriptor into dedicated area.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - unable to get fragment descriptor.
 */
static
int ssdfs_peb_store_block_descriptor(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_block_descriptor *blk_desc,
				struct ssdfs_peb_phys_offset *data_off,
				struct ssdfs_peb_phys_offset *desc_off)
{
	struct ssdfs_fs_info *fsi;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req || !blk_desc || !data_off || !desc_off);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "logical_offset %llu, processed_blks %d\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  req->extent.ino, req->extent.logical_offset,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	flags = fsi->metadata_options.blk2off_tbl.flags;

	if (flags & SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION) {
		err = ssdfs_peb_store_compressed_block_descriptor(pebi, req,
								  blk_desc,
								  data_off,
								  desc_off);
	} else {
		err = __ssdfs_peb_store_block_descriptor(pebi, req,
							  blk_desc,
							  data_off,
							  desc_off);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to store block descriptor: "
			  "seg %llu, peb %llu, ino %llu, "
			  "logical_offset %llu, processed_blks %d, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  req->extent.ino,
			  req->extent.logical_offset,
			  req->result.processed_blks,
			  err);
	}

	return err;
}

/*
 * ssdfs_peb_store_block_descriptor_offset() - store offset in blk2off table
 * @pebi: pointer on PEB object
 * @logical_offset: offset in pages from file's begin
 * @logical_blk: segment's logical block
 * @blk_desc: block descriptor
 * @off: pointer on block descriptor offset
 */
static
int ssdfs_peb_store_block_descriptor_offset(struct ssdfs_peb_info *pebi,
					u32 logical_offset,
					u16 logical_blk,
					struct ssdfs_block_descriptor *blk_desc,
					struct ssdfs_peb_phys_offset *off)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_phys_offset_descriptor blk_desc_off;
	struct ssdfs_blk2off_table *table;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!off);
	BUG_ON(logical_blk == U16_MAX);

	SSDFS_DBG("seg %llu, peb %llu, logical_offset %u, "
		  "logical_blk %u, area_type %#x,"
		  "peb_index %u, peb_page %u, byte_offset %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, logical_offset, logical_blk,
		  off->log_area, off->peb_index,
		  off->peb_page, off->byte_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	blk_desc_off.page_desc.logical_offset = cpu_to_le32(logical_offset);
	blk_desc_off.page_desc.logical_blk = cpu_to_le16(logical_blk);
	blk_desc_off.page_desc.peb_page = cpu_to_le16(off->peb_page);

	blk_desc_off.blk_state.log_start_page =
		cpu_to_le16(pebi->current_log.start_page);
	blk_desc_off.blk_state.log_area = off->log_area;
	blk_desc_off.blk_state.peb_migration_id = off->peb_migration_id;
	blk_desc_off.blk_state.byte_offset = cpu_to_le32(off->byte_offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("PHYS OFFSET: logical_offset %u, logical_blk %u, "
		  "peb_page %u, log_start_page %u, "
		  "log_area %u, peb_migration_id %u, "
		  "byte_offset %u\n",
		  logical_offset, logical_blk,
		  off->peb_page, pebi->current_log.start_page,
		  off->log_area, off->peb_migration_id,
		  off->byte_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	table = pebi->pebc->parent_si->blk2off_table;

	err = ssdfs_blk2off_table_change_offset(table, logical_blk,
						off->peb_index,
						blk_desc,
						&blk_desc_off);
	if (err == -EAGAIN) {
		struct completion *end = &table->full_init_end;

		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_blk2off_table_change_offset(table, logical_blk,
							off->peb_index,
							blk_desc,
							&blk_desc_off);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to change offset: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

	return 0;
}

/*
 * __ssdfs_peb_create_block() - create data block
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to create data block in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_peb_create_block(struct ssdfs_peb_info *pebi,
			     struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_phys_offset_descriptor *blk_desc_off = NULL;
	struct ssdfs_block_descriptor blk_desc = {0};
	struct ssdfs_peb_phys_offset data_off = {0};
	struct ssdfs_peb_phys_offset desc_off = {0};
	struct ssdfs_offset_position pos = {0};
	u16 logical_block;
	int processed_blks;
	u64 logical_offset;
	struct ssdfs_block_bmap_range range;
	u32 rest_bytes, written_bytes;
	u32 len;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->extent.data_bytes <
		(req->result.processed_blks *
			pebi->pebc->parent_si->fsi->pagesize));
	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.len >= U16_MAX);
	BUG_ON(req->result.processed_blks > req->place.len);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, "
		  "peb_index %u, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	si = pebi->pebc->parent_si;
	processed_blks = req->result.processed_blks;
	logical_block = req->place.start.blk_index + processed_blks;
	rest_bytes = ssdfs_request_rest_bytes(pebi, req);
	logical_offset = req->extent.logical_offset +
				((u64)processed_blks * fsi->pagesize);
	logical_offset /= fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "logical_block %u, logical_offset %llu, "
		  "processed_blks %d, rest_size %u\n",
		  req->place.start.seg_id,
		  pebi->peb_id, pebi->peb_index,
		  logical_block, logical_offset,
		  processed_blks, rest_bytes);

	BUG_ON(logical_offset >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_reserve_block_descriptor(pebi, req);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try again to add block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to reserve block descriptor: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id, err);
		return err;
	}

	err = ssdfs_peb_add_block_into_data_area(pebi, req,
						 blk_desc_off, &pos,
						 &data_off,
						 &written_bytes);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try again to add block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to add block: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id, err);
		return err;
	}

	len = (written_bytes + fsi->pagesize - 1) >> fsi->log_pagesize;

	if (!is_ssdfs_block_full(fsi->pagesize, written_bytes)) {
		err = ssdfs_segment_blk_bmap_pre_allocate(&si->blk_bmap,
							  pebi->pebc,
							  &len,
							  &range);
	} else {
		err = ssdfs_segment_blk_bmap_allocate(&si->blk_bmap,
							pebi->pebc,
							&len,
							&range);
	}

	if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try again to add block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EAGAIN;
	} else if (unlikely(err || (len != range.len))) {
		SSDFS_ERR("fail to allocate range: "
			  "seg %llu, peb %llu, "
			  "range (start %u, len %u), err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  range.start, range.len, err);
		return err;
	}

	data_off.peb_page = (u16)range.start;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("logical_blk %u, peb_page %u\n",
		  logical_block, range.start);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_BLK_DESC_INIT(&blk_desc);

	err = ssdfs_peb_store_block_descriptor(pebi, req,
						&blk_desc, &data_off,
						&desc_off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store block descriptor: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id, err);
		return err;
	}

	err = ssdfs_peb_store_block_descriptor_offset(pebi, (u32)logical_offset,
						      logical_block,
						      &blk_desc, &desc_off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store block descriptor offset: "
			  "err %d\n",
			  err);
		return err;
	}

	req->result.processed_blks += range.len;
	return 0;
}

/*
 * ssdfs_peb_create_block() - create data block
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to create data block in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_create_block(struct ssdfs_peb_info *pebi,
			   struct ssdfs_segment_request *req)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.start.blk_index >=
		pebi->pebc->parent_si->fsi->pages_per_seg);
	switch (req->private.class) {
	case SSDFS_PEB_CREATE_DATA_REQ:
	case SSDFS_PEB_CREATE_LNODE_REQ:
	case SSDFS_PEB_CREATE_HNODE_REQ:
	case SSDFS_PEB_CREATE_IDXNODE_REQ:
		/* expected state */
		break;
	default:
		BUG();
	};
	BUG_ON(req->private.cmd != SSDFS_CREATE_BLOCK);
	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);
	BUG_ON(req->extent.data_bytes > pebi->pebc->parent_si->fsi->pagesize);
	BUG_ON(req->result.processed_blks > 0);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
		  "logical_block %u, data_bytes %u, cno %llu, "
		  "parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->extent.logical_offset, req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_peb_create_block(pebi, req);
	if (err == -ENOSPC) {
		SSDFS_DBG("block bitmap hasn't free space\n");
		return err;
	} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try again to create block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to create block: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  pebi->peb_id, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_create_extent() - create extent
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to create extent of data blocks in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_create_extent(struct ssdfs_peb_info *pebi,
			    struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	u32 rest_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.start.blk_index >=
		pebi->pebc->parent_si->fsi->pages_per_seg);
	switch (req->private.class) {
	case SSDFS_PEB_CREATE_DATA_REQ:
	case SSDFS_PEB_CREATE_LNODE_REQ:
	case SSDFS_PEB_CREATE_HNODE_REQ:
	case SSDFS_PEB_CREATE_IDXNODE_REQ:
		/* expected state */
		break;
	default:
		BUG();
	};
	BUG_ON(req->private.cmd != SSDFS_CREATE_EXTENT);
	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);

	SSDFS_DBG("peb %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu"
		  "seg %llu, logical_block %u, cmd %#x, type %#x, "
		  "processed_blks %d\n",
		  pebi->peb_id, req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->place.start.seg_id, req->place.start.blk_index,
		  req->private.cmd, req->private.type,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	rest_bytes = ssdfs_request_rest_bytes(pebi, req);

	while (rest_bytes > 0) {
		u32 logical_block = req->place.start.blk_index +
					req->result.processed_blks;

		err = __ssdfs_peb_create_block(pebi, req);
		if (err == -ENOSPC) {
			SSDFS_DBG("block bitmap hasn't free space\n");
			return err;
		} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("try again to create block: "
				  "seg %llu, logical_block %u, peb %llu\n",
				  req->place.start.seg_id, logical_block,
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create block: "
				  "seg %llu, logical_block %u, "
				  "peb %llu, err %d\n",
				  req->place.start.seg_id, logical_block,
				  pebi->peb_id, err);
			return err;
		}

		rest_bytes = ssdfs_request_rest_bytes(pebi, req);
	};

	return 0;
}

/*
 * __ssdfs_peb_pre_allocate_extent() - pre-allocate extent
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to pre-allocate an extent of blocks in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_peb_pre_allocate_extent(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_phys_offset desc_off = {0};
	u16 logical_block;
	int processed_blks;
	u64 logical_offset;
	struct ssdfs_block_bmap_range range;
	u32 rest_bytes;
	u32 len;
	u8 id;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->extent.data_bytes <
		(req->result.processed_blks *
			pebi->pebc->parent_si->fsi->pagesize));
	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.len >= U16_MAX);
	BUG_ON(req->result.processed_blks > req->place.len);
	WARN_ON(pagevec_count(&req->result.pvec) != 0);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	si = pebi->pebc->parent_si;
	processed_blks = req->result.processed_blks;
	logical_block = req->place.start.blk_index + processed_blks;
	rest_bytes = ssdfs_request_rest_bytes(pebi, req);
	logical_offset = req->extent.logical_offset +
				((u64)processed_blks * fsi->pagesize);
	logical_offset /= fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, logical_block %u, "
		  "logical_offset %llu, "
		  "processed_blks %d, rest_size %u\n",
		  req->place.start.seg_id, pebi->peb_id,
		  logical_block, logical_offset,
		  processed_blks, rest_bytes);

	if (req->extent.logical_offset >= U64_MAX) {
		SSDFS_ERR("seg %llu, peb %llu, logical_block %u, "
			  "logical_offset %llu, "
			  "processed_blks %d, rest_size %u\n",
			  req->place.start.seg_id, pebi->peb_id,
			  logical_block, logical_offset,
			  processed_blks, rest_bytes);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	len = req->extent.data_bytes;
	len -= req->result.processed_blks * si->fsi->pagesize;
	len >>= fsi->log_pagesize;

	err = ssdfs_segment_blk_bmap_pre_allocate(&si->blk_bmap,
						  pebi->pebc,
						  &len,
						  &range);
	if (err == -ENOSPC) {
		SSDFS_DBG("block bitmap hasn't free space\n");
		return err;
	} else if (unlikely(err || (len != range.len))) {
		SSDFS_ERR("fail to allocate range: "
			  "seg %llu, peb %llu, "
			  "range (start %u, len %u), err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  range.start, range.len, err);
		return err;
	}

	id = ssdfs_get_peb_migration_id_checked(pebi);
	if (unlikely(id < 0)) {
		SSDFS_ERR("invalid peb_migration_id: "
			  "seg %llu, peb_id %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, id);
		return id;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(id > U8_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < range.len; i++) {
		desc_off.peb_index = pebi->peb_index;
		desc_off.peb_migration_id = id;
		desc_off.peb_page = (u16)(range.start + i);
		desc_off.log_area = SSDFS_LOG_AREA_MAX;
		desc_off.byte_offset = U32_MAX;

		logical_block += i;
		logical_offset += i;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("logical_blk %u, peb_page %u\n",
			  logical_block, range.start + i);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_peb_store_block_descriptor_offset(pebi,
							(u32)logical_offset,
							logical_block,
							NULL,
							&desc_off);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store block descriptor offset: "
				  "logical_block %u, logical_offset %llu, "
				  "err %d\n",
				  logical_block, logical_offset, err);
			return err;
		}
	}

	req->result.processed_blks += range.len;
	return 0;
}

/*
 * ssdfs_peb_pre_allocate_block() - pre-allocate block
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to pre-allocate a block in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_pre_allocate_block(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.start.blk_index >=
		pebi->pebc->parent_si->fsi->pages_per_seg);

	switch (req->private.class) {
	case SSDFS_PEB_PRE_ALLOCATE_DATA_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ:
		/* expected state */
		break;
	default:
		SSDFS_ERR("unexpected request: "
			  "req->private.class %#x\n",
			  req->private.class);
		BUG();
	};

	switch (req->private.cmd) {
	case SSDFS_CREATE_BLOCK:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected request: "
			  "req->private.cmd %#x\n",
			  req->private.cmd);
		BUG();
	};

	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);
	BUG_ON(req->extent.data_bytes > pebi->pebc->parent_si->fsi->pagesize);
	BUG_ON(req->result.processed_blks > 0);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
		  "logical_block %u, data_bytes %u, cno %llu, "
		  "parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->extent.logical_offset, req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_peb_pre_allocate_extent(pebi, req);
	if (err == -ENOSPC) {
		SSDFS_DBG("block bitmap hasn't free space\n");
		return err;
	} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try again to pre-allocate block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-allocate block: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  pebi->peb_id, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_pre_allocate_extent() - pre-allocate extent
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to pre-allocate an extent of blocks in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_pre_allocate_extent(struct ssdfs_peb_info *pebi,
				  struct ssdfs_segment_request *req)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);

	SSDFS_DBG("peb %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu, "
		  "seg %llu, logical_block %u, cmd %#x, type %#x, "
		  "processed_blks %d\n",
		  pebi->peb_id, req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->place.start.seg_id, req->place.start.blk_index,
		  req->private.cmd, req->private.type,
		  req->result.processed_blks);

	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.start.blk_index >=
		pebi->pebc->parent_si->fsi->pages_per_seg);

	switch (req->private.class) {
	case SSDFS_PEB_PRE_ALLOCATE_DATA_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ:
		/* expected state */
		break;
	default:
		SSDFS_ERR("unexpected request: "
			  "req->private.class %#x\n",
			  req->private.class);
		BUG();
	};

	switch (req->private.cmd) {
	case SSDFS_CREATE_EXTENT:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected request: "
			  "req->private.cmd %#x\n",
			  req->private.cmd);
		BUG();
	};

	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);
	BUG_ON((req->extent.data_bytes /
		pebi->pebc->parent_si->fsi->pagesize) < 1);

	SSDFS_DBG("peb %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu, "
		  "seg %llu, logical_block %u, cmd %#x, type %#x, "
		  "processed_blks %d\n",
		  pebi->peb_id, req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->place.start.seg_id, req->place.start.blk_index,
		  req->private.cmd, req->private.type,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_peb_pre_allocate_extent(pebi, req);
	if (err == -ENOSPC) {
		SSDFS_DBG("block bitmap hasn't free space\n");
		return err;
	} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try again to pre-allocate extent: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-allocate extent: "
			  "seg %llu, logical_block %u, peb %llu, "
			  "ino %llu, logical_offset %llu, err %d\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  pebi->peb_id, req->extent.ino,
			  req->extent.logical_offset, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_process_create_request() - process create request
 * @pebi: pointer on PEB object
 * @req: request
 *
 * This function detects command of request and
 * to call a proper function for request processing.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_process_create_request(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req)
{
	struct ssdfs_segment_info *si;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req);

	SSDFS_DBG("req %p, cmd %#x, type %#x\n",
		  req, req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (req->private.cmd <= SSDFS_READ_CMD_MAX ||
	    req->private.cmd >= SSDFS_CREATE_CMD_MAX) {
		SSDFS_ERR("unknown create command %d, seg %llu, peb %llu\n",
			  req->private.cmd,
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id);
		req->result.err = -EINVAL;
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		return -EINVAL;
	}

	atomic_set(&req->result.state, SSDFS_REQ_STARTED);

	switch (req->private.cmd) {
	case SSDFS_CREATE_BLOCK:
		switch (req->private.class) {
		case SSDFS_PEB_CREATE_DATA_REQ:
		case SSDFS_PEB_CREATE_LNODE_REQ:
		case SSDFS_PEB_CREATE_HNODE_REQ:
		case SSDFS_PEB_CREATE_IDXNODE_REQ:
			err = ssdfs_peb_create_block(pebi, req);
			break;

		case SSDFS_PEB_PRE_ALLOCATE_DATA_REQ:
		case SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ:
		case SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ:
		case SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ:
			err = ssdfs_peb_pre_allocate_block(pebi, req);
			break;

		default:
			BUG();
		}

		if (err == -ENOSPC) {
			SSDFS_DBG("block bitmap hasn't free space\n");
			return err;
		} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("try again to create block: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to create block: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_CREATE_EXTENT:
		switch (req->private.class) {
		case SSDFS_PEB_CREATE_DATA_REQ:
		case SSDFS_PEB_CREATE_LNODE_REQ:
		case SSDFS_PEB_CREATE_HNODE_REQ:
		case SSDFS_PEB_CREATE_IDXNODE_REQ:
			err = ssdfs_peb_create_extent(pebi, req);
			break;

		case SSDFS_PEB_PRE_ALLOCATE_DATA_REQ:
		case SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ:
		case SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ:
		case SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ:
			err = ssdfs_peb_pre_allocate_extent(pebi, req);
			break;

		default:
			BUG();
		}

		if (err == -ENOSPC) {
			SSDFS_DBG("block bitmap hasn't free space\n");
			return err;
		} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("try again to create extent: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to create extent: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_MIGRATE_ZONE_USER_BLOCK:
		switch (req->private.class) {
		case SSDFS_ZONE_USER_DATA_MIGRATE_REQ:
			err = ssdfs_peb_create_block(pebi, req);
			break;

		default:
			BUG();
		}

		if (err == -ENOSPC) {
			SSDFS_DBG("block bitmap hasn't free space\n");
			return err;
		} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("try again to migrate block: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to migrate block: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_MIGRATE_ZONE_USER_EXTENT:
		switch (req->private.class) {
		case SSDFS_ZONE_USER_DATA_MIGRATE_REQ:
			err = ssdfs_peb_create_extent(pebi, req);
			break;

		default:
			BUG();
		}

		if (err == -ENOSPC) {
			SSDFS_DBG("block bitmap hasn't free space\n");
			return err;
		} else if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("try again to migrate extent: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to migrate extent: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	default:
		BUG();
	}

	if (unlikely(err)) {
		/* request failed */
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);
	} else if ((req->private.class == SSDFS_PEB_CREATE_DATA_REQ ||
		    req->private.class == SSDFS_ZONE_USER_DATA_MIGRATE_REQ) &&
		   is_ssdfs_peb_containing_user_data(pebi->pebc)) {
		int processed_blks = req->result.processed_blks;
		u32 pending = 0;

		si = pebi->pebc->parent_si;

		spin_lock(&si->pending_lock);
		pending = si->pending_new_user_data_pages;
		if (si->pending_new_user_data_pages >= processed_blks) {
			si->pending_new_user_data_pages -= processed_blks;
			pending = si->pending_new_user_data_pages;
		} else {
			/* wrong accounting */
			err = -ERANGE;
		}
		spin_unlock(&si->pending_lock);

		if (unlikely(err)) {
			SSDFS_ERR("pending %u < processed_blks %d\n",
				  pending, processed_blks);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("seg %llu, pending %u, processed_blks %d\n",
				  si->seg_id, pending, processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}

	return err;
}

/*
 * ssdfs_peb_read_from_offset() - read in buffer from offset
 * @pebi: pointer on PEB object
 * @off: offset in PEB
 * @buf: pointer on buffer
 * @buf_size: size of the buffer
 *
 * This function tries to read from volume into buffer.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
#ifdef CONFIG_SSDFS_UNDER_DEVELOPMENT_FUNC
static
int ssdfs_peb_read_from_offset(struct ssdfs_peb_info *pebi,
			       struct ssdfs_phys_offset_descriptor *off,
			       void *buf, size_t buf_size)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor desc_array[SSDFS_SEG_HDR_DESC_MAX];
	u16 log_start_page;
	u32 byte_offset;
	u16 log_index;
	int area_index;
	u32 area_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!off || !buf);
	BUG_ON(buf_size == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	log_start_page = le16_to_cpu(off->blk_state.log_start_page);
	byte_offset = le32_to_cpu(off->blk_state.byte_offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, "
		  "log_start_page %u, log_area %#x, "
		  "peb_migration_id %u, byte_offset %u, "
		  "buf %p, buf_size %zu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  log_start_page, off->blk_state.log_area,
		  off->blk_state.peb_migration_id,
		  byte_offset, buf, buf_size);
#endif /* CONFIG_SSDFS_DEBUG */

	log_index = log_start_page / pebi->log_pages;

	if (log_index >= (fsi->pages_per_peb / pebi->log_pages)) {
		SSDFS_ERR("invalid log index %u\n", log_index);
		return -ERANGE;
	}

	area_index = SSDFS_AREA_TYPE2INDEX(off->blk_state.log_area);

	if (area_index >= SSDFS_SEG_HDR_DESC_MAX) {
		SSDFS_ERR("invalid area index %#x\n", area_index);
		return -ERANGE;
	}

	err = ssdfs_peb_read_log_hdr_desc_array(pebi, log_index, desc_array,
						SSDFS_SEG_HDR_DESC_MAX);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read log's header desc array: "
			  "seg %llu, peb %llu, log_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  log_index, err);
		return err;
	}

	area_offset = le32_to_cpu(desc_array[area_index].offset);

	err = ssdfs_unaligned_read_buffer(fsi, pebi->peb_id,
					  area_offset + byte_offset,
					  buf, buf_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read buffer: "
			  "peb %llu, area_offset %u, byte_offset %u, "
			  "buf_size %zu, err %d\n",
			  pebi->peb_id, area_offset, byte_offset,
			  buf_size, err);
		return err;
	}

	return 0;
}
#endif /* CONFIG_SSDFS_UNDER_DEVELOPMENT_FUNC */

static inline
bool does_user_data_block_contain_diff(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	u32 mem_pages_per_block;
	int page_index;
	struct page *page;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_peb_containing_user_data(pebi->pebc))
		return false;

	fsi = pebi->pebc->parent_si->fsi;
	mem_pages_per_block = fsi->pagesize / PAGE_SIZE;
	page_index = req->result.processed_blks * mem_pages_per_block;
	page = req->result.pvec.pages[page_index];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_diff_page(page);
}

/*
 * __ssdfs_peb_update_block() - update data block
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to update data block in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - try again to update data block.
 * %-ENOENT     - need migrate base state before storing diff.
 */
static
int __ssdfs_peb_update_block(struct ssdfs_peb_info *pebi,
			     struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_phys_offset_descriptor *blk_desc_off;
	struct ssdfs_peb_phys_offset data_off = {0};
	struct ssdfs_peb_phys_offset desc_off = {0};
	u16 blk;
	u64 logical_offset;
	struct ssdfs_block_bmap_range range;
	int range_state;
	u32 written_bytes;
	u16 peb_index;
	int migration_state = SSDFS_LBLOCK_UNKNOWN_STATE;
	struct ssdfs_offset_position pos = {0};
	u8 migration_id1;
	int migration_id2;
#ifdef CONFIG_SSDFS_DEBUG
	int i;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.start.blk_index >=
		pebi->pebc->parent_si->fsi->pages_per_seg);
	switch (req->private.class) {
	case SSDFS_PEB_UPDATE_REQ:
	case SSDFS_PEB_PRE_ALLOC_UPDATE_REQ:
	case SSDFS_PEB_DIFF_ON_WRITE_REQ:
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		/* expected case */
		break;
	default:
		BUG();
		break;
	}
	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebi->pebc->parent_si;
	fsi = si->fsi;
	table = pebi->pebc->parent_si->blk2off_table;
	seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;
	peb_blkbmap = &seg_blkbmap->peb[pebi->pebc->peb_index];

#ifdef CONFIG_SSDFS_DEBUG
	if (req->extent.logical_offset >= U64_MAX) {
		SSDFS_ERR("seg %llu, peb %llu, logical_block %u, "
			  "logical_offset %llu, "
			  "processed_blks %d\n",
			  req->place.start.seg_id, pebi->peb_id,
			  req->place.start.blk_index,
			  req->extent.logical_offset,
			  req->result.processed_blks);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	blk = req->place.start.blk_index + req->result.processed_blks;
	logical_offset = req->extent.logical_offset +
			    ((u64)req->result.processed_blks * fsi->pagesize);
	logical_offset = div64_u64(logical_offset, fsi->pagesize);

	if (req->private.class == SSDFS_PEB_DIFF_ON_WRITE_REQ) {
		u32 pvec_size = pagevec_count(&req->result.pvec);
		u32 cur_index = req->result.processed_blks;

		if (cur_index >= pvec_size) {
			SSDFS_ERR("processed_blks %u > pagevec_size %u\n",
				  cur_index, pvec_size);
			return -ERANGE;
		}

		if (req->result.pvec.pages[cur_index] == NULL) {
			req->result.processed_blks++;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("block %u hasn't diff\n",
				  blk);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_update_block;
		}
	}

	blk_desc_off = ssdfs_blk2off_table_convert(table, blk,
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

		blk_desc_off = ssdfs_blk2off_table_convert(table, blk,
							   &peb_index,
							   &migration_state,
							   &pos);
	}

	if (IS_ERR_OR_NULL(blk_desc_off)) {
		err = (blk_desc_off == NULL ? -ERANGE : PTR_ERR(blk_desc_off));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  blk, err);
		return err;
	}

	if (req->private.class == SSDFS_PEB_DIFF_ON_WRITE_REQ) {
		migration_id1 =
			SSDFS_GET_BLK_DESC_MIGRATION_ID(&pos.blk_desc.buf);
		migration_id2 = ssdfs_get_peb_migration_id_checked(pebi);

		if (migration_id1 < U8_MAX && migration_id1 != migration_id2) {
			/*
			 * Base state and diff in different PEBs
			 */

			range.start = blk;
			range.len = 1;

			ssdfs_requests_queue_add_head(&pebi->pebc->update_rq,
							req);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("range: (start %u, len %u)\n",
				  range.start, range.len);
#endif /* CONFIG_SSDFS_DEBUG */

			if (is_ssdfs_peb_containing_user_data(pebi->pebc)) {
				ssdfs_account_updated_user_data_pages(fsi,
								    range.len);
			}

			err = ssdfs_peb_migrate_valid_blocks_range(si,
								   pebi->pebc,
								   peb_blkbmap,
								   &range);
			if (unlikely(err)) {
				SSDFS_ERR("fail to migrate valid blocks: "
					  "range (start %u, len %u), err %d\n",
					  range.start, range.len, err);
				return err;
			}

			return -ENOENT;
		}
	}

	down_write(&table->translation_lock);

	migration_state = ssdfs_blk2off_table_get_block_migration(table, blk,
								  peb_index);
	switch (migration_state) {
	case SSDFS_LBLOCK_UNKNOWN_STATE:
		err = -ENOENT;
		/* logical block is not migrating */
		break;

	case SSDFS_LBLOCK_UNDER_MIGRATION:
		switch (req->private.cmd) {
		case SSDFS_MIGRATE_RANGE:
		case SSDFS_MIGRATE_FRAGMENT:
			err = 0;
			/* continue logic */
			break;

		default:
			err = ssdfs_blk2off_table_update_block_state(table,
								     req);
			if (unlikely(err)) {
				SSDFS_ERR("fail to update block's state: "
					  "seg %llu, logical_block %u, "
					  "peb %llu, err %d\n",
					  req->place.start.seg_id, blk,
					  pebi->peb_id, err);
			} else
				err = -EEXIST;
			break;
		}
		break;

	case SSDFS_LBLOCK_UNDER_COMMIT:
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try again to update block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, blk, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	default:
		err = -ERANGE;
		SSDFS_ERR("unexpected migration state: "
			  "seg %llu, logical_block %u, "
			  "peb %llu, migration_state %#x\n",
			  req->place.start.seg_id, blk,
			  pebi->peb_id, migration_state);
		break;
	}

	up_write(&table->translation_lock);

	if (err == -ENOENT) {
		/* logical block is not migrating */
		err = 0;
	} else if (err == -EEXIST) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("migrating block has been updated in buffer: "
			  "seg %llu, peb %llu, logical_block %u\n",
			  req->place.start.seg_id, pebi->peb_id,
			  blk);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	} else if (unlikely(err))
		return err;

	err = ssdfs_peb_reserve_block_descriptor(pebi, req);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try again to add block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, blk, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to reserve block descriptor: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, blk, pebi->peb_id, err);
		return err;
	}

	err = ssdfs_peb_add_block_into_data_area(pebi, req,
						 blk_desc_off, &pos,
						 &data_off,
						 &written_bytes);
	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try again to add block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, blk, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to add block: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, blk, pebi->peb_id, err);
		return err;
	}

	range.start = le16_to_cpu(blk_desc_off->page_desc.peb_page);
	range.len = (written_bytes + fsi->pagesize - 1) >> fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("written_bytes %u, range (start %u, len %u)\n",
		  written_bytes, range.start, range.len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (req->private.class == SSDFS_PEB_DIFF_ON_WRITE_REQ)
		range_state = SSDFS_BLK_VALID;
	else if (is_ssdfs_block_full(fsi->pagesize, written_bytes))
		range_state = SSDFS_BLK_VALID;
	else
		range_state = SSDFS_BLK_PRE_ALLOCATED;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("logical_blk %u, peb_page %u\n",
		  blk, range.start);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_segment_blk_bmap_update_range(seg_blkbmap, pebi->pebc,
				blk_desc_off->blk_state.peb_migration_id,
				range_state, &range);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update range: "
			  "seg %llu, peb %llu, "
			  "range (start %u, len %u), err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, range.start, range.len,
			  err);
		return err;
	}

	data_off.peb_page = (u16)range.start;

	if (req->private.class != SSDFS_PEB_DIFF_ON_WRITE_REQ &&
	    !does_user_data_block_contain_diff(pebi, req))
		SSDFS_BLK_DESC_INIT(&pos.blk_desc.buf);
	else {
#ifdef CONFIG_SSDFS_DEBUG
		migration_id1 =
			SSDFS_GET_BLK_DESC_MIGRATION_ID(&pos.blk_desc.buf);
		if (migration_id1 >= U8_MAX) {
			/*
			 * continue logic
			 */
		} else {
			migration_id2 =
				ssdfs_get_peb_migration_id_checked(pebi);

			if (migration_id1 != migration_id2) {
				struct ssdfs_block_descriptor *blk_desc;

				SSDFS_WARN("invalid request: "
					   "migration_id1 %u, "
					   "migration_id2 %d\n",
					   migration_id1, migration_id2);

				blk_desc = &pos.blk_desc.buf;

				SSDFS_ERR("seg_id %llu, peb_id %llu, "
					  "ino %llu, logical_offset %u, "
					  "peb_index %u, peb_page %u\n",
					  req->place.start.seg_id,
					  pebi->peb_id,
					  le64_to_cpu(blk_desc->ino),
					  le32_to_cpu(blk_desc->logical_offset),
					  le16_to_cpu(blk_desc->peb_index),
					  le16_to_cpu(blk_desc->peb_page));

				for (i = 0; i < SSDFS_BLK_STATE_OFF_MAX; i++) {
					struct ssdfs_blk_state_offset *state;

					state = &blk_desc->state[i];

					SSDFS_ERR("BLK STATE OFFSET %d: "
						  "log_start_page %u, "
						  "log_area %#x, "
						  "byte_offset %u, "
						  "peb_migration_id %u\n",
					  i,
					  le16_to_cpu(state->log_start_page),
					  state->log_area,
					  le32_to_cpu(state->byte_offset),
					  state->peb_migration_id);
				}

				BUG();
			}
		}
#endif /* CONFIG_SSDFS_DEBUG */
	}

	err = ssdfs_peb_store_block_descriptor(pebi, req,
						&pos.blk_desc.buf,
						&data_off, &desc_off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store block descriptor: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, blk,
			  pebi->peb_id, err);
		return err;
	}

	err = ssdfs_peb_store_block_descriptor_offset(pebi,
							(u32)logical_offset,
							blk,
							&pos.blk_desc.buf,
							&desc_off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store block descriptor offset: "
			  "err %d\n",
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_block %u, "
		  "migration_state %#x\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->place.start.blk_index, migration_state);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_ssdfs_logical_block_migrating(migration_state)) {
		err = ssdfs_blk2off_table_set_block_commit(table, blk,
							   peb_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set block commit: "
				  "logical_blk %u, peb_index %u, err %d\n",
				  blk, peb_index, err);
			return err;
		}
	}

	req->result.processed_blks += range.len;

finish_update_block:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finish update block: "
		  "ino %llu, seg %llu, peb %llu, logical_block %u, "
		  "req->result.processed_blks %d\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->place.start.blk_index,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_check_zone_move_request() - check request
 * @req: segment request
 *
 * This method tries to check the state of request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_check_zone_move_request(struct ssdfs_segment_request *req)
{
	wait_queue_head_t *wq = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);

	SSDFS_DBG("req %p\n", req);
#endif /* CONFIG_SSDFS_DEBUG */

check_req_state:
	switch (atomic_read(&req->result.state)) {
	case SSDFS_REQ_CREATED:
	case SSDFS_REQ_STARTED:
		wq = &req->private.wait_queue;

		err = wait_event_killable_timeout(*wq,
					has_request_been_executed(req),
					SSDFS_DEFAULT_TIMEOUT);
		if (err < 0)
			WARN_ON(err < 0);
		else
			err = 0;

		goto check_req_state;
		break;

	case SSDFS_REQ_FINISHED:
		/* do nothing */
		break;

	case SSDFS_REQ_FAILED:
		err = req->result.err;

		if (!err) {
			SSDFS_ERR("error code is absent: "
				  "req %p, err %d\n",
				  req, err);
			err = -ERANGE;
		}

		SSDFS_ERR("flush request is failed: "
			  "err %d\n", err);
		return err;

	default:
		SSDFS_ERR("invalid result's state %#x\n",
		    atomic_read(&req->result.state));
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_extract_left_extent() - extract left extent
 * @req: I/O request
 * @migration: recommended migration extent
 * @left_fragment: difference between recommended and requested extents [out]
 *
 * This function tries to extract difference between recommended
 * and requested extents from the left.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_extract_left_extent(struct ssdfs_segment_request *req,
			      struct ssdfs_zone_fragment *migration,
			      struct ssdfs_zone_fragment *left_fragment)
{
	u64 seg_id;
	u32 start_blk;
	u32 len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !migration || !left_fragment);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu, "
		  "seg %llu, logical_block %u, len %u, "
		  "cmd %#x, type %#x, processed_blks %d\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->place.start.seg_id,
		  req->place.start.blk_index,
		  req->place.len,
		  req->private.cmd, req->private.type,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_id = le64_to_cpu(migration->extent.seg_id);
	start_blk = le32_to_cpu(migration->extent.logical_blk);
	len = le32_to_cpu(migration->extent.len);

	if (req->extent.ino != migration->ino) {
		SSDFS_ERR("invalid input: "
			  "ino1 %llu != ino2 %llu\n",
			  req->extent.ino, migration->ino);
		return -ERANGE;
	}

	if (req->place.start.seg_id != seg_id) {
		SSDFS_ERR("invalid input: "
			  "seg_id1 %llu != seg_id2 %llu\n",
			  req->place.start.seg_id, seg_id);
		return -ERANGE;
	}

	if (req->place.start.blk_index < start_blk) {
		SSDFS_ERR("invalid input: "
			  "request (seg_id %llu, logical_blk %u, len %u), "
			  "migration (seg_id %llu, logical_blk %u, len %u)\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  req->place.len,
			  seg_id, start_blk, len);
		return -ERANGE;
	}

	if (req->place.start.blk_index == start_blk) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no extent from the left: "
			  "request (seg_id %llu, logical_blk %u, len %u), "
			  "migration (seg_id %llu, logical_blk %u, len %u)\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  req->place.len,
			  seg_id, start_blk, len);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	left_fragment->ino = migration->ino;
	left_fragment->logical_blk_offset = migration->logical_blk_offset;
	left_fragment->extent.seg_id = migration->extent.seg_id;
	left_fragment->extent.logical_blk = migration->extent.logical_blk;
	left_fragment->extent.len =
			cpu_to_le32(req->place.start.blk_index - start_blk);

	return 0;
}

/*
 * ssdfs_extract_right_extent() - extract right extent
 * @req: I/O request
 * @migration: recommended migration extent
 * @right_fragment: difference between recommended and requested extents [out]
 *
 * This function tries to extract difference between recommended
 * and requested extents from the right.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static inline
int ssdfs_extract_right_extent(struct ssdfs_segment_request *req,
			       struct ssdfs_zone_fragment *migration,
			       struct ssdfs_zone_fragment *right_fragment)
{
	u64 seg_id;
	u32 start_blk;
	u32 len;
	u32 upper_bound1, upper_bound2;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !migration || !right_fragment);

	SSDFS_DBG("ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu, "
		  "seg %llu, logical_block %u, len %u, "
		  "cmd %#x, type %#x, processed_blks %d\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->place.start.seg_id,
		  req->place.start.blk_index,
		  req->place.len,
		  req->private.cmd, req->private.type,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_id = le64_to_cpu(migration->extent.seg_id);
	start_blk = le32_to_cpu(migration->extent.logical_blk);
	len = le32_to_cpu(migration->extent.len);

	if (req->extent.ino != migration->ino) {
		SSDFS_ERR("invalid input: "
			  "ino1 %llu != ino2 %llu\n",
			  req->extent.ino, migration->ino);
		return -ERANGE;
	}

	if (req->place.start.seg_id != seg_id) {
		SSDFS_ERR("invalid input: "
			  "seg_id1 %llu != seg_id2 %llu\n",
			  req->place.start.seg_id, seg_id);
		return -ERANGE;
	}

	upper_bound1 = req->place.start.blk_index + req->place.len;
	upper_bound2 = start_blk + len;

	if (upper_bound1 > upper_bound2) {
		SSDFS_ERR("invalid input: "
			  "request (seg_id %llu, logical_blk %u, len %u), "
			  "migration (seg_id %llu, logical_blk %u, len %u)\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  req->place.len,
			  seg_id, start_blk, len);
		return -ERANGE;
	}

	if (upper_bound1 == upper_bound2) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no extent from the right: "
			  "request (seg_id %llu, logical_blk %u, len %u), "
			  "migration (seg_id %llu, logical_blk %u, len %u)\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  req->place.len,
			  seg_id, start_blk, len);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	right_fragment->ino = migration->ino;
	right_fragment->logical_blk_offset =
			migration->logical_blk_offset + upper_bound1;
	right_fragment->extent.seg_id = migration->extent.seg_id;
	right_fragment->extent.logical_blk = cpu_to_le32(upper_bound1);
	right_fragment->extent.len = cpu_to_le32(upper_bound2 - upper_bound1);

	return 0;
}

/*
 * __ssdfs_zone_issue_move_request() - issue move request
 * @pebi: pointer on PEB object
 * @fragment: zone fragment
 * @req_type: request type
 * @req: I/O request
 *
 * This function tries to issue move request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_zone_issue_move_request(struct ssdfs_peb_info *pebi,
				    struct ssdfs_zone_fragment *fragment,
				    int req_type,
				    struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct inode *inode;
	struct ssdfs_inode_info *ii;
	struct ssdfs_extents_btree_info *etree;
	struct ssdfs_btree_search *search;
	struct page *page;
	struct ssdfs_blk2off_range new_extent;
	struct ssdfs_raw_extent old_raw_extent;
	struct ssdfs_raw_extent new_raw_extent;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u64 logical_offset;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !fragment);

	SSDFS_DBG("peb %llu, ino %llu, logical_blk_offset %llu, "
		  "extent (seg_id %llu, logical_blk %u, len %u)\n",
		  pebi->peb_id,
		  fragment->ino,
		  fragment->logical_blk_offset,
		  le64_to_cpu(fragment->extent.seg_id),
		  le32_to_cpu(fragment->extent.logical_blk),
		  le32_to_cpu(fragment->extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	seg_id = le64_to_cpu(fragment->extent.seg_id);
	logical_blk = le32_to_cpu(fragment->extent.logical_blk);
	len = le32_to_cpu(fragment->extent.len);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(len > PAGEVEC_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_init(req);
	ssdfs_get_request(req);

	req->private.flags |= SSDFS_REQ_DONT_FREE_PAGES;

	logical_offset = fragment->logical_blk_offset << fsi->log_pagesize;
	ssdfs_request_prepare_logical_extent(fragment->ino, logical_offset,
					     len, 0, 0, req);

	req->place.start.seg_id = seg_id;
	req->place.start.blk_index = logical_blk;
	req->place.len = 0;

	req->result.processed_blks = 0;

	for (i = 0; i < len; i++) {
		logical_blk += i;
		req->place.len++;

		err = ssdfs_peb_copy_page(pebi->pebc, logical_blk, req);
		if (err == -EAGAIN) {
			req->place.len = req->result.processed_blks;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to copy the whole range: "
				  "seg %llu, logical_blk %u, len %u\n",
				  pebi->pebc->parent_si->seg_id,
				  logical_blk, req->place.len);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to copy page: "
				  "seg %llu, logical_blk %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  logical_blk, err);
			return err;
		}
	}

	for (i = 0; i < req->result.processed_blks; i++)
		ssdfs_peb_mark_request_block_uptodate(pebi->pebc, req, i);

	for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
		page = req->result.pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		set_page_writeback(page);
	}

	req->result.err = 0;
	req->result.processed_blks = 0;
	atomic_set(&req->result.state, SSDFS_UNKNOWN_REQ_RESULT);

	err = ssdfs_segment_migrate_zone_extent_async(fsi,
						      req_type,
						      req,
						      &seg_id,
						      &new_extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to migrate zone extent: "
			  "peb %llu, ino %llu, logical_blk_offset %llu, "
			  "extent (seg_id %llu, logical_blk %u, len %u)\n",
			  pebi->peb_id,
			  fragment->ino,
			  fragment->logical_blk_offset,
			  le64_to_cpu(fragment->extent.seg_id),
			  le32_to_cpu(fragment->extent.logical_blk),
			  le32_to_cpu(fragment->extent.len));
		goto fail_issue_move_request;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg_id >= U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	old_raw_extent.seg_id = fragment->extent.seg_id;
	old_raw_extent.logical_blk = fragment->extent.logical_blk;
	old_raw_extent.len = fragment->extent.len;

	new_raw_extent.seg_id = cpu_to_le64(seg_id);
	new_raw_extent.logical_blk = cpu_to_le32(new_extent.start_lblk);
	new_raw_extent.len = cpu_to_le32(new_extent.len);

	page = req->result.pvec.pages[0];
	inode = page->mapping->host;
	ii = SSDFS_I(inode);

	etree = SSDFS_EXTREE(ii);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!etree);
#endif /* CONFIG_SSDFS_DEBUG */

	search = ssdfs_btree_search_alloc();
	if (!search) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate btree search object\n");
		goto fail_issue_move_request;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_extents_tree_move_extent(etree,
					     fragment->logical_blk_offset,
					     &old_raw_extent,
					     &new_raw_extent,
					     search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to move extent: "
			  "old_extent (seg_id %llu, logical_blk %u, len %u), "
			  "new_extent (seg_id %llu, logical_blk %u, len %u), "
			  "err %d\n",
			  le64_to_cpu(old_raw_extent.seg_id),
			  le32_to_cpu(old_raw_extent.logical_blk),
			  le32_to_cpu(old_raw_extent.len),
			  le64_to_cpu(new_raw_extent.seg_id),
			  le32_to_cpu(new_raw_extent.logical_blk),
			  le32_to_cpu(new_raw_extent.len),
			  err);
		goto fail_issue_move_request;
	}

	return 0;

fail_issue_move_request:
	ssdfs_request_unlock_and_remove_pages(req);
	ssdfs_put_request(req);

	return err;
}

/*
 * ssdfs_zone_issue_async_move_request() - issue async move request
 * @pebi: pointer on PEB object
 * @fragment: zone fragment
 *
 * This function tries to issue async move request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_zone_issue_async_move_request(struct ssdfs_peb_info *pebi,
					struct ssdfs_zone_fragment *fragment)
{
	struct ssdfs_segment_request *req;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !fragment);

	SSDFS_DBG("peb %llu, ino %llu, logical_blk_offset %llu, "
		  "extent (seg_id %llu, logical_blk %u, len %u)\n",
		  pebi->peb_id,
		  fragment->ino,
		  fragment->logical_blk_offset,
		  le64_to_cpu(fragment->extent.seg_id),
		  le32_to_cpu(fragment->extent.logical_blk),
		  le32_to_cpu(fragment->extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	err = __ssdfs_zone_issue_move_request(pebi, fragment,
					      SSDFS_REQ_ASYNC,
					      req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to issue move request: "
			  "peb %llu, ino %llu, logical_blk_offset %llu, "
			  "extent (seg_id %llu, logical_blk %u, len %u)\n",
			  pebi->peb_id,
			  fragment->ino,
			  fragment->logical_blk_offset,
			  le64_to_cpu(fragment->extent.seg_id),
			  le32_to_cpu(fragment->extent.logical_blk),
			  le32_to_cpu(fragment->extent.len));
		goto fail_issue_move_request;
	}

	return 0;

fail_issue_move_request:
	ssdfs_request_free(req);
	return err;
}

/*
 * ssdfs_zone_issue_move_request() - issue move request
 * @pebi: pointer on PEB object
 * @fragment: zone fragment
 * @req: I/O request
 *
 * This function tries to issue move request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_zone_issue_move_request(struct ssdfs_peb_info *pebi,
				  struct ssdfs_zone_fragment *fragment,
				  struct ssdfs_segment_request *req)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !fragment);

	SSDFS_DBG("peb %llu, ino %llu, logical_blk_offset %llu, "
		  "extent (seg_id %llu, logical_blk %u, len %u)\n",
		  pebi->peb_id,
		  fragment->ino,
		  fragment->logical_blk_offset,
		  le64_to_cpu(fragment->extent.seg_id),
		  le32_to_cpu(fragment->extent.logical_blk),
		  le32_to_cpu(fragment->extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_zone_issue_move_request(pebi, fragment,
					      SSDFS_REQ_ASYNC_NO_FREE,
					      req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to issue move request: "
			  "peb %llu, ino %llu, logical_blk_offset %llu, "
			  "extent (seg_id %llu, logical_blk %u, len %u)\n",
			  pebi->peb_id,
			  fragment->ino,
			  fragment->logical_blk_offset,
			  le64_to_cpu(fragment->extent.seg_id),
			  le32_to_cpu(fragment->extent.logical_blk),
			  le32_to_cpu(fragment->extent.len));
		goto fail_issue_move_request;
	}

fail_issue_move_request:
	return err;
}

/*
 * ssdfs_zone_prepare_migration_request() - stimulate migration
 * @pebi: pointer on PEB object
 * @fragment: zone fragment
 * @req: I/O request
 *
 * This function tries to prepare migration stimulation request
 * during moving updated data from exhausted zone into current zone
 * for updates.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_zone_prepare_migration_request(struct ssdfs_peb_info *pebi,
					 struct ssdfs_zone_fragment *fragment,
					 struct ssdfs_segment_request *req)
{
	struct ssdfs_zone_fragment sub_fragment;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u32 offset = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !fragment || !req);

	SSDFS_DBG("peb %llu, logical_blk_offset %llu, "
		  "extent (seg_id %llu, logical_blk %u, len %u)\n",
		  pebi->peb_id,
		  fragment->logical_blk_offset,
		  le64_to_cpu(fragment->extent.seg_id),
		  le32_to_cpu(fragment->extent.logical_blk),
		  le32_to_cpu(fragment->extent.len));
#endif /* CONFIG_SSDFS_DEBUG */

	seg_id = le64_to_cpu(fragment->extent.seg_id);
	logical_blk = le32_to_cpu(fragment->extent.logical_blk);
	len = le32_to_cpu(fragment->extent.len);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg_id != pebi->pebc->parent_si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

	while (len > PAGEVEC_SIZE) {
		sub_fragment.ino = fragment->ino;
		sub_fragment.logical_blk_offset =
				fragment->logical_blk_offset + offset;
		sub_fragment.extent.seg_id = fragment->extent.seg_id;
		sub_fragment.extent.logical_blk =
					cpu_to_le32(logical_blk + offset);
		sub_fragment.extent.len = cpu_to_le32(PAGEVEC_SIZE);

		err = ssdfs_zone_issue_async_move_request(pebi, &sub_fragment);
		if (unlikely(err)) {
			SSDFS_ERR("fail to issue zone async move request: "
				  "peb %llu, logical_blk_offset %llu, "
				  "sub_extent (seg_id %llu, "
				  "logical_blk %u, len %u), err %d\n",
				  pebi->peb_id,
				  sub_fragment.logical_blk_offset,
				  le64_to_cpu(sub_fragment.extent.seg_id),
				  le32_to_cpu(sub_fragment.extent.logical_blk),
				  le32_to_cpu(sub_fragment.extent.len),
				  err);
			return err;
		}

		offset += PAGEVEC_SIZE;
		len -= PAGEVEC_SIZE;
	}

	sub_fragment.ino = fragment->ino;
	sub_fragment.logical_blk_offset =
			fragment->logical_blk_offset + offset;
	sub_fragment.extent.seg_id = fragment->extent.seg_id;
	sub_fragment.extent.logical_blk = cpu_to_le32(logical_blk + offset);
	sub_fragment.extent.len = cpu_to_le32(len);

	err = ssdfs_zone_issue_move_request(pebi, &sub_fragment, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to issue zone move request: "
			  "peb %llu, logical_blk_offset %llu, "
			  "sub_extent (seg_id %llu, "
			  "logical_blk %u, len %u), err %d\n",
			  pebi->peb_id,
			  sub_fragment.logical_blk_offset,
			  le64_to_cpu(sub_fragment.extent.seg_id),
			  le32_to_cpu(sub_fragment.extent.logical_blk),
			  le32_to_cpu(sub_fragment.extent.len),
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_zone_prepare_move_flush_request() - convert update into move request
 * @pebi: pointer on PEB object
 * @src: source I/O request
 * @dst: destination I/O request
 *
 * This function tries to convert update request into
 * move request.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_zone_prepare_move_flush_request(struct ssdfs_peb_info *pebi,
					  struct ssdfs_segment_request *src,
					  struct ssdfs_segment_request *dst)
{
	struct ssdfs_fs_info *fsi;
	struct inode *inode;
	struct ssdfs_inode_info *ii;
	struct ssdfs_extents_btree_info *etree;
	struct ssdfs_btree_search *search;
	struct page *page;
	struct ssdfs_blk2off_range new_extent;
	struct ssdfs_raw_extent old_raw_extent;
	struct ssdfs_raw_extent new_raw_extent;
	u64 seg_id;
	u32 logical_blk;
	u32 len;
	u64 logical_offset;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !src || !dst);

	SSDFS_DBG("peb %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu, "
		  "seg %llu, logical_block %u, cmd %#x, type %#x, "
		  "processed_blks %d\n",
		  pebi->peb_id, src->extent.ino, src->extent.logical_offset,
		  src->extent.data_bytes, src->extent.cno,
		  src->extent.parent_snapshot,
		  src->place.start.seg_id, src->place.start.blk_index,
		  src->private.cmd, src->private.type,
		  src->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	seg_id = src->place.start.seg_id;
	logical_blk = src->place.start.blk_index;
	len = src->place.len;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(len > PAGEVEC_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	page = src->result.pvec.pages[0];
	inode = page->mapping->host;
	ii = SSDFS_I(inode);

	etree = SSDFS_EXTREE(ii);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!etree);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_request_init(dst);
	ssdfs_get_request(dst);

	dst->private.flags |= SSDFS_REQ_DONT_FREE_PAGES;

	logical_offset = src->extent.logical_offset;
	ssdfs_request_prepare_logical_extent(src->extent.ino,
					     logical_offset, len,
					     0, 0, dst);

	dst->place.start.seg_id = seg_id;
	dst->place.start.blk_index = logical_blk;
	dst->place.len = len;

	dst->result.processed_blks = 0;

	for (i = 0; i < pagevec_count(&src->result.pvec); i++) {
		page = src->result.pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

		dst->result.pvec.pages[i] = page;
		src->result.pvec.pages[i] = NULL;
	}

	pagevec_reinit(&src->result.pvec);

	dst->result.err = 0;
	dst->result.processed_blks = 0;
	atomic_set(&dst->result.state, SSDFS_UNKNOWN_REQ_RESULT);

	err = ssdfs_segment_migrate_zone_extent_async(fsi,
						      SSDFS_REQ_ASYNC_NO_FREE,
						      dst,
						      &seg_id,
						      &new_extent);
	if (unlikely(err)) {
		SSDFS_ERR("fail to migrate zone extent: "
			  "peb %llu, ino %llu, logical_blk_offset %llu, "
			  "extent (seg_id %llu, logical_blk %u, len %u)\n",
			  pebi->peb_id,
			  src->extent.ino, src->extent.logical_offset,
			  src->place.start.seg_id,
			  src->place.start.blk_index,
			  src->place.len);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(seg_id >= U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	old_raw_extent.seg_id = cpu_to_le64(src->place.start.seg_id);
	old_raw_extent.logical_blk = cpu_to_le32(src->place.start.blk_index);
	old_raw_extent.len = cpu_to_le32(src->place.len);

	new_raw_extent.seg_id = cpu_to_le64(seg_id);
	new_raw_extent.logical_blk = cpu_to_le32(new_extent.start_lblk);
	new_raw_extent.len = cpu_to_le32(new_extent.len);

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	ssdfs_btree_search_init(search);
	err = ssdfs_extents_tree_move_extent(etree,
					     src->extent.logical_offset,
					     &old_raw_extent,
					     &new_raw_extent,
					     search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to move extent: "
			  "old_extent (seg_id %llu, logical_blk %u, len %u), "
			  "new_extent (seg_id %llu, logical_blk %u, len %u), "
			  "err %d\n",
			  le64_to_cpu(old_raw_extent.seg_id),
			  le32_to_cpu(old_raw_extent.logical_blk),
			  le32_to_cpu(old_raw_extent.len),
			  le64_to_cpu(new_raw_extent.seg_id),
			  le32_to_cpu(new_raw_extent.logical_blk),
			  le32_to_cpu(new_raw_extent.len),
			  err);
		return err;
	}

	return 0;
}

enum {
	SSDFS_ZONE_LEFT_EXTENT,
	SSDFS_ZONE_MAIN_EXTENT,
	SSDFS_ZONE_RIGHT_EXTENT,
	SSDFS_ZONE_MIGRATING_EXTENTS
};

/*
 * ssdfs_zone_move_extent() - move extent (ZNS SSD case)
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to move extent from exhausted zone
 * into current zone for updates.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_zone_move_extent(struct ssdfs_peb_info *pebi,
			   struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_invextree_info *invextree;
	struct ssdfs_btree_search *search;
	struct ssdfs_raw_extent extent;
	struct ssdfs_segment_request *queue[SSDFS_ZONE_MIGRATING_EXTENTS] = {0};
	struct ssdfs_zone_fragment migration;
	struct ssdfs_zone_fragment left_fragment;
	struct ssdfs_zone_fragment *left_fragment_ptr;
	struct ssdfs_zone_fragment right_fragment;
	struct ssdfs_zone_fragment *right_fragment_ptr;
	size_t desc_size = sizeof(struct ssdfs_zone_fragment);
	u32 rest_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);

	SSDFS_DBG("peb %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu, "
		  "seg %llu, logical_block %u, cmd %#x, type %#x, "
		  "processed_blks %d\n",
		  pebi->peb_id, req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->place.start.seg_id, req->place.start.blk_index,
		  req->private.cmd, req->private.type,
		  req->result.processed_blks);

	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.start.blk_index >=
		pebi->pebc->parent_si->fsi->pages_per_seg);
	switch (req->private.class) {
	case SSDFS_PEB_UPDATE_REQ:
	case SSDFS_PEB_PRE_ALLOC_UPDATE_REQ:
	case SSDFS_PEB_DIFF_ON_WRITE_REQ:
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		/* expected case */
		break;
	default:
		BUG();
		break;
	}
	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	rest_bytes = ssdfs_request_rest_bytes(pebi, req);

	memset(&migration, 0xFF, desc_size);
	memset(&left_fragment, 0xFF, desc_size);
	memset(&right_fragment, 0xFF, desc_size);

	err = ssdfs_recommend_migration_extent(fsi, req,
						&migration);
	if (err == -ENODATA) {
		err = 0;
		/* do nothing */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to recommend migration extent: "
			  "err %d\n", err);
		goto finish_zone_move_extent;
	} else {
		err = ssdfs_extract_left_extent(req, &migration,
						&left_fragment);
		if (err == -ENODATA) {
			err = 0;
			SSDFS_DBG("no extent from the left\n");
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to extract left extent: "
				  "seg_id %llu, peb_id %llu, "
				  "logical_block %u, err %d\n",
				  req->place.start.seg_id,
				  pebi->peb_id,
				  req->place.start.blk_index,
				  err);
			goto finish_zone_move_extent;
		} else
			left_fragment_ptr = &left_fragment;

		err = ssdfs_extract_right_extent(req, &migration,
						 &right_fragment);
		if (err == -ENODATA) {
			err = 0;
			SSDFS_DBG("no extent from the right\n");
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to extract right extent: "
				  "seg_id %llu, peb_id %llu, "
				  "logical_block %u, err %d\n",
				  req->place.start.seg_id,
				  pebi->peb_id,
				  req->place.start.blk_index,
				  err);
			goto finish_zone_move_extent;
		} else
			right_fragment_ptr = &right_fragment;
	}

	if (left_fragment_ptr) {
		queue[SSDFS_ZONE_LEFT_EXTENT] = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(queue[SSDFS_ZONE_LEFT_EXTENT])) {
			SSDFS_ERR("fail to allocate segment request\n");
			goto free_moving_requests;
		}
	}

	queue[SSDFS_ZONE_MAIN_EXTENT] = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(queue[SSDFS_ZONE_MAIN_EXTENT])) {
		SSDFS_ERR("fail to allocate segment request\n");
		goto free_moving_requests;
	}

	if (right_fragment_ptr) {
		queue[SSDFS_ZONE_RIGHT_EXTENT] = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(queue[SSDFS_ZONE_RIGHT_EXTENT])) {
			SSDFS_ERR("fail to allocate segment request\n");
			goto free_moving_requests;
		}
	}

	if (left_fragment_ptr) {
		err = ssdfs_zone_prepare_migration_request(pebi,
					   left_fragment_ptr,
					   queue[SSDFS_ZONE_LEFT_EXTENT]);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare zone migration request: "
				  "err %d\n", err);
			goto free_moving_requests;
		}
	}

	err = ssdfs_zone_prepare_move_flush_request(pebi, req,
					queue[SSDFS_ZONE_MAIN_EXTENT]);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare zone move request: "
			  "err %d\n", err);
		goto free_moving_requests;
	}

	if (right_fragment_ptr) {
		err = ssdfs_zone_prepare_migration_request(pebi,
					   left_fragment_ptr,
					   queue[SSDFS_ZONE_RIGHT_EXTENT]);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare zone migration request: "
				  "err %d\n", err);
			goto free_moving_requests;
		}
	}

	for (i = 0; i < SSDFS_ZONE_MIGRATING_EXTENTS; i++) {
		if (queue[i] == NULL)
			continue;

		err = ssdfs_check_zone_move_request(queue[i]);
		if (unlikely(err)) {
			SSDFS_ERR("flush request failed: "
				  "index %d, err %d\n",
				  i, err);
		}

		ssdfs_put_request(queue[i]);
		ssdfs_request_free(queue[i]);
	}

	invextree = fsi->invextree;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!invextree);
#endif /* CONFIG_SSDFS_DEBUG */

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	extent.seg_id = migration.extent.seg_id;
	extent.logical_blk = migration.extent.logical_blk;
	extent.len = migration.extent.len;

	ssdfs_btree_search_init(search);
	err = ssdfs_invextree_add(invextree, &extent, search);
	ssdfs_btree_search_free(search);

	if (unlikely(err)) {
		SSDFS_ERR("fail to add invalidated extent: "
			  "seg_id %llu, logical_blk %u, "
			  "len %u, err %d\n",
			  le64_to_cpu(extent.seg_id),
			  le32_to_cpu(extent.logical_blk),
			  le32_to_cpu(extent.len),
			  err);
		return err;
	}

	return 0;

free_moving_requests:
	for (i = 0; i < SSDFS_ZONE_MIGRATING_EXTENTS; i++) {
		if (queue[i] == NULL)
			continue;

		ssdfs_put_request(queue[i]);
		ssdfs_request_free(queue[i]);
	}

finish_zone_move_extent:
	return err;
}

/*
 * ssdfs_peb_update_block() - update data block
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to update data block in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - try again to update data block.
 * %-ENOENT     - need migrate base state before storing diff.
 */
static
int ssdfs_peb_update_block(struct ssdfs_peb_info *pebi,
			   struct ssdfs_segment_request *req)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&pebi->pebc->migration_phase)) {
	case SSDFS_SHARED_ZONE_RECEIVES_DATA:
		err = ssdfs_zone_move_extent(pebi, req);
		break;

	default:
		err = __ssdfs_peb_update_block(pebi, req);
		break;
	}

	return err;
}

/*
 * __ssdfs_peb_update_extent() - update extent of blocks
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to update extent of blocks in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_peb_update_extent(struct ssdfs_peb_info *pebi,
			      struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	u32 blk;
	u32 rest_bytes;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);

	SSDFS_DBG("peb %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu, "
		  "seg %llu, logical_block %u, cmd %#x, type %#x, "
		  "processed_blks %d\n",
		  pebi->peb_id, req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->place.start.seg_id, req->place.start.blk_index,
		  req->private.cmd, req->private.type,
		  req->result.processed_blks);

	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.start.blk_index >=
		pebi->pebc->parent_si->fsi->pages_per_seg);
	switch (req->private.class) {
	case SSDFS_PEB_UPDATE_REQ:
	case SSDFS_PEB_PRE_ALLOC_UPDATE_REQ:
	case SSDFS_PEB_DIFF_ON_WRITE_REQ:
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		/* expected case */
		break;
	default:
		BUG();
		break;
	}
	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	rest_bytes = ssdfs_request_rest_bytes(pebi, req);

	while (rest_bytes > 0) {
		blk = req->place.start.blk_index +
				req->result.processed_blks;

		err = __ssdfs_peb_update_block(pebi, req);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to update block: "
				  "seg %llu, logical_block %u, "
				  "peb %llu\n",
				  req->place.start.seg_id, blk,
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("need to migrate base state for diff: "
				  "seg %llu, logical_block %u, "
				  "peb %llu\n",
				  req->place.start.seg_id, blk,
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to update block: "
				  "seg %llu, logical_block %u, "
				  "peb %llu, err %d\n",
				  req->place.start.seg_id, blk,
				  pebi->peb_id, err);
			return err;
		}

		rest_bytes = ssdfs_request_rest_bytes(pebi, req);
	};

	return 0;
}

/*
 * ssdfs_peb_update_extent() - update extent of blocks
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to update extent of blocks in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_update_extent(struct ssdfs_peb_info *pebi,
			    struct ssdfs_segment_request *req)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);

	SSDFS_DBG("peb %llu, ino %llu, logical_offset %llu, "
		  "data_bytes %u, cno %llu, parent_snapshot %llu, "
		  "seg %llu, logical_block %u, cmd %#x, type %#x, "
		  "processed_blks %d\n",
		  pebi->peb_id, req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->place.start.seg_id, req->place.start.blk_index,
		  req->private.cmd, req->private.type,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&pebi->pebc->migration_phase)) {
	case SSDFS_SHARED_ZONE_RECEIVES_DATA:
		err = ssdfs_zone_move_extent(pebi, req);
		break;

	default:
		err = __ssdfs_peb_update_extent(pebi, req);
		break;
	}

	return err;
}

/*
 * ssdfs_peb_migrate_pre_allocated_block() - migrate pre-allocated block
 * @pebi: pointer on PEB object
 * @req: I/O request
 *
 * This function tries to update data block in PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_migrate_pre_allocated_block(struct ssdfs_peb_info *pebi,
					  struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_phys_offset_descriptor *blk_desc_off;
	struct ssdfs_peb_phys_offset desc_off = {0};
	u16 peb_index;
	u16 logical_block;
	int processed_blks;
	u64 logical_offset;
	struct ssdfs_block_bmap_range range;
	int range_state;
	int migration_state = SSDFS_LBLOCK_UNKNOWN_STATE;
	struct ssdfs_offset_position pos = {0};
	u32 len;
	u8 id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.start.blk_index >=
		pebi->pebc->parent_si->fsi->pages_per_seg);

	switch (req->private.class) {
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		/* expected state */
		break;
	default:
		SSDFS_ERR("unexpected request: "
			  "req->private.class %#x\n",
			  req->private.class);
		BUG();
	};

	switch (req->private.cmd) {
	case SSDFS_MIGRATE_PRE_ALLOC_PAGE:
		/* expected state */
		break;

	default:
		SSDFS_ERR("unexpected request: "
			  "req->private.cmd %#x\n",
			  req->private.cmd);
		BUG();
	};

	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);
	BUG_ON(req->extent.data_bytes > pebi->pebc->parent_si->fsi->pagesize);
	BUG_ON(req->result.processed_blks > 0);

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	si = pebi->pebc->parent_si;
	table = pebi->pebc->parent_si->blk2off_table;
	seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;
	processed_blks = req->result.processed_blks;
	logical_block = req->place.start.blk_index + processed_blks;
	logical_offset = req->extent.logical_offset +
				((u64)processed_blks * fsi->pagesize);
	logical_offset /= fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, logical_block %u, "
		  "logical_offset %llu, "
		  "processed_blks %d\n",
		  req->place.start.seg_id, pebi->peb_id,
		  logical_block, logical_offset,
		  processed_blks);

	if (req->extent.logical_offset >= U64_MAX) {
		SSDFS_ERR("seg %llu, peb %llu, logical_block %u, "
			  "logical_offset %llu, "
			  "processed_blks %d\n",
			  req->place.start.seg_id, pebi->peb_id,
			  logical_block, logical_offset,
			  processed_blks);
		BUG();
	}
#endif /* CONFIG_SSDFS_DEBUG */

	len = req->extent.data_bytes;
	len -= req->result.processed_blks * si->fsi->pagesize;
	len >>= fsi->log_pagesize;

	blk_desc_off = ssdfs_blk2off_table_convert(table,
						   logical_block,
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
							   logical_block,
							   &peb_index,
							   &migration_state,
							   &pos);
	}

	if (IS_ERR_OR_NULL(blk_desc_off)) {
		err = (blk_desc_off == NULL ? -ERANGE : PTR_ERR(blk_desc_off));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_block, err);
		return err;
	}

	if (migration_state == SSDFS_LBLOCK_UNDER_COMMIT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("try again to add block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EAGAIN;
	}

	range.start = le16_to_cpu(blk_desc_off->page_desc.peb_page);
	range.len = len;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("logical_blk %u, peb_page %u\n",
		  logical_block, range.start);
	SSDFS_DBG("range (start %u, len %u)\n",
		  range.start, range.len);
#endif /* CONFIG_SSDFS_DEBUG */

	range_state = SSDFS_BLK_PRE_ALLOCATED;

	err = ssdfs_segment_blk_bmap_update_range(seg_blkbmap, pebi->pebc,
				blk_desc_off->blk_state.peb_migration_id,
				range_state, &range);
	if (unlikely(err)) {
		SSDFS_ERR("fail to update range: "
			  "seg %llu, peb %llu, "
			  "range (start %u, len %u), err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, range.start, range.len,
			  err);
		return err;
	}

	id = ssdfs_get_peb_migration_id_checked(pebi);
	if (unlikely(id < 0)) {
		SSDFS_ERR("invalid peb_migration_id: "
			  "seg %llu, peb_id %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, id);
		return id;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(id > U8_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	desc_off.peb_index = pebi->peb_index;
	desc_off.peb_migration_id = id;
	desc_off.peb_page = (u16)range.start;
	desc_off.log_area = SSDFS_LOG_AREA_MAX;
	desc_off.byte_offset = U32_MAX;

	err = ssdfs_peb_store_block_descriptor_offset(pebi,
						(u32)logical_offset,
						logical_block,
						NULL,
						&desc_off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store block descriptor offset: "
			  "logical_block %u, logical_offset %llu, "
			  "err %d\n",
			  logical_block, logical_offset, err);
		return err;
	}

	req->result.processed_blks += range.len;
	return 0;
}

/*
 * ssdfs_process_update_request() - process update request
 * @pebi: pointer on PEB object
 * @req: request
 *
 * This function detects command of request and
 * to call a proper function for request processing.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-EAGAIN     - unable to update block.
 */
static
int ssdfs_process_update_request(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req);

	SSDFS_DBG("req %p, cmd %#x, type %#x\n",
		  req, req->private.cmd, req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (req->private.cmd <= SSDFS_CREATE_CMD_MAX ||
	    req->private.cmd >= SSDFS_COLLECT_GARBAGE_CMD_MAX) {
		SSDFS_ERR("unknown update command %d, seg %llu, peb %llu\n",
			  req->private.cmd, pebi->pebc->parent_si->seg_id,
			  pebi->peb_id);
		req->result.err = -EINVAL;
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		return -EINVAL;
	}

	atomic_set(&req->result.state, SSDFS_REQ_STARTED);

	switch (req->private.cmd) {
	case SSDFS_UPDATE_BLOCK:
	case SSDFS_UPDATE_PRE_ALLOC_BLOCK:
		err = ssdfs_peb_update_block(pebi, req);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to update block: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to update block: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_UPDATE_EXTENT:
	case SSDFS_UPDATE_PRE_ALLOC_EXTENT:
		err = ssdfs_peb_update_extent(pebi, req);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to update block: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to update extent: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_BTREE_NODE_DIFF:
		err = ssdfs_peb_update_extent(pebi, req);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to update extent: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("need to migrate base state for diff: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id,
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to update extent: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_USER_DATA_DIFF:
		err = ssdfs_peb_update_block(pebi, req);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to update block: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to update block: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_COMMIT_LOG_NOW:
	case SSDFS_START_MIGRATION_NOW:
	case SSDFS_EXTENT_WAS_INVALIDATED:
		/* simply continue logic */
		break;

	case SSDFS_MIGRATE_RANGE:
		err = ssdfs_peb_update_extent(pebi, req);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to migrate extent: "
				  "seg %llu, peb %llu\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to migrate extent: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_MIGRATE_PRE_ALLOC_PAGE:
		err = ssdfs_peb_migrate_pre_allocated_block(pebi, req);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to migrate pre-alloc page: "
				  "seg %llu, peb %llu\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to migrate pre-alloc page: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_MIGRATE_FRAGMENT:
		err = ssdfs_peb_update_block(pebi, req);
		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to migrate fragment: "
				  "seg %llu, peb %llu\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to migrate fragment: "
				"seg %llu, peb %llu, err %d\n",
				pebi->pebc->parent_si->seg_id,
				pebi->peb_id, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	default:
		BUG();
	}

	if (unlikely(err)) {
		/* request failed */
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);
	} else if (is_ssdfs_peb_containing_user_data(pebi->pebc)) {
		struct ssdfs_peb_container *pebc = pebi->pebc;
		int processed_blks = req->result.processed_blks;
		u32 pending = 0;

		switch (req->private.cmd) {
		case SSDFS_UPDATE_BLOCK:
		case SSDFS_UPDATE_PRE_ALLOC_BLOCK:
		case SSDFS_UPDATE_EXTENT:
		case SSDFS_UPDATE_PRE_ALLOC_EXTENT:
		case SSDFS_BTREE_NODE_DIFF:
		case SSDFS_USER_DATA_DIFF:
		case SSDFS_MIGRATE_RANGE:
		case SSDFS_MIGRATE_PRE_ALLOC_PAGE:
		case SSDFS_MIGRATE_FRAGMENT:
			spin_lock(&pebc->pending_lock);
			pending = pebc->pending_updated_user_data_pages;
			if (pending >= processed_blks) {
				pebc->pending_updated_user_data_pages -=
								processed_blks;
				pending = pebc->pending_updated_user_data_pages;
			} else {
				/* wrong accounting */
				err = -ERANGE;
			}
			spin_unlock(&pebc->pending_lock);
			break;

		default:
			/* do nothing */
			break;
		}

		if (unlikely(err)) {
			SSDFS_ERR("pending %u < processed_blks %d\n",
				  pending, processed_blks);
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("seg_id %llu, peb_index %u, pending %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->pebc->peb_index,
				  pending);
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}

	return err;
}

/*
 * ssdfs_peb_has_dirty_pages() - check that PEB has dirty pages
 * @pebi: pointer on PEB object
 */
bool ssdfs_peb_has_dirty_pages(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_page_array *area_pages;
	bool is_peb_dirty = false;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_LOG_AREA_MAX; i++) {
		area_pages = &pebi->current_log.area[i].array;

		if (atomic_read(&area_pages->state) == SSDFS_PAGE_ARRAY_DIRTY) {
			is_peb_dirty = true;
			break;
		}
	}

	return is_peb_dirty;
}

/*
 * is_full_log_ready() - check that full log is ready
 * @pebi: pointer on PEB object
 */
static inline
bool is_full_log_ready(struct ssdfs_peb_info *pebi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, free_data_pages %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  pebi->current_log.free_data_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	return pebi->current_log.free_data_pages == 0;
}

/*
 * should_partial_log_being_commited() - check that it's time to commit
 * @pebi: pointer on PEB object
 */
static inline
bool should_partial_log_being_commited(struct ssdfs_peb_info *pebi)
{
	u16 free_data_pages;
	u16 min_partial_log_pages;
	int log_strategy;
	bool time_to_commit = false;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	free_data_pages = pebi->current_log.free_data_pages;
	min_partial_log_pages = ssdfs_peb_estimate_min_partial_log_pages(pebi);

	log_strategy = is_log_partial(pebi);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, log_strategy %#x, "
		  "free_data_pages %u, min_partial_log_pages %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, log_strategy,
		  free_data_pages, min_partial_log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (log_strategy) {
	case SSDFS_START_FULL_LOG:
	case SSDFS_START_PARTIAL_LOG:
		if (free_data_pages <= min_partial_log_pages) {
			time_to_commit = true;
		} else {
			time_to_commit = false;
		}
		break;

	case SSDFS_CONTINUE_PARTIAL_LOG:
	case SSDFS_FINISH_PARTIAL_LOG:
	case SSDFS_FINISH_FULL_LOG:
		/* do nothing */
		time_to_commit = false;
		break;

	default:
		SSDFS_CRIT("unexpected log strategy %#x\n",
			   log_strategy);
		time_to_commit = false;
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("time_to_commit %#x\n", time_to_commit);
#endif /* CONFIG_SSDFS_DEBUG */

	return time_to_commit;
}

/*
 * ssdfs_reserve_segment_header() - reserve space for segment header
 * @pebi: pointer on PEB object
 * @log_offset: current log offset [in|out]
 *
 * This function reserves space for segment header in PEB's cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - fail to allocate page.
 */
static
int ssdfs_reserve_segment_header(struct ssdfs_peb_info *pebi,
				 struct ssdfs_peb_log_offset *log_offset)
{
	struct page *page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!log_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));

	if (log_offset->cur_page != pebi->current_log.start_page) {
		SSDFS_ERR("cur_page %lu != start_page %u\n",
			  log_offset->cur_page,
			  pebi->current_log.start_page);
		return -EINVAL;
	}

	if (SSDFS_LOCAL_LOG_OFFSET(log_offset) != 0) {
		SSDFS_ERR("write_offset %u != 0\n",
			  SSDFS_LOCAL_LOG_OFFSET(log_offset));
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	page = ssdfs_page_array_grab_page(&pebi->cache, log_offset->cur_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to grab cache page: index %lu\n",
			  log_offset->cur_page);
		return -ENOMEM;
	}

	/* prepare header space */
	ssdfs_memset_page(page, 0, PAGE_SIZE, 0xFF, PAGE_SIZE);

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	err = SSDFS_SHIFT_LOG_OFFSET(log_offset,
			offsetof(struct ssdfs_segment_header, payload));
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift log offset: "
			  "err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_reserve_partial_log_header() - reserve space for partial log's header
 * @pebi: pointer on PEB object
 * @log_offset: current log offset [in|out]
 *
 * This function reserves space for partial log's header in PEB's cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - fail to allocate page.
 */
static
int ssdfs_reserve_partial_log_header(struct ssdfs_peb_info *pebi,
				     struct ssdfs_peb_log_offset *log_offset)
{
	struct page *page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!log_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));

	if (log_offset->cur_page != pebi->current_log.start_page) {
		SSDFS_ERR("cur_page %lu != start_page %u\n",
			  log_offset->cur_page,
			  pebi->current_log.start_page);
		return -EINVAL;
	}

	if (SSDFS_LOCAL_LOG_OFFSET(log_offset) != 0) {
		SSDFS_ERR("write_offset %u != 0\n",
			  SSDFS_LOCAL_LOG_OFFSET(log_offset));
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	page = ssdfs_page_array_grab_page(&pebi->cache, log_offset->cur_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to grab cache page: index %lu\n",
			  log_offset->cur_page);
		return -ENOMEM;
	}

	/* prepare header space */
	ssdfs_memset_page(page, 0, PAGE_SIZE, 0xFF, PAGE_SIZE);

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	err = SSDFS_SHIFT_LOG_OFFSET(log_offset,
			offsetof(struct ssdfs_partial_log_header, payload));
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift log offset: "
			  "err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_store_pagevec() - store pagevec into page cache
 * @desc: descriptor of pagevec environment
 *
 * This function tries to store pagevec into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_pagevec(struct ssdfs_pagevec_descriptor *desc)
{
	struct ssdfs_fs_info *fsi;
	struct page *src_page, *dst_page;
	unsigned char *kaddr;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
	BUG_ON(!desc->pebi || !desc->pebi->pebc->parent_si);
	BUG_ON(!desc->pebi->pebc->parent_si->fsi);
	BUG_ON(!desc->page_vec || !desc->desc_array);
	BUG_ON(!desc->log_offset);

	switch (desc->compression_type) {
	case SSDFS_FRAGMENT_UNCOMPR_BLOB:
	case SSDFS_FRAGMENT_ZLIB_BLOB:
	case SSDFS_FRAGMENT_LZO_BLOB:
		/* valid type */
		break;

	default:
		SSDFS_WARN("invalid compression %#x\n",
			   desc->compression_type);
		return -EINVAL;
	}

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  desc->pebi->pebc->parent_si->seg_id,
		  desc->pebi->peb_id,
		  desc->pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = desc->pebi->pebc->parent_si->fsi;
	desc->compr_size = 0;
	desc->uncompr_size = 0;
	desc->fragments_count = 0;

	for (i = 0; i < ssdfs_page_vector_count(desc->page_vec); i++) {
		size_t iter_bytes;
		size_t dst_page_off;
		size_t dst_free_space;
		struct ssdfs_fragment_source from;
		struct ssdfs_fragment_destination to;

		BUG_ON(i >= desc->array_capacity);

		if (desc->uncompr_size > desc->bytes_count) {
			SSDFS_WARN("uncompr_size %u > bytes_count %zu\n",
				   desc->uncompr_size,
				   desc->bytes_count);
			break;
		} else if (desc->uncompr_size == desc->bytes_count)
			break;

		iter_bytes = min_t(size_t, PAGE_SIZE,
				   desc->bytes_count - desc->uncompr_size);

		src_page = desc->page_vec->pages[i];

try_get_next_page:
		dst_page = ssdfs_page_array_grab_page(&desc->pebi->cache,
						desc->log_offset->cur_page);
		if (IS_ERR_OR_NULL(dst_page)) {
			SSDFS_ERR("fail to grab cache page: index %lu\n",
				  desc->log_offset->cur_page);
			return -ENOMEM;
		}

		dst_page_off = desc->log_offset->offset_into_page;
		dst_free_space = PAGE_SIZE - dst_page_off;

		kaddr = kmap_local_page(dst_page);

		from.page = src_page;
		from.start_offset = 0;
		from.data_bytes = iter_bytes;
		from.sequence_id = desc->start_sequence_id + i;
		from.fragment_type = desc->compression_type;
		from.fragment_flags = SSDFS_FRAGMENT_HAS_CSUM;

		to.area_offset = desc->area_offset;
		to.write_offset = SSDFS_LOCAL_LOG_OFFSET(desc->log_offset);
		to.store = kaddr + dst_page_off;
		to.free_space = dst_free_space;
		to.compr_size = 0;
		to.desc = &desc->desc_array[i];

		err = ssdfs_peb_store_fragment(&from, &to);

		flush_dcache_page(dst_page);
		kunmap_local(kaddr);

		if (!err) {
			ssdfs_set_page_private(dst_page, 0);
			SetPageUptodate(dst_page);

			err =
			    ssdfs_page_array_set_page_dirty(&desc->pebi->cache,
						    desc->log_offset->cur_page);
			if (unlikely(err)) {
				SSDFS_ERR("fail to set page %lu dirty: "
					  "err %d\n",
					  desc->log_offset->cur_page, err);
			}
		}

		ssdfs_unlock_page(dst_page);
		ssdfs_put_page(dst_page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  dst_page, page_ref_count(dst_page));
#endif /* CONFIG_SSDFS_DEBUG */

		if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("try to get next page: "
				  "write_offset %u, dst_free_space %zu\n",
				  SSDFS_LOCAL_LOG_OFFSET(desc->log_offset),
				  dst_free_space);
#endif /* CONFIG_SSDFS_DEBUG */

			err = SSDFS_SHIFT_LOG_OFFSET(desc->log_offset,
						     dst_free_space);
			if (unlikely(err)) {
				SSDFS_ERR("fail to shift log offset: "
					  "err %d\n", err);
				return err;
			}

			goto try_get_next_page;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to store fragment: "
				  "sequence_id %u, write_offset %u, err %d\n",
				  desc->start_sequence_id + i,
				  SSDFS_LOCAL_LOG_OFFSET(desc->log_offset),
				  err);
			return err;
		}

		err = SSDFS_SHIFT_LOG_OFFSET(desc->log_offset, to.compr_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to shift log offset: "
				  "err %d\n", err);
			return err;
		}

		desc->uncompr_size += iter_bytes;
		desc->compr_size += to.compr_size;
		desc->fragments_count++;
	}

	return 0;
}

/*
 * ssdfs_peb_store_blk_bmap_fragment() - store fragment of block bitmap
 * @desc: descriptor of block bitmap fragment environment
 * @bmap_hdr_offset: offset of header from log's beginning
 *
 * This function tries to store block bitmap fragment
 * into PEB's log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_blk_bmap_fragment(struct ssdfs_bmap_descriptor *desc,
				      u32 bmap_hdr_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_bitmap_fragment *frag_hdr = NULL;
	struct ssdfs_fragment_desc *frag_desc_array = NULL;
	size_t frag_hdr_size = sizeof(struct ssdfs_block_bitmap_fragment);
	size_t frag_desc_size = sizeof(struct ssdfs_fragment_desc);
	size_t allocation_size = 0;
	u32 frag_hdr_off;
	struct ssdfs_pagevec_descriptor pvec_desc;
	u32 pages_per_peb;
	struct page *page;
	pgoff_t index;
	u32 page_off;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
	BUG_ON(!desc->pebi || !desc->log_offset);
	BUG_ON(ssdfs_page_vector_count(desc->snapshot) == 0);

	switch (desc->compression_type) {
	case SSDFS_BLK_BMAP_NOCOMPR_TYPE:
	case SSDFS_BLK_BMAP_ZLIB_COMPR_TYPE:
	case SSDFS_BLK_BMAP_LZO_COMPR_TYPE:
		/* valid type */
		break;

	default:
		SSDFS_WARN("invalid compression %#x\n",
			   desc->compression_type);
		return -EINVAL;
	}

	SSDFS_DBG("peb_id %llu, peb_index %u, "
		  "cur_page %lu, write_offset %u, "
		  "desc->compression_type %#x\n",
		  desc->pebi->peb_id,
		  desc->pebi->peb_index,
		  desc->log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(desc->log_offset),
		  desc->compression_type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = desc->pebi->pebc->parent_si->fsi;

	allocation_size = frag_hdr_size;
	allocation_size +=
		ssdfs_page_vector_count(desc->snapshot) * frag_desc_size;

	frag_hdr = ssdfs_flush_kzalloc(allocation_size, GFP_KERNEL);
	if (!frag_hdr) {
		SSDFS_ERR("unable to allocate block bmap header\n");
		return -ENOMEM;
	}

	frag_hdr_off = SSDFS_LOCAL_LOG_OFFSET(desc->log_offset);

	err = SSDFS_SHIFT_LOG_OFFSET(desc->log_offset, allocation_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift log offset: "
			  "err %d\n", err);
		return err;
	}

	frag_desc_array = (struct ssdfs_fragment_desc *)((u8 *)frag_hdr +
							  frag_hdr_size);

	switch (desc->compression_type) {
	case SSDFS_BLK_BMAP_NOCOMPR_TYPE:
		pvec_desc.compression_type = SSDFS_FRAGMENT_UNCOMPR_BLOB;
		break;

	case SSDFS_BLK_BMAP_ZLIB_COMPR_TYPE:
		pvec_desc.compression_type = SSDFS_FRAGMENT_ZLIB_BLOB;
		break;

	case SSDFS_BLK_BMAP_LZO_COMPR_TYPE:
		pvec_desc.compression_type = SSDFS_FRAGMENT_LZO_BLOB;
		break;

	default:
		SSDFS_WARN("invalid compression %#x\n",
			   desc->compression_type);
		return -EINVAL;
	}

	pvec_desc.pebi = desc->pebi;
	pvec_desc.start_sequence_id = 0;
	pvec_desc.area_offset = bmap_hdr_offset;
	pvec_desc.page_vec = desc->snapshot;
	pvec_desc.bytes_count = desc->bytes_count;
	pvec_desc.desc_array = frag_desc_array;
	pvec_desc.array_capacity = SSDFS_BLK_BMAP_FRAGMENTS_CHAIN_MAX;
	pvec_desc.log_offset = desc->log_offset;

	err = ssdfs_peb_store_pagevec(&pvec_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store block bitmap in the log: "
			  "seg %llu, peb %llu, write_offset %u, "
			  "err %d\n",
			  desc->pebi->pebc->parent_si->seg_id,
			  desc->pebi->peb_id,
			  SSDFS_LOCAL_LOG_OFFSET(desc->log_offset),
			  err);
		goto fail_store_bmap_fragment;
	}

	frag_hdr->peb_index = cpu_to_le16(desc->peb_index);
	frag_hdr->sequence_id = *(desc->frag_id);
	*(desc->frag_id) += 1;
	frag_hdr->flags = desc->flags;
	frag_hdr->type = desc->type;

	pages_per_peb = fsi->pages_per_peb;

	if (desc->last_free_blk >= pages_per_peb) {
		SSDFS_ERR("last_free_page %u >= pages_per_peb %u\n",
			  desc->last_free_blk, pages_per_peb);
		err = -ERANGE;
		goto fail_store_bmap_fragment;
	}

	if ((desc->invalid_blks + desc->metadata_blks) > pages_per_peb) {
		SSDFS_ERR("invalid descriptor state: "
			  "invalid_blks %u, metadata_blks %u, "
			  "pages_per_peb %u\n",
			  desc->invalid_blks,
			  desc->metadata_blks,
			  pages_per_peb);
		err = -ERANGE;
		goto fail_store_bmap_fragment;
	}

	frag_hdr->last_free_blk = cpu_to_le32(desc->last_free_blk);
	frag_hdr->metadata_blks = cpu_to_le32(desc->metadata_blks);
	frag_hdr->invalid_blks = cpu_to_le32(desc->invalid_blks);

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(pvec_desc.compr_size > pvec_desc.uncompr_size);
	WARN_ON(pvec_desc.compr_size >
			desc->pebi->pebc->parent_si->fsi->segsize);
#endif /* CONFIG_SSDFS_DEBUG */
	frag_hdr->chain_hdr.compr_bytes = cpu_to_le32(pvec_desc.compr_size);

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(pvec_desc.uncompr_size >
			desc->pebi->pebc->parent_si->fsi->segsize);
#endif /* CONFIG_SSDFS_DEBUG */
	frag_hdr->chain_hdr.uncompr_bytes = cpu_to_le32(pvec_desc.uncompr_size);

#ifdef CONFIG_SSDFS_DEBUG
	WARN_ON(pvec_desc.fragments_count > SSDFS_BLK_BMAP_FRAGMENTS_CHAIN_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	frag_hdr->chain_hdr.fragments_count =
		cpu_to_le16(pvec_desc.fragments_count);

	frag_hdr->chain_hdr.desc_size = cpu_to_le16(frag_desc_size);
	frag_hdr->chain_hdr.magic = SSDFS_CHAIN_HDR_MAGIC;
	frag_hdr->chain_hdr.type = SSDFS_BLK_BMAP_CHAIN_HDR;
	frag_hdr->chain_hdr.flags = 0;

	index = ssdfs_write_offset_to_mem_page_index(fsi,
				desc->pebi->current_log.start_page,
				frag_hdr_off);

	page = ssdfs_page_array_get_page_locked(&desc->pebi->cache, index);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %lu\n", index);
		err = -ENOMEM;
		goto fail_store_bmap_fragment;
	}

	page_off = frag_hdr_off % PAGE_SIZE;

	err = ssdfs_memcpy_to_page(page, page_off, PAGE_SIZE,
				   frag_hdr, 0, allocation_size,
				   allocation_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: "
			  "page_off %u, allocation_size %zu, err %d\n",
			  page_off, allocation_size, err);
		goto finish_copy;
	}

	ssdfs_set_page_private(page, 0);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&desc->pebi->cache, index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: "
			  "err %d\n",
			  index, err);
	}

finish_copy:
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

fail_store_bmap_fragment:
	ssdfs_block_bmap_forget_snapshot(desc->snapshot);
	ssdfs_flush_kfree(frag_hdr);
	return err;
}

/*
 * ssdfs_peb_store_dst_blk_bmap() - store destination block bitmap
 * @pebi: pointer on PEB object
 * @items_state: PEB container's items state
 * @compression: compression type
 * @bmap_hdr_off: offset from log's beginning to bitmap header
 * @frag_id: pointer on fragments counter [in|out]
 * @log_offset: current log offset [in|out]
 *
 * This function tries to store destination block bitmap
 * into destination PEB's log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_dst_blk_bmap(struct ssdfs_peb_info *pebi,
				 int items_state,
				 u8 compression,
				 u32 bmap_hdr_off,
				 u8 *frag_id,
				 struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_block_bmap *bmap;
	struct ssdfs_bmap_descriptor desc;
	int buffers_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!frag_id || !log_offset);
	BUG_ON(!rwsem_is_locked(&pebi->pebc->lock));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	switch (items_state) {
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		return -EINVAL;
	}

	switch (compression) {
	case SSDFS_BLK_BMAP_NOCOMPR_TYPE:
	case SSDFS_BLK_BMAP_ZLIB_COMPR_TYPE:
	case SSDFS_BLK_BMAP_LZO_COMPR_TYPE:
		/* valid type */
		break;

	default:
		SSDFS_WARN("invalid compression %#x\n",
			   compression);
		return -EINVAL;
	}

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_index,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	desc.compression_type = compression;
	desc.flags = SSDFS_PEB_HAS_RELATION | SSDFS_MIGRATING_BLK_BMAP;
	desc.type = SSDFS_DST_BLK_BMAP;
	desc.frag_id = frag_id;
	desc.log_offset = log_offset;

	desc.snapshot = &pebi->current_log.bmap_snapshot;

	if (!pebi->pebc->src_peb || !pebi->pebc->dst_peb) {
		SSDFS_WARN("empty src or dst PEB pointer\n");
		return -ERANGE;
	}

	if (pebi == pebi->pebc->src_peb)
		desc.pebi = pebi->pebc->src_peb;
	else
		desc.pebi = pebi->pebc->dst_peb;

	if (!desc.pebi) {
		SSDFS_WARN("destination PEB doesn't exist\n");
		return -ERANGE;
	}

	desc.peb_index = desc.pebi->peb_index;

	seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;
	peb_blkbmap = &seg_blkbmap->peb[pebi->pebc->peb_index];

	err = ssdfs_page_vector_init(desc.snapshot);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init page vector: "
			  "err %d\n", err);
		return err;
	}

	if (!ssdfs_peb_blk_bmap_initialized(peb_blkbmap)) {
		SSDFS_ERR("PEB's block bitmap isn't initialized\n");
		return -ERANGE;
	}

	down_read(&peb_blkbmap->lock);

	buffers_state = atomic_read(&peb_blkbmap->buffers_state);
	switch (buffers_state) {
	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		/* valid state */
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid buffers_state %#x\n",
			   buffers_state);
		goto finish_store_dst_blk_bmap;
	}

	bmap = peb_blkbmap->dst;
	if (!bmap) {
		err = -ERANGE;
		SSDFS_WARN("destination bitmap doesn't exist\n");
		goto finish_store_dst_blk_bmap;
	}

	err = ssdfs_block_bmap_lock(bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_store_dst_blk_bmap;
	}

	err = ssdfs_block_bmap_snapshot(bmap, desc.snapshot,
					&desc.last_free_blk,
					&desc.metadata_blks,
					&desc.invalid_blks,
					&desc.bytes_count);

	ssdfs_block_bmap_unlock(bmap);

	if (unlikely(err)) {
		SSDFS_ERR("fail to snapshot block bitmap: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index, err);
		goto finish_store_dst_blk_bmap;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, DST: last_free_blk %u, "
		  "metadata_blks %u, invalid_blks %u\n",
		  pebi->peb_id, desc.last_free_blk,
		  desc.metadata_blks, desc.invalid_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	if (ssdfs_page_vector_count(desc.snapshot) == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty block bitmap\n");
		goto finish_store_dst_blk_bmap;
	}

finish_store_dst_blk_bmap:
	up_read(&peb_blkbmap->lock);

	if (unlikely(err))
		return err;

	return ssdfs_peb_store_blk_bmap_fragment(&desc, bmap_hdr_off);
}

/*
 * ssdfs_peb_store_source_blk_bmap() - store source block bitmap
 * @pebi: pointer on PEB object
 * @items_state: PEB container's items state
 * @compression: compression type
 * @bmap_hdr_off: offset from log's beginning to bitmap header
 * @frag_id: pointer on fragments counter [in|out]
 * @log_offset: current log offset [in|out]
 *
 * This function tries to store source block bitmap
 * into destination PEB's log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_source_blk_bmap(struct ssdfs_peb_info *pebi,
				    int items_state,
				    u8 compression,
				    u32 bmap_hdr_off,
				    u8 *frag_id,
				    struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_block_bmap *bmap;
	struct ssdfs_bmap_descriptor desc;
	int buffers_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!frag_id || !log_offset);
	BUG_ON(!pebi);
	BUG_ON(!rwsem_is_locked(&pebi->pebc->lock));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	switch (items_state) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		return -EINVAL;
	}

	switch (compression) {
	case SSDFS_BLK_BMAP_NOCOMPR_TYPE:
	case SSDFS_BLK_BMAP_ZLIB_COMPR_TYPE:
	case SSDFS_BLK_BMAP_LZO_COMPR_TYPE:
		/* valid type */
		break;

	default:
		SSDFS_WARN("invalid compression %#x\n",
			   compression);
		return -EINVAL;
	}

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_index,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	desc.compression_type = compression;
	desc.frag_id = frag_id;
	desc.log_offset = log_offset;

	desc.snapshot = &pebi->current_log.bmap_snapshot;

	switch (items_state) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
		desc.flags = 0;
		desc.type = SSDFS_SRC_BLK_BMAP;
		desc.pebi = pebi->pebc->src_peb;
		break;

	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		if (!pebi->pebc->src_peb || !pebi->pebc->dst_peb) {
			SSDFS_WARN("empty src or dst PEB pointer\n");
			return -ERANGE;
		}

		desc.flags = SSDFS_PEB_HAS_RELATION |
				SSDFS_MIGRATING_BLK_BMAP;
		desc.type = SSDFS_SRC_BLK_BMAP;

		if (pebi == pebi->pebc->src_peb)
			desc.pebi = pebi->pebc->src_peb;
		else
			desc.pebi = pebi->pebc->dst_peb;
		break;

	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		desc.flags = SSDFS_MIGRATING_BLK_BMAP;
		desc.type = SSDFS_DST_BLK_BMAP;
		/* log could be created in destintaion PEB only */
		desc.pebi = pebi->pebc->dst_peb;
		break;

	default:
		BUG();
	}

	if (!desc.pebi) {
		SSDFS_WARN("destination PEB doesn't exist\n");
		return -ERANGE;
	}

	desc.peb_index = desc.pebi->peb_index;

	seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;
	peb_blkbmap = &seg_blkbmap->peb[pebi->peb_index];

	err = ssdfs_page_vector_init(desc.snapshot);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init page vector: "
			  "err %d\n", err);
		return err;
	}

	if (!ssdfs_peb_blk_bmap_initialized(peb_blkbmap)) {
		SSDFS_ERR("PEB's block bitmap isn't initialized\n");
		return -ERANGE;
	}

	down_read(&peb_blkbmap->lock);

	buffers_state = atomic_read(&peb_blkbmap->buffers_state);
	switch (buffers_state) {
	case SSDFS_PEB_BMAP1_SRC:
	case SSDFS_PEB_BMAP2_SRC:
	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		/* valid state */
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid buffers_state %#x\n",
			   buffers_state);
		goto finish_store_src_blk_bmap;
	}

	bmap = peb_blkbmap->src;
	if (!bmap) {
		err = -ERANGE;
		SSDFS_WARN("source bitmap doesn't exist\n");
		goto finish_store_src_blk_bmap;
	}

	err = ssdfs_block_bmap_lock(bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
		goto finish_store_src_blk_bmap;
	}

	err = ssdfs_block_bmap_snapshot(bmap, desc.snapshot,
					&desc.last_free_blk,
					&desc.metadata_blks,
					&desc.invalid_blks,
					&desc.bytes_count);

	ssdfs_block_bmap_unlock(bmap);

	if (unlikely(err)) {
		SSDFS_ERR("fail to snapshot block bitmap: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index, err);
		goto finish_store_src_blk_bmap;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, SRC: last_free_blk %u, "
		  "metadata_blks %u, invalid_blks %u\n",
		  pebi->peb_id, desc.last_free_blk,
		  desc.metadata_blks, desc.invalid_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	if (desc.metadata_blks == 0) {
		SSDFS_WARN("peb_id %llu, SRC: last_free_blk %u, "
			   "metadata_blks %u, invalid_blks %u\n",
			   pebi->peb_id, desc.last_free_blk,
			   desc.metadata_blks, desc.invalid_blks);
		BUG();
	}

	if (ssdfs_page_vector_count(desc.snapshot) == 0) {
		err = -ERANGE;
		SSDFS_ERR("empty block bitmap\n");
		goto finish_store_src_blk_bmap;
	}

finish_store_src_blk_bmap:
	up_read(&peb_blkbmap->lock);

	if (unlikely(err))
		return err;

	return ssdfs_peb_store_blk_bmap_fragment(&desc, bmap_hdr_off);
}

/*
 * ssdfs_peb_store_dependent_blk_bmap() - store dependent source bitmaps
 * @pebi: pointer on PEB object
 * @items_state: PEB container's items state
 * @compression: compression type
 * @bmap_hdr_off: offset from log's beginning to bitmap header
 * @frag_id: pointer on fragments counter [in|out]
 * @log_offset: current log offset [in|out]
 *
 * This function tries to store dependent source block bitmaps
 * of migrating PEBs into destination PEB's log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_dependent_blk_bmap(struct ssdfs_peb_info *pebi,
					int items_state,
					u8 compression,
					u32 bmap_hdr_off,
					u8 *frag_id,
					struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_block_bmap *bmap;
	struct ssdfs_bmap_descriptor desc;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!frag_id || !log_offset);
	BUG_ON(!rwsem_is_locked(&pebi->pebc->lock));
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	switch (items_state) {
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		return -EINVAL;
	}

	switch (compression) {
	case SSDFS_BLK_BMAP_NOCOMPR_TYPE:
	case SSDFS_BLK_BMAP_ZLIB_COMPR_TYPE:
	case SSDFS_BLK_BMAP_LZO_COMPR_TYPE:
		/* valid type */
		break;

	default:
		SSDFS_WARN("invalid compression %#x\n",
			   compression);
		return -EINVAL;
	}

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_index,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	desc.compression_type = compression;
	desc.frag_id = frag_id;
	desc.log_offset = log_offset;

	desc.snapshot = &pebi->current_log.bmap_snapshot;

	switch (items_state) {
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		desc.flags = SSDFS_PEB_HAS_EXT_PTR | SSDFS_MIGRATING_BLK_BMAP;
		desc.type = SSDFS_SRC_BLK_BMAP;
		desc.pebi = pebi->pebc->dst_peb;
		break;

	default:
		BUG();
	}

	if (!desc.pebi) {
		SSDFS_WARN("destination PEB doesn't exist\n");
		return -ERANGE;
	}

	seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;

	for (i = 0; i < pebi->pebc->parent_si->pebs_count; i++) {
		struct ssdfs_peb_container *cur_pebc;
		struct ssdfs_peb_info *dst_peb;
		int buffers_state;

		cur_pebc = &pebi->pebc->parent_si->peb_array[i];

		switch (atomic_read(&cur_pebc->items_state)) {
		case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
		case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
			/* do nothing here */
			break;

		default:
			continue;
		};

		down_read(&cur_pebc->lock);
		dst_peb = cur_pebc->dst_peb;
		up_read(&cur_pebc->lock);

		if (dst_peb == NULL) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("dst_peb is NULL: "
				  "peb_index %u\n",
				  i);
#endif /* CONFIG_SSDFS_DEBUG */
			continue;
		} else if (dst_peb != pebi->pebc->dst_peb)
			continue;

		peb_blkbmap = &seg_blkbmap->peb[i];

		err = ssdfs_page_vector_init(desc.snapshot);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init page vector: "
				  "err %d\n", err);
			return err;
		}

		desc.peb_index = (u16)i;

		if (!ssdfs_peb_blk_bmap_initialized(peb_blkbmap)) {
			SSDFS_ERR("PEB's block bitmap isn't initialized\n");
			return -ERANGE;
		}

		down_read(&peb_blkbmap->lock);

		buffers_state = atomic_read(&peb_blkbmap->buffers_state);
		switch (buffers_state) {
		case SSDFS_PEB_BMAP1_SRC:
		case SSDFS_PEB_BMAP2_SRC:
			/* valid state */
			break;

		default:
			err = -ERANGE;
			SSDFS_WARN("invalid buffers_state %#x\n",
				   buffers_state);
			goto finish_store_dependent_blk_bmap;
		}

		bmap = peb_blkbmap->src;
		if (!bmap) {
			err = -ERANGE;
			SSDFS_WARN("source bitmap doesn't exist\n");
			goto finish_store_dependent_blk_bmap;
		}

		err = ssdfs_block_bmap_lock(bmap);
		if (unlikely(err)) {
			SSDFS_ERR("fail to lock block bitmap: err %d\n", err);
			goto finish_store_dependent_blk_bmap;
		}

		err = ssdfs_block_bmap_snapshot(bmap, desc.snapshot,
						&desc.last_free_blk,
						&desc.metadata_blks,
						&desc.invalid_blks,
						&desc.bytes_count);

		ssdfs_block_bmap_unlock(bmap);

		if (unlikely(err)) {
			SSDFS_ERR("fail to snapshot block bitmap: "
				  "seg %llu, peb_index %u, err %d\n",
				  cur_pebc->parent_si->seg_id,
				  cur_pebc->peb_index, err);
			goto finish_store_dependent_blk_bmap;
		}

		if (ssdfs_page_vector_count(desc.snapshot) == 0) {
			err = -ERANGE;
			SSDFS_ERR("empty block bitmap\n");
			goto finish_store_dependent_blk_bmap;
		}

finish_store_dependent_blk_bmap:
		up_read(&peb_blkbmap->lock);

		if (unlikely(err))
			return err;

		err = ssdfs_peb_store_blk_bmap_fragment(&desc, bmap_hdr_off);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store block bitmap fragment: "
				  "peb_index %u, err %d\n",
				  i, err);
			return err;
		}

		ssdfs_block_bmap_forget_snapshot(desc.snapshot);
	}

	return 0;
}

static inline
void ssdfs_prepare_blk_bmap_options(struct ssdfs_fs_info *fsi,
				    u16 *flags, u8 *compression)
{
	u8 type;

	*flags = fsi->metadata_options.blk_bmap.flags;
	type = fsi->metadata_options.blk_bmap.compression;

	*compression = SSDFS_BLK_BMAP_UNCOMPRESSED_BLOB;

	if (*flags & SSDFS_BLK_BMAP_MAKE_COMPRESSION) {
		switch (type) {
		case SSDFS_BLK_BMAP_NOCOMPR_TYPE:
			*compression = SSDFS_BLK_BMAP_UNCOMPRESSED_BLOB;
			break;

		case SSDFS_BLK_BMAP_ZLIB_COMPR_TYPE:
			*compression = SSDFS_BLK_BMAP_ZLIB_BLOB;
			break;

		case SSDFS_BLK_BMAP_LZO_COMPR_TYPE:
			*compression = SSDFS_BLK_BMAP_LZO_BLOB;
			break;
		}
	}
}

/*
 * ssdfs_peb_store_block_bmap() - store block bitmap into page cache
 * @pebi: pointer on PEB object
 * @desc: block bitmap descriptor [out]
 * @log_offset: current log offset [in|out]
 *
 * This function tries to store block bitmap into log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_block_bmap(struct ssdfs_peb_info *pebi,
				struct ssdfs_metadata_descriptor *desc,
				struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_block_bitmap_header *bmap_hdr = NULL;
	size_t bmap_hdr_size = sizeof(struct ssdfs_block_bitmap_header);
	int items_state;
	u8 frag_id = 0;
	u32 bmap_hdr_off;
	u32 pages_per_peb;
	u16 log_start_page = 0;
	u16 flags = 0;
	u8 compression = SSDFS_BLK_BMAP_UNCOMPRESSED_BLOB;
	struct page *page;
	pgoff_t index;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(flags & ~SSDFS_BLK_BMAP_FLAG_MASK);
	BUG_ON(!desc || !log_offset);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_index,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;

	pages_per_peb = min_t(u32, fsi->leb_pages_capacity,
				   fsi->peb_pages_capacity);

	ssdfs_prepare_blk_bmap_options(fsi, &flags, &compression);

	bmap_hdr_off = SSDFS_LOCAL_LOG_OFFSET(log_offset);

	err = SSDFS_SHIFT_LOG_OFFSET(log_offset, bmap_hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift log offset: "
			  "err %d\n", err);
		return err;
	}

	items_state = atomic_read(&pebi->pebc->items_state);
	switch (items_state) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
		/* Prepare source bitmap only */
		err = ssdfs_peb_store_source_blk_bmap(pebi, items_state,
						      compression,
						      bmap_hdr_off,
						      &frag_id,
						      log_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store source bitmap: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  log_offset->cur_page,
				  SSDFS_LOCAL_LOG_OFFSET(log_offset),
				  err);
			goto finish_store_block_bitmap;
		}
		break;

	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		if (!pebi->pebc->src_peb || !pebi->pebc->dst_peb) {
			err = -ERANGE;
			SSDFS_WARN("invalid src or dst PEB pointer\n");
			goto finish_store_block_bitmap;
		}

		/*
		 * Prepare
		 * (1) destination bitmap
		 * (2) source bitmap
		 * (3) all dependent bitmaps
		 */
		err = ssdfs_peb_store_dst_blk_bmap(pebi, items_state,
						   compression,
						   bmap_hdr_off,
						   &frag_id,
						   log_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store destination bitmap: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  log_offset->cur_page,
				  SSDFS_LOCAL_LOG_OFFSET(log_offset),
				  err);
			goto finish_store_block_bitmap;
		}

		err = ssdfs_peb_store_source_blk_bmap(pebi, items_state,
						      compression,
						      bmap_hdr_off,
						      &frag_id,
						      log_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store source bitmap: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  log_offset->cur_page,
				  SSDFS_LOCAL_LOG_OFFSET(log_offset),
				  err);
			goto finish_store_block_bitmap;
		}

		err = ssdfs_peb_store_dependent_blk_bmap(pebi, items_state,
							 compression,
							 bmap_hdr_off,
							 &frag_id,
							 log_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store dependent bitmaps: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  log_offset->cur_page,
				  SSDFS_LOCAL_LOG_OFFSET(log_offset),
				  err);
			goto finish_store_block_bitmap;
		}
		break;

	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		/*
		 * Prepare
		 * (1) source bitmap
		 * (2) all dependent bitmaps
		 */
		err = ssdfs_peb_store_source_blk_bmap(pebi, items_state,
						      compression,
						      bmap_hdr_off,
						      &frag_id,
						      log_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store source bitmap: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  log_offset->cur_page,
				  SSDFS_LOCAL_LOG_OFFSET(log_offset),
				  err);
			goto finish_store_block_bitmap;
		}

		err = ssdfs_peb_store_dependent_blk_bmap(pebi, items_state,
							 compression,
							 bmap_hdr_off,
							 &frag_id,
							 log_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store dependent bitmaps: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  log_offset->cur_page,
				  SSDFS_LOCAL_LOG_OFFSET(log_offset),
				  err);
			goto finish_store_block_bitmap;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		break;
	}

	if (pebi->current_log.start_page >= pages_per_peb) {
		err = -ERANGE;
		SSDFS_ERR("log_start_page %u >= pages_per_peb %u\n",
			  log_start_page, pages_per_peb);
		goto finish_store_block_bitmap;
	}

	desc->offset = cpu_to_le32(bmap_hdr_off +
			    (pebi->current_log.start_page * fsi->pagesize));

	index = ssdfs_write_offset_to_mem_page_index(fsi,
					     pebi->current_log.start_page,
					     bmap_hdr_off);

	page = ssdfs_page_array_get_page_locked(&pebi->cache, index);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %lu\n", index);
		err = -ENOMEM;
		goto finish_store_block_bitmap;
	}

	kaddr = kmap_local_page(page);

	bmap_hdr = SSDFS_BLKBMP_HDR((u8 *)kaddr +
				    (bmap_hdr_off % PAGE_SIZE));

	bmap_hdr->magic.common = cpu_to_le32(SSDFS_SUPER_MAGIC);
	bmap_hdr->magic.key = cpu_to_le16(SSDFS_BLK_BMAP_MAGIC);
	bmap_hdr->magic.version.major = SSDFS_MAJOR_REVISION;
	bmap_hdr->magic.version.minor = SSDFS_MINOR_REVISION;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(frag_id == 0);
#endif /* CONFIG_SSDFS_DEBUG */
	bmap_hdr->fragments_count = cpu_to_le16(frag_id);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(SSDFS_LOCAL_LOG_OFFSET(log_offset) <= bmap_hdr_off);
	BUG_ON(SSDFS_LOCAL_LOG_OFFSET(log_offset) <=
					(bmap_hdr_off + bmap_hdr_size));
#endif /* CONFIG_SSDFS_DEBUG */
	bmap_hdr->bytes_count =
		cpu_to_le32(SSDFS_LOCAL_LOG_OFFSET(log_offset) - bmap_hdr_off);
	desc->size = bmap_hdr->bytes_count;

	pebi->current_log.prev_log_bmap_bytes =
			le32_to_cpu(bmap_hdr->bytes_count);

	bmap_hdr->flags = flags;
	bmap_hdr->type = compression;

	desc->check.bytes = cpu_to_le16(bmap_hdr_size);

	switch (compression) {
	case SSDFS_BLK_BMAP_ZLIB_BLOB:
		desc->check.flags = cpu_to_le16(SSDFS_CRC32 |
						SSDFS_ZLIB_COMPRESSED);
		break;

	case SSDFS_BLK_BMAP_LZO_BLOB:
		desc->check.flags = cpu_to_le16(SSDFS_CRC32 |
						SSDFS_LZO_COMPRESSED);
		break;

	default:
		desc->check.flags = cpu_to_le16(SSDFS_CRC32);
		break;
	}

	err = ssdfs_calculate_csum(&desc->check, bmap_hdr, bmap_hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto finish_bmap_hdr_preparation;
	}

	pebi->current_log.seg_flags |= SSDFS_SEG_HDR_HAS_BLK_BMAP;

finish_bmap_hdr_preparation:
	flush_dcache_page(page);
	kunmap_local(kaddr);

	ssdfs_set_page_private(page, 0);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&pebi->cache, index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: "
			  "err %d\n",
			  index, err);
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

finish_store_block_bitmap:
	return err;
}

/*
 * is_peb_area_empty() - check that PEB's area is empty
 * @pebi: pointer on PEB object
 * @area_type: type of area
 */
static inline
bool is_peb_area_empty(struct ssdfs_peb_info *pebi, int area_type)
{
	struct ssdfs_peb_area *area;
	size_t blk_table_size = sizeof(struct ssdfs_area_block_table);
	bool is_empty = false;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	area = &pebi->current_log.area[area_type];

	if (area->has_metadata)
		is_empty = area->write_offset == blk_table_size;
	else
		is_empty = area->write_offset == 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_type %#x, write_offset %u, is_empty %d\n",
		  area_type, area->write_offset, (int)is_empty);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_empty;
}

/*
 * ssdfs_peb_copy_area_pages_into_cache() - copy area pages into cache
 * @pebi: pointer on PEB object
 * @area_type: type of area
 * @desc: descriptor of metadata area
 * @log_offset: current log offset [in|out]
 *
 * This function tries to copy area pages into log's page cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - area is empty.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_copy_area_pages_into_cache(struct ssdfs_peb_info *pebi,
					 int area_type,
					 struct ssdfs_metadata_descriptor *desc,
					 struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_area *area;
	size_t blk_table_size = sizeof(struct ssdfs_area_block_table);
	struct pagevec pvec;
	struct ssdfs_page_array *smap, *dmap;
	pgoff_t page_index, end, pages_count, range_len;
	struct page *page;
	u32 area_offset, area_size = 0;
	u16 log_start_page;
	u32 read_bytes = 0;
	u32 area_write_offset = 0;
	u16 flags;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!desc || !log_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];
	log_start_page = pebi->current_log.start_page;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "area_type %#x, area->write_offset %u, "
		  "area->compressed_offset %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  area_type, area->write_offset,
		  area->compressed_offset,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_peb_area_empty(pebi, area_type)) {
		SSDFS_DBG("area %#x is empty\n", area_type);
		return -ENODATA;
	}

	smap = &area->array;
	dmap = &pebi->cache;

	switch (area_type) {
	case SSDFS_LOG_BLK_DESC_AREA:
		flags = fsi->metadata_options.blk2off_tbl.flags;
		if (flags & SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION)
			area_write_offset = area->compressed_offset;
		else
			area_write_offset = area->write_offset;
		break;

	default:
		area_write_offset = area->write_offset;
		break;
	}

	area_offset = SSDFS_LOCAL_LOG_OFFSET(log_offset);
	area_size = area_write_offset;

	desc->offset = cpu_to_le32(area_offset +
					(log_start_page * fsi->pagesize));
	desc->size = cpu_to_le32(area_size);

	if (area->has_metadata) {
		void *kaddr;
		u8 compression = fsi->metadata_options.blk2off_tbl.compression;
		u16 metadata_flags = SSDFS_CRC32;

		switch (area_type) {
		case SSDFS_LOG_BLK_DESC_AREA:
			flags = fsi->metadata_options.blk2off_tbl.flags;
			if (flags & SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION) {
				switch (compression) {
				case SSDFS_BLK2OFF_TBL_ZLIB_COMPR_TYPE:
					metadata_flags |= SSDFS_ZLIB_COMPRESSED;
					break;

				case SSDFS_BLK2OFF_TBL_LZO_COMPR_TYPE:
					metadata_flags |= SSDFS_LZO_COMPRESSED;
					break;

				default:
					/* do nothing */
					break;
				}
			}
			break;

		default:
			/* do nothing */
			break;
		}

		page = ssdfs_page_array_get_page_locked(smap, 0);
		if (IS_ERR_OR_NULL(page)) {
			SSDFS_ERR("fail to get page of area %#x\n",
				  area_type);
			return -ERANGE;
		}

		kaddr = kmap_local_page(page);
		desc->check.bytes = cpu_to_le16(blk_table_size);
		desc->check.flags = cpu_to_le16(metadata_flags);
		err = ssdfs_calculate_csum(&desc->check, kaddr, blk_table_size);
		kunmap_local(kaddr);
		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		if (unlikely(err)) {
			SSDFS_ERR("unable to calculate checksum: err %d\n",
				  err);
			return err;
		}

		err = ssdfs_page_array_set_page_dirty(smap, 0);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page dirty: err %d\n",
				  err);
			return err;
		}
	}

	pagevec_init(&pvec);

	page_index = 0;
	pages_count = area_write_offset + PAGE_SIZE - 1;
	pages_count >>= PAGE_SHIFT;

	while (page_index < pages_count) {
		int i;

		range_len = min_t(pgoff_t,
				  (pgoff_t)PAGEVEC_SIZE,
				  (pgoff_t)(pages_count - page_index));
		end = page_index + range_len - 1;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page_index %lu, pages_count %lu\n",
			  page_index, pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_page_array_lookup_range(smap, &page_index, end,
						    SSDFS_DIRTY_PAGE_TAG,
						    PAGEVEC_SIZE,
						    &pvec);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find any dirty pages: err %d\n",
				  err);
			return err;
		}

		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page1 = pvec.pages[i], *page2;
			pgoff_t src_index = page1->index;
			u32 src_len, dst_len, copy_len;
			u32 src_off, dst_off;
			u32 rest_len = PAGE_SIZE;

			if (read_bytes == area_size)
				goto finish_pagevec_copy;
			else if (read_bytes > area_size) {
				err = -E2BIG;
				SSDFS_ERR("too many pages: "
					  "pages_count %u, area_size %u\n",
					  pagevec_count(&pvec),
					  area_size);
				goto finish_current_copy;
			}

			src_off = 0;

try_copy_area_data:
			ssdfs_lock_page(page1);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page1, page_ref_count(page1));
#endif /* CONFIG_SSDFS_DEBUG */

			dst_off = log_offset->offset_into_page;
			src_len = min_t(u32, area_size - read_bytes, rest_len);
			dst_len = min_t(u32, PAGE_SIZE, PAGE_SIZE - dst_off);
			copy_len = min_t(u32, src_len, dst_len);

			page2 = ssdfs_page_array_grab_page(dmap,
							log_offset->cur_page);
			if (unlikely(IS_ERR_OR_NULL(page2))) {
				err = -ENOMEM;
				SSDFS_ERR("fail to grab page: index %lu\n",
					  log_offset->cur_page);
				goto unlock_page1;
			}

			err = ssdfs_memcpy_page(page2, dst_off, PAGE_SIZE,
						page1, src_off, PAGE_SIZE,
						copy_len);
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy: "
					  "src_off %u, dst_off %u, "
					  "copy_len %u\n",
					  src_off, dst_off, copy_len);
				goto unlock_page2;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("src_off %u, dst_off %u, src_len %u, "
				  "dst_len %u, copy_len %u, "
				  "write_offset %u, cur_page %lu, "
				  "page_index %d\n",
				  src_off, dst_off, src_len, dst_len, copy_len,
				  SSDFS_LOCAL_LOG_OFFSET(log_offset),
				  log_offset->cur_page, i);
#endif /* CONFIG_SSDFS_DEBUG */

			if (PageDirty(page1)) {
				err = ssdfs_page_array_set_page_dirty(dmap,
							log_offset->cur_page);
				if (unlikely(err)) {
					SSDFS_ERR("fail to set page dirty: "
						  "page_index %lu, err %d\n",
						  log_offset->cur_page, err);
					goto unlock_page2;
				}
			} else {
				err = -ERANGE;
				SSDFS_ERR("page %d is not dirty\n", i);
				goto unlock_page2;
			}

unlock_page2:
			ssdfs_unlock_page(page2);
			ssdfs_put_page(page2);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page2, page_ref_count(page2));
#endif /* CONFIG_SSDFS_DEBUG */

unlock_page1:
			ssdfs_unlock_page(page1);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page1, page_ref_count(page1));
#endif /* CONFIG_SSDFS_DEBUG */

finish_current_copy:
			if (unlikely(err)) {
				SSDFS_ERR("fail to copy page: "
					  " from %lu to %lu, err %d\n",
					  src_index,
					  log_offset->cur_page,
					  err);
				goto fail_copy_area_pages;
			}

			read_bytes += copy_len;
			rest_len -= copy_len;

			err = SSDFS_SHIFT_LOG_OFFSET(log_offset, copy_len);
			if (unlikely(err)) {
				SSDFS_ERR("fail to shift log offset: "
					  "err %d\n", err);
				return err;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("read_bytes %u, area_size %u, "
				  "write_offset %u, copy_len %u, rest_len %u\n",
				  read_bytes, area_size,
				  SSDFS_LOCAL_LOG_OFFSET(log_offset),
				  copy_len, rest_len);
#endif /* CONFIG_SSDFS_DEBUG */

			if (read_bytes == area_size) {
				err = ssdfs_page_array_clear_dirty_page(smap,
								page_index + i);
				if (unlikely(err)) {
					SSDFS_ERR("fail to mark page clean: "
						  "page_index %lu\n",
						  page_index + i);
					goto fail_copy_area_pages;
				} else
					goto finish_pagevec_copy;
			} else if ((src_off + copy_len) < PAGE_SIZE) {
				src_off += copy_len;
				goto try_copy_area_data;
			} else {
				err = ssdfs_page_array_clear_dirty_page(smap,
								page_index + i);
				if (unlikely(err)) {
					SSDFS_ERR("fail to mark page clean: "
						  "page_index %lu\n",
						  page_index + i);
					goto fail_copy_area_pages;
				}
			}
		}

finish_pagevec_copy:
		page_index += PAGEVEC_SIZE;

		for (i = 0; i < pagevec_count(&pvec); i++) {
			page = pvec.pages[i];
			ssdfs_put_page(page);
		}

		pagevec_reinit(&pvec);
		cond_resched();
	};

	err = ssdfs_page_array_release_all_pages(smap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to release area's pages: "
			  "err %d\n", err);
		goto finish_copy_area_pages;
	}

	pebi->current_log.seg_flags |= SSDFS_AREA_TYPE2FLAG(area_type);

	return 0;

fail_copy_area_pages:
	for (i = 0; i < pagevec_count(&pvec); i++) {
		page = pvec.pages[i];
		ssdfs_put_page(page);
	}

	pagevec_reinit(&pvec);

finish_copy_area_pages:
	return err;
}

/*
 * ssdfs_peb_move_area_pages_into_cache() - move area pages into cache
 * @pebi: pointer on PEB object
 * @area_type: type of area
 * @desc: descriptor of metadata area
 * @log_offset: current log offset [in|out]
 *
 * This function tries to move area pages into log's page cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - area is empty.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_move_area_pages_into_cache(struct ssdfs_peb_info *pebi,
					 int area_type,
					 struct ssdfs_metadata_descriptor *desc,
					 struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_area *area;
	size_t blk_table_size = sizeof(struct ssdfs_area_block_table);
	struct pagevec pvec;
	struct ssdfs_page_array *smap, *dmap;
	pgoff_t page_index, end, pages_count, range_len;
	struct page *page;
	u32 area_offset, area_size;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!desc || !log_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "area_type %#x, area->write_offset %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  area_type, area->write_offset,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_peb_area_empty(pebi, area_type)) {
		SSDFS_DBG("area %#x is empty\n", area_type);
		return -ENODATA;
	}

	smap = &area->array;
	dmap = &pebi->cache;

	area_offset = SSDFS_LOCAL_LOG_OFFSET(log_offset);
	area_size = area->write_offset;

	desc->offset = cpu_to_le32(area_offset +
				(pebi->current_log.start_page * fsi->pagesize));

	desc->size = cpu_to_le32(area_size);

	if (area->has_metadata) {
		page = ssdfs_page_array_get_page_locked(smap, 0);
		if (IS_ERR_OR_NULL(page)) {
			SSDFS_ERR("fail to get page of area %#x\n",
				  area_type);
			return -ERANGE;
		}

		kaddr = kmap_local_page(page);
		desc->check.bytes = cpu_to_le16(blk_table_size);
		desc->check.flags = cpu_to_le16(SSDFS_CRC32);
		err = ssdfs_calculate_csum(&desc->check, kaddr, blk_table_size);
		kunmap_local(kaddr);
		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		if (unlikely(err)) {
			SSDFS_ERR("unable to calculate checksum: err %d\n",
				  err);
			return err;
		}

		err = ssdfs_page_array_set_page_dirty(smap, 0);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page dirty: err %d\n",
				  err);
			return err;
		}
	}

	pagevec_init(&pvec);

	page_index = 0;
	pages_count = area->write_offset + PAGE_SIZE - 1;
	pages_count >>= PAGE_SHIFT;

	while (page_index < pages_count) {
		int i;

		range_len = min_t(pgoff_t,
				  (pgoff_t)PAGEVEC_SIZE,
				  (pgoff_t)(pages_count - page_index));
		end = page_index + range_len - 1;

		err = ssdfs_page_array_lookup_range(smap, &page_index, end,
						    SSDFS_DIRTY_PAGE_TAG,
						    PAGEVEC_SIZE,
						    &pvec);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find any dirty pages: err %d\n",
				  err);
			return err;
		}

		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i], *page2;
			pgoff_t src_off = page->index;

			ssdfs_lock_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

			page2 = ssdfs_page_array_delete_page(smap, src_off);
			if (IS_ERR_OR_NULL(page2)) {
				err = !page2 ? -ERANGE : PTR_ERR(page2);
				SSDFS_ERR("fail to delete page %lu: err %d\n",
					  src_off, err);
				goto finish_current_move;
			}

			WARN_ON(page2 != page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cur_page %lu, write_offset %u, "
				  "i %d, pvec_count %u\n",
				  log_offset->cur_page,
				  SSDFS_LOCAL_LOG_OFFSET(log_offset),
				  i, pagevec_count(&pvec));
#endif /* CONFIG_SSDFS_DEBUG */

			page->index = log_offset->cur_page;

			err = ssdfs_page_array_add_page(dmap, page,
							log_offset->cur_page);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add page %lu: err %d\n",
					  log_offset->cur_page, err);
				goto finish_current_move;
			}

			if (PageDirty(page)) {
				err = ssdfs_page_array_set_page_dirty(dmap,
							log_offset->cur_page);
				if (unlikely(err)) {
					SSDFS_ERR("fail to set page dirty: "
						  "page_index %lu, err %d\n",
						  log_offset->cur_page, err);
					goto finish_current_move;
				}
			} else {
				err = -ERANGE;
				SSDFS_ERR("page %d is not dirty\n", i);
				goto finish_current_move;
			}

			pvec.pages[i] = NULL;

finish_current_move:
			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

			if (unlikely(err)) {
				for (i = 0; i < pagevec_count(&pvec); i++) {
					page = pvec.pages[i];
					if (!page)
						continue;
					ssdfs_put_page(page);
				}

				pagevec_reinit(&pvec);
				SSDFS_ERR("fail to move page: "
					  " from %lu to %lu, err %d\n",
					  src_off, log_offset->cur_page,
					  err);
				return err;
			}

			err = SSDFS_SHIFT_LOG_OFFSET(log_offset, PAGE_SIZE);
			if (unlikely(err)) {
				SSDFS_ERR("fail to shift log offset: "
					  "err %d\n", err);
				return err;
			}
		}

		page_index += PAGEVEC_SIZE;

		pagevec_reinit(&pvec);
		cond_resched();
	};

	pebi->current_log.seg_flags |= SSDFS_AREA_TYPE2FLAG(area_type);

	return 0;
}

/*
 * ssdfs_peb_store_blk_desc_table() - try to store block descriptor table
 * @pebi: pointer on PEB object
 * @desc: descriptor of metadata area
 * @log_offset: current log offset [in|out]
 *
 * This function tries to store block descriptor into log's page cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA    - area is empty.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_blk_desc_table(struct ssdfs_peb_info *pebi,
				   struct ssdfs_metadata_descriptor *desc,
				   struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_area *area;
	struct ssdfs_fragment_desc *meta_desc;
	struct ssdfs_fragments_chain_header *chain_hdr;
	struct ssdfs_peb_temp_buffer *buf;
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	u16 flags;
	u16 fragments_count;
	size_t uncompr_size;
	size_t compr_size = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!desc || !log_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];
	chain_hdr = &area->metadata.area.blk_desc.table.chain_hdr;
	buf = &area->metadata.area.blk_desc.flush_buf;
	flags = fsi->metadata_options.blk2off_tbl.flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "area->write_offset %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  area->write_offset,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_peb_area_empty(pebi, area_type)) {
		SSDFS_DBG("area %#x is empty\n", area_type);
		return -ENODATA;
	}

	fragments_count = le16_to_cpu(chain_hdr->fragments_count);

	if (fragments_count == 0) {
		SSDFS_ERR("invalid fragments_count %u\n",
			  fragments_count);
		return -ERANGE;
	}

	meta_desc = ssdfs_peb_get_area_cur_frag_desc(pebi, area_type);
	if (IS_ERR(meta_desc)) {
		SSDFS_ERR("fail to get current fragment descriptor: "
			  "err %d\n",
			  (int)PTR_ERR(meta_desc));
		return PTR_ERR(meta_desc);
	} else if (!meta_desc) {
		err = -ERANGE;
		SSDFS_ERR("fail to get current fragment descriptor: "
			  "err %d\n",
			  err);
		return err;
	}

	uncompr_size = le32_to_cpu(meta_desc->uncompr_size);

	if (uncompr_size == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("latest fragment of blk desc table is empty: "
			  "seg %llu, peb %llu, current_log.start_page %u, "
			  "area->write_offset %u, "
			  "cur_page %lu, write_offset %u\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  pebi->current_log.start_page,
			  area->write_offset,
			  log_offset->cur_page,
			  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */
		fragments_count--;
		chain_hdr->fragments_count = cpu_to_le16(fragments_count);
		goto store_area_block_table;
	}

	if (flags & SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!buf->ptr);

		if (buf->write_offset >= buf->size) {
			SSDFS_ERR("invalid request: "
				  "buf->write_offset %u, buf->size %zu\n",
				  buf->write_offset, buf->size);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		meta_desc->flags = SSDFS_FRAGMENT_HAS_CSUM;

		if (uncompr_size > buf->size) {
			SSDFS_ERR("invalid state: "
				  "uncompr_size %zu > buf->size %zu\n",
				  uncompr_size, buf->size);
			return -ERANGE;
		}

		meta_desc->checksum = ssdfs_crc32_le(buf->ptr, uncompr_size);

		if (le32_to_cpu(meta_desc->checksum) == 0) {
			SSDFS_WARN("checksum is invalid: "
				   "seg %llu, peb %llu, bytes_count %zu\n",
				   pebi->pebc->parent_si->seg_id,
				   pebi->peb_id,
				   uncompr_size);
			return -ERANGE;
		}

		err = ssdfs_peb_compress_blk_descs_fragment(pebi,
							    uncompr_size,
							    &compr_size);
		if (err == -E2BIG) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fragment has been stored uncompressed: "
				  "size %zu\n", compr_size);
#endif /* CONFIG_SSDFS_DEBUG */
			meta_desc->type = SSDFS_DATA_BLK_DESC;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to compress blk desc fragment: "
				  "err %d\n", err);
			return err;
		}

		meta_desc->offset = cpu_to_le32(area->compressed_offset);

#ifdef CONFIG_SSDFS_DEBUG
		WARN_ON(compr_size > U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
		meta_desc->compr_size = cpu_to_le16((u16)compr_size);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("offset %u, compr_size %u, "
			  "uncompr_size %u, checksum %#x\n",
			  le32_to_cpu(meta_desc->offset),
			  le16_to_cpu(meta_desc->compr_size),
			  le16_to_cpu(meta_desc->uncompr_size),
			  le32_to_cpu(meta_desc->checksum));
#endif /* CONFIG_SSDFS_DEBUG */

		area->compressed_offset += compr_size;
		le32_add_cpu(&chain_hdr->compr_bytes, compr_size);
	}

store_area_block_table:
	err = ssdfs_peb_store_area_block_table(pebi, area_type, 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store area's block table: "
			  "area %#x, err %d\n",
			  area_type, err);
		return err;
	}

	err = ssdfs_peb_copy_area_pages_into_cache(pebi, area_type,
						   desc, log_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move pages in the cache: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_store_log_footer() - store log footer
 * @pebi: pointer on PEB object
 * @flags: log footer's flags
 * @hdr_desc: log footer's metadata descriptor in header
 * @lf_desc: log footer's metadata descriptors array
 * @array_size: count of items in array
 * @cur_segs: current segment IDs array
 * @cur_segs_size: size of segment IDs array size in bytes
 * @log_offset: current log offset [in|out]
 *
 * This function tries to store log footer into PEB's page cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory page.
 */
static
int ssdfs_peb_store_log_footer(struct ssdfs_peb_info *pebi,
				u32 flags,
				struct ssdfs_metadata_descriptor *hdr_desc,
				struct ssdfs_metadata_descriptor *lf_desc,
				size_t array_size,
				__le64 *cur_segs,
				size_t cur_segs_size,
				struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_log_footer *footer;
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	size_t array_bytes = desc_size * array_size;
	int padding;
	u32 log_pages;
	struct page *page;
	pgoff_t lf_page_index;
	u32 area_offset, area_size;
	u64 last_log_time;
	u64 last_log_cno;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!hdr_desc || !lf_desc || !cur_segs);
	BUG_ON(!log_offset);
	BUG_ON(array_size != SSDFS_LOG_FOOTER_DESC_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	area_offset = SSDFS_LOCAL_LOG_OFFSET(log_offset);
	area_size = sizeof(struct ssdfs_log_footer);

	lf_page_index = log_offset->cur_page;

	err = SSDFS_SHIFT_LOG_OFFSET(log_offset,
			max_t(u32, PAGE_SIZE, area_size));
	if (unlikely(err)) {
		SSDFS_ERR("fail ot shift log offset: err %d\n", err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(flags & ~SSDFS_LOG_FOOTER_FLAG_MASK);
#endif /* CONFIG_SSDFS_DEBUG */

	log_pages = (SSDFS_LOCAL_LOG_OFFSET(log_offset) + fsi->pagesize - 1);
	log_pages /= fsi->pagesize;

	padding = lf_page_index % pebi->log_pages;
	padding = pebi->log_pages - padding;
	padding--;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_offset %u, write_offset %u, "
		  "log_pages %u, padding %d, "
		  "cur_page %lu\n",
		  area_offset,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset),
		  log_pages, padding,
		  lf_page_index);

	if (padding > 1) {
		SSDFS_WARN("padding is big: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "cur_page %lu, write_offset %u, "
			   "padding %d\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   pebi->current_log.start_page,
			   lf_page_index,
			   SSDFS_LOCAL_LOG_OFFSET(log_offset),
			   padding);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (padding > 0) {
		/*
		 * Align the log_pages.
		 */
		log_pages += padding;
		area_offset = (log_pages * fsi->pagesize) - fsi->pagesize;

		for (i = 0; i < padding; i++) {
			page = ssdfs_page_array_grab_page(&pebi->cache,
							  lf_page_index);
			if (IS_ERR_OR_NULL(page)) {
				SSDFS_ERR("fail to get cache page: index %lu\n",
					  lf_page_index);
				return -ENOMEM;
			}

			ssdfs_memset_page(page, 0, PAGE_SIZE, 0xFF, PAGE_SIZE);

			ssdfs_set_page_private(page, 0);
			SetPageUptodate(page);

			err = ssdfs_page_array_set_page_dirty(&pebi->cache,
							      lf_page_index);
			if (unlikely(err)) {
				SSDFS_ERR("fail to set page dirty: "
					  "page_index %lu, err %d\n",
					  lf_page_index, err);
			}

			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

			if (unlikely(err))
				return err;

			lf_page_index++;
		}
	}

	page = ssdfs_page_array_grab_page(&pebi->cache, lf_page_index);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %lu\n",
			  lf_page_index);
		return -ENOMEM;
	}

	footer = kmap_local_page(page);
	memset(footer, 0xFF, PAGE_SIZE);
	ssdfs_memcpy(footer->desc_array, 0, array_bytes,
		     lf_desc, 0, array_bytes,
		     array_bytes);

	last_log_time = pebi->current_log.last_log_time;
	last_log_cno = pebi->current_log.last_log_cno;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(pebi->peb_create_time > last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_prepare_volume_state_info_for_commit(fsi, SSDFS_MOUNTED_FS,
							 cur_segs,
							 cur_segs_size,
							 last_log_time,
							 last_log_cno,
							 &footer->volume_state);

	if (!err) {
		err = ssdfs_prepare_log_footer_for_commit(fsi, log_pages,
							  flags,
							  last_log_time,
							  last_log_cno,
							  footer);

		footer->peb_create_time = cpu_to_le64(pebi->peb_create_time);
	}

	if (!err) {
		hdr_desc->offset = cpu_to_le32(area_offset +
				(pebi->current_log.start_page * fsi->pagesize));
		hdr_desc->size = cpu_to_le32(area_size);

		ssdfs_memcpy(&hdr_desc->check,
			     0, sizeof(struct ssdfs_metadata_check),
			     &footer->volume_state.check,
			     0, sizeof(struct ssdfs_metadata_check),
			     sizeof(struct ssdfs_metadata_check));
	}

	flush_dcache_page(page);
	kunmap_local(footer);

	ssdfs_set_page_private(page, 0);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&pebi->cache, lf_page_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page dirty: "
			  "page_index %lu, err %d\n",
			  lf_page_index, err);
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log footer: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		return err;
	}

	pebi->current_log.seg_flags |= SSDFS_LOG_HAS_FOOTER;

	lf_page_index++;
	log_offset->cur_page = lf_page_index;
	log_offset->offset_into_page = 0;

	return 0;
}

/*
 * ssdfs_extract_src_peb_migration_id() - prepare src PEB's migration_id
 * @pebi: pointer on PEB object
 * @prev_id: pointer on previous PEB's peb_migration_id [out]
 * @cur_id: pointer on current PEB's peb_migration_id [out]
 */
static inline
int ssdfs_extract_src_peb_migration_id(struct ssdfs_peb_info *pebi,
					u8 *prev_id, u8 *cur_id)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->src_peb);
	BUG_ON(!prev_id || !cur_id);
	BUG_ON(!rwsem_is_locked(&pebi->pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	*prev_id = SSDFS_PEB_UNKNOWN_MIGRATION_ID;
	*cur_id = SSDFS_PEB_UNKNOWN_MIGRATION_ID;

	if (pebi != pebi->pebc->src_peb) {
		SSDFS_ERR("pebi %p != src_peb %p\n",
			  pebi, pebi->pebc->src_peb);
		return -ERANGE;
	}

	*cur_id = ssdfs_get_peb_migration_id_checked(pebi);
	if (unlikely(*cur_id < 0)) {
		err = *cur_id;
		*cur_id = SSDFS_PEB_UNKNOWN_MIGRATION_ID;
		SSDFS_ERR("fail to get migration_id: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  err);
		return err;
	}

	*prev_id = ssdfs_define_prev_peb_migration_id(pebi);
	if (!is_peb_migration_id_valid(*prev_id)) {
		err = *prev_id;
		*prev_id = SSDFS_PEB_UNKNOWN_MIGRATION_ID;
		SSDFS_ERR("fail to define prev migration_id: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  err);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_extract_dst_peb_migration_id() - prepare dst PEB's migration_id
 * @pebi: pointer on PEB object
 * @prev_id: pointer on previous PEB's peb_migration_id [out]
 * @cur_id: pointer on current PEB's peb_migration_id [out]
 */
static inline
int ssdfs_extract_dst_peb_migration_id(struct ssdfs_peb_info *pebi,
					u8 *prev_id, u8 *cur_id)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->src_peb || !pebi->pebc->dst_peb);
	BUG_ON(!prev_id || !cur_id);
	BUG_ON(!rwsem_is_locked(&pebi->pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	*prev_id = SSDFS_PEB_UNKNOWN_MIGRATION_ID;
	*cur_id = SSDFS_PEB_UNKNOWN_MIGRATION_ID;

	*cur_id = ssdfs_get_peb_migration_id_checked(pebi->pebc->dst_peb);
	if (unlikely(*cur_id < 0)) {
		err = *cur_id;
		*cur_id = SSDFS_PEB_UNKNOWN_MIGRATION_ID;
		SSDFS_ERR("fail to get migration_id: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  err);
		return err;
	}

	*prev_id = ssdfs_get_peb_migration_id_checked(pebi->pebc->src_peb);
	if (unlikely(*prev_id < 0)) {
		err = *prev_id;
		*prev_id = SSDFS_PEB_UNKNOWN_MIGRATION_ID;
		SSDFS_ERR("fail to get migration_id: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_store_peb_migration_id() - store peb_migration_id into header
 * @pebi: pointer on PEB object
 * @hdr: pointer on segment header [out]
 */
static
int ssdfs_store_peb_migration_id(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_header *hdr)
{
	int items_state;
	u8 prev_id = SSDFS_PEB_UNKNOWN_MIGRATION_ID;
	u8 cur_id = SSDFS_PEB_UNKNOWN_MIGRATION_ID;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!rwsem_is_locked(&pebi->pebc->lock));

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	items_state = atomic_read(&pebi->pebc->items_state);
	switch (items_state) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebi->pebc->src_peb || pebi->pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_extract_src_peb_migration_id(pebi,
							 &prev_id,
							 &cur_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract peb_migration_id: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			return err;
		}
		break;

	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(pebi->pebc->src_peb || !pebi->pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

		if (pebi != pebi->pebc->dst_peb) {
			SSDFS_ERR("pebi %p != dst_peb %p\n",
				  pebi, pebi->pebc->dst_peb);
			return -ERANGE;
		}

		cur_id = ssdfs_get_peb_migration_id_checked(pebi);
		if (unlikely(cur_id < 0)) {
			err = cur_id;
			SSDFS_ERR("fail to get migration_id: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  err);
			return err;
		}
		break;

	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebi->pebc->src_peb || !pebi->pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

		err = -ERANGE;

		if (pebi == pebi->pebc->src_peb) {
			err = ssdfs_extract_src_peb_migration_id(pebi,
								 &prev_id,
								 &cur_id);
		} else if (pebi == pebi->pebc->dst_peb) {
			err = ssdfs_extract_dst_peb_migration_id(pebi,
								 &prev_id,
								 &cur_id);
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to extract peb_migration_id: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			return err;
		}
		break;

	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebi->pebc->src_peb || !pebi->pebc->dst_peb);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_extract_src_peb_migration_id(pebi,
							 &prev_id,
							 &cur_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to extract peb_migration_id: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			return err;
		}
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	hdr->peb_migration_id[SSDFS_PREV_MIGRATING_PEB] = prev_id;
	hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB] = cur_id;

	return 0;
}

/*
 * ssdfs_peb_store_log_header() - store log's header
 * @pebi: pointer on PEB object
 * @desc_array: pointer on descriptors array
 * @array_size: count of items in array
 * @write_offset: current write offset in log
 *
 * This function tries to store log's header in PEB's page cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_log_header(struct ssdfs_peb_info *pebi,
				struct ssdfs_metadata_descriptor *desc_array,
				size_t array_size,
				u32 write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_header *hdr;
	struct page *page;
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	size_t array_bytes = desc_size * array_size;
	u32 seg_flags;
	u32 log_pages;
	u16 seg_type;
	u64 last_log_time;
	u64 last_log_cno;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!desc_array);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(pebi->pebc->parent_si->seg_type > SSDFS_LAST_KNOWN_SEG_TYPE);
	BUG_ON(pebi->current_log.seg_flags & ~SSDFS_SEG_HDR_FLAG_MASK);
	BUG_ON(write_offset % fsi->pagesize);
	BUG_ON((write_offset >> fsi->log_pagesize) > pebi->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	seg_type = pebi->pebc->parent_si->seg_type;
	log_pages = pebi->log_pages;
	seg_flags = pebi->current_log.seg_flags;

	page = ssdfs_page_array_get_page_locked(&pebi->cache,
						pebi->current_log.start_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %u\n",
			  pebi->current_log.start_page);
		return -ERANGE;
	}

	hdr = kmap_local_page(page);

	ssdfs_memcpy(hdr->desc_array, 0, array_bytes,
		     desc_array, 0, array_bytes,
		     array_bytes);

	ssdfs_create_volume_header(fsi, &hdr->volume_hdr);

	err = ssdfs_prepare_volume_header_for_commit(fsi, &hdr->volume_hdr);
	if (unlikely(err))
		goto finish_segment_header_preparation;

	err = ssdfs_store_peb_migration_id(pebi, hdr);
	if (unlikely(err))
		goto finish_segment_header_preparation;

	hdr->peb_create_time = cpu_to_le64(pebi->peb_create_time);

	last_log_time = pebi->current_log.last_log_time;
	last_log_cno = pebi->current_log.last_log_cno;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, "
		  "peb_create_time %llx, last_log_time %llx\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  pebi->peb_create_time,
		  last_log_time);

	BUG_ON(pebi->peb_create_time > last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_prepare_segment_header_for_commit(fsi,
						      log_pages,
						      seg_type,
						      seg_flags,
						      last_log_time,
						      last_log_cno,
						      hdr);
	if (unlikely(err))
		goto finish_segment_header_preparation;

finish_segment_header_preparation:
	flush_dcache_page(page);
	kunmap_local(hdr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_CRIT("fail to store segment header: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_flush_current_log_dirty_pages() - flush log's dirty pages
 * @pebi: pointer on PEB object
 * @write_offset: current write offset in log
 *
 * This function tries to flush the current log's dirty pages.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_flush_current_log_dirty_pages(struct ssdfs_peb_info *pebi,
					    u32 write_offset)
{
	struct ssdfs_fs_info *fsi;
	loff_t peb_offset;
	struct pagevec pvec;
	u32 log_bytes, written_bytes;
	u32 log_start_off;
	unsigned flushed_pages;
#ifdef CONFIG_SSDFS_CHECK_LOGICAL_BLOCK_EMPTYNESS
	u32 pages_per_block;
#endif /* CONFIG_SSDFS_CHECK_LOGICAL_BLOCK_EMPTYNESS */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(write_offset == 0);
	BUG_ON(write_offset % pebi->pebc->parent_si->fsi->pagesize);
	BUG_ON(!pebi->pebc->parent_si->fsi->devops);
	BUG_ON(!pebi->pebc->parent_si->fsi->devops->writepages);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	pagevec_init(&pvec);

	peb_offset = (pebi->peb_id * fsi->pages_per_peb) << fsi->log_pagesize;

	log_bytes = write_offset;
	log_start_off = pebi->current_log.start_page << fsi->log_pagesize;
	written_bytes = 0;
	flushed_pages = 0;

	while (written_bytes < log_bytes) {
		pgoff_t index, end;
		unsigned i;
		u32 page_start_off, write_size;
		loff_t iter_write_offset;
		u32 pagevec_bytes;
		pgoff_t written_pages = 0;

		index = pebi->current_log.start_page + flushed_pages;
		end = (pgoff_t)pebi->current_log.start_page + pebi->log_pages;
		end = min_t(pgoff_t, end, (pgoff_t)(index + PAGEVEC_SIZE));

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("index %lu, end %lu\n",
			  index, end);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_page_array_lookup_range(&pebi->cache,
						    &index, end,
						    SSDFS_DIRTY_PAGE_TAG,
						    PAGEVEC_SIZE,
						    &pvec);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find dirty pages: "
				  "index %lu, end %lu, err %d\n",
				  index, end, err);
			return -ERANGE;
		}

		page_start_off = log_start_off + written_bytes;
		page_start_off %= PAGE_SIZE;

		pagevec_bytes = (u32)pagevec_count(&pvec) * PAGE_SIZE;

		write_size = min_t(u32,
				   pagevec_bytes - page_start_off,
				   log_bytes - written_bytes);

		if ((written_bytes + write_size) > log_bytes) {
			pagevec_reinit(&pvec);
			SSDFS_ERR("written_bytes %u > log_bytes %u\n",
				  written_bytes + write_size,
				  log_bytes);
			return -ERANGE;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(write_size % fsi->pagesize);
		BUG_ON(written_bytes % fsi->pagesize);

		for (i = 1; i < pagevec_count(&pvec); i++) {
			struct page *page1, *page2;

			page1 = pvec.pages[i - 1];
			page2 = pvec.pages[i];

			if ((page_index(page1) + 1) != page_index(page2)) {
				SSDFS_ERR("not contiguous log: "
					  "page_index1 %lu, page_index2 %lu\n",
					  page_index(page1),
					  page_index(page2));
			}
		}
#endif /* CONFIG_SSDFS_DEBUG */

		iter_write_offset = peb_offset + log_start_off;
		iter_write_offset += written_bytes;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("iter_write_offset %llu, write_size %u, "
			  "page_start_off %u\n",
			  iter_write_offset, write_size, page_start_off);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_CHECK_LOGICAL_BLOCK_EMPTYNESS
		pages_per_block = fsi->pagesize / PAGE_SIZE;
		for (i = 0; i < pagevec_count(&pvec); i += pages_per_block) {
			u64 byte_off;

			if (!fsi->devops->can_write_page) {
				SSDFS_DBG("can_write_page is not supported\n");
				break;
			}

			byte_off = iter_write_offset;
			byte_off += i * PAGE_SIZE;

			err = fsi->devops->can_write_page(fsi->sb, byte_off,
							  true);
			if (err) {
				pagevec_reinit(&pvec);
				ssdfs_fs_error(fsi->sb,
					__FILE__, __func__, __LINE__,
					"offset %llu err %d\n",
					byte_off, err);
				return err;
			}
		}
#endif /* CONFIG_SSDFS_CHECK_LOGICAL_BLOCK_EMPTYNESS */

		err = fsi->devops->writepages(fsi->sb, iter_write_offset,
						&pvec,
						page_start_off,
						write_size);
		if (unlikely(err)) {
			pagevec_reinit(&pvec);
			SSDFS_ERR("fail to flush pagevec: "
				  "iter_write_offset %llu, write_size %u, "
				  "err %d\n",
				  iter_write_offset, write_size, err);
			return err;
		}

		written_pages = write_size / PAGE_SIZE;

		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

			if (i < written_pages) {
				ssdfs_lock_page(page);
				ClearPageUptodate(page);
				ssdfs_clear_page_private(page, 0);
				pvec.pages[i] = NULL;
				ssdfs_unlock_page(page);
			} else {
				ssdfs_lock_page(page);
				pvec.pages[i] = NULL;
				ssdfs_unlock_page(page);
			}
		}

		end = index + written_pages - 1;
		err = ssdfs_page_array_clear_dirty_range(&pebi->cache,
							 index,
							 end);
		if (unlikely(err)) {
			SSDFS_ERR("fail to clean dirty pages: "
				  "start %lu, end %lu, err %d\n",
				  index, end, err);
		}

		err = ssdfs_page_array_release_pages(&pebi->cache,
						     &index, end);
		if (unlikely(err)) {
			SSDFS_ERR("fail to release pages: "
				  "seg_id %llu, peb_id %llu, "
				  "start %lu, end %lu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, index, end, err);
		}

		written_bytes += write_size;
		flushed_pages += written_pages;

		pagevec_reinit(&pvec);
		cond_resched();
	};

	return 0;
}

/*
 * ssdfs_peb_commit_log_payload() - commit payload of the log
 * @pebi: pointer on PEB object
 * @hdr_desc: log header's metadata descriptors array
 * @log_has_data: does log contain data? [out]
 * @log_offset: current log offset [in|out]
 */
static
int ssdfs_peb_commit_log_payload(struct ssdfs_peb_info *pebi,
				 struct ssdfs_metadata_descriptor *hdr_desc,
				 bool *log_has_data,
				 struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor *cur_hdr_desc;
	int area_type;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!hdr_desc || !log_offset || !log_has_data);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	*log_has_data = false;

	cur_hdr_desc = &hdr_desc[SSDFS_BLK_BMAP_INDEX];
	err = ssdfs_peb_store_block_bmap(pebi, cur_hdr_desc,
					 log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store block bitmap: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset->cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(log_offset),
			   err);
		goto finish_commit_payload;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0001-payload: cur_page %lu, write_offset %u\n",
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	cur_hdr_desc = &hdr_desc[SSDFS_OFF_TABLE_INDEX];
	err = ssdfs_peb_store_offsets_table(pebi, cur_hdr_desc,
					    log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store offsets table: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset->cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(log_offset),
			   err);
		goto finish_commit_payload;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0002-payload: cur_page %lu, write_offset %u\n",
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	area_type = SSDFS_LOG_BLK_DESC_AREA;
	cur_hdr_desc = &hdr_desc[SSDFS_AREA_TYPE2INDEX(area_type)];
	err = ssdfs_peb_store_blk_desc_table(pebi, cur_hdr_desc,
					     log_offset);
	if (err == -ENODATA) {
		err = 0;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("block descriptor area is absent: "
			   "seg %llu, peb %llu, "
			   "cur_page %lu, write_offset %u\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset->cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */
	} else if (unlikely(err)) {
		SSDFS_CRIT("fail to store block descriptors table: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset->cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(log_offset),
			   err);
		goto finish_commit_payload;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0003-payload: cur_page %lu, write_offset %u\n",
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	area_type = SSDFS_LOG_DIFFS_AREA;
	cur_hdr_desc = &hdr_desc[SSDFS_AREA_TYPE2INDEX(area_type)];
	err = ssdfs_peb_copy_area_pages_into_cache(pebi,
						   area_type,
						   cur_hdr_desc,
						   log_offset);
	if (err == -ENODATA) {
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_CRIT("fail to move the area %d into PEB cache: "
			   "seg %llu, peb %llu, cur_page %lu, "
			   "write_offset %u, err %d\n",
			   area_type, pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset->cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(log_offset),
			   err);
		goto finish_commit_payload;
	} else
		*log_has_data = true;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0004-payload: cur_page %lu, write_offset %u\n",
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	area_type = SSDFS_LOG_JOURNAL_AREA;
	cur_hdr_desc = &hdr_desc[SSDFS_AREA_TYPE2INDEX(area_type)];
	err = ssdfs_peb_copy_area_pages_into_cache(pebi,
						   area_type,
						   cur_hdr_desc,
						   log_offset);
	if (err == -ENODATA) {
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_CRIT("fail to move the area %d into PEB cache: "
			   "seg %llu, peb %llu, cur_page %lu, "
			   "write_offset %u, err %d\n",
			   area_type, pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset->cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(log_offset),
			   err);
		goto finish_commit_payload;
	} else
		*log_has_data = true;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0005-payload: cur_page %lu, write_offset %u\n",
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	if (IS_SSDFS_LOG_OFFSET_UNALIGNED(log_offset))
		SSDFS_ALIGN_LOG_OFFSET(log_offset);

	area_type = SSDFS_LOG_MAIN_AREA;
	cur_hdr_desc = &hdr_desc[SSDFS_AREA_TYPE2INDEX(area_type)];
	err = ssdfs_peb_move_area_pages_into_cache(pebi,
						   area_type,
						   cur_hdr_desc,
						   log_offset);
	if (err == -ENODATA) {
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_CRIT("fail to move the area %d into PEB cache: "
			   "seg %llu, peb %llu, cur_page %lu, "
			   "write_offset %u, err %d\n",
			   area_type, pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset->cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(log_offset),
			   err);
		goto finish_commit_payload;
	} else
		*log_has_data = true;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0006-payload: cur_page %lu, write_offset %u\n",
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

finish_commit_payload:
	return err;
}

/*
 * ssdfs_peb_define_next_log_start() - define start of the next log
 * @pebi: pointer on PEB object
 * @log_strategy: strategy in log creation
 * @log_offset: current log offset [in|out]
 */
static
void ssdfs_peb_define_next_log_start(struct ssdfs_peb_info *pebi,
				     int log_strategy,
				     struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_fs_info *fsi;
	u16 pages_diff;
	u16 rest_phys_free_pages = 0;
	u32 pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !log_offset);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, log_strategy %#x, "
		  "current_log.start_page %u, "
		  "cur_page %lu, write_offset %u, "
		  "current_log.free_data_pages %u, "
		  "sequence_id %d\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  log_strategy,
		  pebi->current_log.start_page,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset),
		  pebi->current_log.free_data_pages,
		  atomic_read(&pebi->current_log.sequence_id));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	pages_per_peb = min_t(u32, fsi->leb_pages_capacity,
				   fsi->peb_pages_capacity);

	switch (log_strategy) {
	case SSDFS_START_PARTIAL_LOG:
	case SSDFS_CONTINUE_PARTIAL_LOG:
		pebi->current_log.start_page = log_offset->cur_page;
		rest_phys_free_pages = pebi->log_pages -
				(log_offset->cur_page % pebi->log_pages);
		pebi->current_log.free_data_pages = rest_phys_free_pages;
		atomic_inc(&pebi->current_log.sequence_id);
		WARN_ON(pebi->current_log.free_data_pages == 0);
		break;

	case SSDFS_FINISH_PARTIAL_LOG:
	case SSDFS_FINISH_FULL_LOG:
		if (log_offset->cur_page % pebi->log_pages) {
			log_offset->cur_page += pebi->log_pages - 1;
			log_offset->cur_page =
				(log_offset->cur_page / pebi->log_pages) *
					pebi->log_pages;
			log_offset->offset_into_page = 0;
		}

		pebi->current_log.start_page = log_offset->cur_page;

		if (pebi->current_log.start_page >= pages_per_peb) {
			pebi->current_log.free_data_pages = 0;
		} else {
			pages_diff = pages_per_peb;
			pages_diff -= pebi->current_log.start_page;

			pebi->current_log.free_data_pages =
				min_t(u16, pebi->log_pages, pages_diff);
		}

		atomic_set(&pebi->current_log.sequence_id, 0);
		break;

	default:
		BUG();
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebi->current_log.start_page %u, "
		  "current_log.free_data_pages %u, "
		  "sequence_id %d\n",
		  pebi->current_log.start_page,
		  pebi->current_log.free_data_pages,
		  atomic_read(&pebi->current_log.sequence_id));
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_peb_store_pl_header_like_footer() - store partial log's header
 * @pebi: pointer on PEB object
 * @flags: partial log header's flags
 * @hdr_desc: partial log header's metadata descriptor in segment header
 * @plh_desc: partial log header's metadata descriptors array
 * @array_size: count of items in array
 * @log_offset: current log offset [in|out]
 *
 * This function tries to store the partial log's header
 * in the end of the log (instead of footer).
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_pl_header_like_footer(struct ssdfs_peb_info *pebi,
				    u32 flags,
				    struct ssdfs_metadata_descriptor *hdr_desc,
				    struct ssdfs_metadata_descriptor *plh_desc,
				    size_t array_size,
				    struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_partial_log_header *pl_hdr;
	struct page *page;
	pgoff_t plh_page_index;
	u32 log_pages;
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	size_t array_bytes = desc_size * array_size;
	u32 area_offset, area_size;
	u16 seg_type;
	int sequence_id;
	u64 last_log_time;
	u64 last_log_cno;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!hdr_desc || !plh_desc || !log_offset);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	seg_type = pebi->pebc->parent_si->seg_type;

	sequence_id = atomic_read(&pebi->current_log.sequence_id);
	if (sequence_id < 0 || sequence_id >= INT_MAX) {
		SSDFS_ERR("invalid sequence_id %d\n", sequence_id);
		return -ERANGE;
	}

	plh_page_index = log_offset->cur_page;

	area_offset = SSDFS_LOCAL_LOG_OFFSET(log_offset);
	area_size = sizeof(struct ssdfs_partial_log_header);

	err = SSDFS_SHIFT_LOG_OFFSET(log_offset,
			max_t(u32, PAGE_SIZE, area_size));
	if (unlikely(err)) {
		SSDFS_ERR("fail to shift log offset: err %d\n", err);
		return err;
	}

	log_pages = (SSDFS_LOCAL_LOG_OFFSET(log_offset) + fsi->pagesize - 1);
	log_pages /= fsi->pagesize;

	page = ssdfs_page_array_grab_page(&pebi->cache, plh_page_index);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %lu\n",
			  plh_page_index);
		return -ENOMEM;
	}

	pl_hdr = kmap_local_page(page);
	memset(pl_hdr, 0xFF, PAGE_SIZE);
	ssdfs_memcpy(pl_hdr->desc_array, 0, array_bytes,
		     plh_desc, 0, array_bytes,
		     array_bytes);

	pl_hdr->peb_create_time = cpu_to_le64(pebi->peb_create_time);

	last_log_time = pebi->current_log.last_log_time;
	last_log_cno = pebi->current_log.last_log_cno;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, "
		  "peb_create_time %llx, last_log_time %llx\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  pebi->peb_create_time,
		  last_log_time);

	BUG_ON(pebi->peb_create_time > last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_prepare_partial_log_header_for_commit(fsi,
							  sequence_id,
							  log_pages,
							  seg_type, flags,
							  last_log_time,
							  last_log_cno,
							  pl_hdr);

	if (!err) {
		hdr_desc->offset = cpu_to_le32(area_offset +
				(pebi->current_log.start_page * fsi->pagesize));
		hdr_desc->size = cpu_to_le32(area_size);

		ssdfs_memcpy(&hdr_desc->check,
			     0, sizeof(struct ssdfs_metadata_check),
			     &pl_hdr->check,
			     0, sizeof(struct ssdfs_metadata_check),
			     sizeof(struct ssdfs_metadata_check));
	}

	flush_dcache_page(page);
	kunmap_local(pl_hdr);

	ssdfs_set_page_private(page, 0);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&pebi->cache, plh_page_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page dirty: "
			  "page_index %lu, err %d\n",
			  plh_page_index, err);
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_CRIT("fail to store partial log header: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		return err;
	}

	pebi->current_log.seg_flags |=
		SSDFS_LOG_IS_PARTIAL |
		SSDFS_LOG_HAS_PARTIAL_HEADER |
		SSDFS_PARTIAL_HEADER_INSTEAD_FOOTER;

	return 0;
}

/*
 * ssdfs_peb_store_pl_header_like_header() - store partial log's header
 * @pebi: pointer on PEB object
 * @flags: partial log header's flags
 * @plh_desc: partial log header's metadata descriptors array
 * @array_size: count of items in array
 * @log_offset: current log offset [in|out]
 *
 * This function tries to store the partial log's header
 * in the beginning of the log.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_pl_header_like_header(struct ssdfs_peb_info *pebi,
				    u32 flags,
				    struct ssdfs_metadata_descriptor *plh_desc,
				    size_t array_size,
				    struct ssdfs_peb_log_offset *log_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_partial_log_header *pl_hdr;
	struct page *page;
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	size_t array_bytes = desc_size * array_size;
	u32 seg_flags;
	u32 log_pages;
	u16 seg_type;
	int sequence_id;
	u64 last_log_time;
	u64 last_log_cno;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!plh_desc || !log_offset);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(pebi->pebc->parent_si->seg_type > SSDFS_LAST_KNOWN_SEG_TYPE);
	BUG_ON(SSDFS_LOCAL_LOG_OFFSET(log_offset) % fsi->pagesize);
	BUG_ON((SSDFS_LOCAL_LOG_OFFSET(log_offset) >> fsi->log_pagesize) >
							    pebi->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	sequence_id = atomic_read(&pebi->current_log.sequence_id);
	if (sequence_id < 0 || sequence_id >= INT_MAX) {
		SSDFS_ERR("invalid sequence_id %d\n", sequence_id);
		return -ERANGE;
	}

	seg_type = pebi->pebc->parent_si->seg_type;
	seg_flags = pebi->current_log.seg_flags;

	log_pages = (SSDFS_LOCAL_LOG_OFFSET(log_offset) + fsi->pagesize - 1);
	log_pages /= fsi->pagesize;

	page = ssdfs_page_array_get_page_locked(&pebi->cache,
						pebi->current_log.start_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %u\n",
			  pebi->current_log.start_page);
		return -ERANGE;
	}

	pl_hdr = kmap_local_page(page);

	ssdfs_memcpy(pl_hdr->desc_array, 0, array_bytes,
		     plh_desc, 0, array_bytes,
		     array_bytes);

	pl_hdr->peb_create_time = cpu_to_le64(pebi->peb_create_time);

	last_log_time = pebi->current_log.last_log_time;
	last_log_cno = pebi->current_log.last_log_cno;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, "
		  "peb_create_time %llx, last_log_time %llx\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  pebi->peb_create_time,
		  last_log_time);

	BUG_ON(pebi->peb_create_time > last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_prepare_partial_log_header_for_commit(fsi,
							  sequence_id,
							  log_pages,
							  seg_type,
							  flags | seg_flags,
							  last_log_time,
							  last_log_cno,
							  pl_hdr);
	if (unlikely(err))
		goto finish_pl_header_preparation;

finish_pl_header_preparation:
	flush_dcache_page(page);
	kunmap_local(pl_hdr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_CRIT("fail to store partial log header: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_store_partial_log_header() - store partial log's header
 * @pebi: pointer on PEB object
 * @flags: partial log header's flags
 * @hdr_desc: partial log header's metadata descriptor in segment header
 * @plh_desc: partial log header's metadata descriptors array
 * @array_size: count of items in array
 * @log_offset: current log offset [in|out]
 *
 * This function tries to store the partial log's header.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_store_partial_log_header(struct ssdfs_peb_info *pebi, u32 flags,
				    struct ssdfs_metadata_descriptor *hdr_desc,
				    struct ssdfs_metadata_descriptor *plh_desc,
				    size_t array_size,
				    struct ssdfs_peb_log_offset *log_offset)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!plh_desc || !log_offset);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  log_offset->cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	if (hdr_desc) {
		return ssdfs_peb_store_pl_header_like_footer(pebi, flags,
							     hdr_desc,
							     plh_desc,
							     array_size,
							     log_offset);
	} else {
		return ssdfs_peb_store_pl_header_like_header(pebi, flags,
							     plh_desc,
							     array_size,
							     log_offset);
	}
}

/*
 * ssdfs_peb_commit_first_partial_log() - commit first partial log
 * @pebi: pointer on PEB object
 *
 * This function tries to commit the first partial log.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_commit_first_partial_log(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor hdr_desc[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_metadata_descriptor plh_desc[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_metadata_descriptor *cur_hdr_desc;
	u32 flags;
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	struct ssdfs_peb_log_offset log_offset;
	bool log_has_data = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	memset(hdr_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);
	memset(plh_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);

	SSDFS_LOG_OFFSET_INIT(&log_offset, pebi->log_pages,
			      pebi->current_log.start_page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0001: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_reserve_segment_header(pebi, &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to reserve segment header: "
			   "seg %llu, peb %llu, err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id, err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0002: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_commit_log_payload(pebi, hdr_desc, &log_has_data,
					   &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to commit payload: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset.cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(&log_offset),
			   err);
		goto finish_commit_log;
	}

	if (!log_has_data) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("current log hasn't data: start_page %u\n",
			  pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0003: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	cur_hdr_desc = &hdr_desc[SSDFS_LOG_FOOTER_INDEX];
	flags = SSDFS_LOG_IS_PARTIAL |
		SSDFS_LOG_HAS_PARTIAL_HEADER |
		SSDFS_PARTIAL_HEADER_INSTEAD_FOOTER;
	err = ssdfs_peb_store_partial_log_header(pebi, flags, cur_hdr_desc,
						 plh_desc,
						 SSDFS_SEG_HDR_DESC_MAX,
						 &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's partial header: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset.cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(&log_offset),
			   err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0004: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_store_log_header(pebi, hdr_desc,
					 SSDFS_SEG_HDR_DESC_MAX,
					 SSDFS_LOCAL_LOG_OFFSET(&log_offset));
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's header: "
			   "seg %llu, peb %llu, write_offset %u,"
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   SSDFS_LOCAL_LOG_OFFSET(&log_offset), err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0005: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_flush_current_log_dirty_pages(pebi,
					SSDFS_LOCAL_LOG_OFFSET(&log_offset));
	if (unlikely(err)) {
		SSDFS_CRIT("fail to flush current log: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0006: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_define_next_log_start(pebi, SSDFS_START_PARTIAL_LOG,
					&log_offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0007: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->current_log.reserved_pages = 0;
	pebi->current_log.seg_flags = 0;

	ssdfs_peb_set_current_log_state(pebi, SSDFS_LOG_COMMITTED);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("log commited: seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

finish_commit_log:
	return err;
}

/*
 * ssdfs_peb_commit_next_partial_log() - commit next partial log
 * @pebi: pointer on PEB object
 *
 * This function tries to commit the next partial log.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_commit_next_partial_log(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor plh_desc[SSDFS_SEG_HDR_DESC_MAX];
	u32 flags;
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	struct ssdfs_peb_log_offset log_offset;
	bool log_has_data = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	memset(plh_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);

	SSDFS_LOG_OFFSET_INIT(&log_offset, pebi->log_pages,
			      pebi->current_log.start_page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0001: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_reserve_partial_log_header(pebi, &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to reserve partial log's header: "
			   "seg %llu, peb %llu, err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id, err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0002: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_commit_log_payload(pebi, plh_desc, &log_has_data,
					   &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to commit payload: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset.cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(&log_offset),
			   err);
		goto finish_commit_log;
	}

	if (!log_has_data) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("current log hasn't data: start_page %u\n",
			  pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	flags = SSDFS_LOG_IS_PARTIAL |
		SSDFS_LOG_HAS_PARTIAL_HEADER;
	err = ssdfs_peb_store_partial_log_header(pebi, flags, NULL,
						 plh_desc,
						 SSDFS_SEG_HDR_DESC_MAX,
						 &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's partial header: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset.cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(&log_offset),
			   err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0003: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_flush_current_log_dirty_pages(pebi,
				SSDFS_LOCAL_LOG_OFFSET(&log_offset));
	if (unlikely(err)) {
		SSDFS_CRIT("fail to flush current log: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0004: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_define_next_log_start(pebi, SSDFS_CONTINUE_PARTIAL_LOG,
					&log_offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0005: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->current_log.reserved_pages = 0;
	pebi->current_log.seg_flags = 0;

	ssdfs_peb_set_current_log_state(pebi, SSDFS_LOG_COMMITTED);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("log commited: seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

finish_commit_log:
	return err;
}

/*
 * ssdfs_peb_commit_last_partial_log() - commit last partial log
 * @pebi: pointer on PEB object
 * @cur_segs: current segment IDs array
 * @cur_segs_size: size of segment IDs array size in bytes
 *
 * This function tries to commit the last partial log.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_commit_last_partial_log(struct ssdfs_peb_info *pebi,
					__le64 *cur_segs,
					size_t cur_segs_size)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor plh_desc[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_metadata_descriptor lf_desc[SSDFS_LOG_FOOTER_DESC_MAX];
	struct ssdfs_metadata_descriptor *cur_hdr_desc;
	u32 flags;
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	struct ssdfs_peb_log_offset log_offset;
	pgoff_t cur_page_offset;
	bool log_has_data = false;
	int log_strategy = SSDFS_FINISH_PARTIAL_LOG;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	memset(plh_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);
	memset(lf_desc, 0, desc_size * SSDFS_LOG_FOOTER_DESC_MAX);

	SSDFS_LOG_OFFSET_INIT(&log_offset, pebi->log_pages,
			      pebi->current_log.start_page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0001: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_reserve_partial_log_header(pebi, &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to reserve partial log's header: "
			   "seg %llu, peb %llu, err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id, err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0002: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_commit_log_payload(pebi, plh_desc,
					   &log_has_data,
					   &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to commit payload: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   log_offset.cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(&log_offset),
			   err);
		goto finish_commit_log;
	}

	if (!log_has_data) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("current log hasn't data: start_page %u\n",
			  pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0003: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	cur_page_offset = log_offset.cur_page % pebi->log_pages;

	if (cur_page_offset == 0) {
		/*
		 * There is no space for log footer.
		 * So, full log will be without footer.
		 */
		SSDFS_DBG("There is no space for log footer.\n");

		flags = SSDFS_LOG_IS_PARTIAL |
			SSDFS_LOG_HAS_PARTIAL_HEADER;
		log_strategy = SSDFS_FINISH_PARTIAL_LOG;
	} else if ((pebi->log_pages - cur_page_offset) == 1) {
		cur_hdr_desc = &plh_desc[SSDFS_LOG_FOOTER_INDEX];
		flags = SSDFS_PARTIAL_LOG_FOOTER | SSDFS_ENDING_LOG_FOOTER;
		err = ssdfs_peb_store_log_footer(pebi, flags, cur_hdr_desc,
						 lf_desc,
						 SSDFS_LOG_FOOTER_DESC_MAX,
						 cur_segs, cur_segs_size,
						 &log_offset);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to store log's footer: "
				   "seg %llu, peb %llu, cur_page %lu, "
				   "write_offset %u, err %d\n",
				   pebi->pebc->parent_si->seg_id,
				   pebi->peb_id,
				   log_offset.cur_page,
				   SSDFS_LOCAL_LOG_OFFSET(&log_offset),
				   err);
			goto finish_commit_log;
		}

		flags = SSDFS_LOG_IS_PARTIAL |
			SSDFS_LOG_HAS_PARTIAL_HEADER |
			SSDFS_LOG_HAS_FOOTER;
		log_strategy = SSDFS_FINISH_PARTIAL_LOG;
	} else {
		/*
		 * It is possible to add another log.
		 */
		flags = SSDFS_LOG_IS_PARTIAL |
			SSDFS_LOG_HAS_PARTIAL_HEADER;
		log_strategy = SSDFS_CONTINUE_PARTIAL_LOG;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0004: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_store_partial_log_header(pebi, flags, NULL,
						 plh_desc,
						 SSDFS_SEG_HDR_DESC_MAX,
						 &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's partial header: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   log_offset.cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(&log_offset),
			   err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0005: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_flush_current_log_dirty_pages(pebi,
				SSDFS_LOCAL_LOG_OFFSET(&log_offset));
	if (unlikely(err)) {
		SSDFS_CRIT("fail to flush current log: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0006: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_define_next_log_start(pebi, log_strategy,
					&log_offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0007: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->current_log.reserved_pages = 0;
	pebi->current_log.seg_flags = 0;

	ssdfs_peb_set_current_log_state(pebi, SSDFS_LOG_COMMITTED);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("log commited: seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

finish_commit_log:
	return err;
}

/*
 * ssdfs_peb_commit_full_log() - commit full current log
 * @pebi: pointer on PEB object
 * @cur_segs: current segment IDs array
 * @cur_segs_size: size of segment IDs array size in bytes
 *
 * This function tries to commit the current log.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_commit_full_log(struct ssdfs_peb_info *pebi,
				__le64 *cur_segs,
				size_t cur_segs_size)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor hdr_desc[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_metadata_descriptor plh_desc[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_metadata_descriptor lf_desc[SSDFS_LOG_FOOTER_DESC_MAX];
	struct ssdfs_metadata_descriptor *cur_hdr_desc;
	int log_strategy = SSDFS_FINISH_FULL_LOG;
	u32 flags;
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	struct ssdfs_peb_log_offset log_offset;
	pgoff_t cur_page_offset;
	bool log_has_data = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	memset(hdr_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);
	memset(lf_desc, 0, desc_size * SSDFS_LOG_FOOTER_DESC_MAX);

	SSDFS_LOG_OFFSET_INIT(&log_offset, pebi->log_pages,
			      pebi->current_log.start_page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0001: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_reserve_segment_header(pebi, &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to reserve segment header: "
			   "seg %llu, peb %llu, err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id, err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0002: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_commit_log_payload(pebi, hdr_desc,
					   &log_has_data,
					   &log_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to commit payload: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   log_offset.cur_page,
			   SSDFS_LOCAL_LOG_OFFSET(&log_offset),
			   err);
		goto finish_commit_log;
	}

	if (!log_has_data) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("current log hasn't data: start_page %u\n",
			  pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_DEBUG */
		goto define_next_log_start;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0003: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	cur_page_offset = log_offset.cur_page % pebi->log_pages;
	if (cur_page_offset == 0) {
		SSDFS_WARN("There is no space for log footer.\n");
	}

	if ((pebi->log_pages - cur_page_offset) > 1) {
		log_strategy = SSDFS_START_PARTIAL_LOG;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("start partial log: "
			  "cur_page_offset %lu, pebi->log_pages %u\n",
			  cur_page_offset, pebi->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

		cur_hdr_desc = &hdr_desc[SSDFS_LOG_FOOTER_INDEX];
		flags = SSDFS_LOG_IS_PARTIAL |
			SSDFS_LOG_HAS_PARTIAL_HEADER |
			SSDFS_PARTIAL_HEADER_INSTEAD_FOOTER;
		err = ssdfs_peb_store_partial_log_header(pebi, flags,
							 cur_hdr_desc,
							 plh_desc,
							 SSDFS_SEG_HDR_DESC_MAX,
							 &log_offset);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to store log's partial header: "
				   "seg %llu, peb %llu, cur_page %lu, "
				   "write_offset %u, err %d\n",
				   pebi->pebc->parent_si->seg_id,
				   pebi->peb_id,
				   log_offset.cur_page,
				   SSDFS_LOCAL_LOG_OFFSET(&log_offset),
				   err);
			goto finish_commit_log;
		}
	} else {
		log_strategy = SSDFS_FINISH_FULL_LOG;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("finish full log: "
			  "cur_page_offset %lu, pebi->log_pages %u\n",
			  cur_page_offset, pebi->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

		cur_hdr_desc = &hdr_desc[SSDFS_LOG_FOOTER_INDEX];
		flags = 0;
		err = ssdfs_peb_store_log_footer(pebi, flags, cur_hdr_desc,
						 lf_desc,
						 SSDFS_LOG_FOOTER_DESC_MAX,
						 cur_segs, cur_segs_size,
						 &log_offset);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to store log's footer: "
				   "seg %llu, peb %llu, cur_page %lu, "
				   "write_offset %u, err %d\n",
				   pebi->pebc->parent_si->seg_id,
				   pebi->peb_id,
				   log_offset.cur_page,
				   SSDFS_LOCAL_LOG_OFFSET(&log_offset),
				   err);
			goto finish_commit_log;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0004: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_store_log_header(pebi, hdr_desc,
					 SSDFS_SEG_HDR_DESC_MAX,
					 SSDFS_LOCAL_LOG_OFFSET(&log_offset));
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's header: "
			   "seg %llu, peb %llu, write_offset %u,"
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   SSDFS_LOCAL_LOG_OFFSET(&log_offset), err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0005: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_flush_current_log_dirty_pages(pebi,
				SSDFS_LOCAL_LOG_OFFSET(&log_offset));
	if (unlikely(err)) {
		SSDFS_CRIT("fail to flush current log: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		goto finish_commit_log;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0006: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

define_next_log_start:
	ssdfs_peb_define_next_log_start(pebi, log_strategy,
					&log_offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("0007: cur_page %lu, write_offset %u\n",
		  log_offset.cur_page,
		  SSDFS_LOCAL_LOG_OFFSET(&log_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->current_log.reserved_pages = 0;
	pebi->current_log.seg_flags = 0;

	ssdfs_peb_set_current_log_state(pebi, SSDFS_LOG_COMMITTED);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("log commited: seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

finish_commit_log:
	return err;
}

/*
 * ssdfs_peb_calculate_reserved_metapages() - calculate reserved metapages
 * @page_size: size of page in bytes
 * @data_pages: number of allocated data pages
 * @pebs_per_seg: number of PEBs in one segment
 * @log_strategy: stategy of log commiting
 */
u16 ssdfs_peb_calculate_reserved_metapages(u32 page_size,
					   u32 data_pages,
					   u32 pebs_per_seg,
					   int log_strategy)
{
	size_t seg_hdr_size = sizeof(struct ssdfs_segment_header);
	size_t lf_hdr_size = sizeof(struct ssdfs_log_footer);
	u32 blk_bmap_bytes = 0;
	u32 blk2off_tbl_bytes = 0;
	u32 blk_desc_tbl_bytes = 0;
	u32 reserved_bytes = 0;
	u32 reserved_pages = 0;

	/* segment header */
	reserved_bytes += seg_hdr_size;

	/* block bitmap */
	blk_bmap_bytes = __ssdfs_peb_estimate_blk_bmap_bytes(data_pages, true);
	reserved_bytes += blk_bmap_bytes;

	/* blk2off table */
	blk2off_tbl_bytes = __ssdfs_peb_estimate_blk2off_bytes(data_pages,
								pebs_per_seg);
	reserved_bytes += blk2off_tbl_bytes;

	/* block descriptor table */
	blk_desc_tbl_bytes =
		__ssdfs_peb_estimate_blk_desc_tbl_bytes(data_pages);
	reserved_bytes += blk_desc_tbl_bytes;

	reserved_bytes += page_size - 1;
	reserved_bytes /= page_size;
	reserved_bytes *= page_size;

	switch (log_strategy) {
	case SSDFS_START_FULL_LOG:
	case SSDFS_FINISH_PARTIAL_LOG:
	case SSDFS_FINISH_FULL_LOG:
		/* log footer header */
		reserved_bytes += lf_hdr_size;

		/* block bitmap */
		reserved_bytes += blk_bmap_bytes;

		/* blk2off table */
		reserved_bytes += blk2off_tbl_bytes;

		reserved_bytes += page_size - 1;
		reserved_bytes /= page_size;
		reserved_bytes *= page_size;

		reserved_pages = reserved_bytes / page_size;
		break;

	case SSDFS_START_PARTIAL_LOG:
	case SSDFS_CONTINUE_PARTIAL_LOG:
		/* do nothing */
		break;

	default:
		SSDFS_CRIT("unexpected log strategy %#x\n",
			   log_strategy);
		return U16_MAX;
	}

	reserved_pages = reserved_bytes / page_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("data_pages %u, log_strategy %#x, "
		  "blk_bmap_bytes %u, blk2off_tbl_bytes %u, "
		  "blk_desc_tbl_bytes %u, reserved_bytes %u, "
		  "reserved_pages %u\n",
		  data_pages, log_strategy,
		  blk_bmap_bytes, blk2off_tbl_bytes,
		  blk_desc_tbl_bytes, reserved_bytes,
		  reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	BUG_ON(reserved_pages >= U16_MAX);

	return (u16)reserved_pages;
}

/*
 * ssdfs_peb_commit_log() - commit current log
 * @pebi: pointer on PEB object
 * @cur_segs: current segment IDs array
 * @cur_segs_size: size of segment IDs array size in bytes
 *
 * This function tries to commit the current log.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_commit_log(struct ssdfs_peb_info *pebi,
			 __le64 *cur_segs, size_t cur_segs_size)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_blk2off_table *table;
	int log_state;
	int log_strategy;
	u32 page_size;
	u32 pebs_per_seg;
	u32 pages_per_peb;
	int used_pages;
	int invalid_pages;
	u32 data_pages;
	u16 reserved_pages;
	u16 diff;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	log_state = atomic_read(&pebi->current_log.state);

	switch (log_state) {
	case SSDFS_LOG_UNKNOWN:
	case SSDFS_LOG_PREPARED:
	case SSDFS_LOG_INITIALIZED:
		SSDFS_WARN("peb %llu current log can't be commited\n",
			   pebi->peb_id);
		return -EINVAL;

	case SSDFS_LOG_CREATED:
		/* do function's work */
		break;

	case SSDFS_LOG_COMMITTED:
		SSDFS_WARN("peb %llu current log has been commited\n",
			   pebi->peb_id);
		return 0;

	default:
		BUG();
	};

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);
#else
	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	si = pebi->pebc->parent_si;
	log_strategy = is_log_partial(pebi);
	page_size = pebi->pebc->parent_si->fsi->pagesize;
	pebs_per_seg = pebi->pebc->parent_si->fsi->pebs_per_seg;
	pages_per_peb = pebi->pebc->parent_si->fsi->pages_per_peb;

	used_pages = ssdfs_peb_get_used_data_pages(pebi->pebc);
	if (used_pages < 0) {
		err = used_pages;
		SSDFS_ERR("fail to get used data pages count: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		return err;
	}

	invalid_pages = ssdfs_peb_get_invalid_pages(pebi->pebc);
	if (invalid_pages < 0) {
		err = invalid_pages;
		SSDFS_ERR("fail to get invalid pages count: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		return err;
	}

	data_pages = used_pages + invalid_pages;

	if (data_pages == 0) {
		SSDFS_ERR("invalid data pages count: "
			  "used_pages %d, invalid_pages %d, "
			  "data_pages %u\n",
			  used_pages, invalid_pages, data_pages);
		return -ERANGE;
	}

	reserved_pages = ssdfs_peb_calculate_reserved_metapages(page_size,
								data_pages,
								pebs_per_seg,
								log_strategy);
	if (reserved_pages > pages_per_peb) {
		SSDFS_ERR("reserved_pages %u > pages_per_peb %u\n",
			  reserved_pages, pages_per_peb);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_pages %u, "
		  "pebi->current_log.reserved_pages %u\n",
		  reserved_pages,
		  pebi->current_log.reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	if (reserved_pages > pebi->current_log.reserved_pages) {
		diff = reserved_pages - pebi->current_log.reserved_pages;

		err = ssdfs_segment_blk_bmap_reserve_metapages(&si->blk_bmap,
								pebi->pebc,
								diff);
		if (err == -ENOSPC) {
			/* ignore error */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to reserve metadata pages: "
				  "count %u, err %d\n",
				  diff, err);
			return err;
		}

		pebi->current_log.reserved_pages += diff;
		if (diff > pebi->current_log.free_data_pages)
			pebi->current_log.free_data_pages = 0;
		else
			pebi->current_log.free_data_pages -= diff;
	} else if (reserved_pages < pebi->current_log.reserved_pages) {
		diff = pebi->current_log.reserved_pages - reserved_pages;

		err = ssdfs_segment_blk_bmap_free_metapages(&si->blk_bmap,
							    pebi->pebc,
							    diff);
		if (unlikely(err)) {
			SSDFS_ERR("fail to free metadata pages: "
				  "count %u, err %d\n",
				  diff, err);
			return err;
		}

		pebi->current_log.reserved_pages -= diff;
		pebi->current_log.free_data_pages += diff;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("data_pages %u, "
		  "current_log (reserved_pages %u, free_data_pages %u)\n",
		  data_pages,
		  pebi->current_log.reserved_pages,
		  pebi->current_log.free_data_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->current_log.last_log_time = ssdfs_current_timestamp();
	pebi->current_log.last_log_cno = ssdfs_current_cno(si->fsi->sb);

	log_strategy = is_log_partial(pebi);

	switch (log_strategy) {
	case SSDFS_START_FULL_LOG:
		SSDFS_CRIT("log contains nothing: "
			   "seg %llu, peb %llu, "
			   "free_data_pages %u\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id,
			   pebi->current_log.free_data_pages);
		return -ERANGE;

	case SSDFS_START_PARTIAL_LOG:
		err = ssdfs_peb_commit_first_partial_log(pebi);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to commit first partial log: "
				   "err %d\n", err);
			return err;
		}
		break;

	case SSDFS_CONTINUE_PARTIAL_LOG:
		err = ssdfs_peb_commit_next_partial_log(pebi);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to commit next partial log: "
				   "err %d\n", err);
			return err;
		}
		break;

	case SSDFS_FINISH_PARTIAL_LOG:
		err = ssdfs_peb_commit_last_partial_log(pebi, cur_segs,
							cur_segs_size);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to commit last partial log: "
				   "err %d\n", err);
			return err;
		}
		break;

	case SSDFS_FINISH_FULL_LOG:
		err = ssdfs_peb_commit_full_log(pebi, cur_segs,
						cur_segs_size);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to commit full log: "
				   "err %d\n", err);
			return err;
		}
		break;

	default:
		SSDFS_CRIT("unexpected log strategy %#x\n",
			   log_strategy);
		return -ERANGE;
	}

	table = pebi->pebc->parent_si->blk2off_table;

	err = ssdfs_blk2off_table_revert_migration_state(table,
							 pebi->peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to revert migration state: "
			  "seg %llu, peb %llu, peb_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  pebi->peb_index,
			  err);
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_peb_remain_log_creation_thread() - remain as log creation thread
 * @pebc: pointer on PEB container
 *
 * This function check that PEB's flush thread can work
 * as thread that creates logs.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOSPC     - PEB hasn't free space.
 */
static
int ssdfs_peb_remain_log_creation_thread(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	int peb_free_pages;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);

	SSDFS_DBG("seg %llu, peb_index %d\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;

	peb_free_pages = ssdfs_peb_get_free_pages(pebc);
	if (unlikely(peb_free_pages < 0)) {
		err = peb_free_pages;
		SSDFS_ERR("fail to calculate PEB's free pages: "
			  "seg %llu, peb index %d, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_free_pages %d\n", peb_free_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_free_pages == 0) {
		SSDFS_DBG("PEB hasn't free space\n");
		return -ENOSPC;
	}

	if (!is_peb_joined_into_create_requests_queue(pebc)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_WARN("peb_index %u hasn't creation role\n",
			    pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_peb_join_create_requests_queue(pebc,
							   &si->create_rq);
		if (unlikely(err)) {
			SSDFS_ERR("fail to join create requests queue: "
				  "seg %llu, peb_index %d, err %d\n",
				  si->seg_id, pebc->peb_index, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_peb_delegate_log_creation_role() - try to delegate log creation role
 * @pebc: pointer on PEB container
 * @found_peb_index: index of PEB candidate
 *
 * This function tries to delegate the role of logs creation to
 * PEB with @found_peb_index.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EAGAIN     - it needs to search another candidate.
 */
static
int ssdfs_peb_delegate_log_creation_role(struct ssdfs_peb_container *pebc,
					 int found_peb_index)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *found_pebc;
	int peb_free_pages;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
	BUG_ON(found_peb_index >= pebc->parent_si->pebs_count);

	SSDFS_DBG("seg %llu, peb_index %d, found_peb_index %d\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  found_peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;

	if (found_peb_index == pebc->peb_index) {
		err = ssdfs_peb_remain_log_creation_thread(pebc);
		if (err == -ENOSPC) {
			SSDFS_WARN("PEB hasn't free space\n");
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to remain log creation thread: "
				  "seg %llu, peb_index %d, "
				  "err %d\n",
				  si->seg_id, pebc->peb_index, err);
			return err;
		}

		return 0;
	}

	found_pebc = &si->peb_array[found_peb_index];

	peb_free_pages = ssdfs_peb_get_free_pages(found_pebc);
	if (unlikely(peb_free_pages < 0)) {
		err = peb_free_pages;
		SSDFS_ERR("fail to calculate PEB's free pages: "
			  "seg %llu, peb index %d, err %d\n",
			  found_pebc->parent_si->seg_id,
			  found_pebc->peb_index, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb_index %d, peb_free_pages %d\n",
		  found_pebc->parent_si->seg_id,
		  found_pebc->peb_index,
		  peb_free_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_free_pages == 0)
		return -EAGAIN;

	if (is_peb_joined_into_create_requests_queue(found_pebc)) {
		SSDFS_WARN("PEB is creating log: "
			   "seg %llu, peb_index %d\n",
			   found_pebc->parent_si->seg_id,
			   found_pebc->peb_index);
		return -EAGAIN;
	}

	ssdfs_peb_forget_create_requests_queue(pebc);

	err = ssdfs_peb_join_create_requests_queue(found_pebc,
						   &si->create_rq);
	if (unlikely(err)) {
		SSDFS_ERR("fail to join create requests queue: "
			  "seg %llu, peb_index %d, err %d\n",
			  si->seg_id, found_pebc->peb_index, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_find_next_log_creation_thread() - search PEB for logs creation
 * @pebc: pointer on PEB container
 *
 * This function tries to find and to delegate the role of logs creation
 * to another PEB's flush thread.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - fail to find another PEB.
 */
static
int ssdfs_peb_find_next_log_creation_thread(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	int start_pos;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);

	SSDFS_DBG("seg %llu, peb_index %d\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;

	if (!is_peb_joined_into_create_requests_queue(pebc)) {
		SSDFS_WARN("peb_index %u hasn't creation role\n",
			    pebc->peb_index);
		return -EINVAL;
	}

	start_pos = pebc->peb_index + si->create_threads;

	if (start_pos >= si->pebs_count)
		start_pos = pebc->peb_index % si->create_threads;

	if (start_pos == pebc->peb_index) {
		err = ssdfs_peb_remain_log_creation_thread(pebc);
		if (err == -ENOSPC) {
			SSDFS_DBG("PEB hasn't free space\n");
			return 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to remain log creation thread: "
				  "seg %llu, peb_index %d, "
				  "err %d\n",
				  si->seg_id, pebc->peb_index, err);
			return err;
		} else
			return 0;
	}

	if (start_pos < pebc->peb_index)
		goto search_from_begin;

	for (i = start_pos; i < si->pebs_count; i += si->create_threads) {
		err = ssdfs_peb_delegate_log_creation_role(pebc, i);
		if (err == -EAGAIN)
			continue;
		else if (err == -ENOSPC) {
			SSDFS_WARN("PEB hasn't free space\n");
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to delegate log creation role: "
				  "seg %llu, peb_index %d, "
				  "found_peb_index %d, err %d\n",
				  si->seg_id, pebc->peb_index,
				  i, err);
			return err;
		} else
			return 0;
	}

	start_pos = pebc->peb_index % si->create_threads;

search_from_begin:
	for (i = start_pos; i <= pebc->peb_index; i += si->create_threads) {
		err = ssdfs_peb_delegate_log_creation_role(pebc, i);
		if (err == -EAGAIN)
			continue;
		if (err == -ENOSPC) {
			SSDFS_WARN("PEB hasn't free space\n");
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to delegate log creation role: "
				  "seg %llu, peb_index %d, "
				  "found_peb_index %d, err %d\n",
				  si->seg_id, pebc->peb_index,
				  i, err);
			return err;
		} else
			return 0;
	}

	SSDFS_ERR("fail to delegate log creation role: "
		  "seg %llu, peb_index %d\n",
		  si->seg_id, pebc->peb_index);
	return -ERANGE;
}

/*
 * __ssdfs_finish_request() - common logic of request's finishing
 * @pebc: pointer on PEB container
 * @req: request
 * @wait: wait queue head
 * @err: error of processing request
 */
static
void __ssdfs_finish_request(struct ssdfs_peb_container *pebc,
			    struct ssdfs_segment_request *req,
			    wait_queue_head_t *wait,
			    int err)
{
	u32 pagesize;
	u32 processed_bytes_max;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);

	SSDFS_DBG("req %p, cmd %#x, type %#x, err %d\n",
		  req, req->private.cmd, req->private.type, err);
#endif /* CONFIG_SSDFS_DEBUG */

	pagesize = pebc->parent_si->fsi->pagesize;
	processed_bytes_max = req->result.processed_blks * pagesize;

	if (req->extent.data_bytes > processed_bytes_max) {
		SSDFS_WARN("data_bytes %u > processed_bytes_max %u\n",
			   req->extent.data_bytes,
			   processed_bytes_max);
	}

	req->result.err = err;

	switch (req->private.type) {
	case SSDFS_REQ_SYNC:
		/* do nothing */
		break;

	case SSDFS_REQ_ASYNC:
		ssdfs_free_flush_request_pages(req);
		pagevec_reinit(&req->result.pvec);
		break;

	case SSDFS_REQ_ASYNC_NO_FREE:
		ssdfs_free_flush_request_pages(req);
		pagevec_reinit(&req->result.pvec);
		break;

	default:
		BUG();
	};

	switch (req->private.type) {
	case SSDFS_REQ_SYNC:
		if (err) {
			SSDFS_DBG("failure: req %p, err %d\n", req, err);
			atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		} else
			atomic_set(&req->result.state, SSDFS_REQ_FINISHED);

		complete(&req->result.wait);
		wake_up_all(&req->private.wait_queue);
		break;

	case SSDFS_REQ_ASYNC:
		ssdfs_put_request(req);

		if (err) {
			SSDFS_DBG("failure: req %p, err %d\n", req, err);
			atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		} else
			atomic_set(&req->result.state, SSDFS_REQ_FINISHED);

		complete(&req->result.wait);

		if (atomic_read(&req->private.refs_count) != 0) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("start waiting: refs_count %d\n",
				   atomic_read(&req->private.refs_count));
#endif /* CONFIG_SSDFS_DEBUG */

			err = wait_event_killable_timeout(*wait,
			    atomic_read(&req->private.refs_count) == 0,
			    SSDFS_DEFAULT_TIMEOUT);
			if (err < 0)
				WARN_ON(err < 0);
			else
				err = 0;
		}

		wake_up_all(&req->private.wait_queue);
		ssdfs_request_free(req);
		break;

	case SSDFS_REQ_ASYNC_NO_FREE:
		ssdfs_put_request(req);

		if (err) {
			SSDFS_DBG("failure: req %p, err %d\n", req, err);
			atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		} else
			atomic_set(&req->result.state, SSDFS_REQ_FINISHED);

		complete(&req->result.wait);

		if (atomic_read(&req->private.refs_count) != 0) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("start waiting: refs_count %d\n",
				   atomic_read(&req->private.refs_count));
#endif /* CONFIG_SSDFS_DEBUG */

			err = wait_event_killable_timeout(*wait,
			    atomic_read(&req->private.refs_count) == 0,
			    SSDFS_DEFAULT_TIMEOUT);
			if (err < 0)
				WARN_ON(err < 0);
			else
				err = 0;
		}

		wake_up_all(&req->private.wait_queue);
		break;

	default:
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		BUG();
	};
}

/*
 * ssdfs_finish_pre_allocate_request() - finish pre-allocate request
 * @pebc: pointer on PEB container
 * @req: request
 * @wait: wait queue head
 * @err: error of processing request
 *
 * This function finishes pre-allocate request processing. If attempt of
 * pre-allocate an extent has been resulted with %-EAGAIN error then
 * function returns request into create queue for final
 * processing.
 */
static
void ssdfs_finish_pre_allocate_request(struct ssdfs_peb_container *pebc,
					struct ssdfs_segment_request *req,
					wait_queue_head_t *wait,
					int err)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);

	SSDFS_DBG("req %p, cmd %#x, type %#x, err %d\n",
		  req, req->private.cmd, req->private.type, err);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!err) {
		WARN_ON(pagevec_count(&req->result.pvec) != 0);
		ssdfs_flush_pagevec_release(&req->result.pvec);
	}

	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("return request into queue: "
			  "seg %llu, peb_index %u, "
			  "ino %llu, logical_offset %llu, "
			  "data_bytes %u, cno %llu, parent_snapshot %llu"
			  "seg %llu, logical_block %u, cmd %#x, type %#x, "
			  "processed_blks %d\n",
			  pebc->parent_si->seg_id, pebc->peb_index,
			  req->extent.ino, req->extent.logical_offset,
			  req->extent.data_bytes, req->extent.cno,
			  req->extent.parent_snapshot,
			  req->place.start.seg_id, req->place.start.blk_index,
			  req->private.cmd, req->private.type,
			  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

		atomic_set(&req->result.state, SSDFS_REQ_CREATED);

		spin_lock(&pebc->crq_ptr_lock);
		ssdfs_requests_queue_add_head(pebc->create_rq, req);
		spin_unlock(&pebc->crq_ptr_lock);
	} else
		__ssdfs_finish_request(pebc, req, wait, err);
}

/*
 * ssdfs_finish_create_request() - finish create request
 * @pebc: pointer on PEB container
 * @req: request
 * @wait: wait queue head
 * @err: error of processing request
 *
 * This function finishes create request processing. If attempt of
 * adding data block has been resulted with %-EAGAIN error then
 * function returns request into create queue for final
 * processing.
 */
static
void ssdfs_finish_create_request(struct ssdfs_peb_container *pebc,
				 struct ssdfs_segment_request *req,
				 wait_queue_head_t *wait,
				 int err)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);

	SSDFS_DBG("req %p, cmd %#x, type %#x, err %d\n",
		  req, req->private.cmd, req->private.type, err);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!err) {
		for (i = 0; i < req->result.processed_blks; i++)
			ssdfs_peb_mark_request_block_uptodate(pebc, req, i);
	}

	if (err == -EAGAIN) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("return request into queue: "
			  "seg %llu, peb_index %u, "
			  "ino %llu, logical_offset %llu, "
			  "data_bytes %u, cno %llu, parent_snapshot %llu"
			  "seg %llu, logical_block %u, cmd %#x, type %#x, "
			  "processed_blks %d\n",
			  pebc->parent_si->seg_id, pebc->peb_index,
			  req->extent.ino, req->extent.logical_offset,
			  req->extent.data_bytes, req->extent.cno,
			  req->extent.parent_snapshot,
			  req->place.start.seg_id, req->place.start.blk_index,
			  req->private.cmd, req->private.type,
			  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

		atomic_set(&req->result.state, SSDFS_REQ_CREATED);

		spin_lock(&pebc->crq_ptr_lock);
		ssdfs_requests_queue_add_head(pebc->create_rq, req);
		spin_unlock(&pebc->crq_ptr_lock);
	} else
		__ssdfs_finish_request(pebc, req, wait, err);
}

/*
 * ssdfs_finish_update_request() - finish update request
 * @pebc: pointer on PEB container
 * @req: request
 * @wait: wait queue head
 * @err: error of processing request
 *
 * This function finishes update request processing.
 */
static
void ssdfs_finish_update_request(struct ssdfs_peb_container *pebc,
				 struct ssdfs_segment_request *req,
				 wait_queue_head_t *wait,
				 int err)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);

	SSDFS_DBG("req %p, cmd %#x, type %#x, err %d\n",
		  req, req->private.cmd, req->private.type, err);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!err) {
		for (i = 0; i < req->result.processed_blks; i++)
			ssdfs_peb_mark_request_block_uptodate(pebc, req, i);
	}

	__ssdfs_finish_request(pebc, req, wait, err);
}

/*
 * ssdfs_finish_flush_request() - finish flush request
 * @pebc: pointer on PEB container
 * @req: request
 * @wait: wait queue head
 * @err: error of processing request
 */
static inline
void ssdfs_finish_flush_request(struct ssdfs_peb_container *pebc,
				struct ssdfs_segment_request *req,
				wait_queue_head_t *wait,
				int err)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);

	SSDFS_DBG("req %p, cmd %#x, type %#x, err %d\n",
		  req, req->private.cmd, req->private.type, err);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req->private.class) {
	case SSDFS_PEB_PRE_ALLOCATE_DATA_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_LNODE_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_HNODE_REQ:
	case SSDFS_PEB_PRE_ALLOCATE_IDXNODE_REQ:
		ssdfs_finish_pre_allocate_request(pebc, req, wait, err);
		break;

	case SSDFS_PEB_CREATE_DATA_REQ:
	case SSDFS_PEB_CREATE_LNODE_REQ:
	case SSDFS_PEB_CREATE_HNODE_REQ:
	case SSDFS_PEB_CREATE_IDXNODE_REQ:
		ssdfs_finish_create_request(pebc, req, wait, err);
		break;

	case SSDFS_PEB_UPDATE_REQ:
	case SSDFS_PEB_PRE_ALLOC_UPDATE_REQ:
	case SSDFS_PEB_DIFF_ON_WRITE_REQ:
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
	case SSDFS_ZONE_USER_DATA_MIGRATE_REQ:
		ssdfs_finish_update_request(pebc, req, wait, err);
		break;

	default:
		BUG();
	};

	ssdfs_forget_user_data_flush_request(pebc->parent_si);
	ssdfs_segment_finish_request_cno(pebc->parent_si);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("flush_reqs %lld\n",
		  atomic64_read(&pebc->parent_si->fsi->flush_reqs));
#endif /* CONFIG_SSDFS_DEBUG */

	WARN_ON(atomic64_dec_return(&pebc->parent_si->fsi->flush_reqs) < 0);
}

/*
 * ssdfs_peb_clear_current_log_pages() - clear dirty pages of current log
 * @pebi: pointer on PEB object
 */
static inline
void ssdfs_peb_clear_current_log_pages(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_page_array *area_pages;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < SSDFS_LOG_AREA_MAX; i++) {
		area_pages = &pebi->current_log.area[i].array;
		err = ssdfs_page_array_clear_all_dirty_pages(area_pages);
		if (unlikely(err)) {
			SSDFS_ERR("fail to clear dirty pages: "
				  "area_type %#x, err %d\n",
				  i, err);
		}
	}
}

/*
 * ssdfs_peb_clear_current_log_pages() - clear dirty pages of PEB's cache
 * @pebi: pointer on PEB object
 */
static inline
void ssdfs_peb_clear_cache_dirty_pages(struct ssdfs_peb_info *pebi)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_page_array_clear_all_dirty_pages(&pebi->cache);
	if (unlikely(err)) {
		SSDFS_ERR("fail to clear dirty pages: "
			  "err %d\n",
			  err);
	}
}

/*
 * ssdfs_peb_commit_log_on_thread_stop() - commit log on thread stopping
 * @pebi: pointer on PEB object
 * @cur_segs: current segment IDs array
 * @size: size of segment IDs array size in bytes
 */
static
int ssdfs_peb_commit_log_on_thread_stop(struct ssdfs_peb_info *pebi,
					__le64 *cur_segs, size_t size)
{
	struct ssdfs_fs_info *fsi;
	u64 reserved_new_user_data_pages;
	u64 updated_user_data_pages;
	u64 flushing_user_data_requests;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));

	SSDFS_DBG("seg %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	if (ssdfs_peb_has_dirty_pages(pebi)) {
		/*
		 * Unexpected situation.
		 * Try to commit anyway.
		 */

		spin_lock(&fsi->volume_state_lock);
		reserved_new_user_data_pages =
			fsi->reserved_new_user_data_pages;
		updated_user_data_pages =
			fsi->updated_user_data_pages;
		flushing_user_data_requests =
			fsi->flushing_user_data_requests;
		spin_unlock(&fsi->volume_state_lock);

		SSDFS_WARN("PEB has dirty pages: "
			   "seg %llu, peb %llu, peb_type %#x, "
			   "global_fs_state %#x, "
			   "reserved_new_user_data_pages %llu, "
			   "updated_user_data_pages %llu, "
			   "flushing_user_data_requests %llu\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_id, pebi->pebc->peb_type,
			   atomic_read(&fsi->global_fs_state),
			   reserved_new_user_data_pages,
			   updated_user_data_pages,
			   flushing_user_data_requests);

		err = ssdfs_peb_commit_log(pebi, cur_segs, size);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to commit log: "
				   "seg %llu, peb_index %u, err %d\n",
				   pebi->pebc->parent_si->seg_id,
				   pebi->peb_index, err);

			ssdfs_peb_clear_current_log_pages(pebi);
			ssdfs_peb_clear_cache_dirty_pages(pebi);
		}
	}

	return err;
}

/*
 * ssdfs_peb_get_current_log_state() - get state of PEB's current log
 * @pebc: pointer on PEB container
 */
static
int ssdfs_peb_get_current_log_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_info *pebi = NULL;
	bool is_peb_exhausted;
	int state;
	int err = 0;

	fsi = pebc->parent_si->fsi;

try_get_current_state:
	down_read(&pebc->lock);

	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_NOT_MIGRATING:
		pebi = pebc->src_peb;
		if (!pebi) {
			err = -ERANGE;
			SSDFS_WARN("source PEB is NULL\n");
			goto finish_get_current_log_state;
		}
		state = atomic_read(&pebi->current_log.state);
		break;

	case SSDFS_PEB_UNDER_MIGRATION:
		pebi = pebc->src_peb;
		if (!pebi) {
			err = -ERANGE;
			SSDFS_WARN("source PEB is NULL\n");
			goto finish_get_current_log_state;
		}

		ssdfs_peb_current_log_lock(pebi);
		is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
		ssdfs_peb_current_log_unlock(pebi);

		if (is_peb_exhausted) {
			pebi = pebc->dst_peb;
			if (!pebi) {
				err = -ERANGE;
				SSDFS_WARN("destination PEB is NULL\n");
				goto finish_get_current_log_state;
			}
		}

		state = atomic_read(&pebi->current_log.state);
		break;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
	case SSDFS_PEB_FINISHING_MIGRATION:
		err = -EAGAIN;
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid state: %#x\n",
			   atomic_read(&pebc->migration_state));
		goto finish_get_current_log_state;
		break;
	}

finish_get_current_log_state:
	up_read(&pebc->lock);

	if (err == -EAGAIN) {
		DEFINE_WAIT(wait);

		err = 0;
		prepare_to_wait(&pebc->migration_wq, &wait,
				TASK_UNINTERRUPTIBLE);
		schedule();
		finish_wait(&pebc->migration_wq, &wait);
		goto try_get_current_state;
	} else if (unlikely(err))
		state = SSDFS_LOG_UNKNOWN;

	return state;
}

bool is_ssdfs_peb_exhausted(struct ssdfs_fs_info *fsi,
			    struct ssdfs_peb_info *pebi)
{
	bool is_exhausted = false;
	u16 start_page;
	u32 pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi);
	BUG_ON(!mutex_is_locked(&pebi->current_log.lock));
#endif /* CONFIG_SSDFS_DEBUG */

	start_page = pebi->current_log.start_page;
	pages_per_peb = min_t(u32, fsi->leb_pages_capacity,
				   fsi->peb_pages_capacity);

	switch (atomic_read(&pebi->current_log.state)) {
	case SSDFS_LOG_INITIALIZED:
	case SSDFS_LOG_COMMITTED:
	case SSDFS_LOG_CREATED:
		is_exhausted = start_page >= pages_per_peb;
		break;

	default:
		is_exhausted = false;
		break;
	};

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, peb_id %llu, start_page %u, "
		  "pages_per_peb %u, is_exhausted %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, start_page,
		  pages_per_peb, is_exhausted);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_exhausted;
}

bool is_ssdfs_peb_ready_to_exhaust(struct ssdfs_fs_info *fsi,
				   struct ssdfs_peb_info *pebi)
{
	bool is_ready_to_exhaust = false;
	u16 start_page;
	u32 pages_per_peb;
	u16 free_data_pages;
	u16 reserved_pages;
	u16 min_partial_log_pages;
	int empty_pages;
	int migration_state;
	int migration_phase;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!mutex_is_locked(&pebi->current_log.lock));
#endif /* CONFIG_SSDFS_DEBUG */

	migration_state = atomic_read(&pebi->pebc->migration_state);
	migration_phase = atomic_read(&pebi->pebc->migration_phase);

	switch (migration_state) {
	case SSDFS_PEB_NOT_MIGRATING:
		/* continue logic */
		break;

	case SSDFS_PEB_UNDER_MIGRATION:
		switch (migration_phase) {
		case SSDFS_SRC_PEB_NOT_EXHAUSTED:
			is_ready_to_exhaust = false;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("peb under migration: "
				  "src_peb %llu is not exhausted\n",
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			return is_ready_to_exhaust;

		default:
			/* continue logic */
			break;
		}
		break;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
	case SSDFS_PEB_FINISHING_MIGRATION:
		is_ready_to_exhaust = true;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb is going to migrate: "
			  "src_peb %llu is exhausted\n",
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return is_ready_to_exhaust;

	default:
		SSDFS_WARN("migration_state %#x, migration_phase %#x\n",
			   migration_state, migration_phase);
		BUG();
		break;
	}

	start_page = pebi->current_log.start_page;
	pages_per_peb = min_t(u32, fsi->leb_pages_capacity,
				   fsi->peb_pages_capacity);
	empty_pages = pages_per_peb - start_page;
	free_data_pages = pebi->current_log.free_data_pages;
	reserved_pages = pebi->current_log.reserved_pages;
	min_partial_log_pages = ssdfs_peb_estimate_min_partial_log_pages(pebi);

	switch (atomic_read(&pebi->current_log.state)) {
	case SSDFS_LOG_INITIALIZED:
	case SSDFS_LOG_COMMITTED:
	case SSDFS_LOG_CREATED:
		if (empty_pages > min_partial_log_pages)
			is_ready_to_exhaust = false;
		else if (reserved_pages == 0) {
			if (free_data_pages <= min_partial_log_pages)
				is_ready_to_exhaust = true;
			else
				is_ready_to_exhaust = false;
		} else {
			if (free_data_pages < min_partial_log_pages)
				is_ready_to_exhaust = true;
			else
				is_ready_to_exhaust = false;
		}
		break;

	default:
		is_ready_to_exhaust = false;
		break;
	};

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, peb_id %llu, free_data_pages %u, "
		  "reserved_pages %u, min_partial_log_pages %u, "
		  "is_ready_to_exhaust %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, free_data_pages,
		  reserved_pages, min_partial_log_pages,
		  is_ready_to_exhaust);
#endif /* CONFIG_SSDFS_DEBUG */

	return is_ready_to_exhaust;
}

static inline
bool ssdfs_peb_has_partial_empty_log(struct ssdfs_fs_info *fsi,
				     struct ssdfs_peb_info *pebi)
{
	bool has_partial_empty_log = false;
	u16 start_page;
	u32 pages_per_peb;
	u16 log_pages;
	int empty_pages;
	u16 min_partial_log_pages;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi);
	BUG_ON(!mutex_is_locked(&pebi->current_log.lock));
#endif /* CONFIG_SSDFS_DEBUG */

	start_page = pebi->current_log.start_page;
	pages_per_peb = min_t(u32, fsi->leb_pages_capacity,
				   fsi->peb_pages_capacity);
	log_pages = pebi->log_pages;
	min_partial_log_pages = ssdfs_peb_estimate_min_partial_log_pages(pebi);

	switch (atomic_read(&pebi->current_log.state)) {
	case SSDFS_LOG_INITIALIZED:
	case SSDFS_LOG_COMMITTED:
	case SSDFS_LOG_CREATED:
		empty_pages = pages_per_peb - start_page;
		if (empty_pages < 0)
			has_partial_empty_log = false;
		else if (empty_pages < min_partial_log_pages)
			has_partial_empty_log = true;
		else
			has_partial_empty_log = false;
		break;

	default:
		has_partial_empty_log = false;
		break;
	};

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, peb_id %llu, start_page %u, "
		  "pages_per_peb %u, log_pages %u, "
		  "min_partial_log_pages %u, "
		  "has_partial_empty_log %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, start_page,
		  pages_per_peb, log_pages,
		  min_partial_log_pages,
		  has_partial_empty_log);
#endif /* CONFIG_SSDFS_DEBUG */

	return has_partial_empty_log;
}

static inline
bool has_commit_log_now_requested(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_request *req = NULL;
	bool commit_log_now = false;
	int err;

	if (is_ssdfs_requests_queue_empty(&pebc->update_rq))
		return false;

	err = ssdfs_requests_queue_remove_first(&pebc->update_rq, &req);
	if (err || !req)
		return false;

	commit_log_now = req->private.cmd == SSDFS_COMMIT_LOG_NOW;
	ssdfs_requests_queue_add_head(&pebc->update_rq, req);
	return commit_log_now;
}

static inline
bool has_start_migration_now_requested(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_request *req = NULL;
	bool start_migration_now = false;
	int err;

	if (is_ssdfs_requests_queue_empty(&pebc->update_rq))
		return false;

	err = ssdfs_requests_queue_remove_first(&pebc->update_rq, &req);
	if (err || !req)
		return false;

	start_migration_now = req->private.cmd == SSDFS_START_MIGRATION_NOW;
	ssdfs_requests_queue_add_head(&pebc->update_rq, req);
	return start_migration_now;
}

static inline
void ssdfs_peb_check_update_queue(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_request *req = NULL;
	int err;

	if (is_ssdfs_requests_queue_empty(&pebc->update_rq)) {
		SSDFS_DBG("update request queue is empty\n");
		return;
	}

	err = ssdfs_requests_queue_remove_first(&pebc->update_rq, &req);
	if (err || !req)
		return;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
	SSDFS_DBG("req->private.class %#x, req->private.cmd %#x\n",
		  req->private.class, req->private.cmd);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_requests_queue_add_head(&pebc->update_rq, req);
	return;
}

static inline
int __ssdfs_peb_finish_migration(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_segment_request *req;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_finish_migration(pebc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to finish migration: "
			  "seg %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
		return err;
	}

	/*
	 * The responsibility of finish migration code
	 * is to copy the state of valid blocks of
	 * source erase block into the buffers.
	 * So, this buffered state of valid blocks
	 * should be commited ASAP. It needs to send
	 * the COMMIT_LOG_NOW command to guarantee
	 * that valid blocks will be flushed on the volume.
	 */

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate request: "
			  "err %d\n", err);
		return err;
	}

	ssdfs_request_init(req);
	ssdfs_get_request(req);

	err = ssdfs_segment_commit_log_async2(si, SSDFS_REQ_ASYNC,
						pebc->peb_index, req);
	if (unlikely(err)) {
		SSDFS_ERR("commit log request failed: "
			  "err %d\n", err);
		ssdfs_put_request(req);
		ssdfs_request_free(req);
		return err;
	}

	return 0;
}

static inline
bool need_wait_next_create_data_request(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_segment_info *si = pebi->pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	bool has_pending_pages = false;
	bool has_reserved_pages = false;
	int state;
	bool is_current_seg = false;
	u64 reserved_pages = 0;
	u64 pending_pages = 0;
	bool need_wait = false;

	if (!is_ssdfs_peb_containing_user_data(pebi->pebc))
		goto finish_check;

	spin_lock(&si->pending_lock);
	pending_pages = si->pending_new_user_data_pages;
	has_pending_pages = si->pending_new_user_data_pages > 0;
	spin_unlock(&si->pending_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pending_pages %llu\n", pending_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	if (has_pending_pages) {
		need_wait = true;
		goto finish_check;
	}

	spin_lock(&fsi->volume_state_lock);
	reserved_pages = fsi->reserved_new_user_data_pages;
	has_reserved_pages = fsi->reserved_new_user_data_pages > 0;
	spin_unlock(&fsi->volume_state_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("reserved_pages %llu\n", reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	state = atomic_read(&si->obj_state);
	is_current_seg = (state == SSDFS_CURRENT_SEG_OBJECT);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("is_current_seg %#x, has_reserved_pages %#x\n",
		  is_current_seg, has_reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	need_wait = is_current_seg && has_reserved_pages;

finish_check:
	return need_wait;
}

static inline
bool need_wait_next_update_request(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_segment_info *si = pebi->pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	bool has_pending_pages = false;
	bool has_updated_pages = false;
	u64 updated_pages = 0;
	u64 pending_pages = 0;
	bool need_wait = false;

	if (!is_ssdfs_peb_containing_user_data(pebi->pebc))
		goto finish_check;

	spin_lock(&pebi->pebc->pending_lock);
	pending_pages = pebi->pebc->pending_updated_user_data_pages;
	has_pending_pages = pending_pages > 0;
	spin_unlock(&pebi->pebc->pending_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pending_pages %llu\n", pending_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	if (has_pending_pages) {
		need_wait = true;
		goto finish_check;
	}

	spin_lock(&fsi->volume_state_lock);
	updated_pages = fsi->updated_user_data_pages;
	has_updated_pages = fsi->updated_user_data_pages > 0;
	spin_unlock(&fsi->volume_state_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("updated_pages %llu\n", updated_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	need_wait = has_updated_pages;

finish_check:
	return need_wait;
}

static inline
bool no_more_updated_pages(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	bool has_updated_pages = false;

	if (!is_ssdfs_peb_containing_user_data(pebc))
		return true;

	spin_lock(&fsi->volume_state_lock);
	has_updated_pages = fsi->updated_user_data_pages > 0;
	spin_unlock(&fsi->volume_state_lock);

	return !has_updated_pages;
}

static inline
bool is_regular_fs_operations(struct ssdfs_peb_container *pebc)
{
	int state;

	state = atomic_read(&pebc->parent_si->fsi->global_fs_state);
	return state == SSDFS_REGULAR_FS_OPERATIONS;
}

/* Flush thread possible states */
enum {
	SSDFS_FLUSH_THREAD_ERROR,
	SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT,
	SSDFS_FLUSH_THREAD_RO_STATE,
	SSDFS_FLUSH_THREAD_NEED_CREATE_LOG,
	SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION,
	SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST,
	SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST,
	SSDFS_FLUSH_THREAD_PROCESS_CREATE_REQUEST,
	SSDFS_FLUSH_THREAD_PROCESS_UPDATE_REQUEST,
	SSDFS_FLUSH_THREAD_PROCESS_INVALIDATED_EXTENT,
	SSDFS_FLUSH_THREAD_CHECK_MIGRATION_NEED,
	SSDFS_FLUSH_THREAD_START_MIGRATION_NOW,
	SSDFS_FLUSH_THREAD_COMMIT_LOG,
	SSDFS_FLUSH_THREAD_DELEGATE_CREATE_ROLE,
};

#define FLUSH_THREAD_WAKE_CONDITION(pebc) \
	(kthread_should_stop() || have_flush_requests(pebc))
#define FLUSH_FAILED_THREAD_WAKE_CONDITION() \
	(kthread_should_stop())
#define FLUSH_THREAD_CUR_SEG_WAKE_CONDITION(pebc) \
	(kthread_should_stop() || have_flush_requests(pebc) || \
	 !is_regular_fs_operations(pebc) || \
	 atomic_read(&pebc->parent_si->obj_state) != SSDFS_CURRENT_SEG_OBJECT)
#define FLUSH_THREAD_UPDATE_WAKE_CONDITION(pebc) \
	(kthread_should_stop() || have_flush_requests(pebc) || \
	 no_more_updated_pages(pebc) || !is_regular_fs_operations(pebc))
#define FLUSH_THREAD_INVALIDATE_WAKE_CONDITION(pebc) \
	(kthread_should_stop() || have_flush_requests(pebc) || \
	 !is_regular_fs_operations(pebc))

static
int wait_next_create_request(struct ssdfs_peb_container *pebc,
			     int *thread_state)
{
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	struct ssdfs_peb_info *pebi;
	u64 reserved_pages = 0;
	bool has_reserved_pages = false;
	int state;
	bool is_current_seg = false;
	bool has_dirty_pages = false;
	bool need_commit_log = false;
	wait_queue_head_t *wq = NULL;
	struct ssdfs_segment_request *req;
	int err;

	if (!is_ssdfs_peb_containing_user_data(pebc)) {
		*thread_state = SSDFS_FLUSH_THREAD_ERROR;
		return -ERANGE;
	}

	spin_lock(&fsi->volume_state_lock);
	reserved_pages = fsi->reserved_new_user_data_pages;
	has_reserved_pages = reserved_pages > 0;
	spin_unlock(&fsi->volume_state_lock);

	state = atomic_read(&si->obj_state);
	is_current_seg = (state == SSDFS_CURRENT_SEG_OBJECT);

	if (is_current_seg && has_reserved_pages) {
		wq = &fsi->pending_wq;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("wait next data request: reserved_pages %llu\n",
			  reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */

		err = wait_event_killable_timeout(*wq,
				FLUSH_THREAD_CUR_SEG_WAKE_CONDITION(pebc),
				SSDFS_DEFAULT_TIMEOUT);
		if (err < 0)
			WARN_ON(err < 0);
		else
			err = 0;
	}

	state = atomic_read(&si->obj_state);
	is_current_seg = (state == SSDFS_CURRENT_SEG_OBJECT);

	pebi = ssdfs_get_current_peb_locked(pebc);
	if (!IS_ERR_OR_NULL(pebi)) {
		ssdfs_peb_current_log_lock(pebi);
		has_dirty_pages = ssdfs_peb_has_dirty_pages(pebi);
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);
	}

	if (!is_regular_fs_operations(pebc))
		need_commit_log = true;
	else if (!is_current_seg)
		need_commit_log = true;
	else if (!have_flush_requests(pebc) && has_dirty_pages)
		need_commit_log = true;

	if (need_commit_log) {
		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate request: "
				  "err %d\n", err);
			*thread_state = SSDFS_FLUSH_THREAD_ERROR;
			return err;
		}

		ssdfs_request_init(req);
		ssdfs_get_request(req);

		err = ssdfs_segment_commit_log_async2(si, SSDFS_REQ_ASYNC,
							pebc->peb_index, req);
		if (unlikely(err)) {
			SSDFS_ERR("commit log request failed: "
				  "err %d\n", err);
			ssdfs_put_request(req);
			ssdfs_request_free(req);
			*thread_state = SSDFS_FLUSH_THREAD_ERROR;
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("request commit log now: reserved_pages %llu\n",
			  reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("get next create request: reserved_pages %llu\n",
			  reserved_pages);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	*thread_state = SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
	return 0;
}

static
int wait_next_update_request(struct ssdfs_peb_container *pebc,
			     int *thread_state)
{
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_peb_info *pebi;
	struct ssdfs_fs_info *fsi = si->fsi;
	u64 updated_pages = 0;
	bool has_updated_pages = false;
	bool has_dirty_pages = false;
	bool need_commit_log = false;
	wait_queue_head_t *wq = NULL;
	struct ssdfs_segment_request *req;
	int err;

	if (!is_ssdfs_peb_containing_user_data(pebc)) {
		*thread_state = SSDFS_FLUSH_THREAD_ERROR;
		return -ERANGE;
	}

	spin_lock(&fsi->volume_state_lock);
	updated_pages = fsi->updated_user_data_pages;
	has_updated_pages = updated_pages > 0;
	spin_unlock(&fsi->volume_state_lock);

	if (has_updated_pages) {
		wq = &fsi->pending_wq;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("wait next update request: updated_pages %llu\n",
			  updated_pages);
#endif /* CONFIG_SSDFS_DEBUG */

		err = wait_event_killable_timeout(*wq,
				FLUSH_THREAD_UPDATE_WAKE_CONDITION(pebc),
				SSDFS_DEFAULT_TIMEOUT);
		if (err < 0)
			WARN_ON(err < 0);
		else
			err = 0;
	}

	pebi = ssdfs_get_current_peb_locked(pebc);
	if (!IS_ERR_OR_NULL(pebi)) {
		ssdfs_peb_current_log_lock(pebi);
		has_dirty_pages = ssdfs_peb_has_dirty_pages(pebi);
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);
	}

	if (!is_regular_fs_operations(pebc))
		need_commit_log = true;
	else if (no_more_updated_pages(pebc))
		need_commit_log = true;
	else if (!have_flush_requests(pebc) && has_dirty_pages)
		need_commit_log = true;

	if (need_commit_log) {
		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate request: "
				  "err %d\n", err);
			*thread_state = SSDFS_FLUSH_THREAD_ERROR;
			return err;
		}

		ssdfs_request_init(req);
		ssdfs_get_request(req);

		err = ssdfs_segment_commit_log_async2(si, SSDFS_REQ_ASYNC,
							pebc->peb_index, req);
		if (unlikely(err)) {
			SSDFS_ERR("commit log request failed: "
				  "err %d\n", err);
			ssdfs_put_request(req);
			ssdfs_request_free(req);
			*thread_state = SSDFS_FLUSH_THREAD_ERROR;
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("request commit log now: updated_pages %llu\n",
			  updated_pages);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("get next create request: updated_pages %llu\n",
			  updated_pages);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	*thread_state = SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
	return 0;
}

static
int wait_next_invalidate_request(struct ssdfs_peb_container *pebc,
				 int *thread_state)
{
	struct ssdfs_segment_info *si = pebc->parent_si;
	struct ssdfs_fs_info *fsi = si->fsi;
	int state;
	wait_queue_head_t *wq = NULL;
	struct ssdfs_segment_request *req;
	int err;

	if (!is_ssdfs_peb_containing_user_data(pebc)) {
		*thread_state = SSDFS_FLUSH_THREAD_ERROR;
		return -ERANGE;
	}

	if (!is_user_data_pages_invalidated(si)) {
		*thread_state = SSDFS_FLUSH_THREAD_ERROR;
		return -ERANGE;
	}

	state = atomic_read(&fsi->global_fs_state);
	switch(state) {
	case SSDFS_REGULAR_FS_OPERATIONS:
		wq = &fsi->pending_wq;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("wait next invalidate request\n");
#endif /* CONFIG_SSDFS_DEBUG */

		err = wait_event_killable_timeout(*wq,
				FLUSH_THREAD_INVALIDATE_WAKE_CONDITION(pebc),
				SSDFS_DEFAULT_TIMEOUT);
		if (err < 0)
			WARN_ON(err < 0);
		else
			err = 0;

		if (have_flush_requests(pebc))
			SSDFS_DBG("get next create request\n");
		else
			goto request_commit_log_now;
		break;

	case SSDFS_METADATA_GOING_FLUSHING:
request_commit_log_now:
		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate request: "
				  "err %d\n", err);
			*thread_state = SSDFS_FLUSH_THREAD_ERROR;
			return err;
		}

		ssdfs_request_init(req);
		ssdfs_get_request(req);

		err = ssdfs_segment_commit_log_async2(si, SSDFS_REQ_ASYNC,
							pebc->peb_index, req);
		if (unlikely(err)) {
			SSDFS_ERR("commit log request failed: "
				  "err %d\n", err);
			ssdfs_put_request(req);
			ssdfs_request_free(req);
			*thread_state = SSDFS_FLUSH_THREAD_ERROR;
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("request commit log now\n");
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	default:
		SSDFS_ERR("unexpected global FS state %#x\n",
			  state);
		*thread_state = SSDFS_FLUSH_THREAD_ERROR;
		return -ERANGE;
	}

	*thread_state = SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
	return 0;
}

static inline
int ssdfs_check_peb_init_state(u64 seg_id, u64 peb_id, int state,
				struct completion *init_end)
{
	int res;

	if (peb_id >= U64_MAX ||
	    state == SSDFS_PEB_OBJECT_INITIALIZED ||
	    !init_end) {
		/* do nothing */
		return 0;
	}

	res = wait_for_completion_timeout(init_end, SSDFS_DEFAULT_TIMEOUT);
	if (res == 0) {
		SSDFS_ERR("PEB init failed: "
			  "seg %llu, peb %llu\n",
			  seg_id, peb_id);
		return -ERANGE;
	}

	return 0;
}

static inline
int ssdfs_check_src_peb_init_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_peb_info *pebi = NULL;
	struct completion *init_end = NULL;
	u64 peb_id = U64_MAX;
	int state = SSDFS_PEB_OBJECT_UNKNOWN_STATE;

	down_read(&pebc->lock);
	pebi = pebc->src_peb;
	if (pebi) {
		init_end = &pebi->init_end;
		peb_id = pebi->peb_id;
		state = atomic_read(&pebi->state);
	}
	up_read(&pebc->lock);

	return ssdfs_check_peb_init_state(pebc->parent_si->seg_id,
					  peb_id, state, init_end);
}

static inline
int ssdfs_check_dst_peb_init_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_peb_info *pebi = NULL;
	struct completion *init_end = NULL;
	u64 peb_id = U64_MAX;
	int state = SSDFS_PEB_OBJECT_UNKNOWN_STATE;

	down_read(&pebc->lock);
	pebi = pebc->dst_peb;
	if (pebi) {
		init_end = &pebi->init_end;
		peb_id = pebi->peb_id;
		state = atomic_read(&pebi->state);
	}
	up_read(&pebc->lock);

	return ssdfs_check_peb_init_state(pebc->parent_si->seg_id,
					  peb_id, state, init_end);
}

static inline
int ssdfs_check_peb_container_init_state(struct ssdfs_peb_container *pebc)
{
	int err;

	err = ssdfs_check_src_peb_init_state(pebc);
	if (!err)
		err = ssdfs_check_dst_peb_init_state(pebc);

	return err;
}

/*
 * ssdfs_process_free_space_absent_state() - process absence of free space
 * @pebc: pointer on PEB container
 *
 * This function tries to process the absence of free space.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOSPC     - free space is absent.
 */
static
int ssdfs_process_free_space_absent_state(struct ssdfs_peb_container *pebc,
					  int err)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_mapping_table *maptbl;
	struct ssdfs_thread_state *thread_state = NULL;
	struct ssdfs_peb_info *pebi = NULL;
	int res = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state = &pebc->thread_state[SSDFS_PEB_FLUSH_THREAD];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(thread_state->state != SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	fsi = si->fsi;
	maptbl = fsi->maptbl;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("[FLUSH THREAD STATE] FREE SPACE ABSENT: "
		  "seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_peb_joined_into_create_requests_queue(pebc)) {
		res = ssdfs_peb_find_next_log_creation_thread(pebc);
		if (res == -ENOSPC) {
			res = 0;
			thread_state->err = -ENOSPC;
		} else if (unlikely(res)) {
			SSDFS_WARN("fail to delegate log creation role:"
				   " seg %llu, peb_index %u, err %d\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index, res);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = res;
			return err;
		}
	}

	/*
	 * Check that we've delegated log creation role.
	 * Otherwise, simply forget about creation queue.
	 */
	if (is_peb_joined_into_create_requests_queue(pebc)) {
		spin_lock(&pebc->crq_ptr_lock);
		ssdfs_requests_queue_remove_all(pebc->create_rq,
						-EROFS);
		spin_unlock(&pebc->crq_ptr_lock);

		ssdfs_peb_forget_create_requests_queue(pebc);
	}

	if (err == -ENOSPC && have_flush_requests(pebc)) {
		thread_state->err = -ENOSPC;

		if (is_peb_under_migration(pebc)) {
			res = __ssdfs_peb_finish_migration(pebc);
			if (unlikely(res))
				goto finish_process_free_space_absence;
		}

		res = ssdfs_peb_start_migration(pebc);
		if (unlikely(res))
			goto finish_process_free_space_absence;

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			res = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, res);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = res;
			goto finish_process_free_space_absence;
		}

		if (is_ssdfs_maptbl_going_to_be_destroyed(maptbl)) {
			SSDFS_WARN("seg %llu, peb_index %u\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index);
		}

		res = ssdfs_peb_container_change_state(pebc);
		ssdfs_unlock_current_peb(pebc);

finish_process_free_space_absence:
		if (unlikely(res)) {
			SSDFS_WARN("fail to start PEB's migration: "
				   "seg %llu, peb_index %u, err %d\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index, res);
			ssdfs_requests_queue_remove_all(&pebc->update_rq,
							-ENOSPC);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = res;
			return res;
		}

		thread_state->state = SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
		return 0;
	} else if (have_flush_requests(pebc)) {
		ssdfs_requests_queue_remove_all(&pebc->update_rq,
						-ENOSPC);
	}

	thread_state->state = SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT;
	thread_state->err = -ENOSPC;
	return -ENOSPC;
}

/*
 * ssdfs_process_read_only_state() - process READ-ONLY state
 * @pebc: pointer on PEB container
 *
 * This function tries to process the READ-ONLY state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EFAULT     - file system is inconsistent.
 */
static
int ssdfs_process_read_only_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_mapping_table *maptbl;
	struct ssdfs_thread_state *thread_state = NULL;
	struct ssdfs_peb_info *pebi = NULL;
	__le64 cur_segs[SSDFS_CUR_SEGS_COUNT];
	size_t size = sizeof(__le64) * SSDFS_CUR_SEGS_COUNT;
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state = &pebc->thread_state[SSDFS_PEB_FLUSH_THREAD];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(thread_state->state != SSDFS_FLUSH_THREAD_RO_STATE);

	SSDFS_DBG("[FLUSH THREAD STATE] READ-ONLY STATE: "
		  "seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	fsi = si->fsi;
	maptbl = fsi->maptbl;

	err = ssdfs_prepare_current_segment_ids(fsi, cur_segs, size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare current segments IDs: "
			  "err %d\n", err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
		return err;
	}

	pebi = ssdfs_get_current_peb_locked(pebc);
	if (IS_ERR_OR_NULL(pebi)) {
		err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
		SSDFS_ERR("fail to get PEB object: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
		return err;
	}

	if (!(fsi->sb->s_flags & SB_RDONLY)) {
		/*
		 * File system state was changed.
		 * Now file system has RW state.
		 */
		if (fsi->fs_state == SSDFS_ERROR_FS) {
			err = -ERANGE;
			ssdfs_peb_current_log_lock(pebi);
			if (ssdfs_peb_has_dirty_pages(pebi))
				ssdfs_peb_clear_current_log_pages(pebi);
			ssdfs_peb_current_log_unlock(pebi);
			ssdfs_unlock_current_peb(pebc);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return -EFAULT;
		} else {
			state = ssdfs_peb_get_current_log_state(pebc);
			if (state <= SSDFS_LOG_UNKNOWN ||
			    state >= SSDFS_LOG_STATE_MAX) {
				err = -ERANGE;
				SSDFS_WARN("invalid log state: "
					   "state %#x\n",
					   state);
				ssdfs_unlock_current_peb(pebc);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				thread_state->err = err;
				return err;
			}

			if (state != SSDFS_LOG_CREATED) {
				thread_state->state =
					SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
				ssdfs_unlock_current_peb(pebc);
				return 0;
			}

			thread_state->state =
				SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
			ssdfs_unlock_current_peb(pebc);
			return 0;
		}
	}

	ssdfs_peb_current_log_lock(pebi);
	if (ssdfs_peb_has_dirty_pages(pebi)) {
		if (fsi->fs_state == SSDFS_ERROR_FS) {
			err = -ERANGE;
			ssdfs_peb_clear_current_log_pages(pebi);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
		} else {
			mutex_lock(&pebc->migration_lock);
			err = ssdfs_peb_commit_log(pebi, cur_segs, size);
			mutex_unlock(&pebc->migration_lock);

			if (unlikely(err)) {
				SSDFS_CRIT("fail to commit log: "
					   "seg %llu, peb_index %u, "
					   "err %d\n",
					   pebc->parent_si->seg_id,
					   pebc->peb_index,
					   err);
				ssdfs_peb_clear_current_log_pages(pebi);
				ssdfs_peb_clear_cache_dirty_pages(pebi);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				thread_state->err = err;
			}
		}
	}
	ssdfs_peb_current_log_unlock(pebi);

	if (!err) {
		if (is_ssdfs_maptbl_going_to_be_destroyed(maptbl)) {
			SSDFS_WARN("seg %llu, peb_index %u\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index);
		}

		err = ssdfs_peb_container_change_state(pebc);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to change peb state: "
				  "err %d\n", err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
		}
	}

	ssdfs_unlock_current_peb(pebc);

	return err;
}

/*
 * ssdfs_process_need_create_log_state() - create log
 * @pebc: pointer on PEB container
 *
 * This function tries to process the state of log creation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - no necessity to create log.
 * %-EFAULT     - fail to create the log.
 */
static
int ssdfs_process_need_create_log_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_thread_state *thread_state = NULL;
	struct ssdfs_segment_info *si;
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_mapping_table *maptbl;
	struct ssdfs_peb_info *pebi = NULL;
	u64 peb_id = U64_MAX;
	bool is_peb_exhausted = false;
	bool peb_has_dirty_pages = false;
	bool need_create_log = true;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state = &pebc->thread_state[SSDFS_PEB_FLUSH_THREAD];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(thread_state->state != SSDFS_FLUSH_THREAD_NEED_CREATE_LOG);

	SSDFS_DBG("[FLUSH THREAD STATE] NEED CREATE LOG: "
		  "seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	fsi = si->fsi;
	maptbl = fsi->maptbl;

	if (fsi->sb->s_flags & SB_RDONLY) {
		thread_state->state = SSDFS_FLUSH_THREAD_RO_STATE;
		return 0;
	}

	if (kthread_should_stop()) {
		if (have_flush_requests(pebc)) {
			SSDFS_WARN("discovered unprocessed requests: "
				   "seg %llu, peb_index %u\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index);
		} else {
			thread_state->state =
			    SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
			return 0;
		}
	}

	if (!has_ssdfs_segment_blk_bmap_initialized(&si->blk_bmap,
						    pebc)) {
		err = ssdfs_segment_blk_bmap_wait_init_end(&si->blk_bmap,
							   pebc);
		if (unlikely(err)) {
			SSDFS_ERR("block bitmap init failed: "
				  "seg %llu, peb_index %u, err %d\n",
				  si->seg_id, pebc->peb_index, err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}
	}

	err = ssdfs_check_peb_container_init_state(pebc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to check init state: "
			  "seg %llu, peb_index %u, err %d\n",
			  si->seg_id, pebc->peb_index, err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
		return err;
	}

	pebi = ssdfs_get_current_peb_locked(pebc);
	if (IS_ERR_OR_NULL(pebi)) {
		err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
		SSDFS_ERR("fail to get PEB object: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb_index %u, migration_state %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  atomic_read(&pebc->migration_state));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_lock(pebi);
	peb_id = pebi->peb_id;
	peb_has_dirty_pages = ssdfs_peb_has_dirty_pages(pebi);
	need_create_log = peb_has_dirty_pages || have_flush_requests(pebc);
	is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, ssdfs_peb_has_dirty_pages %#x, "
		  "have_flush_requests %#x, need_create_log %#x, "
		  "is_peb_exhausted %#x\n",
		  peb_id, peb_has_dirty_pages,
		  have_flush_requests(pebc),
		  need_create_log, is_peb_exhausted);
#endif /* CONFIG_SSDFS_DEBUG */
	ssdfs_peb_current_log_unlock(pebi);

	if (!need_create_log) {
		ssdfs_unlock_current_peb(pebc);
		thread_state->state = SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
		return -ENOENT;
	}

	if (has_commit_log_now_requested(pebc) &&
	    is_create_requests_queue_empty(pebc)) {
		/*
		 * If no other commands in the queue
		 * then ignore the log creation now.
		 */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("Don't create log: "
			  "COMMIT_LOG_NOW command: "
			  "seg %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		ssdfs_unlock_current_peb(pebc);
		thread_state->state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
		return 0;
	}

	if (has_start_migration_now_requested(pebc)) {
		/*
		 * No necessity to create log
		 * for START_MIGRATION_NOW command.
		 */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("Don't create log: "
			  "START_MIGRATION_NOW command: "
			  "seg %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		ssdfs_unlock_current_peb(pebc);
		thread_state->state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
		return 0;
	}

	if (is_peb_exhausted) {
		ssdfs_unlock_current_peb(pebc);

		if (is_ssdfs_maptbl_under_flush(fsi)) {
			if (is_ssdfs_peb_containing_user_data(pebc)) {
				/*
				 * Continue logic for user data.
				 */
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("ignore mapping table's "
					  "flush for user data\n");
#endif /* CONFIG_SSDFS_DEBUG */
			} else if (have_flush_requests(pebc)) {
				SSDFS_ERR("maptbl is flushing: "
					  "unprocessed requests: "
					  "seg %llu, peb %llu\n",
					  pebc->parent_si->seg_id,
					  peb_id);

#ifdef CONFIG_SSDFS_DEBUG
				ssdfs_peb_check_update_queue(pebc);
#endif /* CONFIG_SSDFS_DEBUG */
				BUG();
			} else {
				SSDFS_ERR("maptbl is flushing\n");
				thread_state->state =
				    SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
				return -ENOENT;
			}
		}

		if (is_peb_under_migration(pebc)) {
			err = __ssdfs_peb_finish_migration(pebc);
			if (unlikely(err)) {
				SSDFS_ERR("fail to finish migration: "
					  "seg %llu, peb_index %u, "
					  "err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				thread_state->err = err;
				return err;
			}
		}

		if (!has_peb_migration_done(pebc)) {
			SSDFS_ERR("migration is not finished: "
				  "seg %llu, peb_index %u, "
				  "err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}

		err = ssdfs_peb_start_migration(pebc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to start migration: "
				  "seg %llu, peb_index %u, "
				  "err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}

		if (is_ssdfs_maptbl_going_to_be_destroyed(maptbl)) {
			SSDFS_WARN("seg %llu, peb_index %u\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index);
		}

		err = ssdfs_peb_container_change_state(pebc);
		if (unlikely(err)) {
			ssdfs_unlock_current_peb(pebc);
			SSDFS_ERR("fail to change peb state: "
				  "err %d\n", err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("is_peb_under_migration %#x, "
		  "has_peb_migration_done %#x\n",
		  is_peb_under_migration(pebc),
		  has_peb_migration_done(pebc));
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_peb_under_migration(pebc) &&
	    has_peb_migration_done(pebc)) {
		ssdfs_unlock_current_peb(pebc);

		err = __ssdfs_peb_finish_migration(pebc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to finish migration: "
				  "seg %llu, peb_index %u, "
				  "err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}

		if (is_ssdfs_maptbl_going_to_be_destroyed(maptbl)) {
			SSDFS_WARN("seg %llu, peb_index %u\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index);
		}

		err = ssdfs_peb_container_change_state(pebc);
		if (unlikely(err)) {
			ssdfs_unlock_current_peb(pebc);
			SSDFS_ERR("fail to change peb state: "
				  "err %d\n", err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}
	}

	mutex_lock(&pebc->migration_lock);
	err = ssdfs_peb_create_log(pebi);
	mutex_unlock(&pebc->migration_lock);
	ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (err == -EAGAIN) {
		if (kthread_should_stop()) {
			err = -EFAULT;
			goto fail_create_log;
		} else {
			/* do nothing */
			err = -ENOENT;
		}
	} else if (err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("PEB hasn't free space: "
			  "seg %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		thread_state->state = SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT;
		thread_state->err = err;
	} else if (unlikely(err)) {
fail_create_log:
		SSDFS_CRIT("fail to create log: "
			   "seg %llu, peb_index %u, err %d\n",
			   pebc->parent_si->seg_id,
			   pebc->peb_index, err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
	} else {
		thread_state->state = SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
	}

	return err;
}

/*
 * ssdfs_process_get_create_request_state() - get create request
 * @pebc: pointer on PEB container
 *
 * This function tries to get a create request from the queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - create and update queues are empty.
 */
static
int ssdfs_process_get_create_request_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_thread_state *thread_state = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state = &pebc->thread_state[SSDFS_PEB_FLUSH_THREAD];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(thread_state->state != SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST);

	SSDFS_DBG("[FLUSH THREAD STATE] GET CREATE REQUEST: "
		  "seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!have_flush_requests(pebc)) {
		thread_state->state = SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
		return -ENOENT;
	}

	if (!is_peb_joined_into_create_requests_queue(pebc) ||
	    is_create_requests_queue_empty(pebc)) {
		thread_state->state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
		return 0;
	}

	spin_lock(&pebc->crq_ptr_lock);
	err = ssdfs_requests_queue_remove_first(pebc->create_rq,
						&thread_state->req);
	spin_unlock(&pebc->crq_ptr_lock);

	if (err == -ENODATA) {
		SSDFS_DBG("empty create queue\n");
		thread_state->err = 0;
		thread_state->state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
		return 0;
	} else if (err == -ENOENT) {
		SSDFS_WARN("request queue contains NULL request\n");
		thread_state->err = 0;
		thread_state->state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
		return 0;
	} else if (unlikely(err < 0)) {
		SSDFS_CRIT("fail to get request from create queue: "
			   "err %d\n", err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("req->private.class %#x, req->private.cmd %#x\n",
		  thread_state->req->private.class,
		  thread_state->req->private.cmd);
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state->state = SSDFS_FLUSH_THREAD_PROCESS_CREATE_REQUEST;
	return 0;
}

/*
 * ssdfs_process_get_update_request_state() - get update request
 * @pebc: pointer on PEB container
 *
 * This function tries to get an update request from the queue.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-ENOENT     - create and update queues are empty.
 */
static
int ssdfs_process_get_update_request_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_thread_state *thread_state = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state = &pebc->thread_state[SSDFS_PEB_FLUSH_THREAD];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(thread_state->state != SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST);

	SSDFS_DBG("[FLUSH THREAD STATE] GET UPDATE REQUEST: "
		  "seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_ssdfs_requests_queue_empty(&pebc->update_rq)) {
		if (have_flush_requests(pebc)) {
			thread_state->state =
				SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
			return 0;
		} else {
			thread_state->state =
				SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
			return -ENOENT;
		}
	}

	err = ssdfs_requests_queue_remove_first(&pebc->update_rq,
						&thread_state->req);
	if (err == -ENODATA) {
		SSDFS_DBG("empty update queue\n");
		thread_state->err = 0;
		thread_state->state = SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
		return 0;
	} else if (err == -ENOENT) {
		SSDFS_WARN("request queue contains NULL request\n");
		thread_state->err = 0;
		thread_state->state = SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
		return 0;
	} else if (unlikely(err < 0)) {
		SSDFS_CRIT("fail to get request from update queue: "
			   "err %d\n", err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("req->private.class %#x, req->private.cmd %#x\n",
		  thread_state->req->private.class,
		  thread_state->req->private.cmd);
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state->state = SSDFS_FLUSH_THREAD_PROCESS_UPDATE_REQUEST;
	return 0;
}

/*
 * ssdfs_process_start_migration_now_state() - try to finish/start migration
 * @pebc: pointer on PEB container
 *
 * This function tries to finish old migration to be ready
 * for a new migration during metadata flushing.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_process_start_migration_now_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_thread_state *thread_state = NULL;
	wait_queue_head_t *wait_queue;
	struct ssdfs_segment_info *si;
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_mapping_table *maptbl;
	struct ssdfs_peb_info *pebi = NULL;
	bool is_peb_exhausted = false;
	bool is_peb_ready_to_exhaust = false;
	bool has_partial_empty_log = false;
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state = &pebc->thread_state[SSDFS_PEB_FLUSH_THREAD];
	wait_queue = &pebc->parent_si->wait_queue[SSDFS_PEB_FLUSH_THREAD];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(thread_state->state !=
			SSDFS_FLUSH_THREAD_START_MIGRATION_NOW);

	SSDFS_DBG("[FLUSH THREAD STATE] START MIGRATION REQUEST: "
		  "seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	fsi = si->fsi;
	maptbl = fsi->maptbl;

	pebi = ssdfs_get_current_peb_locked(pebc);
	if (IS_ERR_OR_NULL(pebi)) {
		err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
		SSDFS_ERR("fail to get PEB object: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
		return err;
	}

	ssdfs_peb_current_log_lock(pebi);
	is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
	is_peb_ready_to_exhaust = is_ssdfs_peb_ready_to_exhaust(fsi, pebi);
	has_partial_empty_log = ssdfs_peb_has_partial_empty_log(fsi, pebi);
	ssdfs_peb_current_log_unlock(pebi);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("is_peb_exhausted %#x, "
			  "is_peb_ready_to_exhaust %#x\n",
			  is_peb_exhausted, is_peb_ready_to_exhaust);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_peb_exhausted || is_peb_ready_to_exhaust) {
		ssdfs_unlock_current_peb(pebc);

		if (is_peb_under_migration(pebc)) {
			/*
			 * START_MIGRATION_NOW is requested during
			 * the flush operation of PEB mapping table,
			 * segment bitmap or any btree. It is the first
			 * step to initiate the migration.
			 * Then, fragments or nodes will be flushed.
			 * And final step is the COMMIT_LOG_NOW
			 * request. So, it doesn't need to request
			 * the COMMIT_LOG_NOW here.
			 */
			err = ssdfs_peb_finish_migration(pebc);
			if (unlikely(err)) {
				SSDFS_ERR("fail to finish migration: "
					  "seg %llu, peb_index %u, "
					  "err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				thread_state->err = err;
				goto process_migration_failure;
			}
		}

		if (!has_peb_migration_done(pebc)) {
			err = -ERANGE;
			SSDFS_ERR("migration is not finished: "
				  "seg %llu, peb_index %u, "
				  "err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			goto process_migration_failure;
		}

		err = ssdfs_peb_start_migration(pebc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to start migration: "
				  "seg %llu, peb_index %u, "
				  "err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			goto process_migration_failure;
		}

process_migration_failure:
		pebi = ssdfs_get_current_peb_locked(pebc);
		if (err) {
			if (IS_ERR_OR_NULL(pebi)) {
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				thread_state->err = err;
				return err;
			}

			ssdfs_peb_current_log_lock(pebi);
			ssdfs_finish_flush_request(pebc, thread_state->req,
						   wait_queue, err);
			ssdfs_peb_current_log_unlock(pebi);
			ssdfs_unlock_current_peb(pebc);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		} else if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}

		if (is_ssdfs_maptbl_going_to_be_destroyed(maptbl)) {
			SSDFS_WARN("seg %llu, peb_index %u\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index);
		}

		err = ssdfs_peb_container_change_state(pebc);
		if (unlikely(err)) {
			ssdfs_unlock_current_peb(pebc);
			SSDFS_ERR("fail to change peb state: "
				  "err %d\n", err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}
	} else if (has_partial_empty_log) {
			/*
			 * TODO: it will need to implement logic here
			 */
			SSDFS_WARN("log is partially empty\n");
	}

	ssdfs_peb_current_log_lock(pebi);
	ssdfs_finish_flush_request(pebc, thread_state->req, wait_queue, err);
	ssdfs_peb_current_log_unlock(pebi);
	ssdfs_unlock_current_peb(pebc);

	state = ssdfs_peb_get_current_log_state(pebc);
	if (state <= SSDFS_LOG_UNKNOWN ||
	    state >= SSDFS_LOG_STATE_MAX) {
		err = -ERANGE;
		SSDFS_WARN("invalid log state: "
			   "state %#x\n",
			   state);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
		return err;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (state != SSDFS_LOG_CREATED)
		thread_state->state = SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
	else
		thread_state->state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;

	return 0;
}

/*
 * ssdfs_process_commit_log_state() - commit current log
 * @pebc: pointer on PEB container
 *
 * This function tries to commit a current log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_process_commit_log_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_thread_state *thread_state = NULL;
	wait_queue_head_t *wait_queue = NULL;
	struct ssdfs_segment_info *si = NULL;
	struct ssdfs_fs_info *fsi = NULL;
	struct ssdfs_peb_mapping_table *maptbl = NULL;
	struct ssdfs_peb_info *pebi = NULL;
	__le64 cur_segs[SSDFS_CUR_SEGS_COUNT];
	size_t size = sizeof(__le64) * SSDFS_CUR_SEGS_COUNT;
	u64 peb_id;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state = &pebc->thread_state[SSDFS_PEB_FLUSH_THREAD];
	wait_queue = &pebc->parent_si->wait_queue[SSDFS_PEB_FLUSH_THREAD];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(thread_state->state != SSDFS_FLUSH_THREAD_COMMIT_LOG);

	SSDFS_DBG("[FLUSH THREAD STATE] COMMIT LOG: "
		  "seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	fsi = si->fsi;
	maptbl = fsi->maptbl;

	if (thread_state->postponed_req) {
		thread_state->req = thread_state->postponed_req;
		thread_state->postponed_req = NULL;
		thread_state->has_migration_check_requested = false;
	} else if (thread_state->req != NULL) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("req->private.class %#x, "
			  "req->private.cmd %#x\n",
			  thread_state->req->private.class,
			  thread_state->req->private.cmd);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (thread_state->req->private.class) {
		case SSDFS_PEB_COLLECT_GARBAGE_REQ:
			/* ignore this case */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("ignore request class %#x\n",
				  thread_state->req->private.class);
#endif /* CONFIG_SSDFS_DEBUG */
			goto make_log_commit;

		default:
			/* Try to stimulate the migration */
			break;
		}

		if (is_peb_under_migration(pebc) &&
		    !thread_state->has_migration_check_requested) {
			SSDFS_DBG("Try to stimulate the migration\n");
			thread_state->state =
				SSDFS_FLUSH_THREAD_CHECK_MIGRATION_NEED;
			thread_state->has_migration_check_requested = true;
			thread_state->postponed_req = thread_state->req;
			thread_state->req = NULL;
			return 0;
		} else {
			thread_state->has_migration_check_requested = false;
		}
	}

make_log_commit:
	err = ssdfs_prepare_current_segment_ids(fsi, cur_segs, size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare current segments IDs: "
			  "err %d\n",
			  err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
		return err;
	}

	pebi = ssdfs_get_current_peb_locked(pebc);
	if (IS_ERR_OR_NULL(pebi)) {
		err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
		SSDFS_ERR("fail to get PEB object: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
		return err;
	}

	ssdfs_peb_current_log_lock(pebi);
	mutex_lock(&pebc->migration_lock);
	peb_id = pebi->peb_id;
	err = ssdfs_peb_commit_log(pebi, cur_segs, size);
	mutex_unlock(&pebc->migration_lock);

	if (err) {
		ssdfs_peb_clear_current_log_pages(pebi);
		ssdfs_peb_clear_cache_dirty_pages(pebi);
		ssdfs_requests_queue_remove_all(&pebc->update_rq,
						-EROFS);

		ssdfs_fs_error(fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to commit log: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
	}
	ssdfs_peb_current_log_unlock(pebi);

	if (!err) {
		thread_state->has_extent_been_invalidated = false;

		if (is_ssdfs_maptbl_going_to_be_destroyed(maptbl)) {
			SSDFS_WARN("mapping table is near destroy: "
				   "seg %llu, peb_index %u, "
				   "peb_id %llu, peb_type %#x, "
				   "req->private.class %#x, "
				   "req->private.cmd %#x\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index,
				   peb_id,
				   pebc->peb_type,
				   thread_state->req->private.class,
				   thread_state->req->private.cmd);
		}

		ssdfs_forget_invalidated_user_data_pages(si);

		err = ssdfs_peb_container_change_state(pebc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to change peb state: "
				  "err %d\n", err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
		}
	}

	ssdfs_peb_current_log_lock(pebi);
	if (thread_state->skip_finish_flush_request)
		thread_state->skip_finish_flush_request = false;
	else {
		ssdfs_finish_flush_request(pebc, thread_state->req,
					   wait_queue, err);
	}
	ssdfs_peb_current_log_unlock(pebi);

	ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_DEBUG
	ssdfs_peb_check_update_queue(pebc);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (!err) {
		thread_state->state = SSDFS_FLUSH_THREAD_DELEGATE_CREATE_ROLE;
	} else {
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
		thread_state->err = err;
	}

	return err;
}

/*
 * ssdfs_process_check_migration_state() - stimulate migration
 * @pebc: pointer on PEB container
 *
 * This function tries to stimulate migration of valid blocks
 * from source PEB in migration chain.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_process_check_migration_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_thread_state *thread_state = NULL;
	struct ssdfs_peb_info *pebi = NULL;
	bool peb_has_dirty_pages = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state = &pebc->thread_state[SSDFS_PEB_FLUSH_THREAD];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(thread_state->state != SSDFS_FLUSH_THREAD_CHECK_MIGRATION_NEED);

	SSDFS_DBG("[FLUSH THREAD STATE] CHECK MIGRATION NEED REQUEST: "
		  "seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_peb_under_migration(pebc)) {
		u32 free_space1, free_space2;
		u16 free_data_pages;

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			thread_state->err = err;
			return err;
		}

		ssdfs_peb_current_log_lock(pebi);
		free_space1 = ssdfs_area_free_space(pebi,
					SSDFS_LOG_JOURNAL_AREA);
		free_space2 = ssdfs_area_free_space(pebi,
					SSDFS_LOG_DIFFS_AREA);
		free_data_pages = pebi->current_log.free_data_pages;
		peb_has_dirty_pages = ssdfs_peb_has_dirty_pages(pebi);
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free_space1 %u, free_space2 %u, "
			  "free_data_pages %u, peb_has_dirty_pages %#x\n",
			  free_space1, free_space2,
			  free_data_pages, peb_has_dirty_pages);
#endif /* CONFIG_SSDFS_DEBUG */

		if (!peb_has_dirty_pages) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("PEB has no dirty pages: "
				  "seg_id %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_check_migration_need;
		}

		if (free_data_pages == 0) {
			/*
			 * No free space for shadow migration.
			 */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("No free space for shadow migration: "
				  "seg_id %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_check_migration_need;
		}

		if (free_space1 < (PAGE_SIZE / 2) &&
		    free_space2 < (PAGE_SIZE / 2)) {
			/*
			 * No free space for shadow migration.
			 */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("No free space for shadow migration: "
				  "seg_id %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_check_migration_need;
		}

		if (!has_ssdfs_source_peb_valid_blocks(pebc)) {
			/*
			 * No used blocks in the source PEB.
			 */
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("No used blocks in the source PEB: "
				  "seg_id %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_check_migration_need;
		}

		mutex_lock(&pebc->migration_lock);

		if (free_space1 >= (PAGE_SIZE / 2)) {
			err = ssdfs_peb_prepare_range_migration(pebc, 1,
						SSDFS_BLK_PRE_ALLOCATED);
			if (err == -ENODATA) {
				err = 0;
				SSDFS_DBG("unable to migrate: "
					  "no pre-allocated blocks\n");
			} else
				goto stimulate_migration_done;
		}

		if (free_space2 >= (PAGE_SIZE / 2)) {
			err = ssdfs_peb_prepare_range_migration(pebc, 1,
						SSDFS_BLK_VALID);
			if (err == -ENODATA) {
				SSDFS_DBG("unable to migrate: "
					  "no valid blocks\n");
			}
		}

stimulate_migration_done:
		mutex_unlock(&pebc->migration_lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("finished: err %d\n", err);
#else
		SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		if (err == -ENODATA) {
			err = 0;
			goto finish_check_migration_need;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to prepare range migration: "
				  "err %d\n", err);
			thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			return err;
		}

		thread_state->state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
	} else {
finish_check_migration_need:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("no migration necessary: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
	}

	return err;
}

/*
 * ssdfs_process_delegate_create_role_state() - process delegate create role
 * @pebc: pointer on PEB container
 *
 * This function tries to delegate a create role to the next PEB
 * of segment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_process_delegate_create_role_state(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_thread_state *thread_state = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	thread_state = &pebc->thread_state[SSDFS_PEB_FLUSH_THREAD];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(thread_state->state != SSDFS_FLUSH_THREAD_DELEGATE_CREATE_ROLE);

	SSDFS_DBG("[FLUSH THREAD STATE] DELEGATE CREATE ROLE: "
		  "seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_peb_joined_into_create_requests_queue(pebc)) {
		if (thread_state->err) {
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			return thread_state->err;
		} else {
			thread_state->state =
				SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
			return 0;
		}
	}

	err = ssdfs_peb_find_next_log_creation_thread(pebc);
	if (unlikely(err)) {
		SSDFS_WARN("fail to delegate log creation role: "
			   "seg %llu, peb_index %u, err %d\n",
			   pebc->parent_si->seg_id,
			   pebc->peb_index, err);
		thread_state->err = err;
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
	} else {
		thread_state->state =
			SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
	}

	return err;
}

/*
 * ssdfs_peb_flush_thread_func() - main fuction of flush thread
 * @data: pointer on data object
 *
 * This function is main fuction of flush thread.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_peb_flush_thread_func(void *data)
{
	struct ssdfs_peb_container *pebc = data;
	struct ssdfs_segment_info *si;
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_mapping_table *maptbl;
	wait_queue_head_t *wait_queue;
	struct ssdfs_thread_state *thread_state = NULL;
	struct ssdfs_peb_info *pebi = NULL;
	int state;
	__le64 cur_segs[SSDFS_CUR_SEGS_COUNT];
	size_t size = sizeof(__le64) * SSDFS_CUR_SEGS_COUNT;
	bool is_user_data = false;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		BUG();
	}

	SSDFS_DBG("flush thread: seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;
	fsi = si->fsi;
	maptbl = fsi->maptbl;

	wait_queue = &pebc->parent_si->wait_queue[SSDFS_PEB_FLUSH_THREAD];
	thread_state = &pebc->thread_state[SSDFS_PEB_FLUSH_THREAD];
	thread_state->state = SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
	thread_state->err = 0;

repeat:
	if (thread_state->err)
		thread_state->state = SSDFS_FLUSH_THREAD_ERROR;

	if (thread_state->state != SSDFS_FLUSH_THREAD_ERROR &&
	    thread_state->state != SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT) {
		if (fsi->sb->s_flags & SB_RDONLY)
			thread_state->state = SSDFS_FLUSH_THREAD_RO_STATE;
	}

next_partial_step:
	switch (thread_state->state) {
	case SSDFS_FLUSH_THREAD_ERROR:
		BUG_ON(thread_state->err == 0);
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("[FLUSH THREAD STATE] ERROR\n");
		SSDFS_DBG("thread after-error state: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id, pebc->peb_index,
			  thread_state->err);
#endif /* CONFIG_SSDFS_DEBUG */

		if (have_flush_requests(pebc)) {
			ssdfs_requests_queue_remove_all(&pebc->update_rq,
							-EROFS);
		}

		if (is_peb_joined_into_create_requests_queue(pebc))
			ssdfs_peb_find_next_log_creation_thread(pebc);

		/*
		 * Check that we've delegated log creation role.
		 * Otherwise, simply forget about creation queue.
		 */
		if (is_peb_joined_into_create_requests_queue(pebc)) {
			spin_lock(&pebc->crq_ptr_lock);
			ssdfs_requests_queue_remove_all(pebc->create_rq,
							-EROFS);
			spin_unlock(&pebc->crq_ptr_lock);

			ssdfs_peb_forget_create_requests_queue(pebc);
		}

check_necessity_to_stop_thread:
		if (kthread_should_stop()) {
			struct completion *ptr;

stop_flush_thread:
			ptr = &pebc->thread[SSDFS_PEB_FLUSH_THREAD].full_stop;
			complete_all(ptr);
			return thread_state->err;
		} else
			goto sleep_failed_flush_thread;
		break;

	case SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("[FLUSH THREAD STATE] FREE SPACE ABSENT: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_process_free_space_absent_state(pebc, err);
		if (err == -ENOSPC) {
			goto check_necessity_to_stop_thread;
		} else if (err) {
			goto repeat;
		} else {
			goto next_partial_step;
		}
		break;

	case SSDFS_FLUSH_THREAD_RO_STATE:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("[FLUSH THREAD STATE] READ-ONLY STATE: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_process_read_only_state(pebc);
		if (err == -EFAULT) {
			goto check_necessity_to_stop_thread;
		} else if (err) {
			goto repeat;
		} else {
			goto next_partial_step;
		}
		break;

	case SSDFS_FLUSH_THREAD_NEED_CREATE_LOG:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("[FLUSH THREAD STATE] NEED CREATE LOG: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#else
		SSDFS_DBG("[FLUSH THREAD STATE] NEED CREATE LOG: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		err = ssdfs_process_need_create_log_state(pebc);
		if (err == -EFAULT) {
			goto repeat;
		} else if (err == -ENOENT) {
			/* no necessity to create log */
			err = 0;
			goto sleep_flush_thread;
		} else if (err) {
			goto repeat;
		} else {
			goto next_partial_step;
		}
		break;

	case SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("[FLUSH THREAD STATE] CHECK NECESSITY TO STOP: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#else
		SSDFS_DBG("[FLUSH THREAD STATE] CHECK NECESSITY TO STOP: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		if (kthread_should_stop()) {
			if (have_flush_requests(pebc)) {
				state = ssdfs_peb_get_current_log_state(pebc);
				if (state <= SSDFS_LOG_UNKNOWN ||
				    state >= SSDFS_LOG_STATE_MAX) {
					thread_state->err = -ERANGE;
					SSDFS_WARN("invalid log state: "
						   "state %#x\n",
						   state);
					goto repeat;
				}

				if (state != SSDFS_LOG_CREATED) {
					thread_state->state =
					    SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
					goto next_partial_step;
				} else
					goto process_flush_requests;
			}

			thread_state->err =
				ssdfs_prepare_current_segment_ids(fsi,
								cur_segs,
								size);
			if (unlikely(thread_state->err)) {
				SSDFS_ERR("fail to prepare current seg IDs: "
					  "err %d\n",
					  thread_state->err);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			pebi = ssdfs_get_current_peb_locked(pebc);
			if (IS_ERR_OR_NULL(pebi)) {
				thread_state->err =
					pebi == NULL ? -ERANGE : PTR_ERR(pebi);
				SSDFS_ERR("fail to get PEB object: "
					  "seg %llu, peb_index %u, err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index,
					  thread_state->err);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			ssdfs_peb_current_log_lock(pebi);
			mutex_lock(&pebc->migration_lock);
			thread_state->err =
				ssdfs_peb_commit_log_on_thread_stop(pebi,
								  cur_segs,
								  size);
			mutex_unlock(&pebc->migration_lock);
			ssdfs_peb_current_log_unlock(pebi);

			if (unlikely(thread_state->err)) {
				SSDFS_CRIT("fail to commit log: "
					   "seg %llu, peb_index %u, err %d\n",
					   pebc->parent_si->seg_id,
					   pebc->peb_index,
					   thread_state->err);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			}

			ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
			SSDFS_ERR("finished: err %d\n", thread_state->err);
#else
			SSDFS_DBG("finished: err %d\n", thread_state->err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

			goto stop_flush_thread;
		} else {
process_flush_requests:
			state = ssdfs_peb_get_current_log_state(pebc);
			if (state <= SSDFS_LOG_UNKNOWN ||
			    state >= SSDFS_LOG_STATE_MAX) {
				thread_state->err = -ERANGE;
				SSDFS_WARN("invalid log state: "
					   "state %#x\n",
					   state);
				goto repeat;
			}

			if (state != SSDFS_LOG_CREATED) {
				thread_state->state =
					SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
			} else {
				thread_state->state =
					SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
			}
			goto repeat;
		}
		break;

	case SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("[FLUSH THREAD STATE] GET CREATE REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#else
		SSDFS_DBG("[FLUSH THREAD STATE] GET CREATE REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		err = ssdfs_process_get_create_request_state(pebc);
		if (err == -ENOENT) {
			err = 0;
			if (kthread_should_stop())
				goto repeat;
			else
				goto sleep_flush_thread;
		} else if (unlikely(err))
			goto repeat;
		else
			goto next_partial_step;
		break;

	case SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("[FLUSH THREAD STATE] GET UPDATE REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#else
		SSDFS_DBG("[FLUSH THREAD STATE] GET UPDATE REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		err = ssdfs_process_get_update_request_state(pebc);
		if (err == -ENOENT) {
			err = 0;
			if (kthread_should_stop())
				goto repeat;
			else
				goto sleep_flush_thread;
		} else if (unlikely(err))
			goto repeat;
		else
			goto next_partial_step;
		break;

	case SSDFS_FLUSH_THREAD_PROCESS_CREATE_REQUEST:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("[FLUSH THREAD STATE] PROCESS CREATE REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
		SSDFS_ERR("req->private.class %#x, req->private.cmd %#x\n",
			  thread_state->req->private.class,
			  thread_state->req->private.cmd);
#else
		SSDFS_DBG("[FLUSH THREAD STATE] PROCESS CREATE REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
		SSDFS_DBG("req->private.class %#x, req->private.cmd %#x\n",
			  thread_state->req->private.class,
			  thread_state->req->private.cmd);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		is_user_data = is_ssdfs_peb_containing_user_data(pebc);

		if (!has_ssdfs_segment_blk_bmap_initialized(&si->blk_bmap,
							    pebc)) {
			thread_state->err =
			    ssdfs_segment_blk_bmap_wait_init_end(&si->blk_bmap,
								   pebc);
			if (unlikely(thread_state->err)) {
				SSDFS_ERR("block bitmap init failed: "
					  "seg %llu, peb_index %u, err %d\n",
					  si->seg_id, pebc->peb_index,
					  thread_state->err);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}
		}

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			thread_state->err =
				pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  thread_state->err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		ssdfs_peb_current_log_lock(pebi);

		mutex_lock(&pebc->migration_lock);
		thread_state->err = ssdfs_process_create_request(pebi,
							thread_state->req);
		mutex_unlock(&pebc->migration_lock);

		if (thread_state->err == -ENOSPC) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to process create request: "
				  "seg %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
			ssdfs_finish_flush_request(pebc,
						   thread_state->req,
						   wait_queue,
						   thread_state->err);
			thread_state->state =
				SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT;
			goto finish_create_request_processing;
		} else if (thread_state->err == -EAGAIN) {
			thread_state->err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to process create request : "
				  "seg %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
			spin_lock(&pebc->crq_ptr_lock);
			ssdfs_requests_queue_add_head(pebc->create_rq,
						      thread_state->req);
			spin_unlock(&pebc->crq_ptr_lock);
			thread_state->req = NULL;
			thread_state->skip_finish_flush_request = true;
			thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_create_request_processing;
		} else if (unlikely(thread_state->err)) {
			SSDFS_ERR("fail to process create request: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  thread_state->err);
			ssdfs_finish_flush_request(pebc,
						   thread_state->req,
						   wait_queue,
						   thread_state->err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			goto finish_create_request_processing;
		}

		if (thread_state->req->private.type == SSDFS_REQ_SYNC) {
			thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_create_request_processing;
		}

		/* SSDFS_REQ_ASYNC */
		if (is_full_log_ready(pebi)) {
			thread_state->skip_finish_flush_request = false;
			thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_create_request_processing;
		} else if (should_partial_log_being_commited(pebi)) {
			thread_state->skip_finish_flush_request = false;
			thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_create_request_processing;
		} else if (!have_flush_requests(pebc)) {
			if (need_wait_next_create_data_request(pebi)) {
				ssdfs_account_user_data_flush_request(si);
				ssdfs_finish_flush_request(pebc,
							   thread_state->req,
							   wait_queue,
							   thread_state->err);
				ssdfs_peb_current_log_unlock(pebi);
				ssdfs_unlock_current_peb(pebc);

				thread_state->err =
					wait_next_create_request(pebc,
							&thread_state->state);
				ssdfs_forget_user_data_flush_request(si);
				thread_state->skip_finish_flush_request = false;
				goto finish_wait_next_create_request;
			} else if (is_user_data) {
				thread_state->skip_finish_flush_request = false;
				thread_state->state =
					SSDFS_FLUSH_THREAD_COMMIT_LOG;
				goto finish_create_request_processing;
			} else {
				goto get_next_update_request;
			}
		} else {
get_next_update_request:
			ssdfs_finish_flush_request(pebc,
						   thread_state->req,
						   wait_queue,
						   thread_state->err);
			thread_state->state =
				SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
		}

finish_create_request_processing:
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("finished\n");
#else
		SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

finish_wait_next_create_request:
		if (thread_state->state == SSDFS_FLUSH_THREAD_COMMIT_LOG)
			goto next_partial_step;
		else
			goto repeat;
		break;

	case SSDFS_FLUSH_THREAD_PROCESS_UPDATE_REQUEST:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("[FLUSH THREAD STATE] PROCESS UPDATE REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
		SSDFS_ERR("req->private.class %#x, req->private.cmd %#x\n",
			  thread_state->req->private.class,
			  thread_state->req->private.cmd);
#else
		SSDFS_DBG("[FLUSH THREAD STATE] PROCESS UPDATE REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
		SSDFS_DBG("req->private.class %#x, req->private.cmd %#x\n",
			  thread_state->req->private.class,
			  thread_state->req->private.cmd);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		is_user_data = is_ssdfs_peb_containing_user_data(pebc);

		if (!has_ssdfs_segment_blk_bmap_initialized(&si->blk_bmap,
							    pebc)) {
			thread_state->err =
			    ssdfs_segment_blk_bmap_wait_init_end(&si->blk_bmap,
								   pebc);
			if (unlikely(thread_state->err)) {
				SSDFS_ERR("block bitmap init failed: "
					  "seg %llu, peb_index %u, err %d\n",
					  si->seg_id, pebc->peb_index,
					  thread_state->err);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}
		}

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			thread_state->err =
				pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  thread_state->err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		ssdfs_peb_current_log_lock(pebi);

		mutex_lock(&pebc->migration_lock);
		thread_state->err =
			ssdfs_process_update_request(pebi,
						     thread_state->req);
		mutex_unlock(&pebc->migration_lock);

		if (thread_state->err == -EAGAIN) {
			thread_state->err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to process update request : "
				  "seg %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
			ssdfs_requests_queue_add_head(&pebc->update_rq,
						      thread_state->req);
			thread_state->req = NULL;
			thread_state->skip_finish_flush_request = true;
			thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_update_request_processing;
		} else if (thread_state->err == -ENOENT &&
			   thread_state->req->private.cmd ==
						SSDFS_BTREE_NODE_DIFF) {
			thread_state->err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to process update request : "
				  "seg %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
			thread_state->req = NULL;
			thread_state->state =
				SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
			goto finish_update_request_processing;
		} else if (unlikely(thread_state->err)) {
			SSDFS_ERR("fail to process update request: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  thread_state->err);
			ssdfs_finish_flush_request(pebc,
						   thread_state->req,
						   wait_queue,
						   thread_state->err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			goto finish_update_request_processing;
		}

		switch (thread_state->req->private.cmd) {
		case SSDFS_EXTENT_WAS_INVALIDATED:
			/* log has to be committed */
			thread_state->has_extent_been_invalidated = true;
			thread_state->state =
				SSDFS_FLUSH_THREAD_PROCESS_INVALIDATED_EXTENT;
			goto finish_update_request_processing;

		case SSDFS_START_MIGRATION_NOW:
			thread_state->state =
				SSDFS_FLUSH_THREAD_START_MIGRATION_NOW;
			goto finish_update_request_processing;

		case SSDFS_COMMIT_LOG_NOW:
			if (has_commit_log_now_requested(pebc)) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("Ignore current COMMIT_LOG_NOW: "
					  "seg %llu, peb_index %u\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
				ssdfs_finish_flush_request(pebc,
							   thread_state->req,
							   wait_queue,
							   thread_state->err);
				thread_state->state =
					SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
			} else if (have_flush_requests(pebc)) {
				ssdfs_requests_queue_add_tail(&pebc->update_rq,
							      thread_state->req);
				thread_state->req = NULL;

				state = atomic_read(&pebi->current_log.state);
				if (state == SSDFS_LOG_COMMITTED) {
					thread_state->state =
					  SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
				} else {
					thread_state->state =
					  SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
				}
			} else if (thread_state->has_extent_been_invalidated) {
				if (is_user_data_pages_invalidated(si) &&
				    is_regular_fs_operations(pebc)) {
					ssdfs_account_user_data_flush_request(si);
					ssdfs_finish_flush_request(pebc,
							   thread_state->req,
							   wait_queue,
							   thread_state->err);
					ssdfs_peb_current_log_unlock(pebi);
					ssdfs_unlock_current_peb(pebc);

					thread_state->err =
					    wait_next_invalidate_request(pebc,
							&thread_state->state);
					ssdfs_forget_user_data_flush_request(si);
					thread_state->skip_finish_flush_request =
									    false;
					goto finish_wait_next_data_request;
				} else {
					thread_state->state =
						SSDFS_FLUSH_THREAD_COMMIT_LOG;
				}
			} else if (ssdfs_peb_has_dirty_pages(pebi)) {
				if (need_wait_next_create_data_request(pebi)) {
					ssdfs_account_user_data_flush_request(si);
					ssdfs_finish_flush_request(pebc,
							   thread_state->req,
							   wait_queue,
							   thread_state->err);
					ssdfs_peb_current_log_unlock(pebi);
					ssdfs_unlock_current_peb(pebc);

					thread_state->err =
					    wait_next_create_request(pebc,
							&thread_state->state);
					ssdfs_forget_user_data_flush_request(si);
					thread_state->skip_finish_flush_request =
									    false;
					goto finish_wait_next_data_request;
				} else if (need_wait_next_update_request(pebi)) {
					ssdfs_account_user_data_flush_request(si);
					ssdfs_finish_flush_request(pebc,
							   thread_state->req,
							   wait_queue,
							   thread_state->err);
					ssdfs_peb_current_log_unlock(pebi);
					ssdfs_unlock_current_peb(pebc);

					thread_state->err =
						wait_next_update_request(pebc,
							&thread_state->state);
					ssdfs_forget_user_data_flush_request(si);
					thread_state->skip_finish_flush_request =
									    false;
					goto finish_wait_next_data_request;

				} else {
					thread_state->state =
						SSDFS_FLUSH_THREAD_COMMIT_LOG;
				}
			} else {
				ssdfs_finish_flush_request(pebc,
							   thread_state->req,
							   wait_queue,
							   thread_state->err);

				state = atomic_read(&pebi->current_log.state);
				if (state == SSDFS_LOG_COMMITTED) {
					thread_state->state =
					  SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
				} else {
					thread_state->state =
					  SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
				}
			}
			goto finish_update_request_processing;

		default:
			/* do nothing */
			break;
		}

		if (thread_state->req->private.type == SSDFS_REQ_SYNC) {
			thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_update_request_processing;
		} else if (thread_state->has_migration_check_requested) {
			ssdfs_finish_flush_request(pebc,
						   thread_state->req,
						   wait_queue,
						   thread_state->err);
			thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_update_request_processing;
		} else if (is_full_log_ready(pebi)) {
			thread_state->skip_finish_flush_request = false;
			thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_update_request_processing;
		} else if (should_partial_log_being_commited(pebi)) {
			thread_state->skip_finish_flush_request = false;
			thread_state->state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_update_request_processing;
		} else if (!have_flush_requests(pebc)) {
			if (need_wait_next_update_request(pebi)) {
				ssdfs_account_user_data_flush_request(si);
				ssdfs_finish_flush_request(pebc,
							   thread_state->req,
							   wait_queue,
							   thread_state->err);
				ssdfs_peb_current_log_unlock(pebi);
				ssdfs_unlock_current_peb(pebc);

				thread_state->err =
				    wait_next_update_request(pebc,
							&thread_state->state);
				ssdfs_forget_user_data_flush_request(si);
				thread_state->skip_finish_flush_request = false;
				goto finish_wait_next_data_request;
			} else if (is_user_data &&
				   ssdfs_peb_has_dirty_pages(pebi)) {
				thread_state->skip_finish_flush_request = false;
				thread_state->state =
					SSDFS_FLUSH_THREAD_COMMIT_LOG;
				goto finish_update_request_processing;
			} else
				goto get_next_create_request;
		} else {
get_next_create_request:
			ssdfs_finish_flush_request(pebc,
						   thread_state->req,
						   wait_queue,
						   thread_state->err);
			thread_state->state =
				SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
			goto finish_update_request_processing;
		}

finish_update_request_processing:
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("finished\n");
#else
		SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

finish_wait_next_data_request:
		if (thread_state->state == SSDFS_FLUSH_THREAD_COMMIT_LOG ||
		    thread_state->state ==
				SSDFS_FLUSH_THREAD_START_MIGRATION_NOW) {
			goto next_partial_step;
		} else if (thread_state->state ==
				SSDFS_FLUSH_THREAD_NEED_CREATE_LOG)
			goto sleep_flush_thread;
		else
			goto repeat;
		break;

	case SSDFS_FLUSH_THREAD_PROCESS_INVALIDATED_EXTENT:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("[FLUSH THREAD STATE] PROCESS INVALIDATED EXTENT: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#else
		SSDFS_DBG("[FLUSH THREAD STATE] PROCESS INVALIDATED EXTENT: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			thread_state->err =
				pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  thread_state->err);
			thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		if (is_peb_under_migration(pebc) &&
		    has_peb_migration_done(pebc)) {
			ssdfs_unlock_current_peb(pebc);

			thread_state->err = __ssdfs_peb_finish_migration(pebc);
			if (unlikely(thread_state->err)) {
				SSDFS_ERR("fail to finish migration: "
					  "seg %llu, peb_index %u, "
					  "err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index,
					  thread_state->err);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			pebi = ssdfs_get_current_peb_locked(pebc);
			if (IS_ERR_OR_NULL(pebi)) {
				thread_state->err =
					pebi == NULL ? -ERANGE : PTR_ERR(pebi);
				SSDFS_ERR("fail to get PEB object: "
					  "seg %llu, peb_index %u, err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index,
					  thread_state->err);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			if (is_ssdfs_maptbl_going_to_be_destroyed(maptbl)) {
				SSDFS_WARN("seg %llu, peb_index %u\n",
					   pebc->parent_si->seg_id,
					   pebc->peb_index);
			}

			thread_state->err =
				ssdfs_peb_container_change_state(pebc);
			if (unlikely(thread_state->err)) {
				ssdfs_unlock_current_peb(pebc);
				SSDFS_ERR("fail to change peb state: "
					  "err %d\n",
					  thread_state->err);
				thread_state->state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}
		}

		ssdfs_peb_current_log_lock(pebi);
		ssdfs_finish_flush_request(pebc,
					   thread_state->req,
					   wait_queue,
					   thread_state->err);
		ssdfs_peb_current_log_unlock(pebi);

		ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("finished\n");
#else
		SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		thread_state->state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
		goto next_partial_step;
		break;

	case SSDFS_FLUSH_THREAD_START_MIGRATION_NOW:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("[FLUSH THREAD STATE] START MIGRATION REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#else
		SSDFS_DBG("[FLUSH THREAD STATE] START MIGRATION REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		err = ssdfs_process_start_migration_now_state(pebc);
		if (err) {
			goto repeat;
		} else {
			goto next_partial_step;
		}
		break;

	case SSDFS_FLUSH_THREAD_COMMIT_LOG:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("[FLUSH THREAD STATE] COMMIT LOG: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#else
		SSDFS_DBG("[FLUSH THREAD STATE] COMMIT LOG: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		err = ssdfs_process_commit_log_state(pebc);
		if (err) {
			goto repeat;
		} else {
			goto next_partial_step;
		}
		break;

	case SSDFS_FLUSH_THREAD_CHECK_MIGRATION_NEED:
#ifdef CONFIG_SSDFS_TRACK_API_CALL
		SSDFS_ERR("[FLUSH THREAD STATE] CHECK MIGRATION NEED REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#else
		SSDFS_DBG("[FLUSH THREAD STATE] CHECK MIGRATION NEED REQUEST: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

		err = ssdfs_process_check_migration_state(pebc);
		if (err) {
			goto repeat;
		} else {
			goto next_partial_step;
		}
		break;

	case SSDFS_FLUSH_THREAD_DELEGATE_CREATE_ROLE:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("[FLUSH THREAD STATE] DELEGATE CREATE ROLE: "
			  "seg_id %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_process_delegate_create_role_state(pebc);
		if (err)
			goto repeat;
		else
			goto sleep_flush_thread;
		break;

	default:
		BUG();
	};

/*
 * Every thread should be added into one wait queue only.
 * Segment object should have several queues:
 * (1) read threads waiting queue;
 * (2) flush threads waiting queue;
 * (3) GC threads waiting queue.
 * The wakeup operation should be the operation under group
 * of threads of the same type. Thread function should check
 * several condition in the case of wakeup.
 */

sleep_flush_thread:
#ifdef CONFIG_SSDFS_DEBUG
	if (is_ssdfs_peb_containing_user_data(pebc)) {
		pebi = ssdfs_get_current_peb_locked(pebc);
		if (!IS_ERR_OR_NULL(pebi)) {
			ssdfs_peb_current_log_lock(pebi);

			if (ssdfs_peb_has_dirty_pages(pebi)) {
				u64 reserved_new_user_data_pages;
				u64 updated_user_data_pages;
				u64 flushing_user_data_requests;

				spin_lock(&fsi->volume_state_lock);
				reserved_new_user_data_pages =
					fsi->reserved_new_user_data_pages;
				updated_user_data_pages =
					fsi->updated_user_data_pages;
				flushing_user_data_requests =
					fsi->flushing_user_data_requests;
				spin_unlock(&fsi->volume_state_lock);

				SSDFS_WARN("seg %llu, peb %llu, peb_type %#x, "
					  "global_fs_state %#x, "
					  "reserved_new_user_data_pages %llu, "
					  "updated_user_data_pages %llu, "
					  "flushing_user_data_requests %llu\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id, pebi->pebc->peb_type,
					  atomic_read(&fsi->global_fs_state),
					  reserved_new_user_data_pages,
					  updated_user_data_pages,
					  flushing_user_data_requests);
			}

			ssdfs_peb_current_log_unlock(pebi);
			ssdfs_unlock_current_peb(pebc);
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	wait_event_interruptible(*wait_queue,
				 FLUSH_THREAD_WAKE_CONDITION(pebc));
	goto repeat;

sleep_failed_flush_thread:
	wait_event_interruptible(*wait_queue,
		FLUSH_FAILED_THREAD_WAKE_CONDITION());
	goto repeat;
}
