//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_flush_thread.c - flush thread functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2014-2019, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "compression.h"
#include "block_bitmap.h"
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "offset_translation_table.h"
#include "page_array.h"
#include "peb.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

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
 * @last_free_blk: last logical free block
 * @metadata_blks: count of physical pages are used by metadata
 * @invalid_blks: count of invalid blocks
 * @frag_id: pointer on fragment counter
 * @cur_page: pointer on current page value
 * @write_offset: pointer on write offset value
 */
struct ssdfs_bmap_descriptor {
	struct ssdfs_peb_info *pebi;
	struct pagevec snapshot;
	u16 peb_index;
	u16 flags;
	u16 type;
	u32 last_free_blk;
	u32 metadata_blks;
	u32 invalid_blks;
	size_t bytes_count;
	u16 *frag_id;
	pgoff_t *cur_page;
	u32 *write_offset;
};

/*
 * struct ssdfs_pagevec_descriptor - pagevec descriptor
 * @pebi: pointer on PEB object
 * @pvec: pagevec with saving data
 * @start_sequence_id: start sequence id
 * @area_offset: offset of area
 * @bytes_count: size in bytes of valid data in pagevec
 * @desc_array: array of fragment descriptors
 * @array_capacity: capacity of fragment descriptors' array
 * @compr_size: whole size of all compressed fragments [out]
 * @uncompr_size: whole size of all fragments in uncompressed state [out]
 * @fragments_count: count of saved fragments
 * @cur_page: pointer on current page value
 * @write_offset: pointer on write offset value
 */
struct ssdfs_pagevec_descriptor {
	struct ssdfs_peb_info *pebi;
	struct pagevec *pvec;
	u16 start_sequence_id;
	u32 area_offset;
	size_t bytes_count;
	struct ssdfs_fragment_desc *desc_array;
	size_t array_capacity;
	u32 compr_size;
	u32 uncompr_size;
	u16 fragments_count;
	pgoff_t *cur_page;
	u32 *write_offset;
};

/*
 * ssdfs_write_offset_to_mem_page_index() - convert write offset into mem page
 * @fsi: pointer on shared file system object
 * @start_page: index of log's start physical page
 * @write_offset: offset in bytes from log's beginning
 */
static inline
pgoff_t ssdfs_write_offset_to_mem_page_index(struct ssdfs_fs_info *fsi,
					     u16 start_page,
					     u32 write_offset)
{
	u32 page_off;

	page_off = ssdfs_phys_page_to_mem_page(fsi, start_page);
	page_off = SSDFS_MEMPAGE2BYTES(page_off) + write_offset;
	return SSDFS_BYTES2MEMPAGE(page_off);
}

/******************************************************************************
 *                         FLUSH THREAD FUNCTIONALITY                         *
 ******************************************************************************/

/*
 * ssdfs_peb_estimate_blk_bmap_bytes() - estimate block bitmap's bytes
 * @pages_per_peb: number of pages in one PEB
 * @is_migrating: is PEB migrating?
 */
static inline
int ssdfs_peb_estimate_blk_bmap_bytes(u32 pages_per_peb, bool is_migrating)
{
	size_t blk_bmap_hdr_size = sizeof(struct ssdfs_block_bitmap_header);
	size_t blk_bmap_frag_hdr_size = sizeof(struct ssdfs_block_bitmap_fragment);
	size_t frag_desc_size = sizeof(struct ssdfs_fragment_desc);
	size_t blk_bmap_bytes;
	int reserved_bytes = 0;

	blk_bmap_bytes = BLK_BMAP_BYTES(pages_per_peb);

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
 * ssdfs_peb_estimate_blk2off_bytes() - estimate blk2off table's bytes
 * @log_pages: number of pages in the full log
 * @pebs_per_seg: number of PEBs in one segment
 */
static inline
int ssdfs_peb_estimate_blk2off_bytes(u16 log_pages, u32 pebs_per_seg)
{
	size_t blk2off_tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	size_t pot_tbl_hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	size_t phys_off_desc_size = sizeof(struct ssdfs_phys_offset_descriptor);
	int reserved_bytes = 0;

	reserved_bytes += blk2off_tbl_hdr_size;
	reserved_bytes += pot_tbl_hdr_size;
	reserved_bytes += (phys_off_desc_size * log_pages) * pebs_per_seg;

	return reserved_bytes;
}

/*
 * ssdfs_peb_estimate_blk_desc_tbl_bytes() - estimate block desc table's bytes
 * @log_pages: number of pages in the full log
 */
static inline
int ssdfs_peb_estimate_blk_desc_tbl_bytes(u16 log_pages)
{
	size_t blk_desc_tbl_hdr_size = sizeof(struct ssdfs_area_block_table);
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	int reserved_bytes = 0;

	reserved_bytes += blk_desc_tbl_hdr_size;
	reserved_bytes += blk_desc_size * log_pages;

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
							    is_migrating);

	/* blk2off table */
	reserved_bytes += ssdfs_peb_estimate_blk2off_bytes(log_pages,
							   pebs_per_seg);

	/* block descriptor table */
	reserved_bytes += ssdfs_peb_estimate_blk_desc_tbl_bytes(log_pages);

	reserved_bytes += page_size - 1;
	reserved_bytes /= page_size;
	reserved_bytes *= page_size;

	/* log footer header */
	reserved_bytes += lf_hdr_size;

	/* block bitmap */
	reserved_bytes += ssdfs_peb_estimate_blk_bmap_bytes(pages_per_peb,
							    is_migrating);

	/* blk2off table */
	reserved_bytes += ssdfs_peb_estimate_blk2off_bytes(log_pages,
							   pebs_per_seg);

	reserved_bytes += page_size - 1;
	reserved_bytes /= page_size;
	reserved_bytes *= page_size;

	reserved_pages = reserved_bytes / page_size;

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

	return ssdfs_peb_estimate_blk_bmap_bytes(pages_per_peb, is_migrating);
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

	return ssdfs_peb_estimate_blk2off_bytes(log_pages, pebs_per_seg);
}

/*
 * ssdfs_peb_blk_desc_tbl_reserved_bytes() - calculate block desc reserved bytes
 * @pebi: pointer on PEB object
 */
static inline
int ssdfs_peb_blk_desc_tbl_reserved_bytes(struct ssdfs_peb_info *pebi)
{
	u16 log_pages = pebi->log_pages;

	return ssdfs_peb_estimate_blk_desc_tbl_bytes(log_pages);
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

	/* blk2off table */
	atomic_set(&pebi->reserved_bytes.blk2off_tbl,
		   ssdfs_peb_blk2off_reserved_bytes(pebi));
	reserved_bytes += atomic_read(&pebi->reserved_bytes.blk2off_tbl);

	/* block descriptor table */
	offset = reserved_bytes;
	blk_desc_reserved = ssdfs_peb_blk_desc_tbl_reserved_bytes(pebi);
	atomic_set(&pebi->reserved_bytes.blk_desc_tbl, blk_desc_reserved);
	reserved_bytes += atomic_read(&pebi->reserved_bytes.blk_desc_tbl);

	reserved_bytes += page_size - 1;
	reserved_bytes /= page_size;
	reserved_bytes *= page_size;

	if (blk_desc_reserved < (reserved_bytes - offset)) {
		atomic_set(&pebi->reserved_bytes.blk_desc_tbl,
			   (reserved_bytes - offset));
	}

	reserved_bytes += ssdfs_peb_log_footer_reserved_bytes(pebi);

	reserved_pages = reserved_bytes / page_size;

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
	void *kaddr;

	SSDFS_DBG("peb %llu, current_log.start_page %u\n",
		  pebi->peb_id, pebi->current_log.start_page);

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

	area_pages = &pebi->current_log.area[SSDFS_LOG_BLK_DESC_AREA].array;

	page = ssdfs_page_array_grab_page(area_pages, 0);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to add page into area space\n");
		return -ENOMEM;
	}

	kaddr = kmap_atomic(page);
	memset(kaddr, 0, PAGE_SIZE);
	kunmap_atomic(kaddr);
	SetPagePrivate(page);
	put_page(page);
	unlock_page(page);

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

	SSDFS_DBG("log_pages %u, free_data_pages %u, sequence_id %d\n",
		  log_pages, free_data_pages, sequence_id);

	if (free_data_pages == 0) {
		if (sequence_id > 0)
			return SSDFS_FINISH_PARTIAL_LOG;
		else
			return SSDFS_FINISH_FULL_LOG;
	}

	if (free_data_pages >= log_pages)
		return SSDFS_START_FULL_LOG;

	min_partial_log_pages = ssdfs_peb_estimate_min_partial_log_pages(pebi);

	SSDFS_DBG("min_partial_log_pages %u, reserved_pages %u\n",
		  min_partial_log_pages, reserved_pages);

	if (reserved_pages == 0) {
		if (free_data_pages <= min_partial_log_pages) {
			if (sequence_id > 0)
				return SSDFS_FINISH_PARTIAL_LOG;
			else
				return SSDFS_FINISH_FULL_LOG;
		}
	} else {
		if (free_data_pages == 0) {
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
	int log_state;
	int log_strategy;
	u32 pages_per_peb;
	u32 log_footer_pages;
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
		SSDFS_WARN("peb %llu current log is initialized\n",
			   pebi->peb_id);
		return -ERANGE;

	default:
		BUG();
	};

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);

	ssdfs_peb_current_log_lock(pebi);

	log = &pebi->current_log;
	pages_per_peb = si->fsi->pages_per_peb;

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
		log_footer_pages = ssdfs_peb_log_footer_metapages(pebi);
		log->reserved_pages = ssdfs_peb_define_reserved_metapages(pebi);
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
			log_footer_pages =
				ssdfs_peb_log_footer_metapages(pebi);
			log->reserved_pages =
				ssdfs_peb_define_reserved_metapages(pebi);
			/*
			 * The reserved pages imply presence of header
			 * and footer. However, it needs to add the page
			 * for data itself. If header's page is able
			 * to keep the data too then footer will be in
			 * the log. Otherwise, footer will be absent.
			 */
			log->free_data_pages += log_footer_pages;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_CRIT("unexpected log strategy %#x\n",
			   log_strategy);
		goto finish_log_create;
	}

	if (log->free_data_pages <= log->reserved_pages) {
		SSDFS_DBG("log->free_data_pages %u <= log->reserved_pages %u\n",
			  log->free_data_pages, log->reserved_pages);
		err = -ENOSPC;
		goto finish_log_create;
	}

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
			ssdfs_fs_error(si->fsi->sb,
					__FILE__, __func__, __LINE__,
					"PEB %llu is dirty on log creation\n",
					pebi->peb_id);
			err = -EIO;
			goto finish_log_create;
		}

		err = ssdfs_page_array_release_all_pages(area_pages);
		if (unlikely(err)) {
			ssdfs_fs_error(si->fsi->sb,
					__FILE__, __func__, __LINE__,
					"fail to release pages of PEB %llu\n",
					pebi->peb_id);
			err = -EIO;
			goto finish_log_create;
		}

		metadata = &area->metadata;
		memset(metadata, 0, metadata_size);

		switch (i) {
		case SSDFS_LOG_BLK_DESC_AREA:
			chain_hdr = &metadata->area.blk_desc.table.chain_hdr;
			chain_hdr->desc_size = cpu_to_le16(desc_size);
			chain_hdr->magic = SSDFS_CHAIN_HDR_MAGIC;
			chain_hdr->type = SSDFS_BLK_DESC_CHAIN_HDR;
			area->has_metadata = true;
			area->write_offset = blk_table_size;
			area->metadata.reserved_offset = 0;

			err = ssdfs_peb_reserve_blk_desc_space(pebi, metadata);
			if (unlikely(err)) {
				SSDFS_ERR("fail to reserve blk desc space: "
					  "err %d\n", err);
				goto finish_log_create;
			}
			break;

		case SSDFS_LOG_DIFFS_AREA:
			chain_hdr = &metadata->area.diffs.table.hdr.chain_hdr;
			chain_hdr->desc_size = cpu_to_le16(desc_size);
			chain_hdr->magic = SSDFS_CHAIN_HDR_MAGIC;
			chain_hdr->type = SSDFS_BLK_STATE_CHAIN_HDR;
			area->has_metadata = false;
			area->write_offset = 0;
			area->metadata.reserved_offset = 0;
			break;

		case SSDFS_LOG_JOURNAL_AREA:
			chain_hdr = &metadata->area.journal.table.hdr.chain_hdr;
			chain_hdr->desc_size = cpu_to_le16(desc_size);
			chain_hdr->magic = SSDFS_CHAIN_HDR_MAGIC;
			chain_hdr->type = SSDFS_BLK_STATE_CHAIN_HDR;
			area->has_metadata = false;
			area->write_offset = 0;
			area->metadata.reserved_offset = 0;
			break;

		case SSDFS_LOG_MAIN_AREA:
			area->has_metadata = false;
			area->write_offset = 0;
			area->metadata.reserved_offset = 0;
			break;

		default:
			BUG();
		};
	}

	ssdfs_peb_set_current_log_state(pebi, SSDFS_LOG_CREATED);

	SSDFS_DBG("log created: "
		  "seg %llu, peb %llu, current_log.start_page %u\n",
		  si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);

finish_log_create:
	ssdfs_peb_current_log_unlock(pebi);
	return err;
}

/*
 * is_create_requests_queue_empty() - check that create queue has requests
 * @pebc: pointer on PEB container
 */
static inline
bool is_create_requests_queue_empty(struct ssdfs_peb_container *pebc)
{
	bool is_create_rq_empty = true;

	spin_lock(&pebc->crq_ptr_lock);
	if (pebc->create_rq) {
		is_create_rq_empty =
			is_ssdfs_requests_queue_empty(pebc->create_rq);
	}
	spin_unlock(&pebc->crq_ptr_lock);

	return is_create_rq_empty;
}

/*
 * have_flush_requests() - check that create or update queue have requests
 * @pebc: pointer on PEB container
 */
static inline
bool have_flush_requests(struct ssdfs_peb_container *pebc)
{
	bool is_create_rq_empty = true;
	bool is_update_rq_empty = true;

	is_create_rq_empty = is_create_requests_queue_empty(pebc);
	is_update_rq_empty = is_ssdfs_requests_queue_empty(&pebc->update_rq);

	return !is_create_rq_empty || !is_update_rq_empty;
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("page %p, start_offset %u, data_bytes %zu, "
		  "sequence_id %u, fragment_type %#x, fragment_flags %#x, "
		  "write_offset %u, store %p, free_space %zu\n",
		  from->page, from->start_offset, from->data_bytes,
		  from->sequence_id, from->fragment_type,
		  from->fragment_flags,
		  to->write_offset, to->store, to->free_space);

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

	src = kmap(from->page);
	src += from->start_offset;
	to->desc->checksum = ssdfs_crc32_le(src, from->data_bytes);
	err = ssdfs_compress(compr_type, src, to->store,
			     &from->data_bytes, &to->compr_size);
	kunmap(from->page);

	if (err == -E2BIG) {
		BUG_ON(from->data_bytes > PAGE_SIZE);
		BUG_ON(from->data_bytes > to->free_space);

		from->fragment_type = SSDFS_FRAGMENT_UNCOMPR_BLOB;

		src = kmap_atomic(from->page);
		src += from->start_offset;
		memcpy(to->store, src, from->data_bytes);
		kunmap_atomic(src);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("from->page %p, from->start_offset %u, "
		  "from->data_bytes %zu, from->sequence_id %u, "
		  "write_offset %u, type %#x\n",
		  from->page, from->start_offset, from->data_bytes,
		  from->sequence_id, write_offset, type);

	to.area_offset = 0;
	to.write_offset = write_offset;

	to.store = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!to.store) {
		SSDFS_ERR("fail to allocate buffer for fragment\n");
		return -ENOMEM;
	}

	to.free_space = PAGE_SIZE;
	to.compr_size = 0;
	to.desc = desc;

	err = ssdfs_peb_store_fragment(from, &to);
	if (err == -EAGAIN) {
		SSDFS_DBG("unable to store data fragment: "
			  "write_offset %u, dst_free_space %zu\n",
			  write_offset, to.free_space);
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
		void *kaddr;
		u32 size;

		page_index = to.write_offset + written_bytes;
		page_index >>= PAGE_SHIFT;

		area_pages = &pebi->current_log.area[type].array;
		page = ssdfs_page_array_get_page_locked(area_pages,
							page_index);
		if (IS_ERR_OR_NULL(page)) {
			err = page == NULL ? -ERANGE : PTR_ERR(page);
			SSDFS_ERR("fail to get page %lu for area %#x\n",
				  page_index, type);
			goto free_compr_buffer;
		}

		offset = to.write_offset + written_bytes;
		offset %= PAGE_SIZE;
		size = PAGE_SIZE - offset;
		size = min_t(u32, size, to.compr_size - written_bytes);

		kaddr = kmap_atomic(page);
		memcpy(kaddr + offset, to.store + written_bytes, size);
		kunmap_atomic(kaddr);

		SetPageUptodate(page);
		err = ssdfs_page_array_set_page_dirty(area_pages,
						      page_index);
		if (unlikely(err)) {
			SSDFS_ERR("fail to set page %lu dirty: "
				  "err %d\n",
				  page_index, err);
		}

		unlock_page(page);
		put_page(page);

		if (err)
			goto free_compr_buffer;

		written_bytes += size;
	} while (written_bytes < to.compr_size);

free_compr_buffer:
	kfree(to.store);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("write_offset %u, type %#x, desc %p, "
		  "array %p, array_size %u\n",
		  write_offset, type, desc, array, array_size);

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
	kaddr = kmap_atomic(page);
	memcpy(kaddr + page_off, desc, desc_size);
	memcpy(kaddr + page_off + desc_size, array, table_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("write_offset %u, page_off %u, "
		  "desc_size %zu, table_size %zu\n",
		  write_offset, page_off, desc_size, table_size);
	SSDFS_DBG("BLOCK STATE DESC AREA DUMP:\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     kaddr, PAGE_SIZE);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	kunmap_atomic(kaddr);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(area_pages,
					      page_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: "
			  "err %d\n",
			  page_index, err);
	}

	unlock_page(page);
	put_page(page);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, "
		  "write_offset %u, "
		  "stream->start_offset %u, stream->data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.area[area_type].write_offset,
		  stream->start_offset, stream->data_bytes);

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

			SSDFS_DBG("try to get next page: "
				  "write_offset %u, free_space %u\n",
				  write_offset, rest);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, "
		  "area_type %#x, write_offset %u, "
		  "start_offset %u, data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_type,
		  pebi->current_log.area[area_type].write_offset,
		  start_offset, data_bytes);

	area = &pebi->current_log.area[area_type];

	*metadata_offset = area->write_offset;
	*metadata_space = sizeof(struct ssdfs_block_state_descriptor);

	SSDFS_DBG("metadata_offset %u, metadata_space %u\n",
		  *metadata_offset, *metadata_space);

	fragments = ssdfs_define_stream_fragments_count(start_offset,
							data_bytes);
	if (fragments == 0) {
		SSDFS_ERR("invalid fragments count %u\n", fragments);
		return -ERANGE;
	}

	*metadata_space += fragments * sizeof(struct ssdfs_fragment_desc);
	*metadata_offset = ssdfs_peb_correct_area_write_offset(*metadata_offset,
							       *metadata_space);

	SSDFS_DBG("fragments %u, metadata_offset %u, metadata_space %u\n",
		  fragments, *metadata_offset, *metadata_space);

	return 0;
}

/*
 * ssdfs_peb_store_byte_stream() - store byte stream into log
 * @pebi: pointer on PEB object
 * @stream: byte stream descriptor
 * @type: area type
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, "
		  "area_type %#x, fragment_type %#x, write_offset %u, "
		  "stream->start_offset %u, stream->data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_type, fragment_type,
		  pebi->current_log.area[area_type].write_offset,
		  stream->start_offset, stream->data_bytes);

	area = &pebi->current_log.area[area_type];

	fragments = ssdfs_define_stream_fragments_count(stream->start_offset,
							stream->data_bytes);
	if (fragments == 0) {
		SSDFS_ERR("invalid fragments count %u\n", fragments);
		return -ERANGE;
	} else if (fragments > 1) {
		array = kcalloc(fragments, sizeof(struct ssdfs_fragment_desc),
				GFP_KERNEL);
		if (!array) {
			SSDFS_ERR("fail to allocate fragment desc array: "
				  "fragments %u\n",
				  fragments);
			return -ENOMEM;
		}
	}

	SSDFS_DBG("fragments %u, start_offset %u, data_bytes %u\n",
		  fragments, stream->start_offset, stream->data_bytes);

	start_page = stream->start_offset >> PAGE_SHIFT;

	if ((start_page + fragments) > pagevec_count(stream->pvec)) {
		SSDFS_ERR("start_page %d + fragments %u > pagevec_count %u\n",
			  start_page, fragments, pagevec_count(stream->pvec));
		err = -ERANGE;
		goto free_array;
	}

	stream->write_offset = area->write_offset;

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

	area->write_offset = metadata_offset;
	area->write_offset += metadata_space;

	SSDFS_DBG("write_offset %u\n", area->write_offset);

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

		from.page = stream->pvec->pages[i];
		from.start_offset = (stream->start_offset + written_bytes) %
					PAGE_SIZE;
		from.data_bytes = min_t(u32, PAGE_SIZE,
					stream->data_bytes - written_bytes);
		from.sequence_id = page_index;

		/*
		 * TODO: temporary fragment flag is hardcoded as zlib fragment
		 *       It needs to get flag from feature_compat of volume_info
		 */
		from.fragment_type = fragment_type;
		from.fragment_flags = SSDFS_FRAGMENT_HAS_CSUM;

		SSDFS_DBG("from.start_offset %u, from.data_bytes %zu\n",
			  from.start_offset, from.data_bytes);

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

			SSDFS_DBG("try to get next page: "
				  "write_offset %u, free_space %u\n",
				  write_offset, rest);

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
			memcpy(&array[page_index], &cur_desc,
				sizeof(struct ssdfs_fragment_desc));
		} else if (page_index > 0)
			BUG();

		written_bytes += from.data_bytes;
		area->write_offset += le16_to_cpu(cur_desc.compr_size);

		SSDFS_DBG("written_bytes %u, write_offset %u\n",
			  written_bytes, area->write_offset);
	}

	stream->compr_bytes =
		area->write_offset - (metadata_offset + metadata_space);

	SSDFS_DBG("write_offset %u, metadata_offset %u, metadata_space %u\n",
		  area->write_offset, metadata_offset, metadata_space);

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
		kfree(array);

	if (err)
		area->write_offset = metadata_offset;

	SSDFS_DBG("seg %llu, peb %llu, "
		  "area_type %#x, fragment_type %#x, write_offset %u, "
		  "stream->start_offset %u, stream->data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_type, fragment_type,
		  pebi->current_log.area[area_type].write_offset,
		  stream->start_offset, stream->data_bytes);

	return err;
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
	struct ssdfs_fs_info *fsi;
	u32 write_offset;
	u32 free_space;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(fragment_size == 0);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("area_type %#x, fragment_size %u\n",
		  area_type, fragment_size);

	fsi = pebi->pebc->parent_si->fsi;
	write_offset = pebi->current_log.area[area_type].write_offset;
	free_space = PAGE_SIZE - (write_offset % PAGE_SIZE);
	free_space += pebi->current_log.free_data_pages * fsi->pagesize;

	SSDFS_DBG("write_offset %u, free_space %u\n",
		  write_offset, free_space);

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
	struct ssdfs_page_array *area_pages;
	bool is_space_enough, is_page_available;
	u32 write_offset;
	u32 free_space;
	pgoff_t page_index;
	struct page *page;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(fragment_size == 0);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("area_type %#x, fragment_size %u\n",
		  area_type, fragment_size);

	write_offset = pebi->current_log.area[area_type].write_offset;
	free_space = PAGE_SIZE - (write_offset % PAGE_SIZE);

	SSDFS_DBG("write_offset %u, free_space %u\n",
		  write_offset, free_space);

	is_space_enough = fragment_size <= free_space;

	page_index = write_offset >> PAGE_SHIFT;
	area_pages = &pebi->current_log.area[area_type].array;
	page = ssdfs_page_array_get_page(area_pages, page_index);
	if (IS_ERR_OR_NULL(page))
		is_page_available = false;
	else {
		is_page_available = true;
		put_page(page);
	}

	return is_space_enough && is_page_available;
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
	void *kaddr;
	u16 metadata_pages = 0;
	int phys_pages = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("current_log.free_data_pages %u, "
		  "area_type %#x, area.write_offset %u, "
		  "fragment_size %u\n",
		  pebi->current_log.free_data_pages,
		  area_type,
		  pebi->current_log.area[area_type].write_offset,
		  fragment_size);

	fsi = pebi->pebc->parent_si->fsi;
	si = pebi->pebc->parent_si;
	area_pages = &pebi->current_log.area[area_type].array;

	if (pebi->current_log.free_data_pages < 1) {
		SSDFS_DBG("free_data_pages %u\n",
			  pebi->current_log.free_data_pages);
		return -ENOSPC;
	}

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
			put_page(page);
		}
	} while (index_start < index_end);

	if (index_start >= index_end) {
		SSDFS_DBG("log doesn't need in growing\n");
		return 0;
	}

	phys_pages = index_end - index_start;

	if (fsi->pagesize > PAGE_SIZE) {
		phys_pages >>= fsi->log_pagesize - PAGE_SHIFT;
		if (phys_pages == 0)
			phys_pages = 1;
	} else if (fsi->pagesize < PAGE_SIZE)
		phys_pages <<= PAGE_SHIFT - fsi->log_pagesize;

	if (phys_pages > pebi->current_log.free_data_pages) {
		SSDFS_DBG("new_page_count %u > free_data_pages %u\n",
			  phys_pages,
			  pebi->current_log.free_data_pages);
		return -ENOSPC;
	}

	for (; index_start < index_end; index_start++) {
		SSDFS_DBG("page_index %lu, current_log.free_data_pages %u\n",
			  index_start, pebi->current_log.free_data_pages);

		page = ssdfs_page_array_grab_page(area_pages, index_start);
		if (IS_ERR_OR_NULL(page)) {
			SSDFS_ERR("fail to add page %lu into area %#x space\n",
				  index_start, area_type);
			return -ENOMEM;
		}

		kaddr = kmap_atomic(page);
		memset(kaddr, 0, PAGE_SIZE);
		kunmap_atomic(kaddr);
		SetPagePrivate(page);
		put_page(page);
		unlock_page(page);
	}

	pebi->current_log.free_data_pages -= phys_pages;

	if (area_type == SSDFS_LOG_BLK_DESC_AREA)
		metadata_pages = phys_pages;

	if (metadata_pages > 0) {
		err = ssdfs_segment_blk_bmap_reserve_metapages(&si->blk_bmap,
								pebi->pebc,
								metadata_pages);
		if (unlikely(err)) {
			SSDFS_ERR("fail to reserve metadata pages: "
				  "count %u, err %d\n",
				  metadata_pages, err);
			return err;
		}
	}

	return 0;
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

	SSDFS_DBG("area_type %#x, vacant_item %u\n",
		  area_type, vacant_item);

	BUG_ON(vacant_item > SSDFS_NEXT_BLK_TABLE_INDEX);
	if (vacant_item == SSDFS_NEXT_BLK_TABLE_INDEX) {
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
	else {
		cur_item = 0;
		le16_add_cpu(&table->chain_hdr.fragments_count, 1);
	}

	SSDFS_DBG("area_type %#x, cur_item %u\n",
		  area_type, cur_item);

	BUG_ON(cur_item >= SSDFS_NEXT_BLK_TABLE_INDEX);

	return &table->blk[cur_item];
}

/*
 * ssdfs_peb_store_area_block_table() - store block table
 * @pebi: pointer on PEB object
 * @area_type: area type
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
				     int area_type)
{
	struct ssdfs_peb_area *area;
	struct ssdfs_area_block_table *table;
	struct ssdfs_fragment_desc *last_desc;
	u16 fragments;
	u32 reserved_offset, new_offset;
	size_t blk_table_size = sizeof(struct ssdfs_area_block_table);
	u16 hdr_flags;
	u16 flags = 0;
	struct page *page;
	pgoff_t page_index;
	unsigned char *kaddr;
	u32 page_off;
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

	SSDFS_DBG("reserved_offset %u, area_type %#x\n",
		  pebi->current_log.area[area_type].metadata.reserved_offset,
		  area_type);

	area = &pebi->current_log.area[area_type];
	table = &area->metadata.area.blk_desc.table;

	fragments = le16_to_cpu(table->chain_hdr.fragments_count);

	if (fragments < SSDFS_NEXT_BLK_TABLE_INDEX) {
		if (fragments > 0)
			last_desc = &table->blk[fragments - 1];
		else
			last_desc = &table->blk[0];

		last_desc->magic = SSDFS_FRAGMENT_DESC_MAGIC;
		last_desc->type = SSDFS_DATA_BLK_DESC;
		last_desc->flags = 0;
	} else {
		BUG_ON(fragments > SSDFS_NEXT_BLK_TABLE_INDEX);

		flags = SSDFS_MULTIPLE_HDR_CHAIN;

		last_desc = &table->blk[SSDFS_NEXT_BLK_TABLE_INDEX];

		new_offset =
			ssdfs_peb_correct_area_write_offset(area->write_offset,
							    blk_table_size);
		area->write_offset = new_offset;

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
	kaddr = kmap_atomic(page);
	memcpy(kaddr + page_off, table, blk_table_size);
	kunmap_atomic(kaddr);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&area->array, page_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: "
			  "err %d\n",
			  page_index, err);
	}

	unlock_page(page);
	put_page(page);

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
	struct ssdfs_peb_area *area;
	u16 fragments;
	struct ssdfs_area_block_table *table;
	struct ssdfs_fragment_desc *last_desc;
	size_t blk_table_size = sizeof(struct ssdfs_area_block_table);
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

	SSDFS_DBG("write_offset %u, area_type %#x\n",
		  pebi->current_log.area[area_type].write_offset,
		  area_type);

	area = &pebi->current_log.area[area_type];
	table = &area->metadata.area.blk_desc.table;
	fragments = le16_to_cpu(table->chain_hdr.fragments_count);

	BUG_ON(fragments > SSDFS_NEXT_BLK_TABLE_INDEX);

	if (fragments < SSDFS_NEXT_BLK_TABLE_INDEX) {
		SSDFS_ERR("invalid fragments count %u\n", fragments);
		return -ERANGE;
	}

	last_desc = &table->blk[SSDFS_NEXT_BLK_TABLE_INDEX];

	if (le32_to_cpu(last_desc->offset) != area->write_offset) {
		SSDFS_ERR("last_desc->offset %u != area->write_offset %u\n",
			  le32_to_cpu(last_desc->offset), area->write_offset);
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

	memset(table->blk, 0,
		sizeof(struct ssdfs_fragment_desc) * SSDFS_BLK_TABLE_MAX);

	area->metadata.reserved_offset = area->write_offset;
	area->write_offset += blk_table_size;

	return 0;
}

/* try to estimate fragment size in the log */
static inline
u32 ssdfs_peb_estimate_data_fragment_size(u32 uncompr_bytes)
{
	u32 estimated_compr_size;

	/*
	 * TODO: Research function
	 * Maybe we don't need in this function. But, anyway, we can try
	 * to estimate potential size of data fragment. There are several
	 * alternatives: (1) overestimate size; (2) underestimate size;
	 * (3) try to predict possible size by means of some formula.
	 *
	 * Currently, I try to estimate size as 75% from uncompressed state
	 * for compression case.
	 */

	estimated_compr_size = (uncompr_bytes * 75) / 100;

	SSDFS_DBG("uncompr_bytes %u, estimated_compr_size %u\n",
		  uncompr_bytes, estimated_compr_size);

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

	SSDFS_DBG("processed_bytes %u, req->extent.data_bytes %u\n",
		  processed_bytes, req->extent.data_bytes);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(processed_bytes > req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

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

	return 0;
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
	struct ssdfs_byte_stream_descriptor byte_stream = {0};
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, area_type %#x, "
		  "start_offset %u, data_bytes %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks, area_type,
		  start_offset, data_bytes);

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

#if defined(CONFIG_SSDFS_ZLIB)
	estimated_compr_size =
		ssdfs_peb_estimate_data_fragment_size(data_bytes);
#elif defined(CONFIG_SSDFS_LZO)
	estimated_compr_size =
		ssdfs_peb_estimate_data_fragment_size(data_bytes);
#else
	estimated_compr_size = data_bytes;
#endif

	check_bytes = metadata_space + estimated_compr_size;

	if (!can_area_add_fragment(pebi, area_type, check_bytes)) {
		pebi->current_log.free_data_pages = 0;
		SSDFS_DBG("log is full\n");
		return -ENOSPC;
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

	/*
	 * TODO: temporary fragment flag is hardcoded as zlib fragment
	 *       It needs to get flag from feature_compat of volume_info
	 */
	err = ssdfs_peb_store_byte_stream(pebi, &byte_stream, area_type,
#if defined(CONFIG_SSDFS_ZLIB)
					  SSDFS_FRAGMENT_ZLIB_BLOB,
#elif defined(CONFIG_SSDFS_LZO)
					  SSDFS_FRAGMENT_LZO_BLOB,
#else
					  SSDFS_FRAGMENT_UNCOMPR_BLOB,
#endif
					  req->extent.cno,
					  req->extent.parent_snapshot);

	if (err == -EAGAIN) {
		SSDFS_DBG("unable to add byte stream: "
			  "start_offset %u, data_bytes %u, area_type %#x, "
			  "cno %llu, parent_snapshot %llu\n",
			  start_offset, data_bytes, area_type,
			  req->extent.cno, req->extent.parent_snapshot);
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, start_offset %u, data_bytes %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks, start_offset, data_bytes);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, start_offset %u, data_bytes %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks, start_offset, data_bytes);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, rest_bytes %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks,
		  data_bytes);

	if (!can_area_add_fragment(pebi, area_type, data_bytes)) {
		pebi->current_log.free_data_pages = 0;
		SSDFS_DBG("log is full\n");
		return -ENOSPC;
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
		SSDFS_DBG("unable to add byte stream: "
			  "start_offset %u, data_bytes %u, area_type %#x, "
			  "cno %llu, parent_snapshot %llu\n",
			  start_offset, data_bytes, area_type,
			  req->extent.cno, req->extent.parent_snapshot);
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
	if (pagesize > PAGE_SIZE)
		return data_size >= pagesize;

	return data_size >= PAGE_SIZE;
}

/*
 * ssdfs_peb_add_block_into_data_area() - try to add data block into log
 * @pebi: pointer on PEB object
 * @req: I/O request
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
					struct ssdfs_peb_phys_offset *off,
					u32 *written_bytes)
{
	struct ssdfs_fs_info *fsi;
	int area_type;
	u32 rest_bytes, tested_bytes = 0;
	u32 start_page;
	u32 page_count;
	u32 start_offset;
	u32 portion_size;
	int page_index;
	struct page *page;
	u32 can_compress[2] = {0, 0};
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

	SSDFS_DBG("seg %llu, peb %llu, ino %llu, "
		  "processed_blks %d, rest_bytes %u\n",
		  req->place.start.seg_id, pebi->peb_id, req->extent.ino,
		  req->result.processed_blks,
		  rest_bytes);

	fsi = pebi->pebc->parent_si->fsi;
	start_page = req->result.processed_blks << fsi->log_pagesize;
	start_page >>= PAGE_SHIFT;

	if (fsi->pagesize < PAGE_SIZE) {
		rest_bytes = min_t(u32, rest_bytes, PAGE_SIZE);
		page_count = rest_bytes + PAGE_SIZE - 1;
		page_count >>= PAGE_SHIFT;
	} else {
		rest_bytes = min_t(u32, rest_bytes, fsi->pagesize);
		page_count = rest_bytes + fsi->pagesize - 1;
		page_count >>= PAGE_SHIFT;
	}

	if (!is_ssdfs_block_full(fsi->pagesize, rest_bytes))
		area_type = SSDFS_LOG_JOURNAL_AREA;
	else {
		for (i = 0; i < page_count; i++) {
			int state;

			page_index = i + start_page;
			start_offset = page_index >> PAGE_SHIFT;
			portion_size = PAGE_SIZE;
			page = req->result.pvec.pages[page_index];

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(tested_bytes >= rest_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

			portion_size = min_t(u32, portion_size,
					     rest_bytes - tested_bytes);

			if (ssdfs_can_compress_data(page, portion_size))
				state = 1;
			else
				state = 0;

			can_compress[state]++;
			tested_bytes += portion_size;
		}

		if (can_compress[true] >= can_compress[false])
			area_type = SSDFS_LOG_DIFFS_AREA;
		else
			area_type = SSDFS_LOG_MAIN_AREA;
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
			SSDFS_DBG("unable to add page into current log: "
				  "index %d, portion_size %u\n",
				  page_index, portion_size);
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add page: "
				  "index %d, portion_size %u, err %d\n",
				  page_index, portion_size, err);
			return err;
		}

		*written_bytes += portion_size;
	}

	return 0;
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
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area_metadata *metadata;
	struct ssdfs_area_block_table *table;
	int items_count, capacity;
	u16 vacant_item;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!req);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, logical_offset %llu, processed_blks %d\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->result.processed_blks);

	metadata = &pebi->current_log.area[area_type].metadata;
	table = &metadata->area.blk_desc.table;

	items_count = metadata->area.blk_desc.items_count;
	capacity = metadata->area.blk_desc.capacity;

	if (items_count < capacity) {
		/* reserved space can be used */
		metadata->area.blk_desc.items_count++;
		return 0;
	}

	vacant_item = le16_to_cpu(table->chain_hdr.fragments_count);
	BUG_ON(vacant_item > SSDFS_NEXT_BLK_TABLE_INDEX);

	if (vacant_item == SSDFS_NEXT_BLK_TABLE_INDEX) {
		err = ssdfs_peb_store_area_block_table(pebi, area_type);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store area's block table: "
				  "area %#x, err %d\n",
				  area_type, err);
			return err;
		}

		err = ssdfs_peb_allocate_area_block_table(pebi, area_type);
		if (err == -EAGAIN) {
			SSDFS_DBG("log is full, "
				  "unable to add next fragments chain: "
				  "area %#x\n",
				  area_type);
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to add next fragments chain: "
				  "area %#x\n",
				  area_type);
			return err;
		}
	}

	if (!has_current_page_free_space(pebi, area_type, blk_desc_size)) {
		err = ssdfs_peb_grow_log_area(pebi, area_type, blk_desc_size);
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

	metadata->area.blk_desc.items_count++;

	return 0;
}

/*
 * ssdfs_peb_prepare_block_descriptor() - prepare new state of block descriptor
 * @pebi: pointer on PEB object
 * @req: I/O request
 * @data: data offset inside PEB
 * @desc: block descriptor [out] - temporary argument
 *
 * This function prepares new state of block descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code.
 */
static
int ssdfs_peb_prepare_block_descriptor(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_peb_phys_offset *data,
					struct ssdfs_block_descriptor *desc)
{
	u64 logical_offset;
	u32 pagesize;
	int id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req || !desc || !data);
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, logical_offset %llu, processed_blks %d\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->result.processed_blks);

	pagesize = pebi->pebc->parent_si->fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON((req->result.processed_blks * pagesize) >=
		req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_offset = req->extent.logical_offset +
			 (req->result.processed_blks * pagesize);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_offset >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	/*
	 * TODO: Temporary we don't support updates.
	 *       So, block descriptor contains description of
	 *       one fragment only.
	 */
	memset(desc, 0xFF, sizeof(struct ssdfs_block_descriptor));

	desc->ino = cpu_to_le64(req->extent.ino);
	desc->logical_offset = cpu_to_le32((u32)(logical_offset / pagesize));
	desc->peb_index = cpu_to_le16(data->peb_index);
	desc->peb_page = cpu_to_le16(data->peb_page);

	desc->state[0].log_start_page =
			cpu_to_le16(pebi->current_log.start_page);
	desc->state[0].log_area = data->log_area;
	desc->state[0].byte_offset = cpu_to_le32(data->byte_offset);

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

	desc->state[0].peb_migration_id = (u8)id;

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
 */
static
int ssdfs_peb_write_block_descriptor(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_block_descriptor *desc,
					struct ssdfs_peb_phys_offset *data_off,
					struct ssdfs_peb_phys_offset *off,
					u32 *write_offset)
{
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area *area;
	struct ssdfs_peb_area_metadata *metadata;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	struct page *page;
	pgoff_t page_index;
	unsigned char *kaddr;
	u32 page_off;
	int id;
	int items_count, capacity;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req || !desc || !off || !write_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, logical_offset %llu, processed_blks %d\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->result.processed_blks);

	area = &pebi->current_log.area[area_type];
	metadata = &area->metadata;
	items_count = metadata->area.blk_desc.items_count;
	capacity = metadata->area.blk_desc.capacity;

	if (items_count < 1) {
		SSDFS_ERR("block descriptor is not reserved\n");
		return -ERANGE;
	}

	*write_offset =
		ssdfs_peb_correct_area_write_offset(area->write_offset,
						    blk_desc_size);
	page_index = *write_offset / PAGE_SIZE;

	page = ssdfs_page_array_get_page_locked(&area->array,
						page_index);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get page %lu for area %#x\n",
			  page_index, area_type);
		return -ERANGE;
	}

	page_off = *write_offset % PAGE_SIZE;
	kaddr = kmap_atomic(page);
	memcpy(kaddr + page_off, desc, blk_desc_size);
	kunmap_atomic(kaddr);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&area->array,
						page_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: "
			  "err %d\n",
			  page_index, err);
	}

	unlock_page(page);
	put_page(page);

	if (unlikely(err))
		return err;

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

	area->write_offset = *write_offset + blk_desc_size;

	return 0;
}

/*
 * ssdfs_peb_store_block_descriptor() - store block descriptor into area
 * @pebi: pointer on PEB object
 * @req: I/O request
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
 */
static
int ssdfs_peb_store_block_descriptor(struct ssdfs_peb_info *pebi,
				     struct ssdfs_segment_request *req,
				     struct ssdfs_peb_phys_offset *data_off,
				     struct ssdfs_peb_phys_offset *desc_off)
{
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	struct ssdfs_peb_area *area;
	struct ssdfs_fragments_chain_header *chain_hdr;
	struct ssdfs_fragment_desc *meta_desc;
	struct ssdfs_block_descriptor blk_desc;
	u32 write_offset, old_offset;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	u16 bytes_count;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req || !data_off || !desc_off);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, logical_offset %llu, processed_blks %d\n",
		  req->extent.ino, req->extent.logical_offset,
		  req->result.processed_blks);

	err = ssdfs_peb_prepare_block_descriptor(pebi, req, data_off,
						 &blk_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare block descriptor: "
			  "ino %llu, logical_offset %llu, "
			  "processed_blks %d, err %d\n",
			  req->extent.ino, req->extent.logical_offset,
			  req->result.processed_blks, err);
		return err;
	}

	err = ssdfs_peb_write_block_descriptor(pebi, req, &blk_desc,
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

	old_offset = le32_to_cpu(meta_desc->offset);
	bytes_count = le16_to_cpu(meta_desc->compr_size);

	area = &pebi->current_log.area[area_type];

	if ((old_offset / PAGE_SIZE) == (write_offset / PAGE_SIZE)) {
		bytes_count += blk_desc_size;

		BUG_ON(bytes_count >= U16_MAX);

		meta_desc->compr_size = cpu_to_le16((u16)bytes_count);
		meta_desc->uncompr_size = cpu_to_le16((u16)bytes_count);
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
	}

	chain_hdr = &area->metadata.area.blk_desc.table.chain_hdr;

	le32_add_cpu(&chain_hdr->compr_bytes, (u32)blk_desc_size);
	le32_add_cpu(&chain_hdr->uncompr_bytes, (u32)blk_desc_size);

	return 0;
}

/*
 * ssdfs_peb_store_block_descriptor_offset() - store offset in blk2off table
 * @pebi: pointer on PEB object
 * @logical_offset: offset in pages from file's begin
 * @logical_blk: segment's logical block
 * @off: pointer on block descriptor offset
 */
static
int ssdfs_peb_store_block_descriptor_offset(struct ssdfs_peb_info *pebi,
					    u32 logical_offset,
					    u16 logical_blk,
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, logical_offset %u, "
		  "logical_blk %u, area_type %#x,"
		  "peb_index %u, peb_page %u, byte_offset %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, logical_offset, logical_blk,
		  off->log_area, off->peb_index,
		  off->peb_page, off->byte_offset);

	fsi = pebi->pebc->parent_si->fsi;

	blk_desc_off.page_desc.logical_offset = cpu_to_le32(logical_offset);
	blk_desc_off.page_desc.logical_blk = cpu_to_le16(logical_blk);
	blk_desc_off.page_desc.peb_page = cpu_to_le16(off->peb_page);

	blk_desc_off.blk_state.log_start_page =
		cpu_to_le16(pebi->current_log.start_page);
	blk_desc_off.blk_state.log_area = off->log_area;
	blk_desc_off.blk_state.peb_migration_id = off->peb_migration_id;
	blk_desc_off.blk_state.byte_offset = cpu_to_le32(off->byte_offset);

	table = pebi->pebc->parent_si->blk2off_table;

	err = ssdfs_blk2off_table_change_offset(table, logical_blk,
						off->peb_index,
						&blk_desc_off);
	if (err == -EAGAIN) {
		struct completion *end;
		unsigned long res;

		end = &table->full_init_end;

		res = wait_for_completion_timeout(end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_blk2off_table_change_offset(table, logical_blk,
							off->peb_index,
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
	struct ssdfs_peb_phys_offset data_off = {0};
	struct ssdfs_peb_phys_offset desc_off = {0};
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
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	si = pebi->pebc->parent_si;
	processed_blks = req->result.processed_blks;
	logical_block = req->place.start.blk_index + processed_blks;
	rest_bytes = ssdfs_request_rest_bytes(pebi, req);
	logical_offset = req->extent.logical_offset +
				((u64)processed_blks * fsi->pagesize);
	logical_offset /= fsi->pagesize;

	SSDFS_DBG("seg %llu, peb %llu, logical_block %u, "
		  "logical_offset %llu, "
		  "processed_blks %d, rest_size %u\n",
		  req->place.start.seg_id, pebi->peb_id,
		  logical_block, logical_offset,
		  processed_blks, rest_bytes);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_offset >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_reserve_block_descriptor(pebi, req);
	if (err == -EAGAIN) {
		SSDFS_DBG("try again to add block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to reserve block descriptor: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id, err);
		return err;
	}

	err = ssdfs_peb_add_block_into_data_area(pebi, req, &data_off,
						 &written_bytes);
	if (err == -EAGAIN) {
		SSDFS_DBG("try again to add block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id);
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

	data_off.peb_page = (u16)range.start;

	err = ssdfs_peb_store_block_descriptor(pebi, req, &data_off, &desc_off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store block descriptor: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, logical_block,
			  pebi->peb_id, err);
		return err;
	}

	err = ssdfs_peb_store_block_descriptor_offset(pebi, (u32)logical_offset,
						      logical_block, &desc_off);
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
		  "logical_block %u, data_bytes %u, cno %llu, "
		  "parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->extent.logical_offset, req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);

	err = __ssdfs_peb_create_block(pebi, req);
	if (err == -ENOSPC) {
		SSDFS_DBG("block bitmap hasn't free space\n");
		return err;
	} else if (err == -EAGAIN) {
		SSDFS_DBG("try again to create block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  pebi->peb_id);
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
#endif /* CONFIG_SSDFS_DEBUG */

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
			SSDFS_DBG("try again to create block: "
				  "seg %llu, logical_block %u, peb %llu\n",
				  req->place.start.seg_id, logical_block,
				  pebi->peb_id);
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
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	si = pebi->pebc->parent_si;
	processed_blks = req->result.processed_blks;
	logical_block = req->place.start.blk_index + processed_blks;
	rest_bytes = ssdfs_request_rest_bytes(pebi, req);
	logical_offset = req->extent.logical_offset +
				((u64)processed_blks * fsi->pagesize);
	logical_offset /= fsi->pagesize;

	SSDFS_DBG("seg %llu, peb %llu, logical_block %u, "
		  "logical_offset %llu, "
		  "processed_blks %d, rest_size %u\n",
		  req->place.start.seg_id, pebi->peb_id,
		  logical_block, logical_offset,
		  processed_blks, rest_bytes);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_offset >= U32_MAX);
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

		err = ssdfs_peb_store_block_descriptor_offset(pebi,
							(u32)logical_offset,
							logical_block,
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
		BUG();
	};
	BUG_ON(req->private.cmd != SSDFS_CREATE_BLOCK);
	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);
	BUG_ON(req->extent.data_bytes > pebi->pebc->parent_si->fsi->pagesize);
	BUG_ON(req->result.processed_blks > 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
		  "logical_block %u, data_bytes %u, cno %llu, "
		  "parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->extent.logical_offset, req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);

	err = __ssdfs_peb_pre_allocate_extent(pebi, req);
	if (err == -ENOSPC) {
		SSDFS_DBG("block bitmap hasn't free space\n");
		return err;
	} else if (err == -EAGAIN) {
		SSDFS_DBG("try again to pre-allocate block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  pebi->peb_id);
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
		BUG();
	};
	BUG_ON(req->private.cmd != SSDFS_CREATE_EXTENT);
	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);
	BUG_ON((req->extent.data_bytes /
		pebi->pebc->parent_si->fsi->pagesize) <= 1);
#endif /* CONFIG_SSDFS_DEBUG */

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

	err = __ssdfs_peb_pre_allocate_extent(pebi, req);
	if (err == -ENOSPC) {
		SSDFS_DBG("block bitmap hasn't free space\n");
		return err;
	} else if (err == -EAGAIN) {
		SSDFS_DBG("try again to pre-allocate extent: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  pebi->peb_id);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-allocate extent: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id,
			  req->place.start.blk_index,
			  pebi->peb_id, err);
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
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("req %p, cmd %#x, type %#x\n",
		  req, req->private.cmd, req->private.type);

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
			SSDFS_DBG("try again to create block: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create block: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
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
			SSDFS_DBG("try again to create extent: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to create extent: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
		}
		break;

	default:
		BUG();
	}

	if (unlikely(err))
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);

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

	SSDFS_DBG("seg %llu, peb %llu, "
		  "log_start_page %u, log_area %#x, "
		  "peb_migration_id %u, byte_offset %u, "
		  "buf %p, buf_size %zu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  log_start_page, off->blk_state.log_area,
		  off->blk_state.peb_migration_id,
		  byte_offset, buf, buf_size);

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
 */
static
int ssdfs_peb_update_block(struct ssdfs_peb_info *pebi,
			   struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_phys_offset_descriptor *blk_desc_off;
	struct ssdfs_peb_phys_offset data_off = {0};
	struct ssdfs_peb_phys_offset desc_off = {0};
	u16 blk;
	u64 logical_offset;
	struct ssdfs_block_bmap_range range;
	int range_state;
	u32 written_bytes;
	u16 peb_index;
	bool is_migrating = false;
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

	SSDFS_DBG("ino %llu, seg %llu, peb %llu, logical_offset %llu, "
		  "processed_blks %d, logical_block %u, data_bytes %u, "
		  "cno %llu, parent_snapshot %llu, cmd %#x, type %#x\n",
		  req->extent.ino, req->place.start.seg_id, pebi->peb_id,
		  req->extent.logical_offset, req->result.processed_blks,
		  req->place.start.blk_index,
		  req->extent.data_bytes, req->extent.cno,
		  req->extent.parent_snapshot,
		  req->private.cmd, req->private.type);

	fsi = pebi->pebc->parent_si->fsi;
	table = pebi->pebc->parent_si->blk2off_table;
	seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;

	blk = req->place.start.blk_index + req->result.processed_blks;
	logical_offset = req->extent.logical_offset +
			    ((u64)req->result.processed_blks * fsi->pagesize);
	logical_offset /= fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_offset >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	blk_desc_off = ssdfs_blk2off_table_convert(table, blk,
						   &peb_index,
						   &is_migrating);
	if (IS_ERR(blk_desc_off) && PTR_ERR(blk_desc_off) == -EAGAIN) {
		struct completion *end;
		unsigned long res;

		end = &table->full_init_end;

		res = wait_for_completion_timeout(end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		blk_desc_off = ssdfs_blk2off_table_convert(table, blk,
							   &peb_index,
							   &is_migrating);
	}

	if (IS_ERR_OR_NULL(blk_desc_off)) {
		err = (blk_desc_off == NULL ? -ERANGE : PTR_ERR(blk_desc_off));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  blk, err);
		return err;
	}

	err = ssdfs_peb_reserve_block_descriptor(pebi, req);
	if (err == -EAGAIN) {
		SSDFS_DBG("try again to add block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, blk, pebi->peb_id);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to reserve block descriptor: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, blk, pebi->peb_id, err);
		return err;
	}

	err = ssdfs_peb_add_block_into_data_area(pebi, req, &data_off,
						 &written_bytes);
	if (err == -EAGAIN) {
		SSDFS_DBG("try again to add block: "
			  "seg %llu, logical_block %u, peb %llu\n",
			  req->place.start.seg_id, blk, pebi->peb_id);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to add block: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, blk, pebi->peb_id, err);
		return err;
	}

	range.start = le16_to_cpu(blk_desc_off->page_desc.peb_page);
	range.len = (written_bytes + fsi->pagesize - 1) >> fsi->log_pagesize;

	if (is_ssdfs_block_full(fsi->pagesize, written_bytes))
		range_state = SSDFS_BLK_VALID;
	else
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

	data_off.peb_page = (u16)range.start;

	err = ssdfs_peb_store_block_descriptor(pebi, req, &data_off, &desc_off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store block descriptor: "
			  "seg %llu, logical_block %u, peb %llu, err %d\n",
			  req->place.start.seg_id, blk,
			  pebi->peb_id, err);
		return err;
	}

	err = ssdfs_peb_store_block_descriptor_offset(pebi,
							(u32)logical_offset,
							blk, &desc_off);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store block descriptor offset: "
			  "err %d\n",
			  err);
		return err;
	}

	if (is_migrating) {
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
	struct ssdfs_fs_info *fsi;
	u32 rest_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !req);
#endif /* CONFIG_SSDFS_DEBUG */

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

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(req->place.start.seg_id != pebi->pebc->parent_si->seg_id);
	BUG_ON(req->place.start.blk_index >=
		pebi->pebc->parent_si->fsi->pages_per_seg);
	switch (req->private.class) {
	case SSDFS_PEB_UPDATE_REQ:
	case SSDFS_PEB_PRE_ALLOC_UPDATE_REQ:
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		/* expected case */
		break;
	default:
		BUG();
		break;
	}
	BUG_ON(req->private.type >= SSDFS_REQ_TYPE_MAX);
	BUG_ON(atomic_read(&req->private.refs_count) == 0);
	BUG_ON(req->result.processed_blks > 0);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	rest_bytes = ssdfs_request_rest_bytes(pebi, req);

	while (rest_bytes > 0) {
		u32 logical_block = req->place.start.blk_index +
					req->result.processed_blks;

		err = ssdfs_peb_update_block(pebi, req);
		if (err == -EAGAIN) {
			SSDFS_DBG("unable to update block: "
				  "seg %llu, logical_block %u, "
				  "peb %llu\n",
				  req->place.start.seg_id, logical_block,
				  pebi->peb_id);
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to update block: "
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("req %p, cmd %#x, type %#x\n",
		  req, req->private.cmd, req->private.type);

	if (req->private.cmd <= SSDFS_CREATE_CMD_MAX ||
	    req->private.cmd >= SSDFS_COLLECT_GARBAGE_CMD_MAX) {
		SSDFS_ERR("unknown create command %d, seg %llu, peb %llu\n",
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
			SSDFS_DBG("unable to update block: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to update block: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
		}
		break;

	case SSDFS_UPDATE_EXTENT:
	case SSDFS_UPDATE_PRE_ALLOC_EXTENT:
		err = ssdfs_peb_update_extent(pebi, req);
		if (err == -EAGAIN) {
			SSDFS_DBG("unable to update block: "
				  "seg %llu, peb %llu\n",
				  req->place.start.seg_id, pebi->peb_id);
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to update extent: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
		}
		break;

	case SSDFS_COMMIT_LOG_NOW:
	case SSDFS_START_MIGRATION_NOW:
		/* simply continue logic */
		break;

	case SSDFS_MIGRATE_RANGE:
		err = ssdfs_peb_update_extent(pebi, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to update extent: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
		}
		break;

	case SSDFS_MIGRATE_PRE_ALLOC_PAGE:
		err = ssdfs_peb_pre_allocate_block(pebi, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to migrate pre-alloc page: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
		}
		break;

	case SSDFS_MIGRATE_FRAGMENT:
		err = ssdfs_peb_update_block(pebi, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to migrate fragment: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
		}
		break;

	default:
		BUG();
	}

	if (unlikely(err))
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);

	return err;
}

/*
 * ssdfs_peb_has_dirty_pages() - check that PEB has dirty pages
 * @pebi: pointer on PEB object
 */
static inline
bool ssdfs_peb_has_dirty_pages(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_page_array *area_pages;
	bool is_peb_dirty = false;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, free_data_pages %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  pebi->current_log.free_data_pages);

	return pebi->current_log.free_data_pages == 0;
}

/*
 * ssdfs_reserve_segment_header() - reserve space for segment header
 * @pebi: pointer on PEB object
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
				 pgoff_t *cur_page, u32 *write_offset)
{
	struct page *page;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!cur_page || !write_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *cur_page, *write_offset);

#ifdef CONFIG_SSDFS_DEBUG
	if (*cur_page != pebi->current_log.start_page) {
		SSDFS_ERR("cur_page %lu != start_page %u\n",
			  *cur_page, pebi->current_log.start_page);
		return -EINVAL;
	}

	if (*write_offset != 0) {
		SSDFS_ERR("write_offset %u != 0\n",
			  *write_offset);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	page = ssdfs_page_array_grab_page(&pebi->cache, *cur_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to grab cache page: index %lu\n",
			  *cur_page);
		return -ENOMEM;
	}

	kaddr = kmap_atomic(page);
	/* prepare header space */
	memset(kaddr, 0xFF, PAGE_SIZE);
	kunmap_atomic(kaddr);

	unlock_page(page);
	put_page(page);

	*write_offset = offsetof(struct ssdfs_segment_header, payload);

	return 0;
}

/*
 * ssdfs_reserve_partial_log_header() - reserve space for partial log's header
 * @pebi: pointer on PEB object
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
				     pgoff_t *cur_page, u32 *write_offset)
{
	struct page *page;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!cur_page || !write_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *cur_page, *write_offset);

#ifdef CONFIG_SSDFS_DEBUG
	if (*cur_page != pebi->current_log.start_page) {
		SSDFS_ERR("cur_page %lu != start_page %u\n",
			  *cur_page, pebi->current_log.start_page);
		return -EINVAL;
	}

	if (*write_offset != 0) {
		SSDFS_ERR("write_offset %u != 0\n",
			  *write_offset);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	page = ssdfs_page_array_grab_page(&pebi->cache, *cur_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to grab cache page: index %lu\n",
			  *cur_page);
		return -ENOMEM;
	}

	kaddr = kmap_atomic(page);
	/* prepare header space */
	memset(kaddr, 0xFF, PAGE_SIZE);
	kunmap_atomic(kaddr);

	unlock_page(page);
	put_page(page);

	*write_offset = offsetof(struct ssdfs_partial_log_header, payload);

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
	BUG_ON(!desc->pvec || !desc->desc_array);
	BUG_ON(!desc->cur_page || !desc->write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  desc->pebi->pebc->parent_si->seg_id,
		  desc->pebi->peb_id,
		  desc->pebi->current_log.start_page);

	fsi = desc->pebi->pebc->parent_si->fsi;
	desc->compr_size = 0;
	desc->uncompr_size = 0;
	desc->fragments_count = 0;

	for (i = 0; i < pagevec_count(desc->pvec); i++) {
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

		src_page = desc->pvec->pages[i];

try_get_next_page:
		dst_page = ssdfs_page_array_grab_page(&desc->pebi->cache,
						      *desc->cur_page);
		if (IS_ERR_OR_NULL(dst_page)) {
			SSDFS_ERR("fail to grab cache page: index %lu\n",
				  *desc->cur_page);
			return -ENOMEM;
		}

		dst_page_off = *(desc->write_offset) % PAGE_SIZE;
		dst_free_space = PAGE_SIZE - dst_page_off;

		kaddr = kmap(dst_page);

		from.page = src_page;
		from.start_offset = 0;
		from.data_bytes = iter_bytes;
		from.sequence_id = desc->start_sequence_id + i;
		from.fragment_type = SSDFS_FRAGMENT_ZLIB_BLOB;
		from.fragment_flags = SSDFS_FRAGMENT_HAS_CSUM;

		to.area_offset = desc->area_offset;
		to.write_offset = *desc->write_offset;
		to.store = kaddr + dst_page_off;
		to.free_space = dst_free_space;
		to.compr_size = 0;
		to.desc = &desc->desc_array[i];

		/*
		 * TODO: temporary fragment flag is hardcoded as zlib fragment
		 *       It needs to get flag from feature_compat of volume_info
		 */
		err = ssdfs_peb_store_fragment(&from, &to);

		kunmap(dst_page);

		if (!err) {
			SetPagePrivate(dst_page);
			SetPageUptodate(dst_page);

			err =
			    ssdfs_page_array_set_page_dirty(&desc->pebi->cache,
							    *desc->cur_page);
			if (unlikely(err)) {
				SSDFS_ERR("fail to set page %lu dirty: "
					  "err %d\n",
					  *desc->cur_page, err);
			}
		}

		unlock_page(dst_page);
		put_page(dst_page);

		if (err == -EAGAIN) {
			SSDFS_DBG("try to get next page: "
				  "write_offset %u, dst_free_space %zu\n",
				  *desc->write_offset,
				  dst_free_space);

			*desc->write_offset += dst_free_space;
			(*desc->cur_page)++;
			goto try_get_next_page;
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to store fragment: "
				  "sequence_id %u, write_offset %u, err %d\n",
				  desc->start_sequence_id + i,
				  *desc->write_offset, err);
			return err;
		}

		desc->uncompr_size += iter_bytes;
		*desc->write_offset += to.compr_size;
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
	u16 pages_per_peb;
	struct page *page;
	pgoff_t index;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
	BUG_ON(!desc->pebi || !desc->cur_page || !desc->write_offset);
	BUG_ON(pagevec_count(&desc->snapshot) == 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_id %llu, peb_index %u, "
		  "cur_page %lu, write_offset %u\n",
		  desc->pebi->peb_id,
		  desc->pebi->peb_index,
		  *(desc->cur_page), *(desc->write_offset));

	fsi = desc->pebi->pebc->parent_si->fsi;

	allocation_size = frag_hdr_size;
	allocation_size += pagevec_count(&desc->snapshot) * frag_desc_size;

	frag_hdr = kzalloc(allocation_size, GFP_KERNEL);
	if (!frag_hdr) {
		SSDFS_ERR("unable to allocate block bmap header\n");
		return -ENOMEM;
	}

	frag_hdr_off = *(desc->write_offset);
	*(desc->write_offset) += allocation_size;

	frag_desc_array = (struct ssdfs_fragment_desc *)((u8 *)frag_hdr +
							  frag_hdr_size);

	pvec_desc.pebi = desc->pebi;
	pvec_desc.start_sequence_id = 0;
	pvec_desc.area_offset = bmap_hdr_offset;
	pvec_desc.pvec = &desc->snapshot;
	pvec_desc.bytes_count = desc->bytes_count;
	pvec_desc.desc_array = frag_desc_array;
	pvec_desc.array_capacity = SSDFS_FRAGMENTS_CHAIN_MAX;
	pvec_desc.cur_page = desc->cur_page;
	pvec_desc.write_offset = desc->write_offset;

	err = ssdfs_peb_store_pagevec(&pvec_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store block bitmap in the log: "
			  "seg %llu, peb %llu, write_offset %u, "
			  "err %d\n",
			  desc->pebi->pebc->parent_si->seg_id,
			  desc->pebi->peb_id,
			  *(desc->write_offset), err);
		goto fail_store_bmap_fragment;
	}

	frag_hdr->peb_index = cpu_to_le16(desc->peb_index);
	frag_hdr->sequence_id = cpu_to_le16(*(desc->frag_id));
	*(desc->frag_id) += 1;
	frag_hdr->flags = cpu_to_le16(desc->flags);
	frag_hdr->type = cpu_to_le16(desc->type);

	pages_per_peb = fsi->pages_per_peb;

	if (desc->last_free_blk >= pages_per_peb) {
		SSDFS_ERR("last_free_page %u >= pages_per_peb %u\n",
			  desc->last_free_blk, pages_per_peb);
		err = -ERANGE;
		goto fail_store_bmap_fragment;
	}

	frag_hdr->last_free_blk = cpu_to_le16((u16)desc->last_free_blk);

	if (desc->metadata_blks > (pages_per_peb - desc->last_free_blk)) {
		SSDFS_ERR("metadata_blks %u > used pages %u\n",
			  desc->metadata_blks,
			  (pages_per_peb - desc->last_free_blk));
		err = -ERANGE;
		goto fail_store_bmap_fragment;
	}

	frag_hdr->metadata_blks = cpu_to_le16((u16)desc->metadata_blks);

	if (desc->invalid_blks > (pages_per_peb - desc->last_free_blk)) {
		SSDFS_ERR("invalid_blks %u > used pages %u\n",
			  desc->invalid_blks,
			  (pages_per_peb - desc->last_free_blk));
		err = -ERANGE;
		goto fail_store_bmap_fragment;
	}

	frag_hdr->invalid_blks = cpu_to_le16((u16)desc->invalid_blks);

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
	WARN_ON(pvec_desc.fragments_count > SSDFS_FRAGMENTS_CHAIN_MAX);
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

	kaddr = kmap_atomic(page);
	memcpy((u8 *)kaddr + (frag_hdr_off % PAGE_SIZE),
		frag_hdr, allocation_size);
	kunmap_atomic(kaddr);

	SetPagePrivate(page);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&desc->pebi->cache, index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: "
			  "err %d\n",
			  index, err);
	}

	unlock_page(page);
	put_page(page);

fail_store_bmap_fragment:
	pagevec_release(&desc->snapshot);
	kfree(frag_hdr);
	return err;
}

/*
 * ssdfs_peb_store_dst_blk_bmap() - store destination block bitmap
 * @pebi: pointer on PEB object
 * @items_state: PEB container's items state
 * @flags: block bitmap's header flags
 * @bmap_hdr_off: offset from log's beginning to bitmap header
 * @frag_id: pointer on fragments counter [in|out]
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
				 u16 flags,
				 u32 bmap_hdr_off,
				 u16 *frag_id,
				 pgoff_t *cur_page,
				 u32 *write_offset)
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
	BUG_ON(flags & ~SSDFS_BLK_BMAP_FLAG_MASK);
	BUG_ON(!frag_id || !cur_page || !write_offset);
	BUG_ON(!rwsem_is_locked(&pebi->pebc->lock));

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_index,
		  *cur_page, *write_offset);

	desc.flags = SSDFS_PEB_HAS_RELATION | SSDFS_MIGRATING_BLK_BMAP;
	desc.type = SSDFS_DST_BLK_BMAP;
	desc.frag_id = frag_id;
	desc.cur_page = cur_page;
	desc.write_offset = write_offset;

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
	pagevec_init(&desc.snapshot);

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

	err = ssdfs_block_bmap_snapshot(bmap, &desc.snapshot,
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

	SSDFS_DBG("peb_id %llu, DST: last_free_blk %u, "
		  "metadata_blks %u, invalid_blks %u\n",
		  pebi->peb_id, desc.last_free_blk,
		  desc.metadata_blks, desc.invalid_blks);

	if (pagevec_count(&desc.snapshot) == 0) {
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
 * @flags: block bitmap's header flags
 * @bmap_hdr_off: offset from log's beginning to bitmap header
 * @frag_id: pointer on fragments counter [in|out]
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
				    u16 flags,
				    u32 bmap_hdr_off,
				    u16 *frag_id,
				    pgoff_t *cur_page,
				    u32 *write_offset)
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
	BUG_ON(flags & ~SSDFS_BLK_BMAP_FLAG_MASK);
	BUG_ON(!frag_id || !cur_page || !write_offset);
	BUG_ON(!pebi);
	BUG_ON(!rwsem_is_locked(&pebi->pebc->lock));

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_index,
		  *cur_page, *write_offset);

	desc.frag_id = frag_id;
	desc.cur_page = cur_page;
	desc.write_offset = write_offset;

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
	pagevec_init(&desc.snapshot);

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

	err = ssdfs_block_bmap_snapshot(bmap, &desc.snapshot,
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

	SSDFS_DBG("peb_id %llu, SRC: last_free_blk %u, "
		  "metadata_blks %u, invalid_blks %u\n",
		  pebi->peb_id, desc.last_free_blk,
		  desc.metadata_blks, desc.invalid_blks);

	if (pagevec_count(&desc.snapshot) == 0) {
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
 * @flags: block bitmap's header flags
 * @bmap_hdr_off: offset from log's beginning to bitmap header
 * @frag_id: pointer on fragments counter [in|out]
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
					u16 flags,
					u32 bmap_hdr_off,
					u16 *frag_id,
					pgoff_t *cur_page,
					u32 *write_offset)
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
	BUG_ON(flags & ~SSDFS_BLK_BMAP_FLAG_MASK);
	BUG_ON(!frag_id || !cur_page || !write_offset);
	BUG_ON(!rwsem_is_locked(&pebi->pebc->lock));

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_index,
		  *cur_page, *write_offset);

	desc.frag_id = frag_id;
	desc.cur_page = cur_page;
	desc.write_offset = write_offset;

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
			SSDFS_DBG("dst_peb is NULL: "
				  "peb_index %u\n",
				  i);
			continue;
		} else if (dst_peb != pebi->pebc->dst_peb)
			continue;

		peb_blkbmap = &seg_blkbmap->peb[i];
		pagevec_init(&desc.snapshot);

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

		err = ssdfs_block_bmap_snapshot(bmap, &desc.snapshot,
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

		if (pagevec_count(&desc.snapshot) == 0) {
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

		pagevec_release(&desc.snapshot);
	}

	return 0;
}

/*
 * ssdfs_peb_store_block_bmap() - store block bitmap into page cache
 * @pebi: pointer on PEB object
 * @flags: block bitmap's header flags
 * @desc: block bitmap descriptor [out]
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
				u8 flags,
				struct ssdfs_metadata_descriptor *desc,
				pgoff_t *cur_page,
				u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_block_bitmap_header *bmap_hdr = NULL;
	size_t bmap_hdr_size = sizeof(struct ssdfs_block_bitmap_header);
	int items_state;
	u16 frag_id = 0;
	u32 bmap_hdr_off;
	u16 log_start_page = 0;
	struct page *page;
	pgoff_t index;
	void *kaddr;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(flags & ~SSDFS_BLK_BMAP_FLAG_MASK);
	BUG_ON(!desc || !cur_page || !write_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_index,
		  *cur_page, *write_offset);

	fsi = pebi->pebc->parent_si->fsi;
	seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;

	bmap_hdr_off = *write_offset;
	*write_offset += bmap_hdr_size;

	items_state = atomic_read(&pebi->pebc->items_state);
	switch (items_state) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
		/* Prepare source bitmap only */
		err = ssdfs_peb_store_source_blk_bmap(pebi, items_state,
						      flags,
						      bmap_hdr_off,
						      &frag_id,
						      cur_page,
						      write_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store source bitmap: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  *cur_page, *write_offset, err);
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
						   flags,
						   bmap_hdr_off,
						   &frag_id,
						   cur_page,
						   write_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store destination bitmap: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  *cur_page, *write_offset, err);
			goto finish_store_block_bitmap;
		}

		err = ssdfs_peb_store_source_blk_bmap(pebi, items_state,
						      flags,
						      bmap_hdr_off,
						      &frag_id,
						      cur_page,
						      write_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store source bitmap: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  *cur_page, *write_offset, err);
			goto finish_store_block_bitmap;
		}

		err = ssdfs_peb_store_dependent_blk_bmap(pebi, items_state,
							 flags,
							 bmap_hdr_off,
							 &frag_id,
							 cur_page,
							 write_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store dependent bitmaps: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  *cur_page, *write_offset, err);
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
						      flags,
						      bmap_hdr_off,
						      &frag_id,
						      cur_page,
						      write_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store source bitmap: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  *cur_page, *write_offset, err);
			goto finish_store_block_bitmap;
		}

		err = ssdfs_peb_store_dependent_blk_bmap(pebi, items_state,
							 flags,
							 bmap_hdr_off,
							 &frag_id,
							 cur_page,
							 write_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to store dependent bitmaps: "
				  "cur_page %lu, write_offset %u, "
				  "err %d\n",
				  *cur_page, *write_offset, err);
			goto finish_store_block_bitmap;
		}
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		break;
	}

	if (pebi->current_log.start_page >= fsi->pages_per_peb) {
		err = -ERANGE;
		SSDFS_ERR("log_start_page %u >= pages_per_peb %u\n",
			  log_start_page, fsi->pages_per_peb);
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

	kaddr = kmap(page);

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
	BUG_ON(*write_offset <= bmap_hdr_off);
	BUG_ON(*write_offset <= (bmap_hdr_off + bmap_hdr_size));
#endif /* CONFIG_SSDFS_DEBUG */
	bmap_hdr->bytes_count = cpu_to_le32(*write_offset - bmap_hdr_off);
	desc->size = bmap_hdr->bytes_count;

	bmap_hdr->flags = flags;

	if (flags & SSDFS_BLK_BMAP_COMPRESSED) {
		/* TODO: define type -> temporary solution */
		bmap_hdr->type = SSDFS_BLK_BMAP_ZLIB_BLOB;
	} else
		bmap_hdr->type = SSDFS_BLK_BMAP_UNCOMPRESSED_BLOB;

	desc->check.bytes = cpu_to_le16(bmap_hdr_size);
	desc->check.flags = cpu_to_le16(SSDFS_CRC32);

	err = ssdfs_calculate_csum(&desc->check, bmap_hdr, bmap_hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("unable to calculate checksum: err %d\n", err);
		goto finish_bmap_hdr_preparation;
	}

	pebi->current_log.seg_flags |= SSDFS_SEG_HDR_HAS_BLK_BMAP;

finish_bmap_hdr_preparation:
	kunmap(page);

	SetPagePrivate(page);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&pebi->cache, index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page %lu dirty: "
			  "err %d\n",
			  index, err);
	}

	unlock_page(page);
	put_page(page);

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

	SSDFS_DBG("area_type %#x, write_offset %u, is_empty %d\n",
		  area_type, area->write_offset, (int)is_empty);

	return is_empty;
}

/*
 * ssdfs_peb_copy_area_pages_into_cache() - copy area pages into cache
 * @pebi: pointer on PEB object
 * @area_type: type of area
 * @desc: descriptor of metadata area
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
					 pgoff_t *cur_page,
					 u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_area *area;
	size_t blk_table_size = sizeof(struct ssdfs_area_block_table);
	struct pagevec pvec;
	struct ssdfs_page_array *smap, *dmap;
	pgoff_t page_index, end, pages_count, range_len;
	struct page *page;
	u32 area_offset, area_size;
	void *kaddr1, *kaddr2;
	u16 log_start_page;
	u32 read_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(area_type >= SSDFS_LOG_AREA_MAX);
	BUG_ON(!desc || !cur_page || !write_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];
	log_start_page = pebi->current_log.start_page;

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "area_type %#x, area->write_offset %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  area_type, area->write_offset,
		  *cur_page, *write_offset);

	if (is_peb_area_empty(pebi, area_type)) {
		SSDFS_DBG("area %#x is empty\n", area_type);
		return -ENODATA;
	}

	smap = &area->array;
	dmap = &pebi->cache;

	area_offset = *write_offset;
	area_size = area->write_offset;

	desc->offset = cpu_to_le32(area_offset +
					(log_start_page * fsi->pagesize));
	desc->size = cpu_to_le32(area_size);

	if (area->has_metadata) {
		void *kaddr;

		page = ssdfs_page_array_get_page_locked(smap, 0);
		if (IS_ERR_OR_NULL(page)) {
			SSDFS_ERR("fail to get page of area %#x\n",
				  area_type);
			return -ERANGE;
		}

		kaddr = kmap_atomic(page);
		desc->check.bytes = cpu_to_le16(blk_table_size);
		desc->check.flags = cpu_to_le16(SSDFS_CRC32);
		err = ssdfs_calculate_csum(&desc->check, kaddr, blk_table_size);
		kunmap_atomic(kaddr);
		unlock_page(page);
		put_page(page);

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
			struct page *page1 = pvec.pages[i], *page2;
			pgoff_t src_index = page1->index;
			u32 src_len, dst_len, copy_len;
			u32 src_off, dst_off;

			if (read_bytes >= area_size) {
				err = -E2BIG;
				SSDFS_ERR("too many pages: "
					  "pages_count %u, area_size %u\n",
					  pagevec_count(&pvec),
					  area_size);
				goto finish_current_copy;
			}

			src_off = 0;

try_copy_area_data:
			get_page(page1);
			lock_page(page1);

			if (*write_offset >= PAGE_SIZE)
				dst_off = *write_offset % PAGE_SIZE;
			else
				dst_off = *write_offset;

			src_len = min_t(u32, PAGE_SIZE, area_size - read_bytes);
			dst_len = min_t(u32, PAGE_SIZE, PAGE_SIZE - dst_off);
			copy_len = min_t(u32, src_len, dst_len);

			page2 = ssdfs_page_array_grab_page(dmap, *cur_page);
			if (unlikely(IS_ERR_OR_NULL(page2))) {
				err = -ENOMEM;
				SSDFS_ERR("fail to grab page: index %lu\n",
					  *cur_page);
				goto unlock_page1;
			}

			kaddr1 = kmap_atomic(page1);
			kaddr2 = kmap_atomic(page2);
			memcpy((u8 *)kaddr2 + dst_off,
				(u8 *)kaddr1 + src_off, copy_len);
			kunmap_atomic(kaddr2);
			kunmap_atomic(kaddr1);

			SSDFS_DBG("src_off %u, dst_off %u, src_len %u, "
				  "dst_len %u, copy_len %u, "
				  "write_offset %u, cur_page %lu, "
				  "page_index %d\n",
				  src_off, dst_off, src_len, dst_len, copy_len,
				  *write_offset, *cur_page, i);

			if (PageDirty(page1)) {
				err = ssdfs_page_array_set_page_dirty(dmap,
								     *cur_page);
				if (unlikely(err)) {
					SSDFS_ERR("fail to set page dirty: "
						  "page_index %lu, err %d\n",
						  *cur_page, err);
					goto unlock_page2;
				}
			} else {
				err = -ERANGE;
				SSDFS_ERR("page %d is not dirty\n", i);
				goto unlock_page2;
			}

unlock_page2:
			unlock_page(page2);
			put_page(page2);

unlock_page1:
			unlock_page(page1);
			put_page(page1);

finish_current_copy:
			if (unlikely(err)) {
				pagevec_release(&pvec);
				SSDFS_ERR("fail to copy page: "
					  " from %lu to %lu, err %d\n",
					  src_index, *cur_page, err);
				return err;
			}

			read_bytes += copy_len;
			*write_offset += copy_len;

			if ((dst_off + copy_len) >= PAGE_SIZE)
				++(*cur_page);

			if (copy_len < src_len) {
				src_off = copy_len;
				goto try_copy_area_data;
			} else {
				err = ssdfs_page_array_clear_dirty_page(smap,
								page_index + i);
				if (unlikely(err)) {
					pagevec_release(&pvec);
					SSDFS_ERR("fail to mark page clean: "
						  "page_index %lu\n",
						  page_index + i);
					return err;
				}
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
 * ssdfs_peb_move_area_pages_into_cache() - move area pages into cache
 * @pebi: pointer on PEB object
 * @area_type: type of area
 * @desc: descriptor of metadata area
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
					 pgoff_t *cur_page,
					 u32 *write_offset)
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
	BUG_ON(!desc || !cur_page || !write_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "area_type %#x, area->write_offset %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  area_type, area->write_offset,
		  *cur_page, *write_offset);

	if (is_peb_area_empty(pebi, area_type)) {
		SSDFS_DBG("area %#x is empty\n", area_type);
		return -ENODATA;
	}

	smap = &area->array;
	dmap = &pebi->cache;

	area_offset = *write_offset;
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

		kaddr = kmap_atomic(page);
		desc->check.bytes = cpu_to_le16(blk_table_size);
		desc->check.flags = cpu_to_le16(SSDFS_CRC32);
		err = ssdfs_calculate_csum(&desc->check, kaddr, blk_table_size);
		kunmap_atomic(kaddr);
		unlock_page(page);
		put_page(page);

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

			get_page(page);
			lock_page(page);

			page2 = ssdfs_page_array_delete_page(smap, src_off);
			if (IS_ERR_OR_NULL(page2)) {
				err = !page2 ? -ERANGE : PTR_ERR(page2);
				SSDFS_ERR("fail to delete page %lu: err %d\n",
					  src_off, err);
				goto finish_current_move;
			}

			WARN_ON(page2 != page);

			page->index = *cur_page;

			err = ssdfs_page_array_add_page(dmap, page, *cur_page);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add page %lu: err %d\n",
					  *cur_page, err);
				goto finish_current_move;
			}

			if (PageDirty(page)) {
				err = ssdfs_page_array_set_page_dirty(dmap,
								     *cur_page);
				if (unlikely(err)) {
					SSDFS_ERR("fail to set page dirty: "
						  "page_index %lu, err %d\n",
						  *cur_page, err);
					goto finish_current_move;
				}
			} else {
				err = -ERANGE;
				SSDFS_ERR("page %d is not dirty\n", i);
				goto finish_current_move;
			}

			pvec.pages[i] = NULL;

finish_current_move:
			unlock_page(page);
			put_page(page);

			if (unlikely(err)) {
				pagevec_release(&pvec);
				SSDFS_ERR("fail to move page: "
					  " from %lu to %lu, err %d\n",
					  src_off, *cur_page, err);
				return err;
			}

			(*cur_page)++;
			*write_offset += PAGE_SIZE;
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
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
				   pgoff_t *cur_page,
				   u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_area *area;
	int area_type = SSDFS_LOG_BLK_DESC_AREA;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!desc || !cur_page || !write_offset);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area = &pebi->current_log.area[area_type];

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "area->write_offset %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  area->write_offset,
		  *cur_page, *write_offset);

	if (is_peb_area_empty(pebi, area_type)) {
		SSDFS_DBG("area %#x is empty\n", area_type);
		return -ENODATA;
	}

	err = ssdfs_peb_store_area_block_table(pebi, area_type);
	if (unlikely(err)) {
		SSDFS_ERR("fail to store area's block table: "
			  "area %#x, err %d\n",
			  area_type, err);
		return err;
	}

	err = ssdfs_peb_copy_area_pages_into_cache(pebi, area_type, desc,
						   cur_page, write_offset);
	if (unlikely(err)) {
		SSDFS_ERR("fail to move pages in the cache: err %d\n", err);
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
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
				pgoff_t *cur_page,
				u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_log_footer *footer;
	int padding;
	u32 log_pages;
	struct page *page;
	u32 area_offset, area_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!hdr_desc || !lf_desc || !cur_segs);
	BUG_ON(!cur_page || !write_offset);
	BUG_ON(array_size != SSDFS_LOG_FOOTER_DESC_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *cur_page, *write_offset);

	fsi = pebi->pebc->parent_si->fsi;

	area_offset = *write_offset;
	area_size = sizeof(struct ssdfs_log_footer);

	*write_offset += max_t(u32, PAGE_SIZE, area_size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(flags & ~SSDFS_LOG_FOOTER_FLAG_MASK);
	BUG_ON(((*write_offset + fsi->pagesize - 1) >> fsi->log_pagesize) >
		pebi->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	log_pages = (*write_offset + fsi->pagesize - 1) / fsi->pagesize;

	padding = *cur_page % pebi->log_pages;
	padding = pebi->log_pages - padding;
	padding--;

	if (padding > 0) {
		/*
		 * Align the log_pages and log_bytes.
		 */
		log_pages += padding;
		*write_offset = log_pages * fsi->pagesize;
	}

	page = ssdfs_page_array_grab_page(&pebi->cache, *cur_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %lu\n",
			  *cur_page);
		return -ENOMEM;
	}

	footer = kmap(page);
	memset(footer, 0xFF, PAGE_SIZE);

	memcpy(footer->desc_array, lf_desc,
		array_size * sizeof(struct ssdfs_metadata_descriptor));

	err = ssdfs_prepare_volume_state_info_for_commit(fsi, SSDFS_MOUNTED_FS,
							 cur_segs,
							 cur_segs_size,
							 &footer->volume_state);

	if (!err) {
		err = ssdfs_prepare_log_footer_for_commit(fsi, log_pages,
							  flags, footer);
	}

	if (!err) {
		hdr_desc->offset = cpu_to_le32(area_offset +
				(pebi->current_log.start_page * fsi->pagesize));
		hdr_desc->size = cpu_to_le32(area_size);

		memcpy(&hdr_desc->check, &footer->volume_state.check,
			sizeof(struct ssdfs_metadata_check));
	}

	kunmap(page);

	SetPagePrivate(page);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&pebi->cache, *cur_page);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page dirty: "
			  "page_index %lu, err %d\n",
			  *cur_page, err);
	}

	unlock_page(page);
	put_page(page);

	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log footer: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		return err;
	}

	pebi->current_log.seg_flags |= SSDFS_LOG_HAS_FOOTER;

	(*cur_page)++;

	if (padding > 0)
		*cur_page += padding;

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

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
	u32 seg_flags;
	u32 log_pages;
	u16 seg_type;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!desc_array);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  write_offset);

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

	hdr = kmap(page);

	memcpy(hdr->desc_array, desc_array,
		array_size * sizeof(struct ssdfs_metadata_descriptor));

	ssdfs_create_volume_header(fsi, &hdr->volume_hdr);

	err = ssdfs_prepare_volume_header_for_commit(fsi, &hdr->volume_hdr);
	if (unlikely(err))
		goto finish_segment_header_preparation;

	err = ssdfs_store_peb_migration_id(pebi, hdr);
	if (unlikely(err))
		goto finish_segment_header_preparation;

	err = ssdfs_prepare_segment_header_for_commit(fsi,
						      log_pages,
						      seg_type,
						      seg_flags,
						      hdr);
	if (unlikely(err))
		goto finish_segment_header_preparation;

finish_segment_header_preparation:
	kunmap(page);
	unlock_page(page);
	put_page(page);

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
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(write_offset == 0);
	BUG_ON(write_offset % pebi->pebc->parent_si->fsi->pagesize);
	BUG_ON(!pebi->pebc->parent_si->fsi->devops);
	BUG_ON(!pebi->pebc->parent_si->fsi->devops->writepages);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  write_offset);

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
		u32 pagevec_capacity = PAGEVEC_SIZE * PAGE_SIZE;
		pgoff_t written_pages = 0;

		index = pebi->current_log.start_page + flushed_pages;
		end = (pgoff_t)pebi->current_log.start_page + pebi->log_pages;
		end = min_t(pgoff_t, end, (pgoff_t)(index + PAGEVEC_SIZE - 1));

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

		write_size = min_t(u32,
				   pagevec_capacity - page_start_off,
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
				lock_page(page);
				ClearPageUptodate(page);
				ClearPagePrivate(page);
				pvec.pages[i] = NULL;
				unlock_page(page);
			} else {
				lock_page(page);
				pvec.pages[i] = NULL;
				unlock_page(page);
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
				  "start %lu, end %lu, err %d\n",
				  index, end, err);
		}

		written_bytes += write_size;
		flushed_pages += written_pages - 1;

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
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
 */
static
int ssdfs_peb_commit_log_payload(struct ssdfs_peb_info *pebi,
				 struct ssdfs_metadata_descriptor *hdr_desc,
				 bool *log_has_data,
				 pgoff_t *cur_page, u32 *write_offset)
{
	struct ssdfs_metadata_descriptor *cur_hdr_desc;
	int area_type;
	u32 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!hdr_desc || !cur_page || !write_offset || !log_has_data);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *cur_page, *write_offset);

	/*
	 * TODO: currently it is used compressed flag
	 *       It needs to get flag from feature_compat of volume_info
	 */
	cur_hdr_desc = &hdr_desc[SSDFS_BLK_BMAP_INDEX];
	flags = SSDFS_BLK_BMAP_COMPRESSED;
	err = ssdfs_peb_store_block_bmap(pebi,
					 (u8)flags, cur_hdr_desc,
					 cur_page, write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store block bitmap: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   *cur_page, *write_offset, err);
		goto finish_commit_payload;
	}

	SSDFS_DBG("0001-payload: cur_page %lu, write_offset %u\n",
		  *cur_page, *write_offset);

	cur_hdr_desc = &hdr_desc[SSDFS_OFF_TABLE_INDEX];
	err = ssdfs_peb_store_offsets_table(pebi, cur_hdr_desc,
					    cur_page, write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store offsets table: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   *cur_page, *write_offset, err);
		goto finish_commit_payload;
	}

	SSDFS_DBG("0002-payload: cur_page %lu, write_offset %u\n",
		  *cur_page, *write_offset);

	area_type = SSDFS_LOG_BLK_DESC_AREA;
	cur_hdr_desc = &hdr_desc[SSDFS_AREA_TYPE2INDEX(area_type)];
	err = ssdfs_peb_store_blk_desc_table(pebi, cur_hdr_desc,
					     cur_page, write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store block descriptors table: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   *cur_page, *write_offset, err);
		goto finish_commit_payload;
	}

	SSDFS_DBG("0003-payload: cur_page %lu, write_offset %u\n",
		  *cur_page, *write_offset);

	area_type = SSDFS_LOG_DIFFS_AREA;
	cur_hdr_desc = &hdr_desc[SSDFS_AREA_TYPE2INDEX(area_type)];
	err = ssdfs_peb_copy_area_pages_into_cache(pebi,
						   area_type,
						   cur_hdr_desc,
						   cur_page,
						   write_offset);
	if (err == -ENODATA) {
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_CRIT("fail to move the area %d into PEB cache: "
			   "seg %llu, peb %llu, cur_page %lu, "
			   "write_offset %u, err %d\n",
			   area_type, pebi->pebc->parent_si->seg_id,
			   pebi->peb_id, *cur_page, *write_offset,
			   err);
		goto finish_commit_payload;
	} else
		*log_has_data = true;

	SSDFS_DBG("0004-payload: cur_page %lu, write_offset %u\n",
		  *cur_page, *write_offset);

	area_type = SSDFS_LOG_JOURNAL_AREA;
	cur_hdr_desc = &hdr_desc[SSDFS_AREA_TYPE2INDEX(area_type)];
	err = ssdfs_peb_copy_area_pages_into_cache(pebi,
						   area_type,
						   cur_hdr_desc,
						   cur_page,
						   write_offset);
	if (err == -ENODATA) {
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_CRIT("fail to move the area %d into PEB cache: "
			   "seg %llu, peb %llu, cur_page %lu, "
			   "write_offset %u, err %d\n",
			   area_type, pebi->pebc->parent_si->seg_id,
			   pebi->peb_id, *cur_page, *write_offset,
			   err);
		goto finish_commit_payload;
	} else
		*log_has_data = true;

	SSDFS_DBG("0005-payload: cur_page %lu, write_offset %u\n",
		  *cur_page, *write_offset);

	if (*write_offset % PAGE_SIZE) {
		(*cur_page)++;

		*write_offset += PAGE_SIZE - 1;
		*write_offset >>= PAGE_SHIFT;
		*write_offset <<= PAGE_SHIFT;
	}

	area_type = SSDFS_LOG_MAIN_AREA;
	cur_hdr_desc = &hdr_desc[SSDFS_AREA_TYPE2INDEX(area_type)];
	err = ssdfs_peb_move_area_pages_into_cache(pebi,
						   area_type,
						   cur_hdr_desc,
						   cur_page,
						   write_offset);
	if (err == -ENODATA) {
		err = 0;
	} else if (unlikely(err)) {
		SSDFS_CRIT("fail to move the area %d into PEB cache: "
			   "seg %llu, peb %llu, cur_page %lu, "
			   "write_offset %u, err %d\n",
			   area_type, pebi->pebc->parent_si->seg_id,
			   pebi->peb_id, *cur_page, *write_offset,
			   err);
		goto finish_commit_payload;
	} else
		*log_has_data = true;

	SSDFS_DBG("0006-payload: cur_page %lu, write_offset %u\n",
		  *cur_page, *write_offset);

finish_commit_payload:
	return err;
}

/*
 * ssdfs_peb_define_next_log_start() - define start of the next log
 * @pebi: pointer on PEB object
 * @log_strategy: strategy in log creation
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
 */
static
void ssdfs_peb_define_next_log_start(struct ssdfs_peb_info *pebi,
				     int log_strategy,
				     pgoff_t *cur_page, u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	u16 pages_diff;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!cur_page || !write_offset);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *cur_page, *write_offset);

	fsi = pebi->pebc->parent_si->fsi;

	switch (log_strategy) {
	case SSDFS_START_PARTIAL_LOG:
	case SSDFS_CONTINUE_PARTIAL_LOG:
		pebi->current_log.start_page = *cur_page;
		atomic_inc(&pebi->current_log.sequence_id);
		WARN_ON(pebi->current_log.free_data_pages == 0);
		break;

	case SSDFS_FINISH_PARTIAL_LOG:
	case SSDFS_FINISH_FULL_LOG:
		if (*cur_page % pebi->log_pages) {
			*cur_page += pebi->log_pages - 1;
			*cur_page =
			    (*cur_page / pebi->log_pages) * pebi->log_pages;
		}

		pebi->current_log.start_page = *cur_page;

		if (pebi->current_log.start_page >= fsi->pages_per_peb) {
			pebi->current_log.free_data_pages = 0;
		} else {
			pages_diff = fsi->pages_per_peb;
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
}

/*
 * ssdfs_peb_store_pl_header_like_footer() - store partial log's header
 * @pebi: pointer on PEB object
 * @flags: partial log header's flags
 * @hdr_desc: partial log header's metadata descriptor in segment header
 * @plh_desc: partial log header's metadata descriptors array
 * @array_size: count of items in array
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
				    pgoff_t *cur_page,
				    u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_partial_log_header *pl_hdr;
	u32 log_pages;
	struct page *page;
	u32 area_offset, area_size;
	u16 seg_type;
	int sequence_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!hdr_desc || !plh_desc);
	BUG_ON(!cur_page || !write_offset);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *cur_page, *write_offset);

	fsi = pebi->pebc->parent_si->fsi;
	seg_type = pebi->pebc->parent_si->seg_type;

	sequence_id = atomic_read(&pebi->current_log.sequence_id);
	if (sequence_id < 0 || sequence_id >= U8_MAX) {
		SSDFS_ERR("invalid sequence_id %d\n", sequence_id);
		return -ERANGE;
	}

	area_offset = *write_offset;
	area_size = sizeof(struct ssdfs_partial_log_header);

	*write_offset += max_t(u32, PAGE_SIZE, area_size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(((*write_offset + PAGE_SIZE - 1) >> fsi->log_pagesize) >
		pebi->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	log_pages = (*write_offset + fsi->pagesize - 1) / fsi->pagesize;

	page = ssdfs_page_array_grab_page(&pebi->cache, *cur_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %lu\n",
			  *cur_page);
		return -ENOMEM;
	}

	pl_hdr = kmap(page);
	memset(pl_hdr, 0xFF, PAGE_SIZE);

	memcpy(pl_hdr->desc_array, plh_desc,
		array_size * sizeof(struct ssdfs_metadata_descriptor));

	err = ssdfs_prepare_partial_log_header_for_commit(fsi,
							  (u8)sequence_id,
							  log_pages,
							  seg_type, flags,
							  pl_hdr);

	if (!err) {
		hdr_desc->offset = cpu_to_le32(area_offset +
				(pebi->current_log.start_page * fsi->pagesize));
		hdr_desc->size = cpu_to_le32(area_size);

		memcpy(&hdr_desc->check, &pl_hdr->check,
			sizeof(struct ssdfs_metadata_check));
	}

	kunmap(page);

	SetPagePrivate(page);
	SetPageUptodate(page);

	err = ssdfs_page_array_set_page_dirty(&pebi->cache, *cur_page);
	if (unlikely(err)) {
		SSDFS_ERR("fail to set page dirty: "
			  "page_index %lu, err %d\n",
			  *cur_page, err);
	}

	unlock_page(page);
	put_page(page);

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

	(*cur_page)++;

	return 0;
}

/*
 * ssdfs_peb_store_pl_header_like_header() - store partial log's header
 * @pebi: pointer on PEB object
 * @flags: partial log header's flags
 * @plh_desc: partial log header's metadata descriptors array
 * @array_size: count of items in array
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
				    pgoff_t *cur_page,
				    u32 *write_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_partial_log_header *pl_hdr;
	struct page *page;
	u32 seg_flags;
	u32 log_pages;
	u16 seg_type;
	int sequence_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!plh_desc);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *write_offset);

	fsi = pebi->pebc->parent_si->fsi;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(pebi->pebc->parent_si->seg_type > SSDFS_LAST_KNOWN_SEG_TYPE);
	BUG_ON(*write_offset % fsi->pagesize);
	BUG_ON((*write_offset >> fsi->log_pagesize) > pebi->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	sequence_id = atomic_read(&pebi->current_log.sequence_id);
	if (sequence_id < 0 || sequence_id >= U8_MAX) {
		SSDFS_ERR("invalid sequence_id %d\n", sequence_id);
		return -ERANGE;
	}

	seg_type = pebi->pebc->parent_si->seg_type;
	seg_flags = pebi->current_log.seg_flags;

	log_pages = (*write_offset + fsi->pagesize - 1) / fsi->pagesize;

	page = ssdfs_page_array_get_page_locked(&pebi->cache,
						pebi->current_log.start_page);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to get cache page: index %u\n",
			  pebi->current_log.start_page);
		return -ERANGE;
	}

	pl_hdr = kmap(page);

	memcpy(pl_hdr->desc_array, plh_desc,
		array_size * sizeof(struct ssdfs_metadata_descriptor));

	err = ssdfs_prepare_partial_log_header_for_commit(fsi,
							  (u8)sequence_id,
							  log_pages,
							  seg_type,
							  flags | seg_flags,
							  pl_hdr);
	if (unlikely(err))
		goto finish_pl_header_preparation;

finish_pl_header_preparation:
	kunmap(page);
	unlock_page(page);
	put_page(page);

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
 * @cur_page: pointer on current page value [in|out]
 * @write_offset: pointer on write offset value [in|out]
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
				    pgoff_t *cur_page,
				    u32 *write_offset)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!plh_desc);
	BUG_ON(!cur_page || !write_offset);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u, "
		  "cur_page %lu, write_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page,
		  *cur_page, *write_offset);

	if (hdr_desc) {
		return ssdfs_peb_store_pl_header_like_footer(pebi, flags,
							     hdr_desc,
							     plh_desc,
							     array_size,
							     cur_page,
							     write_offset);
	} else {
		return ssdfs_peb_store_pl_header_like_header(pebi, flags,
							     plh_desc,
							     array_size,
							     cur_page,
							     write_offset);
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
	pgoff_t cur_page = pebi->current_log.start_page;
	u32 write_offset = 0;
	bool log_has_data = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);

	memset(hdr_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);
	memset(plh_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);

	SSDFS_DBG("0001: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_reserve_segment_header(pebi, &cur_page, &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to reserve segment header: "
			   "seg %llu, peb %llu, err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0002: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_commit_log_payload(pebi, hdr_desc, &log_has_data,
					   &cur_page, &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to commit payload: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   cur_page, write_offset, err);
		goto finish_commit_log;
	}

	if (!log_has_data) {
		SSDFS_DBG("current log hasn't data: start_page %u\n",
			  pebi->current_log.start_page);
		goto define_next_log_start;
	}

	SSDFS_DBG("0003: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	cur_hdr_desc = &hdr_desc[SSDFS_LOG_FOOTER_INDEX];
	flags = SSDFS_LOG_IS_PARTIAL |
		SSDFS_LOG_HAS_PARTIAL_HEADER |
		SSDFS_PARTIAL_HEADER_INSTEAD_FOOTER;
	err = ssdfs_peb_store_partial_log_header(pebi, flags, cur_hdr_desc,
						 plh_desc,
						 SSDFS_SEG_HDR_DESC_MAX,
						 &cur_page,
						 &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's partial header: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   cur_page, write_offset, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0004: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_store_log_header(pebi, hdr_desc,
					 SSDFS_SEG_HDR_DESC_MAX,
					 write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's header: "
			   "seg %llu, peb %llu, write_offset %u,"
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   write_offset, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0005: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_flush_current_log_dirty_pages(pebi, write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to flush current log: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0006: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

define_next_log_start:
	ssdfs_peb_define_next_log_start(pebi, SSDFS_START_PARTIAL_LOG,
					&cur_page, &write_offset);

	SSDFS_DBG("0007: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	pebi->current_log.reserved_pages = 0;
	pebi->current_log.seg_flags = 0;

	ssdfs_peb_set_current_log_state(pebi, SSDFS_LOG_COMMITTED);

	SSDFS_DBG("log commited: seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

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
	pgoff_t cur_page = pebi->current_log.start_page;
	u32 write_offset = 0;
	bool log_has_data = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);

	memset(plh_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);

	SSDFS_DBG("0001: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_reserve_partial_log_header(pebi, &cur_page, &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to reserve partial log's header: "
			   "seg %llu, peb %llu, err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0002: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_commit_log_payload(pebi, plh_desc, &log_has_data,
					   &cur_page, &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to commit payload: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   cur_page, write_offset, err);
		goto finish_commit_log;
	}

	if (!log_has_data) {
		SSDFS_DBG("current log hasn't data: start_page %u\n",
			  pebi->current_log.start_page);
		goto define_next_log_start;
	}

	flags = SSDFS_LOG_IS_PARTIAL |
		SSDFS_LOG_HAS_PARTIAL_HEADER;
	err = ssdfs_peb_store_partial_log_header(pebi, flags, NULL,
						 plh_desc,
						 SSDFS_SEG_HDR_DESC_MAX,
						 &cur_page,
						 &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's partial header: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   cur_page, write_offset, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0003: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_flush_current_log_dirty_pages(pebi, write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to flush current log: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0004: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

define_next_log_start:
	ssdfs_peb_define_next_log_start(pebi, SSDFS_CONTINUE_PARTIAL_LOG,
					&cur_page, &write_offset);

	SSDFS_DBG("0005: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	pebi->current_log.reserved_pages = 0;
	pebi->current_log.seg_flags = 0;

	ssdfs_peb_set_current_log_state(pebi, SSDFS_LOG_COMMITTED);

	SSDFS_DBG("log commited: seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

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
	pgoff_t cur_page = pebi->current_log.start_page;
	u32 write_offset = 0;
	bool log_has_data = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);

	memset(plh_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);
	memset(lf_desc, 0, desc_size * SSDFS_LOG_FOOTER_DESC_MAX);

	SSDFS_DBG("0001: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_reserve_partial_log_header(pebi, &cur_page, &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to reserve partial log's header: "
			   "seg %llu, peb %llu, err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0002: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_commit_log_payload(pebi, plh_desc, &log_has_data,
					   &cur_page, &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to commit payload: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   cur_page, write_offset, err);
		goto finish_commit_log;
	}

	if (!log_has_data) {
		SSDFS_DBG("current log hasn't data: start_page %u\n",
			  pebi->current_log.start_page);
		goto define_next_log_start;
	}

	SSDFS_DBG("0003: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	if ((cur_page % pebi->log_pages) == 0) {
		/*
		 * There is no space for log footer.
		 * So, full log will be without footer.
		 */
		flags = SSDFS_LOG_IS_PARTIAL |
			SSDFS_LOG_HAS_PARTIAL_HEADER;
	} else {
		cur_hdr_desc = &plh_desc[SSDFS_LOG_FOOTER_INDEX];
		flags = SSDFS_PARTIAL_LOG_FOOTER | SSDFS_ENDING_LOG_FOOTER;
		err = ssdfs_peb_store_log_footer(pebi, flags, cur_hdr_desc,
						 lf_desc,
						 SSDFS_LOG_FOOTER_DESC_MAX,
						 cur_segs, cur_segs_size,
						 &cur_page,
						 &write_offset);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to store log's footer: "
				   "seg %llu, peb %llu, cur_page %lu, "
				   "write_offset %u, err %d\n",
				   pebi->pebc->parent_si->seg_id,
				   pebi->peb_id,
				   cur_page, write_offset, err);
			goto finish_commit_log;
		}

		flags = SSDFS_LOG_IS_PARTIAL |
			SSDFS_LOG_HAS_PARTIAL_HEADER |
			SSDFS_LOG_HAS_FOOTER;
	}

	SSDFS_DBG("0004: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_store_partial_log_header(pebi, flags, NULL,
						 plh_desc,
						 SSDFS_SEG_HDR_DESC_MAX,
						 &cur_page,
						 &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's partial header: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   cur_page, write_offset, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0005: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_flush_current_log_dirty_pages(pebi, write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to flush current log: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0006: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

define_next_log_start:
	ssdfs_peb_define_next_log_start(pebi, SSDFS_FINISH_PARTIAL_LOG,
					&cur_page, &write_offset);

	SSDFS_DBG("0007: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	pebi->current_log.reserved_pages = 0;
	pebi->current_log.seg_flags = 0;

	ssdfs_peb_set_current_log_state(pebi, SSDFS_LOG_COMMITTED);

	SSDFS_DBG("log commited: seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

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
	struct ssdfs_metadata_descriptor lf_desc[SSDFS_LOG_FOOTER_DESC_MAX];
	struct ssdfs_metadata_descriptor *cur_hdr_desc;
	u32 flags;
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	pgoff_t cur_page = pebi->current_log.start_page;
	u32 write_offset = 0;
	bool log_has_data = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!pebi->pebc->parent_si || !pebi->pebc->parent_si->fsi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);

	memset(hdr_desc, 0, desc_size * SSDFS_SEG_HDR_DESC_MAX);
	memset(lf_desc, 0, desc_size * SSDFS_LOG_FOOTER_DESC_MAX);

	SSDFS_DBG("0001: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_reserve_segment_header(pebi, &cur_page, &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to reserve segment header: "
			   "seg %llu, peb %llu, err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0002: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_commit_log_payload(pebi, hdr_desc, &log_has_data,
					   &cur_page, &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to commit payload: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   cur_page, write_offset, err);
		goto finish_commit_log;
	}

	if (!log_has_data) {
		SSDFS_DBG("current log hasn't data: start_page %u\n",
			  pebi->current_log.start_page);
		goto define_next_log_start;
	}

	SSDFS_DBG("0003: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	cur_hdr_desc = &hdr_desc[SSDFS_LOG_FOOTER_INDEX];
	flags = 0;
	err = ssdfs_peb_store_log_footer(pebi, flags, cur_hdr_desc,
					   lf_desc,
					   SSDFS_LOG_FOOTER_DESC_MAX,
					   cur_segs, cur_segs_size,
					   &cur_page,
					   &write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's footer: "
			   "seg %llu, peb %llu, cur_page %lu, write_offset %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   cur_page, write_offset, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0004: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_store_log_header(pebi, hdr_desc,
					 SSDFS_SEG_HDR_DESC_MAX,
					 write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to store log's header: "
			   "seg %llu, peb %llu, write_offset %u,"
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   write_offset, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0005: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	err = ssdfs_peb_flush_current_log_dirty_pages(pebi, write_offset);
	if (unlikely(err)) {
		SSDFS_CRIT("fail to flush current log: "
			   "seg %llu, peb %llu, current_log.start_page %u, "
			   "err %d\n",
			   pebi->pebc->parent_si->seg_id, pebi->peb_id,
			   pebi->current_log.start_page, err);
		goto finish_commit_log;
	}

	SSDFS_DBG("0006: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

define_next_log_start:
	ssdfs_peb_define_next_log_start(pebi, SSDFS_FINISH_FULL_LOG,
					&cur_page, &write_offset);

	SSDFS_DBG("0007: cur_page %lu, write_offset %u\n",
		  cur_page, write_offset);

	pebi->current_log.reserved_pages = 0;
	pebi->current_log.seg_flags = 0;

	ssdfs_peb_set_current_log_state(pebi, SSDFS_LOG_COMMITTED);

	SSDFS_DBG("log commited: seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

finish_commit_log:
	return err;
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
	int log_state;
	int log_strategy;
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

	SSDFS_DBG("seg %llu, peb %llu, current_log.start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->current_log.start_page);

	log_strategy = is_log_partial(pebi);

	switch (log_strategy) {
	case SSDFS_START_FULL_LOG:
		SSDFS_CRIT("log contains nothing: "
			   "seg %llu, peb %llu, free_data_pages %u\n",
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

	return 0;
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %d\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

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

	SSDFS_DBG("peb_free_pages %d\n", peb_free_pages);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %d, found_peb_index %d\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  found_peb_index);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %d\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

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

/* TODO: it needs to call put_page() for all pages of all areas after log flushing */

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
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("req %p, cmd %#x, type %#x, err %d\n",
		  req, req->private.cmd, req->private.type, err);

	pagesize = pebc->parent_si->fsi->pagesize;
	processed_bytes_max = req->result.processed_blks * pagesize;

	if (req->extent.data_bytes > processed_bytes_max) {
		SSDFS_WARN("data_bytes %u > processed_bytes_max %u\n",
			   req->extent.data_bytes,
			   processed_bytes_max);
	}

	req->result.err = err;

	if (err) {
		SSDFS_DBG("failure: req %p, err %d\n", req, err);
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);
	} else
		atomic_set(&req->result.state, SSDFS_REQ_FINISHED);

	switch (req->private.type) {
	case SSDFS_REQ_SYNC:
		complete(&req->result.wait);
		wake_up_all(&req->private.wait_queue);
		break;

	case SSDFS_REQ_ASYNC:
		complete(&req->result.wait);

		ssdfs_put_request(req);
		if (atomic_read(&req->private.refs_count) != 0) {
			err = wait_event_killable(*wait,
			    atomic_read(&req->private.refs_count) == 0);
			WARN_ON(err != 0);
		}

		wake_up_all(&req->private.wait_queue);

		for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
			struct page *page = req->result.pvec.pages[i];

			if (PageLocked(page))
				unlock_page(page);
			else
				SSDFS_WARN("page %d is not locked\n", i);

			if (PageWriteback(page))
				end_page_writeback(page);
			else {
				SSDFS_WARN("page %d is not under writeback\n",
					   i);
			}
		}

		ssdfs_request_free(req);
		break;

	case SSDFS_REQ_ASYNC_NO_FREE:
		complete(&req->result.wait);

		ssdfs_put_request(req);
		if (atomic_read(&req->private.refs_count) != 0) {
			err = wait_event_killable(*wait,
			    atomic_read(&req->private.refs_count) == 0);
			WARN_ON(err != 0);
		}

		wake_up_all(&req->private.wait_queue);

		for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
			struct page *page = req->result.pvec.pages[i];

			if (PageLocked(page))
				unlock_page(page);
			else
				SSDFS_WARN("page %d is not locked\n", i);

			if (PageWriteback(page))
				end_page_writeback(page);
			else {
				SSDFS_WARN("page %d is not under writeback\n",
					   i);
			}
		}
		break;

	default:
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("req %p, cmd %#x, type %#x, err %d\n",
		  req, req->private.cmd, req->private.type, err);

	if (!err) {
		WARN_ON(pagevec_count(&req->result.pvec) != 0);
		pagevec_release(&req->result.pvec);
	}

	if (err == -EAGAIN) {
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("req %p, cmd %#x, type %#x, err %d\n",
		  req, req->private.cmd, req->private.type, err);

	if (!err) {
		for (i = 0; i < req->result.processed_blks; i++)
			ssdfs_peb_mark_request_block_uptodate(pebc, req, i);
	}

	if (err == -EAGAIN) {
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("req %p, cmd %#x, type %#x, err %d\n",
		  req, req->private.cmd, req->private.type, err);

	if (!err) {
		for (i = 0; i < req->result.processed_blks; i++)
			ssdfs_peb_mark_request_block_uptodate(pebc, req, i);
	}

	/* TODO: check necessity to do this here */
	/*atomic_add(req->result.processed_blks,
			&pebi->pebc->parent_si->invalid_pages);*/

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
	WARN_ON(!req);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("req %p, cmd %#x, type %#x, err %d\n",
		  req, req->private.cmd, req->private.type, err);

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
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		ssdfs_finish_update_request(pebc, req, wait, err);
		break;

	default:
		BUG();
	};
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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id);

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id);

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
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!is_ssdfs_peb_current_log_locked(pebi));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_index);

	if (ssdfs_peb_has_dirty_pages(pebi)) {
		/*
		 * TODO: if we have unfinished log then
		 * it needs to close and to commit
		 * aggregated small log
		 */
		err = ssdfs_peb_commit_log(pebi, cur_segs, size);
		if (unlikely(err)) {
			SSDFS_CRIT("fail to commit log: "
				   "seg %llu, peb_index %u, err %d\n",
				   pebi->pebc->parent_si->seg_id,
				   pebi->peb_index, err);

			ssdfs_peb_clear_current_log_pages(pebi);
			ssdfs_peb_clear_cache_dirty_pages(pebi);
		}

		SSDFS_WARN("PEB has dirty pages: "
			   "seg %llu, peb_index %u\n",
			   pebi->pebc->parent_si->seg_id,
			   pebi->peb_index);
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
		prepare_to_wait(&pebc->parent_si->migration.wait,
				&wait,
				TASK_UNINTERRUPTIBLE);
		schedule();
		finish_wait(&pebc->parent_si->migration.wait,
			    &wait);
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
	u16 pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi);
	BUG_ON(!mutex_is_locked(&pebi->current_log.lock));
#endif /* CONFIG_SSDFS_DEBUG */

	start_page = pebi->current_log.start_page;
	pages_per_peb = fsi->pages_per_peb;

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

	SSDFS_DBG("seg_id %llu, peb_id %llu, start_page %u, "
		  "pages_per_peb %u, is_exhausted %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, start_page,
		  pages_per_peb, is_exhausted);

	return is_exhausted;
}

static inline
bool is_ssdfs_peb_ready_to_exhaust(struct ssdfs_fs_info *fsi,
				   struct ssdfs_peb_info *pebi)
{
	bool is_ready_to_exhaust = false;
	u16 start_page;
	u16 pages_per_peb;
	u16 free_data_pages;
	u16 reserved_pages;
	u16 min_partial_log_pages;
	int empty_pages;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!mutex_is_locked(&pebi->current_log.lock));
#endif /* CONFIG_SSDFS_DEBUG */

	start_page = pebi->current_log.start_page;
	pages_per_peb = fsi->pages_per_peb;
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

	SSDFS_DBG("seg_id %llu, peb_id %llu, free_data_pages %u, "
		  "reserved_pages %u, min_partial_log_pages %u, "
		  "is_ready_to_exhaust %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, free_data_pages,
		  reserved_pages, min_partial_log_pages,
		  is_ready_to_exhaust);

	return is_ready_to_exhaust;
}

static inline
bool ssdfs_peb_has_partial_empty_log(struct ssdfs_fs_info *fsi,
				     struct ssdfs_peb_info *pebi)
{
	bool has_partial_empty_log = false;
	u16 start_page;
	u16 pages_per_peb;
	u16 log_pages;
	int empty_pages;
	u16 min_partial_log_pages;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi);
	BUG_ON(!mutex_is_locked(&pebi->current_log.lock));
#endif /* CONFIG_SSDFS_DEBUG */

	start_page = pebi->current_log.start_page;
	pages_per_peb = fsi->pages_per_peb;
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

	SSDFS_DBG("seg_id %llu, peb_id %llu, start_page %u, "
		  "pages_per_peb %u, log_pages %u, "
		  "min_partial_log_pages %u, "
		  "has_partial_empty_log %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, start_page,
		  pages_per_peb, log_pages,
		  min_partial_log_pages,
		  has_partial_empty_log);

	return has_partial_empty_log;
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
	SSDFS_FLUSH_THREAD_START_MIGRATION_NOW,
	SSDFS_FLUSH_THREAD_COMMIT_LOG,
	SSDFS_FLUSH_THREAD_DELEGATE_CREATE_ROLE,
};

#define FLUSH_THREAD_WAKE_CONDITION(pebc) \
	(kthread_should_stop() || have_flush_requests(pebc))

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
	struct ssdfs_fs_info *fsi = pebc->parent_si->fsi;
	wait_queue_head_t *wait_queue;
	struct ssdfs_segment_request *req;
	struct ssdfs_peb_info *pebi = NULL;
	int state;
	int thread_state = SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
	__le64 cur_segs[SSDFS_CUR_SEGS_COUNT];
	size_t size = sizeof(__le64) * SSDFS_CUR_SEGS_COUNT;
	bool is_peb_exhausted = false;
	bool is_peb_ready_to_exhaust = false;
	bool has_partial_empty_log = false;
	bool skip_finish_flush_request = false;
	bool need_create_log = true;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("flush thread: seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	wait_queue = &pebc->parent_si->wait_queue[SSDFS_PEB_FLUSH_THREAD];

repeat:
	if (err)
		thread_state = SSDFS_FLUSH_THREAD_ERROR;

	if (thread_state != SSDFS_FLUSH_THREAD_ERROR &&
	    thread_state != SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT) {
		if (fsi->sb->s_flags & SB_RDONLY)
			thread_state = SSDFS_FLUSH_THREAD_RO_STATE;
	}

next_partial_step:
	switch (thread_state) {
	case SSDFS_FLUSH_THREAD_ERROR:
		BUG_ON(err == 0);
		SSDFS_DBG("[FLUSH THREAD STATE] ERROR\n");
		SSDFS_DBG("thread after-error state: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id, pebc->peb_index, err);

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
			return err;
		} else
			goto sleep_flush_thread;
		break;

	case SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT:
		SSDFS_DBG("[FLUSH THREAD STATE] FREE SPACE ABSENT\n");

		if (is_peb_joined_into_create_requests_queue(pebc)) {
			err = ssdfs_peb_find_next_log_creation_thread(pebc);
			if (err == -ENOSPC)
				err = 0;
			else if (unlikely(err)) {
				SSDFS_WARN("fail to delegate log creation role:"
					   " seg %llu, peb_index %u, err %d\n",
					   pebc->parent_si->seg_id,
					   pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
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
			err = 0;

			if (is_peb_under_migration(pebc)) {
				err = ssdfs_peb_finish_migration(pebc);
				if (unlikely(err))
					goto finish_process_free_space_absence;
			}

			err = ssdfs_peb_start_migration(pebc);
			if (unlikely(err))
				goto finish_process_free_space_absence;

			pebi = ssdfs_get_current_peb_locked(pebc);
			if (IS_ERR_OR_NULL(pebi)) {
				err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
				SSDFS_ERR("fail to get PEB object: "
					  "seg %llu, peb_index %u, err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto finish_process_free_space_absence;
			}

			err = ssdfs_peb_container_change_state(pebc);
			ssdfs_unlock_current_peb(pebc);

finish_process_free_space_absence:
			if (unlikely(err)) {
				SSDFS_WARN("fail to start PEB's migration: "
					   "seg %llu, peb_index %u, err %d\n",
					   pebc->parent_si->seg_id,
					   pebc->peb_index, err);
			       ssdfs_requests_queue_remove_all(&pebc->update_rq,
								-ENOSPC);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			thread_state = SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
			goto next_partial_step;
		} else if (have_flush_requests(pebc)) {
			ssdfs_requests_queue_remove_all(&pebc->update_rq,
							-ENOSPC);
		}

		goto check_necessity_to_stop_thread;
		break;

	case SSDFS_FLUSH_THREAD_RO_STATE:
		SSDFS_DBG("[FLUSH THREAD STATE] READ-ONLY STATE\n");

		err = ssdfs_prepare_current_segment_ids(fsi, cur_segs, size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare current segments IDs: "
				  "err %d\n",
				  err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		if (!(fsi->sb->s_flags & SB_RDONLY)) {
			/*
			 * File system state was changed.
			 * Now file system has RW state.
			 */
			if (fsi->fs_state == SSDFS_ERROR_FS) {
				ssdfs_peb_current_log_lock(pebi);
				if (ssdfs_peb_has_dirty_pages(pebi))
					ssdfs_peb_clear_current_log_pages(pebi);
				ssdfs_peb_current_log_unlock(pebi);
				ssdfs_unlock_current_peb(pebc);
				goto check_necessity_to_stop_thread;
			} else {
				state = ssdfs_peb_get_current_log_state(pebc);
				if (state <= SSDFS_LOG_UNKNOWN ||
				    state >= SSDFS_LOG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_WARN("invalid log state: "
						   "state %#x\n",
						   state);
					ssdfs_unlock_current_peb(pebc);
					goto repeat;
				}

				if (state != SSDFS_LOG_CREATED) {
					thread_state =
					    SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
					ssdfs_unlock_current_peb(pebc);
					goto next_partial_step;
				}

				thread_state =
					SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
				ssdfs_unlock_current_peb(pebc);
				goto repeat;
			}
		}

		ssdfs_peb_current_log_lock(pebi);
		if (ssdfs_peb_has_dirty_pages(pebi)) {
			if (fsi->fs_state == SSDFS_ERROR_FS)
				ssdfs_peb_clear_current_log_pages(pebi);
			else {
				err = ssdfs_peb_commit_log(pebi,
							   cur_segs, size);
				if (unlikely(err)) {
					SSDFS_CRIT("fail to commit log: "
						   "seg %llu, peb_index %u, "
						   "err %d\n",
						   pebc->parent_si->seg_id,
						   pebc->peb_index,
						   err);
					ssdfs_peb_clear_current_log_pages(pebi);
					ssdfs_peb_clear_cache_dirty_pages(pebi);
					thread_state = SSDFS_FLUSH_THREAD_ERROR;
				}
			}
		}
		ssdfs_peb_current_log_unlock(pebi);

		if (!err) {
			err = ssdfs_peb_container_change_state(pebc);
			if (unlikely(err)) {
				SSDFS_CRIT("fail to change peb state: "
					  "err %d\n", err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
			}
		}

		ssdfs_unlock_current_peb(pebc);

		goto check_necessity_to_stop_thread;
		break;

	case SSDFS_FLUSH_THREAD_NEED_CREATE_LOG:
		SSDFS_DBG("[FLUSH THREAD STATE] NEED CREATE LOG\n");

		if (fsi->sb->s_flags & SB_RDONLY) {
			thread_state = SSDFS_FLUSH_THREAD_RO_STATE;
			goto repeat;
		}

		if (kthread_should_stop()) {
			if (have_flush_requests(pebc)) {
				SSDFS_WARN("discovered unprocessed requests: "
					   "seg %llu, peb_index %u\n",
					   pebc->parent_si->seg_id,
					   pebc->peb_index);
			} else {
				thread_state =
				    SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
				goto repeat;
			}
		}

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		ssdfs_peb_current_log_lock(pebi);
		need_create_log = ssdfs_peb_has_dirty_pages(pebi) ||
					have_flush_requests(pebc);
		is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
		ssdfs_peb_current_log_unlock(pebi);

		if (!need_create_log) {
			ssdfs_unlock_current_peb(pebc);
			thread_state = SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
			goto sleep_flush_thread;
		}

		if (is_peb_exhausted) {
			ssdfs_unlock_current_peb(pebc);

			if (is_ssdfs_maptbl_under_flush(fsi)) {
				if (have_flush_requests(pebc)) {
					SSDFS_ERR("maptbl is flushing: "
						  "unprocessed requests\n");
					BUG();
				} else {
					SSDFS_ERR("maptbl is flushing\n");
					thread_state =
					    SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
					goto sleep_flush_thread;
				}
			}

			if (is_peb_under_migration(pebc)) {
				err = ssdfs_peb_finish_migration(pebc);
				if (unlikely(err)) {
					SSDFS_ERR("fail to finish migration: "
						  "seg %llu, peb_index %u, "
						  "err %d\n",
						  pebc->parent_si->seg_id,
						  pebc->peb_index, err);
					thread_state = SSDFS_FLUSH_THREAD_ERROR;
					goto repeat;
				}
			}

			if (!has_peb_migration_done(pebc)) {
				SSDFS_ERR("migration is not finished: "
					  "seg %llu, peb_index %u, "
					  "err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			err = ssdfs_peb_start_migration(pebc);
			if (unlikely(err)) {
				SSDFS_ERR("fail to start migration: "
					  "seg %llu, peb_index %u, "
					  "err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			pebi = ssdfs_get_current_peb_locked(pebc);
			if (IS_ERR_OR_NULL(pebi)) {
				err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
				SSDFS_ERR("fail to get PEB object: "
					  "seg %llu, peb_index %u, err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			err = ssdfs_peb_container_change_state(pebc);
			if (unlikely(err)) {
				ssdfs_unlock_current_peb(pebc);
				SSDFS_ERR("fail to change peb state: "
					  "err %d\n", err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}
		}

		if (is_peb_under_migration(pebc) &&
		    has_peb_migration_done(pebc)) {
			ssdfs_unlock_current_peb(pebc);

			err = ssdfs_peb_finish_migration(pebc);
			if (unlikely(err)) {
				SSDFS_ERR("fail to finish migration: "
					  "seg %llu, peb_index %u, "
					  "err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			pebi = ssdfs_get_current_peb_locked(pebc);
			if (IS_ERR_OR_NULL(pebi)) {
				err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
				SSDFS_ERR("fail to get PEB object: "
					  "seg %llu, peb_index %u, err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			err = ssdfs_peb_container_change_state(pebc);
			if (unlikely(err)) {
				ssdfs_unlock_current_peb(pebc);
				SSDFS_ERR("fail to change peb state: "
					  "err %d\n", err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}
		}

		err = ssdfs_peb_create_log(pebi);
		ssdfs_unlock_current_peb(pebc);

		if (err == -EAGAIN) {
			if (kthread_should_stop())
				goto fail_create_log;
			else {
				err = 0;
				goto sleep_flush_thread;
			}
		} else if (err == -ENOSPC) {
			err = 0;
			SSDFS_DBG("PEB hasn't free space: "
				  "seg %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
			thread_state = SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT;
		} else if (unlikely(err)) {
fail_create_log:
			SSDFS_CRIT("fail to create log: "
				   "seg %llu, peb_index %u, err %d\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index, err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
		} else
			thread_state = SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
		goto repeat;
		break;

	case SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION:
		SSDFS_DBG("[FLUSH THREAD STATE] CHECK NECESSITY TO STOP\n");

		if (kthread_should_stop()) {
			if (have_flush_requests(pebc)) {
				state = ssdfs_peb_get_current_log_state(pebc);
				if (state <= SSDFS_LOG_UNKNOWN ||
				    state >= SSDFS_LOG_STATE_MAX) {
					err = -ERANGE;
					SSDFS_WARN("invalid log state: "
						   "state %#x\n",
						   state);
					goto repeat;
				}

				if (state != SSDFS_LOG_CREATED) {
					thread_state =
					    SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
					goto next_partial_step;
				} else
					goto process_flush_requests;
			}

			err = ssdfs_prepare_current_segment_ids(fsi,
								cur_segs,
								size);
			if (unlikely(err)) {
				SSDFS_ERR("fail to prepare current seg IDs: "
					  "err %d\n",
					  err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			pebi = ssdfs_get_current_peb_locked(pebc);
			if (IS_ERR_OR_NULL(pebi)) {
				err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
				SSDFS_ERR("fail to get PEB object: "
					  "seg %llu, peb_index %u, err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			ssdfs_peb_current_log_lock(pebi);
			err = ssdfs_peb_commit_log_on_thread_stop(pebi,
								  cur_segs,
								  size);
			ssdfs_peb_current_log_unlock(pebi);

			if (unlikely(err)) {
				SSDFS_CRIT("fail to commit log: "
					   "seg %llu, peb_index %u, err %d\n",
					   pebc->parent_si->seg_id,
					   pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
			}

			ssdfs_unlock_current_peb(pebc);

			goto stop_flush_thread;
		} else {
process_flush_requests:
			state = ssdfs_peb_get_current_log_state(pebc);
			if (state <= SSDFS_LOG_UNKNOWN ||
			    state >= SSDFS_LOG_STATE_MAX) {
				err = -ERANGE;
				SSDFS_WARN("invalid log state: "
					   "state %#x\n",
					   state);
				goto repeat;
			}

			if (state != SSDFS_LOG_CREATED) {
				thread_state =
					SSDFS_FLUSH_THREAD_NEED_CREATE_LOG;
			} else {
				thread_state =
					SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
			}
			goto repeat;
		}
		break;

	case SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST:
		SSDFS_DBG("[FLUSH THREAD STATE] GET CREATE REQUEST\n");

		if (!have_flush_requests(pebc)) {
			thread_state = SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
			if (kthread_should_stop())
				goto repeat;
			else
				goto sleep_flush_thread;
		}

		if (!is_peb_joined_into_create_requests_queue(pebc) ||
		    is_create_requests_queue_empty(pebc)) {
			thread_state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
			goto repeat;
		}

		spin_lock(&pebc->crq_ptr_lock);
		err = ssdfs_requests_queue_remove_first(pebc->create_rq, &req);
		spin_unlock(&pebc->crq_ptr_lock);

		if (err == -ENODATA) {
			SSDFS_DBG("empty create queue\n");
			err = 0;
			thread_state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
			goto repeat;
		} else if (err == -ENOENT) {
			SSDFS_WARN("request queue contains NULL request\n");
			err = 0;
			thread_state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
			goto repeat;
		} else if (unlikely(err < 0)) {
			SSDFS_CRIT("fail to get request from create queue: "
				   "err %d\n",
				   err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		thread_state = SSDFS_FLUSH_THREAD_PROCESS_CREATE_REQUEST;
		goto next_partial_step;
		break;

	case SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST:
		SSDFS_DBG("[FLUSH THREAD STATE] GET UPDATE REQUEST\n");

		if (is_ssdfs_requests_queue_empty(&pebc->update_rq)) {
			thread_state = SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
			goto sleep_flush_thread;
		}

		err = ssdfs_requests_queue_remove_first(&pebc->update_rq, &req);
		if (err == -ENODATA) {
			SSDFS_DBG("empty update queue\n");
			err = 0;
			thread_state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
			goto repeat;
		} else if (err == -ENOENT) {
			SSDFS_WARN("request queue contains NULL request\n");
			err = 0;
			thread_state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
			goto repeat;
		} else if (unlikely(err < 0)) {
			SSDFS_CRIT("fail to get request from update queue: "
				   "err %d\n",
				   err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		thread_state = SSDFS_FLUSH_THREAD_PROCESS_UPDATE_REQUEST;
		goto next_partial_step;
		break;

	case SSDFS_FLUSH_THREAD_PROCESS_CREATE_REQUEST:
		SSDFS_DBG("[FLUSH THREAD STATE] PROCESS CREATE REQUEST\n");

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		ssdfs_peb_current_log_lock(pebi);

		err = ssdfs_process_create_request(pebi, req);
		if (err == -ENOSPC) {
			SSDFS_DBG("unable to process create request: "
				  "seg %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
			ssdfs_finish_flush_request(pebc, req, wait_queue, err);
			thread_state = SSDFS_FLUSH_THREAD_FREE_SPACE_ABSENT;
			goto finish_create_request_processing;
		} else if (err == -EAGAIN) {
			err = 0;
			SSDFS_DBG("unable to process create request : "
				  "seg %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
			req->result.processed_blks = 0;
			spin_lock(&pebc->crq_ptr_lock);
			ssdfs_requests_queue_add_head(pebc->create_rq, req);
			spin_unlock(&pebc->crq_ptr_lock);
			req = NULL;
			skip_finish_flush_request = true;
			thread_state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_create_request_processing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to process create request: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			ssdfs_finish_flush_request(pebc, req, wait_queue, err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto finish_create_request_processing;
		}

		if (req->private.type == SSDFS_REQ_SYNC) {
			thread_state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_create_request_processing;
		} else {
			ssdfs_finish_flush_request(pebc, req, wait_queue, err);
			if (is_full_log_ready(pebi)) {
				thread_state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
				goto finish_create_request_processing;
			}
			thread_state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
		}

finish_create_request_processing:
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);

		if (thread_state == SSDFS_FLUSH_THREAD_COMMIT_LOG)
			goto next_partial_step;
		else
			goto repeat;
		break;

	case SSDFS_FLUSH_THREAD_PROCESS_UPDATE_REQUEST:
		SSDFS_DBG("[FLUSH THREAD STATE] PROCESS UPDATE REQUEST\n");

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		ssdfs_peb_current_log_lock(pebi);

		err = ssdfs_process_update_request(pebi, req);
		if (err == -EAGAIN) {
			err = 0;
			SSDFS_DBG("unable to process update request : "
				  "seg %llu, peb_index %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index);
			req->result.processed_blks = 0;
			ssdfs_requests_queue_add_head(&pebc->update_rq, req);
			req = NULL;
			skip_finish_flush_request = true;
			thread_state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_update_request_processing;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to process update request: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			ssdfs_finish_flush_request(pebc, req, wait_queue, err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto finish_update_request_processing;
		}

		if (req->private.type == SSDFS_REQ_SYNC) {
			thread_state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_update_request_processing;
		} else if (req->private.cmd == SSDFS_START_MIGRATION_NOW) {
			thread_state = SSDFS_FLUSH_THREAD_START_MIGRATION_NOW;
			goto finish_update_request_processing;
		} else if (req->private.cmd == SSDFS_COMMIT_LOG_NOW) {
			if (ssdfs_peb_has_dirty_pages(pebi)) {
				thread_state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
				goto finish_update_request_processing;
			} else {
				ssdfs_finish_flush_request(pebc, req,
							   wait_queue, err);
				thread_state =
					SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
			}
		} else if (is_full_log_ready(pebi)) {
			thread_state = SSDFS_FLUSH_THREAD_COMMIT_LOG;
			goto finish_update_request_processing;
		} else {
			ssdfs_finish_flush_request(pebc, req, wait_queue, err);
			thread_state = SSDFS_FLUSH_THREAD_GET_CREATE_REQUEST;
		}

finish_update_request_processing:
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);

		if (thread_state == SSDFS_FLUSH_THREAD_COMMIT_LOG ||
		    thread_state == SSDFS_FLUSH_THREAD_START_MIGRATION_NOW) {
			goto next_partial_step;
		} else
			goto repeat;
		break;

	case SSDFS_FLUSH_THREAD_START_MIGRATION_NOW:
		SSDFS_DBG("[FLUSH THREAD STATE] START MIGRATION REQUEST\n");

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		ssdfs_peb_current_log_lock(pebi);
		is_peb_exhausted = is_ssdfs_peb_exhausted(fsi, pebi);
		is_peb_ready_to_exhaust =
			is_ssdfs_peb_ready_to_exhaust(fsi, pebi);
		has_partial_empty_log =
			ssdfs_peb_has_partial_empty_log(fsi, pebi);
		ssdfs_peb_current_log_unlock(pebi);

		if (is_peb_exhausted || is_peb_ready_to_exhaust) {
			ssdfs_unlock_current_peb(pebc);

			if (is_peb_under_migration(pebc)) {
				err = ssdfs_peb_finish_migration(pebc);
				if (unlikely(err)) {
					SSDFS_ERR("fail to finish migration: "
						  "seg %llu, peb_index %u, "
						  "err %d\n",
						  pebc->parent_si->seg_id,
						  pebc->peb_index, err);
					thread_state = SSDFS_FLUSH_THREAD_ERROR;
					goto process_migration_failure;
				}
			}

			if (!has_peb_migration_done(pebc)) {
				SSDFS_ERR("migration is not finished: "
					  "seg %llu, peb_index %u, "
					  "err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto process_migration_failure;
			}

			err = ssdfs_peb_start_migration(pebc);
			if (unlikely(err)) {
				SSDFS_ERR("fail to start migration: "
					  "seg %llu, peb_index %u, "
					  "err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto process_migration_failure;
			}

process_migration_failure:
			pebi = ssdfs_get_current_peb_locked(pebc);
			if (err) {
				if (IS_ERR_OR_NULL(pebi)) {
					thread_state = SSDFS_FLUSH_THREAD_ERROR;
					goto repeat;
				}

				ssdfs_peb_current_log_lock(pebi);
				ssdfs_finish_flush_request(pebc, req,
							   wait_queue,
							   err);
				ssdfs_peb_current_log_unlock(pebi);
				ssdfs_unlock_current_peb(pebc);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			} else if (IS_ERR_OR_NULL(pebi)) {
				err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
				SSDFS_ERR("fail to get PEB object: "
					  "seg %llu, peb_index %u, err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}

			err = ssdfs_peb_container_change_state(pebc);
			if (unlikely(err)) {
				ssdfs_unlock_current_peb(pebc);
				SSDFS_ERR("fail to change peb state: "
					  "err %d\n", err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			}
		} else if (has_partial_empty_log) {
			/*
			 * TODO: it will need to implement logic here
			 */
			SSDFS_WARN("log is partially empty\n");
		}

		ssdfs_peb_current_log_lock(pebi);
		ssdfs_finish_flush_request(pebc, req, wait_queue, err);
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);

		thread_state = SSDFS_FLUSH_THREAD_GET_UPDATE_REQUEST;
		goto next_partial_step;
		break;

	case SSDFS_FLUSH_THREAD_COMMIT_LOG:
		SSDFS_DBG("[FLUSH THREAD STATE] COMMIT LOG\n");

		err = ssdfs_prepare_current_segment_ids(fsi, cur_segs, size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to prepare current segments IDs: "
				  "err %d\n",
				  err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			thread_state = SSDFS_FLUSH_THREAD_ERROR;
			goto repeat;
		}

		ssdfs_peb_current_log_lock(pebi);

		err = ssdfs_peb_commit_log(pebi, cur_segs, size);
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
		} else {
			err = ssdfs_peb_container_change_state(pebc);
			if (unlikely(err)) {
				SSDFS_ERR("fail to change peb state: "
					  "err %d\n", err);
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
			}
		}

		if (skip_finish_flush_request)
			skip_finish_flush_request = false;
		else
			ssdfs_finish_flush_request(pebc, req, wait_queue, err);

		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);

		if (unlikely(err))
			goto repeat;

		thread_state = SSDFS_FLUSH_THREAD_DELEGATE_CREATE_ROLE;
		goto next_partial_step;
		break;

	case SSDFS_FLUSH_THREAD_DELEGATE_CREATE_ROLE:
		SSDFS_DBG("[FLUSH THREAD STATE] DELEGATE CREATE ROLE\n");

		if (!is_peb_joined_into_create_requests_queue(pebc)) {
finish_delegation:
			if (err) {
				thread_state = SSDFS_FLUSH_THREAD_ERROR;
				goto repeat;
			} else {
				thread_state =
					SSDFS_FLUSH_THREAD_CHECK_STOP_CONDITION;
				goto sleep_flush_thread;
			}
		}

		err = ssdfs_peb_find_next_log_creation_thread(pebc);
		if (unlikely(err)) {
			SSDFS_WARN("fail to delegate log creation role: "
				   "seg %llu, peb_index %u, err %d\n",
				   pebc->parent_si->seg_id,
				   pebc->peb_index, err);
		}
		goto finish_delegation;
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
	wait_event_interruptible(*wait_queue,
				 FLUSH_THREAD_WAKE_CONDITION(pebc));

	goto repeat;
}
