//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_read_thread.c - read thread functionality.
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
 * struct ssdfs_segbmap_extent - segbmap extent
 * @logical_offset: logical offset inside of segbmap's content
 * @data_size: requested data size
 * @fragment_size: fragment size of segbmap
 */
struct ssdfs_segbmap_extent {
	u64 logical_offset;
	u32 data_size;
	u16 fragment_size;
};

#define SSDFS_BLKBMAP_FRAG_HDR_CAPACITY \
	(sizeof(struct ssdfs_block_bitmap_fragment) + \
	 (sizeof(struct ssdfs_fragment_desc) * \
	  SSDFS_FRAGMENTS_CHAIN_MAX))

#define SSDFS_BLKBMAP_HDR_CAPACITY \
	(sizeof(struct ssdfs_block_bitmap_header) + \
	 SSDFS_BLKBMAP_FRAG_HDR_CAPACITY)

/*
 * struct ssdfs_blk_bmap_init_env - block bitmap init environment
 * @bmap_hdr: pointer on block bitmap header
 * @bmap_hdr_buf: block bitmap header buffer
 * @frag_hdr: block bitmap fragment header
 * @frag_hdr_buf: block bitmap fragment header buffer
 * @fragment_index: index of bmap fragment
 * @pvec: pagevec that stores block bitmap content
 * @read_bytes: counter of all read bytes
 */
struct ssdfs_blk_bmap_init_env {
	struct ssdfs_block_bitmap_header *bmap_hdr;
	struct ssdfs_block_bitmap_fragment *frag_hdr;
	u8 bmap_hdr_buf[SSDFS_BLKBMAP_HDR_CAPACITY];
	int fragment_index;
	struct pagevec pvec;
	u32 read_bytes;
};

static
void ssdfs_prepare_blk_bmap_init_env(struct ssdfs_blk_bmap_init_env *env)
{
	memset(env->bmap_hdr_buf, 0, SSDFS_BLKBMAP_HDR_CAPACITY);
	env->bmap_hdr = (struct ssdfs_block_bitmap_header *)env->bmap_hdr_buf;
	env->frag_hdr =
		(struct ssdfs_block_bitmap_fragment *)(env->bmap_hdr_buf +
				    sizeof(struct ssdfs_block_bitmap_header));
	env->fragment_index = -1;
	pagevec_init(&env->pvec);
	env->read_bytes = 0;
}

/*
 * struct ssdfs_blk2off_table_init_env - blk2off table init environment
 * @tbl_hdr: blk2off table header
 * @pvec: pagevec with blk2off table fragment
 * @read_off: current read offset
 * @write_off: current write offset
 */
struct ssdfs_blk2off_table_init_env {
	struct ssdfs_blk2off_table_header tbl_hdr;
	struct pagevec pvec;
	u32 read_off;
	u32 write_off;
};

static void
ssdfs_prepare_blk2off_table_init_env(struct ssdfs_blk2off_table_init_env *env)
{
	memset(&env->tbl_hdr, 0, sizeof(struct ssdfs_blk2off_table_header));
	pagevec_init(&env->pvec);
	env->read_off = 0;
	env->write_off = 0;
}

/*
 * struct ssdfs_read_init_env - read operation init environment
 * @log_hdr: log header
 * @has_seg_hdr: does log have segment header?
 * @footer: log footer
 * @has_footer: does log have footer?
 * @cur_migration_id: current PEB's migration ID
 * @prev_migration_id: previous PEB's migration ID
 * @log_offset: offset in pages of the requested log
 * @log_pages: pages count in every log of segment
 * @log_bytes: number of bytes in the requested log
 * @b_init: block bitmap init environment
 * @t_init: blk2off table init environment
 */
struct ssdfs_read_init_env {
	void *log_hdr;
	bool has_seg_hdr;
	struct ssdfs_log_footer *footer;
	bool has_footer;
	int cur_migration_id;
	int prev_migration_id;
	u16 log_offset;
	u16 log_pages;
	u32 log_bytes;

	struct ssdfs_blk_bmap_init_env b_init;
	struct ssdfs_blk2off_table_init_env t_init;
};

static
int ssdfs_prepare_read_init_env(struct ssdfs_read_init_env *env)
{
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
	size_t footer_buf_size;

	env->log_hdr = kzalloc(hdr_size, GFP_KERNEL);
	if (!env->log_hdr) {
		SSDFS_ERR("fail to allocate log header buffer\n");
		return -ENOMEM;
	}

	env->has_seg_hdr = false;

	footer_buf_size = max_t(size_t, hdr_size,
				sizeof(struct ssdfs_log_footer));
	env->footer = kzalloc(footer_buf_size, GFP_KERNEL);
	if (!env->footer) {
		SSDFS_ERR("fail to allocate log footer buffer\n");
		return -ENOMEM;
	}

	env->has_footer = false;

	env->cur_migration_id = -1;
	env->prev_migration_id = -1;

	env->log_offset = 0;
	env->log_pages = U16_MAX;
	env->log_bytes = U32_MAX;

	ssdfs_prepare_blk_bmap_init_env(&env->b_init);
	ssdfs_prepare_blk2off_table_init_env(&env->t_init);

	return 0;
}

static
void ssdfs_destroy_init_env(struct ssdfs_read_init_env *env)
{
	if (env->log_hdr)
		kfree(env->log_hdr);

	env->log_hdr = NULL;
	env->has_seg_hdr = false;

	if (env->footer)
		kfree(env->footer);

	env->footer = NULL;
	env->has_footer = false;

	pagevec_release(&env->b_init.pvec);
	pagevec_release(&env->t_init.pvec);
}

static
int ssdfs_read_blk2off_table_fragment(struct ssdfs_peb_info *pebi,
				      struct ssdfs_read_init_env *env);

/******************************************************************************
 *                          READ THREAD FUNCTIONALITY                         *
 ******************************************************************************/

/*
 * __ssdfs_peb_release_pages() - release memory pages
 * @pebi: pointer on PEB object
 *
 * This method tries to release the used pages from the page
 * array upon the init has been finished.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_peb_release_pages(struct ssdfs_peb_info *pebi)
{
	u16 last_log_start_page = U16_MAX;
	u16 log_pages = 0;
	pgoff_t start, end;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(!rwsem_is_locked(&pebi->pebc->lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_id %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->pebc->peb_index,
		  pebi->peb_id);

	switch (atomic_read(&pebi->current_log.state)) {
	case SSDFS_LOG_INITIALIZED:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid current log's state: "
			  "%#x\n",
			  atomic_read(&pebi->current_log.state));
		return -ERANGE;
	}

	ssdfs_peb_current_log_lock(pebi);
	last_log_start_page = pebi->current_log.start_page;
	log_pages = pebi->log_pages;
	ssdfs_peb_current_log_unlock(pebi);

	if (last_log_start_page > 0 && last_log_start_page <= log_pages) {
		start = 0;
		end = last_log_start_page - 1;

		err = ssdfs_page_array_release_pages(&pebi->cache,
						     &start, end);
		if (unlikely(err)) {
			SSDFS_ERR("fail to release pages: "
				  "seg_id %llu, peb_id %llu, "
				  "start %lu, end %lu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, start, end, err);
		}
	}

	return err;
}

/*
 * ssdfs_peb_release_pages_after_init() - release memory pages
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This method tries to release the used pages from the page
 * array upon the init has been finished.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_release_pages(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_peb_info *pebi;
	int err1 = 0, err2 = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (pebi) {
		err1 = __ssdfs_peb_release_pages(pebi);
		if (unlikely(err1)) {
			SSDFS_ERR("fail to release source PEB pages: "
				  "seg_id %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err1);
		}
	}

	pebi = pebc->dst_peb;
	if (pebi) {
		err2 = __ssdfs_peb_release_pages(pebi);
		if (unlikely(err1)) {
			SSDFS_ERR("fail to release dest PEB pages: "
				  "seg_id %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err2);
		}
	}

	up_read(&pebc->lock);

	if (err1 || err2)
		return -ERANGE;

	return 0;
}

/*
 * ssdfs_unaligned_read_cache() - unaligned read from PEB's cache
 * @pebi: pointer on PEB object
 * @area_offset: offset from the log's beginning
 * @area_size: size of the data portion
 * @buf: buffer for read
 *
 * This function tries to read some data portion from
 * the PEB's cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_unaligned_read_cache(struct ssdfs_peb_info *pebi,
				u32 area_offset, u32 area_size,
				void *buf)
{
	struct ssdfs_fs_info *fsi;
	struct page *page;
	void *kaddr;
	u32 page_off;
	u32 bytes_off;
	size_t read_bytes = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si || !buf);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, "
		  "area_offset %u, area_size %u, buf %p\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_offset, area_size, buf);

	fsi = pebi->pebc->parent_si->fsi;

	do {
		size_t iter_read_bytes;
		size_t offset;

		bytes_off = area_offset + read_bytes;
		page_off = bytes_off / PAGE_SIZE;
		offset = bytes_off % PAGE_SIZE;

		iter_read_bytes = min_t(size_t,
					(size_t)(area_size - read_bytes),
					(size_t)(PAGE_SIZE - offset));

		page = ssdfs_page_array_get_page_locked(&pebi->cache, page_off);
		if (IS_ERR_OR_NULL(page)) {
			SSDFS_DBG("fail to get page: index %u\n",
				  page_off);
			return -ERANGE;
		}

		kaddr = kmap_atomic(page);
		memcpy((u8 *)buf + read_bytes,
			(u8 *)kaddr + offset,
			iter_read_bytes);
		kunmap_atomic(kaddr);
		unlock_page(page);
		put_page(page);

		read_bytes += iter_read_bytes;
	} while (read_bytes < area_size);

	return 0;
}

/*
 * ssdfs_peb_read_log_hdr_desc_array() - read log's header area's descriptors
 * @pebi: pointer on PEB object
 * @log_start_page: starting page of the log
 * @array: array of area's descriptors [out]
 * @array_size: count of items into array
 *
 * This function tries to read log's header area's descriptors.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_peb_read_log_hdr_desc_array(struct ssdfs_peb_info *pebi,
				      u16 log_start_page,
				      struct ssdfs_metadata_descriptor *array,
				      size_t array_size)
{
	struct ssdfs_fs_info *fsi;
	struct page *page;
	void *kaddr;
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *plh_hdr = NULL;
	size_t hdr_size = max_t(size_t,
				sizeof(struct ssdfs_segment_header),
				sizeof(struct ssdfs_partial_log_header));
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	u32 page_off;
	size_t read_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!array);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, log_start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  log_start_page);

	fsi = pebi->pebc->parent_si->fsi;
	page_off = log_start_page;

	page = ssdfs_page_array_grab_page(&pebi->cache, page_off);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		SSDFS_ERR("fail to grab page: index %u\n",
			  page_off);
		return -ENOMEM;
	}

	kaddr = kmap(page);

	if (PageUptodate(page) || PageDirty(page))
		goto copy_desc_array;

	err = ssdfs_aligned_read_buffer(fsi, pebi->peb_id,
					(page_off * PAGE_SIZE) + hdr_size,
					(u8 *)kaddr + hdr_size,
					PAGE_SIZE - hdr_size,
					&read_bytes);
	if (unlikely(err))
		goto fail_copy_desc_array;
	else if (unlikely(read_bytes != (PAGE_SIZE - hdr_size))) {
		err = -ERANGE;
		goto fail_copy_desc_array;
	}

	SetPageUptodate(page);

copy_desc_array:
	magic = (struct ssdfs_signature *)kaddr;

	if (!is_ssdfs_magic_valid(magic)) {
		err = -ERANGE;
		SSDFS_ERR("valid magic is not detected\n");
		goto fail_copy_desc_array;
	}

	if (__is_ssdfs_segment_header_magic_valid(magic)) {
		seg_hdr = SSDFS_SEG_HDR(kaddr);

		err = ssdfs_check_segment_header(fsi, seg_hdr, false);
		if (unlikely(err)) {
			SSDFS_ERR("log header is corrupted: "
				  "seg %llu, peb %llu, log_start_page %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  log_start_page);
			goto fail_copy_desc_array;
		}

		memcpy(array, seg_hdr->desc_array, array_size * desc_size);
	} else if (is_ssdfs_partial_log_header_magic_valid(magic)) {
		plh_hdr = SSDFS_PLH(kaddr);

		err = ssdfs_check_partial_log_header(fsi, plh_hdr, false);
		if (unlikely(err)) {
			SSDFS_ERR("partial log header is corrupted: "
				  "seg %llu, peb %llu, log_start_page %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  log_start_page);
			goto fail_copy_desc_array;
		}

		memcpy(array, plh_hdr->desc_array, array_size * desc_size);
	} else {
		err = -EIO;
		SSDFS_ERR("log header is corrupted: "
			  "seg %llu, peb %llu, log_start_page %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  log_start_page);
		goto fail_copy_desc_array;
	}

fail_copy_desc_array:
	kunmap(page);
	unlock_page(page);
	put_page(page);

	if (unlikely(err)) {
		SSDFS_ERR("fail to read checked segment header: "
			  "seg %llu, peb %llu, pages_off %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  page_off, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_read_page_locked() - read locked page into PEB's cache
 * @pebi: pointer on PEB object
 * @page_off: page index
 *
 * This function tries to read locked page into PEB's cache.
 */
static
struct page *ssdfs_peb_read_page_locked(struct ssdfs_peb_info *pebi,
					u32 page_off)
{
	struct ssdfs_fs_info *fsi;
	struct page *page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, page_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  page_off);

	fsi = pebi->pebc->parent_si->fsi;

	page = ssdfs_page_array_grab_page(&pebi->cache, page_off);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		SSDFS_ERR("fail to grab page: index %u\n",
			  page_off);
		return NULL;
	}

	if (PageUptodate(page) || PageDirty(page))
		goto finish_page_read;

	err = ssdfs_read_page_from_volume(fsi, pebi->peb_id,
					  page_off << PAGE_SHIFT,
					  page);
	if (unlikely(err))
		goto fail_read_page;

	SetPageUptodate(page);

finish_page_read:
	return page;

fail_read_page:
	unlock_page(page);
	put_page(page);

	SSDFS_ERR("fail to read locked page: "
		  "seg %llu, peb %llu, page_off %u, err %d\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  page_off, err);

	return NULL;
}

/*
 * ssdfs_peb_find_block_descriptor() - find block descriptor
 * @pebi: pointer on PEB object
 * @req: request
 * @array: array of area's descriptors
 * @array_size: count of items into array
 * @desc_off: block descriptor offset
 * @blk_desc: block descriptor [out]
 *
 * This function tries to get block descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - I/O error.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_peb_find_block_descriptor(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req,
				    struct ssdfs_metadata_descriptor *array,
				    size_t array_size,
				    struct ssdfs_blk_state_offset *desc_off,
				    struct ssdfs_block_descriptor *blk_desc)
{
	struct ssdfs_fs_info *fsi;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	int area_index;
	u32 area_offset;
	u32 blk_desc_off;
	u64 calculated;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !array || !desc_off || !blk_desc);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, "
		  "log_start_page %u, log_area %#x, "
		  "peb_migration_id %u, byte_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  le16_to_cpu(desc_off->log_start_page),
		  desc_off->log_area, desc_off->peb_migration_id,
		  le32_to_cpu(desc_off->byte_offset));

	fsi = pebi->pebc->parent_si->fsi;
	area_index = SSDFS_AREA_TYPE2INDEX(desc_off->log_area);

	if (area_index >= SSDFS_SEG_HDR_DESC_MAX) {
		SSDFS_ERR("invalid area index %#x\n", area_index);
		return -ERANGE;
	}

	area_offset = le32_to_cpu(array[area_index].offset);
	blk_desc_off = le32_to_cpu(desc_off->byte_offset);

	err = ssdfs_unaligned_read_cache(pebi,
					 area_offset + blk_desc_off,
					 blk_desc_size,
					 blk_desc);
	if (err) {
		err = ssdfs_unaligned_read_buffer(fsi, pebi->peb_id,
						  area_offset + blk_desc_off,
						  blk_desc, blk_desc_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read buffer: "
				  "peb %llu, area_offset %u, byte_offset %u, "
				  "buf_size %zu, err %d\n",
				  pebi->peb_id, area_offset, blk_desc_off,
				  blk_desc_size, err);
			return err;
		}
	}

	if (le64_to_cpu(blk_desc->ino) != req->extent.ino) {
		SSDFS_ERR("blk_desc->ino %llu != req->extent.ino %llu\n",
			  le64_to_cpu(blk_desc->ino), req->extent.ino);
		return -ERANGE;
	}

	calculated = (u64)req->result.processed_blks * fsi->pagesize;

	if (calculated >= req->extent.data_bytes) {
		SSDFS_ERR("calculated %llu >= req->extent.data_bytes %u\n",
			  calculated, req->extent.data_bytes);
		return -ERANGE;
	}

	return 0;
}

/*
 * __ssdfs_peb_get_block_state_desc() - get block state descriptor
 * @pebi: pointer on PEB object
 * @area_desc: area descriptor
 * @desc: block state descriptor [out]
 * @cno: checkpoint ID [out]
 * @parent_snapshot: parent snapshot ID [out]
 *
 * This function tries to get block state descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - I/O error.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
int __ssdfs_peb_get_block_state_desc(struct ssdfs_peb_info *pebi,
				struct ssdfs_metadata_descriptor *area_desc,
				struct ssdfs_block_state_descriptor *desc,
				u64 *cno, u64 *parent_snapshot)
{
	struct ssdfs_fs_info *fsi;
	size_t state_desc_size = sizeof(struct ssdfs_block_state_descriptor);
	u32 area_offset;
	u32 page_off;
	struct page *page;
	struct ssdfs_block_state_descriptor *cur_item;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!area_desc || !desc);
	BUG_ON(!cno || !parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area_offset = le32_to_cpu(area_desc->offset);
	page_off = area_offset >> PAGE_SHIFT;

	SSDFS_DBG("seg %llu, peb %llu, "
		  "area_offset %u, page_index %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_offset, page_off);

	page = ssdfs_peb_read_page_locked(pebi, page_off);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to read locked page: index %u\n",
			  page_off);
		return -ERANGE;
	}

	kaddr = kmap_atomic(page);
	cur_item = (struct ssdfs_block_state_descriptor *)((u8 *)kaddr +
						(area_offset % PAGE_SIZE));
	memcpy(desc, cur_item, state_desc_size);
	kunmap_atomic(kaddr);
	unlock_page(page);
	put_page(page);

	if (cur_item->chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		SSDFS_ERR("chain header magic invalid\n");
		return -EIO;
	}

	if (cur_item->chain_hdr.type != SSDFS_BLK_STATE_CHAIN_HDR) {
		SSDFS_ERR("chain header type invalid\n");
		return -EIO;
	}

	if (le16_to_cpu(cur_item->chain_hdr.desc_size) !=
	    sizeof(struct ssdfs_fragment_desc)) {
		SSDFS_ERR("fragment descriptor size is invalid\n");
		return -EIO;
	}

	*cno = le64_to_cpu(cur_item->cno);
	*parent_snapshot = le64_to_cpu(cur_item->parent_snapshot);

	return 0;
}

/*
 * ssdfs_peb_get_block_state_desc() - get block state descriptor
 * @pebi: pointer on PEB object
 * @req: request
 * @area_desc: area descriptor
 * @desc: block state descriptor [out]
 *
 * This function tries to get block state descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - I/O error.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_peb_get_block_state_desc(struct ssdfs_peb_info *pebi,
				   struct ssdfs_segment_request *req,
				   struct ssdfs_metadata_descriptor *area_desc,
				   struct ssdfs_block_state_descriptor *desc)
{
	u64 cno;
	u64 parent_snapshot;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !area_desc || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

	err = __ssdfs_peb_get_block_state_desc(pebi, area_desc,
						desc, &cno, &parent_snapshot);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get block state descriptor: "
			  "err %d\n", err);
		return err;
	}

	if (req->extent.cno != cno) {
		SSDFS_ERR("req->extent.cno %llu != cno %llu\n",
			  req->extent.cno, cno);
		return -EIO;
	}

	if (req->extent.parent_snapshot != parent_snapshot) {
		SSDFS_ERR("req->extent.parent_snapshot %llu != "
			  "parent_snapshot %llu\n",
			  req->extent.parent_snapshot,
			  parent_snapshot);
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_peb_get_fragment_desc_array() - get fragment descriptors array
 * @pebi: pointer on PEB object
 * @array_offset: offset of array from the log's beginning
 * @array: array of fragment descriptors [out]
 * @array_size: count of items into array
 *
 * This function tries to get array of fragment descriptors.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_peb_get_fragment_desc_array(struct ssdfs_peb_info *pebi,
					u32 array_offset,
					struct ssdfs_fragment_desc *array,
					size_t array_size)
{
	struct ssdfs_fs_info *fsi;
	u32 page_off;
	struct page *page;
	void *kaddr, *cur_item;
	size_t frag_desc_size = sizeof(struct ssdfs_fragment_desc);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!array);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, "
		  "array_offset %u, array_size %zu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  array_offset, array_size);

	fsi = pebi->pebc->parent_si->fsi;
	page_off = array_offset >> PAGE_SHIFT;

	page = ssdfs_peb_read_page_locked(pebi, page_off);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to read locked page: index %u\n",
			  page_off);
		return -ERANGE;
	}

	kaddr = kmap_atomic(page);

	cur_item = (u8 *)kaddr + (array_offset % PAGE_SIZE);
	memcpy(array, cur_item, array_size * frag_desc_size);

	kunmap_atomic(kaddr);
	unlock_page(page);
	put_page(page);

	return 0;
}

/*
 * ssdfs_peb_unaligned_read_fragment() - unaligned read fragment
 * @pebi: pointer on PEB object
 * @byte_off: offset in bytes from PEB's begin
 * @size: size of fragment in bytes
 * @buf: buffer pointer
 *
 * This function tries to read fragment.
 *
 * RETURN:
 * [success] - fragment has been read successfully.
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_unaligned_read_fragment(struct ssdfs_peb_info *pebi,
				      u32 byte_off,
				      size_t size,
				      void *buf)
{
	u32 page_index, page_off;
	struct page *page;
	void *kaddr;
	size_t read_size = 0;
	u32 buf_off = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(byte_off > pebi->pebc->parent_si->fsi->erasesize);
	BUG_ON(size > PAGE_SIZE);
	WARN_ON(size == 0);
	BUG_ON(!buf);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, "
		  "offset %u, size %zu, buf %p\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  byte_off, size, buf);

read_next_page:
	if (byte_off > pebi->pebc->parent_si->fsi->erasesize) {
		SSDFS_ERR("offset %u > erasesize %u\n",
			  byte_off,
			  pebi->pebc->parent_si->fsi->erasesize);
		return -ERANGE;
	}

	page_off = byte_off % PAGE_SIZE;
	read_size = min_t(size_t, size, PAGE_SIZE - page_off);

	page_index = byte_off >> PAGE_SHIFT;
	page = ssdfs_peb_read_page_locked(pebi, page_index);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to read locked page: index %u\n",
			  page_off);
		return -ERANGE;
	}

	kaddr = kmap_atomic(page);
	memcpy((u8 *)buf + buf_off, (u8 *)kaddr + page_off, read_size);
	kunmap_atomic(kaddr);
	unlock_page(page);
	put_page(page);

	size -= read_size;
	buf_off += read_size;
	byte_off += read_size;

	if (size != 0)
		goto read_next_page;

	return 0;
}

/*
 * ssdfs_read_checked_fragment() - read and check data fragment
 * @pebi: pointer on PEB object
 * @area_offset: offset in bytes from log's begin
 * @sequence_id: fragment identification number
 * @desc: fragment descriptor
 * @cdata_buf: compressed data buffer
 * @page: buffer for uncompressed data
 *
 * This function reads data fragment, uncompressed it
 * (if neccessary) and check fragment's checksum.
 *
 * RETURN:
 * [success] - fragment has been read successfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal calculation error.
 * %-EIO        - I/O error.
 */
static
int ssdfs_read_checked_fragment(struct ssdfs_peb_info *pebi,
				u32 area_offset,
				int sequence_id,
				struct ssdfs_fragment_desc *desc,
				void *cdata_buf,
				struct page *page)
{
	struct ssdfs_fs_info *fsi;
	u32 pebsize;
	u32 offset;
	size_t compr_size, uncompr_size;
	bool is_compressed;
	void *kaddr;
	__le32 checksum;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!desc || !cdata_buf || !page);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, area_offset %u, sequence_id %u, "
		  "offset %u, compr_size %u, uncompr_size %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_offset,
		  le16_to_cpu(desc->sequence_id),
		  le32_to_cpu(desc->offset),
		  le16_to_cpu(desc->compr_size),
		  le16_to_cpu(desc->uncompr_size));

	fsi = pebi->pebc->parent_si->fsi;

	if (sequence_id != le16_to_cpu(desc->sequence_id)) {
		SSDFS_ERR("sequence_id %d != desc->sequence_id %u\n",
			  sequence_id, le16_to_cpu(desc->sequence_id));
		return -EINVAL;
	}

	pebsize = fsi->pages_per_peb * fsi->pagesize;
	offset = area_offset + le32_to_cpu(desc->offset);
	compr_size = le16_to_cpu(desc->compr_size);
	uncompr_size = le16_to_cpu(desc->uncompr_size);

	if (offset >= pebsize) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"desc->offset %u >= pebsize %u\n",
				offset, pebsize);
		return -EIO;
	}

	if (uncompr_size > PAGE_SIZE) {
		SSDFS_ERR("uncompr_size %zu > PAGE_SIZE %lu\n",
			  uncompr_size, PAGE_SIZE);
		return -ERANGE;
	}

	is_compressed = (desc->type == SSDFS_FRAGMENT_ZLIB_BLOB ||
			 desc->type == SSDFS_FRAGMENT_LZO_BLOB);

	if (desc->type == SSDFS_FRAGMENT_UNCOMPR_BLOB) {
		if (compr_size != uncompr_size) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"compr_size %zu != uncompr_size %zu\n",
					compr_size, uncompr_size);
			return -EIO;
		}

		if (uncompr_size > PAGE_SIZE) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"uncompr_size %zu > PAGE_CACHE %lu\n",
					uncompr_size, PAGE_SIZE);
			return -EIO;
		}

		kaddr = kmap(page);
		err = ssdfs_peb_unaligned_read_fragment(pebi, offset,
							uncompr_size,
							kaddr);
		if (!err)
			checksum = ssdfs_crc32_le(kaddr, uncompr_size);
		kunmap(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to read fragment: "
				  "seg %llu, peb %llu, offset %u, size %zu, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  offset, uncompr_size, err);
			return err;
		}
	} else if (is_compressed) {
		int type;

		err = ssdfs_peb_unaligned_read_fragment(pebi, offset,
							compr_size,
							cdata_buf);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read fragment: "
				  "seg %llu, peb %llu, offset %u, size %zu, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  offset, compr_size, err);
			return err;
		}

		if (desc->type == SSDFS_FRAGMENT_ZLIB_BLOB)
			type = SSDFS_COMPR_ZLIB;
		else if (desc->type == SSDFS_FRAGMENT_LZO_BLOB)
			type = SSDFS_COMPR_LZO;
		else
			BUG();

		kaddr = kmap(page);
		err = ssdfs_decompress(type, cdata_buf, kaddr,
					compr_size, uncompr_size);
		if (!err)
			checksum = ssdfs_crc32_le(kaddr, uncompr_size);
		kunmap(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to decompress fragment: "
				  "seg %llu, peb %llu, offset %u, "
				  "compr_size %zu, uncompr_size %zu"
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  offset, compr_size, uncompr_size, err);
			return err;
		}
	} else
		BUG();

	if (desc->checksum != checksum) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"desc->checksum %#x != checksum %#x\n",
				le32_to_cpu(desc->checksum),
				le32_to_cpu(checksum));
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_peb_read_main_area_page() - read main area's page
 * @pebi: pointer on PEB object
 * @req: request
 * @array: array of area's descriptors
 * @array_size: count of items into array
 * @blk_state_off: block state offset
 *
 * This function tries to read main area's page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - I/O error.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_peb_read_main_area_page(struct ssdfs_peb_info *pebi,
				  struct ssdfs_segment_request *req,
				  struct ssdfs_metadata_descriptor *array,
				  size_t array_size,
				  struct ssdfs_blk_state_offset *blk_state_off)
{
	struct ssdfs_fs_info *fsi;
	u8 area_index;
	u32 area_offset;
	u32 data_bytes;
	u32 read_bytes;
	u32 byte_offset;
	int page_index;
	struct page *page;
	void *kaddr;
	u32 processed_blks;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !array || !blk_state_off);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

	fsi = pebi->pebc->parent_si->fsi;

	area_index = SSDFS_AREA_TYPE2INDEX(blk_state_off->log_area);
	if (area_index >= array_size) {
		SSDFS_ERR("area_index %u >= array_size %zu\n",
			  area_index, array_size);
		return -EIO;
	}

	read_bytes = req->result.processed_blks * fsi->pagesize;

	if (read_bytes > req->extent.data_bytes) {
		SSDFS_ERR("read_bytes %u > req->extent.data_bytes %u\n",
			  read_bytes, req->extent.data_bytes);
		return -ERANGE;
	} else if (read_bytes == req->extent.data_bytes) {
		SSDFS_WARN("read_bytes %u == req->extent.data_bytes %u\n",
			   read_bytes, req->extent.data_bytes);
		return -ERANGE;
	}

	data_bytes = req->extent.data_bytes - read_bytes;

	if (fsi->pagesize > PAGE_SIZE)
		data_bytes = min_t(u32, data_bytes, fsi->pagesize);
	else
		data_bytes = min_t(u32, data_bytes, PAGE_SIZE);

	area_offset = le32_to_cpu(array[area_index].offset);
	byte_offset = le32_to_cpu(blk_state_off->byte_offset);

	page_index = (int)(read_bytes >> PAGE_SHIFT);
	BUG_ON(page_index >= U16_MAX);

	if (pagevec_count(&req->result.pvec) <= page_index) {
		SSDFS_ERR("page_index %d >= pagevec_count %u\n",
			  page_index,
			  pagevec_count(&req->result.pvec));
		return -EIO;
	}

	page = req->result.pvec.pages[page_index];

	kaddr = kmap(page);
	err = ssdfs_peb_unaligned_read_fragment(pebi,
						area_offset + byte_offset,
						data_bytes,
						kaddr);
	kunmap(page);

	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, size %u, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  area_offset + byte_offset, data_bytes, err);
		return err;
	}

	processed_blks = (data_bytes + fsi->pagesize - 1) >> fsi->log_pagesize;
	req->result.processed_blks += processed_blks;

	return 0;
}

/*
 * ssdfs_peb_read_area_fragment() - read area's fragment
 * @pebi: pointer on PEB object
 * @req: request
 * @array: array of area's descriptors
 * @array_size: count of items into array
 * @blk_state_off: block state offset
 *
 * This function tries to read area's fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - I/O error.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_peb_read_area_fragment(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req,
				 struct ssdfs_metadata_descriptor *array,
				 size_t array_size,
				 struct ssdfs_blk_state_offset *blk_state_off)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_state_descriptor found_blk_state;
	size_t state_desc_size = sizeof(struct ssdfs_block_state_descriptor);
	struct ssdfs_fragment_desc *frag_descs = NULL;
	size_t frag_desc_size = sizeof(struct ssdfs_fragment_desc);
	void *cdata_buf = NULL;
	u8 area_index;
	u32 area_offset;
	u32 frag_desc_offset;
	u32 full_offset;
	u32 data_bytes;
	u32 read_bytes;
	int page_index;
	u16 fragments;
	u32 processed_blks;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !array || !blk_state_off);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

	fsi = pebi->pebc->parent_si->fsi;

	area_index = SSDFS_AREA_TYPE2INDEX(blk_state_off->log_area);
	if (area_index >= array_size) {
		SSDFS_ERR("area_index %u >= array_size %zu\n",
			  area_index, array_size);
		return -EIO;
	}

	read_bytes = req->result.processed_blks * fsi->pagesize;

	if (read_bytes > req->extent.data_bytes) {
		SSDFS_ERR("read_bytes %u > req->extent.data_bytes %u\n",
			  read_bytes, req->extent.data_bytes);
		return -ERANGE;
	} else if (read_bytes == req->extent.data_bytes) {
		SSDFS_WARN("read_bytes %u == req->extent.data_bytes %u\n",
			   read_bytes, req->extent.data_bytes);
		return -ERANGE;
	}

	data_bytes = req->extent.data_bytes - read_bytes;

	if (fsi->pagesize > PAGE_SIZE)
		data_bytes = min_t(u32, data_bytes, fsi->pagesize);
	else
		data_bytes = min_t(u32, data_bytes, PAGE_SIZE);

	err = ssdfs_peb_get_block_state_desc(pebi, req, &array[area_index],
					     &found_blk_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get block state descriptor: "
			  "area_offset %u, err %d\n",
			  le32_to_cpu(array[area_index].offset),
			  err);
		return err;
	}

	if (data_bytes > le32_to_cpu(found_blk_state.chain_hdr.uncompr_bytes)) {
		SSDFS_ERR("data_bytes %u > uncompr_bytes %u\n",
			  data_bytes,
			  le32_to_cpu(found_blk_state.chain_hdr.uncompr_bytes));
		return -EIO;
	}

	fragments = le16_to_cpu(found_blk_state.chain_hdr.fragments_count);
	if (fragments == 0 || fragments > SSDFS_FRAGMENTS_CHAIN_MAX) {
		SSDFS_ERR("invalid fragments count %u\n", fragments);
		return -EIO;
	}

	frag_descs = kcalloc(fragments, frag_desc_size, GFP_KERNEL);
	if (!frag_descs) {
		SSDFS_ERR("fail to allocate fragment descriptors array\n");
		return -ENOMEM;
	}

	area_offset = le32_to_cpu(array[area_index].offset);
	frag_desc_offset = le32_to_cpu(blk_state_off->byte_offset);
	frag_desc_offset += state_desc_size;
	full_offset = area_offset + frag_desc_offset;

	err = ssdfs_peb_get_fragment_desc_array(pebi, full_offset,
						frag_descs, fragments);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get fragment descriptor array: "
			  "offset %u, fragments %u, err %d\n",
			  full_offset, fragments, err);
		goto free_bufs;
	}

	cdata_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!cdata_buf) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate cdata_buf\n");
		goto free_bufs;
	}

	page_index = (int)(read_bytes >> PAGE_SHIFT);
	BUG_ON(page_index >= U16_MAX);

	for (i = 0; i < fragments; i++) {
		struct page *page;
		struct ssdfs_fragment_desc *cur_desc;
		u32 offset;
		u32 compr_size;
		u32 uncompr_size;

		if (pagevec_count(&req->result.pvec) <= (page_index + i)) {
			err = -EIO;
			SSDFS_ERR("page_index %d >= pagevec_count %u\n",
				  page_index + i,
				  pagevec_count(&req->result.pvec));
			goto free_bufs;
		}

		cur_desc = &frag_descs[i];

		if (cur_desc->magic != SSDFS_FRAGMENT_DESC_MAGIC) {
			err = -EIO;
			SSDFS_ERR("invalid fragment descriptor magic\n");
			goto free_bufs;
		}

		if (cur_desc->type < SSDFS_FRAGMENT_UNCOMPR_BLOB ||
		    cur_desc->type > SSDFS_FRAGMENT_LZO_BLOB) {
			err = -EIO;
			SSDFS_ERR("invalid fragment descriptor type\n");
			goto free_bufs;
		}

		if (cur_desc->sequence_id != i) {
			err = -EIO;
			SSDFS_ERR("invalid fragment's sequence id\n");
			goto free_bufs;
		}

		offset = le32_to_cpu(cur_desc->offset);
		compr_size = le16_to_cpu(cur_desc->compr_size);
		uncompr_size = le16_to_cpu(cur_desc->uncompr_size);

		if (compr_size > PAGE_SIZE) {
			err = -EIO;
			SSDFS_ERR("compr_size %u > PAGE_SIZE %lu\n",
				  compr_size, PAGE_SIZE);
			goto free_bufs;
		}

		page = req->result.pvec.pages[page_index + i];

		err = ssdfs_read_checked_fragment(pebi, area_offset,
						  i, cur_desc,
						  cdata_buf,
						  page);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read fragment: "
				  "index %d, err %d\n",
				  i, err);
			goto free_bufs;
		}
	}

	processed_blks = (data_bytes + fsi->pagesize - 1) >> fsi->log_pagesize;
	req->result.processed_blks += processed_blks;

free_bufs:
	kfree(frag_descs);
	kfree(cdata_buf);

	return err;
}

/*
 * ssdfs_peb_read_block_state() - read state of the block
 * @pebi: pointer on PEB object
 * @req: request
 * @array: array of area's descriptors
 * @array_size: count of items into array
 * @blk_desc: block descriptor
 * @blk_state_index: index of block state in block descriptor
 *
 * This function tries to read block state.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - I/O error.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_peb_read_block_state(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_metadata_descriptor *array,
				size_t array_size,
				struct ssdfs_block_descriptor *blk_desc,
				int blk_state_index)
{
	struct ssdfs_blk_state_offset *blk_state_off = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !array || !blk_desc);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);
	BUG_ON(blk_state_index >= SSDFS_BLK_STATE_OFF_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, "
		  "ino %llu, logical_offset %u, peb_index %u, page_index %u, "
		  "blk_state_index %d\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  le64_to_cpu(blk_desc->ino),
		  le32_to_cpu(blk_desc->logical_offset),
		  le16_to_cpu(blk_desc->peb_index),
		  le16_to_cpu(blk_desc->peb_page),
		  blk_state_index);

	blk_state_off = &blk_desc->state[blk_state_index];

	if (blk_state_off->log_area == SSDFS_LOG_MAIN_AREA) {
		err = ssdfs_peb_read_main_area_page(pebi, req,
						    array, array_size,
						    blk_state_off);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read main area's page: "
				  "seg %llu, peb %llu, "
				  "ino %llu, logical_offset %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  le64_to_cpu(blk_desc->ino),
				  le32_to_cpu(blk_desc->logical_offset),
				  err);
			return err;
		}
	} else {
		err = ssdfs_peb_read_area_fragment(pebi, req,
						   array, array_size,
						   blk_state_off);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read area's fragment: "
				  "seg %llu, peb %llu, "
				  "ino %llu, logical_offset %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  le64_to_cpu(blk_desc->ino),
				  le32_to_cpu(blk_desc->logical_offset),
				  err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_peb_read_page() - read page from PEB
 * @pebc: pointer on PEB container
 * @req: request [in|out]
 * @end: pointer on waiting queue [out]
 *
 * This function tries to read PEB's page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EAGAIN     - PEB object is not initialized yet.
 */
int ssdfs_peb_read_page(struct ssdfs_peb_container *pebc,
			struct ssdfs_segment_request *req,
			struct completion **end)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *desc_off = NULL;
	struct ssdfs_blk_state_offset *blk_state = NULL;
	struct ssdfs_peb_info *pebi = NULL;
	u16 logical_blk;
	u16 log_start_page;
	struct ssdfs_metadata_descriptor desc_array[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_block_descriptor blk_desc = {0};
	int area_index;
	u8 peb_migration_id;
	u16 peb_index;
	bool is_migrating = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "ino %llu, logical_offset %llu, data_bytes %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes);

	fsi = pebc->parent_si->fsi;

	if (req->extent.data_bytes == 0) {
		SSDFS_WARN("empty read request: ino %llu, logical_offset %llu\n",
			   req->extent.ino, req->extent.logical_offset);
		return 0;
	}

	table = pebc->parent_si->blk2off_table;
	logical_blk = req->place.start.blk_index + req->result.processed_blks;

	desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index, &is_migrating);
	if (IS_ERR(desc_off) && PTR_ERR(desc_off) == -EAGAIN) {
		struct completion *init_end;
		unsigned long res;

		init_end = &table->full_init_end;

		res = wait_for_completion_timeout(init_end,
						  SSDFS_DEFAULT_TIMEOUT);
		if (res == 0) {
			err = -ERANGE;
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
							&peb_index,
							&is_migrating);
	}

	if (IS_ERR_OR_NULL(desc_off)) {
		err = (desc_off == NULL ? -ERANGE : PTR_ERR(desc_off));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

	peb_migration_id = desc_off->blk_state.peb_migration_id;

	SSDFS_DBG("logical_blk %u, peb_index %u, "
		  "logical_offset %u, logical_blk %u, peb_page %u, "
		  "log_start_page %u, log_area %u, "
		  "peb_migration_id %u, byte_offset %u\n",
		  logical_blk, pebc->peb_index,
		  le32_to_cpu(desc_off->page_desc.logical_offset),
		  le16_to_cpu(desc_off->page_desc.logical_blk),
		  le16_to_cpu(desc_off->page_desc.peb_page),
		  le16_to_cpu(desc_off->blk_state.log_start_page),
		  desc_off->blk_state.log_area,
		  desc_off->blk_state.peb_migration_id,
		  le32_to_cpu(desc_off->blk_state.byte_offset));

	if (is_migrating) {
		err = ssdfs_blk2off_table_get_block_state(table, req);
		if (err == -EAGAIN) {
			desc_off = ssdfs_blk2off_table_convert(table,
								logical_blk,
								&peb_index,
								&is_migrating);
			if (IS_ERR_OR_NULL(desc_off)) {
				err = (desc_off == NULL ?
						-ERANGE : PTR_ERR(desc_off));
				SSDFS_ERR("fail to convert: "
					  "logical_blk %u, err %d\n",
					  logical_blk, err);
				return err;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get migrating block state: "
				  "logical_blk %u, peb_index %u, err %d\n",
				  logical_blk, pebc->peb_index, err);
			return err;
		} else
			return 0;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (pebc->src_peb) {
		SSDFS_DBG("SRC: peb_migration_id %d\n",
			  ssdfs_get_peb_migration_id(pebc->src_peb));
	}

	if (pebc->dst_peb) {
		SSDFS_DBG("DST: peb_migration_id %d\n",
			  ssdfs_get_peb_migration_id(pebc->dst_peb));
	}
#endif /* CONFIG_SSDFS_DEBUG */

	down_read(&pebc->lock);

	if (pebc->src_peb) {
		int id1;

		switch (atomic_read(&pebc->src_peb->state)) {
		case SSDFS_PEB_OBJECT_CREATED:
			if (end == NULL) {
				err = -ERANGE;
				SSDFS_ERR("PEB object is not initialized\n");
				goto finish_read_page;
			} else {
				err = -EAGAIN;
				*end = &pebc->src_peb->init_end;
				goto finish_read_page;
			}
			break;

		case SSDFS_PEB_OBJECT_INITIALIZED:
			id1 = ssdfs_get_peb_migration_id(pebc->src_peb);
			if (peb_migration_id == id1) {
				/* use source PEB */
				pebi = pebc->src_peb;
				goto start_read_page;
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid SRC PEB state %#x\n",
				  atomic_read(&pebc->src_peb->state));
			goto finish_read_page;
		}
	}

	if (pebc->dst_peb) {
		int id2;

		switch (atomic_read(&pebc->dst_peb->state)) {
		case SSDFS_PEB_OBJECT_CREATED:
			if (end == NULL) {
				err = -ERANGE;
				SSDFS_ERR("PEB object is not initialized\n");
				goto finish_read_page;
			} else {
				err = -EAGAIN;
				*end = &pebc->dst_peb->init_end;
				goto finish_read_page;
			}
			break;

		case SSDFS_PEB_OBJECT_INITIALIZED:
			id2 = ssdfs_get_peb_migration_id(pebc->dst_peb);
			if (peb_migration_id == id2) {
				/* use destination PEB */
				pebi = pebc->dst_peb;
				goto start_read_page;
			}
			break;

		default:
			err = -ERANGE;
			SSDFS_ERR("invalid DST PEB state %#x\n",
				  atomic_read(&pebc->dst_peb->state));
			goto finish_read_page;
		}
	}

start_read_page:
	if (!pebi) {
		err = -ERANGE;

		if (pebc->src_peb) {
			SSDFS_ERR("SRC: peb_id %llu, peb_migration_id %d\n",
				  pebc->src_peb->peb_id,
				  ssdfs_get_peb_migration_id(pebc->src_peb));
		}

		if (pebc->dst_peb) {
			SSDFS_ERR("DST: peb_id %llu, peb_migration_id %d\n",
				  pebc->dst_peb->peb_id,
				  ssdfs_get_peb_migration_id(pebc->dst_peb));
		}

		SSDFS_WARN("invalid peb_migration_id: "
			   "seg %llu, peb_index %u, src_peb %p, "
			   "dst_peb %p, peb_migration_id %u\n",
			   pebc->parent_si->seg_id, pebc->peb_index,
			   pebc->src_peb, pebc->dst_peb,
			   peb_migration_id);
		goto finish_read_page;
	}

	blk_state = &desc_off->blk_state;
	log_start_page = le16_to_cpu(blk_state->log_start_page);

	if (log_start_page >= fsi->pages_per_peb) {
		err = -ERANGE;
		SSDFS_ERR("invalid log_start_page %u\n", log_start_page);
		goto finish_read_page;
	}

	err = ssdfs_peb_read_log_hdr_desc_array(pebi, log_start_page,
						desc_array,
						SSDFS_SEG_HDR_DESC_MAX);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read log's header desc array: "
			  "seg %llu, peb %llu, log_start_page %u, err %d\n",
			  pebc->parent_si->seg_id, pebi->peb_id,
			  log_start_page, err);
		goto finish_read_page;
	}

	area_index = SSDFS_AREA_TYPE2INDEX(blk_state->log_area);

	if (area_index >= SSDFS_SEG_HDR_DESC_MAX) {
		err = -ERANGE;
		SSDFS_ERR("invalid area index %#x\n", area_index);
		goto finish_read_page;
	}

	err = ssdfs_peb_find_block_descriptor(pebi, req,
					      desc_array,
					      SSDFS_SEG_HDR_DESC_MAX,
					      blk_state,
					      &blk_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get block descriptor: err %d\n",
			  err);
		goto finish_read_page;
	}

	err = ssdfs_peb_read_block_state(pebi, req,
					 desc_array,
					 SSDFS_SEG_HDR_DESC_MAX,
					 &blk_desc, 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block state: err %d\n",
			  err);
		goto finish_read_page;
	}

finish_read_page:
	up_read(&pebc->lock);

	return err;
}

/*
 * ssdfs_peb_readahead_pages() - read-ahead pages from PEB
 * @pebc: pointer on PEB container
 * @req: request [in|out]
 * @end: pointer on waiting queue [out]
 *
 * This function tries to read-ahead PEB's pages.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_readahead_pages(struct ssdfs_peb_container *pebc,
			      struct ssdfs_segment_request *req,
			      struct completion **end)
{
	struct ssdfs_fs_info *fsi;
	u32 pages_count;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "ino %llu, logical_offset %llu, data_bytes %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes);

	fsi = pebc->parent_si->fsi;

	if (req->extent.data_bytes == 0) {
		SSDFS_WARN("empty read request: ino %llu, logical_offset %llu\n",
			   req->extent.ino, req->extent.logical_offset);
		return 0;
	}

	pages_count = req->extent.data_bytes + fsi->pagesize - 1;
	pages_count >>= fsi->log_pagesize;

	for (i = req->result.processed_blks; i < pages_count; i++) {
		int err = ssdfs_peb_read_page(pebc, req, end);
		if (err == -EAGAIN) {
			SSDFS_DBG("unable to process page %d\n", i);
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to process page %d, err %d\n",
				  i, err);
			return err;
		}
	}

	return 0;
}

/*
 * __ssdfs_peb_read_log_footer() - read log's footer
 * @fsi: file system info object
 * @pebi: PEB object
 * @page_off: log's starting page
 * @desc: footer's descriptor
 * @log_bytes: pointer on value of bytes in the log [out]
 *
 * This function tries to read log's footer.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - valid footer is not found.
 */
static
int __ssdfs_peb_read_log_footer(struct ssdfs_fs_info *fsi,
				struct ssdfs_peb_info *pebi,
				u16 page_off,
				struct ssdfs_metadata_descriptor *desc,
				u32 *log_bytes)
{
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_partial_log_header *plh_hdr = NULL;
	struct ssdfs_log_footer *footer = NULL;
	u16 footer_off;
	u32 bytes_off;
	struct page *page;
	void *kaddr;
	size_t read_bytes;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!desc || !log_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_id %llu, page_off %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, page_off);

	*log_bytes = U32_MAX;

	bytes_off = le32_to_cpu(desc->offset);
	footer_off = bytes_off / fsi->pagesize;

	page = ssdfs_page_array_grab_page(&pebi->cache, footer_off);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		SSDFS_ERR("fail to grab page: index %u\n",
			  footer_off);
		return -ENOMEM;
	}

	kaddr = kmap(page);

	if (PageUptodate(page) || PageDirty(page))
		goto check_footer_magic;

	err = ssdfs_aligned_read_buffer(fsi, pebi->peb_id,
					bytes_off,
					(u8 *)kaddr,
					PAGE_SIZE,
					&read_bytes);
	if (unlikely(err))
		goto fail_read_footer;
	else if (unlikely(read_bytes != PAGE_SIZE)) {
		err = -ERANGE;
		goto fail_read_footer;
	}

	SetPageUptodate(page);

check_footer_magic:
	magic = (struct ssdfs_signature *)kaddr;

	if (!is_ssdfs_magic_valid(magic)) {
		err = -ENODATA;
		goto fail_read_footer;
	}

	if (is_ssdfs_partial_log_header_magic_valid(magic)) {
		plh_hdr = SSDFS_PLH(kaddr);
		*log_bytes = le32_to_cpu(plh_hdr->log_bytes);
	} else if (__is_ssdfs_log_footer_magic_valid(magic)) {
		footer = SSDFS_LF(kaddr);
		*log_bytes = le32_to_cpu(footer->log_bytes);
	} else {
		err = -ENODATA;
		SSDFS_DBG("log footer is corrupted: "
			  "peb %llu, page_off %u\n",
			  pebi->peb_id, page_off);
		goto fail_read_footer;
	}

fail_read_footer:
	kunmap(page);
	unlock_page(page);
	put_page(page);

	if (err == -ENODATA) {
		SSDFS_DBG("valid footer is not detected: "
			  "seg_id %llu, peb_id %llu, "
			  "page_off %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  footer_off);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read footer: "
			  "seg %llu, peb %llu, "
			  "pages_off %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  footer_off,
			  err);
		return err;
	}

	return 0;
}

/*
 * __ssdfs_peb_read_log_header() - read log's header
 * @fsi: file system info object
 * @pebi: PEB object
 * @page_off: log's starting page
 * @log_bytes: pointer on value of bytes in the log [out]
 *
 * This function tries to read the log's header.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - valid footer is not found.
 */
static
int __ssdfs_peb_read_log_header(struct ssdfs_fs_info *fsi,
				struct ssdfs_peb_info *pebi,
				u16 page_off,
				u32 *log_bytes)
{
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *pl_hdr = NULL;
	struct ssdfs_metadata_descriptor *desc = NULL;
	struct page *page;
	void *kaddr;
	size_t read_bytes;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!log_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_id %llu, page_off %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, page_off);

	*log_bytes = U32_MAX;

	page = ssdfs_page_array_grab_page(&pebi->cache, page_off);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		SSDFS_ERR("fail to grab page: index %u\n",
			  page_off);
		return -ENOMEM;
	}

	kaddr = kmap(page);

	if (PageUptodate(page) || PageDirty(page))
		goto check_header_magic;

	err = ssdfs_aligned_read_buffer(fsi, pebi->peb_id,
					page_off * PAGE_SIZE,
					(u8 *)kaddr,
					PAGE_SIZE,
					&read_bytes);
	if (unlikely(err))
		goto fail_read_log_header;
	else if (unlikely(read_bytes != PAGE_SIZE)) {
		err = -ERANGE;
		goto fail_read_log_header;
	}

	SetPageUptodate(page);

check_header_magic:
	magic = (struct ssdfs_signature *)kaddr;

	if (!is_ssdfs_magic_valid(magic)) {
		err = -ENODATA;
		goto fail_read_log_header;
	}

	if (__is_ssdfs_segment_header_magic_valid(magic)) {
		seg_hdr = SSDFS_SEG_HDR(kaddr);

		err = ssdfs_check_segment_header(fsi, seg_hdr,
						 false);
		if (unlikely(err)) {
			err = -ENODATA;
			SSDFS_DBG("log header is corrupted: "
				  "seg %llu, peb %llu, page_off %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  page_off);
			goto fail_read_log_header;
		}

		desc = &seg_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];

		err = __ssdfs_peb_read_log_footer(fsi, pebi, page_off,
						   desc, log_bytes);
		if (err == -ENODATA) {
			SSDFS_DBG("fail to read footer: "
				  "seg %llu, peb %llu, page_off %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  page_off,
				  err);
			goto fail_read_log_header;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read footer: "
				  "seg %llu, peb %llu, page_off %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  page_off,
				  err);
			goto fail_read_log_header;
		}
	} else if (is_ssdfs_partial_log_header_magic_valid(magic)) {
		pl_hdr = SSDFS_PLH(kaddr);

		err = ssdfs_check_partial_log_header(fsi, pl_hdr,
						     false);
		if (unlikely(err)) {
			err = -ENODATA;
			SSDFS_DBG("partial log header is corrupted: "
				  "seg %llu, peb %llu, page_off %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  page_off);
			goto fail_read_log_header;
		}

		desc = &pl_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];

		if (ssdfs_pl_has_footer(pl_hdr)) {
			err = __ssdfs_peb_read_log_footer(fsi, pebi, page_off,
							  desc, log_bytes);
			if (err == -ENODATA) {
				SSDFS_DBG("fail to read footer: "
					  "seg %llu, peb %llu, page_off %u, "
					  "err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  page_off,
					  err);
				goto fail_read_log_header;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to read footer: "
					  "seg %llu, peb %llu, page_off %u, "
					  "err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  page_off,
					  err);
				goto fail_read_log_header;
			}
		} else
			*log_bytes = le32_to_cpu(pl_hdr->log_bytes);
	} else {
		err = -ENODATA;
		SSDFS_DBG("log header is corrupted: "
			  "seg %llu, peb %llu, page_off %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  page_off);
		goto fail_read_log_header;
	}

fail_read_log_header:
	kunmap(page);
	unlock_page(page);
	put_page(page);

	if (err == -ENODATA) {
		SSDFS_DBG("valid header is not detected: "
			  "seg_id %llu, peb_id %llu, page_off %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  page_off);
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read checked log header: "
			  "seg %llu, peb %llu, "
			  "pages_off %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  page_off, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_read_all_log_headers() - read all PEB's log headers
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This function tries to read all headers and footers of
 * the PEB's logs.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_peb_read_all_log_headers(struct ssdfs_peb_info *pebi,
				   struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	u32 log_bytes = U32_MAX;
	u32 page_off;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "ino %llu, logical_offset %llu, data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes);

	fsi = pebi->pebc->parent_si->fsi;
	page_off = 0;

	do {
		u32 pages_per_log;

		err = __ssdfs_peb_read_log_header(fsi, pebi, page_off,
						  &log_bytes);
		if (err == -ENODATA)
			return 0;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to read log header: "
				  "seg %llu, peb %llu, page_off %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  page_off,
				  err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(log_bytes >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		pages_per_log = log_bytes + fsi->pagesize - 1;
		pages_per_log /= fsi->pagesize;
		page_off += pages_per_log;
	} while (page_off < fsi->pages_per_peb);

	return 0;
}

/*
 * ssdfs_peb_read_src_all_log_headers() - read all source PEB's log headers
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This function tries to read all headers and footers of
 * the source PEB's logs.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_peb_read_src_all_log_headers(struct ssdfs_peb_container *pebc,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_peb_info *pebi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (!pebi) {
		SSDFS_WARN("source PEB is NULL\n");
		err = -ERANGE;
		goto finish_read_src_all_log_headers;
	}

	err = ssdfs_peb_read_all_log_headers(pebi, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read the log's headers: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		goto finish_read_src_all_log_headers;
	}

finish_read_src_all_log_headers:
	up_read(&pebc->lock);

	return err;
}

/*
 * ssdfs_peb_read_dst_all_log_headers() - read all dst PEB's log headers
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This function tries to read all headers and footers of
 * the destination PEB's logs.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_peb_read_dst_all_log_headers(struct ssdfs_peb_container *pebc,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_peb_info *pebi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	down_read(&pebc->lock);

	pebi = pebc->dst_peb;
	if (!pebi) {
		SSDFS_WARN("destination PEB is NULL\n");
		err = -ERANGE;
		goto finish_read_dst_all_log_headers;
	}

	err = ssdfs_peb_read_all_log_headers(pebi, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read the log's headers: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		goto finish_read_dst_all_log_headers;
	}

finish_read_dst_all_log_headers:
	up_read(&pebc->lock);

	return err;
}

/*
 * ssdfs_peb_get_log_pages_count() - determine count of pages in the log
 * @fsi: file system info object
 * @pebi: PEB object
 * @env: init environment [in | out]
 *
 * This function reads segment header of the first log in
 * segment and to retrieve log_pages field. Also it initilizes
 * current and previous PEB migration IDs.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_get_log_pages_count(struct ssdfs_fs_info *fsi,
				  struct ssdfs_peb_info *pebi,
				  struct ssdfs_read_init_env *env)
{
	struct ssdfs_signature *magic;
	struct page *page;
	void *kaddr;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u16 log_pages;
	u32 pages_off = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !env || !env->log_hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb %llu, env %p\n", pebi->peb_id, env);

	page = ssdfs_page_array_get_page_locked(&pebi->cache, 0);
	if (IS_ERR_OR_NULL(page)) {
		err = ssdfs_read_checked_segment_header(fsi,
							pebi->peb_id,
							0,
							env->log_hdr,
							false);
		if (err) {
			SSDFS_ERR("fail to read checked segment header: "
				  "peb %llu, err %d\n",
				  pebi->peb_id, err);
			return err;
		}
	} else {
		kaddr = kmap_atomic(page);
		memcpy(env->log_hdr, kaddr, hdr_buf_size);
		kunmap_atomic(kaddr);
		unlock_page(page);
		put_page(page);
	}

	magic = (struct ssdfs_signature *)env->log_hdr;

#ifdef CONFIG_SSDFS_DEBUG
	if (!is_ssdfs_magic_valid(magic)) {
		SSDFS_ERR("valid magic is not detected\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (__is_ssdfs_segment_header_magic_valid(magic)) {
		struct ssdfs_segment_header *seg_hdr;

		seg_hdr = SSDFS_SEG_HDR(env->log_hdr);
		log_pages = le16_to_cpu(seg_hdr->log_pages);
		env->log_pages = log_pages;
		env->cur_migration_id =
			seg_hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB];
		env->prev_migration_id =
			seg_hdr->peb_migration_id[SSDFS_PREV_MIGRATING_PEB];
	} else {
		SSDFS_ERR("log header is corrupted: "
			  "peb %llu, pages_off %u\n",
			  pebi->peb_id, pages_off);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	/* BUG_ON(fsi->pages_per_peb % log_pages); */
	if (fsi->pages_per_peb % log_pages) {
		SSDFS_WARN("fsi->pages_per_peb %u, log_pages %u\n",
			   fsi->pages_per_peb, log_pages);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (log_pages > fsi->pages_per_peb) {
		SSDFS_ERR("log_pages %u > fsi->pages_per_peb %u\n",
			  log_pages, fsi->pages_per_peb);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_find_last_partial_log() - find the last partial log
 * @fsi: file system info object
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 * @new_log_start_page: pointer on the new log's start page [out]
 *
 * This function tries to find the last partial log
 * in the PEB's cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 */
static
int ssdfs_find_last_partial_log(struct ssdfs_fs_info *fsi,
				struct ssdfs_peb_info *pebi,
				struct ssdfs_read_init_env *env,
				u16 *new_log_start_page)
{
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *pl_hdr = NULL;
	struct ssdfs_log_footer *footer = NULL;
	struct page *page;
	void *kaddr;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u32 byte_offset, page_offset;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !env);
	BUG_ON(!new_log_start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);

	*new_log_start_page = U16_MAX;

	for (i = fsi->pages_per_peb - 1; i >= 0; i--) {
		page = ssdfs_page_array_get_page_locked(&pebi->cache, i);
		if (IS_ERR_OR_NULL(page)) {
			if (page == NULL) {
				SSDFS_ERR("fail to get page: "
					  "index %d\n",
					  i);
				return -ERANGE;
			} else {
				err = PTR_ERR(page);

				if (err == -ENOENT)
					continue;
				else {
					SSDFS_ERR("fail to get page: "
						  "index %d, err %d\n",
						  i, err);
					return err;
				}
			}
		}

		kaddr = kmap_atomic(page);
		memcpy(env->log_hdr, kaddr, hdr_buf_size);
		kunmap_atomic(kaddr);
		unlock_page(page);
		put_page(page);

		magic = (struct ssdfs_signature *)env->log_hdr;

		if (!is_ssdfs_magic_valid(magic))
			continue;

		if (__is_ssdfs_segment_header_magic_valid(magic)) {
			seg_hdr = SSDFS_SEG_HDR(env->log_hdr);

			err = ssdfs_check_segment_header(fsi, seg_hdr,
							 false);
			if (unlikely(err)) {
				SSDFS_ERR("log header is corrupted: "
					  "seg %llu, peb %llu, index %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  i);
				return -EIO;
			}

			if (*new_log_start_page >= U16_MAX) {
				SSDFS_ERR("invalid new_log_start_page\n");
				return -EIO;
			}

			byte_offset = i * fsi->pagesize;
			byte_offset += env->log_bytes;
			byte_offset += fsi->pagesize - 1;
			page_offset = byte_offset / fsi->pagesize;

			if (*new_log_start_page < page_offset) {
				SSDFS_DBG("correct new log start page: "
					  "old value %u, new value %u\n",
					  *new_log_start_page,
					  page_offset);
				*new_log_start_page = page_offset;
			} else if (page_offset != *new_log_start_page) {
				SSDFS_ERR("invalid new log start: "
					  "page_offset %u, "
					  "new_log_start_page %u\n",
					  page_offset,
					  *new_log_start_page);
				return -EIO;
			}

			env->log_offset = (u16)i;
			goto finish_last_log_search;
		} else if (is_ssdfs_partial_log_header_magic_valid(magic)) {
			u32 flags;

			pl_hdr = SSDFS_PLH(kaddr);

			err = ssdfs_check_partial_log_header(fsi, pl_hdr,
							     false);
			if (unlikely(err)) {
				SSDFS_ERR("partial log header is corrupted: "
					  "seg %llu, peb %llu, index %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  i);
				return -EIO;
			}

			flags = le32_to_cpu(pl_hdr->pl_flags);

			if (flags & SSDFS_PARTIAL_HEADER_INSTEAD_FOOTER) {
				/* first partial log */
#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON((i + 1) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

				byte_offset = (i + 1) * fsi->pagesize;
				byte_offset += fsi->pagesize - 1;

				*new_log_start_page =
					(u16)(byte_offset / fsi->pagesize);
				env->log_bytes =
					le32_to_cpu(pl_hdr->log_bytes);
				continue;
			} else if (flags & SSDFS_LOG_HAS_FOOTER) {
				/* last partial log */

				env->log_bytes =
					le32_to_cpu(pl_hdr->log_bytes);

				byte_offset = i * fsi->pagesize;
				byte_offset += env->log_bytes;
				byte_offset += fsi->pagesize - 1;
				page_offset = byte_offset / fsi->pagesize;

				if (*new_log_start_page < page_offset) {
					SSDFS_DBG("correct new log start page: "
						  "old value %u, "
						  "new value %u\n",
						  *new_log_start_page,
						  page_offset);
					*new_log_start_page = page_offset;
				} else if (page_offset != *new_log_start_page) {
					SSDFS_ERR("invalid new log start: "
						  "page_offset %u, "
						  "new_log_start_page %u\n",
						  page_offset,
						  *new_log_start_page);
					return -EIO;
				}

				env->log_offset = (u16)i;
				goto finish_last_log_search;
			} else {
				/* intermediate partial log */

				env->log_bytes =
					le32_to_cpu(pl_hdr->log_bytes);

				byte_offset = i * fsi->pagesize;
				byte_offset += env->log_bytes;
				byte_offset += fsi->pagesize - 1;
				page_offset = byte_offset / fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(page_offset >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

				*new_log_start_page = (u16)page_offset;
				env->log_offset = (u16)i;
				goto finish_last_log_search;
			}
		} else if (__is_ssdfs_log_footer_magic_valid(magic)) {
			footer = SSDFS_LF(env->footer);

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON((i + 1) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

			byte_offset = (i + 1) * fsi->pagesize;
			byte_offset += fsi->pagesize - 1;

			*new_log_start_page =
				(u16)(byte_offset / fsi->pagesize);
			env->log_bytes =
				le32_to_cpu(footer->log_bytes);
			continue;
		} else {
			SSDFS_ERR("log header is corrupted: "
				  "seg %llu, peb %llu, index %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  i);
			return -ERANGE;
		}
	}

finish_last_log_search:
	if (env->log_offset >= fsi->pages_per_peb) {
		SSDFS_ERR("log_offset %u >= pages_per_peb %u\n",
			  env->log_offset, fsi->pages_per_peb);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->erasesize < env->log_bytes) {
		SSDFS_WARN("fsi->erasesize %u, log_bytes %u\n",
			   fsi->erasesize,
			   env->log_bytes);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_check_log_header() - check log's header
 * @fsi: file system info object
 * @env: init environment [in|out]
 *
 * This function checks the log's header.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - I/O error.
 * %-ENODATA    - valid magic is not detected.
 */
static inline
int ssdfs_check_log_header(struct ssdfs_fs_info *fsi,
			   struct ssdfs_read_init_env *env)
{
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *pl_hdr = NULL;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!env || !env->log_hdr || !env->footer);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("log_offset %u, log_pages %u\n",
		  env->log_offset, env->log_pages);

	magic = (struct ssdfs_signature *)env->log_hdr;

	if (!is_ssdfs_magic_valid(magic)) {
		SSDFS_DBG("valid magic is not detected\n");
		return -ENODATA;
	}

	if (__is_ssdfs_segment_header_magic_valid(magic)) {
		seg_hdr = SSDFS_SEG_HDR(env->log_hdr);

		err = ssdfs_check_segment_header(fsi, seg_hdr,
						 false);
		if (unlikely(err)) {
			SSDFS_ERR("log header is corrupted\n");
			return -EIO;
		}

		env->has_seg_hdr = true;
		env->has_footer = ssdfs_log_has_footer(seg_hdr);
	} else if (is_ssdfs_partial_log_header_magic_valid(magic)) {
		pl_hdr = SSDFS_PLH(env->log_hdr);

		err = ssdfs_check_partial_log_header(fsi, pl_hdr,
						     false);
		if (unlikely(err)) {
			SSDFS_ERR("partial log header is corrupted\n");
			return -EIO;
		}

		env->has_seg_hdr = false;
		env->has_footer = ssdfs_pl_has_footer(pl_hdr);
	} else {
		SSDFS_DBG("log header is corrupted\n");
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_get_segment_header_blk_bmap_desc() - get block bitmap's descriptor
 * @pebi: pointer on PEB object
 * @env: init environment [in]
 * @desc: block bitmap's descriptor [out]
 *
 * This function tries to extract the block bitmap's descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 */
static
int ssdfs_get_segment_header_blk_bmap_desc(struct ssdfs_peb_info *pebi,
					struct ssdfs_read_init_env *env,
					struct ssdfs_metadata_descriptor **desc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_header *seg_hdr = NULL;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	u32 pages_off;
	u32 bytes_off;
	struct page *page;
	void *kaddr;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	*desc = NULL;

	if (!env->has_seg_hdr) {
		SSDFS_ERR("segment header is absent\n");
		return -ERANGE;
	}

	seg_hdr = SSDFS_SEG_HDR(env->log_hdr);

	if (!ssdfs_seg_hdr_has_blk_bmap(seg_hdr)) {
		if (!env->has_footer) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__,
					__LINE__,
					"log hasn't footer\n");
			return -EIO;
		}

		*desc = &seg_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];

		bytes_off = le32_to_cpu((*desc)->offset);
		pages_off = bytes_off / fsi->pagesize;

		page = ssdfs_page_array_get_page_locked(&pebi->cache,
							pages_off);
		if (IS_ERR_OR_NULL(page)) {
			err = ssdfs_read_checked_log_footer(fsi,
							    env->log_hdr,
							    pebi->peb_id,
							    bytes_off,
							    env->footer,
							    false);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read checked log footer: "
					  "seg %llu, peb %llu, bytes_off %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id, bytes_off);
				return err;
			}
		} else {
			kaddr = kmap_atomic(page);
			memcpy(env->footer, kaddr, footer_size);
			kunmap_atomic(kaddr);
			unlock_page(page);
			put_page(page);
		}

		if (!ssdfs_log_footer_has_blk_bmap(env->footer)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__,
					__LINE__,
					"log hasn't block bitmap\n");
			return -EIO;
		}

		*desc = &env->footer->desc_array[SSDFS_BLK_BMAP_INDEX];
	} else
		*desc = &seg_hdr->desc_array[SSDFS_BLK_BMAP_INDEX];

	return 0;
}

/*
 * ssdfs_get_partial_header_blk_bmap_desc() - get block bitmap's descriptor
 * @pebi: pointer on PEB object
 * @env: init environment [in]
 * @desc: block bitmap's descriptor [out]
 *
 * This function tries to extract the block bitmap's descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 */
static
int ssdfs_get_partial_header_blk_bmap_desc(struct ssdfs_peb_info *pebi,
					struct ssdfs_read_init_env *env,
					struct ssdfs_metadata_descriptor **desc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_partial_log_header *pl_hdr = NULL;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	u32 pages_off;
	u32 bytes_off;
	struct page *page;
	void *kaddr;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	*desc = NULL;

	if (env->has_seg_hdr) {
		SSDFS_ERR("partial log header is absent\n");
		return -ERANGE;
	}

	pl_hdr = SSDFS_PLH(env->log_hdr);

	if (!ssdfs_pl_hdr_has_blk_bmap(pl_hdr)) {
		if (!env->has_footer) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__,
					__LINE__,
					"log hasn't footer\n");
			return -EIO;
		}

		*desc = &pl_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];

		bytes_off = le32_to_cpu((*desc)->offset);
		pages_off = bytes_off / fsi->pagesize;

		page = ssdfs_page_array_get_page_locked(&pebi->cache,
							pages_off);
		if (IS_ERR_OR_NULL(page)) {
			err = ssdfs_read_checked_log_footer(fsi,
							    env->log_hdr,
							    pebi->peb_id,
							    bytes_off,
							    env->footer,
							    false);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read checked log footer: "
					  "seg %llu, peb %llu, bytes_off %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id, bytes_off);
				return err;
			}
		} else {
			kaddr = kmap_atomic(page);
			memcpy(env->footer, kaddr, footer_size);
			kunmap_atomic(kaddr);
			unlock_page(page);
			put_page(page);
		}

		if (!ssdfs_log_footer_has_blk_bmap(env->footer)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__,
					__LINE__,
					"log hasn't block bitmap\n");
			return -EIO;
		}

		*desc = &env->footer->desc_array[SSDFS_BLK_BMAP_INDEX];
	} else
		*desc = &pl_hdr->desc_array[SSDFS_BLK_BMAP_INDEX];

	return 0;
}

/*
 * ssdfs_pre_fetch_block_bitmap() - pre-fetch block bitmap
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 *
 * This function tries to check the presence of block bitmap
 * in the PEB's cache. Otherwise, it tries to read the block
 * bitmap from the volume into the PEB's cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_pre_fetch_block_bitmap(struct ssdfs_peb_info *pebi,
				 struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor *desc = NULL;
	struct page *page;
	void *kaddr;
	u32 pages_off;
	u32 bytes_off;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u32 area_offset, area_size;
	u32 cur_page, page_start, page_end;
	size_t read_bytes;
	size_t bmap_hdr_size = sizeof(struct ssdfs_block_bitmap_header);
	u32 pebsize;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);

	fsi = pebi->pebc->parent_si->fsi;
	pages_off = env->log_offset;
	pebsize = fsi->pages_per_peb * fsi->pagesize;

	page = ssdfs_page_array_get_page_locked(&pebi->cache, pages_off);
	if (IS_ERR_OR_NULL(page)) {
		err = ssdfs_read_checked_segment_header(fsi,
							pebi->peb_id,
							pages_off,
							env->log_hdr,
							false);
		if (err) {
			SSDFS_ERR("fail to read checked segment header: "
				  "peb %llu, err %d\n",
				  pebi->peb_id, err);
			return err;
		}
	} else {
		kaddr = kmap_atomic(page);
		memcpy(env->log_hdr, kaddr, hdr_buf_size);
		kunmap_atomic(kaddr);
		unlock_page(page);
		put_page(page);
	}

	err = ssdfs_check_log_header(fsi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to check log header: "
			  "err %d\n", err);
		return err;
	}

	if (env->has_seg_hdr)
		err = ssdfs_get_segment_header_blk_bmap_desc(pebi, env, &desc);
	else
		err = ssdfs_get_partial_header_blk_bmap_desc(pebi, env, &desc);

	if (unlikely(err)) {
		SSDFS_ERR("fail to get descriptor: "
			  "err %d\n", err);
		return err;
	}

	if (!desc) {
		SSDFS_ERR("invalid descriptor pointer\n");
		return -ERANGE;
	}

	area_offset = le32_to_cpu(desc->offset);
	area_size = le32_to_cpu(desc->size);

	if (bmap_hdr_size != le16_to_cpu(desc->check.bytes)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"bmap_hdr_size %zu != desc->check.bytes %u\n",
				bmap_hdr_size,
				le16_to_cpu(desc->check.bytes));
		return -EIO;
	}

	if (area_offset >= pebsize) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"desc->offset %u >= pebsize %u\n",
				area_offset, pebsize);
		return -EIO;
	}

	bytes_off = area_offset;
	page_start = bytes_off / fsi->pagesize;
	bytes_off += area_size - 1;
	page_end = bytes_off / fsi->pagesize;

	for (cur_page = page_start; cur_page <= page_end; cur_page++) {
		page = ssdfs_page_array_get_page_locked(&pebi->cache,
							cur_page);
		if (IS_ERR_OR_NULL(page)) {
			page = ssdfs_page_array_grab_page(&pebi->cache,
							  cur_page);
			if (unlikely(IS_ERR_OR_NULL(page))) {
				SSDFS_ERR("fail to grab page: index %u\n",
					  cur_page);
				return -ENOMEM;
			}

			kaddr = kmap(page);
			err = ssdfs_aligned_read_buffer(fsi, pebi->peb_id,
							cur_page * PAGE_SIZE,
							(u8 *)kaddr,
							PAGE_SIZE,
							&read_bytes);
			kunmap(page);

			if (unlikely(err)) {
				SSDFS_ERR("fail to read memory page: "
					  "index %u, err %d\n",
					  cur_page, err);
				goto finish_read_page;
			} else if (unlikely(read_bytes != PAGE_SIZE)) {
				err = -ERANGE;
				SSDFS_ERR("invalid read_bytes %zu\n",
					  read_bytes);
				goto finish_read_page;
			}

			SetPageUptodate(page);

finish_read_page:
			unlock_page(page);
			put_page(page);
		} else {
			unlock_page(page);
			put_page(page);
		}
	}

	return err;
}

/*
 * ssdfs_get_segment_header_blk2off_tbl_desc() - get blk2off tbl's descriptor
 * @pebi: pointer on PEB object
 * @env: init environment [in]
 * @desc: blk2off tbl's descriptor [out]
 *
 * This function tries to extract the blk2off table's descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 */
static inline
int ssdfs_get_segment_header_blk2off_tbl_desc(struct ssdfs_peb_info *pebi,
					struct ssdfs_read_init_env *env,
					struct ssdfs_metadata_descriptor **desc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_header *seg_hdr = NULL;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	*desc = NULL;
	fsi = pebi->pebc->parent_si->fsi;

	if (!env->has_seg_hdr) {
		SSDFS_ERR("segment header is absent\n");
		return -ERANGE;
	}

	seg_hdr = SSDFS_SEG_HDR(env->log_hdr);

	if (!ssdfs_seg_hdr_has_offset_table(seg_hdr)) {
		if (!env->has_footer) {
			ssdfs_fs_error(fsi->sb, __FILE__,
					__func__, __LINE__,
					"log hasn't footer\n");
			return -EIO;
		}

		if (!ssdfs_log_footer_has_offset_table(env->footer)) {
			ssdfs_fs_error(fsi->sb, __FILE__,
					__func__, __LINE__,
					"log hasn't blk2off table\n");
			return -EIO;
		}

		*desc = &env->footer->desc_array[SSDFS_OFF_TABLE_INDEX];
	} else
		*desc = &seg_hdr->desc_array[SSDFS_OFF_TABLE_INDEX];

	return 0;
}

/*
 * ssdfs_get_partial_header_blk2off_tbl_desc() - get blk2off tbl's descriptor
 * @pebi: pointer on PEB object
 * @env: init environment [in]
 * @desc: blk2off tbl's descriptor [out]
 *
 * This function tries to extract the blk2off table's descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 */
static inline
int ssdfs_get_partial_header_blk2off_tbl_desc(struct ssdfs_peb_info *pebi,
					struct ssdfs_read_init_env *env,
					struct ssdfs_metadata_descriptor **desc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_partial_log_header *pl_hdr = NULL;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	*desc = NULL;
	fsi = pebi->pebc->parent_si->fsi;

	if (env->has_seg_hdr) {
		SSDFS_ERR("partial log header is absent\n");
		return -ERANGE;
	}

	pl_hdr = SSDFS_PLH(env->log_hdr);

	if (!ssdfs_pl_hdr_has_offset_table(pl_hdr)) {
		if (!env->has_footer) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__,
					__LINE__,
					"log hasn't footer\n");
			return -EIO;
		}

		if (!ssdfs_log_footer_has_offset_table(env->footer)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__,
					__LINE__,
					"log hasn't block bitmap\n");
			return -EIO;
		}

		*desc = &env->footer->desc_array[SSDFS_OFF_TABLE_INDEX];
	} else
		*desc = &pl_hdr->desc_array[SSDFS_OFF_TABLE_INDEX];

	return 0;
}

/*
 * ssdfs_pre_fetch_blk2off_table_area() - pre-fetch blk2off table
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 *
 * This function tries to check the presence of blk2off table
 * in the PEB's cache. Otherwise, it tries to read the blk2off table
 * from the volume into the PEB's cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_pre_fetch_blk2off_table_area(struct ssdfs_peb_info *pebi,
					struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor *desc = NULL;
	struct page *page;
	void *kaddr;
	u32 pages_off;
	u32 bytes_off;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u32 area_offset, area_size;
	u32 cur_page, page_start, page_end;
	size_t read_bytes;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);

	fsi = pebi->pebc->parent_si->fsi;
	pages_off = env->log_offset;

	page = ssdfs_page_array_get_page_locked(&pebi->cache, pages_off);
	if (IS_ERR_OR_NULL(page)) {
		err = ssdfs_read_checked_segment_header(fsi,
							pebi->peb_id,
							pages_off,
							env->log_hdr,
							false);
		if (err) {
			SSDFS_ERR("fail to read checked segment header: "
				  "peb %llu, err %d\n",
				  pebi->peb_id, err);
			return err;
		}
	} else {
		kaddr = kmap_atomic(page);
		memcpy(env->log_hdr, kaddr, hdr_buf_size);
		kunmap_atomic(kaddr);
		unlock_page(page);
		put_page(page);
	}

	err = ssdfs_check_log_header(fsi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to check log header: "
			  "err %d\n", err);
		return err;
	}

	if (env->has_seg_hdr) {
		err = ssdfs_get_segment_header_blk2off_tbl_desc(pebi, env,
								&desc);
	} else {
		err = ssdfs_get_partial_header_blk2off_tbl_desc(pebi, env,
								&desc);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to get descriptor: "
			  "err %d\n", err);
		return err;
	}

	if (!desc) {
		SSDFS_ERR("invalid descriptor pointer\n");
		return -ERANGE;
	}

	area_offset = le32_to_cpu(desc->offset);
	area_size = le32_to_cpu(desc->size);

	bytes_off = area_offset;
	page_start = bytes_off / fsi->pagesize;
	bytes_off += area_size - 1;
	page_end = bytes_off / fsi->pagesize;

	for (cur_page = page_start; cur_page <= page_end; cur_page++) {
		page = ssdfs_page_array_get_page_locked(&pebi->cache,
							cur_page);
		if (IS_ERR_OR_NULL(page)) {
			page = ssdfs_page_array_grab_page(&pebi->cache,
							  cur_page);
			if (unlikely(IS_ERR_OR_NULL(page))) {
				SSDFS_ERR("fail to grab page: index %u\n",
					  cur_page);
				return -ENOMEM;
			}

			kaddr = kmap(page);
			err = ssdfs_aligned_read_buffer(fsi, pebi->peb_id,
							cur_page * PAGE_SIZE,
							(u8 *)kaddr,
							PAGE_SIZE,
							&read_bytes);
			kunmap(page);

			if (unlikely(err)) {
				SSDFS_ERR("fail to read memory page: "
					  "index %u, err %d\n",
					  cur_page, err);
				goto finish_read_page;
			} else if (unlikely(read_bytes != PAGE_SIZE)) {
				err = -ERANGE;
				SSDFS_ERR("invalid read_bytes %zu\n",
					  read_bytes);
				goto finish_read_page;
			}

			SetPageUptodate(page);

finish_read_page:
			unlock_page(page);
			put_page(page);
		} else {
			unlock_page(page);
			put_page(page);
		}
	}

	return err;
}

/*
 * ssdfs_read_checked_block_bitmap_header() - read and check block bitmap header
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 *
 * This function reads block bitmap header from the volume and
 * to check it consistency.
 *
 * RETURN:
 * [success] - block bitmap header has been read in consistent state.
 * [failure] - error code:
 *
 * %-EIO        - I/O error.
 */
static
int ssdfs_read_checked_block_bitmap_header(struct ssdfs_peb_info *pebi,
					   struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct page *page;
	void *kaddr;
	u32 pages_off;
	u32 area_offset;
	struct ssdfs_metadata_descriptor *desc = NULL;
	size_t bmap_hdr_size = sizeof(struct ssdfs_block_bitmap_header);
	size_t hdr_buf_size = max_t(size_t,
				sizeof(struct ssdfs_segment_header),
				sizeof(struct ssdfs_partial_log_header));
	u32 pebsize;
	u32 read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env || !env->log_hdr || !env->footer);
	BUG_ON(env->log_pages >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON((env->log_offset) >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON(!env->b_init.bmap_hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, log_offset %u, log_pages %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->log_offset, env->log_pages);

	fsi = pebi->pebc->parent_si->fsi;
	pages_off = env->log_offset;
	pebsize = fsi->pages_per_peb * fsi->pagesize;

	page = ssdfs_page_array_get_page_locked(&pebi->cache, pages_off);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to read checked segment header: "
			  "peb %llu\n", pebi->peb_id);
		return -ERANGE;
	} else {
		kaddr = kmap_atomic(page);
		memcpy(env->log_hdr, kaddr, hdr_buf_size);
		kunmap_atomic(kaddr);
		unlock_page(page);
		put_page(page);
	}

	err = ssdfs_check_log_header(fsi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to check log header: "
			  "err %d\n", err);
		return err;
	}

	if (env->has_seg_hdr)
		err = ssdfs_get_segment_header_blk_bmap_desc(pebi, env, &desc);
	else
		err = ssdfs_get_partial_header_blk_bmap_desc(pebi, env, &desc);

	if (unlikely(err)) {
		SSDFS_ERR("fail to get descriptor: "
			  "err %d\n", err);
		return err;
	}

	if (!desc) {
		SSDFS_ERR("invalid descriptor pointer\n");
		return -ERANGE;
	}

	if (bmap_hdr_size != le16_to_cpu(desc->check.bytes)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"bmap_hdr_size %zu != desc->check.bytes %u\n",
				bmap_hdr_size,
				le16_to_cpu(desc->check.bytes));
		return -EIO;
	}

	if (le32_to_cpu(desc->offset) >= pebsize) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"desc->offset %u >= pebsize %u\n",
				le32_to_cpu(desc->offset), pebsize);
		return -EIO;
	}

	area_offset = le32_to_cpu(desc->offset);
	read_bytes = le16_to_cpu(desc->check.bytes);

	err = ssdfs_unaligned_read_cache(pebi,
					 area_offset, bmap_hdr_size,
					 env->b_init.bmap_hdr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block bitmap's header: "
			  "seg %llu, peb %llu, offset %u, size %zu, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  area_offset, bmap_hdr_size,
			  err);
		return err;
	}

	SSDFS_DBG("BLOCK BITMAP HEADER: "
		  "magic: common %#x, key %#x, version (%u.%u), "
		  "fragments_count %u, bytes_count %u, "
		  "flags %#x, type %#x\n",
		  le32_to_cpu(env->b_init.bmap_hdr->magic.common),
		  le16_to_cpu(env->b_init.bmap_hdr->magic.key),
		  env->b_init.bmap_hdr->magic.version.major,
		  env->b_init.bmap_hdr->magic.version.minor,
		  le16_to_cpu(env->b_init.bmap_hdr->fragments_count),
		  le32_to_cpu(env->b_init.bmap_hdr->bytes_count),
		  env->b_init.bmap_hdr->flags,
		  env->b_init.bmap_hdr->type);

	if (!is_csum_valid(&desc->check, env->b_init.bmap_hdr, read_bytes)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap header has invalid checksum\n");
		return -EIO;
	}

	env->b_init.read_bytes += read_bytes;

	return 0;
}

/*
 * ssdfs_read_checked_block_bitmap() - read and check block bitmap
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 *
 * This function reads block bitmap from the volume and
 * to check it consistency.
 *
 * RETURN:
 * [success] - block bitmap has been read in consistent state.
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_read_checked_block_bitmap(struct ssdfs_peb_info *pebi,
				    struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor *desc = NULL;
	size_t hdr_size = sizeof(struct ssdfs_block_bitmap_fragment);
	size_t desc_size = sizeof(struct ssdfs_fragment_desc);
	struct ssdfs_fragment_desc *frag_array = NULL;
	struct ssdfs_block_bitmap_fragment *frag_hdr = NULL;
	u32 area_offset;
	void *cdata_buf;
	u32 chain_compr_bytes, chain_uncompr_bytes;
	u32 read_bytes, uncompr_bytes;
	u16 fragments_count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env || !env->log_hdr || !env->footer);
	BUG_ON(!env->b_init.frag_hdr);
	BUG_ON(env->log_pages >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON(env->log_offset >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON(pagevec_count(&env->b_init.pvec) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, log_offset %u, log_pages %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->log_offset, env->log_pages);

	fsi = pebi->pebc->parent_si->fsi;

	if (env->has_seg_hdr)
		err = ssdfs_get_segment_header_blk_bmap_desc(pebi, env, &desc);
	else
		err = ssdfs_get_partial_header_blk_bmap_desc(pebi, env, &desc);

	if (unlikely(err)) {
		SSDFS_ERR("fail to get descriptor: "
			  "err %d\n", err);
		return err;
	}

	if (!desc) {
		SSDFS_ERR("invalid descriptor pointer\n");
		return -ERANGE;
	}

	area_offset = le32_to_cpu(desc->offset);

	err = ssdfs_unaligned_read_cache(pebi,
					 area_offset + env->b_init.read_bytes,
					 SSDFS_BLKBMAP_FRAG_HDR_CAPACITY,
					 env->b_init.frag_hdr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read fragment's header: "
			  "seg %llu, peb %llu, offset %u, size %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  area_offset + env->b_init.read_bytes,
			  (u32)SSDFS_BLKBMAP_FRAG_HDR_CAPACITY,
			  err);
		return err;
	}

	cdata_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!cdata_buf) {
		SSDFS_ERR("fail to allocate cdata_buf\n");
		return -ENOMEM;
	}

	frag_hdr = env->b_init.frag_hdr;

	frag_array = (struct ssdfs_fragment_desc *)((u8 *)frag_hdr + hdr_size);

	SSDFS_DBG("BLOCK BITMAP FRAGMENT HEADER: "
		  "peb_index %u, sequence_id %u, flags %#x, "
		  "type %#x, last_free_blk %u, "
		  "metadata_blks %u, invalid_blks %u\n",
		  le16_to_cpu(frag_hdr->peb_index),
		  le16_to_cpu(frag_hdr->sequence_id),
		  le16_to_cpu(frag_hdr->flags),
		  le16_to_cpu(frag_hdr->type),
		  le16_to_cpu(frag_hdr->last_free_blk),
		  le16_to_cpu(frag_hdr->metadata_blks),
		  le16_to_cpu(frag_hdr->invalid_blks));

	SSDFS_DBG("FRAGMENT CHAIN HEADER: "
		  "compr_bytes %u, uncompr_bytes %u, "
		  "fragments_count %u, desc_size %u, "
		  "magic %#x, type %#x, flags %#x\n",
		  le32_to_cpu(frag_hdr->chain_hdr.compr_bytes),
		  le32_to_cpu(frag_hdr->chain_hdr.uncompr_bytes),
		  le16_to_cpu(frag_hdr->chain_hdr.fragments_count),
		  le16_to_cpu(frag_hdr->chain_hdr.desc_size),
		  frag_hdr->chain_hdr.magic,
		  frag_hdr->chain_hdr.type,
		  le16_to_cpu(frag_hdr->chain_hdr.flags));

	if (le16_to_cpu(frag_hdr->last_free_blk) >= fsi->pages_per_peb) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"last_free_blk %u is invalid\n",
				le16_to_cpu(frag_hdr->last_free_blk));
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (le16_to_cpu(frag_hdr->metadata_blks) > fsi->pages_per_peb) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"metadata_blks %u is invalid\n",
				le16_to_cpu(frag_hdr->metadata_blks));
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (le16_to_cpu(frag_hdr->invalid_blks) >
	    le16_to_cpu(frag_hdr->last_free_blk)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"invalid_blks %u is invalid\n",
				le16_to_cpu(frag_hdr->invalid_blks));
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (desc_size != le16_to_cpu(frag_hdr->chain_hdr.desc_size)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"desc_size %u is invalid\n",
			    le16_to_cpu(frag_hdr->chain_hdr.desc_size));
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (frag_hdr->chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"chain header magic %#x is invalid\n",
				frag_hdr->chain_hdr.magic);
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (frag_hdr->chain_hdr.type != SSDFS_BLK_BMAP_CHAIN_HDR) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"chain header type %#x is invalid\n",
				frag_hdr->chain_hdr.type);
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (le16_to_cpu(frag_hdr->chain_hdr.flags) &
	    ~SSDFS_CHAIN_HDR_FLAG_MASK) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"unknown chain header flags %#x\n",
			    le16_to_cpu(frag_hdr->chain_hdr.flags));
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	fragments_count = le16_to_cpu(frag_hdr->chain_hdr.fragments_count);
	if (fragments_count == 0) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"fragments count is zero\n");
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (fragments_count > SSDFS_FRAGMENTS_CHAIN_MAX) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"fragments_count %u\n", fragments_count);
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	env->b_init.read_bytes += hdr_size + (fragments_count * desc_size);

	chain_compr_bytes = le32_to_cpu(frag_hdr->chain_hdr.compr_bytes);
	chain_uncompr_bytes = le32_to_cpu(frag_hdr->chain_hdr.uncompr_bytes);
	read_bytes = 0;
	uncompr_bytes = 0;

	for (i = 0; i < fragments_count; i++) {
		struct ssdfs_fragment_desc *frag_desc;
		struct page *page;
		u16 sequence_id = i;

		if (read_bytes >= chain_compr_bytes ||
		    uncompr_bytes >= chain_uncompr_bytes) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"block bitmap is corrupted: "
					"fragments header: "
					"compr_bytes %u, "
					"uncompr_bytes %u\n",
					chain_compr_bytes,
					chain_uncompr_bytes);
			err = -EIO;
			goto fail_read_blk_bmap;
		}

		frag_desc = &frag_array[i];

		page = ssdfs_add_pagevec_page(&env->b_init.pvec);
		if (unlikely(IS_ERR_OR_NULL(page))) {
			err = !page ? -ENOMEM : PTR_ERR(page);
			SSDFS_ERR("fail to add pagevec page: "
				  "sequence_id %u, "
				  "fragments count %u, err %d\n",
				  sequence_id, fragments_count, err);
			goto fail_read_blk_bmap;
		}

		lock_page(page);
		err = ssdfs_read_checked_fragment(pebi, area_offset,
						  sequence_id,
						  frag_desc,
						  cdata_buf, page);
		unlock_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to read checked fragment: "
				  "offset %u, compr_size %u, "
				  "uncompr_size %u, sequence_id %u, "
				  "flags %#x, err %d\n",
				  le32_to_cpu(frag_desc->offset),
				  le16_to_cpu(frag_desc->compr_size),
				  le16_to_cpu(frag_desc->uncompr_size),
				  le16_to_cpu(frag_desc->sequence_id),
				  le16_to_cpu(frag_desc->flags),
				  err);
			goto fail_read_blk_bmap;
		}

		read_bytes += le16_to_cpu(frag_desc->compr_size);
		uncompr_bytes += le16_to_cpu(frag_desc->uncompr_size);
		env->b_init.read_bytes += le16_to_cpu(frag_desc->compr_size);
	}

	SSDFS_DBG("last_free_blk %u, metadata_blks %u, invalid_blks %u\n",
		  le16_to_cpu(frag_hdr->last_free_blk),
		  le16_to_cpu(frag_hdr->metadata_blks),
		  le16_to_cpu(frag_hdr->invalid_blks));

fail_read_blk_bmap:
	kfree(cdata_buf);
	return err;
}

/*
 * ssdfs_init_block_bitmap_fragment() - init block bitmap fragment
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 *
 * This function reads block bitmap's fragment from the volume and
 * try to initialize the fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_init_block_bitmap_fragment(struct ssdfs_peb_info *pebi,
				     struct ssdfs_read_init_env *env)
{
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	u64 cno;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!env || !env->log_hdr || !env->footer);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "log_offset %u, log_pages %u, "
		  "fragment_index %d, read_bytes %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  env->log_offset, env->log_pages,
		  env->b_init.fragment_index, env->b_init.read_bytes);

	pagevec_init(&env->b_init.pvec);

	err = ssdfs_read_checked_block_bitmap(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block bitmap: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		goto fail_init_blk_bmap_fragment;
	}

	seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;

	if (env->has_seg_hdr) {
		struct ssdfs_segment_header *seg_hdr = NULL;

		seg_hdr = SSDFS_SEG_HDR(env->log_hdr);
		cno = le64_to_cpu(seg_hdr->cno);
	} else {
		struct ssdfs_partial_log_header *pl_hdr = NULL;

		pl_hdr = SSDFS_PLH(env->log_hdr);
		cno = le64_to_cpu(pl_hdr->cno);
	}

	err = ssdfs_segment_blk_bmap_partial_init(seg_blkbmap,
						  pebi->peb_index,
						  &env->b_init.pvec,
						  env->b_init.frag_hdr,
						  cno);
	if (unlikely(err)) {
		SSDFS_ERR("fail to initialize block bitmap: "
			  "seg %llu, peb %llu, cno %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, cno, err);
		goto fail_init_blk_bmap_fragment;
	}

fail_init_blk_bmap_fragment:
	pagevec_release(&env->b_init.pvec);

	return err;
}

/*
 * ssdfs_read_blk2off_table_header() - read blk2off table header
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 *
 * This function tries to read blk2off table header.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_read_blk2off_table_header(struct ssdfs_peb_info *pebi,
				    struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor *desc = NULL;
	struct ssdfs_blk2off_table_header *hdr = NULL;
	size_t hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	struct page *page;
	void *kaddr;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env || !env->log_hdr || !env->footer);
	BUG_ON(pagevec_count(&env->t_init.pvec) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->t_init.read_off, env->t_init.write_off);

	fsi = pebi->pebc->parent_si->fsi;

	if (env->has_seg_hdr) {
		err = ssdfs_get_segment_header_blk2off_tbl_desc(pebi, env,
								&desc);
	} else {
		err = ssdfs_get_partial_header_blk2off_tbl_desc(pebi, env,
								&desc);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to get descriptor: "
			  "err %d\n", err);
		return err;
	}

	if (!desc) {
		SSDFS_ERR("invalid descriptor pointer\n");
		return -ERANGE;
	}

	env->t_init.read_off = le32_to_cpu(desc->offset);
	env->t_init.write_off = 0;

	err = ssdfs_unaligned_read_cache(pebi,
					 env->t_init.read_off, hdr_size,
					 &env->t_init.tbl_hdr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read table's header: "
			  "seg %llu, peb %llu, offset %u, size %zu, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  env->t_init.read_off, hdr_size, err);
		return err;
	}

	hdr = &env->t_init.tbl_hdr;

	if (le32_to_cpu(hdr->magic.common) != SSDFS_SUPER_MAGIC ||
	    le16_to_cpu(hdr->magic.key) != SSDFS_BLK2OFF_TABLE_HDR_MAGIC) {
		SSDFS_ERR("invalid magic of blk2off_table\n");
		return -EIO;
	}

	page = ssdfs_add_pagevec_page(&env->t_init.pvec);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		err = !page ? -ENOMEM : PTR_ERR(page);
		SSDFS_ERR("fail to add pagevec page: err %d\n",
			  err);
		return err;
	}

	lock_page(page);
	kaddr = kmap_atomic(page);
	memcpy(kaddr, hdr, hdr_size);
	kunmap_atomic(kaddr);
	unlock_page(page);

	env->t_init.read_off += offsetof(struct ssdfs_blk2off_table_header,
					sequence);
	env->t_init.write_off += offsetof(struct ssdfs_blk2off_table_header,
					sequence);

	return 0;
}

/*
 * ssdfs_read_blk2off_byte_stream() - read blk2off's byte stream
 * @pebi: pointer on PEB object
 * @read_bytes: amount of bytes for reading
 * @env: init environment [in|out]
 *
 * This function tries to read blk2off table's byte stream.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_read_blk2off_byte_stream(struct ssdfs_peb_info *pebi,
				   u32 read_bytes,
				   struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, read_bytes %u, "
		  "read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  read_bytes, env->t_init.read_off,
		  env->t_init.write_off);

	fsi = pebi->pebc->parent_si->fsi;

	while (read_bytes > 0) {
		struct page *page = NULL;
		void *kaddr;
		pgoff_t page_index = env->t_init.write_off >> PAGE_SHIFT;
		u32 capacity = pagevec_count(&env->t_init.pvec) << PAGE_SHIFT;
		u32 offset, bytes;

		if (env->t_init.write_off >= capacity) {
			page = ssdfs_add_pagevec_page(&env->t_init.pvec);
			if (unlikely(IS_ERR_OR_NULL(page))) {
				err = !page ? -ENOMEM : PTR_ERR(page);
				SSDFS_ERR("fail to add pagevec page: err %d\n",
					  err);
				return err;
			}
		} else {
			page = env->t_init.pvec.pages[page_index];
			if (unlikely(!page)) {
				err = -ERANGE;
				SSDFS_ERR("fail to get page: err %d\n",
					  err);
				return err;
			}
		}

		offset = env->t_init.write_off % PAGE_SIZE;
		bytes = min_t(u32, read_bytes, PAGE_SIZE - offset);

		lock_page(page);
		kaddr = kmap(page);
		err = ssdfs_unaligned_read_cache(pebi,
						 env->t_init.read_off, bytes,
						 (u8 *)kaddr + offset);
		kunmap(page);
		unlock_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to read page: "
				  "seg %llu, peb %llu, offset %u, "
				  "size %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, env->t_init.read_off,
				  bytes, err);
			return err;
		}

		read_bytes -= bytes;
		env->t_init.read_off += bytes;
		env->t_init.write_off += bytes;
	};

	return 0;
}

/*
 * ssdfs_read_blk2off_table_extents() - read blk2off table's extents
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 *
 * This function tries to read blk2off table's extents.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_read_blk2off_table_extents(struct ssdfs_peb_info *pebi,
				     struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	u16 extents_off;
	u16 extent_count;
	size_t extent_size = sizeof(struct ssdfs_translation_extent);
	u32 offset = offsetof(struct ssdfs_blk2off_table_header, sequence);
	u32 read_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env);
#endif /* CONFIG_SSDFS_DEBUG */

	extents_off = le16_to_cpu(env->t_init.tbl_hdr.extents_off);
	extent_count = le16_to_cpu(env->t_init.tbl_hdr.extents_count);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "extents_off %u, extent_count %u, "
		  "read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  extents_off, extent_count,
		  env->t_init.read_off,
		  env->t_init.write_off);

	fsi = pebi->pebc->parent_si->fsi;

	if (offset != extents_off) {
		SSDFS_ERR("extents_off %u != offset %u\n",
			  extents_off, offset);
		return -EIO;
	}

	if (extent_count == 0 || extent_count == U16_MAX) {
		SSDFS_ERR("invalid extent_count %u\n",
			  extent_count);
		return -EIO;
	}

	read_bytes = extent_size * extent_count;

	err = ssdfs_read_blk2off_byte_stream(pebi, read_bytes, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read byte stream: err %d\n",
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_read_blk2off_pot_fragment() - read blk2off table's POT fragment
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 *
 * This function tries to read blk2off table's Physical Offsets Table
 * fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_read_blk2off_pot_fragment(struct ssdfs_peb_info *pebi,
				    struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_phys_offset_table_header hdr;
	size_t hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	u32 start_off, next_frag_off;
	u32 read_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, "
		  "read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->t_init.read_off, env->t_init.write_off);

	fsi = pebi->pebc->parent_si->fsi;
	start_off = env->t_init.read_off;

	err = ssdfs_unaligned_read_cache(pebi,
					 env->t_init.read_off, hdr_size,
					 &hdr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, "
			  "size %zu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, env->t_init.read_off,
			  hdr_size, err);
		return err;
	}

	if (le32_to_cpu(hdr.magic) != SSDFS_PHYS_OFF_TABLE_MAGIC) {
		SSDFS_ERR("invalid magic\n");
		return -EIO;
	}

	read_bytes = le32_to_cpu(hdr.byte_size);

	err = ssdfs_read_blk2off_byte_stream(pebi, read_bytes, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read byte stream: err %d\n",
			  err);
		return err;
	}

	next_frag_off = le16_to_cpu(hdr.next_fragment_off);

	if (next_frag_off >= U16_MAX)
		goto finish_read_blk2off_pot_fragment;

	next_frag_off += start_off;

	if (next_frag_off != env->t_init.read_off) {
		SSDFS_ERR("next_frag_off %u != read_off %u\n",
			  next_frag_off, env->t_init.read_off);
		return -EIO;
	}

finish_read_blk2off_pot_fragment:
	return 0;
}

/*
 * ssdfs_read_blk2off_table_fragment() - read blk2off table's log's fragments
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 *
 * This function tries to read blk2off table's log's fragments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_read_blk2off_table_fragment(struct ssdfs_peb_info *pebi,
				      struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	u16 fragment_count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env || !env->log_hdr || !env->footer);
	BUG_ON(pagevec_count(&env->t_init.pvec) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

	fsi = pebi->pebc->parent_si->fsi;
	env->t_init.read_off = 0;
	env->t_init.write_off = 0;

	err = ssdfs_read_blk2off_table_header(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read translation table header: "
			  "seg %llu, peb %llu, "
			  "read_off %u, write_off %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  env->t_init.read_off, env->t_init.write_off,
			  err);
		goto fail_read_blk2off_fragments;
	}

	err = ssdfs_read_blk2off_table_extents(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read translation table's extents: "
			  "seg %llu, peb %llu, "
			  "read_off %u, write_off %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  env->t_init.read_off, env->t_init.write_off,
			  err);
		goto fail_read_blk2off_fragments;
	}

	fragment_count = le16_to_cpu(env->t_init.tbl_hdr.fragments_count);

	for (i = 0; i < fragment_count; i++) {
		err = ssdfs_read_blk2off_pot_fragment(pebi, env);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read physical offset table's "
				  "fragment: seg %llu, peb %llu, "
				  "fragment_index %d, "
				  "read_off %u, write_off %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  i, env->t_init.read_off,
				  env->t_init.write_off, err);
			goto fail_read_blk2off_fragments;
		}
	}

fail_read_blk2off_fragments:
	return err;
}

/*
 * ssdfs_peb_init_using_metadata_state() - initialize "using" PEB
 * @pebi: pointer on PEB object
 * @env: read operation's init environment
 * @req: read request
 *
 * This function tries to initialize last actual metadata state for
 * the case of "using" state of PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_peb_init_using_metadata_state(struct ssdfs_peb_info *pebi,
					struct ssdfs_read_init_env *env,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *pl_hdr = NULL;
	u16 fragments_count;
	u32 bytes_count;
	u16 new_log_start_page;
	u64 cno;
	u8 sequence_id = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);

	si = pebi->pebc->parent_si;
	fsi = si->fsi;

	/*
	 * Allow creating thread to continue creation logic.
	 */
	complete(&req->result.wait);

	err = ssdfs_peb_get_log_pages_count(fsi, pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define log_pages: "
			  "seg %llu, peb %llu\n",
			  si->seg_id, pebi->peb_id);
		goto fail_init_using_blk_bmap;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->pages_per_peb % env->log_pages) {
		SSDFS_WARN("fsi->pages_per_peb %u, log_pages %u\n",
			   fsi->pages_per_peb, env->log_pages);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->log_pages = env->log_pages;

	err = ssdfs_find_last_partial_log(fsi, pebi, env,
					  &new_log_start_page);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find last partial log: err %d\n", err);
		goto fail_init_using_blk_bmap;
	}

	err = ssdfs_pre_fetch_block_bitmap(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch block bitmap: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log_offset, err);
		goto fail_init_using_blk_bmap;
	}

	err = ssdfs_read_checked_block_bitmap_header(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block bitmap header: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log_offset, err);
		goto fail_init_using_blk_bmap;
	}

	fragments_count = le16_to_cpu(env->b_init.bmap_hdr->fragments_count);
	bytes_count = le32_to_cpu(env->b_init.bmap_hdr->bytes_count);

	for (i = 0; i < fragments_count; i++) {
		env->b_init.fragment_index = i;
		err = ssdfs_init_block_bitmap_fragment(pebi, env);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init block bitmap: "
				  "peb_id %llu, peb_index %u, "
				  "log_offset %u, fragment_index %u, "
				  "read_bytes %u, err %d\n",
				  pebi->peb_id, pebi->peb_index,
				  env->log_offset, i,
				  env->b_init.read_bytes, err);
			goto fail_init_using_blk_bmap;
		}
	}

	if (bytes_count != env->b_init.read_bytes) {
		SSDFS_WARN("bytes_count %u != read_bytes %u\n",
			   bytes_count, env->b_init.read_bytes);
		err = -EIO;
		goto fail_init_using_blk_bmap;
	}

	BUG_ON(new_log_start_page >= U16_MAX);

	if (env->has_seg_hdr) {
		/* first log */
		sequence_id = 0;
	} else {
		pl_hdr = SSDFS_PLH(env->log_hdr);
		sequence_id = pl_hdr->sequence_id;
	}

	BUG_ON(sequence_id >= U8_MAX);

	if (new_log_start_page < fsi->pages_per_peb) {
		u16 free_pages;
		u16 min_log_pages;

		free_pages = new_log_start_page % pebi->log_pages;
		free_pages = pebi->log_pages - free_pages;
		min_log_pages = ssdfs_peb_estimate_min_partial_log_pages(pebi);
		sequence_id++;

		if (free_pages == pebi->log_pages) {
			/* start new full log */
			sequence_id = 0;
		} else if (free_pages < min_log_pages) {
			new_log_start_page += free_pages;
			free_pages = pebi->log_pages;
			sequence_id = 0;
		}

		ssdfs_peb_current_log_init(pebi, free_pages,
					   new_log_start_page,
					   sequence_id);
	} else {
		sequence_id = 0;
		ssdfs_peb_current_log_init(pebi,
					   0,
					   new_log_start_page,
					   sequence_id);
	}

fail_init_using_blk_bmap:
	if (unlikely(err))
		goto fail_init_using_peb;

	err = ssdfs_pre_fetch_blk2off_table_area(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch blk2off_table area: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log_offset, err);
		goto fail_init_using_peb;
	}

	err = ssdfs_read_blk2off_table_fragment(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read translation table fragments: "
			  "seg %llu, peb %llu, err %d\n",
			  si->seg_id, pebi->peb_id, err);
		goto fail_init_using_peb;
	}

	SSDFS_DBG("blk2off_table_partial_init: seg_id %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

	if (env->has_seg_hdr) {
		seg_hdr = SSDFS_SEG_HDR(env->log_hdr);
		cno = le64_to_cpu(seg_hdr->cno);
	} else {
		pl_hdr = SSDFS_PLH(env->log_hdr);
		cno = le64_to_cpu(pl_hdr->cno);
	}

	err = ssdfs_blk2off_table_partial_init(si->blk2off_table,
						&env->t_init.pvec,
						pebi->peb_index, cno);
	if (unlikely(err)) {
		SSDFS_ERR("fail to start initialization of offset table: "
			  "seg %llu, peb %llu, err %d\n",
			  si->seg_id, pebi->peb_id, err);
		goto fail_init_using_peb;
	}

fail_init_using_peb:
	return err;
}

/*
 * ssdfs_peb_init_used_metadata_state() - initialize "used" PEB
 * @pebi: pointer on PEB object
 * @env: read operation's init environment
 * @req: read request
 *
 * This function tries to initialize last actual metadata state for
 * the case of "used" state of PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_peb_init_used_metadata_state(struct ssdfs_peb_info *pebi,
					struct ssdfs_read_init_env *env,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *pl_hdr = NULL;
	u16 fragments_count;
	u32 bytes_count;
	u16 new_log_start_page;
	u64 cno;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);

	si = pebi->pebc->parent_si;
	fsi = si->fsi;

	/*
	 * Allow creating thread to continue creation logic.
	 */
	complete(&req->result.wait);

	err = ssdfs_peb_get_log_pages_count(fsi, pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define log_pages: "
			  "seg %llu, peb %llu\n",
			  si->seg_id, pebi->peb_id);
		goto fail_init_used_blk_bmap;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->pages_per_peb % env->log_pages) {
		SSDFS_WARN("fsi->pages_per_peb %u, log_pages %u\n",
			   fsi->pages_per_peb, env->log_pages);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->log_pages = env->log_pages;

	err = ssdfs_find_last_partial_log(fsi, pebi, env,
					  &new_log_start_page);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find last partial log: err %d\n", err);
		goto fail_init_used_blk_bmap;
	}

	err = ssdfs_pre_fetch_block_bitmap(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch block bitmap: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log_offset, err);
		goto fail_init_used_blk_bmap;
	}

	err = ssdfs_read_checked_block_bitmap_header(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block bitmap header: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log_offset, err);
		goto fail_init_used_blk_bmap;
	}

	fragments_count = le16_to_cpu(env->b_init.bmap_hdr->fragments_count);
	bytes_count = le32_to_cpu(env->b_init.bmap_hdr->bytes_count);

	for (i = 0; i < fragments_count; i++) {
		env->b_init.fragment_index = i;
		err = ssdfs_init_block_bitmap_fragment(pebi, env);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init block bitmap: "
				  "peb_id %llu, peb_index %u, "
				  "log_offset %u, fragment_index %u, "
				  "read_bytes %u, err %d\n",
				  pebi->peb_id, pebi->peb_index,
				  env->log_offset, i,
				  env->b_init.read_bytes, err);
			goto fail_init_used_blk_bmap;
		}
	}

	if (bytes_count != env->b_init.read_bytes) {
		SSDFS_WARN("bytes_count %u != read_bytes %u\n",
			   bytes_count, env->b_init.read_bytes);
		err = -EIO;
		goto fail_init_used_blk_bmap;
	}

	ssdfs_peb_current_log_init(pebi, 0, fsi->pages_per_peb, 0);

fail_init_used_blk_bmap:
	if (unlikely(err))
		goto fail_init_used_peb;

	err = ssdfs_pre_fetch_blk2off_table_area(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch blk2off_table area: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log_offset, err);
		goto fail_init_used_peb;
	}

	err = ssdfs_read_blk2off_table_fragment(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read translation table fragments: "
			  "seg %llu, peb %llu, err %d\n",
			  si->seg_id, pebi->peb_id, err);
		goto fail_init_used_peb;
	}

	SSDFS_DBG("blk2off_table_partial_init: seg_id %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

	if (env->has_seg_hdr) {
		seg_hdr = SSDFS_SEG_HDR(env->log_hdr);
		cno = le64_to_cpu(seg_hdr->cno);
	} else {
		pl_hdr = SSDFS_PLH(env->log_hdr);
		cno = le64_to_cpu(pl_hdr->cno);
	}

	err = ssdfs_blk2off_table_partial_init(si->blk2off_table,
						&env->t_init.pvec,
						pebi->peb_index,
						cno);
	if (unlikely(err)) {
		SSDFS_ERR("fail to start initialization of offset table: "
			  "seg %llu, peb %llu, err %d\n",
			  si->seg_id, pebi->peb_id, err);
		goto fail_init_used_peb;
	}

fail_init_used_peb:
	return err;
}

/*
 * ssdfs_src_peb_init_using_metadata_state() - init src "using" PEB container
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This function tries to initialize "using" PEB container.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_src_peb_init_using_metadata_state(struct ssdfs_peb_container *pebc,
					    struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_info *pebi;
	struct ssdfs_read_init_env env;
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	fsi = pebc->parent_si->fsi;

	items_state = atomic_read(&pebc->items_state);
	switch(items_state) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
		/* valid states */
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		return -ERANGE;
	};

	err = ssdfs_prepare_read_init_env(&env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init read environment: err %d\n",
			  err);
		return err;
	}

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (!pebi) {
		SSDFS_WARN("source PEB is NULL\n");
		err = -ERANGE;
		goto finish_src_init_using_metadata_state;
	}

	err = ssdfs_peb_init_using_metadata_state(pebi, &env, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init using metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_src_init_using_metadata_state;
	}

	id1 = env.cur_migration_id;

	if (!is_peb_migration_id_valid(id1)) {
		err = -EIO;
		SSDFS_ERR("invalid peb_migration_id: "
			  "seg_id %llu, peb_index %u, "
			  "peb_migration_id %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  id1);
		goto finish_src_init_using_metadata_state;
	}

	id2 = ssdfs_get_peb_migration_id(pebi);

	if (id2 == SSDFS_PEB_UNKNOWN_MIGRATION_ID) {
		/* it needs to initialize the migration id */
		ssdfs_set_peb_migration_id(pebi, id1);
	} else if (is_peb_migration_id_valid(id2)) {
		if (id1 != id2) {
			err = -ERANGE;
			SSDFS_ERR("migration_id1 %d != migration_id2 %d\n",
				  id1, id2);
			goto finish_src_init_using_metadata_state;
		} else {
			/*
			 * Do nothing.
			 */
		}
	} else {
		err = -ERANGE;
		SSDFS_ERR("invalid migration_id %d\n", id2);
		goto finish_src_init_using_metadata_state;
	}

	atomic_set(&pebi->state,
		   SSDFS_PEB_OBJECT_INITIALIZED);
	complete_all(&pebi->init_end);

finish_src_init_using_metadata_state:
	up_read(&pebc->lock);
	ssdfs_destroy_init_env(&env);
	return err;
}

/*
 * ssdfs_dst_peb_init_using_metadata_state() - init dst "using" PEB container
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This function tries to initialize "using" PEB container.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_dst_peb_init_using_metadata_state(struct ssdfs_peb_container *pebc,
					    struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_info *pebi;
	struct ssdfs_read_init_env env;
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	fsi = pebc->parent_si->fsi;

	items_state = atomic_read(&pebc->items_state);
	switch(items_state) {
	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		/* valid states */
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		return -ERANGE;
	};

	err = ssdfs_prepare_read_init_env(&env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init read environment: err %d\n",
			  err);
		return err;
	}

	down_read(&pebc->lock);

	pebi = pebc->dst_peb;
	if (!pebi) {
		SSDFS_WARN("destination PEB is NULL\n");
		err = -ERANGE;
		goto finish_dst_init_using_metadata_state;
	}

	err = ssdfs_peb_init_using_metadata_state(pebi, &env, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init using metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_dst_init_using_metadata_state;
	}

	id1 = env.cur_migration_id;

	if (!is_peb_migration_id_valid(id1)) {
		err = -EIO;
		SSDFS_ERR("invalid peb_migration_id: "
			  "seg_id %llu, peb_index %u, "
			  "peb_migration_id %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  id1);
		goto finish_dst_init_using_metadata_state;
	}

	ssdfs_set_peb_migration_id(pebc->dst_peb, id1);

	atomic_set(&pebc->dst_peb->state,
		   SSDFS_PEB_OBJECT_INITIALIZED);
	complete_all(&pebc->dst_peb->init_end);

	switch (items_state) {
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		if (!pebc->src_peb) {
			SSDFS_WARN("source PEB is NULL\n");
			err = -ERANGE;
			goto finish_dst_init_using_metadata_state;
		}

		id1 = env.prev_migration_id;

		if (!is_peb_migration_id_valid(id1)) {
			err = -EIO;
			SSDFS_ERR("invalid peb_migration_id: "
				  "seg_id %llu, peb_index %u, "
				  "peb_migration_id %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  id1);
			goto finish_dst_init_using_metadata_state;
		}

		id2 = ssdfs_get_peb_migration_id(pebc->src_peb);

		if (id2 == SSDFS_PEB_UNKNOWN_MIGRATION_ID) {
			/* it needs to initialize the migration id */
			ssdfs_set_peb_migration_id(pebc->src_peb, id1);
			atomic_set(&pebc->src_peb->state,
				   SSDFS_PEB_OBJECT_INITIALIZED);
			complete_all(&pebc->src_peb->init_end);
		} else if (is_peb_migration_id_valid(id2)) {
			if (id1 != id2) {
				err = -ERANGE;
				SSDFS_ERR("id1 %d != id2 %d\n",
					  id1, id2);
				goto finish_dst_init_using_metadata_state;
			} else {
				/*
				 * Do nothing.
				 */
			}
		} else {
			err = -ERANGE;
			SSDFS_ERR("invalid migration_id %d\n", id2);
			goto finish_dst_init_using_metadata_state;
		}
		break;

	default:
		/* do nothing */
		break;
	};

finish_dst_init_using_metadata_state:
	up_read(&pebc->lock);
	ssdfs_destroy_init_env(&env);
	return err;
}

/*
 * ssdfs_src_peb_init_used_metadata_state() - init src "used" PEB container
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This function tries to initialize "used" PEB container.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_src_peb_init_used_metadata_state(struct ssdfs_peb_container *pebc,
					   struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_info *pebi;
	struct ssdfs_read_init_env env;
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	fsi = pebc->parent_si->fsi;

	items_state = atomic_read(&pebc->items_state);
	switch(items_state) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		/* valid states */
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		return -ERANGE;
	};

	err = ssdfs_prepare_read_init_env(&env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init read environment: err %d\n",
			  err);
		return err;
	}

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (!pebi) {
		SSDFS_WARN("source PEB is NULL\n");
		err = -ERANGE;
		goto finish_src_init_used_metadata_state;
	}

	err = ssdfs_peb_init_used_metadata_state(pebi, &env, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init used metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_src_init_used_metadata_state;
	}

	id1 = env.cur_migration_id;

	if (!is_peb_migration_id_valid(id1)) {
		err = -EIO;
		SSDFS_ERR("invalid peb_migration_id: "
			  "seg_id %llu, peb_index %u, "
			  "peb_migration_id %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  id1);
		goto finish_src_init_used_metadata_state;
	}

	id2 = ssdfs_get_peb_migration_id(pebi);

	if (id2 == SSDFS_PEB_UNKNOWN_MIGRATION_ID) {
		/* it needs to initialize the migration id */
		ssdfs_set_peb_migration_id(pebi, id1);
		atomic_set(&pebi->state,
			   SSDFS_PEB_OBJECT_INITIALIZED);
		complete_all(&pebi->init_end);
	} else if (is_peb_migration_id_valid(id2)) {
		if (id1 != id2) {
			err = -ERANGE;
			SSDFS_ERR("migration_id1 %d != migration_id2 %d\n",
				  id1, id2);
			goto finish_src_init_used_metadata_state;
		} else {
			/*
			 * Do nothing.
			 */
		}
	} else {
		err = -ERANGE;
		SSDFS_ERR("invalid migration_id %d\n", id2);
		goto finish_src_init_used_metadata_state;
	}

	switch (items_state) {
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		if (!pebc->dst_peb) {
			SSDFS_WARN("destination PEB is NULL\n");
			err = -ERANGE;
			goto finish_src_init_used_metadata_state;
		}

		id1 = __ssdfs_define_next_peb_migration_id(id1);
		if (!is_peb_migration_id_valid(id1)) {
			err = -EIO;
			SSDFS_ERR("invalid peb_migration_id: "
				  "seg_id %llu, peb_index %u, "
				  "peb_migration_id %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  id1);
			goto finish_src_init_used_metadata_state;
		}

		id2 = ssdfs_get_peb_migration_id(pebc->dst_peb);

		if (id2 == SSDFS_PEB_UNKNOWN_MIGRATION_ID) {
			/* it needs to initialize the migration id */
			ssdfs_set_peb_migration_id(pebc->dst_peb, id1);
			atomic_set(&pebc->dst_peb->state,
				   SSDFS_PEB_OBJECT_INITIALIZED);
			complete_all(&pebc->dst_peb->init_end);
		} else if (is_peb_migration_id_valid(id2)) {
			if (id1 != id2) {
				err = -ERANGE;
				SSDFS_ERR("id1 %d != id2 %d\n",
					  id1, id2);
				goto finish_src_init_used_metadata_state;
			} else {
				/*
				 * Do nothing.
				 */
			}
		} else {
			err = -ERANGE;
			SSDFS_ERR("invalid migration_id %d\n", id2);
			goto finish_src_init_used_metadata_state;
		}
		break;

	default:
		/* do nothing */
		break;
	};

finish_src_init_used_metadata_state:
	up_read(&pebc->lock);
	ssdfs_destroy_init_env(&env);
	return err;
}

/*
 * ssdfs_dst_peb_init_used_metadata_state() - init dst "used" PEB container
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This function tries to initialize "used" PEB container.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_dst_peb_init_used_metadata_state(struct ssdfs_peb_container *pebc,
					   struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_info *pebi;
	struct ssdfs_read_init_env env;
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	fsi = pebc->parent_si->fsi;

	items_state = atomic_read(&pebc->items_state);
	switch(items_state) {
	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		/* valid states */
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		return -ERANGE;
	};

	err = ssdfs_prepare_read_init_env(&env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init read environment: err %d\n",
			  err);
		return err;
	}

	down_read(&pebc->lock);

	pebi = pebc->dst_peb;
	if (!pebi) {
		SSDFS_WARN("destination PEB is NULL\n");
		err = -ERANGE;
		goto finish_dst_init_used_metadata_state;
	}

	err = ssdfs_peb_init_used_metadata_state(pebi, &env, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init used metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_dst_init_used_metadata_state;
	}

	id1 = env.cur_migration_id;

	if (!is_peb_migration_id_valid(id1)) {
		err = -EIO;
		SSDFS_ERR("invalid peb_migration_id: "
			  "seg_id %llu, peb_index %u, "
			  "peb_migration_id %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  id1);
		goto finish_dst_init_used_metadata_state;
	}

	id2 = ssdfs_get_peb_migration_id(pebi);

	if (id2 == SSDFS_PEB_UNKNOWN_MIGRATION_ID) {
		/* it needs to initialize the migration id */
		ssdfs_set_peb_migration_id(pebi, id1);
	} else if (is_peb_migration_id_valid(id2)) {
		if (id1 != id2) {
			err = -ERANGE;
			SSDFS_ERR("migration_id1 %d != migration_id2 %d\n",
				  id1, id2);
			goto finish_dst_init_used_metadata_state;
		} else {
			/*
			 * Do nothing.
			 */
		}
	} else {
		err = -ERANGE;
		SSDFS_ERR("invalid migration_id %d\n", id2);
		goto finish_dst_init_used_metadata_state;
	}

	switch (items_state) {
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		if (!pebc->src_peb) {
			SSDFS_WARN("source PEB is NULL\n");
			err = -ERANGE;
			goto finish_dst_init_used_metadata_state;
		}

		id1 = env.prev_migration_id;

		if (!is_peb_migration_id_valid(id1)) {
			err = -EIO;
			SSDFS_ERR("invalid peb_migration_id: "
				  "seg_id %llu, peb_index %u, "
				  "peb_migration_id %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  id1);
			goto finish_dst_init_used_metadata_state;
		}

		id2 = ssdfs_get_peb_migration_id(pebc->src_peb);

		if (id2 == SSDFS_PEB_UNKNOWN_MIGRATION_ID) {
			/* it needs to initialize the migration id */
			ssdfs_set_peb_migration_id(pebc->src_peb, id1);
			atomic_set(&pebc->src_peb->state,
				   SSDFS_PEB_OBJECT_INITIALIZED);
			complete_all(&pebc->src_peb->init_end);
		} else if (is_peb_migration_id_valid(id2)) {
			if (id1 != id2) {
				err = -ERANGE;
				SSDFS_ERR("id1 %d != id2 %d\n",
					  id1, id2);
				goto finish_dst_init_used_metadata_state;
			} else {
				/*
				 * Do nothing.
				 */
			}
		} else {
			err = -ERANGE;
			SSDFS_ERR("invalid migration_id %d\n", id2);
			goto finish_dst_init_used_metadata_state;
		}
		break;

	default:
		/* do nothing */
		break;
	};

	atomic_set(&pebc->dst_peb->state,
		   SSDFS_PEB_OBJECT_INITIALIZED);
	complete_all(&pebc->dst_peb->init_end);

finish_dst_init_used_metadata_state:
	up_read(&pebc->lock);
	ssdfs_destroy_init_env(&env);
	return err;
}

/*
 * ssdfs_find_prev_partial_log() - find previous partial log
 * @fsi: file system info object
 * @pebi: pointer on PEB object
 * @env: read operation's init environment [in|out]
 * @log_diff: offset for logs processing
 *
 * This function tries to find a previous partial log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 * %-ENOENT     - unable to find any log.
 */
static
int ssdfs_find_prev_partial_log(struct ssdfs_fs_info *fsi,
				struct ssdfs_peb_info *pebi,
				struct ssdfs_read_init_env *env,
				int log_diff)
{
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *pl_hdr = NULL;
	struct ssdfs_log_footer *footer = NULL;
	struct page *page;
	void *kaddr;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	int start_offset;
	int skipped_logs = 0;
	int i;
	int err = -ENOENT;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !env);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "log_offset %u, log_diff %d\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  env->log_offset, log_diff);

	if (env->log_offset > fsi->pages_per_peb) {
		SSDFS_ERR("log_offset %u > pages_per_peb %u\n",
			  env->log_offset, fsi->pages_per_peb);
		return -ERANGE;
	} else if (env->log_offset == fsi->pages_per_peb)
		env->log_offset--;

	start_offset = env->log_offset;

	if (log_diff > 0) {
		SSDFS_ERR("invalid log_diff %d\n", log_diff);
		return -EINVAL;
	}

	if (env->log_offset == 0) {
		SSDFS_DBG("previous log is absent\n");
		return -ENOENT;
	}

	for (i = start_offset; i >= 0; i--) {
		page = ssdfs_page_array_get_page_locked(&pebi->cache, i);
		if (IS_ERR_OR_NULL(page)) {
			if (page == NULL) {
				SSDFS_ERR("fail to get page: "
					  "index %d\n",
					  i);
				return -ERANGE;
			} else {
				err = PTR_ERR(page);

				if (err == -ENOENT)
					continue;
				else {
					SSDFS_ERR("fail to get page: "
						  "index %d, err %d\n",
						  i, err);
					return err;
				}
			}
		}

		kaddr = kmap_atomic(page);
		memcpy(env->log_hdr, kaddr, hdr_buf_size);
		kunmap_atomic(kaddr);
		unlock_page(page);
		put_page(page);

		magic = (struct ssdfs_signature *)env->log_hdr;

		if (__is_ssdfs_segment_header_magic_valid(magic)) {
			seg_hdr = SSDFS_SEG_HDR(env->log_hdr);

			err = ssdfs_check_segment_header(fsi, seg_hdr,
							 false);
			if (unlikely(err)) {
				SSDFS_ERR("log header is corrupted: "
					  "seg %llu, peb %llu, index %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  i);
				return -EIO;
			}

			if (start_offset == i) {
				/*
				 * Requested starting log_offset points out
				 * on segment header. It needs to skip this
				 * header because of searching the previous
				 * log.
				 */
				continue;
			}

			env->has_seg_hdr = true;
			env->has_footer = ssdfs_log_has_footer(seg_hdr);
			env->log_offset = (u16)i;

			if (skipped_logs > log_diff) {
				skipped_logs--;
				err = -ENOENT;
				continue;
			} else {
				/* log has been found */
				err = 0;
				goto finish_prev_log_search;
			}
		} else if (is_ssdfs_partial_log_header_magic_valid(magic)) {
			u32 flags;

			pl_hdr = SSDFS_PLH(kaddr);

			err = ssdfs_check_partial_log_header(fsi, pl_hdr,
							     false);
			if (unlikely(err)) {
				SSDFS_ERR("partial log header is corrupted: "
					  "seg %llu, peb %llu, index %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  i);
				return -EIO;
			}

			env->has_seg_hdr = false;
			env->has_footer = ssdfs_pl_has_footer(pl_hdr);

			env->log_bytes =
				le32_to_cpu(pl_hdr->log_bytes);

			flags = le32_to_cpu(pl_hdr->pl_flags);

			if (flags & SSDFS_PARTIAL_HEADER_INSTEAD_FOOTER) {
				/* first partial log */
				err = -ENOENT;
				continue;
			} else if (flags & SSDFS_LOG_HAS_FOOTER) {
				/* last partial log */
				if (start_offset == i) {
					/*
					 * Requested starting log_offset
					 * points out on segment header.
					 * It needs to skip this header
					 * because of searching the previous
					 * log.
					 */
					continue;
				}

				env->log_offset = (u16)i;

				if (skipped_logs > log_diff) {
					skipped_logs--;
					err = -ENOENT;
					continue;
				} else {
					/* log has been found */
					err = 0;
					goto finish_prev_log_search;
				}
			} else {
				/* intermediate partial log */
				if (start_offset == i) {
					/*
					 * Requested starting log_offset
					 * points out on segment header.
					 * It needs to skip this header
					 * because of searching the previous
					 * log.
					 */
					continue;
				}

				env->log_offset = (u16)i;

				if (skipped_logs > log_diff) {
					skipped_logs--;
					err = -ENOENT;
					continue;
				} else {
					/* log has been found */
					err = 0;
					goto finish_prev_log_search;
				}
			}
		} else if (__is_ssdfs_log_footer_magic_valid(magic)) {
			footer = SSDFS_LF(env->footer);

			env->log_bytes =
				le32_to_cpu(footer->log_bytes);
			continue;
		} else {
			err = -ENOENT;
			continue;
		}
	}

finish_prev_log_search:
	SSDFS_DBG("log_offset %u, log_bytes %u\n",
		  env->log_offset,
		  env->log_bytes);

	return err;
}

/*
 * ssdfs_peb_complete_init_blk2off_table() - init blk2off table's fragment
 * @pebi: pointer on PEB object
 * @log_diff: offset for logs processing
 * @req: read request
 *
 * This function tries to init blk2off table's fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_peb_complete_init_blk2off_table(struct ssdfs_peb_info *pebi,
					  int log_diff,
					  struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *blk2off_table = NULL;
	struct ssdfs_read_init_env env;
	u64 cno;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, log_diff %d, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, log_diff,
		  req->private.class,
		  req->private.cmd,
		  req->private.type);

	fsi = pebi->pebc->parent_si->fsi;
	blk2off_table = pebi->pebc->parent_si->blk2off_table;

	switch (atomic_read(&blk2off_table->state)) {
	case SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT:
		SSDFS_DBG("blk2off table has been initialized: "
			  "peb_id %llu\n",
	  		  pebi->peb_id);
		return 0;

	default:
		/* continue to init blk2off table */
		break;
	}

	err = ssdfs_prepare_read_init_env(&env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init read environment: err %d\n",
			  err);
		return err;
	}

	env.log_offset = fsi->pages_per_peb;

	do {
		err = ssdfs_find_prev_partial_log(fsi, pebi, &env, log_diff);
		if (err == -ENOENT) {
			if (env.log_offset > 0) {
				SSDFS_ERR("fail to find prev log: "
					  "log_offset %u, err %d\n",
					  env.log_offset, err);
				goto fail_init_blk2off_table;
			} else {
				/* no previous log exists */
				err = 0;
				SSDFS_DBG("no previous log exists\n");
				goto fail_init_blk2off_table;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find prev log: "
				  "log_offset %u, err %d\n",
				  env.log_offset, err);
			goto fail_init_blk2off_table;
		}

		err = ssdfs_pre_fetch_blk2off_table_area(pebi, &env);
		if (unlikely(err)) {
			SSDFS_ERR("fail to pre-fetch blk2off_table area: "
				  "seg %llu, peb %llu, log_offset %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  env.log_offset,
				  err);
			goto fail_init_blk2off_table;
		}

		err = ssdfs_read_blk2off_table_fragment(pebi, &env);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read translation table fragments: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			goto fail_init_blk2off_table;
		}

		if (env.has_seg_hdr) {
			struct ssdfs_segment_header *seg_hdr = NULL;

			seg_hdr = SSDFS_SEG_HDR(env.log_hdr);
			cno = le64_to_cpu(seg_hdr->cno);
		} else {
			struct ssdfs_partial_log_header *pl_hdr = NULL;

			pl_hdr = SSDFS_PLH(env.log_hdr);
			cno = le64_to_cpu(pl_hdr->cno);
		}

		err = ssdfs_blk2off_table_partial_init(blk2off_table,
							&env.t_init.pvec,
							pebi->peb_index,
							cno);
		if (unlikely(err)) {
			SSDFS_ERR("fail to start init of offset table: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			goto fail_init_blk2off_table;
		}

		pagevec_release(&env.t_init.pvec);
		log_diff = 0;
	} while (env.log_offset > 0);

fail_init_blk2off_table:
	ssdfs_destroy_init_env(&env);
	return err;
}

/*
 * ssdfs_start_complete_init_blk2off_table() - start to init blk2off table
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This function tries to start the initialization of blk2off table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_start_complete_init_blk2off_table(struct ssdfs_peb_info *pebi,
					    struct ssdfs_segment_request *req)
{
	int log_diff = -1;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_id %llu, peb_index %u\n",
		  pebi->peb_id, pebi->peb_index);

	switch (atomic_read(&pebi->current_log.state)) {
	case SSDFS_LOG_INITIALIZED:
	case SSDFS_LOG_CREATED:
	case SSDFS_LOG_COMMITTED:
		/*
		 * The last log was processed during initialization of
		 * "using" or "used" PEB. So, it needs to process the
		 * log before the last one.
		 */
		log_diff = -1;
		break;

	default:
		/*
		 * It needs to process the last log.
		 */
		log_diff = 0;
		break;
	}

	err = ssdfs_peb_complete_init_blk2off_table(pebi, log_diff, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to complete blk2off table init: "
			  "peb_id %llu, peb_index %u, "
			  "log_diff %d, err %d\n",
			  pebi->peb_id, pebi->peb_index,
			  log_diff, err);
	}

	return err;
}

/*
 * ssdfs_finish_complete_init_blk2off_table() - finish to init blk2off table
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This function tries to finish the initialization of blk2off table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_finish_complete_init_blk2off_table(struct ssdfs_peb_info *pebi,
					     struct ssdfs_segment_request *req)
{
	int log_diff = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_id %llu, peb_index %u\n",
		  pebi->peb_id, pebi->peb_index);

	switch (atomic_read(&pebi->current_log.state)) {
	case SSDFS_LOG_INITIALIZED:
	case SSDFS_LOG_CREATED:
	case SSDFS_LOG_COMMITTED:
		/*
		 * It needs to process the last log of source PEB.
		 * The destination PEB has been/will be processed
		 * in a real pair.
		 */
		log_diff = 0;
		break;

	default:
		/*
		 * It needs to process the last log.
		 */
		log_diff = 0;
		break;
	}

	err = ssdfs_peb_complete_init_blk2off_table(pebi, log_diff, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to complete blk2off table init: "
			  "peb_id %llu, peb_index %u, "
			  "log_diff %d, err %d\n",
			  pebi->peb_id, pebi->peb_index, log_diff, err);
	}

	return err;
}

/*
 * ssdfs_src_peb_complete_init_blk2off_table() - init src PEB's blk2off table
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This function tries to init the source PEB's blk2off table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_src_peb_complete_init_blk2off_table(struct ssdfs_peb_container *pebc,
					      struct ssdfs_segment_request *req)
{
	struct ssdfs_peb_info *pebi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (!pebi) {
		SSDFS_WARN("source PEB is NULL\n");
		err = -ERANGE;
		goto finish_src_peb_init_blk2off_table;
	}

	err = ssdfs_start_complete_init_blk2off_table(pebi, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to complete blk2off table init: "
			  "seg_id %llu, peb_index %u, "
			  "err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  err);
		goto finish_src_peb_init_blk2off_table;
	}

finish_src_peb_init_blk2off_table:
	up_read(&pebc->lock);

	return err;
}

/*
 * ssdfs_dst_peb_complete_init_blk2off_table() - init dst PEB's blk2off table
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This function tries to init the destination PEB's blk2off table.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_dst_peb_complete_init_blk2off_table(struct ssdfs_peb_container *pebc,
					      struct ssdfs_segment_request *req)
{
	struct ssdfs_peb_info *pebi;
	int items_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	down_read(&pebc->lock);

	items_state = atomic_read(&pebc->items_state);
	switch (items_state) {
	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		pebi = pebc->dst_peb;
		if (!pebi) {
			SSDFS_WARN("destination PEB is NULL\n");
			err = -ERANGE;
			goto finish_dst_peb_init_blk2off_table;
		}

		err = ssdfs_start_complete_init_blk2off_table(pebi, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to complete blk2off table init: "
				  "seg_id %llu, peb_index %u, "
				  "err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  err);
			goto finish_dst_peb_init_blk2off_table;
		}
		break;

	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		pebi = pebc->src_peb;
		if (!pebi) {
			SSDFS_WARN("source PEB is NULL\n");
			err = -ERANGE;
			goto finish_dst_peb_init_blk2off_table;
		}

		err = ssdfs_finish_complete_init_blk2off_table(pebi, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to complete blk2off table init: "
				  "seg_id %llu, peb_index %u, "
				  "err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  err);
			goto finish_dst_peb_init_blk2off_table;
		}
		break;

	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		pebi = pebc->dst_peb;
		if (!pebi) {
			SSDFS_WARN("destination PEB is NULL\n");
			err = -ERANGE;
			goto finish_dst_peb_init_blk2off_table;
		}

		err = ssdfs_start_complete_init_blk2off_table(pebi, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to complete blk2off table init: "
				  "seg_id %llu, peb_index %u, "
				  "err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  err);
			goto finish_dst_peb_init_blk2off_table;
		}

		pebi = pebc->src_peb;
		if (!pebi) {
			SSDFS_WARN("source PEB is NULL\n");
			err = -ERANGE;
			goto finish_dst_peb_init_blk2off_table;
		}

		err = ssdfs_finish_complete_init_blk2off_table(pebi, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to complete blk2off table init: "
				  "seg_id %llu, peb_index %u, "
				  "err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  err);
			goto finish_dst_peb_init_blk2off_table;
		}
		break;

	default:
		BUG();
	}

finish_dst_peb_init_blk2off_table:
	up_read(&pebc->lock);

	return err;
}

/*
 * ssdfs_peb_define_segbmap_seg_index() - define segbmap segment index
 * @pebc: pointer on PEB container
 *
 * RETURN:
 * [success] - segbmap segment index
 * [failure] - U16_MAX
 */
static
u16 ssdfs_peb_define_segbmap_seg_index(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_bmap *segbmap;
	int seg_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->fsi->segbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	segbmap = pebc->parent_si->fsi->segbmap;

	down_read(&segbmap->resize_lock);

	seg_index = ssdfs_segbmap_seg_id_2_seg_index(segbmap,
						     pebc->parent_si->seg_id);
	if (seg_index < 0) {
		SSDFS_ERR("fail to convert seg_id %llu, err %d\n",
			  pebc->parent_si->seg_id, seg_index);
		seg_index = U16_MAX;
	}

	up_read(&segbmap->resize_lock);

	return (u16)seg_index;
}

/*
 * ssdfs_peb_define_segbmap_sequence_id() - define fragment's sequence ID
 * @pebc: pointer on PEB container
 * @seg_index: index of segment in segbmap's segments sequence
 * @logical_offset: logical offset
 *
 * RETURN:
 * [success] - sequence ID
 * [failure] - U16_MAX
 */
static
u16 ssdfs_peb_define_segbmap_sequence_id(struct ssdfs_peb_container *pebc,
					 u16 seg_index,
					 u64 logical_offset)
{
	struct ssdfs_segment_bmap *segbmap;
	u16 peb_index;
	u16 fragments_per_seg;
	u16 fragment_size;
	u32 id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->fsi->segbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, logical_offset %llu\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  logical_offset);

	segbmap = pebc->parent_si->fsi->segbmap;
	peb_index = pebc->peb_index;

	down_read(&segbmap->resize_lock);
	fragments_per_seg = segbmap->fragments_per_seg;
	fragment_size = segbmap->fragment_size;
	up_read(&segbmap->resize_lock);

	logical_offset /= fragment_size;
	BUG_ON(logical_offset >= U16_MAX);

	id = seg_index * fragments_per_seg;
	id += (u32)logical_offset;
	BUG_ON(id >= U16_MAX);

	return (u16)id;
}

/*
 * ssdfs_peb_define_segbmap_logical_extent() - define logical extent
 * @pebc: pointer on PEB container
 * @ptr: pointer on segbmap extent [out]
 */
static
void ssdfs_peb_define_segbmap_logical_extent(struct ssdfs_peb_container *pebc,
					     struct ssdfs_segbmap_extent *ptr)
{
	struct ssdfs_segment_bmap *segbmap;
	u16 peb_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->fsi->segbmap);
	BUG_ON(!ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, extent %p\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  ptr);

	segbmap = pebc->parent_si->fsi->segbmap;
	peb_index = pebc->peb_index;

	down_read(&segbmap->resize_lock);

	ptr->fragment_size = segbmap->fragment_size;
	ptr->logical_offset = peb_index * segbmap->fragments_per_peb;
	ptr->logical_offset *= ptr->fragment_size;
	ptr->data_size = segbmap->fragments_per_peb * ptr->fragment_size;

	up_read(&segbmap->resize_lock);
}

/*
 * ssdfs_peb_define_segbmap_logical_block() - convert offset into block number
 * @pebc: pointer on PEB container
 * @logical_offset: logical offset
 *
 * RETURN:
 * [success] - logical block number
 * [failure] - U16_MAX
 */
static
u16 ssdfs_peb_define_segbmap_logical_block(struct ssdfs_peb_container *pebc,
					   u64 logical_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_bmap *segbmap;
	u16 peb_index;
	u32 blks_per_peb;
	u32 peb_blk_off, blk_off;
	u32 logical_blk;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->fsi->segbmap);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, "
		  "logical_offset %llu\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  logical_offset);

	fsi = pebc->parent_si->fsi;
	segbmap = fsi->segbmap;
	peb_index = pebc->peb_index;

	down_read(&segbmap->resize_lock);
	blks_per_peb = (u32)segbmap->fragments_per_peb * segbmap->fragment_size;
	blks_per_peb >>= fsi->log_pagesize;
	up_read(&segbmap->resize_lock);

	peb_blk_off = blks_per_peb * peb_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(peb_blk_off >= U16_MAX);
	BUG_ON((logical_offset >> fsi->log_pagesize) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	blk_off = (u32)(logical_offset >> fsi->log_pagesize);

	if (blk_off < peb_blk_off || blk_off >= (peb_blk_off + blks_per_peb)) {
		SSDFS_ERR("invalid logical offset: "
			  "blk_off %u, peb_blk_off %u, blks_per_peb %u\n",
			  blk_off, peb_blk_off, blks_per_peb);
		return U16_MAX;
	}

	logical_blk = blk_off - peb_blk_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(logical_blk >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u16)logical_blk;
}

/*
 * ssdfs_peb_read_segbmap_first_page() - read first page of segbmap
 * @pebc: pointer on PEB container
 * @seg_index: index of segment in segbmap's segments sequence
 * @extent: requested extent for reading
 *
 * This method tries to read first page of segbmap, to check it
 * and to initialize the available fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA     - no pages for read.
 * %-ENOMEM      - fail to allocate memory.
 * %-ERANGE      - internal error.
 */
static
int ssdfs_peb_read_segbmap_first_page(struct ssdfs_peb_container *pebc,
				      u16 seg_index,
				      struct ssdfs_segbmap_extent *extent)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_request *req;
	u16 pages_count = 1;
	u16 logical_blk;
	u16 sequence_id;
	int state;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!extent);
	BUG_ON(extent->fragment_size != PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "logical_offset %llu, data_size %u, "
		  "fragment_size %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  extent->logical_offset, extent->data_size,
		  extent->fragment_size);

	fsi = pebc->parent_si->fsi;

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req);
	ssdfs_get_request(req);

	ssdfs_request_prepare_logical_extent(SSDFS_SEG_BMAP_INO,
					     extent->logical_offset,
					     extent->fragment_size,
					     0, 0, req);

	err = ssdfs_request_add_allocated_page_locked(req);
	if (unlikely(err)) {
		SSDFS_ERR("fail allocate memory page: err %d\n", err);
		goto fail_read_segbmap_page;
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    SSDFS_READ_PAGE,
					    SSDFS_REQ_SYNC,
					    req);

	ssdfs_request_define_segment(pebc->parent_si->seg_id, req);

	logical_blk = ssdfs_peb_define_segbmap_logical_block(pebc,
							extent->logical_offset);
	if (unlikely(logical_blk == U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("fail to define logical block\n");
		goto fail_read_segbmap_page;
	}

	if (fsi->pagesize < PAGE_SIZE)
		pages_count = PAGE_SIZE >> fsi->log_pagesize;

	ssdfs_request_define_volume_extent(logical_blk, pages_count, req);

	err = ssdfs_peb_read_page(pebc, req, NULL);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		goto fail_read_segbmap_page;
	}

	if (!err) {
		for (i = 0; i < req->result.processed_blks; i++)
			ssdfs_peb_mark_request_block_uptodate(pebc, req, i);
	}

	if (!ssdfs_segbmap_fragment_has_content(req->result.pvec.pages[0])) {
		err = -ENODATA;
		SSDFS_DBG("peb_index %u hasn't segbmap's fragments\n",
			  pebc->peb_index);
		goto fail_read_segbmap_page;
	}

	sequence_id = ssdfs_peb_define_segbmap_sequence_id(pebc, seg_index,
							extent->logical_offset);
	if (unlikely(sequence_id == U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("fail to define sequence_id\n");
		goto fail_read_segbmap_page;
	}

	err = ssdfs_segbmap_check_fragment_header(pebc, seg_index, sequence_id,
						  req->result.pvec.pages[0]);
	if (unlikely(err)) {
		SSDFS_CRIT("segbmap fragment is corrupted: err %d\n",
			   err);
	}

	if (err) {
		state = SSDFS_SEGBMAP_FRAG_INIT_FAILED;
		goto fail_read_segbmap_page;
	} else
		state = SSDFS_SEGBMAP_FRAG_INITIALIZED;

	err = ssdfs_segbmap_fragment_init(pebc, sequence_id,
					  req->result.pvec.pages[0],
					  state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init fragment: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		goto fail_read_segbmap_page;
	} else {
		unlock_page(req->result.pvec.pages[0]);
		req->result.pvec.pages[0] = NULL;
	}

	pagevec_reinit(&req->result.pvec);

	extent->logical_offset += extent->fragment_size;
	extent->data_size -= extent->fragment_size;

fail_read_segbmap_page:
	ssdfs_request_unlock_and_remove_pages(req);
	ssdfs_put_request(req);
	ssdfs_request_free(req);

	return err;
}

/*
 * ssdfs_peb_read_segbmap_pages() - read pagevec-based amount of pages
 * @pebc: pointer on PEB container
 * @seg_index: index of segment in segbmap's segments sequence
 * @extent: requested extent for reading
 *
 * This method tries to read pagevec-based amount of pages of
 * segbmap in PEB (excluding the first one) and to initialize all
 * available fragments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA     - no pages for read.
 * %-ENOMEM      - fail to allocate memory.
 * %-ERANGE      - internal error.
 */
static
int ssdfs_peb_read_segbmap_pages(struct ssdfs_peb_container *pebc,
				 u16 seg_index,
				 struct ssdfs_segbmap_extent *extent)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_request *req;
	u32 read_bytes;
	u16 fragments_count;
	u16 pages_count = 1;
	u16 logical_blk;
	u16 sequence_id;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!extent);
	BUG_ON(extent->fragment_size != PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "logical_offset %llu, data_size %u, "
		  "fragment_size %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  extent->logical_offset, extent->data_size,
		  extent->fragment_size);

	fsi = pebc->parent_si->fsi;

	req = ssdfs_request_alloc();
	if (IS_ERR_OR_NULL(req)) {
		err = (req == NULL ? -ENOMEM : PTR_ERR(req));
		SSDFS_ERR("fail to allocate segment request: err %d\n",
			  err);
		return err;
	}

	ssdfs_request_init(req);
	ssdfs_get_request(req);

	read_bytes = min_t(u32, PAGEVEC_SIZE * PAGE_SIZE,
			   extent->data_size);

	ssdfs_request_prepare_logical_extent(SSDFS_SEG_BMAP_INO,
					     extent->logical_offset,
					     read_bytes,
					     0, 0, req);

	fragments_count = read_bytes + extent->fragment_size - 1;
	fragments_count /= extent->fragment_size;

	for (i = 0; i < fragments_count; i++) {
		err = ssdfs_request_add_allocated_page_locked(req);
		if (unlikely(err)) {
			SSDFS_ERR("fail allocate memory page: err %d\n", err);
			goto fail_read_segbmap_pages;
		}
	}

	ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
					    SSDFS_READ_PAGES_READAHEAD,
					    SSDFS_REQ_SYNC,
					    req);

	ssdfs_request_define_segment(pebc->parent_si->seg_id, req);

	logical_blk = ssdfs_peb_define_segbmap_logical_block(pebc,
							extent->logical_offset);
	if (unlikely(logical_blk == U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("fail to define logical block\n");
		goto fail_read_segbmap_pages;
	}

	pages_count = (read_bytes + fsi->pagesize - 1) >> PAGE_SHIFT;
	ssdfs_request_define_volume_extent(logical_blk, pages_count, req);

	err = ssdfs_peb_readahead_pages(pebc, req, NULL);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read pages: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		goto fail_read_segbmap_pages;
	}

	for (i = 0; i < req->result.processed_blks; i++)
		ssdfs_peb_mark_request_block_uptodate(pebc, req, i);

	sequence_id = ssdfs_peb_define_segbmap_sequence_id(pebc, seg_index,
							extent->logical_offset);
	if (unlikely(sequence_id == U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("fail to define sequence_id\n");
		goto fail_read_segbmap_pages;
	}

	for (i = 0; i < fragments_count; i++) {
		int state;
		struct page *page = req->result.pvec.pages[i];

		err = ssdfs_segbmap_check_fragment_header(pebc, seg_index,
							  sequence_id, page);
		if (unlikely(err)) {
			SSDFS_CRIT("segbmap fragment is corrupted: "
				   "sequence_id %u, err %d\n",
				   sequence_id, err);
		}

		if (err) {
			state = SSDFS_SEGBMAP_FRAG_INIT_FAILED;
			goto fail_read_segbmap_pages;
		} else
			state = SSDFS_SEGBMAP_FRAG_INITIALIZED;

		err = ssdfs_segbmap_fragment_init(pebc, sequence_id,
						  page, state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init fragment: "
				  "sequence_id %u, err %d\n",
				  sequence_id, err);
			goto fail_read_segbmap_pages;
		} else {
			unlock_page(req->result.pvec.pages[i]);
			req->result.pvec.pages[i] = NULL;
		}

		sequence_id++;
	}

	pagevec_reinit(&req->result.pvec);

	extent->logical_offset += read_bytes;
	extent->data_size -= read_bytes;

fail_read_segbmap_pages:
	ssdfs_request_unlock_and_remove_pages(req);
	ssdfs_put_request(req);
	ssdfs_request_free(req);

	return err;
}

/*
 * ssdfs_peb_read_segbmap_rest_pages() - read all pages of segbmap in PEB
 * @pebc: pointer on PEB container
 * @seg_index: index of segment in segbmap's segments sequence
 * @extent: requested extent for reading
 *
 * This method tries to read all pages of segbmap in PEB (excluding
 * the first one) and initialize all available fragments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA     - no pages for read.
 */
static
int ssdfs_peb_read_segbmap_rest_pages(struct ssdfs_peb_container *pebc,
				      u16 seg_index,
				      struct ssdfs_segbmap_extent *extent)
{
	int err = 0, err1;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!extent);
	BUG_ON(extent->fragment_size != PAGE_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "logical_offset %llu, data_size %u, "
		  "fragment_size %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  extent->logical_offset, extent->data_size,
		  extent->fragment_size);

	if (extent->data_size == 0) {
		SSDFS_DBG("extent->data_size == 0\n");
		return -ENODATA;
	}

	do {
		err1 = ssdfs_peb_read_segbmap_pages(pebc, seg_index,
						   extent);
		if (unlikely(err1)) {
			SSDFS_ERR("fail to read segbmap's pages: "
				  "logical_offset %llu, data_bytes %u, "
				  "err %d\n",
				  extent->logical_offset,
				  extent->data_size,
				  err1);
			err = err1;
			break;
		}
	} while (extent->data_size > 0);

	return err;
}

/*
 * ssdfs_peb_init_segbmap_object() - init segment bitmap object
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This method tries to initialize segment bitmap object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_init_segbmap_object(struct ssdfs_peb_container *pebc,
				  struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	u16 seg_index;
	struct ssdfs_segbmap_extent extent = {0};
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);

	fsi = pebc->parent_si->fsi;

	seg_index = ssdfs_peb_define_segbmap_seg_index(pebc);
	if (seg_index == U16_MAX) {
		SSDFS_ERR("fail to determine segment index\n");
		return -ERANGE;
	}

	ssdfs_peb_define_segbmap_logical_extent(pebc, &extent);

	err = ssdfs_peb_read_segbmap_first_page(pebc, seg_index, &extent);
	if (err == -ENODATA) {
		SSDFS_DBG("peb_index %u hasn't segbmap's content\n",
			  pebc->peb_index);
		return 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read PEB's segbmap first page: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_peb_read_segbmap_rest_pages(pebc, seg_index, &extent);
	if (err == -ENODATA) {
		SSDFS_DBG("peb_index %u has only one page\n",
			  pebc->peb_index);
		return 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read PEB's segbmap rest pages: "
			  "err %d\n", err);
		return err;
	}

	{
		int err1 = ssdfs_peb_release_pages(pebc);
		if (unlikely(err1)) {
			SSDFS_ERR("fail to release pages: err %d\n",
				  err1);
		}
	}

	return 0;
}

/*
 * ssdfs_maptbl_fragment_pages_count() - calculate count of pages in fragment
 * @fsi: file system info object
 *
 * This method calculates count of pages in the mapping table's
 * fragment.
 *
 * RETURN:
 * [success] - count of pages in fragment
 * [failure] - U16_MAX
 */
static inline
u16 ssdfs_maptbl_fragment_pages_count(struct ssdfs_fs_info *fsi)
{
	u32 fragment_pages;

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->maptbl->fragment_bytes % PAGE_SIZE) {
		SSDFS_WARN("invalid fragment_bytes %u\n",
			   fsi->maptbl->fragment_bytes);
		return U16_MAX;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	fragment_pages = fsi->maptbl->fragment_bytes / PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(fragment_pages >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return fragment_pages;
}

/*
 * ssdfs_peb_read_maptbl_fragment() - read mapping table's fragment's pages
 * @pebc: pointer on PEB container
 * @index: index of fragment in the PEB
 * @fragment_bytes: size of fragment in bytes
 * @area: fragment content [out]
 *
 * This method tries to read mapping table's fragment's pages.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - fragment hasn't content.
 */
static
int ssdfs_peb_read_maptbl_fragment(struct ssdfs_peb_container *pebc,
				   int index, u32 fragment_bytes,
				   struct ssdfs_maptbl_area *area)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_request *req;
	u64 logical_offset = 0;
	u32 pagevec_bytes = (u32)PAGEVEC_SIZE << PAGE_SHIFT;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi || !area);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("pebc %p, index %d, fragment_bytes %u, area %p\n",
		  pebc, index, fragment_bytes, area);

	fsi = pebc->parent_si->fsi;

	if (fragment_bytes == 0) {
		SSDFS_ERR("invalid fragment_bytes %u\n",
			  fragment_bytes);
		return -ERANGE;
	}

	do {
		u32 logical_blk;
		u32 size;
		u16 pages_count;
		int i;

		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			return err;
		}

		ssdfs_request_init(req);
		ssdfs_get_request(req);

		if (logical_offset == 0)
			size = PAGE_SIZE;
		else
			size = min_t(u32, fragment_bytes, pagevec_bytes);

		ssdfs_request_prepare_logical_extent(SSDFS_MAPTBL_INO,
						     logical_offset, size,
						     0, 0, req);

		pages_count = (size + fsi->pagesize - 1) >> PAGE_SHIFT;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(pages_count > PAGEVEC_SIZE);
#endif /* CONFIG_SSDFS_DEBUG */

		for (i = 0; i < pages_count; i++) {
			err = ssdfs_request_add_allocated_page_locked(req);
			if (unlikely(err)) {
				SSDFS_ERR("fail allocate memory page: err %d\n",
					  err);
				goto fail_read_maptbl_pages;
			}
		}

		ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
						    SSDFS_READ_PAGES_READAHEAD,
						    SSDFS_REQ_SYNC,
						    req);

		ssdfs_request_define_segment(pebc->parent_si->seg_id, req);

		logical_blk = (u32)((((u64)fragment_bytes * index) +
					logical_offset) >> fsi->log_pagesize);
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(logical_blk >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_request_define_volume_extent((u16)logical_blk,
						   pages_count, req);

		err = ssdfs_peb_readahead_pages(pebc, req, NULL);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read pages: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			goto fail_read_maptbl_pages;
		}

		for (i = 0; i < req->result.processed_blks; i++)
			ssdfs_peb_mark_request_block_uptodate(pebc, req, i);

		if (logical_offset == 0) {
			struct ssdfs_leb_table_fragment_header *hdr;
			u16 magic;
			void *kaddr;
			bool is_fragment_valid = false;

			kaddr = kmap_atomic(req->result.pvec.pages[0]);
			hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;
			magic = le16_to_cpu(hdr->magic);
			is_fragment_valid = magic == SSDFS_LEB_TABLE_MAGIC;
			area->portion_id = le16_to_cpu(hdr->portion_id);
			kunmap_atomic(kaddr);

			if (!is_fragment_valid) {
				err = -ENODATA;
				area->portion_id = U16_MAX;
				SSDFS_DBG("empty fragment: "
					  "peb_index %u, index %d\n",
					  pebc->peb_index, index);
				goto fail_read_maptbl_pages;
			}
		}

		for (i = 0; i < pages_count; i++) {
			struct page *page = req->result.pvec.pages[i];

			get_page(page);
			area->pages[area->pages_count] = page;
			area->pages_count++;
			unlock_page(page);
			req->result.pvec.pages[i] = NULL;
		}

		pagevec_reinit(&req->result.pvec);

		ssdfs_request_unlock_and_remove_pages(req);
		ssdfs_put_request(req);
		ssdfs_request_free(req);

		fragment_bytes -= size;
		logical_offset += size;
	} while (fragment_bytes > 0);

	return 0;

fail_read_maptbl_pages:
	ssdfs_request_unlock_and_remove_pages(req);
	ssdfs_put_request(req);
	ssdfs_request_free(req);

	return err;
}

/*
 * ssdfs_peb_init_maptbl_object() - init mapping table's fragment
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This method tries to read and to init mapping table's fragment.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
static
int ssdfs_peb_init_maptbl_object(struct ssdfs_peb_container *pebc,
				 struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_maptbl_area area = {0};
	u32 fragment_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);

	fsi = pebc->parent_si->fsi;

	down_read(&fsi->maptbl->tbl_lock);
	fragment_bytes = fsi->maptbl->fragment_bytes;
	area.pages_count = 0;
	area.pages_capacity = ssdfs_maptbl_fragment_pages_count(fsi);
	up_read(&fsi->maptbl->tbl_lock);

	if (unlikely(area.pages_capacity >= U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("invalid fragment pages_capacity\n");
		goto end_init;
	}

	area.pages = kcalloc(area.pages_capacity, sizeof(struct page *),
			     GFP_KERNEL);
	if (!area.pages) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory: "
			  "area.pages_capacity %zu\n",
			  area.pages_capacity);
		goto end_init;
	}

	for (i = 0; i < fsi->maptbl->fragments_per_peb; i++) {
		err = ssdfs_peb_read_maptbl_fragment(pebc, i,
						     fragment_bytes,
						     &area);
		if (err == -ENODATA) {
			err = 0;
			SSDFS_DBG("peb_index %u hasn't more maptbl fragments: "
				  "last index %d\n",
				  pebc->peb_index, i);
			goto end_init;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read maptbl fragment: "
				  "index %d, err %d\n",
				  i, err);
			goto end_init;
		}

		down_read(&fsi->maptbl->tbl_lock);
		err = ssdfs_maptbl_fragment_init(pebc, &area);
		up_read(&fsi->maptbl->tbl_lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to init maptbl fragment: "
				  "index %d, err %d\n",
				  i, err);
			goto end_init;
		}
	}

end_init:
	for (i = 0; i < area.pages_capacity; i++) {
		if (area.pages[i]) {
			ssdfs_free_page(area.pages[i]);
			area.pages[i] = NULL;
		}
	}

	kfree(area.pages);

	{
		int err1 = ssdfs_peb_release_pages(pebc);
		if (unlikely(err1)) {
			SSDFS_ERR("fail to release pages: err %d\n",
				  err1);
		}
	}

	return err;
}

/*
 * ssdfs_process_read_request() - process read request
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This function detects command of read request and
 * to call a proper function for request processing.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_process_read_request(struct ssdfs_peb_container *pebc,
				struct ssdfs_segment_request *req)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("req %p, class %#x, cmd %#x, type %#x\n",
		  req, req->private.class, req->private.cmd,
		  req->private.type);

	if (req->private.cmd < SSDFS_READ_PAGE ||
	    req->private.cmd >= SSDFS_READ_CMD_MAX) {
		SSDFS_ERR("unknown read command %d, seg %llu, peb_index %u\n",
			  req->private.cmd, pebc->parent_si->seg_id,
			  pebc->peb_index);
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		req->result.err = -EINVAL;
		return -EINVAL;
	}

	atomic_set(&req->result.state, SSDFS_REQ_STARTED);

	switch (req->private.cmd) {
	case SSDFS_READ_PAGE:
		err = ssdfs_peb_read_page(pebc, req, NULL);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read page: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_PAGES_READAHEAD:
		err = ssdfs_peb_readahead_pages(pebc, req, NULL);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read pages: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_SRC_ALL_LOG_HEADERS:
		err = ssdfs_peb_read_src_all_log_headers(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read log headers: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_DST_ALL_LOG_HEADERS:
		err = ssdfs_peb_read_dst_all_log_headers(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read log headers: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_BLK_BMAP_SRC_USING_PEB:
		err = ssdfs_src_peb_init_using_metadata_state(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init source PEB (using state): "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_BLK_BMAP_DST_USING_PEB:
		err = ssdfs_dst_peb_init_using_metadata_state(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init destination PEB (using state): "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_BLK_BMAP_SRC_USED_PEB:
		err = ssdfs_src_peb_init_used_metadata_state(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init source PEB (used state): "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_BLK_BMAP_DST_USED_PEB:
		err = ssdfs_dst_peb_init_used_metadata_state(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init destination PEB (used state): "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_BLK2OFF_TABLE_SRC_PEB:
		err = ssdfs_src_peb_complete_init_blk2off_table(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to finish offset table init: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_BLK2OFF_TABLE_DST_PEB:
		err = ssdfs_dst_peb_complete_init_blk2off_table(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to finish offset table init: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_INIT_SEGBMAP:
		err = ssdfs_peb_init_segbmap_object(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init segment bitmap object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_INIT_MAPTBL:
		err = ssdfs_peb_init_maptbl_object(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init mapping table object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
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
 * ssdfs_finish_read_request() - finish read request
 * @pebc: pointer on PEB container
 * @req: segment request
 * @wait: wait queue head
 * @err: error code (read request failure code)
 *
 * This function makes final activity with read request.
 */
static
void ssdfs_finish_read_request(struct ssdfs_peb_container *pebc,
				struct ssdfs_segment_request *req,
				wait_queue_head_t *wait, int err)
{
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("req %p, class %#x, cmd %#x, type %#x, err %d\n",
		  req, req->private.class, req->private.cmd,
		  req->private.type, err);

	if (!err) {
		for (i = 0; i < req->result.processed_blks; i++)
			ssdfs_peb_mark_request_block_uptodate(pebc, req, i);
	}

	req->result.err = err;

	if (err)
		atomic_set(&req->result.state, SSDFS_REQ_FAILED);
	else
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

#ifdef CONFIG_SSDFS_DEBUG
			WARN_ON(!PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

			unlock_page(page);
			put_page(page);
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

#ifdef CONFIG_SSDFS_DEBUG
			WARN_ON(!PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

			unlock_page(page);
			put_page(page);
		}
		break;

	default:
		BUG();
	};
}

#define PEBI_PTR(pebi) \
	((struct ssdfs_peb_info *)(pebi))
#define PEBC_PTR(pebc) \
	((struct ssdfs_peb_container *)(pebc))
#define READ_RQ_PTR(pebc) \
	(&PEBC_PTR(pebc)->read_rq)
#define READ_THREAD_WAKE_CONDITION(pebc) \
	(kthread_should_stop() || \
	 !is_ssdfs_requests_queue_empty(READ_RQ_PTR(pebc)))

/*
 * ssdfs_peb_read_thread_func() - main fuction of read thread
 * @data: pointer on data object
 *
 * This function is main fuction of read thread.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_peb_read_thread_func(void *data)
{
	struct ssdfs_peb_container *pebc = data;
	wait_queue_head_t *wait_queue;
	struct ssdfs_segment_request *req;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("read thread: seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

	wait_queue = &pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD];

repeat:
	if (kthread_should_stop()) {
		complete_all(&pebc->thread[SSDFS_PEB_READ_THREAD].full_stop);
		return 0;
	}

	if (is_ssdfs_requests_queue_empty(&pebc->read_rq))
		goto sleep_read_thread;

	do {
		err = ssdfs_requests_queue_remove_first(&pebc->read_rq,
							&req);
		if (err == -ENODATA) {
			/* empty queue */
			err = 0;
			break;
		} else if (err == -ENOENT) {
			SSDFS_WARN("request queue contains NULL request\n");
			err = 0;
			continue;
		} else if (unlikely(err < 0)) {
			SSDFS_CRIT("fail to get request from the queue: "
				   "err %d\n",
				   err);
			return err;
		}

		err = ssdfs_process_read_request(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to process read request: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}

		ssdfs_finish_read_request(pebc, req, wait_queue, err);
	} while (!is_ssdfs_requests_queue_empty(&pebc->read_rq));

sleep_read_thread:
	wait_event_interruptible(*wait_queue, READ_THREAD_WAKE_CONDITION(pebc));
	goto repeat;
}
