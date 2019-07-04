//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_read_thread.c - read thread functionality.
 *
 * Copyright (c) 2014-2018 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2009-2018, HGST, Inc., All rights reserved.
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
 * @seg_hdr: segment header
 * @footer: log footer
 * @bmap_hdr: pointer on block bitmap header
 * @bmap_hdr_buf: block bitmap header buffer
 * @frag_hdr: block bitmap fragment header
 * @frag_hdr_buf: block bitmap fragment header buffer
 * @log_index: index of the requested log
 * @log_pages: pages count in every log of segment
 * @fragment_index: index of bmap fragment
 * @pvec: pagevec that stores block bitmap content
 * @read_bytes: counter of all read bytes
 */
struct ssdfs_blk_bmap_init_env {
	struct ssdfs_segment_header *seg_hdr;
	struct ssdfs_log_footer *footer;
	struct ssdfs_block_bitmap_header *bmap_hdr;
	struct ssdfs_block_bitmap_fragment *frag_hdr;
	u8 bmap_hdr_buf[SSDFS_BLKBMAP_HDR_CAPACITY];
	u16 log_index;
	u16 log_pages;
	int fragment_index;
	struct pagevec pvec;
	u32 read_bytes;
};

static
void ssdfs_prepare_blk_bmap_init_env(struct ssdfs_blk_bmap_init_env *env)
{
	env->seg_hdr = NULL;
	env->footer = NULL;
	memset(env->bmap_hdr_buf, 0, SSDFS_BLKBMAP_HDR_CAPACITY);
	env->bmap_hdr = (struct ssdfs_block_bitmap_header *)env->bmap_hdr_buf;
	env->frag_hdr =
		(struct ssdfs_block_bitmap_fragment *)(env->bmap_hdr_buf +
				    sizeof(struct ssdfs_block_bitmap_header));
	env->log_index = U16_MAX;
	env->log_pages = U16_MAX;
	env->fragment_index = -1;
	pagevec_init(&env->pvec);
	env->read_bytes = 0;
}

/*
 * struct ssdfs_blk2off_table_init_env - blk2off table init environment
 * @seg_hdr: segment header
 * @footer: log footer
 * @tbl_hdr: blk2off table header
 * @pvec: pagevec with blk2off table fragment
 * @read_off: current read offset
 * @write_off: current write offset
 */
struct ssdfs_blk2off_table_init_env {
	struct ssdfs_segment_header *seg_hdr;
	struct ssdfs_log_footer *footer;
	struct ssdfs_blk2off_table_header tbl_hdr;
	struct pagevec pvec;
	u32 read_off;
	u32 write_off;
};

static void
ssdfs_prepare_blk2off_table_init_env(struct ssdfs_blk2off_table_init_env *env)
{
	env->seg_hdr = NULL;
	env->footer = NULL;
	memset(&env->tbl_hdr, 0, sizeof(struct ssdfs_blk2off_table_header));
	pagevec_init(&env->pvec);
	env->read_off = 0;
	env->write_off = 0;
}

static
int ssdfs_read_blk2off_table_fragment(struct ssdfs_peb_info *pebi,
				      struct ssdfs_blk2off_table_init_env *init);

/******************************************************************************
 *                          READ THREAD FUNCTIONALITY                         *
 ******************************************************************************/

/*
 * ssdfs_peb_read_log_hdr_desc_array() - read log's header area's descriptors
 * @pebi: pointer on PEB object
 * @log_index: index of the log
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
				      u16 log_index,
				      struct ssdfs_metadata_descriptor *array,
				      size_t array_size)
{
	struct ssdfs_fs_info *fsi;
	struct page *page;
	void *kaddr;
	struct ssdfs_segment_header *seg_hdr = NULL;
	size_t hdr_size = sizeof(struct ssdfs_segment_header);
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

	SSDFS_DBG("seg %llu, peb %llu, log_index %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  log_index);

	fsi = pebi->pebc->parent_si->fsi;
	page_off = log_index * pebi->log_pages;

	page = ssdfs_page_array_grab_page(&pebi->cache, page_off);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		SSDFS_ERR("fail to grab page: index %u\n",
			  page_off);
		return -ENOMEM;
	}

	kaddr = kmap(page);

	if (PageUptodate(page) || PageDirty(page))
		goto copy_desc_array;

	err = ssdfs_read_checked_segment_header(fsi, pebi->peb_id,
						page_off, kaddr,
						false);
	if (unlikely(err))
		goto fail_copy_desc_array;

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
	seg_hdr = SSDFS_SEG_HDR(kaddr);
	memcpy(array, seg_hdr->desc_array, array_size * desc_size);

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
 * ssdfs_peb_get_block_state_desc() - get block state descriptor
 * @pebi: pointer on PEB object
 * @req: request
 * @area_desc: area descriptor
 * @state_off: block state offset descriptor
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
				   struct ssdfs_blk_state_offset *state_off,
				   struct ssdfs_block_state_descriptor *desc)
{
	struct ssdfs_fs_info *fsi;
	size_t state_desc_size = sizeof(struct ssdfs_block_state_descriptor);
	u32 area_offset;
	u32 frag_offset;
	u32 page_off;
	struct page *page;
	struct ssdfs_block_state_descriptor *cur_item;
	void *kaddr;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !area_desc || !state_off || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area_offset = le32_to_cpu(area_desc->offset);
	frag_offset = le32_to_cpu(state_off->byte_offset);
	page_off = area_offset + frag_offset;
	page_off >>= PAGE_SHIFT;

	SSDFS_DBG("seg %llu, peb %llu, "
		  "area_offset %u, frag_offset %u, page_index %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_offset, frag_offset, page_off);

	page = ssdfs_peb_read_page_locked(pebi, page_off);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to read locked page: index %u\n",
			  page_off);
		return -ERANGE;
	}

	kaddr = kmap_atomic(page);

	cur_item = (struct ssdfs_block_state_descriptor *)((u8 *)kaddr +
			((area_offset + frag_offset) % PAGE_SIZE));
	memcpy(desc, cur_item, state_desc_size);

	kunmap_atomic(kaddr);
	unlock_page(page);
	put_page(page);

	if (req->extent.cno != le64_to_cpu(cur_item->cno)) {
		SSDFS_ERR("req->extent.cno %llu != cur_item->cno %llu\n",
			  req->extent.cno, le64_to_cpu(cur_item->cno));
		return -EIO;
	}

	if (req->extent.parent_snapshot !=
	    le64_to_cpu(cur_item->parent_snapshot)) {
		SSDFS_ERR("req->extent.parent_snapshot %llu != "
			  "cur_item->parent_snapshot %llu\n",
			  req->extent.parent_snapshot,
			  le64_to_cpu(cur_item->parent_snapshot));
		return -EIO;
	}

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
					     blk_state_off, &found_blk_state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get block state descriptor: "
			  "area_offset %u, fragment_offset %u, err %d\n",
			  le32_to_cpu(array[area_index].offset),
			  le32_to_cpu(blk_state_off->byte_offset),
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
static
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
 * @req: request
 *
 * This function tries to read PEB's page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_peb_read_page(struct ssdfs_peb_container *pebc,
			struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *table;
	struct ssdfs_phys_offset_descriptor *desc_off = NULL;
	struct ssdfs_blk_state_offset *blk_state = NULL;
	struct ssdfs_peb_info *pebi = NULL;
	u16 logical_blk;
	u16 log_index;
	struct ssdfs_metadata_descriptor desc_array[SSDFS_SEG_HDR_DESC_MAX];
	struct ssdfs_block_descriptor blk_desc = {0};
	int area_index;
	u8 peb_migration_id;
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

	desc_off = ssdfs_blk2off_table_convert(table, logical_blk);
	if (IS_ERR(desc_off) && PTR_ERR(desc_off) == -EAGAIN) {
		struct completion *end;

		end = &table->full_init_end;
		err = wait_for_completion_killable(end);
		if (unlikely(err)) {
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		desc_off = ssdfs_blk2off_table_convert(table, logical_blk);
	}

	if (IS_ERR_OR_NULL(desc_off)) {
		err = (desc_off == NULL ? -ERANGE : PTR_ERR(desc_off));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

	peb_migration_id = desc_off->blk_state.peb_migration_id;

	down_read(&pebc->lock);

	if (pebc->src_peb &&
	    peb_migration_id == ssdfs_get_peb_migration_id(pebc->src_peb)) {
		/* use source PEB */
		pebi = pebc->src_peb;
	} else if (pebc->dst_peb &&
	    peb_migration_id == ssdfs_get_peb_migration_id(pebc->dst_peb)) {
		/* use destination PEB */
		pebi = pebc->dst_peb;
	}

	if (!pebi) {
		err = -ERANGE;
		SSDFS_ERR("invalid peb_migration_id: "
			  "src_peb %p, dst_peb %p, peb_migration_id %u\n",
			  pebc->src_peb, pebc->dst_peb,
			  peb_migration_id);
		goto finish_read_page;
	}

	blk_state = &desc_off->blk_state;
	log_index = le16_to_cpu(blk_state->log_start_page) / pebi->log_pages;

	if (log_index >= (fsi->pages_per_peb / pebi->log_pages)) {
		err = -ERANGE;
		SSDFS_ERR("invalid log index %u\n", log_index);
		goto finish_read_page;
	}

	err = ssdfs_peb_read_log_hdr_desc_array(pebi, log_index, desc_array,
						SSDFS_SEG_HDR_DESC_MAX);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read log's header desc array: "
			  "seg %llu, peb %llu, log_index %u, err %d\n",
			  pebc->parent_si->seg_id, pebi->peb_id,
			  log_index, err);
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

/* TODO: too many big structures on the stack!!! Check it. */

	return err;
}

/*
 * ssdfs_peb_readahead_pages() - read-ahead pages from PEB
 * @pebc: pointer on PEB container
 * @req: request
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
			      struct ssdfs_segment_request *req)
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

	for (i = 0; i < pages_count; i++) {
		int err = ssdfs_peb_read_page(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to process page %d, err %d\n",
				  i, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_peb_get_log_pages_count() - determine count of pages in the log
 * @pebi: PEB object
 * @peb_id: PEB identification number
 * @hdr_buf: buffer for segment header
 *
 * This function reads segment header of the first log in
 * segment and to retrieve log_pages field.
 *
 * RETURN:
 * [success] - log pages count.
 * [failure] - U16_MAX.
 */
static
u16 ssdfs_peb_get_log_pages_count(struct ssdfs_fs_info *fsi,
				  u64 peb_id, void *hdr_buf)
{
	u16 log_pages;
	u32 pages_off = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !hdr_buf);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb %llu, hdr_buf %p\n", peb_id, hdr_buf);

	err = ssdfs_read_checked_segment_header(fsi, peb_id, pages_off,
						hdr_buf, false);
	if (err) {
		SSDFS_ERR("fail to read checked segment header: "
			  "peb %llu, pages_off %u, err %d\n",
			  peb_id, pages_off, err);
		return U16_MAX;
	}

	log_pages = le16_to_cpu(SSDFS_SEG_HDR(hdr_buf)->log_pages);

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
		return U16_MAX;
	}

	return log_pages;
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
					   struct ssdfs_blk_bmap_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	u32 pages_off;
	u32 bytes_off;
	struct ssdfs_metadata_descriptor *desc;
	size_t bmap_hdr_size = sizeof(struct ssdfs_block_bitmap_header);
	u32 pebsize;
	u32 read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env || !env->seg_hdr || !env->footer);
	BUG_ON(env->log_index >=
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON(env->log_pages >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON((env->log_index * env->log_pages) >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON(!env->bmap_hdr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, log_index %u, log_pages %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->log_index, env->log_pages);

	fsi = pebi->pebc->parent_si->fsi;
	pages_off = env->log_index * env->log_pages;
	pebsize = fsi->pages_per_peb * fsi->pagesize;

	err = ssdfs_read_checked_segment_header(fsi, pebi->peb_id,
						pages_off, env->seg_hdr,
						false);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read checked segment header: "
			  "seg %llu, peb %llu, pages_off %u\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  pages_off);
		return err;
	}

	if (!ssdfs_seg_hdr_has_blk_bmap(env->seg_hdr)) {
		if (!ssdfs_log_has_footer(env->seg_hdr)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"log hasn't footer\n");
			return -EIO;
		}

		desc = &env->seg_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];
		bytes_off = (pages_off * fsi->pagesize);
		bytes_off += le32_to_cpu(desc->offset);

		err = ssdfs_read_checked_log_footer(fsi, env->seg_hdr,
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

		if (!ssdfs_log_footer_has_blk_bmap(env->footer)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"log hasn't block bitmap\n");
			return -EIO;
		}

		desc = &env->footer->desc_array[SSDFS_BLK_BMAP_INDEX];
	} else
		desc = &env->seg_hdr->desc_array[SSDFS_BLK_BMAP_INDEX];

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

	bytes_off = le32_to_cpu(desc->offset);
	read_bytes = le16_to_cpu(desc->check.bytes);

	err = ssdfs_unaligned_read_buffer(fsi, pebi->peb_id,
					  bytes_off,
					  env->bmap_hdr,
					  read_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, size %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  bytes_off, read_bytes,
			  err);
		return err;
	}

	if (!is_csum_valid(&desc->check, env->bmap_hdr,
			    le16_to_cpu(desc->check.bytes))) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap header has invalid checksum\n");
		return -EIO;
	}

	env->read_bytes += read_bytes;

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
				    struct ssdfs_blk_bmap_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor *desc;
	size_t hdr_size = sizeof(struct ssdfs_block_bitmap_fragment);
	size_t desc_size = sizeof(struct ssdfs_fragment_desc);
	struct ssdfs_fragment_desc *frag_array = NULL;
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
	BUG_ON(!env || !env->seg_hdr || !env->footer);
	BUG_ON(!env->frag_hdr);
	BUG_ON(env->log_index >=
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON(env->log_pages >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON((env->log_index * env->log_pages) >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON(pagevec_count(&env->pvec) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, log_index %u, log_pages %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->log_index, env->log_pages);

	fsi = pebi->pebc->parent_si->fsi;

	if (!ssdfs_seg_hdr_has_blk_bmap(env->seg_hdr)) {
		if (!ssdfs_log_footer_has_blk_bmap(env->footer)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"log hasn't block bitmap\n");
			return -EIO;
		}

		desc = &env->footer->desc_array[SSDFS_BLK_BMAP_INDEX];
	} else
		desc = &env->seg_hdr->desc_array[SSDFS_BLK_BMAP_INDEX];

	area_offset = le32_to_cpu(desc->offset);

	err = ssdfs_unaligned_read_buffer(fsi, pebi->peb_id,
					  area_offset + env->read_bytes,
					  env->frag_hdr,
					  SSDFS_BLKBMAP_FRAG_HDR_CAPACITY);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, size %zu, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  area_offset + env->read_bytes,
			  SSDFS_BLKBMAP_FRAG_HDR_CAPACITY,
			  err);
		return err;
	}

	cdata_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!cdata_buf) {
		SSDFS_ERR("fail to allocate cdata_buf\n");
		return -ENOMEM;
	}

	frag_array = (struct ssdfs_fragment_desc *)((u8 *)env->frag_hdr +
							hdr_size);

	if (le16_to_cpu(env->frag_hdr->last_free_blk) >= fsi->pages_per_peb) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"last_free_blk %u is invalid\n",
				le16_to_cpu(env->frag_hdr->last_free_blk));
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (le16_to_cpu(env->frag_hdr->metadata_blks) > fsi->pages_per_peb) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"metadata_blks %u is invalid\n",
				le16_to_cpu(env->frag_hdr->metadata_blks));
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (le16_to_cpu(env->frag_hdr->invalid_blks) >
	    le16_to_cpu(env->frag_hdr->last_free_blk)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"invalid_blks %u is invalid\n",
				le16_to_cpu(env->frag_hdr->invalid_blks));
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (desc_size != le16_to_cpu(env->frag_hdr->chain_hdr.desc_size)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"desc_size %u is invalid\n",
			    le16_to_cpu(env->frag_hdr->chain_hdr.desc_size));
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (env->frag_hdr->chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"chain header magic %#x is invalid\n",
				env->frag_hdr->chain_hdr.magic);
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (env->frag_hdr->chain_hdr.type != SSDFS_BLK_BMAP_CHAIN_HDR) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"chain header type %#x is invalid\n",
				env->frag_hdr->chain_hdr.type);
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	if (le16_to_cpu(env->frag_hdr->chain_hdr.flags) &
	    ~SSDFS_CHAIN_HDR_FLAG_MASK) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"unknown chain header flags %#x\n",
			    le16_to_cpu(env->frag_hdr->chain_hdr.flags));
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	fragments_count = le16_to_cpu(env->frag_hdr->chain_hdr.fragments_count);
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

	env->read_bytes += hdr_size + (fragments_count * desc_size);

	chain_compr_bytes =
		le32_to_cpu(env->frag_hdr->chain_hdr.compr_bytes);
	chain_uncompr_bytes =
		le32_to_cpu(env->frag_hdr->chain_hdr.uncompr_bytes);
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

		page = ssdfs_add_pagevec_page(&env->pvec);
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
		env->read_bytes += le16_to_cpu(frag_desc->compr_size);
	}

	SSDFS_DBG("last_free_blk %u, metadata_blks %u, invalid_blks %u\n",
		  le16_to_cpu(env->frag_hdr->last_free_blk),
		  le16_to_cpu(env->frag_hdr->metadata_blks),
		  le16_to_cpu(env->frag_hdr->invalid_blks));

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
				     struct ssdfs_blk_bmap_init_env *env)
{
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	u64 cno;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!env || !env->seg_hdr || !env->footer);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "log_index %u, log_pages %u, "
		  "fragment_index %d, read_bytes %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  env->log_index, env->log_pages,
		  env->fragment_index, env->read_bytes);

	pagevec_init(&env->pvec);

	err = ssdfs_read_checked_block_bitmap(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block bitmap: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		goto fail_init_blk_bmap_fragment;
	}

	seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;
	cno = le64_to_cpu(env->seg_hdr->cno);

	err = ssdfs_segment_blk_bmap_partial_init(seg_blkbmap,
						  pebi->peb_index,
						  &env->pvec,
						  env->frag_hdr,
						  cno);
	if (unlikely(err)) {
		SSDFS_ERR("fail to initialize block bitmap: "
			  "seg %llu, peb %llu, cno %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, cno, err);
		goto fail_init_blk_bmap_fragment;
	}

fail_init_blk_bmap_fragment:
	pagevec_release(&env->pvec);

	return err;
}

/*
 * ssdfs_peb_init_using_metadata_state() - initialize "using" PEB
 * @pebi: pointer on PEB object
 * @seg_hdr: pointer on segment buffer
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
					struct ssdfs_segment_header *seg_hdr,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_blk_bmap_init_env b_init;
	struct ssdfs_blk2off_table_init_env t_init;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	size_t footer_buf_size;
	u16 logs_per_peb;
	u16 fragments_count;
	u32 bytes_count;
	u16 new_log_start_page;
	u64 cno;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !seg_hdr || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);

	si = pebi->pebc->parent_si;
	fsi = si->fsi;
	ssdfs_prepare_blk_bmap_init_env(&b_init);

	/*
	 * Allow creating thread to continue creation logic.
	 */
	complete(&req->result.wait);

	b_init.seg_hdr = seg_hdr;

	footer_buf_size = max_t(size_t, hdr_buf_size,
					sizeof(struct ssdfs_log_footer));
	b_init.footer = kzalloc(footer_buf_size, GFP_NOFS);
	if (!b_init.footer) {
		SSDFS_ERR("fail to allocate log footer buffer\n");
		err = -ENOMEM;
		goto fail_init_using_blk_bmap;
	}

	b_init.log_pages = ssdfs_peb_get_log_pages_count(fsi, pebi->peb_id,
							 b_init.seg_hdr);
	if (b_init.log_pages == U16_MAX) {
		SSDFS_ERR("fail to define log_pages: "
			  "seg %llu, peb %llu\n",
			  si->seg_id, pebi->peb_id);
		err = -EIO;
		goto fail_init_using_blk_bmap;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->pages_per_peb % b_init.log_pages) {
		SSDFS_WARN("fsi->pages_per_peb %u, log_pages %u\n",
			   fsi->pages_per_peb, b_init.log_pages);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->log_pages = b_init.log_pages;
	logs_per_peb = fsi->pages_per_peb / b_init.log_pages;

	/*
	 * use footer_buf as temporary storage of
	 * previous state of header_buf
	 */
	memcpy(b_init.footer, b_init.seg_hdr, hdr_buf_size);

	for (b_init.log_index = 1; b_init.log_index < logs_per_peb;
							b_init.log_index++) {
		err = ssdfs_read_checked_segment_header(fsi, pebi->peb_id,
					b_init.log_index * b_init.log_pages,
					b_init.seg_hdr, true);
		if (err) {
			new_log_start_page =
				b_init.log_index * b_init.log_pages;
			b_init.log_index--;
			/* copy previous state of header_buf */
			memcpy(b_init.seg_hdr, b_init.footer, hdr_buf_size);
			break;
		} else {
			/*
			 * use footer_buf as temporary storage of
			 * previous state of header_buf
			 */
			memcpy(b_init.footer, b_init.seg_hdr, hdr_buf_size);
		}
	}

	if (!err) {
		WARN_ON(b_init.log_index > logs_per_peb);
		new_log_start_page = b_init.log_index * b_init.log_pages;
		b_init.log_index = logs_per_peb - 1;
	} else if (b_init.log_index >= logs_per_peb) {
		SSDFS_ERR("log_index %u >= logs_per_peb %u\n",
			  b_init.log_index, logs_per_peb);
		err = -ERANGE;
		goto fail_init_using_blk_bmap;
	}

	err = ssdfs_read_checked_block_bitmap_header(pebi, &b_init);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block bitmap header: "
			  "seg %llu, peb %llu, log_index %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  b_init.log_index, err);
		goto fail_init_using_blk_bmap;
	}

	fragments_count = le16_to_cpu(b_init.bmap_hdr->fragments_count);
	bytes_count = le32_to_cpu(b_init.bmap_hdr->bytes_count);

	for (i = 0; i < fragments_count; i++) {
		b_init.fragment_index = i;
		err = ssdfs_init_block_bitmap_fragment(pebi, &b_init);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init block bitmap: "
				  "peb_id %llu, peb_index %u, "
				  "log_index %u, fragment_index %u, "
				  "read_bytes %u, err %d\n",
				  pebi->peb_id, pebi->peb_index,
				  b_init.log_index, i,
				  b_init.read_bytes, err);
			goto fail_init_using_blk_bmap;
		}
	}

	if (bytes_count != b_init.read_bytes) {
		SSDFS_WARN("bytes_count %u != read_bytes %u\n",
			   bytes_count, b_init.read_bytes);
		err = -EIO;
		goto fail_init_using_blk_bmap;
	}

	/*
	 * TODO: Temporary we use full log model only.
	 *       It needs to rework this code with the goal of partial
	 *       logs support.
	 */
	BUG_ON(new_log_start_page == U16_MAX);

	if (new_log_start_page < fsi->pages_per_peb) {
		ssdfs_peb_current_log_init(pebi,
					   pebi->log_pages,
					   new_log_start_page);
	} else {
		ssdfs_peb_current_log_init(pebi,
					   0,
					   new_log_start_page);
	}

fail_init_using_blk_bmap:
	if (unlikely(err))
		goto fail_init_using_peb;

	ssdfs_prepare_blk2off_table_init_env(&t_init);
	t_init.seg_hdr = b_init.seg_hdr;
	t_init.footer = b_init.footer;

	err = ssdfs_read_blk2off_table_fragment(pebi, &t_init);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read translation table fragments: "
			  "seg %llu, peb %llu, err %d\n",
			  si->seg_id, pebi->peb_id, err);
		goto fail_init_blk2off_table;
	}

	cno = le64_to_cpu(t_init.seg_hdr->cno);
	err = ssdfs_blk2off_table_partial_init(si->blk2off_table,
						&t_init.pvec,
						pebi->peb_index,
						cno);
	if (unlikely(err)) {
		SSDFS_ERR("fail to start initialization of offset table: "
			  "seg %llu, peb %llu, err %d\n",
			  si->seg_id, pebi->peb_id, err);
		goto fail_init_blk2off_table;
	}

fail_init_blk2off_table:
	pagevec_release(&b_init.pvec);
	pagevec_release(&t_init.pvec);

fail_init_using_peb:
	kfree(b_init.footer);
	return err;
}

/*
 * ssdfs_peb_init_used_metadata_state() - initialize "used" PEB
 * @pebi: pointer on PEB object
 * @seg_hdr: pointer on segment buffer
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
					struct ssdfs_segment_header *seg_hdr,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_blk_bmap_init_env b_init;
	struct ssdfs_blk2off_table_init_env t_init;
	u16 logs_per_peb;
	u16 fragments_count;
	u32 bytes_count;
	u64 cno;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !seg_hdr || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);

	si = pebi->pebc->parent_si;
	fsi = si->fsi;
	ssdfs_prepare_blk_bmap_init_env(&b_init);

	/*
	 * Allow creating thread to continue creation logic.
	 */
	complete(&req->result.wait);

	b_init.seg_hdr = seg_hdr;

	b_init.footer = kzalloc(sizeof(struct ssdfs_log_footer), GFP_NOFS);
	if (!b_init.footer) {
		SSDFS_ERR("fail to allocate log footer buffer\n");
		err = -ENOMEM;
		goto fail_init_used_blk_bmap;
	}

	b_init.log_pages = ssdfs_peb_get_log_pages_count(fsi, pebi->peb_id,
							 b_init.seg_hdr);
	if (b_init.log_pages == U16_MAX) {
		SSDFS_ERR("fail to define log_pages: "
			  "seg %llu, peb %llu\n",
			  si->seg_id, pebi->peb_id);
		err = -EIO;
		goto fail_init_used_blk_bmap;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->pages_per_peb % b_init.log_pages) {
		SSDFS_WARN("fsi->pages_per_peb %u, log_pages %u\n",
			   fsi->pages_per_peb, b_init.log_pages);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->log_pages = b_init.log_pages;
	logs_per_peb = fsi->pages_per_peb / b_init.log_pages;
	b_init.log_index = logs_per_peb - 1;

	err = ssdfs_read_checked_block_bitmap_header(pebi, &b_init);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block bitmap header: "
			  "seg %llu, peb %llu, log_index %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  b_init.log_index, err);
		goto fail_init_used_blk_bmap;
	}

	fragments_count = le16_to_cpu(b_init.bmap_hdr->fragments_count);
	bytes_count = le32_to_cpu(b_init.bmap_hdr->bytes_count);

	for (i = 0; i < fragments_count; i++) {
		b_init.fragment_index = i;
		err = ssdfs_init_block_bitmap_fragment(pebi, &b_init);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init block bitmap: "
				  "peb_id %llu, peb_index %u, "
				  "log_index %u, fragment_index %u, "
				  "read_bytes %u, err %d\n",
				  pebi->peb_id, pebi->peb_index,
				  b_init.log_index,
				  i, b_init.read_bytes, err);
			goto fail_init_used_blk_bmap;
		}
	}

	if (bytes_count != b_init.read_bytes) {
		SSDFS_WARN("bytes_count %u != read_bytes %u\n",
			   bytes_count, b_init.read_bytes);
		err = -EIO;
		goto fail_init_used_blk_bmap;
	}

	ssdfs_peb_current_log_init(pebi, 0, fsi->pages_per_peb);

fail_init_used_blk_bmap:
	if (unlikely(err))
		goto fail_init_used_peb;

	ssdfs_prepare_blk2off_table_init_env(&t_init);
	t_init.seg_hdr = b_init.seg_hdr;
	t_init.footer = b_init.footer;

	err = ssdfs_read_blk2off_table_fragment(pebi, &t_init);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read translation table fragments: "
			  "seg %llu, peb %llu, err %d\n",
			  si->seg_id, pebi->peb_id, err);
		goto fail_init_blk2off_table;
	}

	cno = le64_to_cpu(t_init.seg_hdr->cno);
	err = ssdfs_blk2off_table_partial_init(si->blk2off_table,
						&t_init.pvec,
						pebi->peb_index,
						cno);
	if (unlikely(err)) {
		SSDFS_ERR("fail to start initialization of offset table: "
			  "seg %llu, peb %llu, err %d\n",
			  si->seg_id, pebi->peb_id, err);
		goto fail_init_blk2off_table;
	}

fail_init_blk2off_table:
	pagevec_release(&b_init.pvec);
	pagevec_release(&t_init.pvec);

fail_init_used_peb:
	kfree(b_init.footer);
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
	struct ssdfs_peb_info *pebi;
	struct ssdfs_segment_header *seg_hdr;
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

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

	seg_hdr = kzalloc(sizeof(struct ssdfs_segment_header), GFP_NOFS);
	if (!seg_hdr) {
		SSDFS_ERR("fail to allocate segment header buffer\n");
		return -ENOMEM;
	}

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (!pebi) {
		SSDFS_WARN("source PEB is NULL\n");
		err = -ERANGE;
		goto finish_src_init_using_metadata_state;
	}

	err = ssdfs_peb_init_using_metadata_state(pebi, seg_hdr, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init using metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_src_init_using_metadata_state;
	}

	id1 = seg_hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB];

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

finish_src_init_using_metadata_state:
	up_read(&pebc->lock);
	kfree(seg_hdr);
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
	struct ssdfs_peb_info *pebi;
	struct ssdfs_segment_header *seg_hdr;
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

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

	seg_hdr = kzalloc(sizeof(struct ssdfs_segment_header), GFP_NOFS);
	if (!seg_hdr) {
		SSDFS_ERR("fail to allocate segment header buffer\n");
		return -ENOMEM;
	}

	down_read(&pebc->lock);

	pebi = pebc->dst_peb;
	if (!pebi) {
		SSDFS_WARN("destination PEB is NULL\n");
		err = -ERANGE;
		goto finish_dst_init_using_metadata_state;
	}

	err = ssdfs_peb_init_using_metadata_state(pebi, seg_hdr, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init using metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_dst_init_using_metadata_state;
	}

	id1 = seg_hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB];

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

	switch (items_state) {
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		if (!pebc->src_peb) {
			SSDFS_WARN("source PEB is NULL\n");
			err = -ERANGE;
			goto finish_dst_init_using_metadata_state;
		}

		id1 = seg_hdr->peb_migration_id[SSDFS_PREV_MIGRATING_PEB];

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
	kfree(seg_hdr);
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
	struct ssdfs_peb_info *pebi;
	struct ssdfs_segment_header *seg_hdr;
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

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

	seg_hdr = kzalloc(sizeof(struct ssdfs_segment_header), GFP_NOFS);
	if (!seg_hdr) {
		SSDFS_ERR("fail to allocate segment header buffer\n");
		return -ENOMEM;
	}

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (!pebi) {
		SSDFS_WARN("source PEB is NULL\n");
		err = -ERANGE;
		goto finish_src_init_used_metadata_state;
	}

	err = ssdfs_peb_init_used_metadata_state(pebi, seg_hdr, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init used metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_src_init_used_metadata_state;
	}

	id1 = seg_hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB];

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
	kfree(seg_hdr);
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
	struct ssdfs_peb_info *pebi;
	struct ssdfs_segment_header *seg_hdr;
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);

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

	seg_hdr = kzalloc(sizeof(struct ssdfs_segment_header), GFP_NOFS);
	if (!seg_hdr) {
		SSDFS_ERR("fail to allocate segment header buffer\n");
		return -ENOMEM;
	}

	down_read(&pebc->lock);

	pebi = pebc->dst_peb;
	if (!pebi) {
		SSDFS_WARN("destination PEB is NULL\n");
		err = -ERANGE;
		goto finish_dst_init_used_metadata_state;
	}

	err = ssdfs_peb_init_used_metadata_state(pebi, seg_hdr, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init used metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_dst_init_used_metadata_state;
	}

	id1 = seg_hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB];

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

		id1 = seg_hdr->peb_migration_id[SSDFS_PREV_MIGRATING_PEB];

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

finish_dst_init_used_metadata_state:
	up_read(&pebc->lock);
	kfree(seg_hdr);
	return err;
}

/*
 * ssdfs_read_blk2off_table_header() - read blk2off table header
 * @pebi: pointer on PEB object
 * @init: init environment [in|out]
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
				    struct ssdfs_blk2off_table_init_env *init)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor *desc;
	struct ssdfs_blk2off_table_header *hdr = NULL;
	size_t hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	struct page *page;
	void *kaddr;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!init || !init->seg_hdr || !init->footer);
	BUG_ON(pagevec_count(&init->pvec) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  init->read_off, init->write_off);

	fsi = pebi->pebc->parent_si->fsi;

	if (!ssdfs_seg_hdr_has_offset_table(init->seg_hdr)) {
		if (!ssdfs_log_has_footer(init->seg_hdr)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"log hasn't footer\n");
			return -EIO;
		}

		if (!ssdfs_log_footer_has_offset_table(init->footer)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"log hasn't blk2off table\n");
			return -EIO;
		}

		desc = &init->footer->desc_array[SSDFS_OFF_TABLE_INDEX];
	} else
		desc = &init->seg_hdr->desc_array[SSDFS_OFF_TABLE_INDEX];

	init->read_off = le32_to_cpu(desc->offset);
	init->write_off = 0;

	err = ssdfs_unaligned_read_buffer(fsi, pebi->peb_id, init->read_off,
					  &init->tbl_hdr, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, size %zu, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  init->read_off, hdr_size, err);
		return err;
	}

	hdr = &init->tbl_hdr;

	if (le32_to_cpu(hdr->magic.common) != SSDFS_SUPER_MAGIC ||
	    le16_to_cpu(hdr->magic.key) != SSDFS_BLK2OFF_TABLE_HDR_MAGIC) {
		SSDFS_ERR("invalid magic of blk2off_table\n");
		return -EIO;
	}

	page = ssdfs_add_pagevec_page(&init->pvec);
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

	init->read_off += offsetof(struct ssdfs_blk2off_table_header,
					sequence);
	init->write_off += offsetof(struct ssdfs_blk2off_table_header,
					sequence);

	return 0;
}

/*
 * ssdfs_read_blk2off_byte_stream() - read blk2off's byte stream
 * @pebi: pointer on PEB object
 * @read_bytes: amount of bytes for reading
 * @init: init environment [in|out]
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
				   struct ssdfs_blk2off_table_init_env *init)
{
	struct ssdfs_fs_info *fsi;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!init);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, read_bytes %u, "
		  "read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  read_bytes, init->read_off, init->write_off);

	fsi = pebi->pebc->parent_si->fsi;

	while (read_bytes > 0) {
		struct page *page = NULL;
		void *kaddr;
		pgoff_t page_index = init->write_off >> PAGE_SHIFT;
		u32 capacity = pagevec_count(&init->pvec) << PAGE_SHIFT;
		u32 offset, bytes;

		if (init->write_off >= capacity) {
			page = ssdfs_add_pagevec_page(&init->pvec);
			if (unlikely(IS_ERR_OR_NULL(page))) {
				err = !page ? -ENOMEM : PTR_ERR(page);
				SSDFS_ERR("fail to add pagevec page: err %d\n",
					  err);
				return err;
			}
		} else {
			page = init->pvec.pages[page_index];
			if (unlikely(!page)) {
				err = -ERANGE;
				SSDFS_ERR("fail to get page: err %d\n",
					  err);
				return err;
			}
		}

		offset = init->write_off % PAGE_SIZE;
		bytes = min_t(u32, read_bytes, PAGE_SIZE - offset);

		lock_page(page);
		kaddr = kmap(page);
		err = ssdfs_unaligned_read_buffer(fsi, pebi->peb_id,
						  init->read_off,
						  (u8 *)kaddr + offset,
						  bytes);
		kunmap(page);
		unlock_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to read page: "
				  "seg %llu, peb %llu, offset %u, "
				  "size %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, init->read_off, bytes,
				  err);
			return err;
		}

		read_bytes -= bytes;
		init->read_off += bytes;
		init->write_off += bytes;
	};

	return 0;
}

/*
 * ssdfs_read_blk2off_table_extents() - read blk2off table's extents
 * @pebi: pointer on PEB object
 * @init: init environment [in|out]
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
				     struct ssdfs_blk2off_table_init_env *init)
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
	BUG_ON(!init);
#endif /* CONFIG_SSDFS_DEBUG */

	extents_off = le16_to_cpu(init->tbl_hdr.extents_off);
	extent_count = le16_to_cpu(init->tbl_hdr.extents_count);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "extents_off %u, extent_count %u, "
		  "read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  extents_off, extent_count,
		  init->read_off, init->write_off);

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

	err = ssdfs_read_blk2off_byte_stream(pebi, read_bytes, init);
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
 * @init: init environment [in|out]
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
				    struct ssdfs_blk2off_table_init_env *init)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_phys_offset_table_header hdr;
	size_t hdr_size = sizeof(struct ssdfs_phys_offset_table_header);
	u32 read_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!init);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, "
		  "read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  init->read_off, init->write_off);

	fsi = pebi->pebc->parent_si->fsi;

	err = ssdfs_unaligned_read_buffer(fsi, pebi->peb_id,
					  init->read_off, &hdr, hdr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, "
			  "size %zu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, init->read_off, hdr_size,
			  err);
		return err;
	}

	if (le32_to_cpu(hdr.magic) != SSDFS_PHYS_OFF_TABLE_MAGIC) {
		SSDFS_ERR("invalid magic\n");
		return -EIO;
	}

	read_bytes = le32_to_cpu(hdr.byte_size);

	err = ssdfs_read_blk2off_byte_stream(pebi, read_bytes, init);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read byte stream: err %d\n",
			  err);
		return err;
	}

	init->read_off = le16_to_cpu(hdr.next_fragment_off);

	return 0;
}

/*
 * ssdfs_read_blk2off_table_fragment() - read blk2off table's log's fragments
 * @pebi: pointer on PEB object
 * @init: init environment [in|out]
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
				      struct ssdfs_blk2off_table_init_env *init)
{
	struct ssdfs_fs_info *fsi;
	u16 fragment_count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!init || !init->seg_hdr || !init->footer);
	BUG_ON(pagevec_count(&init->pvec) != 0);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);

	fsi = pebi->pebc->parent_si->fsi;
	init->read_off = 0;
	init->write_off = 0;

	err = ssdfs_read_blk2off_table_header(pebi, init);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read translation table header: "
			  "seg %llu, peb %llu, "
			  "read_off %u, write_off %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  init->read_off, init->write_off, err);
		goto fail_read_blk2off_fragments;
	}

	err = ssdfs_read_blk2off_table_extents(pebi, init);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read translation table's extents: "
			  "seg %llu, peb %llu, "
			  "read_off %u, write_off %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  init->read_off, init->write_off, err);
		goto fail_read_blk2off_fragments;
	}

	fragment_count = le16_to_cpu(init->tbl_hdr.fragments_count);

	for (i = 0; i < fragment_count; i++) {
		err = ssdfs_read_blk2off_pot_fragment(pebi, init);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read physical offset table's "
				  "fragment: seg %llu, peb %llu, "
				  "fragment_index %d, "
				  "read_off %u, write_off %u, err %d\n",
				  pebi->pebc->parent_si->seg_id, pebi->peb_id,
				  i, init->read_off, init->write_off, err);
			goto fail_read_blk2off_fragments;
		}
	}

fail_read_blk2off_fragments:
	return err;
}

/*
 * ssdfs_peb_complete_init_blk2off_table() - init blk2off table's fragment
 * @pebi: pointer on PEB object
 * @start_log_index: start index for logs processing
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
					  int start_log_index,
					  struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *blk2off_table;
	struct ssdfs_blk2off_table_init_env init;
	size_t hdr_buf_size;
	size_t footer_buf_size;
	u16 log_pages;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg %llu, peb %llu, start_log_index %d, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  start_log_index,
		  req->private.class,
		  req->private.cmd,
		  req->private.type);

	if (start_log_index < 0) {
		SSDFS_DBG("nothing should be done: "
			  "seg %llu, peb %llu, start_log_index %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  start_log_index);
		return 0;
	}

	fsi = pebi->pebc->parent_si->fsi;
	blk2off_table = pebi->pebc->parent_si->blk2off_table;
	log_pages = pebi->log_pages;

	ssdfs_prepare_blk2off_table_init_env(&init);

	hdr_buf_size = sizeof(struct ssdfs_segment_header);
	init.seg_hdr = kzalloc(hdr_buf_size, GFP_NOFS);
	if (!init.seg_hdr) {
		SSDFS_ERR("fail to allocate segment header buffer\n");
		err = -ENOMEM;
		goto fail_init_blk2off_table;
	}

	footer_buf_size = max_t(size_t, hdr_buf_size,
					sizeof(struct ssdfs_log_footer));
	init.footer = kzalloc(footer_buf_size, GFP_NOFS);
	if (!init.footer) {
		SSDFS_ERR("fail to allocate log footer buffer\n");
		err = -ENOMEM;
		goto fail_init_blk2off_table;
	}

	if ((start_log_index * log_pages) >= fsi->pages_per_peb) {
		SSDFS_ERR("invalid log index: "
			  "start_log_index %d, log_pages %u, "
			  "pages_per_peb %u\n",
			  start_log_index, log_pages,
			  fsi->pages_per_peb);
		err = -ERANGE;
		goto fail_init_blk2off_table;
	}

	for (i = start_log_index; i >= 0; i--) {
		struct ssdfs_metadata_descriptor *desc;
		u32 pages_off = i * log_pages;
		u32 bytes_off;
		u64 cno;

		err = ssdfs_read_checked_segment_header(fsi, pebi->peb_id,
							pages_off,
							init.seg_hdr, false);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read checked segment header: "
				  "seg %llu, peb %llu, pages_off %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  pages_off);
			goto fail_init_blk2off_table;
		}

		if (!ssdfs_log_has_footer(init.seg_hdr)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"log hasn't footer\n");
			err = -EIO;
			goto fail_init_blk2off_table;
		}

		desc = &init.seg_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];
		bytes_off = le32_to_cpu(desc->offset);

		err = ssdfs_read_checked_log_footer(fsi, init.seg_hdr,
						    pebi->peb_id,
						    bytes_off, init.footer,
						    false);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read checked log footer: "
				  "seg %llu, peb %llu, bytes_off %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  bytes_off);
			goto fail_init_blk2off_table;
		}

		pagevec_init(&init.pvec);

		err = ssdfs_read_blk2off_table_fragment(pebi, &init);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read translation table fragments: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			goto fail_init_blk2off_fragment;
		}

		cno = le64_to_cpu(init.seg_hdr->cno);
		err = ssdfs_blk2off_table_partial_init(blk2off_table,
							&init.pvec,
							pebi->peb_index,
							cno);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init the offset table: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			goto fail_init_blk2off_fragment;
		}

fail_init_blk2off_fragment:
		pagevec_release(&init.pvec);

		if (unlikely(err))
			goto fail_init_blk2off_table;
	}

fail_init_blk2off_table:
	kfree(init.seg_hdr);
	kfree(init.footer);
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
	struct ssdfs_fs_info *fsi;
	u16 log_pages;
	int pages_per_peb;
	int cur_log_index = -1;
	int start_log_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_id %llu, peb_index %u\n",
		  pebi->peb_id, pebi->peb_index);

	fsi = pebi->pebc->parent_si->fsi;
	pages_per_peb = (int)fsi->pages_per_peb;
	log_pages = pebi->log_pages;

	switch (atomic_read(&pebi->current_log.state)) {
	case SSDFS_LOG_INITIALIZED:
	case SSDFS_LOG_CREATED:
	case SSDFS_LOG_COMMITTED:
		ssdfs_peb_current_log_lock(pebi);
		cur_log_index = pebi->current_log.start_page / log_pages;
		ssdfs_peb_current_log_unlock(pebi);

		/*
		 * The cur_log_index defines index ot the new empty log.
		 * The last log was processed during initialization of
		 * "using" or "used" PEB. So, it needs to process the
		 * log before the last one.
		 */
		start_log_index = cur_log_index - 2;
		break;

	default:
		start_log_index = pages_per_peb / log_pages;
		start_log_index--;
		break;
	}

	err = ssdfs_peb_complete_init_blk2off_table(pebi,
						    start_log_index,
						    req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to complete blk2off table init: "
			  "peb_id %llu, peb_index %u, "
			  "start_log_index %d, err %d\n",
			  pebi->peb_id,
			  pebi->peb_index,
			  start_log_index, err);
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
	struct ssdfs_fs_info *fsi;
	u16 log_pages;
	int pages_per_peb;
	int cur_log_index = -1;
	int start_log_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("peb_id %llu, peb_index %u\n",
		  pebi->peb_id, pebi->peb_index);

	fsi = pebi->pebc->parent_si->fsi;
	pages_per_peb = (int)fsi->pages_per_peb;
	log_pages = pebi->log_pages;

	switch (atomic_read(&pebi->current_log.state)) {
	case SSDFS_LOG_INITIALIZED:
	case SSDFS_LOG_CREATED:
	case SSDFS_LOG_COMMITTED:
		ssdfs_peb_current_log_lock(pebi);
		cur_log_index = pebi->current_log.start_page / log_pages;
		ssdfs_peb_current_log_unlock(pebi);

		/*
		 * The cur_log_index defines index ot the new empty log.
		 * So, it needs to process the log before the new
		 * empty one. The destination PEB was been/will be
		 * processed in a real pair.
		 */
		start_log_index = cur_log_index - 1;
		break;

	default:
		start_log_index = pages_per_peb / log_pages;
		start_log_index--;
		break;
	}

	err = ssdfs_peb_complete_init_blk2off_table(pebi,
						    start_log_index,
						    req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to complete blk2off table init: "
			  "peb_id %llu, peb_index %u, "
			  "start_log_index %d, err %d\n",
			  pebi->peb_id,
			  pebi->peb_index,
			  start_log_index, err);
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

	err = ssdfs_peb_read_page(pebc, req);
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

	err = ssdfs_peb_readahead_pages(pebc, req);
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

		err = ssdfs_peb_readahead_pages(pebc, req);
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
		err = ssdfs_peb_read_page(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read page: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
		}
		break;

	case SSDFS_READ_PAGES_READAHEAD:
		err = ssdfs_peb_readahead_pages(pebc, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read pages: "
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
			WARN_ON(!test_bit(PG_locked, &page->flags));
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
			WARN_ON(!test_bit(PG_locked, &page->flags));
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
