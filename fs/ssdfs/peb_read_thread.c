// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_read_thread.c - read thread functionality.
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
#include "peb_mapping_table.h"
#include "extents_queue.h"
#include "request_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "diff_on_write.h"
#include "shared_extents_tree.h"
#include "invalidated_extents_tree.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_read_page_leaks;
atomic64_t ssdfs_read_memory_leaks;
atomic64_t ssdfs_read_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_read_cache_leaks_increment(void *kaddr)
 * void ssdfs_read_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_read_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_read_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_read_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_read_kfree(void *kaddr)
 * struct page *ssdfs_read_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_read_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_read_free_page(struct page *page)
 * void ssdfs_read_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(read)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(read)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_read_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_read_page_leaks, 0);
	atomic64_set(&ssdfs_read_memory_leaks, 0);
	atomic64_set(&ssdfs_read_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_read_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_read_page_leaks) != 0) {
		SSDFS_ERR("READ THREAD: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_read_page_leaks));
	}

	if (atomic64_read(&ssdfs_read_memory_leaks) != 0) {
		SSDFS_ERR("READ THREAD: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_read_memory_leaks));
	}

	if (atomic64_read(&ssdfs_read_cache_leaks) != 0) {
		SSDFS_ERR("READ THREAD: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_read_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

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

static
void ssdfs_prepare_blk_bmap_init_env(struct ssdfs_blk_bmap_init_env *env,
				     u32 pages_per_peb)
{
	size_t bmap_bytes;
	size_t bmap_pages;

	memset(env->bmap_hdr_buf, 0, SSDFS_BLKBMAP_HDR_CAPACITY);
	env->bmap_hdr = (struct ssdfs_block_bitmap_header *)env->bmap_hdr_buf;
	env->frag_hdr =
		(struct ssdfs_block_bitmap_fragment *)(env->bmap_hdr_buf +
				    sizeof(struct ssdfs_block_bitmap_header));
	env->fragment_index = -1;

	bmap_bytes = BLK_BMAP_BYTES(pages_per_peb);
	bmap_pages = (bmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
	ssdfs_page_vector_create(&env->array, bmap_pages);

	env->read_bytes = 0;
}

static
void ssdfs_destroy_blk_bmap_init_env(struct ssdfs_blk_bmap_init_env *env)
{
	ssdfs_page_vector_release(&env->array);
	ssdfs_page_vector_destroy(&env->array);
}

static void
ssdfs_prepare_blk2off_table_init_env(struct ssdfs_blk2off_table_init_env *env,
				     u32 pages_per_peb)
{
	memset(&env->hdr, 0, sizeof(struct ssdfs_blk2off_table_header));

	ssdfs_page_vector_create(&env->extents.pvec, pages_per_peb);
	env->extents.write_off = 0;
	env->extents.bytes_count = 0;

	ssdfs_page_vector_create(&env->descriptors.pvec, pages_per_peb);
	env->descriptors.write_off = 0;
	env->descriptors.bytes_count = 0;

	env->area_offset = 0;
	env->read_off = 0;
}

static void
ssdfs_reinit_blk2off_table_init_env(struct ssdfs_blk2off_table_init_env *env)
{
	memset(&env->hdr, 0, sizeof(struct ssdfs_blk2off_table_header));

	ssdfs_page_vector_release(&env->extents.pvec);
	ssdfs_page_vector_reinit(&env->extents.pvec);
	env->extents.write_off = 0;
	env->extents.bytes_count = 0;

	ssdfs_page_vector_release(&env->descriptors.pvec);
	ssdfs_page_vector_reinit(&env->descriptors.pvec);
	env->descriptors.write_off = 0;
	env->descriptors.bytes_count = 0;

	env->area_offset = 0;
	env->read_off = 0;
}

static void
ssdfs_destroy_blk2off_table_init_env(struct ssdfs_blk2off_table_init_env *env)
{
	ssdfs_page_vector_release(&env->extents.pvec);
	ssdfs_page_vector_destroy(&env->extents.pvec);
	env->extents.write_off = 0;
	env->extents.bytes_count = 0;

	ssdfs_page_vector_release(&env->descriptors.pvec);
	ssdfs_page_vector_destroy(&env->descriptors.pvec);
	env->descriptors.write_off = 0;
	env->descriptors.bytes_count = 0;

	env->area_offset = 0;
	env->read_off = 0;
}

static void
ssdfs_prepare_blk_desc_table_init_env(struct ssdfs_blk_desc_table_init_env *env,
				      u32 pages_per_peb)
{
	memset(&env->hdr, 0, sizeof(struct ssdfs_area_block_table));
	ssdfs_page_vector_create(&env->array, pages_per_peb);
	env->area_offset = 0;
	env->read_off = 0;
	env->write_off = 0;
}

static void
ssdfs_reinit_blk_desc_table_init_env(struct ssdfs_blk_desc_table_init_env *env)
{
	memset(&env->hdr, 0, sizeof(struct ssdfs_area_block_table));

	ssdfs_page_vector_release(&env->array);
	ssdfs_page_vector_reinit(&env->array);

	env->area_offset = 0;
	env->read_off = 0;
	env->write_off = 0;
}

static void
ssdfs_destroy_blk_desc_table_init_env(struct ssdfs_blk_desc_table_init_env *env)
{
	ssdfs_page_vector_release(&env->array);
	ssdfs_page_vector_destroy(&env->array);
}

static
int ssdfs_prepare_read_init_env(struct ssdfs_read_init_env *env,
				u32 pages_per_peb)
{
	size_t hdr_size;
	size_t footer_buf_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("env %p\n", env);
#endif /* CONFIG_SSDFS_DEBUG */

	hdr_size = sizeof(struct ssdfs_segment_header);
	hdr_size = max_t(size_t, hdr_size, (size_t)SSDFS_4KB);

	env->log_hdr = ssdfs_read_kzalloc(hdr_size, GFP_KERNEL);
	if (!env->log_hdr) {
		SSDFS_ERR("fail to allocate log header buffer\n");
		return -ENOMEM;
	}

	env->has_seg_hdr = false;

	footer_buf_size = max_t(size_t, hdr_size,
				sizeof(struct ssdfs_log_footer));
	env->footer = ssdfs_read_kzalloc(footer_buf_size, GFP_KERNEL);
	if (!env->footer) {
		SSDFS_ERR("fail to allocate log footer buffer\n");
		return -ENOMEM;
	}

	env->has_footer = false;

	env->cur_migration_id = -1;
	env->prev_migration_id = -1;

	env->log_offset = 0;
	env->log_pages = U32_MAX;
	env->log_bytes = U32_MAX;

	ssdfs_prepare_blk_bmap_init_env(&env->b_init, pages_per_peb);
	ssdfs_prepare_blk2off_table_init_env(&env->t_init, pages_per_peb);
	ssdfs_prepare_blk_desc_table_init_env(&env->bdt_init, pages_per_peb);

	return 0;
}

static
void ssdfs_destroy_init_env(struct ssdfs_read_init_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("env %p\n", env);
#endif /* CONFIG_SSDFS_DEBUG */

	if (env->log_hdr)
		ssdfs_read_kfree(env->log_hdr);

	env->log_hdr = NULL;
	env->has_seg_hdr = false;

	if (env->footer)
		ssdfs_read_kfree(env->footer);

	env->footer = NULL;
	env->has_footer = false;

	ssdfs_destroy_blk_bmap_init_env(&env->b_init);
	ssdfs_destroy_blk2off_table_init_env(&env->t_init);
	ssdfs_destroy_blk_desc_table_init_env(&env->bdt_init);
}

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

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_id %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->pebc->peb_index,
		  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&pebi->current_log.state)) {
	case SSDFS_LOG_INITIALIZED:
	case SSDFS_LOG_CREATED:
	case SSDFS_LOG_COMMITTED:
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

	if (!err && is_ssdfs_page_array_empty(&pebi->cache)) {
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cache is empty: "
			  "seg_id %llu, peb_index %u, peb_id %llu\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&pebc->lock);

	pebi = pebc->src_peb;
	if (pebi) {
		err1 = __ssdfs_peb_release_pages(pebi);
		if (err1 == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache is empty: "
				  "seg_id %llu, peb_index %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (unlikely(err1)) {
			SSDFS_ERR("fail to release source PEB pages: "
				  "seg_id %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err1);
		}
	}

	pebi = pebc->dst_peb;
	if (pebi) {
		err2 = __ssdfs_peb_release_pages(pebi);
		if (err2 == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache is empty: "
				  "seg_id %llu, peb_index %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (unlikely(err2)) {
			SSDFS_ERR("fail to release dest PEB pages: "
				  "seg_id %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err2);
		}
	}

	up_write(&pebc->lock);

	if (err1 || err2) {
		if (err1 == -ENODATA && err2 == -ENODATA)
			return -ENODATA;
		else if (!err1) {
			if (err2 != -ENODATA)
				return err2;
			else
				return 0;
		} else if (!err2) {
			if (err1 != -ENODATA)
				return err1;
			else
				return 0;
		} else
			return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_unaligned_read_cache() - unaligned read from PEB's cache
 * @pebi: pointer on PEB object
 * @req: request
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
				struct ssdfs_segment_request *req,
				u32 area_offset, u32 area_size,
				void *buf)
{
	struct ssdfs_fs_info *fsi;
	struct page *page;
	u32 page_off;
	u32 bytes_off;
	size_t read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si || !buf);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "area_offset %u, area_size %u, buf %p\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_offset, area_size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

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
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to get page: index %u\n",
				   page_off);
#endif /* CONFIG_SSDFS_DEBUG */

			if (req->private.flags & SSDFS_REQ_READ_ONLY_CACHE)
				return -ENOENT;

			page = ssdfs_page_array_grab_page(&pebi->cache, page_off);
			if (unlikely(IS_ERR_OR_NULL(page))) {
				SSDFS_ERR("fail to grab page: index %u\n",
					  page_off);
				return -ENOMEM;
			}

			err = ssdfs_read_page_from_volume(fsi, pebi->peb_id,
							  page_off << PAGE_SHIFT,
							  page);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read locked page: "
					  "seg %llu, peb %llu, "
					  "page_off %u, err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  page_off, err);
				ssdfs_unlock_page(page);
				ssdfs_put_page(page);
			}

			/*
			 * ->readpage() unlock the page
			 */
			ssdfs_lock_page(page);

			SetPageUptodate(page);
			flush_dcache_page(page);
		}

		err = ssdfs_memcpy_from_page(buf, read_bytes, area_size,
					     page, offset, PAGE_SIZE,
					     iter_read_bytes);

		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "read_bytes %zu, offset %zu, "
				  "iter_read_bytes %zu, err %d\n",
				  read_bytes, offset,
				  iter_read_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		read_bytes += iter_read_bytes;
	} while (read_bytes < area_size);

	return 0;
}

/*
 * ssdfs_peb_read_log_hdr_desc_array() - read log's header area's descriptors
 * @pebi: pointer on PEB object
 * @req: request
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
 * %-ENOENT     - cache hasn't the requested page.
 */
int ssdfs_peb_read_log_hdr_desc_array(struct ssdfs_peb_info *pebi,
				      struct ssdfs_segment_request *req,
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
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	size_t array_bytes = array_size * desc_size;
	u32 page_off;
	size_t read_bytes;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!array);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);

	SSDFS_DBG("seg %llu, peb %llu, log_start_page %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  log_start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	page_off = log_start_page;

	page = ssdfs_page_array_get_page_locked(&pebi->cache, page_off);
	if (unlikely(IS_ERR_OR_NULL(page))) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to get page: index %u\n",
			   page_off);
#endif /* CONFIG_SSDFS_DEBUG */

		if (req->private.flags & SSDFS_REQ_READ_ONLY_CACHE)
			return -ENOENT;

		page = ssdfs_page_array_grab_page(&pebi->cache, page_off);
		if (unlikely(IS_ERR_OR_NULL(page))) {
			SSDFS_ERR("fail to grab page: index %u\n",
				  page_off);
			return -ENOMEM;
		}

		kaddr = kmap_local_page(page);

		err = ssdfs_aligned_read_buffer(fsi, pebi->peb_id,
						(page_off * PAGE_SIZE),
						(u8 *)kaddr,
						PAGE_SIZE,
						&read_bytes);
		if (unlikely(err))
			goto fail_copy_desc_array;
		else if (unlikely(read_bytes != (PAGE_SIZE))) {
			err = -ERANGE;
			goto fail_copy_desc_array;
		}

		SetPageUptodate(page);
		flush_dcache_page(page);
	} else
		kaddr = kmap_local_page(page);

	magic = (struct ssdfs_signature *)kaddr;

	if (!is_ssdfs_magic_valid(magic)) {
		err = -ERANGE;
		SSDFS_ERR("valid magic is not detected\n");
		goto fail_copy_desc_array;
	}

	if (__is_ssdfs_segment_header_magic_valid(magic)) {
		seg_hdr = SSDFS_SEG_HDR(kaddr);
		ssdfs_memcpy(array, 0, array_bytes,
			     seg_hdr->desc_array, 0, array_bytes,
			     array_bytes);
	} else if (is_ssdfs_partial_log_header_magic_valid(magic)) {
		plh_hdr = SSDFS_PLH(kaddr);
		ssdfs_memcpy(array, 0, array_bytes,
			     plh_hdr->desc_array, 0, array_bytes,
			     array_bytes);
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
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

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
 * @req: request
 * @page_off: page index
 *
 * This function tries to read locked page into PEB's cache.
 */
static
struct page *ssdfs_peb_read_page_locked(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					u32 page_off)
{
	struct ssdfs_fs_info *fsi;
	struct page *page;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);

	SSDFS_DBG("seg %llu, peb %llu, page_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  page_off);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	page = ssdfs_page_array_get_page_locked(&pebi->cache, page_off);
	if (unlikely(IS_ERR_OR_NULL(page))) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to get page: index %u\n",
			   page_off);
#endif /* CONFIG_SSDFS_DEBUG */

		if (req->private.flags & SSDFS_REQ_READ_ONLY_CACHE)
			return ERR_PTR(-ENOENT);

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

		/*
		 * ->readpage() unlock the page
		 * But caller expects that page is locked
		 */
		ssdfs_lock_page(page);

		if (unlikely(err))
			goto fail_read_page;

		SetPageUptodate(page);
	}

finish_page_read:
	return page;

fail_read_page:
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_ERR("fail to read locked page: "
		  "seg %llu, peb %llu, page_off %u, err %d\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  page_off, err);

	return NULL;
}

/*
 * __ssdfs_decompress_blk2off_fragment() - decompress blk2off fragment
 * @pebi: pointer on PEB object
 * @req: request
 * @frag: fragment descriptor
 * @area_offset: area offset in bytes
 * @read_buffer: buffer to read [out]
 * @buf_size: size of buffer in bytes
 *
 * This function tries to decompress offset translation table's fragment.
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
int __ssdfs_decompress_blk2off_fragment(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_fragment_desc *frag,
					u32 area_offset,
					void *read_buffer, size_t buf_size)
{
	void *cdata_buf = NULL;
	u32 frag_offset;
	u16 compr_size;
	u16 uncompr_size;
	int compr_type = SSDFS_COMPR_NONE;
	__le32 checksum = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!frag || !read_buffer);

	SSDFS_DBG("seg %llu, peb %llu, area_offset %u, buf_size %zu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, area_offset, buf_size);
#endif /* CONFIG_SSDFS_DEBUG */

	frag_offset = le32_to_cpu(frag->offset);
	compr_size = le16_to_cpu(frag->compr_size);
	uncompr_size = le16_to_cpu(frag->uncompr_size);

	if (buf_size < uncompr_size) {
		SSDFS_ERR("invalid request: buf_size %zu < uncompr_size %u\n",
			  buf_size, uncompr_size);
		return -E2BIG;
	}

	cdata_buf = ssdfs_read_kzalloc(compr_size, GFP_KERNEL);
	if (!cdata_buf) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate cdata_buf\n");
		goto free_buf;
	}

	err = ssdfs_unaligned_read_cache(pebi, req,
					 area_offset + frag_offset,
					 compr_size,
					 cdata_buf);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read blk desc fragment: "
			  "area_offset %u, frag_offset %u, compr_size %u, "
			  "err %d\n",
			  area_offset, frag_offset, compr_size, err);
		goto free_buf;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("COMPRESSED FRAGMENT DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     cdata_buf, compr_size);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	switch (frag->type) {
	case SSDFS_DATA_BLK_DESC_ZLIB:
	case SSDFS_BLK2OFF_EXTENT_DESC_ZLIB:
	case SSDFS_BLK2OFF_DESC_ZLIB:
		compr_type = SSDFS_COMPR_ZLIB;
		break;

	case SSDFS_DATA_BLK_DESC_LZO:
	case SSDFS_BLK2OFF_EXTENT_DESC_LZO:
	case SSDFS_BLK2OFF_DESC_LZO:
		compr_type = SSDFS_COMPR_LZO;
		break;

	default:
		BUG();
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("compr_type %#x, cdata_buf %px, read_buffer %px, "
		  "buf_size %zu, compr_size %u, uncompr_size %u\n",
		  compr_type, cdata_buf, read_buffer,
		  buf_size, compr_size, uncompr_size);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_decompress(compr_type,
				cdata_buf, read_buffer,
				compr_size, uncompr_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to decompress fragment: "
			  "seg %llu, peb %llu, "
			  "compr_size %u, uncompr_size %u, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  compr_size, uncompr_size,
			  err);
		goto free_buf;
	}

	if (frag->flags & SSDFS_FRAGMENT_HAS_CSUM) {
		checksum = ssdfs_crc32_le(read_buffer, uncompr_size);
		if (checksum != frag->checksum) {
			err = -EIO;
			SSDFS_ERR("invalid checksum: "
				  "(calculated %#x, csum %#x)\n",
				  le32_to_cpu(checksum),
				  le32_to_cpu(frag->checksum));
			goto free_buf;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("FRAGMENT DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     read_buffer, buf_size);
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

free_buf:
	if (cdata_buf)
		ssdfs_read_kfree(cdata_buf);

	return err;
}

/*
 * ssdfs_decompress_blk_desc_fragment() - decompress blk desc fragment
 * @pebi: pointer on PEB object
 * @req: request
 * @frag: fragment descriptor
 * @area_offset: area offset in bytes
 *
 * This function tries to decompress block descriptor fragment.
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
int ssdfs_decompress_blk_desc_fragment(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_fragment_desc *frag,
					u32 area_offset)
{
	struct ssdfs_peb_read_buffer *buf;
	u16 uncompr_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!frag);
	BUG_ON(!rwsem_is_locked(&pebi->read_buffer.lock));

	SSDFS_DBG("seg %llu, peb %llu, area_offset %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  area_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	buf = &pebi->read_buffer.blk_desc;
	uncompr_size = le16_to_cpu(frag->uncompr_size);

	if (buf->buf_size < uncompr_size) {
		err = ssdfs_peb_realloc_read_buffer(buf, uncompr_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to realloc read buffer: "
				  "old_size %zu, new_size %u, err %d\n",
				  buf->buf_size, uncompr_size, err);
			return err;
		}
	}

	err = __ssdfs_decompress_blk2off_fragment(pebi, req, frag, area_offset,
						  buf->ptr, buf->buf_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to decompress blk desc fragment: "
			  "err %d\n", err);
		return err;
	}

	buf->fragment_size = uncompr_size;

	return 0;
}

/*
 * ssdfs_peb_decompress_blk_desc_fragment() - decompress blk desc fragment
 * @pebi: pointer on PEB object
 * @req: request
 * @meta_desc: area descriptor
 * @offset: offset in bytes to read block descriptor
 * @fragment_offset: offset to fragment's beginning [out]
 *
 * This function tries to decompress block descriptor fragment.
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
int ssdfs_peb_decompress_blk_desc_fragment(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				struct ssdfs_metadata_descriptor *meta_desc,
				u32 offset,
				u32 *fragment_offset)
{
	struct ssdfs_area_block_table table;
	size_t tbl_size = sizeof(struct ssdfs_area_block_table);
	u32 portion_offset;
	u32 portion_size;
	u32 tbl_offset = 0;
	u32 compr_bytes = 0;
	u32 uncompr_bytes = 0;
	u16 flags;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!meta_desc || !fragment_offset);
	BUG_ON(!rwsem_is_locked(&pebi->read_buffer.lock));

	SSDFS_DBG("seg %llu, peb %llu, offset %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  offset);
#endif /* CONFIG_SSDFS_DEBUG */

	*fragment_offset = U32_MAX;

	portion_offset = le32_to_cpu(meta_desc->offset);
	portion_size = le32_to_cpu(meta_desc->size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("portion_offset %u, portion_size %u\n",
		  portion_offset, portion_size);
#endif /* CONFIG_SSDFS_DEBUG */

try_read_area_block_table:
	if ((tbl_offset + tbl_size) > portion_size) {
		SSDFS_ERR("area block table out of area: "
			  "tbl_offset %u, tbl_size %zu, portion_size %u\n",
			  tbl_offset, tbl_size, portion_size);
		return -ERANGE;
	}

	err = ssdfs_unaligned_read_cache(pebi, req,
					 portion_offset + tbl_offset,
					 tbl_size,
					 &table);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read area block table: "
			  "portion_offset %u, portion_size %u, "
			  "tbl_offset %u, tbl_size %zu, err %d\n",
			  portion_offset, portion_size,
			  tbl_offset, tbl_size, err);
		return err;
	}

	if (table.chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		SSDFS_ERR("corrupted area block table: "
			  "magic (expected %#x, found %#x)\n",
			  SSDFS_CHAIN_HDR_MAGIC,
			  table.chain_hdr.magic);
		return -EIO;
	}

	switch (table.chain_hdr.type) {
	case SSDFS_BLK_DESC_ZLIB_CHAIN_HDR:
	case SSDFS_BLK_DESC_LZO_CHAIN_HDR:
		/* expected type */
		break;

	default:
		SSDFS_ERR("unexpected area block table's type %#x\n",
			  table.chain_hdr.type);
		return -EIO;
	}

	compr_bytes = le32_to_cpu(table.chain_hdr.compr_bytes);
	uncompr_bytes = le32_to_cpu(table.chain_hdr.uncompr_bytes);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("compr_bytes %u, uncompr_bytes %u\n",
		  compr_bytes, uncompr_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	*fragment_offset = portion_offset + tbl_offset + tbl_size;

	if (offset < (*fragment_offset + uncompr_bytes)) {
		struct ssdfs_fragment_desc *frag;
		u16 fragments_count;
		u16 frag_uncompr_size;
		int i;

		fragments_count = le16_to_cpu(table.chain_hdr.fragments_count);

		for (i = 0; i < fragments_count; i++) {
			frag = &table.blk[i];

			if (frag->magic != SSDFS_FRAGMENT_DESC_MAGIC) {
				SSDFS_ERR("corrupted area block table: "
					  "magic (expected %#x, found %#x)\n",
					  SSDFS_FRAGMENT_DESC_MAGIC,
					  frag->magic);
				return -EIO;
			}

			switch (frag->type) {
			case SSDFS_DATA_BLK_DESC_ZLIB:
			case SSDFS_DATA_BLK_DESC_LZO:
				/* expected type */
				break;

			default:
				SSDFS_ERR("unexpected fragment's type %#x\n",
					  frag->type);
				return -EIO;
			}

			*fragment_offset = portion_offset + tbl_offset +
						le32_to_cpu(frag->offset);
			frag_uncompr_size = le16_to_cpu(frag->uncompr_size);

			if (offset < (*fragment_offset + frag_uncompr_size)) {
				err = ssdfs_decompress_blk_desc_fragment(pebi,
								req, frag,
								portion_offset);
				if (unlikely(err)) {
					SSDFS_ERR("fail to decompress: "
						  "err %d\n", err);
					return err;
				}

				break;
			}
		}

		if (i >= fragments_count) {
			SSDFS_ERR("corrupted area block table: "
				  "i %d >= fragments_count %u\n",
				  i, fragments_count);
			return -EIO;
		}
	} else {
		flags = le16_to_cpu(table.chain_hdr.flags);

		if (!(flags & SSDFS_MULTIPLE_HDR_CHAIN)) {
			SSDFS_ERR("corrupted area block table: "
				  "invalid flags set %#x\n",
				  flags);
			return -EIO;
		}

		tbl_offset += tbl_size + compr_bytes;
		goto try_read_area_block_table;
	}

	return 0;
}

static inline
bool is_read_buffer_offset_invalid(struct ssdfs_peb_temp_read_buffers *buf)
{
	return buf->blk_desc.offset >= U32_MAX;
}

static inline
bool read_buffer_has_no_requested_data(struct ssdfs_peb_temp_read_buffers *buf,
				       u32 offset)
{
	u32 lower_bound = buf->blk_desc.offset;
	u32 upper_bound = buf->blk_desc.offset + buf->blk_desc.fragment_size;

	return offset < lower_bound || upper_bound;
}

/*
 * ssdfs_peb_read_block_descriptor() - read block descriptor
 * @pebi: pointer on PEB object
 * @req: request
 * @meta_desc: area descriptor
 * @offset: offset in bytes to read block descriptor
 * @blk_desc: block descriptor [out]
 *
 * This function tries to read block descriptor.
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
int ssdfs_peb_read_block_descriptor(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req,
				    struct ssdfs_metadata_descriptor *meta_desc,
				    u32 offset,
				    struct ssdfs_block_descriptor *blk_desc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_temp_read_buffers *buf;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	int compr_type = SSDFS_COMPR_NONE;
	u32 fragment_offset;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!meta_desc || !blk_desc);

	SSDFS_DBG("seg %llu, peb %llu, offset %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  offset);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	flags = le16_to_cpu(meta_desc->check.flags);

	if ((flags & SSDFS_ZLIB_COMPRESSED) && (flags & SSDFS_LZO_COMPRESSED)) {
		SSDFS_ERR("invalid set of flags: "
			  "flags %#x\n",
			  flags);
		return -ERANGE;
	}

	if (flags & SSDFS_ZLIB_COMPRESSED)
		compr_type = SSDFS_COMPR_ZLIB;
	else if (flags & SSDFS_LZO_COMPRESSED)
		compr_type = SSDFS_COMPR_LZO;

	if (compr_type != SSDFS_COMPR_NONE) {
		buf = &pebi->read_buffer;

		down_write(&buf->lock);

		if (!buf->blk_desc.ptr) {
			err = -ENOMEM;
			SSDFS_ERR("buffer is not allocated\n");
			goto finish_decompress;
		}

		if (is_read_buffer_offset_invalid(buf)) {
			err = ssdfs_peb_decompress_blk_desc_fragment(pebi,
							    req,
							    meta_desc,
							    offset,
							    &fragment_offset);
			if (unlikely(err)) {
				SSDFS_ERR("fail to decompress: err %d\n",
					  err);
				goto finish_decompress;
			}

			if (fragment_offset >= U32_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid fragment offset\n");
				goto finish_decompress;
			}

			buf->blk_desc.offset = fragment_offset;
		} else if (read_buffer_has_no_requested_data(buf, offset)) {
			err = ssdfs_peb_decompress_blk_desc_fragment(pebi,
							    req,
							    meta_desc,
							    offset,
							    &fragment_offset);
			if (unlikely(err)) {
				SSDFS_ERR("fail to decompress: err %d\n",
					  err);
				goto finish_decompress;
			}

			if (fragment_offset >= U32_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid fragment offset\n");
				goto finish_decompress;
			}

			buf->blk_desc.offset = fragment_offset;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("Read block descsriptor from the buffer\n");
#endif /* CONFIG_SSDFS_DEBUG */
		}

finish_decompress:
		downgrade_write(&buf->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to decompress portion: "
				  "err %d\n", err);
			goto finish_read_compressed_blk_desc;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("offset %u, buf->blk_desc.offset %u, "
			  "buf->blk_desc.fragment_size %zu, "
			  "buf->blk_desc.buf_size %zu\n",
			  offset,
			  buf->blk_desc.offset,
			  buf->blk_desc.fragment_size,
			  buf->blk_desc.buf_size);

		BUG_ON(buf->blk_desc.offset > offset);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_memcpy(blk_desc,
				   0, blk_desc_size,
				   buf->blk_desc.ptr,
				   offset - buf->blk_desc.offset,
				   buf->blk_desc.fragment_size,
				   blk_desc_size);
		if (unlikely(err)) {
			SSDFS_ERR("invalid buffer state: "
				  "offset %u, buffer (offset %u, size %zu)\n",
				  offset,
				  buf->blk_desc.offset,
				  buf->blk_desc.fragment_size);
			goto finish_read_compressed_blk_desc;
		}

finish_read_compressed_blk_desc:
		up_read(&buf->lock);

		if (unlikely(err)) {
			SSDFS_ERR("fail to read compressed block descriptor: "
				  "offset %u, err %d\n",
				  offset, err);
			return err;
		}
	} else {
		err = ssdfs_unaligned_read_cache(pebi, req, offset,
						 blk_desc_size,
						 blk_desc);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to read block descriptor: "
				  "seg %llu, peb %llu, "
				  "offset %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  offset, err);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_peb_find_block_descriptor() - find block descriptor
 * @pebi: pointer on PEB object
 * @req: request
 * @array: array of area's descriptors
 * @array_size: count of items into array
 * @desc_off: descriptor of physical offset
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
				struct ssdfs_phys_offset_descriptor *desc_off,
				struct ssdfs_block_descriptor *blk_desc)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk_state_offset *blk_state;
	struct page *page;
	struct pagevec pvec;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	int area_index;
	u32 area_offset;
	u32 area_size;
	u32 blk_desc_off;
	u64 calculated;
	u32 page_off;
	u32 pages_count;
	u32 i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !array || !desc_off || !blk_desc);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "log_start_page %u, log_area %#x, "
		  "peb_migration_id %u, byte_offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  le16_to_cpu(desc_off->blk_state.log_start_page),
		  desc_off->blk_state.log_area,
		  desc_off->blk_state.peb_migration_id,
		  le32_to_cpu(desc_off->blk_state.byte_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	blk_state = &desc_off->blk_state;

	err = ssdfs_peb_read_log_hdr_desc_array(pebi, req,
					le16_to_cpu(blk_state->log_start_page),
					array, array_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read log's header desc array: "
			  "seg %llu, peb %llu, log_start_page %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  le16_to_cpu(blk_state->log_start_page),
			  err);
		return err;
	}

	area_index = SSDFS_AREA_TYPE2INDEX(blk_state->log_area);

	if (area_index >= SSDFS_SEG_HDR_DESC_MAX) {
		SSDFS_ERR("invalid area index %#x\n", area_index);
		return -ERANGE;
	}

	area_offset = le32_to_cpu(array[area_index].offset);
	area_size = le32_to_cpu(array[area_index].size);
	blk_desc_off = le32_to_cpu(blk_state->byte_offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_offset %u, blk_desc_off %u\n",
		  area_offset, blk_desc_off);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_read_block_descriptor(pebi, req,
					      &array[area_index],
					      area_offset + blk_desc_off,
					      blk_desc);
	if (err) {
		page_off = (area_offset + blk_desc_off) / PAGE_SIZE;
		pages_count = (area_size + PAGE_SIZE - 1) / PAGE_SIZE;
		pages_count = min_t(u32, pages_count, PAGEVEC_SIZE);

		pagevec_init(&pvec);

		for (i = 0; i < pages_count; i++) {
			page = ssdfs_page_array_grab_page(&pebi->cache,
							  page_off + i);
			if (unlikely(IS_ERR_OR_NULL(page))) {
				SSDFS_ERR("fail to grab page: index %u\n",
					  page_off);
				return -ENOMEM;
			}

			if (PageUptodate(page) || PageDirty(page))
				break;

			pagevec_add(&pvec, page);
		}

		err = ssdfs_read_pagevec_from_volume(fsi, pebi->peb_id,
						     page_off << PAGE_SHIFT,
						     &pvec);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read pagevec: "
				  "peb_id %llu, page_off %u, "
				  "pages_count %u, err %d\n",
				  pebi->peb_id, page_off,
				  pages_count, err);
			return err;
		}

		for (i = 0; i < pagevec_count(&pvec); i++) {
			page = pvec.pages[i];

			if (!page) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("page %d is NULL\n", i);
#endif /* CONFIG_SSDFS_DEBUG */
				continue;
			}

			pvec.pages[i] = NULL;
		}

		pagevec_reinit(&pvec);

		err = ssdfs_peb_read_block_descriptor(pebi, req,
						     &array[area_index],
						     area_offset + blk_desc_off,
						     blk_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read block descriptor: "
				  "peb %llu, area_offset %u, byte_offset %u, "
				  "buf_size %zu, err %d\n",
				  pebi->peb_id, area_offset, blk_desc_off,
				  blk_desc_size, err);
			return err;
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %llu, logical_offset %u, "
		  "peb_index %u, peb_page %u\n",
		  le64_to_cpu(blk_desc->ino),
		  le32_to_cpu(blk_desc->logical_offset),
		  le16_to_cpu(blk_desc->peb_index),
		  le16_to_cpu(blk_desc->peb_page));

	for (i = 0; i < SSDFS_BLK_STATE_OFF_MAX; i++) {
		struct ssdfs_blk_state_offset *state_off;

		state_off = &blk_desc->state[i];

		SSDFS_DBG("BLK STATE OFFSET %d: "
			  "log_start_page %u, log_area %#x, "
			  "byte_offset %u, peb_migration_id %u\n",
			  i,
			  le16_to_cpu(state_off->log_start_page),
			  state_off->log_area,
			  le32_to_cpu(state_off->byte_offset),
			  state_off->peb_migration_id);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	switch (req->private.class) {
	case SSDFS_PEB_COLLECT_GARBAGE_REQ:
		/*
		 * The inode ID and logical offset are unavailable
		 * during the garbage collection operation.
		 * Do nothing.
		 */
		break;

	default:
		if (le64_to_cpu(blk_desc->ino) != req->extent.ino) {
			SSDFS_ERR("seg %llu, peb %llu, "
				  "blk_desc->ino %llu != req->extent.ino %llu\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  le64_to_cpu(blk_desc->ino), req->extent.ino);
			return -ERANGE;
		}

		calculated = req->extent.logical_offset;
		calculated += (u64)req->result.processed_blks * fsi->pagesize;
		calculated = div_u64(calculated, fsi->pagesize);

		if (calculated != le32_to_cpu(blk_desc->logical_offset)) {
			SSDFS_WARN("requested logical_offset %llu "
				   "differs from found logical_offset %u\n",
				   calculated,
				   le32_to_cpu(blk_desc->logical_offset));
			return -ERANGE;
		}

		calculated = (u64)req->result.processed_blks * fsi->pagesize;

		if (calculated >= req->extent.data_bytes) {
			SSDFS_ERR("calculated %llu >= req->extent.data_bytes %u\n",
				  calculated, req->extent.data_bytes);
			return -ERANGE;
		}
		break;
	}

	return 0;
}

/*
 * __ssdfs_peb_get_block_state_desc() - get block state descriptor
 * @pebi: pointer on PEB object
 * @req: segment request
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
				struct ssdfs_segment_request *req,
				struct ssdfs_metadata_descriptor *area_desc,
				struct ssdfs_block_state_descriptor *desc,
				u64 *cno, u64 *parent_snapshot)
{
	struct ssdfs_fs_info *fsi;
	size_t state_desc_size = sizeof(struct ssdfs_block_state_descriptor);
	u32 area_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!area_desc || !desc);
	BUG_ON(!cno || !parent_snapshot);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	area_offset = le32_to_cpu(area_desc->offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, area_offset %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, area_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_unaligned_read_cache(pebi, req,
					 area_offset,
					 state_desc_size,
					 desc);
	if (err) {
		SSDFS_DBG("cache hasn't requested page\n");

		if (req->private.flags & SSDFS_REQ_READ_ONLY_CACHE)
			return -ENOENT;

		err = ssdfs_unaligned_read_buffer(fsi, pebi->peb_id,
						  area_offset,
						  desc, state_desc_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read buffer: "
				  "peb %llu, area_offset %u, "
				  "buf_size %zu, err %d\n",
				  pebi->peb_id, area_offset,
				  state_desc_size, err);
			return err;
		}
	}

	if (desc->chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		SSDFS_ERR("chain header magic invalid\n");
		return -EIO;
	}

	if (desc->chain_hdr.type != SSDFS_BLK_STATE_CHAIN_HDR) {
		SSDFS_ERR("chain header type invalid\n");
		return -EIO;
	}

	if (le16_to_cpu(desc->chain_hdr.desc_size) !=
	    sizeof(struct ssdfs_fragment_desc)) {
		SSDFS_ERR("fragment descriptor size is invalid\n");
		return -EIO;
	}

	*cno = le64_to_cpu(desc->cno);
	*parent_snapshot = le64_to_cpu(desc->parent_snapshot);

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

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	err = __ssdfs_peb_get_block_state_desc(pebi, req, area_desc,
						desc, &cno, &parent_snapshot);
	if (err == -ENOENT) {
		SSDFS_DBG("cache hasn't requested page\n");
		return err;
	} else if (unlikely(err)) {
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
 * @req: segment request
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
					struct ssdfs_segment_request *req,
					u32 array_offset,
					struct ssdfs_fragment_desc *array,
					size_t array_size)
{
	struct ssdfs_fs_info *fsi;
	u32 page_index, page_off;
	struct page *page;
	size_t frag_desc_size = sizeof(struct ssdfs_fragment_desc);
	size_t array_bytes = frag_desc_size * array_size;
	size_t size = array_bytes;
	size_t read_size = 0;
	u32 buf_off = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!array);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "array_offset %u, array_size %zu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  array_offset, array_size);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

read_next_page:
	page_off = array_offset % PAGE_SIZE;
	read_size = min_t(size_t, size, PAGE_SIZE - page_off);

	page_index = array_offset >> PAGE_SHIFT;
	page = ssdfs_peb_read_page_locked(pebi, req, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = IS_ERR(page) ? PTR_ERR(page) : -ERANGE;
		if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache hasn't page: index %u\n",
				  page_index);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			SSDFS_ERR("fail to read locked page: index %u\n",
				  page_index);
		}
		return err;
	}

	err = ssdfs_memcpy_from_page(array, buf_off, array_bytes,
				     page, page_off, PAGE_SIZE,
				     read_size);

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: "
			  "page_off %u, buf_off %u, "
			  "read_size %zu, size %zu, err %d\n",
			  page_off, buf_off,
			  read_size, array_bytes, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	size -= read_size;
	buf_off += read_size;
	array_offset += read_size;

	if (size != 0)
		goto read_next_page;

	return 0;
}

/*
 * ssdfs_peb_unaligned_read_fragment() - unaligned read fragment
 * @pebi: pointer on PEB object
 * @req: request
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
				      struct ssdfs_segment_request *req,
				      u32 byte_off,
				      size_t size,
				      void *buf)
{
	u32 page_index, page_off;
	struct page *page;
	size_t read_size = 0;
	u32 buf_off = 0;
	size_t array_bytes = size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(byte_off > pebi->pebc->parent_si->fsi->erasesize);
	BUG_ON(size > PAGE_SIZE);
	WARN_ON(size == 0);
	BUG_ON(!buf);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "offset %u, size %zu, buf %p\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  byte_off, size, buf);
#endif /* CONFIG_SSDFS_DEBUG */

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
	page = ssdfs_peb_read_page_locked(pebi, req, page_index);
	if (IS_ERR_OR_NULL(page)) {
		err = IS_ERR(page) ? PTR_ERR(page) : -ERANGE;
		if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache hasn't page: page_off %u\n",
				  page_off);
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			SSDFS_ERR("fail to read locked page: index %u\n",
				  page_off);
		}
		return err;
	}

	err = ssdfs_memcpy_from_page(buf, buf_off, array_bytes,
				     page, page_off, PAGE_SIZE,
				     read_size);

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

	if (unlikely(err)) {
		SSDFS_ERR("fail to copy: "
			  "page_off %u, buf_off %u, "
			  "read_size %zu, size %zu, err %d\n",
			  page_off, buf_off,
			  read_size, array_bytes, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

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
 * @req: segment request
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
				struct ssdfs_segment_request *req,
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

	SSDFS_DBG("seg %llu, peb %llu, area_offset %u, sequence_id %u, "
		  "offset %u, compr_size %u, uncompr_size %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_offset,
		  le16_to_cpu(desc->sequence_id),
		  le32_to_cpu(desc->offset),
		  le16_to_cpu(desc->compr_size),
		  le16_to_cpu(desc->uncompr_size));
#endif /* CONFIG_SSDFS_DEBUG */

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

		kaddr = kmap_local_page(page);
		err = ssdfs_peb_unaligned_read_fragment(pebi, req, offset,
							uncompr_size,
							kaddr);
		if (!err)
			checksum = ssdfs_crc32_le(kaddr, uncompr_size);
		flush_dcache_page(page);
		kunmap_local(kaddr);

		if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache hasn't requested page: "
				  "seg %llu, peb %llu, offset %u, size %zu\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  offset, uncompr_size);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
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

		err = ssdfs_peb_unaligned_read_fragment(pebi, req, offset,
							compr_size,
							cdata_buf);
		if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache hasn't requested page: "
				  "seg %llu, peb %llu, offset %u, size %zu\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  offset, uncompr_size);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
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

		kaddr = kmap_local_page(page);
		err = ssdfs_decompress(type, cdata_buf, kaddr,
					compr_size, uncompr_size);
		if (!err)
			checksum = ssdfs_crc32_le(kaddr, uncompr_size);
		flush_dcache_page(page);
		kunmap_local(kaddr);

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
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !array || !blk_state_off);

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

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

	if (req->private.flags & SSDFS_REQ_PREPARE_DIFF) {
		if (pagevec_count(&req->result.old_state) <= page_index) {
			SSDFS_ERR("page_index %d >= pagevec_count %u\n",
				  page_index,
				  pagevec_count(&req->result.old_state));
			return -EIO;
		}

		page = req->result.old_state.pages[page_index];
	} else {
		if (pagevec_count(&req->result.pvec) <= page_index) {
			SSDFS_ERR("page_index %d >= pagevec_count %u\n",
				  page_index,
				  pagevec_count(&req->result.pvec));
			return -EIO;
		}

		page = req->result.pvec.pages[page_index];
	}

	kaddr = kmap_local_page(page);
	err = ssdfs_peb_unaligned_read_fragment(pebi, req,
						area_offset + byte_offset,
						data_bytes,
						kaddr);
	flush_dcache_page(page);
	kunmap_local(kaddr);

	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, size %u, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  area_offset + byte_offset, data_bytes, err);
		return err;
	}

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
	u32 uncompr_bytes;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !array || !blk_state_off);

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

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
	if (err == -ENOENT) {
		SSDFS_DBG("cache hasn't requested page\n");
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get block state descriptor: "
			  "area_offset %u, err %d\n",
			  le32_to_cpu(array[area_index].offset),
			  err);
		return err;
	}

	uncompr_bytes = le32_to_cpu(found_blk_state.chain_hdr.uncompr_bytes);
	if (data_bytes > uncompr_bytes) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("data_bytes %u > uncompr_bytes %u\n",
			  data_bytes, uncompr_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		req->extent.data_bytes -= data_bytes - uncompr_bytes;
		data_bytes = uncompr_bytes;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("CORRECTED VALUE: data_bytes %u\n",
			  data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */
	}

	fragments = le16_to_cpu(found_blk_state.chain_hdr.fragments_count);
	if (fragments == 0 || fragments > SSDFS_FRAGMENTS_CHAIN_MAX) {
		SSDFS_ERR("invalid fragments count %u\n", fragments);
		return -EIO;
	}

	frag_descs = ssdfs_read_kcalloc(fragments, frag_desc_size, GFP_KERNEL);
	if (!frag_descs) {
		SSDFS_ERR("fail to allocate fragment descriptors array\n");
		return -ENOMEM;
	}

	area_offset = le32_to_cpu(array[area_index].offset);
	frag_desc_offset = le32_to_cpu(blk_state_off->byte_offset);
	frag_desc_offset += state_desc_size;
	full_offset = area_offset + frag_desc_offset;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_offset %u, blk_state_off->byte_offset %u, "
		  "state_desc_size %zu, frag_desc_offset %u, "
		  "full_offset %u\n",
		  area_offset, le32_to_cpu(blk_state_off->byte_offset),
		  state_desc_size, frag_desc_offset, full_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_get_fragment_desc_array(pebi, req, full_offset,
						frag_descs, fragments);
	if (err == -ENOENT) {
		SSDFS_DBG("cache hasn't requested page\n");
		goto free_bufs;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get fragment descriptor array: "
			  "offset %u, fragments %u, err %d\n",
			  full_offset, fragments, err);
		goto free_bufs;
	}

	cdata_buf = ssdfs_read_kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!cdata_buf) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate cdata_buf\n");
		goto free_bufs;
	}

	page_index = (int)(read_bytes >> PAGE_SHIFT);
	BUG_ON(page_index >= U16_MAX);

	for (i = 0; i < fragments; i++) {
		struct pagevec *pvec;
		struct page *page;
		struct ssdfs_fragment_desc *cur_desc;
		u32 compr_size;

		if (req->private.flags & SSDFS_REQ_PREPARE_DIFF) {
			pvec = &req->result.old_state;

			if (pagevec_count(pvec) <= i) {
				err = -EIO;
				SSDFS_ERR("page_index %d >= pagevec_count %u\n",
					  i, pagevec_count(pvec));
				goto free_bufs;
			}
		} else {
			pvec = &req->result.pvec;

			if (pagevec_count(pvec) <= (page_index + i)) {
				err = -EIO;
				SSDFS_ERR("page_index %d >= pagevec_count %u\n",
					  page_index + i,
					  pagevec_count(pvec));
				goto free_bufs;
			}
		}

		cur_desc = &frag_descs[i];

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("FRAGMENT DESC DUMP: index %d\n", i);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     cur_desc,
				     sizeof(struct ssdfs_fragment_desc));
		SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

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

		compr_size = le16_to_cpu(cur_desc->compr_size);

		if (compr_size > PAGE_SIZE) {
			err = -EIO;
			SSDFS_ERR("compr_size %u > PAGE_SIZE %lu\n",
				  compr_size, PAGE_SIZE);
			goto free_bufs;
		}

		if (req->private.flags & SSDFS_REQ_PREPARE_DIFF)
			page = pvec->pages[i];
		else
			page = pvec->pages[page_index + i];

		err = ssdfs_read_checked_fragment(pebi, req, area_offset,
						  i, cur_desc,
						  cdata_buf,
						  page);
		if (err == -ENOENT) {
			SSDFS_DBG("cache hasn't requested page\n");
			goto free_bufs;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read fragment: "
				  "index %d, err %d\n",
				  i, err);
			goto free_bufs;
		}
	}

free_bufs:
	ssdfs_read_kfree(frag_descs);
	ssdfs_read_kfree(cdata_buf);

	return err;
}

/*
 * ssdfs_peb_read_base_block_state() - read base state of block
 * @pebi: pointer on PEB object
 * @req: request
 * @array: array of area's descriptors
 * @array_size: count of items into array
 * @offset: block state offset
 *
 * This function tries to extract a base state of block.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - I/O error.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENOENT     - cache hasn't requested page.
 */
static
int ssdfs_peb_read_base_block_state(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req,
				    struct ssdfs_metadata_descriptor *array,
				    size_t array_size,
				    struct ssdfs_blk_state_offset *offset)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req || !array || !offset);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_read_log_hdr_desc_array(pebi, req,
					le16_to_cpu(offset->log_start_page),
					array, array_size);
	if (err == -ENOENT) {
		SSDFS_DBG("cache hasn't requested page\n");
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read log's header desc array: "
			  "seg %llu, peb %llu, log_start_page %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  le16_to_cpu(offset->log_start_page),
			  err);
		return err;
	}

	if (offset->log_area == SSDFS_LOG_MAIN_AREA) {
		err = ssdfs_peb_read_main_area_page(pebi, req,
						    array, array_size,
						    offset);
		if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache hasn't requested page: "
				  "seg %llu, peb %llu, "
				  "ino %llu, logical_offset %llu\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  req->extent.ino,
				  req->extent.logical_offset);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read main area's page: "
				  "seg %llu, peb %llu, "
				  "ino %llu, logical_offset %llu, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  req->extent.ino,
				  req->extent.logical_offset,
				  err);
			return err;
		}
	} else {
		err = ssdfs_peb_read_area_fragment(pebi, req,
						   array, array_size,
						   offset);
		if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache hasn't requested page: "
				  "seg %llu, peb %llu, "
				  "ino %llu, logical_offset %llu\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  req->extent.ino,
				  req->extent.logical_offset);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read area's fragment: "
				  "seg %llu, peb %llu, "
				  "ino %llu, logical_offset %llu, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  req->extent.ino,
				  req->extent.logical_offset,
				  err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_peb_read_area_diff_fragment() - read diff fragment
 * @pebi: pointer on PEB object
 * @req: request
 * @array: array of area's descriptors
 * @array_size: count of items into array
 * @blk_state_off: block state offset
 * @page: page with current diff blob
 * @sequence_id: sequence ID of the fragment
 *
 * This function tries to extract a diff blob into @page.
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
int ssdfs_peb_read_area_diff_fragment(struct ssdfs_peb_info *pebi,
				 struct ssdfs_segment_request *req,
				 struct ssdfs_metadata_descriptor *array,
				 size_t array_size,
				 struct ssdfs_blk_state_offset *blk_state_off,
				 struct page *page,
				 int sequence_id)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_block_state_descriptor found_blk_state;
	size_t state_desc_size = sizeof(struct ssdfs_block_state_descriptor);
	struct ssdfs_fragment_desc frag_desc = {0};
	void *cdata_buf = NULL;
	u8 area_index;
	u32 area_offset;
	u32 frag_desc_offset;
	u32 full_offset;
	u16 fragments;
	u64 cno;
	u64 parent_snapshot;
	u32 compr_size;
#ifdef CONFIG_SSDFS_DEBUG
	void *kaddr;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!array || !blk_state_off || !page);

	SSDFS_DBG("seg %llu, peb %llu, sequence_id %d\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, sequence_id);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	err = ssdfs_peb_read_log_hdr_desc_array(pebi, req,
				le16_to_cpu(blk_state_off->log_start_page),
				array, array_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read log's header desc array: "
			  "seg %llu, peb %llu, log_start_page %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  le16_to_cpu(blk_state_off->log_start_page),
			  err);
		return err;
	}

	area_index = SSDFS_AREA_TYPE2INDEX(blk_state_off->log_area);
	if (area_index >= array_size) {
		SSDFS_ERR("area_index %u >= array_size %zu\n",
			  area_index, array_size);
		return -EIO;
	}

	err = __ssdfs_peb_get_block_state_desc(pebi, req, &array[area_index],
						&found_blk_state,
						&cno, &parent_snapshot);
	if (unlikely(err)) {
		SSDFS_ERR("fail to get block state descriptor: "
			  "area_offset %u, err %d\n",
			  le32_to_cpu(array[area_index].offset),
			  err);
		return err;
	}

	fragments = le16_to_cpu(found_blk_state.chain_hdr.fragments_count);
	if (fragments == 0 || fragments > 1) {
		SSDFS_ERR("invalid fragments count %u\n", fragments);
		return -EIO;
	}

	area_offset = le32_to_cpu(array[area_index].offset);
	frag_desc_offset = le32_to_cpu(blk_state_off->byte_offset);
	frag_desc_offset += state_desc_size;
	full_offset = area_offset + frag_desc_offset;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_offset %u, blk_state_off->byte_offset %u, "
		  "state_desc_size %zu, frag_desc_offset %u, "
		  "full_offset %u\n",
		  area_offset, le32_to_cpu(blk_state_off->byte_offset),
		  state_desc_size, frag_desc_offset, full_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_get_fragment_desc_array(pebi, req, full_offset,
						&frag_desc, 1);
	if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cache hasn't requested page: "
			  "seg %llu, peb %llu\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get fragment descriptor array: "
			  "offset %u, fragments %u, err %d\n",
			  full_offset, fragments, err);
		return err;
	}

	cdata_buf = ssdfs_read_kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!cdata_buf) {
		SSDFS_ERR("fail to allocate cdata_buf\n");
		return -ENOMEM;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("FRAGMENT DESC DUMP: index %d\n", sequence_id);
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     &frag_desc,
			     sizeof(struct ssdfs_fragment_desc));
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (frag_desc.magic != SSDFS_FRAGMENT_DESC_MAGIC) {
		err = -EIO;
		SSDFS_ERR("invalid fragment descriptor magic\n");
		goto free_bufs;
	}

	if (frag_desc.type < SSDFS_FRAGMENT_UNCOMPR_BLOB ||
	    frag_desc.type > SSDFS_FRAGMENT_LZO_BLOB) {
		err = -EIO;
		SSDFS_ERR("invalid fragment descriptor type\n");
		goto free_bufs;
	}

	compr_size = le16_to_cpu(frag_desc.compr_size);

	if (compr_size > PAGE_SIZE) {
		err = -EIO;
		SSDFS_ERR("compr_size %u > PAGE_SIZE %lu\n",
			  compr_size, PAGE_SIZE);
		goto free_bufs;
	}

	err = ssdfs_read_checked_fragment(pebi, req, area_offset,
					  0, &frag_desc,
					  cdata_buf,
					  page);
	if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cache hasn't requested page: "
			  "seg %llu, peb %llu\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		goto free_bufs;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read fragment: "
			  "index %d, err %d\n",
			  sequence_id, err);
		goto free_bufs;
	}

#ifdef CONFIG_SSDFS_DEBUG
	kaddr = kmap_local_page(page);
	SSDFS_DBG("DIFF DUMP: index %d\n",
		  sequence_id);
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     kaddr,
			     PAGE_SIZE);
	SSDFS_DBG("\n");
	kunmap_local(kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

free_bufs:
	if (cdata_buf)
		ssdfs_read_kfree(cdata_buf);

	return err;
}

/*
 * ssdfs_peb_read_diff_block_state() - read diff blob
 * @pebi: pointer on PEB object
 * @req: request
 * @array: array of area's descriptors
 * @array_size: count of items into array
 * @offset: block state offset
 *
 * This function tries to extract a diff blob.
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
int ssdfs_peb_read_diff_block_state(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req,
				    struct ssdfs_metadata_descriptor *array,
				    size_t array_size,
				    struct ssdfs_blk_state_offset *offset)
{
	struct page *page = NULL;
	int sequence_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!array || !offset);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);

	SSDFS_DBG("seg %llu, peb %llu, pagevec_size %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pagevec_count(&req->result.diffs));
#endif /* CONFIG_SSDFS_DEBUG */

	page = ssdfs_request_allocate_and_add_diff_page(req);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		err = !page ? -ENOMEM : PTR_ERR(page);
		SSDFS_ERR("fail to add pagevec page: err %d\n",
			  err);
		return err;
	}

	ssdfs_lock_page(page);

	sequence_id = pagevec_count(&req->result.diffs) - 1;
	err = ssdfs_peb_read_area_diff_fragment(pebi, req, array, array_size,
						offset, page, sequence_id);
	if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cache hasn't requested page: "
			  "seg %llu, peb %llu\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read area's fragment: "
			  "seg %llu, peb %llu, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_blk_desc_buffer_init() - init block descriptor buffer
 * @pebc: pointer on PEB container
 * @req: request
 * @desc_off: block descriptor offset
 * @pos: offset position
 * @array: array of area's descriptors
 * @array_size: count of items into array
 *
 * This function tries to init block descriptor buffer.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO        - I/O error.
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
int ssdfs_blk_desc_buffer_init(struct ssdfs_peb_container *pebc,
				struct ssdfs_segment_request *req,
				struct ssdfs_phys_offset_descriptor *desc_off,
				struct ssdfs_offset_position *pos,
				struct ssdfs_metadata_descriptor *array,
				size_t array_size)
{
	struct ssdfs_peb_info *pebi = NULL;
	struct ssdfs_blk2off_table *table;
	u8 peb_migration_id;
	u16 logical_blk;
	struct ssdfs_blk_state_offset *state_off;
	int j;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!desc_off || !pos);

	SSDFS_DBG("seg %llu, peb_index %u, blk_desc.status %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  pos->blk_desc.status);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (pos->blk_desc.status) {
	case SSDFS_BLK_DESC_BUF_UNKNOWN_STATE:
	case SSDFS_BLK_DESC_BUF_ALLOCATED:
		peb_migration_id = desc_off->blk_state.peb_migration_id;

		pebi = ssdfs_get_peb_for_migration_id(pebc, peb_migration_id);
		if (IS_ERR_OR_NULL(pebi)) {
			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			goto finish_blk_desc_buffer_init;
		}

		err = ssdfs_peb_find_block_descriptor(pebi, req,
						      array, array_size,
						      desc_off,
						      &pos->blk_desc.buf);
		if (unlikely(err)) {
			SSDFS_ERR("fail to find block descriptor: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			goto finish_blk_desc_buffer_init;
		}

		pos->blk_desc.status = SSDFS_BLK_DESC_BUF_INITIALIZED;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("status %#x, ino %llu, "
			  "logical_offset %u, peb_index %u, peb_page %u\n",
			  pos->blk_desc.status,
			  le64_to_cpu(pos->blk_desc.buf.ino),
			  le32_to_cpu(pos->blk_desc.buf.logical_offset),
			  le16_to_cpu(pos->blk_desc.buf.peb_index),
			  le16_to_cpu(pos->blk_desc.buf.peb_page));

		for (j = 0; j < SSDFS_BLK_STATE_OFF_MAX; j++) {
			state_off = &pos->blk_desc.buf.state[j];

			SSDFS_DBG("BLK STATE OFFSET %d: "
				  "log_start_page %u, log_area %#x, "
				  "byte_offset %u, peb_migration_id %u\n",
				  j,
				  le16_to_cpu(state_off->log_start_page),
				  state_off->log_area,
				  le32_to_cpu(state_off->byte_offset),
				  state_off->peb_migration_id);
		}
#endif /* CONFIG_SSDFS_DEBUG */

		table = pebi->pebc->parent_si->blk2off_table;
		logical_blk = req->place.start.blk_index +
					req->result.processed_blks;

		err = ssdfs_blk2off_table_blk_desc_init(table, logical_blk,
							pos);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init blk desc: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
			goto finish_blk_desc_buffer_init;
		}
		break;

	case SSDFS_BLK_DESC_BUF_INITIALIZED:
		/* do nothing */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("descriptor buffer is initialized already\n");
		SSDFS_DBG("status %#x, ino %llu, "
			  "logical_offset %u, peb_index %u, peb_page %u\n",
			  pos->blk_desc.status,
			  le64_to_cpu(pos->blk_desc.buf.ino),
			  le32_to_cpu(pos->blk_desc.buf.logical_offset),
			  le16_to_cpu(pos->blk_desc.buf.peb_index),
			  le16_to_cpu(pos->blk_desc.buf.peb_page));

		for (j = 0; j < SSDFS_BLK_STATE_OFF_MAX; j++) {
			state_off = &pos->blk_desc.buf.state[j];

			SSDFS_DBG("BLK STATE OFFSET %d: "
				  "log_start_page %u, log_area %#x, "
				  "byte_offset %u, peb_migration_id %u\n",
				  j,
				  le16_to_cpu(state_off->log_start_page),
				  state_off->log_area,
				  le32_to_cpu(state_off->byte_offset),
				  state_off->peb_migration_id);
		}
#endif /* CONFIG_SSDFS_DEBUG */
		break;

	default:
		SSDFS_ERR("status %#x, ino %llu, "
			  "logical_offset %u, peb_index %u, peb_page %u\n",
			  pos->blk_desc.status,
			  le64_to_cpu(pos->blk_desc.buf.ino),
			  le32_to_cpu(pos->blk_desc.buf.logical_offset),
			  le16_to_cpu(pos->blk_desc.buf.peb_index),
			  le16_to_cpu(pos->blk_desc.buf.peb_page));

		for (j = 0; j < SSDFS_BLK_STATE_OFF_MAX; j++) {
			state_off = &pos->blk_desc.buf.state[j];

			SSDFS_ERR("BLK STATE OFFSET %d: "
				  "log_start_page %u, log_area %#x, "
				  "byte_offset %u, peb_migration_id %u\n",
				  j,
				  le16_to_cpu(state_off->log_start_page),
				  state_off->log_area,
				  le32_to_cpu(state_off->byte_offset),
				  state_off->peb_migration_id);
		}
		BUG();
	}

finish_blk_desc_buffer_init:
	return err;
}

/*
 * ssdfs_peb_read_block_state() - read state of the block
 * @pebc: pointer on PEB container
 * @req: request
 * @desc_off: block descriptor offset
 * @pos: offset position
 * @array: array of area's descriptors
 * @array_size: count of items into array
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
int ssdfs_peb_read_block_state(struct ssdfs_peb_container *pebc,
				struct ssdfs_segment_request *req,
				struct ssdfs_phys_offset_descriptor *desc_off,
				struct ssdfs_offset_position *pos,
				struct ssdfs_metadata_descriptor *array,
				size_t array_size)
{
	struct ssdfs_peb_info *pebi = NULL;
	struct ssdfs_blk_state_offset *offset = NULL;
	u64 ino;
	u32 logical_offset;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req || !array);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);

	SSDFS_DBG("seg %llu, peb_index %u, processed_blks %d\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->result.processed_blks);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_blk_desc_buffer_init(pebc, req, desc_off, pos,
					 array, array_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init blk desc buffer: err %d\n",
			  err);
		goto finish_prepare_pvec;
	}

	ino = le64_to_cpu(pos->blk_desc.buf.ino);
	logical_offset = le32_to_cpu(pos->blk_desc.buf.logical_offset);

	offset = &pos->blk_desc.buf.state[0];

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("ino %llu, logical_offset %u\n",
		  ino, logical_offset);
	SSDFS_DBG("log_start_page %u, log_area %u, "
		  "peb_migration_id %u, byte_offset %u\n",
		  le16_to_cpu(offset->log_start_page),
		  offset->log_area,
		  offset->peb_migration_id,
		  le32_to_cpu(offset->byte_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	if (IS_SSDFS_BLK_STATE_OFFSET_INVALID(offset)) {
		err = -ERANGE;
		SSDFS_ERR("block state offset invalid\n");
		SSDFS_ERR("log_start_page %u, log_area %u, "
			  "peb_migration_id %u, byte_offset %u\n",
			  le16_to_cpu(offset->log_start_page),
			  offset->log_area,
			  offset->peb_migration_id,
			  le32_to_cpu(offset->byte_offset));
		goto finish_prepare_pvec;
	}

	pebi = ssdfs_get_peb_for_migration_id(pebc, offset->peb_migration_id);
	if (IS_ERR_OR_NULL(pebi)) {
		err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
		SSDFS_ERR("fail to get PEB object: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		goto finish_prepare_pvec;
	}

#ifdef CONFIG_SSDFS_DEBUG
	DEBUG_BLOCK_DESCRIPTOR(pebi->pebc->parent_si->seg_id,
				pebi->peb_id, &pos->blk_desc.buf);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_read_base_block_state(pebi, req,
					      array, array_size,
					      offset);
	if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to read block state: "
			  "seg %llu, peb_index %u, ino %llu, "
			  "logical_offset %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  ino, logical_offset);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_prepare_pvec;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read block state: "
			  "seg %llu, peb_index %u, ino %llu, "
			  "logical_offset %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  ino, logical_offset,
			  err);
		goto finish_prepare_pvec;
	}

	for (i = 0; i < SSDFS_BLK_STATE_OFF_MAX; i++) {
		offset = &pos->blk_desc.buf.state[i];

		if (i == 0) {
			/*
			 * base block state has been read already
			 */
			continue;
		} else {
			if (IS_SSDFS_BLK_STATE_OFFSET_INVALID(offset))
				goto finish_prepare_pvec;

			pebi = ssdfs_get_peb_for_migration_id(pebc,
						offset->peb_migration_id);
			if (IS_ERR_OR_NULL(pebi)) {
				err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
				SSDFS_ERR("fail to get PEB object: "
					  "seg %llu, peb_index %u, err %d\n",
					  pebc->parent_si->seg_id,
					  pebc->peb_index, err);
				goto finish_prepare_pvec;
			}

			err = ssdfs_peb_read_diff_block_state(pebi,
							      req,
							      array,
							      array_size,
							      offset);
		}

		if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache hasn't requested page: "
				  "seg %llu, peb_index %u, ino %llu, "
				  "logical_offset %u\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  ino, logical_offset);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_prepare_pvec;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read block state: "
				  "seg %llu, peb_index %u, ino %llu, "
				  "logical_offset %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  ino, logical_offset, err);
			goto finish_prepare_pvec;
		}
	}

finish_prepare_pvec:
	if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to read the block state: "
			  "seg %llu, peb_index %u, ino %llu, "
			  "logical_offset %u, peb_index %u, "
			  "peb_page %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  le64_to_cpu(pos->blk_desc.buf.ino),
			  le32_to_cpu(pos->blk_desc.buf.logical_offset),
			  le16_to_cpu(pos->blk_desc.buf.peb_index),
			  le16_to_cpu(pos->blk_desc.buf.peb_page));
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_read_block_state;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read the block state: "
			  "seg %llu, peb_index %u, ino %llu, "
			  "logical_offset %u, peb_index %u, "
			  "peb_page %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  le64_to_cpu(pos->blk_desc.buf.ino),
			  le32_to_cpu(pos->blk_desc.buf.logical_offset),
			  le16_to_cpu(pos->blk_desc.buf.peb_index),
			  le16_to_cpu(pos->blk_desc.buf.peb_page),
			  err);
		goto finish_read_block_state;
	}

	if (pagevec_count(&req->result.diffs) == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("diffs pagevec is empty: "
			  "seg %llu, peb_index %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_read_block_state;
	}

	switch (pebi->pebc->peb_type) {
	case SSDFS_MAPTBL_DATA_PEB_TYPE:
		err = ssdfs_user_data_apply_diffs(pebi, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to apply diffs on base state: "
				  "seg %llu, peb_index %u, ino %llu, "
				  "logical_offset %u, peb_index %u, "
				  "peb_page %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  le64_to_cpu(pos->blk_desc.buf.ino),
				  le32_to_cpu(pos->blk_desc.buf.logical_offset),
				  le16_to_cpu(pos->blk_desc.buf.peb_index),
				  le16_to_cpu(pos->blk_desc.buf.peb_page),
				  err);
			goto finish_read_block_state;
		}
		break;

	case SSDFS_MAPTBL_LNODE_PEB_TYPE:
	case SSDFS_MAPTBL_HNODE_PEB_TYPE:
	case SSDFS_MAPTBL_IDXNODE_PEB_TYPE:
		err = ssdfs_btree_node_apply_diffs(pebi, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail to apply diffs on base state: "
				  "seg %llu, peb_index %u, ino %llu, "
				  "logical_offset %u, peb_index %u, "
				  "peb_page %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  le64_to_cpu(pos->blk_desc.buf.ino),
				  le32_to_cpu(pos->blk_desc.buf.logical_offset),
				  le16_to_cpu(pos->blk_desc.buf.peb_index),
				  le16_to_cpu(pos->blk_desc.buf.peb_page),
				  err);
			goto finish_read_block_state;
		}
		break;

	default:
		err = -EOPNOTSUPP;
		SSDFS_ERR("diff-on-write is not supported: "
			  "seg %llu, peb_index %u, peb_type %#x, ino %llu, "
			  "logical_offset %u, peb_index %u, "
			  "peb_page %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  pebi->pebc->peb_type,
			  le64_to_cpu(pos->blk_desc.buf.ino),
			  le32_to_cpu(pos->blk_desc.buf.logical_offset),
			  le16_to_cpu(pos->blk_desc.buf.peb_index),
			  le16_to_cpu(pos->blk_desc.buf.peb_page),
			  err);
		goto finish_read_block_state;
	}

finish_read_block_state:
	if (!err && !(req->private.flags & SSDFS_REQ_PREPARE_DIFF))
		req->result.processed_blks++;

	if (err)
		ssdfs_request_unlock_and_remove_old_state(req);

	ssdfs_request_unlock_and_remove_diffs(req);

	return err;
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
	u16 logical_blk;
	u16 log_start_page;
	struct ssdfs_metadata_descriptor desc_array[SSDFS_SEG_HDR_DESC_MAX];
	u8 peb_migration_id;
	u16 peb_index;
	int migration_state = SSDFS_LBLOCK_UNKNOWN_STATE;
	struct ssdfs_offset_position pos = {0};
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "ino %llu, logical_offset %llu, data_bytes %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;

	if (req->extent.data_bytes == 0) {
		SSDFS_WARN("empty read request: ino %llu, logical_offset %llu\n",
			   req->extent.ino, req->extent.logical_offset);
		return 0;
	}

	table = pebc->parent_si->blk2off_table;
	logical_blk = req->place.start.blk_index + req->result.processed_blks;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("request: place (seg_id %llu, blk_index %u, len %u), "
		  "processed_blks %d, logical_blk %u\n",
		  req->place.start.seg_id,
		  req->place.start.blk_index,
		  req->place.len,
		  req->result.processed_blks,
		  logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

	desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index,
						&migration_state,
						&pos);
	if (IS_ERR(desc_off) && PTR_ERR(desc_off) == -EAGAIN) {
		struct completion *init_end = &table->full_init_end;

		err = SSDFS_WAIT_COMPLETION(init_end);
		if (unlikely(err)) {
			SSDFS_ERR("blk2off init failed: "
				  "err %d\n", err);
			return err;
		}

		desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
							&peb_index,
							&migration_state,
							&pos);
	}

	if (IS_ERR_OR_NULL(desc_off)) {
		err = (desc_off == NULL ? -ERANGE : PTR_ERR(desc_off));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		return err;
	}

	peb_migration_id = desc_off->blk_state.peb_migration_id;

#ifdef CONFIG_SSDFS_DEBUG
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
#endif /* CONFIG_SSDFS_DEBUG */

	if (is_ssdfs_logical_block_migrating(migration_state)) {
		err = ssdfs_blk2off_table_get_block_state(table, req);
		if (err == -EAGAIN) {
			desc_off = ssdfs_blk2off_table_convert(table,
							    logical_blk,
							    &peb_index,
							    &migration_state,
							    &pos);
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

	down_read(&pebc->lock);

	blk_state = &desc_off->blk_state;
	log_start_page = le16_to_cpu(blk_state->log_start_page);

	if (log_start_page >= fsi->pages_per_peb) {
		err = -ERANGE;
		SSDFS_ERR("invalid log_start_page %u\n", log_start_page);
		goto finish_read_page;
	}

	err = ssdfs_peb_read_block_state(pebc, req,
					 desc_off, &pos,
					 desc_array,
					 SSDFS_SEG_HDR_DESC_MAX);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block state: "
			  "seg %llu, peb_index %u, "
			  "class %#x, cmd %#x, type %#x, "
			  "ino %llu, logical_offset %llu, "
			  "data_bytes %u, migration_state %#x, "
			  "err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  req->private.class, req->private.cmd,
			  req->private.type,
			  req->extent.ino,
			  req->extent.logical_offset,
			  req->extent.data_bytes,
			  migration_state,
			  err);

		SSDFS_ERR("seg_id %llu, peb_index %u, ino %llu, "
			  "logical_offset %u, peb_index %u, "
			  "peb_page %u\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  le64_to_cpu(pos.blk_desc.buf.ino),
			  le32_to_cpu(pos.blk_desc.buf.logical_offset),
			  le16_to_cpu(pos.blk_desc.buf.peb_index),
			  le16_to_cpu(pos.blk_desc.buf.peb_page));

		for (i = 0; i < SSDFS_BLK_STATE_OFF_MAX; i++) {
			blk_state = &pos.blk_desc.buf.state[i];

			SSDFS_ERR("BLK STATE OFFSET %d: "
				  "log_start_page %u, log_area %#x, "
				  "byte_offset %u, peb_migration_id %u\n",
				  i,
				  le16_to_cpu(blk_state->log_start_page),
				  blk_state->log_area,
				  le32_to_cpu(blk_state->byte_offset),
				  blk_state->peb_migration_id);
		}

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

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "ino %llu, logical_offset %llu, data_bytes %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

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
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to process page %d\n", i);
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("seg %llu, peb_id %llu, page_off %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, page_off);
#endif /* CONFIG_SSDFS_DEBUG */

	*log_bytes = U32_MAX;

	bytes_off = le32_to_cpu(desc->offset);
	footer_off = bytes_off / fsi->pagesize;

	page = ssdfs_page_array_grab_page(&pebi->cache, footer_off);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		SSDFS_ERR("fail to grab page: index %u\n",
			  footer_off);
		return -ENOMEM;
	}

	kaddr = kmap_local_page(page);

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
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("log footer is corrupted: "
			  "peb %llu, page_off %u\n",
			  pebi->peb_id, page_off);
#endif /* CONFIG_SSDFS_DEBUG */
		goto fail_read_footer;
	}

fail_read_footer:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("valid footer is not detected: "
			  "seg_id %llu, peb_id %llu, "
			  "page_off %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  footer_off);
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("seg %llu, peb_id %llu, page_off %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, page_off);
#endif /* CONFIG_SSDFS_DEBUG */

	*log_bytes = U32_MAX;

	page = ssdfs_page_array_grab_page(&pebi->cache, page_off);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		SSDFS_ERR("fail to grab page: index %u\n",
			  page_off);
		return -ENOMEM;
	}

	kaddr = kmap_local_page(page);

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
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log header is corrupted: "
				  "seg %llu, peb %llu, page_off %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  page_off);
#endif /* CONFIG_SSDFS_DEBUG */
			goto fail_read_log_header;
		}

		desc = &seg_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];

		err = __ssdfs_peb_read_log_footer(fsi, pebi, page_off,
						   desc, log_bytes);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("fail to read footer: "
				  "seg %llu, peb %llu, page_off %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  page_off,
				  err);
#endif /* CONFIG_SSDFS_DEBUG */
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
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("partial log header is corrupted: "
				  "seg %llu, peb %llu, page_off %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  page_off);
#endif /* CONFIG_SSDFS_DEBUG */
			goto fail_read_log_header;
		}

		desc = &pl_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];

		if (ssdfs_pl_has_footer(pl_hdr)) {
			err = __ssdfs_peb_read_log_footer(fsi, pebi, page_off,
							  desc, log_bytes);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("fail to read footer: "
					  "seg %llu, peb %llu, page_off %u, "
					  "err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  page_off,
					  err);
#endif /* CONFIG_SSDFS_DEBUG */
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
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("log header is corrupted: "
			  "seg %llu, peb %llu, page_off %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  page_off);
#endif /* CONFIG_SSDFS_DEBUG */
		goto fail_read_log_header;
	}

fail_read_log_header:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("valid header is not detected: "
			  "seg_id %llu, peb_id %llu, page_off %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  page_off);
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "ino %llu, logical_offset %llu, data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

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

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (!pebi) {
		SSDFS_WARN("source PEB is NULL\n");
		err = -ERANGE;
		goto finish_read_src_all_log_headers;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u, peb_id %llu\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  pebi->peb_id);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u, peb_id %llu\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  pebi->peb_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_peb_read_all_log_headers(pebi, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read the log's headers: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		goto finish_read_src_all_log_headers;
	}

finish_read_src_all_log_headers:
	up_read(&pebc->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	down_read(&pebc->lock);

	pebi = pebc->dst_peb;
	if (!pebi) {
		SSDFS_WARN("destination PEB is NULL\n");
		err = -ERANGE;
		goto finish_read_dst_all_log_headers;
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u, peb_id %llu\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  pebi->peb_id);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u, peb_id %llu\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  pebi->peb_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	err = ssdfs_peb_read_all_log_headers(pebi, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read the log's headers: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		goto finish_read_dst_all_log_headers;
	}

finish_read_dst_all_log_headers:
	up_read(&pebc->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u32 log_pages;
	u32 pages_off = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !env || !env->log_hdr);

	SSDFS_DBG("peb %llu, env %p\n", pebi->peb_id, env);
#endif /* CONFIG_SSDFS_DEBUG */

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
		ssdfs_memcpy_from_page(env->log_hdr, 0, hdr_buf_size,
					page, 0, PAGE_SIZE,
					hdr_buf_size);

		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
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
	unsigned long last_page_idx;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !env);
	BUG_ON(!new_log_start_page);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	*new_log_start_page = U16_MAX;

	last_page_idx = ssdfs_page_array_get_last_page_index(&pebi->cache);

	if (last_page_idx >= SSDFS_PAGE_ARRAY_INVALID_LAST_PAGE) {
		SSDFS_ERR("empty page array: last_page_idx %lu\n",
			  last_page_idx);
		return -ERANGE;
	}

	if (last_page_idx >= fsi->pages_per_peb) {
		SSDFS_ERR("corrupted page array: "
			  "last_page_idx %lu, fsi->pages_per_peb %u\n",
			  last_page_idx, fsi->pages_per_peb);
		return -ERANGE;
	}

	for (i = (int)last_page_idx; i >= 0; i--) {
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

		kaddr = kmap_local_page(page);
		ssdfs_memcpy(env->log_hdr, 0, hdr_buf_size,
			     kaddr, 0, PAGE_SIZE,
			     hdr_buf_size);
		ssdfs_memcpy(env->footer, 0, hdr_buf_size,
			     kaddr, 0, PAGE_SIZE,
			     hdr_buf_size);
		kunmap_local(kaddr);
		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page_index %d, page %p, count %d\n",
			  i, page, page_ref_count(page));

		SSDFS_DBG("PAGE DUMP: cur_page %u\n",
			  i);
		kaddr = kmap_local_page(page);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
		kunmap_local(kaddr);
		SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

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

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("byte_offset %u, page_offset %u, "
				  "new_log_start_page %u\n",
				  byte_offset, page_offset, *new_log_start_page);
			SSDFS_DBG("log_bytes %u\n", env->log_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

			if (*new_log_start_page < page_offset) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("correct new log start page: "
					  "old value %u, new value %u\n",
					  *new_log_start_page,
					  page_offset);
#endif /* CONFIG_SSDFS_DEBUG */
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
			pebi->peb_create_time =
				le64_to_cpu(seg_hdr->peb_create_time);
			pebi->current_log.last_log_time =
				le64_to_cpu(seg_hdr->timestamp);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("seg %llu, peb %llu, "
				  "peb_create_time %llx, last_log_time %llx\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  pebi->peb_create_time,
				  pebi->current_log.last_log_time);

			BUG_ON(pebi->peb_create_time >
				pebi->current_log.last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

			goto finish_last_log_search;
		} else if (is_ssdfs_partial_log_header_magic_valid(magic)) {
			u32 flags;

			pl_hdr = SSDFS_PLH(env->log_hdr);

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

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("byte_offset %u, "
					  "new_log_start_page %u\n",
					  byte_offset, *new_log_start_page);
#endif /* CONFIG_SSDFS_DEBUG */

				*new_log_start_page =
					(u16)(byte_offset / fsi->pagesize);
				env->log_bytes =
					le32_to_cpu(pl_hdr->log_bytes);

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("log_bytes %u\n", env->log_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

				continue;
			} else if (flags & SSDFS_LOG_HAS_FOOTER) {
				/* last partial log */

				env->log_bytes =
					le32_to_cpu(pl_hdr->log_bytes);

				byte_offset = i * fsi->pagesize;
				byte_offset += env->log_bytes;
				byte_offset += fsi->pagesize - 1;
				page_offset = byte_offset / fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("byte_offset %u, page_offset %u, "
					  "new_log_start_page %u\n",
					  byte_offset, page_offset, *new_log_start_page);
				SSDFS_DBG("log_bytes %u\n", env->log_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

				if (*new_log_start_page < page_offset) {
#ifdef CONFIG_SSDFS_DEBUG
					SSDFS_DBG("correct new log start page: "
						  "old value %u, "
						  "new value %u\n",
						  *new_log_start_page,
						  page_offset);
#endif /* CONFIG_SSDFS_DEBUG */
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
				pebi->peb_create_time =
					le64_to_cpu(pl_hdr->peb_create_time);
				pebi->current_log.last_log_time =
					le64_to_cpu(pl_hdr->timestamp);

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("seg %llu, peb %llu, "
					  "peb_create_time %llx, last_log_time %llx\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  pebi->peb_create_time,
					  pebi->current_log.last_log_time);

				BUG_ON(pebi->peb_create_time >
					pebi->current_log.last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

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
				SSDFS_DBG("byte_offset %u, page_offset %u, "
					  "new_log_start_page %u\n",
					  byte_offset, page_offset, *new_log_start_page);
				SSDFS_DBG("log_bytes %u\n", env->log_bytes);

				BUG_ON(page_offset >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

				*new_log_start_page = (u16)page_offset;
				env->log_offset = (u16)i;
				pebi->peb_create_time =
					le64_to_cpu(pl_hdr->peb_create_time);
				pebi->current_log.last_log_time =
					le64_to_cpu(pl_hdr->timestamp);

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("seg %llu, peb %llu, "
					  "peb_create_time %llx, last_log_time %llx\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  pebi->peb_create_time,
					  pebi->current_log.last_log_time);

				BUG_ON(pebi->peb_create_time >
					pebi->current_log.last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

				goto finish_last_log_search;
			}
		} else if (__is_ssdfs_log_footer_magic_valid(magic)) {
			footer = SSDFS_LF(env->footer);

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON((i + 1) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

			byte_offset = (i + 1) * fsi->pagesize;
			byte_offset += fsi->pagesize - 1;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("byte_offset %u, new_log_start_page %u\n",
				  byte_offset, *new_log_start_page);
#endif /* CONFIG_SSDFS_DEBUG */

			*new_log_start_page =
				(u16)(byte_offset / fsi->pagesize);
			env->log_bytes =
				le32_to_cpu(footer->log_bytes);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log_bytes %u\n", env->log_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

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

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "new_log_start_page %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  *new_log_start_page);
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

	SSDFS_DBG("log_offset %u, log_pages %u\n",
		  env->log_offset, env->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

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
			ssdfs_memcpy_from_page(env->footer, 0, footer_size,
						page, 0, PAGE_SIZE,
						footer_size);

			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
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
			ssdfs_memcpy_from_page(env->footer, 0, footer_size,
						page, 0, PAGE_SIZE,
						footer_size);

			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

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
		ssdfs_memcpy_from_page(env->log_hdr, 0, hdr_buf_size,
					page, 0, PAGE_SIZE,
					hdr_buf_size);

		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
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

			kaddr = kmap_local_page(page);
			err = ssdfs_aligned_read_buffer(fsi, pebi->peb_id,
							cur_page * PAGE_SIZE,
							(u8 *)kaddr,
							PAGE_SIZE,
							&read_bytes);
			kunmap_local(kaddr);

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
			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
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
 * %-ENOENT     - blk2off table's descriptor is absent.
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
			SSDFS_DBG("log hasn't blk2off table\n");
			return -ENOENT;
		}

		*desc = &env->footer->desc_array[SSDFS_OFF_TABLE_INDEX];
	} else
		*desc = &seg_hdr->desc_array[SSDFS_OFF_TABLE_INDEX];

	return 0;
}

/*
 * ssdfs_get_segment_header_blk_desc_tbl_desc() - get blk desc tbl's descriptor
 * @pebi: pointer on PEB object
 * @env: init environment [in]
 * @desc: blk desc tbl's descriptor [out]
 *
 * This function tries to extract the block descriptor table's descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 * %-ENOENT     - block descriptor table's descriptor is absent.
 */
static inline
int ssdfs_get_segment_header_blk_desc_tbl_desc(struct ssdfs_peb_info *pebi,
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

	if (!ssdfs_log_has_blk_desc_chain(seg_hdr)) {
		SSDFS_DBG("log hasn't block descriptor table\n");
		return -ENOENT;
	} else
		*desc = &seg_hdr->desc_array[SSDFS_BLK_DESC_AREA_INDEX];

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
 * %-ENOENT     - blk2off table's descriptor is absent.
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
			SSDFS_DBG("log hasn't blk2off table\n");
			return -ENOENT;
		}

		if (!ssdfs_log_footer_has_offset_table(env->footer)) {
			SSDFS_DBG("log hasn't blk2off table\n");
			return -ENOENT;
		}

		*desc = &env->footer->desc_array[SSDFS_OFF_TABLE_INDEX];
	} else
		*desc = &pl_hdr->desc_array[SSDFS_OFF_TABLE_INDEX];

	return 0;
}

/*
 * ssdfs_get_partial_header_blk_desc_tbl_desc() - get blk desc tbl's descriptor
 * @pebi: pointer on PEB object
 * @env: init environment [in]
 * @desc: blk desc tbl's descriptor [out]
 *
 * This function tries to extract the block descriptor table's descriptor.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 * %-ENOENT     - block descriptor table's descriptor is absent.
 */
static inline
int ssdfs_get_partial_header_blk_desc_tbl_desc(struct ssdfs_peb_info *pebi,
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

	if (!ssdfs_pl_has_blk_desc_chain(pl_hdr)) {
		SSDFS_DBG("log hasn't block descriptor table\n");
		return -ENOENT;
	} else
		*desc = &pl_hdr->desc_array[SSDFS_BLK_DESC_AREA_INDEX];

	return 0;
}

/*
 * ssdfs_pre_fetch_metadata_area() - pre-fetch metadata area
 * @pebi: pointer on PEB object
 * @desc: metadata area's descriptor
 *
 * This function tries to check the presence of metadata area
 * in the PEB's cache. Otherwise, it tries to read the metadata area
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
int ssdfs_pre_fetch_metadata_area(struct ssdfs_peb_info *pebi,
				  struct ssdfs_metadata_descriptor *desc)
{
	struct ssdfs_fs_info *fsi;
	struct page *page;
	void *kaddr;
	u32 bytes_off;
	u32 area_offset, area_size;
	u32 cur_page, page_start, page_end;
	size_t read_bytes;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !desc);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

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

			kaddr = kmap_local_page(page);
			err = ssdfs_aligned_read_buffer(fsi, pebi->peb_id,
							cur_page * PAGE_SIZE,
							(u8 *)kaddr,
							PAGE_SIZE,
							&read_bytes);
			flush_dcache_page(page);
			kunmap_local(kaddr);

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
			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}

	return err;
}

/*
 * ssdfs_read_blk2off_table_header() - read blk2off table header
 * @pebi: pointer on PEB object
 * @req: segment request
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
				    struct ssdfs_segment_request *req,
				    struct ssdfs_read_init_env *env)
{
	struct ssdfs_blk2off_table_header *hdr = NULL;
	size_t hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env || !env->log_hdr || !env->footer);

	SSDFS_DBG("seg %llu, peb %llu, read_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->t_init.read_off);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_unaligned_read_cache(pebi, req,
					 env->t_init.read_off, hdr_size,
					 &env->t_init.hdr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read table's header: "
			  "seg %llu, peb %llu, offset %u, size %zu, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  env->t_init.read_off, hdr_size, err);
		return err;
	}

	hdr = &env->t_init.hdr;

	if (le32_to_cpu(hdr->magic.common) != SSDFS_SUPER_MAGIC ||
	    le16_to_cpu(hdr->magic.key) != SSDFS_BLK2OFF_TABLE_HDR_MAGIC) {
		SSDFS_ERR("invalid magic of blk2off_table\n");
		return -EIO;
	}

	env->t_init.read_off += hdr_size;

	return 0;
}

/*
 * __ssdfs_read_blk2off_byte_stream() - read blk2off byte stream
 * @pebi: pointer on PEB object
 * @req: segment request
 * @frag_type: fragment type
 * @frag_offset: fragment offset
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
int __ssdfs_read_blk2off_byte_stream(struct ssdfs_peb_info *pebi,
				     struct ssdfs_segment_request *req,
				     int frag_type,
				     u32 frag_offset,
				     u32 read_bytes,
				     struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_content_stream *stream = NULL;
	struct page *page = NULL;
	void *kaddr;
	u32 diff;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env);

	SSDFS_DBG("seg %llu, peb %llu, frag_type %#x, "
		  "frag_offset %u, read_bytes %u, read_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  frag_type, frag_offset, read_bytes,
		  env->t_init.read_off);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	diff = env->t_init.read_off - env->t_init.area_offset;
	if (diff != frag_offset) {
		SSDFS_ERR("invalid fragment offset: "
			  "seg %llu, peb %llu, "
			  "area_offset %u, read_off %u, "
			  "frag_offset %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  env->t_init.area_offset,
			  env->t_init.read_off,
			  frag_offset);
		return -ERANGE;
	}

	switch (frag_type) {
	case SSDFS_BLK2OFF_EXTENT_DESC:
		stream = &env->t_init.extents;
		break;

	case SSDFS_BLK2OFF_DESC:
		stream = &env->t_init.descriptors;
		break;

	default:
		BUG();
	}

	if (read_bytes > PAGE_SIZE) {
		SSDFS_ERR("invalid size: read_bytes %u\n",
			  read_bytes);
		return -E2BIG;
	}

	page = ssdfs_page_vector_allocate(&stream->pvec);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		err = !page ? -ENOMEM : PTR_ERR(page);
		SSDFS_ERR("fail to add pagevec page: err %d\n",
			  err);
		return err;
	}

	ssdfs_lock_page(page);
	kaddr = kmap_local_page(page);
	err = ssdfs_unaligned_read_cache(pebi, req,
					 env->t_init.read_off, read_bytes,
					 (u8 *)kaddr);
	flush_dcache_page(page);
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);

	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, "
			  "size %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, env->t_init.read_off,
			  read_bytes, err);
		return err;
	}

	env->t_init.read_off += read_bytes;
	stream->write_off += PAGE_SIZE;
	stream->bytes_count += read_bytes;

	return 0;
}

/*
 * ssdfs_read_blk2off_pot_fragment() - read blk2off table's POT fragment
 * @pebi: pointer on PEB object
 * @req: segment request
 * @frag_type: fragment type
 * @frag_offset: fragment offset
 * @frag_size: fragment size
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
				    struct ssdfs_segment_request *req,
				    int frag_type,
				    u32 frag_offset,
				    u32 frag_size,
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

	SSDFS_DBG("seg %llu, peb %llu, frag_type %#x, "
		  "frag_offset %u, frag_size %u, read_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  frag_type, frag_offset, frag_size,
		  env->t_init.read_off);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	start_off = env->t_init.read_off;

	err = ssdfs_unaligned_read_cache(pebi, req,
					 start_off, hdr_size,
					 &hdr);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, "
			  "size %zu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, start_off,
			  hdr_size, err);
		return err;
	}

	if (le32_to_cpu(hdr.magic) != SSDFS_PHYS_OFF_TABLE_MAGIC) {
		SSDFS_ERR("invalid magic\n");
		return -EIO;
	}

	read_bytes = le32_to_cpu(hdr.byte_size);

	if (read_bytes != frag_size) {
		SSDFS_ERR("corrupted fragment: "
			  "read_bytes %u != frag_size %u\n",
			  read_bytes, frag_size);
		return -EIO;
	}

	err = __ssdfs_read_blk2off_byte_stream(pebi, req, frag_type,
						frag_offset, read_bytes,
						env);
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
 * ssdfs_read_blk2off_compressed_byte_stream() - read compressed byte stream
 * @pebi: pointer on PEB object
 * @req: segment request
 * @frag: pointer on fragment descriptor
 * @env: init environment [in|out]
 * @processed_bytes: number of processed bytes [in|out]
 *
 * This function tries to read blk2off table's compressed stream.
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
int ssdfs_read_blk2off_compressed_byte_stream(struct ssdfs_peb_info *pebi,
					      struct ssdfs_segment_request *req,
					      struct ssdfs_fragment_desc *frag,
					      struct ssdfs_read_init_env *env,
					      u32 *processed_bytes)
{
	struct ssdfs_content_stream *stream = NULL;
	struct ssdfs_phys_offset_table_header *hdr;
	struct page *page = NULL;
	void *kaddr;
	u32 area_offset;
	u32 frag_offset;
	u16 frag_compr_size;
	u16 frag_uncompr_size;
	u32 magic;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!frag || !env || !processed_bytes);

	SSDFS_DBG("seg %llu, peb %llu, frag_type %#x, "
		  "frag_offset %u, compr_size %u, "
		  "uncompr_size %u, read_off %u, "
		  "processed_bytes %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  frag->type,
		  le32_to_cpu(frag->offset),
		  le16_to_cpu(frag->compr_size),
		  le16_to_cpu(frag->uncompr_size),
		  env->t_init.read_off,
		  *processed_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (frag->type) {
	case SSDFS_BLK2OFF_EXTENT_DESC_ZLIB:
	case SSDFS_BLK2OFF_EXTENT_DESC_LZO:
		stream = &env->t_init.extents;
		page = ssdfs_page_vector_allocate(&stream->pvec);
		if (unlikely(IS_ERR_OR_NULL(page))) {
			err = !page ? -ENOMEM : PTR_ERR(page);
			SSDFS_ERR("fail to add pagevec page: err %d\n",
				  err);
			return err;
		}
		break;

	case SSDFS_BLK2OFF_DESC_ZLIB:
	case SSDFS_BLK2OFF_DESC_LZO:
		stream = &env->t_init.descriptors;
		page = ssdfs_page_vector_allocate(&stream->pvec);
		if (unlikely(IS_ERR_OR_NULL(page))) {
			err = !page ? -ENOMEM : PTR_ERR(page);
			SSDFS_ERR("fail to add pagevec page: err %d\n",
				  err);
			return err;
		}
		break;

	default:
		SSDFS_ERR("unexpected fragment's type %#x\n",
			  frag->type);
		return -EIO;
	}

	area_offset = env->t_init.area_offset;
	frag_offset = le32_to_cpu(frag->offset);
	frag_compr_size = le16_to_cpu(frag->compr_size);
	frag_uncompr_size = le16_to_cpu(frag->uncompr_size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_lock_page(page);
	kaddr = kmap_local_page(page);
	err = __ssdfs_decompress_blk2off_fragment(pebi, req, frag,
						  area_offset,
						  kaddr, PAGE_SIZE);
	hdr = (struct ssdfs_phys_offset_table_header *)kaddr;
	magic = le32_to_cpu(hdr->magic);
	flush_dcache_page(page);
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);

	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, "
			  "size %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, env->t_init.read_off,
			  frag_uncompr_size, err);
		return err;
	}

	switch (frag->type) {
	case SSDFS_BLK2OFF_DESC_ZLIB:
	case SSDFS_BLK2OFF_DESC_LZO:
		if (magic != SSDFS_PHYS_OFF_TABLE_MAGIC) {
			SSDFS_ERR("invalid magic\n");
			return -EIO;
		}
		break;

	default:
		/* do nothing */
		break;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!stream);
#endif /* CONFIG_SSDFS_DEBUG */

	env->t_init.read_off += frag_compr_size;
	stream->write_off += PAGE_SIZE;
	stream->bytes_count += frag_uncompr_size;
	*processed_bytes += frag_compr_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("compr_size %u, uncompr_size %u, "
		  "processed_bytes %u\n",
		  frag_compr_size, frag_uncompr_size,
		  *processed_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * __ssdfs_read_blk2off_compressed_fragment() - read compressed fragment
 * @pebi: pointer on PEB object
 * @req: segment request
 * @env: init environment [in|out]
 * @processed_bytes: number of processed bytes [in|out]
 *
 * This function tries to read blk2off table's Physical Offsets Table
 * compressed fragment.
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
int __ssdfs_read_blk2off_compressed_fragment(struct ssdfs_peb_info *pebi,
					     struct ssdfs_segment_request *req,
					     struct ssdfs_read_init_env *env,
					     u32 *processed_bytes)
{
	struct ssdfs_fragment_desc *frag;
	size_t hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	u32 area_offset;
	u32 frag_offset;
	u16 fragments_count;
	u16 frag_uncompr_size;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env || !processed_bytes);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "read_off %u, processed_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->t_init.read_off, *processed_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_read_blk2off_table_header(pebi, req, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read blk2off table header: "
			  "err %d\n", err);
		return err;
	}

	*processed_bytes += hdr_size;

	area_offset = env->t_init.area_offset;

	if (env->t_init.hdr.chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		SSDFS_ERR("corrupted chain header: "
			  "magic (expected %#x, found %#x)\n",
			  SSDFS_CHAIN_HDR_MAGIC,
			  env->t_init.hdr.chain_hdr.magic);
		return -EIO;
	}

	switch (env->t_init.hdr.chain_hdr.type) {
	case SSDFS_BLK2OFF_ZLIB_CHAIN_HDR:
	case SSDFS_BLK2OFF_LZO_CHAIN_HDR:
		/* expected type */
		break;

	default:
		SSDFS_ERR("unexpected chain header's type %#x\n",
			  env->t_init.hdr.chain_hdr.type);
		return -EIO;
	}

	fragments_count =
		le16_to_cpu(env->t_init.hdr.chain_hdr.fragments_count);

	for (i = 0; i < fragments_count; i++) {
		u32 padding = 0;

		frag = &env->t_init.hdr.blk[i];

		if (frag->magic != SSDFS_FRAGMENT_DESC_MAGIC) {
			SSDFS_ERR("corrupted fragment: "
				  "magic (expected %#x, found %#x)\n",
				  SSDFS_FRAGMENT_DESC_MAGIC,
				  frag->magic);
			return -EIO;
		}

		frag_offset = le32_to_cpu(frag->offset);
		frag_uncompr_size = le16_to_cpu(frag->uncompr_size);

		if (frag_offset < *processed_bytes) {
			SSDFS_ERR("corrupted fragment descriptor: "
				  "frag_offset %u < processed_bytes %u\n",
				  frag_offset, *processed_bytes);
			return -EIO;
		}

		padding = frag_offset - *processed_bytes;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("frag_offset %u, processed_bytes %u, "
			  "padding %u\n",
			  frag_offset, *processed_bytes,
			  padding);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (frag->type) {
		case SSDFS_BLK2OFF_EXTENT_DESC_ZLIB:
		case SSDFS_BLK2OFF_EXTENT_DESC_LZO:
		case SSDFS_BLK2OFF_DESC_ZLIB:
		case SSDFS_BLK2OFF_DESC_LZO:
			err = ssdfs_read_blk2off_compressed_byte_stream(pebi,
							    req, frag, env,
							    processed_bytes);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read compressed stream: "
					  "index %d, err %d\n",
					  i, err);
				return err;
			}

			*processed_bytes += padding;
			break;

		case SSDFS_BLK2OFF_EXTENT_DESC:
			err = __ssdfs_read_blk2off_byte_stream(pebi,
							req,
							frag->type,
							frag_offset,
							frag_uncompr_size,
							env);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read fragment: "
					  "seg %llu, peb %llu, index %d, "
					  "frag_offset %u, frag_size %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  i,
					  frag_offset,
					  frag_uncompr_size);
				return err;
			}

			*processed_bytes += frag_uncompr_size;
			*processed_bytes += padding;
			break;

		case SSDFS_BLK2OFF_DESC:
			err = ssdfs_read_blk2off_pot_fragment(pebi,
						      req,
						      frag->type,
						      frag_offset,
						      frag_uncompr_size,
						      env);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read fragment: "
					  "seg %llu, peb %llu, index %d, "
					  "frag_offset %u, frag_size %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  i,
					  frag_offset,
					  frag_uncompr_size);
				return err;
			}

			*processed_bytes += frag_uncompr_size;
			*processed_bytes += padding;
			break;

		case SSDFS_NEXT_TABLE_DESC:
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(i != SSDFS_NEXT_BLK2OFF_TBL_INDEX);
#endif /* CONFIG_SSDFS_DEBUG */

			env->t_init.read_off = area_offset + frag_offset;

			SSDFS_DBG("process next table descriptor: "
				  "offset %u\n",
				  env->t_init.read_off);
			return -EAGAIN;

		default:
			SSDFS_ERR("unexpected fragment's type %#x\n",
				  frag->type);
			return -EIO;
		}
	}

	return 0;
}

/*
 * ssdfs_read_blk2off_compressed_fragment() - read compressed fragment
 * @pebi: pointer on PEB object
 * @req: segment request
 * @read_bytes: size of fragment in bytes
 * @env: init environment [in|out]
 *
 * This function tries to read blk2off table's Physical Offsets Table
 * compressed fragment.
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
int ssdfs_read_blk2off_compressed_fragment(struct ssdfs_peb_info *pebi,
					   struct ssdfs_segment_request *req,
					   u32 read_bytes,
					   struct ssdfs_read_init_env *env)
{
	u32 processed_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env);

	SSDFS_DBG("seg %llu, peb %llu, read_bytes %u, "
		  "read_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  read_bytes, env->t_init.read_off);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		err = __ssdfs_read_blk2off_compressed_fragment(pebi, req, env,
							       &processed_bytes);
		if (err == -EAGAIN) {
			/*
			 * continue logic
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read compressed stream: "
				  "err %d\n", err);
			return err;
		}
	} while (err == -EAGAIN);

	if (processed_bytes != read_bytes) {
		SSDFS_ERR("corrupted compressed stream: "
			  "processed_bytes %u != read_bytes %u\n",
			  processed_bytes, read_bytes);
		return -ERANGE;
	}

	return err;
}

/*
 * __ssdfs_read_blk2off_fragment() - read blk2off table's log's fragment
 * @pebi: pointer on PEB object
 * @req: segment request
 * @env: init environment [in|out]
 * @processed_bytes: number of processed bytes [in|out]
 *
 * This function tries to read blk2off table's log's fragment.
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
int __ssdfs_read_blk2off_fragment(struct ssdfs_peb_info *pebi,
				  struct ssdfs_segment_request *req,
				  struct ssdfs_read_init_env *env,
				  u32 *processed_bytes)
{
	struct ssdfs_fragment_desc *frag;
	size_t hdr_size = sizeof(struct ssdfs_blk2off_table_header);
	u32 area_offset;
	u32 frag_offset;
	u16 fragments_count;
	u16 frag_size;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env || !processed_bytes);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "read_off %u, processed_bytes %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  env->t_init.read_off,
		  *processed_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_read_blk2off_table_header(pebi, req, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read blk2off table header: "
			  "err %d\n", err);
		return err;
	}

	*processed_bytes += hdr_size;

	area_offset = env->t_init.area_offset;

	if (env->t_init.hdr.chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		SSDFS_ERR("corrupted chain header: "
			  "magic (expected %#x, found %#x)\n",
			  SSDFS_CHAIN_HDR_MAGIC,
			  env->t_init.hdr.chain_hdr.magic);
		return -EIO;
	}

	switch (env->t_init.hdr.chain_hdr.type) {
	case SSDFS_BLK2OFF_CHAIN_HDR:
		/* expected type */
		break;

	default:
		SSDFS_ERR("unexpected chain header's type %#x\n",
			  env->t_init.hdr.chain_hdr.type);
		return -EIO;
	}

	fragments_count =
		le16_to_cpu(env->t_init.hdr.chain_hdr.fragments_count);

	for (i = 0; i < fragments_count; i++) {
		u32 padding = 0;

		frag = &env->t_init.hdr.blk[i];

		if (frag->magic != SSDFS_FRAGMENT_DESC_MAGIC) {
			SSDFS_ERR("corrupted fragment: "
				  "magic (expected %#x, found %#x)\n",
				  SSDFS_FRAGMENT_DESC_MAGIC,
				  frag->magic);
			return -EIO;
		}

		frag_offset = le32_to_cpu(frag->offset);
		frag_size = le16_to_cpu(frag->uncompr_size);

		if (frag_offset < *processed_bytes) {
			SSDFS_ERR("corrupted fragment descriptor: "
				  "frag_offset %u < processed_bytes %u\n",
				  frag_offset, *processed_bytes);
			return -EIO;
		}

		padding = frag_offset - *processed_bytes;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("frag_offset %u, processed_bytes %u, "
			  "padding %u\n",
			  frag_offset, *processed_bytes,
			  padding);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (frag->type) {
		case SSDFS_BLK2OFF_EXTENT_DESC:
			err = __ssdfs_read_blk2off_byte_stream(pebi,
								req,
								frag->type,
								frag_offset,
								frag_size,
								env);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read fragment: "
					  "seg %llu, peb %llu, index %d, "
					  "frag_offset %u, frag_size %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  i,
					  frag_offset,
					  frag_size);
				return err;
			}
			break;

		case SSDFS_BLK2OFF_DESC:
			err = ssdfs_read_blk2off_pot_fragment(pebi,
							      req,
							      frag->type,
							      frag_offset,
							      frag_size,
							      env);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read fragment: "
					  "seg %llu, peb %llu, index %d, "
					  "frag_offset %u, frag_size %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  i,
					  frag_offset,
					  frag_size);
				return err;
			}
			break;

		case SSDFS_NEXT_TABLE_DESC:
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(i != SSDFS_NEXT_BLK2OFF_TBL_INDEX);
#endif /* CONFIG_SSDFS_DEBUG */

			env->t_init.read_off = area_offset + frag_offset;

			SSDFS_DBG("process next table descriptor: "
				  "offset %u\n",
				  env->t_init.read_off);
			return -EAGAIN;

		default:
			SSDFS_ERR("unexpected fragment's type %#x\n",
				  frag->type);
			return -EIO;
		}

		*processed_bytes += frag_size;
		*processed_bytes += padding;
	}

	return err;
}

/*
 * ssdfs_read_blk2off_fragment() - read blk2off table's log's fragments
 * @pebi: pointer on PEB object
 * @req: segment request
 * @read_bytes: amount of bytes for reading
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
int ssdfs_read_blk2off_fragment(struct ssdfs_peb_info *pebi,
				struct ssdfs_segment_request *req,
				u32 read_bytes,
				struct ssdfs_read_init_env *env)
{
	u32 processed_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env);

	SSDFS_DBG("seg %llu, peb %llu, read_bytes %u, "
		  "read_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  read_bytes, env->t_init.read_off);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		err = __ssdfs_read_blk2off_fragment(pebi, req,
						    env, &processed_bytes);
		if (err == -EAGAIN) {
			/*
			 * continue logic
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read stream: "
				  "err %d\n", err);
			return err;
		}
	} while (err == -EAGAIN);

	if (processed_bytes != read_bytes) {
		SSDFS_ERR("corrupted stream: "
			  "processed_bytes %u != read_bytes %u\n",
			  processed_bytes, read_bytes);
		return -ERANGE;
	}

	return err;
}

/*
 * ssdfs_pre_fetch_blk2off_table_area() - pre-fetch blk2off table
 * @pebi: pointer on PEB object
 * @req: segment request
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
 * %-ENOENT     - blk2off table is absent.
 */
static
int ssdfs_pre_fetch_blk2off_table_area(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor *desc = NULL;
	struct page *page;
	u32 pages_off;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u16 flags;
	bool is_compressed = false;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

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
		ssdfs_memcpy_from_page(env->log_hdr, 0, hdr_buf_size,
					page, 0, PAGE_SIZE,
					hdr_buf_size);

		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
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

	if (err == -ENOENT) {
		SSDFS_DBG("blk2off table is absent\n");
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get descriptor: "
			  "err %d\n", err);
		return err;
	}

	if (!desc) {
		SSDFS_ERR("invalid descriptor pointer\n");
		return -ERANGE;
	}

	env->t_init.area_offset = le32_to_cpu(desc->offset);
	env->t_init.read_off = env->t_init.area_offset;
	env->t_init.extents.write_off = 0;
	env->t_init.descriptors.write_off = 0;

	err = ssdfs_pre_fetch_metadata_area(pebi, desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch a metadata area: "
			  "err %d\n", err);
		return err;
	}

	flags = le16_to_cpu(desc->check.flags);

	if ((flags & SSDFS_ZLIB_COMPRESSED) && (flags & SSDFS_LZO_COMPRESSED)) {
		SSDFS_ERR("invalid set of flags: "
			  "flags %#x\n",
			  flags);
		return -ERANGE;
	}

	is_compressed = (flags & SSDFS_ZLIB_COMPRESSED) ||
			(flags & SSDFS_LZO_COMPRESSED);

	if (is_compressed) {
		err = ssdfs_read_blk2off_compressed_fragment(pebi, req,
						      le32_to_cpu(desc->size),
						      env);
	} else {
		err = ssdfs_read_blk2off_fragment(pebi, req,
						  le32_to_cpu(desc->size),
						  env);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare block descriptor table: "
			  "err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_read_blk_desc_byte_stream() - read blk desc's byte stream
 * @pebi: pointer on PEB object
 * @req: segment request
 * @read_bytes: amount of bytes for reading
 * @env: init environment [in|out]
 *
 * This function tries to read blk desc table's byte stream.
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
int ssdfs_read_blk_desc_byte_stream(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req,
				    u32 read_bytes,
				    struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_page_vector *array;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env);

	SSDFS_DBG("seg %llu, peb %llu, read_bytes %u, "
		  "read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  read_bytes, env->bdt_init.read_off,
		  env->bdt_init.write_off);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	array = &env->bdt_init.array;

	while (read_bytes > 0) {
		struct page *page = NULL;
		void *kaddr;
		pgoff_t page_index;
		u32 capacity;
		u32 offset, bytes;

		page_index = env->bdt_init.write_off >> PAGE_SHIFT;
		capacity = ssdfs_page_vector_count(array);
		capacity <<= PAGE_SHIFT;

		if (env->bdt_init.write_off >= capacity) {
			if (ssdfs_page_vector_capacity(array) == 0) {
				/*
				 * Block descriptor table byte stream could be
				 * bigger than page vector capacity.
				 * As a result, not complete byte stream will
				 * read and initialization will be done only
				 * partially. The rest byte stream will be
				 * extracted and be used for initialization
				 * of request of particular logical block.
				 */
				SSDFS_DBG("pagevec is full\n");
				return 0;
			}

			page = ssdfs_page_vector_allocate(array);
			if (unlikely(IS_ERR_OR_NULL(page))) {
				err = !page ? -ENOMEM : PTR_ERR(page);
				SSDFS_ERR("fail to add pagevec page: err %d\n",
					  err);
				return err;
			}
		} else {
			page = env->bdt_init.array.pages[page_index];
			if (unlikely(!page)) {
				err = -ERANGE;
				SSDFS_ERR("fail to get page: err %d\n",
					  err);
				return err;
			}
		}

		offset = env->bdt_init.write_off % PAGE_SIZE;
		bytes = min_t(u32, read_bytes, PAGE_SIZE - offset);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("offset %u, bytes %u\n",
			  offset, bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_lock_page(page);
		kaddr = kmap_local_page(page);
		err = ssdfs_unaligned_read_cache(pebi, req,
						 env->bdt_init.read_off, bytes,
						 (u8 *)kaddr + offset);
		flush_dcache_page(page);
		kunmap_local(kaddr);
		ssdfs_unlock_page(page);

		if (unlikely(err)) {
			SSDFS_ERR("fail to read page: "
				  "seg %llu, peb %llu, offset %u, "
				  "size %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, env->bdt_init.read_off,
				  bytes, err);
			return err;
		}

		read_bytes -= bytes;
		env->bdt_init.read_off += bytes;
		env->bdt_init.write_off += bytes;
	};

	return 0;
}

/*
 * __ssdfs_read_blk_desc_compressed_byte_stream() - read blk desc's byte stream
 * @pebi: pointer on PEB object
 * @req: segment request
 * @env: init environment [in|out]
 * @processed_bytes: number of processed bytes [in|out]
 *
 * This function tries to read blk desc table's byte stream.
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
int __ssdfs_read_blk_desc_compressed_byte_stream(struct ssdfs_peb_info *pebi,
					     struct ssdfs_segment_request *req,
					     struct ssdfs_read_init_env *env,
					     u32 *processed_bytes)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_area_block_table table;
	struct ssdfs_fragment_desc *frag;
	struct page *page = NULL;
	void *kaddr;
	size_t tbl_size = sizeof(struct ssdfs_area_block_table);
	u32 area_offset;
	u32 frag_offset;
	u16 fragments_count;
	u16 frag_compr_size;
	u16 frag_uncompr_size;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  env->bdt_init.read_off,
		  env->bdt_init.write_off);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	area_offset = env->bdt_init.area_offset;

	err = ssdfs_unaligned_read_cache(pebi, req,
					 env->bdt_init.read_off,
					 tbl_size, &table);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read area block table: "
			  "table_offset %u, tbl_size %zu, err %d\n",
			  env->bdt_init.read_off, tbl_size, err);
		return err;
	}

	*processed_bytes += tbl_size;

	if (table.chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		SSDFS_ERR("corrupted area block table: "
			  "magic (expected %#x, found %#x)\n",
			  SSDFS_CHAIN_HDR_MAGIC,
			  table.chain_hdr.magic);
		return -EIO;
	}

	switch (table.chain_hdr.type) {
	case SSDFS_BLK_DESC_ZLIB_CHAIN_HDR:
	case SSDFS_BLK_DESC_LZO_CHAIN_HDR:
		/* expected type */
		break;

	default:
		SSDFS_ERR("unexpected area block table's type %#x\n",
			  table.chain_hdr.type);
		return -EIO;
	}

	fragments_count = le16_to_cpu(table.chain_hdr.fragments_count);

	for (i = 0; i < fragments_count; i++) {
		u32 padding = 0;

		frag = &table.blk[i];

		if (frag->magic != SSDFS_FRAGMENT_DESC_MAGIC) {
			SSDFS_ERR("corrupted area block table: "
				  "magic (expected %#x, found %#x)\n",
				  SSDFS_FRAGMENT_DESC_MAGIC,
				  frag->magic);
			return -EIO;
		}

		frag_offset = le32_to_cpu(frag->offset);
		frag_compr_size = le16_to_cpu(frag->compr_size);
		frag_uncompr_size = le16_to_cpu(frag->uncompr_size);

		if (frag_offset < *processed_bytes) {
			SSDFS_ERR("corrupted fragment descriptor: "
				  "frag_offset %u < processed_bytes %u\n",
				  frag_offset, *processed_bytes);
			return -EIO;
		}

		padding = frag_offset - *processed_bytes;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("frag_offset %u, processed_bytes %u, "
			  "padding %u\n",
			  frag_offset, *processed_bytes,
			  padding);
#endif /* CONFIG_SSDFS_DEBUG */

		switch (frag->type) {
		case SSDFS_DATA_BLK_DESC_ZLIB:
		case SSDFS_DATA_BLK_DESC_LZO:
			page = ssdfs_page_vector_allocate(&env->bdt_init.array);
			if (unlikely(IS_ERR_OR_NULL(page))) {
				err = !page ? -ENOMEM : PTR_ERR(page);
				SSDFS_ERR("fail to add pagevec page: err %d\n",
					  err);
				return err;
			}

			ssdfs_lock_page(page);
			kaddr = kmap_local_page(page);
			err = __ssdfs_decompress_blk2off_fragment(pebi,
								  req,
								  frag,
								  area_offset,
								  kaddr,
								  PAGE_SIZE);
			flush_dcache_page(page);
			kunmap_local(kaddr);
			ssdfs_unlock_page(page);

			if (unlikely(err)) {
				SSDFS_ERR("fail to read page: "
					  "seg %llu, peb %llu, offset %u, "
					  "size %u, err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id, env->bdt_init.read_off,
					  frag_uncompr_size, err);
				return err;
			}

			env->bdt_init.read_off += frag_compr_size;
			env->bdt_init.write_off += frag_uncompr_size;

			*processed_bytes += frag_compr_size;
			*processed_bytes += padding;
			break;

		case SSDFS_NEXT_TABLE_DESC:
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(i != SSDFS_NEXT_BLK_TABLE_INDEX);
#endif /* CONFIG_SSDFS_DEBUG */

			env->bdt_init.read_off = area_offset + frag_offset;

			SSDFS_DBG("process next table descriptor: "
				  "offset %u\n",
				  env->bdt_init.read_off);
			return -EAGAIN;

		default:
			SSDFS_ERR("unexpected fragment's type %#x\n",
				  frag->type);
			return -EIO;
		}
	}

	return 0;
}

/*
 * ssdfs_read_blk_desc_compressed_byte_stream() - read blk desc's byte stream
 * @pebi: pointer on PEB object
 * @req: segment request
 * @read_bytes: amount of bytes for reading
 * @env: init environment [in|out]
 *
 * This function tries to read blk desc table's byte stream.
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
int ssdfs_read_blk_desc_compressed_byte_stream(struct ssdfs_peb_info *pebi,
						struct ssdfs_segment_request *req,
						u32 read_bytes,
						struct ssdfs_read_init_env *env)
{
	u32 processed_bytes = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env);

	SSDFS_DBG("seg %llu, peb %llu, read_bytes %u, "
		  "read_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  read_bytes, env->bdt_init.read_off);
#endif /* CONFIG_SSDFS_DEBUG */

	do {
		err = __ssdfs_read_blk_desc_compressed_byte_stream(pebi, req, env,
								&processed_bytes);
		if (err == -EAGAIN) {
			/*
			 * continue logic
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read compressed stream: "
				  "err %d\n", err);
			return err;
		}
	} while (err == -EAGAIN);

	if (processed_bytes != read_bytes) {
		SSDFS_ERR("corrupted compressed stream: "
			  "processed_bytes %u != read_bytes %u\n",
			  processed_bytes, read_bytes);
		return -ERANGE;
	}

	return err;
}

/*
 * ssdfs_pre_fetch_blk_desc_table_area() - pre-fetch blk desc table
 * @pebi: pointer on PEB object
 * @req: segment request
 * @env: init environment [in|out]
 *
 * This function tries to check the presence of blk desc table
 * in the PEB's cache. Otherwise, it tries to read the blk desc table
 * from the volume into the PEB's cache.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-EIO        - I/O error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENOENT     - blk desc table is absent.
 */
static
int ssdfs_pre_fetch_blk_desc_table_area(struct ssdfs_peb_info *pebi,
					struct ssdfs_segment_request *req,
					struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_metadata_descriptor *desc = NULL;
	struct page *page;
	u32 pages_off;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	pages_off = env->log_offset;
	env->bdt_init.area_offset = 0;
	env->bdt_init.read_off = 0;
	env->bdt_init.write_off = 0;

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
		ssdfs_memcpy_from_page(env->log_hdr, 0, hdr_buf_size,
					page, 0, PAGE_SIZE,
					hdr_buf_size);

		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	err = ssdfs_check_log_header(fsi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to check log header: "
			  "err %d\n", err);
		return err;
	}

	if (env->has_seg_hdr) {
		err = ssdfs_get_segment_header_blk_desc_tbl_desc(pebi, env,
								 &desc);
	} else {
		err = ssdfs_get_partial_header_blk_desc_tbl_desc(pebi, env,
								 &desc);
	}

	if (err == -ENOENT) {
		SSDFS_DBG("blk descriptor table is absent\n");
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to get descriptor: "
			  "err %d\n", err);
		return err;
	}

	if (!desc) {
		SSDFS_ERR("invalid descriptor pointer\n");
		return -ERANGE;
	}

	env->bdt_init.area_offset = le32_to_cpu(desc->offset);
	env->bdt_init.read_off = le32_to_cpu(desc->offset);

	err = ssdfs_pre_fetch_metadata_area(pebi, desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch a metadata area: "
			  "err %d\n", err);
		return err;
	}

	flags = le16_to_cpu(desc->check.flags);

	if ((flags & SSDFS_ZLIB_COMPRESSED) && (flags & SSDFS_LZO_COMPRESSED)) {
		SSDFS_ERR("invalid set of flags: "
			  "flags %#x\n",
			  flags);
		return -ERANGE;
	}

	if ((flags & SSDFS_ZLIB_COMPRESSED) || (flags & SSDFS_LZO_COMPRESSED)) {
		err = ssdfs_read_blk_desc_compressed_byte_stream(pebi, req,
						      le32_to_cpu(desc->size),
						      env);
	} else {
		u32 read_bytes = le32_to_cpu(desc->size);
		size_t area_tbl_size = sizeof(struct ssdfs_area_block_table);

		env->bdt_init.read_off += area_tbl_size;

		if (read_bytes <= area_tbl_size) {
			SSDFS_ERR("corrupted area blocks table: "
				  "read_bytes %u, area_tbl_size %zu\n",
				  read_bytes, area_tbl_size);
			return -EIO;
		}

		read_bytes -= area_tbl_size;

		err = ssdfs_read_blk_desc_byte_stream(pebi, req,
						      read_bytes, env);
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare block descriptor table: "
			  "err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_read_checked_block_bitmap_header() - read and check block bitmap header
 * @pebi: pointer on PEB object
 * @req: segment request
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
					   struct ssdfs_segment_request *req,
					   struct ssdfs_read_init_env *env)
{
	struct ssdfs_fs_info *fsi;
	struct page *page;
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

	SSDFS_DBG("seg %llu, peb %llu, log_offset %u, log_pages %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->log_offset, env->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	pages_off = env->log_offset;
	pebsize = fsi->pages_per_peb * fsi->pagesize;

	page = ssdfs_page_array_get_page_locked(&pebi->cache, pages_off);
	if (IS_ERR_OR_NULL(page)) {
		SSDFS_ERR("fail to read checked segment header: "
			  "peb %llu\n", pebi->peb_id);
		return -ERANGE;
	} else {
		ssdfs_memcpy_from_page(env->log_hdr, 0, hdr_buf_size,
					page, 0, PAGE_SIZE,
					hdr_buf_size);

		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
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

	err = ssdfs_unaligned_read_cache(pebi, req,
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

#ifdef CONFIG_SSDFS_DEBUG
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
#endif /* CONFIG_SSDFS_DEBUG */

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
 * @req: segment request
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
				    struct ssdfs_segment_request *req,
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
	u16 last_free_blk;
	u32 bmap_bytes = 0;
	u32 bmap_pages = 0;
	u32 pages_count;
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
	BUG_ON(ssdfs_page_vector_count(&env->b_init.array) != 0);

	SSDFS_DBG("seg %llu, peb %llu, log_offset %u, log_pages %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->log_offset, env->log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

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

	err = ssdfs_unaligned_read_cache(pebi, req,
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

	cdata_buf = ssdfs_read_kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!cdata_buf) {
		SSDFS_ERR("fail to allocate cdata_buf\n");
		return -ENOMEM;
	}

	frag_hdr = env->b_init.frag_hdr;

	frag_array = (struct ssdfs_fragment_desc *)((u8 *)frag_hdr + hdr_size);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("BLOCK BITMAP FRAGMENT HEADER: "
		  "peb_index %u, sequence_id %u, flags %#x, "
		  "type %#x, last_free_blk %u, "
		  "metadata_blks %u, invalid_blks %u\n",
		  le16_to_cpu(frag_hdr->peb_index),
		  frag_hdr->sequence_id,
		  frag_hdr->flags,
		  frag_hdr->type,
		  le32_to_cpu(frag_hdr->last_free_blk),
		  le32_to_cpu(frag_hdr->metadata_blks),
		  le32_to_cpu(frag_hdr->invalid_blks));

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
#endif /* CONFIG_SSDFS_DEBUG */

	last_free_blk = le16_to_cpu(frag_hdr->last_free_blk);

	if (last_free_blk >= fsi->pages_per_peb) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"last_free_blk %u is invalid\n",
				last_free_blk);
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

	env->b_init.read_bytes += hdr_size + (fragments_count * desc_size);

	chain_compr_bytes = le32_to_cpu(frag_hdr->chain_hdr.compr_bytes);
	chain_uncompr_bytes = le32_to_cpu(frag_hdr->chain_hdr.uncompr_bytes);
	read_bytes = 0;
	uncompr_bytes = 0;

	if (last_free_blk == 0) {
		/* need to process as minumum one page */
		bmap_pages = 1;
	} else {
		bmap_bytes = BLK_BMAP_BYTES(last_free_blk);
		bmap_pages = (bmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
	}

	pages_count = min_t(u32, (u32)fragments_count, bmap_pages);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("last_free_blk %u, bmap_bytes %u, "
		  "bmap_pages %u, fragments_count %u, "
		  "pages_count %u\n",
		  last_free_blk, bmap_bytes,
		  bmap_pages, fragments_count,
		  pages_count);
#endif /* CONFIG_SSDFS_DEBUG */

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

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("FRAGMENT DESCRIPTOR: index %d, "
			  "offset %u, compr_size %u, uncompr_size %u, "
			  "checksum %#x, sequence_id %u, magic %#x, "
			  "type %#x, flags %#x\n",
			  i,
			  le32_to_cpu(frag_desc->offset),
			  le16_to_cpu(frag_desc->compr_size),
			  le16_to_cpu(frag_desc->uncompr_size),
			  le32_to_cpu(frag_desc->checksum),
			  frag_desc->sequence_id,
			  frag_desc->magic,
			  frag_desc->type,
			  frag_desc->flags);
#endif /* CONFIG_SSDFS_DEBUG */

		if (i >= pages_count) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("account fragment bytes: "
				  "i %d, pages_count %u\n",
				  i, pages_count);
#endif /* CONFIG_SSDFS_DEBUG */
			goto account_fragment_bytes;
		}

		page = ssdfs_page_vector_allocate(&env->b_init.array);
		if (unlikely(IS_ERR_OR_NULL(page))) {
			err = !page ? -ENOMEM : PTR_ERR(page);
			SSDFS_ERR("fail to add pagevec page: "
				  "sequence_id %u, "
				  "fragments count %u, err %d\n",
				  sequence_id, fragments_count, err);
			goto fail_read_blk_bmap;
		}

		ssdfs_lock_page(page);
		err = ssdfs_read_checked_fragment(pebi, req, area_offset,
						  sequence_id,
						  frag_desc,
						  cdata_buf, page);
		ssdfs_unlock_page(page);

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

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("FRAG ARRAY DUMP: \n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     frag_array,
					     fragments_count * desc_size);
			SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

			goto fail_read_blk_bmap;
		}

account_fragment_bytes:
		read_bytes += le16_to_cpu(frag_desc->compr_size);
		uncompr_bytes += le16_to_cpu(frag_desc->uncompr_size);
		env->b_init.read_bytes += le16_to_cpu(frag_desc->compr_size);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("last_free_blk %u, metadata_blks %u, invalid_blks %u\n",
		  le16_to_cpu(frag_hdr->last_free_blk),
		  le16_to_cpu(frag_hdr->metadata_blks),
		  le16_to_cpu(frag_hdr->invalid_blks));
#endif /* CONFIG_SSDFS_DEBUG */

fail_read_blk_bmap:
	ssdfs_read_kfree(cdata_buf);
	return err;
}

/*
 * ssdfs_init_block_bitmap_fragment() - init block bitmap fragment
 * @pebi: pointer on PEB object
 * @req: segment request
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
				     struct ssdfs_segment_request *req,
				     struct ssdfs_read_init_env *env)
{
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	u64 cno;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!env || !env->log_hdr || !env->footer);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "log_offset %u, log_pages %u, "
		  "fragment_index %d, read_bytes %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  env->log_offset, env->log_pages,
		  env->b_init.fragment_index,
		  env->b_init.read_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_page_vector_init(&env->b_init.array);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init page vector: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		goto fail_init_blk_bmap_fragment;
	}

	err = ssdfs_read_checked_block_bitmap(pebi, req, env);
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
						  &env->b_init.array,
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
	ssdfs_page_vector_release(&env->b_init.array);

	return err;
}

/*
 * ssdfs_correct_zone_block_bitmap() - set all migrated blocks as invalidated
 * @pebi: pointer on PEB object
 *
 * This function tries to mark all migrated blocks as
 * invalidated for the case of source zone. Actually, invalidated
 * extents will be added into the queue. Invalidation operation
 * happens after complete intialization of segment object.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENOMEM     - fail to allocate memory.
 * %-EIO        - I/O error.
 */
static
int ssdfs_correct_zone_block_bitmap(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_invextree_info *invextree;
	struct ssdfs_shared_extents_tree *shextree;
	struct ssdfs_btree_search *search;
	struct ssdfs_raw_extent extent;
	struct ssdfs_raw_extent *found;
#ifdef CONFIG_SSDFS_DEBUG
	size_t item_size = sizeof(struct ssdfs_raw_extent);
#endif /* CONFIG_SSDFS_DEBUG */
	u32 logical_blk = 0;
	u32 len;
	u32 count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebi->pebc->parent_si;
	fsi = si->fsi;
	len = fsi->pages_per_seg;

	invextree = fsi->invextree;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!invextree);
#endif /* CONFIG_SSDFS_DEBUG */

	shextree = fsi->shextree;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!shextree);
#endif /* CONFIG_SSDFS_DEBUG */

	search = ssdfs_btree_search_alloc();
	if (!search) {
		SSDFS_ERR("fail to allocate btree search object\n");
		return -ENOMEM;
	}

	do {
		extent.seg_id = cpu_to_le64(si->seg_id);
		extent.logical_blk = cpu_to_le32(logical_blk);
		extent.len = cpu_to_le32(len);

		ssdfs_btree_search_init(search);
		err = ssdfs_invextree_find(invextree, &extent, search);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to find invalidated extents: "
				  "seg_id %llu, logical_blk %u, len %u\n",
				  si->seg_id, logical_blk, len);
#endif /* CONFIG_SSDFS_DEBUG */
			break;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find invalidated extents: "
				  "seg_id %llu, logical_blk %u, len %u\n",
				  si->seg_id, logical_blk, len);
			goto finish_correct_zone_block_bmap;
		}

		count = search->result.items_in_buffer;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!search->result.buf);
		BUG_ON(count == 0);
		BUG_ON((count * item_size) != search->result.buf_size);
#endif /* CONFIG_SSDFS_DEBUG */

		for (i = 0; i < count; i++) {
			found = (struct ssdfs_raw_extent *)search->result.buf;
			found += i;

			err = ssdfs_shextree_add_pre_invalid_extent(shextree,
						SSDFS_INVALID_EXTENTS_BTREE_INO,
						found);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add pre-invalid extent: "
					  "seg_id %llu, logical_blk %u, "
					  "len %u, err %d\n",
					  le64_to_cpu(found->seg_id),
					  le32_to_cpu(found->logical_blk),
					  le32_to_cpu(found->len),
					  err);
				goto finish_correct_zone_block_bmap;
			}
		}

		found = (struct ssdfs_raw_extent *)search->result.buf;
		found += count - 1;

		logical_blk = le32_to_cpu(found->logical_blk) +
				le32_to_cpu(found->len);

		if (logical_blk >= fsi->pages_per_seg)
			len = 0;
		else
			len = fsi->pages_per_seg - logical_blk;
	} while (len > 0);

	if (err == -ENODATA) {
		/* all extents have been processed */
		err = 0;
	}

finish_correct_zone_block_bmap:
	ssdfs_btree_search_free(search);
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
	int sequence_id = 0;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env || !req);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

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

	err = ssdfs_read_checked_block_bitmap_header(pebi, req, env);
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
		err = ssdfs_init_block_bitmap_fragment(pebi, req, env);
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

	if (fsi->is_zns_device &&
	    is_ssdfs_peb_containing_user_data(pebi->pebc)) {
		err = ssdfs_correct_zone_block_bitmap(pebi);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct zone's block bitmap: "
				  "seg %llu, peb %llu, peb_index %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, pebi->peb_index,
				  err);
			goto fail_init_using_blk_bmap;
		}
	}

	BUG_ON(new_log_start_page >= U16_MAX);

	if (env->has_seg_hdr) {
		/* first log */
		sequence_id = 0;
	} else {
		pl_hdr = SSDFS_PLH(env->log_hdr);
		sequence_id = le32_to_cpu(pl_hdr->sequence_id);
	}

	BUG_ON((sequence_id + 1) >= INT_MAX);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("new_log_start_page %u\n", new_log_start_page);
#endif /* CONFIG_SSDFS_DEBUG */

	if (new_log_start_page < fsi->pages_per_peb) {
		u16 free_pages;
		u16 min_log_pages;

		/*
		 * Set the value of log's start page
		 * by temporary value. It needs for
		 * estimation of min_partial_log_pages.
		 */
		ssdfs_peb_current_log_lock(pebi);
		pebi->current_log.start_page = new_log_start_page;
		ssdfs_peb_current_log_unlock(pebi);

		free_pages = new_log_start_page % pebi->log_pages;
		free_pages = pebi->log_pages - free_pages;
		min_log_pages = ssdfs_peb_estimate_min_partial_log_pages(pebi);
		sequence_id++;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free_pages %u, min_log_pages %u, "
			  "new_log_start_page %u\n",
			  free_pages, min_log_pages,
			  new_log_start_page);
#endif /* CONFIG_SSDFS_DEBUG */

		if (free_pages == pebi->log_pages) {
			/* start new full log */
			sequence_id = 0;
		} else if (free_pages < min_log_pages) {
			SSDFS_WARN("POTENTIAL HOLE: "
				   "seg %llu, peb %llu, "
				   "peb_index %u, start_page %u, "
				   "free_pages %u, min_log_pages %u, "
				   "new_log_start_page %u\n",
				   pebi->pebc->parent_si->seg_id,
				   pebi->peb_id, pebi->peb_index,
				   new_log_start_page,
				   free_pages, min_log_pages,
				   new_log_start_page + free_pages);

#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */

			new_log_start_page += free_pages;
			free_pages = pebi->log_pages;
			sequence_id = 0;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free_pages %u, min_log_pages %u, "
			  "new_log_start_page %u\n",
			  free_pages, min_log_pages,
			  new_log_start_page);
#endif /* CONFIG_SSDFS_DEBUG */

		bytes_count = le32_to_cpu(env->b_init.bmap_hdr->bytes_count);
		ssdfs_peb_current_log_init(pebi, free_pages,
					   new_log_start_page,
					   sequence_id,
					   bytes_count);
	} else {
		sequence_id = 0;
		ssdfs_peb_current_log_init(pebi,
					   0,
					   new_log_start_page,
					   sequence_id,
					   U32_MAX);
	}

fail_init_using_blk_bmap:
	if (unlikely(err))
		goto fail_init_using_peb;

	err = ssdfs_pre_fetch_blk2off_table_area(pebi, req, env);
	if (err == -ENOENT) {
		SSDFS_DBG("blk2off table's fragment is absent\n");
		return 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch blk2off_table area: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log_offset, err);
		goto fail_init_using_peb;
	}

	err = ssdfs_pre_fetch_blk_desc_table_area(pebi, req, env);
	if (err == -ENOENT) {
		SSDFS_DBG("blk desc table's fragment is absent\n");
		/* continue logic -> process free extents */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch blk desc table area: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log_offset, err);
		goto fail_init_using_peb;
	}

	if (env->has_seg_hdr) {
		seg_hdr = SSDFS_SEG_HDR(env->log_hdr);
		cno = le64_to_cpu(seg_hdr->cno);
	} else {
		pl_hdr = SSDFS_PLH(env->log_hdr);
		cno = le64_to_cpu(pl_hdr->cno);
	}

	err = ssdfs_blk2off_table_partial_init(si->blk2off_table, env,
						pebi->peb_index,
						pebi->peb_id, cno);
	if (unlikely(err)) {
		SSDFS_ERR("fail to start initialization of offset table: "
			  "seg %llu, peb %llu, err %d\n",
			  si->seg_id, pebi->peb_id, err);
		goto fail_init_using_peb;
	}

fail_init_using_peb:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

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

	err = ssdfs_read_checked_block_bitmap_header(pebi, req, env);
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
		err = ssdfs_init_block_bitmap_fragment(pebi, req, env);
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

	if (fsi->is_zns_device &&
	    is_ssdfs_peb_containing_user_data(pebi->pebc)) {
		err = ssdfs_correct_zone_block_bitmap(pebi);
		if (unlikely(err)) {
			SSDFS_ERR("fail to correct zone's block bitmap: "
				  "seg %llu, peb %llu, peb_index %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, pebi->peb_index,
				  err);
			goto fail_init_used_blk_bmap;
		}
	}

	ssdfs_peb_current_log_init(pebi, 0, fsi->pages_per_peb, 0, U32_MAX);

fail_init_used_blk_bmap:
	if (unlikely(err))
		goto fail_init_used_peb;

	err = ssdfs_pre_fetch_blk2off_table_area(pebi, req, env);
	if (err == -ENOENT) {
		SSDFS_DBG("blk2off table's fragment is absent\n");
		return 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch blk2off_table area: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log_offset, err);
		goto fail_init_used_peb;
	}

	err = ssdfs_pre_fetch_blk_desc_table_area(pebi, req, env);
	if (err == -ENOENT) {
		SSDFS_DBG("blk desc table's fragment is absent\n");
		/* continue logic -> process free extents */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch blk desc table area: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log_offset, err);
		goto fail_init_used_peb;
	}

	if (env->has_seg_hdr) {
		seg_hdr = SSDFS_SEG_HDR(env->log_hdr);
		cno = le64_to_cpu(seg_hdr->cno);
	} else {
		pl_hdr = SSDFS_PLH(env->log_hdr);
		cno = le64_to_cpu(pl_hdr->cno);
	}

	err = ssdfs_blk2off_table_partial_init(si->blk2off_table, env,
						pebi->peb_index,
						pebi->peb_id, cno);
	if (unlikely(err)) {
		SSDFS_ERR("fail to start initialization of offset table: "
			  "seg %llu, peb %llu, err %d\n",
			  si->seg_id, pebi->peb_id, err);
		goto fail_init_used_peb;
	}

fail_init_used_peb:
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */
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
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (!pebi) {
		SSDFS_WARN("source PEB is NULL\n");
		err = -ERANGE;
		goto finish_src_init_using_metadata_state;
	}

	err = ssdfs_prepare_read_init_env(&pebi->env, fsi->pages_per_peb);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init read environment: err %d\n",
			  err);
		goto finish_src_init_using_metadata_state;
	}

	err = ssdfs_peb_init_using_metadata_state(pebi, &pebi->env, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init using metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_src_init_using_metadata_state;
	}

	id1 = pebi->env.cur_migration_id;

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
	ssdfs_destroy_init_env(&pebi->env);
	up_read(&pebc->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	down_read(&pebc->lock);

	pebi = pebc->dst_peb;
	if (!pebi) {
		SSDFS_WARN("destination PEB is NULL\n");
		err = -ERANGE;
		goto finish_dst_init_using_metadata_state;
	}

	err = ssdfs_prepare_read_init_env(&pebi->env, fsi->pages_per_peb);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init read environment: err %d\n",
			  err);
		goto finish_dst_init_using_metadata_state;
	}

	err = ssdfs_peb_init_using_metadata_state(pebi, &pebi->env, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init using metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_dst_init_using_metadata_state;
	}

	id1 = pebi->env.cur_migration_id;

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

		id1 = pebi->env.prev_migration_id;

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
	ssdfs_destroy_init_env(&pebi->env);
	up_read(&pebc->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (!pebi) {
		SSDFS_WARN("source PEB is NULL\n");
		err = -ERANGE;
		goto finish_src_init_used_metadata_state;
	}

	err = ssdfs_prepare_read_init_env(&pebi->env, fsi->pages_per_peb);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init read environment: err %d\n",
			  err);
		goto finish_src_init_used_metadata_state;
	}

	err = ssdfs_peb_init_used_metadata_state(pebi, &pebi->env, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init used metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_src_init_used_metadata_state;
	}

	id1 = pebi->env.cur_migration_id;

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
	ssdfs_destroy_init_env(&pebi->env);
	up_read(&pebc->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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
	int items_state;
	int id1, id2;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	down_read(&pebc->lock);

	pebi = pebc->dst_peb;
	if (!pebi) {
		SSDFS_WARN("destination PEB is NULL\n");
		err = -ERANGE;
		goto finish_dst_init_used_metadata_state;
	}

	err = ssdfs_prepare_read_init_env(&pebi->env, fsi->pages_per_peb);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init read environment: err %d\n",
			  err);
		goto finish_dst_init_used_metadata_state;
	}

	err = ssdfs_peb_init_used_metadata_state(pebi, &pebi->env, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init used metadata state: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		ssdfs_segment_blk_bmap_init_failed(&pebc->parent_si->blk_bmap,
						   pebc->peb_index);
		goto finish_dst_init_used_metadata_state;
	}

	id1 = pebi->env.cur_migration_id;

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

		id1 = pebi->env.prev_migration_id;

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
	ssdfs_destroy_init_env(&pebi->env);
	up_read(&pebc->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_peb_init_clean_metadata_state() - init clean PEB container
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This function tries to initialize clean PEB container.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_init_clean_metadata_state(struct ssdfs_peb_container *pebc,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	int items_state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = pebc->parent_si->fsi;
	si = pebc->parent_si;

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

	err = ssdfs_segment_blk_bmap_partial_clean_init(&si->blk_bmap,
							pebc->peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to initialize block bitmap: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		goto fail_init_clean_metadata_state;
	}

	err = ssdfs_blk2off_table_partial_clean_init(si->blk2off_table,
						     pebc->peb_index);
	if (unlikely(err)) {
		SSDFS_ERR("fail to initialize blk2off table: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		goto fail_init_clean_metadata_state;
	}

fail_init_clean_metadata_state:
	complete(&req->result.wait);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "log_offset %u, log_diff %d\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  env->log_offset, log_diff);
#endif /* CONFIG_SSDFS_DEBUG */

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

		kaddr = kmap_local_page(page);
		ssdfs_memcpy(env->log_hdr, 0, hdr_buf_size,
			     kaddr, 0, PAGE_SIZE,
			     hdr_buf_size);
		ssdfs_memcpy(env->footer, 0, hdr_buf_size,
			     kaddr, 0, PAGE_SIZE,
			     hdr_buf_size);
		kunmap_local(kaddr);
		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

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

			pl_hdr = SSDFS_PLH(env->log_hdr);

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
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("log_offset %u, log_bytes %u\n",
		  env->log_offset,
		  env->log_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

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
	u64 cno;
	unsigned long last_page_idx;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!req);

	SSDFS_DBG("seg %llu, peb %llu, log_diff %d, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, log_diff,
		  req->private.class,
		  req->private.cmd,
		  req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	blk2off_table = pebi->pebc->parent_si->blk2off_table;

	switch (atomic_read(&blk2off_table->state)) {
	case SSDFS_BLK2OFF_OBJECT_COMPLETE_INIT:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("blk2off table has been initialized: "
			  "peb_id %llu\n",
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;

	default:
		/* continue to init blk2off table */
		break;
	}

	err = ssdfs_prepare_read_init_env(&pebi->env, fsi->pages_per_peb);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init read environment: err %d\n",
			  err);
		return err;
	}

	last_page_idx = ssdfs_page_array_get_last_page_index(&pebi->cache);

	if (last_page_idx >= SSDFS_PAGE_ARRAY_INVALID_LAST_PAGE) {
		SSDFS_ERR("empty page array: last_page_idx %lu\n",
			  last_page_idx);
		return -ERANGE;
	}

	if (last_page_idx >= fsi->pages_per_peb) {
		SSDFS_ERR("corrupted page array: "
			  "last_page_idx %lu, fsi->pages_per_peb %u\n",
			  last_page_idx, fsi->pages_per_peb);
		return -ERANGE;
	}

	pebi->env.log_offset = (u32)last_page_idx + 1;

	do {
		err = ssdfs_find_prev_partial_log(fsi, pebi,
						  &pebi->env, log_diff);
		if (err == -ENOENT) {
			if (pebi->env.log_offset > 0) {
				SSDFS_ERR("fail to find prev log: "
					  "log_offset %u, err %d\n",
					  pebi->env.log_offset, err);
				goto finish_init_blk2off_table;
			} else {
				/* no previous log exists */
				err = 0;
				SSDFS_DBG("no previous log exists\n");
				goto finish_init_blk2off_table;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to find prev log: "
				  "log_offset %u, err %d\n",
				  pebi->env.log_offset, err);
			goto finish_init_blk2off_table;
		}

		err = ssdfs_pre_fetch_blk2off_table_area(pebi, req, &pebi->env);
		if (err == -ENOENT) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("blk2off table's fragment is absent: "
				  "seg %llu, peb %llu, log_offset %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  pebi->env.log_offset);
#endif /* CONFIG_SSDFS_DEBUG */
			goto try_next_log;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to pre-fetch blk2off_table area: "
				  "seg %llu, peb %llu, log_offset %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  pebi->env.log_offset,
				  err);
			goto finish_init_blk2off_table;
		}

		err = ssdfs_pre_fetch_blk_desc_table_area(pebi, req, &pebi->env);
		if (err == -ENOENT) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("blk desc table's fragment is absent: "
				  "seg %llu, peb %llu, log_offset %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  pebi->env.log_offset);
#endif /* CONFIG_SSDFS_DEBUG */
			goto try_next_log;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to pre-fetch blk desc table area: "
				  "seg %llu, peb %llu, log_offset %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  pebi->env.log_offset,
				  err);
			goto finish_init_blk2off_table;
		}

		if (pebi->env.has_seg_hdr) {
			struct ssdfs_segment_header *seg_hdr = NULL;

			seg_hdr = SSDFS_SEG_HDR(pebi->env.log_hdr);
			cno = le64_to_cpu(seg_hdr->cno);
		} else {
			struct ssdfs_partial_log_header *pl_hdr = NULL;

			pl_hdr = SSDFS_PLH(pebi->env.log_hdr);
			cno = le64_to_cpu(pl_hdr->cno);
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_id %llu, peb %llu, "
			  "env.log_offset %u\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  pebi->env.log_offset);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_blk2off_table_partial_init(blk2off_table,
						       &pebi->env,
						       pebi->peb_index,
						       pebi->peb_id,
						       cno);
		if (err == -EEXIST) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("blk2off table has been initialized: "
				  "peb_id %llu\n",
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			err = 0;
			goto finish_init_blk2off_table;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to start init of offset table: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			goto finish_init_blk2off_table;
		}

try_next_log:
		ssdfs_reinit_blk2off_table_init_env(&pebi->env.t_init);
		ssdfs_reinit_blk_desc_table_init_env(&pebi->env.bdt_init);
		log_diff = 0;
	} while (pebi->env.log_offset > 0);

finish_init_blk2off_table:
	ssdfs_destroy_init_env(&pebi->env);
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

	SSDFS_DBG("peb_id %llu, peb_index %u\n",
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

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
	struct ssdfs_fs_info *fsi;
	struct ssdfs_maptbl_peb_relation pebr;
	struct completion *end;
	struct ssdfs_maptbl_peb_descriptor *ptr;
	u64 leb_id;
	int log_diff = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !req);
	BUG_ON(!pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);

	SSDFS_DBG("peb_id %llu, peb_index %u\n",
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	leb_id = ssdfs_get_leb_id_for_peb_index(fsi,
				pebi->pebc->parent_si->seg_id,
				pebi->peb_index);
	if (leb_id == U64_MAX) {
		SSDFS_ERR("fail to convert PEB index into LEB ID: "
			  "seg %llu, peb_index %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_index);
		return -ERANGE;
	}

	err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id,
					   pebi->pebc->peb_type,
					   &pebr, &end);
	if (err == -EAGAIN) {
		err = SSDFS_WAIT_COMPLETION(end);
		if (unlikely(err)) {
			SSDFS_ERR("maptbl init failed: "
				  "err %d\n", err);
			return err;
		}

		err = ssdfs_maptbl_convert_leb2peb(fsi, leb_id,
						   pebi->pebc->peb_type,
						   &pebr, &end);
	}

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("LEB is not mapped: leb_id %llu\n",
			  leb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to convert LEB to PEB: "
			  "leb_id %llu, peb_type %#x, err %d\n",
			  leb_id, pebi->pebc->peb_type, err);
		return err;
	}

	ptr = &pebr.pebs[SSDFS_MAPTBL_MAIN_INDEX];

	if (ptr->peb_id != pebi->peb_id) {
		SSDFS_ERR("ptr->peb_id %llu != pebi->peb_id %llu\n",
			  ptr->peb_id, pebi->peb_id);
		return -ERANGE;
	}

	switch (ptr->state) {
	case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("ignore PEB: peb_id %llu, state %#x\n",
			  pebi->peb_id, ptr->state);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;

	default:
		/* continue logic */
		break;
	}

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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#else
	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

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
	u32 fragments_bytes_per_seg;
	u64 seg_logical_offset;
	u32 id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->fsi->segbmap);

	SSDFS_DBG("seg_id %llu, seg_index %u, "
		  "peb_index %u, logical_offset %llu\n",
		  pebc->parent_si->seg_id, seg_index,
		  pebc->peb_index, logical_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	segbmap = pebc->parent_si->fsi->segbmap;
	peb_index = pebc->peb_index;

	down_read(&segbmap->resize_lock);
	fragments_per_seg = segbmap->fragments_per_seg;
	fragment_size = segbmap->fragment_size;
	fragments_bytes_per_seg =
		(u32)segbmap->fragments_per_seg * fragment_size;
	up_read(&segbmap->resize_lock);

	seg_logical_offset = (u64)seg_index * fragments_bytes_per_seg;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_index %u, seg_logical_offset %llu, "
		  "logical_offset %llu\n",
		  seg_index, seg_logical_offset,
		  logical_offset);

	BUG_ON(seg_logical_offset > logical_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_offset -= seg_logical_offset;

	id = logical_offset / fragment_size;
	id += seg_index * fragments_per_seg;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_index %u, fragments_per_seg %u, "
		  "logical_offset %llu, fragment_size %u, "
		  "id %u\n",
		  seg_index, fragments_per_seg,
		  logical_offset, fragment_size,
		  id);

	BUG_ON(id >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u16)id;
}

/*
 * ssdfs_peb_define_segbmap_logical_extent() - define logical extent
 * @pebc: pointer on PEB container
 * @seg_index: index of segment in segment bitmap
 * @ptr: pointer on segbmap extent [out]
 */
static
void ssdfs_peb_define_segbmap_logical_extent(struct ssdfs_peb_container *pebc,
					     u16 seg_index,
					     struct ssdfs_segbmap_extent *ptr)
{
	struct ssdfs_segment_bmap *segbmap;
	u16 peb_index;
	u32 fragments_bytes_per_seg;
	u32 fragments_bytes_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->fsi->segbmap);
	BUG_ON(!ptr);

	SSDFS_DBG("seg_id %llu, seg_index %u, peb_index %u, extent %p\n",
		  pebc->parent_si->seg_id, seg_index,
		  pebc->peb_index, ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	segbmap = pebc->parent_si->fsi->segbmap;
	peb_index = pebc->peb_index;

	down_read(&segbmap->resize_lock);
	ptr->fragment_size = segbmap->fragment_size;
	fragments_bytes_per_seg =
		(u32)segbmap->fragments_per_seg * ptr->fragment_size;
	fragments_bytes_per_peb =
		(u32)segbmap->fragments_per_peb * ptr->fragment_size;
	ptr->logical_offset = fragments_bytes_per_seg * seg_index;
	ptr->logical_offset += fragments_bytes_per_peb * peb_index;
	ptr->data_size = segbmap->fragments_per_peb * ptr->fragment_size;
	up_read(&segbmap->resize_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("fragment_size %u, fragments_bytes_per_seg %u, "
		  "fragments_bytes_per_peb %u, seg_index %u, "
		  "peb_index %u, logical_offset %llu, data_size %u\n",
		  ptr->fragment_size,
		  fragments_bytes_per_seg,
		  fragments_bytes_per_peb,
		  seg_index, peb_index,
		  ptr->logical_offset,
		  ptr->data_size);
#endif /* CONFIG_SSDFS_DEBUG */
}

/*
 * ssdfs_peb_define_segbmap_logical_block() - convert offset into block number
 * @pebc: pointer on PEB container
 * @seg_index: index of segment in segment bitmap
 * @logical_offset: logical offset
 *
 * RETURN:
 * [success] - logical block number
 * [failure] - U16_MAX
 */
static
u16 ssdfs_peb_define_segbmap_logical_block(struct ssdfs_peb_container *pebc,
					   u16 seg_index,
					   u64 logical_offset)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_bmap *segbmap;
	u16 peb_index;
	u32 fragments_bytes_per_seg;
	u32 fragments_bytes_per_peb;
	u32 blks_per_peb;
	u64 seg_logical_offset;
	u32 peb_blk_off, blk_off;
	u32 logical_blk;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!pebc->parent_si->fsi->segbmap);

	SSDFS_DBG("seg_id %llu, peb_index %u, "
		  "logical_offset %llu\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  logical_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;
	segbmap = fsi->segbmap;
	peb_index = pebc->peb_index;

	down_read(&segbmap->resize_lock);
	fragments_bytes_per_seg =
		(u32)segbmap->fragments_per_seg * segbmap->fragment_size;
	fragments_bytes_per_peb =
		(u32)segbmap->fragments_per_peb * segbmap->fragment_size;
	blks_per_peb = fragments_bytes_per_peb;
	blks_per_peb >>= fsi->log_pagesize;
	up_read(&segbmap->resize_lock);

	seg_logical_offset = (u64)seg_index * fragments_bytes_per_seg;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_index %u, seg_logical_offset %llu, "
		  "logical_offset %llu\n",
		  seg_index, seg_logical_offset,
		  logical_offset);

	BUG_ON(seg_logical_offset > logical_offset);
#endif /* CONFIG_SSDFS_DEBUG */

	logical_offset -= seg_logical_offset;

	logical_blk = blks_per_peb * peb_index;
	peb_blk_off = blks_per_peb * peb_index;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(peb_blk_off >= U16_MAX);
	BUG_ON((logical_offset >> fsi->log_pagesize) >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	blk_off = (u32)(logical_offset >> fsi->log_pagesize);

	if (blk_off < peb_blk_off || blk_off >= (peb_blk_off + blks_per_peb)) {
		SSDFS_ERR("invalid logical offset: "
			  "blk_off %u, peb_blk_off %u, "
			  "blks_per_peb %u, logical_offset %llu\n",
			  blk_off, peb_blk_off,
			  blks_per_peb, logical_offset);
		return U16_MAX;
	}

	logical_blk = blk_off - peb_blk_off;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_blk_off %u, blk_off %u, "
		  "logical_blk %u\n",
		  peb_blk_off, blk_off,
		  logical_blk);

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

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "logical_offset %llu, data_size %u, "
		  "fragment_size %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  extent->logical_offset, extent->data_size,
		  extent->fragment_size);
#endif /* CONFIG_SSDFS_DEBUG */

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
							seg_index,
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
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_index %u hasn't segbmap's fragments\n",
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
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
	} else
		ssdfs_request_unlock_and_remove_page(req, 0);

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

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "logical_offset %llu, data_size %u, "
		  "fragment_size %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  extent->logical_offset, extent->data_size,
		  extent->fragment_size);
#endif /* CONFIG_SSDFS_DEBUG */

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
							seg_index,
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
		} else
			ssdfs_request_unlock_and_remove_page(req, i);

		sequence_id++;
	}

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

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "logical_offset %llu, data_size %u, "
		  "fragment_size %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  extent->logical_offset, extent->data_size,
		  extent->fragment_size);
#endif /* CONFIG_SSDFS_DEBUG */

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

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);
#else
	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = pebc->parent_si->fsi;

	seg_index = ssdfs_peb_define_segbmap_seg_index(pebc);
	if (seg_index == U16_MAX) {
		SSDFS_ERR("fail to determine segment index\n");
		return -ERANGE;
	}

	ssdfs_peb_define_segbmap_logical_extent(pebc, seg_index, &extent);

	err = ssdfs_peb_read_segbmap_first_page(pebc, seg_index, &extent);
	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_index %u hasn't segbmap's content\n",
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read PEB's segbmap first page: "
			  "err %d\n", err);
		return err;
	}

	err = ssdfs_peb_read_segbmap_rest_pages(pebc, seg_index, &extent);
	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_index %u has only one page\n",
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read PEB's segbmap rest pages: "
			  "err %d\n", err);
		return err;
	}

	{
		int err1 = ssdfs_peb_release_pages(pebc);
		if (err1 == -ENODATA) {
			SSDFS_DBG("PEB cache is empty\n");
		} else if (unlikely(err1)) {
			SSDFS_ERR("fail to release pages: err %d\n",
				  err1);
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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
 * @logical_offset: logical offset of fragment in mapping table
 * @logical_blk: starting logical block of fragment
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
				   int index, u64 logical_offset,
				   u16 logical_blk,
				   u32 fragment_bytes,
				   struct ssdfs_maptbl_area *area)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_request *req;
	u32 pagevec_bytes = (u32)PAGEVEC_SIZE << PAGE_SHIFT;
	u32 cur_offset = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi || !area);

	SSDFS_DBG("pebc %p, index %d, logical_offset %llu, "
		  "logical_blk %u, fragment_bytes %u, area %p\n",
		  pebc, index, logical_offset,
		  logical_blk, fragment_bytes, area);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebc->parent_si->fsi;

	if (fragment_bytes == 0) {
		SSDFS_ERR("invalid fragment_bytes %u\n",
			  fragment_bytes);
		return -ERANGE;
	}

	do {
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

		if (cur_offset == 0)
			size = fsi->pagesize;
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

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("logical_offset %llu, size %u, "
			  "logical_blk %u, pages_count %u\n",
			  logical_offset, size,
			  logical_blk, pages_count);
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

		if (cur_offset == 0) {
			struct ssdfs_leb_table_fragment_header *hdr;
			u16 magic;
			void *kaddr;
			bool is_fragment_valid = false;

			kaddr = kmap_local_page(req->result.pvec.pages[0]);
			hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;
			magic = le16_to_cpu(hdr->magic);
			is_fragment_valid = magic == SSDFS_LEB_TABLE_MAGIC;
			area->portion_id = le16_to_cpu(hdr->portion_id);


#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("FRAGMENT DUMP\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr, PAGE_SIZE);
			SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */


			kunmap_local(kaddr);

			if (!is_fragment_valid) {
				err = -ENODATA;
				area->portion_id = U16_MAX;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("empty fragment: "
					  "peb_index %u, index %d\n",
					  pebc->peb_index, index);
#endif /* CONFIG_SSDFS_DEBUG */
				goto fail_read_maptbl_pages;
			}
		}

		ssdfs_maptbl_move_fragment_pages(req, area, pages_count);
		ssdfs_request_unlock_and_remove_pages(req);
		ssdfs_put_request(req);
		ssdfs_request_free(req);

		fragment_bytes -= size;
		logical_offset += size;
		cur_offset += size;
		logical_blk += pages_count;
	} while (fragment_bytes > 0);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

fail_read_maptbl_pages:
	ssdfs_request_unlock_and_remove_pages(req);
	ssdfs_put_request(req);
	ssdfs_request_free(req);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_DEBUG */

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
	u64 logical_offset;
	u32 logical_blk;
	u32 fragment_bytes;
	u32 blks_per_fragment;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi || !req);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);
#else
	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	area.pages = ssdfs_read_kcalloc(area.pages_capacity,
				   sizeof(struct page *),
				   GFP_KERNEL);
	if (!area.pages) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory: "
			  "area.pages_capacity %zu\n",
			  area.pages_capacity);
		goto end_init;
	}

	logical_offset = req->extent.logical_offset;
	logical_blk = req->place.start.blk_index;

	blks_per_fragment =
		(fragment_bytes + fsi->pagesize - 1) / fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(blks_per_fragment >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < fsi->maptbl->fragments_per_peb; i++) {
		logical_offset = logical_offset + ((u64)fragment_bytes * i);
		logical_blk = logical_blk + (blks_per_fragment * i);

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(logical_blk >= U16_MAX);

		SSDFS_DBG("seg %llu, peb_index %d, "
			  "logical_offset %llu, logical_blk %u\n",
			  pebc->parent_si->seg_id, i,
			  logical_offset, logical_blk);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_peb_read_maptbl_fragment(pebc, i,
						     logical_offset,
						     (u16)logical_blk,
						     fragment_bytes,
						     &area);
		if (err == -ENODATA) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("peb_index %u hasn't more maptbl fragments: "
				  "last index %d\n",
				  pebc->peb_index, i);
#endif /* CONFIG_SSDFS_DEBUG */
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
			ssdfs_read_free_page(area.pages[i]);
			area.pages[i] = NULL;
		}
	}

	ssdfs_read_kfree(area.pages);

	{
		int err1 = ssdfs_peb_release_pages(pebc);
		if (err1 == -ENODATA) {
			SSDFS_DBG("PEB cache is empty\n");
		} else if (unlikely(err1)) {
			SSDFS_ERR("fail to release pages: err %d\n",
				  err1);
		}
	}

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_peb_get_last_log_time() - get PEB's last log timestamp
 * @fsi: file system info object
 * @pebi: pointer on PEB object
 * @page_off: page offset to footer's placement
 * @peb_create_time: PEB's create timestamp [out]
 * @last_log_time: PEB's last log timestamp
 *
 * This method tries to read the last log footer of PEB
 * and retrieve peb_create_time and last_log_time.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - no valid log footer.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_get_last_log_time(struct ssdfs_fs_info *fsi,
				struct ssdfs_peb_info *pebi,
				u32 page_off,
				u64 *peb_create_time,
				u64 *last_log_time)
{
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_partial_log_header *plh_hdr = NULL;
	struct ssdfs_log_footer *footer = NULL;
	struct page *page;
	void *kaddr;
	u32 bytes_off;
	size_t read_bytes;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!peb_create_time || !last_log_time);

	SSDFS_DBG("seg %llu, peb_id %llu, page_off %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, page_off);
#endif /* CONFIG_SSDFS_DEBUG */

	*peb_create_time = U64_MAX;
	*last_log_time = U64_MAX;

	page = ssdfs_page_array_grab_page(&pebi->cache, page_off);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		SSDFS_ERR("fail to grab page: index %u\n",
			  page_off);
		return -ENOMEM;
	}

	kaddr = kmap_local_page(page);

	if (PageUptodate(page) || PageDirty(page))
		goto check_footer_magic;

	bytes_off = page_off * fsi->pagesize;

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
		*peb_create_time = le64_to_cpu(plh_hdr->peb_create_time);
		*last_log_time = le64_to_cpu(plh_hdr->timestamp);
	} else if (__is_ssdfs_log_footer_magic_valid(magic)) {
		footer = SSDFS_LF(kaddr);
		*peb_create_time = le64_to_cpu(footer->peb_create_time);
		*last_log_time = le64_to_cpu(footer->timestamp);
	} else {
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("log footer is corrupted: "
			  "peb %llu, page_off %u\n",
			  pebi->peb_id, page_off);
#endif /* CONFIG_SSDFS_DEBUG */
		goto fail_read_footer;
	}

fail_read_footer:
	kunmap_local(kaddr);
	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("valid footer is not detected: "
			  "seg_id %llu, peb_id %llu, "
			  "page_off %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  page_off);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read footer: "
			  "seg %llu, peb %llu, "
			  "pages_off %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  page_off,
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_read_last_log_footer() - read PEB's last log footer
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This method tries to read the last log footer of PEB
 * and initialize peb_create_time and last_log_time fields.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - no valid log footer.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_read_last_log_footer(struct ssdfs_peb_info *pebi,
				   struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	u32 log_bytes;
	u32 pages_per_log;
	u32 logs_count;
	u32 page_off;
	u64 peb_create_time;
	u64 last_log_time;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi || !req);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  req->private.class, req->private.cmd,
		  req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	page_off = 0;

	err = __ssdfs_peb_read_log_header(fsi, pebi, page_off,
					  &log_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read log header: "
			  "seg %llu, peb %llu, page_off %u, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  page_off,
			  err);
		return err;
	}

	pages_per_log = log_bytes + fsi->pagesize - 1;
	pages_per_log /= fsi->pagesize;
	logs_count = fsi->pages_per_peb / pages_per_log;

	for (i = logs_count; i > 0; i--) {
		page_off = (i * pages_per_log) - 1;

		err = ssdfs_peb_get_last_log_time(fsi, pebi,
						  page_off,
						  &peb_create_time,
						  &last_log_time);
		if (err == -ENODATA)
			continue;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to get last log time: "
				  "seg %llu, peb %llu, "
				  "page_off %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  page_off,
				  err);
			return err;
		} else
			break;
	}

	if (i <= 0 || err == -ENODATA) {
		SSDFS_ERR("fail to get last log time: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		return -ERANGE;
	}

	pebi->peb_create_time = peb_create_time;
	pebi->current_log.last_log_time = last_log_time;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb %llu, "
		  "peb_create_time %llx, last_log_time %llx\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  peb_create_time,
		  last_log_time);

	BUG_ON(pebi->peb_create_time > last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;
}

/*
 * ssdfs_peb_read_src_last_log_footer() - read src PEB's last log footer
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This method tries to read the last log footer of source PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - no valid log footer.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_read_src_last_log_footer(struct ssdfs_peb_container *pebc,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_info *pebi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi || !req);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);
#else
	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = pebc->parent_si->fsi;

	down_read(&pebc->lock);

	pebi = pebc->src_peb;
	if (!pebi) {
		SSDFS_WARN("source PEB is NULL\n");
		err = -ERANGE;
		goto finish_read_src_last_log_footer;
	}

	err = ssdfs_peb_read_last_log_footer(pebi, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read last log's footer: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		goto finish_read_src_last_log_footer;
	}

finish_read_src_last_log_footer:
	up_read(&pebc->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_peb_read_dst_last_log_footer() - read dst PEB's last log footer
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This method tries to read the last log footer of destination PEB.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 * %-ENODATA    - no valid log footer.
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_read_dst_last_log_footer(struct ssdfs_peb_container *pebc,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_info *pebi;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi || !req);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);
#else
	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req->private.class, req->private.cmd,
		  req->private.type);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = pebc->parent_si->fsi;

	down_read(&pebc->lock);

	pebi = pebc->dst_peb;
	if (!pebi) {
		SSDFS_WARN("destination PEB is NULL\n");
		err = -ERANGE;
		goto finish_read_dst_last_log_footer;
	}

	err = ssdfs_peb_read_last_log_footer(pebi, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read last log's footer: "
			  "peb_id %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index, err);
		goto finish_read_dst_last_log_footer;
	}

finish_read_dst_last_log_footer:
	up_read(&pebc->lock);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

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

	SSDFS_DBG("req %p, class %#x, cmd %#x, type %#x\n",
		  req, req->private.class, req->private.cmd,
		  req->private.type);
#endif /* CONFIG_SSDFS_DEBUG */

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
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to read page: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_PAGES_READAHEAD:
		err = ssdfs_peb_readahead_pages(pebc, req, NULL);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to read pages: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_SRC_ALL_LOG_HEADERS:
		err = ssdfs_peb_read_src_all_log_headers(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to read log headers: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_DST_ALL_LOG_HEADERS:
		err = ssdfs_peb_read_dst_all_log_headers(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to read log headers: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_BLK_BMAP_INIT_CLEAN_PEB:
		err = ssdfs_peb_init_clean_metadata_state(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to init clean block bitmap: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_BLK_BMAP_SRC_USING_PEB:
		err = ssdfs_src_peb_init_using_metadata_state(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to init source PEB (using state): "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_BLK_BMAP_DST_USING_PEB:
		err = ssdfs_dst_peb_init_using_metadata_state(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to init destination PEB (using state): "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_BLK_BMAP_SRC_USED_PEB:
		err = ssdfs_src_peb_init_used_metadata_state(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to init source PEB (used state): "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_BLK_BMAP_DST_USED_PEB:
		err = ssdfs_dst_peb_init_used_metadata_state(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to init destination PEB (used state): "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_BLK2OFF_TABLE_SRC_PEB:
		err = ssdfs_src_peb_complete_init_blk2off_table(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to finish offset table init: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_BLK2OFF_TABLE_DST_PEB:
		err = ssdfs_dst_peb_complete_init_blk2off_table(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to finish offset table init: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_INIT_SEGBMAP:
		err = ssdfs_peb_init_segbmap_object(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to init segment bitmap object: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_INIT_MAPTBL:
		err = ssdfs_peb_init_maptbl_object(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to init mapping table object: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_SRC_LAST_LOG_FOOTER:
		err = ssdfs_peb_read_src_last_log_footer(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to read last log footer: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	case SSDFS_READ_DST_LAST_LOG_FOOTER:
		err = ssdfs_peb_read_dst_last_log_footer(pebc, req);
		if (unlikely(err)) {
			ssdfs_fs_error(pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"fail to read last log footer: "
				"seg %llu, peb_index %u, err %d\n",
				pebc->parent_si->seg_id,
				pebc->peb_index, err);
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
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

	SSDFS_DBG("req %p, class %#x, cmd %#x, type %#x, err %d\n",
		  req, req->private.class, req->private.cmd,
		  req->private.type, err);
#endif /* CONFIG_SSDFS_DEBUG */

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
			err = wait_event_killable_timeout(*wait,
				atomic_read(&req->private.refs_count) == 0,
				SSDFS_DEFAULT_TIMEOUT);
			if (err < 0)
				WARN_ON(err < 0);
			else
				err = 0;
		}

		wake_up_all(&req->private.wait_queue);

		for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
			struct page *page = req->result.pvec.pages[i];

			if (!page) {
				SSDFS_WARN("page %d is NULL\n", i);
				continue;
			}

#ifdef CONFIG_SSDFS_DEBUG
			WARN_ON(!PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
			SSDFS_DBG("page_index %llu, flags %#lx\n",
				  (u64)page_index(page), page->flags);
#endif /* CONFIG_SSDFS_DEBUG */
		}

		ssdfs_request_free(req);
		break;

	case SSDFS_REQ_ASYNC_NO_FREE:
		complete(&req->result.wait);

		ssdfs_put_request(req);
		if (atomic_read(&req->private.refs_count) != 0) {
			err = wait_event_killable_timeout(*wait,
				atomic_read(&req->private.refs_count) == 0,
				SSDFS_DEFAULT_TIMEOUT);
			if (err < 0)
				WARN_ON(err < 0);
			else
				err = 0;
		}

		wake_up_all(&req->private.wait_queue);

		for (i = 0; i < pagevec_count(&req->result.pvec); i++) {
			struct page *page = req->result.pvec.pages[i];

			if (!page) {
				SSDFS_WARN("page %d is NULL\n", i);
				continue;
			}

#ifdef CONFIG_SSDFS_DEBUG
			WARN_ON(!PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_unlock_page(page);
			ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %p, count %d\n",
				  page, page_ref_count(page));
			SSDFS_DBG("page_index %llu, flags %#lx\n",
				  (u64)page_index(page), page->flags);
#endif /* CONFIG_SSDFS_DEBUG */
		}
		break;

	default:
		BUG();
	};

	ssdfs_peb_finish_read_request_cno(pebc);
}

#define READ_THREAD_WAKE_CONDITION(pebc) \
	(kthread_should_stop() || \
	 !is_ssdfs_requests_queue_empty(READ_RQ_PTR(pebc)))
#define READ_FAILED_THREAD_WAKE_CONDITION() \
	(kthread_should_stop())
#define READ_THREAD_WAKEUP_TIMEOUT	(msecs_to_jiffies(3000))

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
	u64 timeout = READ_THREAD_WAKEUP_TIMEOUT;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	if (!pebc) {
		SSDFS_ERR("pointer on PEB container is NULL\n");
		BUG();
	}

	SSDFS_DBG("read thread: seg %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	wait_queue = &pebc->parent_si->wait_queue[SSDFS_PEB_READ_THREAD];

repeat:
	if (kthread_should_stop()) {
		complete_all(&pebc->thread[SSDFS_PEB_READ_THREAD].full_stop);
		return err;
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
			goto sleep_failed_read_thread;
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
	wait_event_interruptible_timeout(*wait_queue,
					 READ_THREAD_WAKE_CONDITION(pebc),
					 timeout);
	if (!is_ssdfs_requests_queue_empty(&pebc->read_rq)) {
		/* do requests processing */
		goto repeat;
	} else {
		if (is_it_time_free_peb_cache_memory(pebc)) {
			err = ssdfs_peb_release_pages(pebc);
			if (err == -ENODATA) {
				err = 0;
				timeout = min_t(u64, timeout * 2,
						(u64)SSDFS_DEFAULT_TIMEOUT);
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to release pages: "
					  "err %d\n", err);
				err = 0;
			} else
				timeout = READ_THREAD_WAKEUP_TIMEOUT;
		}

		if (!is_ssdfs_requests_queue_empty(&pebc->read_rq) ||
		    kthread_should_stop())
			goto repeat;
		else
			goto sleep_read_thread;
	}

sleep_failed_read_thread:
	ssdfs_peb_release_pages(pebc);
	wait_event_interruptible(*wait_queue,
			READ_FAILED_THREAD_WAKE_CONDITION());
	goto repeat;
}
