/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_read_thread.c - read thread functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2025 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include "folio_vector.h"
#include "ssdfs.h"
#include "compression.h"
#include "block_bitmap.h"
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"
#include "segment_tree.h"
#include "peb_mapping_table.h"
#include "request_queue.h"
#include "btree_search.h"
#include "btree_node.h"
#include "extents_queue.h"
#include "btree.h"
#include "diff_on_write.h"
#include "shared_extents_tree.h"
#include "invalidated_extents_tree.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_read_folio_leaks;
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
 * struct folio *ssdfs_read_alloc_folio(gfp_t gfp_mask,
 *                                      unsigned int order)
 * struct folio *ssdfs_read_add_batch_folio(struct folio_batch *batch,
 *                                          unsigned int order)
 * void ssdfs_read_free_folio(struct folio *folio)
 * void ssdfs_read_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(read)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(read)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_read_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_read_folio_leaks, 0);
	atomic64_set(&ssdfs_read_memory_leaks, 0);
	atomic64_set(&ssdfs_read_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_read_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_read_folio_leaks) != 0) {
		SSDFS_ERR("READ THREAD: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_read_folio_leaks));
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
	size_t bmap_folios;
	size_t blk_bmap_hdr_size = sizeof(struct ssdfs_block_bitmap_header);

	bmap_bytes = BLK_BMAP_BYTES(pages_per_peb);
	bmap_folios = (bmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	ssdfs_folio_vector_create(&env->raw.content,
				  get_order(PAGE_SIZE), bmap_folios);

	memset(env->raw.metadata, 0xFF, sizeof(env->raw.metadata));
	env->header.ptr = (struct ssdfs_block_bitmap_header *)env->raw.metadata;

	env->fragment.index = -1;
	env->fragment.header =
		(struct ssdfs_block_bitmap_fragment *)(env->raw.metadata +
							    blk_bmap_hdr_size);

	env->read_bytes = 0;
}

static
void ssdfs_destroy_blk_bmap_init_env(struct ssdfs_blk_bmap_init_env *env)
{
	ssdfs_folio_vector_release(&env->raw.content);
	ssdfs_folio_vector_destroy(&env->raw.content);

	memset(env->raw.metadata, 0xFF, sizeof(env->raw.metadata));
	env->header.ptr = NULL;

	env->fragment.index = -1;
	env->fragment.header = NULL;
}

static void
ssdfs_prepare_blk2off_table_init_env(struct ssdfs_blk2off_table_init_env *env,
				     u32 pages_per_peb)
{
	size_t tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);

	ssdfs_create_content_stream(&env->extents.stream, pages_per_peb);
	env->extents.count = 0;

	memset(&env->portion.header, 0xFF, tbl_hdr_size);
	ssdfs_create_content_stream(&env->portion.fragments.stream,
				    pages_per_peb);

//	SSDFS_FRAG_RAW_ITER_CREATE(&env->portion.read_iter);

	env->portion.area_offset = 0;
	env->portion.read_off = 0;
}

#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
	/*
	 * No implementation of this function.
	 */
#else /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */
static void
ssdfs_reinit_blk2off_table_init_env(struct ssdfs_blk2off_table_init_env *env)
{
	size_t tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);

	ssdfs_reinit_content_stream(&env->extents.stream);
	env->extents.count = 0;

	memset(&env->portion.header, 0xFF, tbl_hdr_size);
	ssdfs_reinit_content_stream(&env->portion.fragments.stream);

/*
	if (!IS_SSDFS_FRAG_RAW_ITER_ENDED(&env->portion.read_iter)) {
		SSDFS_WARN("read iterator is not completely processed: "
			   "processed_bytes %u, bytes_count %u, "
			   "processed_fragments %u, "
			   "fragments_count %u\n",
			   env->portion.read_iter.processed_bytes,
			   env->portion.read_iter.bytes_count,
			   env->portion.read_iter.processed_fragments,
			   env->portion.read_iter.fragments_count);
	}

	SSDFS_FRAG_RAW_ITER_CREATE(&env->portion.read_iter);
*/

	env->portion.area_offset = 0;
	env->portion.read_off = 0;
}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

static void
ssdfs_destroy_blk2off_table_init_env(struct ssdfs_blk2off_table_init_env *env)
{
	size_t tbl_hdr_size = sizeof(struct ssdfs_blk2off_table_header);

	ssdfs_destroy_content_stream(&env->extents.stream);
	env->extents.count = 0;

	memset(&env->portion.header, 0xFF, tbl_hdr_size);
	ssdfs_destroy_content_stream(&env->portion.fragments.stream);

/*
	if (!IS_SSDFS_FRAG_RAW_ITER_ENDED(&env->portion.read_iter)) {
		SSDFS_WARN("read iterator is not completely processed: "
			   "processed_bytes %u, bytes_count %u, "
			   "processed_fragments %u, "
			   "fragments_count %u\n",
			   env->portion.read_iter.processed_bytes,
			   env->portion.read_iter.bytes_count,
			   env->portion.read_iter.processed_fragments,
			   env->portion.read_iter.fragments_count);
	}

	SSDFS_FRAG_RAW_ITER_CREATE(&env->portion.read_iter);
*/

	env->portion.area_offset = 0;
	env->portion.read_off = 0;
}

static void
ssdfs_prepare_blk_desc_table_init_env(struct ssdfs_blk_desc_table_init_env *env,
				      u32 pages_per_peb)
{
	memset(&env->portion.header, 0xFF,
		sizeof(struct ssdfs_area_block_table));

	ssdfs_folio_vector_create(&env->portion.raw.content,
				  get_order(PAGE_SIZE), pages_per_peb);
//	SSDFS_FRAG_RAW_ITER_CREATE(&env->portion.read_iter);

	env->portion.area_offset = 0;
	env->portion.read_off = 0;
	env->portion.write_off = 0;
}

#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
	/*
	 * No implementation of this function.
	 */
#else /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */
static void
ssdfs_reinit_blk_desc_table_init_env(struct ssdfs_blk_desc_table_init_env *env)
{
	memset(&env->portion.header, 0xFF,
		sizeof(struct ssdfs_area_block_table));

	ssdfs_folio_vector_release(&env->portion.raw.content);
	ssdfs_folio_vector_reinit(&env->portion.raw.content);

/*
	if (!IS_SSDFS_FRAG_RAW_ITER_ENDED(&env->portion.read_iter)) {
		SSDFS_WARN("read iterator is not completely processed: "
			   "processed_bytes %u, bytes_count %u, "
			   "processed_fragments %u, "
			   "fragments_count %u\n",
			   env->portion.read_iter.processed_bytes,
			   env->portion.read_iter.bytes_count,
			   env->portion.read_iter.processed_fragments,
			   env->portion.read_iter.fragments_count);
	}

	SSDFS_FRAG_RAW_ITER_CREATE(&env->portion.read_iter);
*/

	env->portion.area_offset = 0;
	env->portion.read_off = 0;
	env->portion.write_off = 0;
}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

static void
ssdfs_destroy_blk_desc_table_init_env(struct ssdfs_blk_desc_table_init_env *env)
{
	memset(&env->portion.header, 0xFF,
		sizeof(struct ssdfs_area_block_table));

	ssdfs_folio_vector_release(&env->portion.raw.content);
	ssdfs_folio_vector_destroy(&env->portion.raw.content);

/*
	if (!IS_SSDFS_FRAG_RAW_ITER_ENDED(&env->portion.read_iter)) {
		SSDFS_WARN("read iterator is not completely processed: "
			   "processed_bytes %u, bytes_count %u, "
			   "processed_fragments %u, "
			   "fragments_count %u\n",
			   env->portion.read_iter.processed_bytes,
			   env->portion.read_iter.bytes_count,
			   env->portion.read_iter.processed_fragments,
			   env->portion.read_iter.fragments_count);
	}

	SSDFS_FRAG_RAW_ITER_CREATE(&env->portion.read_iter);
*/
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

	env->peb.cur_migration_id = -1;
	env->peb.prev_migration_id = -1;
	env->peb.free_pages = 0;

	env->log.offset = 0;
	env->log.blocks = U32_MAX;
	env->log.bytes = U32_MAX;

	hdr_size = sizeof(struct ssdfs_segment_header);
	hdr_size = max_t(size_t, hdr_size, (size_t)SSDFS_4KB);

	env->log.header.ptr = ssdfs_read_kzalloc(hdr_size, GFP_KERNEL);
	if (!env->log.header.ptr) {
		SSDFS_ERR("fail to allocate log header buffer\n");
		return -ENOMEM;
	}

	env->log.header.of_full_log = true;

	footer_buf_size = max_t(size_t, hdr_size,
				sizeof(struct ssdfs_log_footer));
	env->log.footer.ptr = ssdfs_read_kzalloc(footer_buf_size, GFP_KERNEL);
	if (!env->log.footer.ptr) {
		SSDFS_ERR("fail to allocate log footer buffer\n");
		return -ENOMEM;
	}

	env->log.footer.is_present = false;

	ssdfs_prepare_blk_bmap_init_env(&env->log.blk_bmap, pages_per_peb);
	ssdfs_prepare_blk2off_table_init_env(&env->log.blk2off_tbl,
					     pages_per_peb);
	ssdfs_prepare_blk_desc_table_init_env(&env->log.blk_desc_tbl,
					      pages_per_peb);

	return 0;
}

static
void ssdfs_destroy_init_env(struct ssdfs_read_init_env *env)
{
#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("env %p\n", env);
#endif /* CONFIG_SSDFS_DEBUG */

	env->peb.cur_migration_id = -1;
	env->peb.prev_migration_id = -1;
	env->peb.free_pages = 0;

	env->log.offset = 0;
	env->log.blocks = U32_MAX;
	env->log.bytes = U32_MAX;

	if (env->log.header.ptr)
		ssdfs_read_kfree(env->log.header.ptr);

	env->log.header.ptr = NULL;
	env->log.header.of_full_log = true;

	if (env->log.footer.ptr)
		ssdfs_read_kfree(env->log.footer.ptr);

	env->log.footer.ptr = NULL;
	env->log.footer.is_present = false;

	ssdfs_destroy_blk_bmap_init_env(&env->log.blk_bmap);
	ssdfs_destroy_blk2off_table_init_env(&env->log.blk2off_tbl);
	ssdfs_destroy_blk_desc_table_init_env(&env->log.blk_desc_tbl);
}

/******************************************************************************
 *                          READ THREAD FUNCTIONALITY                         *
 ******************************************************************************/

/*
 * __ssdfs_peb_release_folios() - release memory folios
 * @pebi: pointer on PEB object
 *
 * This method tries to release the used folios from the folio
 * array upon the init has been finished.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int __ssdfs_peb_release_folios(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_fs_info *fsi;
	u16 last_log_start_block = U16_MAX;
	u16 log_blocks = 0;
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

	fsi = pebi->pebc->parent_si->fsi;

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
	last_log_start_block = pebi->current_log.start_block;
	log_blocks = pebi->log_blocks;
	ssdfs_peb_current_log_unlock(pebi);

	if (last_log_start_block > 0 && last_log_start_block <= log_blocks) {
		start = 0;
		end = last_log_start_block - 1;
		end <<= fsi->log_pagesize;
		end += fsi->pagesize - 1;
		end /= pebi->cache.folio_size;

		err = ssdfs_folio_array_release_folios(&pebi->cache,
							&start, end);
		if (unlikely(err)) {
			SSDFS_ERR("fail to release folios: "
				  "seg_id %llu, peb_id %llu, "
				  "start %lu, end %lu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, start, end, err);
		}
	}

	if (!err && is_ssdfs_folio_array_empty(&pebi->cache)) {
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
 * ssdfs_peb_release_folios_after_init() - release memory folios
 * @pebc: pointer on PEB container
 * @req: read request
 *
 * This method tries to release the used folios from the folio
 * array upon the init has been finished.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_release_folios(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_peb_info *pebi;
	int err1 = 0, err2 = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);

	SSDFS_DBG("seg_id %llu, peb_index %u\n",
		  pebc->parent_si->seg_id, pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&pebc->lock);
	mutex_lock(&pebc->migration_lock);

	pebi = pebc->src_peb;
	if (pebi) {
		err1 = __ssdfs_peb_release_folios(pebi);
		if (err1 == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache is empty: "
				  "seg_id %llu, peb_index %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (unlikely(err1)) {
			SSDFS_ERR("fail to release source PEB folios: "
				  "seg_id %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err1);
		}
	}

	pebi = pebc->dst_peb;
	if (pebi) {
		err2 = __ssdfs_peb_release_folios(pebi);
		if (err2 == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache is empty: "
				  "seg_id %llu, peb_index %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		} else if (unlikely(err2)) {
			SSDFS_ERR("fail to release dest PEB folios: "
				  "seg_id %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err2);
		}
	}

	mutex_unlock(&pebc->migration_lock);
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
	struct ssdfs_smart_folio folio;
	u32 bytes_off;
	size_t read_bytes = 0;
#ifdef CONFIG_SSDFS_DEBUG
	void *kaddr;
	u32 processed_bytes;
	u32 page_index;
#endif /* CONFIG_SSDFS_DEBUG */
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

		bytes_off = area_offset + read_bytes;

		err = SSDFS_OFF2FOLIO(pebi->cache.folio_size,
				      bytes_off, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "bytes_off %u, err %d\n",
				  bytes_off, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		iter_read_bytes = min_t(size_t,
					(size_t)(area_size - read_bytes),
					(size_t)(PAGE_SIZE -
						folio.desc.offset_inside_page));

		folio.ptr = ssdfs_folio_array_get_folio_locked(&pebi->cache,
							folio.desc.folio_index);
		if (IS_ERR_OR_NULL(folio.ptr)) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to get folio: index %u\n",
				   folio.desc.folio_index);
#endif /* CONFIG_SSDFS_DEBUG */

			if (req->private.flags & SSDFS_REQ_READ_ONLY_CACHE)
				return -ENOENT;

			folio.ptr = ssdfs_folio_array_grab_folio(&pebi->cache,
							folio.desc.folio_index);
			if (unlikely(IS_ERR_OR_NULL(folio.ptr))) {
				SSDFS_ERR("fail to grab folio: index %u\n",
					  folio.desc.folio_index);
				return -ENOMEM;
			}

			err = ssdfs_read_folio_from_volume(fsi, pebi->peb_id,
						folio.desc.folio_index *
							folio_size(folio.ptr),
						folio.ptr);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read locked folio: "
					  "seg %llu, peb %llu, "
					  "folio_index %u, err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  folio.desc.folio_index, err);
				ssdfs_folio_unlock(folio.ptr);
				ssdfs_folio_put(folio.ptr);
				return err;
			}

			/*
			 * ->readpage() unlock the page
			 */
			ssdfs_folio_lock(folio.ptr);

			folio_mark_uptodate(folio.ptr);
			flush_dcache_folio(folio.ptr);
		}

#ifdef CONFIG_SSDFS_DEBUG
		processed_bytes = 0;
		page_index = 0;

		do {
			kaddr = kmap_local_folio(folio.ptr, processed_bytes);
			SSDFS_DBG("PAGE DUMP: page_index %u\n",
				  page_index);
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
					     kaddr,
					     PAGE_SIZE);
			SSDFS_DBG("\n");
			kunmap_local(kaddr);

			processed_bytes += PAGE_SIZE;
			page_index++;
		} while (processed_bytes < folio_size(folio.ptr));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_memcpy_from_folio(buf, read_bytes, area_size,
					      &folio, iter_read_bytes);

		ssdfs_folio_unlock(folio.ptr);
		ssdfs_folio_put(folio.ptr);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "read_bytes %zu, iter_read_bytes %zu, "
				  "err %d\n",
				  read_bytes, iter_read_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio.ptr, folio_ref_count(folio.ptr));
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
 * %-ENOENT     - cache hasn't the requested folio.
 */
int ssdfs_peb_read_log_hdr_desc_array(struct ssdfs_peb_info *pebi,
				      struct ssdfs_segment_request *req,
				      u16 log_start_page,
				      struct ssdfs_metadata_descriptor *array,
				      size_t array_size)
{
	struct ssdfs_fs_info *fsi;
	struct folio *folio;
	void *kaddr;
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *plh_hdr = NULL;
	size_t desc_size = sizeof(struct ssdfs_metadata_descriptor);
	size_t array_bytes = array_size * desc_size;
	u32 folio_index;
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

	folio_index = log_start_page << fsi->log_pagesize;
	folio_index /= pebi->cache.folio_size;

	folio = ssdfs_folio_array_get_folio_locked(&pebi->cache,
						   folio_index);
	if (unlikely(IS_ERR_OR_NULL(folio))) {
		u32 byte_offset;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to get folio: index %u\n",
			  folio_index);
#endif /* CONFIG_SSDFS_DEBUG */

		if (req->private.flags & SSDFS_REQ_READ_ONLY_CACHE)
			return -ENOENT;

		folio = ssdfs_folio_array_grab_folio(&pebi->cache,
						     folio_index);
		if (unlikely(IS_ERR_OR_NULL(folio))) {
			SSDFS_ERR("fail to grab folio: index %u\n",
				  folio_index);
			return -ENOMEM;
		}

		byte_offset = (u32)log_start_page << fsi->log_pagesize;
		err = ssdfs_read_folio_from_volume(fsi, pebi->peb_id,
						   byte_offset,
						   folio);
		if (unlikely(err))
			goto fail_copy_desc_array;

		/* read_block() unlocks the folio */
		ssdfs_folio_lock(folio);

		folio_mark_uptodate(folio);
		flush_dcache_folio(folio);
	}

	kaddr = kmap_local_folio(folio, 0);
	magic = (struct ssdfs_signature *)kaddr;

	if (!is_ssdfs_magic_valid(magic)) {
		err = -ERANGE;
		SSDFS_ERR("valid magic is not detected\n");
		goto finish_desc_array_copy;
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
		goto finish_desc_array_copy;
	}

finish_desc_array_copy:
	kunmap_local(kaddr);

fail_copy_desc_array:
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	if (unlikely(err)) {
		SSDFS_ERR("fail to read checked segment header: "
			  "seg %llu, peb %llu, log_start_page %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  log_start_page, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_read_folio_locked() - read locked folio into PEB's cache
 * @pebi: pointer on PEB object
 * @req: request
 * @folio_index: folio index
 *
 * This function tries to read locked folio into PEB's cache.
 */
static
struct folio *ssdfs_peb_read_folio_locked(struct ssdfs_peb_info *pebi,
					  struct ssdfs_segment_request *req,
					  u32 folio_index)
{
	struct ssdfs_fs_info *fsi;
	struct folio *folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);

	SSDFS_DBG("seg %llu, peb %llu, folio_index %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  folio_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	folio = ssdfs_folio_array_get_folio_locked(&pebi->cache, folio_index);
	if (unlikely(IS_ERR_OR_NULL(folio))) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to get folio: index %u\n",
			   folio_index);
#endif /* CONFIG_SSDFS_DEBUG */

		if (req->private.flags & SSDFS_REQ_READ_ONLY_CACHE)
			return ERR_PTR(-ENOENT);

		folio = ssdfs_folio_array_grab_folio(&pebi->cache, folio_index);
		if (unlikely(IS_ERR_OR_NULL(folio))) {
			SSDFS_ERR("fail to grab folio: index %u\n",
				  folio_index);
			return NULL;
		}

		if (folio_test_uptodate(folio) || folio_test_dirty(folio))
			goto finish_folio_read;

		err = ssdfs_read_folio_from_volume(fsi, pebi->peb_id,
						   (u64)folio_index *
							pebi->cache.folio_size,
						   folio);

		/*
		 * ->read_folio() unlock the folio
		 * But caller expects that folio is locked
		 */
		ssdfs_folio_lock(folio);

		if (unlikely(err))
			goto fail_read_folio;

		folio_mark_uptodate(folio);
	}

finish_folio_read:
	return folio;

fail_read_folio:
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_ERR("fail to read locked folio: "
		  "seg %llu, peb %llu, folio_index %u, err %d\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  folio_index, err);

	return NULL;
}

/*
 * SSDFS_FRAG_TYPE_TO_COMPR_TYPE() - convert fragment type into compression type
 */
static inline
int SSDFS_FRAG_TYPE_TO_COMPR_TYPE(int frag_type)
{
	int compr_type = SSDFS_COMPR_NONE;

	switch (frag_type) {
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
		SSDFS_ERR("frag_type %#x\n", frag_type);
		BUG();
	}

	return compr_type;
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

	SSDFS_DBG("FRAGMENT DESC DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     frag, sizeof(struct ssdfs_fragment_desc));
	SSDFS_DBG("\n");
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

	compr_type = SSDFS_FRAG_TYPE_TO_COMPR_TYPE(frag->type);

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
					struct ssdfs_compressed_fragment *desc)
{
	struct ssdfs_peb_read_buffer *buf;
	u32 area_offset;
	u16 uncompr_size;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!desc);
	BUG_ON(!rwsem_is_locked(&pebi->read_buffer.lock));

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id);

	BUG_ON(IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(desc));
	BUG_ON(!IS_SSDFS_COMPRESSED_FRAGMENT_IN_PORTION(desc));
#endif /* CONFIG_SSDFS_DEBUG */

	buf = &pebi->read_buffer.blk_desc;
	uncompr_size = desc->uncompressed.size;

	if (buf->buf_size < uncompr_size) {
		err = ssdfs_peb_realloc_read_buffer(buf, uncompr_size);
		if (unlikely(err)) {
			SSDFS_ERR("fail to realloc read buffer: "
				  "old_size %zu, new_size %u, err %d\n",
				  buf->buf_size, uncompr_size, err);
			return err;
		}
	}

	area_offset = SSDFS_AREA_COMPRESSED_OFFSET(&desc->portion.area);

	err = __ssdfs_decompress_blk2off_fragment(pebi, req,
						  &desc->frag_desc,
						  area_offset,
						  buf->ptr, buf->buf_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to decompress blk desc fragment: "
			  "err %d\n", err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_check_blk_desc_fragment() - check and decompress blk desc fragment
 * @pebi: pointer on PEB object
 * @req: request
 * @frag: fragment descriptor
 * @offset: offset in bytes to read block descriptor
 * @frag_desc: fragment offset descriptor [in|out]
 *
 * This function tries to check and decompress block descriptor fragment.
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
int ssdfs_peb_check_blk_desc_fragment(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req,
				    struct ssdfs_fragment_desc *frag,
				    u32 offset,
				    struct ssdfs_compressed_fragment *frag_desc)
{
	u32 portion_offset;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!frag || !frag_desc);

	SSDFS_DBG("seg %llu, peb %llu, offset %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, offset);
#endif /* CONFIG_SSDFS_DEBUG */

	portion_offset = SSDFS_PORTION_COMPRESSED_OFFSET(&frag_desc->portion);

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

	if (IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(frag_desc)) {
		err = SSDFS_INIT_COMPRESSED_FRAGMENT_DESC(frag_desc, frag);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init fragment: "
				  "err %d\n", err);
			return err;
		}
	} else {
		err = SSDFS_ADD_COMPRESSED_FRAGMENT(frag_desc, frag);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add fragment: "
				  "err %d\n", err);
			return err;
		}
	}

	if (IS_OFFSET_INSIDE_UNCOMPRESSED_FRAGMENT(frag_desc, offset)) {
		err = ssdfs_decompress_blk_desc_fragment(pebi, req, frag_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to decompress: "
				  "err %d\n", err);
			return err;
		}

		return 0;
	}

	return -EAGAIN;
}

/*
 * ssdfs_peb_find_blk_desc_portion() - find block descriptor portion
 * @pebi: pointer on PEB object
 * @req: request
 * @meta_desc: area descriptor
 * @offset: offset in bytes to read block descriptor
 * @table: block descriptor portion's header [out]
 * @frag_desc: fragment offset descriptor [in|out]
 *
 * This function tries to find a block descriptor portion
 * for requested offset.
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
int ssdfs_peb_find_blk_desc_portion(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req,
				    struct ssdfs_metadata_descriptor *meta_desc,
				    u32 offset,
				    struct ssdfs_area_block_table *table,
				    struct ssdfs_compressed_fragment *frag_desc)
{
	struct ssdfs_compressed_area area;
	struct ssdfs_compressed_portion *portion_desc;
	struct ssdfs_fragment_desc *next_portion_desc;
	size_t tbl_size = sizeof(struct ssdfs_area_block_table);
	u16 fragments;
	u32 cur_offset;
	u32 next_portion_offset;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!meta_desc || !table || !frag_desc);

	SSDFS_DBG("seg %llu, peb %llu, offset %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  offset);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_INIT_COMPRESSED_AREA_DESC(&area, meta_desc);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_offset %u, area_size %u\n",
		  area.compressed.offset, area.compressed.size);
#endif /* CONFIG_SSDFS_DEBUG */

	err = -ENODATA;

	cur_offset = area.compressed.offset;

	while (cur_offset < SSDFS_COMPRESSED_AREA_UPPER_BOUND(&area)) {
		err = ssdfs_unaligned_read_cache(pebi, req, cur_offset,
						 tbl_size, table);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read area block table: "
				  "area_offset %u, area_size %u, "
				  "cur_offset %u, tbl_size %zu, err %d\n",
				  area.compressed.offset,
				  area.compressed.size,
				  cur_offset, tbl_size, err);
			return err;
		}

		if (table->chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
			SSDFS_ERR("corrupted area block table: "
				  "magic (expected %#x, found %#x)\n",
				  SSDFS_CHAIN_HDR_MAGIC,
				  table->chain_hdr.magic);
			return -EIO;
		}

		switch (table->chain_hdr.type) {
		case SSDFS_BLK_DESC_ZLIB_CHAIN_HDR:
		case SSDFS_BLK_DESC_LZO_CHAIN_HDR:
			/* expected type */
			break;

		default:
			SSDFS_ERR("unexpected area block table's type %#x\n",
				  table->chain_hdr.type);
			return -EIO;
		}

		portion_desc = &frag_desc->portion;

		if (IS_SSDFS_COMPRESSED_PORTION_INVALID(portion_desc)) {
			SSDFS_INIT_COMPRESSED_PORTION_DESC(portion_desc,
							   meta_desc,
							   &table->chain_hdr,
							   tbl_size);
		} else {
			err = SSDFS_ADD_COMPRESSED_PORTION(portion_desc,
							   &table->chain_hdr);
			if (unlikely(err)) {
				SSDFS_ERR("fail to add portion: "
					  "cur_offset %u, offset %u, err %d\n",
					  cur_offset, offset, err);
				return err;
			}
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cur_offset %u, offset %u, "
			  "compr_bytes %u, uncompr_bytes %u\n",
			  cur_offset, offset,
			  le32_to_cpu(table->chain_hdr.compr_bytes),
			  le32_to_cpu(table->chain_hdr.uncompr_bytes));
#endif /* CONFIG_SSDFS_DEBUG */

		if (IS_OFFSET_INSIDE_UNCOMPRESSED_PORTION(portion_desc,
							  offset)) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("portion has been found: "
				  "cur_offset %u, offset %u, "
				  "compr_bytes %u, uncompr_bytes %u\n",
				  cur_offset, offset,
				  le32_to_cpu(table->chain_hdr.compr_bytes),
				  le32_to_cpu(table->chain_hdr.uncompr_bytes));
#endif /* CONFIG_SSDFS_DEBUG */
			break;
		} else {
			flags = le16_to_cpu(table->chain_hdr.flags);

			if (!(flags & SSDFS_MULTIPLE_HDR_CHAIN)) {
				SSDFS_ERR("corrupted area block table: "
					  "invalid flags set %#x\n",
					  flags);
				return -EIO;
			}

			cur_offset =
			    SSDFS_COMPRESSED_PORTION_UPPER_BOUND(portion_desc);

			fragments =
			    le16_to_cpu(table->chain_hdr.fragments_count);
			if (fragments <= SSDFS_NEXT_BLK_TABLE_INDEX) {
				SSDFS_ERR("corrupted area block table: "
					  "fragments_count %u\n",
					  fragments);
				return -EIO;
			}

			next_portion_desc =
				&table->blk[SSDFS_NEXT_BLK_TABLE_INDEX];

			if (next_portion_desc->magic !=
						SSDFS_FRAGMENT_DESC_MAGIC) {
				SSDFS_ERR("corrupted fragment descriptor: "
					  "magic (expected %#x, found %#x)\n",
					  SSDFS_FRAGMENT_DESC_MAGIC,
					  next_portion_desc->magic);
				return -EIO;
			}

			if (next_portion_desc->type != SSDFS_NEXT_TABLE_DESC) {
				SSDFS_ERR("corrupted fragment descriptor: "
					  "type (expected %#x, found %#x)\n",
					  SSDFS_NEXT_TABLE_DESC,
					  next_portion_desc->type);
				return -EIO;
			}

			next_portion_offset = area.compressed.offset +
					le32_to_cpu(next_portion_desc->offset);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cur_offset %u, area.compressed.offset %u, "
				  "frag offset %u, next_portion_offset %u\n",
				  cur_offset, area.compressed.offset,
				  le32_to_cpu(next_portion_desc->offset),
				  next_portion_offset);
#endif /* CONFIG_SSDFS_DEBUG */

			if (next_portion_offset < cur_offset ||
			    next_portion_offset >=
				    SSDFS_COMPRESSED_AREA_UPPER_BOUND(&area)) {
				SSDFS_ERR("corrupted fragment descriptor: "
					  "offset %u\n",
					  next_portion_offset);
				return -EIO;
			}

			/*
			 * Next portion offset can be aligned.
			 * Fragment offset keeps accurate value.
			 */
			cur_offset = next_portion_offset;
		}
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to find block descriptor portion: "
			  "offset %u, err %d\n",
			  offset, err);
	}

	return err;
}

/*
 * ssdfs_peb_decompress_blk_desc_fragment() - decompress blk desc fragment
 * @pebi: pointer on PEB object
 * @req: request
 * @meta_desc: area descriptor
 * @offset: offset in bytes to read block descriptor
 * @frag_desc: fragment offset descriptor [in|out]
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
				struct ssdfs_compressed_fragment *frag_desc)
{
	struct ssdfs_area_block_table table;
	struct ssdfs_fragment_desc *frag;
	u16 fragments_count;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!meta_desc || !frag_desc);
	BUG_ON(!rwsem_is_locked(&pebi->read_buffer.lock));

	SSDFS_DBG("seg %llu, peb %llu, offset %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id,
		  offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_find_blk_desc_portion(pebi, req, meta_desc,
					      offset, &table, frag_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find block descriptor portion: "
			  "offset %u, err %d\n",
			  offset, err);
		return err;
	}

	if (IS_SSDFS_COMPRESSED_PORTION_INVALID(&frag_desc->portion)) {
		SSDFS_ERR("portion is invalid\n");
		return -ERANGE;
	}

	fragments_count = le16_to_cpu(table.chain_hdr.fragments_count);

	for (i = 0; i < fragments_count; i++) {
		frag = &table.blk[i];

		err = ssdfs_peb_check_blk_desc_fragment(pebi, req, frag,
							offset, frag_desc);
		if (err == -EAGAIN) {
			/* check next fragment */
			err = 0;
		} else if (unlikely(err)) {
			SSDFS_ERR("fragment check has failed: "
				  "offset %u, "
				  "fragment_index %d, "
				  "err %d\n",
				  offset, i, err);
			return err;
		} else {
			/* fragment has been found */
			break;
		}
	}

	if (i >= fragments_count) {
		SSDFS_ERR("corrupted area block table: "
			  "i %d >= fragments_count %u\n",
			  i, fragments_count);
		return -EIO;
	}

	return 0;
}

/*
 * is_read_buffer_offset_invalid() - check that read buffer's offset is invalid
 */
static inline
bool is_read_buffer_offset_invalid(struct ssdfs_peb_temp_read_buffers *buf,
				   u32 area_offset)
{
	struct ssdfs_compressed_area *area_desc;
	struct ssdfs_compressed_fragment *frag_desc;

	frag_desc = &buf->blk_desc.frag_desc;
	area_desc = &frag_desc->portion.area;

	if (IS_SSDFS_COMPRESSED_AREA_DESC_INVALID(area_desc) ||
	    SSDFS_AREA_COMPRESSED_OFFSET(area_desc) != area_offset ||
	    IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(frag_desc)) {
		memset(frag_desc,
			0xFF, sizeof(struct ssdfs_compressed_fragment));
		return true;
	} else
		return false;
}

/*
 * read_buffer_has_no_requested_data() - check that buffer contains requested data
 */
static inline
bool read_buffer_has_no_requested_data(struct ssdfs_peb_temp_read_buffers *buf,
				       u32 offset)
{
	struct ssdfs_compressed_fragment *frag_desc;

	frag_desc = &buf->blk_desc.frag_desc;

	if (!IS_OFFSET_INSIDE_UNCOMPRESSED_FRAGMENT(frag_desc, offset)) {
		memset(frag_desc,
			0xFF, sizeof(struct ssdfs_compressed_fragment));
		return true;
	} else
		return false;
}

/*
 * SSDFS_METADATA_DESC_COMPR_TYPE() - define metadata's compression type
 */
static inline
int SSDFS_METADATA_DESC_COMPR_TYPE(struct ssdfs_metadata_descriptor *meta_desc)
{
	u16 flags;
	int compr_type = SSDFS_COMPR_NONE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!meta_desc);
#endif /* CONFIG_SSDFS_DEBUG */

	flags = le16_to_cpu(meta_desc->check.flags);

	if ((flags & SSDFS_ZLIB_COMPRESSED) &&
	    (flags & SSDFS_LZO_COMPRESSED)) {
		SSDFS_ERR("invalid set of flags: "
			  "flags %#x\n",
			  flags);
		return compr_type;
	}

	if (flags & SSDFS_ZLIB_COMPRESSED)
		compr_type = SSDFS_COMPR_ZLIB;
	else if (flags & SSDFS_LZO_COMPRESSED)
		compr_type = SSDFS_COMPR_LZO;

	return compr_type;
}

/*
 * ssdfs_peb_read_compressed_block_descriptor() - read compressed block descriptor
 * @pebi: pointer on PEB object
 * @req: request
 * @meta_desc: area descriptor
 * @blk_state: block state descriptor
 * @blk_desc: block descriptor [out]
 *
 * This function tries to read compressed block descriptor.
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
int ssdfs_peb_read_compressed_block_descriptor(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req,
				    struct ssdfs_metadata_descriptor *meta_desc,
				    struct ssdfs_blk_state_offset *blk_state,
				    struct ssdfs_block_descriptor *blk_desc)
{
	struct ssdfs_peb_temp_read_buffers *buf;
	struct ssdfs_compressed_fragment *frag_desc;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	u32 area_offset;
	u32 area_size;
	u32 blk_desc_off;
	u32 frag_offset;
	u32 frag_size;
	u32 offset;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!meta_desc || !blk_state || !blk_desc);

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	buf = &pebi->read_buffer;

	area_offset = le32_to_cpu(meta_desc->offset);
	area_size = le32_to_cpu(meta_desc->size);
	blk_desc_off = le32_to_cpu(blk_state->byte_offset);
	offset = area_offset + blk_desc_off;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("area_offset %u, blk_desc_off %u\n",
		  area_offset, blk_desc_off);
#endif /* CONFIG_SSDFS_DEBUG */

	down_write(&buf->lock);

	if (!buf->blk_desc.ptr) {
		err = -ENOMEM;
		SSDFS_ERR("buffer is not allocated\n");
		goto finish_decompress;
	}

	frag_desc = &buf->blk_desc.frag_desc;

	if (is_read_buffer_offset_invalid(buf, area_offset)) {
		err = ssdfs_peb_decompress_blk_desc_fragment(pebi,
							     req,
							     meta_desc,
							     offset,
							     frag_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to decompress: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			goto finish_decompress;
		}
	} else if (read_buffer_has_no_requested_data(buf, offset)) {
		err = ssdfs_peb_decompress_blk_desc_fragment(pebi,
							     req,
							     meta_desc,
							     offset,
							     frag_desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to decompress: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			goto finish_decompress;
		}
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("Read block descsriptor from the buffer\n");
#endif /* CONFIG_SSDFS_DEBUG */
	}

finish_decompress:
	downgrade_write(&buf->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to decompress portion: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		goto finish_read_compressed_blk_desc;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(IS_SSDFS_COMPRESSED_FRAGMENT_INVALID(frag_desc));
#endif /* CONFIG_SSDFS_DEBUG */

	frag_offset = SSDFS_FRAGMENT_UNCOMPRESSED_OFFSET(frag_desc);
	frag_size = frag_desc->uncompressed.size;

	err = ssdfs_memcpy(blk_desc,
			   0, blk_desc_size,
			   buf->blk_desc.ptr,
			   offset - frag_offset,
			   frag_size,
			   blk_desc_size);
	if (unlikely(err)) {
		SSDFS_ERR("invalid buffer state: "
			  "seg %llu, peb %llu, offset %u, "
			  "buffer (offset %u, size %u)\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, offset, frag_offset,
			  frag_size);
		goto finish_read_compressed_blk_desc;
	}

finish_read_compressed_blk_desc:
	up_read(&buf->lock);

	if (unlikely(err)) {
		SSDFS_ERR("fail to read compressed block descriptor: "
			  "seg %llu, peb %llu, offset %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, offset, err);
		return err;
	}

	return err;
}

/*
 * ssdfs_peb_read_block_descriptor() - read block descriptor
 * @pebi: pointer on PEB object
 * @req: request
 * @meta_desc: area descriptor
 * @blk_state: block state descriptor
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
				    struct ssdfs_blk_state_offset *blk_state,
				    struct ssdfs_block_descriptor *blk_desc)
{
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	int compr_type = SSDFS_COMPR_NONE;
	u32 area_offset;
	u32 blk_desc_off;
	u32 offset;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!meta_desc || !blk_state || !blk_desc);

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	compr_type = SSDFS_METADATA_DESC_COMPR_TYPE(meta_desc);

	if (compr_type != SSDFS_COMPR_NONE) {
		err = ssdfs_peb_read_compressed_block_descriptor(pebi, req,
								 meta_desc,
								 blk_state,
								 blk_desc);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to read compressed block descriptor: "
				  "seg %llu, peb %llu, "
				  "offset %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  offset, err);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		}
	} else {
		area_offset = le32_to_cpu(meta_desc->offset);
		blk_desc_off = le32_to_cpu(blk_state->byte_offset);
		offset = area_offset + blk_desc_off;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("area_offset %u, blk_desc_off %u\n",
			  area_offset, blk_desc_off);
#endif /* CONFIG_SSDFS_DEBUG */

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
 * ssdfs_peb_read_block_descriptor_from_volume() - read block descriptor
 * @pebi: pointer on PEB object
 * @req: request
 * @meta_desc: area descriptor
 * @blk_state: block state descriptor
 * @blk_desc: block descriptor [out]
 *
 * This function tries to read block descriptor from volume.
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
int ssdfs_peb_read_block_descriptor_from_volume(struct ssdfs_peb_info *pebi,
				    struct ssdfs_segment_request *req,
				    struct ssdfs_metadata_descriptor *meta_desc,
				    struct ssdfs_blk_state_offset *blk_state,
				    struct ssdfs_block_descriptor *blk_desc)
{
	struct ssdfs_fs_info *fsi;
	struct folio *folio;
	struct folio_batch batch;
	u32 area_offset;
	u32 area_size;
	u32 blk_desc_off;
	u32 folio_index;
	u32 folios_count;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!meta_desc || !blk_desc);

	SSDFS_DBG("seg %llu, peb %llu\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	area_offset = le32_to_cpu(meta_desc->offset);
	area_size = le32_to_cpu(meta_desc->size);
	blk_desc_off = le32_to_cpu(blk_state->byte_offset);

	folio_index = (area_offset + blk_desc_off) / pebi->cache.folio_size;

	folios_count = (area_size + fsi->pagesize - 1) / pebi->cache.folio_size;
	folios_count = min_t(u32, folios_count, SSDFS_EXTENT_LEN_MAX);

	folio_batch_init(&batch);

	for (i = 0; i < folios_count; i++) {
		folio = ssdfs_folio_array_grab_folio(&pebi->cache,
							folio_index + i);
		if (unlikely(IS_ERR_OR_NULL(folio))) {
			SSDFS_ERR("fail to grab folio: index %u\n",
				  folio_index);
			return -ENOMEM;
		}

		if (folio_test_uptodate(folio) || folio_test_dirty(folio))
			break;

		folio_batch_add(&batch, folio);
	}

	err = ssdfs_read_folio_batch_from_volume(fsi, pebi->peb_id,
						 folio_index *
							pebi->cache.folio_size,
						 &batch);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read folio batch: "
			  "peb_id %llu, folio_index %u, "
			  "folios_count %u, err %d\n",
			  pebi->peb_id, folio_index,
			  folios_count, err);
		return err;
	}

	for (i = 0; i < folio_batch_count(&batch); i++) {
		folio = batch.folios[i];

		if (!folio) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %d is NULL\n", i);
#endif /* CONFIG_SSDFS_DEBUG */
			continue;
		}

		ssdfs_folio_put(folio);
		batch.folios[i] = NULL;
	}

	folio_batch_reinit(&batch);

	err = ssdfs_peb_read_block_descriptor(pebi, req, meta_desc,
					      blk_state, blk_desc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block descriptor: "
			  "peb %llu, area_offset %u, "
			  "byte_offset %u, err %d\n",
			  pebi->peb_id, area_offset,
			  blk_desc_off, err);
		return err;
	}

	return 0;
}

/*
 * is_ssdfs_block_descriptor_valid() - check that block descriptor is valid
 */
static inline
bool is_ssdfs_block_descriptor_valid(struct ssdfs_fs_info *fsi,
				     struct ssdfs_segment_request *req,
				     struct ssdfs_block_descriptor *blk_desc)
{
	u64 calculated;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !req || !blk_desc);
#endif /* CONFIG_SSDFS_DEBUG */

	if (le64_to_cpu(blk_desc->ino) != req->extent.ino) {
		SSDFS_ERR("blk_desc->ino %llu != req->extent.ino %llu\n",
			  le64_to_cpu(blk_desc->ino), req->extent.ino);
		return false;
	}

	calculated = req->extent.logical_offset;
	calculated += (u64)req->result.processed_blks * fsi->pagesize;
	calculated = div_u64(calculated, fsi->pagesize);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("req->extent.logical_offset %llu, "
		  "req->result.processed_blks %d, "
		  "calculated %llu, "
		  "blk_desc->logical_offset %u\n",
		  req->extent.logical_offset,
		  req->result.processed_blks,
		  calculated,
		  le32_to_cpu(blk_desc->logical_offset));
#endif /* CONFIG_SSDFS_DEBUG */

	if (calculated != le32_to_cpu(blk_desc->logical_offset)) {
		SSDFS_WARN("requested logical_offset %llu "
			   "differs from found logical_offset %u\n",
			   calculated,
			   le32_to_cpu(blk_desc->logical_offset));
		return false;
	}

	calculated = (u64)req->result.processed_blks * fsi->pagesize;

	if (calculated >= req->extent.data_bytes) {
		SSDFS_ERR("calculated %llu >= req->extent.data_bytes %u\n",
			  calculated, req->extent.data_bytes);
		return false;
	}

	return true;
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
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	int area_index;
	u32 area_offset;
	u32 blk_desc_off;
	u16 log_start_page;
#ifdef CONFIG_SSDFS_DEBUG
	u32 i;
#endif /* CONFIG_SSDFS_DEBUG */
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
	log_start_page = le16_to_cpu(blk_state->log_start_page);

	err = ssdfs_peb_read_log_hdr_desc_array(pebi, req,
						log_start_page,
						array, array_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read log's header desc array: "
			  "seg %llu, peb %llu, log_start_page %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  log_start_page,
			  err);
		return err;
	}

	area_index = SSDFS_AREA_TYPE2INDEX(blk_state->log_area);

	if (area_index >= SSDFS_SEG_HDR_DESC_MAX) {
		SSDFS_ERR("invalid area index %#x\n", area_index);
		return -ERANGE;
	}

	err = ssdfs_peb_read_block_descriptor(pebi, req,
					      &array[area_index],
					      blk_state, blk_desc);
	if (err) {
		err = ssdfs_peb_read_block_descriptor_from_volume(pebi, req,
							&array[area_index],
							blk_state, blk_desc);
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
		if (!is_ssdfs_block_descriptor_valid(fsi, req, blk_desc)) {
			SSDFS_ERR("invalid block descriptor!!!\n");
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
		SSDFS_DBG("cache hasn't requested folio\n");

		if (req->private.flags & SSDFS_REQ_READ_ONLY_CACHE)
			return -ENOENT;

		err = ssdfs_unaligned_read_buffer(fsi, pebi->peb_id,
						  fsi->pagesize,
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
		SSDFS_DBG("cache hasn't requested folio\n");
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
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	size_t read_size = 0;
	u32 buf_off = 0;
	size_t array_bytes = size;
#ifdef CONFIG_SSDFS_DEBUG
	void *kaddr;
#endif /* CONFIG_SSDFS_DEBUG */

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

	fsi = pebi->pebc->parent_si->fsi;

	while (size > 0) {
		err = SSDFS_OFF2FOLIO(pebi->cache.folio_size,
				      byte_off, &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "byte_off %u, err %d\n",
				  byte_off, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		read_size = min_t(size_t, size,
				    PAGE_SIZE - folio.desc.offset_inside_page);

		folio.ptr = ssdfs_peb_read_folio_locked(pebi, req,
							folio.desc.folio_index);
		if (IS_ERR_OR_NULL(folio.ptr)) {
			err = IS_ERR(folio.ptr) ? PTR_ERR(folio.ptr) : -ERANGE;
			if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("cache hasn't folio: index %u\n",
					  folio.desc.folio_index);
#endif /* CONFIG_SSDFS_DEBUG */
			} else {
				SSDFS_ERR("fail to read locked folio: index %u\n",
					  folio.desc.folio_index);
			}
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("byte_off %u, size %zu, read_size %zu, "
			  "folio_index %u, page_in_folio %u, "
			  "offset_inside_page %u, buf_off %u\n",
			  byte_off, size, read_size,
			  folio.desc.folio_index,
			  folio.desc.page_in_folio,
			  folio.desc.offset_inside_page,
			  buf_off);

		kaddr = kmap_local_folio(folio.ptr, folio.desc.page_offset);
		SSDFS_DBG("PAGE DUMP: folio_index %d, "
			  "page_offset %u\n",
			  folio.desc.folio_index,
			  folio.desc.page_offset);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr,
				     PAGE_SIZE);
		SSDFS_DBG("\n");
		kunmap_local(kaddr);
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_memcpy_from_folio(buf, buf_off, array_bytes,
					      &folio, read_size);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("FRAGMENT DUMP: offset %u, size %u\n",
			  buf_off, 128);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     buf, 128);
		SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_unlock(folio.ptr);
		ssdfs_folio_put(folio.ptr);

		if (unlikely(err)) {
			SSDFS_ERR("fail to copy: "
				  "offset_inside_page %u, buf_off %u, "
				  "read_size %zu, size %zu, err %d\n",
				  folio.desc.offset_inside_page,
				  buf_off, read_size, array_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio.ptr, folio_ref_count(folio.ptr));
#endif /* CONFIG_SSDFS_DEBUG */

		size -= read_size;
		buf_off += read_size;
		byte_off += read_size;
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
	size_t frag_desc_size = sizeof(struct ssdfs_fragment_desc);
	size_t array_bytes = frag_desc_size * array_size;
	size_t size = array_bytes;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!array);

	SSDFS_DBG("seg %llu, peb %llu, "
		  "array_offset %u, array_size %zu\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  array_offset, array_size);
#endif /* CONFIG_SSDFS_DEBUG */

	return ssdfs_peb_unaligned_read_fragment(pebi, req,
						 array_offset,
						 size, array);
}

/*
 * IS_SSDFS_FRAGMENT_COMPRESSED() - check that fragment is compressed
 */
static inline
bool IS_SSDFS_FRAGMENT_COMPRESSED(struct ssdfs_fragment_desc *desc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	return desc->type == SSDFS_FRAGMENT_ZLIB_BLOB ||
		desc->type == SSDFS_FRAGMENT_LZO_BLOB;
}

/*
 * SSDFS_GET_FRAGMENT_COMPR_TYPE() - get fragment compression type
 */
static inline
int SSDFS_GET_FRAGMENT_COMPR_TYPE(struct ssdfs_fragment_desc *desc)
{
	int compr_type = SSDFS_COMPR_NONE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

	if (desc->type == SSDFS_FRAGMENT_ZLIB_BLOB)
		compr_type = SSDFS_COMPR_ZLIB;
	else if (desc->type == SSDFS_FRAGMENT_LZO_BLOB)
		compr_type = SSDFS_COMPR_LZO;

	return compr_type;
}

/*
 * ssdfs_read_compressed_fragment() - read compressed fragment
 * @pebi: pointer on PEB object
 * @req: segment request
 * @area_offset: offset in bytes from log's begin
 * @desc: fragment descriptor
 * @cdata_buf: compressed data buffer
 * @page: buffer for uncompressed data
 *
 * This function tries to read compressed fragment.
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
int ssdfs_read_compressed_fragment(struct ssdfs_peb_info *pebi,
				   struct ssdfs_segment_request *req,
				   u32 area_offset,
				   struct ssdfs_fragment_desc *desc,
				   void *cdata_buf,
				   struct page *page)
{
	struct ssdfs_fs_info *fsi;
	void *kaddr;
	u32 pebsize;
	u32 offset;
	int compr_type;
	size_t compr_size, uncompr_size;
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
		  desc->sequence_id,
		  le32_to_cpu(desc->offset),
		  le16_to_cpu(desc->compr_size),
		  le16_to_cpu(desc->uncompr_size));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	pebsize = fsi->pages_per_peb * fsi->pagesize;
	offset = area_offset + le32_to_cpu(desc->offset);
	compr_type = SSDFS_GET_FRAGMENT_COMPR_TYPE(desc);
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

	kaddr = kmap_local_page(page);
	err = ssdfs_decompress(compr_type, cdata_buf, kaddr,
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
 * ssdfs_read_uncompressed_fragment() - read uncompressed fragment
 * @pebi: pointer on PEB object
 * @req: segment request
 * @area_offset: offset in bytes from log's begin
 * @desc: fragment descriptor
 * @cdata_buf: compressed data buffer
 * @page: buffer for uncompressed data
 *
 * This function tries to read uncompressed fragment.
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
int ssdfs_read_uncompressed_fragment(struct ssdfs_peb_info *pebi,
				     struct ssdfs_segment_request *req,
				     u32 area_offset,
				     struct ssdfs_fragment_desc *desc,
				     void *cdata_buf,
				     struct page *page)
{
	struct ssdfs_fs_info *fsi;
	void *kaddr;
	u32 pebsize;
	u32 offset;
	size_t compr_size, uncompr_size;
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
		  desc->sequence_id,
		  le32_to_cpu(desc->offset),
		  le16_to_cpu(desc->compr_size),
		  le16_to_cpu(desc->uncompr_size));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

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
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"uncompr_size %zu > PAGE_CACHE %lu\n",
				uncompr_size, PAGE_SIZE);
		return -EIO;
	}

	if (compr_size != uncompr_size) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"compr_size %zu != uncompr_size %zu\n",
				compr_size, uncompr_size);
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
	size_t uncompr_size;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!desc || !cdata_buf || !page);

	SSDFS_DBG("seg %llu, peb %llu, area_offset %u, sequence_id %u, "
		  "offset %u, compr_size %u, uncompr_size %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  area_offset,
		  desc->sequence_id,
		  le32_to_cpu(desc->offset),
		  le16_to_cpu(desc->compr_size),
		  le16_to_cpu(desc->uncompr_size));
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	if (sequence_id != desc->sequence_id) {
		SSDFS_ERR("sequence_id %d != desc->sequence_id %u\n",
			  sequence_id, desc->sequence_id);
		return -EINVAL;
	}

	pebsize = fsi->pages_per_peb * fsi->pagesize;
	offset = area_offset + le32_to_cpu(desc->offset);
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

	if (IS_SSDFS_FRAGMENT_COMPRESSED(desc)) {
		err = ssdfs_read_compressed_fragment(pebi, req, area_offset,
						     desc, cdata_buf, page);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read compressed fragment: "
				  "seg %llu, peb %llu, offset %u, size %zu, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  offset, uncompr_size, err);
		}
	} else {
		err = ssdfs_read_uncompressed_fragment(pebi, req, area_offset,
							desc, cdata_buf, page);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read uncompressed fragment: "
				  "seg %llu, peb %llu, offset %u, size %zu, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  offset, uncompr_size, err);
		}
	}

	return err;
}

/*
 * ssdfs_peb_read_main_area_block() - read main area's block
 * @pebi: pointer on PEB object
 * @req: request
 * @array: array of area's descriptors
 * @array_size: count of items into array
 * @blk_state_off: block state offset
 *
 * This function tries to read main area's block.
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
int ssdfs_peb_read_main_area_block(struct ssdfs_peb_info *pebi,
				   struct ssdfs_segment_request *req,
				   struct ssdfs_metadata_descriptor *array,
				   size_t array_size,
				   struct ssdfs_blk_state_offset *blk_state_off)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_smart_folio folio;
	struct ssdfs_request_content_block *block = NULL;
	struct ssdfs_content_block *state = NULL;
	void *kaddr;
	u8 area_index;
	u32 area_offset;
	u32 data_bytes;
	u32 processed_bytes;
	u32 read_bytes;
	u32 byte_offset;
	u32 batch_count;
	u32 blk_index;
	int folio_index = 0;
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

	blk_index = req->result.processed_blks;
	processed_bytes = req->result.processed_blks * fsi->pagesize;

	if (processed_bytes > req->extent.data_bytes) {
		SSDFS_ERR("processed_bytes %u > req->extent.data_bytes %u\n",
			  processed_bytes, req->extent.data_bytes);
		return -ERANGE;
	} else if (processed_bytes == req->extent.data_bytes) {
		SSDFS_WARN("processed_bytes %u == req->extent.data_bytes %u\n",
			   processed_bytes, req->extent.data_bytes);
		return -ERANGE;
	}

	data_bytes = req->extent.data_bytes - processed_bytes;
	data_bytes = min_t(u32, data_bytes, fsi->pagesize);

	area_offset = le32_to_cpu(array[area_index].offset);
	byte_offset = le32_to_cpu(blk_state_off->byte_offset);

	read_bytes = 0;
	while (read_bytes < data_bytes) {
		u8 *ptr;
		u32 cur_offset;
		size_t iter_size;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("processed_bytes %u, read_bytes %u\n",
			  processed_bytes, read_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		block = &req->result.content.blocks[blk_index];

		if (req->private.flags & SSDFS_REQ_PREPARE_DIFF)
			state = &block->old_state;
		else
			state = &block->new_state;

		batch_count = folio_batch_count(&state->batch);

		if (folio_index >= batch_count) {
			SSDFS_ERR("folio_index %d >= batch_count %u\n",
				  folio_index, batch_count);
			return -EIO;
		}

		folio.ptr = state->batch.folios[folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		err = SSDFS_OFF2FOLIO(folio_size(folio.ptr), processed_bytes,
				      &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "processed_bytes %u, err %d\n",
				  processed_bytes, err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		iter_size = min_t(size_t, PAGE_SIZE, data_bytes - read_bytes);
		iter_size = min_t(size_t, iter_size,
				    PAGE_SIZE - folio.desc.offset_inside_page);

		cur_offset = area_offset + byte_offset + read_bytes;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("area_offset %u, byte_offset %u, "
			  "read_bytes %u, cur_offset %u, "
			  "iter_size %zu, folio.desc.page_offset %u, "
			  "folio.desc.offset_inside_page %u\n",
			  area_offset, byte_offset,
			  read_bytes, cur_offset,
			  iter_size, folio.desc.page_offset,
			  folio.desc.offset_inside_page);
#endif /* CONFIG_SSDFS_DEBUG */

		kaddr = kmap_local_folio(folio.ptr, folio.desc.page_offset);
		ptr = (u8 *)kaddr + folio.desc.offset_inside_page;
		err = ssdfs_peb_unaligned_read_fragment(pebi, req,
							cur_offset,
							iter_size,
							ptr);
		kunmap_local(kaddr);

		if (unlikely(err)) {
			SSDFS_ERR("fail to read folio: "
				  "seg %llu, peb %llu, "
				  "offset %u, size %zu, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, cur_offset,
				  iter_size, err);
			return err;
		}

		if ((folio.desc.page_offset + PAGE_SIZE) >= folio_size(folio.ptr))
			folio_index++;

		read_bytes += iter_size;
		processed_bytes += iter_size;

		flush_dcache_folio(folio.ptr);
	}

	return 0;
}

/*
 * IS_SSDFS_FRAGMENT_DESCRIPTOR_VALID() - check fragment descriptor is valid
 */
static inline
bool IS_SSDFS_FRAGMENT_DESCRIPTOR_VALID(struct ssdfs_fragment_desc *desc,
					int fragment_index)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!desc);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("FRAGMENT DESC DUMP: index %d\n",
		  fragment_index);
	print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
			     desc,
			     sizeof(struct ssdfs_fragment_desc));
	SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

	if (desc->magic != SSDFS_FRAGMENT_DESC_MAGIC) {
		SSDFS_ERR("invalid fragment descriptor magic\n");
		return false;
	}

	if (desc->type < SSDFS_FRAGMENT_UNCOMPR_BLOB ||
	    desc->type > SSDFS_FRAGMENT_LZO_BLOB) {
		SSDFS_ERR("invalid fragment descriptor type\n");
		return false;
	}

	if (desc->sequence_id != fragment_index) {
		SSDFS_ERR("invalid fragment's sequence id\n");
		return false;
	}

	return true;
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
	struct ssdfs_request_content_block *block = NULL;
	struct ssdfs_content_block *state = NULL;
	struct ssdfs_smart_folio folio;
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
	u32 processed_bytes;
	u16 fragments;
	u32 uncompr_bytes;
	u32 blk_index;
	int folio_index = 0;
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

	blk_index = req->result.processed_blks;
	processed_bytes = req->result.processed_blks * fsi->pagesize;

	if (processed_bytes > req->extent.data_bytes) {
		SSDFS_ERR("processed_bytes %u > req->extent.data_bytes %u\n",
			  processed_bytes, req->extent.data_bytes);
		return -ERANGE;
	} else if (processed_bytes == req->extent.data_bytes) {
		SSDFS_WARN("processed_bytes %u == req->extent.data_bytes %u\n",
			   processed_bytes, req->extent.data_bytes);
		return -ERANGE;
	}

	data_bytes = req->extent.data_bytes - processed_bytes;
	data_bytes = min_t(u32, data_bytes, fsi->pagesize);

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
		  "full_offset %u, fragments %u\n",
		  area_offset, le32_to_cpu(blk_state_off->byte_offset),
		  state_desc_size, frag_desc_offset, full_offset,
		  fragments);
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

	for (i = 0; i < fragments; i++) {
		struct page *page;
		struct ssdfs_fragment_desc *cur_desc;
		u32 compr_size;

		block = &req->result.content.blocks[blk_index];

		if (req->private.flags & SSDFS_REQ_PREPARE_DIFF)
			state = &block->old_state;
		else
			state = &block->new_state;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment_index %d, fragments %u, "
			  "processed_bytes %u, folio_index %d\n",
			  i, fragments,
			  processed_bytes, folio_index);
#endif /* CONFIG_SSDFS_DEBUG */

		if (folio_index >= folio_batch_count(&state->batch)) {
			SSDFS_ERR("folio_index %d >= batch_count %u\n",
				  folio_index,
				  folio_batch_count(&state->batch));
			return -EIO;
		}

		folio.ptr = state->batch.folios[folio_index];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!folio.ptr);
#endif /* CONFIG_SSDFS_DEBUG */

		err = SSDFS_OFF2FOLIO(folio_size(folio.ptr), processed_bytes,
				      &folio.desc);
		if (unlikely(err)) {
			SSDFS_ERR("fail to convert offset into folio: "
				  "processed_bytes %u, err %d\n",
				  processed_bytes, err);
			goto free_bufs;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!IS_SSDFS_OFF2FOLIO_VALID(&folio.desc));
#endif /* CONFIG_SSDFS_DEBUG */

		cur_desc = &frag_descs[i];

		if (!IS_SSDFS_FRAGMENT_DESCRIPTOR_VALID(cur_desc, i)) {
			err = -EIO;
			SSDFS_ERR("corrupted fragment descriptor\n");
			goto free_bufs;
		}

		compr_size = le16_to_cpu(cur_desc->compr_size);

		if (compr_size > PAGE_SIZE) {
			err = -EIO;
			SSDFS_ERR("compr_size %u > PAGE_SIZE %lu\n",
				  compr_size, PAGE_SIZE);
			goto free_bufs;
		}

		page = folio_page(folio.ptr, folio.desc.page_in_folio);

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

		processed_bytes += PAGE_SIZE;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio.desc.page_offset %u, "
			  "folio_size %zu, folio_index %d\n",
			  folio.desc.page_offset,
			  folio_size(folio.ptr),
			  folio_index);
#endif /* CONFIG_SSDFS_DEBUG */

		if ((folio.desc.page_offset + PAGE_SIZE) >=
						folio_size(folio.ptr)) {
			folio_index++;
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
		err = ssdfs_peb_read_main_area_block(pebi, req,
						     array, array_size,
						     offset);
		if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("cache hasn't requested block: "
				  "seg %llu, peb %llu, "
				  "ino %llu, logical_offset %llu\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  req->extent.ino,
				  req->extent.logical_offset);
#endif /* CONFIG_SSDFS_DEBUG */
			return err;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read main area's block: "
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
 * @folio: folio with current diff blob
 * @sequence_id: sequence ID of the fragment
 *
 * This function tries to extract a diff blob into @folio.
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
				 struct folio *folio,
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
	u16 log_start_blk;
#ifdef CONFIG_SSDFS_DEBUG
	void *kaddr;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!array || !blk_state_off || !folio);

	SSDFS_DBG("seg %llu, peb %llu, sequence_id %d\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, sequence_id);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	log_start_blk = le16_to_cpu(blk_state_off->log_start_page);

	err = ssdfs_peb_read_log_hdr_desc_array(pebi, req, log_start_blk,
						array, array_size);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read log's header desc array: "
			  "seg %llu, peb %llu, log_start_blk %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  log_start_blk,
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

	if (!IS_SSDFS_FRAGMENT_DESCRIPTOR_VALID(&frag_desc, sequence_id)) {
		err = -EIO;
		SSDFS_ERR("corrupted fragment descriptor\n");
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
					  folio_page(folio, 0));
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
	kaddr = kmap_local_page(folio_page(folio, 0));
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
	struct folio *folio = NULL;
	int sequence_id;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!array || !offset);
	BUG_ON(array_size != SSDFS_SEG_HDR_DESC_MAX);

	SSDFS_DBG("seg %llu, peb %llu, batch_size %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  folio_batch_count(&req->result.diffs));
#endif /* CONFIG_SSDFS_DEBUG */

	folio = ssdfs_request_allocate_and_add_diff_folio(req);
	if (unlikely(IS_ERR_OR_NULL(folio))) {
		err = !folio ? -ENOMEM : PTR_ERR(folio);
		SSDFS_ERR("fail to add folio into batch: err %d\n",
			  err);
		return err;
	}

	ssdfs_folio_lock(folio);

	sequence_id = folio_batch_count(&req->result.diffs) - 1;
	err = ssdfs_peb_read_area_diff_fragment(pebi, req, array, array_size,
						offset, folio, sequence_id);
	if (err == -ENOENT) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cache hasn't requested folio: "
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
			struct ssdfs_peb_page_descriptor *page_desc;
			struct ssdfs_blk_state_offset *blk_state;

			page_desc = &desc_off->page_desc;
			blk_state = &desc_off->blk_state;

			err = pebi == NULL ? -ERANGE : PTR_ERR(pebi);
			SSDFS_ERR("fail to get PEB object: "
				  "seg %llu, peb_index %u, "
				  "logical_offset %u, logical_blk %u, "
				  "peb_page %u, log_start_page %u, "
				  "log_area %u, peb_migration_id %u, "
				  "byte_offset %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index,
				  le32_to_cpu(page_desc->logical_offset),
				  le16_to_cpu(page_desc->logical_blk),
				  le16_to_cpu(page_desc->peb_page),
				  le16_to_cpu(blk_state->log_start_page),
				  blk_state->log_area,
				  peb_migration_id,
				  le32_to_cpu(blk_state->byte_offset),
				  err);
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
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to init blk desc: "
				  "logical_blk %u, err %d\n",
				  logical_blk, err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto finish_blk_desc_buffer_init;
		} else if (unlikely(err)) {
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

	if (folio_batch_count(&req->result.diffs) == 0) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("diffs batch is empty: "
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

	ssdfs_peb_container_lock(pebc);

	desc_off = ssdfs_blk2off_table_convert(table, logical_blk,
						&peb_index,
						&migration_state,
						&pos);
	if (IS_ERR_OR_NULL(desc_off)) {
		err = (desc_off == NULL ? -ERANGE : PTR_ERR(desc_off));
		SSDFS_ERR("fail to convert: "
			  "logical_blk %u, err %d\n",
			  logical_blk, err);
		goto finish_read_page;
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
				goto finish_read_page;
			}
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to get migrating block state: "
				  "logical_blk %u, peb_index %u, err %d\n",
				  logical_blk, pebc->peb_index, err);
			goto finish_read_page;
		} else
			goto finish_read_page;
	}

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

#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */

		goto finish_read_page;
	}

finish_read_page:
	ssdfs_peb_container_unlock(pebc);

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
 * @footer_block: footer block index
 * @peb_create_time: PEB's create timestamp [out]
 * @last_log_time: PEB's last log timestamp [out]
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
				u32 footer_block,
				u64 *peb_create_time,
				u64 *last_log_time,
				u32 *log_bytes)
{
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_partial_log_header *plh_hdr = NULL;
	struct ssdfs_log_footer *footer = NULL;
	struct folio *folio;
	void *kaddr;
	u32 bytes_off;
	pgoff_t folio_index;
	int err = 0, err1;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!log_bytes);
	BUG_ON(footer_block == 0);
	BUG_ON(footer_block >= fsi->pages_per_peb);

	SSDFS_DBG("seg %llu, peb_id %llu, footer_block %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, footer_block);
#endif /* CONFIG_SSDFS_DEBUG */

	*peb_create_time = U64_MAX;
	*last_log_time = U64_MAX;
	*log_bytes = U32_MAX;

	bytes_off = footer_block << fsi->log_pagesize;
	folio_index = bytes_off / pebi->cache.folio_size;

	folio = ssdfs_folio_array_grab_folio(&pebi->cache, folio_index);
	if (unlikely(IS_ERR_OR_NULL(folio))) {
		SSDFS_ERR("fail to grab folio: index %lu\n",
			  folio_index);
		return -ENOMEM;
	}

	kaddr = kmap_local_folio(folio, 0);

	if (folio_test_uptodate(folio) || folio_test_dirty(folio))
		goto check_footer_magic;

	err = ssdfs_read_folio_from_volume(fsi, pebi->peb_id,
					   bytes_off,
					   folio);
	if (unlikely(err))
		goto fail_read_footer;

	/*
	 * ->read_folio() unlock the folio
	 * But caller expects that folio is locked
	 */
	ssdfs_folio_lock(folio);

	folio_mark_uptodate(folio);

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
		*log_bytes = le32_to_cpu(plh_hdr->log_bytes);
	} else if (__is_ssdfs_log_footer_magic_valid(magic)) {
		footer = SSDFS_LF(kaddr);
		*peb_create_time = le64_to_cpu(footer->peb_create_time);
		*last_log_time = le64_to_cpu(footer->timestamp);
		*log_bytes = le32_to_cpu(footer->log_bytes);
	} else {
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("log footer is corrupted: "
			  "peb %llu, footer_block %u\n",
			  pebi->peb_id, footer_block);
#endif /* CONFIG_SSDFS_DEBUG */
		goto fail_read_footer;
	}

fail_read_footer:
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	if (err == -ENODATA) {
		pgoff_t start = folio_index;
		pgoff_t end = start;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("valid footer is not detected: "
			  "seg_id %llu, peb_id %llu, "
			  "footer_block %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  footer_block);
#endif /* CONFIG_SSDFS_DEBUG */

		err1 = ssdfs_folio_array_release_folios(&pebi->cache,
							&start, end);
		if (unlikely(err1)) {
			SSDFS_ERR("fail to release folio: "
				  "seg_id %llu, peb_id %llu, "
				  "start %lu, end %lu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, start, end, err1);
			return err1;
		}

		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read footer: "
			  "seg %llu, peb %llu, "
			  "footer_block %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  footer_block,
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_read_log_footer() - read log's footer
 * @fsi: file system info object
 * @pebi: PEB object
 * @page_off: log's starting page
 * @desc: footer's descriptor
 * @peb_create_time: PEB's create timestamp [out]
 * @last_log_time: PEB's last log timestamp [out]
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
int ssdfs_peb_read_log_footer(struct ssdfs_fs_info *fsi,
				struct ssdfs_peb_info *pebi,
				u16 page_off,
				struct ssdfs_metadata_descriptor *desc,
				u64 *peb_create_time,
				u64 *last_log_time,
				u32 *log_bytes)
{
	u16 footer_off;
	u32 bytes_off;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!desc || !log_bytes);

	SSDFS_DBG("seg %llu, peb_id %llu, page_off %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, page_off);
#endif /* CONFIG_SSDFS_DEBUG */

	bytes_off = le32_to_cpu(desc->offset);
	footer_off = bytes_off / fsi->pagesize;

	return __ssdfs_peb_read_log_footer(fsi, pebi, footer_off,
					   peb_create_time, last_log_time,
					   log_bytes);
}

/*
 * ssdfs_peb_read_log_header() - read log's header
 * @fsi: file system info object
 * @pebi: PEB object
 * @block_index: log's starting logical block
 * @peb_create_time: PEB's create timestamp [out]
 * @last_log_time: PEB's last log timestamp [out]
 * @log_pages: pointer on value of logical blocks in the full log [out]
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
int ssdfs_peb_read_log_header(struct ssdfs_fs_info *fsi,
				struct ssdfs_peb_info *pebi,
				u16 block_index,
				u64 *peb_create_time,
				u64 *last_log_time,
				u32 *log_pages,
				u32 *log_bytes)
{
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *pl_hdr = NULL;
	struct ssdfs_metadata_descriptor *desc = NULL;
	struct folio *folio;
	void *kaddr;
	pgoff_t folio_index;
	int err = 0, err1;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!log_bytes);

	SSDFS_DBG("seg %llu, peb_id %llu, block_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, block_index);
#endif /* CONFIG_SSDFS_DEBUG */

	*peb_create_time = U64_MAX;
	*last_log_time = U64_MAX;
	*log_pages = U32_MAX;
	*log_bytes = U32_MAX;

	folio_index = (pgoff_t)block_index << fsi->log_pagesize;
	folio_index /= pebi->cache.folio_size;

	folio = ssdfs_folio_array_grab_folio(&pebi->cache, folio_index);
	if (unlikely(IS_ERR_OR_NULL(folio))) {
		SSDFS_ERR("fail to grab folio: index %lu\n",
			  folio_index);
		return -ENOMEM;
	}

	kaddr = kmap_local_folio(folio, 0);

	if (folio_test_uptodate(folio) || folio_test_dirty(folio))
		goto check_header_magic;

	err = ssdfs_read_folio_from_volume(fsi, pebi->peb_id,
					   block_index * fsi->pagesize,
					   folio);
	if (unlikely(err))
		goto fail_read_log_header;

	/*
	 * ->read_folio() unlock the folio
	 * But caller expects that folio is locked
	 */
	ssdfs_folio_lock(folio);

	folio_mark_uptodate(folio);

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
				  "seg %llu, peb %llu, block_index %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  block_index);
#endif /* CONFIG_SSDFS_DEBUG */
			goto fail_read_log_header;
		}

		*log_pages = le16_to_cpu(seg_hdr->log_pages);

		desc = &seg_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];

		err = ssdfs_peb_read_log_footer(fsi, pebi, block_index,
						desc, peb_create_time,
						last_log_time, log_bytes);
		if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("unable to read footer: "
				  "seg %llu, peb %llu, block_index %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  block_index,
				  err);
#endif /* CONFIG_SSDFS_DEBUG */
			goto fail_read_log_header;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read footer: "
				  "seg %llu, peb %llu, block_index %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  block_index,
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
				  "seg %llu, peb %llu, block_index %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  block_index);
#endif /* CONFIG_SSDFS_DEBUG */
			goto fail_read_log_header;
		}

		*log_pages = le16_to_cpu(pl_hdr->log_pages);

		desc = &pl_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];

		if (ssdfs_pl_has_footer(pl_hdr)) {
			err = ssdfs_peb_read_log_footer(fsi, pebi, block_index,
							desc, peb_create_time,
							last_log_time,
							log_bytes);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to read footer: "
					  "seg %llu, peb %llu, block_index %u, "
					  "err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  block_index,
					  err);
#endif /* CONFIG_SSDFS_DEBUG */
				goto fail_read_log_header;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to read footer: "
					  "seg %llu, peb %llu, block_index %u, "
					  "err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  block_index,
					  err);
				goto fail_read_log_header;
			}
		} else
			*log_bytes = le32_to_cpu(pl_hdr->log_bytes);

		*peb_create_time = le64_to_cpu(pl_hdr->peb_create_time);
		*last_log_time = le64_to_cpu(pl_hdr->timestamp);
	} else {
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("log header is corrupted: "
			  "seg %llu, peb %llu, block_index %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  block_index);
#endif /* CONFIG_SSDFS_DEBUG */
		goto fail_read_log_header;
	}

fail_read_log_header:
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	if (err == -ENODATA) {
		pgoff_t start = folio_index;
		pgoff_t end = start;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("valid header is not detected: "
			  "seg_id %llu, peb_id %llu, block_index %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  block_index);
#endif /* CONFIG_SSDFS_DEBUG */

		err1 = ssdfs_folio_array_release_folios(&pebi->cache,
							&start, end);
		if (unlikely(err1)) {
			SSDFS_ERR("fail to release folio: "
				  "seg_id %llu, peb_id %llu, "
				  "start %lu, end %lu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, start, end, err1);
			return err1;
		}

		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read checked log header: "
			  "seg %llu, peb %llu, "
			  "block_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  block_index, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_peb_check_full_log_end() - check presence of ending partial log
 * @fsi: file system info object
 * @pebi: pointer on PEB object
 * @footer_block: index of footer logical block in erase block
 *
 * This function tries to check the presence of ending
 * partail log of full log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
static
int ssdfs_peb_check_full_log_end(struct ssdfs_fs_info *fsi,
				 struct ssdfs_peb_info *pebi,
				 u32 footer_block)
{
	u32 header_block;
	u32 partial_log_blocks;
	u32 log_blocks;
	u32 log_bytes;
	u64 byte_offset;
	u64 peb_create_time;
	u64 last_log_time;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi);
	BUG_ON(footer_block == 0);
	BUG_ON(footer_block >= fsi->pages_per_peb);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "footer_block %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->pebc->peb_index,
		  footer_block);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!fsi->devops->can_write_block) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("can_write_block is not supported\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return -EOPNOTSUPP;
	}

	byte_offset = pebi->peb_id * fsi->pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
	if (byte_offset > div_u64(ULLONG_MAX, fsi->pagesize)) {
		SSDFS_ERR("byte_offset value %llu is too big\n",
			  byte_offset);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	byte_offset *= fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	if ((u64)footer_block > div_u64(ULLONG_MAX, fsi->pagesize)) {
		SSDFS_ERR("footer_block value %d is too big\n",
			  footer_block);
		return -ERANGE;
	}

	if (byte_offset > (ULLONG_MAX - ((u64)footer_block * fsi->pagesize))) {
		SSDFS_ERR("byte_offset value %llu is too big\n",
			  byte_offset);
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	byte_offset += (u64)footer_block * fsi->pagesize;

	err = fsi->devops->can_write_block(fsi->sb, fsi->pagesize,
					   byte_offset, true);
	if (err) {
		err = 0;
		/* continue logic */
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("block %d can't be written: err %d\n",
			  footer_block, err);
#endif /* CONFIG_SSDFS_DEBUG */
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("block %d is empty\n",
			  footer_block);
		SSDFS_DBG("unable to read footer: "
			  "seg %llu, peb %llu, footer_block %u, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  footer_block,
			  err);
#endif /* CONFIG_SSDFS_DEBUG */
		return -ENODATA;
	}

	err = __ssdfs_peb_read_log_footer(fsi, pebi, footer_block,
					  &peb_create_time,
					  &last_log_time,
					  &log_bytes);
	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to read footer: "
			  "seg %llu, peb %llu, footer_block %u, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  footer_block,
			  err);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read footer: "
			  "seg %llu, peb %llu, footer_block %u, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  footer_block,
			  err);
		return err;
	} else if (log_bytes == 0 || log_bytes >= U32_MAX) {
		SSDFS_ERR("invalid log_bytes: "
			  "seg %llu, peb_index %u, log_bytes %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index,
			  log_bytes);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(peb_create_time >= U64_MAX);
	BUG_ON(last_log_time >= U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->peb_create_time = peb_create_time;
	pebi->current_log.last_log_time = last_log_time;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb_index %u, peb_id %llu, "
		  "peb_create_time %llx, last_log_time %llx\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->pebc->peb_index,
		  pebi->peb_id,
		  peb_create_time,
		  last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

	partial_log_blocks = log_bytes >> fsi->log_pagesize;

	if (partial_log_blocks == 0) {
		SSDFS_ERR("invalid log_bytes %u\n",
			  log_bytes);
		return -ERANGE;
	}

	header_block = (footer_block + 1) - partial_log_blocks;

	err = ssdfs_peb_read_log_header(fsi, pebi, header_block,
					&peb_create_time,
					&last_log_time,
					&log_blocks,
					&log_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read log header: "
			  "seg %llu, peb %llu, header_block %u, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  header_block,
			  err);
		return err;
	}

	return 0;
}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

/*
 * ssdfs_peb_find_last_partial_log() - find last partial log of full log
 * @fsi: file system info object
 * @pebi: pointer on PEB object
 * @high_block: upper bound for search (block index)
 *
 * This function tries to find a last partial log of full log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
static
int ssdfs_peb_find_last_partial_log(struct ssdfs_fs_info *fsi,
				    struct ssdfs_peb_info *pebi,
				    u32 high_block)
{
	u32 log_blocks = U32_MAX;
	u32 log_bytes = U32_MAX;
	int cur_block = 0;
	u32 low_block;
	u64 byte_offset;
	u64 peb_create_time;
	u64 last_log_time;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi);
	BUG_ON(high_block > fsi->pages_per_peb);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "high_block %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->pebc->peb_index,
		  high_block);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!fsi->devops->can_write_block) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("can_write_block is not supported\n");
#endif /* CONFIG_SSDFS_DEBUG */
		return -EOPNOTSUPP;
	}

	low_block = 0;
	cur_block = high_block - 1;

	do {
		u32 diff_blocks;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("low_block %u, high_block %u, "
			  "cur_block %d\n",
			  low_block, high_block,
			  cur_block);
#endif /* CONFIG_SSDFS_DEBUG */

		byte_offset = pebi->peb_id * fsi->pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
		if (byte_offset > div_u64(ULLONG_MAX, fsi->pagesize)) {
			SSDFS_ERR("byte_offset value %llu is too big\n",
				  byte_offset);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		byte_offset *= fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
		if ((u64)cur_block > div_u64(ULLONG_MAX, fsi->pagesize)) {
			SSDFS_ERR("cur_block value %d is too big\n",
				  cur_block);
			return -ERANGE;
		}

		if (byte_offset >
			(ULLONG_MAX - ((u64)cur_block * fsi->pagesize))) {
			SSDFS_ERR("byte_offset value %llu is too big\n",
				  byte_offset);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		byte_offset += (u64)cur_block * fsi->pagesize;

		err = fsi->devops->can_write_block(fsi->sb, fsi->pagesize,
						   byte_offset, true);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("block %d can't be written: err %d\n",
				  cur_block, err);
#endif /* CONFIG_SSDFS_DEBUG */
			low_block = cur_block;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("block %d is empty\n",
				  cur_block);
#endif /* CONFIG_SSDFS_DEBUG */
			high_block = cur_block;
		}

		diff_blocks = (high_block - low_block) / 2;
		cur_block = low_block + diff_blocks;
	} while (cur_block > low_block && cur_block < high_block);

	cur_block = low_block;

	do {
		err = ssdfs_peb_read_log_header(fsi, pebi, cur_block,
						&peb_create_time,
						&last_log_time,
						&log_blocks,
						&log_bytes);
		if (err == -ENODATA) {
			/*
			 * continue search the log's header
			 */
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to read log header: "
				  "seg %llu, peb %llu, cur_block %u, "
				  "err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  cur_block,
				  err);
			return err;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("header has been found: cur_block %d\n",
				  cur_block);

			BUG_ON(peb_create_time >= U64_MAX);
			BUG_ON(last_log_time >= U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

			pebi->peb_create_time = peb_create_time;
			pebi->current_log.last_log_time = last_log_time;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("seg %llu, peb_index %u, peb_id %llu, "
				  "peb_create_time %llx, last_log_time %llx\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->pebc->peb_index,
				  pebi->peb_id,
				  peb_create_time,
				  last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

			break;
		}

		cur_block--;
	} while (cur_block > 0);

	return err;
}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

/*
 * ssdfs_zone_pre_fetch_last_full_log() - pre-fetch last full log
 * @fsi: file system info object
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This function tries to pre-fetch the last full log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
static
int ssdfs_zone_pre_fetch_last_full_log(struct ssdfs_fs_info *fsi,
				       struct ssdfs_peb_info *pebi,
				       struct ssdfs_segment_request *req)
{
	u32 log_blocks = U32_MAX;
	u32 log_bytes = U32_MAX;
	loff_t offset;
	u32 full_log_bytes;
	u32 full_log_blocks;
	u64 zone_wp;
	u64 cur_block = 0;
	u32 low_block, high_block;
	u32 partial_log_blocks;
	u64 peb_create_time;
	u64 last_log_time;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi);
	BUG_ON(!req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "ino %llu, logical_offset %llu, data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	offset = (loff_t)pebi->peb_id * fsi->pages_per_peb;
	offset *= fsi->pagesize;

	zone_wp = ssdfs_zns_zone_write_pointer(fsi->sb, offset);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_id %llu, pages_per_peb %u, "
		  "pagesize %u, offset %llu, "
		  "write_pointer %llu\n",
		  pebi->peb_id, fsi->pages_per_peb,
		  fsi->pagesize, offset, zone_wp);
#endif /* CONFIG_SSDFS_DEBUG */

	/*
	 * Read the very first header with the goal
	 * to extract full log blocks count.
	 */
	err = ssdfs_peb_read_log_header(fsi, pebi, (u32)cur_block,
					&peb_create_time, &last_log_time,
					&log_blocks, &log_bytes);
	if (err == -ENODATA)
		return 0;
	else if (unlikely(err)) {
		SSDFS_ERR("fail to read log header: "
			  "seg %llu, peb %llu, "
			  "cur_block %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, cur_block,
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(log_blocks >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	full_log_blocks = log_blocks;
	full_log_bytes = full_log_blocks * fsi->pagesize;

	if (zone_wp >= U64_MAX)
		zone_wp = fsi->zone_capacity - full_log_bytes;

	cur_block = (zone_wp - offset) >> PAGE_SHIFT;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(cur_block >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	/*
	 * Try to read header of last full log.
	 */
	if (cur_block > full_log_blocks) {
		cur_block /= full_log_blocks;
		cur_block *= full_log_blocks;

		err = ssdfs_peb_read_log_header(fsi, pebi, cur_block,
						&peb_create_time,
						&last_log_time,
						&log_blocks,
						&log_bytes);
		if (err == -ENODATA) {
			SSDFS_DBG("try previous full log's header: "
				  "valid header is not detected: "
				  "cur_block %llu\n",
				  cur_block);

			if (cur_block > full_log_blocks) {
				cur_block -= full_log_blocks;

				err = ssdfs_peb_read_log_header(fsi, pebi,
								cur_block,
								&peb_create_time,
								&last_log_time,
								&log_blocks,
								&log_bytes);
			}
		}

		if (unlikely(err)) {
			SSDFS_ERR("fail to read log header: "
				  "seg %llu, peb %llu, cur_block %llu, "
				  "full_log_blocks %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  cur_block,
				  full_log_blocks,
				  err);
			return err;
		}

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(log_blocks == 0);
		BUG_ON(log_blocks >= U32_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
	} else
		cur_block = 0;

	if (log_bytes == 0 || log_bytes >= U32_MAX) {
		SSDFS_ERR("invalid log_bytes: "
			  "seg %llu, peb_index %u, log_bytes %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index,
			  log_bytes);
		return -ERANGE;
	}

	low_block = cur_block;
	high_block = cur_block + full_log_blocks;
	cur_block = high_block - 1;

	err = ssdfs_peb_check_full_log_end(fsi, pebi, cur_block);
	if (err == -ENODATA) {
		err = 0;
		/*
		 * Last partial log of full log is absent.
		 * Continue logic.
		 */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check full log end: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index,
			  err);
		return err;
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("ending partial log of full log is found: "
			  "seg %llu, peb_index %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	high_block = (zone_wp - offset) >> PAGE_SHIFT;

	err = ssdfs_peb_find_last_partial_log(fsi, pebi, high_block);
	if (err == -EOPNOTSUPP) {
		err = 0;

		cur_block = low_block;

		do {
			err = ssdfs_peb_read_log_header(fsi, pebi, cur_block,
							&peb_create_time,
							&last_log_time,
							&log_blocks,
							&log_bytes);
			if (err == -ENODATA) {
				err = 0;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("header is not found: "
					  "cur_block %llu\n",
					  cur_block);
#endif /* CONFIG_SSDFS_DEBUG */
				break;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to read log header: "
					  "seg %llu, peb %llu, cur_block %llu, "
					  "err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  cur_block,
					  err);
				break;
			} else if (log_bytes == 0 || log_bytes >= U32_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid log_bytes: "
					  "seg %llu, peb_index %u, "
					  "log_bytes %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->pebc->peb_index,
					  log_bytes);
				break;
			} else {
#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(peb_create_time >= U64_MAX);
				BUG_ON(last_log_time >= U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

				pebi->peb_create_time = peb_create_time;
				pebi->current_log.last_log_time = last_log_time;

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("seg %llu, peb_index %u, peb_id %llu, "
					  "peb_create_time %llx, last_log_time %llx\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->pebc->peb_index,
					  pebi->peb_id,
					  peb_create_time,
					  last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */
			}

			partial_log_blocks = log_bytes >> fsi->log_pagesize;

			if (partial_log_blocks == 0) {
				err = -ERANGE;
				SSDFS_ERR("invalid log_bytes %u\n",
					  log_bytes);
				break;
			}

			cur_block += partial_log_blocks;
		} while (cur_block < high_block);
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find last partial log: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index,
			  err);
		return err;
	}

	return 0;
}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

/*
 * ssdfs_peb_find_last_full_log() - find last full log
 * @fsi: file system info object
 * @pebi: pointer on PEB object
 * @start_page: start page for search
 * @full_log_pages: number of pages in full log
 * @found_page: start page of found full log [out]
 * @log_bytes: number of bytes in first partial log [out]
 *
 * This function tries to find last full log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
static
int ssdfs_peb_find_last_full_log(struct ssdfs_fs_info *fsi,
				 struct ssdfs_peb_info *pebi,
				 u32 start_page,
				 u32 full_log_pages,
				 u32 *found_page,
				 u32 *log_bytes)
{
	u32 log_pages = U32_MAX;
	u32 cur_page = 0;
	u32 low_page, high_page;
	u64 byte_offset;
	u64 peb_create_time;
	u64 last_log_time;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi);
	BUG_ON(!found_page || !log_bytes);
	BUG_ON(full_log_pages == 0);
	BUG_ON(full_log_pages >= U32_MAX);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "start_page %u, full_log_pages %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->pebc->peb_index,
		  start_page, full_log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	*found_page = U32_MAX;
	*log_bytes = U32_MAX;

	low_page = start_page;
	high_page = fsi->pages_per_peb;
	cur_page = high_page - full_log_pages;

	do {
		u32 diff_pages;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("low_page %u, high_page %u, "
			  "cur_page %u, log_pages %u\n",
			  low_page, high_page,
			  cur_page, full_log_pages);
#endif /* CONFIG_SSDFS_DEBUG */

		byte_offset = pebi->peb_id * fsi->pages_per_peb;

#ifdef CONFIG_SSDFS_DEBUG
		if (byte_offset > div_u64(ULLONG_MAX, fsi->pagesize)) {
			SSDFS_ERR("byte_offset value %llu is too big\n",
				  byte_offset);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		byte_offset *= fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
		if ((u64)cur_page > div_u64(ULLONG_MAX, fsi->pagesize)) {
			SSDFS_ERR("cur_page value %d is too big\n",
				  cur_page);
			return -ERANGE;
		}

		if (byte_offset >
			(ULLONG_MAX - ((u64)cur_page * fsi->pagesize))) {
			SSDFS_ERR("byte_offset value %llu is too big\n",
				  byte_offset);
			return -ERANGE;
		}
#endif /* CONFIG_SSDFS_DEBUG */

		byte_offset += (u64)cur_page * fsi->pagesize;

		err = fsi->devops->can_write_block(fsi->sb, fsi->pagesize,
						   byte_offset, true);
		if (err) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %d can't be written: err %d\n",
				  cur_page, err);
#endif /* CONFIG_SSDFS_DEBUG */

			err = ssdfs_peb_read_log_header(fsi, pebi, cur_page,
							&peb_create_time,
							&last_log_time,
							&log_pages,
							log_bytes);
			if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("unable to read log header: "
					  "seg %llu, peb %llu, cur_page %u, "
					  "err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  cur_page,
					  err);
#endif /* CONFIG_SSDFS_DEBUG */
				/* correct upper bound */
				high_page = cur_page;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to read log header: "
					  "seg %llu, peb %llu, cur_page %u, "
					  "err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  cur_page,
					  err);
				return err;
			} else {
				/* correct low bound */
				low_page = cur_page;
			}
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("page %d is empty\n",
				  cur_page);
#endif /* CONFIG_SSDFS_DEBUG */
			/* correct upper bound */
			high_page = cur_page;
		}

		diff_pages = (high_page - low_page) / 2;
		cur_page = low_page + diff_pages;

		cur_page += full_log_pages - 1;
		cur_page /= full_log_pages;
		cur_page *= full_log_pages;
	} while (cur_page > low_page && cur_page < high_page);

	*found_page = low_page;

	return 0;
}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

/*
 * ssdfs_peb_pre_fetch_last_full_log() - pre-fetch last full log
 * @fsi: file system info object
 * @pebi: pointer on PEB object
 * @req: read request
 *
 * This function tries to pre-fetch the last full log.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 * %-ENOMEM     - fail to allocate memory.
 */
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
static
int ssdfs_peb_pre_fetch_last_full_log(struct ssdfs_fs_info *fsi,
				      struct ssdfs_peb_info *pebi,
				      struct ssdfs_segment_request *req)
{
	u32 log_pages = U32_MAX;
	u32 log_bytes = U32_MAX;
	u32 full_log_pages;
	u32 partial_log_pages;
	u32 found_log_bytes;
	u32 cur_page = 0;
	u32 low_page, high_page;
	u64 peb_create_time;
	u64 last_log_time;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi);
	BUG_ON(!req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "class %#x, cmd %#x, type %#x, "
		  "ino %llu, logical_offset %llu, data_bytes %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->pebc->peb_index,
		  req->private.class, req->private.cmd, req->private.type,
		  req->extent.ino, req->extent.logical_offset,
		  req->extent.data_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_peb_read_log_header(fsi, pebi, cur_page,
					&peb_create_time,
					&last_log_time,
					&log_pages,
					&log_bytes);
	if (err == -ENODATA)
		return 0;
	else if (unlikely(err)) {
		SSDFS_ERR("fail to read log header: "
			  "seg %llu, peb %llu, cur_page %u, "
			  "err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  cur_page,
			  err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(log_pages >= U32_MAX);
	BUG_ON(log_pages == 0);
	BUG_ON(log_bytes >= U32_MAX);
	BUG_ON(log_bytes > ((u64)fsi->pages_per_peb * fsi->pagesize));
#endif /* CONFIG_SSDFS_DEBUG */

	full_log_pages = log_pages;
	found_log_bytes = log_bytes;

	err = ssdfs_peb_find_last_full_log(fsi, pebi,
					   cur_page,
					   full_log_pages,
					   &cur_page,
					   &log_bytes);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find last full log: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index,
			  err);
		return err;
	} else if (cur_page >= fsi->pages_per_peb) {
		SSDFS_ERR("invalid cur_page: "
			  "seg %llu, peb_index %u, cur_page %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index,
			  cur_page);
		return -ERANGE;
	}

	if (log_bytes == 0) {
		SSDFS_ERR("invalid log_bytes: "
			  "seg %llu, peb_index %u, log_bytes %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index,
			  log_bytes);
		return -ERANGE;
	} else if (log_bytes >= U32_MAX) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("continue to use: found_log_bytes %u\n",
			  found_log_bytes);
#endif /* CONFIG_SSDFS_DEBUG */
	} else
		found_log_bytes = log_bytes;

	if (full_log_pages <= (found_log_bytes >> fsi->log_pagesize)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("log is full: "
			  "found_log_bytes %u, full_log_pages %u, "
			  "pagesize %u\n",
			  found_log_bytes, full_log_pages,
			  fsi->pagesize);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	low_page = cur_page;
	high_page = cur_page + full_log_pages;
	cur_page = high_page - 1;

	err = ssdfs_peb_check_full_log_end(fsi, pebi, cur_page);
	if (err == -ENODATA) {
		err = 0;
		/*
		 * Last partial log of full log is absent.
		 * Continue logic.
		 */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to check full log end: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index,
			  err);
		return err;
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("ending partial log of full log is found: "
			  "seg %llu, peb_index %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	err = ssdfs_peb_find_last_partial_log(fsi, pebi, high_page);
	if (err == -EOPNOTSUPP) {
		err = 0;

		cur_page = low_page;

		do {
			err = ssdfs_peb_read_log_header(fsi, pebi, cur_page,
							&peb_create_time,
							&last_log_time,
							&log_pages,
							&log_bytes);
			if (err == -ENODATA) {
				err = 0;
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("header is not found: "
					  "cur_page %u\n",
					  cur_page);
#endif /* CONFIG_SSDFS_DEBUG */
				break;
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to read log header: "
					  "seg %llu, peb %llu, cur_page %u, "
					  "err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  cur_page,
					  err);
				break;
			} else if (log_bytes == 0 || log_bytes >= U32_MAX) {
				err = -ERANGE;
				SSDFS_ERR("invalid log_bytes: "
					  "seg %llu, peb_index %u, "
					  "log_bytes %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->pebc->peb_index,
					  log_bytes);
				break;
			} else {
#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(peb_create_time >= U64_MAX);
				BUG_ON(last_log_time >= U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

				pebi->peb_create_time = peb_create_time;
				pebi->current_log.last_log_time = last_log_time;

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("seg %llu, peb_index %u, peb_id %llu, "
					  "peb_create_time %llx, last_log_time %llx\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->pebc->peb_index,
					  pebi->peb_id,
					  peb_create_time,
					  last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */
			}

			partial_log_pages = log_bytes >> fsi->log_pagesize;

			if (partial_log_pages == 0) {
				err = -ERANGE;
				SSDFS_ERR("invalid log_bytes %u\n",
					  log_bytes);
				break;
			}

			cur_page += partial_log_pages;
		} while (cur_page < high_page);
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find last partial log: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->pebc->peb_index,
			  err);
		return err;
	}

	return err;
}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

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
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
static
int ssdfs_peb_read_all_log_headers(struct ssdfs_peb_info *pebi,
				   struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
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

	if (fsi->is_zns_device) {
		err = ssdfs_zone_pre_fetch_last_full_log(fsi, pebi, req);
		if (err == -ENODATA)
			return 0;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to read log header: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			return err;
		}
	} else {
		err = ssdfs_peb_pre_fetch_last_full_log(fsi, pebi, req);
		if (err == -ENODATA)
			return 0;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to read log header: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			return err;
		}
	}

	return 0;
}
#else /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */
static
int ssdfs_peb_read_all_log_headers(struct ssdfs_peb_info *pebi,
				   struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	u32 log_pages = U32_MAX;
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

		err = ssdfs_peb_read_log_header(fsi, pebi, page_off,
						&log_pages, &log_bytes);
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
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

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

	ssdfs_peb_container_lock(pebc);

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
	ssdfs_peb_container_unlock(pebc);

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

	ssdfs_peb_container_lock(pebc);

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
	ssdfs_peb_container_unlock(pebc);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_peb_get_log_blocks_count() - determine count of logical blocks in the log
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
int ssdfs_peb_get_log_blocks_count(struct ssdfs_fs_info *fsi,
				   struct ssdfs_peb_info *pebi,
				   struct ssdfs_read_init_env *env)
{
	struct ssdfs_signature *magic;
	struct folio *folio;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u32 log_blocks;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !env || !env->log.header.ptr);

	SSDFS_DBG("peb %llu, env %p\n", pebi->peb_id, env);
#endif /* CONFIG_SSDFS_DEBUG */

	folio = ssdfs_folio_array_get_folio_locked(&pebi->cache, 0);
	if (IS_ERR_OR_NULL(folio)) {
		err = ssdfs_read_checked_segment_header(fsi,
							pebi->peb_id,
							fsi->pagesize,
							0,
							env->log.header.ptr,
							false);
		if (err) {
			SSDFS_ERR("fail to read checked segment header: "
				  "peb %llu, err %d\n",
				  pebi->peb_id, err);
			return err;
		}
	} else {
		__ssdfs_memcpy_from_folio(env->log.header.ptr, 0, hdr_buf_size,
					  folio, 0, folio_size(folio),
					  hdr_buf_size);

		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	magic = (struct ssdfs_signature *)env->log.header.ptr;

#ifdef CONFIG_SSDFS_DEBUG
	if (!is_ssdfs_magic_valid(magic)) {
		SSDFS_ERR("valid magic is not detected\n");
		return -ERANGE;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (__is_ssdfs_segment_header_magic_valid(magic)) {
		struct ssdfs_segment_header *seg_hdr;

		seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);
		log_blocks = le16_to_cpu(seg_hdr->log_pages);
		env->log.blocks = log_blocks;
		env->peb.cur_migration_id =
			seg_hdr->peb_migration_id[SSDFS_CUR_MIGRATING_PEB];
		env->peb.prev_migration_id =
			seg_hdr->peb_migration_id[SSDFS_PREV_MIGRATING_PEB];
	} else {
		SSDFS_ERR("log header is corrupted: "
			  "peb %llu\n", pebi->peb_id);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->pages_per_peb % log_blocks) {
		SSDFS_WARN("fsi->pages_per_peb %u, log_blocks %u\n",
			   fsi->pages_per_peb, log_blocks);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	if (log_blocks > fsi->pages_per_peb) {
		SSDFS_ERR("log_blocks %u > fsi->pages_per_peb %u\n",
			  log_blocks, fsi->pages_per_peb);
		return -ERANGE;
	}

	return 0;
}

/*
 * ssdfs_find_last_partial_log() - find the last partial log
 * @fsi: file system info object
 * @pebi: pointer on PEB object
 * @env: init environment [in|out]
 * @new_log_start_block: pointer on the new log's start block [out]
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
				u16 *new_log_start_block)
{
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *pl_hdr = NULL;
	struct ssdfs_log_footer *footer = NULL;
	struct folio *folio;
	void *kaddr;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u32 byte_offset, block_index;
	unsigned long last_folio_idx;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !env);
	BUG_ON(!new_log_start_block);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	*new_log_start_block = U16_MAX;

	last_folio_idx = ssdfs_folio_array_get_last_folio_index(&pebi->cache);

	if (last_folio_idx >= SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO) {
		SSDFS_ERR("empty folio array: last_folio_idx %lu\n",
			  last_folio_idx);
		return -ERANGE;
	}

	block_index = last_folio_idx * pebi->cache.folio_size;
	block_index >>= fsi->log_pagesize;

	if (block_index >= fsi->pages_per_peb) {
		SSDFS_ERR("corrupted folio array: "
			  "block_index %u, fsi->pages_per_peb %u\n",
			  block_index, fsi->pages_per_peb);
		return -ERANGE;
	}

	for (i = (int)last_folio_idx; i >= 0; i--) {
		folio = ssdfs_folio_array_get_folio_locked(&pebi->cache, i);
		if (IS_ERR_OR_NULL(folio)) {
			if (folio == NULL) {
				SSDFS_ERR("fail to get folio: "
					  "index %d\n",
					  i);
				return -ERANGE;
			} else {
				err = PTR_ERR(folio);

				if (err == -ENOENT)
					continue;
				else {
					SSDFS_ERR("fail to get folio: "
						  "index %d, err %d\n",
						  i, err);
					return err;
				}
			}
		}

		kaddr = kmap_local_folio(folio, 0);
		ssdfs_memcpy(env->log.header.ptr, 0, hdr_buf_size,
			     kaddr, 0, PAGE_SIZE,
			     hdr_buf_size);
		ssdfs_memcpy(env->log.footer.ptr, 0, hdr_buf_size,
			     kaddr, 0, PAGE_SIZE,
			     hdr_buf_size);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio_index %d, folio %p, count %d\n",
			  i, folio, folio_ref_count(folio));

		SSDFS_DBG("PAGE DUMP: cur_folio %u\n",
			  i);
		kaddr = kmap_local_folio(folio, 0);
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     kaddr, PAGE_SIZE);
		kunmap_local(kaddr);
		SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

		magic = (struct ssdfs_signature *)env->log.header.ptr;

		if (!is_ssdfs_magic_valid(magic))
			continue;

		if (__is_ssdfs_segment_header_magic_valid(magic)) {
			seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);

			byte_offset = i * pebi->cache.folio_size;
			byte_offset += env->log.bytes;
			byte_offset += fsi->pagesize - 1;
			block_index = byte_offset >> fsi->log_pagesize;

			err = ssdfs_check_segment_header(fsi, seg_hdr,
							 false);
			if (unlikely(err)) {
				ssdfs_folio_get(folio);
				ssdfs_folio_lock(folio);

				err = ssdfs_read_folio_from_volume(fsi,
						pebi->peb_id,
						block_index * fsi->pagesize,
						folio);
				if (unlikely(err)) {
					SSDFS_ERR("fail to read from volume: "
						  "seg %llu, peb %llu, "
						  "index %u, err %d\n",
						  pebi->pebc->parent_si->seg_id,
						  pebi->peb_id,
						  i, err);
					return err;
				}

				/*
				 * ->read_folio() unlock the folio
				 */
				ssdfs_folio_lock(folio);

				kaddr = kmap_local_folio(folio, 0);
				ssdfs_memcpy(env->log.header.ptr,
					     0, hdr_buf_size,
					     kaddr, 0, PAGE_SIZE,
					     hdr_buf_size);
				ssdfs_memcpy(env->log.footer.ptr,
					     0, hdr_buf_size,
					     kaddr, 0, PAGE_SIZE,
					     hdr_buf_size);
				kunmap_local(kaddr);
				ssdfs_folio_unlock(folio);
				ssdfs_folio_put(folio);

				err = ssdfs_check_segment_header(fsi, seg_hdr,
								 false);
				if (unlikely(err)) {
					SSDFS_WARN("log header is corrupted: "
						  "seg %llu, peb %llu, "
						  "index %u\n",
						  pebi->pebc->parent_si->seg_id,
						  pebi->peb_id,
						  i);
					return -EIO;
				}
			}

			if (*new_log_start_block >= U16_MAX) {
				SSDFS_ERR("invalid new_log_start_page\n");
				return -EIO;
			}

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("byte_offset %u, block_index %u, "
				  "new_log_start_block %u\n",
				  byte_offset, block_index,
				  *new_log_start_block);
			SSDFS_DBG("log_bytes %u\n", env->log.bytes);
#endif /* CONFIG_SSDFS_DEBUG */

			if (*new_log_start_block < block_index) {
#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("correct new log start block: "
					  "old value %u, new value %u\n",
					  *new_log_start_block,
					  block_index);
#endif /* CONFIG_SSDFS_DEBUG */
				*new_log_start_block = block_index;
			} else if (block_index != *new_log_start_block) {
				SSDFS_ERR("invalid new log start: "
					  "block_index %u, "
					  "new_log_start_block %u\n",
					  block_index,
					  *new_log_start_block);
				return -EIO;
			}

			block_index = i * pebi->cache.folio_size;
			block_index >>= fsi->log_pagesize;
			env->log.offset = (u16)block_index;

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

			pl_hdr = SSDFS_PLH(env->log.header.ptr);

			byte_offset = i * pebi->cache.folio_size;
			byte_offset += env->log.bytes;
			byte_offset += fsi->pagesize - 1;
			block_index = byte_offset >> fsi->log_pagesize;

			err = ssdfs_check_partial_log_header(fsi, pl_hdr,
							     false);
			if (unlikely(err)) {
				ssdfs_folio_get(folio);
				ssdfs_folio_lock(folio);

				err = ssdfs_read_folio_from_volume(fsi,
						pebi->peb_id,
						block_index * fsi->pagesize,
						folio);
				if (unlikely(err)) {
					SSDFS_ERR("fail to read from volume: "
						  "seg %llu, peb %llu, "
						  "index %u, err %d\n",
						  pebi->pebc->parent_si->seg_id,
						  pebi->peb_id,
						  i, err);
					return err;
				}

				/*
				 * ->read_folio() unlock the folio
				 */
				ssdfs_folio_lock(folio);

				kaddr = kmap_local_folio(folio, 0);
				ssdfs_memcpy(env->log.header.ptr,
					     0, hdr_buf_size,
					     kaddr, 0, PAGE_SIZE,
					     hdr_buf_size);
				ssdfs_memcpy(env->log.footer.ptr,
					     0, hdr_buf_size,
					     kaddr, 0, PAGE_SIZE,
					     hdr_buf_size);
				kunmap_local(kaddr);
				ssdfs_folio_unlock(folio);
				ssdfs_folio_put(folio);

				err = ssdfs_check_partial_log_header(fsi,
								     pl_hdr,
								     false);
				if (unlikely(err)) {
					SSDFS_ERR("partial log header is corrupted: "
						  "seg %llu, peb %llu, index %u\n",
						  pebi->pebc->parent_si->seg_id,
						  pebi->peb_id,
						  i);
					return -EIO;
				}
			}

			flags = le32_to_cpu(pl_hdr->pl_flags);

			if (flags & SSDFS_PARTIAL_HEADER_INSTEAD_FOOTER) {
				/* first partial log */
#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON((i + 1) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

				byte_offset = (i + 1) * pebi->cache.folio_size;
				byte_offset += fsi->pagesize - 1;

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("byte_offset %u, "
					  "new_log_start_block %u\n",
					  byte_offset, *new_log_start_block);
#endif /* CONFIG_SSDFS_DEBUG */

				*new_log_start_block =
					(u16)(byte_offset / fsi->pagesize);
				env->log.bytes =
					le32_to_cpu(pl_hdr->log_bytes);

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("log_bytes %u\n", env->log.bytes);
#endif /* CONFIG_SSDFS_DEBUG */

				continue;
			} else if (flags & SSDFS_LOG_HAS_FOOTER) {
				/* last partial log */

				env->log.bytes =
					le32_to_cpu(pl_hdr->log_bytes);

				byte_offset = i * pebi->cache.folio_size;
				byte_offset += env->log.bytes;
				byte_offset += fsi->pagesize - 1;
				block_index = byte_offset >> fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("byte_offset %u, block_index %u, "
					  "new_log_start_block %u\n",
					  byte_offset, block_index,
					  *new_log_start_block);
				SSDFS_DBG("log_bytes %u\n", env->log.bytes);
#endif /* CONFIG_SSDFS_DEBUG */

				if (*new_log_start_block < block_index) {
#ifdef CONFIG_SSDFS_DEBUG
					SSDFS_DBG("correct new log start block: "
						  "old value %u, "
						  "new value %u\n",
						  *new_log_start_block,
						  block_index);
#endif /* CONFIG_SSDFS_DEBUG */
					*new_log_start_block = block_index;
				} else if (block_index != *new_log_start_block) {
					SSDFS_ERR("invalid new log start: "
						  "block_index %u, "
						  "new_log_start_block %u\n",
						  block_index,
						  *new_log_start_block);
					return -EIO;
				}

				block_index = i * pebi->cache.folio_size;
				block_index >>= fsi->log_pagesize;
				env->log.offset = (u16)block_index;

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

				env->log.bytes =
					le32_to_cpu(pl_hdr->log_bytes);

				byte_offset = i * pebi->cache.folio_size;
				byte_offset += env->log.bytes;
				byte_offset += fsi->pagesize - 1;
				block_index = byte_offset >> fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
				SSDFS_DBG("byte_offset %u, block_index %u, "
					  "new_log_start_block %u\n",
					  byte_offset, block_index,
					  *new_log_start_block);
				SSDFS_DBG("log_bytes %u\n", env->log.bytes);

				BUG_ON(block_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

				*new_log_start_block = (u16)block_index;

				block_index = i * pebi->cache.folio_size;
				block_index >>= fsi->log_pagesize;
				env->log.offset = (u16)block_index;

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
			footer = SSDFS_LF(env->log.footer.ptr);

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON((i + 1) >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

			byte_offset = (i + 1) * pebi->cache.folio_size;
			byte_offset += fsi->pagesize - 1;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("byte_offset %u, new_log_start_block %u\n",
				  byte_offset, *new_log_start_block);
#endif /* CONFIG_SSDFS_DEBUG */

			*new_log_start_block =
				(u16)(byte_offset >> fsi->log_pagesize);
			env->log.bytes =
				le32_to_cpu(footer->log_bytes);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log_bytes %u\n", env->log.bytes);
#endif /* CONFIG_SSDFS_DEBUG */

			continue;
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("log header/footer is not found: "
				  "seg %llu, peb %llu, index %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  i);
#endif /* CONFIG_SSDFS_DEBUG */
			continue;
		}
	}

finish_last_log_search:
	if (env->log.offset >= fsi->pages_per_peb) {
		SSDFS_ERR("log_offset %u >= pages_per_peb %u\n",
			  env->log.offset, fsi->pages_per_peb);
		return -ERANGE;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->erasesize < env->log.bytes) {
		SSDFS_WARN("fsi->erasesize %u, log_bytes %u\n",
			   fsi->erasesize,
			   env->log.bytes);
	}

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "new_log_start_block %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  *new_log_start_block);
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
	BUG_ON(!env || !env->log.header.ptr || !env->log.footer.ptr);

	SSDFS_DBG("log_offset %u, log_blocks %u\n",
		  env->log.offset, env->log.blocks);
#endif /* CONFIG_SSDFS_DEBUG */

	magic = (struct ssdfs_signature *)env->log.header.ptr;

	if (!is_ssdfs_magic_valid(magic)) {
		SSDFS_DBG("valid magic is not detected\n");
		return -ENODATA;
	}

	if (__is_ssdfs_segment_header_magic_valid(magic)) {
		seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);

		err = ssdfs_check_segment_header(fsi, seg_hdr,
						 false);
		if (unlikely(err)) {
			SSDFS_ERR("log header is corrupted\n");
			return -EIO;
		}

		env->log.header.of_full_log = true;
		env->log.footer.is_present = ssdfs_log_has_footer(seg_hdr) ||
				ssdfs_partial_header_instead_footer(seg_hdr);
	} else if (is_ssdfs_partial_log_header_magic_valid(magic)) {
		pl_hdr = SSDFS_PLH(env->log.header.ptr);

		err = ssdfs_check_partial_log_header(fsi, pl_hdr,
						     false);
		if (unlikely(err)) {
			SSDFS_ERR("partial log header is corrupted\n");
			return -EIO;
		}

		env->log.header.of_full_log = false;
		env->log.footer.is_present = ssdfs_pl_has_footer(pl_hdr);
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
	struct folio *folio;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	u32 bytes_offset;
	u32 folio_index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	*desc = NULL;

	if (!env->log.header.of_full_log) {
		SSDFS_ERR("segment header is absent\n");
		return -ERANGE;
	}

	seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);

	if (!ssdfs_seg_hdr_has_blk_bmap(seg_hdr)) {
		if (!env->log.footer.is_present) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__,
					__LINE__,
					"log hasn't footer\n");
			return -EIO;
		}

		*desc = &seg_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];

		bytes_offset = le32_to_cpu((*desc)->offset);
		folio_index = bytes_offset / pebi->cache.folio_size;

		folio = ssdfs_folio_array_get_folio_locked(&pebi->cache,
							   folio_index);
		if (IS_ERR_OR_NULL(folio)) {
			err = ssdfs_read_checked_log_footer(fsi,
							    env->log.header.ptr,
							    pebi->peb_id,
							    fsi->pagesize,
							    bytes_offset,
							    env->log.footer.ptr,
							    false);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read checked log footer: "
					  "seg %llu, peb %llu, bytes_offset %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id, bytes_offset);
				return err;
			}
		} else {
			__ssdfs_memcpy_from_folio(env->log.footer.ptr,
						  0, footer_size,
						  folio, 0, folio_size(folio),
						  footer_size);

			ssdfs_folio_unlock(folio);
			ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
		}

		if (!ssdfs_log_footer_has_blk_bmap(env->log.footer.ptr)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__,
					__LINE__,
					"log hasn't block bitmap\n");
			return -EIO;
		}

		*desc = &env->log.footer.ptr->desc_array[SSDFS_BLK_BMAP_INDEX];
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
	struct folio *folio;
	size_t footer_size = sizeof(struct ssdfs_log_footer);
	u32 bytes_offset;
	u32 folio_index;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env || !desc);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	*desc = NULL;

	if (env->log.header.of_full_log) {
		SSDFS_ERR("partial log header is absent\n");
		return -ERANGE;
	}

	pl_hdr = SSDFS_PLH(env->log.header.ptr);

	if (!ssdfs_pl_hdr_has_blk_bmap(pl_hdr)) {
		if (!env->log.footer.is_present) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__,
					__LINE__,
					"log hasn't footer\n");
			return -EIO;
		}

		*desc = &pl_hdr->desc_array[SSDFS_LOG_FOOTER_INDEX];

		bytes_offset = le32_to_cpu((*desc)->offset);
		folio_index = bytes_offset / pebi->cache.folio_size;

		folio = ssdfs_folio_array_get_folio_locked(&pebi->cache,
							   folio_index);
		if (IS_ERR_OR_NULL(folio)) {
			err = ssdfs_read_checked_log_footer(fsi,
							    env->log.header.ptr,
							    pebi->peb_id,
							    fsi->pagesize,
							    bytes_offset,
							    env->log.footer.ptr,
							    false);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read checked log footer: "
					  "seg %llu, peb %llu, "
					  "bytes_offset %u\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id, bytes_offset);
				return err;
			}
		} else {
			__ssdfs_memcpy_from_folio(env->log.footer.ptr,
						  0, footer_size,
						  folio,
						  0, folio_size(folio),
						  footer_size);

			ssdfs_folio_unlock(folio);
			ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
		}

		if (!ssdfs_log_footer_has_blk_bmap(env->log.footer.ptr)) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__,
					__LINE__,
					"log hasn't block bitmap\n");
			return -EIO;
		}

		*desc = &env->log.footer.ptr->desc_array[SSDFS_BLK_BMAP_INDEX];
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
	struct folio *folio;
	u32 bytes_offset;
	u32 block_index;
	u32 folio_index;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u32 area_offset, area_size;
	u32 cur_folio, folio_start, folio_end;
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
	block_index = env->log.offset;
	pebsize = fsi->pages_per_peb * fsi->pagesize;

	folio_index = block_index << fsi->log_pagesize;
	folio_index /= pebi->cache.folio_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("block_index %u, "
		  "pebi->cache.folio_size %zu, "
		  "folio_index %u\n",
		  block_index,
		  pebi->cache.folio_size,
		  folio_index);
#endif /* CONFIG_SSDFS_DEBUG */

	folio = ssdfs_folio_array_get_folio_locked(&pebi->cache, folio_index);
	if (IS_ERR_OR_NULL(folio)) {
		err = ssdfs_read_checked_segment_header(fsi,
							pebi->peb_id,
							fsi->pagesize,
							block_index,
							env->log.header.ptr,
							false);
		if (err) {
			SSDFS_ERR("fail to read checked segment header: "
				  "peb %llu, err %d\n",
				  pebi->peb_id, err);
			return err;
		}
	} else {
		__ssdfs_memcpy_from_folio(env->log.header.ptr,
					  0, hdr_buf_size,
					  folio, 0, folio_size(folio),
					  hdr_buf_size);

		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	err = ssdfs_check_log_header(fsi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to check log header: "
			  "err %d\n", err);
		return err;
	}

	if (env->log.header.of_full_log)
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

	bytes_offset = area_offset;
	folio_start = bytes_offset / pebi->cache.folio_size;
	bytes_offset += area_size - 1;
	folio_end = bytes_offset / pebi->cache.folio_size;

	for (cur_folio = folio_start; cur_folio <= folio_end; cur_folio++) {
		folio = ssdfs_folio_array_get_folio_locked(&pebi->cache,
							   cur_folio);
		if (IS_ERR_OR_NULL(folio)) {
			folio = ssdfs_folio_array_grab_folio(&pebi->cache,
							     cur_folio);
			if (unlikely(IS_ERR_OR_NULL(folio))) {
				SSDFS_ERR("fail to grab folio: index %u\n",
					  cur_folio);
				return -ENOMEM;
			}

			err = ssdfs_read_folio_from_volume(fsi, pebi->peb_id,
					    cur_folio * pebi->cache.folio_size,
					    folio);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read memory folio: "
					  "index %u, err %d\n",
					  cur_folio, err);
				goto finish_read_block;
			}

			/*
			 * ->read_folio() unlock the folio
			 * But caller expects that folio is locked
			 */
			ssdfs_folio_lock(folio);

			folio_mark_uptodate(folio);

finish_read_block:
			ssdfs_folio_unlock(folio);
			ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			ssdfs_folio_unlock(folio);
			ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
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

	if (!env->log.header.of_full_log) {
		SSDFS_ERR("segment header is absent\n");
		return -ERANGE;
	}

	seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);

	if (!ssdfs_seg_hdr_has_offset_table(seg_hdr)) {
		if (!env->log.footer.is_present) {
			SSDFS_DBG("log hasn't block descriptor table\n");
			return -ENOENT;
		}

		if (!ssdfs_log_footer_has_offset_table(env->log.footer.ptr)) {
			SSDFS_DBG("log hasn't blk2off table\n");
			return -ENOENT;
		}

		*desc = &env->log.footer.ptr->desc_array[SSDFS_OFF_TABLE_INDEX];
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

	if (!env->log.header.of_full_log) {
		SSDFS_ERR("segment header is absent\n");
		return -ERANGE;
	}

	seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);

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

	if (env->log.header.of_full_log) {
		SSDFS_ERR("partial log header is absent\n");
		return -ERANGE;
	}

	pl_hdr = SSDFS_PLH(env->log.header.ptr);

	if (!ssdfs_pl_hdr_has_offset_table(pl_hdr)) {
		if (!env->log.footer.is_present) {
			SSDFS_DBG("log hasn't blk2off table\n");
			return -ENOENT;
		}

		if (!ssdfs_log_footer_has_offset_table(env->log.footer.ptr)) {
			SSDFS_DBG("log hasn't blk2off table\n");
			return -ENOENT;
		}

		*desc = &env->log.footer.ptr->desc_array[SSDFS_OFF_TABLE_INDEX];
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

	if (env->log.header.of_full_log) {
		SSDFS_ERR("partial log header is absent\n");
		return -ERANGE;
	}

	pl_hdr = SSDFS_PLH(env->log.header.ptr);

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
	struct folio *folio;
	u32 bytes_offset;
	u32 area_offset, area_size;
	u32 cur_folio, folio_start, folio_end;
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

	bytes_offset = area_offset;
	folio_start = bytes_offset / pebi->cache.folio_size;
	bytes_offset += area_size - 1;
	folio_end = bytes_offset / pebi->cache.folio_size;

	for (cur_folio = folio_start; cur_folio <= folio_end; cur_folio++) {
		folio = ssdfs_folio_array_get_folio_locked(&pebi->cache,
							   cur_folio);
		if (IS_ERR_OR_NULL(folio)) {
			folio = ssdfs_folio_array_grab_folio(&pebi->cache,
							     cur_folio);
			if (unlikely(IS_ERR_OR_NULL(folio))) {
				SSDFS_ERR("fail to grab folio: index %u\n",
					  cur_folio);
				return -ENOMEM;
			}

			err = ssdfs_read_folio_from_volume(fsi, pebi->peb_id,
					    cur_folio * pebi->cache.folio_size,
					    folio);
			if (unlikely(err)) {
				SSDFS_ERR("fail to read memory folio: "
					  "index %u, err %d\n",
					  cur_folio, err);
				goto finish_read_block;
			}

			/*
			 * ->read_folio() unlock the folio
			 * But caller expects that folio is locked
			 */
			ssdfs_folio_lock(folio);

			folio_mark_uptodate(folio);

finish_read_block:
			ssdfs_folio_unlock(folio);
			ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
		} else {
			ssdfs_folio_unlock(folio);
			ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
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
	BUG_ON(!env || !env->log.header.ptr || !env->log.footer.ptr);

	SSDFS_DBG("seg %llu, peb %llu, read_off %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->log.blk2off_tbl.portion.read_off);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_unaligned_read_cache(pebi, req,
					 env->log.blk2off_tbl.portion.read_off,
					 hdr_size,
					 &env->log.blk2off_tbl.portion.header);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read table's header: "
			  "seg %llu, peb %llu, offset %u, size %zu, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  env->log.blk2off_tbl.portion.read_off, hdr_size, err);
		return err;
	}

	hdr = &env->log.blk2off_tbl.portion.header;

	if (le32_to_cpu(hdr->magic.common) != SSDFS_SUPER_MAGIC ||
	    le16_to_cpu(hdr->magic.key) != SSDFS_BLK2OFF_TABLE_HDR_MAGIC) {
		SSDFS_ERR("invalid magic of blk2off_table\n");
		return -EIO;
	}

	env->log.blk2off_tbl.portion.read_off += hdr_size;

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
	struct folio *folio = NULL;
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
		  env->log.blk2off_tbl.portion.read_off);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	diff = env->log.blk2off_tbl.portion.read_off -
				env->log.blk2off_tbl.portion.area_offset;
	if (diff != frag_offset) {
		SSDFS_ERR("invalid fragment offset: "
			  "seg %llu, peb %llu, "
			  "area_offset %u, read_off %u, "
			  "frag_offset %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  env->log.blk2off_tbl.portion.area_offset,
			  env->log.blk2off_tbl.portion.read_off,
			  frag_offset);
		return -ERANGE;
	}

	switch (frag_type) {
	case SSDFS_BLK2OFF_EXTENT_DESC:
		stream = &env->log.blk2off_tbl.extents.stream;
		break;

	case SSDFS_BLK2OFF_DESC:
		stream = &env->log.blk2off_tbl.portion.fragments.stream;
		break;

	default:
		BUG();
	}

	if (read_bytes > PAGE_SIZE) {
		SSDFS_ERR("invalid size: read_bytes %u\n",
			  read_bytes);
		return -E2BIG;
	}

	if (ssdfs_folio_vector_space(&stream->batch) == 0) {
		u32 new_capacity;

		new_capacity = ssdfs_folio_vector_capacity(&stream->batch);
		new_capacity *= 2;

		err = ssdfs_folio_vector_inflate(&stream->batch, new_capacity);
		if (unlikely(err)) {
			SSDFS_ERR("fail to inflate folio vector: "
				  "new_capacity %u, err %d\n",
				  new_capacity, err);
			return err;
		}
	}

	folio = ssdfs_folio_vector_allocate(&stream->batch);
	if (unlikely(IS_ERR_OR_NULL(folio))) {
		err = !folio ? -ENOMEM : PTR_ERR(folio);
		SSDFS_ERR("fail to add folio into batch: err %d\n",
			  err);
		return err;
	}

	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);
	err = ssdfs_unaligned_read_cache(pebi, req,
					 env->log.blk2off_tbl.portion.read_off,
					 read_bytes,
					 (u8 *)kaddr);
	flush_dcache_folio(folio);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);

	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb %llu, offset %u, "
			  "size %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  env->log.blk2off_tbl.portion.read_off,
			  read_bytes, err);
		return err;
	}

	env->log.blk2off_tbl.portion.read_off += read_bytes;
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
		  env->log.blk2off_tbl.portion.read_off);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	start_off = env->log.blk2off_tbl.portion.read_off;

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

	if (next_frag_off != env->log.blk2off_tbl.portion.read_off) {
		SSDFS_ERR("next_frag_off %u != read_off %u\n",
			  next_frag_off,
			  env->log.blk2off_tbl.portion.read_off);
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
	struct folio *folio = NULL;
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
		  env->log.blk2off_tbl.portion.read_off,
		  *processed_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (frag->type) {
	case SSDFS_BLK2OFF_EXTENT_DESC_ZLIB:
	case SSDFS_BLK2OFF_EXTENT_DESC_LZO:
		stream = &env->log.blk2off_tbl.extents.stream;
		folio = ssdfs_folio_vector_allocate(&stream->batch);
		if (unlikely(IS_ERR_OR_NULL(folio))) {
			err = !folio ? -ENOMEM : PTR_ERR(folio);
			SSDFS_ERR("fail to add folio into batch: err %d\n",
				  err);
			return err;
		}
		break;

	case SSDFS_BLK2OFF_DESC_ZLIB:
	case SSDFS_BLK2OFF_DESC_LZO:
		stream = &env->log.blk2off_tbl.portion.fragments.stream;

		if (ssdfs_folio_vector_space(&stream->batch) == 0) {
			u32 new_capacity;

			new_capacity =
				ssdfs_folio_vector_capacity(&stream->batch);
			new_capacity *= 2;

			err = ssdfs_folio_vector_inflate(&stream->batch,
							 new_capacity);
			if (unlikely(err)) {
				SSDFS_ERR("fail to inflate folio vector: "
					  "new_capacity %u, err %d\n",
					  new_capacity, err);
				return err;
			}
		}

		folio = ssdfs_folio_vector_allocate(&stream->batch);
		if (unlikely(IS_ERR_OR_NULL(folio))) {
			err = !folio ? -ENOMEM : PTR_ERR(folio);
			SSDFS_ERR("fail to add folio into batch: err %d\n",
				  err);
			return err;
		}
		break;

	default:
		SSDFS_ERR("unexpected fragment's type %#x\n",
			  frag->type);
		return -EIO;
	}

	area_offset = env->log.blk2off_tbl.portion.area_offset;
	frag_offset = le32_to_cpu(frag->offset);
	frag_compr_size = le16_to_cpu(frag->compr_size);
	frag_uncompr_size = le16_to_cpu(frag->uncompr_size);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_folio_lock(folio);
	kaddr = kmap_local_folio(folio, 0);
	err = __ssdfs_decompress_blk2off_fragment(pebi, req, frag,
						  area_offset,
						  kaddr, PAGE_SIZE);
	hdr = (struct ssdfs_phys_offset_table_header *)kaddr;
	magic = le32_to_cpu(hdr->magic);
	flush_dcache_folio(folio);
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);

	if (unlikely(err)) {
		SSDFS_ERR("fail to read folio: "
			  "seg %llu, peb %llu, offset %u, "
			  "size %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  env->log.blk2off_tbl.portion.read_off,
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

	env->log.blk2off_tbl.portion.read_off += frag_compr_size;
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
	struct ssdfs_blk2off_table_header *hdr;
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
		  env->log.blk2off_tbl.portion.read_off,
		  *processed_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_read_blk2off_table_header(pebi, req, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read blk2off table header: "
			  "err %d\n", err);
		return err;
	}

	*processed_bytes += hdr_size;

	area_offset = env->log.blk2off_tbl.portion.area_offset;
	hdr = &env->log.blk2off_tbl.portion.header;

	if (hdr->chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		SSDFS_ERR("corrupted chain header: "
			  "magic (expected %#x, found %#x)\n",
			  SSDFS_CHAIN_HDR_MAGIC,
			  hdr->chain_hdr.magic);
		return -EIO;
	}

	switch (hdr->chain_hdr.type) {
	case SSDFS_BLK2OFF_ZLIB_CHAIN_HDR:
	case SSDFS_BLK2OFF_LZO_CHAIN_HDR:
		/* expected type */
		break;

	default:
		SSDFS_ERR("unexpected chain header's type %#x\n",
			  hdr->chain_hdr.type);
		return -EIO;
	}

	fragments_count = le16_to_cpu(hdr->chain_hdr.fragments_count);

	for (i = 0; i < fragments_count; i++) {
		u32 padding = 0;

		frag = &hdr->blk[i];

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

			env->log.blk2off_tbl.portion.read_off =
						area_offset + frag_offset;

			SSDFS_DBG("process next table descriptor: "
				  "offset %u\n",
				  env->log.blk2off_tbl.portion.read_off);
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
		  read_bytes, env->log.blk2off_tbl.portion.read_off);
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
	struct ssdfs_blk2off_table_header *hdr;
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
		  env->log.blk2off_tbl.portion.read_off,
		  *processed_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_read_blk2off_table_header(pebi, req, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read blk2off table header: "
			  "err %d\n", err);
		return err;
	}

	*processed_bytes += hdr_size;

	area_offset = env->log.blk2off_tbl.portion.area_offset;
	hdr = &env->log.blk2off_tbl.portion.header;

	if (hdr->chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		SSDFS_ERR("corrupted chain header: "
			  "magic (expected %#x, found %#x)\n",
			  SSDFS_CHAIN_HDR_MAGIC,
			  hdr->chain_hdr.magic);
		return -EIO;
	}

	switch (hdr->chain_hdr.type) {
	case SSDFS_BLK2OFF_CHAIN_HDR:
		/* expected type */
		break;

	default:
		SSDFS_ERR("unexpected chain header's type %#x\n",
			  hdr->chain_hdr.type);
		return -EIO;
	}

	fragments_count = le16_to_cpu(hdr->chain_hdr.fragments_count);

	for (i = 0; i < fragments_count; i++) {
		u32 padding = 0;

		frag = &hdr->blk[i];

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

			env->log.blk2off_tbl.portion.read_off =
						area_offset + frag_offset;

			SSDFS_DBG("process next table descriptor: "
				  "offset %u\n",
				  env->log.blk2off_tbl.portion.read_off);
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
		  read_bytes, env->log.blk2off_tbl.portion.read_off);
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
	struct folio *folio;
	u32 block_index;
	u32 folio_index;
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
	block_index = env->log.offset;
	folio_index = block_index << fsi->log_pagesize;
	folio_index /= pebi->cache.folio_size;

	folio = ssdfs_folio_array_get_folio_locked(&pebi->cache, folio_index);
	if (IS_ERR_OR_NULL(folio)) {
		err = ssdfs_read_checked_segment_header(fsi,
							pebi->peb_id,
							fsi->pagesize,
							block_index,
							env->log.header.ptr,
							false);
		if (err) {
			SSDFS_ERR("fail to read checked segment header: "
				  "peb %llu, err %d\n",
				  pebi->peb_id, err);
			return err;
		}
	} else {
		__ssdfs_memcpy_from_folio(env->log.header.ptr,
					  0, hdr_buf_size,
					  folio, 0, folio_size(folio),
					  hdr_buf_size);

		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	err = ssdfs_check_log_header(fsi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to check log header: "
			  "err %d\n", err);
		return err;
	}

	if (env->log.header.of_full_log) {
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

	env->log.blk2off_tbl.portion.area_offset = le32_to_cpu(desc->offset);
	env->log.blk2off_tbl.portion.read_off =
				env->log.blk2off_tbl.portion.area_offset;
	env->log.blk2off_tbl.extents.stream.write_off = 0;
	env->log.blk2off_tbl.portion.fragments.stream.write_off = 0;

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
	struct ssdfs_blk_desc_table_init_env *blk_desc_tbl;
	struct ssdfs_folio_vector *content;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env);

	SSDFS_DBG("seg %llu, peb %llu, read_bytes %u, "
		  "read_off %u, write_off %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, read_bytes,
		  env->log.blk_desc_tbl.portion.read_off,
		  env->log.blk_desc_tbl.portion.write_off);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	blk_desc_tbl = &env->log.blk_desc_tbl;
	content = &blk_desc_tbl->portion.raw.content;

	while (read_bytes > 0) {
		struct folio *folio = NULL;
		void *kaddr;
		pgoff_t folio_index;
		u32 capacity;
		u32 offset, bytes;

		folio_index = blk_desc_tbl->portion.write_off >> PAGE_SHIFT;
		capacity = ssdfs_folio_vector_count(content);
		capacity <<= PAGE_SHIFT;

		if (blk_desc_tbl->portion.write_off >= capacity) {
			if (ssdfs_folio_vector_capacity(content) == 0) {
				/*
				 * Block descriptor table byte stream could be
				 * bigger than folio vector capacity.
				 * As a result, not complete byte stream will
				 * read and initialization will be done only
				 * partially. The rest byte stream will be
				 * extracted and be used for initialization
				 * of request of particular logical block.
				 */
				SSDFS_DBG("pagevec is full\n");
				return 0;
			}

			folio = ssdfs_folio_vector_allocate(content);
			if (unlikely(IS_ERR_OR_NULL(folio))) {
				err = !folio ? -ENOMEM : PTR_ERR(folio);
				SSDFS_ERR("fail to add folio into batch: "
					  "err %d\n", err);
				return err;
			}
		} else {
			folio = content->folios[folio_index];
			if (unlikely(!folio)) {
				err = -ERANGE;
				SSDFS_ERR("fail to get folio: err %d\n",
					  err);
				return err;
			}
		}

		offset = blk_desc_tbl->portion.write_off % PAGE_SIZE;
		bytes = min_t(u32, read_bytes, PAGE_SIZE - offset);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("offset %u, bytes %u\n",
			  offset, bytes);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_folio_lock(folio);
		kaddr = kmap_local_folio(folio, 0);
		err = ssdfs_unaligned_read_cache(pebi, req,
						 blk_desc_tbl->portion.read_off,
						 bytes,
						 (u8 *)kaddr + offset);
		flush_dcache_folio(folio);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);

		if (unlikely(err)) {
			SSDFS_ERR("fail to read folio: "
				  "seg %llu, peb %llu, offset %u, "
				  "size %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, blk_desc_tbl->portion.read_off,
				  bytes, err);
			return err;
		}

		read_bytes -= bytes;
		blk_desc_tbl->portion.read_off += bytes;
		blk_desc_tbl->portion.write_off += bytes;
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
	struct ssdfs_blk_desc_table_init_env *blk_desc_tbl;
	struct ssdfs_folio_vector *content;
	struct folio *folio = NULL;
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
		  env->log.blk_desc_tbl.portion.read_off,
		  env->log.blk_desc_tbl.portion.write_off);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	blk_desc_tbl = &env->log.blk_desc_tbl;
	content = &blk_desc_tbl->portion.raw.content;

	area_offset = blk_desc_tbl->portion.area_offset;

	err = ssdfs_unaligned_read_cache(pebi, req,
					 blk_desc_tbl->portion.read_off,
					 tbl_size, &table);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read area block table: "
			  "table_offset %u, tbl_size %zu, err %d\n",
			  blk_desc_tbl->portion.read_off, tbl_size, err);
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
				  "frag_offset %u, processed_bytes %u\n",
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
			folio = ssdfs_folio_vector_allocate(content);
			if (unlikely(IS_ERR_OR_NULL(folio))) {
				err = !folio ? -ENOMEM : PTR_ERR(folio);
				SSDFS_ERR("fail to add folio into batch: "
					  "err %d\n", err);
				return err;
			}

			ssdfs_folio_lock(folio);
			kaddr = kmap_local_folio(folio, 0);
			err = __ssdfs_decompress_blk2off_fragment(pebi,
								  req,
								  frag,
								  area_offset,
								  kaddr,
								  PAGE_SIZE);
			flush_dcache_folio(folio);
			kunmap_local(kaddr);
			ssdfs_folio_unlock(folio);

			if (unlikely(err)) {
				SSDFS_ERR("fail to read folio: "
					  "seg %llu, peb %llu, offset %u, "
					  "size %u, err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id,
					  blk_desc_tbl->portion.read_off,
					  frag_uncompr_size, err);
				return err;
			}

			blk_desc_tbl->portion.read_off += frag_compr_size;
			blk_desc_tbl->portion.write_off += frag_uncompr_size;

			*processed_bytes += frag_compr_size;
			*processed_bytes += padding;
			break;

		case SSDFS_NEXT_TABLE_DESC:
#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(i != SSDFS_NEXT_BLK_TABLE_INDEX);
#endif /* CONFIG_SSDFS_DEBUG */

			blk_desc_tbl->portion.read_off =
					area_offset + frag_offset;

			SSDFS_DBG("process next table descriptor: "
				  "offset %u\n",
				  blk_desc_tbl->portion.read_off);
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
		  read_bytes, env->log.blk_desc_tbl.portion.read_off);
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
	struct folio *folio;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u32 block_index;
	u32 folio_index;
	u16 flags;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !env);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	env->log.blk_desc_tbl.portion.area_offset = 0;
	env->log.blk_desc_tbl.portion.read_off = 0;
	env->log.blk_desc_tbl.portion.write_off = 0;

	block_index = env->log.offset;
	folio_index = block_index << fsi->log_pagesize;
	folio_index /= pebi->cache.folio_size;

	folio = ssdfs_folio_array_get_folio_locked(&pebi->cache, folio_index);
	if (IS_ERR_OR_NULL(folio)) {
		err = ssdfs_read_checked_segment_header(fsi,
							pebi->peb_id,
							fsi->pagesize,
							block_index,
							env->log.header.ptr,
							false);
		if (err) {
			SSDFS_ERR("fail to read checked segment header: "
				  "peb %llu, err %d\n",
				  pebi->peb_id, err);
			return err;
		}
	} else {
		__ssdfs_memcpy_from_folio(env->log.header.ptr,
					  0, hdr_buf_size,
					  folio,
					  0, folio_size(folio),
					  hdr_buf_size);

		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	err = ssdfs_check_log_header(fsi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to check log header: "
			  "err %d\n", err);
		return err;
	}

	if (env->log.header.of_full_log) {
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

	env->log.blk_desc_tbl.portion.area_offset = le32_to_cpu(desc->offset);
	env->log.blk_desc_tbl.portion.read_off = le32_to_cpu(desc->offset);

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

		env->log.blk_desc_tbl.portion.read_off += area_tbl_size;

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
	struct ssdfs_metadata_descriptor *desc = NULL;
	struct folio *folio;
	size_t bmap_hdr_size = sizeof(struct ssdfs_block_bitmap_header);
	size_t hdr_buf_size = max_t(size_t,
				sizeof(struct ssdfs_segment_header),
				sizeof(struct ssdfs_partial_log_header));
	u32 area_offset;
	u32 block_index;
	u32 folio_index;
	u32 pebsize;
	u32 read_bytes = 0;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env || !env->log.header.ptr || !env->log.footer.ptr);
	BUG_ON(env->log.blocks >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON((env->log.offset) >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON(!env->log.blk_bmap.header.ptr);

	SSDFS_DBG("seg %llu, peb %llu, log_offset %u, log_blocks %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->log.offset, env->log.blocks);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	pebsize = fsi->pages_per_peb * fsi->pagesize;

	block_index = env->log.offset;
	folio_index = block_index << fsi->log_pagesize;
	folio_index /= pebi->cache.folio_size;

	folio = ssdfs_folio_array_get_folio_locked(&pebi->cache, folio_index);
	if (IS_ERR_OR_NULL(folio)) {
		SSDFS_ERR("fail to read checked segment header: "
			  "peb %llu\n", pebi->peb_id);
		return -ERANGE;
	} else {
		__ssdfs_memcpy_from_folio(env->log.header.ptr,
					  0, hdr_buf_size,
					  folio, 0, folio_size(folio),
					  hdr_buf_size);

		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	err = ssdfs_check_log_header(fsi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to check log header: "
			  "err %d\n", err);
		return err;
	}

	if (env->log.header.of_full_log)
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
					 env->log.blk_bmap.header.ptr);
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
		  le32_to_cpu(env->log.blk_bmap.header.ptr->magic.common),
		  le16_to_cpu(env->log.blk_bmap.header.ptr->magic.key),
		  env->log.blk_bmap.header.ptr->magic.version.major,
		  env->log.blk_bmap.header.ptr->magic.version.minor,
		  le16_to_cpu(env->log.blk_bmap.header.ptr->fragments_count),
		  le32_to_cpu(env->log.blk_bmap.header.ptr->bytes_count),
		  env->log.blk_bmap.header.ptr->flags,
		  env->log.blk_bmap.header.ptr->type);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_csum_valid(&desc->check,
			   env->log.blk_bmap.header.ptr, read_bytes)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap header has invalid checksum\n");
		return -EIO;
	}

	env->log.blk_bmap.read_bytes += read_bytes;

	return 0;
}

/*
 * ssdfs_check_block_bitmap_fragment_header() - check fragment header
 * @fsi: pointer on shared file system object
 * @frag_hdr: block bitmap's fragment header
 */
static inline
int ssdfs_check_block_bitmap_fragment_header(struct ssdfs_fs_info *fsi,
				struct ssdfs_block_bitmap_fragment *frag_hdr)
{
	u32 last_free_blk;
	size_t desc_size = sizeof(struct ssdfs_fragment_desc);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !frag_hdr);

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

	last_free_blk = le32_to_cpu(frag_hdr->last_free_blk);

	if (frag_hdr->flags & SSDFS_INFLATED_BLK_BMAP) {
		/*
		 * The last_free_blk and metadata_blks can be bigger
		 * than pages_per_peb. Skip the check here.
		 */
	} else {
		if (last_free_blk > fsi->pages_per_seg) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"block bitmap is corrupted: "
					"last_free_blk %u, pages_per_seg %u\n",
					last_free_blk,
					fsi->pages_per_seg);
			return -EIO;
		}

		if (le32_to_cpu(frag_hdr->metadata_blks) > fsi->pages_per_peb) {
			ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
					"block bitmap is corrupted: "
					"metadata_blks %u is invalid\n",
					le32_to_cpu(frag_hdr->metadata_blks));
			return -EIO;
		}
	}

	if (desc_size != le16_to_cpu(frag_hdr->chain_hdr.desc_size)) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"desc_size %u is invalid\n",
			    le16_to_cpu(frag_hdr->chain_hdr.desc_size));
		return -EIO;
	}

	if (frag_hdr->chain_hdr.magic != SSDFS_CHAIN_HDR_MAGIC) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"chain header magic %#x is invalid\n",
				frag_hdr->chain_hdr.magic);
		return -EIO;
	}

	if (frag_hdr->chain_hdr.type != SSDFS_BLK_BMAP_CHAIN_HDR) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"chain header type %#x is invalid\n",
				frag_hdr->chain_hdr.type);
		return -EIO;
	}

	if (le16_to_cpu(frag_hdr->chain_hdr.flags) &
	    ~SSDFS_CHAIN_HDR_FLAG_MASK) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"unknown chain header flags %#x\n",
			    le16_to_cpu(frag_hdr->chain_hdr.flags));
		return -EIO;
	}

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
	struct ssdfs_folio_vector *content;
	u32 area_offset;
	void *cdata_buf;
	u32 chain_compr_bytes, chain_uncompr_bytes;
	u32 read_bytes, uncompr_bytes;
	u16 fragments_count;
	u32 last_free_blk;
	u32 bmap_bytes = 0;
	u32 bmap_folios = 0;
	u32 folios_count;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(!env || !env->log.header.ptr || !env->log.footer.ptr);
	BUG_ON(!env->log.blk_bmap.fragment.header);
	BUG_ON(env->log.blocks >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON(env->log.offset >
			pebi->pebc->parent_si->fsi->pages_per_peb);
	BUG_ON(ssdfs_folio_vector_count(&env->log.blk_bmap.raw.content) != 0);

	SSDFS_DBG("seg %llu, peb %llu, log_offset %u, log_blocks %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  env->log.offset, env->log.blocks);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	content = &env->log.blk_bmap.raw.content;

	if (env->log.header.of_full_log)
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
				area_offset + env->log.blk_bmap.read_bytes,
				SSDFS_BLKBMAP_FRAG_HDR_CAPACITY,
				env->log.blk_bmap.fragment.header);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read fragment's header: "
			  "seg %llu, peb %llu, offset %u, size %u, err %d\n",
			  pebi->pebc->parent_si->seg_id, pebi->peb_id,
			  area_offset + env->log.blk_bmap.read_bytes,
			  (u32)SSDFS_BLKBMAP_FRAG_HDR_CAPACITY,
			  err);
		return err;
	}

	cdata_buf = ssdfs_read_kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!cdata_buf) {
		SSDFS_ERR("fail to allocate cdata_buf\n");
		return -ENOMEM;
	}

	frag_hdr = env->log.blk_bmap.fragment.header;
	frag_array = (struct ssdfs_fragment_desc *)((u8 *)frag_hdr + hdr_size);

	err = ssdfs_check_block_bitmap_fragment_header(fsi, frag_hdr);
	if (unlikely(err)) {
		SSDFS_ERR("block bitmap's fragment header is corrupted: "
			  "err %d\n", err);
		goto fail_read_blk_bmap;
	}

	last_free_blk = le32_to_cpu(frag_hdr->last_free_blk);

	fragments_count = le16_to_cpu(frag_hdr->chain_hdr.fragments_count);
	if (fragments_count == 0) {
		ssdfs_fs_error(fsi->sb, __FILE__, __func__, __LINE__,
				"block bitmap is corrupted: "
				"fragments count is zero\n");
		err = -EIO;
		goto fail_read_blk_bmap;
	}

	env->log.blk_bmap.read_bytes += hdr_size + (fragments_count * desc_size);

	chain_compr_bytes = le32_to_cpu(frag_hdr->chain_hdr.compr_bytes);
	chain_uncompr_bytes = le32_to_cpu(frag_hdr->chain_hdr.uncompr_bytes);
	read_bytes = 0;
	uncompr_bytes = 0;

	if (last_free_blk == 0) {
		/* need to process as minumum one folio */
		bmap_folios = 1;
	} else {
		bmap_bytes = BLK_BMAP_BYTES(last_free_blk);
		bmap_folios = (bmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
	}

	folios_count = min_t(u32, (u32)fragments_count, bmap_folios);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("last_free_blk %u, bmap_bytes %u, "
		  "bmap_folios %u, fragments_count %u, "
		  "folios_countt %u\n",
		  last_free_blk, bmap_bytes,
		  bmap_folios, fragments_count,
		  folios_count);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < fragments_count; i++) {
		struct ssdfs_fragment_desc *frag_desc;
		struct folio *folio;
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

		if (i >= folios_count) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("account fragment bytes: "
				  "i %d, folios_count %u\n",
				  i, folios_count);
#endif /* CONFIG_SSDFS_DEBUG */
			goto account_fragment_bytes;
		}

		folio = ssdfs_folio_vector_allocate(content);
		if (unlikely(IS_ERR_OR_NULL(folio))) {
			err = !folio ? -ENOMEM : PTR_ERR(folio);
			SSDFS_ERR("fail to add folio into batch: "
				  "sequence_id %u, "
				  "fragments count %u, err %d\n",
				  sequence_id, fragments_count, err);
			goto fail_read_blk_bmap;
		}

		ssdfs_folio_lock(folio);
		err = ssdfs_read_checked_fragment(pebi, req, area_offset,
						  sequence_id,
						  frag_desc,
						  cdata_buf,
						  folio_page(folio, 0));
		ssdfs_folio_unlock(folio);

		if (unlikely(err)) {
			SSDFS_ERR("fail to read checked fragment: "
				  "offset %u, compr_size %u, "
				  "uncompr_size %u, sequence_id %u, "
				  "flags %#x, err %d\n",
				  le32_to_cpu(frag_desc->offset),
				  le16_to_cpu(frag_desc->compr_size),
				  le16_to_cpu(frag_desc->uncompr_size),
				  frag_desc->sequence_id,
				  frag_desc->flags,
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
		env->log.blk_bmap.read_bytes +=
				le16_to_cpu(frag_desc->compr_size);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("last_free_blk %u, metadata_blks %u, invalid_blks %u\n",
		  le32_to_cpu(frag_hdr->last_free_blk),
		  le32_to_cpu(frag_hdr->metadata_blks),
		  le32_to_cpu(frag_hdr->invalid_blks));
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
	struct ssdfs_folio_vector *content;
	u64 cno;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(!env || !env->log.header.ptr || !env->log.footer.ptr);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "log_offset %u, log_blocks %u, "
		  "fragment_index %d, read_bytes %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  env->log.offset, env->log.blocks,
		  env->log.blk_bmap.fragment.index,
		  env->log.blk_bmap.read_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	content = &env->log.blk_bmap.raw.content;

	err = ssdfs_folio_vector_init(content);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init folio vector: "
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

	if (env->log.header.of_full_log) {
		struct ssdfs_segment_header *seg_hdr = NULL;

		seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);
		cno = le64_to_cpu(seg_hdr->cno);
	} else {
		struct ssdfs_partial_log_header *pl_hdr = NULL;

		pl_hdr = SSDFS_PLH(env->log.header.ptr);
		cno = le64_to_cpu(pl_hdr->cno);
	}

	err = ssdfs_segment_blk_bmap_partial_init(seg_blkbmap,
					pebi->peb_index,
					content,
					env->log.blk_bmap.fragment.header,
					env->peb.free_pages,
					cno);
	if (unlikely(err)) {
		SSDFS_ERR("fail to initialize block bitmap: "
			  "seg %llu, peb %llu, free_pages %u, "
			  "cno %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, env->peb.free_pages,
			  cno, err);
		goto fail_init_blk_bmap_fragment;
	}

fail_init_blk_bmap_fragment:
	ssdfs_folio_vector_release(content);

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
 * %-ERANGE     - internal error.
 */
static
int ssdfs_peb_init_using_metadata_state(struct ssdfs_peb_info *pebi,
					struct ssdfs_read_init_env *env,
					struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_segment_header *seg_hdr = NULL;
	struct ssdfs_partial_log_header *pl_hdr = NULL;
	u16 fragments_count;
	u32 bytes_count;
	u16 new_log_start_block;
	int peb_free_pages;
	u16 free_blocks;
	u64 cno;
	int items_state;
	bool is_migrating = false;
	int sequence_id = 0;
	u32 default_threshold = SSDFS_RESERVED_FREE_PAGE_THRESHOLD_PER_PEB;
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

	err = ssdfs_peb_get_log_blocks_count(fsi, pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define log_blocks: "
			  "seg %llu, peb %llu\n",
			  si->seg_id, pebi->peb_id);
		goto fail_init_using_blk_bmap;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->pages_per_peb % env->log.blocks) {
		SSDFS_WARN("fsi->pages_per_peb %u, log_blocks %u\n",
			   fsi->pages_per_peb, env->log.blocks);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->log_blocks = env->log.blocks;

	err = ssdfs_find_last_partial_log(fsi, pebi, env,
					  &new_log_start_block);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find last partial log: err %d\n", err);
		goto fail_init_using_blk_bmap;
	}

	err = ssdfs_pre_fetch_block_bitmap(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch block bitmap: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log.offset, err);
		goto fail_init_using_blk_bmap;
	}

	err = ssdfs_read_checked_block_bitmap_header(pebi, req, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block bitmap header: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log.offset, err);
		goto fail_init_using_blk_bmap;
	}

	fragments_count =
		le16_to_cpu(env->log.blk_bmap.header.ptr->fragments_count);
	bytes_count =
		le32_to_cpu(env->log.blk_bmap.header.ptr->bytes_count);

	BUG_ON(new_log_start_block > fsi->pages_per_peb);
	env->peb.free_pages = fsi->pages_per_peb - new_log_start_block;

	if (env->peb.free_pages <= default_threshold)
		env->peb.free_pages = 0;
	else
		env->peb.free_pages -= default_threshold;

	for (i = 0; i < fragments_count; i++) {
		env->log.blk_bmap.fragment.index = i;
		err = ssdfs_init_block_bitmap_fragment(pebi, req, env);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init block bitmap: "
				  "peb_id %llu, peb_index %u, "
				  "log_offset %u, fragment_index %u, "
				  "read_bytes %u, err %d\n",
				  pebi->peb_id, pebi->peb_index,
				  env->log.offset, i,
				  env->log.blk_bmap.read_bytes, err);
			goto fail_init_using_blk_bmap;
		}
	}

	if (bytes_count != env->log.blk_bmap.read_bytes) {
		SSDFS_WARN("bytes_count %u != read_bytes %u\n",
			   bytes_count, env->log.blk_bmap.read_bytes);
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

	BUG_ON(new_log_start_block >= U16_MAX);

	if (env->log.header.of_full_log) {
		/* first log */
		sequence_id = 0;
	} else {
		pl_hdr = SSDFS_PLH(env->log.header.ptr);
		sequence_id = le32_to_cpu(pl_hdr->sequence_id);
	}

	BUG_ON((sequence_id + 1) >= INT_MAX);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("new_log_start_block %u\n", new_log_start_block);
#endif /* CONFIG_SSDFS_DEBUG */

	free_blocks = 0;

	if (new_log_start_block < fsi->pages_per_peb) {
		struct ssdfs_peb_prev_log prev_log;
		struct ssdfs_metadata_descriptor *meta_desc;
		u16 free_blocks;
		u16 min_log_blocks;

		/*
		 * Set the value of log's start block
		 * by temporary value. It needs for
		 * estimation of min_partial_log_blocks.
		 */
		ssdfs_peb_current_log_lock(pebi);
		pebi->current_log.start_block = new_log_start_block;
		ssdfs_peb_current_log_unlock(pebi);

		free_blocks = new_log_start_block % pebi->log_blocks;
		free_blocks = pebi->log_blocks - free_blocks;
		min_log_blocks = ssdfs_peb_estimate_min_partial_log_pages(pebi);
		sequence_id++;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free_blocks %u, min_log_blocks %u, "
			  "new_log_start_block %u\n",
			  free_blocks, min_log_blocks,
			  new_log_start_block);
#endif /* CONFIG_SSDFS_DEBUG */

		if (free_blocks == pebi->log_blocks) {
			/* start new full log */
			sequence_id = 0;
		} else if (free_blocks < min_log_blocks &&
			   free_blocks < default_threshold) {
			SSDFS_WARN("POTENTIAL HOLE: "
				   "seg %llu, peb %llu, "
				   "peb_index %u, start_block %u, "
				   "free_blocks %u, min_log_blocks %u, "
				   "new_log_start_block %u\n",
				   pebi->pebc->parent_si->seg_id,
				   pebi->peb_id, pebi->peb_index,
				   new_log_start_block,
				   free_blocks, min_log_blocks,
				   new_log_start_block + free_blocks);

#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */

			new_log_start_block += free_blocks;
			free_blocks = pebi->log_blocks;
			sequence_id = 0;
		}

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("free_blocks %u, min_log_blocks %u, "
			  "new_log_start_block %u\n",
			  free_blocks, min_log_blocks,
			  new_log_start_block);

		SSDFS_DBG("HEADER DUMP\n");
		print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
				     env->log.header.ptr,
				     sizeof(struct ssdfs_segment_header));
		SSDFS_DBG("\n");
#endif /* CONFIG_SSDFS_DEBUG */

		bytes_count =
			le32_to_cpu(env->log.blk_bmap.header.ptr->bytes_count);
		prev_log.bmap_bytes = bytes_count;

		if (env->log.header.of_full_log) {
			seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);

			meta_desc =
			    &seg_hdr->desc_array[SSDFS_OFF_TABLE_INDEX];
			bytes_count = le32_to_cpu(meta_desc->size);
			prev_log.blk2off_bytes = bytes_count;

			meta_desc =
			    &seg_hdr->desc_array[SSDFS_BLK_DESC_AREA_INDEX];
			bytes_count = le32_to_cpu(meta_desc->size);
			prev_log.blk_desc_bytes = bytes_count;
		} else {
			pl_hdr = SSDFS_PLH(env->log.header.ptr);

			meta_desc =
			    &pl_hdr->desc_array[SSDFS_OFF_TABLE_INDEX];
			bytes_count = le32_to_cpu(meta_desc->size);
			prev_log.blk2off_bytes = bytes_count;

			meta_desc =
			    &pl_hdr->desc_array[SSDFS_BLK_DESC_AREA_INDEX];
			bytes_count = le32_to_cpu(meta_desc->size);
			prev_log.blk_desc_bytes = bytes_count;
		}

		ssdfs_peb_current_log_init(pebi, free_blocks,
					   new_log_start_block,
					   sequence_id,
					   &prev_log);
	} else {
		struct ssdfs_peb_prev_log prev_log = {
			.bmap_bytes = U32_MAX,
			.blk2off_bytes = U32_MAX,
			.blk_desc_bytes = U32_MAX,
		};

		sequence_id = 0;
		ssdfs_peb_current_log_init(pebi,
					   0,
					   new_log_start_block,
					   sequence_id,
					   &prev_log);
	}

fail_init_using_blk_bmap:
	if (unlikely(err))
		goto fail_init_using_peb;

	peb_free_pages = ssdfs_peb_get_free_pages(pebi->pebc);
	if (unlikely(peb_free_pages < 0)) {
		err = peb_free_pages;
		SSDFS_ERR("fail to calculate PEB's free pages: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		goto fail_init_using_peb;
	}

	items_state = atomic_read(&pebi->pebc->items_state);
	switch(items_state) {
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		is_migrating = true;
		break;

	default:
		is_migrating = false;
		break;
	};

	free_blocks = fsi->pages_per_peb - new_log_start_block;

	if (!is_ssdfs_peb_containing_user_data(pebi->pebc)) {
		int pages_per_peb;
		u32 threshold;
		int peb_used_blocks;

		pages_per_peb = ssdfs_peb_get_pages_capacity(pebi->pebc);
		if (unlikely(pages_per_peb < 0)) {
			err = -ERANGE;
			SSDFS_ERR("fail to get PEB's capacity: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			goto fail_init_using_peb;
		} else if (pages_per_peb < default_threshold) {
			pages_per_peb = fsi->pages_per_peb;
		}

		threshold = pages_per_peb - default_threshold;

		peb_used_blocks = ssdfs_peb_get_used_data_pages(pebi->pebc);
		if (unlikely(peb_used_blocks < 0)) {
			err = peb_used_blocks;
			SSDFS_ERR("fail to calculate PEB's used blocks: "
				  "seg %llu, peb %llu, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, err);
			goto fail_init_using_peb;
		}

		if (peb_used_blocks > threshold) {
			err = -ERANGE;
			SSDFS_ERR("peb_used_blocks %d > threshold %u\n",
				  peb_used_blocks, threshold);
			goto fail_init_using_peb;
		}

		if (free_blocks < default_threshold)
			free_blocks = 0;
		else if (peb_used_blocks == threshold)
			free_blocks = 0;
		else {
			free_blocks = min_t(u32, free_blocks,
					    threshold - peb_used_blocks);
		}
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("peb_free_pages %d, is_migrating %#x, "
		  "free_blocks %u\n",
		  peb_free_pages, is_migrating, free_blocks);
#endif /* CONFIG_SSDFS_DEBUG */

	if (peb_free_pages < free_blocks && !is_migrating) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("pages_per_peb %u, new_log_start_block %u, "
			  "free_blocks %u\n",
			  fsi->pages_per_peb, new_log_start_block,
			  free_blocks);
#endif /* CONFIG_SSDFS_DEBUG */

		if (free_blocks > 0) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("INFLATE: seg %llu, peb %llu, peb_index %u, "
				  "class %#x, cmd %#x, type %#x, "
				  "new_log_start_block %u, free_blocks %u, "
				  "peb_free_pages %d, is_migrating %#x\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, pebi->peb_index,
				  req->private.class, req->private.cmd,
				  req->private.type, new_log_start_block,
				  free_blocks, peb_free_pages, is_migrating);
#endif /* CONFIG_SSDFS_DEBUG */

			seg_blkbmap = &pebi->pebc->parent_si->blk_bmap;
			err = ssdfs_segment_blk_bmap_partial_inflate(seg_blkbmap,
								pebi->peb_index,
								free_blocks);
			if (unlikely(err)) {
				SSDFS_ERR("fail to inflate block bitmap: "
					  "seg %llu, peb %llu, "
					  "free_blocks %u, err %d\n",
					  pebi->pebc->parent_si->seg_id,
					  pebi->peb_id, free_blocks, err);
				goto fail_init_using_peb;
			}
		} else {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("DON'T INFLATE: seg %llu, peb %llu, peb_index %u, "
				  "class %#x, cmd %#x, type %#x, "
				  "new_log_start_block %u, free_blocks %u, "
				  "peb_free_pages %d, is_migrating %#x\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id, pebi->peb_index,
				  req->private.class, req->private.cmd,
				  req->private.type, new_log_start_block,
				  free_blocks, peb_free_pages, is_migrating);
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}

	err = ssdfs_pre_fetch_blk2off_table_area(pebi, req, env);
	if (err == -ENOENT) {
		SSDFS_DBG("blk2off table's fragment is absent\n");
		return 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch blk2off_table area: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log.offset, err);
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
			  env->log.offset, err);
		goto fail_init_using_peb;
	}

	if (env->log.header.of_full_log) {
		seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);
		cno = le64_to_cpu(seg_hdr->cno);
	} else {
		pl_hdr = SSDFS_PLH(env->log.header.ptr);
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
	struct ssdfs_peb_prev_log prev_log = {
		.bmap_bytes = U32_MAX,
		.blk2off_bytes = U32_MAX,
		.blk_desc_bytes = U32_MAX,
	};
	u16 fragments_count;
	u32 bytes_count;
	u16 new_log_start_block;
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

	err = ssdfs_peb_get_log_blocks_count(fsi, pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to define log_pages: "
			  "seg %llu, peb %llu\n",
			  si->seg_id, pebi->peb_id);
		goto fail_init_used_blk_bmap;
	}

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->pages_per_peb % env->log.blocks) {
		SSDFS_WARN("fsi->pages_per_peb %u, log_blocks %u\n",
			   fsi->pages_per_peb, env->log.blocks);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	pebi->log_blocks = env->log.blocks;

	err = ssdfs_find_last_partial_log(fsi, pebi, env,
					  &new_log_start_block);
	if (unlikely(err)) {
		SSDFS_ERR("fail to find last partial log: err %d\n", err);
		goto fail_init_used_blk_bmap;
	}

	err = ssdfs_pre_fetch_block_bitmap(pebi, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch block bitmap: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log.offset, err);
		goto fail_init_used_blk_bmap;
	}

	err = ssdfs_read_checked_block_bitmap_header(pebi, req, env);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read block bitmap header: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  si->seg_id, pebi->peb_id,
			  env->log.offset, err);
		goto fail_init_used_blk_bmap;
	}

	fragments_count =
		le16_to_cpu(env->log.blk_bmap.header.ptr->fragments_count);
	bytes_count =
		le32_to_cpu(env->log.blk_bmap.header.ptr->bytes_count);

	for (i = 0; i < fragments_count; i++) {
		env->log.blk_bmap.fragment.index = i;
		err = ssdfs_init_block_bitmap_fragment(pebi, req, env);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init block bitmap: "
				  "peb_id %llu, peb_index %u, "
				  "log_offset %u, fragment_index %u, "
				  "read_bytes %u, err %d\n",
				  pebi->peb_id, pebi->peb_index,
				  env->log.offset, i,
				  env->log.blk_bmap.read_bytes, err);
			goto fail_init_used_blk_bmap;
		}
	}

	if (bytes_count != env->log.blk_bmap.read_bytes) {
		SSDFS_WARN("bytes_count %u != read_bytes %u\n",
			   bytes_count, env->log.blk_bmap.read_bytes);
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

	ssdfs_peb_current_log_init(pebi, 0, fsi->pages_per_peb, 0, &prev_log);

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
			  env->log.offset, err);
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
			  env->log.offset, err);
		goto fail_init_used_peb;
	}

	if (env->log.header.of_full_log) {
		seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);
		cno = le64_to_cpu(seg_hdr->cno);
	} else {
		pl_hdr = SSDFS_PLH(env->log.header.ptr);
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
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		/* valid states */
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   items_state);
		return -ERANGE;
	};

	ssdfs_peb_container_lock(pebc);

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

	id1 = pebi->env.peb.cur_migration_id;

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

	switch (items_state) {
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		if (!pebc->dst_peb) {
			SSDFS_WARN("destination PEB is NULL\n");
			err = -ERANGE;
			goto finish_src_init_using_metadata_state;
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
			goto finish_src_init_using_metadata_state;
		}

		id2 = ssdfs_get_peb_migration_id(pebc->dst_peb);

		if (id2 == SSDFS_PEB_UNKNOWN_MIGRATION_ID) {
			/* it needs to initialize the migration id */
			ssdfs_set_peb_migration_id(pebc->dst_peb, id1);
			atomic_set(&pebc->dst_peb->state,
				   SSDFS_PEB_OBJECT_INITIALIZED);
			complete_all(&pebc->dst_peb->init_end);
		}  else if (is_peb_migration_id_valid(id2)) {
			if (id1 != id2) {
				err = -ERANGE;
				SSDFS_ERR("id1 %d != id2 %d\n",
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
		break;

	default:
		/* do nothing */
		break;
	};

finish_src_init_using_metadata_state:
	ssdfs_destroy_init_env(&pebi->env);
	ssdfs_peb_container_unlock(pebc);

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

	ssdfs_peb_container_lock(pebc);

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

	id1 = pebi->env.peb.cur_migration_id;

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

		id1 = pebi->env.peb.prev_migration_id;

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
	ssdfs_peb_container_unlock(pebc);

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

	ssdfs_peb_container_lock(pebc);

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

	id1 = pebi->env.peb.cur_migration_id;

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
	ssdfs_peb_container_unlock(pebc);

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

	ssdfs_peb_container_lock(pebc);

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

	id1 = pebi->env.peb.cur_migration_id;

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

		id1 = pebi->env.peb.prev_migration_id;

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
	ssdfs_peb_container_unlock(pebc);

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
	struct folio *folio;
	void *kaddr;
	size_t hdr_buf_size = sizeof(struct ssdfs_segment_header);
	u32 start_folio;
	u32 block_index;
	int skipped_logs = 0;
	int i;
	int err = -ENOENT;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !env);

	SSDFS_DBG("seg %llu, peb %llu, peb_index %u, "
		  "log_offset %u, log_diff %d\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, pebi->peb_index,
		  env->log.offset, log_diff);
#endif /* CONFIG_SSDFS_DEBUG */

	if (env->log.offset > fsi->pages_per_peb) {
		SSDFS_ERR("log_offset %u > pages_per_peb %u\n",
			  env->log.offset, fsi->pages_per_peb);
		return -ERANGE;
	} else if (env->log.offset == fsi->pages_per_peb)
		env->log.offset--;

	if (log_diff > 0) {
		SSDFS_ERR("invalid log_diff %d\n", log_diff);
		return -EINVAL;
	}

	if (env->log.offset == 0) {
		SSDFS_DBG("previous log is absent\n");
		return -ENOENT;
	}

	start_folio = env->log.offset << fsi->log_pagesize;
	start_folio /= pebi->cache.folio_size;

	for (i = start_folio; i >= 0; i--) {
		folio = ssdfs_folio_array_get_folio_locked(&pebi->cache, i);
		if (IS_ERR_OR_NULL(folio)) {
			if (folio == NULL) {
				SSDFS_ERR("fail to get folio: "
					  "index %d\n",
					  i);
				return -ERANGE;
			} else {
				err = PTR_ERR(folio);

				if (err == -ENOENT)
					continue;
				else {
					SSDFS_ERR("fail to get folio: "
						  "index %d, err %d\n",
						  i, err);
					return err;
				}
			}
		}

		kaddr = kmap_local_folio(folio, 0);
		ssdfs_memcpy(env->log.header.ptr, 0, hdr_buf_size,
			     kaddr, 0, PAGE_SIZE,
			     hdr_buf_size);
		ssdfs_memcpy(env->log.footer.ptr, 0, hdr_buf_size,
			     kaddr, 0, PAGE_SIZE,
			     hdr_buf_size);
		kunmap_local(kaddr);
		ssdfs_folio_unlock(folio);
		ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("folio %p, count %d\n",
			  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

		magic = (struct ssdfs_signature *)env->log.header.ptr;

		if (__is_ssdfs_segment_header_magic_valid(magic)) {
			seg_hdr = SSDFS_SEG_HDR(env->log.header.ptr);

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

			if (start_folio == i) {
				/*
				 * Requested starting log_offset points out
				 * on segment header. It needs to skip this
				 * header because of searching the previous
				 * log.
				 */
				continue;
			}

			env->log.header.of_full_log = true;
			env->log.footer.is_present = ssdfs_log_has_footer(seg_hdr);

			block_index = (u32)i * pebi->cache.folio_size;
			block_index >>= fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
			BUG_ON(block_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

			env->log.offset = (u16)block_index;

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

			pl_hdr = SSDFS_PLH(env->log.header.ptr);

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

			env->log.header.of_full_log = false;
			env->log.footer.is_present = ssdfs_pl_has_footer(pl_hdr);

			env->log.bytes =
				le32_to_cpu(pl_hdr->log_bytes);

			flags = le32_to_cpu(pl_hdr->pl_flags);

			if (flags & SSDFS_PARTIAL_HEADER_INSTEAD_FOOTER) {
				/* first partial log */
				err = -ENOENT;
				continue;
			} else if (flags & SSDFS_LOG_HAS_FOOTER) {
				/* last partial log */
				if (start_folio == i) {
					/*
					 * Requested starting log_offset
					 * points out on segment header.
					 * It needs to skip this header
					 * because of searching the previous
					 * log.
					 */
					continue;
				}

				block_index = (u32)i * pebi->cache.folio_size;
				block_index >>= fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(block_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

				env->log.offset = (u16)block_index;

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
				if (start_folio == i) {
					/*
					 * Requested starting log_offset
					 * points out on segment header.
					 * It needs to skip this header
					 * because of searching the previous
					 * log.
					 */
					continue;
				}

				block_index = (u32)i * pebi->cache.folio_size;
				block_index >>= fsi->log_pagesize;

#ifdef CONFIG_SSDFS_DEBUG
				BUG_ON(block_index >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

				env->log.offset = (u16)block_index;

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
			footer = SSDFS_LF(env->log.footer.ptr);

			env->log.bytes =
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
		  env->log.offset,
		  env->log.bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_peb_process_current_log_blk2off_table() - process current log
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
 * %-ENOENT     - no previous log exists.
 * %-EAGAIN     - try next log.
 * %-EEXIST     - blk2off table has been initialized.
 */
static
int ssdfs_peb_process_current_log_blk2off_table(struct ssdfs_peb_info *pebi,
						int log_diff,
						struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *blk2off_table = NULL;
	u64 cno;
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
		return -EEXIST;

	default:
		/* continue to init blk2off table */
		break;
	}

	err = ssdfs_find_prev_partial_log(fsi, pebi,
					  &pebi->env, log_diff);
	if (err == -ENOENT) {
		if (pebi->env.log.offset > 0) {
			SSDFS_ERR("fail to find prev log: "
				  "log_offset %u, err %d\n",
				  pebi->env.log.offset, err);
			goto finish_init_blk2off_table;
		} else {
			/* no previous log exists */
			SSDFS_DBG("no previous log exists\n");
			goto finish_init_blk2off_table;
		}
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to find prev log: "
			  "log_offset %u, err %d\n",
			  pebi->env.log.offset, err);
		goto finish_init_blk2off_table;
	}

	err = ssdfs_pre_fetch_blk2off_table_area(pebi, req, &pebi->env);
	if (err == -ENOENT) {
		err = -EAGAIN;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("blk2off table's fragment is absent: "
			  "seg %llu, peb %llu, log_offset %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  pebi->env.log.offset);
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_init_blk2off_table;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch blk2off_table area: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  pebi->env.log.offset,
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
			  pebi->env.log.offset);
#endif /* CONFIG_SSDFS_DEBUG */
		/*
		 * Continue initialization logic.
		 * Block descriptor table could be absent
		 * in the case of delete operation.
		 */
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to pre-fetch blk desc table area: "
			  "seg %llu, peb %llu, log_offset %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  pebi->env.log.offset,
			  err);
		goto finish_init_blk2off_table;
	}

	if (pebi->env.log.header.of_full_log) {
		struct ssdfs_segment_header *seg_hdr = NULL;

		seg_hdr = SSDFS_SEG_HDR(pebi->env.log.header.ptr);
		cno = le64_to_cpu(seg_hdr->cno);
	} else {
		struct ssdfs_partial_log_header *pl_hdr = NULL;

		pl_hdr = SSDFS_PLH(pebi->env.log.header.ptr);
		cno = le64_to_cpu(pl_hdr->cno);
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg_id %llu, peb %llu, "
		  "env.log.offset %u\n",
		  pebi->pebc->parent_si->seg_id, pebi->peb_id,
		  pebi->env.log.offset);
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
		goto finish_init_blk2off_table;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to start init of offset table: "
			  "seg %llu, peb %llu, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id, err);
		goto finish_init_blk2off_table;
	}

finish_init_blk2off_table:
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
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
static
int ssdfs_peb_complete_init_blk2off_table(struct ssdfs_peb_info *pebi,
					  int log_diff,
					  struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *blk2off_table = NULL;
	unsigned long last_folio_idx;
	unsigned long block_index;
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

	last_folio_idx = ssdfs_folio_array_get_last_folio_index(&pebi->cache);

	if (last_folio_idx >= SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO) {
		SSDFS_ERR("empty folio array: last_folio_idx %lu\n",
			  last_folio_idx);
		return -ERANGE;
	}

	block_index = last_folio_idx * pebi->cache.folio_size;
	block_index >>= fsi->log_pagesize;

	if (block_index >= fsi->pages_per_peb) {
		SSDFS_ERR("corrupted folio array: "
			  "block_index %lu, fsi->pages_per_peb %u\n",
			  block_index, fsi->pages_per_peb);
		return -ERANGE;
	}

	pebi->env.log.offset = (u32)block_index + 1;

	err = ssdfs_peb_process_current_log_blk2off_table(pebi,
							  log_diff,
							  req);
	if (err == -EEXIST) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("blk2off table has been initialized: "
			  "peb_id %llu\n",
			  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		err = 0;
		goto finish_init_blk2off_table;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to process current log: "
			  "seg %llu, peb %llu, "
			  "log_offset %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  pebi->env.log.offset,
			  err);
		goto finish_init_blk2off_table;
	}

finish_init_blk2off_table:
	ssdfs_destroy_init_env(&pebi->env);
	return err;
}
#else /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */
static
int ssdfs_peb_complete_init_blk2off_table(struct ssdfs_peb_info *pebi,
					  int log_diff,
					  struct ssdfs_segment_request *req)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_blk2off_table *blk2off_table = NULL;
	unsigned long last_folio_idx;
	unsigned long block_index;
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

	last_folio_idx = ssdfs_folio_array_get_last_folio_index(&pebi->cache);

	if (last_folio_idx >= SSDFS_FOLIO_ARRAY_INVALID_LAST_FOLIO) {
		SSDFS_ERR("empty folio array: last_folio_idx %lu\n",
			  last_folio_idx);
		return -ERANGE;
	}

	block_index = last_folio_idx * pebi->cache.folio_size;
	block_index >>= fsi->log_pagesize;

	if (block_index >= fsi->pages_per_peb) {
		SSDFS_ERR("corrupted folio array: "
			  "block_index %lu, fsi->pages_per_peb %u\n",
			  block_index, fsi->pages_per_peb);
		return -ERANGE;
	}

	pebi->env.log.offset = (u32)block_index + 1;

	do {
		err = ssdfs_peb_process_current_log_blk2off_table(pebi,
								  log_diff,
								  req);
		if (err == -EEXIST) {
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("blk2off table has been initialized: "
				  "peb_id %llu\n",
				  pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
			err = 0;
			goto finish_init_blk2off_table;
		} else if (err == -EAGAIN) {
			err = 0;
#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("try next log: "
				  "seg %llu, peb %llu, log_offset %u\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  pebi->env.log.offset);
#endif /* CONFIG_SSDFS_DEBUG */
			goto try_next_log;
		} else if (err == -ENOENT) {
			/* no previous log exists */
			err = 0;
			SSDFS_DBG("no previous log exists\n");
			goto finish_init_blk2off_table;
		} else if (unlikely(err)) {
			SSDFS_ERR("fail to process current log: "
				  "seg %llu, peb %llu, "
				  "log_offset %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  pebi->env.log.offset,
				  err);
			goto finish_init_blk2off_table;
		}

try_next_log:
		ssdfs_reinit_blk2off_table_init_env(&pebi->env.log.blk2off_tbl);
		ssdfs_reinit_blk_desc_table_init_env(&pebi->env.log.blk_desc_tbl);
		log_diff = 0;
	} while (pebi->env.log.offset > 0);

finish_init_blk2off_table:
	ssdfs_destroy_init_env(&pebi->env);
	return err;
}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

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
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
	/*
	 * No implementation of this function.
	 */
#else /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */
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
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

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
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
static
int ssdfs_src_peb_complete_init_blk2off_table(struct ssdfs_peb_container *pebc,
					      struct ssdfs_segment_request *req)
{
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

	/*
	 * Offset translation table should be intialized
	 * by the content of last log only. No activity is
	 * requered here.
	 */
	return err;
}
#else /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */
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

	ssdfs_peb_container_lock(pebc);

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
	ssdfs_peb_container_unlock(pebc);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

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
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
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

	ssdfs_peb_container_lock(pebc);

	items_state = atomic_read(&pebc->items_state);
	switch (items_state) {
	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		/* do nothing */
		break;

	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
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

	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
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
		SSDFS_ERR("seg_id %llu, peb_index %u, items_state %#x\n",
			  pebc->parent_si->seg_id, pebc->peb_index,
			  items_state);
		BUG();
	}

finish_dst_peb_init_blk2off_table:
	ssdfs_peb_container_unlock(pebc);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}
#else /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */
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

	ssdfs_peb_container_lock(pebc);

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

	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
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
	ssdfs_peb_container_unlock(pebc);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

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
	fragment_size = pebc->parent_si->fsi->pagesize;
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
	u16 fragment_id;
	u16 fragments_count;
	u16 fragments_per_peb;

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
	ptr->fragment_size = pebc->parent_si->fsi->pagesize;
	fragments_bytes_per_seg =
		(u32)segbmap->fragments_per_seg * ptr->fragment_size;
	fragments_per_peb = segbmap->fragments_per_peb;
	fragments_bytes_per_peb = (u32)fragments_per_peb * ptr->fragment_size;
	ptr->logical_offset = fragments_bytes_per_seg * seg_index;
	ptr->logical_offset += fragments_bytes_per_peb * peb_index;
	ptr->data_size = fragments_per_peb * ptr->fragment_size;
	fragments_count = segbmap->fragments_count;
	up_read(&segbmap->resize_lock);

	fragment_id = ssdfs_peb_define_segbmap_sequence_id(pebc, seg_index,
							   ptr->logical_offset);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(fragment_id >= U16_MAX);
	BUG_ON(fragment_id >= fragments_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fragment_id < fragments_count) {
		fragments_per_peb = min_t(u16, fragments_per_peb,
						fragments_count - fragment_id);
		ptr->data_size = min_t(u32, ptr->data_size,
					fragments_per_peb * ptr->fragment_size);
	}

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
		(u32)segbmap->fragments_per_seg * fsi->pagesize;
	fragments_bytes_per_peb =
		(u32)segbmap->fragments_per_peb * fsi->pagesize;
	blks_per_peb = fragments_bytes_per_peb + fsi->pagesize - 1;
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
 * ssdfs_peb_read_segbmap_first_folio() - read first folio of segbmap
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
 * %-ENODATA     - no folios for read.
 * %-ENOMEM      - fail to allocate memory.
 * %-ERANGE      - internal error.
 */
static
int ssdfs_peb_read_segbmap_first_folio(struct ssdfs_peb_container *pebc,
				       u16 seg_index,
				       struct ssdfs_segbmap_extent *extent)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_request *req;
	struct ssdfs_request_content_block *block;
	struct ssdfs_content_block *blk_state;
	struct folio *folio;
	u16 folios_count = 1;
	u16 logical_blk;
	u16 sequence_id;
	int state;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!extent);
	BUG_ON(extent->fragment_size != pebc->parent_si->fsi->pagesize);

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

	ssdfs_request_init(req, fsi->pagesize);
	ssdfs_get_request(req);

	ssdfs_request_prepare_logical_extent(SSDFS_SEG_BMAP_INO,
					     extent->logical_offset,
					     extent->fragment_size,
					     0, 0, req);

	err = ssdfs_request_add_allocated_folio_locked(0, req);
	if (unlikely(err)) {
		SSDFS_ERR("fail allocate memory folio: err %d\n", err);
		goto fail_read_segbmap_folio;
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
		goto fail_read_segbmap_folio;
	}

	ssdfs_request_define_volume_extent(logical_blk, folios_count, req);

	err = ssdfs_peb_read_page(pebc, req, NULL);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read page: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		goto fail_read_segbmap_folio;
	}

	if (!err) {
		for (i = 0; i < req->result.processed_blks; i++)
			ssdfs_peb_mark_request_block_uptodate(pebc, req, i);
	}

	block = &req->result.content.blocks[0];
	blk_state = &block->new_state;
	folio = blk_state->batch.folios[0];

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!folio);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!ssdfs_segbmap_fragment_has_content(folio)) {
		err = -ENODATA;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_index %u hasn't segbmap's fragments\n",
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		goto fail_read_segbmap_folio;
	}

	sequence_id = ssdfs_peb_define_segbmap_sequence_id(pebc, seg_index,
							extent->logical_offset);
	if (unlikely(sequence_id == U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("fail to define sequence_id\n");
		goto fail_read_segbmap_folio;
	}

	err = ssdfs_segbmap_check_fragment_header(pebc, seg_index, sequence_id,
						  folio);
	if (unlikely(err)) {
		SSDFS_CRIT("segbmap fragment is corrupted: err %d\n",
			   err);
	}

	if (err) {
		state = SSDFS_SEGBMAP_FRAG_INIT_FAILED;
		goto fail_read_segbmap_folio;
	} else
		state = SSDFS_SEGBMAP_FRAG_INITIALIZED;

	err = ssdfs_segbmap_fragment_init(pebc, sequence_id,
					  folio, state);
	if (unlikely(err)) {
		SSDFS_ERR("fail to init fragment: "
			  "sequence_id %u, err %d\n",
			  sequence_id, err);
		goto fail_read_segbmap_folio;
	} else {
		ssdfs_request_unlock_and_forget_block(0, req);
	}

	extent->logical_offset += extent->fragment_size;
	extent->data_size -= extent->fragment_size;

fail_read_segbmap_folio:
	ssdfs_request_unlock_and_remove_folios(req);
	ssdfs_put_request(req);
	ssdfs_request_free(req, pebc->parent_si);

	return err;
}

/*
 * ssdfs_peb_read_segbmap_folios() - read folio batch
 * @pebc: pointer on PEB container
 * @seg_index: index of segment in segbmap's segments sequence
 * @extent: requested extent for reading
 *
 * This method tries to read folio batch of segbmap in PEB
 * (excluding the first one) and to initialize all
 * available fragments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA     - no folios for read.
 * %-ENOMEM      - fail to allocate memory.
 * %-ERANGE      - internal error.
 */
static
int ssdfs_peb_read_segbmap_folios(struct ssdfs_peb_container *pebc,
				  u16 seg_index,
				  struct ssdfs_segbmap_extent *extent)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_segment_request *req;
	struct ssdfs_request_content_block *block;
	struct ssdfs_content_block *blk_state;
	u32 read_bytes;
	u16 fragments_count;
	u16 blks_count = 1;
	u16 logical_blk;
	u16 sequence_id;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!extent);
	BUG_ON(extent->fragment_size != pebc->parent_si->fsi->pagesize);

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

	ssdfs_request_init(req, fsi->pagesize);
	ssdfs_get_request(req);

	read_bytes = min_t(u32, SSDFS_EXTENT_LEN_MAX * PAGE_SIZE,
			   extent->data_size);

	ssdfs_request_prepare_logical_extent(SSDFS_SEG_BMAP_INO,
					     extent->logical_offset,
					     read_bytes,
					     0, 0, req);

	fragments_count = read_bytes + extent->fragment_size - 1;
	fragments_count /= extent->fragment_size;

	for (i = 0; i < fragments_count; i++) {
		err = ssdfs_request_add_allocated_folio_locked(i, req);
		if (unlikely(err)) {
			SSDFS_ERR("fail allocate memory folio: err %d\n", err);
			goto fail_read_segbmap_folios;
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
		goto fail_read_segbmap_folios;
	}

	blks_count = (read_bytes + fsi->pagesize - 1) >> fsi->log_pagesize;
	ssdfs_request_define_volume_extent(logical_blk, blks_count, req);

	err = ssdfs_peb_readahead_pages(pebc, req, NULL);
	if (unlikely(err)) {
		SSDFS_ERR("fail to read pages: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		goto fail_read_segbmap_folios;
	}

	for (i = 0; i < req->result.processed_blks; i++)
		ssdfs_peb_mark_request_block_uptodate(pebc, req, i);

#ifdef CONFIG_SSDFS_DEBUG
	for (i = 0; i < req->result.content.count; i++) {
		int j;

		block = &req->result.content.blocks[i];
		blk_state = &block->new_state;

		BUG_ON(folio_batch_count(&blk_state->batch) == 0);

		for (j = 0; j < folio_batch_count(&blk_state->batch); j++) {
			struct folio *folio;
			void *kaddr;
			u32 processed_bytes = 0;
			u32 page_index = 0;

			folio = blk_state->batch.folios[j];

			do {
				kaddr = kmap_local_folio(folio,
							 processed_bytes);
				SSDFS_DBG("PAGE DUMP: blk_index %d, "
					  "folio_index %d, page_index %u\n",
					  i, j, page_index);
				print_hex_dump_bytes("", DUMP_PREFIX_OFFSET,
						     kaddr,
						     PAGE_SIZE);
				SSDFS_DBG("\n");
				kunmap_local(kaddr);

				processed_bytes += PAGE_SIZE;
				page_index++;
			} while (processed_bytes < folio_size(folio));
		}
	}
#endif /* CONFIG_SSDFS_DEBUG */

	sequence_id = ssdfs_peb_define_segbmap_sequence_id(pebc, seg_index,
							extent->logical_offset);
	if (unlikely(sequence_id == U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("fail to define sequence_id\n");
		goto fail_read_segbmap_folios;
	}

	for (i = 0; i < fragments_count; i++) {
		int state;
		struct folio *folio;

		block = &req->result.content.blocks[i];
		blk_state = &block->new_state;
		folio = blk_state->batch.folios[0];

		err = ssdfs_segbmap_check_fragment_header(pebc, seg_index,
							  sequence_id, folio);
		if (unlikely(err)) {
			SSDFS_CRIT("segbmap fragment is corrupted: "
				   "sequence_id %u, err %d\n",
				   sequence_id, err);
		}

		if (err) {
			state = SSDFS_SEGBMAP_FRAG_INIT_FAILED;
			goto fail_read_segbmap_folios;
		} else
			state = SSDFS_SEGBMAP_FRAG_INITIALIZED;

		err = ssdfs_segbmap_fragment_init(pebc, sequence_id,
						  folio, state);
		if (unlikely(err)) {
			SSDFS_ERR("fail to init fragment: "
				  "sequence_id %u, err %d\n",
				  sequence_id, err);
			goto fail_read_segbmap_folios;
		} else {
			ssdfs_request_unlock_and_forget_block(i, req);
		}

		sequence_id++;
	}

	extent->logical_offset += read_bytes;
	extent->data_size -= read_bytes;

fail_read_segbmap_folios:
	ssdfs_request_unlock_and_remove_folios(req);
	ssdfs_put_request(req);
	ssdfs_request_free(req, pebc->parent_si);

	return err;
}

/*
 * ssdfs_peb_read_segbmap_rest_folios() - read all folios of segbmap in PEB
 * @pebc: pointer on PEB container
 * @seg_index: index of segment in segbmap's segments sequence
 * @extent: requested extent for reading
 *
 * This method tries to read all folios of segbmap in PEB (excluding
 * the first one) and initialize all available fragments.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ENODATA     - no pages for read.
 */
static
int ssdfs_peb_read_segbmap_rest_folios(struct ssdfs_peb_container *pebc,
				       u16 seg_index,
				       struct ssdfs_segbmap_extent *extent)
{
	int err = 0, err1;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si || !pebc->parent_si->fsi);
	BUG_ON(!extent);
	BUG_ON(extent->fragment_size != pebc->parent_si->fsi->pagesize);

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
		err1 = ssdfs_peb_read_segbmap_folios(pebc, seg_index,
						     extent);
		if (unlikely(err1)) {
			SSDFS_ERR("fail to read segbmap's folios: "
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

	err = ssdfs_peb_read_segbmap_first_folio(pebc, seg_index, &extent);
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

	err = ssdfs_peb_read_segbmap_rest_folios(pebc, seg_index, &extent);
	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("peb_index %u has only one folio\n",
			  pebc->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read PEB's segbmap rest folios: "
			  "err %d\n", err);
		return err;
	}

	{
		int err1 = ssdfs_peb_release_folios(pebc);
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
 * ssdfs_maptbl_fragment_folios_count() - calculate count of folios in fragment
 * @fsi: file system info object
 *
 * This method calculates count of folios in the mapping table's
 * fragment.
 *
 * RETURN:
 * [success] - count of folios in fragment
 * [failure] - U16_MAX
 */
static inline
u16 ssdfs_maptbl_fragment_folios_count(struct ssdfs_fs_info *fsi)
{
	u32 fragment_folios;

#ifdef CONFIG_SSDFS_DEBUG
	if (fsi->maptbl->fragment_bytes % PAGE_SIZE) {
		SSDFS_WARN("invalid fragment_bytes %u\n",
			   fsi->maptbl->fragment_bytes);
		return U16_MAX;
	}
#endif /* CONFIG_SSDFS_DEBUG */

	fragment_folios = fsi->maptbl->fragment_bytes / fsi->pagesize;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(fragment_folios >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	return fragment_folios;
}

/*
 * ssdfs_peb_read_maptbl_fragment() - read mapping table's fragment
 * @pebc: pointer on PEB container
 * @index: index of fragment in the PEB
 * @logical_offset: logical offset of fragment in mapping table
 * @logical_blk: starting logical block of fragment
 * @fragment_bytes: size of fragment in bytes
 * @area: fragment content [out]
 *
 * This method tries to read mapping table's fragment.
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
	struct ssdfs_request_content_block *block;
	struct ssdfs_content_block *blk_state;
	u32 batch_bytes;
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

	batch_bytes = (u32)SSDFS_EXTENT_LEN_MAX << fsi->log_pagesize;

	if (fragment_bytes == 0) {
		SSDFS_ERR("invalid fragment_bytes %u\n",
			  fragment_bytes);
		return -ERANGE;
	}

	do {
		u32 size;
		u16 blks_count;
		int i;

		req = ssdfs_request_alloc();
		if (IS_ERR_OR_NULL(req)) {
			err = (req == NULL ? -ENOMEM : PTR_ERR(req));
			SSDFS_ERR("fail to allocate segment request: err %d\n",
				  err);
			return err;
		}

		ssdfs_request_init(req, fsi->pagesize);
		ssdfs_get_request(req);

		size = min_t(u32, fragment_bytes, batch_bytes);

		ssdfs_request_prepare_logical_extent(SSDFS_MAPTBL_INO,
						     logical_offset, size,
						     0, 0, req);

		blks_count = (size + fsi->pagesize - 1) >> fsi->log_pagesize;
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(blks_count > SSDFS_EXTENT_LEN_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

		for (i = 0; i < blks_count; i++) {
			err = ssdfs_request_add_allocated_folio_locked(i, req);
			if (unlikely(err)) {
				SSDFS_ERR("fail allocate memory folio: "
					  "err %d\n", err);
				goto fail_read_maptbl_folios;
			}
		}

		ssdfs_request_prepare_internal_data(SSDFS_PEB_READ_REQ,
						    SSDFS_READ_PAGES_READAHEAD,
						    SSDFS_REQ_SYNC,
						    req);

		ssdfs_request_define_segment(pebc->parent_si->seg_id, req);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("logical_offset %llu, size %u, "
			  "logical_blk %u, blks_count %u\n",
			  logical_offset, size,
			  logical_blk, blks_count);
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_request_define_volume_extent((u16)logical_blk,
						   blks_count, req);

		err = ssdfs_peb_readahead_pages(pebc, req, NULL);
		if (unlikely(err)) {
			SSDFS_ERR("fail to read folios: "
				  "seg %llu, peb_index %u, err %d\n",
				  pebc->parent_si->seg_id,
				  pebc->peb_index, err);
			goto fail_read_maptbl_folios;
		}

		for (i = 0; i < req->result.processed_blks; i++)
			ssdfs_peb_mark_request_block_uptodate(pebc, req, i);

		if (cur_offset == 0) {
			struct ssdfs_leb_table_fragment_header *hdr;
			u16 magic;
			void *kaddr;
			bool is_fragment_valid = false;

			block = &req->result.content.blocks[0];
			blk_state = &block->new_state;

			kaddr = kmap_local_folio(blk_state->batch.folios[0], 0);
			hdr = (struct ssdfs_leb_table_fragment_header *)kaddr;
			magic = le16_to_cpu(hdr->magic);
			is_fragment_valid = magic == SSDFS_LEB_TABLE_MAGIC;
			area->portion_id = le16_to_cpu(hdr->portion_id);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("FRAGMENT DUMP\n");
			print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, kaddr,
				sizeof(struct ssdfs_leb_table_fragment_header));
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
				goto fail_read_maptbl_folios;
			}
		}

		ssdfs_maptbl_move_fragment_folios(req, area, blks_count);
		ssdfs_request_unlock_and_remove_folios(req);
		ssdfs_put_request(req);
		ssdfs_request_free(req, pebc->parent_si);

		if (size > fragment_bytes)
			fragment_bytes = 0;
		else
			fragment_bytes -= size;

		logical_offset += size;
		cur_offset += size;
		logical_blk += blks_count;

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("fragment_bytes %u, size %u, "
			  "logical_offset %llu, cur_offset %u, "
			  "logical_blk %u, blks_count %u\n",
			  fragment_bytes, size,
			  logical_offset, cur_offset,
			  logical_blk, blks_count);
#endif /* CONFIG_SSDFS_DEBUG */
	} while (fragment_bytes > 0);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_DEBUG */

	return 0;

fail_read_maptbl_folios:
	ssdfs_request_unlock_and_remove_folios(req);
	ssdfs_put_request(req);
	ssdfs_request_free(req, pebc->parent_si);

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
	area.folios_count = 0;
	area.folios_capacity = ssdfs_maptbl_fragment_folios_count(fsi);
	up_read(&fsi->maptbl->tbl_lock);

	if (unlikely(area.folios_capacity >= U16_MAX)) {
		err = -ERANGE;
		SSDFS_ERR("invalid fragment's folios_capacity\n");
		goto end_init;
	}

	area.folios = ssdfs_read_kcalloc(area.folios_capacity,
					 sizeof(struct folio *),
					 GFP_KERNEL);
	if (!area.folios) {
		err = -ENOMEM;
		SSDFS_ERR("fail to allocate memory: "
			  "area.folios_capacity %zu\n",
			  area.folios_capacity);
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
			  "logical_offset %llu, logical_blk %u, "
			  "fragment_bytes %u\n",
			  pebc->parent_si->seg_id, i,
			  logical_offset, logical_blk,
			  fragment_bytes);
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
	for (i = 0; i < area.folios_capacity; i++) {
		if (area.folios[i]) {
			ssdfs_read_free_folio(area.folios[i]);
			area.folios[i] = NULL;
		}
	}

	ssdfs_read_kfree(area.folios);

	{
		int err1 = ssdfs_peb_release_folios(pebc);
		if (err1 == -ENODATA) {
			SSDFS_DBG("PEB cache is empty\n");
		} else if (unlikely(err1)) {
			SSDFS_ERR("fail to release folios: err %d\n",
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
 * @block_index: block index of footer's placement
 * @peb_create_time: PEB's create timestamp [out]
 * @last_log_time: PEB's last log timestamp [out]
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
				u32 block_index,
				u64 *peb_create_time,
				u64 *last_log_time)
{
	struct ssdfs_signature *magic = NULL;
	struct ssdfs_partial_log_header *plh_hdr = NULL;
	struct ssdfs_log_footer *footer = NULL;
	struct folio *folio;
	void *kaddr;
	u32 bytes_offset;
	u32 folio_index;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!peb_create_time || !last_log_time);

	SSDFS_DBG("seg %llu, peb_id %llu, block_index %u\n",
		  pebi->pebc->parent_si->seg_id,
		  pebi->peb_id, block_index);
#endif /* CONFIG_SSDFS_DEBUG */

	*peb_create_time = U64_MAX;
	*last_log_time = U64_MAX;

	folio_index = block_index << fsi->log_pagesize;
	folio_index /= pebi->cache.folio_size;

	folio = ssdfs_folio_array_grab_folio(&pebi->cache, folio_index);
	if (unlikely(IS_ERR_OR_NULL(folio))) {
		SSDFS_ERR("fail to grab folio: index %u\n",
			  folio_index);
		return -ENOMEM;
	}

	if (!folio_test_uptodate(folio) && !folio_test_dirty(folio)) {
		bytes_offset = block_index * fsi->pagesize;

		err = ssdfs_read_folio_from_volume(fsi, pebi->peb_id,
						   bytes_offset,
						   folio);
		if (unlikely(err))
			goto fail_read_footer;

		/*
		 * ->read_folio() unlock the folio
		 * But caller expects that folio is locked
		 */
		ssdfs_folio_lock(folio);

		folio_mark_uptodate(folio);
	}

	kaddr = kmap_local_folio(folio, 0);
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
			  "peb %llu, block_index %u\n",
			  pebi->peb_id, block_index);
#endif /* CONFIG_SSDFS_DEBUG */
		goto fail_read_footer;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("last_log_time %llx\n",
		  *last_log_time);
#endif /* CONFIG_SSDFS_DEBUG */

fail_read_footer:
	kunmap_local(kaddr);
	ssdfs_folio_unlock(folio);
	ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("folio %p, count %d\n",
		  folio, folio_ref_count(folio));
#endif /* CONFIG_SSDFS_DEBUG */

	if (err == -ENODATA) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("valid footer is not detected: "
			  "seg_id %llu, peb_id %llu, "
			  "block_index %u\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  block_index);
#endif /* CONFIG_SSDFS_DEBUG */
		return err;
	} else if (unlikely(err)) {
		SSDFS_ERR("fail to read footer: "
			  "seg %llu, peb %llu, "
			  "block_index %u, err %d\n",
			  pebi->pebc->parent_si->seg_id,
			  pebi->peb_id,
			  block_index,
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

	for (i = fsi->pages_per_peb - 1; i > 0; i--) {
		err = ssdfs_peb_get_last_log_time(fsi, pebi, i,
						  &peb_create_time,
						  &last_log_time);
		if (err == -ENODATA)
			continue;
		else if (unlikely(err)) {
			SSDFS_ERR("fail to get last log time: "
				  "seg %llu, peb %llu, "
				  "block_index %u, err %d\n",
				  pebi->pebc->parent_si->seg_id,
				  pebi->peb_id,
				  i, err);
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

	ssdfs_peb_container_lock(pebc);

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
	ssdfs_peb_container_unlock(pebc);

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

	ssdfs_peb_container_lock(pebc);

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
	ssdfs_peb_container_unlock(pebc);

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

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "req %p, class %#x, cmd %#x, type %#x\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
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
 * ssdfs_unlock_request_folios() - unlock request's folios
 * @req: segment request
 */
static
void ssdfs_unlock_request_folios(struct ssdfs_segment_request *req)
{
	struct ssdfs_request_content_block *block;
	struct ssdfs_content_block *blk_state;
	int i, j;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!req);
#endif /* CONFIG_SSDFS_DEBUG */

	for (i = 0; i < req->result.content.count; i++) {
		block = &req->result.content.blocks[i];
		blk_state = &block->new_state;

		for (j = 0; j < folio_batch_count(&blk_state->batch); j++) {
			struct folio *folio = blk_state->batch.folios[j];

			if (!folio) {
				SSDFS_WARN("folio %d is NULL\n", i);
				continue;
			}

#ifdef CONFIG_SSDFS_DEBUG
			WARN_ON(!folio_test_locked(folio));
#endif /* CONFIG_SSDFS_DEBUG */

			ssdfs_folio_unlock(folio);
			ssdfs_folio_put(folio);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("folio %p, count %d\n",
				  folio, folio_ref_count(folio));
			SSDFS_DBG("folio_index %llu, flags %#lx\n",
				  (u64)folio->index, folio->flags);
#endif /* CONFIG_SSDFS_DEBUG */
		}
	}
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
	int res;
	int i;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !req);

	SSDFS_DBG("seg %llu, peb_index %u, "
		  "req %p, class %#x, cmd %#x, type %#x, err %d\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  req, req->private.class, req->private.cmd,
		  req->private.type, err);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!err) {
		for (i = 0; i < req->result.processed_blks; i++)
			ssdfs_peb_mark_request_block_uptodate(pebc, req, i);
	}

	req->result.err = err;

	switch (req->private.type) {
	case SSDFS_REQ_SYNC:
		if (err) {
			SSDFS_DBG("failure: req %p, err %d\n", req, err);
			atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		} else
			atomic_set(&req->result.state, SSDFS_REQ_FINISHED);

		complete(&req->result.wait);
		wake_up_all(&req->private.wait_queue);
		wake_up_all(wait);
		break;

	case SSDFS_REQ_ASYNC:
		ssdfs_unlock_request_folios(req);

		if (err) {
			SSDFS_DBG("failure: req %p, err %d\n", req, err);
			atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		} else
			atomic_set(&req->result.state, SSDFS_REQ_FINISHED);

		complete(&req->result.wait);
		wake_up_all(&req->private.wait_queue);
		wake_up_all(wait);

		ssdfs_put_request(req);
		if (atomic_read(&req->private.refs_count) != 0) {
			struct ssdfs_request_internal_data *ptr;

			ptr = &req->private;

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("start waiting: refs_count %d\n",
				   atomic_read(&ptr->refs_count));
#endif /* CONFIG_SSDFS_DEBUG */

			res = wait_event_killable_timeout(*wait,
					atomic_read(&ptr->refs_count) == 0,
					SSDFS_DEFAULT_TIMEOUT);
			if (res < 0) {
				WARN_ON(1);
			} else if (res > 1) {
				/*
				 * Condition changed before timeout
				 */
			} else {
				/* timeout is elapsed */
				SSDFS_ERR("seg %llu, ino %llu, "
					  "logical_offset %llu, "
					  "class %#x, cmd %#x, type %#x, "
					  "result.state %#x, "
					  "refs_count %#x\n",
					  pebc->parent_si->seg_id,
					  req->extent.ino,
					  req->extent.logical_offset,
					  req->private.class,
					  req->private.cmd,
					  req->private.type,
					  atomic_read(&req->result.state),
					  atomic_read(&ptr->refs_count));
				WARN_ON(1);
			}
		}

		ssdfs_request_free(req, pebc->parent_si);
		break;

	case SSDFS_REQ_ASYNC_NO_FREE:
		ssdfs_unlock_request_folios(req);

		if (err) {
			SSDFS_DBG("failure: req %p, err %d\n", req, err);
			atomic_set(&req->result.state, SSDFS_REQ_FAILED);
		} else
			atomic_set(&req->result.state, SSDFS_REQ_FINISHED);

		complete(&req->result.wait);
		wake_up_all(&req->private.wait_queue);
		ssdfs_put_request(req);
		wake_up_all(wait);
		break;

	default:
		BUG();
	};

	ssdfs_peb_finish_read_request_cno(pebc);
}

/*
 * should_ssdfs_segment_be_destroyed() - check necessity to destroy a segment
 * @si: pointer on segment object
 *
 * This method tries to check the necessity to destroy
 * a segment object.
 */
static
bool should_ssdfs_segment_be_destroyed(struct ssdfs_segment_info *si)
{
	struct ssdfs_peb_container *pebc;
	struct ssdfs_peb_info *pebi;
	u64 peb_id;
	bool is_rq_empty;
	bool is_fq_empty;
	bool peb_has_dirty_folios = false;
	bool is_blk_bmap_dirty = false;
	u32 reqs_count;
	u64 cur_cno;
	u64 future_request_cno;
	u64 cno_diff;
	u64 threshold;
	int i;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!si);

	SSDFS_DBG("seg_id %llu, refs_count %d\n",
		  si->seg_id,
		  atomic_read(&si->refs_count));
#endif /* CONFIG_SSDFS_DEBUG */

	if (!is_ssdfs_segment_ready_for_requests(si)) {
		err = ssdfs_wait_segment_init_end(si);
		if (unlikely(err)) {
			SSDFS_ERR("segment initialization failed: "
				  "seg %llu, err %d\n",
				  si->seg_id, err);
			return false;
		}
	}

	switch (atomic_read(&si->obj_state)) {
	case SSDFS_CURRENT_SEG_OBJECT:
	case SSDFS_SEG_OBJECT_PRE_DELETED:
		return false;

	default:
		/* continue logic */
		break;
	}

	switch (si->seg_type) {
	case SSDFS_SEGBMAP_SEG_TYPE:
	case SSDFS_MAPTBL_SEG_TYPE:
		return false;

	case SSDFS_LEAF_NODE_SEG_TYPE:
	case SSDFS_HYBRID_NODE_SEG_TYPE:
	case SSDFS_INDEX_NODE_SEG_TYPE:
	case SSDFS_USER_DATA_SEG_TYPE:
		/* continue logic */
		break;

	default:
		SSDFS_ERR("unexpected segment type %#x\n",
			  si->seg_type);
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

	for (i = 0; i < si->pebs_count; i++) {
		pebc = &si->peb_array[i];

		is_rq_empty = is_ssdfs_requests_queue_empty(READ_RQ_PTR(pebc));
		is_fq_empty = !have_flush_requests(pebc);

		is_blk_bmap_dirty =
			is_ssdfs_segment_blk_bmap_dirty(&si->blk_bmap, i);

		pebi = ssdfs_get_current_peb_locked(pebc);
		if (IS_ERR_OR_NULL(pebi))
			return false;

		ssdfs_peb_current_log_lock(pebi);
		peb_has_dirty_folios = ssdfs_peb_has_dirty_folios(pebi);
		peb_id = pebi->peb_id;
		ssdfs_peb_current_log_unlock(pebi);
		ssdfs_unlock_current_peb(pebc);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("seg_id %llu, peb_id %llu, refs_count %d, "
			  "peb_has_dirty_folios %#x, "
			  "not empty: (read %#x, flush %#x), "
			  "is_blk_bmap_dirty %#x\n",
			  si->seg_id, peb_id,
			  atomic_read(&si->refs_count),
			  peb_has_dirty_folios,
			  !is_rq_empty, !is_fq_empty,
			  is_blk_bmap_dirty);
#endif /* CONFIG_SSDFS_DEBUG */

		if (!is_rq_empty || !is_fq_empty ||
		    peb_has_dirty_folios || is_blk_bmap_dirty)
			return false;
	}

	spin_lock(&si->protection.cno_lock);
	cur_cno = ssdfs_current_cno(si->fsi->sb);
	reqs_count = si->protection.reqs_count;
	future_request_cno = si->protection.future_request_cno;
	spin_unlock(&si->protection.cno_lock);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cur_cno %llu, future_request_cno %llu, reqs_count %u\n",
		  cur_cno, future_request_cno, reqs_count);
#endif /* CONFIG_SSDFS_DEBUG */

	if (reqs_count > 0)
		return false;
	else if (cur_cno <= future_request_cno)
		return false;
	else
		cno_diff = cur_cno - future_request_cno;

	switch (si->seg_type) {
	case SSDFS_LEAF_NODE_SEG_TYPE:
		threshold = SSDFS_DEFAULT_TIMEOUT_NS *
				SSDFS_LEAF_NODE_TIME_FACTOR;
		break;

	case SSDFS_HYBRID_NODE_SEG_TYPE:
		threshold = SSDFS_DEFAULT_TIMEOUT_NS *
				SSDFS_HYBRID_NODE_TIME_FACTOR;
		break;

	case SSDFS_INDEX_NODE_SEG_TYPE:
		threshold = SSDFS_DEFAULT_TIMEOUT_NS *
				SSDFS_INDEX_NODE_TIME_FACTOR;
		break;

	case SSDFS_USER_DATA_SEG_TYPE:
		threshold = SSDFS_DEFAULT_TIMEOUT_NS *
				SSDFS_USER_DATA_TIME_FACTOR;
		break;

	default:
		SSDFS_ERR("unexpected segment type %#x\n",
			  si->seg_type);
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return false;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("cno_diff %llu, threshold %llu\n",
		  cno_diff, threshold);
#endif /* CONFIG_SSDFS_DEBUG */

	if (cno_diff < threshold)
		return false;

	return true;
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
	struct ssdfs_fs_info *fsi;
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

	fsi = pebc->parent_si->fsi;
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
	wake_up_all(wait_queue);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb_index %u, timeout %llu\n",
		  pebc->parent_si->seg_id, pebc->peb_index,
		  timeout);
#endif /* CONFIG_SSDFS_DEBUG */

	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	add_wait_queue(wait_queue, &wait);
	if (!READ_THREAD_WAKE_CONDITION(pebc)) {
		if (!signal_pending(current)) {
			wait_woken(&wait, TASK_INTERRUPTIBLE, timeout);
		}
	}
	remove_wait_queue(wait_queue, &wait);

	if (!is_ssdfs_requests_queue_empty(&pebc->read_rq)) {
		/* do requests processing */
		goto repeat;
	} else {
		if (should_ssdfs_segment_be_destroyed(pebc->parent_si)) {
			struct ssdfs_seg_object_info *soi = NULL;
			struct ssdfs_seg_objects_queue *rq = NULL;
			int thread_type = SSDFS_DESTROY_SEG_GC_THREAD;

			soi = ssdfs_seg_object_info_alloc();
			if (IS_ERR_OR_NULL(soi)) {
				SSDFS_ERR("fail to allocate seg object info\n");
				goto continue_normal_flow;
			}

			err = ssdfs_segment_tree_remove(fsi, pebc->parent_si);
			if (err) {
				ssdfs_seg_object_info_free(soi);
				goto continue_normal_flow;
			}

			atomic_set(&pebc->parent_si->obj_state,
					SSDFS_SEG_OBJECT_PRE_DELETED);

			rq = &fsi->pre_destroyed_segs_rq;
			ssdfs_seg_object_info_init(soi, pebc->parent_si);
			ssdfs_seg_objects_queue_add_tail(rq, soi);

#ifdef CONFIG_SSDFS_DEBUG
			SSDFS_DBG("ADD INTO QUEUE: pre-deleted segment %llu\n",
				  pebc->parent_si->seg_id);
#endif /* CONFIG_SSDFS_DEBUG */

			atomic_inc(&fsi->gc_should_act[thread_type]);
			wake_up_all(&fsi->gc_wait_queue[thread_type]);
			goto sleep_read_thread;
		}

continue_normal_flow:
		if (is_it_time_free_peb_cache_memory(pebc)) {
			err = ssdfs_peb_release_folios(pebc);
			if (err == -ENODATA) {
				err = 0;
				timeout = min_t(u64, timeout * 2,
						(u64)SSDFS_DEFAULT_TIMEOUT);
			} else if (unlikely(err)) {
				SSDFS_ERR("fail to release folios: "
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
	ssdfs_peb_release_folios(pebc);
	wait_event_interruptible(*wait_queue,
			READ_FAILED_THREAD_WAKE_CONDITION());
	goto repeat;
}
