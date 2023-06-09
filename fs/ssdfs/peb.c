// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb.c - Physical Erase Block (PEB) object's functionality.
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

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "page_vector.h"
#include "ssdfs.h"
#include "compression.h"
#include "page_vector.h"
#include "block_bitmap.h"
#include "segment_bitmap.h"
#include "page_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_peb_page_leaks;
atomic64_t ssdfs_peb_memory_leaks;
atomic64_t ssdfs_peb_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_peb_cache_leaks_increment(void *kaddr)
 * void ssdfs_peb_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_peb_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_peb_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_peb_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_peb_kfree(void *kaddr)
 * struct page *ssdfs_peb_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_peb_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_peb_free_page(struct page *page)
 * void ssdfs_peb_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(peb)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(peb)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_peb_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_peb_page_leaks, 0);
	atomic64_set(&ssdfs_peb_memory_leaks, 0);
	atomic64_set(&ssdfs_peb_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_peb_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_peb_page_leaks) != 0) {
		SSDFS_ERR("PEB: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_peb_page_leaks));
	}

	if (atomic64_read(&ssdfs_peb_memory_leaks) != 0) {
		SSDFS_ERR("PEB: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_peb_memory_leaks));
	}

	if (atomic64_read(&ssdfs_peb_cache_leaks) != 0) {
		SSDFS_ERR("PEB: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_peb_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

/*
 * ssdfs_create_clean_peb_object() - create "clean" PEB object
 * @pebi: pointer on unitialized PEB object
 *
 * This function tries to initialize PEB object for "clean"
 * state of the segment.
 *
 * RETURN:
 * [success] - PEB object has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_create_clean_peb_object(struct ssdfs_peb_info *pebi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(pebi->peb_id == U64_MAX);

	SSDFS_DBG("pebi %p, peb_id %llu\n",
		  pebi, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_init(pebi, pebi->log_pages, 0, 0, U32_MAX);

	return 0;
}

/*
 * ssdfs_create_using_peb_object() - create "using" PEB object
 * @pebi: pointer on unitialized PEB object
 *
 * This function tries to initialize PEB object for "using"
 * state of the segment.
 *
 * RETURN:
 * [success] - PEB object has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_create_using_peb_object(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_fs_info *fsi;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(pebi->peb_id == U64_MAX);

	SSDFS_DBG("pebi %p, peb_id %llu\n",
		  pebi, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	if (fsi->is_zns_device) {
		loff_t offset = pebi->peb_id * fsi->erasesize;

		err = fsi->devops->reopen_zone(fsi->sb, offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to reopen zone: "
				  "offset %llu, err %d\n",
				  offset, err);
			return err;
		}
	}

	return 0;
}

/*
 * ssdfs_create_used_peb_object() - create "used" PEB object
 * @pebi: pointer on unitialized PEB object
 *
 * This function tries to initialize PEB object for "used"
 * state of the segment.
 *
 * RETURN:
 * [success] - PEB object has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 * %-ENOMEM     - unable to allocate memory.
 */
static
int ssdfs_create_used_peb_object(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_fs_info *fsi;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(pebi->peb_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebi %p, peb_id %llu\n",
		  pebi, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_init(pebi, 0, fsi->pages_per_peb, 0, U32_MAX);

	return 0;
}

/*
 * ssdfs_create_dirty_peb_object() - create "dirty" PEB object
 * @pebi: pointer on unitialized PEB object
 *
 * This function tries to initialize PEB object for "dirty"
 * state of the PEB.
 *
 * RETURN:
 * [success] - PEB object has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
static
int ssdfs_create_dirty_peb_object(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_fs_info *fsi;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
	BUG_ON(pebi->peb_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebi %p, peb_id %llu\n",
		  pebi, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_init(pebi, 0, fsi->pages_per_peb, 0, U32_MAX);

	return 0;
}

static inline
size_t ssdfs_peb_temp_buffer_default_size(u32 pagesize)
{
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	size_t size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(pagesize > SSDFS_128KB);
#endif /* CONFIG_SSDFS_DEBUG */

	size = (SSDFS_128KB / pagesize) * blk_desc_size;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page_size %u, default_size %zu\n",
		  pagesize, size);
#endif /* CONFIG_SSDFS_DEBUG */

	return size;
}

/*
 * ssdfs_peb_realloc_read_buffer() - realloc temporary read buffer
 * @buf: pointer on read buffer
 */
int ssdfs_peb_realloc_read_buffer(struct ssdfs_peb_read_buffer *buf,
				  size_t new_size)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (buf->buf_size >= PAGE_SIZE) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to realloc buffer: "
			  "old_size %zu\n",
			  buf->buf_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return -E2BIG;
	}

	if (buf->buf_size == new_size) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("do nothing: old_size %zu, new_size %zu\n",
			  buf->buf_size, new_size);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;
	}

	if (buf->buf_size > new_size) {
		SSDFS_ERR("shrink not supported\n");
		return -EOPNOTSUPP;
	}

	buf->ptr = krealloc(buf->ptr, new_size, GFP_KERNEL);
	if (!buf->ptr) {
		SSDFS_ERR("fail to allocate buffer\n");
		return -ENOMEM;
	}

	buf->buf_size = new_size;

	return 0;
}

/*
 * ssdfs_peb_realloc_write_buffer() - realloc temporary write buffer
 * @buf: pointer on write buffer
 */
int ssdfs_peb_realloc_write_buffer(struct ssdfs_peb_temp_buffer *buf)
{
	size_t new_size;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!buf);
#endif /* CONFIG_SSDFS_DEBUG */

	if (buf->size >= PAGE_SIZE) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("unable to realloc buffer: "
			  "old_size %zu\n",
			  buf->size);
#endif /* CONFIG_SSDFS_DEBUG */
		return -E2BIG;
	}

	new_size = min_t(size_t, buf->size * 2, (size_t)PAGE_SIZE);

	buf->ptr = krealloc(buf->ptr, new_size, GFP_KERNEL);
	if (!buf->ptr) {
		SSDFS_ERR("fail to allocate buffer\n");
		return -ENOMEM;
	}

	buf->size = new_size;

	return 0;
}

/*
 * ssdfs_peb_current_log_prepare() - prepare current log object
 * @pebi: pointer on PEB object
 */
static inline
int ssdfs_peb_current_log_prepare(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_fs_info *fsi;
	struct ssdfs_peb_area *area;
	struct ssdfs_peb_temp_buffer *write_buf;
	size_t blk_desc_size = sizeof(struct ssdfs_block_descriptor);
	size_t buf_size;
	u16 flags;
	size_t bmap_bytes;
	size_t bmap_pages;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;
	flags = fsi->metadata_options.blk2off_tbl.flags;
	buf_size = ssdfs_peb_temp_buffer_default_size(fsi->pagesize);

	mutex_init(&pebi->current_log.lock);
	atomic_set(&pebi->current_log.sequence_id, 0);

	pebi->current_log.start_page = U32_MAX;
	pebi->current_log.reserved_pages = 0;
	pebi->current_log.free_data_pages = pebi->log_pages;
	pebi->current_log.seg_flags = 0;
	pebi->current_log.prev_log_bmap_bytes = U32_MAX;
	pebi->current_log.last_log_time = U64_MAX;
	pebi->current_log.last_log_cno = U64_MAX;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_data_pages %u\n",
		  pebi->current_log.free_data_pages);
#endif /* CONFIG_SSDFS_DEBUG */

	bmap_bytes = BLK_BMAP_BYTES(fsi->pages_per_peb);
	bmap_pages = (bmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	err = ssdfs_page_vector_create(&pebi->current_log.bmap_snapshot,
					bmap_pages);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create page vector: "
			  "bmap_pages %zu, err %d\n",
			  bmap_pages, err);
		return err;
	}

	memset(&pebi->current_log.blk2off_tbl.hdr, 0xFF,
		sizeof(struct ssdfs_blk2off_table_header));
	pebi->current_log.blk2off_tbl.reserved_offset = U32_MAX;
	pebi->current_log.blk2off_tbl.compressed_offset = 0;
	pebi->current_log.blk2off_tbl.sequence_id = 0;

	for (i = 0; i < SSDFS_LOG_AREA_MAX; i++) {
		struct ssdfs_peb_area_metadata *metadata;
		size_t metadata_size = sizeof(struct ssdfs_peb_area_metadata);
		size_t blk_table_size = sizeof(struct ssdfs_area_block_table);

		area = &pebi->current_log.area[i];
		metadata = &area->metadata;
		memset(&area->metadata, 0, metadata_size);

		switch (i) {
		case SSDFS_LOG_BLK_DESC_AREA:
			write_buf = &area->metadata.area.blk_desc.flush_buf;

			area->has_metadata = true;
			area->write_offset = blk_table_size;
			area->compressed_offset = blk_table_size;
			area->metadata.reserved_offset = blk_table_size;

			if (flags & SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION) {
				write_buf->ptr = ssdfs_peb_kzalloc(buf_size,
								   GFP_KERNEL);
				if (!write_buf->ptr) {
					err = -ENOMEM;
					SSDFS_ERR("unable to allocate\n");
					goto fail_init_current_log;
				}

				write_buf->write_offset = 0;
				write_buf->granularity = blk_desc_size;
				write_buf->size = buf_size;
			} else {
				write_buf->ptr = NULL;
				write_buf->write_offset = 0;
				write_buf->granularity = 0;
				write_buf->size = 0;
			}
			break;

		case SSDFS_LOG_MAIN_AREA:
		case SSDFS_LOG_DIFFS_AREA:
		case SSDFS_LOG_JOURNAL_AREA:
			area->has_metadata = false;
			area->write_offset = 0;
			area->compressed_offset = 0;
			area->metadata.reserved_offset = 0;
			break;

		default:
			BUG();
		};

		err = ssdfs_create_page_array(fsi->pages_per_peb,
					      &area->array);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create page array: "
				  "capacity %u, err %d\n",
				  fsi->pages_per_peb, err);
			goto fail_init_current_log;
		}
	}

	atomic_set(&pebi->current_log.state, SSDFS_LOG_PREPARED);
	return 0;

fail_init_current_log:
	for (--i; i >= 0; i--) {
		area = &pebi->current_log.area[i];

		if (i == SSDFS_LOG_BLK_DESC_AREA) {
			write_buf = &area->metadata.area.blk_desc.flush_buf;

			area->metadata.area.blk_desc.capacity = 0;
			area->metadata.area.blk_desc.items_count = 0;

			if (write_buf->ptr) {
				ssdfs_peb_kfree(write_buf->ptr);
				write_buf->ptr = NULL;
			}
		}

		ssdfs_destroy_page_array(&area->array);
	}

	ssdfs_page_vector_destroy(&pebi->current_log.bmap_snapshot);

	return err;
}

/*
 * ssdfs_peb_current_log_destroy() - destroy current log object
 * @pebi: pointer on PEB object
 */
static inline
int ssdfs_peb_current_log_destroy(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_peb_temp_buffer *write_buf;
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(mutex_is_locked(&pebi->current_log.lock));

	SSDFS_DBG("pebi %p\n", pebi);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_lock(pebi);

	for (i = 0; i < SSDFS_LOG_AREA_MAX; i++) {
		struct ssdfs_page_array *area_pages;

		area_pages = &pebi->current_log.area[i].array;

		if (atomic_read(&area_pages->state) == SSDFS_PAGE_ARRAY_DIRTY) {
			ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
					__FILE__, __func__, __LINE__,
					"PEB %llu is dirty on destruction\n",
					pebi->peb_id);
			err = -EIO;
		}

		if (i == SSDFS_LOG_BLK_DESC_AREA) {
			struct ssdfs_peb_area *area;

			area = &pebi->current_log.area[i];
			area->metadata.area.blk_desc.capacity = 0;
			area->metadata.area.blk_desc.items_count = 0;

			write_buf = &area->metadata.area.blk_desc.flush_buf;

			if (write_buf->ptr) {
				ssdfs_peb_kfree(write_buf->ptr);
				write_buf->ptr = NULL;
				write_buf->write_offset = 0;
				write_buf->size = 0;
			}
		}

		ssdfs_destroy_page_array(area_pages);
	}

	ssdfs_page_vector_release(&pebi->current_log.bmap_snapshot);
	ssdfs_page_vector_destroy(&pebi->current_log.bmap_snapshot);

	atomic_set(&pebi->current_log.state, SSDFS_LOG_UNKNOWN);
	ssdfs_peb_current_log_unlock(pebi);

	return err;
}

/*
 * ssdfs_peb_object_create() - create PEB object in array
 * @pebi: pointer on PEB object
 * @pebc: pointer on PEB container
 * @peb_id: PEB identification number
 * @peb_state: PEB's state
 * @peb_migration_id: PEB's migration ID
 *
 * This function tries to create PEB object for
 * @peb_index in array.
 *
 * RETURN:
 * [success] - PEB object has been constructed sucessfully.
 * [failure] - error code:
 *
 * %-EINVAL     - invalid input.
 */
int ssdfs_peb_object_create(struct ssdfs_peb_info *pebi,
			    struct ssdfs_peb_container *pebc,
			    u64 peb_id, int peb_state,
			    u8 peb_migration_id)
{
	struct ssdfs_fs_info *fsi;
	int peb_type;
	size_t buf_size;
	u16 flags;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebc || !pebc->parent_si);

	if ((peb_id * pebc->parent_si->fsi->pebs_per_seg) >=
	    pebc->parent_si->fsi->nsegs) {
		SSDFS_ERR("requested peb_id %llu >= nsegs %llu\n",
			  peb_id, pebc->parent_si->fsi->nsegs);
		return -EINVAL;
	}

	if (pebc->peb_index >= pebc->parent_si->pebs_count) {
		SSDFS_ERR("requested peb_index %u >= pebs_count %u\n",
			  pebc->peb_index,
			  pebc->parent_si->pebs_count);
		return -EINVAL;
	}
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("pebi %p, seg %llu, peb_id %llu, "
		  "peb_index %u, pebc %p, "
		  "peb_state %#x, peb_migration_id %u\n",
		  pebi, pebc->parent_si->seg_id,
		  pebi->peb_id, pebc->peb_index, pebc,
		  peb_state, peb_migration_id);
#else
	SSDFS_DBG("pebi %p, seg %llu, peb_id %llu, "
		  "peb_index %u, pebc %p, "
		  "peb_state %#x, peb_migration_id %u\n",
		  pebi, pebc->parent_si->seg_id,
		  pebi->peb_id, pebc->peb_index, pebc,
		  peb_state, peb_migration_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = pebc->parent_si->fsi;
	flags = fsi->metadata_options.blk2off_tbl.flags;
	buf_size = ssdfs_peb_temp_buffer_default_size(fsi->pagesize);

	atomic_set(&pebi->state, SSDFS_PEB_OBJECT_UNKNOWN_STATE);

	peb_type = SEG2PEB_TYPE(pebc->parent_si->seg_type);
	if (peb_type >= SSDFS_MAPTBL_PEB_TYPE_MAX) {
		err = -EINVAL;
		SSDFS_ERR("invalid seg_type %#x\n",
			  pebc->parent_si->seg_type);
		goto fail_conctruct_peb_obj;
	}

	pebi->peb_id = peb_id;
	pebi->peb_index = pebc->peb_index;
	pebi->log_pages = pebc->log_pages;
	pebi->peb_create_time = ssdfs_current_timestamp();
	ssdfs_set_peb_migration_id(pebi, peb_migration_id);
	init_completion(&pebi->init_end);
	atomic_set(&pebi->reserved_bytes.blk_bmap, 0);
	atomic_set(&pebi->reserved_bytes.blk2off_tbl, 0);
	atomic_set(&pebi->reserved_bytes.blk_desc_tbl, 0);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb_id %llu, "
		  "peb_create_time %llx\n",
		  pebc->parent_si->seg_id,
		  pebi->peb_id,
		  pebi->peb_create_time);
#endif /* CONFIG_SSDFS_DEBUG */

	init_rwsem(&pebi->read_buffer.lock);
	if (flags & SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION) {
		pebi->read_buffer.blk_desc.ptr = ssdfs_peb_kzalloc(buf_size,
								  GFP_KERNEL);
		if (!pebi->read_buffer.blk_desc.ptr) {
			err = -ENOMEM;
			SSDFS_ERR("unable to allocate\n");
			goto fail_conctruct_peb_obj;
		}

		pebi->read_buffer.blk_desc.offset = U32_MAX;
		pebi->read_buffer.blk_desc.fragment_size = 0;
		pebi->read_buffer.blk_desc.buf_size = buf_size;
	} else {
		pebi->read_buffer.blk_desc.ptr = NULL;
		pebi->read_buffer.blk_desc.offset = U32_MAX;
		pebi->read_buffer.blk_desc.fragment_size = 0;
		pebi->read_buffer.blk_desc.buf_size = 0;
	}

	pebi->pebc = pebc;

	err = ssdfs_create_page_array(fsi->pages_per_peb,
				      &pebi->cache);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create page array: "
			  "capacity %u, err %d\n",
			  fsi->pages_per_peb, err);
		goto fail_conctruct_peb_obj;
	}

	err = ssdfs_peb_current_log_prepare(pebi);
	if (unlikely(err)) {
		SSDFS_ERR("fail to prepare current log: err %d\n",
			  err);
		goto fail_conctruct_peb_obj;
	}

	switch (peb_state) {
	case SSDFS_MAPTBL_CLEAN_PEB_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_CLEAN_STATE:
		err = ssdfs_create_clean_peb_object(pebi);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create clean PEB object: err %d\n",
				  err);
			goto fail_conctruct_peb_obj;
		}
		break;

	case SSDFS_MAPTBL_USING_PEB_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USING_STATE:
		err = ssdfs_create_using_peb_object(pebi);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create using PEB object: err %d\n",
				  err);
			goto fail_conctruct_peb_obj;
		}
		break;

	case SSDFS_MAPTBL_USED_PEB_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_USED_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_USED_STATE:
	case SSDFS_MAPTBL_PRE_DIRTY_PEB_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_PRE_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_PRE_DIRTY_STATE:
		err = ssdfs_create_used_peb_object(pebi);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create used PEB object: err %d\n",
				  err);
			goto fail_conctruct_peb_obj;
		}
		break;

	case SSDFS_MAPTBL_DIRTY_PEB_STATE:
	case SSDFS_MAPTBL_MIGRATION_SRC_DIRTY_STATE:
	case SSDFS_MAPTBL_MIGRATION_DST_DIRTY_STATE:
		err = ssdfs_create_dirty_peb_object(pebi);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create dirty PEB object: err %d\n",
				  err);
			goto fail_conctruct_peb_obj;
		}
		break;

	default:
		SSDFS_ERR("invalid PEB state\n");
		err = -EINVAL;
		goto fail_conctruct_peb_obj;
	};

	atomic_set(&pebi->state, SSDFS_PEB_OBJECT_CREATED);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished\n");
#else
	SSDFS_DBG("finished\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return 0;

fail_conctruct_peb_obj:
	ssdfs_peb_object_destroy(pebi);
	pebi->peb_id = U64_MAX;
	pebi->pebc = pebc;
	return err;
}

/*
 * ssdfs_peb_object_destroy() - destroy PEB object in array
 * @pebi: pointer on PEB object
 *
 * This function tries to destroy PEB object.
 *
 * RETURN:
 * [success] - PEB object has been destroyed sucessfully.
 * [failure] - error code:
 *
 * %-EIO     - I/O errors were detected.
 */
int ssdfs_peb_object_destroy(struct ssdfs_peb_info *pebi)
{
	struct ssdfs_fs_info *fsi;
	int state;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
#endif /* CONFIG_SSDFS_DEBUG */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("peb_id %llu\n", pebi->peb_id);
#else
	SSDFS_DBG("peb_id %llu\n", pebi->peb_id);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	fsi = pebi->pebc->parent_si->fsi;

	if (pebi->peb_id >= (fsi->nsegs * fsi->pebs_per_seg)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("invalid PEB id %llu\n", pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EINVAL;
	}

	err = ssdfs_peb_current_log_destroy(pebi);

	down_write(&pebi->read_buffer.lock);
	if (pebi->read_buffer.blk_desc.ptr) {
		ssdfs_peb_kfree(pebi->read_buffer.blk_desc.ptr);
		pebi->read_buffer.blk_desc.ptr = NULL;
		pebi->read_buffer.blk_desc.offset = U32_MAX;
		pebi->read_buffer.blk_desc.fragment_size = 0;
		pebi->read_buffer.blk_desc.buf_size = 0;
	}
	up_write(&pebi->read_buffer.lock);

	state = atomic_read(&pebi->cache.state);
	if (state == SSDFS_PAGE_ARRAY_DIRTY) {
		ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"PEB %llu is dirty on destruction\n",
				pebi->peb_id);
		err = -EIO;
	}

	ssdfs_destroy_page_array(&pebi->cache);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}
