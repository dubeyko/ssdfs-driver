/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb.c - Physical Erase Block (PEB) object's functionality.
 *
 * Copyright (c) 2014-2019 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 * Copyright (c) 2014-2026 Viacheslav Dubeyko <slava@dubeyko.com>
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
#include <crypto/hash.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "compression.h"
#include "block_bitmap.h"
#include "segment_bitmap.h"
#include "folio_array.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_peb_page_leaks;
atomic64_t ssdfs_peb_folio_leaks;
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
 * struct folio *ssdfs_peb_alloc_folio(gfp_t gfp_mask,
 *                                     unsigned int order)
 * struct folio *ssdfs_peb_add_batch_folio(struct folio_batch *batch,
 *                                         unsigned int order)
 * void ssdfs_peb_free_folio(struct folio *folio)
 * void ssdfs_peb_folio_batch_release(struct folio_batch *batch)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(peb)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(peb)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_peb_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_peb_folio_leaks, 0);
	atomic64_set(&ssdfs_peb_memory_leaks, 0);
	atomic64_set(&ssdfs_peb_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_peb_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_peb_folio_leaks) != 0) {
		SSDFS_ERR("PEB: "
			  "memory leaks include %lld folios\n",
			  atomic64_read(&ssdfs_peb_folio_leaks));
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
	struct ssdfs_peb_prev_log prev_log = {
		.bmap_bytes = U32_MAX,
		.blk2off_bytes = U32_MAX,
		.blk_desc_bytes = U32_MAX,
	};

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(pebi->peb_id == U64_MAX);

	SSDFS_DBG("pebi %p, peb_id %llu\n",
		  pebi, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_init(pebi, pebi->log_blocks, 0, 0, &prev_log);

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
	struct ssdfs_peb_prev_log prev_log = {
		.bmap_bytes = U32_MAX,
		.blk2off_bytes = U32_MAX,
		.blk_desc_bytes = U32_MAX,
	};

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(pebi->peb_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("pebi %p, peb_id %llu\n",
		  pebi, pebi->peb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_init(pebi, 0, fsi->pages_per_peb, 0, &prev_log);

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
	struct ssdfs_peb_prev_log prev_log = {
		.bmap_bytes = U32_MAX,
		.blk2off_bytes = U32_MAX,
		.blk_desc_bytes = U32_MAX,
	};

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

	ssdfs_peb_current_log_init(pebi, 0, fsi->pages_per_peb, 0, &prev_log);

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
	size_t bmap_folios;
	u32 pages_capacity;
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

	pebi->current_log.start_block = U32_MAX;
	pebi->current_log.reserved_blocks = 0;
	pebi->current_log.free_data_blocks = pebi->log_blocks;
	pebi->current_log.seg_flags = 0;
	pebi->current_log.prev_log.bmap_bytes = U32_MAX;
	pebi->current_log.prev_log.blk2off_bytes = U32_MAX;
	pebi->current_log.prev_log.blk_desc_bytes = U32_MAX;
	pebi->current_log.last_log_time = U64_MAX;
	pebi->current_log.last_log_cno = U64_MAX;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("free_data_blocks %u\n",
		  pebi->current_log.free_data_blocks);
#endif /* CONFIG_SSDFS_DEBUG */

	bmap_bytes = BLK_BMAP_BYTES(fsi->pages_per_peb);
	bmap_folios = (bmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	err = ssdfs_folio_vector_create(&pebi->current_log.bmap_snapshot,
					get_order(PAGE_SIZE),
					bmap_folios);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create folio vector: "
			  "bmap_folios %zu, err %d\n",
			  bmap_folios, err);
		return err;
	}

	memset(&pebi->current_log.blk2off_tbl.hdr, 0xFF,
		sizeof(struct ssdfs_blk2off_table_header));
	pebi->current_log.blk2off_tbl.reserved_offset = U32_MAX;
	pebi->current_log.blk2off_tbl.compressed_offset = 0;
	pebi->current_log.blk2off_tbl.sequence_id = 0;

	pages_capacity = fsi->pagesize >> PAGE_SHIFT;
	pages_capacity *= fsi->pages_per_peb;

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
			area->frag_offset = blk_table_size;
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
			area->frag_offset = 0;
			area->metadata.reserved_offset = 0;
			break;

		default:
			BUG();
		};

		err = ssdfs_create_folio_array(&area->array,
					       get_order(PAGE_SIZE),
					       pages_capacity);
		if (unlikely(err)) {
			SSDFS_ERR("fail to create page array: "
				  "capacity %u, err %d\n",
				  pages_capacity, err);
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

		ssdfs_destroy_folio_array(&area->array);
	}

	ssdfs_folio_vector_destroy(&pebi->current_log.bmap_snapshot);

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
		struct ssdfs_folio_array *area_folios;

		area_folios = &pebi->current_log.area[i].array;

		if (atomic_read(&area_folios->state) == SSDFS_FOLIO_ARRAY_DIRTY) {
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

		ssdfs_destroy_folio_array(area_folios);
	}

	ssdfs_folio_vector_release(&pebi->current_log.bmap_snapshot);
	ssdfs_folio_vector_destroy(&pebi->current_log.bmap_snapshot);

	atomic_set(&pebi->current_log.state, SSDFS_LOG_UNKNOWN);
	ssdfs_peb_current_log_unlock(pebi);

	return err;
}

/*
 * ssdfs_peb_current_log_init() - initialize current log object
 * @pebi: pointer on PEB object
 * @free_blocks: free blocks in the current log
 * @start_block: start block of the current log
 * @sequence_id: index of partial log in the sequence
 * @prev_log: previous log's details
 */
void ssdfs_peb_current_log_init(struct ssdfs_peb_info *pebi,
				u32 free_blocks,
				u32 start_block,
				int sequence_id,
				struct ssdfs_peb_prev_log *prev_log)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !prev_log);

	SSDFS_DBG("peb_id %llu, "
		  "pebi->current_log.start_block %u, "
		  "free_blocks %u, sequence_id %d, "
		  "prev_log (bmap_bytes %u, blk2off_bytes %u, "
		  "blk_desc_bytes %u)\n",
		  pebi->peb_id, start_block, free_blocks,
		  sequence_id, prev_log->bmap_bytes,
		  prev_log->blk2off_bytes,
		  prev_log->blk_desc_bytes);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_peb_current_log_lock(pebi);
	pebi->current_log.start_block = start_block;
	pebi->current_log.free_data_blocks = free_blocks;
	pebi->current_log.prev_log.bmap_bytes = prev_log->bmap_bytes;
	pebi->current_log.prev_log.blk2off_bytes = prev_log->blk2off_bytes;
	pebi->current_log.prev_log.blk_desc_bytes = prev_log->blk_desc_bytes;
	atomic_set(&pebi->current_log.sequence_id, sequence_id);
	atomic_set(&pebi->current_log.state, SSDFS_LOG_INITIALIZED);
	ssdfs_peb_current_log_unlock(pebi);
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
	u32 pages_capacity;
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
	pebi->log_blocks = pebc->log_blocks;
	pebi->peb_create_time = ssdfs_current_timestamp();
	ssdfs_set_peb_migration_id(pebi, peb_migration_id);
	init_completion(&pebi->init_end);
	atomic_set(&pebi->peb_state, peb_state);
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

#ifdef CONFIG_SSDFS_PEB_DEDUPLICATION
	pebi->dedup.shash_tfm =
		crypto_alloc_shash(SSDFS_DEFAULT_FINGERPRINT_NAME(), 0, 0);
	if (IS_ERR(pebi->dedup.shash_tfm)) {
		err = PTR_ERR(pebi->dedup.shash_tfm);
		pebi->dedup.shash_tfm = NULL;
		SSDFS_ERR("fail to allocate message digest handle: "
			  "err %d\n", err);
		goto fail_conctruct_peb_obj;
	}

	err = ssdfs_fingerprint_array_create(&pebi->dedup.fingerprints,
					     fsi->pages_per_seg);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create fingeprints array: "
			  "capacity %u, err %d\n",
			  fsi->pages_per_seg, err);
		goto fail_conctruct_peb_obj;
	}
#endif /* CONFIG_SSDFS_PEB_DEDUPLICATION */

	init_rwsem(&pebi->read_buffer.lock);
	if (flags & SSDFS_BLK2OFF_TBL_MAKE_COMPRESSION) {
		pebi->read_buffer.blk_desc.ptr = ssdfs_peb_kzalloc(buf_size,
								  GFP_KERNEL);
		if (!pebi->read_buffer.blk_desc.ptr) {
			err = -ENOMEM;
			SSDFS_ERR("unable to allocate\n");
			goto fail_conctruct_peb_obj;
		}

		pebi->read_buffer.blk_desc.buf_size = buf_size;

		memset(&pebi->read_buffer.blk_desc.frag_desc,
			0xFF, sizeof(struct ssdfs_compressed_fragment));
	} else {
		pebi->read_buffer.blk_desc.ptr = NULL;
		pebi->read_buffer.blk_desc.buf_size = 0;

		memset(&pebi->read_buffer.blk_desc.frag_desc,
			0xFF, sizeof(struct ssdfs_compressed_fragment));
	}

	pebi->pebc = pebc;
	pages_capacity = fsi->pagesize >> PAGE_SHIFT;
	pages_capacity *= fsi->pages_per_peb;

	err = ssdfs_create_folio_array(&pebi->cache,
				       get_order(PAGE_SIZE),
				       pages_capacity);
	if (unlikely(err)) {
		SSDFS_ERR("fail to create page array: "
			  "capacity %u, err %d\n",
			  pages_capacity, err);
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
	case SSDFS_MAPTBL_MIGRATION_SRC_USING_STATE:
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
#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
	struct ssdfs_segment_info *si;
	struct ssdfs_blk2off_table *blk2off_table;
	struct ssdfs_sequence_array *sequence;
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */
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

#ifdef CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG
	state = atomic_read(&pebi->state);
	if (state >= SSDFS_PEB_OBJECT_CREATED) {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!pebi->pebc || !pebi->pebc->parent_si);
		BUG_ON(!pebi->pebc->parent_si->blk2off_table);
#endif /* CONFIG_SSDFS_DEBUG */

		si = pebi->pebc->parent_si;
		blk2off_table = si->blk2off_table;
		sequence = blk2off_table->peb[pebi->peb_index].sequence;

		err = ssdfs_sequence_array_pre_delete_all(sequence,
					ssdfs_blk2off_table_pre_delete_fragment,
					pebi->peb_id);
		if (unlikely(err)) {
			SSDFS_ERR("fail to pre-delete blk2off table fragments: "
				  "peb_id %llu, err %d\n",
				  pebi->peb_id, err);
		}
	}
#endif /* CONFIG_SSDFS_SAVE_WHOLE_BLK2OFF_TBL_IN_EVERY_LOG */

	err = ssdfs_peb_current_log_destroy(pebi);

	down_write(&pebi->read_buffer.lock);
	if (pebi->read_buffer.blk_desc.ptr) {
		ssdfs_peb_kfree(pebi->read_buffer.blk_desc.ptr);
		pebi->read_buffer.blk_desc.ptr = NULL;
		pebi->read_buffer.blk_desc.buf_size = 0;

		memset(&pebi->read_buffer.blk_desc.frag_desc,
			0xFF, sizeof(struct ssdfs_compressed_fragment));

	}
	up_write(&pebi->read_buffer.lock);

	state = atomic_read(&pebi->cache.state);
	if (state == SSDFS_FOLIO_ARRAY_DIRTY) {
		ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"PEB %llu is dirty on destruction\n",
				pebi->peb_id);
		err = -EIO;
	}

	ssdfs_destroy_folio_array(&pebi->cache);

#ifdef CONFIG_SSDFS_PEB_DEDUPLICATION
	if (pebi->dedup.shash_tfm)
		crypto_free_shash(pebi->dedup.shash_tfm);

	ssdfs_fingerprint_array_destroy(&pebi->dedup.fingerprints);
#endif /* CONFIG_SSDFS_PEB_DEDUPLICATION */

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("finished: err %d\n", err);
#else
	SSDFS_DBG("finished: err %d\n", err);
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	return err;
}

/*
 * ssdfs_get_leb_id_for_peb_index() - convert PEB's index into LEB's ID
 * @fsi: pointer on shared file system object
 * @seg: segment number
 * @peb_index: index of PEB object in array
 *
 * This function converts PEB's index into LEB's identification
 * number.
 *
 * RETURN:
 * [success] - LEB's identification number.
 * [failure] - U64_MAX.
 */
u64 ssdfs_get_leb_id_for_peb_index(struct ssdfs_fs_info *fsi,
				   u64 seg, u32 peb_index)
{
	u64 leb_id = U64_MAX;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	if (peb_index >= fsi->pebs_per_seg) {
		SSDFS_ERR("requested peb_index %u >= pebs_per_seg %u\n",
			  peb_index, fsi->pebs_per_seg);
		return U64_MAX;
	}

	SSDFS_DBG("fsi %p, seg %llu, peb_index %u\n",
		  fsi, seg, peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fsi->lebs_per_peb_index == SSDFS_LEBS_PER_PEB_INDEX_DEFAULT)
		leb_id = (seg * fsi->pebs_per_seg) + peb_index;
	else
		leb_id = seg + (peb_index * fsi->lebs_per_peb_index);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("seg %llu, peb_index %u, leb_id %llu\n",
		  seg, peb_index, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	return leb_id;
}

/*
 * ssdfs_get_seg_id_for_leb_id() - convert LEB's into segment's ID
 * @fsi: pointer on shared file system object
 * @leb_id: LEB ID
 *
 * This function converts LEB's ID into segment's identification
 * number.
 *
 * RETURN:
 * [success] - LEB's identification number.
 * [failure] - U64_MAX.
 */
u64 ssdfs_get_seg_id_for_leb_id(struct ssdfs_fs_info *fsi,
				u64 leb_id)
{
	u64 seg_id = U64_MAX;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p, leb_id %llu\n",
		  fsi, leb_id);
#endif /* CONFIG_SSDFS_DEBUG */

	if (fsi->lebs_per_peb_index == SSDFS_LEBS_PER_PEB_INDEX_DEFAULT)
		seg_id = div_u64(leb_id, fsi->pebs_per_seg);
	else
		seg_id = div_u64(leb_id, fsi->lebs_per_peb_index);

	return seg_id;
}

/*
 * ssdfs_get_peb_migration_id() - get PEB's migration ID
 * @pebi: pointer on PEB object
 */
int ssdfs_get_peb_migration_id(struct ssdfs_peb_info *pebi)
{
	int id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
#endif /* CONFIG_SSDFS_DEBUG */

	id = atomic_read(&pebi->peb_migration_id);

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(id >= U8_MAX);
	BUG_ON(id < 0);
#endif /* CONFIG_SSDFS_DEBUG */

	return id;
}

/*
 * is_peb_migration_id_valid() - check PEB's migration_id
 * @peb_migration_id: PEB's migration ID value
 */
bool is_peb_migration_id_valid(int peb_migration_id)
{
	if (peb_migration_id < 0 ||
	    peb_migration_id > SSDFS_PEB_MIGRATION_ID_MAX) {
		/* preliminary check */
		return false;
	}

	switch (peb_migration_id) {
	case SSDFS_PEB_MIGRATION_ID_MAX:
	case SSDFS_PEB_UNKNOWN_MIGRATION_ID:
		return false;
	}

	return true;
}

/*
 * ssdfs_get_peb_migration_id_checked() - get checked PEB's migration ID
 * @pebi: pointer on PEB object
 */
int ssdfs_get_peb_migration_id_checked(struct ssdfs_peb_info *pebi)
{
	int res, err;

	switch (atomic_read(&pebi->state)) {
	case SSDFS_PEB_OBJECT_CREATED:
		err = SSDFS_WAIT_COMPLETION(&pebi->init_end);
		if (unlikely(err)) {
			SSDFS_ERR("PEB init failed: "
				  "err %d\n", err);
			return err;
		}

		if (atomic_read(&pebi->state) != SSDFS_PEB_OBJECT_INITIALIZED) {
			SSDFS_ERR("PEB %llu is not initialized\n",
				  pebi->peb_id);
			return -ERANGE;
		}
		break;

	case SSDFS_PEB_OBJECT_INITIALIZED:
		/* expected state */
		break;

	default:
		SSDFS_ERR("invalid PEB state %#x\n",
			  atomic_read(&pebi->state));
		return -ERANGE;
	}

	res = ssdfs_get_peb_migration_id(pebi);

	if (!is_peb_migration_id_valid(res)) {
		res = -ERANGE;
		SSDFS_WARN("invalid peb_migration_id: "
			   "peb %llu, peb_index %u, id %d\n",
			   pebi->peb_id, pebi->peb_index, res);
	}

	return res;
}

/*
 * ssdfs_set_peb_migration_id() - set PEB's migration ID
 * @pebi: pointer on PEB object
 * @id: new PEB's migration_id
 */
void ssdfs_set_peb_migration_id(struct ssdfs_peb_info *pebi,
				int id)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);

	SSDFS_DBG("peb_id %llu, peb_migration_id %d\n",
		  pebi->peb_id, id);
#endif /* CONFIG_SSDFS_DEBUG */

	atomic_set(&pebi->peb_migration_id, id);
}

int __ssdfs_define_next_peb_migration_id(int prev_id)
{
	int id = prev_id;

	if (id < 0)
		return SSDFS_PEB_MIGRATION_ID_START;

	id += 1;

	if (id >= SSDFS_PEB_MIGRATION_ID_MAX)
		id = SSDFS_PEB_MIGRATION_ID_START;

	return id;
}

/*
 * ssdfs_define_next_peb_migration_id() - define next PEB's migration_id
 * @pebi: pointer on source PEB object
 */
int ssdfs_define_next_peb_migration_id(struct ssdfs_peb_info *src_peb)
{
	int id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!src_peb);

	SSDFS_DBG("peb %llu, peb_index %u\n",
		  src_peb->peb_id, src_peb->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	id = ssdfs_get_peb_migration_id_checked(src_peb);
	if (id < 0) {
		SSDFS_ERR("fail to get peb_migration_id: "
			  "peb %llu, peb_index %u, err %d\n",
			  src_peb->peb_id, src_peb->peb_index,
			  id);
		return SSDFS_PEB_MIGRATION_ID_MAX;
	}

	return __ssdfs_define_next_peb_migration_id(id);
}

/*
 * ssdfs_define_prev_peb_migration_id() - define prev PEB's migration_id
 * @pebi: pointer on source PEB object
 */
int ssdfs_define_prev_peb_migration_id(struct ssdfs_peb_info *pebi)
{
	int id;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);

	SSDFS_DBG("peb %llu, peb_index %u\n",
		  pebi->peb_id, pebi->peb_index);
#endif /* CONFIG_SSDFS_DEBUG */

	id = ssdfs_get_peb_migration_id_checked(pebi);
	if (id < 0) {
		SSDFS_ERR("fail to get peb_migration_id: "
			  "peb %llu, peb_index %u, err %d\n",
			  pebi->peb_id, pebi->peb_index,
			  id);
		return SSDFS_PEB_MIGRATION_ID_MAX;
	}

	id--;

	if (id == SSDFS_PEB_UNKNOWN_MIGRATION_ID)
		id = SSDFS_PEB_MIGRATION_ID_MAX - 1;

	return id;
}
