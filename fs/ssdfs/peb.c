//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb.c - Physical Erase Block (PEB) object's functionality.
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

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "compression.h"
#include "block_bitmap.h"
#include "segment_bitmap.h"
#include "page_array.h"
#include "peb.h"
#include "peb_container.h"
#include "segment.h"
#include "peb_mapping_table.h"

#include <trace/events/ssdfs.h>

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
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("pebi %p, peb_id %llu\n",
		  pebi, pebi->peb_id);

	ssdfs_peb_current_log_init(pebi, pebi->log_pages, 0, 0);

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
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc);
	BUG_ON(pebi->peb_id == U64_MAX);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("pebi %p, peb_id %llu\n",
		  pebi, pebi->peb_id);

	/* Do nothing temporary */

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

	SSDFS_DBG("pebi %p, peb_id %llu\n",
		  pebi, pebi->peb_id);

	ssdfs_peb_current_log_init(pebi, 0, fsi->pages_per_peb, 0);

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

	SSDFS_DBG("pebi %p, peb_id %llu\n",
		  pebi, pebi->peb_id);

	ssdfs_peb_current_log_init(pebi, 0, fsi->pages_per_peb, 0);

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
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi || !pebi->pebc || !pebi->pebc->parent_si);
	BUG_ON(!pebi->pebc->parent_si->fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	fsi = pebi->pebc->parent_si->fsi;

	mutex_init(&pebi->current_log.lock);
	atomic_set(&pebi->current_log.sequence_id, 0);

	pebi->current_log.start_page = U16_MAX;
	pebi->current_log.reserved_pages = 0;
	pebi->current_log.free_data_pages = pebi->log_pages;
	pebi->current_log.seg_flags = 0;

	for (i = 0; i < SSDFS_LOG_AREA_MAX; i++) {
		size_t metadata_size = sizeof(struct ssdfs_peb_area_metadata);
		size_t blk_table_size = sizeof(struct ssdfs_area_block_table);

		area = &pebi->current_log.area[i];
		memset(&area->metadata, 0, metadata_size);

		switch (i) {
		case SSDFS_LOG_BLK_DESC_AREA:
			area->has_metadata = true;
			area->write_offset = blk_table_size;
			area->metadata.reserved_offset = blk_table_size;
			break;

		case SSDFS_LOG_MAIN_AREA:
		case SSDFS_LOG_DIFFS_AREA:
		case SSDFS_LOG_JOURNAL_AREA:
			area->has_metadata = false;
			area->write_offset = 0;
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
			area->metadata.area.blk_desc.capacity = 0;
			area->metadata.area.blk_desc.items_count = 0;
		}

		ssdfs_destroy_page_array(&area->array);
	}

	return err;
}

/*
 * ssdfs_peb_current_log_destroy() - destroy current log object
 * @pebi: pointer on PEB object
 */
static inline
int ssdfs_peb_current_log_destroy(struct ssdfs_peb_info *pebi)
{
	int i;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebi);
	BUG_ON(mutex_is_locked(&pebi->current_log.lock));
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("pebi %p\n", pebi);

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
		}

		ssdfs_destroy_page_array(area_pages);
	}

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
	size_t pebi_size = sizeof(struct ssdfs_peb_info);
	int peb_type;
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

	SSDFS_DBG("pebi %p, seg %llu, peb_id %llu, "
		  "peb_index %u, pebc %p, "
		  "peb_state %#x, peb_migration_id %u\n",
		  pebi, pebc->parent_si->seg_id,
		  pebi->peb_id, pebc->peb_index, pebc,
		  peb_state, peb_migration_id);

	fsi = pebc->parent_si->fsi;

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
	ssdfs_set_peb_migration_id(pebi, peb_migration_id);
	init_completion(&pebi->init_end);
	atomic_set(&pebi->reserved_bytes.blk_bmap, 0);
	atomic_set(&pebi->reserved_bytes.blk2off_tbl, 0);
	atomic_set(&pebi->reserved_bytes.blk_desc_tbl, 0);
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

	return 0;

fail_conctruct_peb_obj:
	memset(pebi, 0, pebi_size);
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

	fsi = pebi->pebc->parent_si->fsi;

	if (pebi->peb_id >= (fsi->nsegs * fsi->pebs_per_seg)) {
		SSDFS_DBG("invalid PEB id %llu\n", pebi->peb_id);
		return -EINVAL;
	}

	SSDFS_DBG("peb_id %llu\n", pebi->peb_id);

	err = ssdfs_peb_current_log_destroy(pebi);

	state = atomic_read(&pebi->cache.state);
	if (state == SSDFS_PAGE_ARRAY_DIRTY) {
		ssdfs_fs_error(pebi->pebc->parent_si->fsi->sb,
				__FILE__, __func__, __LINE__,
				"PEB %llu is dirty on destruction\n",
				pebi->peb_id);
		err = -EIO;
	}

	ssdfs_destroy_page_array(&pebi->cache);

	return err;
}
