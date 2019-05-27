//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_migration_scheme.c - Implementation of PEBs' migration scheme.
 *
 * Copyright (c) 2014-2018 HGST, a Western Digital Company.
 *              http://www.hgst.com/
 *
 * HGST Confidential
 * (C) Copyright 2009-2018, HGST, Inc., All rights reserved.
 *
 * Created by HGST, San Jose Research Center, Storage Architecture Group
 * Authors: Vyacheslav Dubeyko <Vyacheslav.Dubeyko@wdc.com>
 *
 * Acknowledgement: Cyril Guyot <Cyril.Guyot@wdc.com>
 *                  Zvonimir Bandic <Zvonimir.Bandic@wdc.com>
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "block_bitmap.h"
#include "peb_block_bitmap.h"
#include "segment_block_bitmap.h"
#include "page_array.h"
#include "peb.h"
#include "peb_container.h"
#include "segment_bitmap.h"
#include "segment.h"

/*
 * ssdfs_peb_start_migration() - prepare and start PEB's migration
 * @pebc: pointer on PEB container
 */
int ssdfs_peb_start_migration(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_type %#x, "
		  "migration_state %#x, items_state %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  atomic_read(&pebc->migration_state),
		  atomic_read(&pebc->items_state));

	si = pebc->parent_si;

check_migration_state:
	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_NOT_MIGRATING:
		/* valid state */
		break;

	case SSDFS_PEB_UNDER_MIGRATION:
		SSDFS_DBG("PEB is under migration already\n");
		return 0;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION: {
			DEFINE_WAIT(wait);

			prepare_to_wait(&si->migration.wait, &wait,
					TASK_UNINTERRUPTIBLE);
			schedule();
			finish_wait(&si->migration.wait, &wait);
			goto check_migration_state;
		}
		break;

	default:
		SSDFS_WARN("invalid migration_state %#x\n",
			   atomic_read(&pebc->migration_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	err = ssdfs_peb_container_create_destination(pebc);
	if (unlikely(err)) {
		SSDFS_ERR("fail to start PEB migration: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index,
			  err);
		return err;
	}

	return 0;
}

/*
 * is_peb_under_migration() - check that PEB is under migration
 * @pebc: pointer on PEB container
 */
bool is_peb_under_migration(struct ssdfs_peb_container *pebc)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_NOT_MIGRATING:
		return false;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
	case SSDFS_PEB_UNDER_MIGRATION:
		return true;

	default:
		SSDFS_WARN("invalid migration_state %#x\n",
			   atomic_read(&pebc->migration_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return false;
}

/*
 * is_pebs_relation_alive() - check PEBs' relation validity
 * @pebc: pointer on PEB container
 */
bool is_pebs_relation_alive(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_peb_container *dst_pebc;
	int shared_free_dst_blks = 0;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
#endif /* CONFIG_SSDFS_DEBUG */

	si = pebc->parent_si;

try_define_items_state:
	switch (atomic_read(&pebc->items_state)) {
	case SSDFS_PEB1_SRC_CONTAINER:
	case SSDFS_PEB2_SRC_CONTAINER:
		return false;

	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
		if (atomic_read(&pebc->shared_free_dst_blks) <= 0)
			return false;
		else
			return true;

	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		return true;

	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		switch (atomic_read(&pebc->migration_state)) {
		case SSDFS_PEB_UNDER_MIGRATION:
			/* valid state */
			break;

		case SSDFS_PEB_RELATION_PREPARATION: {
				DEFINE_WAIT(wait);

				prepare_to_wait(&si->migration.wait, &wait,
						TASK_UNINTERRUPTIBLE);
				schedule();
				finish_wait(&si->migration.wait, &wait);
				goto try_define_items_state;
			}
			break;

		default:
			SSDFS_WARN("invalid migration_state %#x\n",
				   atomic_read(&pebc->migration_state));
#ifdef CONFIG_SSDFS_DEBUG
			BUG();
#endif /* CONFIG_SSDFS_DEBUG */
			return false;
		}

		down_read(&pebc->lock);

		if (!pebc->dst_peb) {
			err = -ERANGE;
			SSDFS_WARN("dst_peb is NULL\n");
			goto finish_relation_check;
		}

		dst_pebc = pebc->dst_peb->pebc;

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!dst_pebc);
#endif /* CONFIG_SSDFS_DEBUG */

		shared_free_dst_blks =
			atomic_read(&dst_pebc->shared_free_dst_blks);

finish_relation_check:
		up_read(&pebc->lock);

		if (unlikely(err))
			return false;

		if (shared_free_dst_blks > 0)
			return true;
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   atomic_read(&pebc->items_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		break;
	}

	return false;
}

/*
 * has_peb_migration_done() - check that PEB's migration has been done
 * @pebc: pointer on PEB container
 */
bool has_peb_migration_done(struct ssdfs_peb_container *pebc)
{
	struct ssdfs_segment_info *si;
	struct ssdfs_segment_blk_bmap *seg_blkbmap;
	struct ssdfs_peb_blk_bmap *peb_blkbmap;
	struct ssdfs_block_bmap *blk_bmap;
	u16 valid_blks;
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc || !pebc->parent_si);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_NOT_MIGRATING:
		return true;

	case SSDFS_PEB_MIGRATION_PREPARATION:
	case SSDFS_PEB_RELATION_PREPARATION:
		return false;

	case SSDFS_PEB_UNDER_MIGRATION:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid migration_state %#x\n",
			   atomic_read(&pebc->migration_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return true;
	}

	si = pebc->parent_si;
	seg_blkbmap = &si->blk_bmap;

	if (pebc->peb_index >= seg_blkbmap->pebs_count) {
		SSDFS_WARN("peb_index %u >= pebs_count %u\n",
			   pebc->peb_index,
			   seg_blkbmap->pebs_count);
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return true;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!seg_blkbmap->peb);
#endif /* CONFIG_SSDFS_DEBUG */

	peb_blkbmap = &seg_blkbmap->peb[pebc->peb_index];

	down_read(&peb_blkbmap->lock);

	switch (atomic_read(&peb_blkbmap->buffers_state)) {
	case SSDFS_PEB_BMAP1_SRC_PEB_BMAP2_DST:
	case SSDFS_PEB_BMAP2_SRC_PEB_BMAP1_DST:
		/* valid state */
		break;

	default:
		err = -ERANGE;
		SSDFS_WARN("invalid buffers_state %#x\n",
			   atomic_read(&peb_blkbmap->buffers_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_define_bmap_state;
		break;
	}

	blk_bmap = peb_blkbmap->src;

	if (!blk_bmap) {
		err = -ERANGE;
		SSDFS_WARN("source block bitmap is NULL\n");
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		goto finish_define_bmap_state;
	}

	err = ssdfs_block_bmap_lock(blk_bmap);
	if (unlikely(err)) {
		SSDFS_ERR("fail to lock block bitmap\n");
		goto finish_define_bmap_state;
	}

	err = ssdfs_block_bmap_get_used_pages(blk_bmap);

	ssdfs_block_bmap_unlock(blk_bmap);

	if (unlikely(err < 0)) {
		SSDFS_ERR("fail to define valid blocks count: "
			  "err %d\n", err);
		goto finish_define_bmap_state;
	} else {
#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(err >= U16_MAX);
#endif /* CONFIG_SSDFS_DEBUG */
		valid_blks = (u16)err;
	}

finish_define_bmap_state:
	up_read(&peb_blkbmap->lock);

	if (unlikely(err))
		return true;

	return valid_blks == 0 ? true : false;
}

/*
 * should_migration_be_finished() - check that migration should be finished
 * @pebc: pointer on PEB container
 */
bool should_migration_be_finished(struct ssdfs_peb_container *pebc)
{
	return !is_pebs_relation_alive(pebc) || has_peb_migration_done(pebc);
}

/*
 * ssdfs_peb_finish_migration() - finish PEB migration
 * @pebc: pointer on PEB container
 */
int ssdfs_peb_finish_migration(struct ssdfs_peb_container *pebc)
{
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pebc);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("seg_id %llu, peb_index %u, peb_type %#x, "
		  "migration_state %#x, items_state %#x\n",
		  pebc->parent_si->seg_id,
		  pebc->peb_index, pebc->peb_type,
		  atomic_read(&pebc->migration_state),
		  atomic_read(&pebc->items_state));

	switch (atomic_read(&pebc->migration_state)) {
	case SSDFS_PEB_UNDER_MIGRATION:
		/* valid state */
		break;

	default:
		SSDFS_WARN("invalid migration_state %#x\n",
			   atomic_read(&pebc->migration_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	switch (atomic_read(&pebc->items_state)) {
	case SSDFS_PEB1_SRC_EXT_PTR_DST_CONTAINER:
	case SSDFS_PEB2_SRC_EXT_PTR_DST_CONTAINER:
		err = ssdfs_peb_container_forget_relation(pebc);
		break;

	case SSDFS_PEB1_DST_CONTAINER:
	case SSDFS_PEB2_DST_CONTAINER:
	case SSDFS_PEB1_SRC_PEB2_DST_CONTAINER:
	case SSDFS_PEB2_SRC_PEB1_DST_CONTAINER:
		err = ssdfs_peb_container_forget_source(pebc);
		break;

	default:
		SSDFS_WARN("invalid items_state %#x\n",
			   atomic_read(&pebc->items_state));
#ifdef CONFIG_SSDFS_DEBUG
		BUG();
#endif /* CONFIG_SSDFS_DEBUG */
		return -ERANGE;
	}

	if (unlikely(err)) {
		SSDFS_ERR("fail to break relation: "
			  "seg %llu, peb_index %u, err %d\n",
			  pebc->parent_si->seg_id,
			  pebc->peb_index, err);
		return err;
	}

	return 0;
}
