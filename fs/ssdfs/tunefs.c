// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/tunefs.c - tunefs request processing functionality.
 *
 * Copyright (c) 2023-2024 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "version.h"
#include "compression.h"
#include "folio_array.h"
#include "segment_bitmap.h"
#include "peb.h"
#include "offset_translation_table.h"
#include "peb_container.h"
#include "segment.h"
#include "segment_tree.h"
#include "current_segment.h"
#include "peb_mapping_table.h"

/*
 * IS_TUNEFS_REQUESTED() - check that tunefs requested changing configuration
 * @request: configuration request
 */
bool IS_TUNEFS_REQUESTED(struct ssdfs_tunefs_request_copy *request)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!request);
	BUG_ON(!mutex_is_locked(&request->lock));

	SSDFS_DBG("request %p, state %#x\n",
		  request, request->state);
#endif /* CONFIG_SSDFS_DEBUG */

	return request->state == SSDFS_ENABLE_OPTION;
}

/*
 * IS_OPTION_ENABLE_REQUESTED() - check that option enabling has been requested
 * @option: configuration option
 */
bool IS_OPTION_ENABLE_REQUESTED(struct ssdfs_tunefs_option *option)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!option);

	SSDFS_DBG("option %p, state %#x\n",
		  option, option->state);
#endif /* CONFIG_SSDFS_DEBUG */

	return option->state == SSDFS_ENABLE_OPTION;
}

/*
 * IS_OPTION_DISABLE_REQUESTED() - check that option disabling has been requested
 * @option: configuration option
 */
bool IS_OPTION_DISABLE_REQUESTED(struct ssdfs_tunefs_option *option)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!option);

	SSDFS_DBG("option %p, state %#x\n",
		  option, option->state);
#endif /* CONFIG_SSDFS_DEBUG */

	return option->state == SSDFS_DISABLE_OPTION;
}

/*
 * IS_VOLUME_LABEL_NEED2CHANGE() - check that volume label needs to be changed
 * @option: configuration option
 */
bool IS_VOLUME_LABEL_NEED2CHANGE(struct ssdfs_tunefs_volume_label_option *option)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!option);

	SSDFS_DBG("option %p, state %#x\n",
		  option, option->state);
#endif /* CONFIG_SSDFS_DEBUG */

	return option->state == SSDFS_ENABLE_OPTION;
}

/*
 * ssdfs_tunefs_get_current_volume_config() - get current volume config
 * @fsi: pointer on shared file system object
 * @config: current volume config [out]
 */
void ssdfs_tunefs_get_current_volume_config(struct ssdfs_fs_info *fsi,
				struct ssdfs_current_volume_config *config)
{
	struct ssdfs_segment_bmap *segbmap;
	struct ssdfs_peb_mapping_table *maptbl;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !config);

	SSDFS_DBG("fsi %p, config %p\n", fsi, config);
#endif /* CONFIG_SSDFS_DEBUG */

	spin_lock(&fsi->volume_state_lock);
	ssdfs_memcpy(config->fs_uuid, 0, SSDFS_UUID_SIZE,
		     fsi->fs_uuid, 0, SSDFS_UUID_SIZE,
		     SSDFS_UUID_SIZE);
	ssdfs_memcpy(config->fs_label, 0, SSDFS_VOLUME_LABEL_MAX,
		     fsi->fs_label, 0, SSDFS_VOLUME_LABEL_MAX,
		     SSDFS_VOLUME_LABEL_MAX);
	config->migration_threshold = fsi->migration_threshold;
	spin_unlock(&fsi->volume_state_lock);

	mutex_lock(&fsi->resize_mutex);
	config->nsegs = fsi->nsegs;
	mutex_unlock(&fsi->resize_mutex);

	config->pagesize = fsi->pagesize;
	config->erasesize = fsi->erasesize;
	config->segsize = fsi->segsize;
	config->pebs_per_seg = fsi->pebs_per_seg;
	config->pages_per_peb = fsi->pages_per_peb;
	config->pages_per_seg = fsi->pages_per_seg;
	config->leb_pages_capacity = fsi->leb_pages_capacity;
	config->peb_pages_capacity = fsi->peb_pages_capacity;
	config->fs_ctime = fsi->fs_ctime;
	config->raw_inode_size = fsi->raw_inode_size;
	config->create_threads_per_seg = fsi->create_threads_per_seg;

	ssdfs_memcpy(&config->metadata_options,
		     0, sizeof(struct ssdfs_metadata_options),
		     &fsi->metadata_options,
		     0, sizeof(struct ssdfs_metadata_options),
		     sizeof(struct ssdfs_metadata_options));

	down_read(&fsi->volume_sem);
	config->sb_seg_log_pages = fsi->sb_seg_log_pages;
	config->segbmap_log_pages = fsi->segbmap_log_pages;
	config->maptbl_log_pages = fsi->maptbl_log_pages;
	config->lnodes_seg_log_pages = fsi->lnodes_seg_log_pages;
	config->hnodes_seg_log_pages = fsi->hnodes_seg_log_pages;
	config->inodes_seg_log_pages = fsi->inodes_seg_log_pages;
	config->user_data_log_pages = fsi->user_data_log_pages;
	up_read(&fsi->volume_sem);

	segbmap = fsi->segbmap;

	down_read(&segbmap->resize_lock);
	config->segbmap_flags = segbmap->flags;
	up_read(&segbmap->resize_lock);

	maptbl = fsi->maptbl;
	config->maptbl_flags = (u16)atomic_read(&maptbl->flags);

	config->is_zns_device = fsi->is_zns_device;
	config->zone_size = fsi->zone_size;
	config->zone_capacity = fsi->zone_capacity;
	config->max_open_zones = fsi->max_open_zones;
}

/*
 * At minimum, log requires to have header and footer
 */
#define SSDFS_LOG_PAGES_MIN	(2)

static
int ssdfs_tunefs_check_log_pages_value(u32 pages_per_peb,
					struct ssdfs_tunefs_option *log_pages)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!log_pages);

	SSDFS_DBG("log_pages %d, pages_per_peb %u\n",
		  log_pages->value, pages_per_peb);
#endif /* CONFIG_SSDFS_DEBUG */

	if (log_pages->value <= SSDFS_LOG_PAGES_MIN) {
		log_pages->state = SSDFS_USE_RECOMMENDED_VALUE;
		log_pages->recommended_value =
				1 << (ilog2(SSDFS_LOG_PAGES_MIN) + 1);
		return -EINVAL;
	} else if (log_pages->value > pages_per_peb) {
		log_pages->state = SSDFS_USE_RECOMMENDED_VALUE;
		log_pages->recommended_value = pages_per_peb;
		return -EINVAL;
	} else {
		if (log_pages->value % pages_per_peb) {
			log_pages->state = SSDFS_USE_RECOMMENDED_VALUE;
			log_pages->recommended_value =
				1 << (ilog2(log_pages->value) + 1);
			if (log_pages->value > pages_per_peb) {
				log_pages->value = pages_per_peb;
			}
			return -EINVAL;
		}
	}

	/* TODO: currently functionality is not implemented */
	log_pages->state = SSDFS_NOT_IMPLEMENTED_OPTION;
	return -EINVAL;

	return 0;
}

/*
 * ssdfs_tunefs_check_requested_compression() - check requested compression
 * @option: tunefs option [in|out]
 */
static inline
int ssdfs_tunefs_check_requested_compression(struct ssdfs_tunefs_option *option)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!option);

	SSDFS_DBG("option %p\n", option);
#endif /* CONFIG_SSDFS_DEBUG */

	if (option->state != SSDFS_IGNORE_OPTION) {
		switch (option->value) {
		case SSDFS_COMPR_NONE:
		case SSDFS_COMPR_ZLIB:
		case SSDFS_COMPR_LZO:
			/* expected value */

			/* TODO: currently functionality is not implemented */
			option->state = SSDFS_NOT_IMPLEMENTED_OPTION;
			return -EINVAL;

			break;

		default:
			option->state = SSDFS_UNRECOGNIZED_VALUE;
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * ssdfs_tunefs_check_requested_volume_config() - check requested volume config
 * @fsi: pointer on shared file system object
 * @options: tunefs options [in|out]
 */
int ssdfs_tunefs_check_requested_volume_config(struct ssdfs_fs_info *fsi,
					struct ssdfs_tunefs_options *options)
{
	struct ssdfs_tunefs_blkbmap_options *blkbmap;
	struct ssdfs_tunefs_blk2off_table_options *blk2off_tbl;
	struct ssdfs_tunefs_segbmap_options *segbmap;
	struct ssdfs_tunefs_maptbl_options *maptbl;
	struct ssdfs_tunefs_btree_options *btree;
	struct ssdfs_tunefs_user_data_options *user_data;
	u32 pages_per_peb;
	bool is_config_valid = true;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !options);

	SSDFS_DBG("fsi %p, options %p\n", fsi, options);
#endif /* CONFIG_SSDFS_DEBUG */

	pages_per_peb = options->old_config.pages_per_peb;

	blkbmap = &options->new_config.blkbmap;
	err = ssdfs_tunefs_check_requested_compression(&blkbmap->compression);
	if (err == -EINVAL) {
		err = 0;
		is_config_valid = false;
	}

	blk2off_tbl = &options->new_config.blk2off_tbl;
	err = ssdfs_tunefs_check_requested_compression(&blk2off_tbl->compression);
	if (err == -EINVAL) {
		err = 0;
		is_config_valid = false;
	}

	segbmap = &options->new_config.segbmap;

	if (segbmap->has_backup_copy.state != SSDFS_IGNORE_OPTION) {
		if (options->old_config.segbmap_flags &
						SSDFS_SEGBMAP_HAS_COPY) {
			if (segbmap->has_backup_copy.value ==
						SSDFS_DISABLE_OPTION) {
				segbmap->has_backup_copy.state =
						SSDFS_DONT_SUPPORT_OPTION;
				is_config_valid = false;
			}
		}

		/* TODO: currently functionality is not implemented */
		segbmap->has_backup_copy.state = SSDFS_NOT_IMPLEMENTED_OPTION;
		is_config_valid = false;
	}

	if (segbmap->log_pages.state != SSDFS_IGNORE_OPTION) {
		err = ssdfs_tunefs_check_log_pages_value(pages_per_peb,
							 &segbmap->log_pages);
		if (err == -EINVAL) {
			err = 0;
			is_config_valid = false;
		}
	}

	if (segbmap->migration_threshold.state != SSDFS_IGNORE_OPTION) {
		segbmap->migration_threshold.state = SSDFS_DONT_SUPPORT_OPTION;
		is_config_valid = false;
	}

	err = ssdfs_tunefs_check_requested_compression(&segbmap->compression);
	if (err == -EINVAL) {
		err = 0;
		is_config_valid = false;
	}

	maptbl = &options->new_config.maptbl;

	if (maptbl->has_backup_copy.state != SSDFS_IGNORE_OPTION) {
		if (options->old_config.maptbl_flags &
						SSDFS_MAPTBL_HAS_COPY) {
			if (maptbl->has_backup_copy.value ==
						SSDFS_DISABLE_OPTION) {
				maptbl->has_backup_copy.state =
						SSDFS_DONT_SUPPORT_OPTION;
				is_config_valid = false;
			}
		}

		/* TODO: currently functionality is not implemented */
		maptbl->has_backup_copy.state = SSDFS_NOT_IMPLEMENTED_OPTION;
		is_config_valid = false;
	}

	if (maptbl->log_pages.state != SSDFS_IGNORE_OPTION) {
		err = ssdfs_tunefs_check_log_pages_value(pages_per_peb,
							 &maptbl->log_pages);
		if (err == -EINVAL) {
			err = 0;
			is_config_valid = false;
		}
	}

	if (maptbl->migration_threshold.state != SSDFS_IGNORE_OPTION) {
		maptbl->migration_threshold.state = SSDFS_DONT_SUPPORT_OPTION;
		is_config_valid = false;
	}

	if (maptbl->reserved_pebs_per_fragment.state != SSDFS_IGNORE_OPTION) {
		maptbl->reserved_pebs_per_fragment.state =
						SSDFS_DONT_SUPPORT_OPTION;
		is_config_valid = false;
	}

	err = ssdfs_tunefs_check_requested_compression(&maptbl->compression);
	if (err == -EINVAL) {
		err = 0;
		is_config_valid = false;
	}

	btree = &options->new_config.btree;

	if (btree->min_index_area_size.state != SSDFS_IGNORE_OPTION) {
		btree->min_index_area_size.state = SSDFS_DONT_SUPPORT_OPTION;
		is_config_valid = false;
	}

	if (btree->lnode_log_pages.state != SSDFS_IGNORE_OPTION) {
		err = ssdfs_tunefs_check_log_pages_value(pages_per_peb,
						&btree->lnode_log_pages);
		if (err == -EINVAL) {
			err = 0;
			is_config_valid = false;
		}
	}

	if (btree->hnode_log_pages.state != SSDFS_IGNORE_OPTION) {
		err = ssdfs_tunefs_check_log_pages_value(pages_per_peb,
						&btree->hnode_log_pages);
		if (err == -EINVAL) {
			err = 0;
			is_config_valid = false;
		}
	}

	if (btree->inode_log_pages.state != SSDFS_IGNORE_OPTION) {
		err = ssdfs_tunefs_check_log_pages_value(pages_per_peb,
						&btree->inode_log_pages);
		if (err == -EINVAL) {
			err = 0;
			is_config_valid = false;
		}
	}

	user_data = &options->new_config.user_data_seg;

	if (user_data->log_pages.state != SSDFS_IGNORE_OPTION) {
		err = ssdfs_tunefs_check_log_pages_value(pages_per_peb,
							 &user_data->log_pages);
		if (err == -EINVAL) {
			err = 0;
			is_config_valid = false;
		}
	}

	err = ssdfs_tunefs_check_requested_compression(&user_data->compression);
	if (err == -EINVAL) {
		err = 0;
		is_config_valid = false;
	}

	err = is_config_valid == false ? -EINVAL : 0;

	if (err) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("requested volume config is invalid\n");
#endif /* CONFIG_SSDFS_DEBUG */
	}

	return err;
}

/*
 * ssdfs_tunefs_get_new_config_request() - get tunefs request
 * @fsi: pointer on shared file system object
 * @new_config: new config request
 */
void ssdfs_tunefs_get_new_config_request(struct ssdfs_fs_info *fsi,
				struct ssdfs_tunefs_config_request *new_config)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !new_config);

	SSDFS_DBG("fsi %p, new_config %p\n", fsi, new_config);
#endif /* CONFIG_SSDFS_DEBUG */

	mutex_lock(&fsi->tunefs_request.lock);
	if (fsi->tunefs_request.state == SSDFS_ENABLE_OPTION) {
		ssdfs_memcpy(new_config,
			     0, sizeof(struct ssdfs_tunefs_config_request),
			     &fsi->tunefs_request.new_config,
			     0, sizeof(struct ssdfs_tunefs_config_request),
			     sizeof(struct ssdfs_tunefs_config_request));
	} else {
		memset(new_config, 0,
			sizeof(struct ssdfs_tunefs_config_request));
	}
	mutex_unlock(&fsi->tunefs_request.lock);
}

/*
 * ssdfs_tunefs_save_new_config_request() - save tunefs request
 * @fsi: pointer on shared file system object
 * @options: tunefs options
 */
void ssdfs_tunefs_save_new_config_request(struct ssdfs_fs_info *fsi,
					struct ssdfs_tunefs_options *options)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi || !options);

	SSDFS_DBG("fsi %p, options %p\n", fsi, options);
#endif /* CONFIG_SSDFS_DEBUG */

	mutex_lock(&fsi->tunefs_request.lock);
	fsi->tunefs_request.state = SSDFS_ENABLE_OPTION;
	ssdfs_memcpy(&fsi->tunefs_request.new_config,
		     0, sizeof(struct ssdfs_tunefs_config_request),
		     &options->new_config,
		     0, sizeof(struct ssdfs_tunefs_config_request),
		     sizeof(struct ssdfs_tunefs_config_request));
	mutex_unlock(&fsi->tunefs_request.lock);
}
