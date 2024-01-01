/*
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshot.c - snapshots subsystem implementation.
 *
 * Copyright (c) 2021-2024 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"
#include "btree_search.h"
#include "btree_node.h"
#include "btree.h"
#include "snapshot.h"
#include "snapshots_tree.h"

/*
 * ssdfs_snapshot_subsystem_init() - initialize the snapshot subsystem
 * @fsi: pointer on shared file system object
 *
 * This function tries to initialize the snapshots subsystem.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_snapshot_subsystem_init(struct ssdfs_fs_info *fsi)
{
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_snapshot_reqs_queue_init(&fsi->snapshots.reqs_queue);
	ssdfs_snapshot_rules_list_init(&fsi->snapshots.rules_list);

#ifdef CONFIG_SSDFS_TRACK_API_CALL
	SSDFS_ERR("create snapshots tree started...\n");
#else
	SSDFS_DBG("create snapshots tree started...\n");
#endif /* CONFIG_SSDFS_TRACK_API_CALL */

	if (fsi->fs_feature_compat & SSDFS_HAS_SNAPSHOTS_TREE_COMPAT_FLAG) {
		down_write(&fsi->volume_sem);
		err = ssdfs_snapshots_btree_create(fsi);
		up_write(&fsi->volume_sem);
		if (err)
			return err;
	} else {
		SSDFS_WARN("volume hasn't snapshots tree\n");
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_snapshot_subsystem_destroy() - destroy the snapshot subsystem
 * @fsi: pointer on shared file system object
 *
 * This function tries to destroy the snapshots subsystem.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_snapshot_subsystem_destroy(struct ssdfs_fs_info *fsi)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!fsi);

	SSDFS_DBG("fsi %p\n", fsi);
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_snapshot_reqs_queue_remove_all(&fsi->snapshots.reqs_queue);
	ssdfs_snapshot_rules_list_remove_all(&fsi->snapshots.rules_list);
	ssdfs_snapshots_btree_destroy(fsi);

	return 0;
}
