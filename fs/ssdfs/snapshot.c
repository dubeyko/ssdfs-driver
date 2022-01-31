//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/snapshot.c - snapshots subsystem implementation.
 *
 * Copyright (c) 2021-2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pagevec.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"
#include "snapshot.h"

/*
 * ssdfs_snapshot_subsystem_init() - initialize the snapshot subsystem
 * @ptr: snapshots subsystem
 *
 * This function tries to initialize the snapshots subsystem.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_snapshot_subsystem_init(struct ssdfs_snapshot_subsystem *ptr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("snapshots %p\n", ptr);

	ssdfs_snapshot_reqs_queue_init(&ptr->reqs_queue);
	ssdfs_snapshot_rules_list_init(&ptr->rules_list);

	return 0;
}

/*
 * ssdfs_snapshot_subsystem_destroy() - destroy the snapshot subsystem
 * @ptr: snapshots subsystem
 *
 * This function tries to destroy the snapshots subsystem.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-ERANGE     - internal error.
 */
int ssdfs_snapshot_subsystem_destroy(struct ssdfs_snapshot_subsystem *ptr)
{
#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!ptr);
#endif /* CONFIG_SSDFS_DEBUG */

	SSDFS_DBG("snapshots %p\n", ptr);

	ssdfs_snapshot_reqs_queue_remove_all(&ptr->reqs_queue);
	ssdfs_snapshot_rules_list_remove_all(&ptr->rules_list);

	return 0;
}
