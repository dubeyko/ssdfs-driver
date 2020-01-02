//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_table_cache.h - PEB mapping table cache declarations.
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

#ifndef _SSDFS_PEB_MAPPING_TABLE_CACHE_H
#define _SSDFS_PEB_MAPPING_TABLE_CACHE_H

#include <linux/ssdfs_fs.h>

/*
 * struct ssdfs_maptbl_cache - maptbl cache
 * @lock: lock of maptbl cache
 * @pvec: memory pages of maptbl cache
 * @bytes_count: count of bytes in maptbl cache
 * @pm_queue: PEB mappings queue
 */
struct ssdfs_maptbl_cache {
	struct rw_semaphore lock;
	struct pagevec pvec;
	atomic_t bytes_count;

	struct ssdfs_peb_mapping_queue pm_queue;
};

/*
 * struct ssdfs_maptbl_cache_item - cache item descriptor
 * @page_index: index of the found memory page
 * @item_index: item of found index
 * @found: found LEB2PEB pair
 */
struct ssdfs_maptbl_cache_item {
#define SSDFS_MAPTBL_CACHE_ITEM_UNKNOWN		(0)
#define SSDFS_MAPTBL_CACHE_ITEM_FOUND		(1)
#define SSDFS_MAPTBL_CACHE_ITEM_ABSENT		(2)
#define SSDFS_MAPTBL_CACHE_SEARCH_ERROR		(3)
#define SSDFS_MAPTBL_CACHE_SEARCH_MAX		(4)
	int state;
	unsigned page_index;
	u16 item_index;
	struct ssdfs_leb2peb_pair found;
};

#define SSDFS_MAPTBL_MAIN_INDEX		(0)
#define SSDFS_MAPTBL_RELATION_INDEX	(1)
#define SSDFS_MAPTBL_RELATION_MAX	(2)

/*
 * struct ssdfs_maptbl_cache_search_result - PEBs association
 * @pebs: array of PEB descriptors
 */
struct ssdfs_maptbl_cache_search_result {
	struct ssdfs_maptbl_cache_item pebs[SSDFS_MAPTBL_RELATION_MAX];
};

struct ssdfs_maptbl_peb_relation;

/*
 * PEB mapping table cache's API
 */
void ssdfs_maptbl_cache_init(struct ssdfs_maptbl_cache *cache);
void ssdfs_maptbl_cache_destroy(struct ssdfs_maptbl_cache *cache);

int ssdfs_maptbl_cache_convert_leb2peb(struct ssdfs_maptbl_cache *cache,
					u64 leb_id,
					struct ssdfs_maptbl_peb_relation *pebr);
int ssdfs_maptbl_cache_map_leb2peb(struct ssdfs_maptbl_cache *cache,
				   u64 leb_id,
				   struct ssdfs_maptbl_peb_relation *pebr,
				   int consistency);
int ssdfs_maptbl_cache_forget_leb2peb(struct ssdfs_maptbl_cache *cache,
				      u64 leb_id,
				      int consistency);
int ssdfs_maptbl_cache_change_peb_state(struct ssdfs_maptbl_cache *cache,
					u64 leb_id, int peb_state,
					int consistency);
int ssdfs_maptbl_cache_add_migration_peb(struct ssdfs_maptbl_cache *cache,
					u64 leb_id,
					struct ssdfs_maptbl_peb_relation *pebr,
					int consistency);
int ssdfs_maptbl_cache_exclude_migration_peb(struct ssdfs_maptbl_cache *cache,
					     u64 leb_id,
					     int consistency);

#endif /* _SSDFS_PEB_MAPPING_TABLE_CACHE_H */
