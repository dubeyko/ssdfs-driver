//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_table_cache.h - PEB mapping table cache declarations.
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

#ifndef _SSDFS_PEB_MAPPING_TABLE_CACHE_H
#define _SSDFS_PEB_MAPPING_TABLE_CACHE_H

/*
 * struct ssdfs_maptbl_cache - maptbl cache
 * @lock: lock of maptbl cache
 * @pvec: memory pages of maptbl cache
 * @bytes_count: count of bytes in maptbl cache
 */
struct ssdfs_maptbl_cache {
	struct rw_semaphore lock;
	struct pagevec pvec;
	atomic_t bytes_count;
};

struct ssdfs_maptbl_peb_relation;

/*
 * PEB mapping table cache's API
 */
int ssdfs_maptbl_cache_convert_leb2peb(struct ssdfs_maptbl_cache *cache,
					u64 leb_id,
					struct ssdfs_maptbl_peb_relation *pebr);
int ssdfs_maptbl_cache_map_leb2peb(struct ssdfs_maptbl_cache *cache,
				   u64 leb_id,
				   struct ssdfs_maptbl_peb_relation *pebr,
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
