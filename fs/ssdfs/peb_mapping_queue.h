//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_mapping_queue.h - PEB mappings queue declarations.
 *
 * Copyright (c) 2019-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_PEB_MAPPING_QUEUE_H
#define _SSDFS_PEB_MAPPING_QUEUE_H

/*
 * struct ssdfs_peb_mapping_queue - PEB mappings queue descriptor
 * @lock: extents queue's lock
 * @list: extents queue's list
 */
struct ssdfs_peb_mapping_queue {
	spinlock_t lock;
	struct list_head list;
};

/*
 * struct ssdfs_peb_mapping_info - peb mapping info
 * @list: extents queue list
 * @leb_id: LEB ID
 * @peb_id: PEB ID
 * @consistency: consistency state in the mapping table cache
 */
struct ssdfs_peb_mapping_info {
	struct list_head list;
	u64 leb_id;
	u64 peb_id;
	int consistency;
};

/*
 * PEB mappings queue API
 */
void ssdfs_peb_mapping_queue_init(struct ssdfs_peb_mapping_queue *pmq);
bool is_ssdfs_peb_mapping_queue_empty(struct ssdfs_peb_mapping_queue *pmq);
void ssdfs_peb_mapping_queue_add_tail(struct ssdfs_peb_mapping_queue *pmq,
				      struct ssdfs_peb_mapping_info *pmi);
void ssdfs_peb_mapping_queue_add_head(struct ssdfs_peb_mapping_queue *pmq,
				      struct ssdfs_peb_mapping_info *pmi);
int ssdfs_peb_mapping_queue_remove_first(struct ssdfs_peb_mapping_queue *pmq,
					 struct ssdfs_peb_mapping_info **pmi);
void ssdfs_peb_mapping_queue_remove_all(struct ssdfs_peb_mapping_queue *pmq);

/*
 * PEB mapping info's API
 */
void ssdfs_zero_peb_mapping_info_cache_ptr(void);
int ssdfs_init_peb_mapping_info_cache(void);
void ssdfs_shrink_peb_mapping_info_cache(void);
void ssdfs_destroy_peb_mapping_info_cache(void);

struct ssdfs_peb_mapping_info *ssdfs_peb_mapping_info_alloc(void);
void ssdfs_peb_mapping_info_free(struct ssdfs_peb_mapping_info *pmi);
void ssdfs_peb_mapping_info_init(u64 leb_id, u64 peb_id, int consistency,
				 struct ssdfs_peb_mapping_info *pmi);

#endif /* _SSDFS_PEB_MAPPING_QUEUE_H */
