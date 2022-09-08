//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/peb_group_array.h - PEBs group array's declarations.
 *
 * Copyright (c) 2021-2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#ifndef _SSDFS_PEB_GROUP_ARRAY_H
#define _SSDFS_PEB_GROUP_ARRAY_H

/*
 * struct ssdfs_peb_group_array - array of PEB group objects
 * @pebs_per_group: number of PEBs in group
 * @groups_per_volume: number of groups per volume
 * @pga_lock: PEB group array's lock
 * @pages: pages of PEB group objects
 */
struct ssdfs_peb_group_array {
	u32 pebs_per_group;
	u64 groups_per_volume;

	struct rw_semaphore pga_lock;
	struct address_space pages;
};

#define SSDFS_PEB_GRP_ARRAY_PTR_PER_PAGE \
	(PAGE_SIZE / sizeof(struct ssdfs_peb_group *))

/*
 * PEB group array's API
 */
#ifdef CONFIG_SSDFS_ERASE_BLOCKS_GROUP
int ssdfs_init_peb_group_cache(void);
void ssdfs_shrink_peb_group_cache(void);
void ssdfs_destroy_peb_group_cache(void);

int ssdfs_peb_group_array_create(struct ssdfs_fs_info *fsi);
void ssdfs_peb_group_array_destroy(struct ssdfs_fs_info *fsi);
struct ssdfs_peb_group *
ssdfs_peb_group_array_get(struct ssdfs_fs_info *fsi, u64 group_id);
#else
static inline
int ssdfs_init_peb_group_cache(void)
{
	return 0;
}
static inline
void ssdfs_shrink_peb_group_cache(void)
{
	return;
}
static inline
void ssdfs_destroy_peb_group_cache(void)
{
	return;
}
static inline
int ssdfs_peb_group_array_create(struct ssdfs_fs_info *fsi)
{
	SSDFS_DBG("PEBs group is not supported. "
		  "Please, enable CONFIG_SSDFS_ERASE_BLOCKS_GROUP option.\n");
	return 0;
}
static inline
void ssdfs_peb_group_array_destroy(struct ssdfs_fs_info *fsi)
{
	SSDFS_DBG("PEBs group is not supported. "
		  "Please, enable CONFIG_SSDFS_ERASE_BLOCKS_GROUP option.\n");
}
static inline
struct ssdfs_peb_group *
ssdfs_peb_group_array_get(struct ssdfs_fs_info *fsi, u64 group_id)
{
	SSDFS_ERR("PEBs group is not supported. "
		  "Please, enable CONFIG_SSDFS_ERASE_BLOCKS_GROUP option.\n");
	return ERR_PTR(-EOPNOTSUPP);
}
#endif /* CONFIG_SSDFS_ERASE_BLOCKS_GROUP */

#endif /* _SSDFS_PEB_GROUP_ARRAY_H */
