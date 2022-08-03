//SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dev_zns.c - ZNS SSD support.
 *
 * Copyright (c) 2022 Viacheslav Dubeyko <slava@dubeyko.com>
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "ssdfs.h"

#include <trace/events/ssdfs.h>

#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
atomic64_t ssdfs_dev_zns_page_leaks;
atomic64_t ssdfs_dev_zns_memory_leaks;
atomic64_t ssdfs_dev_zns_cache_leaks;
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

/*
 * void ssdfs_dev_zns_cache_leaks_increment(void *kaddr)
 * void ssdfs_dev_zns_cache_leaks_decrement(void *kaddr)
 * void *ssdfs_dev_zns_kmalloc(size_t size, gfp_t flags)
 * void *ssdfs_dev_zns_kzalloc(size_t size, gfp_t flags)
 * void *ssdfs_dev_zns_kcalloc(size_t n, size_t size, gfp_t flags)
 * void ssdfs_dev_zns_kfree(void *kaddr)
 * struct page *ssdfs_dev_zns_alloc_page(gfp_t gfp_mask)
 * struct page *ssdfs_dev_zns_add_pagevec_page(struct pagevec *pvec)
 * void ssdfs_dev_zns_free_page(struct page *page)
 * void ssdfs_dev_zns_pagevec_release(struct pagevec *pvec)
 */
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	SSDFS_MEMORY_LEAKS_CHECKER_FNS(dev_zns)
#else
	SSDFS_MEMORY_ALLOCATOR_FNS(dev_zns)
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */

void ssdfs_dev_zns_memory_leaks_init(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	atomic64_set(&ssdfs_dev_zns_page_leaks, 0);
	atomic64_set(&ssdfs_dev_zns_memory_leaks, 0);
	atomic64_set(&ssdfs_dev_zns_cache_leaks, 0);
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

void ssdfs_dev_zns_check_memory_leaks(void)
{
#ifdef CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING
	if (atomic64_read(&ssdfs_dev_zns_page_leaks) != 0) {
		SSDFS_ERR("ZNS DEV: "
			  "memory leaks include %lld pages\n",
			  atomic64_read(&ssdfs_dev_zns_page_leaks));
	}

	if (atomic64_read(&ssdfs_dev_zns_memory_leaks) != 0) {
		SSDFS_ERR("ZNS DEV: "
			  "memory allocator suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dev_zns_memory_leaks));
	}

	if (atomic64_read(&ssdfs_dev_zns_cache_leaks) != 0) {
		SSDFS_ERR("ZNS DEV: "
			  "caches suffers from %lld leaks\n",
			  atomic64_read(&ssdfs_dev_zns_cache_leaks));
	}
#endif /* CONFIG_SSDFS_MEMORY_LEAKS_ACCOUNTING */
}

static DECLARE_WAIT_QUEUE_HEAD(zns_wq);

/*
 * ssdfs_zns_device_name() - get device name
 * @sb: superblock object
 */
static const char *ssdfs_zns_device_name(struct super_block *sb)
{
	return sb->s_id;
}

/*
 * ssdfs_zns_device_size() - get partition size in bytes
 * @sb: superblock object
 */
static __u64 ssdfs_zns_device_size(struct super_block *sb)
{
	return i_size_read(sb->s_bdev->bd_inode);
}

/*
 * ssdfs_zns_open_zone() - open zone
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 */
static int ssdfs_zns_open_zone(struct super_block *sb, loff_t offset)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	sector_t zone_size = fsi->erasesize >> SECTOR_SHIFT;
	u32 open_zones;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu\n",
		  sb, (unsigned long long)offset);
#endif /* CONFIG_SSDFS_DEBUG */

	open_zones = atomic_inc_return(&fsi->open_zones);
	if (open_zones > fsi->max_open_zones) {
		atomic_dec(&fsi->open_zones);

		SSDFS_WARN("open zones limit achieved: "
			   "open_zones %u\n", open_zones);
		return -EBUSY;
	}

	err = blkdev_zone_mgmt(sb->s_bdev, REQ_OP_ZONE_OPEN,
				zone_sector, zone_size, GFP_NOFS);
	if (unlikely(err)) {
		SSDFS_ERR("fail to open zone: "
			  "zone_sector %llu, zone_size %llu, err %d\n",
			  zone_sector, zone_size, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_zns_close_zone() - close zone
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 */
static int ssdfs_zns_close_zone(struct super_block *sb, loff_t offset)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	sector_t zone_size = fsi->erasesize >> SECTOR_SHIFT;
	u32 open_zones;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu\n",
		  sb, (unsigned long long)offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = blkdev_zone_mgmt(sb->s_bdev, REQ_OP_ZONE_FINISH,
				zone_sector, zone_size, GFP_NOFS);
	if (unlikely(err)) {
		SSDFS_ERR("fail to open zone: "
			  "zone_sector %llu, zone_size %llu, err %d\n",
			  zone_sector, zone_size, err);
		return err;
	}

	open_zones = atomic_dec_return(&fsi->open_zones);
	if (open_zones > fsi->max_open_zones) {
		SSDFS_WARN("open zones limit exhausted: "
			   "open_zones %u\n", open_zones);
	}

	return 0;
}

static int ssdfs_report_zone(struct blk_zone *zone,
			     unsigned int index, void *data)
{
	ssdfs_memcpy(data, 0, sizeof(struct blk_zone),
		     zone, 0, sizeof(struct blk_zone),
		     sizeof(struct blk_zone));
	return 0;
}

/*
 * ssdfs_zns_zone_size() - retrieve zone size
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to retrieve zone size.
 */
u64 ssdfs_zns_zone_size(struct super_block *sb, loff_t offset)
{
	struct blk_zone zone;
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	int res;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu\n",
		  sb, (unsigned long long)offset);
#endif /* CONFIG_SSDFS_DEBUG */

	res = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (res != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, res);
		return U64_MAX;
	}

	return (u64)zone.capacity << SECTOR_SHIFT;
}

/*
 * ssdfs_zns_can_write_page() - check that page can be written
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 * @need_check: make check or not?
 *
 * This function checks that page can be written.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-ENOMEM      - fail to allocate memory.
 * %-EIO         - I/O error.
 */
static int ssdfs_zns_can_write_page(struct super_block *sb, loff_t offset,
				    bool need_check)
{
	struct blk_zone zone;
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	int res;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, need_check %d\n",
		  sb, (unsigned long long)offset, (int)need_check);
#endif /* CONFIG_SSDFS_DEBUG */

	if (!need_check)
		return 0;

	res = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (res != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, res);
		return res;
	}

	switch (zone.type) {
	case BLK_ZONE_TYPE_CONVENTIONAL:
		return ssdfs_bdev_can_write_page(sb, offset, need_check);

	default:
		/*
		 * BLK_ZONE_TYPE_SEQWRITE_REQ
		 * BLK_ZONE_TYPE_SEQWRITE_PREF
		 *
		 * continue logic
		 */
		break;
	}

	switch (zone.cond) {
	case BLK_ZONE_COND_NOT_WP:
		return ssdfs_bdev_can_write_page(sb, offset, need_check);

	case BLK_ZONE_COND_EMPTY:
		/* can write */
		SSDFS_DBG("zone is empty: offset %llu\n",
			  offset);
		return 0;

	case BLK_ZONE_COND_CLOSED:
		SSDFS_DBG("zone is closed: offset %llu\n",
			  offset);
		return -EIO;

	case BLK_ZONE_COND_READONLY:
		SSDFS_DBG("zone is READ-ONLY: offset %llu\n",
			  offset);
		return -EIO;

	case BLK_ZONE_COND_FULL:
		SSDFS_DBG("zone is full: offset %llu\n",
			  offset);
		return -EIO;

	case BLK_ZONE_COND_OFFLINE:
		SSDFS_DBG("zone is offline: offset %llu\n",
			  offset);
		return -EIO;

	default:
		/* continue logic */
		break;
	}

	if (zone_sector < zone.wp) {
		SSDFS_DBG("cannot be written: "
			  "zone_sector %llu, zone.wp %llu\n",
			  zone_sector, zone.wp);
		return -EIO;
	}

	return 0;
}

/*
 * ssdfs_zns_trim() - initiate background erase operation
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 * @len: size in bytes
 *
 * This function tries to initiate background erase operation.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EFAULT      - erase operation error.
 */
static int ssdfs_zns_trim(struct super_block *sb, loff_t offset, size_t len)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	u32 erase_size = fsi->erasesize;
	loff_t page_start, page_end;
	u32 pages_count;
	u32 remainder;
	sector_t start_sector;
	sector_t sectors_count;
	int err = 0;

	SSDFS_DBG("sb %p, offset %llu, len %zu\n",
		  sb, (unsigned long long)offset, len);

#ifdef CONFIG_SSDFS_DEBUG
	div_u64_rem((u64)len, (u64)erase_size, &remainder);
	BUG_ON(remainder);
	div_u64_rem((u64)offset, (u64)erase_size, &remainder);
	BUG_ON(remainder);
#endif /* CONFIG_SSDFS_DEBUG */

	if (sb->s_flags & SB_RDONLY)
		return -EROFS;

	div_u64_rem((u64)len, (u64)erase_size, &remainder);
	if (remainder) {
		SSDFS_WARN("len %llu, erase_size %u, remainder %u\n",
			   (unsigned long long)len,
			   erase_size, remainder);
		return -ERANGE;
	}

	page_start = offset >> PAGE_SHIFT;
	page_end = (offset + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	pages_count = (u32)(page_end - page_start);

	if (pages_count == 0) {
		SSDFS_WARN("pages_count equals to zero\n");
		return -ERANGE;
	}

	start_sector = offset >> SECTOR_SHIFT;
	sectors_count = fsi->erasesize >> SECTOR_SHIFT;

	err = blkdev_zone_mgmt(sb->s_bdev, REQ_OP_ZONE_RESET,
				start_sector, sectors_count, GFP_NOFS);
	if (unlikely(err)) {
		SSDFS_ERR("fail to reset zone: "
			  "zone_sector %llu, zone_size %llu, err %d\n",
			  start_sector, sectors_count, err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_zns_peb_isbad() - check that PEB is bad
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to detect that PEB is bad or not.
 */
static int ssdfs_zns_peb_isbad(struct super_block *sb, loff_t offset)
{
	/* do nothing */
	return 0;
}

/*
 * ssdfs_zns_mark_peb_bad() - mark PEB as bad
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to mark PEB as bad.
 */
int ssdfs_zns_mark_peb_bad(struct super_block *sb, loff_t offset)
{
	/* do nothing */
	return 0;
}

/*
 * ssdfs_zns_sync() - make sync operation
 * @sb: superblock object
 */
static void ssdfs_zns_sync(struct super_block *sb)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);

	SSDFS_DBG("device %s\n", sb->s_id);

	wait_event(zns_wq, atomic_read(&fsi->pending_bios) == 0);
}

const struct ssdfs_device_ops ssdfs_zns_devops = {
	.device_name		= ssdfs_zns_device_name,
	.device_size		= ssdfs_zns_device_size,
	.open_zone		= ssdfs_zns_open_zone,
	.close_zone		= ssdfs_zns_close_zone,
	.read			= ssdfs_bdev_read,
	.readpage		= ssdfs_bdev_readpage,
	.readpages		= ssdfs_bdev_readpages,
	.can_write_page		= ssdfs_zns_can_write_page,
	.writepage		= ssdfs_bdev_writepage,
	.writepages		= ssdfs_bdev_writepages,
	.erase			= ssdfs_zns_trim,
	.trim			= ssdfs_zns_trim,
	.peb_isbad		= ssdfs_zns_peb_isbad,
	.mark_peb_bad		= ssdfs_zns_mark_peb_bad,
	.sync			= ssdfs_zns_sync,
};
