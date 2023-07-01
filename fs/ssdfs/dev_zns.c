// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dev_zns.c - ZNS SSD support.
 *
 * Copyright (c) 2022-2023 Bytedance Ltd. and/or its affiliates.
 *              https://www.bytedance.com/
 * Copyright (c) 2022-2023 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 *
 * Acknowledgement: Cong Wang
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

static int ssdfs_report_zone(struct blk_zone *zone,
			     unsigned int index, void *data)
{
	ssdfs_memcpy(data, 0, sizeof(struct blk_zone),
		     zone, 0, sizeof(struct blk_zone),
		     sizeof(struct blk_zone));
	return 0;
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
	SSDFS_DBG("BEFORE: open_zones %d\n",
		  atomic_read(&fsi->open_zones));
#endif /* CONFIG_SSDFS_DEBUG */

	open_zones = atomic_inc_return(&fsi->open_zones);
	if (open_zones > fsi->max_open_zones) {
		atomic_dec(&fsi->open_zones);

		SSDFS_WARN("open zones limit achieved: "
			   "open_zones %u\n", open_zones);
		return -EBUSY;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("AFTER: open_zones %d\n",
		   atomic_read(&fsi->open_zones));
#endif /* CONFIG_SSDFS_DEBUG */

	err = blkdev_zone_mgmt(sb->s_bdev, REQ_OP_ZONE_OPEN,
				zone_sector, zone_size, GFP_NOFS);
	if (unlikely(err)) {
		SSDFS_ERR("fail to open zone: "
			  "zone_sector %llu, zone_size %llu, "
			  "open_zones %u, max_open_zones %u, "
			  "err %d\n",
			  zone_sector, zone_size,
			  open_zones, fsi->max_open_zones,
			  err);
		return err;
	}

	return 0;
}

/*
 * ssdfs_zns_reopen_zone() - reopen closed zone
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 */
static int ssdfs_zns_reopen_zone(struct super_block *sb, loff_t offset)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct blk_zone zone;
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	sector_t zone_size = fsi->erasesize >> SECTOR_SHIFT;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu\n",
		  sb, (unsigned long long)offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (err != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("zone before: start %llu, len %llu, wp %llu, "
		  "type %#x, cond %#x, non_seq %#x, "
		  "reset %#x, capacity %llu\n",
		  zone.start, zone.len, zone.wp,
		  zone.type, zone.cond, zone.non_seq,
		  zone.reset, zone.capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (zone.cond) {
	case BLK_ZONE_COND_CLOSED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is closed: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		/* continue logic */
		break;

	case BLK_ZONE_COND_READONLY:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is READ-ONLY: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;

	case BLK_ZONE_COND_FULL:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is full: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;

	case BLK_ZONE_COND_OFFLINE:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is offline: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;

	default:
		/* continue logic */
		break;
	}

	err = blkdev_zone_mgmt(sb->s_bdev, REQ_OP_ZONE_OPEN,
				zone_sector, zone_size, GFP_NOFS);
	if (unlikely(err)) {
		SSDFS_ERR("fail to open zone: "
			  "zone_sector %llu, zone_size %llu, "
			  "err %d\n",
			  zone_sector, zone_size,
			  err);
		return err;
	}

	err = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (err != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, err);
		return err;
	}

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("zone after: start %llu, len %llu, wp %llu, "
		  "type %#x, cond %#x, non_seq %#x, "
		  "reset %#x, capacity %llu\n",
		  zone.start, zone.len, zone.wp,
		  zone.type, zone.cond, zone.non_seq,
		  zone.reset, zone.capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	switch (zone.cond) {
	case BLK_ZONE_COND_CLOSED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is closed: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;

	case BLK_ZONE_COND_READONLY:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is READ-ONLY: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;

	case BLK_ZONE_COND_FULL:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is full: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;

	case BLK_ZONE_COND_OFFLINE:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is offline: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;

	default:
		/* continue logic */
		break;
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("zone: start %llu, len %llu, wp %llu, "
		  "type %#x, cond %#x, non_seq %#x, "
		  "reset %#x, capacity %llu\n",
		  zone.start, zone.len, zone.wp,
		  zone.type, zone.cond, zone.non_seq,
		  zone.reset, zone.capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u64)zone.len << SECTOR_SHIFT;
}

/*
 * ssdfs_zns_zone_capacity() - retrieve zone capacity
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to retrieve zone capacity.
 */
u64 ssdfs_zns_zone_capacity(struct super_block *sb, loff_t offset)
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("zone: start %llu, len %llu, wp %llu, "
		  "type %#x, cond %#x, non_seq %#x, "
		  "reset %#x, capacity %llu\n",
		  zone.start, zone.len, zone.wp,
		  zone.type, zone.cond, zone.non_seq,
		  zone.reset, zone.capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	return (u64)zone.capacity << SECTOR_SHIFT;
}

/*
 * ssdfs_zns_zone_write_pointer() - retrieve zone's write pointer
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to retrieve zone's write pointer.
 */
u64 ssdfs_zns_zone_write_pointer(struct super_block *sb, loff_t offset)
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("zone: start %llu, len %llu, wp %llu, "
		  "type %#x, cond %#x, non_seq %#x, "
		  "reset %#x, capacity %llu\n",
		  zone.start, zone.len, zone.wp,
		  zone.type, zone.cond, zone.non_seq,
		  zone.reset, zone.capacity);
#endif /* CONFIG_SSDFS_DEBUG */

	if (zone.wp >= (zone.start + zone.capacity)) {
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is closed: "
			  "start %llu, len %llu, "
			  "wp %llu, type %#x, cond %#x, non_seq %#x, "
			  "reset %#x, capacity %llu\n",
			  zone.start, zone.len, zone.wp,
			  zone.type, zone.cond, zone.non_seq,
			  zone.reset, zone.capacity);
#endif /* CONFIG_SSDFS_DEBUG */
		return U64_MAX;
	}

	return (u64)zone.wp << SECTOR_SHIFT;
}

/*
 * ssdfs_zns_sync_page_request() - submit page request
 * @sb: superblock object
 * @page: memory page
 * @zone_start: first sector of zone
 * @offset: offset in bytes from partition's begin
 * @op: direction of I/O
 * @op_flags: request op flags
 */
static int ssdfs_zns_sync_page_request(struct super_block *sb,
					struct page *page,
					sector_t zone_start,
					loff_t offset,
					unsigned int op, int op_flags)
{
	struct bio *bio;
#ifdef CONFIG_SSDFS_DEBUG
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	struct blk_zone zone;
	int res;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

	op |= REQ_OP_ZONE_APPEND | REQ_IDLE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);

	SSDFS_DBG("offset %llu, zone_start %llu, "
		  "op %#x, op_flags %#x\n",
		  offset, zone_start, op, op_flags);

	res = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (res != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, res);
	} else {
		SSDFS_DBG("zone: start %llu, len %llu, wp %llu, "
			  "type %#x, cond %#x, non_seq %#x, "
			  "reset %#x, capacity %llu\n",
			  zone.start, zone.len, zone.wp,
			  zone.type, zone.cond, zone.non_seq,
			  zone.reset, zone.capacity);
	}

	BUG_ON(zone_start != zone.start);
#endif /* CONFIG_SSDFS_DEBUG */

	bio = ssdfs_bdev_bio_alloc(sb->s_bdev, 1, op, GFP_NOFS);
	if (IS_ERR_OR_NULL(bio)) {
		err = !bio ? -ERANGE : PTR_ERR(bio);
		SSDFS_ERR("fail to allocate bio: err %d\n",
			  err);
		return err;
	}

	bio->bi_iter.bi_sector = zone_start;
	bio_set_dev(bio, sb->s_bdev);
	bio->bi_opf = op | op_flags;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_bdev_bio_add_page(bio, page, PAGE_SIZE, 0);
	if (unlikely(err)) {
		SSDFS_ERR("fail to add page into bio: "
			  "err %d\n",
			  err);
		goto finish_sync_page_request;
	}

	err = submit_bio_wait(bio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to process request: "
			  "err %d\n",
			  err);
		goto finish_sync_page_request;
	}

finish_sync_page_request:
	ssdfs_bdev_bio_put(bio);

	return err;
}

/*
 * ssdfs_zns_sync_pvec_request() - submit pagevec request
 * @sb: superblock object
 * @pvec: pagevec
 * @zone_start: first sector of zone
 * @offset: offset in bytes from partition's begin
 * @op: direction of I/O
 * @op_flags: request op flags
 */
static int ssdfs_zns_sync_pvec_request(struct super_block *sb,
					struct pagevec *pvec,
					sector_t zone_start,
					loff_t offset,
					unsigned int op, int op_flags)
{
	struct bio *bio;
	int i;
#ifdef CONFIG_SSDFS_DEBUG
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	struct blk_zone zone;
	int res;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

	op |= REQ_OP_ZONE_APPEND | REQ_IDLE;

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec);

	SSDFS_DBG("offset %llu, zone_start %llu, "
		  "op %#x, op_flags %#x\n",
		  offset, zone_start, op, op_flags);

	res = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (res != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, res);
	} else {
		SSDFS_DBG("zone: start %llu, len %llu, wp %llu, "
			  "type %#x, cond %#x, non_seq %#x, "
			  "reset %#x, capacity %llu\n",
			  zone.start, zone.len, zone.wp,
			  zone.type, zone.cond, zone.non_seq,
			  zone.reset, zone.capacity);
	}

	BUG_ON(zone_start != zone.start);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(pvec) == 0) {
		SSDFS_WARN("empty page vector\n");
		return 0;
	}

	bio = ssdfs_bdev_bio_alloc(sb->s_bdev, pagevec_count(pvec),
				   op, GFP_NOFS);
	if (IS_ERR_OR_NULL(bio)) {
		err = !bio ? -ERANGE : PTR_ERR(bio);
		SSDFS_ERR("fail to allocate bio: err %d\n",
			  err);
		return err;
	}

	bio->bi_iter.bi_sector = zone_start;
	bio_set_dev(bio, sb->s_bdev);
	bio->bi_opf = op | op_flags;

	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);

		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

		err = ssdfs_bdev_bio_add_page(bio, page,
					      PAGE_SIZE,
					      0);
		if (unlikely(err)) {
			SSDFS_ERR("fail to add page %d into bio: "
				  "err %d\n",
				  i, err);
			goto finish_sync_pvec_request;
		}
	}

	err = submit_bio_wait(bio);
	if (unlikely(err)) {
		SSDFS_ERR("fail to process request: "
			  "err %d\n",
			  err);
		goto finish_sync_pvec_request;
	}

finish_sync_pvec_request:
	ssdfs_bdev_bio_put(bio);

	return err;
}

/*
 * ssdfs_zns_readpage() - read page from the volume
 * @sb: superblock object
 * @page: memory page
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to read data on @offset
 * from partition's begin in memory page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO         - I/O error.
 */
int ssdfs_zns_readpage(struct super_block *sb, struct page *page,
			loff_t offset)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct blk_zone zone;
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	int res;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu\n",
		  sb, (unsigned long long)offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_bdev_readpage(sb, page, offset);

#ifdef CONFIG_SSDFS_DEBUG
	res = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (res != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, res);
	} else {
		SSDFS_DBG("zone: start %llu, len %llu, wp %llu, "
			  "type %#x, cond %#x, non_seq %#x, "
			  "reset %#x, capacity %llu\n",
			  zone.start, zone.len, zone.wp,
			  zone.type, zone.cond, zone.non_seq,
			  zone.reset, zone.capacity);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_zns_readpages() - read pages from the volume
 * @sb: superblock object
 * @pvec: pagevec
 * @offset: offset in bytes from partition's begin
 *
 * This function tries to read data on @offset
 * from partition's begin in memory page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO         - I/O error.
 */
int ssdfs_zns_readpages(struct super_block *sb, struct pagevec *pvec,
			 loff_t offset)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct blk_zone zone;
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	int res;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu\n",
		  sb, (unsigned long long)offset);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_bdev_readpages(sb, pvec, offset);

#ifdef CONFIG_SSDFS_DEBUG
	res = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (res != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, res);
	} else {
		SSDFS_DBG("zone: start %llu, len %llu, wp %llu, "
			  "type %#x, cond %#x, non_seq %#x, "
			  "reset %#x, capacity %llu\n",
			  zone.start, zone.len, zone.wp,
			  zone.type, zone.cond, zone.non_seq,
			  zone.reset, zone.capacity);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_zns_read() - read from volume into buffer
 * @sb: superblock object
 * @offset: offset in bytes from partition's begin
 * @len: size of buffer in bytes
 * @buf: buffer
 *
 * This function tries to read data on @offset
 * from partition's begin with @len bytes in size
 * from the volume into @buf.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EIO         - I/O error.
 */
int ssdfs_zns_read(struct super_block *sb, loff_t offset,
		   size_t len, void *buf)
{
#ifdef CONFIG_SSDFS_DEBUG
	struct blk_zone zone;
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	int res;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, len %zu, buf %p\n",
		  sb, (unsigned long long)offset, len, buf);
#endif /* CONFIG_SSDFS_DEBUG */

	err = ssdfs_bdev_read(sb, offset, len, buf);

#ifdef CONFIG_SSDFS_DEBUG
	res = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (res != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, res);
	} else {
		SSDFS_DBG("zone: start %llu, len %llu, wp %llu, "
			  "type %#x, cond %#x, non_seq %#x, "
			  "reset %#x, capacity %llu\n",
			  zone.start, zone.len, zone.wp,
			  zone.type, zone.cond, zone.non_seq,
			  zone.reset, zone.capacity);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
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
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct blk_zone zone;
	sector_t zone_sector = offset >> SECTOR_SHIFT;
	sector_t zone_size = fsi->erasesize >> SECTOR_SHIFT;
	u64 peb_id;
	loff_t zone_offset;
	int res;
	int err = 0;

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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("zone before: start %llu, len %llu, wp %llu, "
		  "type %#x, cond %#x, non_seq %#x, "
		  "reset %#x, capacity %llu\n",
		  zone.start, zone.len, zone.wp,
		  zone.type, zone.cond, zone.non_seq,
		  zone.reset, zone.capacity);
#endif /* CONFIG_SSDFS_DEBUG */

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
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is empty: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return 0;

	case BLK_ZONE_COND_CLOSED:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is closed: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */

		peb_id = offset / fsi->erasesize;
		zone_offset = peb_id * fsi->erasesize;

		err = ssdfs_zns_reopen_zone(sb, zone_offset);
		if (unlikely(err)) {
			SSDFS_ERR("fail to reopen zone: "
				  "zone_offset %llu, zone_size %llu, "
				  "err %d\n",
				  zone_offset, zone_size, err);
			return err;
		}

		return 0;

	case BLK_ZONE_COND_READONLY:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is READ-ONLY: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;

	case BLK_ZONE_COND_FULL:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is full: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;

	case BLK_ZONE_COND_OFFLINE:
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("zone is offline: offset %llu\n",
			  offset);
#endif /* CONFIG_SSDFS_DEBUG */
		return -EIO;

	default:
		/* continue logic */
		break;
	}

	if (zone_sector < zone.wp) {
		err = -EIO;
#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("cannot be written: "
			  "zone_sector %llu, zone.wp %llu\n",
			  zone_sector, zone.wp);
#endif /* CONFIG_SSDFS_DEBUG */
	}

#ifdef CONFIG_SSDFS_DEBUG
	res = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (res != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, res);
	} else {
		SSDFS_DBG("zone after: start %llu, len %llu, wp %llu, "
			  "type %#x, cond %#x, non_seq %#x, "
			  "reset %#x, capacity %llu\n",
			  zone.start, zone.len, zone.wp,
			  zone.type, zone.cond, zone.non_seq,
			  zone.reset, zone.capacity);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_zns_writepage() - write memory page on volume
 * @sb: superblock object
 * @to_off: offset in bytes from partition's begin
 * @page: memory page
 * @from_off: offset in bytes from page's begin
 * @len: size of data in bytes
 *
 * This function tries to write from @page data of @len size
 * on @offset from partition's begin in memory page.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EIO         - I/O error.
 */
int ssdfs_zns_writepage(struct super_block *sb, loff_t to_off,
			struct page *page, u32 from_off, size_t len)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	loff_t zone_start;
#ifdef CONFIG_SSDFS_DEBUG
	struct blk_zone zone;
	sector_t zone_sector = to_off >> SECTOR_SHIFT;
	u32 remainder;
	int res;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, to_off %llu, page %p, from_off %u, len %zu\n",
		  sb, to_off, page, from_off, len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (sb->s_flags & SB_RDONLY) {
		SSDFS_WARN("unable to write on RO file system\n");
		return -EROFS;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!page);
	BUG_ON((to_off >= ssdfs_zns_device_size(sb)) ||
		(len > (ssdfs_zns_device_size(sb) - to_off)));
	BUG_ON(len == 0);
	div_u64_rem((u64)to_off, (u64)fsi->pagesize, &remainder);
	BUG_ON(remainder);
	BUG_ON((from_off + len) > PAGE_SIZE);
	BUG_ON(!PageDirty(page));
	BUG_ON(PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

	ssdfs_lock_page(page);
	atomic_inc(&fsi->pending_bios);

	zone_start = (to_off / fsi->erasesize) * fsi->erasesize;
	zone_start >>= SECTOR_SHIFT;

	err = ssdfs_zns_sync_page_request(sb, page, zone_start, to_off,
					  REQ_OP_WRITE, REQ_SYNC);
	if (err) {
		SetPageError(page);
		SSDFS_ERR("failed to write (err %d): offset %llu\n",
			  err, (unsigned long long)to_off);
	} else {
		ssdfs_clear_dirty_page(page);
		SetPageUptodate(page);
		ClearPageError(page);
	}

	ssdfs_unlock_page(page);
	ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("page %p, count %d\n",
		  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */

	if (atomic_dec_and_test(&fsi->pending_bios))
		wake_up_all(&zns_wq);

#ifdef CONFIG_SSDFS_DEBUG
	res = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (res != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, res);
	} else {
		SSDFS_DBG("zone: start %llu, len %llu, wp %llu, "
			  "type %#x, cond %#x, non_seq %#x, "
			  "reset %#x, capacity %llu\n",
			  zone.start, zone.len, zone.wp,
			  zone.type, zone.cond, zone.non_seq,
			  zone.reset, zone.capacity);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
}

/*
 * ssdfs_zns_writepages() - write pagevec on volume
 * @sb: superblock object
 * @to_off: offset in bytes from partition's begin
 * @pvec: memory pages vector
 * @from_off: offset in bytes from page's begin
 * @len: size of data in bytes
 *
 * This function tries to write from @pvec data of @len size
 * on @offset from partition's begin.
 *
 * RETURN:
 * [success]
 * [failure] - error code:
 *
 * %-EROFS       - file system in RO mode.
 * %-EIO         - I/O error.
 */
int ssdfs_zns_writepages(struct super_block *sb, loff_t to_off,
			 struct pagevec *pvec,
			 u32 from_off, size_t len)
{
	struct ssdfs_fs_info *fsi = SSDFS_FS_I(sb);
	struct page *page;
	loff_t zone_start;
	int i;
#ifdef CONFIG_SSDFS_DEBUG
	struct blk_zone zone;
	sector_t zone_sector = to_off >> SECTOR_SHIFT;
	u32 remainder;
	int res;
#endif /* CONFIG_SSDFS_DEBUG */
	int err = 0;

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, to_off %llu, pvec %p, from_off %u, len %zu\n",
		  sb, to_off, pvec, from_off, len);
#endif /* CONFIG_SSDFS_DEBUG */

	if (sb->s_flags & SB_RDONLY) {
		SSDFS_WARN("unable to write on RO file system\n");
		return -EROFS;
	}

#ifdef CONFIG_SSDFS_DEBUG
	BUG_ON(!pvec);
	BUG_ON((to_off >= ssdfs_zns_device_size(sb)) ||
		(len > (ssdfs_zns_device_size(sb) - to_off)));
	BUG_ON(len == 0);
	div_u64_rem((u64)to_off, (u64)fsi->pagesize, &remainder);
	BUG_ON(remainder);
#endif /* CONFIG_SSDFS_DEBUG */

	if (pagevec_count(pvec) == 0) {
		SSDFS_WARN("empty pagevec\n");
		return 0;
	}

	for (i = 0; i < pagevec_count(pvec); i++) {
		page = pvec->pages[i];

#ifdef CONFIG_SSDFS_DEBUG
		BUG_ON(!page);
		BUG_ON(!PageDirty(page));
		BUG_ON(PageLocked(page));
#endif /* CONFIG_SSDFS_DEBUG */

		ssdfs_lock_page(page);
	}

	atomic_inc(&fsi->pending_bios);

	zone_start = (to_off / fsi->erasesize) * fsi->erasesize;
	zone_start >>= SECTOR_SHIFT;

	err = ssdfs_zns_sync_pvec_request(sb, pvec, zone_start, to_off,
					  REQ_OP_WRITE, REQ_SYNC);

	for (i = 0; i < pagevec_count(pvec); i++) {
		page = pvec->pages[i];

		if (err) {
			SetPageError(page);
			SSDFS_ERR("failed to write (err %d): "
				  "page_index %llu\n",
				  err,
				  (unsigned long long)page_index(page));
		} else {
			ssdfs_clear_dirty_page(page);
			SetPageUptodate(page);
			ClearPageError(page);
		}

		ssdfs_unlock_page(page);
		ssdfs_put_page(page);

#ifdef CONFIG_SSDFS_DEBUG
		SSDFS_DBG("page %p, count %d\n",
			  page, page_ref_count(page));
#endif /* CONFIG_SSDFS_DEBUG */
	}

	if (atomic_dec_and_test(&fsi->pending_bios))
		wake_up_all(&zns_wq);

#ifdef CONFIG_SSDFS_DEBUG
	res = blkdev_report_zones(sb->s_bdev, zone_sector, 1,
				  ssdfs_report_zone, &zone);
	if (res != 1) {
		SSDFS_ERR("fail to take report zone: "
			  "zone_sector %llu, err %d\n",
			  zone_sector, res);
	} else {
		SSDFS_DBG("zone: start %llu, len %llu, wp %llu, "
			  "type %#x, cond %#x, non_seq %#x, "
			  "reset %#x, capacity %llu\n",
			  zone.start, zone.len, zone.wp,
			  zone.type, zone.cond, zone.non_seq,
			  zone.reset, zone.capacity);
	}
#endif /* CONFIG_SSDFS_DEBUG */

	return err;
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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("sb %p, offset %llu, len %zu\n",
		  sb, (unsigned long long)offset, len);

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

#ifdef CONFIG_SSDFS_DEBUG
	SSDFS_DBG("device %s\n", sb->s_id);
#endif /* CONFIG_SSDFS_DEBUG */

	wait_event(zns_wq, atomic_read(&fsi->pending_bios) == 0);
}

const struct ssdfs_device_ops ssdfs_zns_devops = {
	.device_name		= ssdfs_zns_device_name,
	.device_size		= ssdfs_zns_device_size,
	.open_zone		= ssdfs_zns_open_zone,
	.reopen_zone		= ssdfs_zns_reopen_zone,
	.close_zone		= ssdfs_zns_close_zone,
	.read			= ssdfs_zns_read,
	.readpage		= ssdfs_zns_readpage,
	.readpages		= ssdfs_zns_readpages,
	.can_write_page		= ssdfs_zns_can_write_page,
	.writepage		= ssdfs_zns_writepage,
	.writepages		= ssdfs_zns_writepages,
	.erase			= ssdfs_zns_trim,
	.trim			= ssdfs_zns_trim,
	.peb_isbad		= ssdfs_zns_peb_isbad,
	.mark_peb_bad		= ssdfs_zns_mark_peb_bad,
	.sync			= ssdfs_zns_sync,
};
