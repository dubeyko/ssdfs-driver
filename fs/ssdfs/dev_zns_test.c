// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dev_zns_test.c - KUnit tests for ZNS SSD support code.
 *
 * Copyright (c) 2026 Viacheslav Dubeyko <slava@dubeyko.com>
 *              http://www.ssdfs.org/
 * All rights reserved.
 *
 * Authors: Viacheslav Dubeyko <slava@dubeyko.com>
 */

#include <kunit/test.h>
#include <kunit/static_stub.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/folio_batch.h>

#include "peb_mapping_queue.h"
#include "peb_mapping_table_cache.h"
#include "folio_vector.h"
#include "ssdfs.h"

/*
 * Test cases for ssdfs_zns_calc_zone_start()
 */
static void test_calc_zone_start_zero_offset(struct kunit *test)
{
	sector_t sector;
	u32 erasesize = 2 * 1024 * 1024; /* 2 MiB */

	sector = ssdfs_zns_calc_zone_start(0, erasesize);
	KUNIT_EXPECT_EQ(test, 0, sector);
}

static void test_calc_zone_start_within_first_zone(struct kunit *test)
{
	sector_t sector;
	u32 erasesize = 2 * 1024 * 1024; /* 2 MiB */

	/* any offset short of the second zone still maps to zone 0 */
	sector = ssdfs_zns_calc_zone_start(100, erasesize);
	KUNIT_EXPECT_EQ(test, 0, sector);
}

static void test_calc_zone_start_second_zone(struct kunit *test)
{
	sector_t sector;
	u32 erasesize = 2 * 1024 * 1024; /* 2 MiB */

	sector = ssdfs_zns_calc_zone_start(erasesize, erasesize);
	KUNIT_EXPECT_EQ(test, (sector_t)erasesize >> SECTOR_SHIFT, sector);
}

static void test_calc_zone_start_middle_of_second_zone(struct kunit *test)
{
	sector_t sector;
	u32 erasesize = 2 * 1024 * 1024; /* 2 MiB */

	/* an offset in the middle of zone 1 truncates down to its start */
	sector = ssdfs_zns_calc_zone_start(erasesize + 12345, erasesize);
	KUNIT_EXPECT_EQ(test, (sector_t)erasesize >> SECTOR_SHIFT, sector);
}

static void test_calc_zone_start_third_zone(struct kunit *test)
{
	sector_t sector;
	u32 erasesize = 2 * 1024 * 1024; /* 2 MiB */

	sector = ssdfs_zns_calc_zone_start(3 * (loff_t)erasesize + 500,
					   erasesize);
	KUNIT_EXPECT_EQ(test, (sector_t)(3ULL * erasesize) >> SECTOR_SHIFT,
			sector);
}

/*
 * Test cases for ssdfs_zns_calc_trim_range()
 */
static void test_calc_trim_range_valid(struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	int err;

	err = ssdfs_zns_calc_trim_range(0, erase_size, erase_size,
					&start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, start_sector);
	KUNIT_EXPECT_EQ(test, erase_size >> SECTOR_SHIFT, sectors_count);
}

static void test_calc_trim_range_second_erase_block(struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	int err;

	err = ssdfs_zns_calc_trim_range(erase_size, erase_size, erase_size,
					&start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, (sector_t)erase_size >> SECTOR_SHIFT,
			start_sector);
	KUNIT_EXPECT_EQ(test, erase_size >> SECTOR_SHIFT, sectors_count);
}

static void test_calc_trim_range_multiple_erase_blocks(struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	int err;

	/*
	 * Unlike ssdfs_bdev_calc_trim_range(), the ZNS variant always
	 * resets exactly one erase block's worth of sectors starting at
	 * @offset: @len only participates in the alignment/emptiness
	 * validation, it isn't folded into @sectors_count. This test
	 * pins down that (pre-existing) behaviour.
	 */
	err = ssdfs_zns_calc_trim_range(0, 3 * (size_t)erase_size, erase_size,
					&start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, start_sector);
	KUNIT_EXPECT_EQ(test, erase_size >> SECTOR_SHIFT, sectors_count);
}

static void test_calc_trim_range_unaligned_len(struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	int err;

	err = ssdfs_zns_calc_trim_range(0, erase_size + 1, erase_size,
					&start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, -ERANGE, err);
}

static void test_calc_trim_range_zero_len(struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	int err;

	/* len == 0 is aligned (remainder 0), but yields zero pages */
	err = ssdfs_zns_calc_trim_range(0, 0, erase_size,
					&start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, -ERANGE, err);
}

static void test_calc_trim_range_start_sector_uses_raw_offset(
							struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	loff_t offset = 5000; /* not page- nor zone-aligned */
	int err;

	/*
	 * @start_sector must come straight from @offset, not from a
	 * PAGE_SIZE-rounded quantity (which would give a different,
	 * smaller sector here).
	 */
	err = ssdfs_zns_calc_trim_range(offset, erase_size, erase_size,
					&start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, (sector_t)offset >> SECTOR_SHIFT, start_sector);
}

/*
 * Test cases for ssdfs_zns_track_zone_open()
 */
static void test_track_zone_open_under_limit(struct kunit *test)
{
	atomic_t open_zones = ATOMIC_INIT(0);
	int err;

	err = ssdfs_zns_track_zone_open(&open_zones, 5);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 1, atomic_read(&open_zones));
}

static void test_track_zone_open_at_limit(struct kunit *test)
{
	atomic_t open_zones = ATOMIC_INIT(2);
	int err;

	/* current value (2) != max_open_zones (3): incremented to 3 */
	err = ssdfs_zns_track_zone_open(&open_zones, 3);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 3, atomic_read(&open_zones));
}

static void test_track_zone_open_exceeds_limit(struct kunit *test)
{
	atomic_t open_zones = ATOMIC_INIT(3);
	int err;

	/* current value (3) == max_open_zones (3): rejected, not touched */
	err = ssdfs_zns_track_zone_open(&open_zones, 3);
	KUNIT_EXPECT_EQ(test, -EBUSY, err);
	KUNIT_EXPECT_EQ(test, 3, atomic_read(&open_zones));
}

/*
 * Test cases for ssdfs_zns_decide_write_permission()
 */
static void test_decide_write_permission_conventional_zone(
							struct kunit *test)
{
	struct blk_zone zone = {};
	int res;

	zone.type = BLK_ZONE_TYPE_CONVENTIONAL;
	/* cond deliberately set to a value that would mean
	 * SSDFS_ZNS_WRITE_DENIED for a zoned type, to prove the type
	 * check short-circuits first.
	 */
	zone.cond = BLK_ZONE_COND_FULL;

	res = ssdfs_zns_decide_write_permission(&zone, 0);
	KUNIT_EXPECT_EQ(test, SSDFS_ZNS_WRITE_NEEDS_BDEV_CHECK, res);
}

static void test_decide_write_permission_not_wp(struct kunit *test)
{
	struct blk_zone zone = {};
	int res;

	zone.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	zone.cond = BLK_ZONE_COND_NOT_WP;

	res = ssdfs_zns_decide_write_permission(&zone, 0);
	KUNIT_EXPECT_EQ(test, SSDFS_ZNS_WRITE_NEEDS_BDEV_CHECK, res);
}

static void test_decide_write_permission_empty_zone(struct kunit *test)
{
	struct blk_zone zone = {};
	int res;

	zone.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	zone.cond = BLK_ZONE_COND_EMPTY;

	res = ssdfs_zns_decide_write_permission(&zone, 0);
	KUNIT_EXPECT_EQ(test, SSDFS_ZNS_WRITE_OK, res);
}

static void test_decide_write_permission_closed_zone(struct kunit *test)
{
	struct blk_zone zone = {};
	int res;

	zone.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	zone.cond = BLK_ZONE_COND_CLOSED;

	res = ssdfs_zns_decide_write_permission(&zone, 0);
	KUNIT_EXPECT_EQ(test, SSDFS_ZNS_WRITE_NEEDS_REOPEN, res);
}

static void test_decide_write_permission_readonly_zone(struct kunit *test)
{
	struct blk_zone zone = {};
	int res;

	zone.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	zone.cond = BLK_ZONE_COND_READONLY;

	res = ssdfs_zns_decide_write_permission(&zone, 0);
	KUNIT_EXPECT_EQ(test, SSDFS_ZNS_WRITE_DENIED, res);
}

static void test_decide_write_permission_full_zone(struct kunit *test)
{
	struct blk_zone zone = {};
	int res;

	zone.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	zone.cond = BLK_ZONE_COND_FULL;

	res = ssdfs_zns_decide_write_permission(&zone, 0);
	KUNIT_EXPECT_EQ(test, SSDFS_ZNS_WRITE_DENIED, res);
}

static void test_decide_write_permission_offline_zone(struct kunit *test)
{
	struct blk_zone zone = {};
	int res;

	zone.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	zone.cond = BLK_ZONE_COND_OFFLINE;

	res = ssdfs_zns_decide_write_permission(&zone, 0);
	KUNIT_EXPECT_EQ(test, SSDFS_ZNS_WRITE_DENIED, res);
}

static void test_decide_write_permission_open_zone_before_wp(
							struct kunit *test)
{
	struct blk_zone zone = {};
	int res;

	zone.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	zone.cond = BLK_ZONE_COND_IMP_OPEN;
	zone.wp = 100;

	res = ssdfs_zns_decide_write_permission(&zone, 50);
	KUNIT_EXPECT_EQ(test, SSDFS_ZNS_WRITE_DENIED, res);
}

static void test_decide_write_permission_open_zone_at_wp(struct kunit *test)
{
	struct blk_zone zone = {};
	int res;

	zone.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	zone.cond = BLK_ZONE_COND_EXP_OPEN;
	zone.wp = 100;

	/* writing right at the write pointer is allowed */
	res = ssdfs_zns_decide_write_permission(&zone, 100);
	KUNIT_EXPECT_EQ(test, SSDFS_ZNS_WRITE_OK, res);
}

/*
 * Test cases for the trivial ssdfs_zns_devops callbacks
 */
static void test_devops_peb_isbad_always_good(struct kunit *test)
{
	int err;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssdfs_zns_devops.peb_isbad);
	err = ssdfs_zns_devops.peb_isbad(NULL, 0);
	KUNIT_EXPECT_EQ(test, 0, err);
}

static void test_devops_mark_peb_bad_is_noop(struct kunit *test)
{
	int err;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssdfs_zns_devops.mark_peb_bad);
	err = ssdfs_zns_devops.mark_peb_bad(NULL, 0);
	KUNIT_EXPECT_EQ(test, 0, err);
}

static void test_devops_device_name(struct kunit *test)
{
	struct super_block *sb;
	const char *name;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssdfs_zns_devops.device_name);

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	strscpy(sb->s_id, "nvme0n1", sizeof(sb->s_id));

	name = ssdfs_zns_devops.device_name(sb);
	KUNIT_EXPECT_STREQ(test, "nvme0n1", name);

	kfree(sb);
}

/*
 * Test cases for the ssdfs_zns_sync_folio_request()/
 * ssdfs_zns_sync_batch_request() static stub redirect, and for
 * ssdfs_zns_write_block()/ssdfs_zns_write_blocks(), exercised
 * end-to-end via that same redirect (reached through the exported
 * ssdfs_zns_devops table, since the functions themselves stay static).
 */
static int fake_zns_sync_folio_request_success(struct super_block *sb,
						struct folio *folio,
						sector_t zone_start,
						loff_t offset,
						unsigned int op, int op_flags)
{
	return 0;
}

static int fake_zns_sync_folio_request_error(struct super_block *sb,
					      struct folio *folio,
					      sector_t zone_start,
					      loff_t offset,
					      unsigned int op, int op_flags)
{
	return -EIO;
}

static int fake_zns_sync_batch_request_success(struct super_block *sb,
						struct folio_batch *batch,
						sector_t zone_start,
						loff_t offset,
						unsigned int op, int op_flags)
{
	return 0;
}

static int fake_zns_sync_batch_request_error(struct super_block *sb,
					      struct folio_batch *batch,
					      sector_t zone_start,
					      loff_t offset,
					      unsigned int op, int op_flags)
{
	return -EIO;
}

static void test_sync_folio_request_redirect_success(struct kunit *test)
{
	int err;

	kunit_activate_static_stub(test, ssdfs_zns_sync_folio_request,
				   fake_zns_sync_folio_request_success);

	/*
	 * Without the redirect this would build a real bio and call
	 * submit_bio_wait() against an unusable fake block device. The
	 * static stub prologue fires before any of that happens.
	 */
	err = ssdfs_zns_sync_folio_request(NULL, NULL, 0, 0,
					   REQ_OP_WRITE, REQ_SYNC);
	KUNIT_EXPECT_EQ(test, 0, err);
}

static void test_sync_folio_request_redirect_propagates_error(
							struct kunit *test)
{
	int err;

	kunit_activate_static_stub(test, ssdfs_zns_sync_folio_request,
				   fake_zns_sync_folio_request_error);

	err = ssdfs_zns_sync_folio_request(NULL, NULL, 0, 0,
					   REQ_OP_WRITE, REQ_SYNC);
	KUNIT_EXPECT_EQ(test, -EIO, err);
}

static void test_sync_batch_request_redirect_success(struct kunit *test)
{
	int err;

	kunit_activate_static_stub(test, ssdfs_zns_sync_batch_request,
				   fake_zns_sync_batch_request_success);

	err = ssdfs_zns_sync_batch_request(NULL, NULL, 0, 0,
					   REQ_OP_WRITE, REQ_SYNC);
	KUNIT_EXPECT_EQ(test, 0, err);
}

static void test_sync_batch_request_redirect_propagates_error(
							struct kunit *test)
{
	int err;

	kunit_activate_static_stub(test, ssdfs_zns_sync_batch_request,
				   fake_zns_sync_batch_request_error);

	err = ssdfs_zns_sync_batch_request(NULL, NULL, 0, 0,
					   REQ_OP_WRITE, REQ_SYNC);
	KUNIT_EXPECT_EQ(test, -EIO, err);
}

static void test_write_block_fails_on_readonly_fs(struct kunit *test)
{
	struct super_block *sb;
	int err;

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	sb->s_flags |= SB_RDONLY;

	/*
	 * The RO check happens before folio/fsi are touched, so it is
	 * safe to leave sb->s_fs_info unset and pass folio == NULL.
	 */
	err = ssdfs_zns_devops.write_block(sb, 0, NULL, SSDFS_FDP_STREAM_NONE);
	KUNIT_EXPECT_EQ(test, -EROFS, err);

	kfree(sb);
}

static void test_write_blocks_fails_on_readonly_fs(struct kunit *test)
{
	struct super_block *sb;
	int err;

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	sb->s_flags |= SB_RDONLY;

	err = ssdfs_zns_devops.write_blocks(sb, 0, NULL,
					    SSDFS_FDP_STREAM_NONE);
	KUNIT_EXPECT_EQ(test, -EROFS, err);

	kfree(sb);
}

static void test_write_blocks_empty_batch_is_noop(struct kunit *test)
{
	struct super_block *sb;
	struct ssdfs_fs_info *fsi;
	struct folio_batch batch;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	/*
	 * Under CONFIG_SSDFS_DEBUG, ssdfs_zns_write_blocks() runs a
	 * BUG_ON(offset >= ssdfs_zns_device_size(sb)) between the RO
	 * check and the empty-batch check, and device_size() derefs
	 * sb->s_bdev. This test doesn't fake a real zoned block device,
	 * so skip it in debug builds rather than crash the test run.
	 */
	kunit_skip(test, "requires !CONFIG_SSDFS_DEBUG (BUG_ON derefs sb->s_bdev)");
	return;
#endif /* CONFIG_SSDFS_DEBUG */

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, fsi);
	sb->s_fs_info = fsi;
	sb->s_flags = 0;

	folio_batch_init(&batch);

	err = ssdfs_zns_devops.write_blocks(sb, 0, &batch,
					    SSDFS_FDP_STREAM_NONE);
	KUNIT_EXPECT_EQ(test, 0, err);

	kfree(sb);
	kfree(fsi);
}

static void test_write_block_end_to_end_success(struct kunit *test)
{
	struct super_block *sb;
	struct ssdfs_fs_info *fsi;
	struct folio *folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	/*
	 * Under CONFIG_SSDFS_DEBUG, ssdfs_zns_write_block() runs a
	 * BUG_ON() range check against ssdfs_zns_device_size(sb), which
	 * derefs sb->s_bdev. This test doesn't fake a real zoned block
	 * device, so skip it in debug builds.
	 */
	kunit_skip(test, "requires !CONFIG_SSDFS_DEBUG (BUG_ON derefs sb->s_bdev)");
	return;
#endif /* CONFIG_SSDFS_DEBUG */

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, fsi);
	sb->s_fs_info = fsi;
	sb->s_flags = 0;
	fsi->erasesize = 2 * 1024 * 1024; /* 2 MiB */
	atomic_set(&fsi->pending_bios, 0);

	folio = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);
	folio_mark_dirty(folio);
	/* extra ref: ssdfs_zns_write_block() consumes one via ssdfs_folio_put() */
	folio_get(folio);

	kunit_activate_static_stub(test, ssdfs_zns_sync_folio_request,
				   fake_zns_sync_folio_request_success);

	/* ssdfs_zns_write_block() locks the folio itself */
	err = ssdfs_zns_devops.write_block(sb, 0, folio, SSDFS_FDP_STREAM_NONE);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio));
	KUNIT_EXPECT_TRUE(test, folio_test_uptodate(folio));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio));

	folio_put(folio);
	kfree(fsi);
	kfree(sb);
}

static void test_write_block_end_to_end_error(struct kunit *test)
{
	struct super_block *sb;
	struct ssdfs_fs_info *fsi;
	struct folio *folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	kunit_skip(test, "requires !CONFIG_SSDFS_DEBUG (BUG_ON derefs sb->s_bdev)");
	return;
#endif /* CONFIG_SSDFS_DEBUG */

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, fsi);
	sb->s_fs_info = fsi;
	sb->s_flags = 0;
	fsi->erasesize = 2 * 1024 * 1024; /* 2 MiB */
	atomic_set(&fsi->pending_bios, 0);

	folio = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);
	folio_mark_dirty(folio);
	folio_get(folio);

	kunit_activate_static_stub(test, ssdfs_zns_sync_folio_request,
				   fake_zns_sync_folio_request_error);

	err = ssdfs_zns_devops.write_block(sb, 0, folio, SSDFS_FDP_STREAM_NONE);
	KUNIT_EXPECT_EQ(test, -EIO, err);
	/* on error the dirty flag is left untouched (still dirty) */
	KUNIT_EXPECT_TRUE(test, folio_test_dirty(folio));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio));

	folio_put(folio);
	kfree(fsi);
	kfree(sb);
}

static void test_write_blocks_end_to_end_success(struct kunit *test)
{
	struct super_block *sb;
	struct ssdfs_fs_info *fsi;
	struct folio_batch batch;
	struct folio *folio1, *folio2;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	kunit_skip(test, "requires !CONFIG_SSDFS_DEBUG (BUG_ON derefs sb->s_bdev)");
	return;
#endif /* CONFIG_SSDFS_DEBUG */

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, fsi);
	sb->s_fs_info = fsi;
	sb->s_flags = 0;
	fsi->erasesize = 2 * 1024 * 1024; /* 2 MiB */
	atomic_set(&fsi->pending_bios, 0);

	folio1 = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio2 = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	folio_mark_dirty(folio1);
	folio_mark_dirty(folio2);
	/* extra refs: ssdfs_zns_write_blocks() consumes one each */
	folio_get(folio1);
	folio_get(folio2);

	folio_batch_init(&batch);
	folio_batch_add(&batch, folio1);
	folio_batch_add(&batch, folio2);

	kunit_activate_static_stub(test, ssdfs_zns_sync_batch_request,
				   fake_zns_sync_batch_request_success);

	/* ssdfs_zns_write_blocks() locks each folio itself */
	err = ssdfs_zns_devops.write_blocks(sb, 0, &batch,
					    SSDFS_FDP_STREAM_NONE);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio1));
	KUNIT_EXPECT_FALSE(test, folio_test_dirty(folio2));
	KUNIT_EXPECT_TRUE(test, folio_test_uptodate(folio1));
	KUNIT_EXPECT_TRUE(test, folio_test_uptodate(folio2));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio1));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio2));

	folio_put(folio1);
	folio_put(folio2);
	kfree(fsi);
	kfree(sb);
}

static void test_write_blocks_end_to_end_error(struct kunit *test)
{
	struct super_block *sb;
	struct ssdfs_fs_info *fsi;
	struct folio_batch batch;
	struct folio *folio1;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	kunit_skip(test, "requires !CONFIG_SSDFS_DEBUG (BUG_ON derefs sb->s_bdev)");
	return;
#endif /* CONFIG_SSDFS_DEBUG */

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, fsi);
	sb->s_fs_info = fsi;
	sb->s_flags = 0;
	fsi->erasesize = 2 * 1024 * 1024; /* 2 MiB */
	atomic_set(&fsi->pending_bios, 0);

	folio1 = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio_mark_dirty(folio1);
	folio_get(folio1);

	folio_batch_init(&batch);
	folio_batch_add(&batch, folio1);

	kunit_activate_static_stub(test, ssdfs_zns_sync_batch_request,
				   fake_zns_sync_batch_request_error);

	err = ssdfs_zns_devops.write_blocks(sb, 0, &batch,
					    SSDFS_FDP_STREAM_NONE);
	KUNIT_EXPECT_EQ(test, -EIO, err);
	KUNIT_EXPECT_TRUE(test, folio_test_dirty(folio1));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio1));

	folio_put(folio1);
	kfree(fsi);
	kfree(sb);
}

/*
 * Test cases for the ssdfs_zns_read_block()/ssdfs_zns_read_blocks()
 * delegation to the (already thoroughly tested in dev_bdev_test.c)
 * ssdfs_bdev_read_block()/ssdfs_bdev_read_blocks() implementation.
 * These just confirm the ZNS wrapper wires through correctly, reusing
 * the cross-module static stub that dev_bdev.c already exports.
 */
static int fake_bdev_sync_folio_request_success(struct super_block *sb,
						 struct folio *folio,
						 loff_t offset,
						 unsigned int op,
						 int op_flags,
						 u8 write_stream)
{
	return 0;
}

static int fake_bdev_sync_folio_request_error(struct super_block *sb,
					       struct folio *folio,
					       loff_t offset,
					       unsigned int op,
					       int op_flags,
					       u8 write_stream)
{
	return -EIO;
}

static void test_read_block_delegates_to_bdev_success(struct kunit *test)
{
	struct folio *folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	/*
	 * Under CONFIG_SSDFS_DEBUG, ssdfs_zns_read_block() takes a
	 * debug-only blkdev_report_zones() snapshot after the read,
	 * which derefs sb->s_bdev.
	 */
	kunit_skip(test, "requires !CONFIG_SSDFS_DEBUG (derefs sb->s_bdev)");
	return;
#endif /* CONFIG_SSDFS_DEBUG */

	folio = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);
	folio_lock(folio);

	kunit_activate_static_stub(test, ssdfs_bdev_sync_folio_request,
				   fake_bdev_sync_folio_request_success);

	err = ssdfs_zns_devops.read_block(NULL, folio, 0);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_TRUE(test, folio_test_uptodate(folio));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio));

	folio_put(folio);
}

static void test_read_block_delegates_to_bdev_error(struct kunit *test)
{
	struct folio *folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	kunit_skip(test, "requires !CONFIG_SSDFS_DEBUG (derefs sb->s_bdev)");
	return;
#endif /* CONFIG_SSDFS_DEBUG */

	folio = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);
	folio_lock(folio);
	folio_mark_uptodate(folio);

	kunit_activate_static_stub(test, ssdfs_bdev_sync_folio_request,
				   fake_bdev_sync_folio_request_error);

	err = ssdfs_zns_devops.read_block(NULL, folio, 0);
	KUNIT_EXPECT_EQ(test, -EIO, err);
	KUNIT_EXPECT_FALSE(test, folio_test_uptodate(folio));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio));

	folio_put(folio);
}

static struct kunit_case dev_zns_test_cases[] = {
	KUNIT_CASE(test_calc_zone_start_zero_offset),
	KUNIT_CASE(test_calc_zone_start_within_first_zone),
	KUNIT_CASE(test_calc_zone_start_second_zone),
	KUNIT_CASE(test_calc_zone_start_middle_of_second_zone),
	KUNIT_CASE(test_calc_zone_start_third_zone),
	KUNIT_CASE(test_calc_trim_range_valid),
	KUNIT_CASE(test_calc_trim_range_second_erase_block),
	KUNIT_CASE(test_calc_trim_range_multiple_erase_blocks),
	KUNIT_CASE(test_calc_trim_range_unaligned_len),
	KUNIT_CASE(test_calc_trim_range_zero_len),
	KUNIT_CASE(test_calc_trim_range_start_sector_uses_raw_offset),
	KUNIT_CASE(test_track_zone_open_under_limit),
	KUNIT_CASE(test_track_zone_open_at_limit),
	KUNIT_CASE(test_track_zone_open_exceeds_limit),
	KUNIT_CASE(test_decide_write_permission_conventional_zone),
	KUNIT_CASE(test_decide_write_permission_not_wp),
	KUNIT_CASE(test_decide_write_permission_empty_zone),
	KUNIT_CASE(test_decide_write_permission_closed_zone),
	KUNIT_CASE(test_decide_write_permission_readonly_zone),
	KUNIT_CASE(test_decide_write_permission_full_zone),
	KUNIT_CASE(test_decide_write_permission_offline_zone),
	KUNIT_CASE(test_decide_write_permission_open_zone_before_wp),
	KUNIT_CASE(test_decide_write_permission_open_zone_at_wp),
	KUNIT_CASE(test_devops_peb_isbad_always_good),
	KUNIT_CASE(test_devops_mark_peb_bad_is_noop),
	KUNIT_CASE(test_devops_device_name),
	KUNIT_CASE(test_sync_folio_request_redirect_success),
	KUNIT_CASE(test_sync_folio_request_redirect_propagates_error),
	KUNIT_CASE(test_sync_batch_request_redirect_success),
	KUNIT_CASE(test_sync_batch_request_redirect_propagates_error),
	KUNIT_CASE(test_write_block_fails_on_readonly_fs),
	KUNIT_CASE(test_write_blocks_fails_on_readonly_fs),
	KUNIT_CASE(test_write_blocks_empty_batch_is_noop),
	KUNIT_CASE(test_write_block_end_to_end_success),
	KUNIT_CASE(test_write_block_end_to_end_error),
	KUNIT_CASE(test_write_blocks_end_to_end_success),
	KUNIT_CASE(test_write_blocks_end_to_end_error),
	KUNIT_CASE(test_read_block_delegates_to_bdev_success),
	KUNIT_CASE(test_read_block_delegates_to_bdev_error),
	{}
};

static struct kunit_suite dev_zns_test_suite = {
	.name = "ssdfs_dev_zns",
	.test_cases = dev_zns_test_cases,
};

kunit_test_suites(&dev_zns_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("KUnit tests for SSDFS ZNS SSD support code");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
