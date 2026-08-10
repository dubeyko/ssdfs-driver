// SPDX-License-Identifier: BSD-3-Clause-Clear
/*
 * SSDFS -- SSD-oriented File System.
 *
 * fs/ssdfs/dev_bdev_test.c - KUnit tests for block device access code.
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
 * Test cases for ssdfs_bdev_calc_sector()
 */
static void test_calc_sector_zero_offset(struct kunit *test)
{
	sector_t sector;

	sector = ssdfs_bdev_calc_sector(0, PAGE_SIZE);
	KUNIT_EXPECT_EQ(test, 0, sector);
}

static void test_calc_sector_aligned_offset(struct kunit *test)
{
	sector_t sector;
	u32 block_size = PAGE_SIZE;

	/* second block starts at offset == block_size */
	sector = ssdfs_bdev_calc_sector(block_size, block_size);
	KUNIT_EXPECT_EQ(test, block_size >> SSDFS_SECTOR_SHIFT, sector);

	/* fifth block */
	sector = ssdfs_bdev_calc_sector(4 * (loff_t)block_size, block_size);
	KUNIT_EXPECT_EQ(test, (4ULL * block_size) >> SSDFS_SECTOR_SHIFT,
			sector);
}

static void test_calc_sector_unaligned_offset(struct kunit *test)
{
	sector_t sector;
	u32 block_size = PAGE_SIZE;

	/* offset in the middle of the second block truncates down to it */
	sector = ssdfs_bdev_calc_sector(block_size + 100, block_size);
	KUNIT_EXPECT_EQ(test, block_size >> SSDFS_SECTOR_SHIFT, sector);
}

static void test_calc_sector_small_block_size(struct kunit *test)
{
	sector_t sector;
	u32 block_size = 4096;

	sector = ssdfs_bdev_calc_sector(3 * (loff_t)block_size, block_size);
	KUNIT_EXPECT_EQ(test, (3ULL * block_size) >> SSDFS_SECTOR_SHIFT,
			sector);
}

/*
 * Test cases for ssdfs_bdev_calc_read_batch_range()
 */
static void test_calc_read_batch_range_single_block(struct kunit *test)
{
	loff_t folio_start, folio_end;
	u32 folios_count;
	int err;

	err = ssdfs_bdev_calc_read_batch_range(0, PAGE_SIZE, PAGE_SIZE,
						&folio_start, &folio_end,
						&folios_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, folio_start);
	KUNIT_EXPECT_EQ(test, 1, folio_end);
	KUNIT_EXPECT_EQ(test, 1, folios_count);
}

static void test_calc_read_batch_range_multiple_blocks(struct kunit *test)
{
	loff_t folio_start, folio_end;
	u32 folios_count;
	int err;

	err = ssdfs_bdev_calc_read_batch_range(0, 4 * PAGE_SIZE, PAGE_SIZE,
						&folio_start, &folio_end,
						&folios_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, folio_start);
	KUNIT_EXPECT_EQ(test, 4, folio_end);
	KUNIT_EXPECT_EQ(test, 4, folios_count);
}

static void test_calc_read_batch_range_unaligned_len(struct kunit *test)
{
	loff_t folio_start, folio_end;
	u32 folios_count;
	int err;

	/* len smaller than block_size still needs one folio */
	err = ssdfs_bdev_calc_read_batch_range(0, 100, PAGE_SIZE,
						&folio_start, &folio_end,
						&folios_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 1, folios_count);

	/* offset + len straddling a block boundary needs two folios */
	err = ssdfs_bdev_calc_read_batch_range(PAGE_SIZE - 100, 200, PAGE_SIZE,
						&folio_start, &folio_end,
						&folios_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 2, folios_count);
}

static void test_calc_read_batch_range_at_extent_max(struct kunit *test)
{
	loff_t folio_start, folio_end;
	u32 folios_count;
	int err;
	size_t len = (size_t)SSDFS_EXTENT_LEN_MAX * PAGE_SIZE;

	err = ssdfs_bdev_calc_read_batch_range(0, len, PAGE_SIZE,
						&folio_start, &folio_end,
						&folios_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, SSDFS_EXTENT_LEN_MAX, folios_count);
}

static void test_calc_read_batch_range_exceeds_extent_max(struct kunit *test)
{
	loff_t folio_start, folio_end;
	u32 folios_count;
	int err;
	size_t len = (size_t)(SSDFS_EXTENT_LEN_MAX + 1) * PAGE_SIZE;

	err = ssdfs_bdev_calc_read_batch_range(0, len, PAGE_SIZE,
						&folio_start, &folio_end,
						&folios_count);
	KUNIT_EXPECT_EQ(test, -ERANGE, err);
	KUNIT_EXPECT_EQ(test, SSDFS_EXTENT_LEN_MAX + 1, folios_count);
}

/*
 * Test cases for ssdfs_bdev_calc_trim_range()
 */
static void test_calc_trim_range_valid(struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	int err;

	err = ssdfs_bdev_calc_trim_range(0, erase_size, erase_size,
					 &start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, start_sector);
	KUNIT_EXPECT_EQ(test, erase_size >> SSDFS_SECTOR_SHIFT,
			sectors_count);
}

static void test_calc_trim_range_second_erase_block(struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	int err;

	err = ssdfs_bdev_calc_trim_range(erase_size, erase_size, erase_size,
					 &start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, (sector_t)erase_size >> SSDFS_SECTOR_SHIFT,
			start_sector);
	KUNIT_EXPECT_EQ(test, erase_size >> SSDFS_SECTOR_SHIFT,
			sectors_count);
}

static void test_calc_trim_range_multiple_erase_blocks(struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	int err;

	err = ssdfs_bdev_calc_trim_range(0, 3 * (size_t)erase_size, erase_size,
					 &start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_EQ(test, 0, start_sector);
	KUNIT_EXPECT_EQ(test, (3ULL * erase_size) >> SSDFS_SECTOR_SHIFT,
			sectors_count);
}

static void test_calc_trim_range_unaligned_len(struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	int err;

	err = ssdfs_bdev_calc_trim_range(0, erase_size + 1, erase_size,
					 &start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, -ERANGE, err);
}

static void test_calc_trim_range_zero_len(struct kunit *test)
{
	sector_t start_sector, sectors_count;
	u32 erase_size = 2 * 1024 * 1024; /* 2 MiB */
	int err;

	/* len == 0 is aligned (remainder 0), but yields zero pages */
	err = ssdfs_bdev_calc_trim_range(0, 0, erase_size,
					 &start_sector, &sectors_count);
	KUNIT_EXPECT_EQ(test, -ERANGE, err);
}

/*
 * Test cases for the trivial ssdfs_bdev_devops callbacks
 */
static void test_devops_open_zone_not_supported(struct kunit *test)
{
	int err;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssdfs_bdev_devops.open_zone);
	err = ssdfs_bdev_devops.open_zone(NULL, 0);
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP, err);
}

static void test_devops_reopen_zone_not_supported(struct kunit *test)
{
	int err;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssdfs_bdev_devops.reopen_zone);
	err = ssdfs_bdev_devops.reopen_zone(NULL, 0);
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP, err);
}

static void test_devops_close_zone_not_supported(struct kunit *test)
{
	int err;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssdfs_bdev_devops.close_zone);
	err = ssdfs_bdev_devops.close_zone(NULL, 0);
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP, err);
}

static void test_devops_peb_isbad_always_good(struct kunit *test)
{
	int err;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssdfs_bdev_devops.peb_isbad);
	err = ssdfs_bdev_devops.peb_isbad(NULL, 0);
	KUNIT_EXPECT_EQ(test, 0, err);
}

static void test_devops_mark_peb_bad_is_noop(struct kunit *test)
{
	int err;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssdfs_bdev_devops.mark_peb_bad);
	err = ssdfs_bdev_devops.mark_peb_bad(NULL, 0);
	KUNIT_EXPECT_EQ(test, 0, err);
}

static void test_devops_device_name(struct kunit *test)
{
	struct super_block *sb;
	const char *name;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ssdfs_bdev_devops.device_name);

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	strscpy(sb->s_id, "loop0", sizeof(sb->s_id));

	name = ssdfs_bdev_devops.device_name(sb);
	KUNIT_EXPECT_STREQ(test, "loop0", name);

	kfree(sb);
}

/*
 * Test cases for guard clauses of the public entry points
 */
static void test_read_zero_length_is_noop(struct kunit *test)
{
	int err;

	/* len == 0 short-circuits before any device is touched */
	err = ssdfs_bdev_read(NULL, PAGE_SIZE, 0, 0, NULL);
	KUNIT_EXPECT_EQ(test, 0, err);
}

static void test_write_block_fails_on_readonly_fs(struct kunit *test)
{
	struct super_block *sb;
	int err;

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	sb->s_flags |= SB_RDONLY;

	/*
	 * The RO check happens before folio/device are touched,
	 * so it is safe to pass folio == NULL here.
	 */
	err = ssdfs_bdev_write_block(sb, 0, NULL, 0);
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

	/*
	 * The RO check happens before the batch is touched,
	 * so it is safe to pass batch == NULL here.
	 */
	err = ssdfs_bdev_write_blocks(sb, 0, NULL, 0);
	KUNIT_EXPECT_EQ(test, -EROFS, err);

	kfree(sb);
}

static void test_write_blocks_empty_batch_is_noop(struct kunit *test)
{
	struct super_block *sb;
	struct folio_batch batch;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	/*
	 * Under CONFIG_SSDFS_DEBUG, ssdfs_bdev_write_blocks() runs a
	 * BUG_ON(offset >= ssdfs_bdev_device_size(sb)) between the RO
	 * check and the empty-batch check, and device_size() derefs
	 * sb->s_bdev. This test doesn't fake a real block device, so
	 * skip it in debug builds rather than crash the test run.
	 */
	kunit_skip(test, "requires !CONFIG_SSDFS_DEBUG (BUG_ON derefs sb->s_bdev)");
	return;
#endif /* CONFIG_SSDFS_DEBUG */

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sb);

	/* not read-only, so the flow reaches the empty batch check */
	sb->s_flags = 0;

	folio_batch_init(&batch);

	err = ssdfs_bdev_write_blocks(sb, 0, &batch, 0);
	KUNIT_EXPECT_EQ(test, 0, err);

	kfree(sb);
}

/*
 * Test cases for the ssdfs_bdev_submit_bio_wait() static stub redirect
 */
static int fake_submit_bio_wait_success(struct bio *bio)
{
	return 0;
}

static int fake_submit_bio_wait_error(struct bio *bio)
{
	return -EIO;
}

static void test_submit_bio_wait_redirect_success(struct kunit *test)
{
	struct bio fake_bio;
	int err;

	memset(&fake_bio, 0, sizeof(fake_bio));

	kunit_activate_static_stub(test, ssdfs_bdev_submit_bio_wait,
				   fake_submit_bio_wait_success);

	/*
	 * Without the redirect this would call the real
	 * submit_bio_wait() against an unusable fake bio and crash
	 * (or block forever). The static stub makes it safe to call
	 * ssdfs_bdev_submit_bio_wait() here.
	 */
	err = ssdfs_bdev_submit_bio_wait(&fake_bio);
	KUNIT_EXPECT_EQ(test, 0, err);
}

static void test_submit_bio_wait_redirect_propagates_error(struct kunit *test)
{
	struct bio fake_bio;
	int err;

	memset(&fake_bio, 0, sizeof(fake_bio));

	kunit_activate_static_stub(test, ssdfs_bdev_submit_bio_wait,
				   fake_submit_bio_wait_error);

	err = ssdfs_bdev_submit_bio_wait(&fake_bio);
	KUNIT_EXPECT_EQ(test, -EIO, err);
}

/*
 * Test cases for ssdfs_bdev_read_block()/ssdfs_bdev_read_blocks() and
 * ssdfs_bdev_write_block()/ssdfs_bdev_write_blocks(), exercised
 * end-to-end via the ssdfs_bdev_sync_folio_request()/
 * ssdfs_bdev_sync_batch_request() static stub redirect.
 */
static int fake_sync_folio_request_success(struct super_block *sb,
					    struct folio *folio,
					    loff_t offset,
					    unsigned int op,
					    int op_flags,
					    u8 write_stream)
{
	return 0;
}

static int fake_sync_folio_request_error(struct super_block *sb,
					  struct folio *folio,
					  loff_t offset,
					  unsigned int op,
					  int op_flags,
					  u8 write_stream)
{
	return -EIO;
}

static int fake_sync_batch_request_success(struct super_block *sb,
					    struct folio_batch *batch,
					    loff_t offset,
					    unsigned int op,
					    int op_flags,
					    u8 write_stream)
{
	return 0;
}

static int fake_sync_batch_request_error(struct super_block *sb,
					  struct folio_batch *batch,
					  loff_t offset,
					  unsigned int op,
					  int op_flags,
					  u8 write_stream)
{
	return -EIO;
}

static void test_read_block_end_to_end_success(struct kunit *test)
{
	struct folio *folio;
	int err;

	folio = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	/* ssdfs_bdev_read_block() expects the caller to have locked it */
	folio_lock(folio);

	kunit_activate_static_stub(test, ssdfs_bdev_sync_folio_request,
				   fake_sync_folio_request_success);

	/* sb is never dereferenced: the redirect fires before it would be */
	err = ssdfs_bdev_read_block(NULL, folio, 0);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_TRUE(test, folio_test_uptodate(folio));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio));

	folio_put(folio);
}

static void test_read_block_end_to_end_error(struct kunit *test)
{
	struct folio *folio;
	int err;

	folio = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);

	folio_lock(folio);
	folio_mark_uptodate(folio);

	kunit_activate_static_stub(test, ssdfs_bdev_sync_folio_request,
				   fake_sync_folio_request_error);

	err = ssdfs_bdev_read_block(NULL, folio, 0);
	KUNIT_EXPECT_EQ(test, -EIO, err);
	KUNIT_EXPECT_FALSE(test, folio_test_uptodate(folio));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio));

	folio_put(folio);
}

static void test_read_blocks_end_to_end_success(struct kunit *test)
{
	struct folio_batch batch;
	struct folio *folio1, *folio2;
	int err;

	folio1 = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio2 = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	folio_lock(folio1);
	folio_lock(folio2);

	folio_batch_init(&batch);
	folio_batch_add(&batch, folio1);
	folio_batch_add(&batch, folio2);

	kunit_activate_static_stub(test, ssdfs_bdev_sync_batch_request,
				   fake_sync_batch_request_success);

	err = ssdfs_bdev_read_blocks(NULL, &batch, 0);
	KUNIT_EXPECT_EQ(test, 0, err);
	KUNIT_EXPECT_TRUE(test, folio_test_uptodate(folio1));
	KUNIT_EXPECT_TRUE(test, folio_test_uptodate(folio2));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio1));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio2));

	folio_put(folio1);
	folio_put(folio2);
}

static void test_read_blocks_end_to_end_error(struct kunit *test)
{
	struct folio_batch batch;
	struct folio *folio1;
	int err;

	folio1 = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);

	folio_lock(folio1);
	folio_mark_uptodate(folio1);

	folio_batch_init(&batch);
	folio_batch_add(&batch, folio1);

	kunit_activate_static_stub(test, ssdfs_bdev_sync_batch_request,
				   fake_sync_batch_request_error);

	err = ssdfs_bdev_read_blocks(NULL, &batch, 0);
	KUNIT_EXPECT_EQ(test, -EIO, err);
	KUNIT_EXPECT_FALSE(test, folio_test_uptodate(folio1));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio1));

	folio_put(folio1);
}

static void test_write_block_end_to_end_success(struct kunit *test)
{
	struct super_block *sb;
	struct ssdfs_fs_info *fsi;
	struct folio *folio;
	int err;

#ifdef CONFIG_SSDFS_DEBUG
	/*
	 * Under CONFIG_SSDFS_DEBUG, ssdfs_bdev_write_block() runs a
	 * BUG_ON() range check against ssdfs_bdev_device_size(sb),
	 * which derefs sb->s_bdev. This test doesn't fake a real
	 * block device, so skip it in debug builds.
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

	folio = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);
	folio_mark_dirty(folio);
	/* extra ref: ssdfs_bdev_write_block() consumes one via ssdfs_folio_put() */
	folio_get(folio);

	kunit_activate_static_stub(test, ssdfs_bdev_sync_folio_request,
				   fake_sync_folio_request_success);

	/* ssdfs_bdev_write_block() locks the folio itself */
	err = ssdfs_bdev_write_block(sb, 0, folio, 0);
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

	folio = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio);
	folio_mark_dirty(folio);
	folio_get(folio);

	kunit_activate_static_stub(test, ssdfs_bdev_sync_folio_request,
				   fake_sync_folio_request_error);

	err = ssdfs_bdev_write_block(sb, 0, folio, 0);
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

	folio1 = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio2 = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio2);

	folio_mark_dirty(folio1);
	folio_mark_dirty(folio2);
	/* extra refs: ssdfs_bdev_write_blocks() consumes one each */
	folio_get(folio1);
	folio_get(folio2);

	folio_batch_init(&batch);
	folio_batch_add(&batch, folio1);
	folio_batch_add(&batch, folio2);

	kunit_activate_static_stub(test, ssdfs_bdev_sync_batch_request,
				   fake_sync_batch_request_success);

	/* ssdfs_bdev_write_blocks() locks each folio itself */
	err = ssdfs_bdev_write_blocks(sb, 0, &batch, 0);
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

	folio1 = folio_alloc(GFP_KERNEL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, folio1);
	folio_mark_dirty(folio1);
	folio_get(folio1);

	folio_batch_init(&batch);
	folio_batch_add(&batch, folio1);

	kunit_activate_static_stub(test, ssdfs_bdev_sync_batch_request,
				   fake_sync_batch_request_error);

	err = ssdfs_bdev_write_blocks(sb, 0, &batch, 0);
	KUNIT_EXPECT_EQ(test, -EIO, err);
	KUNIT_EXPECT_TRUE(test, folio_test_dirty(folio1));
	KUNIT_EXPECT_FALSE(test, folio_test_locked(folio1));

	folio_put(folio1);
	kfree(fsi);
	kfree(sb);
}

static struct kunit_case dev_bdev_test_cases[] = {
	KUNIT_CASE(test_calc_sector_zero_offset),
	KUNIT_CASE(test_calc_sector_aligned_offset),
	KUNIT_CASE(test_calc_sector_unaligned_offset),
	KUNIT_CASE(test_calc_sector_small_block_size),
	KUNIT_CASE(test_calc_read_batch_range_single_block),
	KUNIT_CASE(test_calc_read_batch_range_multiple_blocks),
	KUNIT_CASE(test_calc_read_batch_range_unaligned_len),
	KUNIT_CASE(test_calc_read_batch_range_at_extent_max),
	KUNIT_CASE(test_calc_read_batch_range_exceeds_extent_max),
	KUNIT_CASE(test_calc_trim_range_valid),
	KUNIT_CASE(test_calc_trim_range_second_erase_block),
	KUNIT_CASE(test_calc_trim_range_multiple_erase_blocks),
	KUNIT_CASE(test_calc_trim_range_unaligned_len),
	KUNIT_CASE(test_calc_trim_range_zero_len),
	KUNIT_CASE(test_devops_open_zone_not_supported),
	KUNIT_CASE(test_devops_reopen_zone_not_supported),
	KUNIT_CASE(test_devops_close_zone_not_supported),
	KUNIT_CASE(test_devops_peb_isbad_always_good),
	KUNIT_CASE(test_devops_mark_peb_bad_is_noop),
	KUNIT_CASE(test_devops_device_name),
	KUNIT_CASE(test_read_zero_length_is_noop),
	KUNIT_CASE(test_write_block_fails_on_readonly_fs),
	KUNIT_CASE(test_write_blocks_fails_on_readonly_fs),
	KUNIT_CASE(test_write_blocks_empty_batch_is_noop),
	KUNIT_CASE(test_submit_bio_wait_redirect_success),
	KUNIT_CASE(test_submit_bio_wait_redirect_propagates_error),
	KUNIT_CASE(test_read_block_end_to_end_success),
	KUNIT_CASE(test_read_block_end_to_end_error),
	KUNIT_CASE(test_read_blocks_end_to_end_success),
	KUNIT_CASE(test_read_blocks_end_to_end_error),
	KUNIT_CASE(test_write_block_end_to_end_success),
	KUNIT_CASE(test_write_block_end_to_end_error),
	KUNIT_CASE(test_write_blocks_end_to_end_success),
	KUNIT_CASE(test_write_blocks_end_to_end_error),
	{}
};

static struct kunit_suite dev_bdev_test_suite = {
	.name = "ssdfs_dev_bdev",
	.test_cases = dev_bdev_test_cases,
};

kunit_test_suites(&dev_bdev_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Viacheslav Dubeyko <slava@dubeyko.com>");
MODULE_DESCRIPTION("KUnit tests for SSDFS block device access code");
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
